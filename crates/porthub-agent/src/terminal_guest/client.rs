//! Bounded native relay attachment recovery. Recovery never falls back to the
//! original invitation and never replays old or offline keystrokes.
use super::{relay, tty::Terminal, Guest, Invitation, NetworkGuest, Recovery};
use anyhow::{bail, Context, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

pub struct DirectSession {
    pub(crate) socket: tokio::net::UdpSocket,
    pub(crate) mapped: Option<std::net::SocketAddr>,
    pub(crate) permission: crate::terminal_policy::Permission,
}
#[async_trait::async_trait]
pub trait Connector: Send {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;
    async fn connect(
        &mut self,
        recovery: &mut Option<Recovery>,
        cols: u16,
        rows: u16,
    ) -> Result<(Guest<Self::Stream>, porthub_terminal::protocol::ViewerEvent)>;
    async fn direct(&mut self, _guest: &Guest<Self::Stream>) -> Option<DirectSession> {
        None
    }
}
struct Gateway<'a> {
    invitation: &'a Invitation,
    stun_servers: Vec<String>,
    registration: Option<(crate::service::Layout, String)>,
}
#[async_trait::async_trait]
impl Connector for Gateway<'_> {
    type Stream = tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>;
    async fn connect(
        &mut self,
        recovery: &mut Option<Recovery>,
        cols: u16,
        rows: u16,
    ) -> Result<(NetworkGuest, porthub_terminal::protocol::ViewerEvent)> {
        NetworkGuest::connect_resumable(self.invitation, recovery, cols, rows).await
    }
    async fn direct(&mut self, guest: &NetworkGuest) -> Option<DirectSession> {
        let (layout, id) = self.registration.as_ref()?;
        let permission = crate::terminal_policy::subscribe(layout, id).await.ok()?;
        if !permission.allowed() {
            return None;
        }
        let mut local = guest.local_address().ok()?;
        local.set_port(0);
        let socket = tokio::net::UdpSocket::bind(local).await.ok()?;
        if !permission.allowed() {
            return None;
        }
        #[cfg(target_os = "macos")]
        porthub_mesh::underlay::bind_udp_interface(&socket, local.ip()).ok()?;
        let guard = permission.guard();
        let mapped = if self.stun_servers.is_empty() {
            None
        } else {
            porthub_mesh::stun::mapped_with_permission(&socket, &self.stun_servers, guard.as_ref())
                .await
        };
        if !permission.allowed() {
            return None;
        }
        Some(DirectSession {
            socket,
            permission,
            mapped,
        })
    }
}
pub async fn join_relay(value: &str) -> Result<()> {
    join(value, None, Vec::new()).await
}
pub async fn join_auto(value: &str, selector: Option<&str>, user: bool) -> Result<()> {
    join_auto_with_stun(value, selector, user, &[]).await
}
pub async fn join_auto_with_stun(
    value: &str,
    selector: Option<&str>,
    user: bool,
    servers: &[String],
) -> Result<()> {
    let servers = crate::terminal_connectivity::checked(servers)?;
    let registration = select_registration(selector, user)?;
    join(value, registration, servers).await
}
fn select_registration(
    selector: Option<&str>,
    user: bool,
) -> Result<Option<(crate::service::Layout, String)>> {
    let layouts = if user {
        vec![crate::service::Layout::user()?]
    } else if selector.is_some() {
        vec![crate::service::Layout::system()?]
    } else {
        vec![
            crate::service::Layout::user()?,
            crate::service::Layout::system()?,
        ]
    };
    select_from(layouts, selector)
}
fn select_from(
    layouts: Vec<crate::service::Layout>,
    selector: Option<&str>,
) -> Result<Option<(crate::service::Layout, String)>> {
    let mut candidates = Vec::new();
    for layout in layouts {
        if selector.is_some() {
            let record = crate::service::readable::select(&layout, selector, Some(false))?;
            return Ok(if record.enabled {
                Some((layout, record.id))
            } else {
                None
            });
        }
        let Ok(records) = crate::service::readable::list(&layout) else {
            return Ok(None);
        };
        for record in records
            .into_iter()
            .filter(|record| !record.private && record.enabled)
        {
            candidates.push((layout.clone(), record.id));
        }
    }
    Ok(if candidates.len() == 1 {
        candidates.pop()
    } else {
        None
    })
}
async fn join(
    value: &str,
    registration: Option<(crate::service::Layout, String)>,
    stun_servers: Vec<String>,
) -> Result<()> {
    let invitation = Invitation::parse(value)?;
    // Install termination handlers before changing the local terminal mode.
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let terminal = Terminal::open()?;
    let mut gateway = Gateway {
        invitation: &invitation,
        registration,
        stun_servers,
    };
    tokio::select! {
        result=run(&mut gateway,&terminal)=>{result?;},
        _=hangup.recv()=>{},
        _=terminate.recv()=>{},
        _=interrupt.recv()=>{},
    }
    Ok(())
}
/// Setup may include TLS, a local policy handshake and bounded STUN gathering.
/// Keys typed before it finishes must never become delayed shell commands.
pub(super) async fn preparing<F: std::future::Future>(
    terminal: &Terminal,
    future: F,
) -> Result<Option<F::Output>> {
    tokio::pin!(future);
    let mut discard = [0; 16384];
    loop {
        tokio::select! {
            result=&mut future=>{terminal.discard_offline_input()?;return Ok(Some(result));},
            count=terminal.read(&mut discard)=>{let count=count?;if count==0 || discard[..count].contains(&3){return Ok(None);}},
        }
    }
}
pub async fn run<C: Connector>(connector: &mut C, terminal: &Terminal) -> Result<relay::End> {
    let size = terminal.size()?;
    let Some(connected) = preparing(terminal, connector.connect(&mut None, size.0, size.1)).await?
    else {
        return Ok(relay::End {
            reason: "connection cancelled locally".into(),
            retryable: false,
        });
    };
    let (mut guest, mut welcome) = connected?;
    loop {
        let direct = if matches!(
            welcome,
            porthub_terminal::protocol::ViewerEvent::Welcome {
                direct_transport: true,
                ..
            }
        ) {
            let Some(direct) = preparing(terminal, connector.direct(&guest)).await? else {
                return Ok(relay::End {
                    reason: "connection cancelled locally".into(),
                    retryable: false,
                });
            };
            direct
        } else {
            None
        };
        let (socket, permission, mapped) = match direct {
            Some(direct) => (Some(direct.socket), Some(direct.permission), direct.mapped),
            None => (None, None, None),
        };
        match Box::pin(relay::run_with_reflexive_policy(
            &mut guest, terminal, &welcome, socket, permission, mapped,
        ))
        .await
        {
            Ok(end) if !end.retryable => return Ok(end),
            Err(error) if !super::retryable(&error) => return Err(error),
            _ => {}
        }
        let mut recovery = Some(
            guest
                .take_recovery()
                .context("terminal recovery unavailable; join again")?,
        );
        let deadline = recovery
            .as_ref()
            .and_then(|recovery| recovery.deadline)
            .context("terminal recovery deadline unavailable")?;
        // Close the previous attachment before attempting its replacement.
        drop(guest);
        tokio::time::timeout(
            Duration::from_secs(3),
            terminal.write_all(
                b"\r\n[PortHub reconnecting. Offline keys are discarded; Ctrl+C cancels.]\r\n",
            ),
        )
        .await
        .context("local terminal output stalled")??;
        let reconnect = async {
            let mut delay = Duration::from_millis(250);
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    bail!("terminal recovery window expired; join again");
                }
                let size = terminal.size()?;
                let attempt = tokio::time::timeout(
                    remaining,
                    connector.connect(&mut recovery, size.0, size.1),
                )
                .await;
                match attempt {
                    Ok(Ok(connected)) => return Ok(connected),
                    Ok(Err(error)) if !super::retryable(&error) => return Err(error),
                    _ => {}
                }
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    bail!("terminal recovery window expired; join again");
                }
                tokio::time::sleep(delay.min(remaining)).await;
                delay = (delay * 2).min(Duration::from_secs(2));
            }
        };
        tokio::pin!(reconnect);
        let mut discard = [0; 16384];
        let connected = loop {
            tokio::select! {
                result=&mut reconnect=>break result?,
                count=terminal.read(&mut discard)=>{
                    let count=count?;
                    if count==0 || discard[..count].contains(&3) {
                        return Ok(relay::End {reason:"reconnect cancelled locally".into(),retryable:false});
                    }
                },
            }
        };
        // A just-completed connect and a readable TTY can be ready in the same
        // select. Discard that final offline tail before enabling the new shell.
        terminal.discard_offline_input()?;
        (guest, welcome) = connected;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn automatic_registration_selection_requires_one_unambiguous_readable_public_registration(
    ) -> Result<()> {
        let root = tempfile::tempdir()?;
        let layout = crate::service::Layout {
            user: true,
            state: root.path().join("native"),
            releases: root.path().join("releases"),
            units: root.path().join("units"),
        };
        assert!(select_from(vec![layout.clone()], None)?.is_none());
        let status = crate::service::readable::directory(&layout)?;
        porthub_terminal::multiplexer::create_directory(&status)?;
        let record = |id: &str, machine: &str| crate::service::readable::Record {
            format_version: 1,
            id: id.into(),
            machine_id: machine.into(),
            email: "fixture@example.test".into(),
            gateway: "https://example.test".into(),
            private: false,
            enabled: true,
            active: Some(true),
            state: "running".into(),
            agent_version: "test".into(),
            ports: 0,
            route: "public".into(),
            updated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            strategy: Default::default(),
            strategy_override: false,
            private_status: None,
        };
        let id = "a".repeat(64);
        let other = "b".repeat(64);
        crate::profile::write_private(
            &status.join(format!("{id}.json")),
            &serde_json::to_vec(&record(&id, "1"))?,
            false,
        )?;
        assert_eq!(select_from(vec![layout.clone()], None)?.unwrap().1, id);
        crate::profile::write_private(
            &status.join(format!("{other}.json")),
            &serde_json::to_vec(&record(&other, "2"))?,
            false,
        )?;
        assert!(
            select_from(vec![layout.clone()], None)?.is_none(),
            "auto must not guess between accounts"
        );
        assert_eq!(
            select_from(vec![layout.clone()], Some("aaaaaa"))?
                .unwrap()
                .1,
            id
        );
        crate::profile::write_private(
            &status.join(format!("{other}.json")),
            b"unreadable metadata",
            true,
        )?;
        assert!(
            select_from(vec![layout], None)?.is_none(),
            "unknown registrations cannot approve direct traffic"
        );
        Ok(())
    }
}
