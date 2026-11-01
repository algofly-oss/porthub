//! Authenticated native guest signaling. Experimental; the CLI still uses SSH.
//! Invitation and recovery capabilities travel only in the encrypted first
//! message, never in request URLs or diagnostic values.
#[cfg(unix)]
pub mod relay;
#[cfg(unix)]
pub mod tty;

use anyhow::{bail, ensure, Context, Result};
use futures_util::{SinkExt, StreamExt};
use porthub_terminal::protocol::{dimensions, token, ViewerEvent, ViewerInput};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    tungstenite::{protocol::WebSocketConfig, Message},
    MaybeTlsStream, WebSocketStream,
};

pub struct Invitation {
    endpoint: url::Url,
    capability: String,
}
impl Invitation {
    pub fn parse(value: &str) -> Result<Self> {
        let mut endpoint = url::Url::parse(value)
            .map_err(|_| anyhow::anyhow!("invalid terminal invitation URL"))?;
        ensure!(
            endpoint.scheme() == "https"
                && endpoint.host_str().is_some()
                && endpoint.username().is_empty()
                && endpoint.password().is_none(),
            "terminal invitations must use HTTPS without URL credentials"
        );
        let capability = endpoint
            .fragment()
            .filter(|value| token(value, 64))
            .context("invalid terminal invitation capability")?
            .to_owned();
        endpoint.set_fragment(None);
        endpoint.set_query(None);
        endpoint.set_path("/api/terminal/join");
        endpoint
            .set_scheme("wss")
            .map_err(|_| anyhow::anyhow!("invalid terminal endpoint"))?;
        Ok(Self {
            endpoint,
            capability,
        })
    }
}

/// Kept in memory only. A reconnect gets fresh delivery epochs; this credential
/// does not authorize replaying uncertain shell input from the old attachment.
pub struct Recovery {
    capability: String,
    grace: Duration,
    deadline: Option<Instant>,
}

pub struct Guest<S> {
    socket: WebSocketStream<S>,
    read_only: bool,
    recovery: Option<Recovery>,
    last_received: tokio::time::Instant,
}
pub type NetworkGuest = Guest<MaybeTlsStream<tokio::net::TcpStream>>;

impl NetworkGuest {
    pub async fn connect(
        invitation: &Invitation,
        recovery: Option<Recovery>,
        cols: u16,
        rows: u16,
    ) -> Result<(Self, ViewerEvent)> {
        dimensions(cols, rows)?;
        let limits = WebSocketConfig::default()
            .read_buffer_size(8192)
            .write_buffer_size(8192)
            .max_message_size(Some(32768))
            .max_frame_size(Some(32768));
        let (socket, _) = tokio::time::timeout(
            Duration::from_secs(15),
            tokio_tungstenite::connect_async_with_config(
                invitation.endpoint.as_str(),
                Some(limits),
                false,
            ),
        )
        .await
        .context("terminal gateway connection timed out")?
        .map_err(|_| anyhow::anyhow!("terminal gateway TLS/WebSocket connection failed"))?;
        Self::authenticate(socket, &invitation.capability, recovery, cols, rows).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Guest<S> {
    async fn authenticate(
        mut socket: WebSocketStream<S>,
        invitation: &str,
        recovery: Option<Recovery>,
        cols: u16,
        rows: u16,
    ) -> Result<(Self, ViewerEvent)> {
        dimensions(cols, rows)?;
        ensure!(
            token(invitation, 64),
            "invalid terminal invitation capability"
        );
        let hello = match recovery {
            Some(recovery) => {
                ensure!(
                    recovery
                        .deadline
                        .is_some_and(|deadline| Instant::now() < deadline),
                    "terminal recovery window expired"
                );
                serde_json::json!({"resume_token":recovery.capability,"cols":cols,"rows":rows,"term":"xterm-256color"})
            }
            None => {
                serde_json::json!({"token":invitation,"cols":cols,"rows":rows,"term":"xterm-256color"})
            }
        };
        tokio::time::timeout(
            Duration::from_secs(3),
            socket.send(Message::Text(hello.to_string().into())),
        )
        .await
        .context("terminal authentication send timed out")?
        .map_err(|_| anyhow::anyhow!("terminal authentication send failed"))?;
        let mut guest = Self {
            socket,
            read_only: true,
            recovery: None,
            last_received: tokio::time::Instant::now(),
        };
        let welcome = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let event = guest.read_event().await?;
                match event {
                    ViewerEvent::Welcome { read_only, .. } => {
                        guest.read_only = read_only;
                        return Ok(event);
                    }
                    ViewerEvent::Recovery { .. } => {}
                    _ => bail!("terminal invitation unavailable or invalid handshake"),
                }
            }
        })
        .await
        .context("terminal host handshake timed out")??;
        Ok((guest, welcome))
    }
    pub fn read_only(&self) -> bool {
        self.read_only
    }
    /// Move the credential out when replacing an attachment; never clone a
    /// delivery journal along with it. Deadline starts at the disconnect.
    pub fn take_recovery(&mut self) -> Option<Recovery> {
        self.recovery.take().map(|mut recovery| {
            recovery.deadline = Some(Instant::now() + recovery.grace);
            recovery
        })
    }
    pub async fn send(&mut self, input: &ViewerInput) -> Result<()> {
        match input {
            ViewerInput::Input { .. } => {
                ensure!(!self.read_only, "terminal participant is read-only")
            }
            ViewerInput::Delivery { packet } => {
                if matches!(
                    packet.decode()?,
                    porthub_terminal::delivery::Message::Data(_)
                ) {
                    ensure!(!self.read_only, "terminal participant is read-only");
                }
            }
            ViewerInput::Resize { cols, rows } => dimensions(*cols, *rows)?,
            _ => {}
        }
        let text = serde_json::to_string(input)?;
        ensure!(
            text.len() <= 32768,
            "terminal signaling frame exceeds limit"
        );
        tokio::time::timeout(
            Duration::from_secs(3),
            self.socket.send(Message::Text(text.into())),
        )
        .await
        .context("terminal signaling send timed out")?
        .map_err(|_| anyhow::anyhow!("terminal signaling send failed"))
    }
    pub async fn next_event(&mut self) -> Result<ViewerEvent> {
        let event = tokio::time::timeout_at(
            self.last_received + Duration::from_secs(45),
            self.read_event(),
        )
        .await
        .context("terminal gateway heartbeat timed out")??;
        ensure!(
            !matches!(event, ViewerEvent::Welcome { .. }),
            "duplicate terminal welcome"
        );
        Ok(event)
    }
    async fn read_event(&mut self) -> Result<ViewerEvent> {
        loop {
            let message = self
                .socket
                .next()
                .await
                .context("terminal gateway disconnected")?
                .map_err(|_| anyhow::anyhow!("terminal gateway receive failed"))?;
            match message {
                Message::Text(text) => {
                    ensure!(
                        text.len() <= 32768,
                        "terminal signaling frame exceeds limit"
                    );
                    let event: ViewerEvent = serde_json::from_str(&text)
                        .map_err(|_| anyhow::anyhow!("invalid terminal signaling frame"))?;
                    self.last_received = tokio::time::Instant::now();
                    match &event {
                        ViewerEvent::Ping => {
                            self.send(&ViewerInput::Pong).await?;
                            continue;
                        }
                        ViewerEvent::Recovery {
                            session,
                            token: capability,
                            participant,
                            reconnect_timeout,
                        } => {
                            ensure!(
                                token(session, 32)
                                    && token(capability, 64)
                                    && *participant > 0
                                    && (10..=300).contains(reconnect_timeout),
                                "invalid terminal recovery credential"
                            );
                            self.recovery = Some(Recovery {
                                capability: capability.clone(),
                                grace: Duration::from_secs(*reconnect_timeout as u64),
                                deadline: None,
                            });
                        }
                        _ => {}
                    }
                    return Ok(event);
                }
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Close(_) => bail!("terminal gateway disconnected"),
                _ => bail!("invalid terminal signaling frame type"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, DuplexStream};
    use tokio_tungstenite::tungstenite::protocol::Role;
    async fn pair() -> (WebSocketStream<DuplexStream>, WebSocketStream<DuplexStream>) {
        let (client, server) = duplex(131072);
        (
            WebSocketStream::from_raw_socket(client, Role::Client, None).await,
            WebSocketStream::from_raw_socket(server, Role::Server, None).await,
        )
    }
    async fn event(socket: &mut WebSocketStream<DuplexStream>, event: ViewerEvent) {
        socket
            .send(Message::Text(serde_json::to_string(&event).unwrap().into()))
            .await
            .unwrap();
    }
    fn recovery() -> ViewerEvent {
        ViewerEvent::Recovery {
            session: "a".repeat(32),
            token: "b".repeat(64),
            participant: 1,
            reconnect_timeout: 10,
        }
    }
    fn welcome(read_only: bool) -> ViewerEvent {
        ViewerEvent::Welcome {
            direct_transport: true,
            history_snapshots: true,
            name: "test".into(),
            read_only,
            expires_at: 0,
            participants: 1,
        }
    }
    #[test]
    fn invitations_strip_capabilities_and_queries_and_require_tls() -> Result<()> {
        let invitation = Invitation::parse(&format!(
            "https://example.org:443/terminal?unused=secret#{}",
            "a".repeat(64)
        ))?;
        assert_eq!(
            invitation.endpoint.as_str(),
            "wss://example.org/api/terminal/join"
        );
        assert_eq!(invitation.capability, "a".repeat(64));
        for value in [
            "http://example.org/#",
            "https://user:password@example.org/#",
            "https://example.org/#bad",
        ] {
            assert!(Invitation::parse(value).is_err());
        }
        Ok(())
    }
    #[tokio::test]
    async fn authenticates_before_input_keeps_recovery_and_answers_heartbeats() -> Result<()> {
        let (client, mut server) = pair().await;
        let remote = tokio::spawn(async move {
            let hello = server.next().await.unwrap().unwrap().into_text().unwrap();
            let hello: serde_json::Value = serde_json::from_str(&hello).unwrap();
            assert_eq!(hello["token"], "a".repeat(64));
            assert!(hello.get("resume_token").is_none());
            event(&mut server, recovery()).await;
            event(&mut server, welcome(false)).await;
            event(&mut server, ViewerEvent::Ping).await;
            event(
                &mut server,
                ViewerEvent::Output {
                    data: "b2s=".into(),
                },
            )
            .await;
            let input = server.next().await.unwrap().unwrap().into_text().unwrap();
            assert!(matches!(
                serde_json::from_str::<ViewerInput>(&input).unwrap(),
                ViewerInput::Pong
            ));
            let input = server.next().await.unwrap().unwrap().into_text().unwrap();
            assert!(
                matches!(serde_json::from_str::<ViewerInput>(&input).unwrap(),ViewerInput::Input {data} if data=="eA==")
            );
        });
        let (mut guest, _) = Guest::authenticate(client, &"a".repeat(64), None, 80, 24).await?;
        assert!(!guest.read_only());
        assert!(matches!(
            guest.next_event().await?,
            ViewerEvent::Output { .. }
        ));
        guest
            .send(&ViewerInput::Input {
                data: "eA==".into(),
            })
            .await?;
        let recovery = guest.take_recovery().context("missing recovery")?;
        assert!(recovery.deadline.unwrap() > Instant::now());
        assert_eq!(recovery.grace, Duration::from_secs(10));
        assert!(guest.take_recovery().is_none());
        remote.await?;
        let (client, mut server) = pair().await;
        let remote = tokio::spawn(async move {
            let hello = server.next().await.unwrap().unwrap().into_text().unwrap();
            let hello: serde_json::Value = serde_json::from_str(&hello).unwrap();
            assert_eq!(hello["resume_token"], "b".repeat(64));
            assert!(hello.get("token").is_none());
            event(&mut server, recovery_event()).await;
            event(&mut server, welcome(true)).await;
            event(&mut server, welcome(false)).await;
        });
        let (mut guest, _) =
            Guest::authenticate(client, &"a".repeat(64), Some(recovery), 80, 24).await?;
        assert!(guest.read_only());
        assert!(guest
            .send(&ViewerInput::Input {
                data: "eA==".into()
            })
            .await
            .is_err());
        let packet = porthub_terminal::protocol::DeliveryPacket::encode(
            &porthub_terminal::delivery::Message::Data(porthub_terminal::delivery::Frame::new(
                &"c".repeat(32),
                1,
                b"x",
            )?),
        )?;
        assert!(guest.send(&ViewerInput::Delivery { packet }).await.is_err());
        assert!(guest.next_event().await.is_err());
        assert!(
            guest.read_only(),
            "a duplicate welcome cannot escalate the guest role"
        );
        remote.await?;
        Ok(())
    }
    fn recovery_event() -> ViewerEvent {
        recovery()
    }
    #[tokio::test]
    async fn malformed_or_pre_welcome_output_cannot_authenticate() -> Result<()> {
        for invalid in [
            ViewerEvent::Output {
                data: "eA==".into(),
            },
            ViewerEvent::Recovery {
                session: "a".repeat(32),
                token: "b".repeat(64),
                participant: 1,
                reconnect_timeout: 301,
            },
        ] {
            let (client, mut server) = pair().await;
            let remote = tokio::spawn(async move {
                server.next().await.unwrap().unwrap();
                event(&mut server, invalid).await;
            });
            assert!(Guest::authenticate(client, &"a".repeat(64), None, 80, 24)
                .await
                .is_err());
            remote.await?;
        }
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn silent_handshake_and_lost_heartbeats_have_bounded_waits() -> Result<()> {
        let (client, _server) = pair().await;
        let start = tokio::time::Instant::now();
        assert!(Guest::authenticate(client, &"a".repeat(64), None, 80, 24)
            .await
            .is_err());
        assert_eq!(start.elapsed(), Duration::from_secs(10));
        let (client, mut server) = pair().await;
        event(&mut server, welcome(false)).await;
        let (mut guest, _) = Guest::authenticate(client, &"a".repeat(64), None, 80, 24).await?;
        let start = tokio::time::Instant::now();
        assert!(guest.next_event().await.is_err());
        assert_eq!(start.elapsed(), Duration::from_secs(45));
        let (client, _server) = pair().await;
        let expired = Recovery {
            capability: "b".repeat(64),
            grace: Duration::from_secs(10),
            deadline: Some(Instant::now() - Duration::from_secs(1)),
        };
        assert!(
            Guest::authenticate(client, &"a".repeat(64), Some(expired), 80, 24)
                .await
                .is_err()
        );
        Ok(())
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn untrusted_tls_is_rejected_before_invitation_authentication() -> Result<()> {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let tls = axum_server::tls_rustls::RustlsConfig::from_der(
            vec![identity.cert.der().to_vec()],
            identity.signing_key.serialize_der(),
        )
        .await?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let requests = Arc::new(AtomicUsize::new(0));
        let captured = requests.clone();
        let router = axum::Router::new().fallback(move || {
            let captured = captured.clone();
            async move {
                captured.fetch_add(1, Ordering::SeqCst);
                "unexpected request"
            }
        });
        let handle = axum_server::Handle::new();
        let serving = axum_server::from_tcp_rustls(listener, tls)?.handle(handle.clone());
        let task = tokio::spawn(serving.serve(router.into_make_service()));
        let invitation =
            Invitation::parse(&format!("https://{address}/terminal#{}", "a".repeat(64)))?;
        let result = NetworkGuest::connect(&invitation, None, 80, 24).await;
        handle.shutdown();
        task.await??;
        assert!(result.is_err());
        assert_eq!(
            requests.load(Ordering::SeqCst),
            0,
            "invitation never reaches untrusted HTTP endpoint"
        );
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn cancelling_event_reads_for_keyboard_or_resize_does_not_extend_heartbeat_deadline(
    ) -> Result<()> {
        let (client, mut server) = pair().await;
        event(&mut server, welcome(false)).await;
        let (mut guest, _) = Guest::authenticate(client, &"a".repeat(64), None, 80, 24).await?;
        let start = tokio::time::Instant::now();
        for _ in 0..4 {
            assert!(
                tokio::time::timeout(Duration::from_secs(10), guest.next_event())
                    .await
                    .is_err()
            );
        }
        assert!(guest.next_event().await.is_err());
        assert_eq!(start.elapsed(), Duration::from_secs(45));
        Ok(())
    }
}
