//! Short-lived permission from an OS-authenticated core broker. Never authorizes itself.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWriteExt, BufReader};
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    allowed: bool,
    expires_at: u64,
}
impl Snapshot {
    #[cfg(any(test, all(unix, feature = "terminal-direct")))]
    fn valid(&self, now: u64) -> bool {
        self.allowed && self.expires_at > now && self.expires_at.saturating_sub(now) <= 4
    }
}
#[cfg(all(unix, feature = "terminal-direct"))]
pub(crate) struct Permission {
    pub receiver: tokio::sync::watch::Receiver<Snapshot>,
    _task: tokio_util::task::AbortOnDropHandle<()>,
}
#[cfg(all(unix, feature = "terminal-direct"))]
impl Permission {
    pub fn guard(&self) -> std::sync::Arc<dyn Fn() -> bool + Send + Sync> {
        let receiver = self.receiver.clone();
        std::sync::Arc::new(move || {
            receiver.has_changed().is_ok() && now().is_ok_and(|now| receiver.borrow().valid(now))
        })
    }
    pub fn allowed(&self) -> bool {
        self.receiver.has_changed().is_ok()
            && now().is_ok_and(|now| self.receiver.borrow().valid(now))
    }
}
#[cfg(all(unix, feature = "terminal-direct"))]
pub(crate) async fn subscribe(
    broker: &porthub_components::protocol::terminal::Broker,
) -> Result<Permission> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(3),
        crate::sharing::connect_broker(broker),
    )
    .await??;
    tokio::time::timeout(
        Duration::from_secs(3),
        stream.write_all(b"{\"operation\":\"terminal_guest_policy\"}\n"),
    )
    .await??;
    monitor(BufReader::new(stream)).await
}
#[cfg(all(unix, feature = "terminal-direct"))]
async fn monitor<S: AsyncRead + Unpin + Send + 'static>(
    mut reader: BufReader<S>,
) -> Result<Permission> {
    let bytes = tokio::time::timeout(Duration::from_secs(3), line(&mut reader)).await??;
    let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        snapshot.valid(now()?),
        "native terminal direct permission unavailable"
    );
    let (send, receiver) = tokio::sync::watch::channel(snapshot);
    let task = tokio::spawn(async move {
        let mut snapshot = snapshot;
        loop {
            let valid = async {
                let expiry = UNIX_EPOCH
                    .checked_add(Duration::from_secs(snapshot.expires_at))
                    .ok_or_else(|| anyhow::anyhow!("invalid terminal policy expiry"))?;
                let remaining = expiry.duration_since(SystemTime::now())?;
                anyhow::ensure!(!remaining.is_zero(), "terminal policy expired");
                let bytes = tokio::time::timeout(remaining, line(&mut reader)).await??;
                snapshot = serde_json::from_slice(&bytes)?;
                anyhow::ensure!(snapshot.valid(now()?), "terminal policy revoked");
                send.send(snapshot)
                    .map_err(|_| anyhow::anyhow!("terminal policy subscriber closed"))?;
                Ok::<_, anyhow::Error>(())
            }
            .await;
            if valid.is_err() {
                let _ = send.send(Snapshot {
                    allowed: false,
                    expires_at: 0,
                });
                return;
            }
        }
    });
    Ok(Permission {
        receiver,
        _task: tokio_util::task::AbortOnDropHandle::new(task),
    })
}

#[cfg(all(test, unix, feature = "terminal-direct"))]
pub(crate) async fn test_permission() -> Result<(Permission, tokio::io::DuplexStream)> {
    let (mut writer, reader) = tokio::io::duplex(16384);
    writer
        .write_all(
            format!(
                "{}\n",
                serde_json::to_string(&Snapshot {
                    allowed: true,
                    expires_at: now()? + 4
                })?
            )
            .as_bytes(),
        )
        .await?;
    Ok((monitor(BufReader::new(reader)).await?, writer))
}

async fn line<S: AsyncRead + Unpin>(reader: &mut BufReader<S>) -> Result<Vec<u8>> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    let mut bytes = vec![];
    let count = reader.take(8193).read_until(b'\n', &mut bytes).await?;
    anyhow::ensure!(
        count > 0 && count <= 8192 && bytes.last() == Some(&b'\n'),
        "invalid local terminal policy message"
    );
    Ok(bytes)
}

#[cfg(all(test, unix, feature = "terminal-direct"))]
#[tokio::test]
async fn policy_subscription_revokes_on_denial_disconnect_and_invalid_messages() -> Result<()> {
    for next in [
        None,
        Some(serde_json::json!({"allowed":false,"expires_at":now()?+4})),
        Some(serde_json::json!({"allowed":true,"expires_at":now()?+100})),
    ] {
        let (mut writer, reader) = tokio::io::duplex(16384);
        writer
            .write_all(
                format!(
                    "{}\n",
                    serde_json::to_string(&Snapshot {
                        allowed: true,
                        expires_at: now()? + 4
                    })?
                )
                .as_bytes(),
            )
            .await?;
        let mut permission = monitor(BufReader::new(reader)).await?;
        assert!(permission.allowed());
        if let Some(next) = next {
            writer.write_all(format!("{next}\n").as_bytes()).await?;
        }
        drop(writer);
        tokio::time::timeout(Duration::from_secs(1), permission.receiver.changed()).await??;
        assert!(!permission.allowed());
    }
    Ok(())
}
#[cfg(all(test, unix, feature = "terminal-direct"))]
#[tokio::test(start_paused = true)]
async fn silent_broker_cannot_leave_direct_permission_enabled() -> Result<()> {
    let (mut writer, reader) = tokio::io::duplex(16384);
    writer
        .write_all(
            format!(
                "{}\n",
                serde_json::to_string(&Snapshot {
                    allowed: true,
                    expires_at: now()? + 4
                })?
            )
            .as_bytes(),
        )
        .await?;
    let mut permission = monitor(BufReader::new(reader)).await?;
    assert!(permission.allowed());
    permission.receiver.changed().await?;
    assert!(!permission.allowed());
    drop(writer);
    Ok(())
}
