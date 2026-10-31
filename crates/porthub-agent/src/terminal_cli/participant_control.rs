//! Private, OS-user-scoped owner control. No invitation or service credentials
//! cross this socket. The sharing worker remains the only gateway writer.
use super::*;
use porthub_terminal::protocol::Participant;
use std::os::unix::fs::FileTypeExt;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    List,
    RevokeInvitations,
    RotateInvitations { link_expires: u32 },
    Kick { client: u64 },
}
#[derive(Default, Serialize, Deserialize)]
pub(super) struct Snapshot {
    #[serde(default)]
    pub invitations_revoked: bool,
    #[serde(default)]
    pub invitation_revision: u64,
    #[serde(default)]
    pub rotation_pending: bool,
    pub connected: bool,
    pub members: Vec<Participant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}
pub(super) enum Action {
    Kick(u64),
    RevokeInvitations,
    RotateInvitations(u32),
}
pub(super) type Removal = (Action, oneshot::Sender<std::result::Result<(), String>>);
pub(super) struct Server {
    task: tokio::task::JoinHandle<()>,
    pub state: Arc<Mutex<Snapshot>>,
    pub requests: mpsc::Receiver<Removal>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    pub fn start(job: &Job) -> Result<Self> {
        let path = job.workspace.join("owner.sock");
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            ensure!(
                metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() },
                "invalid owner socket"
            );
            fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        let state = Arc::new(Mutex::new(Snapshot::default()));
        let snapshot = state.clone();
        let (send, requests) = mpsc::channel::<Removal>(8);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                if !stream
                    .peer_cred()
                    .is_ok_and(|cred| cred.uid() == unsafe { libc::geteuid() })
                {
                    continue;
                }
                let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    let mut stream = BufReader::new(stream);
                    let mut bytes = Vec::new();
                    // Read a single bounded frame without buffering unbounded input.
                    while bytes.len() < 256 {
                        let available = stream.fill_buf().await?;
                        ensure!(!available.is_empty(), "owner request closed");
                        let take = available
                            .iter()
                            .position(|b| *b == b'\n')
                            .map_or(available.len(), |i| i + 1)
                            .min(256 - bytes.len());
                        let ended = available.get(take - 1) == Some(&b'\n');
                        bytes.extend_from_slice(&available[..take]);
                        stream.consume(take);
                        if ended {
                            break;
                        }
                    }
                    ensure!(bytes.last() == Some(&b'\n'), "owner request too large");
                    match serde_json::from_slice::<Request>(&bytes)? {
                        Request::List => {}
                        Request::RotateInvitations { link_expires } => {
                            ensure!(
                                link_expires <= 604800,
                                "invitation lifetime exceeds seven days"
                            );
                            ensure!(
                                snapshot.lock().expect("owner state").connected,
                                "gateway reconnecting"
                            );
                            let (reply, result) = oneshot::channel();
                            send.try_send((Action::RotateInvitations(link_expires), reply))
                                .map_err(|_| anyhow::anyhow!("owner control busy"))?;
                            result.await?.map_err(anyhow::Error::msg)?;
                        }
                        Request::RevokeInvitations => {
                            let (connected, revoked) = {
                                let state = snapshot.lock().expect("owner state");
                                (state.connected, state.invitations_revoked)
                            };
                            if !revoked {
                                ensure!(connected, "gateway reconnecting");
                                let (reply, result) = oneshot::channel();
                                send.try_send((Action::RevokeInvitations, reply))
                                    .map_err(|_| anyhow::anyhow!("owner control busy"))?;
                                result.await?.map_err(anyhow::Error::msg)?;
                            }
                        }
                        Request::Kick { client } => {
                            let allowed = {
                                let state = snapshot.lock().expect("owner state");
                                state.connected && state.members.iter().any(|p| p.id == client)
                            };
                            ensure!(
                                allowed,
                                "participant unavailable; refresh the participant list"
                            );
                            let (reply, result) = oneshot::channel();
                            send.try_send((Action::Kick(client), reply))
                                .map_err(|_| anyhow::anyhow!("owner control busy"))?;
                            result.await?.map_err(anyhow::Error::msg)?;
                        }
                    }
                    let mut response =
                        { serde_json::to_vec(&*snapshot.lock().expect("owner state"))? };
                    response.push(b'\n');
                    stream.get_mut().write_all(&response).await?;
                    Ok::<_, anyhow::Error>(())
                })
                .await;
            }
        });
        Ok(Self {
            task,
            state,
            requests,
        })
    }
}
pub(super) async fn fetch(job: &Job, client: Option<u64>) -> Result<Snapshot> {
    fetch_request(
        job,
        client.map_or(Request::List, |client| Request::Kick { client }),
    )
    .await
}
async fn fetch_request(job: &Job, request: Request) -> Result<Snapshot> {
    let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut stream = UnixStream::connect(job.workspace.join("owner.sock"))
            .await
            .context("sharing supervisor unavailable")?;
        let mut bytes = serde_json::to_vec(&request)?;
        bytes.push(b'\n');
        stream.write_all(&bytes).await?;
        let mut stream = BufReader::new(stream);
        let mut buffer = Vec::new();
        crate::terminal_transport::frame(&mut stream, &mut buffer).await
    })
    .await
    .context("owner control timed out")??;
    let snapshot: Snapshot = serde_json::from_slice(&result)
        .context("owner request rejected or sharing supervisor disconnected")?;
    ensure!(
        snapshot.members.len() <= 32
            && snapshot
                .members
                .iter()
                .all(|member| member.id > 0 && member.id < (1u64 << 53)),
        "invalid participant snapshot"
    );
    Ok(snapshot)
}
pub(super) async fn request(job: &Job, client: Option<u64>, json: bool) -> Result<()> {
    let snapshot = fetch(job, client).await?;
    if json {
        println!("{}", serde_json::to_string(&snapshot)?);
    } else if client.is_some() {
        println!("Participant removal requested.");
    } else {
        println!(
            "{} · {} participant(s)",
            if snapshot.connected {
                "Connected"
            } else {
                "Reconnecting"
            },
            snapshot.members.len()
        );
        for member in snapshot.members {
            println!(
                "{}\t{}\tjoined {}\tactive {}",
                member.id,
                if member.read_only {
                    "read-only"
                } else {
                    "interactive"
                },
                member.joined_at,
                member.last_active_at
            );
        }
    }
    Ok(())
}

pub(super) async fn revoke_invitations(job: &Job, json: bool) -> Result<()> {
    let first = fetch_request(job, Request::RevokeInvitations).await?;
    let mut confirmed = first.invitations_revoked;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while !confirmed && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if let Ok(snapshot) = fetch(job, None).await {
            confirmed = snapshot.invitations_revoked;
        }
    }
    ensure!(
        confirmed,
        "invitation revocation was not confirmed; check gateway connectivity before retrying"
    );
    if json {
        println!(
            "{}",
            serde_json::json!({"id":job.id,"invitations_revoked":true})
        );
    } else {
        println!("New invitation joins blocked. Attached guests and their recovery access remain available.");
    }
    Ok(())
}

/// Confirm durable gateway acknowledgement, never just a successful socket write.
pub(super) async fn rotate_invitations(job: &Job, link_expires: u32) -> Result<()> {
    let before = fetch(job, None).await?;
    let target = before
        .invitation_revision
        .checked_add(1)
        .context("invitation revision exhausted")?;
    let first = fetch_request(job, Request::RotateInvitations { link_expires }).await?;
    let mut confirmed = first.invitation_revision >= target && !first.rotation_pending;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while !confirmed && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if let Ok(snapshot) = fetch(job, None).await {
            confirmed = snapshot.invitation_revision >= target && !snapshot.rotation_pending;
        }
    }
    ensure!(confirmed, "invitation rotation is saved but not confirmed; retry --rotate after connectivity returns (the pending links will be reused)");
    Ok(())
}
