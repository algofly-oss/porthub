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
    Kick { client: u64 },
}
#[derive(Default, Serialize, Deserialize)]
pub(super) struct Snapshot {
    pub connected: bool,
    pub members: Vec<Participant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}
pub(super) type Removal = (u64, oneshot::Sender<std::result::Result<(), String>>);
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
                            send.try_send((client, reply))
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
    let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut stream = UnixStream::connect(job.workspace.join("owner.sock"))
            .await
            .context("sharing supervisor unavailable")?;
        let request = client.map_or(Request::List, |client| Request::Kick { client });
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
