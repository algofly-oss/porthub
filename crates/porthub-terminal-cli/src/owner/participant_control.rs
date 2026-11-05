//! Credential-free client for the existing private owner-control socket.
use super::*;
use porthub_terminal::protocol::Participant;
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::UnixStream,
};
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
        frame(&mut stream, &mut buffer).await
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
