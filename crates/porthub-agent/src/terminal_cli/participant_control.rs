//! Private, OS-user-scoped owner control. No invitation or service credentials
//! cross this socket. The sharing worker remains the only gateway writer.
use super::*;
use porthub_terminal::protocol::Participant;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

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
