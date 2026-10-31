//! Read-only tmux capture. Never forwards guest keystrokes or executes a shell.
//! Each request is a live, bounded slice; it does not alter anyone's copy mode.
use crate::{multiplexer::Workspace, protocol::*};
use anyhow::{ensure, Result};
use std::process::Stdio;
use tokio::io::AsyncReadExt;

const MAX_CAPTURE: usize = 128 * 1024;
async fn capture(
    workspace: &Workspace,
    arguments: &[String],
    limit: usize,
) -> Result<(Vec<u8>, bool)> {
    let mut command = tokio::process::Command::from(workspace.command());
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let mut data = Vec::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .take(limit as u64 + 1)
        .read_to_end(&mut data)
        .await?;
    let truncated = data.len() > limit;
    if truncated {
        data.truncate(limit);
        let _ = child.kill().await;
    }
    let status = child.wait().await?;
    ensure!(truncated || status.success(), "terminal pane unavailable");
    Ok((data, truncated))
}
pub async fn page(
    workspace: &Workspace,
    pane: &str,
    before: u32,
    lines: u16,
) -> Result<(Vec<u8>, u32, u16, bool)> {
    history_request(pane, before, lines)?;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let target = if pane.is_empty() { "=workspace:" } else { pane };
        let (metadata, truncated) = capture(
            workspace,
            &[
                "display-message".into(),
                "-p".into(),
                "-t".into(),
                target.into(),
                "#{session_name}|#{pane_id}|#{history_size}".into(),
            ],
            64,
        )
        .await?;
        ensure!(!truncated, "invalid terminal history metadata");
        let metadata = std::str::from_utf8(&metadata)?.trim();
        let mut fields = metadata.split('|');
        ensure!(
            fields.next() == Some("workspace"),
            "terminal pane is outside the shared workspace"
        );
        let resolved_pane = fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("terminal pane identity missing"))?;
        ensure!(
            resolved_pane.starts_with('%'),
            "terminal pane identity missing"
        );
        history_request(resolved_pane, before, lines)?;
        let total = fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("terminal history size missing"))?
            .parse::<u32>()?;
        ensure!(fields.next().is_none(), "invalid terminal history metadata");
        ensure!(
            total <= 200_000,
            "terminal history exceeds configured bound"
        );
        let available = total.saturating_sub(before);
        let count = available.min(u32::from(lines)) as u16;
        if count == 0 {
            return Ok((Vec::new(), total, 0, false));
        }
        let start = -(i64::from(before) + i64::from(count));
        let end = -(i64::from(before) + 1);
        let (bytes, truncated) = capture(
            workspace,
            &[
                "capture-pane".into(),
                "-p".into(),
                "-t".into(),
                resolved_pane.into(),
                "-S".into(),
                start.to_string(),
                "-E".into(),
                end.to_string(),
            ],
            MAX_CAPTURE,
        )
        .await?;
        Ok((bytes, total, count, truncated))
    })
    .await?
}
