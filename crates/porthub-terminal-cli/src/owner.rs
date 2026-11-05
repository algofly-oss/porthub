//! Foreground owner attachment UI; no enrollment or machine credentials.
mod participant_control;
mod participant_panel;
mod participant_popup;
use crate::workspace::{private, read_private, select, workspace};
use anyhow::{ensure, Context, Result};
use fs2::FileExt;
use porthub_components::protocol::terminal::Job;
use porthub_terminal::multiplexer::Workspace;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
#[derive(Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Sidebar {
    Auto,
    On,
    #[default]
    Off,
}
pub fn attach(root: &Path, name: &str, sidebar: Sidebar) -> Result<()> {
    private(root)?;
    let job = select(root, name)?;
    let workspace = workspace(&job)?;
    ensure!(workspace.is_alive(), "workspace has ended");
    if std::env::var_os("PORTHUB_TERMINAL_SOCKET")
        .is_some_and(|value| std::path::PathBuf::from(value) == workspace.socket())
        || std::env::var_os("TMUX").is_some_and(|value| {
            value.to_string_lossy().split(',').next() == workspace.socket().to_str()
        })
    {
        println!("Already attached to {}", job.name);
        return Ok(());
    }
    participant_popup::attach(root, &job, &workspace, sidebar)
}
pub fn popup(root: &Path, id: &str, client: u32) -> Result<()> {
    participant_popup::show(root, id, client)
}
pub async fn view(root: &Path, id: &str, sidebar: bool) -> Result<()> {
    participant_popup::view(root, id, sidebar).await
}
async fn frame<S: tokio::io::AsyncRead + Unpin>(
    reader: &mut tokio::io::BufReader<S>,
    bytes: &mut Vec<u8>,
) -> Result<Vec<u8>> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    let remaining = 32769usize.saturating_sub(bytes.len());
    let count = reader
        .take(remaining as u64)
        .read_until(b'\n', bytes)
        .await?;
    ensure!(
        count > 0 && bytes.len() <= 32768 && bytes.last() == Some(&b'\n'),
        "invalid terminal broker frame"
    );
    Ok(std::mem::take(bytes))
}
