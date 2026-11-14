//! Lightweight component contracts and verified distribution. This crate must
//! not depend on the agent or on any optional tool implementation.
pub mod catalog;
pub mod ipc;
pub mod local;
pub mod maintenance;
pub mod manifest;
pub mod multiplex;
mod process;
pub mod protocol;
pub mod rpc;
pub mod shared;
mod stdio;
pub mod store;
pub mod transport;
#[cfg(windows)]
mod windows_security;
pub mod worker;

/// Launch an explicitly selected verified foreground frontend without a shell.
/// Terminal handles are inherited; machine credentials must not be arguments.
pub async fn foreground(executable: &std::path::Path, arguments: &[std::ffi::OsString],
    cancel: &tokio_util::sync::CancellationToken) -> anyhow::Result<tokio::process::Child>
{
    process::retry_spawn(cancel, || tokio::process::Command::new(executable).args(arguments)
        .env("PORTHUB_COMPONENT_OWNER_PID",std::process::id().to_string())
        .stdin(std::process::Stdio::inherit()).stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit()).kill_on_drop(true).spawn()
        .map_err(anyhow::Error::from)).await
}

pub mod keyboard;

pub mod metrics;
