//! Windows core updates use a short-lived, verified native maintenance process.
//! No Unix upgrade code, persistent task, new service or account grant is used.
#[cfg(windows)]
mod native;
mod preparation;
mod recovery_wait;
mod transaction;
mod verified_file;
#[cfg(windows)]
pub(crate) use native::{service_start_recovery, Controller};
#[cfg(windows)]
pub async fn maintenance(record: &std::path::Path) -> anyhow::Result<()> {
    native::maintenance(record).await
}

pub const PROTOCOL: &str = "windows-scm-v1";
