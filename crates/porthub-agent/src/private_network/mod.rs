pub mod controller;
#[cfg(target_os = "linux")]
pub mod device;
#[cfg(target_os = "macos")]
#[path = "device_macos.rs"]
pub mod device;
#[cfg(windows)]
#[path = "device_windows.rs"]
pub mod device;
pub mod dns;
#[cfg(target_os = "linux")]
mod interfaces;
#[cfg(target_os = "macos")]
#[path = "interfaces_macos.rs"]
mod interfaces;
#[cfg(windows)]
#[path = "interfaces_windows.rs"]
mod interfaces;
pub mod policy;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub mod runtime;

pub fn is_profile(path: &std::path::Path) -> anyhow::Result<bool> {
    let bytes = crate::profile::read_private(path)?;
    anyhow::ensure!(bytes.len() <= 65536, "profile exceeds size limit");
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid agent profile"))?;
    Ok(value.get("peer_id").is_some())
}
pub mod paths;
pub mod relay;
pub mod strategy;
