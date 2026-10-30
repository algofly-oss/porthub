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
#[cfg(target_os="macos")]
mod dns_default_macos;
mod dns_upstream;
pub use porthub_network::exit_selection;
pub use porthub_network::exit_plan;
#[cfg(target_os = "linux")]
pub mod exit_kernel;
#[cfg(target_os = "linux")]
mod exit_forwarding;
#[cfg(target_os = "linux")]
pub mod exit_routes;
#[cfg(target_os = "linux")]
mod exit_containers;
#[cfg(target_os = "linux")]
mod nft;
#[cfg(target_os = "macos")]
#[path = "exit_routes_macos.rs"]
pub mod exit_routes;
#[cfg(target_os = "linux")]
mod exit_journal;
#[cfg(target_os = "linux")]
mod exit_ipv6;
#[cfg(target_os = "linux")]
pub(crate) mod interfaces;
#[cfg(target_os = "macos")]
#[path = "interfaces_macos.rs"]
pub(crate) mod interfaces;
#[cfg(windows)]
#[path = "interfaces_windows.rs"]
pub(crate) mod interfaces;
pub use porthub_network::policy;
mod lan_discovery;
#[cfg(feature="local-tor")]
mod proxy_egress;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub mod runtime;

pub fn is_profile(path: &std::path::Path) -> anyhow::Result<bool> {
    let bytes = crate::profile::read_private(path)?;
    anyhow::ensure!(bytes.len() <= 65536, "profile exceeds size limit");
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid agent profile"))?;
    Ok(value.get("peer_id").is_some())
}
pub use porthub_network::paths;
mod probe;
pub mod relay;
pub mod strategy;
pub(crate) mod settings_watch;
#[cfg(feature="local-tor")]
pub mod tor_preferences;
#[cfg(feature = "private-stream")]
pub mod stream_router;
#[cfg(feature = "private-stream")]
pub use porthub_network::tcp_stream;
#[cfg(feature = "local-tor")]
mod tor_exit;
