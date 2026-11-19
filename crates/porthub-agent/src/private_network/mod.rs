#[cfg(any(windows, target_os = "macos", test))]
mod route_debounce;
pub mod controller;
#[cfg(target_os = "linux")]
pub mod device;
#[cfg(target_os = "linux")]
mod linux_tcp;
#[cfg(target_os = "macos")]
#[path = "device_macos.rs"]
pub mod device;
#[cfg(windows)]
#[path = "device_windows.rs"]
pub mod device;
pub mod dns;
#[cfg(target_os="macos")]
mod dns_default_macos;
#[cfg(target_os="macos")]
mod dns_private_macos;
#[cfg(any(target_os="macos",test))]
mod dns_convergence_macos;
mod dns_upstream;
pub use porthub_network::exit_selection;
pub(crate) mod exit_picker;
pub(crate) mod exit_plumbing;
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
pub mod tor_preferences;
#[cfg(feature = "private-stream")]
pub mod stream_router;
#[cfg(feature = "private-stream")]
pub use porthub_network::tcp_stream;
#[cfg(feature = "local-tor")]
mod tor_exit;

#[cfg(target_os="linux")]
pub(crate) fn owned_exit_underlay(index: u32, source: std::net::IpAddr) -> bool {
    exit_journal::Journal::allows_underlay(index,source)
}

pub(crate) mod traffic;
pub mod sparse;

pub(crate) mod address_lifecycle;

pub(crate) mod topology;

#[cfg(any(windows,test))]
mod native_ownership;

#[cfg(windows)]
mod windows_state;

#[cfg(windows)]
mod windows_nrpt;

#[cfg(windows)]
mod dns_windows;

#[cfg(feature = "private-sparse")]
mod authority_clock;

mod authority_event;
#[cfg(any(target_os="macos",test))]
mod owned_packet_loop;

#[cfg(all(feature="private-sparse",feature="private-stream"))]
mod stream_chunks;

#[cfg(all(feature="private-sparse",feature="private-stream"))]
pub mod sparse_dispatch;

#[cfg(all(test,feature="private-sparse",target_os="linux"))]
mod native_lifecycle_fixture;

#[cfg(all(test,feature="private-sparse",any(windows,target_os="macos")))]
mod native_desktop_lifecycle_fixture;

#[cfg(all(test,feature="private-sparse",target_os="linux"))]
mod native_resolver_lifecycle_fixture;

mod native_owner;
