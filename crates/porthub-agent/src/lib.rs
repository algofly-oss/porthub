#[cfg(target_os = "linux")]
pub mod adopt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod autoupdate;
pub mod bootstrap;
pub mod components;
pub mod sync_cli;
pub mod control;
pub mod outbound;
pub mod connectivity_diagnostics;
pub mod expose;
pub mod legacy;
pub mod logs;
mod os_info;
pub mod private_network;
pub mod private_profile;
#[cfg(target_os="linux")]
mod private_prerequisites;
#[cfg(target_os="linux")]
mod private_dns_setup;
#[cfg(target_os="linux")]
mod private_resolver_file;
pub mod profile;
mod routes;
pub mod runtime;
pub mod service;
pub mod service_health;
pub mod stats;
pub mod update;
mod unified;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod upgrade;
pub const VERSION: &str = match option_env!("PORTHUB_VERSION") {
    Some(value) => value,
    None => env!("CARGO_PKG_VERSION"),
};
pub const BUILD_REVISION: &str = match option_env!("PORTHUB_SOURCE_REVISION") {
    Some(value) => value,
    None => "unknown",
};

#[cfg(unix)]
pub mod exposure_broker;

pub mod http_tools;

mod exposure_protocol;
mod terminal_transport;
mod terminal_policy;
mod terminal_connectivity;
mod terminal_telemetry;
mod terminal_upload;
#[cfg(all(unix,feature = "terminal-direct"))]
pub mod terminal_guest;
#[cfg(unix)]
pub mod terminal_cli;
#[cfg(feature="local-tor")]
mod proxy_transport;
#[cfg(windows)]
#[path = "exposure_broker_windows.rs"]
pub mod exposure_broker;

#[cfg(windows)]
mod detached_windows;

#[cfg(feature="local-tor")]
pub mod proxy_cli;

mod terminal_ui;

#[cfg(feature = "local-tor")]
pub mod tor_component;

pub mod images;

pub mod image_shortcut;
pub mod image_delivery;
pub mod forward;
pub mod mapping_jobs;

pub mod keyboard;
pub mod features;

mod metrics;
