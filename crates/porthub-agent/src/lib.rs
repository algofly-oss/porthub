#[cfg(target_os = "linux")]
pub mod adopt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod autoupdate;
pub mod bootstrap;
pub mod control;
pub mod expose;
pub mod legacy;
pub mod logs;
mod os_info;
pub mod private_network;
pub mod private_profile;
pub mod profile;
mod routes;
pub mod runtime;
pub mod service;
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
#[cfg(feature="local-tor")]
mod proxy_transport;
#[cfg(windows)]
#[path = "exposure_broker_windows.rs"]
pub mod exposure_broker;

#[cfg(windows)]
mod detached_windows;

#[cfg(feature="local-tor")]
pub mod proxy_cli;
