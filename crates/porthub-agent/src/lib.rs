#[cfg(target_os = "linux")]
pub mod adopt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod autoupdate;
pub mod bootstrap;
pub mod control;
pub mod expose;
pub mod legacy;
pub mod logs;
pub mod private_network;
pub mod private_profile;
pub mod profile;
mod routes;
pub mod runtime;
pub mod service;
pub mod update;
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
