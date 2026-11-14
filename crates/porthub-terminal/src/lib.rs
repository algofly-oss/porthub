//! Shared terminal wire protocol. Shell execution belongs to the initiating OS
//! user; the gateway brokers only session-scoped, revocable terminal channels.
pub mod hub;
mod hub_queue;
pub mod names;
#[cfg(all(unix,feature="hosting"))]
pub mod multiplexer;
#[cfg(all(unix,feature="hosting"))]
pub mod runtime;
#[cfg(all(unix,feature="hosting"))]
pub mod pty;
#[cfg(all(unix,feature="hosting"))]
pub mod host;
pub mod protocol;
#[cfg(feature = "ssh")]
pub mod ssh;

#[cfg(all(unix,feature="hosting"))]
pub mod history;

#[cfg(all(unix,feature="hosting"))]
pub mod owner_view;

#[cfg(feature = "data-channel")]
pub mod direct;

pub mod delivery;
pub mod viewer;

#[cfg(feature = "viewer-history")]
pub mod viewer_history;

pub mod traffic;

pub mod traffic_report;

pub mod connectivity;
