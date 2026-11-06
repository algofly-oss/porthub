//! Shared terminal wire protocol. Shell execution belongs to the initiating OS
//! user; the gateway brokers only session-scoped, revocable terminal channels.
pub mod hub;
mod hub_queue;
pub mod names;
#[cfg(unix)]
pub mod multiplexer;
#[cfg(unix)]
pub mod runtime;
#[cfg(unix)]
pub mod pty;
#[cfg(unix)]
pub mod host;
pub mod protocol;
#[cfg(feature = "ssh")]
pub mod ssh;

#[cfg(unix)]
pub mod history;

#[cfg(unix)]
pub mod owner_view;

#[cfg(feature = "direct")]
pub mod direct;

pub mod delivery;
pub mod viewer;

#[cfg(feature = "viewer-history")]
pub mod viewer_history;

pub mod traffic;

pub mod traffic_report;

pub mod connectivity;
