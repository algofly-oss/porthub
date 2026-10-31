//! Shared terminal wire protocol. Shell execution belongs to the initiating OS
//! user; the gateway brokers only session-scoped, revocable terminal channels.
pub mod hub;
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
