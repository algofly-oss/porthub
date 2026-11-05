//! Lightweight component contracts and verified distribution. This crate must
//! not depend on the agent or on any optional tool implementation.
pub mod catalog;
pub mod ipc;
pub mod local;
pub mod maintenance;
pub mod manifest;
mod process;
pub mod protocol;
pub mod rpc;
pub mod shared;
mod stdio;
pub mod store;
pub mod transport;
#[cfg(windows)]
mod windows_security;
pub mod worker;
