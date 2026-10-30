//! Portable agent packet policy and TCP termination, independent of service
//! management, CLI parsing, enrollment, and release metadata. Keep this crate
//! below the agent so small management changes reuse its compiled artifact.
pub mod exit_plan;
pub mod exit_selection;
pub mod paths;
pub mod policy;
#[cfg(feature = "private-stream")]
pub mod tcp_stream;
