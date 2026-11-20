//! Portable agent packet policy and TCP termination, independent of service
//! management, CLI parsing, enrollment, and release metadata. Keep this crate
//! below the agent so small management changes reuse its compiled artifact.
pub mod exit_plan;
pub mod exit_selection;
pub mod paths;
pub mod policy;
#[cfg(feature = "private-stream")]
pub mod tcp_stream;

pub mod capture_routes;
pub mod native_repair;

/// Local wall time for comparing deadlines already translated into the
/// host's clock domain. SystemTime supports machines booted before 1970.
pub fn local_wall_time() -> chrono::DateTime<chrono::Utc> {
    std::time::SystemTime::now().into()
}
