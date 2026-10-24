//! High-level facade APIs — one-line entry points for the
//! 90% case (Plan 200).
//!
//! The library's typed surface (e.g. `Connection::<Route>::new()`
//! followed by `NetworkConfig::apply(&conn)`) is precise and
//! namespace-aware, but every entry point requires several
//! lines of boilerplate. This facade adds three thin
//! compositional wrappers that scale to the typed surface as
//! needs grow:
//!
//! * [`apply`] — `nlink::facade::apply::network(cfg).await?`
//!   replaces "open connection + call apply".
//! * [`diff`] — symmetric drift-detection counterparts.
//! * [`watch`] — `nlink::facade::watch::route_changes()` returns
//!   a resync-wrapped stream with ENOBUFS recovery built in.
//! * [`Stack`] — unified bundle for managing network, firewall and
//!   VPN as one type: planned once ([`StackPlan`]) and applied in a
//!   deterministic order.
//!
//! All four are pure compositional wrappers; they don't change
//! any existing API. The typed surface remains the precise
//! escape hatch.

pub mod apply;
pub mod diff;
pub mod stack;
pub mod watch;

pub use stack::{Stack, StackPlan, StackReport};
#[allow(deprecated)]
pub use stack::{StackApplyReport, StackDiff};
