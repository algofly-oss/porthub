//! DPLL (Digital Phase-Locked Loop) Generic Netlink family.
//!
//! DPLL surfaces clock-synchronization hardware to userspace:
//! SyncE, PTP, GNSS-disciplined oscillators. Telco / RAN, time-sync
//! infrastructure, and SmartNIC users (Intel `ice`, Mellanox `mlx5`,
//! NVIDIA BlueField) consume it daily.
//!
//! Available on Linux **kernel 6.7+** (stabilized Nov 2023). 6.8-6.12
//! added attributes strictly appended; the wire format is otherwise
//! frozen.
//!
//! # Status (Plan 156)
//!
//! This module ships in phases — see
//! [`plans/156-0.16-dpll-genl-family-plan.md`](../../../../../../plans/156-0.16-dpll-genl-family-plan.md):
//!
//! | Phase | Ships | Status |
//! |---|---|---|
//! | 1 | Family marker + module scaffold | ✓ |
//! | 2 | Command + attribute + value enums | ✓ |
//! | 3 | Device-side messages + Connection methods | ✓ |
//! | 4 | Pin-side messages + Connection methods | ✓ |
//! | 5 | Multicast monitor + `DpllEvent` stream | — |
//! | 6 | Scaling helpers + recipe + example | ✓ (example + recipe) |
//!
//! # Why DPLL is the macro dogfood
//!
//! Plan 156 is intentionally the **first in-tree user of
//! `nlink-macros`** (Plan 154). The full family — 12 commands,
//! 14 device attrs, 31 pin attrs, 10 value enums — declares in
//! ~130 lines of macro-derived Rust. The hand-written in-tree
//! families (WireGuard, MACsec, Devlink, …) average ~600 lines
//! each for comparable surface area. DPLL is the existence proof
//! that the macros work end-to-end on a real modern kernel
//! feature.
//!
//! # Construction
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, genl::dpll::Dpll};
//!
//! let conn = Connection::<Dpll>::new_async().await?;
//! // Family ID resolved against the kernel "dpll" registration;
//! // FamilyNotFound on kernels without CONFIG_DPLL.
//! # Ok(())
//! # }
//! ```
//!
//! Resolution failure is the common case on stock distro kernels
//! that haven't loaded the DPLL driver. Handle via
//! [`Error::is_not_found`](crate::Error::is_not_found):
//!
//! ```no_run
//! # async fn example() -> nlink::Result<()> {
//! # use nlink::Connection;
//! # use nlink::netlink::Dpll;
//! match Connection::<Dpll>::new_async().await {
//!     Ok(conn) => { /* use it */ }
//!     Err(e) if e.is_not_found() => {
//!         tracing::warn!("DPLL not available on this kernel; skipping");
//!     }
//!     Err(e) => return Err(e),
//! }
//! # Ok(())
//! # }
//! ```

use crate::macros::genl_family;

pub mod connection;
pub mod events;
pub mod messages;
pub mod types;

pub use events::DpllEvent;
pub use messages::{
    DpllDeviceGetRequest, DpllDeviceReply, DpllDeviceSetRequest, DpllPinGetRequest,
    DpllPinParentDevice, DpllPinParentPin, DpllPinReply, DpllPinSetRequest,
};
pub use types::{
    DpllAttr, DpllClockQualityLevel, DpllCmd, DpllFeatureState, DpllLockStatus,
    DpllLockStatusError, DpllMode, DpllPinAttr, DpllPinCapabilities, DpllPinDirection,
    DpllPinState, DpllPinType, DpllType,
};

/// Divider applied to `DPLL_A_TEMP` (mdegC → degC). Plan 156 §4.5.
pub const DPLL_TEMP_DIVIDER: i32 = 1000;

/// Divider applied to `DPLL_A_PIN_PHASE_OFFSET` (kernel reports
/// attoseconds × 1000; divide for nanoseconds). Plan 156 §4.5.
pub const DPLL_PHASE_OFFSET_DIVIDER: i64 = 1000;

/// Divider applied to `DPLL_A_PIN_MEASURED_FREQUENCY` (mHz × 1000
/// → Hz). Plan 156 §4.5.
pub const DPLL_PIN_MEASURED_FREQUENCY_DIVIDER: u64 = 1000;

/// DPLL Generic Netlink family marker.
///
/// Constructed via [`Connection::<Dpll>::new_async()`][Connection]
/// — the family ID is resolved against the kernel at connection
/// time. Returns
/// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) on
/// kernels without DPLL support (no CONFIG_DPLL, or driver not
/// loaded).
///
/// [Connection]: crate::netlink::Connection
#[genl_family(name = "dpll", version = 1)]
pub struct Dpll;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{construction::AsyncConstructible, AsyncProtocolInit, Protocol, ProtocolState};

    #[test]
    fn family_marker_carries_expected_name_and_version() {
        assert_eq!(Dpll::NAME, "dpll");
        assert_eq!(Dpll::VERSION, 1);
    }

    #[test]
    fn default_marker_has_zero_family_id_before_resolution() {
        let d = Dpll::default();
        assert_eq!(d.family_id(), 0);
    }

    #[test]
    fn protocol_state_routes_to_generic() {
        const _: () = {
            assert!(matches!(Dpll::PROTOCOL, Protocol::Generic));
        };
    }

    /// Generic bound check — proves Dpll satisfies the same
    /// AsyncConstructible + AsyncProtocolInit contract the in-tree
    /// hand-written GENL families do, so
    /// `Connection::<Dpll>::new_async()` typechecks identically.
    fn assert_async_constructible<P: AsyncConstructible>() {}
    fn assert_async_protocol_init<P: AsyncProtocolInit>() {}

    #[test]
    fn dpll_satisfies_async_construction_bounds() {
        assert_async_constructible::<Dpll>();
        assert_async_protocol_init::<Dpll>();
    }
}
