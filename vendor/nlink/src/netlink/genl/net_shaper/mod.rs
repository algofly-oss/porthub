//! `net_shaper` Generic Netlink family — TX hardware shaping.
//!
//! The `net_shaper` family (kernel 6.13+) is a generic interface
//! to per-NIC, per-queue, and intermediate-node TX hardware
//! shapers — drivers like Intel `ice`, Mellanox `mlx5`, and
//! Broadcom `bnxt` expose their hierarchical scheduler trees
//! through it. Operators get a uniform way to set guaranteed /
//! peak bandwidth, burst size, scheduling priority, and RR
//! weights without leaving netlink for ethtool, devlink, or
//! driver-private ioctls.
//!
//! Second in-tree user of [`nlink-macros`] (after
//! [`super::dpll`]). The full family — 5 commands, 10 outer
//! attrs, 10 cap-set attrs, 2 nested handle attrs, 2 enums —
//! declares in ~200 lines of macro-derived Rust.
//!
//! [`nlink-macros`]: crate::macros
//!
//! # Construction
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, genl::net_shaper::NetShaper};
//!
//! let conn = Connection::<NetShaper>::new_async().await?;
//! // Family ID resolved against the kernel's "net-shaper"
//! // registration; `Error::is_not_found()` when the family
//! // isn't loaded (kernel < 6.13 or `CONFIG_NET_SHAPER=n`).
//! # Ok(())
//! # }
//! ```
//!
//! # Capability handshake
//!
//! Drivers expose different feature subsets — always query caps
//! before issuing a `set_shaper` to avoid the round-trip on
//! unsupported attributes:
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let eth0_ifindex: u32 = 2;
//! # let conn = nlink::Connection::<nlink::netlink::genl::net_shaper::NetShaper>::new_async().await?;
//! use nlink::netlink::genl::net_shaper::{
//!     NetShaper, NetShaperHandle, NetShaperScope, NetShaperSetRequest,
//! };
//!
//! let caps = conn.get_caps(eth0_ifindex, NetShaperScope::Queue).await?;
//! if caps.support_bw_max {
//!     let handle = NetShaperHandle::queue(0);
//!     conn.set_shaper(NetShaperSetRequest::new(eth0_ifindex, handle).bw_max(1_000_000_000))
//!         .await?;
//! } else {
//!     tracing::warn!("driver doesn't support bw_max on QUEUE scope");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Permissions
//!
//! `set`, `delete`, and `group` require `CAP_NET_ADMIN`.
//! `get` and `cap-get` are unprivileged.
//!
//! # Status
//!
//! Plan 153 §4.3. Shipped:
//!
//! | Command | Status |
//! |---|---|
//! | `NET_SHAPER_CMD_GET` (get + dump) | ✓ |
//! | `NET_SHAPER_CMD_SET` | ✓ |
//! | `NET_SHAPER_CMD_DELETE` | ✓ |
//! | `NET_SHAPER_CMD_CAP_GET` (get + dump) | ✓ |
//! | `NET_SHAPER_CMD_GROUP` | — (needs `Vec<NetlinkAttrs>` macro support; deferred) |

use crate::macros::genl_family;

pub mod connection;
pub mod messages;
pub mod types;

pub use messages::{
    NetShaperCapsGetRequest, NetShaperCapsReply, NetShaperDeleteRequest, NetShaperGetRequest,
    NetShaperGroupRequest, NetShaperHandle, NetShaperLeaf, NetShaperReply, NetShaperSetRequest,
};
pub use types::{
    NetShaperAttr, NetShaperCapsAttr, NetShaperCmd, NetShaperHandleAttr, NetShaperMetric,
    NetShaperScope, NET_SHAPER_MAX_HANDLE_ID,
};

/// `net_shaper` Generic Netlink family marker.
///
/// Constructed via [`Connection::<NetShaper>::new_async()`][Connection]
/// — the family ID is resolved against the kernel at connection
/// time. Returns
/// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) on
/// kernels without `CONFIG_NET_SHAPER` (the family is built-in
/// when the option is set; there's no separate module to load).
///
/// [Connection]: crate::netlink::Connection
#[genl_family(name = "net-shaper", version = 1)]
pub struct NetShaper;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{
        construction::AsyncConstructible, AsyncProtocolInit, Protocol, ProtocolState,
    };

    #[test]
    fn family_marker_carries_expected_name_and_version() {
        assert_eq!(NetShaper::NAME, "net-shaper");
        assert_eq!(NetShaper::VERSION, 1);
    }

    #[test]
    fn default_marker_has_zero_family_id_before_resolution() {
        let m = NetShaper::default();
        assert_eq!(m.family_id(), 0);
    }

    #[test]
    fn protocol_state_routes_to_generic() {
        const _: () = {
            assert!(matches!(NetShaper::PROTOCOL, Protocol::Generic));
        };
    }

    fn assert_async_constructible<P: AsyncConstructible>() {}
    fn assert_async_protocol_init<P: AsyncProtocolInit>() {}

    #[test]
    fn net_shaper_satisfies_async_construction_bounds() {
        assert_async_constructible::<NetShaper>();
        assert_async_protocol_init::<NetShaper>();
    }
}
