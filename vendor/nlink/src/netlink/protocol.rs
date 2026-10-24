//! Protocol state types for strongly-typed connections.
//!
//! This module provides the type-level protocol distinction that enables
//! compile-time safety for protocol-specific operations on [`Connection`].
//!
//! # Design
//!
//! Each netlink protocol (Route, Generic, etc.) has an associated state type
//! that may carry protocol-specific data:
//!
//! - [`Route`]: Zero-sized, no additional state needed
//! - [`Generic`]: Contains a family ID cache for efficient lookups
//!
//! The [`ProtocolState`] trait is sealed to prevent external implementations.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route, Generic};
//!
//! // Route connection for interface/address/route/TC operations
//! let route = Connection::<Route>::new()?;
//! route.get_links().await?;
//!
//! // Generic connection for WireGuard/MACsec configuration
//! let genl = Connection::<Generic>::new()?;
//! genl.get_family("wireguard").await?;
//! # Ok(())
//! # }
//! ```

use std::{collections::HashMap, sync::RwLock};

use super::{
    error::Result,
    genl::FamilyInfo,
    socket::{NetlinkSocket, Protocol},
};

/// Sealed trait module to prevent external implementations.
mod private {
    pub trait Sealed {}
}

/// Macro-only re-export of the private `Sealed` trait so the
/// `#[genl_family]` attribute macro (`nlink_macros`) can emit
/// the required `impl Sealed` for user-defined family marker
/// structs.
///
/// **Do not implement directly.** The contract is "go through
/// `#[genl_family]`"; opting out at this seam silently breaks the
/// sealed-trait guarantee that downstream consumers rely on for
/// `Connection::<P>::new_async()`'s `AsyncConstructible` bound.
#[doc(hidden)]
pub mod __macro_seal {
    pub use super::construction::AsyncConstructible as AsyncConstructibleSeal;
    pub use super::private::Sealed as ProtocolStateSeal;
}

/// Protocol state trait for typed connections.
///
/// This trait is sealed and cannot be implemented outside this crate.
/// Each implementation provides:
/// - The underlying netlink protocol constant
/// - Protocol-specific state (if any)
///
/// Types that implement `Default` can use the generic `Connection::new()`.
/// Types that require special initialization should provide their own constructor.
pub trait ProtocolState: private::Sealed {
    /// The netlink protocol for this state type.
    const PROTOCOL: Protocol;
}

/// Async initialization trait for protocols requiring async setup.
///
/// GENL protocols (WireGuard, MACsec, MPTCP, Ethtool, nl80211, Devlink) need
/// to resolve their family ID asynchronously after the socket is created.
/// This trait enables `Connection::new_in_async()` to create connections
/// in foreign namespaces for these protocols.
///
/// This trait is sealed and cannot be implemented outside this crate.
pub trait AsyncProtocolInit: ProtocolState {
    /// Resolve protocol-specific state from an already-connected socket.
    ///
    /// The socket has already been created in the target namespace.
    /// This method performs the async GENL family resolution through that socket.
    fn resolve_async(
        socket: &NetlinkSocket,
    ) -> impl std::future::Future<Output = Result<Self>> + Send
    where
        Self: Sized;
}

/// Marker traits used to gate `Connection::<P>::new()` /
/// `Connection::<P>::new_async()` so the constructor that **actually
/// works** for each protocol is the only one that compiles.
///
/// Before this gate landed, `Connection::<Wireguard>::new()` compiled
/// but produced a connection with `family_id = 0`; the first operation
/// failed with a confusing kernel error. Now it's a compile error
/// pointing the user at `new_async()`.
///
/// Both traits are sealed via the same `private::Sealed` supertrait
/// that `ProtocolState` uses, so downstream code cannot opt a custom
/// type in.
pub mod construction {
    use super::*;

    /// Protocols whose connection can be constructed synchronously
    /// (no GENL family-ID resolution needed). `Connection::<P>::new()`
    /// is bounded `where P: SyncConstructible`.
    pub trait SyncConstructible: ProtocolState {}

    /// Protocols that require async GENL family-ID resolution at
    /// construction time. `Connection::<P>::new_async()` is bounded
    /// `where P: AsyncConstructible`.
    pub trait AsyncConstructible: ProtocolState {}
}

// Non-GENL protocols — synchronously constructible. Each must also
// match the existing per-type sealed `Sealed` constraint (i.e. live
// in this crate).
impl construction::SyncConstructible for Route {}
impl construction::SyncConstructible for SockDiag {}
impl construction::SyncConstructible for Generic {}
impl construction::SyncConstructible for KobjectUevent {}
impl construction::SyncConstructible for Connector {}
impl construction::SyncConstructible for Netfilter {}
impl construction::SyncConstructible for Xfrm {}
impl construction::SyncConstructible for FibLookup {}
impl construction::SyncConstructible for SELinux {}
impl construction::SyncConstructible for Audit {}
impl construction::SyncConstructible for Nftables {}
impl construction::SyncConstructible for Nflog {}

// GENL protocols — must be constructed via `new_async()` so the
// family ID is resolved before first use.
impl construction::AsyncConstructible for Wireguard {}
impl construction::AsyncConstructible for Hwsim {}
impl construction::AsyncConstructible for Macsec {}
impl construction::AsyncConstructible for Mptcp {}
impl construction::AsyncConstructible for Devlink {}
impl construction::AsyncConstructible for Nl80211 {}
impl construction::AsyncConstructible for Ethtool {}

/// Route protocol state (RTNetlink).
///
/// Used for interface, address, route, neighbor, and traffic control operations.
/// This is a zero-sized type with no additional state.
#[derive(Debug, Default, Clone, Copy)]
pub struct Route;

impl private::Sealed for Route {}

impl ProtocolState for Route {
    const PROTOCOL: Protocol = Protocol::Route;
}

/// Socket diagnostics protocol state.
///
/// Used for querying socket information (TCP, UDP, Unix, etc.).
/// This is a zero-sized type with no additional state.
#[derive(Debug, Default, Clone, Copy)]
pub struct SockDiag;

impl private::Sealed for SockDiag {}

impl ProtocolState for SockDiag {
    const PROTOCOL: Protocol = Protocol::SockDiag;
}

/// Generic netlink protocol state.
///
/// Used for family-based protocols like WireGuard and MACsec.
/// Contains a cache of resolved family IDs for efficient lookups.
pub struct Generic {
    /// Cache of family name -> family info mappings.
    pub(crate) cache: RwLock<HashMap<String, FamilyInfo>>,
}

impl Default for Generic {
    fn default() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }
}

impl std::fmt::Debug for Generic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Generic")
            .field(
                "cache_size",
                &self.cache.read().map(|c| c.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl private::Sealed for Generic {}

impl ProtocolState for Generic {
    const PROTOCOL: Protocol = Protocol::Generic;
}

/// WireGuard protocol state.
///
/// Used for WireGuard device configuration via Generic Netlink.
/// Contains the resolved WireGuard family ID.
///
/// Construct with `Connection::<Wireguard>::new_async().await?`, not `Connection::new()`.
#[derive(Debug, Default)]
pub struct Wireguard {
    /// Resolved WireGuard GENL family ID.
    pub(crate) family_id: u16,
    /// Whether the kernel removes one allowed-IP prefix
    /// (`WGALLOWEDIP_F_REMOVE_ME`, 6.16+), once probed (#529).
    pub(crate) allowed_ip_removal: std::sync::OnceLock<bool>,
}

impl private::Sealed for Wireguard {}

impl ProtocolState for Wireguard {
    const PROTOCOL: Protocol = Protocol::Generic;
}

/// Kobject uevent protocol state.
///
/// Used for receiving kernel object events (device hotplug, like udev).
/// This is a zero-sized type with no additional state.
///
/// Note: Does not implement `Default` because connections require
/// multicast group subscription. Use `Connection::<KobjectUevent>::new()`.
#[derive(Debug, Clone, Copy)]
pub struct KobjectUevent;

impl private::Sealed for KobjectUevent {}

impl ProtocolState for KobjectUevent {
    const PROTOCOL: Protocol = Protocol::KobjectUevent;
}

/// Connector protocol state.
///
/// Used for kernel connector events, primarily process events (fork/exec/exit).
/// This is a zero-sized type with no additional state.
///
/// Note: Does not implement `Default` because connections require
/// registration with the kernel. Use `Connection::<Connector>::new()`.
#[derive(Debug, Clone, Copy)]
pub struct Connector;

impl private::Sealed for Connector {}

impl ProtocolState for Connector {
    const PROTOCOL: Protocol = Protocol::Connector;
}

/// Netfilter protocol state.
///
/// Used for netfilter operations, primarily connection tracking (conntrack).
/// This is a zero-sized type with no additional state.
#[derive(Debug, Default, Clone, Copy)]
pub struct Netfilter;

impl private::Sealed for Netfilter {}

impl ProtocolState for Netfilter {
    const PROTOCOL: Protocol = Protocol::Netfilter;
}

/// `mac80211_hwsim` protocol state: simulated Wi-Fi radios (#530). See
/// [`genl::hwsim`](super::genl::hwsim).
///
/// Construct with `Connection::<Hwsim>::new_async().await?`.
#[derive(Debug, Default)]
pub struct Hwsim {
    /// Resolved `MAC80211_HWSIM` GENL family ID.
    pub(crate) family_id: u16,
}

impl private::Sealed for Hwsim {}

impl ProtocolState for Hwsim {
    const PROTOCOL: Protocol = Protocol::Generic;
}

/// NFLOG (`nfnetlink_log`) protocol state: the packets `log group N`
/// rules send (#528). See [`nflog`](super::nflog).
#[derive(Debug, Default, Clone, Copy)]
pub struct Nflog;

impl private::Sealed for Nflog {}

impl ProtocolState for Nflog {
    const PROTOCOL: Protocol = Protocol::Netfilter;
}

/// XFRM protocol state.
///
/// Used for IPsec Security Association (SA) and Security Policy (SP) management.
/// This is a zero-sized type with no additional state.
#[derive(Debug, Default, Clone, Copy)]
pub struct Xfrm;

impl private::Sealed for Xfrm {}

impl ProtocolState for Xfrm {
    const PROTOCOL: Protocol = Protocol::Xfrm;
}

/// FIB lookup protocol state.
///
/// Used for performing FIB (Forwarding Information Base) route lookups.
/// This is a zero-sized type with no additional state.
#[derive(Debug, Clone, Copy)]
pub struct FibLookup;

impl private::Sealed for FibLookup {}

impl ProtocolState for FibLookup {
    const PROTOCOL: Protocol = Protocol::FibLookup;
}

/// SELinux protocol state.
///
/// Used for receiving SELinux event notifications (setenforce, policyload).
/// This is a zero-sized type with no additional state.
///
/// Note: Does not implement `Default` because connections require
/// multicast group subscription. Use `Connection::<SELinux>::new()`.
#[derive(Debug, Clone, Copy)]
pub struct SELinux;

impl private::Sealed for SELinux {}

impl ProtocolState for SELinux {
    const PROTOCOL: Protocol = Protocol::SELinux;
}

/// Audit protocol state.
///
/// Used for interacting with the Linux Audit subsystem.
/// This is a zero-sized type with no additional state.
#[derive(Debug, Clone, Copy)]
pub struct Audit;

impl private::Sealed for Audit {}

impl ProtocolState for Audit {
    const PROTOCOL: Protocol = Protocol::Audit;
}

/// MACsec protocol state.
///
/// Used for MACsec (IEEE 802.1AE) device configuration via Generic Netlink.
/// Contains the resolved MACsec family ID.
///
/// Construct with `Connection::<Macsec>::new_async().await?`, not `Connection::new()`.
#[derive(Debug, Default)]
pub struct Macsec {
    /// Resolved MACsec GENL family ID.
    pub(crate) family_id: u16,
}

impl private::Sealed for Macsec {}

impl ProtocolState for Macsec {
    const PROTOCOL: Protocol = Protocol::Generic;
}

/// MPTCP protocol state.
///
/// Used for MPTCP (Multipath TCP) endpoint configuration via Generic Netlink.
/// Contains the resolved MPTCP Path Manager family ID.
///
/// Construct with `Connection::<Mptcp>::new_async().await?`, not `Connection::new()`.
#[derive(Debug, Default)]
pub struct Mptcp {
    /// Resolved MPTCP PM GENL family ID.
    pub(crate) family_id: u16,
}

impl private::Sealed for Mptcp {}

impl ProtocolState for Mptcp {
    const PROTOCOL: Protocol = Protocol::Generic;
}

/// Devlink protocol state.
///
/// Used for querying hardware device management via Generic Netlink.
/// Contains the resolved devlink family ID + the multicast-group
/// map parsed from `CTRL_CMD_GETFAMILY`.
///
/// Construct with `Connection::<Devlink>::new_async().await?`, not `Connection::new()`.
#[derive(Debug, Default)]
pub struct Devlink {
    /// Resolved devlink GENL family ID.
    pub(crate) family_id: u16,
    /// Multicast groups exposed by the family (name → kernel-assigned ID).
    pub(crate) mcast_groups: ::std::collections::HashMap<String, u32>,
}

impl private::Sealed for Devlink {}

impl ProtocolState for Devlink {
    const PROTOCOL: Protocol = Protocol::Generic;
}

/// Nftables protocol state.
///
/// Used for nftables firewall management via NETLINK_NETFILTER.
/// This is a zero-sized type with no additional state.
#[derive(Debug, Default, Clone, Copy)]
pub struct Nftables;

impl private::Sealed for Nftables {}

impl ProtocolState for Nftables {
    const PROTOCOL: Protocol = Protocol::Netfilter;
}

/// nl80211 protocol state.
///
/// Used for WiFi configuration via Generic Netlink.
/// Contains the resolved nl80211 family ID + the multicast-group
/// map parsed from `CTRL_CMD_GETFAMILY` (`"scan"`, `"mlme"`,
/// `"regulatory"`, `"config"`, …).
///
/// Construct with `Connection::<Nl80211>::new_async().await?`, not `Connection::new()`.
#[derive(Debug, Default)]
pub struct Nl80211 {
    /// Resolved nl80211 GENL family ID.
    pub(crate) family_id: u16,
    /// Multicast groups exposed by the family (name → kernel-assigned ID).
    pub(crate) mcast_groups: ::std::collections::HashMap<String, u32>,
}

impl private::Sealed for Nl80211 {}

impl ProtocolState for Nl80211 {
    const PROTOCOL: Protocol = Protocol::Generic;
}

/// Ethtool protocol state.
///
/// Used for querying and configuring network device settings via Generic Netlink.
/// Contains the resolved ethtool family ID + the multicast-group map.
///
/// Construct with `Connection::<Ethtool>::new_async().await?`, not `Connection::new()`.
#[derive(Debug, Default)]
pub struct Ethtool {
    /// Resolved ethtool GENL family ID.
    pub(crate) family_id: u16,
    /// Multicast groups exposed by the family (name → kernel-assigned ID).
    pub(crate) mcast_groups: ::std::collections::HashMap<String, u32>,
}

impl private::Sealed for Ethtool {}

impl ProtocolState for Ethtool {
    const PROTOCOL: Protocol = Protocol::Generic;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_is_zero_sized() {
        assert_eq!(std::mem::size_of::<Route>(), 0);
    }

    #[test]
    fn sockdiag_is_zero_sized() {
        assert_eq!(std::mem::size_of::<SockDiag>(), 0);
    }

    #[test]
    fn generic_has_cache() {
        let g = Generic::default();
        assert!(g.cache.read().unwrap().is_empty());
    }

    #[test]
    fn protocol_constants() {
        assert_eq!(Route::PROTOCOL, Protocol::Route);
        assert_eq!(SockDiag::PROTOCOL, Protocol::SockDiag);
        assert_eq!(Generic::PROTOCOL, Protocol::Generic);
        assert_eq!(Wireguard::PROTOCOL, Protocol::Generic);
        assert_eq!(Macsec::PROTOCOL, Protocol::Generic);
        assert_eq!(Mptcp::PROTOCOL, Protocol::Generic);
        assert_eq!(Ethtool::PROTOCOL, Protocol::Generic);
        assert_eq!(Nl80211::PROTOCOL, Protocol::Generic);
        assert_eq!(KobjectUevent::PROTOCOL, Protocol::KobjectUevent);
        assert_eq!(Connector::PROTOCOL, Protocol::Connector);
        assert_eq!(Netfilter::PROTOCOL, Protocol::Netfilter);
        assert_eq!(Nftables::PROTOCOL, Protocol::Netfilter);
        assert_eq!(Xfrm::PROTOCOL, Protocol::Xfrm);
        assert_eq!(FibLookup::PROTOCOL, Protocol::FibLookup);
        assert_eq!(SELinux::PROTOCOL, Protocol::SELinux);
        assert_eq!(Audit::PROTOCOL, Protocol::Audit);
    }

    #[test]
    fn new_types_are_zero_sized() {
        assert_eq!(std::mem::size_of::<KobjectUevent>(), 0);
        assert_eq!(std::mem::size_of::<Connector>(), 0);
        assert_eq!(std::mem::size_of::<Netfilter>(), 0);
        assert_eq!(std::mem::size_of::<Xfrm>(), 0);
        assert_eq!(std::mem::size_of::<FibLookup>(), 0);
        assert_eq!(std::mem::size_of::<SELinux>(), 0);
        assert_eq!(std::mem::size_of::<Audit>(), 0);
        assert_eq!(std::mem::size_of::<Nftables>(), 0);
    }
}
