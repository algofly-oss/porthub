//! Route management.
//!
//! This module provides typed builders for adding and managing routes.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::route::{Ipv4Route, Ipv6Route, RouteType, NextHop};
//! use std::net::{Ipv4Addr, Ipv6Addr};
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Add a simple route via gateway
//! conn.add_route(
//!     Ipv4Route::new(Ipv4Addr::new(192, 168, 2, 0), 24)
//!         .gateway(Ipv4Addr::new(192, 168, 1, 1))
//! ).await?;
//!
//! // Add a route via interface
//! conn.add_route(
//!     Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
//!         .dev("eth0")
//! ).await?;
//!
//! // Add a route via interface index (namespace-safe)
//! conn.add_route(
//!     Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
//!         .dev_index(5)
//! ).await?;
//!
//! // Add a multipath route (ECMP)
//! conn.add_route(
//!     Ipv4Route::new(Ipv4Addr::UNSPECIFIED, 0)
//!         .multipath(vec![
//!             NextHop::new().gateway_v4(Ipv4Addr::new(192, 168, 1, 1)).dev("eth0").weight(1),
//!             NextHop::new().gateway_v4(Ipv4Addr::new(192, 168, 2, 1)).dev("eth1").weight(1),
//!         ])
//! ).await?;
//!
//! // Add a blackhole route
//! conn.add_route(
//!     Ipv4Route::new(Ipv4Addr::new(10, 255, 0, 0), 16)
//!         .route_type(RouteType::Blackhole)
//! ).await?;
//!
//! // Delete a route
//! conn.del_route_v4(Ipv4Addr::new(192, 168, 2, 0), 24).await?;
//! # Ok(())
//! # }
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    builder::MessageBuilder,
    connection::Connection,
    error::Result,
    interface_ref::InterfaceRef,
    message::{NLM_F_ACK, NLM_F_REQUEST, NlMsgType},
    mpls::MplsEncap,
    protocol::Route,
    srv6::Srv6Encap,
    types::route::{RouteProtocol, RouteScope, RtMsg, RtaAttr, rt_table},
};
// Re-exported so the type named by `Ipv4Route::route_type` can be named from
// the module that defines `Ipv4Route` — every doc example here imported it
// from this path already (#316).
pub use super::types::route::RouteType;

/// NLM_F_CREATE flag
const NLM_F_CREATE: u16 = 0x400;
/// NLM_F_EXCL flag
const NLM_F_EXCL: u16 = 0x200;

/// Address families
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// Route metrics attributes (RTAX_*)
pub(crate) mod rtax {
    /// The metrics locked against path discovery, a bit per `RTAX_*`.
    pub const LOCK: u16 = 1;
    pub const MTU: u16 = 2;
    pub const WINDOW: u16 = 3;
    pub const RTT: u16 = 4;
    pub const RTTVAR: u16 = 5;
    pub const SSTHRESH: u16 = 6;
    pub const CWND: u16 = 7;
    pub const ADVMSS: u16 = 8;
    pub const REORDERING: u16 = 9;
    pub const HOPLIMIT: u16 = 10;
    pub const INITCWND: u16 = 11;
    pub const FEATURES: u16 = 12;
    pub const RTO_MIN: u16 = 13;
    pub const INITRWND: u16 = 14;
    pub const QUICKACK: u16 = 15;
    /// The congestion control, a string.
    pub const CC_ALGO: u16 = 16;
}

/// Nexthop flags (RTNH_F_*)
pub mod rtnh_flags {
    pub const DEAD: u8 = 1;
    pub const PERVASIVE: u8 = 2;
    pub const ONLINK: u8 = 4;
    pub const OFFLOAD: u8 = 8;
    pub const LINKDOWN: u8 = 16;
    pub const UNRESOLVED: u8 = 32;
    pub const TRAP: u8 = 64;
}

/// Resolved interface indices for route operations.
///
/// This struct holds the resolved interface indices for the main output interface
/// and any multipath nexthops that have device references.
#[derive(Debug, Clone, Default)]
pub struct ResolvedRouteInterfaces {
    /// Main output interface index (for RTA_OIF)
    pub oif: Option<u32>,
    /// Multipath nexthop interface indices (in order)
    pub multipath: Vec<Option<u32>>,
}

/// Trait for route configurations that can be added.
pub trait RouteConfig: Send + Sync {
    /// Get the device reference for the main output interface.
    fn device_ref(&self) -> Option<&InterfaceRef>;

    /// Get device references for all multipath nexthops.
    fn multipath_device_refs(&self) -> Vec<Option<&InterfaceRef>>;

    /// Get the address family (AF_INET or AF_INET6).
    fn family(&self) -> u8;

    /// Write the add message to the builder with resolved interface indices.
    fn write_add(&self, builder: &mut MessageBuilder, interfaces: &ResolvedRouteInterfaces);

    /// Write the delete message to the builder.
    ///
    /// Older shape: no interface resolution. Kept for backward
    /// compatibility with downstream `RouteConfig` implementors.
    /// New code should override [`Self::write_delete_with_interfaces`]
    /// (which receives the resolved OIF) so the kernel can match
    /// the route on the full key.
    fn write_delete(&self, builder: &mut MessageBuilder);

    /// Write the delete message to the builder with resolved
    /// interface indices.
    ///
    /// Newer kernels match `RTM_DELROUTE` strictly on the route
    /// key (`dst`, `dst_len`, `table`, `protocol`, `scope`, `type`,
    /// `RTA_OIF`, `RTA_GATEWAY`, `RTA_PRIORITY`), and return ESRCH
    /// when the request is missing fields the original `add` set.
    /// This method lets `Connection::del_route` resolve the device
    /// to an ifindex and pass it through, so the delete request
    /// carries `RTA_OIF`.
    ///
    /// Default impl preserves the legacy [`Self::write_delete`]
    /// behaviour for downstream implementors that haven't migrated
    /// yet. The in-tree [`Ipv4Route`] / [`Ipv6Route`] override this
    /// to write the full discriminating key.
    fn write_delete_with_interfaces(
        &self,
        builder: &mut MessageBuilder,
        _interfaces: &ResolvedRouteInterfaces,
    ) {
        self.write_delete(builder);
    }
}

/// Route metrics configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteMetrics {
    /// Path MTU
    pub mtu: Option<u32>,
    /// Advertised MSS
    pub advmss: Option<u32>,
    /// Window size
    pub window: Option<u32>,
    /// RTT in milliseconds
    pub rtt: Option<u32>,
    /// RTT variance
    pub rttvar: Option<u32>,
    /// Slow-start threshold
    pub ssthresh: Option<u32>,
    /// Congestion window
    pub cwnd: Option<u32>,
    /// Initial congestion window
    pub initcwnd: Option<u32>,
    /// Initial receive window
    pub initrwnd: Option<u32>,
    /// Hop limit
    pub hoplimit: Option<u32>,
    /// RTO minimum
    pub rto_min: Option<u32>,
    /// Quick ACK
    pub quickack: Option<u32>,
    /// Reordering
    pub reordering: Option<u32>,
    /// Features
    pub features: Option<u32>,
}

impl RouteMetrics {
    /// Create empty metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read an `RTA_METRICS` nest. Unknown `RTAX_*` attributes (and
    /// `RTAX_CC_ALGO`, a string) are skipped.
    pub(crate) fn parse(nest: &[u8]) -> Self {
        let mut m = Self::default();
        for (ty, payload) in crate::netlink::attr::AttrIter::new(nest) {
            let Some(v) = payload.get(..4).map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
            else {
                continue;
            };
            let slot = match ty & 0x3FFF {
                rtax::MTU => &mut m.mtu,
                rtax::WINDOW => &mut m.window,
                rtax::RTT => &mut m.rtt,
                rtax::RTTVAR => &mut m.rttvar,
                rtax::SSTHRESH => &mut m.ssthresh,
                rtax::CWND => &mut m.cwnd,
                rtax::ADVMSS => &mut m.advmss,
                rtax::REORDERING => &mut m.reordering,
                rtax::HOPLIMIT => &mut m.hoplimit,
                rtax::INITCWND => &mut m.initcwnd,
                rtax::FEATURES => &mut m.features,
                rtax::RTO_MIN => &mut m.rto_min,
                rtax::INITRWND => &mut m.initrwnd,
                rtax::QUICKACK => &mut m.quickack,
                _ => continue,
            };
            *slot = Some(v);
        }
        m
    }

    /// Set path MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set advertised MSS.
    pub fn advmss(mut self, advmss: u32) -> Self {
        self.advmss = Some(advmss);
        self
    }

    /// Set window size.
    pub fn window(mut self, window: u32) -> Self {
        self.window = Some(window);
        self
    }

    /// Set initial congestion window.
    pub fn initcwnd(mut self, initcwnd: u32) -> Self {
        self.initcwnd = Some(initcwnd);
        self
    }

    /// Set initial receive window.
    pub fn initrwnd(mut self, initrwnd: u32) -> Self {
        self.initrwnd = Some(initrwnd);
        self
    }

    /// Set hop limit.
    pub fn hoplimit(mut self, hoplimit: u32) -> Self {
        self.hoplimit = Some(hoplimit);
        self
    }

    /// Set RTO minimum in milliseconds.
    pub fn rto_min(mut self, rto_min: u32) -> Self {
        self.rto_min = Some(rto_min);
        self
    }

    /// Set quick ACK.
    pub fn quickack(mut self, quickack: u32) -> Self {
        self.quickack = Some(quickack);
        self
    }

    /// Check if any metrics are set.
    pub fn has_any(&self) -> bool {
        self.mtu.is_some()
            || self.advmss.is_some()
            || self.window.is_some()
            || self.rtt.is_some()
            || self.rttvar.is_some()
            || self.ssthresh.is_some()
            || self.cwnd.is_some()
            || self.initcwnd.is_some()
            || self.initrwnd.is_some()
            || self.hoplimit.is_some()
            || self.rto_min.is_some()
            || self.quickack.is_some()
            || self.reordering.is_some()
            || self.features.is_some()
    }

    /// Write metrics as nested attribute.
    fn write_to(&self, builder: &mut MessageBuilder) {
        let metrics = builder.nest_start(RtaAttr::Metrics as u16);

        if let Some(v) = self.mtu {
            builder.append_attr_u32(rtax::MTU, v);
        }
        if let Some(v) = self.advmss {
            builder.append_attr_u32(rtax::ADVMSS, v);
        }
        if let Some(v) = self.window {
            builder.append_attr_u32(rtax::WINDOW, v);
        }
        if let Some(v) = self.rtt {
            builder.append_attr_u32(rtax::RTT, v);
        }
        if let Some(v) = self.rttvar {
            builder.append_attr_u32(rtax::RTTVAR, v);
        }
        if let Some(v) = self.ssthresh {
            builder.append_attr_u32(rtax::SSTHRESH, v);
        }
        if let Some(v) = self.cwnd {
            builder.append_attr_u32(rtax::CWND, v);
        }
        if let Some(v) = self.initcwnd {
            builder.append_attr_u32(rtax::INITCWND, v);
        }
        if let Some(v) = self.initrwnd {
            builder.append_attr_u32(rtax::INITRWND, v);
        }
        if let Some(v) = self.hoplimit {
            builder.append_attr_u32(rtax::HOPLIMIT, v);
        }
        if let Some(v) = self.rto_min {
            builder.append_attr_u32(rtax::RTO_MIN, v);
        }
        if let Some(v) = self.quickack {
            builder.append_attr_u32(rtax::QUICKACK, v);
        }
        if let Some(v) = self.reordering {
            builder.append_attr_u32(rtax::REORDERING, v);
        }
        if let Some(v) = self.features {
            builder.append_attr_u32(rtax::FEATURES, v);
        }

        builder.nest_end(metrics);
    }
}

/// A single nexthop in a multipath route.
#[derive(Debug, Clone)]
pub struct NextHop {
    /// Gateway address (IPv4)
    gateway_v4: Option<Ipv4Addr>,
    /// Gateway address (IPv6)
    gateway_v6: Option<Ipv6Addr>,
    /// Output interface reference
    dev: Option<InterfaceRef>,
    /// Weight (for ECMP), 1 to 256
    weight: u16,
    /// Flags
    flags: u8,
}

impl NextHop {
    /// Create a new nexthop.
    pub fn new() -> Self {
        Self {
            gateway_v4: None,
            gateway_v6: None,
            dev: None,
            weight: 1,
            flags: 0,
        }
    }

    /// Set IPv4 gateway.
    pub fn gateway_v4(mut self, addr: Ipv4Addr) -> Self {
        self.gateway_v4 = Some(addr);
        self.gateway_v6 = None;
        self
    }

    /// Set IPv6 gateway.
    pub fn gateway_v6(mut self, addr: Ipv6Addr) -> Self {
        self.gateway_v6 = Some(addr);
        self.gateway_v4 = None;
        self
    }

    /// Set output interface by name.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(InterfaceRef::Name(dev.into()));
        self
    }

    /// Set output interface by index (namespace-safe).
    pub fn dev_index(mut self, ifindex: u32) -> Self {
        self.dev = Some(InterfaceRef::Index(ifindex));
        self
    }

    /// Get the device reference.
    pub fn device_ref(&self) -> Option<&InterfaceRef> {
        self.dev.as_ref()
    }

    /// Set weight, 1 to 256 (a `u16` since 0.32, #783); one past 256 is
    /// written as 256.
    pub fn weight(mut self, weight: u16) -> Self {
        self.weight = weight.clamp(1, 256);
        self
    }

    /// Mark as onlink (gateway is on-link even if not in subnet).
    pub fn onlink(mut self) -> Self {
        self.flags |= rtnh_flags::ONLINK;
        self
    }
}

impl Default for NextHop {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// IPv4 Route
// ============================================================================

/// Configuration for an IPv4 route.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::route::{Ipv4Route, RouteType, RouteMetrics};
/// use std::net::Ipv4Addr;
///
/// // Simple gateway route
/// let route = Ipv4Route::new(Ipv4Addr::new(192, 168, 2, 0), 24)
///     .gateway(Ipv4Addr::new(192, 168, 1, 1));
///
/// // Route with metrics
/// let route = Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
///     .dev("eth0")
///     .metrics(RouteMetrics::new().mtu(1400));
///
/// // Route with interface by index (namespace-safe)
/// let route = Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
///     .dev_index(5)
///     .metrics(RouteMetrics::new().mtu(1400));
///
/// // Route using a nexthop group (Linux 5.3+)
/// let route = Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
///     .nexthop_group(100);  // Reference nexthop group ID 100
///
/// conn.add_route(route).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Ipv4Route {
    destination: Ipv4Addr,
    prefix_len: u8,
    /// Gateway address
    gateway: Option<Ipv4Addr>,
    /// An IPv6 gateway (`RTA_VIA`, RFC 5549)
    via6: Option<Ipv6Addr>,
    /// Preferred source address
    prefsrc: Option<Ipv4Addr>,
    /// Output interface reference
    dev: Option<InterfaceRef>,
    /// Route type
    route_type: RouteType,
    /// Route protocol
    protocol: RouteProtocol,
    /// Route scope
    scope: Option<RouteScope>,
    /// Routing table
    table: u32,
    /// Route priority/metric
    priority: Option<u32>,
    /// Route metrics
    metrics: Option<RouteMetrics>,
    /// Mark
    mark: Option<u32>,
    /// Multipath nexthops
    multipath: Option<Vec<NextHop>>,
    /// Nexthop group ID (Linux 5.3+, RTA_NH_ID)
    nexthop_id: Option<u32>,
    /// MPLS encapsulation
    mpls_encap: Option<MplsEncap>,
    /// SRv6 encapsulation
    srv6_encap: Option<Srv6Encap>,
    /// `rtm_flags`: `RTNH_F_ONLINK` for [`onlink`](Self::onlink).
    flags: u32,
}

impl Ipv4Route {
    /// Build the default IPv4 route (`0.0.0.0/0`). Equivalent
    /// to [`Ipv4Route::new`]`(Ipv4Addr::UNSPECIFIED, 0)` but
    /// self-documenting. Plan 184.
    pub fn default_route() -> Self {
        Self::new(Ipv4Addr::UNSPECIFIED, 0)
    }

    /// Create a new IPv4 route configuration.
    ///
    /// # Arguments
    ///
    /// * `destination` - Destination network (e.g. `Ipv4Addr::new(192, 168, 1, 0)`,
    ///   or [`Ipv4Addr::UNSPECIFIED`] for the default route)
    /// * `prefix_len` - Prefix length (0-32)
    ///
    /// The destination is an address, not a string (#881). A string that
    /// failed to parse used to become `0.0.0.0` with no error, and with
    /// prefix 0 that is the default route. A caller holding a string parses
    /// it and handles the error:
    ///
    /// ```compile_fail
    /// # use nlink::netlink::route::Ipv4Route;
    /// let route = Ipv4Route::new("10.0.0.0", 8);
    /// ```
    pub fn new(destination: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            destination,
            prefix_len,
            gateway: None,
            via6: None,
            prefsrc: None,
            dev: None,
            route_type: RouteType::Unicast,
            protocol: RouteProtocol::Boot,
            scope: None,
            table: rt_table::MAIN as u32,
            priority: None,
            metrics: None,
            mark: None,
            multipath: None,
            nexthop_id: None,
            mpls_encap: None,
            srv6_encap: None,
            flags: 0,
        }
    }

    /// Create from a parsed Ipv4Addr.
    pub fn from_addr(destination: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            destination,
            prefix_len,
            gateway: None,
            via6: None,
            prefsrc: None,
            dev: None,
            route_type: RouteType::Unicast,
            protocol: RouteProtocol::Boot,
            scope: None,
            table: rt_table::MAIN as u32,
            priority: None,
            metrics: None,
            mark: None,
            multipath: None,
            nexthop_id: None,
            mpls_encap: None,
            srv6_encap: None,
            flags: 0,
        }
    }

    /// Set the gateway address.
    pub fn gateway(mut self, gateway: Ipv4Addr) -> Self {
        self.gateway = Some(gateway);
        self.via6 = None;
        self.multipath = None;
        self
    }

    /// Route via an IPv6 gateway, as `ip route add … via inet6 <gw>` does
    /// (RFC 5549; `RTA_VIA`, kernel 5.2), in place of an IPv4 one (#516).
    pub fn gateway_v6(mut self, gateway: Ipv6Addr) -> Self {
        self.via6 = Some(gateway);
        self.gateway = None;
        self.multipath = None;
        self
    }

    /// Set the preferred source address.
    pub fn prefsrc(mut self, src: Ipv4Addr) -> Self {
        self.prefsrc = Some(src);
        self
    }

    /// Set the output interface by name.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(InterfaceRef::Name(dev.into()));
        self
    }

    /// Set the output interface by index (namespace-safe).
    pub fn dev_index(mut self, ifindex: u32) -> Self {
        self.dev = Some(InterfaceRef::Index(ifindex));
        self
    }

    /// Set the route type.
    pub fn route_type(mut self, rtype: RouteType) -> Self {
        self.route_type = rtype;
        self
    }

    /// Set the route protocol.
    pub fn protocol(mut self, protocol: RouteProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Set the route scope.
    pub fn scope(mut self, scope: RouteScope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Set the routing table.
    pub fn table(mut self, table: u32) -> Self {
        self.table = table;
        self
    }

    /// Set the route priority (metric).
    pub fn priority(mut self, priority: u32) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Alias for priority.
    pub fn metric(self, metric: u32) -> Self {
        self.priority(metric)
    }

    /// Set route metrics (MTU, advmss, etc.).
    pub fn metrics(mut self, metrics: RouteMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// The gateway is on the link even if no address's subnet covers it
    /// (`ip route … onlink`, `RTNH_F_ONLINK`). Needs a device.
    pub fn onlink(mut self) -> Self {
        self.flags |= u32::from(rtnh_flags::ONLINK);
        self
    }

    /// Set fwmark.
    pub fn mark(mut self, mark: u32) -> Self {
        self.mark = Some(mark);
        self
    }

    /// Set multipath nexthops (ECMP).
    ///
    /// This clears any single gateway setting.
    pub fn multipath(mut self, nexthops: Vec<NextHop>) -> Self {
        self.multipath = Some(nexthops);
        self.gateway = None;
        self.nexthop_id = None;
        self
    }

    /// Set nexthop group ID (Linux 5.3+).
    ///
    /// This uses a pre-configured nexthop group for routing decisions.
    /// Nexthop groups provide a more flexible alternative to multipath routes,
    /// supporting features like weighted ECMP and resilient hashing.
    ///
    /// This clears any gateway or multipath settings.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::Ipv4Route;
    /// # use nlink::netlink::nexthop::NexthopGroupBuilder;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # use std::net::Ipv4Addr;
    /// // First, create a nexthop group
    /// conn.add_nexthop_group(
    ///     NexthopGroupBuilder::new(100)
    ///         .member(1, 1)   // nexthop ID 1, weight 1
    ///         .member(2, 1)   // nexthop ID 2, weight 1
    /// ).await?;
    ///
    /// // Then use it in a route
    /// conn.add_route(
    ///     Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
    ///         .nexthop_group(100)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn nexthop_group(mut self, group_id: u32) -> Self {
        self.nexthop_id = Some(group_id);
        self.gateway = None;
        self.multipath = None;
        self
    }

    /// Add MPLS encapsulation (push labels).
    ///
    /// This causes the route to push MPLS labels onto outgoing packets.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use std::net::Ipv4Addr;
    /// use nlink::netlink::route::Ipv4Route;
    /// use nlink::netlink::mpls::MplsEncap;
    ///
    /// // Push a single label
    /// let route = Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
    ///     .gateway("192.168.1.1".parse()?)
    ///     .mpls_encap(MplsEncap::new().label(100));
    ///
    /// // Push a label stack
    /// let route = Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
    ///     .gateway("192.168.1.1".parse()?)
    ///     .mpls_encap(MplsEncap::new().labels(&[100, 200]));
    /// # Ok(())
    /// # }
    /// ```
    pub fn mpls_encap(mut self, encap: MplsEncap) -> Self {
        self.mpls_encap = Some(encap);
        self
    }

    /// Add SRv6 encapsulation.
    ///
    /// This causes the route to encapsulate packets with an SRv6 header.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use std::net::Ipv4Addr;
    /// use nlink::netlink::route::Ipv4Route;
    /// use nlink::netlink::srv6::Srv6Encap;
    ///
    /// // Encapsulate IPv4 traffic in SRv6
    /// let route = Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
    ///     .dev("eth0")
    ///     .srv6_encap(
    ///         Srv6Encap::encap()
    ///             .segment("fc00:1::1".parse()?)
    ///     );
    /// # Ok(())
    /// # }
    /// ```
    pub fn srv6_encap(mut self, encap: Srv6Encap) -> Self {
        self.srv6_encap = Some(encap);
        self
    }

    /// Determine the scope based on route configuration.
    fn determine_scope(&self) -> RouteScope {
        if let Some(scope) = self.scope {
            return scope;
        }

        // Default scope determination based on route type
        match self.route_type {
            RouteType::Local | RouteType::Nat => RouteScope::Host,
            RouteType::Broadcast | RouteType::Multicast | RouteType::Anycast => RouteScope::Link,
            RouteType::Unicast | RouteType::Unspec => {
                if self.gateway.is_some()
                    || self.via6.is_some()
                    || self.multipath.is_some()
                    || self.nexthop_id.is_some()
                {
                    RouteScope::Universe
                } else {
                    RouteScope::Link
                }
            }
            _ => RouteScope::Universe,
        }
    }
}

impl RouteConfig for Ipv4Route {
    fn device_ref(&self) -> Option<&InterfaceRef> {
        self.dev.as_ref()
    }

    fn multipath_device_refs(&self) -> Vec<Option<&InterfaceRef>> {
        match &self.multipath {
            Some(nexthops) => nexthops.iter().map(|nh| nh.device_ref()).collect(),
            None => Vec::new(),
        }
    }

    fn family(&self) -> u8 {
        AF_INET
    }

    fn write_add(&self, builder: &mut MessageBuilder, interfaces: &ResolvedRouteInterfaces) {
        let table_u8 = if self.table > 255 {
            rt_table::UNSPEC
        } else {
            self.table as u8
        };

        let scope = self.determine_scope();

        let rtmsg = RtMsg::new()
            .with_family(AF_INET)
            .with_dst_len(self.prefix_len)
            .with_table(table_u8)
            .with_protocol(self.protocol.number())
            .with_scope(scope as u8)
            .with_type(self.route_type as u8)
            .with_flags(self.flags);

        builder.append(&rtmsg);

        // RTA_DST
        if self.prefix_len > 0 {
            builder.append_attr(RtaAttr::Dst as u16, &self.destination.octets());
        }

        // RTA_GATEWAY
        if let Some(gw) = self.gateway {
            builder.append_attr(RtaAttr::Gateway as u16, &gw.octets());
        }
        // RTA_VIA: an IPv6 gateway, `struct rtvia` (#516)
        if let Some(gw) = self.via6 {
            let mut via = (libc::AF_INET6 as u16).to_ne_bytes().to_vec();
            via.extend_from_slice(&gw.octets());
            builder.append_attr(RtaAttr::Via as u16, &via);
        }

        // RTA_PREFSRC
        if let Some(src) = self.prefsrc {
            builder.append_attr(RtaAttr::Prefsrc as u16, &src.octets());
        }

        // RTA_OIF (from resolved interface)
        if let Some(ifindex) = interfaces.oif {
            builder.append_attr_u32(RtaAttr::Oif as u16, ifindex);
        }

        // RTA_TABLE (for table > 255)
        if self.table > 255 {
            builder.append_attr_u32(RtaAttr::Table as u16, self.table);
        }

        // RTA_PRIORITY
        if let Some(prio) = self.priority {
            builder.append_attr_u32(RtaAttr::Priority as u16, prio);
        }

        // RTA_MARK
        if let Some(mark) = self.mark {
            builder.append_attr_u32(RtaAttr::Mark as u16, mark);
        }

        // RTA_METRICS
        if let Some(ref metrics) = self.metrics
            && metrics.has_any()
        {
            metrics.write_to(builder);
        }

        // RTA_MULTIPATH
        if let Some(ref nexthops) = self.multipath {
            write_multipath_v4(builder, nexthops, &interfaces.multipath);
        }

        // RTA_NH_ID (nexthop group reference, Linux 5.3+)
        if let Some(nh_id) = self.nexthop_id {
            builder.append_attr_u32(RtaAttr::NhId as u16, nh_id);
        }

        // RTA_ENCAP_TYPE + RTA_ENCAP (MPLS encapsulation)
        if let Some(ref encap) = self.mpls_encap {
            encap.write_to(builder);
        }

        // RTA_ENCAP_TYPE + RTA_ENCAP (SRv6 encapsulation)
        if let Some(ref encap) = self.srv6_encap {
            encap.write_to(builder);
        }
    }

    fn write_delete(&self, builder: &mut MessageBuilder) {
        // Legacy delete path: no interface resolution. Newer
        // kernels need RTA_OIF + protocol/scope/type to match the
        // original add — see `write_delete_with_interfaces` for the
        // strict-key form.
        let table_u8 = if self.table > 255 {
            rt_table::UNSPEC
        } else {
            self.table as u8
        };

        let rtmsg = RtMsg::new()
            .with_family(AF_INET)
            .with_dst_len(self.prefix_len)
            .with_table(table_u8);

        builder.append(&rtmsg);

        // RTA_DST
        if self.prefix_len > 0 {
            builder.append_attr(RtaAttr::Dst as u16, &self.destination.octets());
        }

        // RTA_TABLE (for table > 255)
        if self.table > 255 {
            builder.append_attr_u32(RtaAttr::Table as u16, self.table);
        }
    }

    fn write_delete_with_interfaces(
        &self,
        builder: &mut MessageBuilder,
        interfaces: &ResolvedRouteInterfaces,
    ) {
        // Strict-key delete: writes the same discriminating fields
        // `write_add` writes (family, dst_len, table, protocol,
        // scope, type, RTA_DST, RTA_OIF, RTA_GATEWAY, RTA_PREFSRC,
        // RTA_PRIORITY) so newer kernels match the original add and
        // don't return ESRCH.
        //
        // **RTA_METRICS deliberately omitted on delete.** The IPv4
        // kernel's `fib_table_delete` (`net/ipv4/fib_trie.c`) and the
        // IPv6 equivalent `ip6_route_del` (`net/ipv6/route.c`) match
        // on the discriminating-key fields listed above — they don't
        // key on metrics. Metrics live in the shared `fib_info` /
        // `fib6_info` object that may be referenced by multiple
        // route aliases; they're advisory at lookup time, not part
        // of route identity. Asymmetry with `write_add` (which DOES
        // write `RTA_METRICS`) is intentional: add carries the
        // metrics for the kernel to attach to the new route entry;
        // delete just identifies which entry to remove. Verified by
        // kernel-source read during the Plan 147 §4.2 audit.
        let table_u8 = if self.table > 255 {
            rt_table::UNSPEC
        } else {
            self.table as u8
        };

        let scope = self.determine_scope();

        let rtmsg = RtMsg::new()
            .with_family(AF_INET)
            .with_dst_len(self.prefix_len)
            .with_table(table_u8)
            .with_protocol(self.protocol.number())
            .with_scope(scope as u8)
            .with_type(self.route_type as u8)
            .with_flags(self.flags);

        builder.append(&rtmsg);

        // RTA_DST
        if self.prefix_len > 0 {
            builder.append_attr(RtaAttr::Dst as u16, &self.destination.octets());
        }

        // RTA_GATEWAY (kernel matches strictly)
        if let Some(gw) = self.gateway {
            builder.append_attr(RtaAttr::Gateway as u16, &gw.octets());
        }
        // RTA_VIA: an IPv6 gateway, `struct rtvia` (#516)
        if let Some(gw) = self.via6 {
            let mut via = (libc::AF_INET6 as u16).to_ne_bytes().to_vec();
            via.extend_from_slice(&gw.octets());
            builder.append_attr(RtaAttr::Via as u16, &via);
        }

        // RTA_PREFSRC
        if let Some(src) = self.prefsrc {
            builder.append_attr(RtaAttr::Prefsrc as u16, &src.octets());
        }

        // RTA_OIF (from resolved interface) — the field this whole
        // method exists to write
        if let Some(ifindex) = interfaces.oif {
            builder.append_attr_u32(RtaAttr::Oif as u16, ifindex);
        }

        // RTA_TABLE (for table > 255)
        if self.table > 255 {
            builder.append_attr_u32(RtaAttr::Table as u16, self.table);
        }

        // RTA_PRIORITY
        if let Some(prio) = self.priority {
            builder.append_attr_u32(RtaAttr::Priority as u16, prio);
        }
    }
}

// ============================================================================
// IPv6 Route
// ============================================================================

/// Configuration for an IPv6 route.
#[derive(Debug, Clone)]
pub struct Ipv6Route {
    destination: Ipv6Addr,
    prefix_len: u8,
    /// Gateway address
    gateway: Option<Ipv6Addr>,
    /// Preferred source address
    prefsrc: Option<Ipv6Addr>,
    /// Output interface reference
    dev: Option<InterfaceRef>,
    /// Route type
    route_type: RouteType,
    /// Route protocol
    protocol: RouteProtocol,
    /// Route scope
    scope: Option<RouteScope>,
    /// Routing table
    table: u32,
    /// Route priority/metric
    priority: Option<u32>,
    /// Route metrics
    metrics: Option<RouteMetrics>,
    /// Mark
    mark: Option<u32>,
    /// Multipath nexthops
    multipath: Option<Vec<NextHop>>,
    /// Route preference (pref)
    pref: Option<u8>,
    /// Nexthop group ID (Linux 5.3+, RTA_NH_ID)
    nexthop_id: Option<u32>,
    /// MPLS encapsulation
    mpls_encap: Option<MplsEncap>,
    /// SRv6 encapsulation
    srv6_encap: Option<Srv6Encap>,
    /// `rtm_flags`: `RTNH_F_ONLINK` for [`onlink`](Self::onlink).
    flags: u32,
}

impl Ipv6Route {
    /// Build the default IPv6 route (`::/0`). Equivalent to
    /// [`Ipv6Route::new`]`(Ipv6Addr::UNSPECIFIED, 0)` but
    /// self-documenting. Plan 184.
    pub fn default_route() -> Self {
        Self::new(Ipv6Addr::UNSPECIFIED, 0)
    }

    /// Create a new IPv6 route configuration.
    ///
    /// The destination is an address, not a string (#881): a string that
    /// failed to parse used to become `::` with no error.
    ///
    /// ```compile_fail
    /// # use nlink::netlink::route::Ipv6Route;
    /// let route = Ipv6Route::new("2001:db8::", 32);
    /// ```
    pub fn new(destination: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            destination,
            prefix_len,
            gateway: None,
            prefsrc: None,
            dev: None,
            route_type: RouteType::Unicast,
            protocol: RouteProtocol::Boot,
            scope: None,
            table: rt_table::MAIN as u32,
            priority: None,
            metrics: None,
            mark: None,
            multipath: None,
            pref: None,
            nexthop_id: None,
            mpls_encap: None,
            srv6_encap: None,
            flags: 0,
        }
    }

    /// Create from a parsed Ipv6Addr.
    pub fn from_addr(destination: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            destination,
            prefix_len,
            gateway: None,
            prefsrc: None,
            dev: None,
            route_type: RouteType::Unicast,
            protocol: RouteProtocol::Boot,
            scope: None,
            table: rt_table::MAIN as u32,
            priority: None,
            metrics: None,
            mark: None,
            multipath: None,
            pref: None,
            nexthop_id: None,
            mpls_encap: None,
            srv6_encap: None,
            flags: 0,
        }
    }

    /// Set the gateway address.
    pub fn gateway(mut self, gateway: Ipv6Addr) -> Self {
        self.gateway = Some(gateway);
        self.multipath = None;
        self
    }

    /// Set the preferred source address.
    pub fn prefsrc(mut self, src: Ipv6Addr) -> Self {
        self.prefsrc = Some(src);
        self
    }

    /// Set the output interface by name.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(InterfaceRef::Name(dev.into()));
        self
    }

    /// Set the output interface by index (namespace-safe).
    pub fn dev_index(mut self, ifindex: u32) -> Self {
        self.dev = Some(InterfaceRef::Index(ifindex));
        self
    }

    /// Set the route type.
    pub fn route_type(mut self, rtype: RouteType) -> Self {
        self.route_type = rtype;
        self
    }

    /// Set the route protocol.
    pub fn protocol(mut self, protocol: RouteProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Set the route scope.
    pub fn scope(mut self, scope: RouteScope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Set the routing table.
    pub fn table(mut self, table: u32) -> Self {
        self.table = table;
        self
    }

    /// Set the route priority (metric).
    pub fn priority(mut self, priority: u32) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Alias for priority.
    pub fn metric(self, metric: u32) -> Self {
        self.priority(metric)
    }

    /// Set route metrics (MTU, advmss, etc.).
    pub fn metrics(mut self, metrics: RouteMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// The gateway is on the link even if no address's subnet covers it
    /// (`ip route … onlink`, `RTNH_F_ONLINK`). Needs a device.
    pub fn onlink(mut self) -> Self {
        self.flags |= u32::from(rtnh_flags::ONLINK);
        self
    }

    /// Set fwmark.
    pub fn mark(mut self, mark: u32) -> Self {
        self.mark = Some(mark);
        self
    }

    /// Set multipath nexthops (ECMP).
    pub fn multipath(mut self, nexthops: Vec<NextHop>) -> Self {
        self.multipath = Some(nexthops);
        self.gateway = None;
        self.nexthop_id = None;
        self
    }

    /// Set route preference (low=0, medium=1, high=2).
    pub fn pref(mut self, pref: u8) -> Self {
        self.pref = Some(pref);
        self
    }

    /// Set nexthop group ID (Linux 5.3+).
    ///
    /// This uses a pre-configured nexthop group for routing decisions.
    /// Nexthop groups provide a more flexible alternative to multipath routes,
    /// supporting features like weighted ECMP and resilient hashing.
    ///
    /// This clears any gateway or multipath settings.
    pub fn nexthop_group(mut self, group_id: u32) -> Self {
        self.nexthop_id = Some(group_id);
        self.gateway = None;
        self.multipath = None;
        self
    }

    /// Add MPLS encapsulation (push labels).
    ///
    /// This causes the route to push MPLS labels onto outgoing packets.
    pub fn mpls_encap(mut self, encap: MplsEncap) -> Self {
        self.mpls_encap = Some(encap);
        self
    }

    /// Add SRv6 encapsulation.
    ///
    /// This causes the route to encapsulate packets with an SRv6 header.
    /// For IPv6 routes, you can use inline mode to insert the SRH into
    /// the existing IPv6 packet without adding a new outer header.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use std::net::Ipv6Addr;
    /// use nlink::netlink::route::Ipv6Route;
    /// use nlink::netlink::srv6::Srv6Encap;
    ///
    /// // Inline mode (insert SRH into IPv6 packet)
    /// let route = Ipv6Route::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32)
    ///     .dev("eth0")
    ///     .srv6_encap(
    ///         Srv6Encap::inline()
    ///             .segment("fc00:1::1".parse()?)
    ///     );
    ///
    /// // Encap mode (add outer IPv6 header with SRH)
    /// let route = Ipv6Route::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32)
    ///     .dev("eth0")
    ///     .srv6_encap(
    ///         Srv6Encap::encap()
    ///             .segments(&["fc00:1::1".parse()?, "fc00:2::1".parse()?])
    ///     );
    /// # Ok(())
    /// # }
    /// ```
    pub fn srv6_encap(mut self, encap: Srv6Encap) -> Self {
        self.srv6_encap = Some(encap);
        self
    }

    fn determine_scope(&self) -> RouteScope {
        if let Some(scope) = self.scope {
            return scope;
        }

        match self.route_type {
            RouteType::Local => RouteScope::Host,
            RouteType::Unicast | RouteType::Unspec => {
                if self.gateway.is_some() || self.multipath.is_some() || self.nexthop_id.is_some() {
                    RouteScope::Universe
                } else {
                    RouteScope::Link
                }
            }
            _ => RouteScope::Universe,
        }
    }
}

impl RouteConfig for Ipv6Route {
    fn device_ref(&self) -> Option<&InterfaceRef> {
        self.dev.as_ref()
    }

    fn multipath_device_refs(&self) -> Vec<Option<&InterfaceRef>> {
        match &self.multipath {
            Some(nexthops) => nexthops.iter().map(|nh| nh.device_ref()).collect(),
            None => Vec::new(),
        }
    }

    fn family(&self) -> u8 {
        AF_INET6
    }

    fn write_add(&self, builder: &mut MessageBuilder, interfaces: &ResolvedRouteInterfaces) {
        let table_u8 = if self.table > 255 {
            rt_table::UNSPEC
        } else {
            self.table as u8
        };

        let scope = self.determine_scope();

        let rtmsg = RtMsg::new()
            .with_family(AF_INET6)
            .with_dst_len(self.prefix_len)
            .with_table(table_u8)
            .with_protocol(self.protocol.number())
            .with_scope(scope as u8)
            .with_type(self.route_type as u8)
            .with_flags(self.flags);

        builder.append(&rtmsg);

        // RTA_DST
        if self.prefix_len > 0 {
            builder.append_attr(RtaAttr::Dst as u16, &self.destination.octets());
        }

        // RTA_GATEWAY
        if let Some(gw) = self.gateway {
            builder.append_attr(RtaAttr::Gateway as u16, &gw.octets());
        }

        // RTA_PREFSRC
        if let Some(src) = self.prefsrc {
            builder.append_attr(RtaAttr::Prefsrc as u16, &src.octets());
        }

        // RTA_OIF (from resolved interface)
        if let Some(ifindex) = interfaces.oif {
            builder.append_attr_u32(RtaAttr::Oif as u16, ifindex);
        }

        // RTA_TABLE
        if self.table > 255 {
            builder.append_attr_u32(RtaAttr::Table as u16, self.table);
        }

        // RTA_PRIORITY
        if let Some(prio) = self.priority {
            builder.append_attr_u32(RtaAttr::Priority as u16, prio);
        }

        // RTA_MARK
        if let Some(mark) = self.mark {
            builder.append_attr_u32(RtaAttr::Mark as u16, mark);
        }

        // RTA_PREF
        if let Some(pref) = self.pref {
            builder.append_attr_u8(RtaAttr::Pref as u16, pref);
        }

        // RTA_METRICS
        if let Some(ref metrics) = self.metrics
            && metrics.has_any()
        {
            metrics.write_to(builder);
        }

        // RTA_MULTIPATH
        if let Some(ref nexthops) = self.multipath {
            write_multipath_v6(builder, nexthops, &interfaces.multipath);
        }

        // RTA_NH_ID (nexthop group reference, Linux 5.3+)
        if let Some(nh_id) = self.nexthop_id {
            builder.append_attr_u32(RtaAttr::NhId as u16, nh_id);
        }

        // RTA_ENCAP_TYPE + RTA_ENCAP (MPLS encapsulation)
        if let Some(ref encap) = self.mpls_encap {
            encap.write_to(builder);
        }

        // RTA_ENCAP_TYPE + RTA_ENCAP (SRv6 encapsulation)
        if let Some(ref encap) = self.srv6_encap {
            encap.write_to(builder);
        }
    }

    fn write_delete(&self, builder: &mut MessageBuilder) {
        // Legacy delete path: see Ipv4Route::write_delete docs.
        let table_u8 = if self.table > 255 {
            rt_table::UNSPEC
        } else {
            self.table as u8
        };

        let rtmsg = RtMsg::new()
            .with_family(AF_INET6)
            .with_dst_len(self.prefix_len)
            .with_table(table_u8);

        builder.append(&rtmsg);

        // RTA_DST
        if self.prefix_len > 0 {
            builder.append_attr(RtaAttr::Dst as u16, &self.destination.octets());
        }

        // RTA_TABLE
        if self.table > 255 {
            builder.append_attr_u32(RtaAttr::Table as u16, self.table);
        }
    }

    fn write_delete_with_interfaces(
        &self,
        builder: &mut MessageBuilder,
        interfaces: &ResolvedRouteInterfaces,
    ) {
        // Strict-key delete (matches `write_add`'s discriminating
        // fields). See Ipv4Route::write_delete_with_interfaces for
        // rationale.
        let table_u8 = if self.table > 255 {
            rt_table::UNSPEC
        } else {
            self.table as u8
        };

        let scope = self.determine_scope();

        let rtmsg = RtMsg::new()
            .with_family(AF_INET6)
            .with_dst_len(self.prefix_len)
            .with_table(table_u8)
            .with_protocol(self.protocol.number())
            .with_scope(scope as u8)
            .with_type(self.route_type as u8)
            .with_flags(self.flags);

        builder.append(&rtmsg);

        if self.prefix_len > 0 {
            builder.append_attr(RtaAttr::Dst as u16, &self.destination.octets());
        }

        if let Some(gw) = self.gateway {
            builder.append_attr(RtaAttr::Gateway as u16, &gw.octets());
        }

        if let Some(src) = self.prefsrc {
            builder.append_attr(RtaAttr::Prefsrc as u16, &src.octets());
        }

        if let Some(ifindex) = interfaces.oif {
            builder.append_attr_u32(RtaAttr::Oif as u16, ifindex);
        }

        if self.table > 255 {
            builder.append_attr_u32(RtaAttr::Table as u16, self.table);
        }

        if let Some(prio) = self.priority {
            builder.append_attr_u32(RtaAttr::Priority as u16, prio);
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Write IPv4 multipath nexthops with resolved interface indices.
fn write_multipath_v4(
    builder: &mut MessageBuilder,
    nexthops: &[NextHop],
    resolved_indices: &[Option<u32>],
) {
    // Build the multipath attribute payload
    let mut mp_data = Vec::new();

    for (i, nh) in nexthops.iter().enumerate() {
        let ifindex = resolved_indices.get(i).copied().flatten().unwrap_or(0);

        // Calculate the length of this nexthop entry: rtnexthop (8 bytes),
        // then RTA_GATEWAY for an IPv4 gateway (4 + 4 bytes) or RTA_VIA for
        // an IPv6 one (`struct rtvia`: 4 + 2 + 16 bytes, padded to 24; RFC
        // 5549, #786). An IPv6 gateway used to go nowhere: the hop was
        // installed through its bare device.
        let mut nh_len: u16 = 8; // sizeof(rtnexthop)
        if nh.gateway_v4.is_some() {
            nh_len += 8; // NLA header (4) + IPv4 address (4)
        } else if nh.gateway_v6.is_some() {
            nh_len += 24;
        }

        // Write rtnexthop header
        mp_data.extend_from_slice(&nh_len.to_ne_bytes());
        mp_data.push(nh.flags);
        mp_data.push((nh.weight.clamp(1, 256) - 1) as u8); // hops = weight - 1
        mp_data.extend_from_slice(&ifindex.to_ne_bytes());

        // Write RTA_GATEWAY if present
        if let Some(gw) = nh.gateway_v4 {
            // NLA header
            let nla_len: u16 = 4 + 4; // header + data
            mp_data.extend_from_slice(&nla_len.to_ne_bytes());
            mp_data.extend_from_slice(&(RtaAttr::Gateway as u16).to_ne_bytes());
            mp_data.extend_from_slice(&gw.octets());
        } else if let Some(gw) = nh.gateway_v6 {
            let nla_len: u16 = 4 + 2 + 16;
            mp_data.extend_from_slice(&nla_len.to_ne_bytes());
            mp_data.extend_from_slice(&(RtaAttr::Via as u16).to_ne_bytes());
            mp_data.extend_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            mp_data.extend_from_slice(&gw.octets());
            mp_data.extend_from_slice(&[0, 0]); // pad to 4
        }
    }

    builder.append_attr(RtaAttr::Multipath as u16, &mp_data);
}

/// Write IPv6 multipath nexthops with resolved interface indices.
fn write_multipath_v6(
    builder: &mut MessageBuilder,
    nexthops: &[NextHop],
    resolved_indices: &[Option<u32>],
) {
    let mut mp_data = Vec::new();

    for (i, nh) in nexthops.iter().enumerate() {
        let ifindex = resolved_indices.get(i).copied().flatten().unwrap_or(0);

        let mut nh_len: u16 = 8;
        if nh.gateway_v6.is_some() {
            nh_len += 4 + 16; // NLA header + IPv6 address
        }

        // Write rtnexthop header
        mp_data.extend_from_slice(&nh_len.to_ne_bytes());
        mp_data.push(nh.flags);
        mp_data.push((nh.weight.clamp(1, 256) - 1) as u8);
        mp_data.extend_from_slice(&ifindex.to_ne_bytes());

        // Write RTA_GATEWAY if present
        if let Some(gw) = nh.gateway_v6 {
            let nla_len: u16 = 4 + 16;
            mp_data.extend_from_slice(&nla_len.to_ne_bytes());
            mp_data.extend_from_slice(&(RtaAttr::Gateway as u16).to_ne_bytes());
            mp_data.extend_from_slice(&gw.octets());
        }
    }

    builder.append_attr(RtaAttr::Multipath as u16, &mp_data);
}

// ============================================================================
// Connection Methods
// ============================================================================

/// NLM_F_REPLACE flag
const NLM_F_REPLACE: u16 = 0x100;

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Resolve all interface references for a route configuration.
    async fn resolve_route_interfaces<R: RouteConfig>(
        &self,
        config: &R,
    ) -> Result<ResolvedRouteInterfaces> {
        // Resolve main output interface
        let oif = match config.device_ref() {
            Some(iface) => Some(self.resolve_interface(iface).await?),
            None => None,
        };

        // Resolve multipath nexthop interfaces
        let mp_refs = config.multipath_device_refs();
        let mut multipath = Vec::with_capacity(mp_refs.len());
        for iface_opt in mp_refs {
            match iface_opt {
                Some(iface) => multipath.push(Some(self.resolve_interface(iface).await?)),
                None => multipath.push(None),
            }
        }

        Ok(ResolvedRouteInterfaces { oif, multipath })
    }

    /// Add a route.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::route::{Ipv4Route, Ipv6Route};
    /// use std::net::{Ipv4Addr, Ipv6Addr};
    ///
    /// // Add IPv4 route
    /// conn.add_route(
    ///     Ipv4Route::new(Ipv4Addr::new(192, 168, 2, 0), 24)
    ///         .gateway(Ipv4Addr::new(192, 168, 1, 1))
    /// ).await?;
    ///
    /// // Add IPv6 route
    /// conn.add_route(
    ///     Ipv6Route::new(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0), 48)
    ///         .gateway("2001:db8::1".parse()?)
    /// ).await?;
    ///
    /// // Add route with interface by index (namespace-safe)
    /// conn.add_route(
    ///     Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
    ///         .dev_index(5)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn add_route<R: RouteConfig>(&self, config: R) -> Result<()> {
        let interfaces = self.resolve_route_interfaces(&config).await?;
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        config.write_add(&mut builder, &interfaces);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_route"))
    }

    /// Delete a route using a config.
    ///
    /// Resolves any device references (`.dev("eth0")`) to ifindex
    /// and calls [`RouteConfig::write_delete_with_interfaces`] so
    /// the kernel matches the route on the full key — newer
    /// kernels return `ESRCH` if the request omits fields the
    /// original `add` set (e.g. `RTA_OIF` when the route was
    /// added with `.dev(...)`).
    pub async fn del_route<R: RouteConfig>(&self, config: R) -> Result<()> {
        let interfaces = self.resolve_route_interfaces(&config).await?;
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK);
        config.write_delete_with_interfaces(&mut builder, &interfaces);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_route"))
    }

    /// Delete a route if it exists. `Ok(true)` if the kernel removed
    /// it, `Ok(false)` if there was nothing to remove (`ESRCH` /
    /// `ENOENT`).
    ///
    /// The table-aware, full-key sibling of
    /// [`Self::del_route_v4_if_exists`] / [`Self::del_route_v6_if_exists`],
    /// which take a bare destination and so can only name a main-table
    /// route. Pass the same gateway / device / metric / table the route
    /// was added with; newer kernels answer `ESRCH` to a partial key,
    /// and that is then reported as "absent" (#335).
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use std::net::Ipv4Addr;
    /// use nlink::netlink::route::Ipv4Route;
    /// let gone = conn
    ///     .del_route_if_exists(Ipv4Route::new(Ipv4Addr::new(10, 2, 0, 0), 24).dev("eth1").table(100))
    ///     .await?;
    /// # let _ = gone;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_route_if_exists"))]
    pub async fn del_route_if_exists<R: RouteConfig>(&self, config: R) -> Result<bool> {
        match self.del_route(config).await {
            Ok(()) => Ok(true),
            // A delete that matches nothing is ESRCH, which `is_not_found()`
            // reads as such for a route delete (#526).
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Delete an IPv4 route by destination.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # use std::net::Ipv4Addr;
    /// conn.del_route_v4(Ipv4Addr::new(192, 168, 2, 0), 24).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_route_v4"))]
    pub async fn del_route_v4(&self, destination: Ipv4Addr, prefix_len: u8) -> Result<()> {
        let route = Ipv4Route::new(destination, prefix_len);
        self.del_route(route).await
    }

    /// Delete an IPv6 route by destination.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_route_v6"))]
    pub async fn del_route_v6(&self, destination: Ipv6Addr, prefix_len: u8) -> Result<()> {
        let route = Ipv6Route::new(destination, prefix_len);
        self.del_route(route).await
    }

    /// Delete an IPv4 route if it exists. Returns `Ok(true)` if the
    /// route was deleted, `Ok(false)` if it didn't exist. Unlike
    /// [`Self::del_route_v4`], does NOT error on `ESRCH`/`ENOENT`
    /// (#169; mirrors the nftables `del_*_if_exists` family).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_route_v4_if_exists"))]
    pub async fn del_route_v4_if_exists(
        &self,
        destination: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<bool> {
        match self.del_route_v4(destination, prefix_len).await {
            Ok(()) => Ok(true),
            // A delete that matches nothing is ESRCH, which `is_not_found()`
            // reads as such for a route delete (#526).
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Delete an IPv6 route if it exists. See
    /// [`Self::del_route_v4_if_exists`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_route_v6_if_exists"))]
    pub async fn del_route_v6_if_exists(
        &self,
        destination: Ipv6Addr,
        prefix_len: u8,
    ) -> Result<bool> {
        match self.del_route_v6(destination, prefix_len).await {
            Ok(()) => Ok(true),
            // A delete that matches nothing is ESRCH, which `is_not_found()`
            // reads as such for a route delete (#526).
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Replace a route (add or update).
    ///
    /// If the route exists, it will be updated. Otherwise, it will be created.
    pub async fn replace_route<R: RouteConfig>(&self, config: R) -> Result<()> {
        let interfaces = self.resolve_route_interfaces(&config).await?;
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        config.write_add(&mut builder, &interfaces);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("replace_route"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Plan 184 — default_route constructors ----

    #[test]
    fn ipv4_default_route_is_unspecified_slash_zero() {
        let r = Ipv4Route::default_route();
        assert_eq!(r.destination, Ipv4Addr::UNSPECIFIED);
        assert_eq!(r.prefix_len, 0);
    }

    #[test]
    fn ipv6_default_route_is_unspecified_slash_zero() {
        let r = Ipv6Route::default_route();
        assert_eq!(r.destination, Ipv6Addr::UNSPECIFIED);
        assert_eq!(r.prefix_len, 0);
    }

    #[test]
    fn default_route_equals_explicit_new() {
        // Same destination/prefix as the explicit form. Documents the
        // equivalence.
        assert_eq!(
            Ipv4Route::default_route().destination,
            Ipv4Route::new(Ipv4Addr::UNSPECIFIED, 0).destination
        );
        assert_eq!(
            Ipv6Route::default_route().destination,
            Ipv6Route::new(Ipv6Addr::UNSPECIFIED, 0).destination
        );
    }
}
