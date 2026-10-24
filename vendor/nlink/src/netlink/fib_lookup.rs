//! FIB lookup implementation for `Connection<FibLookup>`.
//!
//! This module provides methods for performing FIB (Forwarding Information Base)
//! route lookups via the NETLINK_FIB_LOOKUP protocol.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, FibLookup};
//! use std::net::Ipv4Addr;
//!
//! let conn = Connection::<FibLookup>::new()?;
//!
//! // Look up a route for an IP address
//! let result = conn.lookup(Ipv4Addr::new(8, 8, 8, 8)).await?;
//! println!("Route type: {:?}, table: {}, prefix_len: {}",
//!     result.route_type, result.table_id, result.prefix_len);
//! # Ok(())
//! # }
//! ```

use std::net::Ipv4Addr;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::{
    connection::Connection,
    error::{Error, Result},
    protocol::{FibLookup, ProtocolState},
    socket::NetlinkSocket,
};

// Netlink constants
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;

// Netlink header size
const NLMSG_HDRLEN: usize = 16;

/// FIB result message structure.
///
/// This structure is sent to and received from the kernel for FIB lookups.
/// The kernel fills in the result fields after processing the lookup request.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FibResultNl {
    /// Address to look up (network byte order).
    pub fl_addr: u32,
    /// Firewall mark.
    pub fl_fwmark: u32,
    /// Type of Service.
    pub fl_tos: u8,
    /// Scope for the lookup.
    pub fl_scope: u8,
    /// Input table ID.
    pub tb_id_in: u8,
    /// Result: table ID where route was found.
    pub tb_id: u8,
    /// Result: prefix length of the matched route.
    pub prefixlen: u8,
    /// Result: next hop selector.
    pub nh_sel: u8,
    /// Result: route type.
    pub route_type: u8,
    /// Result: scope.
    pub scope: u8,
    /// Result: error code.
    pub err: i32,
}

impl FibResultNl {
    /// Create a new FIB lookup request for an IPv4 address.
    pub fn for_addr(addr: Ipv4Addr) -> Self {
        Self {
            fl_addr: u32::from_ne_bytes(addr.octets()),
            ..Default::default()
        }
    }

    /// Create a new FIB lookup request with a specific table.
    pub fn for_addr_in_table(addr: Ipv4Addr, table: u8) -> Self {
        Self {
            fl_addr: u32::from_ne_bytes(addr.octets()),
            tb_id_in: table,
            ..Default::default()
        }
    }

    /// Create a new FIB lookup request with a firewall mark.
    pub fn for_addr_with_mark(addr: Ipv4Addr, mark: u32) -> Self {
        Self {
            fl_addr: u32::from_ne_bytes(addr.octets()),
            fl_fwmark: mark,
            ..Default::default()
        }
    }

    /// Get the looked up address as an IPv4 address.
    /// The address this request looks up.
    ///
    /// `fl_addr` is a `__be32` in a `#[repr(C)]` struct that is serialized
    /// natively, so the octets are stored in network order and read back the
    /// same way — `to_ne_bytes`, not `to_be_bytes`.
    ///
    /// Before 0.26 both halves used the big-endian form, which byte-reversed
    /// the address on every little-endian host. The two errors cancelled
    /// in-process, so a round-trip test passed while every lookup asked the
    /// kernel about a different address (#261).
    pub fn addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.fl_addr.to_ne_bytes())
    }
}

/// Route type from FIB lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteType {
    /// Unknown or unspecified.
    Unspec,
    /// Local address.
    Local,
    /// Unicast route.
    Unicast,
    /// Broadcast route.
    Broadcast,
    /// Anycast route.
    Anycast,
    /// Multicast route.
    Multicast,
    /// Blackhole route (silently drop).
    Blackhole,
    /// Unreachable (generate ICMP unreachable).
    Unreachable,
    /// Prohibit (generate ICMP prohibited).
    Prohibit,
    /// Throw (continue lookup in another table).
    Throw,
    /// NAT route.
    Nat,
    /// External resolver.
    XResolve,
    /// Unknown type.
    Unknown(u8),
}

impl RouteType {
    fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Unspec,
            1 => Self::Unicast,
            2 => Self::Local,
            3 => Self::Broadcast,
            4 => Self::Anycast,
            5 => Self::Multicast,
            6 => Self::Blackhole,
            7 => Self::Unreachable,
            8 => Self::Prohibit,
            9 => Self::Throw,
            10 => Self::Nat,
            11 => Self::XResolve,
            other => Self::Unknown(other),
        }
    }

    /// Get the route type number.
    pub fn number(&self) -> u8 {
        match self {
            Self::Unspec => 0,
            Self::Unicast => 1,
            Self::Local => 2,
            Self::Broadcast => 3,
            Self::Anycast => 4,
            Self::Multicast => 5,
            Self::Blackhole => 6,
            Self::Unreachable => 7,
            Self::Prohibit => 8,
            Self::Throw => 9,
            Self::Nat => 10,
            Self::XResolve => 11,
            Self::Unknown(n) => *n,
        }
    }
}

/// Route scope from FIB lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteScope {
    /// Universe (global) scope.
    Universe,
    /// Site scope.
    Site,
    /// Link scope.
    Link,
    /// Host scope.
    Host,
    /// Nowhere scope.
    Nowhere,
    /// Unknown scope.
    Unknown(u8),
}

impl RouteScope {
    fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Universe,
            200 => Self::Site,
            253 => Self::Link,
            254 => Self::Host,
            255 => Self::Nowhere,
            other => Self::Unknown(other),
        }
    }

    /// Get the scope number.
    pub fn number(&self) -> u8 {
        match self {
            Self::Universe => 0,
            Self::Site => 200,
            Self::Link => 253,
            Self::Host => 254,
            Self::Nowhere => 255,
            Self::Unknown(n) => *n,
        }
    }
}

/// Result of a FIB lookup.
#[derive(Debug, Clone)]
pub struct FibLookupResult {
    /// The address that was looked up.
    pub addr: Ipv4Addr,
    /// The routing table where the route was found.
    pub table_id: u8,
    /// The prefix length of the matched route.
    pub prefix_len: u8,
    /// The route type.
    pub route_type: RouteType,
    /// The route scope.
    pub scope: RouteScope,
    /// The next hop selector.
    pub nh_sel: u8,
    /// Error code (0 = success).
    pub error: i32,
}

impl FibLookupResult {
    /// Returns true if the lookup was successful.
    pub fn is_success(&self) -> bool {
        self.error == 0
    }

    /// Returns true if the route is a local address.
    pub fn is_local(&self) -> bool {
        self.route_type == RouteType::Local
    }

    /// Returns true if the route is a unicast route.
    pub fn is_unicast(&self) -> bool {
        self.route_type == RouteType::Unicast
    }

    /// Returns true if the route is a blackhole.
    pub fn is_blackhole(&self) -> bool {
        self.route_type == RouteType::Blackhole
    }

    /// Returns true if the destination is unreachable.
    pub fn is_unreachable(&self) -> bool {
        self.route_type == RouteType::Unreachable
    }
}

#[nlink_macros::send_futures]
impl Connection<FibLookup> {
    /// Create a new FIB lookup connection.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, FibLookup};
    ///
    /// let conn = Connection::<FibLookup>::new()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Result<Self> {
        let socket = NetlinkSocket::new(FibLookup::PROTOCOL)?;
        Ok(Self::from_parts(socket, FibLookup))
    }

    /// Look up a route for an IPv4 address.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, FibLookup};
    /// use std::net::Ipv4Addr;
    ///
    /// let conn = Connection::<FibLookup>::new()?;
    /// let result = conn.lookup(Ipv4Addr::new(8, 8, 8, 8)).await?;
    ///
    /// if result.is_success() {
    ///     println!("Route found: type={:?}, table={}, prefix=/{}",
    ///         result.route_type, result.table_id, result.prefix_len);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "lookup"))]
    pub async fn lookup(&self, addr: Ipv4Addr) -> Result<FibLookupResult> {
        self.lookup_with_options(FibResultNl::for_addr(addr)).await
    }

    /// Look up a route for an IPv4 address in a specific routing table.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, FibLookup};
    /// use std::net::Ipv4Addr;
    ///
    /// let conn = Connection::<FibLookup>::new()?;
    /// // Look up in table 254 (main)
    /// let result = conn.lookup_in_table(Ipv4Addr::new(10, 0, 0, 1), 254).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "lookup_in_table"))]
    pub async fn lookup_in_table(&self, addr: Ipv4Addr, table: u8) -> Result<FibLookupResult> {
        self.lookup_with_options(FibResultNl::for_addr_in_table(addr, table))
            .await
    }

    /// Look up a route for an IPv4 address with a specific firewall mark.
    ///
    /// Firewall marks can be used for policy routing decisions.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, FibLookup};
    /// use std::net::Ipv4Addr;
    ///
    /// let conn = Connection::<FibLookup>::new()?;
    /// let result = conn.lookup_with_mark(Ipv4Addr::new(8, 8, 8, 8), 0x100).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "lookup_with_mark"))]
    pub async fn lookup_with_mark(&self, addr: Ipv4Addr, mark: u32) -> Result<FibLookupResult> {
        self.lookup_with_options(FibResultNl::for_addr_with_mark(addr, mark))
            .await
    }

    /// Look up a route with custom options.
    ///
    /// This method allows full control over the lookup parameters.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, FibLookup};
    /// use nlink::netlink::fib_lookup::FibResultNl;
    /// use std::net::Ipv4Addr;
    ///
    /// let conn = Connection::<FibLookup>::new()?;
    /// let request = FibResultNl {
    ///     fl_addr: u32::from_ne_bytes(Ipv4Addr::new(1, 1, 1, 1).octets()),
    ///     fl_tos: 0x10,  // Specific TOS value
    ///     ..Default::default()
    /// };
    /// let result = conn.lookup_with_options(request).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "lookup_with_options"))]
    pub async fn lookup_with_options(&self, request: FibResultNl) -> Result<FibLookupResult> {
        // Plan 208 Phase 1 — wrap in with_timeout + seq filter loop.
        // Pre-0.19 this raw-recv'd a single frame with no seq check
        // and no timeout. A kernel that dropped the response hung
        // forever; a stale frame on the socket would have been
        // mistaken for the response.
        self.with_timeout(async move {
            let seq = self.socket().next_seq();
            let mut session = self.recv_session(seq).await?;
            let pid = self.socket().pid();

            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len
            buf.extend_from_slice(&0u16.to_ne_bytes()); // nlmsg_type
            buf.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
            buf.extend_from_slice(&seq.to_ne_bytes());
            buf.extend_from_slice(&pid.to_ne_bytes());
            buf.extend_from_slice(request.as_bytes());

            let len = buf.len() as u32;
            buf[0..4].copy_from_slice(&len.to_ne_bytes());

            self.socket().send(&buf).await?;

            loop {
                let data = session.recv_with_timeout(self).await?;
                if data.len() < NLMSG_HDRLEN {
                    return Err(Error::invalid_message("response too short"));
                }

                let resp_seq =
                    u32::from_ne_bytes([data[8], data[9], data[10], data[11]]);
                if resp_seq != seq {
                    continue;
                }

                let nlmsg_type = u16::from_ne_bytes([data[4], data[5]]);
                if nlmsg_type == NLMSG_ERROR && data.len() >= 20 {
                    let errno =
                        i32::from_ne_bytes([data[16], data[17], data[18], data[19]]);
                    if errno != 0 {
                        return Err(Error::from_errno(-errno));
                    }
                }

                if data.len() < NLMSG_HDRLEN + std::mem::size_of::<FibResultNl>() {
                    return Err(Error::invalid_message(
                        "response too short for FIB result",
                    ));
                }

                let (result, _) = FibResultNl::ref_from_prefix(&data[NLMSG_HDRLEN..])
                    .map_err(|_| Error::invalid_message("failed to parse FIB result"))?;

                return Ok(FibLookupResult {
                    addr: result.addr(),
                    table_id: result.tb_id,
                    prefix_len: result.prefixlen,
                    route_type: RouteType::from_u8(result.route_type),
                    scope: RouteScope::from_u8(result.scope),
                    nh_sel: result.nh_sel,
                    error: result.err,
                });
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use zerocopy::IntoBytes;

    /// The address must reach the wire in network byte order.
    ///
    /// This asserts the *emitted bytes*, not a round-trip, and uses a
    /// deliberately non-palindromic address — because a round-trip is exactly
    /// what hid the original bug. `for_addr` used `from_be_bytes` while
    /// `addr()` used `to_be_bytes`, so the two errors cancelled in-process and
    /// every in-crate test agreed with itself while the kernel was asked about
    /// a byte-reversed address (#261).
    ///
    /// The old doc example compounded it by using `8.8.8.8`, which reverses to
    /// itself.
    #[test]
    fn lookup_address_reaches_the_wire_in_network_order() {
        let req = FibResultNl::for_addr(Ipv4Addr::new(10, 0, 0, 1));
        let bytes = req.as_bytes();

        // `fl_addr` is the first field of the struct.
        assert_eq!(
            &bytes[..4],
            &[10, 0, 0, 1],
            "fl_addr must be network order on the wire"
        );
        assert_ne!(
            &bytes[..4],
            &[1, 0, 0, 10],
            "regression: the address is byte-reversed again"
        );
    }

    /// A non-palindromic address must survive the accessor too — the reader
    /// and the writer have to agree with the *wire*, not merely with each
    /// other.
    #[test]
    fn addr_accessor_agrees_with_the_wire() {
        for octets in [[10, 0, 0, 1], [192, 168, 1, 254], [1, 2, 3, 4]] {
            let addr = Ipv4Addr::from(octets);
            let req = FibResultNl::for_addr(addr);
            assert_eq!(req.addr(), addr);
            assert_eq!(&req.as_bytes()[..4], &octets);
        }
    }

    #[test]
    fn fib_result_nl_size() {
        // The structure is 20 bytes (4 + 4 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 4)
        // with padding for i32 alignment
        assert_eq!(std::mem::size_of::<FibResultNl>(), 20);
    }

    #[test]
    fn fib_result_for_addr() {
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        let result = FibResultNl::for_addr(addr);
        assert_eq!(result.addr(), addr);
        assert_eq!(result.fl_fwmark, 0);
        assert_eq!(result.tb_id_in, 0);
    }

    #[test]
    fn fib_result_for_addr_in_table() {
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let result = FibResultNl::for_addr_in_table(addr, 254);
        assert_eq!(result.addr(), addr);
        assert_eq!(result.tb_id_in, 254);
    }

    #[test]
    fn route_type_roundtrip() {
        assert_eq!(RouteType::Unicast.number(), 1);
        assert_eq!(RouteType::from_u8(1), RouteType::Unicast);

        assert_eq!(RouteType::Local.number(), 2);
        assert_eq!(RouteType::from_u8(2), RouteType::Local);

        assert_eq!(RouteType::Blackhole.number(), 6);
        assert_eq!(RouteType::from_u8(6), RouteType::Blackhole);
    }

    #[test]
    fn route_scope_roundtrip() {
        assert_eq!(RouteScope::Universe.number(), 0);
        assert_eq!(RouteScope::from_u8(0), RouteScope::Universe);

        assert_eq!(RouteScope::Link.number(), 253);
        assert_eq!(RouteScope::from_u8(253), RouteScope::Link);

        assert_eq!(RouteScope::Host.number(), 254);
        assert_eq!(RouteScope::from_u8(254), RouteScope::Host);
    }

    #[test]
    fn fib_lookup_result_helpers() {
        let result = FibLookupResult {
            addr: Ipv4Addr::new(8, 8, 8, 8),
            table_id: 254,
            prefix_len: 0,
            route_type: RouteType::Unicast,
            scope: RouteScope::Universe,
            nh_sel: 0,
            error: 0,
        };

        assert!(result.is_success());
        assert!(result.is_unicast());
        assert!(!result.is_local());
        assert!(!result.is_blackhole());
    }
}
