//! MPTCP types and builders.

use std::net::{IpAddr, Ipv4Addr};

use crate::netlink::types::mptcp::mptcp_pm_flags;

/// MPTCP endpoint flags.
///
/// These flags control how an endpoint is used for MPTCP connections.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MptcpFlags {
    /// Announce this endpoint to peers via ADD_ADDR.
    pub signal: bool,
    /// Use this endpoint for creating new subflows.
    pub subflow: bool,
    /// Mark as backup path (lower priority).
    pub backup: bool,
    /// Create subflows to all peer addresses (fullmesh).
    pub fullmesh: bool,
}

impl MptcpFlags {
    /// Create flags from a raw u32 value.
    pub fn from_raw(flags: u32) -> Self {
        Self {
            signal: flags & mptcp_pm_flags::SIGNAL != 0,
            subflow: flags & mptcp_pm_flags::SUBFLOW != 0,
            backup: flags & mptcp_pm_flags::BACKUP != 0,
            fullmesh: flags & mptcp_pm_flags::FULLMESH != 0,
        }
    }

    /// Convert flags to raw u32 value.
    pub fn to_raw(self) -> u32 {
        let mut flags = 0u32;
        if self.signal {
            flags |= mptcp_pm_flags::SIGNAL;
        }
        if self.subflow {
            flags |= mptcp_pm_flags::SUBFLOW;
        }
        if self.backup {
            flags |= mptcp_pm_flags::BACKUP;
        }
        if self.fullmesh {
            flags |= mptcp_pm_flags::FULLMESH;
        }
        flags
    }

    /// Check if any flags are set.
    pub fn is_empty(&self) -> bool {
        !self.signal && !self.subflow && !self.backup && !self.fullmesh
    }
}

/// Parsed MPTCP endpoint information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MptcpEndpoint {
    /// Endpoint ID (0-255).
    pub id: u8,
    /// IP address of the endpoint.
    pub address: IpAddr,
    /// Optional port number.
    pub port: Option<u16>,
    /// Optional interface index.
    pub ifindex: Option<u32>,
    /// Endpoint flags.
    pub flags: MptcpFlags,
}

impl Default for MptcpEndpoint {
    fn default() -> Self {
        Self {
            id: 0,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: None,
            ifindex: None,
            flags: MptcpFlags::default(),
        }
    }
}

impl MptcpEndpoint {
    /// Check if this is a signal endpoint.
    pub fn is_signal(&self) -> bool {
        self.flags.signal
    }

    /// Check if this is a subflow endpoint.
    pub fn is_subflow(&self) -> bool {
        self.flags.subflow
    }

    /// Check if this is a backup endpoint.
    pub fn is_backup(&self) -> bool {
        self.flags.backup
    }

    /// Check if this is a fullmesh endpoint.
    pub fn is_fullmesh(&self) -> bool {
        self.flags.fullmesh
    }
}

/// Builder for MPTCP endpoint configuration.
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct MptcpEndpointBuilder {
    /// Endpoint ID (optional, kernel assigns if not set).
    pub(crate) id: Option<u8>,
    /// IP address of the endpoint.
    pub(crate) address: IpAddr,
    /// Optional port number.
    pub(crate) port: Option<u16>,
    /// Interface index.
    ///
    /// There used to be a `dev(name)` setter here, documented as "the
    /// device name will be resolved to an interface index". No
    /// resolution ever happened — the field had zero read sites and the
    /// writer emitted `IF_IDX` only from this one — so an endpoint
    /// built with `.dev(...)` reached the kernel with **no interface
    /// binding at all** and the path manager chose addresses on
    /// whatever interface it liked (#275).
    ///
    /// It is gone rather than wired up. A `Connection<Mptcp>` lives in
    /// one netns and cannot resolve a name in it — the only route
    /// available is a fresh `Connection<Route>` in the *calling
    /// process's* netns, which is the namespace footgun the crate
    /// exists to avoid. Resolve through a connection in the right
    /// namespace and pass the index:
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use std::net::IpAddr;
    /// use nlink::netlink::genl::mptcp::MptcpEndpointBuilder;
    /// use std::net::Ipv4Addr;
    ///
    /// let route_conn = nlink::Connection::<nlink::Route>::new()?;
    /// let ifindex = route_conn
    ///     .get_link_by_name("eth1")
    ///     .await?
    ///     .expect("eth1 exists in this namespace")
    ///     .ifindex();
    /// let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    /// let endpoint = MptcpEndpointBuilder::new(addr).ifindex(ifindex);
    /// # Ok(())
    /// # }
    /// ```
    pub(crate) ifindex: Option<u32>,
    /// Endpoint flags.
    pub(crate) flags: MptcpFlags,
}

impl MptcpEndpointBuilder {
    /// Create a new endpoint builder with the given address.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::net::IpAddr;
    /// use nlink::netlink::genl::mptcp::MptcpEndpointBuilder;
    /// use std::net::Ipv4Addr;
    ///
    /// let builder = MptcpEndpointBuilder::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
    ///     .id(1)
    ///     .subflow()
    ///     .signal();
    /// ```
    pub fn new(address: IpAddr) -> Self {
        Self {
            id: None,
            address,
            port: None,
            ifindex: None,
            flags: MptcpFlags::default(),
        }
    }

    /// Set the endpoint ID (0-255).
    ///
    /// If not set, the kernel will assign an ID automatically.
    pub fn id(mut self, id: u8) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the port number.
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the interface index directly.
    pub fn ifindex(mut self, ifindex: u32) -> Self {
        self.ifindex = Some(ifindex);
        self
    }

    /// Set the signal flag (announce to peers).
    pub fn signal(mut self) -> Self {
        self.flags.signal = true;
        self
    }

    /// Set the subflow flag (use for new subflows).
    pub fn subflow(mut self) -> Self {
        self.flags.subflow = true;
        self
    }

    /// Set the backup flag (lower priority path).
    pub fn backup(mut self) -> Self {
        self.flags.backup = true;
        self
    }

    /// Set the fullmesh flag (connect to all peer addresses).
    pub fn fullmesh(mut self) -> Self {
        self.flags.fullmesh = true;
        self
    }

    /// Set all flags at once.
    pub fn flags(mut self, flags: MptcpFlags) -> Self {
        self.flags = flags;
        self
    }
}

/// MPTCP limits configuration.
///
/// These limits control the maximum number of subflows and addresses
/// that can be used per MPTCP connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MptcpLimits {
    /// Maximum subflows per connection.
    pub subflows: Option<u32>,
    /// Maximum additional addresses to accept from peers.
    pub add_addr_accepted: Option<u32>,
}

impl MptcpLimits {
    /// Create a new limits builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum subflows per connection.
    pub fn subflows(mut self, max: u32) -> Self {
        self.subflows = Some(max);
        self
    }

    /// Set maximum additional addresses to accept from peers.
    pub fn add_addr_accepted(mut self, max: u32) -> Self {
        self.add_addr_accepted = Some(max);
        self
    }
}

// ============================================================================
// Per-Connection Operations (Subflow Management)
// ============================================================================

/// Address specification for subflow operations.
///
/// Used to specify source or destination addresses for subflow create/destroy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MptcpAddress {
    /// IP address.
    pub addr: IpAddr,
    /// Optional port number.
    pub port: Option<u16>,
}

impl MptcpAddress {
    /// Create a new address specification.
    pub fn new(addr: IpAddr) -> Self {
        Self { addr, port: None }
    }

    /// Create a new address with port.
    pub fn with_port(addr: IpAddr, port: u16) -> Self {
        Self {
            addr,
            port: Some(port),
        }
    }
}

impl From<IpAddr> for MptcpAddress {
    fn from(addr: IpAddr) -> Self {
        Self::new(addr)
    }
}

impl From<std::net::SocketAddr> for MptcpAddress {
    fn from(addr: std::net::SocketAddr) -> Self {
        Self {
            addr: addr.ip(),
            port: Some(addr.port()),
        }
    }
}

/// Builder for subflow creation.
///
/// Creates a new subflow on an existing MPTCP connection.
///
/// # Example
///
/// ```no_run
/// # use std::net::IpAddr;
/// # let connection_token: u32 = 0;
/// use nlink::netlink::genl::mptcp::MptcpSubflowBuilder;
/// use std::net::Ipv4Addr;
///
/// // Create subflow from local address to remote address
/// let subflow = MptcpSubflowBuilder::new(connection_token)
///     .local_addr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
///     .local_id(1)
///     .remote_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
///     .remote_port(80);
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct MptcpSubflowBuilder {
    /// Connection token (identifies the MPTCP connection).
    pub(crate) token: u32,
    /// Local address ID.
    pub(crate) local_id: Option<u8>,
    /// Remote address ID.
    pub(crate) remote_id: Option<u8>,
    /// Local address.
    pub(crate) local_addr: Option<MptcpAddress>,
    /// Remote address.
    pub(crate) remote_addr: Option<MptcpAddress>,
    /// Interface index.
    pub(crate) ifindex: Option<u32>,
    /// Device name (resolved to ifindex).
    /// Backup flag.
    pub(crate) backup: bool,
}

impl MptcpSubflowBuilder {
    /// Create a new subflow builder for the given connection token.
    ///
    /// The token identifies the MPTCP connection and can be obtained from
    /// the socket options or MPTCP events.
    pub fn new(token: u32) -> Self {
        Self {
            token,
            local_id: None,
            remote_id: None,
            local_addr: None,
            remote_addr: None,
            ifindex: None,
            backup: false,
        }
    }

    /// Set the local address ID.
    pub fn local_id(mut self, id: u8) -> Self {
        self.local_id = Some(id);
        self
    }

    /// Set the remote address ID.
    pub fn remote_id(mut self, id: u8) -> Self {
        self.remote_id = Some(id);
        self
    }

    /// Set the local address.
    pub fn local_addr(mut self, addr: impl Into<MptcpAddress>) -> Self {
        self.local_addr = Some(addr.into());
        self
    }

    /// Set the local port.
    pub fn local_port(mut self, port: u16) -> Self {
        if let Some(ref mut addr) = self.local_addr {
            addr.port = Some(port);
        }
        self
    }

    /// Set the remote address.
    pub fn remote_addr(mut self, addr: impl Into<MptcpAddress>) -> Self {
        self.remote_addr = Some(addr.into());
        self
    }

    /// Set the remote port.
    pub fn remote_port(mut self, port: u16) -> Self {
        if let Some(ref mut addr) = self.remote_addr {
            addr.port = Some(port);
        }
        self
    }

    /// Set the interface index directly.
    pub fn ifindex(mut self, ifindex: u32) -> Self {
        self.ifindex = Some(ifindex);
        self
    }

    /// Mark this subflow as a backup path.
    pub fn backup(mut self) -> Self {
        self.backup = true;
        self
    }
}

/// Builder for address announcement on a specific connection.
///
/// Announces a local address to the peer on a specific MPTCP connection.
///
/// # Example
///
/// ```no_run
/// # use std::net::IpAddr;
/// # let connection_token: u32 = 0;
/// use nlink::netlink::genl::mptcp::MptcpAnnounceBuilder;
/// use std::net::Ipv4Addr;
///
/// // Announce address ID 1 to the peer
/// let announce = MptcpAnnounceBuilder::new(connection_token)
///     .addr_id(1)
///     .address(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)));
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct MptcpAnnounceBuilder {
    /// Connection token.
    pub(crate) token: u32,
    /// Address ID to announce.
    pub(crate) addr_id: Option<u8>,
    /// Address to announce.
    pub(crate) address: Option<MptcpAddress>,
}

impl MptcpAnnounceBuilder {
    /// Create a new announce builder for the given connection token.
    pub fn new(token: u32) -> Self {
        Self {
            token,
            addr_id: None,
            address: None,
        }
    }

    /// Set the address ID to announce.
    pub fn addr_id(mut self, id: u8) -> Self {
        self.addr_id = Some(id);
        self
    }

    /// Set the address to announce.
    pub fn address(mut self, addr: impl Into<MptcpAddress>) -> Self {
        self.address = Some(addr.into());
        self
    }

    /// Set the port to announce.
    pub fn port(mut self, port: u16) -> Self {
        if let Some(ref mut addr) = self.address {
            addr.port = Some(port);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flags_from_raw() {
        let flags = MptcpFlags::from_raw(mptcp_pm_flags::SIGNAL | mptcp_pm_flags::BACKUP);
        assert!(flags.signal);
        assert!(!flags.subflow);
        assert!(flags.backup);
        assert!(!flags.fullmesh);
    }

    #[test]
    fn test_flags_to_raw() {
        let flags = MptcpFlags {
            signal: true,
            subflow: true,
            backup: false,
            fullmesh: false,
        };
        assert_eq!(
            flags.to_raw(),
            mptcp_pm_flags::SIGNAL | mptcp_pm_flags::SUBFLOW
        );
    }

    #[test]
    fn test_flags_roundtrip() {
        let original = MptcpFlags {
            signal: true,
            subflow: false,
            backup: true,
            fullmesh: true,
        };
        let raw = original.to_raw();
        let restored = MptcpFlags::from_raw(raw);
        assert_eq!(original, restored);
    }

    #[test]
    fn test_endpoint_builder() {
        let builder = MptcpEndpointBuilder::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .id(1)
            .port(8080)
            .subflow()
            .signal();

        assert_eq!(builder.id, Some(1));
        assert_eq!(builder.address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(builder.port, Some(8080));
        assert!(builder.flags.signal);
        assert!(builder.flags.subflow);
        assert!(!builder.flags.backup);
    }

    #[test]
    fn test_endpoint_builder_ipv6() {
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let builder = MptcpEndpointBuilder::new(addr.into())
            .id(2)
            .backup()
            .fullmesh();

        assert_eq!(builder.id, Some(2));
        assert!(matches!(builder.address, IpAddr::V6(_)));
        assert!(!builder.flags.signal);
        assert!(builder.flags.backup);
        assert!(builder.flags.fullmesh);
    }

    #[test]
    fn test_limits_builder() {
        let limits = MptcpLimits::new().subflows(4).add_addr_accepted(8);

        assert_eq!(limits.subflows, Some(4));
        assert_eq!(limits.add_addr_accepted, Some(8));
    }

    #[test]
    fn test_endpoint_helpers() {
        let ep = MptcpEndpoint {
            id: 1,
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: None,
            ifindex: Some(2),
            flags: MptcpFlags {
                signal: true,
                subflow: false,
                backup: true,
                fullmesh: false,
            },
        };

        assert!(ep.is_signal());
        assert!(!ep.is_subflow());
        assert!(ep.is_backup());
        assert!(!ep.is_fullmesh());
    }

    // ========================================================================
    // Subflow and Announce Builder Tests
    // ========================================================================

    #[test]
    fn test_mptcp_address_new() {
        let addr = MptcpAddress::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(addr.addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(addr.port.is_none());
    }

    #[test]
    fn test_mptcp_address_with_port() {
        let addr = MptcpAddress::with_port(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        assert_eq!(addr.addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(addr.port, Some(8080));
    }

    #[test]
    fn test_mptcp_address_from_socket_addr() {
        let socket_addr: std::net::SocketAddr = "192.168.1.1:443".parse().unwrap();
        let addr: MptcpAddress = socket_addr.into();
        assert_eq!(addr.addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(addr.port, Some(443));
    }

    #[test]
    fn test_subflow_builder() {
        let subflow = MptcpSubflowBuilder::new(0x12345678)
            .local_id(1)
            .remote_id(2)
            .local_addr(MptcpAddress::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))))
            .remote_addr(MptcpAddress::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))))
            .backup();

        assert_eq!(subflow.token, 0x12345678);
        assert_eq!(subflow.local_id, Some(1));
        assert_eq!(subflow.remote_id, Some(2));
        assert!(subflow.local_addr.is_some());
        assert!(subflow.remote_addr.is_some());
        assert!(subflow.backup);
    }

    #[test]
    fn test_subflow_builder_with_ifindex() {
        // `.dev("eth0")` used to be accepted here and emitted nothing
        // (#275). The test asserted the field was *stored*, which it
        // was — that is exactly what made the bug invisible.
        let subflow = MptcpSubflowBuilder::new(0xABCDEF00).ifindex(5);
        assert_eq!(subflow.ifindex, Some(5));
    }

    #[test]
    fn test_announce_builder() {
        let announce = MptcpAnnounceBuilder::new(0x11223344)
            .addr_id(3)
            .address(MptcpAddress::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))))
            .port(8080);

        assert_eq!(announce.token, 0x11223344);
        assert_eq!(announce.addr_id, Some(3));
        assert!(announce.address.is_some());
        let addr = announce.address.unwrap();
        assert_eq!(addr.port, Some(8080));
    }
}
