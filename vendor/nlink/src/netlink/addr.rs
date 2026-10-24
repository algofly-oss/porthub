//! IP address management.
//!
//! This module provides typed builders for adding and managing IP addresses.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::addr::{Ipv4Address, Ipv6Address};
//! use std::net::{Ipv4Addr, Ipv6Addr};
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Add an IPv4 address
//! conn.add_address(
//!     Ipv4Address::new("eth0", Ipv4Addr::new(192, 168, 1, 100), 24)
//!         .broadcast(Ipv4Addr::new(192, 168, 1, 255))
//!         .label("eth0:web")
//! ).await?;
//!
//! // Add an IPv6 address with lifetimes
//! conn.add_address(
//!     Ipv6Address::new("eth0", "2001:db8::1".parse()?, 64)
//!         .preferred_lifetime(3600)
//!         .valid_lifetime(7200)
//! ).await?;
//!
//! // Delete an address
//! conn.del_address("eth0", Ipv4Addr::new(192, 168, 1, 100).into(), 24).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Namespace-Safe Operations
//!
//! When working with network namespaces, use the index-based constructors
//! to avoid sysfs lookups:
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route, namespace};
//! use nlink::netlink::addr::Ipv4Address;
//!
//! // Create connection to namespace
//! let conn = Connection::<Route>::new_in("myns")?;
//!
//! // Get interface index via netlink (namespace-safe)
//! let link = conn.get_link_by_name("eth0").await?.unwrap();
//!
//! // Use index-based constructor
//! conn.add_address(
//!     Ipv4Address::with_index(link.ifindex(), "10.0.0.1".parse()?, 24)
//! ).await?;
//! # Ok(())
//! # }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{
    builder::MessageBuilder,
    connection::Connection,
    error::Result,
    interface_ref::InterfaceRef,
    message::{NLM_F_ACK, NLM_F_REQUEST, NlMsgType},
    protocol::Route,
    types::addr::{IfAddrMsg, IfaAttr, Scope, ifa_flags},
};

/// NLM_F_CREATE flag
const NLM_F_CREATE: u16 = 0x400;
/// NLM_F_EXCL flag
const NLM_F_EXCL: u16 = 0x200;
/// NLM_F_REPLACE flag
const NLM_F_REPLACE: u16 = 0x100;

/// Address families
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

/// Trait for address configurations that can be added.
///
/// This trait separates interface reference from message building.
/// The Connection is responsible for resolving the interface reference
/// to an index before calling the write methods.
pub trait AddressConfig: Send + Sync {
    /// Get the interface reference (name or index).
    fn interface_ref(&self) -> &InterfaceRef;

    /// Get the address family (AF_INET or AF_INET6).
    fn family(&self) -> u8;

    /// Get the prefix length.
    fn prefix_len(&self) -> u8;

    /// Write the "add address" message to the builder.
    ///
    /// The `ifindex` parameter is the resolved interface index.
    fn write_add(&self, builder: &mut MessageBuilder, ifindex: u32) -> Result<()>;

    /// Write the "replace address" message to the builder.
    ///
    /// The `ifindex` parameter is the resolved interface index.
    fn write_replace(&self, builder: &mut MessageBuilder, ifindex: u32) -> Result<()>;

    /// Write the "delete address" message to the builder.
    ///
    /// The `ifindex` parameter is the resolved interface index.
    fn write_delete(&self, builder: &mut MessageBuilder, ifindex: u32) -> Result<()>;
}

/// Cache info structure for address lifetimes.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct IfaCacheinfo {
    /// Preferred lifetime in seconds (INFINITY_LIFE_TIME for forever)
    ifa_prefered: u32,
    /// Valid lifetime in seconds (INFINITY_LIFE_TIME for forever)
    ifa_valid: u32,
    /// Creation timestamp (unused for add)
    cstamp: u32,
    /// Update timestamp (unused for add)
    tstamp: u32,
}

/// Infinity lifetime value (0xFFFFFFFF)
pub const INFINITY_LIFE_TIME: u32 = 0xFFFFFFFF;

// ============================================================================
// IPv4 Address
// ============================================================================

/// Configuration for an IPv4 address.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::addr::Ipv4Address;
/// use std::net::Ipv4Addr;
///
/// let addr = Ipv4Address::new("eth0", Ipv4Addr::new(192, 168, 1, 100), 24)
///     .broadcast(Ipv4Addr::new(192, 168, 1, 255))
///     .label("eth0:web")
///     .scope(nlink::netlink::types::addr::Scope::Universe);
///
/// conn.add_address(addr).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Ipv4Address {
    interface: InterfaceRef,
    address: Ipv4Addr,
    prefix_len: u8,
    /// Peer address for point-to-point links
    peer: Option<Ipv4Addr>,
    /// Broadcast address
    broadcast: Option<Ipv4Addr>,
    /// Address label (max 15 chars + null)
    label: Option<String>,
    /// Address scope
    scope: Scope,
    /// Address flags
    flags: u32,
    /// Preferred lifetime in seconds
    preferred_lft: Option<u32>,
    /// Valid lifetime in seconds
    valid_lft: Option<u32>,
    /// Route metric/priority
    metric: Option<u32>,
}

/// The scope the kernel requires for `addr`, the way `iproute2` derives
/// it.
///
/// `inet_rtm_newaddr` rejects a loopback prefix at any scope but
/// `RT_SCOPE_HOST` — the kernel's own words, read off a socket that
/// parses ext_ack:
///
/// ```text
/// scope=0   (RT_SCOPE_UNIVERSE): errno=-22  "ipv4: Invalid scope value"
/// scope=254 (RT_SCOPE_HOST):     errno=0    OK
/// ```
///
/// Both constructors hardcoded `Scope::Universe`, so **every**
/// `127.0.0.0/8` address failed with a bare `EINVAL` (bare because
/// ext_ack was not being parsed either — #292). `ip addr add
/// 127.0.0.2/8 dev lo` works because iproute2 derives the scope from
/// the prefix; so does this now (#293).
///
/// `.scope()` still overrides, for a caller who means something else.
fn default_scope(addr: IpAddr) -> Scope {
    match addr {
        IpAddr::V4(v4) if v4.is_loopback() => Scope::Host,
        IpAddr::V6(v6) if v6.is_loopback() => Scope::Host,
        _ => Scope::Universe,
    }
}

impl Ipv4Address {
    /// Create a new IPv4 address configuration.
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name (e.g., "eth0")
    /// * `address` - IPv4 address
    /// * `prefix_len` - Prefix length (0-32)
    pub fn new(interface: impl Into<String>, address: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            interface: InterfaceRef::Name(interface.into()),
            address,
            prefix_len,
            peer: None,
            broadcast: None,
            label: None,
            scope: default_scope(address.into()),
            flags: 0,
            preferred_lft: None,
            valid_lft: None,
            metric: None,
        }
    }

    /// Create a new IPv4 address configuration with interface index.
    ///
    /// Use this constructor for namespace-safe operations when you have
    /// already resolved the interface index via `conn.get_link_by_name()`.
    ///
    /// # Arguments
    ///
    /// * `ifindex` - Interface index
    /// * `address` - IPv4 address
    /// * `prefix_len` - Prefix length (0-32)
    pub fn with_index(ifindex: u32, address: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            interface: InterfaceRef::Index(ifindex),
            address,
            prefix_len,
            peer: None,
            broadcast: None,
            label: None,
            scope: default_scope(address.into()),
            flags: 0,
            preferred_lft: None,
            valid_lft: None,
            metric: None,
        }
    }

    /// Set the peer address for point-to-point links.
    pub fn peer(mut self, peer: Ipv4Addr) -> Self {
        self.peer = Some(peer);
        self
    }

    /// Set the broadcast address.
    ///
    /// If not set, the kernel will compute it automatically.
    pub fn broadcast(mut self, broadcast: Ipv4Addr) -> Self {
        self.broadcast = Some(broadcast);
        self
    }

    /// Set an address label.
    ///
    /// Labels are used for compatibility with older tools and can be
    /// used to identify addresses (e.g., "eth0:web").
    /// Maximum 15 characters.
    pub fn label(mut self, label: impl Into<String>) -> Self {
        let mut l = label.into();
        if l.len() > 15 {
            l.truncate(15);
        }
        self.label = Some(l);
        self
    }

    /// Set the address scope.
    pub fn scope(mut self, scope: Scope) -> Self {
        self.scope = scope;
        self
    }

    /// Mark as secondary address.
    pub fn secondary(mut self) -> Self {
        self.flags |= ifa_flags::SECONDARY;
        self
    }

    /// Disable prefix route creation.
    pub fn noprefixroute(mut self) -> Self {
        self.flags |= ifa_flags::NOPREFIXROUTE;
        self
    }

    /// Set home address flag (Mobile IPv6).
    pub fn home(mut self) -> Self {
        self.flags |= ifa_flags::HOMEADDRESS;
        self
    }

    /// Set the preferred lifetime in seconds.
    ///
    /// Use `INFINITY_LIFE_TIME` for forever.
    pub fn preferred_lifetime(mut self, seconds: u32) -> Self {
        self.preferred_lft = Some(seconds);
        self
    }

    /// Set the valid lifetime in seconds.
    ///
    /// Use `INFINITY_LIFE_TIME` for forever.
    pub fn valid_lifetime(mut self, seconds: u32) -> Self {
        self.valid_lft = Some(seconds);
        self
    }

    /// Set the route metric/priority.
    pub fn metric(mut self, metric: u32) -> Self {
        self.metric = Some(metric);
        self
    }

    /// Write common address attributes to the builder.
    fn write_common_attrs(&self, builder: &mut MessageBuilder) {
        // IFA_LOCAL (the actual address on this interface)
        builder.append_attr(IfaAttr::Local as u16, &self.address.octets());

        // IFA_ADDRESS (peer address for ptp, or same as local)
        if let Some(peer) = self.peer {
            builder.append_attr(IfaAttr::Address as u16, &peer.octets());
        } else {
            builder.append_attr(IfaAttr::Address as u16, &self.address.octets());
        }

        // IFA_BROADCAST
        if let Some(brd) = self.broadcast {
            builder.append_attr(IfaAttr::Broadcast as u16, &brd.octets());
        }

        // IFA_LABEL
        if let Some(ref label) = self.label {
            builder.append_attr_str(IfaAttr::Label as u16, label);
        }

        // IFA_FLAGS (extended flags, 32-bit)
        if self.flags != 0 {
            builder.append_attr_u32(IfaAttr::Flags as u16, self.flags);
        }

        // IFA_CACHEINFO (lifetimes)
        if self.preferred_lft.is_some() || self.valid_lft.is_some() {
            let cacheinfo = IfaCacheinfo {
                ifa_prefered: self.preferred_lft.unwrap_or(INFINITY_LIFE_TIME),
                ifa_valid: self.valid_lft.unwrap_or(INFINITY_LIFE_TIME),
                cstamp: 0,
                tstamp: 0,
            };
            // SAFETY: IfaCacheinfo is a #[repr(C)] struct of u32 fields with no padding.
            // The pointer and size are valid for the lifetime of `cacheinfo`.
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &cacheinfo as *const IfaCacheinfo as *const u8,
                    std::mem::size_of::<IfaCacheinfo>(),
                )
            };
            builder.append_attr(IfaAttr::Cacheinfo as u16, bytes);
        }

        // IFA_RT_PRIORITY (metric)
        if let Some(metric) = self.metric {
            builder.append_attr_u32(IfaAttr::RtPriority as u16, metric);
        }
    }
}

impl AddressConfig for Ipv4Address {
    fn interface_ref(&self) -> &InterfaceRef {
        &self.interface
    }

    fn family(&self) -> u8 {
        AF_INET
    }

    fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    fn write_add(&self, builder: &mut MessageBuilder, ifindex: u32) -> Result<()> {
        // Build ifaddrmsg
        let ifaddr = IfAddrMsg::new()
            .with_family(AF_INET)
            .with_prefixlen(self.prefix_len)
            .with_index(ifindex)
            .with_scope(self.scope as u8);

        builder.append(&ifaddr);
        self.write_common_attrs(builder);
        Ok(())
    }

    fn write_replace(&self, builder: &mut MessageBuilder, ifindex: u32) -> Result<()> {
        // Same as write_add - the flags are set by the Connection
        let ifaddr = IfAddrMsg::new()
            .with_family(AF_INET)
            .with_prefixlen(self.prefix_len)
            .with_index(ifindex)
            .with_scope(self.scope as u8);

        builder.append(&ifaddr);
        self.write_common_attrs(builder);
        Ok(())
    }

    fn write_delete(&self, builder: &mut MessageBuilder, ifindex: u32) -> Result<()> {
        let ifaddr = IfAddrMsg::new()
            .with_family(AF_INET)
            .with_prefixlen(self.prefix_len)
            .with_index(ifindex);

        builder.append(&ifaddr);

        // IFA_LOCAL
        builder.append_attr(IfaAttr::Local as u16, &self.address.octets());
        // IFA_ADDRESS, the peer or the address: without it
        // `inet_rtm_deladdr` matches the local alone and deletes the first
        // address with it, whatever its prefix or peer (#516).
        builder.append_attr(
            IfaAttr::Address as u16,
            &self.peer.unwrap_or(self.address).octets(),
        );

        Ok(())
    }
}

// ============================================================================
// IPv6 Address
// ============================================================================

/// Configuration for an IPv6 address.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::addr::Ipv6Address;
/// use std::net::Ipv6Addr;
///
/// let addr = Ipv6Address::new("eth0", "2001:db8::1".parse()?, 64)
///     .preferred_lifetime(3600)
///     .valid_lifetime(7200)
///     .nodad();
///
/// conn.add_address(addr).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Ipv6Address {
    interface: InterfaceRef,
    address: Ipv6Addr,
    prefix_len: u8,
    /// Peer address for point-to-point links
    peer: Option<Ipv6Addr>,
    /// Address scope
    scope: Scope,
    /// Address flags
    flags: u32,
    /// Preferred lifetime in seconds
    preferred_lft: Option<u32>,
    /// Valid lifetime in seconds
    valid_lft: Option<u32>,
    /// Route metric/priority
    metric: Option<u32>,
}

impl Ipv6Address {
    /// Create a new IPv6 address configuration.
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name (e.g., "eth0")
    /// * `address` - IPv6 address
    /// * `prefix_len` - Prefix length (0-128)
    pub fn new(interface: impl Into<String>, address: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            interface: InterfaceRef::Name(interface.into()),
            address,
            prefix_len,
            peer: None,
            scope: default_scope(address.into()),
            flags: 0,
            preferred_lft: None,
            valid_lft: None,
            metric: None,
        }
    }

    /// Create a new IPv6 address configuration with interface index.
    ///
    /// Use this constructor for namespace-safe operations when you have
    /// already resolved the interface index via `conn.get_link_by_name()`.
    ///
    /// # Arguments
    ///
    /// * `ifindex` - Interface index
    /// * `address` - IPv6 address
    /// * `prefix_len` - Prefix length (0-128)
    pub fn with_index(ifindex: u32, address: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            interface: InterfaceRef::Index(ifindex),
            address,
            prefix_len,
            peer: None,
            scope: default_scope(address.into()),
            flags: 0,
            preferred_lft: None,
            valid_lft: None,
            metric: None,
        }
    }

    /// Set the peer address for point-to-point links.
    pub fn peer(mut self, peer: Ipv6Addr) -> Self {
        self.peer = Some(peer);
        self
    }

    /// Set the address scope.
    pub fn scope(mut self, scope: Scope) -> Self {
        self.scope = scope;
        self
    }

    /// Disable Duplicate Address Detection.
    pub fn nodad(mut self) -> Self {
        self.flags |= ifa_flags::NODAD;
        self
    }

    /// Set optimistic DAD flag.
    pub fn optimistic(mut self) -> Self {
        self.flags |= ifa_flags::OPTIMISTIC;
        self
    }

    /// Disable prefix route creation.
    pub fn noprefixroute(mut self) -> Self {
        self.flags |= ifa_flags::NOPREFIXROUTE;
        self
    }

    /// Set home address flag (Mobile IPv6).
    pub fn home(mut self) -> Self {
        self.flags |= ifa_flags::HOMEADDRESS;
        self
    }

    /// Enable management of temporary addresses.
    pub fn mngtmpaddr(mut self) -> Self {
        self.flags |= ifa_flags::MANAGETEMPADDR;
        self
    }

    /// Set the preferred lifetime in seconds.
    ///
    /// Use `INFINITY_LIFE_TIME` for forever.
    pub fn preferred_lifetime(mut self, seconds: u32) -> Self {
        self.preferred_lft = Some(seconds);
        self
    }

    /// Set the valid lifetime in seconds.
    ///
    /// Use `INFINITY_LIFE_TIME` for forever.
    pub fn valid_lifetime(mut self, seconds: u32) -> Self {
        self.valid_lft = Some(seconds);
        self
    }

    /// Set the route metric/priority.
    pub fn metric(mut self, metric: u32) -> Self {
        self.metric = Some(metric);
        self
    }

    /// Write common address attributes to the builder.
    fn write_common_attrs(&self, builder: &mut MessageBuilder) {
        // IFA_LOCAL
        builder.append_attr(IfaAttr::Local as u16, &self.address.octets());

        // IFA_ADDRESS (peer or same as local)
        if let Some(peer) = self.peer {
            builder.append_attr(IfaAttr::Address as u16, &peer.octets());
        } else {
            builder.append_attr(IfaAttr::Address as u16, &self.address.octets());
        }

        // IFA_FLAGS (extended flags, 32-bit)
        if self.flags != 0 {
            builder.append_attr_u32(IfaAttr::Flags as u16, self.flags);
        }

        // IFA_CACHEINFO (lifetimes)
        if self.preferred_lft.is_some() || self.valid_lft.is_some() {
            let cacheinfo = IfaCacheinfo {
                ifa_prefered: self.preferred_lft.unwrap_or(INFINITY_LIFE_TIME),
                ifa_valid: self.valid_lft.unwrap_or(INFINITY_LIFE_TIME),
                cstamp: 0,
                tstamp: 0,
            };
            // SAFETY: IfaCacheinfo is a #[repr(C)] struct of u32 fields with no padding.
            // The pointer and size are valid for the lifetime of `cacheinfo`.
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &cacheinfo as *const IfaCacheinfo as *const u8,
                    std::mem::size_of::<IfaCacheinfo>(),
                )
            };
            builder.append_attr(IfaAttr::Cacheinfo as u16, bytes);
        }

        // IFA_RT_PRIORITY (metric)
        if let Some(metric) = self.metric {
            builder.append_attr_u32(IfaAttr::RtPriority as u16, metric);
        }
    }
}

impl AddressConfig for Ipv6Address {
    fn interface_ref(&self) -> &InterfaceRef {
        &self.interface
    }

    fn family(&self) -> u8 {
        AF_INET6
    }

    fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    fn write_add(&self, builder: &mut MessageBuilder, ifindex: u32) -> Result<()> {
        let ifaddr = IfAddrMsg::new()
            .with_family(AF_INET6)
            .with_prefixlen(self.prefix_len)
            .with_index(ifindex)
            .with_scope(self.scope as u8);

        builder.append(&ifaddr);
        self.write_common_attrs(builder);
        Ok(())
    }

    fn write_replace(&self, builder: &mut MessageBuilder, ifindex: u32) -> Result<()> {
        let ifaddr = IfAddrMsg::new()
            .with_family(AF_INET6)
            .with_prefixlen(self.prefix_len)
            .with_index(ifindex)
            .with_scope(self.scope as u8);

        builder.append(&ifaddr);
        self.write_common_attrs(builder);
        Ok(())
    }

    fn write_delete(&self, builder: &mut MessageBuilder, ifindex: u32) -> Result<()> {
        let ifaddr = IfAddrMsg::new()
            .with_family(AF_INET6)
            .with_prefixlen(self.prefix_len)
            .with_index(ifindex);

        builder.append(&ifaddr);

        // IFA_LOCAL
        builder.append_attr(IfaAttr::Local as u16, &self.address.octets());

        Ok(())
    }
}

// ============================================================================
// Connection Methods
// ============================================================================

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Add an IP address to an interface.
    ///
    /// This method is namespace-safe: interface names are resolved via netlink,
    /// which queries the namespace that this connection is bound to.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::addr::{Ipv4Address, Ipv6Address};
    /// use std::net::{Ipv4Addr, Ipv6Addr};
    ///
    /// // Add IPv4 address
    /// conn.add_address(
    ///     Ipv4Address::new("eth0", Ipv4Addr::new(192, 168, 1, 100), 24)
    /// ).await?;
    ///
    /// // Add IPv6 address
    /// conn.add_address(
    ///     Ipv6Address::new("eth0", "2001:db8::1".parse()?, 64)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn add_address<A: AddressConfig>(&self, config: A) -> Result<()> {
        let ifindex = self.resolve_interface(config.interface_ref()).await?;

        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );

        config.write_add(&mut builder, ifindex)?;
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_address"))
    }

    /// Delete an IP address from an interface.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use std::net::IpAddr;
    /// # use std::net::Ipv4Addr;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.del_address("eth0", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 24).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_address"))]
    pub async fn del_address(
        &self,
        ifname: impl Into<InterfaceRef>,
        address: IpAddr,
        prefix_len: u8,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        self.del_address_by_index(ifindex, address, prefix_len)
            .await
    }

    /// Delete an IP address if present. Returns `Ok(true)` if the
    /// address was deleted, `Ok(false)` if it (or the interface)
    /// wasn't there. Unlike [`Self::del_address`], does NOT error
    /// on `EADDRNOTAVAIL`/`ENOENT`/`ENODEV` (#169; mirrors the
    /// nftables `del_*_if_exists` family).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_address_if_exists"))]
    pub async fn del_address_if_exists(
        &self,
        ifname: impl Into<InterfaceRef>,
        address: IpAddr,
        prefix_len: u8,
    ) -> Result<bool> {
        match self.del_address(ifname, address, prefix_len).await {
            Ok(()) => Ok(true),
            // RTM_DELADDR answers "address not present" with
            // EADDRNOTAVAIL, which `is_not_found()` reads as such (#526).
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Delete an IP address from an interface by index.
    ///
    /// This is namespace-safe as it doesn't require interface name resolution.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_address_by_index"))]
    pub async fn del_address_by_index(
        &self,
        ifindex: u32,
        address: IpAddr,
        prefix_len: u8,
    ) -> Result<()> {
        match address {
            IpAddr::V4(addr) => {
                let config = Ipv4Address::with_index(ifindex, addr, prefix_len);
                self.del_address_config(config).await
            }
            IpAddr::V6(addr) => {
                let config = Ipv6Address::with_index(ifindex, addr, prefix_len);
                self.del_address_config(config).await
            }
        }
    }

    /// Add an IP address to an interface by index.
    ///
    /// This is namespace-safe as it doesn't require interface name resolution.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// // Get interface index via netlink
    /// let link = conn.get_link_by_name("eth0").await?.unwrap();
    ///
    /// // Add address by index
    /// conn.add_address_by_index(link.ifindex(), "192.168.1.100".parse()?, 24).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_address_by_index"))]
    pub async fn add_address_by_index(
        &self,
        ifindex: u32,
        address: IpAddr,
        prefix_len: u8,
    ) -> Result<()> {
        match address {
            IpAddr::V4(addr) => {
                let config = Ipv4Address::with_index(ifindex, addr, prefix_len);
                self.add_address(config).await
            }
            IpAddr::V6(addr) => {
                let config = Ipv6Address::with_index(ifindex, addr, prefix_len);
                self.add_address(config).await
            }
        }
    }

    /// Replace an IP address on an interface by index.
    ///
    /// This is namespace-safe as it doesn't require interface name resolution.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_address_by_index"))]
    pub async fn replace_address_by_index(
        &self,
        ifindex: u32,
        address: IpAddr,
        prefix_len: u8,
    ) -> Result<()> {
        match address {
            IpAddr::V4(addr) => {
                let config = Ipv4Address::with_index(ifindex, addr, prefix_len);
                self.replace_address(config).await
            }
            IpAddr::V6(addr) => {
                let config = Ipv6Address::with_index(ifindex, addr, prefix_len);
                self.replace_address(config).await
            }
        }
    }

    /// Add an IP address to an interface by name.
    ///
    /// This is a convenience method that resolves the interface name internally.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.add_address_by_name("eth0", "192.168.1.100".parse()?, 24).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_address_by_name"))]
    pub async fn add_address_by_name(
        &self,
        ifname: impl Into<InterfaceRef>,
        address: IpAddr,
        prefix_len: u8,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        self.add_address_by_index(ifindex, address, prefix_len)
            .await
    }

    /// Replace an IP address on an interface by name.
    ///
    /// This is a convenience method that resolves the interface name internally.
    /// If the address exists, it will be updated; otherwise it will be created.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.replace_address_by_name("eth0", "192.168.1.100".parse()?, 24).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_address_by_name"))]
    pub async fn replace_address_by_name(
        &self,
        ifname: impl Into<InterfaceRef>,
        address: IpAddr,
        prefix_len: u8,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        self.replace_address_by_index(ifindex, address, prefix_len)
            .await
    }

    /// Delete an IPv4 address from an interface.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_address_v4"))]
    pub async fn del_address_v4(
        &self,
        ifname: impl Into<InterfaceRef>,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        let config = Ipv4Address::with_index(ifindex, address, prefix_len);
        self.del_address_config(config).await
    }

    /// Delete an IPv6 address from an interface.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_address_v6"))]
    pub async fn del_address_v6(
        &self,
        ifname: impl Into<InterfaceRef>,
        address: Ipv6Addr,
        prefix_len: u8,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        let config = Ipv6Address::with_index(ifindex, address, prefix_len);
        self.del_address_config(config).await
    }

    /// Delete an IP address using a typed config.
    pub async fn del_address_config<A: AddressConfig>(&self, config: A) -> Result<()> {
        let ifindex = self.resolve_interface(config.interface_ref()).await?;

        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK);

        config.write_delete(&mut builder, ifindex)?;
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_address"))
    }

    /// Replace an IP address (add or update).
    ///
    /// This is like `add_address` but will update if the address exists.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::Ipv4Address;
    /// # use std::net::Ipv4Addr;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// // Update address properties (lifetimes, etc.)
    /// conn.replace_address(
    ///     Ipv4Address::new("eth0", Ipv4Addr::new(192, 168, 1, 100), 24)
    ///         .preferred_lifetime(3600)
    ///         .valid_lifetime(7200)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn replace_address<A: AddressConfig>(&self, config: A) -> Result<()> {
        let ifindex = self.resolve_interface(config.interface_ref()).await?;

        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );

        config.write_replace(&mut builder, ifindex)?;
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("replace_address"))
    }

    /// Flush all addresses from an interface.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.flush_addresses("eth0").await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_addresses"))]
    pub async fn flush_addresses(&self, ifname: impl Into<InterfaceRef>) -> Result<()> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        self.flush_addresses_by_index(ifindex).await
    }

    /// Flush all addresses from an interface by index.
    ///
    /// This is namespace-safe as it doesn't require interface name resolution.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_addresses_by_index"))]
    pub async fn flush_addresses_by_index(&self, ifindex: u32) -> Result<()> {
        let addresses = self.get_addresses_by_index(ifindex).await?;

        for addr in addresses {
            if let (Some(address), Some(prefix_len)) = (addr.address, Some(addr.prefix_len())) {
                // Skip loopback addresses on loopback interface (index 1 is typically lo)
                if ifindex == 1
                    && (address == IpAddr::V4(Ipv4Addr::LOCALHOST)
                        || address == IpAddr::V6(Ipv6Addr::LOCALHOST))
                {
                    continue;
                }

                if let Err(e) = self
                    .del_address_by_index(ifindex, address, prefix_len)
                    .await
                {
                    // Ignore "not found" errors (race condition)
                    if !e.is_not_found() {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }
}
