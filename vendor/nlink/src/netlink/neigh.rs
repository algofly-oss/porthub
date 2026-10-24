//! Neighbor (ARP/NDP) management.
//!
//! This module provides typed builders for adding and managing neighbor entries.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::neigh::{Neighbor, NeighborState};
//! use std::net::Ipv4Addr;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Add a permanent ARP entry
//! conn.add_neighbor(
//!     Neighbor::new_v4("eth0", Ipv4Addr::new(192, 168, 1, 100))
//!         .lladdr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
//!         .state(NeighborState::Permanent)
//! ).await?;
//!
//! // Add a proxy ARP entry
//! conn.add_neighbor(
//!     Neighbor::new_v4("eth0", Ipv4Addr::new(192, 168, 1, 200))
//!         .proxy()
//! ).await?;
//!
//! // Delete a neighbor entry
//! conn.del_neighbor_v4("eth0", Ipv4Addr::new(192, 168, 1, 100)).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Namespace-Safe Operations
//!
//! When working with network namespaces, use the index-based constructors:
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route, namespace};
//! use nlink::netlink::neigh::Neighbor;
//!
//! let conn = Connection::<Route>::new_in("myns")?;
//! let link = conn.get_link_by_name("eth0").await?.unwrap();
//!
//! conn.add_neighbor(
//!     Neighbor::with_index_v4(link.ifindex(), "10.0.0.1".parse()?)
//!         .lladdr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
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
    types::neigh::{NdMsg, NdaAttr, nud},
};

/// NLM_F_CREATE flag
const NLM_F_CREATE: u16 = 0x400;
/// NLM_F_EXCL flag
const NLM_F_EXCL: u16 = 0x200;
/// NLM_F_REPLACE flag
const NLM_F_REPLACE: u16 = 0x100;

/// Address families
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

// Re-exported so the type named by `Neighbor::state` can be named from the
// module that defines `Neighbor` — every doc example here imported it from
// this path already (#316). `State` is the older, shorter alias; both are
// the same enum.
pub use super::types::neigh::{NeighborState, NeighborState as State};

/// Neighbor flags (`NTF_*`).
///
/// Re-exported so callers decoding [`NeighborMessage::flags`] don't
/// have to redefine kernel constants.
///
/// [`NeighborMessage::flags`]: crate::netlink::messages::NeighborMessage::flags
pub use super::types::neigh::ntf;

/// Trait for neighbor configurations that can be added.
///
/// This trait separates interface reference from message building.
/// The Connection is responsible for resolving the interface reference
/// to an index before calling the write methods.
pub trait NeighborConfig: Send + Sync {
    /// Get the interface reference (name or index).
    fn interface_ref(&self) -> &InterfaceRef;

    /// Get the address family (AF_INET or AF_INET6).
    fn family(&self) -> u8;

    /// Write the "add neighbor" message to the builder.
    ///
    /// The `ifindex` parameter is the resolved interface index.
    fn write_add(&self, builder: &mut MessageBuilder, ifindex: u32) -> Result<()>;

    /// Write the "delete neighbor" message to the builder.
    ///
    /// The `ifindex` parameter is the resolved interface index.
    fn write_delete(&self, builder: &mut MessageBuilder, ifindex: u32) -> Result<()>;
}

// ============================================================================
// Neighbor Entry
// ============================================================================

/// Configuration for a neighbor (ARP/NDP) entry.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::neigh::{Neighbor, NeighborState};
/// use std::net::Ipv4Addr;
///
/// // Add a permanent ARP entry
/// let neigh = Neighbor::new_v4("eth0", Ipv4Addr::new(192, 168, 1, 100))
///     .lladdr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
///     .state(NeighborState::Permanent);
///
/// conn.add_neighbor(neigh).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Neighbor {
    interface: InterfaceRef,
    /// Destination IP address
    destination: IpAddr,
    /// Link-layer address (MAC address for Ethernet)
    lladdr: Option<Vec<u8>>,
    /// Neighbor state
    state: u16,
    /// Neighbor flags
    flags: u8,
    /// VLAN ID (for bridge FDB)
    vlan: Option<u16>,
    /// VNI (for VXLAN)
    vni: Option<u32>,
    /// Master device index
    master: Option<u32>,
}

impl Neighbor {
    /// Create a new IPv4 neighbor entry.
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name (e.g., "eth0")
    /// * `destination` - IPv4 address of the neighbor
    pub fn new_v4(interface: impl Into<String>, destination: Ipv4Addr) -> Self {
        Self {
            interface: InterfaceRef::Name(interface.into()),
            destination: IpAddr::V4(destination),
            lladdr: None,
            state: nud::PERMANENT,
            flags: 0,
            vlan: None,
            vni: None,
            master: None,
        }
    }

    /// Create a new IPv4 neighbor entry with interface index.
    ///
    /// Use this constructor for namespace-safe operations.
    pub fn with_index_v4(ifindex: u32, destination: Ipv4Addr) -> Self {
        Self {
            interface: InterfaceRef::Index(ifindex),
            destination: IpAddr::V4(destination),
            lladdr: None,
            state: nud::PERMANENT,
            flags: 0,
            vlan: None,
            vni: None,
            master: None,
        }
    }

    /// Create a new IPv6 neighbor entry.
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name (e.g., "eth0")
    /// * `destination` - IPv6 address of the neighbor
    pub fn new_v6(interface: impl Into<String>, destination: Ipv6Addr) -> Self {
        Self {
            interface: InterfaceRef::Name(interface.into()),
            destination: IpAddr::V6(destination),
            lladdr: None,
            state: nud::PERMANENT,
            flags: 0,
            vlan: None,
            vni: None,
            master: None,
        }
    }

    /// Create a new IPv6 neighbor entry with interface index.
    ///
    /// Use this constructor for namespace-safe operations.
    pub fn with_index_v6(ifindex: u32, destination: Ipv6Addr) -> Self {
        Self {
            interface: InterfaceRef::Index(ifindex),
            destination: IpAddr::V6(destination),
            lladdr: None,
            state: nud::PERMANENT,
            flags: 0,
            vlan: None,
            vni: None,
            master: None,
        }
    }

    /// Create a new neighbor entry from an IpAddr.
    pub fn new(interface: impl Into<String>, destination: IpAddr) -> Self {
        Self {
            interface: InterfaceRef::Name(interface.into()),
            destination,
            lladdr: None,
            state: nud::PERMANENT,
            flags: 0,
            vlan: None,
            vni: None,
            master: None,
        }
    }

    /// Create a new neighbor entry from an IpAddr with interface index.
    ///
    /// Use this constructor for namespace-safe operations.
    pub fn with_index(ifindex: u32, destination: IpAddr) -> Self {
        Self {
            interface: InterfaceRef::Index(ifindex),
            destination,
            lladdr: None,
            state: nud::PERMANENT,
            flags: 0,
            vlan: None,
            vni: None,
            master: None,
        }
    }

    /// Set the link-layer (MAC) address as a 6-byte array.
    pub fn lladdr(mut self, addr: [u8; 6]) -> Self {
        self.lladdr = Some(addr.to_vec());
        self
    }

    /// Set the link-layer address from bytes.
    pub fn lladdr_bytes(mut self, addr: impl Into<Vec<u8>>) -> Self {
        self.lladdr = Some(addr.into());
        self
    }

    /// Set the neighbor state.
    pub fn state(mut self, state: NeighborState) -> Self {
        self.state = state as u16;
        self
    }

    /// Set as permanent entry.
    pub fn permanent(mut self) -> Self {
        self.state = nud::PERMANENT;
        self
    }

    /// Set as reachable entry.
    pub fn reachable(mut self) -> Self {
        self.state = nud::REACHABLE;
        self
    }

    /// Set as stale entry.
    pub fn stale(mut self) -> Self {
        self.state = nud::STALE;
        self
    }

    /// Set as noarp entry (no ARP requests will be sent).
    pub fn noarp(mut self) -> Self {
        self.state = nud::NOARP;
        self
    }

    /// Mark as proxy ARP entry.
    pub fn proxy(mut self) -> Self {
        self.flags |= ntf::PROXY;
        self
    }

    /// Mark as router (for NDP).
    pub fn router(mut self) -> Self {
        self.flags |= ntf::ROUTER;
        self
    }

    /// Mark as externally learned.
    pub fn extern_learn(mut self) -> Self {
        self.flags |= ntf::EXT_LEARNED;
        self
    }

    /// Set VLAN ID (for bridge FDB entries).
    pub fn vlan(mut self, vlan_id: u16) -> Self {
        self.vlan = Some(vlan_id);
        self
    }

    /// Set VNI (for VXLAN FDB entries).
    pub fn vni(mut self, vni: u32) -> Self {
        self.vni = Some(vni);
        self
    }

    /// Set master device index directly.
    ///
    /// Use this for namespace-safe operations when you have already
    /// resolved the master device index.
    pub fn master_index(mut self, master_ifindex: u32) -> Self {
        self.master = Some(master_ifindex);
        self
    }
}

impl NeighborConfig for Neighbor {
    fn interface_ref(&self) -> &InterfaceRef {
        &self.interface
    }

    fn family(&self) -> u8 {
        match self.destination {
            IpAddr::V4(_) => AF_INET,
            IpAddr::V6(_) => AF_INET6,
        }
    }

    fn write_add(&self, builder: &mut MessageBuilder, ifindex: u32) -> Result<()> {
        let mut ndmsg = NdMsg::new()
            .with_family(self.family())
            .with_ifindex(ifindex as i32);
        ndmsg.ndm_state = self.state;
        ndmsg.ndm_flags = self.flags;

        builder.append(&ndmsg);

        // NDA_DST - destination IP address
        match self.destination {
            IpAddr::V4(addr) => {
                builder.append_attr(NdaAttr::Dst as u16, &addr.octets());
            }
            IpAddr::V6(addr) => {
                builder.append_attr(NdaAttr::Dst as u16, &addr.octets());
            }
        }

        // NDA_LLADDR - link-layer address
        if let Some(ref lladdr) = self.lladdr {
            builder.append_attr(NdaAttr::Lladdr as u16, lladdr);
        }

        // NDA_VLAN
        if let Some(vlan) = self.vlan {
            builder.append_attr_u16(NdaAttr::Vlan as u16, vlan);
        }

        // NDA_VNI
        if let Some(vni) = self.vni {
            builder.append_attr_u32(NdaAttr::Vni as u16, vni);
        }

        // NDA_MASTER
        if let Some(master) = self.master {
            builder.append_attr_u32(NdaAttr::Master as u16, master);
        }

        Ok(())
    }

    fn write_delete(&self, builder: &mut MessageBuilder, ifindex: u32) -> Result<()> {
        let mut ndmsg = NdMsg::new()
            .with_family(self.family())
            .with_ifindex(ifindex as i32);
        // ndm_flags is part of the kernel's lookup key for NTF_PROXY /
        // NTF_ROUTER / NTF_EXT_LEARNED entries. ndm_state deliberately
        // stays unset — the kernel doesn't match on state for delete.
        ndmsg.ndm_flags = self.flags;

        builder.append(&ndmsg);

        // NDA_DST
        match self.destination {
            IpAddr::V4(addr) => {
                builder.append_attr(NdaAttr::Dst as u16, &addr.octets());
            }
            IpAddr::V6(addr) => {
                builder.append_attr(NdaAttr::Dst as u16, &addr.octets());
            }
        }

        Ok(())
    }
}

// ============================================================================
// Connection Methods
// ============================================================================

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Add a neighbor entry.
    ///
    /// This method is namespace-safe: interface names are resolved via netlink.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::neigh::{Neighbor, NeighborState};
    /// use std::net::Ipv4Addr;
    ///
    /// // Add a permanent ARP entry
    /// conn.add_neighbor(
    ///     Neighbor::new_v4("eth0", Ipv4Addr::new(192, 168, 1, 100))
    ///         .lladdr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    ///         .state(NeighborState::Permanent)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn add_neighbor<N: NeighborConfig>(&self, config: N) -> Result<()> {
        let ifindex = self.resolve_interface(config.interface_ref()).await?;

        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );

        config.write_add(&mut builder, ifindex)?;
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_neighbor"))
    }

    /// Delete a neighbor entry using a config.
    pub async fn del_neighbor<N: NeighborConfig>(&self, config: N) -> Result<()> {
        let ifindex = self.resolve_interface(config.interface_ref()).await?;

        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELNEIGH, NLM_F_REQUEST | NLM_F_ACK);

        config.write_delete(&mut builder, ifindex)?;
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_neighbor"))
    }

    /// Delete a neighbour entry if it exists (#718). `Ok(true)` when one
    /// was deleted, `Ok(false)` when there was none, which also covers a
    /// missing interface. The kernel answers a missing entry with `ENOENT`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_neighbor_if_exists"))]
    pub async fn del_neighbor_if_exists<N: NeighborConfig>(&self, config: N) -> Result<bool> {
        match self.del_neighbor(config).await {
            Ok(()) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Add an IPv4 neighbor entry by interface index.
    ///
    /// This is namespace-safe as it doesn't require interface name resolution.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_neighbor_v4_by_index"))]
    pub async fn add_neighbor_v4_by_index(
        &self,
        ifindex: u32,
        destination: Ipv4Addr,
        lladdr: [u8; 6],
    ) -> Result<()> {
        let neigh = Neighbor::with_index_v4(ifindex, destination).lladdr(lladdr);
        self.add_neighbor(neigh).await
    }

    /// Add an IPv6 neighbor entry by interface index.
    ///
    /// This is namespace-safe as it doesn't require interface name resolution.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_neighbor_v6_by_index"))]
    pub async fn add_neighbor_v6_by_index(
        &self,
        ifindex: u32,
        destination: Ipv6Addr,
        lladdr: [u8; 6],
    ) -> Result<()> {
        let neigh = Neighbor::with_index_v6(ifindex, destination).lladdr(lladdr);
        self.add_neighbor(neigh).await
    }

    /// Delete an IPv4 neighbor entry.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use std::net::Ipv4Addr;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.del_neighbor_v4("eth0", Ipv4Addr::new(192, 168, 1, 100)).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_neighbor_v4"))]
    pub async fn del_neighbor_v4(
        &self,
        ifname: impl Into<InterfaceRef>,
        destination: Ipv4Addr,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        let neigh = Neighbor::with_index_v4(ifindex, destination);
        self.del_neighbor(neigh).await
    }

    /// Delete an IPv4 neighbor entry by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_neighbor_v4_by_index"))]
    pub async fn del_neighbor_v4_by_index(
        &self,
        ifindex: u32,
        destination: Ipv4Addr,
    ) -> Result<()> {
        let neigh = Neighbor::with_index_v4(ifindex, destination);
        self.del_neighbor(neigh).await
    }

    /// Delete an IPv6 neighbor entry.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_neighbor_v6"))]
    pub async fn del_neighbor_v6(
        &self,
        ifname: impl Into<InterfaceRef>,
        destination: Ipv6Addr,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        let neigh = Neighbor::with_index_v6(ifindex, destination);
        self.del_neighbor(neigh).await
    }

    /// Delete an IPv6 neighbor entry by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_neighbor_v6_by_index"))]
    pub async fn del_neighbor_v6_by_index(
        &self,
        ifindex: u32,
        destination: Ipv6Addr,
    ) -> Result<()> {
        let neigh = Neighbor::with_index_v6(ifindex, destination);
        self.del_neighbor(neigh).await
    }

    /// Replace a neighbor entry (add or update).
    ///
    /// If the entry exists, it will be updated. Otherwise, it will be created.
    pub async fn replace_neighbor<N: NeighborConfig>(&self, config: N) -> Result<()> {
        let ifindex = self.resolve_interface(config.interface_ref()).await?;

        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );

        config.write_add(&mut builder, ifindex)?;
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("replace_neighbor"))
    }

    /// Replace an IPv4 neighbor entry by interface index.
    ///
    /// This is namespace-safe as it doesn't require interface name resolution.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "replace_neighbor_v4_by_index")
    )]
    pub async fn replace_neighbor_v4_by_index(
        &self,
        ifindex: u32,
        destination: Ipv4Addr,
        lladdr: [u8; 6],
    ) -> Result<()> {
        let neigh = Neighbor::with_index_v4(ifindex, destination).lladdr(lladdr);
        self.replace_neighbor(neigh).await
    }

    /// Replace an IPv6 neighbor entry by interface index.
    ///
    /// This is namespace-safe as it doesn't require interface name resolution.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "replace_neighbor_v6_by_index")
    )]
    pub async fn replace_neighbor_v6_by_index(
        &self,
        ifindex: u32,
        destination: Ipv6Addr,
        lladdr: [u8; 6],
    ) -> Result<()> {
        let neigh = Neighbor::with_index_v6(ifindex, destination).lladdr(lladdr);
        self.replace_neighbor(neigh).await
    }

    /// Flush all neighbor entries for an interface.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.flush_neighbors("eth0").await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_neighbors"))]
    pub async fn flush_neighbors(&self, ifname: impl Into<InterfaceRef>) -> Result<()> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        self.flush_neighbors_by_index(ifindex).await
    }

    /// Flush all neighbor entries for an interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_neighbors_by_index"))]
    pub async fn flush_neighbors_by_index(&self, ifindex: u32) -> Result<()> {
        let neighbors = self.get_neighbors_by_index(ifindex).await?;

        for neigh in neighbors {
            if let Some(dest) = neigh.destination {
                // Skip permanent entries unless explicitly requested
                // (matching iproute2 behavior)
                if neigh.state() == NeighborState::Permanent {
                    continue;
                }

                if let Err(e) = self.del_neighbor(Neighbor::with_index(ifindex, dest)).await {
                    // Ignore "not found" errors (race condition)
                    if !e.is_not_found() {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Add a proxy ARP entry.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use std::net::Ipv4Addr;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.add_proxy_arp("eth0", Ipv4Addr::new(192, 168, 1, 100)).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_proxy_arp"))]
    pub async fn add_proxy_arp(
        &self,
        ifname: impl Into<InterfaceRef>,
        destination: Ipv4Addr,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        let neigh = Neighbor::with_index_v4(ifindex, destination).proxy();
        self.add_neighbor(neigh).await
    }

    /// Add a proxy ARP entry by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_proxy_arp_by_index"))]
    pub async fn add_proxy_arp_by_index(&self, ifindex: u32, destination: Ipv4Addr) -> Result<()> {
        let neigh = Neighbor::with_index_v4(ifindex, destination).proxy();
        self.add_neighbor(neigh).await
    }

    /// Delete a proxy ARP entry.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_proxy_arp"))]
    pub async fn del_proxy_arp(
        &self,
        ifname: impl Into<InterfaceRef>,
        destination: Ipv4Addr,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        let neigh = Neighbor::with_index_v4(ifindex, destination).proxy();
        self.del_neighbor(neigh).await
    }

    /// Delete a proxy ARP entry by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_proxy_arp_by_index"))]
    pub async fn del_proxy_arp_by_index(&self, ifindex: u32, destination: Ipv4Addr) -> Result<()> {
        let neigh = Neighbor::with_index_v4(ifindex, destination).proxy();
        self.del_neighbor(neigh).await
    }

    /// Get neighbor entries for an interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_neighbors_by_index"))]
    pub async fn get_neighbors_by_index(
        &self,
        ifindex: u32,
    ) -> Result<Vec<super::messages::NeighborMessage>> {
        let neighbors = self.get_neighbors().await?;
        Ok(neighbors
            .into_iter()
            .filter(|n| n.ifindex() == ifindex)
            .collect())
    }

    /// Get the proxy entries (`ip neigh show proxy`), every family.
    ///
    /// They are not in the plain dump: `neigh_dump_info` walks the proxy
    /// table instead of the neighbour table only when the request's
    /// `ndm_flags` is exactly `NTF_PROXY`.
    pub(crate) async fn get_proxy_neighbors(
        &self,
    ) -> Result<Vec<super::messages::NeighborMessage>> {
        use super::{message::{NLM_F_DUMP, NLMSG_HDRLEN}, parse::FromNetlink};

        let mut ndmsg = NdMsg::new();
        ndmsg.ndm_flags = ntf::PROXY;
        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP);
        builder.append(&ndmsg);

        let mut parsed = Vec::new();
        for response in self.send_dump(builder).await? {
            if response.len() < NLMSG_HDRLEN {
                continue;
            }
            if let Ok(msg) = super::messages::NeighborMessage::from_bytes(&response[NLMSG_HDRLEN..]) {
                parsed.push(msg);
            }
        }
        Ok(parsed)
    }
}
