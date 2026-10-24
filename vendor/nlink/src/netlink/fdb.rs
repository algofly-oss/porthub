//! Bridge Forwarding Database (FDB) management.
//!
//! This module provides typed builders for managing bridge FDB entries,
//! which are used for MAC address learning and forwarding in Linux bridges.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # use std::net::IpAddr;
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::fdb::FdbEntryBuilder;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // List FDB entries for a bridge
//! let entries = conn.get_fdb("br0").await?;
//! for entry in &entries {
//!     println!("{} vlan={:?}", entry.mac_str(), entry.vlan());
//! }
//!
//! // Add a static FDB entry: frames for the MAC leave through veth0
//! let mac = FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff")?;
//! conn.add_fdb(
//!     FdbEntryBuilder::new(mac)
//!         .dev("veth0")
//!         .master("br0")
//!         .static_()
//! ).await?;
//!
//! // Add VXLAN FDB entry (remote VTEP), in the device's own table
//! use std::net::Ipv4Addr;
//! conn.add_fdb(
//!     FdbEntryBuilder::new([0x00; 6])  // all-zeros for BUM traffic
//!         .dev("vxlan0")
//!         .dst(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
//!         .self_()
//! ).await?;
//!
//! // Delete an entry
//! conn.del_fdb("veth0", mac, None).await?;
//! # Ok(())
//! # }
//! ```

use std::net::IpAddr;

use super::{
    builder::MessageBuilder,
    connection::Connection,
    error::{Error, Result},
    interface_ref::InterfaceRef,
    message::{NLM_F_ACK, NLM_F_APPEND, NLM_F_DUMP, NLM_F_REQUEST, NlMsgType},
    messages::NeighborMessage,
    protocol::Route,
    types::neigh::{NdMsg, NdaAttr, NeighborState},
};

/// NLM_F_CREATE flag
const NLM_F_CREATE: u16 = 0x400;
/// NLM_F_EXCL flag - fail if entry exists
const NLM_F_EXCL: u16 = 0x200;
/// NLM_F_REPLACE flag - replace existing entry
const NLM_F_REPLACE: u16 = 0x100;

/// AF_BRIDGE constant
const AF_BRIDGE: u8 = 7;

/// Neighbor flags for FDB entries (`NTF_*` from `linux/neighbour.h`).
mod ntf {
    /// `NTF_SELF` — entry for the interface itself.
    pub const SELF: u8 = 0x02;
    /// `NTF_MASTER` — entry for the master bridge.
    pub const MASTER: u8 = 0x04;
    /// `NTF_PROXY` — proxy entry (the local stack answers for it).
    pub const PROXY: u8 = 0x08;
    /// `NTF_EXT_LEARNED` — externally learned entry.
    pub const EXT_LEARNED: u8 = 0x10;
    /// `NTF_OFFLOADED` — entry is offloaded to hardware. Read-only,
    /// set by the kernel; ignored on writes.
    pub const OFFLOADED: u8 = 0x20;
    /// `NTF_STICKY` — entry is not refreshed/replaced by MAC learning.
    pub const STICKY: u8 = 0x40;
    /// `NTF_ROUTER` — the destination is a router (VXLAN/EVPN).
    pub const ROUTER: u8 = 0x80;
}

/// Neighbor states
mod nud {
    /// Permanent entry: on a bridge, a local one (the bridge's own MAC)
    pub const PERMANENT: u16 = 0x80;
    /// Static entry: forwarded to its port, never aged
    pub const NOARP: u16 = 0x40;
    /// Reachable (dynamic) entry
    pub const REACHABLE: u16 = 0x02;
}

/// FDB entry information.
///
/// Represents a bridge forwarding database entry, containing MAC address
/// to port mappings, optional VLAN information, and VXLAN remote endpoint
/// data.
///
/// Fields are `pub(crate)`; consumers read via the per-field
/// accessor methods. The struct is `#[non_exhaustive]` so the
/// kernel can grow new FDB attribute fields without it being a
/// breaking change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FdbEntry {
    /// Interface index (bridge port)
    pub(crate) ifindex: u32,
    /// MAC address (6 bytes)
    pub(crate) mac: [u8; 6],
    /// VLAN ID (if VLAN filtering is enabled)
    pub(crate) vlan: Option<u16>,
    /// Destination IP (for VXLAN remote VTEP)
    pub(crate) dst: Option<IpAddr>,
    /// VNI (for VXLAN)
    pub(crate) vni: Option<u32>,
    /// Entry state (permanent, reachable, etc.)
    pub(crate) state: NeighborState,
    /// Entry flags (NTF_SELF, NTF_MASTER, etc.)
    pub(crate) flags: u8,
    /// Master device index (bridge interface)
    pub(crate) master: Option<u32>,
}

impl FdbEntry {
    /// Create from a NeighborMessage.
    ///
    /// Returns `None` if the message doesn't have a valid MAC address.
    pub fn from_neighbor(msg: &NeighborMessage) -> Option<Self> {
        let lladdr = msg.lladdr()?;
        if lladdr.len() != 6 {
            return None;
        }

        let mut mac = [0u8; 6];
        mac.copy_from_slice(lladdr);

        Some(Self {
            ifindex: msg.ifindex(),
            mac,
            vlan: msg.vlan(),
            dst: msg.destination().cloned(),
            vni: msg.vni(),
            state: msg.state(),
            flags: msg.flags(),
            master: msg.master(),
        })
    }

    /// Interface index (bridge port).
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// MAC address (6 bytes).
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// VLAN ID, if VLAN filtering is enabled on the bridge.
    pub fn vlan(&self) -> Option<u16> {
        self.vlan
    }

    /// Destination IP for VXLAN remote VTEP, if set.
    pub fn dst(&self) -> Option<IpAddr> {
        self.dst
    }

    /// VNI for VXLAN tunnels, if set.
    pub fn vni(&self) -> Option<u32> {
        self.vni
    }

    /// Entry state (permanent / reachable / stale / …).
    pub fn state(&self) -> NeighborState {
        self.state
    }

    /// Entry flags (NTF_SELF / NTF_MASTER / NTF_EXT_LEARNED / …).
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Master device index (bridge interface), if set.
    pub fn master(&self) -> Option<u32> {
        self.master
    }

    /// Check if this is a permanent entry (`NUD_PERMANENT`), which
    /// `bridge fdb` shows as `permanent`: on a bridge, a local one — the
    /// MAC is the bridge's own, and frames for it go up its stack.
    pub fn is_permanent(&self) -> bool {
        self.state == NeighborState::Permanent
    }

    /// Check if this is a static entry (`NUD_NOARP`), which `bridge fdb`
    /// shows as `static`: forwarded to its port, and never aged (#663).
    pub fn is_static(&self) -> bool {
        self.state == NeighborState::Noarp
    }

    /// Check if this is a dynamic (learned) entry: neither permanent nor
    /// static. A static entry used to count as dynamic (#663).
    pub fn is_dynamic(&self) -> bool {
        !self.is_permanent() && !self.is_static()
    }

    /// Check if entry is for the interface itself (NTF_SELF).
    pub fn is_self(&self) -> bool {
        self.flags & ntf::SELF != 0
    }

    /// Check if entry is for the master bridge (NTF_MASTER).
    pub fn is_master(&self) -> bool {
        self.flags & ntf::MASTER != 0
    }

    /// Check if entry was externally learned (NTF_EXT_LEARNED).
    pub fn is_extern_learn(&self) -> bool {
        self.flags & ntf::EXT_LEARNED != 0
    }

    /// Check if the entry is sticky (NTF_STICKY) — not refreshed or
    /// replaced by MAC learning.
    pub fn is_sticky(&self) -> bool {
        self.flags & ntf::STICKY != 0
    }

    /// Check if the destination is flagged as a router (NTF_ROUTER).
    pub fn is_router(&self) -> bool {
        self.flags & ntf::ROUTER != 0
    }

    /// Check if the entry is offloaded to hardware (NTF_OFFLOADED).
    /// This flag is set by the kernel and read-only.
    pub fn is_offloaded(&self) -> bool {
        self.flags & ntf::OFFLOADED != 0
    }

    /// Check if the entry is a proxy entry (NTF_PROXY).
    pub fn is_proxy(&self) -> bool {
        self.flags & ntf::PROXY != 0
    }

    /// Format MAC address as a colon-separated hex string.
    pub fn mac_str(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
        )
    }
}

/// The `ndm_state` an [`FdbEntryBuilder`] sends.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum EntryState {
    Permanent,
    Static,
    #[default]
    Dynamic,
}

/// Builder for FDB entries.
///
/// # Example
///
/// ```no_run
/// # use std::net::IpAddr;
/// use nlink::netlink::fdb::FdbEntryBuilder;
/// use std::net::Ipv4Addr;
///
/// // Static entry on a bridge port
/// let entry = FdbEntryBuilder::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
///     .dev("veth0")
///     .master("br0")
///     .vlan(100)
///     .static_();
///
/// // VXLAN remote VTEP entry, in the device's own table
/// let vxlan_entry = FdbEntryBuilder::new([0x00; 6])
///     .dev("vxlan0")
///     .dst(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
///     .self_();
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct FdbEntryBuilder {
    mac: [u8; 6],
    dev: Option<InterfaceRef>,
    vlan: Option<u16>,
    dst: Option<IpAddr>,
    vni: Option<u32>,
    master: Option<InterfaceRef>,
    state: EntryState,
    self_flag: bool,
    extern_learn: bool,
    sticky: bool,
    router: bool,
}

impl FdbEntryBuilder {
    /// Create a new FDB entry builder with the given MAC address.
    ///
    /// By default the entry is [`permanent`](Self::permanent), as with
    /// `bridge fdb add`: on a bridge, a local entry. For one that
    /// forwards to its port, use [`static_`](Self::static_).
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            state: EntryState::Permanent,
            ..Default::default()
        }
    }

    /// Parse a MAC address from a colon-separated hex string.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::FdbEntryBuilder;
    /// let mac = FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_mac(mac_str: &str) -> Result<[u8; 6]> {
        crate::util::addr::parse_mac(mac_str)
            .map_err(|e| Error::invalid_message(format!("invalid MAC: {}", e)))
    }

    /// Set the device name (bridge port interface).
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(InterfaceRef::Name(dev.into()));
        self
    }

    /// Set the interface index directly (namespace-safe).
    ///
    /// Use this instead of `dev()` when operating in a network namespace
    /// to avoid reading `/sys/class/net/` from the wrong namespace.
    pub fn ifindex(mut self, ifindex: u32) -> Self {
        self.dev = Some(InterfaceRef::Index(ifindex));
        self
    }

    /// Get the device reference.
    pub fn device_ref(&self) -> Option<&InterfaceRef> {
        self.dev.as_ref()
    }

    /// Set the VLAN ID.
    ///
    /// Only relevant for bridges with VLAN filtering enabled.
    pub fn vlan(mut self, vlan: u16) -> Self {
        self.vlan = Some(vlan);
        self
    }

    /// Set the destination IP address (for VXLAN FDB entries).
    ///
    /// This specifies the remote VTEP IP address for VXLAN tunneling.
    pub fn dst(mut self, dst: IpAddr) -> Self {
        self.dst = Some(dst);
        self
    }

    /// Set the VNI (for VXLAN FDB entries).
    pub fn vni(mut self, vni: u32) -> Self {
        self.vni = Some(vni);
        self
    }

    /// Set the master bridge device by name.
    pub fn master(mut self, master: impl Into<String>) -> Self {
        self.master = Some(InterfaceRef::Name(master.into()));
        self
    }

    /// Set the master bridge device by interface index (namespace-safe).
    pub fn master_ifindex(mut self, ifindex: u32) -> Self {
        self.master = Some(InterfaceRef::Index(ifindex));
        self
    }

    /// Get the master device reference.
    pub fn master_ref(&self) -> Option<&InterfaceRef> {
        self.master.as_ref()
    }

    /// Mark the entry permanent (`NUD_PERMANENT`, `bridge fdb … permanent`).
    /// This is the default. On a bridge it is a *local* entry: the MAC is
    /// the bridge's own, and frames for it go up the bridge's stack rather
    /// than out of the port. On a VXLAN device's own table, it is the
    /// usual state of a remote. Until 0.32 this was documented as a static
    /// entry, which it is not on a bridge (#663).
    pub fn permanent(mut self) -> Self {
        self.state = EntryState::Permanent;
        self
    }

    /// Mark the entry static (`NUD_NOARP`, `bridge fdb … static`): frames
    /// for the MAC are forwarded to the entry's port, and the entry never
    /// ages (#663).
    pub fn static_(mut self) -> Self {
        self.state = EntryState::Static;
        self
    }

    /// Mark entry as dynamic (will age out).
    pub fn dynamic(mut self) -> Self {
        self.state = EntryState::Dynamic;
        self
    }

    /// Add to interface's own FDB (sets NTF_SELF flag).
    ///
    /// A VXLAN device's remotes go here. Without it the entry goes to the
    /// bridge the device is a port of, and a device that is not one fails
    /// with `EOPNOTSUPP` (#663).
    pub fn self_(mut self) -> Self {
        self.self_flag = true;
        self
    }

    /// Mark the entry as externally learned (sets NTF_EXT_LEARNED).
    ///
    /// Externally-learned entries are managed by a user-space control
    /// plane (e.g. an EVPN/VXLAN agent) rather than the kernel's normal
    /// MAC learning; the kernel will not age or overwrite them.
    pub fn extern_learn(mut self) -> Self {
        self.extern_learn = true;
        self
    }

    /// Mark the entry as sticky (sets NTF_STICKY).
    ///
    /// A sticky entry is pinned to its current port: the kernel will
    /// not move or overwrite it via MAC learning, even if the same MAC
    /// is seen on another port.
    pub fn sticky(mut self) -> Self {
        self.sticky = true;
        self
    }

    /// Mark the destination as a router (sets NTF_ROUTER).
    ///
    /// Used for VXLAN/EVPN remote VTEPs that are routers, so the
    /// bridge treats the peer accordingly (e.g. for ARP/ND suppression).
    pub fn router(mut self) -> Self {
        self.router = true;
        self
    }

    /// Write the add message to the builder with resolved interface indices.
    pub(crate) fn write_add(
        &self,
        builder: &mut MessageBuilder,
        ifindex: u32,
        master_idx: Option<u32>,
    ) {
        let state = match self.state {
            EntryState::Permanent => nud::PERMANENT,
            EntryState::Static => nud::NOARP,
            EntryState::Dynamic => nud::REACHABLE,
        };

        let mut ntf_flags: u8 = 0;
        if self.self_flag {
            ntf_flags |= ntf::SELF;
        }
        if self.extern_learn {
            ntf_flags |= ntf::EXT_LEARNED;
        }
        if self.sticky {
            ntf_flags |= ntf::STICKY;
        }
        if self.router {
            ntf_flags |= ntf::ROUTER;
        }

        let ndmsg = NdMsg::new()
            .with_family(AF_BRIDGE)
            .with_ifindex(ifindex as i32)
            .with_state(state)
            .with_flags(ntf_flags);

        builder.append(&ndmsg);

        // NDA_LLADDR - MAC address (required)
        builder.append_attr(NdaAttr::Lladdr as u16, &self.mac);

        // NDA_MASTER - bridge interface
        if let Some(master) = master_idx {
            builder.append_attr_u32(NdaAttr::Master as u16, master);
        }

        // NDA_VLAN
        if let Some(vlan) = self.vlan {
            builder.append_attr_u16(NdaAttr::Vlan as u16, vlan);
        }

        // NDA_DST - remote IP for VXLAN
        if let Some(ref dst) = self.dst {
            match dst {
                IpAddr::V4(v4) => {
                    builder.append_attr(NdaAttr::Dst as u16, &v4.octets());
                }
                IpAddr::V6(v6) => {
                    builder.append_attr(NdaAttr::Dst as u16, &v6.octets());
                }
            }
        }

        // NDA_VNI
        if let Some(vni) = self.vni {
            builder.append_attr_u32(NdaAttr::Vni as u16, vni);
        }
    }

    /// Write a delete of exactly this entry: in the device's own table
    /// with [`self_`](Self::self_), and only its remote with
    /// [`dst`](Self::dst).
    pub(crate) fn write_delete_exact(&self, builder: &mut MessageBuilder, ifindex: u32) {
        let flags = if self.self_flag { ntf::SELF } else { 0 };
        let ndmsg = NdMsg::new()
            .with_family(AF_BRIDGE)
            .with_ifindex(ifindex as i32)
            .with_flags(flags);
        builder.append(&ndmsg);
        builder.append_attr(NdaAttr::Lladdr as u16, &self.mac);
        if let Some(vlan) = self.vlan {
            builder.append_attr_u16(NdaAttr::Vlan as u16, vlan);
        }
        match self.dst {
            Some(IpAddr::V4(v4)) => builder.append_attr(NdaAttr::Dst as u16, &v4.octets()),
            Some(IpAddr::V6(v6)) => builder.append_attr(NdaAttr::Dst as u16, &v6.octets()),
            None => {}
        }
        if let Some(vni) = self.vni {
            builder.append_attr_u32(NdaAttr::Vni as u16, vni);
        }
    }

    /// Write the delete message to the builder with resolved interface index.
    pub(crate) fn write_delete(&self, builder: &mut MessageBuilder, ifindex: u32) {
        let ndmsg = NdMsg::new()
            .with_family(AF_BRIDGE)
            .with_ifindex(ifindex as i32);

        builder.append(&ndmsg);

        // NDA_LLADDR - MAC address (required for delete)
        builder.append_attr(NdaAttr::Lladdr as u16, &self.mac);

        // NDA_VLAN - needed if VLAN filtering is enabled
        if let Some(vlan) = self.vlan {
            builder.append_attr_u16(NdaAttr::Vlan as u16, vlan);
        }
    }
}

// ============================================================================
// Connection Methods
// ============================================================================

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Get all FDB entries for a bridge.
    ///
    /// Returns entries where the master device matches the specified bridge,
    /// or entries directly on the bridge interface itself.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let entries = conn.get_fdb("br0").await?;
    /// for entry in &entries {
    ///     println!("{} on ifindex {} vlan={:?}",
    ///         entry.mac_str(), entry.ifindex(), entry.vlan());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_fdb"))]
    pub async fn get_fdb(&self, bridge: impl Into<InterfaceRef>) -> Result<Vec<FdbEntry>> {
        let bridge_idx = self.resolve_interface(&bridge.into()).await?;
        self.get_fdb_by_index(bridge_idx).await
    }

    /// Get all FDB entries for a bridge by interface index.
    ///
    /// Use this method when operating in a network namespace to avoid
    /// reading `/sys/class/net/` from the wrong namespace.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_fdb_by_index"))]
    pub async fn get_fdb_by_index(&self, bridge_idx: u32) -> Result<Vec<FdbEntry>> {
        // Query neighbors with AF_BRIDGE family to get FDB entries
        let neighbors = self.get_bridge_neighbors().await?;

        Ok(neighbors
            .iter()
            .filter(|n| n.master() == Some(bridge_idx) || n.ifindex() == bridge_idx)
            .filter_map(FdbEntry::from_neighbor)
            .collect())
    }

    /// Get all bridge neighbor entries (AF_BRIDGE FDB dump): every
    /// device's, not one bridge's — `rtnl_fdb_dump` walks each device,
    /// the bridge database entries of a port and the device's own
    /// (`ndo_fdb_dump`, or its unicast/multicast address lists).
    pub(crate) async fn get_bridge_neighbors(&self) -> Result<Vec<NeighborMessage>> {
        use super::{message::NLMSG_HDRLEN, parse::FromNetlink};

        let ndmsg = NdMsg::new().with_family(AF_BRIDGE);
        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP);
        builder.append(&ndmsg);

        let responses = self.send_dump(builder).await?;

        let mut parsed = Vec::new();
        for response in responses {
            if response.len() < NLMSG_HDRLEN {
                continue;
            }
            let payload = &response[NLMSG_HDRLEN..];
            if let Ok(msg) = NeighborMessage::from_bytes(payload) {
                parsed.push(msg);
            }
        }
        Ok(parsed)
    }

    /// Get FDB entries for a specific bridge port.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let entries = conn.get_fdb_for_port("br0", "veth0").await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_fdb_for_port"))]
    pub async fn get_fdb_for_port(
        &self,
        bridge: impl Into<InterfaceRef>,
        port: impl Into<InterfaceRef>,
    ) -> Result<Vec<FdbEntry>> {
        let bridge_idx = self.resolve_interface(&bridge.into()).await?;
        let port_idx = self.resolve_interface(&port.into()).await?;

        let neighbors = self.get_bridge_neighbors().await?;

        Ok(neighbors
            .iter()
            .filter(|n| n.ifindex() == port_idx)
            .filter(|n| n.master() == Some(bridge_idx))
            .filter_map(FdbEntry::from_neighbor)
            .collect())
    }

    /// Resolve FDB entry interface references.
    async fn resolve_fdb_interfaces(&self, entry: &FdbEntryBuilder) -> Result<(u32, Option<u32>)> {
        let ifindex = match entry.device_ref() {
            Some(iface) => self.resolve_interface(iface).await?,
            None => {
                return Err(Error::invalid_message(
                    "device name or ifindex required",
                ));
            }
        };

        let master_idx = match entry.master_ref() {
            Some(iface) => Some(self.resolve_interface(iface).await?),
            None => None,
        };

        Ok((ifindex, master_idx))
    }

    /// Add an FDB entry.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::fdb::FdbEntryBuilder;
    ///
    /// let mac = FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff")?;
    /// conn.add_fdb(
    ///     FdbEntryBuilder::new(mac)
    ///         .dev("veth0")
    ///         .master("br0")
    ///         .vlan(100)
    /// ).await?;
    ///
    /// // Namespace-safe version using interface index
    /// conn.add_fdb(
    ///     FdbEntryBuilder::new(mac)
    ///         .ifindex(5)
    ///         .master_ifindex(3)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_fdb"))]
    pub async fn add_fdb(&self, entry: FdbEntryBuilder) -> Result<()> {
        let (ifindex, master_idx) = self.resolve_fdb_interfaces(&entry).await?;
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        entry.write_add(&mut builder, ifindex, master_idx);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_fdb"))
    }

    /// Replace an FDB entry (add or update).
    ///
    /// If the entry exists, it will be updated. Otherwise, it will be created.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_fdb"))]
    pub async fn replace_fdb(&self, entry: FdbEntryBuilder) -> Result<()> {
        let (ifindex, master_idx) = self.resolve_fdb_interfaces(&entry).await?;
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        entry.write_add(&mut builder, ifindex, master_idx);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("replace_fdb"))
    }

    /// Add an FDB entry, or one more remote to it (`bridge fdb append`,
    /// `NLM_F_APPEND`): a VXLAN device's all-zeros or multicast entry
    /// holds a list of remotes, which [`replace_fdb`](Self::replace_fdb)
    /// would overwrite the first of. One already listed is left as it is.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "append_fdb"))]
    pub async fn append_fdb(&self, entry: FdbEntryBuilder) -> Result<()> {
        let (ifindex, master_idx) = self.resolve_fdb_interfaces(&entry).await?;
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
        );
        entry.write_add(&mut builder, ifindex, master_idx);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("append_fdb"))
    }

    /// Delete exactly the entry `entry` describes: in the bridge's table,
    /// or the device's own with [`self_`](FdbEntryBuilder::self_); with
    /// its VLAN; and with [`dst`](FdbEntryBuilder::dst), only that remote
    /// of a VXLAN entry, where [`del_fdb`](Self::del_fdb) deletes them all.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_fdb_entry"))]
    pub async fn del_fdb_entry(&self, entry: FdbEntryBuilder) -> Result<()> {
        let (ifindex, _) = self.resolve_fdb_interfaces(&entry).await?;
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELNEIGH, NLM_F_REQUEST | NLM_F_ACK);
        entry.write_delete_exact(&mut builder, ifindex);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_fdb_entry"))
    }

    /// Delete an FDB entry by device name, MAC address, and optional VLAN.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// // Delete entry without VLAN
    /// conn.del_fdb("veth0", [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], None).await?;
    ///
    /// // Delete entry with specific VLAN
    /// conn.del_fdb("veth0", [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], Some(100)).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_fdb"))]
    pub async fn del_fdb(
        &self,
        dev: impl Into<InterfaceRef>,
        mac: [u8; 6],
        vlan: Option<u16>,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.del_fdb_by_index(ifindex, mac, vlan).await
    }

    /// Delete an FDB entry by interface index, MAC address, and optional VLAN.
    ///
    /// Use this method when operating in a network namespace.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_fdb_by_index"))]
    pub async fn del_fdb_by_index(
        &self,
        ifindex: u32,
        mac: [u8; 6],
        vlan: Option<u16>,
    ) -> Result<()> {
        let mut entry = FdbEntryBuilder::new(mac).ifindex(ifindex);
        if let Some(v) = vlan {
            entry = entry.vlan(v);
        }
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELNEIGH, NLM_F_REQUEST | NLM_F_ACK);
        entry.write_delete(&mut builder, ifindex);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_fdb"))
    }

    /// Flush all dynamic FDB entries for a bridge.
    ///
    /// Permanent (static) entries are not removed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.flush_fdb("br0").await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_fdb"))]
    pub async fn flush_fdb(&self, bridge: impl Into<InterfaceRef>) -> Result<()> {
        let entries = self.get_fdb(bridge).await?;

        for entry in entries {
            // Only flush dynamic entries
            if entry.is_dynamic()
                && let Err(e) = self
                    .del_fdb_by_index(entry.ifindex, entry.mac, entry.vlan)
                    .await
            {
                // Ignore "not found" errors (race condition with aging)
                if !e.is_not_found() {
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac() {
        let mac = FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_uppercase() {
        let mac = FdbEntryBuilder::parse_mac("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert!(FdbEntryBuilder::parse_mac("invalid").is_err());
        assert!(FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee").is_err());
        assert!(FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff:gg").is_err());
    }

    #[test]
    fn test_fdb_entry_mac_str() {
        let entry = FdbEntry {
            ifindex: 1,
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            vlan: None,
            dst: None,
            vni: None,
            state: NeighborState::Permanent,
            flags: 0,
            master: None,
        };
        assert_eq!(entry.mac_str(), "00:11:22:33:44:55");
    }

    #[test]
    fn test_fdb_entry_flags() {
        let entry = FdbEntry {
            ifindex: 1,
            mac: [0; 6],
            vlan: None,
            dst: None,
            vni: None,
            state: NeighborState::Permanent,
            flags: ntf::SELF | ntf::MASTER,
            master: None,
        };
        assert!(entry.is_self());
        assert!(entry.is_master());
        assert!(!entry.is_extern_learn());
    }

    #[test]
    fn test_fdb_entry_permanent() {
        let permanent = FdbEntry {
            ifindex: 1,
            mac: [0; 6],
            vlan: None,
            dst: None,
            vni: None,
            state: NeighborState::Permanent,
            flags: 0,
            master: None,
        };
        assert!(permanent.is_permanent());
        assert!(!permanent.is_dynamic());

        let dynamic = FdbEntry {
            ifindex: 1,
            mac: [0; 6],
            vlan: None,
            dst: None,
            vni: None,
            state: NeighborState::Reachable,
            flags: 0,
            master: None,
        };
        assert!(!dynamic.is_permanent());
        assert!(dynamic.is_dynamic());
    }

    #[test]
    fn test_builder_default() {
        let builder = FdbEntryBuilder::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(builder.state, EntryState::Permanent); // default is permanent
        assert!(!builder.self_flag);
    }

    // ---- NTF flag completeness (#137 bridge/FDB audit) ----

    #[test]
    fn ntf_constants_match_kernel() {
        // linux/neighbour.h NTF_* values.
        assert_eq!(ntf::SELF, 0x02);
        assert_eq!(ntf::MASTER, 0x04);
        assert_eq!(ntf::PROXY, 0x08);
        assert_eq!(ntf::EXT_LEARNED, 0x10);
        assert_eq!(ntf::OFFLOADED, 0x20);
        assert_eq!(ntf::STICKY, 0x40);
        assert_eq!(ntf::ROUTER, 0x80);
    }

    #[test]
    fn fdb_entry_flag_accessors() {
        let mk = |flags: u8| FdbEntry {
            ifindex: 1,
            mac: [0; 6],
            vlan: None,
            dst: None,
            vni: None,
            state: NeighborState::Permanent,
            flags,
            master: None,
        };
        assert!(mk(ntf::STICKY).is_sticky());
        assert!(mk(ntf::ROUTER).is_router());
        assert!(mk(ntf::OFFLOADED).is_offloaded());
        assert!(mk(ntf::PROXY).is_proxy());
        // Mutually exclusive: a sticky-only entry isn't router/offloaded.
        let s = mk(ntf::STICKY);
        assert!(!s.is_router() && !s.is_offloaded() && !s.is_proxy());
    }

    /// `write_add` must lower the sticky/router builder flags into the
    /// `ndmsg.ndm_flags` byte (offset 10 in the 12-byte ndmsg, which
    /// follows the 16-byte nlmsghdr → message offset 26).
    #[test]
    fn write_add_lowers_sticky_and_router_into_ndm_flags() {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_NEWNEIGH, 0);
        FdbEntryBuilder::new([0xaa; 6])
            .sticky()
            .router()
            .write_add(&mut builder, 5, None);
        let bytes = builder.finish();
        assert_eq!(bytes[16 + 10], ntf::STICKY | ntf::ROUTER);
    }

    #[test]
    fn write_add_self_and_extern_learn_flags() {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_NEWNEIGH, 0);
        FdbEntryBuilder::new([0xaa; 6])
            .self_()
            .extern_learn()
            .write_add(&mut builder, 5, None);
        let bytes = builder.finish();
        assert_eq!(bytes[16 + 10], ntf::SELF | ntf::EXT_LEARNED);
    }

    #[test]
    fn test_builder_chain() {
        let builder = FdbEntryBuilder::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
            .dev("veth0")
            .master("br0")
            .vlan(100)
            .dynamic()
            .self_();

        assert_eq!(builder.dev, Some(InterfaceRef::Name("veth0".to_string())));
        assert_eq!(builder.master, Some(InterfaceRef::Name("br0".to_string())));
        assert_eq!(builder.vlan, Some(100));
        assert_eq!(builder.state, EntryState::Dynamic);
        assert!(builder.self_flag);
    }

    /// Each state goes out as `bridge fdb` sends it, and a static entry
    /// reads back as static, not dynamic (#663).
    #[test]
    fn test_states_on_the_wire_and_back() {
        for (b, want) in [
            (FdbEntryBuilder::new([2, 0, 0, 0, 0, 1]), nud::PERMANENT),
            (FdbEntryBuilder::new([2, 0, 0, 0, 0, 1]).static_(), nud::NOARP),
            (FdbEntryBuilder::new([2, 0, 0, 0, 0, 1]).dynamic(), nud::REACHABLE),
        ] {
            let mut m = MessageBuilder::new(NlMsgType::RTM_NEWNEIGH, 0);
            b.write_add(&mut m, 3, None);
            let bytes = m.finish();
            // nlmsghdr (16), then ndmsg: family, pad, pad, ifindex (4), state (2).
            assert_eq!(u16::from_ne_bytes([bytes[24], bytes[25]]), want);
        }
        let entry = |state| FdbEntry {
            ifindex: 1,
            mac: [0; 6],
            vlan: None,
            dst: None,
            vni: None,
            state,
            flags: 0,
            master: None,
        };
        let s = entry(NeighborState::Noarp);
        assert!(s.is_static() && !s.is_dynamic() && !s.is_permanent());
        let p = entry(NeighborState::Permanent);
        assert!(p.is_permanent() && !p.is_dynamic() && !p.is_static());
        assert!(entry(NeighborState::Reachable).is_dynamic());
        assert!(entry(NeighborState::Stale).is_dynamic());
    }

    #[test]
    fn test_builder_ifindex() {
        let builder = FdbEntryBuilder::new([0; 6]).ifindex(5).master_ifindex(3);

        assert_eq!(builder.dev, Some(InterfaceRef::Index(5)));
        assert_eq!(builder.master, Some(InterfaceRef::Index(3)));
    }
}
