//! Bridge VLAN filtering configuration.
//!
//! This module provides API for managing per-port VLAN configuration on Linux
//! bridges with VLAN filtering enabled. It allows assigning VLANs to bridge
//! ports, setting PVID (Port VLAN ID), and configuring tagged/untagged modes.
//!
//! # VLAN Tunneling
//!
//! For VXLAN bridges, this module also supports VLAN-to-VNI (tunnel ID) mapping.
//! This allows different VLANs on a bridge port to be mapped to different VXLAN
//! tunnel identifiers.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::bridge_vlan::{BridgeVlanBuilder, BridgeVlanTunnelBuilder};
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Add VLAN 100 as PVID and untagged (native VLAN)
//! conn.add_bridge_vlan(
//!     BridgeVlanBuilder::new(100)
//!         .dev("eth0")
//!         .pvid()
//!         .untagged()
//! ).await?;
//!
//! // Add VLANs 200-210 as tagged
//! conn.add_bridge_vlan(
//!     BridgeVlanBuilder::new(200)
//!         .dev("eth0")
//!         .range(210)
//! ).await?;
//!
//! // Query VLANs
//! let vlans = conn.get_bridge_vlans("eth0").await?;
//! for vlan in &vlans {
//!     println!("VLAN {}: pvid={} untagged={}",
//!         vlan.vid(), vlan.flags().pvid, vlan.flags().untagged);
//! }
//!
//! // Delete VLAN
//! conn.del_bridge_vlan("eth0", 100).await?;
//!
//! // VLAN-to-VNI tunnel mapping (for VXLAN bridges)
//! conn.add_vlan_tunnel(
//!     BridgeVlanTunnelBuilder::new(100, 10000)
//!         .dev("vxlan0")
//! ).await?;
//!
//! // Query tunnel mappings
//! let tunnels = conn.get_vlan_tunnels("vxlan0").await?;
//! for t in &tunnels {
//!     println!("VLAN {} -> VNI {}", t.vid, t.tunnel_id);
//! }
//! # Ok(())
//! # }
//! ```

use super::{
    attr::AttrIter,
    builder::MessageBuilder,
    connection::Connection,
    error::{Error, Result},
    interface_ref::InterfaceRef,
    message::{MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlMsgType},
    protocol::Route,
    types::link::{
        BridgeVlanInfo, BrVlanMsg, IfInfoMsg, IflaAttr, br_state, bridge_af, bridge_vlan_flags,
        bridge_vlan_tunnel, bridge_vlandb, bridge_vlandb_dump, bridge_vlandb_entry,
        bridge_vlandb_gopts, rtext_filter,
    },
};

/// VLAN flags for bridge port configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BridgeVlanFlags {
    /// This is the PVID (Port VLAN ID) - untagged ingress default
    pub pvid: bool,
    /// Egress untagged - remove VLAN tag on egress
    pub untagged: bool,
}

impl BridgeVlanFlags {
    /// Create from raw kernel flags.
    pub fn from_raw(flags: u16) -> Self {
        Self {
            pvid: flags & bridge_vlan_flags::PVID != 0,
            untagged: flags & bridge_vlan_flags::UNTAGGED != 0,
        }
    }
}

/// Bridge VLAN entry information.
///
/// Fields are `pub(crate)`; consumers read via the per-field
/// accessor methods. The struct is `#[non_exhaustive]` so the
/// kernel can grow new VLAN attribute fields without it being
/// a breaking change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BridgeVlanEntry {
    /// Interface index (bridge port or bridge itself)
    pub(crate) ifindex: u32,
    /// VLAN ID (1-4094)
    pub(crate) vid: u16,
    /// VLAN flags
    pub(crate) flags: BridgeVlanFlags,
}

impl BridgeVlanEntry {
    /// Interface index of the bridge port (or bridge device itself).
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// VLAN ID (1-4094).
    pub fn vid(&self) -> u16 {
        self.vid
    }

    /// Combined VLAN flags (PVID / untagged).
    pub fn flags(&self) -> BridgeVlanFlags {
        self.flags
    }

    /// Check if this is the PVID for this port.
    pub fn is_pvid(&self) -> bool {
        self.flags.pvid
    }

    /// Check if egress is untagged.
    pub fn is_untagged(&self) -> bool {
        self.flags.untagged
    }
}

// ============================================================================
// VLAN Tunnel Mapping (VLAN-to-VNI for VXLAN bridges)
// ============================================================================

/// VLAN-to-tunnel ID mapping entry.
///
/// This represents a mapping between a VLAN ID and a tunnel ID (VNI for VXLAN).
/// Used on VXLAN bridge ports to map local VLANs to remote VXLAN tunnel IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeVlanTunnelEntry {
    /// Interface index
    pub ifindex: u32,
    /// VLAN ID (1-4094)
    pub vid: u16,
    /// Tunnel ID (VNI for VXLAN, max 16M)
    pub tunnel_id: u32,
}

/// Builder for VLAN-to-tunnel ID mapping operations.
///
/// Creates mappings between VLAN IDs and tunnel IDs (VNI) for VXLAN bridges.
/// The tunnel ID is typically a VXLAN Network Identifier (VNI).
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::bridge_vlan::BridgeVlanTunnelBuilder;
///
/// // Map VLAN 100 to VNI 10000
/// let config = BridgeVlanTunnelBuilder::new(100, 10000)
///     .dev("vxlan0");
///
/// // Map VLAN range 200-210 to VNI range 20000-20010 (1:1 mapping)
/// let range_config = BridgeVlanTunnelBuilder::new(200, 20000)
///     .dev("vxlan0")
///     .range(210);
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct BridgeVlanTunnelBuilder {
    dev: Option<InterfaceRef>,
    vid: u16,
    vid_end: Option<u16>,
    tunnel_id: u32,
}

impl BridgeVlanTunnelBuilder {
    /// Maximum tunnel ID (24-bit, ~16 million).
    pub const MAX_TUNNEL_ID: u32 = (1 << 24) - 1;

    /// Create a new VLAN tunnel mapping builder.
    ///
    /// # Arguments
    ///
    /// * `vid` - VLAN ID (1-4094)
    /// * `tunnel_id` - Tunnel ID / VNI (0 to 16777215)
    pub fn new(vid: u16, tunnel_id: u32) -> Self {
        Self {
            vid,
            tunnel_id,
            ..Default::default()
        }
    }

    /// Set device name.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(InterfaceRef::Name(dev.into()));
        self
    }

    /// Set interface index directly.
    ///
    /// Use this instead of `dev()` when operating in a network namespace.
    pub fn ifindex(mut self, ifindex: u32) -> Self {
        self.dev = Some(InterfaceRef::Index(ifindex));
        self
    }

    /// Get the device reference.
    pub fn device_ref(&self) -> Option<&InterfaceRef> {
        self.dev.as_ref()
    }

    /// Set VLAN range end for bulk operations.
    ///
    /// When set, VLANs from `vid` to `vid_end` are mapped to tunnel IDs
    /// starting from `tunnel_id` with a 1:1 mapping.
    /// For example, VLAN 100-110 with tunnel_id 10000 maps to:
    /// - VLAN 100 -> VNI 10000
    /// - VLAN 101 -> VNI 10001
    /// - ...
    /// - VLAN 110 -> VNI 10010
    pub fn range(mut self, vid_end: u16) -> Self {
        self.vid_end = Some(vid_end);
        self
    }

    /// Write netlink message for adding tunnel mapping.
    pub(crate) fn write_add(&self, builder: &mut MessageBuilder, ifindex: u32) -> Result<()> {
        self.write_message(builder, NlMsgType::RTM_SETLINK, ifindex)
    }

    /// Write netlink message for deleting tunnel mapping.
    pub(crate) fn write_del(&self, builder: &mut MessageBuilder, ifindex: u32) -> Result<()> {
        self.write_message(builder, NlMsgType::RTM_DELLINK, ifindex)
    }

    fn write_message(
        &self,
        builder: &mut MessageBuilder,
        _msg_type: u16,
        ifindex: u32,
    ) -> Result<()> {
        // Validate tunnel ID
        if self.tunnel_id > Self::MAX_TUNNEL_ID {
            return Err(Error::invalid_message(format!(
                "tunnel_id {} exceeds maximum {}",
                self.tunnel_id,
                Self::MAX_TUNNEL_ID
            )));
        }

        // Use AF_BRIDGE family
        let ifinfo = IfInfoMsg::new()
            .with_family(libc::AF_BRIDGE as u8)
            .with_index(ifindex as i32);
        builder.append(&ifinfo);

        // IFLA_AF_SPEC containing tunnel info
        let af_spec = builder.nest_start(IflaAttr::AfSpec as u16);

        if let Some(vid_end) = self.vid_end {
            if vid_end < self.vid {
                return Err(Error::invalid_message(format!(
                    "VLAN tunnel range {}..={vid_end} ends before it starts",
                    self.vid
                )));
            }
            // Range operation: emit tunnel entries with RANGE_BEGIN and RANGE_END flags
            self.add_tunnel_entry(
                builder,
                self.vid,
                self.tunnel_id,
                bridge_vlan_flags::RANGE_BEGIN,
            );

            // Calculate the end tunnel ID (1:1 mapping)
            let tunnel_id_end = self.tunnel_id + (vid_end - self.vid) as u32;
            if tunnel_id_end > Self::MAX_TUNNEL_ID {
                return Err(Error::invalid_message(format!(
                    "tunnel_id range end {} exceeds maximum {}",
                    tunnel_id_end,
                    Self::MAX_TUNNEL_ID
                )));
            }

            self.add_tunnel_entry(
                builder,
                vid_end,
                tunnel_id_end,
                bridge_vlan_flags::RANGE_END,
            );
        } else {
            // Single mapping
            self.add_tunnel_entry(builder, self.vid, self.tunnel_id, 0);
        }

        builder.nest_end(af_spec);

        Ok(())
    }

    /// Add a single tunnel entry to the message.
    fn add_tunnel_entry(&self, builder: &mut MessageBuilder, vid: u16, tunnel_id: u32, flags: u16) {
        let tunnel_info = builder.nest_start(bridge_af::IFLA_BRIDGE_VLAN_TUNNEL_INFO);

        builder.append_attr_u32(bridge_vlan_tunnel::IFLA_BRIDGE_VLAN_TUNNEL_ID, tunnel_id);
        builder.append_attr_u16(bridge_vlan_tunnel::IFLA_BRIDGE_VLAN_TUNNEL_VID, vid);
        if flags != 0 {
            builder.append_attr_u16(bridge_vlan_tunnel::IFLA_BRIDGE_VLAN_TUNNEL_FLAGS, flags);
        }

        builder.nest_end(tunnel_info);
    }
}

/// Builder for bridge VLAN operations.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::bridge_vlan::BridgeVlanBuilder;
///
/// // Add VLAN 100 as PVID and untagged
/// let config = BridgeVlanBuilder::new(100)
///     .dev("eth0")
///     .pvid()
///     .untagged();
///
/// // Add VLAN range 200-210 as tagged
/// let range_config = BridgeVlanBuilder::new(200)
///     .dev("eth0")
///     .range(210);
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct BridgeVlanBuilder {
    dev: Option<InterfaceRef>,
    vid: u16,
    vid_end: Option<u16>,
    pvid: bool,
    untagged: bool,
    master: bool,
}

impl BridgeVlanBuilder {
    /// Create a new VLAN builder for a single VID.
    ///
    /// VID must be in range 1-4094.
    pub fn new(vid: u16) -> Self {
        Self {
            vid,
            ..Default::default()
        }
    }

    /// Set device name.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(InterfaceRef::Name(dev.into()));
        self
    }

    /// Set interface index directly.
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

    /// Set VLAN range end (for bulk operations).
    ///
    /// When set, VLANs from `vid` to `vid_end` (inclusive) will be added/deleted.
    pub fn range(mut self, vid_end: u16) -> Self {
        self.vid_end = Some(vid_end);
        self
    }

    /// Mark as PVID (ingress untagged default).
    ///
    /// Untagged frames arriving on this port will be assigned this VLAN.
    /// Only one VLAN per port can be the PVID.
    pub fn pvid(mut self) -> Self {
        self.pvid = true;
        self
    }

    /// Mark as untagged (strip tag on egress).
    ///
    /// Frames with this VLAN leaving this port will have their tag removed.
    pub fn untagged(mut self) -> Self {
        self.untagged = true;
        self
    }

    /// Apply to bridge device itself (global VLAN entry).
    ///
    /// This creates a global VLAN entry on the bridge rather than a port-specific one.
    pub fn master(mut self) -> Self {
        self.master = true;
        self
    }

    /// Build the raw flags value.
    fn build_flags(&self) -> u16 {
        let mut flags = 0u16;
        if self.pvid {
            flags |= bridge_vlan_flags::PVID;
        }
        if self.untagged {
            flags |= bridge_vlan_flags::UNTAGGED;
        }
        if self.master {
            flags |= bridge_vlan_flags::MASTER;
        }
        flags
    }

    /// Write netlink message for adding VLAN.
    pub(crate) fn write_add(&self, builder: &mut MessageBuilder, ifindex: u32) {
        self.write_message(builder, ifindex);
    }

    /// Write netlink message for deleting VLAN.
    pub(crate) fn write_del(&self, builder: &mut MessageBuilder, ifindex: u32) {
        self.write_message(builder, ifindex);
    }

    fn write_message(&self, builder: &mut MessageBuilder, ifindex: u32) {
        // Use AF_BRIDGE family
        let ifinfo = IfInfoMsg::new()
            .with_family(libc::AF_BRIDGE as u8)
            .with_index(ifindex as i32);
        builder.append(&ifinfo);

        // IFLA_AF_SPEC containing VLAN info
        let af_spec = builder.nest_start(IflaAttr::AfSpec as u16);

        if let Some(vid_end) = self.vid_end {
            // Range operation: two entries with RANGE_BEGIN and RANGE_END flags
            let mut begin_flags = self.build_flags();
            begin_flags |= bridge_vlan_flags::RANGE_BEGIN;

            let vlan_begin = BridgeVlanInfo::new(self.vid).with_flags(begin_flags);
            builder.append_attr(bridge_af::IFLA_BRIDGE_VLAN_INFO, vlan_begin.as_bytes());

            let mut end_flags = self.build_flags();
            end_flags |= bridge_vlan_flags::RANGE_END;

            let vlan_end = BridgeVlanInfo::new(vid_end).with_flags(end_flags);
            builder.append_attr(bridge_af::IFLA_BRIDGE_VLAN_INFO, vlan_end.as_bytes());
        } else {
            // Single VLAN
            let flags = self.build_flags();
            let vlan_info = BridgeVlanInfo::new(self.vid).with_flags(flags);
            builder.append_attr(bridge_af::IFLA_BRIDGE_VLAN_INFO, vlan_info.as_bytes());
        }

        builder.nest_end(af_spec);
    }
}

// ============================================================================
// Bridge-global VLAN options (BRIDGE_VLANDB_GLOBAL_OPTIONS / GOPTS)
// ============================================================================

/// Builder for bridge-global per-VLAN options.
///
/// Global VLAN options are per-VLAN settings stored on the **bridge
/// device itself** (not on a port) — chiefly per-VLAN multicast
/// snooping (IGMP/MLD querier, versions, counts, and intervals) and
/// the MST instance mapping. They are carried by the newer VLAN-DB
/// netlink API (`RTM_NEWVLAN` over a `struct br_vlan_msg`), distinct
/// from the legacy per-port [`BridgeVlanBuilder`] path.
///
/// Only fields that are explicitly set are emitted, so a builder can
/// change a single option without disturbing the others.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::bridge_vlan::BridgeVlanGlobalOptionsBuilder;
///
/// // Enable multicast snooping on VLAN 100 of bridge br0.
/// conn.set_bridge_vlan_global_options(
///     BridgeVlanGlobalOptionsBuilder::new(100)
///         .dev("br0")
///         .mcast_snooping(true)
/// ).await?;
///
/// // Apply to a VLAN range 200-210.
/// conn.set_bridge_vlan_global_options(
///     BridgeVlanGlobalOptionsBuilder::new(200)
///         .dev("br0")
///         .range(210)
///         .mcast_snooping(false)
/// ).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Not modelled
///
/// `BRIDGE_VLANDB_GOPTS_MCAST_ROUTER_PORTS` (nested router-ports list)
/// and `BRIDGE_VLANDB_GOPTS_MCAST_QUERIER_STATE` (read-only querier
/// state) are recognized on the wire but not exposed as setters or
/// reader fields — they are nested/read-only attributes whose
/// semantics differ across kernel versions.
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct BridgeVlanGlobalOptionsBuilder {
    dev: Option<InterfaceRef>,
    vid: u16,
    vid_end: Option<u16>,
    mcast_snooping: Option<bool>,
    mcast_querier: Option<bool>,
    mcast_igmp_version: Option<u8>,
    mcast_mld_version: Option<u8>,
    mcast_last_member_count: Option<u32>,
    mcast_startup_query_count: Option<u32>,
    mcast_last_member_interval: Option<u64>,
    mcast_membership_interval: Option<u64>,
    mcast_querier_interval: Option<u64>,
    mcast_query_interval: Option<u64>,
    mcast_query_response_interval: Option<u64>,
    mcast_startup_query_interval: Option<u64>,
    msti: Option<u16>,
}

impl BridgeVlanGlobalOptionsBuilder {
    /// Create a builder for a single VLAN.
    pub fn new(vid: u16) -> Self {
        Self {
            vid,
            ..Default::default()
        }
    }

    /// Set the bridge device by name.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(InterfaceRef::Name(dev.into()));
        self
    }

    /// Set the bridge interface index directly.
    ///
    /// Prefer this over [`dev`](Self::dev) in a network namespace.
    pub fn ifindex(mut self, ifindex: u32) -> Self {
        self.dev = Some(InterfaceRef::Index(ifindex));
        self
    }

    /// Get the device reference.
    pub fn device_ref(&self) -> Option<&InterfaceRef> {
        self.dev.as_ref()
    }

    /// Apply the options to a VLAN range `vid..=vid_end`.
    pub fn range(mut self, vid_end: u16) -> Self {
        self.vid_end = Some(vid_end);
        self
    }

    /// Enable or disable per-VLAN multicast snooping.
    pub fn mcast_snooping(mut self, on: bool) -> Self {
        self.mcast_snooping = Some(on);
        self
    }

    /// Enable or disable the per-VLAN multicast querier.
    pub fn mcast_querier(mut self, on: bool) -> Self {
        self.mcast_querier = Some(on);
        self
    }

    /// Set the IGMP query version (2 or 3).
    pub fn mcast_igmp_version(mut self, version: u8) -> Self {
        self.mcast_igmp_version = Some(version);
        self
    }

    /// Set the MLD query version (1 or 2).
    pub fn mcast_mld_version(mut self, version: u8) -> Self {
        self.mcast_mld_version = Some(version);
        self
    }

    /// Set the last-member query count.
    pub fn mcast_last_member_count(mut self, count: u32) -> Self {
        self.mcast_last_member_count = Some(count);
        self
    }

    /// Set the startup query count.
    pub fn mcast_startup_query_count(mut self, count: u32) -> Self {
        self.mcast_startup_query_count = Some(count);
        self
    }

    /// Set the last-member query interval (centiseconds).
    pub fn mcast_last_member_interval(mut self, centisecs: u64) -> Self {
        self.mcast_last_member_interval = Some(centisecs);
        self
    }

    /// Set the membership interval (centiseconds).
    pub fn mcast_membership_interval(mut self, centisecs: u64) -> Self {
        self.mcast_membership_interval = Some(centisecs);
        self
    }

    /// Set the querier interval (centiseconds).
    pub fn mcast_querier_interval(mut self, centisecs: u64) -> Self {
        self.mcast_querier_interval = Some(centisecs);
        self
    }

    /// Set the query interval (centiseconds).
    pub fn mcast_query_interval(mut self, centisecs: u64) -> Self {
        self.mcast_query_interval = Some(centisecs);
        self
    }

    /// Set the query response interval (centiseconds).
    pub fn mcast_query_response_interval(mut self, centisecs: u64) -> Self {
        self.mcast_query_response_interval = Some(centisecs);
        self
    }

    /// Set the startup query interval (centiseconds).
    pub fn mcast_startup_query_interval(mut self, centisecs: u64) -> Self {
        self.mcast_startup_query_interval = Some(centisecs);
        self
    }

    /// Map this VLAN to an MST instance.
    pub fn msti(mut self, msti: u16) -> Self {
        self.msti = Some(msti);
        self
    }

    /// Write the `RTM_NEWVLAN` payload setting these global options.
    pub(crate) fn write_set(&self, builder: &mut MessageBuilder, ifindex: u32) {
        let msg = BrVlanMsg::new()
            .with_family(libc::AF_BRIDGE as u8)
            .with_index(ifindex);
        builder.append(&msg);

        let gopts = builder.nest_start(bridge_vlandb::GLOBAL_OPTIONS);

        builder.append_attr_u16(bridge_vlandb_gopts::ID, self.vid);
        if let Some(vid_end) = self.vid_end {
            builder.append_attr_u16(bridge_vlandb_gopts::RANGE, vid_end);
        }

        if let Some(v) = self.mcast_snooping {
            builder.append_attr_u8(bridge_vlandb_gopts::MCAST_SNOOPING, v as u8);
        }
        if let Some(v) = self.mcast_querier {
            builder.append_attr_u8(bridge_vlandb_gopts::MCAST_QUERIER, v as u8);
        }
        if let Some(v) = self.mcast_igmp_version {
            builder.append_attr_u8(bridge_vlandb_gopts::MCAST_IGMP_VERSION, v);
        }
        if let Some(v) = self.mcast_mld_version {
            builder.append_attr_u8(bridge_vlandb_gopts::MCAST_MLD_VERSION, v);
        }
        if let Some(v) = self.mcast_last_member_count {
            builder.append_attr_u32(bridge_vlandb_gopts::MCAST_LAST_MEMBER_CNT, v);
        }
        if let Some(v) = self.mcast_startup_query_count {
            builder.append_attr_u32(bridge_vlandb_gopts::MCAST_STARTUP_QUERY_CNT, v);
        }
        if let Some(v) = self.mcast_last_member_interval {
            builder.append_attr_u64(bridge_vlandb_gopts::MCAST_LAST_MEMBER_INTVL, v);
        }
        if let Some(v) = self.mcast_membership_interval {
            builder.append_attr_u64(bridge_vlandb_gopts::MCAST_MEMBERSHIP_INTVL, v);
        }
        if let Some(v) = self.mcast_querier_interval {
            builder.append_attr_u64(bridge_vlandb_gopts::MCAST_QUERIER_INTVL, v);
        }
        if let Some(v) = self.mcast_query_interval {
            builder.append_attr_u64(bridge_vlandb_gopts::MCAST_QUERY_INTVL, v);
        }
        if let Some(v) = self.mcast_query_response_interval {
            builder.append_attr_u64(bridge_vlandb_gopts::MCAST_QUERY_RESPONSE_INTVL, v);
        }
        if let Some(v) = self.mcast_startup_query_interval {
            builder.append_attr_u64(bridge_vlandb_gopts::MCAST_STARTUP_QUERY_INTVL, v);
        }
        if let Some(v) = self.msti {
            builder.append_attr_u16(bridge_vlandb_gopts::MSTI, v);
        }

        builder.nest_end(gopts);
    }
}

/// Bridge-global per-VLAN options, as read back from the kernel.
///
/// Returned by [`Connection::get_bridge_vlan_global_options`]. Fields
/// are `Option` because the kernel only reports options relevant to
/// the running configuration. The struct is `#[non_exhaustive]` so new
/// kernel options can be added without a breaking change.
///
/// See [`BridgeVlanGlobalOptionsBuilder`] for the *not modelled*
/// attributes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BridgeVlanGlobalOptions {
    pub(crate) ifindex: u32,
    pub(crate) vid: u16,
    pub(crate) vid_end: Option<u16>,
    pub(crate) mcast_snooping: Option<bool>,
    pub(crate) mcast_querier: Option<bool>,
    pub(crate) mcast_igmp_version: Option<u8>,
    pub(crate) mcast_mld_version: Option<u8>,
    pub(crate) mcast_last_member_count: Option<u32>,
    pub(crate) mcast_startup_query_count: Option<u32>,
    pub(crate) mcast_last_member_interval: Option<u64>,
    pub(crate) mcast_membership_interval: Option<u64>,
    pub(crate) mcast_querier_interval: Option<u64>,
    pub(crate) mcast_query_interval: Option<u64>,
    pub(crate) mcast_query_response_interval: Option<u64>,
    pub(crate) mcast_startup_query_interval: Option<u64>,
    pub(crate) msti: Option<u16>,
}

impl BridgeVlanGlobalOptions {
    /// Bridge interface index these options belong to.
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// VLAN ID (lower bound of the range, if a range).
    pub fn vid(&self) -> u16 {
        self.vid
    }

    /// Upper VLAN ID of the range, if this block covers a range.
    pub fn vid_end(&self) -> Option<u16> {
        self.vid_end
    }

    /// Whether per-VLAN multicast snooping is enabled.
    pub fn mcast_snooping(&self) -> Option<bool> {
        self.mcast_snooping
    }

    /// Whether the per-VLAN multicast querier is enabled.
    pub fn mcast_querier(&self) -> Option<bool> {
        self.mcast_querier
    }

    /// IGMP query version.
    pub fn mcast_igmp_version(&self) -> Option<u8> {
        self.mcast_igmp_version
    }

    /// MLD query version.
    pub fn mcast_mld_version(&self) -> Option<u8> {
        self.mcast_mld_version
    }

    /// Last-member query count.
    pub fn mcast_last_member_count(&self) -> Option<u32> {
        self.mcast_last_member_count
    }

    /// Startup query count.
    pub fn mcast_startup_query_count(&self) -> Option<u32> {
        self.mcast_startup_query_count
    }

    /// Last-member query interval (centiseconds).
    pub fn mcast_last_member_interval(&self) -> Option<u64> {
        self.mcast_last_member_interval
    }

    /// Membership interval (centiseconds).
    pub fn mcast_membership_interval(&self) -> Option<u64> {
        self.mcast_membership_interval
    }

    /// Querier interval (centiseconds).
    pub fn mcast_querier_interval(&self) -> Option<u64> {
        self.mcast_querier_interval
    }

    /// Query interval (centiseconds).
    pub fn mcast_query_interval(&self) -> Option<u64> {
        self.mcast_query_interval
    }

    /// Query response interval (centiseconds).
    pub fn mcast_query_response_interval(&self) -> Option<u64> {
        self.mcast_query_response_interval
    }

    /// Startup query interval (centiseconds).
    pub fn mcast_startup_query_interval(&self) -> Option<u64> {
        self.mcast_startup_query_interval
    }

    /// MST instance this VLAN maps to.
    pub fn msti(&self) -> Option<u16> {
        self.msti
    }
}

// ============================================================================
// Per-VLAN entry options (BRIDGE_VLANDB_ENTRY / per-(port, VLAN))
// ============================================================================

/// Spanning-tree state for a per-VLAN entry (`BR_STATE_*`), used for
/// MSTP — per-VLAN STP state on a bridge port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BridgeVlanState {
    /// Port disabled for this VLAN.
    Disabled,
    /// Listening (STP).
    Listening,
    /// Learning (STP).
    Learning,
    /// Forwarding.
    Forwarding,
    /// Blocking (STP).
    Blocking,
}

impl BridgeVlanState {
    /// Raw `BR_STATE_*` value.
    pub fn to_raw(self) -> u8 {
        match self {
            Self::Disabled => br_state::DISABLED,
            Self::Listening => br_state::LISTENING,
            Self::Learning => br_state::LEARNING,
            Self::Forwarding => br_state::FORWARDING,
            Self::Blocking => br_state::BLOCKING,
        }
    }

    /// Parse a raw `BR_STATE_*` value, `None` if unrecognised.
    pub fn from_raw(v: u8) -> Option<Self> {
        match v {
            br_state::DISABLED => Some(Self::Disabled),
            br_state::LISTENING => Some(Self::Listening),
            br_state::LEARNING => Some(Self::Learning),
            br_state::FORWARDING => Some(Self::Forwarding),
            br_state::BLOCKING => Some(Self::Blocking),
            _ => None,
        }
    }
}

/// Builder for per-VLAN entry options on a bridge port.
///
/// These are per-(port, VLAN) settings carried by the VLAN-DB API
/// (`RTM_NEWVLAN` → `BRIDGE_VLANDB_ENTRY`): the per-VLAN STP state
/// (MSTP), multicast router mode, multicast group limit, and
/// neighbour suppression. This complements (does not replace) the
/// legacy [`BridgeVlanBuilder`] membership path — set a VLAN's
/// membership with `add_bridge_vlan`, then tune its per-VLAN options
/// here.
///
/// Only options that are explicitly set are emitted.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::bridge_vlan::{BridgeVlanEntryOptionsBuilder, BridgeVlanState};
///
/// // Put VLAN 100 into forwarding state on port eth0.
/// conn.set_bridge_vlan_entry_options(
///     BridgeVlanEntryOptionsBuilder::new(100)
///         .dev("eth0")
///         .state(BridgeVlanState::Forwarding)
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct BridgeVlanEntryOptionsBuilder {
    dev: Option<InterfaceRef>,
    vid: u16,
    vid_end: Option<u16>,
    state: Option<BridgeVlanState>,
    mcast_router: Option<u8>,
    mcast_max_groups: Option<u32>,
    neigh_suppress: Option<bool>,
}

impl BridgeVlanEntryOptionsBuilder {
    /// Create a builder for a single VLAN on a port.
    pub fn new(vid: u16) -> Self {
        Self {
            vid,
            ..Default::default()
        }
    }

    /// Set the bridge port by name.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(InterfaceRef::Name(dev.into()));
        self
    }

    /// Set the bridge port interface index directly.
    ///
    /// Prefer this over [`dev`](Self::dev) in a network namespace.
    pub fn ifindex(mut self, ifindex: u32) -> Self {
        self.dev = Some(InterfaceRef::Index(ifindex));
        self
    }

    /// Get the device reference.
    pub fn device_ref(&self) -> Option<&InterfaceRef> {
        self.dev.as_ref()
    }

    /// Apply to a VLAN range `vid..=vid_end`.
    pub fn range(mut self, vid_end: u16) -> Self {
        self.vid_end = Some(vid_end);
        self
    }

    /// Set the per-VLAN STP state (MSTP).
    pub fn state(mut self, state: BridgeVlanState) -> Self {
        self.state = Some(state);
        self
    }

    /// Set the per-VLAN multicast router mode (0 disabled, 1 temp, 2 perm).
    pub fn mcast_router(mut self, mode: u8) -> Self {
        self.mcast_router = Some(mode);
        self
    }

    /// Set the per-VLAN multicast group limit.
    pub fn mcast_max_groups(mut self, max: u32) -> Self {
        self.mcast_max_groups = Some(max);
        self
    }

    /// Enable or disable neighbour suppression for this VLAN.
    pub fn neigh_suppress(mut self, on: bool) -> Self {
        self.neigh_suppress = Some(on);
        self
    }

    /// Write the `RTM_NEWVLAN` payload setting these entry options.
    pub(crate) fn write_set(&self, builder: &mut MessageBuilder, ifindex: u32) {
        let msg = BrVlanMsg::new()
            .with_family(libc::AF_BRIDGE as u8)
            .with_index(ifindex);
        builder.append(&msg);

        let entry = builder.nest_start(bridge_vlandb::ENTRY);

        // ENTRY_INFO is the struct bridge_vlan_info (flags + vid).
        let info = BridgeVlanInfo::new(self.vid);
        builder.append_attr(bridge_vlandb_entry::INFO, info.as_bytes());
        if let Some(vid_end) = self.vid_end {
            builder.append_attr_u16(bridge_vlandb_entry::RANGE, vid_end);
        }
        if let Some(state) = self.state {
            builder.append_attr_u8(bridge_vlandb_entry::STATE, state.to_raw());
        }
        if let Some(mode) = self.mcast_router {
            builder.append_attr_u8(bridge_vlandb_entry::MCAST_ROUTER, mode);
        }
        if let Some(max) = self.mcast_max_groups {
            builder.append_attr_u32(bridge_vlandb_entry::MCAST_MAX_GROUPS, max);
        }
        if let Some(on) = self.neigh_suppress {
            builder.append_attr_u8(bridge_vlandb_entry::NEIGH_SUPPRESS, on as u8);
        }

        builder.nest_end(entry);
    }
}

/// Per-VLAN entry options, as read back from the kernel.
///
/// Returned by [`Connection::get_bridge_vlan_entry_options`]. Fields
/// are `Option` because the kernel only reports options relevant to
/// the running configuration. `#[non_exhaustive]` for forward-compat.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BridgeVlanEntryOptions {
    pub(crate) ifindex: u32,
    pub(crate) vid: u16,
    pub(crate) vid_end: Option<u16>,
    pub(crate) state: Option<BridgeVlanState>,
    pub(crate) mcast_router: Option<u8>,
    pub(crate) mcast_n_groups: Option<u32>,
    pub(crate) mcast_max_groups: Option<u32>,
    pub(crate) neigh_suppress: Option<bool>,
}

impl BridgeVlanEntryOptions {
    /// Bridge port interface index these options belong to.
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// VLAN ID (lower bound of the range, if a range).
    pub fn vid(&self) -> u16 {
        self.vid
    }

    /// Upper VLAN ID of the range, if this block covers a range.
    pub fn vid_end(&self) -> Option<u16> {
        self.vid_end
    }

    /// Per-VLAN STP state.
    pub fn state(&self) -> Option<BridgeVlanState> {
        self.state
    }

    /// Per-VLAN multicast router mode.
    pub fn mcast_router(&self) -> Option<u8> {
        self.mcast_router
    }

    /// Current multicast group count (read-only).
    pub fn mcast_n_groups(&self) -> Option<u32> {
        self.mcast_n_groups
    }

    /// Multicast group limit.
    pub fn mcast_max_groups(&self) -> Option<u32> {
        self.mcast_max_groups
    }

    /// Whether neighbour suppression is enabled for this VLAN.
    pub fn neigh_suppress(&self) -> Option<bool> {
        self.neigh_suppress
    }
}

// ============================================================================
// Connection Methods
// ============================================================================

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Resolve BridgeVlanBuilder interface reference.
    async fn resolve_bridge_vlan_interface(&self, config: &BridgeVlanBuilder) -> Result<u32> {
        match config.device_ref() {
            Some(iface) => self.resolve_interface(iface).await,
            None => Err(Error::invalid_message(
                "device name or ifindex required",
            )),
        }
    }

    /// Resolve BridgeVlanTunnelBuilder interface reference.
    async fn resolve_bridge_vlan_tunnel_interface(
        &self,
        config: &BridgeVlanTunnelBuilder,
    ) -> Result<u32> {
        match config.device_ref() {
            Some(iface) => self.resolve_interface(iface).await,
            None => Err(Error::invalid_message(
                "device name or ifindex required",
            )),
        }
    }

    /// Get VLAN configuration for a bridge port.
    ///
    /// Returns all VLANs configured on the specified interface.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let vlans = conn.get_bridge_vlans("eth0").await?;
    /// for vlan in &vlans {
    ///     println!("VLAN {}: pvid={} untagged={}",
    ///         vlan.vid(), vlan.flags().pvid, vlan.flags().untagged);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_bridge_vlans"))]
    pub async fn get_bridge_vlans(
        &self,
        dev: impl Into<InterfaceRef>,
    ) -> Result<Vec<BridgeVlanEntry>> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.get_bridge_vlans_by_index(ifindex).await
    }

    /// Get VLAN configuration for a bridge port by interface index.
    ///
    /// Use this method when operating in a network namespace.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_bridge_vlans_by_index")
    )]
    pub async fn get_bridge_vlans_by_index(&self, ifindex: u32) -> Result<Vec<BridgeVlanEntry>> {
        // Only the AF_BRIDGE dump (`rtnl_bridge_getlink`) carries VLANs: a
        // single-link RTM_GETLINK falls through to the generic handler,
        // whose reply has none, so this returned nothing for every port
        // (#516).
        Ok(self
            .get_bridge_vlans_dump()
            .await?
            .into_iter()
            .filter(|v| v.ifindex == ifindex)
            .collect())
    }

    /// Get VLAN configuration for all ports of a bridge.
    ///
    /// Returns VLANs for all interfaces that are part of the bridge.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let vlans = conn.get_bridge_vlans_all("br0").await?;
    /// for vlan in &vlans {
    ///     println!("ifindex {}: VLAN {}", vlan.ifindex(), vlan.vid());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_bridge_vlans_all"))]
    pub async fn get_bridge_vlans_all(
        &self,
        bridge: impl Into<InterfaceRef>,
    ) -> Result<Vec<BridgeVlanEntry>> {
        let bridge_idx = self.resolve_interface(&bridge.into()).await?;
        self.get_bridge_vlans_all_by_index(bridge_idx).await
    }

    /// Get VLAN configuration for all ports of a bridge by interface index.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_bridge_vlans_all_by_index")
    )]
    pub async fn get_bridge_vlans_all_by_index(
        &self,
        bridge_idx: u32,
    ) -> Result<Vec<BridgeVlanEntry>> {
        let entries = self.get_bridge_vlans_dump().await?;

        // The bridge's own and its ports'. Every entry was dropped but the
        // bridge's before the ports were matched, so no port's VLANs came
        // back (#516).
        let links = self.get_links().await?;
        let port_indices: Vec<u32> = links
            .iter()
            .filter(|l| l.master == Some(bridge_idx))
            .map(|l| l.ifindex())
            .collect();

        // Include bridge itself and its ports
        let mut filtered = Vec::new();
        for entry in entries {
            if entry.ifindex == bridge_idx || port_indices.contains(&entry.ifindex) {
                filtered.push(entry);
            }
        }

        Ok(filtered)
    }

    /// Every bridge VLAN entry in the namespace: each bridge's and each
    /// port's (one `AF_BRIDGE` link dump with `RTEXT_FILTER_BRVLAN`).
    pub(crate) async fn get_bridge_vlans_dump(&self) -> Result<Vec<BridgeVlanEntry>> {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
        builder.append(&IfInfoMsg::new().with_family(libc::AF_BRIDGE as u8));
        builder.append_attr_u32(IflaAttr::ExtMask as u16, rtext_filter::BRVLAN);
        let responses = self.send_dump(builder).await?;
        let mut entries = Vec::new();
        for response in responses {
            if let Ok(msg_entries) = parse_vlan_entries_from_dump(&response) {
                entries.extend(msg_entries);
            }
        }
        Ok(entries)
    }

    /// Add VLAN to a bridge port.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::bridge_vlan::BridgeVlanBuilder;
    ///
    /// // Add VLAN 100 as PVID and untagged (native VLAN)
    /// conn.add_bridge_vlan(
    ///     BridgeVlanBuilder::new(100)
    ///         .dev("eth0")
    ///         .pvid()
    ///         .untagged()
    /// ).await?;
    ///
    /// // Add VLAN range 200-210 as tagged
    /// conn.add_bridge_vlan(
    ///     BridgeVlanBuilder::new(200)
    ///         .dev("eth0")
    ///         .range(210)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_bridge_vlan"))]
    pub async fn add_bridge_vlan(&self, config: BridgeVlanBuilder) -> Result<()> {
        let ifindex = self.resolve_bridge_vlan_interface(&config).await?;
        let mut builder = MessageBuilder::new(NlMsgType::RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK);
        config.write_add(&mut builder, ifindex);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_bridge_vlan"))
    }

    /// Delete VLAN from a bridge port.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.del_bridge_vlan("eth0", 100).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_bridge_vlan"))]
    pub async fn del_bridge_vlan(&self, dev: impl Into<InterfaceRef>, vid: u16) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.del_bridge_vlan_by_index(ifindex, vid).await
    }

    /// Delete VLAN from a bridge port by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_bridge_vlan_by_index"))]
    pub async fn del_bridge_vlan_by_index(&self, ifindex: u32, vid: u16) -> Result<()> {
        let config = BridgeVlanBuilder::new(vid).ifindex(ifindex);
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK);
        config.write_del(&mut builder, ifindex);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_bridge_vlan"))
    }

    /// Delete a range of VLANs from a bridge port.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.del_bridge_vlan_range("eth0", 200, 210).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_bridge_vlan_range"))]
    pub async fn del_bridge_vlan_range(
        &self,
        dev: impl Into<InterfaceRef>,
        vid_start: u16,
        vid_end: u16,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        let config = BridgeVlanBuilder::new(vid_start)
            .ifindex(ifindex)
            .range(vid_end);
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK);
        config.write_del(&mut builder, ifindex);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_bridge_vlan_range"))
    }

    /// Set PVID for a bridge port.
    ///
    /// This adds the VLAN as PVID and untagged, which is the typical
    /// configuration for a native VLAN.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.set_bridge_pvid("eth0", 100).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_bridge_pvid"))]
    pub async fn set_bridge_pvid(&self, dev: impl Into<InterfaceRef>, vid: u16) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.add_bridge_vlan(
            BridgeVlanBuilder::new(vid)
                .ifindex(ifindex)
                .pvid()
                .untagged(),
        )
        .await
    }

    /// Set PVID for a bridge port by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_bridge_pvid_by_index"))]
    pub async fn set_bridge_pvid_by_index(&self, ifindex: u32, vid: u16) -> Result<()> {
        self.add_bridge_vlan(
            BridgeVlanBuilder::new(vid)
                .ifindex(ifindex)
                .pvid()
                .untagged(),
        )
        .await
    }

    /// Add a tagged VLAN to a bridge port.
    ///
    /// This is a convenience method for adding a VLAN without PVID or untagged flags.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.add_bridge_vlan_tagged("eth0", 200).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_bridge_vlan_tagged"))]
    pub async fn add_bridge_vlan_tagged(
        &self,
        dev: impl Into<InterfaceRef>,
        vid: u16,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.add_bridge_vlan(BridgeVlanBuilder::new(vid).ifindex(ifindex))
            .await
    }

    /// Add a range of tagged VLANs to a bridge port.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.add_bridge_vlan_range("eth0", 200, 210).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_bridge_vlan_range"))]
    pub async fn add_bridge_vlan_range(
        &self,
        dev: impl Into<InterfaceRef>,
        vid_start: u16,
        vid_end: u16,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.add_bridge_vlan(
            BridgeVlanBuilder::new(vid_start)
                .ifindex(ifindex)
                .range(vid_end),
        )
        .await
    }

    // ========================================================================
    // VLAN Tunnel Mapping Methods (VLAN-to-VNI for VXLAN bridges)
    // ========================================================================

    /// Get VLAN-to-tunnel ID mappings for a bridge port.
    ///
    /// Returns all VLAN-to-VNI mappings configured on the specified interface.
    /// This is typically used on VXLAN bridge ports.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let tunnels = conn.get_vlan_tunnels("vxlan0").await?;
    /// for t in &tunnels {
    ///     println!("VLAN {} -> VNI {}", t.vid, t.tunnel_id);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_vlan_tunnels"))]
    pub async fn get_vlan_tunnels(
        &self,
        dev: impl Into<InterfaceRef>,
    ) -> Result<Vec<BridgeVlanTunnelEntry>> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.get_vlan_tunnels_by_index(ifindex).await
    }

    /// Get VLAN-to-tunnel ID mappings by interface index.
    ///
    /// Use this method when operating in a network namespace.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_vlan_tunnels_by_index")
    )]
    pub async fn get_vlan_tunnels_by_index(
        &self,
        ifindex: u32,
    ) -> Result<Vec<BridgeVlanTunnelEntry>> {
        // Request link with BRVLAN filter (tunnel info is included)
        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETLINK, NLM_F_REQUEST);

        let ifinfo = IfInfoMsg::new()
            .with_family(libc::AF_BRIDGE as u8)
            .with_index(ifindex as i32);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::ExtMask as u16, rtext_filter::BRVLAN);

        let response = self.send_request(builder).await?;
        parse_tunnel_entries(&response, ifindex)
    }

    /// Add VLAN-to-tunnel ID mapping.
    ///
    /// Creates a mapping between a VLAN ID and a tunnel ID (VNI) on a
    /// VXLAN bridge port.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::bridge_vlan::BridgeVlanTunnelBuilder;
    ///
    /// // Map VLAN 100 to VNI 10000
    /// conn.add_vlan_tunnel(
    ///     BridgeVlanTunnelBuilder::new(100, 10000)
    ///         .dev("vxlan0")
    /// ).await?;
    ///
    /// // Map VLAN range 200-210 to VNI range 20000-20010
    /// conn.add_vlan_tunnel(
    ///     BridgeVlanTunnelBuilder::new(200, 20000)
    ///         .dev("vxlan0")
    ///         .range(210)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_vlan_tunnel"))]
    pub async fn add_vlan_tunnel(&self, config: BridgeVlanTunnelBuilder) -> Result<()> {
        let ifindex = self.resolve_bridge_vlan_tunnel_interface(&config).await?;
        let mut builder = MessageBuilder::new(NlMsgType::RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK);
        config.write_add(&mut builder, ifindex)?;
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_vlan_tunnel"))
    }

    /// Delete VLAN-to-tunnel ID mapping.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.del_vlan_tunnel("vxlan0", 100).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_vlan_tunnel"))]
    pub async fn del_vlan_tunnel(&self, dev: impl Into<InterfaceRef>, vid: u16) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.del_vlan_tunnel_by_index(ifindex, vid).await
    }

    /// Delete VLAN-to-tunnel ID mapping by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_vlan_tunnel_by_index"))]
    pub async fn del_vlan_tunnel_by_index(&self, ifindex: u32, vid: u16) -> Result<()> {
        let config = BridgeVlanTunnelBuilder::new(vid, 0).ifindex(ifindex);
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK);
        config.write_del(&mut builder, ifindex)?;
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_vlan_tunnel"))
    }

    /// Delete a range of VLAN-to-tunnel ID mappings.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.del_vlan_tunnel_range("vxlan0", 200, 210).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_vlan_tunnel_range"))]
    pub async fn del_vlan_tunnel_range(
        &self,
        dev: impl Into<InterfaceRef>,
        vid_start: u16,
        vid_end: u16,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        let config = BridgeVlanTunnelBuilder::new(vid_start, 0)
            .ifindex(ifindex)
            .range(vid_end);
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK);
        config.write_del(&mut builder, ifindex)?;
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_vlan_tunnel_range"))
    }

    // ========================================================================
    // Bridge-global VLAN options (BRIDGE_VLANDB_GLOBAL_OPTIONS / GOPTS)
    // ========================================================================

    /// Set bridge-global per-VLAN options (multicast snooping, etc.).
    ///
    /// These options live on the bridge device itself, not on a port.
    /// Uses the VLAN-DB API (`RTM_NEWVLAN`).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::bridge_vlan::BridgeVlanGlobalOptionsBuilder;
    ///
    /// conn.set_bridge_vlan_global_options(
    ///     BridgeVlanGlobalOptionsBuilder::new(100)
    ///         .dev("br0")
    ///         .mcast_snooping(true)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "set_bridge_vlan_global_options")
    )]
    pub async fn set_bridge_vlan_global_options(
        &self,
        config: BridgeVlanGlobalOptionsBuilder,
    ) -> Result<()> {
        let ifindex = match config.device_ref() {
            Some(iface) => self.resolve_interface(iface).await?,
            None => {
                return Err(Error::invalid_message(
                    "device name or ifindex required",
                ));
            }
        };
        let mut builder = MessageBuilder::new(NlMsgType::RTM_NEWVLAN, NLM_F_REQUEST | NLM_F_ACK);
        config.write_set(&mut builder, ifindex);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_bridge_vlan_global_options"))
    }

    /// Get bridge-global per-VLAN options for a bridge.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let opts = conn.get_bridge_vlan_global_options("br0").await?;
    /// for o in &opts {
    ///     println!("VLAN {}: snooping={:?}", o.vid(), o.mcast_snooping());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_bridge_vlan_global_options")
    )]
    pub async fn get_bridge_vlan_global_options(
        &self,
        bridge: impl Into<InterfaceRef>,
    ) -> Result<Vec<BridgeVlanGlobalOptions>> {
        let ifindex = self.resolve_interface(&bridge.into()).await?;
        self.get_bridge_vlan_global_options_by_index(ifindex).await
    }

    /// Get bridge-global per-VLAN options by bridge interface index.
    ///
    /// Use this method when operating in a network namespace.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_bridge_vlan_global_options_by_index")
    )]
    pub async fn get_bridge_vlan_global_options_by_index(
        &self,
        ifindex: u32,
    ) -> Result<Vec<BridgeVlanGlobalOptions>> {
        // RTM_GETVLAN dump filtered to global options on this bridge.
        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETVLAN, NLM_F_REQUEST | NLM_F_DUMP);
        let msg = BrVlanMsg::new()
            .with_family(libc::AF_BRIDGE as u8)
            .with_index(ifindex);
        builder.append(&msg);
        builder.append_attr_u32(bridge_vlandb_dump::FLAGS, bridge_vlandb_dump::DUMPF_GLOBAL);

        let responses = self
            .send_dump(builder)
            .await
            .map_err(|e| e.with_context("get_bridge_vlan_global_options"))?;

        let mut entries = Vec::new();
        for response in responses {
            parse_global_options_from_dump(&response, ifindex, &mut entries);
        }
        Ok(entries)
    }

    // ========================================================================
    // Per-VLAN entry options (BRIDGE_VLANDB_ENTRY)
    // ========================================================================

    /// Set per-VLAN entry options on a bridge port (STP state, mcast
    /// router, neighbour suppression). Uses the VLAN-DB API
    /// (`RTM_NEWVLAN`).
    ///
    /// The VLAN must already be a member of the port (e.g. via
    /// [`add_bridge_vlan`](Self::add_bridge_vlan)).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::bridge_vlan::{BridgeVlanEntryOptionsBuilder, BridgeVlanState};
    ///
    /// conn.set_bridge_vlan_entry_options(
    ///     BridgeVlanEntryOptionsBuilder::new(100)
    ///         .dev("eth0")
    ///         .state(BridgeVlanState::Forwarding)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "set_bridge_vlan_entry_options")
    )]
    pub async fn set_bridge_vlan_entry_options(
        &self,
        config: BridgeVlanEntryOptionsBuilder,
    ) -> Result<()> {
        let ifindex = match config.device_ref() {
            Some(iface) => self.resolve_interface(iface).await?,
            None => {
                return Err(Error::invalid_message(
                    "device name or ifindex required",
                ));
            }
        };
        let mut builder = MessageBuilder::new(NlMsgType::RTM_NEWVLAN, NLM_F_REQUEST | NLM_F_ACK);
        config.write_set(&mut builder, ifindex);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_bridge_vlan_entry_options"))
    }

    /// Get per-VLAN entry options for a bridge port.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_bridge_vlan_entry_options")
    )]
    pub async fn get_bridge_vlan_entry_options(
        &self,
        dev: impl Into<InterfaceRef>,
    ) -> Result<Vec<BridgeVlanEntryOptions>> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.get_bridge_vlan_entry_options_by_index(ifindex).await
    }

    /// Get per-VLAN entry options for a bridge port by interface index.
    ///
    /// Use this method when operating in a network namespace.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_bridge_vlan_entry_options_by_index")
    )]
    pub async fn get_bridge_vlan_entry_options_by_index(
        &self,
        ifindex: u32,
    ) -> Result<Vec<BridgeVlanEntryOptions>> {
        // RTM_GETVLAN dump (no DUMPF_GLOBAL → per-VLAN ENTRY blocks),
        // filtered to this port.
        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETVLAN, NLM_F_REQUEST | NLM_F_DUMP);
        let msg = BrVlanMsg::new()
            .with_family(libc::AF_BRIDGE as u8)
            .with_index(ifindex);
        builder.append(&msg);

        let responses = self
            .send_dump(builder)
            .await
            .map_err(|e| e.with_context("get_bridge_vlan_entry_options"))?;

        let mut entries = Vec::new();
        for response in responses {
            parse_entry_options_from_dump(&response, ifindex, &mut entries);
        }
        Ok(entries)
    }
}

// ============================================================================
// Parsing Helpers
// ============================================================================

/// Parse VLAN entries from a dump response (may contain multiple messages).
fn parse_vlan_entries_from_dump(data: &[u8]) -> Result<Vec<BridgeVlanEntry>> {
    let mut entries = Vec::new();

    for msg_result in MessageIter::new(data) {
        let (_header, payload) = match msg_result {
            Ok(msg) => msg,
            Err(_) => continue,
        };

        // Skip if too short for ifinfomsg
        if payload.len() < IfInfoMsg::SIZE {
            continue;
        }

        // Parse ifinfomsg to get ifindex
        if let Ok(ifinfo) = IfInfoMsg::from_bytes(payload) {
            let ifindex = ifinfo.ifi_index as u32;
            let attrs_data = &payload[IfInfoMsg::SIZE..];

            // Look for IFLA_AF_SPEC
            for (attr_type, attr_payload) in AttrIter::new(attrs_data) {
                if attr_type == IflaAttr::AfSpec as u16 {
                    parse_af_spec_vlans(attr_payload, ifindex, &mut entries);
                }
            }
        }
    }

    Ok(entries)
}

/// Parse VLAN info from IFLA_AF_SPEC payload.
fn parse_af_spec_vlans(data: &[u8], ifindex: u32, entries: &mut Vec<BridgeVlanEntry>) {
    let mut range_start: Option<(u16, u16)> = None; // (vid, flags)

    for (attr_type, payload) in AttrIter::new(data) {
        if attr_type == bridge_af::IFLA_BRIDGE_VLAN_INFO
            && let Some(vlan_info) = BridgeVlanInfo::from_bytes(payload)
        {
            let flags = BridgeVlanFlags::from_raw(vlan_info.flags);

            if vlan_info.is_range_begin() {
                // 0.19 N8 — Plan 193 rule 2 defensive: if a previous
                // RANGE_BEGIN never saw its matching RANGE_END (a
                // truncated kernel emit / future protocol extension),
                // emit the orphan as a single VLAN before starting
                // the new range. Pre-fix silently overwrote
                // `range_start` and dropped the prior VLAN entirely.
                if let Some((prev_vid, prev_flags)) = range_start.take() {
                    tracing::warn!(
                        ifindex,
                        prev_vid,
                        new_vid = vlan_info.vid,
                        "BRIDGE_VLAN_INFO RANGE_BEGIN before matching RANGE_END — emitting truncated range as single VLAN",
                    );
                    entries.push(BridgeVlanEntry {
                        ifindex,
                        vid: prev_vid,
                        flags: BridgeVlanFlags::from_raw(prev_flags),
                    });
                }
                range_start = Some((vlan_info.vid, vlan_info.flags));
            } else if vlan_info.is_range_end() {
                // End of range - emit all VLANs in range
                if let Some((start_vid, start_flags)) = range_start.take() {
                    let range_flags = BridgeVlanFlags::from_raw(start_flags);
                    for vid in start_vid..=vlan_info.vid {
                        entries.push(BridgeVlanEntry {
                            ifindex,
                            vid,
                            flags: range_flags,
                        });
                    }
                }
            } else {
                // Single VLAN entry
                entries.push(BridgeVlanEntry {
                    ifindex,
                    vid: vlan_info.vid,
                    flags,
                });
            }
        }
    }

    // 0.19 N8 — trailing unterminated range at end of chain. Same
    // defensive handling: emit as a single VLAN rather than dropping.
    if let Some((prev_vid, prev_flags)) = range_start {
        tracing::warn!(
            ifindex,
            prev_vid,
            "BRIDGE_VLAN_INFO RANGE_BEGIN with no matching RANGE_END at end of chain — emitting as single VLAN",
        );
        entries.push(BridgeVlanEntry {
            ifindex,
            vid: prev_vid,
            flags: BridgeVlanFlags::from_raw(prev_flags),
        });
    }
}

// ============================================================================
// Tunnel Parsing Helpers
// ============================================================================

/// Parse tunnel entries from a single netlink response.
fn parse_tunnel_entries(data: &[u8], ifindex: u32) -> Result<Vec<BridgeVlanTunnelEntry>> {
    let mut entries = Vec::new();

    // Skip ifinfomsg header
    if data.len() < IfInfoMsg::SIZE {
        return Ok(entries);
    }
    let attrs_data = &data[IfInfoMsg::SIZE..];

    // Look for IFLA_AF_SPEC
    for (attr_type, payload) in AttrIter::new(attrs_data) {
        if attr_type == IflaAttr::AfSpec as u16 {
            // Parse nested attributes inside AF_SPEC
            parse_af_spec_tunnels(payload, ifindex, &mut entries);
        }
    }

    Ok(entries)
}

/// Parse tunnel info from IFLA_AF_SPEC payload.
fn parse_af_spec_tunnels(data: &[u8], ifindex: u32, entries: &mut Vec<BridgeVlanTunnelEntry>) {
    let mut range_start: Option<(u16, u32)> = None; // (vid, tunnel_id)

    for (attr_type, payload) in AttrIter::new(data) {
        if attr_type == bridge_af::IFLA_BRIDGE_VLAN_TUNNEL_INFO {
            // Parse the nested tunnel info attributes
            let mut vid: Option<u16> = None;
            let mut tunnel_id: Option<u32> = None;
            let mut flags: u16 = 0;

            for (tunnel_attr, tunnel_payload) in AttrIter::new(payload) {
                match tunnel_attr {
                    t if t == bridge_vlan_tunnel::IFLA_BRIDGE_VLAN_TUNNEL_ID
                        && tunnel_payload.len() >= 4 =>
                    {
                        tunnel_id =
                            Some(u32::from_ne_bytes(tunnel_payload[..4].try_into().unwrap()));
                    }
                    t if t == bridge_vlan_tunnel::IFLA_BRIDGE_VLAN_TUNNEL_VID
                        && tunnel_payload.len() >= 2 =>
                    {
                        vid = Some(u16::from_ne_bytes(tunnel_payload[..2].try_into().unwrap()));
                    }
                    t if t == bridge_vlan_tunnel::IFLA_BRIDGE_VLAN_TUNNEL_FLAGS
                        && tunnel_payload.len() >= 2 =>
                    {
                        flags = u16::from_ne_bytes(tunnel_payload[..2].try_into().unwrap());
                    }
                    _ => {}
                }
            }

            if let (Some(v), Some(t)) = (vid, tunnel_id) {
                let is_range_begin = flags & bridge_vlan_flags::RANGE_BEGIN != 0;
                let is_range_end = flags & bridge_vlan_flags::RANGE_END != 0;

                if is_range_begin {
                    // 0.19 N8 — emit orphan prior RANGE_BEGIN as a
                    // single tunnel mapping rather than silently
                    // dropping. See parse_af_spec_vlans.
                    if let Some((prev_vid, prev_tunnel_id)) = range_start.take() {
                        tracing::warn!(
                            ifindex,
                            prev_vid,
                            new_vid = v,
                            "BRIDGE_VLAN_TUNNEL_INFO RANGE_BEGIN before matching RANGE_END — emitting truncated range as single mapping",
                        );
                        entries.push(BridgeVlanTunnelEntry {
                            ifindex,
                            vid: prev_vid,
                            tunnel_id: prev_tunnel_id,
                        });
                    }
                    range_start = Some((v, t));
                } else if is_range_end {
                    // End of range - emit all mappings (1:1 mapping)
                    if let Some((start_vid, start_tunnel_id)) = range_start.take() {
                        for i in 0..=(v - start_vid) {
                            entries.push(BridgeVlanTunnelEntry {
                                ifindex,
                                vid: start_vid + i,
                                tunnel_id: start_tunnel_id + i as u32,
                            });
                        }
                    }
                } else {
                    // Single entry
                    entries.push(BridgeVlanTunnelEntry {
                        ifindex,
                        vid: v,
                        tunnel_id: t,
                    });
                }
            }
        }
    }
}

// ============================================================================
// Global-options parsing helpers
// ============================================================================

/// Parse `BRIDGE_VLANDB_GLOBAL_OPTIONS` blocks out of an `RTM_GETVLAN`
/// dump chunk (which may carry several netlink messages).
///
/// Per the parser-robustness policy: malformed messages are skipped
/// (no `?` propagation), the `br_vlan_msg` header is accepted
/// larger-than-expected, and every attribute read is length-guarded.
fn parse_global_options_from_dump(
    data: &[u8],
    fallback_ifindex: u32,
    entries: &mut Vec<BridgeVlanGlobalOptions>,
) {
    for msg_result in MessageIter::new(data) {
        let Ok((_header, payload)) = msg_result else {
            continue;
        };

        // br_vlan_msg header gives the bridge ifindex.
        let ifindex = BrVlanMsg::from_bytes(payload)
            .map(|m| m.ifindex)
            .unwrap_or(fallback_ifindex);
        if payload.len() < BrVlanMsg::SIZE {
            continue;
        }
        let attrs = &payload[BrVlanMsg::SIZE..];

        for (attr_type, attr_payload) in AttrIter::new(attrs) {
            if attr_type == bridge_vlandb::GLOBAL_OPTIONS
                && let Some(opts) = parse_one_gopts(attr_payload, ifindex)
            {
                entries.push(opts);
            }
        }
    }
}

/// Parse a single `BRIDGE_VLANDB_GLOBAL_OPTIONS` nest into a typed
/// [`BridgeVlanGlobalOptions`]. Returns `None` if the mandatory
/// `GOPTS_ID` is missing. Unknown / not-modelled attributes (router
/// ports, querier state, future additions) are skipped.
fn parse_one_gopts(payload: &[u8], ifindex: u32) -> Option<BridgeVlanGlobalOptions> {
    let mut opts = BridgeVlanGlobalOptions {
        ifindex,
        ..Default::default()
    };
    let mut have_id = false;

    for (attr, data) in AttrIter::new(payload) {
        match attr {
            t if t == bridge_vlandb_gopts::ID && data.len() >= 2 => {
                opts.vid = u16::from_ne_bytes(data[..2].try_into().unwrap());
                have_id = true;
            }
            t if t == bridge_vlandb_gopts::RANGE && data.len() >= 2 => {
                opts.vid_end = Some(u16::from_ne_bytes(data[..2].try_into().unwrap()));
            }
            t if t == bridge_vlandb_gopts::MCAST_SNOOPING && !data.is_empty() => {
                opts.mcast_snooping = Some(data[0] != 0);
            }
            t if t == bridge_vlandb_gopts::MCAST_QUERIER && !data.is_empty() => {
                opts.mcast_querier = Some(data[0] != 0);
            }
            t if t == bridge_vlandb_gopts::MCAST_IGMP_VERSION && !data.is_empty() => {
                opts.mcast_igmp_version = Some(data[0]);
            }
            t if t == bridge_vlandb_gopts::MCAST_MLD_VERSION && !data.is_empty() => {
                opts.mcast_mld_version = Some(data[0]);
            }
            t if t == bridge_vlandb_gopts::MCAST_LAST_MEMBER_CNT && data.len() >= 4 => {
                opts.mcast_last_member_count =
                    Some(u32::from_ne_bytes(data[..4].try_into().unwrap()));
            }
            t if t == bridge_vlandb_gopts::MCAST_STARTUP_QUERY_CNT && data.len() >= 4 => {
                opts.mcast_startup_query_count =
                    Some(u32::from_ne_bytes(data[..4].try_into().unwrap()));
            }
            t if t == bridge_vlandb_gopts::MCAST_LAST_MEMBER_INTVL && data.len() >= 8 => {
                opts.mcast_last_member_interval =
                    Some(u64::from_ne_bytes(data[..8].try_into().unwrap()));
            }
            t if t == bridge_vlandb_gopts::MCAST_MEMBERSHIP_INTVL && data.len() >= 8 => {
                opts.mcast_membership_interval =
                    Some(u64::from_ne_bytes(data[..8].try_into().unwrap()));
            }
            t if t == bridge_vlandb_gopts::MCAST_QUERIER_INTVL && data.len() >= 8 => {
                opts.mcast_querier_interval =
                    Some(u64::from_ne_bytes(data[..8].try_into().unwrap()));
            }
            t if t == bridge_vlandb_gopts::MCAST_QUERY_INTVL && data.len() >= 8 => {
                opts.mcast_query_interval =
                    Some(u64::from_ne_bytes(data[..8].try_into().unwrap()));
            }
            t if t == bridge_vlandb_gopts::MCAST_QUERY_RESPONSE_INTVL && data.len() >= 8 => {
                opts.mcast_query_response_interval =
                    Some(u64::from_ne_bytes(data[..8].try_into().unwrap()));
            }
            t if t == bridge_vlandb_gopts::MCAST_STARTUP_QUERY_INTVL && data.len() >= 8 => {
                opts.mcast_startup_query_interval =
                    Some(u64::from_ne_bytes(data[..8].try_into().unwrap()));
            }
            t if t == bridge_vlandb_gopts::MSTI && data.len() >= 2 => {
                opts.msti = Some(u16::from_ne_bytes(data[..2].try_into().unwrap()));
            }
            // GOPTS_ID present but too short, or not-modelled attrs
            // (MCAST_ROUTER_PORTS, MCAST_QUERIER_STATE, PAD, future).
            _ => {}
        }
    }

    have_id.then_some(opts)
}

/// Parse `BRIDGE_VLANDB_ENTRY` blocks out of an `RTM_GETVLAN` dump
/// chunk. Same robustness rules as the gopts walker.
fn parse_entry_options_from_dump(
    data: &[u8],
    fallback_ifindex: u32,
    entries: &mut Vec<BridgeVlanEntryOptions>,
) {
    for msg_result in MessageIter::new(data) {
        let Ok((_header, payload)) = msg_result else {
            continue;
        };

        let ifindex = BrVlanMsg::from_bytes(payload)
            .map(|m| m.ifindex)
            .unwrap_or(fallback_ifindex);
        if payload.len() < BrVlanMsg::SIZE {
            continue;
        }
        let attrs = &payload[BrVlanMsg::SIZE..];

        for (attr_type, attr_payload) in AttrIter::new(attrs) {
            if attr_type == bridge_vlandb::ENTRY
                && let Some(opts) = parse_one_entry(attr_payload, ifindex)
            {
                entries.push(opts);
            }
        }
    }
}

/// Parse a single `BRIDGE_VLANDB_ENTRY` nest. Returns `None` if the
/// mandatory `ENTRY_INFO` (carrying the VID) is missing or malformed.
fn parse_one_entry(payload: &[u8], ifindex: u32) -> Option<BridgeVlanEntryOptions> {
    let mut opts = BridgeVlanEntryOptions {
        ifindex,
        ..Default::default()
    };
    let mut have_vid = false;

    for (attr, data) in AttrIter::new(payload) {
        match attr {
            t if t == bridge_vlandb_entry::INFO => {
                // struct bridge_vlan_info { flags: u16, vid: u16 }
                if let Some(info) = BridgeVlanInfo::from_bytes(data) {
                    opts.vid = info.vid;
                    have_vid = true;
                }
            }
            t if t == bridge_vlandb_entry::RANGE && data.len() >= 2 => {
                opts.vid_end = Some(u16::from_ne_bytes(data[..2].try_into().unwrap()));
            }
            t if t == bridge_vlandb_entry::STATE && !data.is_empty() => {
                opts.state = BridgeVlanState::from_raw(data[0]);
            }
            t if t == bridge_vlandb_entry::MCAST_ROUTER && !data.is_empty() => {
                opts.mcast_router = Some(data[0]);
            }
            t if t == bridge_vlandb_entry::MCAST_N_GROUPS && data.len() >= 4 => {
                opts.mcast_n_groups = Some(u32::from_ne_bytes(data[..4].try_into().unwrap()));
            }
            t if t == bridge_vlandb_entry::MCAST_MAX_GROUPS && data.len() >= 4 => {
                opts.mcast_max_groups = Some(u32::from_ne_bytes(data[..4].try_into().unwrap()));
            }
            t if t == bridge_vlandb_entry::NEIGH_SUPPRESS && !data.is_empty() => {
                opts.neigh_suppress = Some(data[0] != 0);
            }
            // ENTRY_TUNNEL_INFO / ENTRY_STATS (nested) and future attrs.
            _ => {}
        }
    }

    have_vid.then_some(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_vlan_flags_from_raw() {
        let flags =
            BridgeVlanFlags::from_raw(bridge_vlan_flags::PVID | bridge_vlan_flags::UNTAGGED);
        assert!(flags.pvid);
        assert!(flags.untagged);

        let flags = BridgeVlanFlags::from_raw(0);
        assert!(!flags.pvid);
        assert!(!flags.untagged);

        let flags = BridgeVlanFlags::from_raw(bridge_vlan_flags::PVID);
        assert!(flags.pvid);
        assert!(!flags.untagged);
    }

    #[test]
    fn test_bridge_vlan_entry_helpers() {
        let entry = BridgeVlanEntry {
            ifindex: 1,
            vid: 100,
            flags: BridgeVlanFlags {
                pvid: true,
                untagged: true,
            },
        };
        assert!(entry.is_pvid());
        assert!(entry.is_untagged());

        let entry = BridgeVlanEntry {
            ifindex: 1,
            vid: 200,
            flags: BridgeVlanFlags::default(),
        };
        assert!(!entry.is_pvid());
        assert!(!entry.is_untagged());
    }

    #[test]
    fn test_builder_default() {
        let builder = BridgeVlanBuilder::new(100);
        assert_eq!(builder.vid, 100);
        assert!(!builder.pvid);
        assert!(!builder.untagged);
        assert!(!builder.master);
        assert!(builder.vid_end.is_none());
    }

    #[test]
    fn test_builder_chain() {
        let builder = BridgeVlanBuilder::new(100)
            .dev("eth0")
            .pvid()
            .untagged()
            .master();

        assert_eq!(builder.dev, Some(InterfaceRef::Name("eth0".to_string())));
        assert!(builder.pvid);
        assert!(builder.untagged);
        assert!(builder.master);
    }

    #[test]
    fn test_builder_range() {
        let builder = BridgeVlanBuilder::new(100).dev("eth0").range(110);

        assert_eq!(builder.vid, 100);
        assert_eq!(builder.vid_end, Some(110));
    }

    #[test]
    fn test_builder_ifindex() {
        let builder = BridgeVlanBuilder::new(100).ifindex(5);
        assert_eq!(builder.dev, Some(InterfaceRef::Index(5)));
    }

    #[test]
    fn test_build_flags() {
        let builder = BridgeVlanBuilder::new(100).pvid().untagged();
        let flags = builder.build_flags();
        assert_eq!(flags, bridge_vlan_flags::PVID | bridge_vlan_flags::UNTAGGED);

        let builder = BridgeVlanBuilder::new(100).master();
        let flags = builder.build_flags();
        assert_eq!(flags, bridge_vlan_flags::MASTER);
    }

    // ========================================================================
    // Tunnel Builder Tests
    // ========================================================================

    #[test]
    fn test_tunnel_builder_new() {
        let builder = BridgeVlanTunnelBuilder::new(100, 10000);
        assert_eq!(builder.vid, 100);
        assert_eq!(builder.tunnel_id, 10000);
        assert!(builder.dev.is_none());
        assert!(builder.vid_end.is_none());
    }

    #[test]
    fn test_tunnel_builder_chain() {
        let builder = BridgeVlanTunnelBuilder::new(100, 10000)
            .dev("vxlan0")
            .range(110);

        assert_eq!(builder.dev, Some(InterfaceRef::Name("vxlan0".to_string())));
        assert_eq!(builder.vid, 100);
        assert_eq!(builder.vid_end, Some(110));
        assert_eq!(builder.tunnel_id, 10000);
    }

    #[test]
    fn test_tunnel_builder_ifindex() {
        let builder = BridgeVlanTunnelBuilder::new(100, 10000).ifindex(5);
        assert_eq!(builder.dev, Some(InterfaceRef::Index(5)));
    }

    #[test]
    fn test_tunnel_entry_equality() {
        let entry1 = BridgeVlanTunnelEntry {
            ifindex: 1,
            vid: 100,
            tunnel_id: 10000,
        };
        let entry2 = BridgeVlanTunnelEntry {
            ifindex: 1,
            vid: 100,
            tunnel_id: 10000,
        };
        let entry3 = BridgeVlanTunnelEntry {
            ifindex: 1,
            vid: 100,
            tunnel_id: 10001,
        };

        assert_eq!(entry1, entry2);
        assert_ne!(entry1, entry3);
    }

    #[test]
    fn test_tunnel_max_id() {
        // Maximum valid tunnel ID
        assert_eq!(BridgeVlanTunnelBuilder::MAX_TUNNEL_ID, 0xFFFFFF);
    }

    /// A range that ends before it starts is an error. It was `vid_end -
    /// vid` on `u16`: a panic in a debug build and a wrapped tunnel id in
    /// a release one.
    #[test]
    fn test_tunnel_reversed_range_is_an_error() {
        let mut b = MessageBuilder::new(0, 0);
        let err = BridgeVlanTunnelBuilder::new(200, 1000)
            .range(100)
            .write_add(&mut b, 1)
            .unwrap_err();
        assert!(err.to_string().contains("range"), "{err}");
    }

    // ========================================================================
    // Bridge-global VLAN options (GOPTS) tests
    // ========================================================================

    /// Emit a netlink attribute (TLV, 4-byte aligned) into `buf`.
    fn push_attr(buf: &mut Vec<u8>, atype: u16, payload: &[u8]) {
        let len = 4 + payload.len();
        buf.extend_from_slice(&(len as u16).to_ne_bytes());
        buf.extend_from_slice(&atype.to_ne_bytes());
        buf.extend_from_slice(payload);
        while !buf.len().is_multiple_of(4) {
            buf.push(0);
        }
    }

    #[test]
    fn br_vlan_msg_layout_is_8_bytes() {
        assert_eq!(BrVlanMsg::SIZE, 8);
        let msg = BrVlanMsg::new()
            .with_family(libc::AF_BRIDGE as u8)
            .with_index(0x0102_0304);
        let bytes = msg.as_bytes();
        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes[0], libc::AF_BRIDGE as u8); // family @ 0
        assert_eq!(&bytes[4..8], &0x0102_0304u32.to_ne_bytes()); // ifindex @ 4
        // Round-trips, and accepts trailing bytes a future kernel adds.
        let mut oversized = bytes.to_vec();
        oversized.extend_from_slice(&[0xff; 4]);
        let parsed = BrVlanMsg::from_bytes(&oversized).unwrap();
        assert_eq!(parsed.ifindex, 0x0102_0304);
    }

    #[test]
    fn gopts_attr_constants_match_kernel_uapi() {
        // Pinned against linux/if_bridge.h so writer+reader can't drift
        // from the kernel onto a self-consistent-but-wrong code.
        assert_eq!(bridge_vlandb::ENTRY, 1);
        assert_eq!(bridge_vlandb::GLOBAL_OPTIONS, 2);
        assert_eq!(bridge_vlandb_dump::FLAGS, 1);
        assert_eq!(bridge_vlandb_dump::DUMPF_GLOBAL, 1 << 1);
        assert_eq!(bridge_vlandb_gopts::ID, 1);
        assert_eq!(bridge_vlandb_gopts::RANGE, 2);
        assert_eq!(bridge_vlandb_gopts::MCAST_SNOOPING, 3);
        assert_eq!(bridge_vlandb_gopts::MCAST_IGMP_VERSION, 4);
        assert_eq!(bridge_vlandb_gopts::MCAST_MLD_VERSION, 5);
        assert_eq!(bridge_vlandb_gopts::MCAST_LAST_MEMBER_CNT, 6);
        assert_eq!(bridge_vlandb_gopts::MCAST_STARTUP_QUERY_CNT, 7);
        assert_eq!(bridge_vlandb_gopts::MCAST_LAST_MEMBER_INTVL, 8);
        assert_eq!(bridge_vlandb_gopts::PAD, 9);
        assert_eq!(bridge_vlandb_gopts::MCAST_MEMBERSHIP_INTVL, 10);
        assert_eq!(bridge_vlandb_gopts::MCAST_QUERIER_INTVL, 11);
        assert_eq!(bridge_vlandb_gopts::MCAST_QUERY_INTVL, 12);
        assert_eq!(bridge_vlandb_gopts::MCAST_QUERY_RESPONSE_INTVL, 13);
        assert_eq!(bridge_vlandb_gopts::MCAST_STARTUP_QUERY_INTVL, 14);
        assert_eq!(bridge_vlandb_gopts::MCAST_QUERIER, 15);
        assert_eq!(bridge_vlandb_gopts::MCAST_ROUTER_PORTS, 16);
        assert_eq!(bridge_vlandb_gopts::MCAST_QUERIER_STATE, 17);
        assert_eq!(bridge_vlandb_gopts::MSTI, 18);
    }

    #[test]
    fn gopts_builder_wire_roundtrips() {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_NEWVLAN, 0);
        BridgeVlanGlobalOptionsBuilder::new(100)
            .ifindex(7)
            .mcast_snooping(true)
            .mcast_querier(false)
            .mcast_igmp_version(3)
            .mcast_mld_version(2)
            .mcast_last_member_count(2)
            .mcast_startup_query_count(2)
            .mcast_last_member_interval(100)
            .mcast_membership_interval(26000)
            .mcast_querier_interval(25500)
            .mcast_query_interval(12500)
            .mcast_query_response_interval(1000)
            .mcast_startup_query_interval(3125)
            .msti(5)
            .write_set(&mut builder, 7);
        let bytes = builder.finish();

        let mut entries = Vec::new();
        // fallback ifindex unused — the br_vlan_msg header carries 7.
        parse_global_options_from_dump(&bytes, 0, &mut entries);
        assert_eq!(entries.len(), 1);
        let o = &entries[0];
        assert_eq!(o.ifindex(), 7);
        assert_eq!(o.vid(), 100);
        assert_eq!(o.vid_end(), None);
        assert_eq!(o.mcast_snooping(), Some(true));
        assert_eq!(o.mcast_querier(), Some(false));
        assert_eq!(o.mcast_igmp_version(), Some(3));
        assert_eq!(o.mcast_mld_version(), Some(2));
        assert_eq!(o.mcast_last_member_count(), Some(2));
        assert_eq!(o.mcast_startup_query_count(), Some(2));
        assert_eq!(o.mcast_last_member_interval(), Some(100));
        assert_eq!(o.mcast_membership_interval(), Some(26000));
        assert_eq!(o.mcast_querier_interval(), Some(25500));
        assert_eq!(o.mcast_query_interval(), Some(12500));
        assert_eq!(o.mcast_query_response_interval(), Some(1000));
        assert_eq!(o.mcast_startup_query_interval(), Some(3125));
        assert_eq!(o.msti(), Some(5));
    }

    #[test]
    fn gopts_builder_emits_range_and_only_set_attrs() {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_NEWVLAN, 0);
        BridgeVlanGlobalOptionsBuilder::new(200)
            .ifindex(7)
            .range(210)
            .mcast_snooping(false)
            .write_set(&mut builder, 7);
        let bytes = builder.finish();

        let mut entries = Vec::new();
        parse_global_options_from_dump(&bytes, 0, &mut entries);
        assert_eq!(entries.len(), 1);
        let o = &entries[0];
        assert_eq!(o.vid(), 200);
        assert_eq!(o.vid_end(), Some(210));
        assert_eq!(o.mcast_snooping(), Some(false));
        // Unset options stay absent rather than defaulting.
        assert_eq!(o.mcast_querier(), None);
        assert_eq!(o.msti(), None);
    }

    #[test]
    fn gopts_parse_skips_unknown_attrs() {
        let mut nest = Vec::new();
        push_attr(&mut nest, bridge_vlandb_gopts::ID, &100u16.to_ne_bytes());
        // Not-modelled / future attr — must be ignored, not fatal.
        push_attr(&mut nest, 0xFFFE, &[1, 2, 3, 4]);
        push_attr(&mut nest, bridge_vlandb_gopts::MCAST_SNOOPING, &[1]);
        let o = parse_one_gopts(&nest, 3).expect("ID present → Some");
        assert_eq!(o.ifindex(), 3);
        assert_eq!(o.vid(), 100);
        assert_eq!(o.mcast_snooping(), Some(true));
    }

    #[test]
    fn gopts_parse_without_id_is_none() {
        let mut nest = Vec::new();
        push_attr(&mut nest, bridge_vlandb_gopts::MCAST_SNOOPING, &[1]);
        assert!(parse_one_gopts(&nest, 3).is_none());
    }

    #[test]
    fn gopts_parse_arbitrary_bytes_never_panics() {
        // Parser-robustness: truncated headers, short attr payloads, and
        // arbitrary noise must not panic the dump walker or nest parser.
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
            let mut entries = Vec::new();
            parse_global_options_from_dump(&data, 9, &mut entries);
            let _ = parse_one_gopts(&data, 9);
        }
        // Truncated multi-byte attr values (short ID / interval) skipped,
        // not indexed out of bounds.
        let mut nest = Vec::new();
        push_attr(&mut nest, bridge_vlandb_gopts::ID, &[0x01]); // 1 byte, needs 2
        push_attr(&mut nest, bridge_vlandb_gopts::MCAST_QUERIER_INTVL, &[0, 0, 0]); // needs 8
        assert!(parse_one_gopts(&nest, 1).is_none()); // ID too short → no id
    }

    // ========================================================================
    // Per-VLAN entry options (ENTRY) tests
    // ========================================================================

    #[test]
    fn entry_attr_and_state_constants_match_kernel_uapi() {
        assert_eq!(bridge_vlandb_entry::INFO, 1);
        assert_eq!(bridge_vlandb_entry::RANGE, 2);
        assert_eq!(bridge_vlandb_entry::STATE, 3);
        assert_eq!(bridge_vlandb_entry::TUNNEL_INFO, 4);
        assert_eq!(bridge_vlandb_entry::STATS, 5);
        assert_eq!(bridge_vlandb_entry::MCAST_ROUTER, 6);
        assert_eq!(bridge_vlandb_entry::MCAST_N_GROUPS, 7);
        assert_eq!(bridge_vlandb_entry::MCAST_MAX_GROUPS, 8);
        assert_eq!(bridge_vlandb_entry::NEIGH_SUPPRESS, 9);
        assert_eq!(br_state::DISABLED, 0);
        assert_eq!(br_state::FORWARDING, 3);
        assert_eq!(br_state::BLOCKING, 4);
    }

    #[test]
    fn bridge_vlan_state_round_trips_all_variants() {
        for s in [
            BridgeVlanState::Disabled,
            BridgeVlanState::Listening,
            BridgeVlanState::Learning,
            BridgeVlanState::Forwarding,
            BridgeVlanState::Blocking,
        ] {
            assert_eq!(BridgeVlanState::from_raw(s.to_raw()), Some(s));
        }
        assert_eq!(BridgeVlanState::from_raw(99), None);
    }

    #[test]
    fn entry_builder_wire_roundtrips() {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_NEWVLAN, 0);
        BridgeVlanEntryOptionsBuilder::new(100)
            .ifindex(7)
            .state(BridgeVlanState::Forwarding)
            .mcast_router(2)
            .mcast_max_groups(64)
            .neigh_suppress(true)
            .write_set(&mut builder, 7);
        let bytes = builder.finish();

        let mut entries = Vec::new();
        parse_entry_options_from_dump(&bytes, 0, &mut entries);
        assert_eq!(entries.len(), 1);
        let o = &entries[0];
        assert_eq!(o.ifindex(), 7);
        assert_eq!(o.vid(), 100);
        assert_eq!(o.vid_end(), None);
        assert_eq!(o.state(), Some(BridgeVlanState::Forwarding));
        assert_eq!(o.mcast_router(), Some(2));
        assert_eq!(o.mcast_max_groups(), Some(64));
        assert_eq!(o.neigh_suppress(), Some(true));
        // Unset / read-only attrs absent.
        assert_eq!(o.mcast_n_groups(), None);
    }

    #[test]
    fn entry_builder_emits_range_and_only_set_attrs() {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_NEWVLAN, 0);
        BridgeVlanEntryOptionsBuilder::new(10)
            .ifindex(7)
            .range(20)
            .state(BridgeVlanState::Blocking)
            .write_set(&mut builder, 7);
        let bytes = builder.finish();

        let mut entries = Vec::new();
        parse_entry_options_from_dump(&bytes, 0, &mut entries);
        assert_eq!(entries.len(), 1);
        let o = &entries[0];
        assert_eq!(o.vid(), 10);
        assert_eq!(o.vid_end(), Some(20));
        assert_eq!(o.state(), Some(BridgeVlanState::Blocking));
        assert_eq!(o.mcast_router(), None);
        assert_eq!(o.neigh_suppress(), None);
    }

    #[test]
    fn entry_parse_without_info_is_none() {
        let mut nest = Vec::new();
        push_attr(&mut nest, bridge_vlandb_entry::STATE, &[br_state::FORWARDING]);
        assert!(parse_one_entry(&nest, 3).is_none());
    }

    #[test]
    fn entry_parse_arbitrary_bytes_never_panics() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(53)).collect();
            let mut entries = Vec::new();
            parse_entry_options_from_dump(&data, 9, &mut entries);
            let _ = parse_one_entry(&data, 9);
        }
    }
}
