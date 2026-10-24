//! Link (network interface) message types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::netlink::error::{Error, Result};

/// Interface info message (struct ifinfomsg).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct IfInfoMsg {
    /// Address family (usually AF_UNSPEC).
    pub ifi_family: u8,
    /// Padding.
    pub __ifi_pad: u8,
    /// Device type (ARPHRD_*).
    pub ifi_type: u16,
    /// Interface index.
    pub ifi_index: i32,
    /// Device flags (IFF_*).
    pub ifi_flags: u32,
    /// Change mask.
    pub ifi_change: u32,
}

impl IfInfoMsg {
    /// Size of this structure.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create a new interface info message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the interface index.
    pub fn with_index(mut self, index: i32) -> Self {
        self.ifi_index = index;
        self
    }

    /// Set the address family.
    pub fn with_family(mut self, family: u8) -> Self {
        self.ifi_family = family;
        self
    }

    /// Convert to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(data)
            .map(|(r, _)| r)
            .map_err(|_| Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: Self::SIZE,
                actual: data.len(),
            }))
    }
}

/// Interface link attributes (IFLA_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
pub enum IflaAttr {
    Unspec = 0,
    Address = 1,
    Broadcast = 2,
    Ifname = 3,
    Mtu = 4,
    Link = 5,
    Qdisc = 6,
    Stats = 7,
    Cost = 8,
    Priority = 9,
    Master = 10,
    /// Wireless extensions
    Wireless = 11,
    /// Protocol specific information
    Protinfo = 12,
    TxqLen = 13,
    Map = 14,
    Weight = 15,
    Operstate = 16,
    Linkmode = 17,
    Linkinfo = 18,
    NetNsPid = 19,
    Ifalias = 20,
    NumVf = 21,
    VfinfoList = 22,
    Stats64 = 23,
    VfPorts = 24,
    PortSelf = 25,
    AfSpec = 26,
    Group = 27,
    NetNsFd = 28,
    ExtMask = 29,
    Promiscuity = 30,
    NumTxQueues = 31,
    NumRxQueues = 32,
    Carrier = 33,
    PhysPortId = 34,
    CarrierChanges = 35,
    PhysSwitchId = 36,
    LinkNetnsid = 37,
    PhysPortName = 38,
    ProtoDown = 39,
    GsoMaxSegs = 40,
    GsoMaxSize = 41,
    Pad = 42,
    Xdp = 43,
    Event = 44,
    NewNetnsid = 45,
    IfNetnsid = 46,
    // TargetNetnsid is an alias for IfNetnsid (same value 46)
    CarrierUpCount = 47,
    CarrierDownCount = 48,
    NewIfindex = 49,
    MinMtu = 50,
    MaxMtu = 51,
    PropList = 52,
    AltIfname = 53,
    PermAddress = 54,
    ProtoDownReason = 55,
    ParentDevName = 56,
    ParentDevBusName = 57,
    GroMaxSize = 58,
    TsoMaxSize = 59,
    TsoMaxSegs = 60,
    Allmulti = 61,
    /// Plan 190 §2.3c — IPv4-specific GSO max size (kernel 6.6+).
    GsoIpv4MaxSize = 63,
    /// Plan 190 §2.3c — IPv4-specific GRO max size (kernel 6.6+).
    GroIpv4MaxSize = 64,
}

impl From<u16> for IflaAttr {
    fn from(val: u16) -> Self {
        match val {
            0 => Self::Unspec,
            1 => Self::Address,
            2 => Self::Broadcast,
            3 => Self::Ifname,
            4 => Self::Mtu,
            5 => Self::Link,
            6 => Self::Qdisc,
            7 => Self::Stats,
            8 => Self::Cost,
            9 => Self::Priority,
            10 => Self::Master,
            11 => Self::Wireless,
            12 => Self::Protinfo,
            13 => Self::TxqLen,
            14 => Self::Map,
            15 => Self::Weight,
            16 => Self::Operstate,
            17 => Self::Linkmode,
            18 => Self::Linkinfo,
            19 => Self::NetNsPid,
            20 => Self::Ifalias,
            21 => Self::NumVf,
            22 => Self::VfinfoList,
            23 => Self::Stats64,
            24 => Self::VfPorts,
            25 => Self::PortSelf,
            26 => Self::AfSpec,
            27 => Self::Group,
            28 => Self::NetNsFd,
            29 => Self::ExtMask,
            30 => Self::Promiscuity,
            31 => Self::NumTxQueues,
            32 => Self::NumRxQueues,
            33 => Self::Carrier,
            34 => Self::PhysPortId,
            35 => Self::CarrierChanges,
            36 => Self::PhysSwitchId,
            37 => Self::LinkNetnsid,
            38 => Self::PhysPortName,
            39 => Self::ProtoDown,
            40 => Self::GsoMaxSegs,
            41 => Self::GsoMaxSize,
            42 => Self::Pad,
            43 => Self::Xdp,
            44 => Self::Event,
            45 => Self::NewNetnsid,
            46 => Self::IfNetnsid,
            47 => Self::CarrierUpCount,
            48 => Self::CarrierDownCount,
            49 => Self::NewIfindex,
            50 => Self::MinMtu,
            51 => Self::MaxMtu,
            52 => Self::PropList,
            53 => Self::AltIfname,
            54 => Self::PermAddress,
            55 => Self::ProtoDownReason,
            56 => Self::ParentDevName,
            57 => Self::ParentDevBusName,
            58 => Self::GroMaxSize,
            59 => Self::TsoMaxSize,
            60 => Self::TsoMaxSegs,
            61 => Self::Allmulti,
            63 => Self::GsoIpv4MaxSize,
            64 => Self::GroIpv4MaxSize,
            _ => Self::Unspec,
        }
    }
}

/// IFLA_LINKINFO nested attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
pub enum IflaInfo {
    Unspec = 0,
    Kind = 1,
    Data = 2,
    Xstats = 3,
    SlaveKind = 4,
    SlaveData = 5,
}

impl From<u16> for IflaInfo {
    fn from(val: u16) -> Self {
        match val {
            1 => Self::Kind,
            2 => Self::Data,
            3 => Self::Xstats,
            4 => Self::SlaveKind,
            5 => Self::SlaveData,
            _ => Self::Unspec,
        }
    }
}

/// Interface flags (IFF_*).
pub mod iff {
    pub const UP: u32 = 1 << 0;
    pub const BROADCAST: u32 = 1 << 1;
    pub const DEBUG: u32 = 1 << 2;
    pub const LOOPBACK: u32 = 1 << 3;
    pub const POINTOPOINT: u32 = 1 << 4;
    pub const NOTRAILERS: u32 = 1 << 5;
    pub const RUNNING: u32 = 1 << 6;
    pub const NOARP: u32 = 1 << 7;
    pub const PROMISC: u32 = 1 << 8;
    pub const ALLMULTI: u32 = 1 << 9;
    pub const MASTER: u32 = 1 << 10;
    pub const SLAVE: u32 = 1 << 11;
    pub const MULTICAST: u32 = 1 << 12;
    pub const PORTSEL: u32 = 1 << 13;
    pub const AUTOMEDIA: u32 = 1 << 14;
    pub const DYNAMIC: u32 = 1 << 15;
    pub const LOWER_UP: u32 = 1 << 16;
    pub const DORMANT: u32 = 1 << 17;
    pub const ECHO: u32 = 1 << 18;
}

/// Operational state (IF_OPER_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum OperState {
    Unknown = 0,
    NotPresent = 1,
    Down = 2,
    LowerLayerDown = 3,
    Testing = 4,
    Dormant = 5,
    Up = 6,
}

impl From<u8> for OperState {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::Unknown,
            1 => Self::NotPresent,
            2 => Self::Down,
            3 => Self::LowerLayerDown,
            4 => Self::Testing,
            5 => Self::Dormant,
            6 => Self::Up,
            _ => Self::Unknown,
        }
    }
}

impl OperState {
    /// Get the name of this state.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::NotPresent => "NOT_PRESENT",
            Self::Down => "DOWN",
            Self::LowerLayerDown => "LOWERLAYERDOWN",
            Self::Testing => "TESTING",
            Self::Dormant => "DORMANT",
            Self::Up => "UP",
        }
    }

    /// Get a lowercase display name suitable for metrics and logging.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::NotPresent => "not_present",
            Self::Down => "down",
            Self::LowerLayerDown => "lower_layer_down",
            Self::Testing => "testing",
            Self::Dormant => "dormant",
            Self::Up => "up",
        }
    }
}

impl std::fmt::Display for OperState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

/// Link statistics (struct rtnl_link_stats64).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, Immutable, KnownLayout)]
pub struct LinkStats64 {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub multicast: u64,
    pub collisions: u64,
    // Detailed rx errors
    pub rx_length_errors: u64,
    pub rx_over_errors: u64,
    pub rx_crc_errors: u64,
    pub rx_frame_errors: u64,
    pub rx_fifo_errors: u64,
    pub rx_missed_errors: u64,
    // Detailed tx errors
    pub tx_aborted_errors: u64,
    pub tx_carrier_errors: u64,
    pub tx_fifo_errors: u64,
    pub tx_heartbeat_errors: u64,
    pub tx_window_errors: u64,
    // For cslip etc
    pub rx_compressed: u64,
    pub tx_compressed: u64,
    pub rx_nohandler: u64,
}

impl LinkStats64 {
    /// Parse from bytes by copying (avoids alignment issues).
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        Self::read_from_prefix(data).map(|(r, _)| r).ok()
    }
}

/// The header of an `RTM_GETSTATS`/`RTM_NEWSTATS` message (struct
/// if_stats_msg, Linux 4.7+). `filter_mask` selects the `IFLA_STATS_*`
/// attributes, one bit each: `1 << (attr - 1)`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct IfStatsMsg {
    pub family: u8,
    pub pad1: u8,
    pub pad2: u16,
    pub ifindex: u32,
    pub filter_mask: u32,
}

impl IfStatsMsg {
    /// The struct's size on the wire.
    pub const SIZE: usize = std::mem::size_of::<Self>();
}

/// `IFLA_STATS_LINK_64`: a `struct rtnl_link_stats64` in an
/// `RTM_NEWSTATS` message.
pub const IFLA_STATS_LINK_64: u16 = 1;

// ============================================================================
// Bridge VLAN types
// ============================================================================

/// IFLA_AF_SPEC attribute types for AF_BRIDGE.
pub mod bridge_af {
    /// Bridge flags
    pub const IFLA_BRIDGE_FLAGS: u16 = 0;
    /// Bridge mode
    pub const IFLA_BRIDGE_MODE: u16 = 1;
    /// VLAN info
    pub const IFLA_BRIDGE_VLAN_INFO: u16 = 2;
    /// VLAN tunnel info
    pub const IFLA_BRIDGE_VLAN_TUNNEL_INFO: u16 = 3;
    /// Multicast router
    pub const IFLA_BRIDGE_MRP: u16 = 4;
    /// CFM
    pub const IFLA_BRIDGE_CFM: u16 = 5;
    /// MST
    pub const IFLA_BRIDGE_MST: u16 = 6;
}

/// Bridge port attributes (`IFLA_BRPORT_*`), carried inside the
/// `IFLA_PROTINFO` nest of an `RTM_SETLINK` with `ifi_family =
/// AF_BRIDGE`. These configure a single port's behaviour on its
/// bridge (`bridge link set dev <port> ...`). Only the subset
/// modelled by [`BridgePortConfig`](crate::netlink::link::BridgePortConfig)
/// is listed.
pub mod brport {
    /// STP port state (u8): 0 disabled, 1 listening, 2 learning,
    /// 3 forwarding, 4 blocking.
    pub const IFLA_BRPORT_STATE: u16 = 1;
    /// STP port priority (u16).
    pub const IFLA_BRPORT_PRIORITY: u16 = 2;
    /// STP path cost (u32).
    pub const IFLA_BRPORT_COST: u16 = 3;
    /// Hairpin mode (u8 bool) — reflect frames back out the
    /// receiving port.
    pub const IFLA_BRPORT_MODE: u16 = 4;
    /// BPDU guard (u8 bool) — disable port on BPDU receipt.
    pub const IFLA_BRPORT_GUARD: u16 = 5;
    /// Root block / `bpdu_guard`'s sibling (u8 bool) — reject
    /// superior BPDUs (a.k.a. `root_block`).
    pub const IFLA_BRPORT_PROTECT: u16 = 6;
    /// Fast leave for IGMP snooping (u8 bool).
    pub const IFLA_BRPORT_FAST_LEAVE: u16 = 7;
    /// MAC learning (u8 bool).
    pub const IFLA_BRPORT_LEARNING: u16 = 8;
    /// Unknown-unicast flooding (u8 bool).
    pub const IFLA_BRPORT_UNICAST_FLOOD: u16 = 9;
    /// Proxy ARP (u8 bool).
    pub const IFLA_BRPORT_PROXYARP: u16 = 10;
    /// Multicast flooding (u8 bool).
    /// Unused by nlink; listed because omitting these two is what shifted
    /// MCAST_FLOOD and MCAST_TO_UCAST down by four (#259).
    #[allow(dead_code)]
    pub const IFLA_BRPORT_MULTICAST_ROUTER: u16 = 25;
    #[allow(dead_code)]
    pub const IFLA_BRPORT_PAD: u16 = 26;
    pub const IFLA_BRPORT_MCAST_FLOOD: u16 = 27;
    /// Multicast-to-unicast (u8 bool).
    pub const IFLA_BRPORT_MCAST_TO_UCAST: u16 = 28;
    /// Broadcast flooding (u8 bool).
    pub const IFLA_BRPORT_BCAST_FLOOD: u16 = 30;
    /// Neighbour suppression (u8 bool).
    pub const IFLA_BRPORT_NEIGH_SUPPRESS: u16 = 32;
    /// Port isolation (u8 bool) — isolated ports cannot talk to
    /// each other.
    pub const IFLA_BRPORT_ISOLATED: u16 = 33;
}

/// Bridge VLAN tunnel info nested attributes (IFLA_BRIDGE_VLAN_TUNNEL_*).
pub mod bridge_vlan_tunnel {
    /// Tunnel ID (VNI for VXLAN)
    pub const IFLA_BRIDGE_VLAN_TUNNEL_ID: u16 = 1;
    /// VLAN ID
    pub const IFLA_BRIDGE_VLAN_TUNNEL_VID: u16 = 2;
    /// Flags (range begin/end)
    pub const IFLA_BRIDGE_VLAN_TUNNEL_FLAGS: u16 = 3;
}

/// Bridge VLAN info flags (BRIDGE_VLAN_INFO_*).
pub mod bridge_vlan_flags {
    /// Operate on bridge device (global VLAN)
    pub const MASTER: u16 = 1 << 0;
    /// This is the PVID (Port VLAN ID)
    pub const PVID: u16 = 1 << 1;
    /// Egress untagged (strip VLAN tag)
    pub const UNTAGGED: u16 = 1 << 2;
    /// Start of VLAN range
    pub const RANGE_BEGIN: u16 = 1 << 3;
    /// End of VLAN range
    pub const RANGE_END: u16 = 1 << 4;
    /// Global bridge VLAN entry
    pub const BRENTRY: u16 = 1 << 5;
    /// VLAN is only for ingress
    pub const ONLY_OPTS: u16 = 1 << 6;
}

/// Bridge VLAN info structure (struct bridge_vlan_info).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct BridgeVlanInfo {
    /// VLAN flags (BRIDGE_VLAN_INFO_*)
    pub flags: u16,
    /// VLAN ID (1-4094)
    pub vid: u16,
}

impl BridgeVlanInfo {
    /// Size of this structure.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create a new bridge VLAN info.
    pub fn new(vid: u16) -> Self {
        Self { flags: 0, vid }
    }

    /// Set the flags.
    pub fn with_flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }

    /// Check if this is the PVID.
    pub fn is_pvid(&self) -> bool {
        self.flags & bridge_vlan_flags::PVID != 0
    }

    /// Check if egress is untagged.
    pub fn is_untagged(&self) -> bool {
        self.flags & bridge_vlan_flags::UNTAGGED != 0
    }

    /// Check if this is start of a range.
    pub fn is_range_begin(&self) -> bool {
        self.flags & bridge_vlan_flags::RANGE_BEGIN != 0
    }

    /// Check if this is end of a range.
    pub fn is_range_end(&self) -> bool {
        self.flags & bridge_vlan_flags::RANGE_END != 0
    }

    /// Convert to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }
}

// ============================================================================
// Bridge VLAN-DB API (RTM_{NEW,DEL,GET}VLAN)
// ============================================================================

/// Bridge VLAN-DB message header (`struct br_vlan_msg`).
///
/// Family header for the `RTM_{NEW,DEL,GET}VLAN` messages that carry
/// per-VLAN entries (`BRIDGE_VLANDB_ENTRY`) and bridge-global VLAN
/// options (`BRIDGE_VLANDB_GLOBAL_OPTIONS`). `family` is `AF_BRIDGE`
/// and `ifindex` is the bridge device.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct BrVlanMsg {
    /// Address family (`AF_BRIDGE`).
    pub family: u8,
    /// Reserved, must be zero.
    pub reserved1: u8,
    /// Reserved, must be zero.
    pub reserved2: u16,
    /// Bridge interface index.
    pub ifindex: u32,
}

impl BrVlanMsg {
    /// Size of this structure (8 bytes).
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create a new message header.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the address family.
    pub fn with_family(mut self, family: u8) -> Self {
        self.family = family;
        self
    }

    /// Set the bridge interface index.
    pub fn with_index(mut self, ifindex: u32) -> Self {
        self.ifindex = ifindex;
        self
    }

    /// Convert to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    /// Parse from bytes (accept-larger-than-expected: reads the prefix,
    /// ignores trailing bytes a future kernel may append).
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }
}

/// Top-level attributes carried in an `RTM_{NEW,GET}VLAN` message
/// (`BRIDGE_VLANDB_*`).
pub mod bridge_vlandb {
    /// Per-VLAN entry nest (`BRIDGE_VLANDB_ENTRY`).
    pub const ENTRY: u16 = 1;
    /// Bridge-global VLAN options nest (`BRIDGE_VLANDB_GLOBAL_OPTIONS`).
    pub const GLOBAL_OPTIONS: u16 = 2;
}

/// Per-VLAN entry attributes (`BRIDGE_VLANDB_ENTRY` → `BRIDGE_VLANDB_ENTRY_*`).
///
/// These are per-(port, VLAN) settings — STP state, multicast router,
/// neighbour suppression — distinct from the bridge-global
/// [`bridge_vlandb_gopts`] options.
pub mod bridge_vlandb_entry {
    /// `struct bridge_vlan_info` (flags + vid).
    pub const INFO: u16 = 1;
    /// Upper VLAN ID of a range (u16); present with [`INFO`] for ranges.
    pub const RANGE: u16 = 2;
    /// Per-VLAN STP state (u8, `BR_STATE_*` — see [`super::br_state`]).
    pub const STATE: u16 = 3;
    /// VLAN tunnel info (nested).
    pub const TUNNEL_INFO: u16 = 4;
    /// Per-VLAN stats (nested, read-only).
    pub const STATS: u16 = 5;
    /// Per-VLAN multicast router mode (u8).
    pub const MCAST_ROUTER: u16 = 6;
    /// Current number of multicast groups (u32, read-only).
    pub const MCAST_N_GROUPS: u16 = 7;
    /// Multicast group limit (u32).
    pub const MCAST_MAX_GROUPS: u16 = 8;
    /// Neighbour suppression enabled (u8 bool).
    pub const NEIGH_SUPPRESS: u16 = 9;
}

/// Spanning-tree port states (`BR_STATE_*`), used by the per-VLAN
/// [`bridge_vlandb_entry::STATE`] attribute (MSTP per-VLAN state).
pub mod br_state {
    /// Port disabled.
    pub const DISABLED: u8 = 0;
    /// Listening (STP).
    pub const LISTENING: u8 = 1;
    /// Learning (STP).
    pub const LEARNING: u8 = 2;
    /// Forwarding.
    pub const FORWARDING: u8 = 3;
    /// Blocking (STP).
    pub const BLOCKING: u8 = 4;
}

/// Attributes carried in an `RTM_GETVLAN` dump *request* to filter the
/// dump (`BRIDGE_VLANDB_DUMP_*`).
pub mod bridge_vlandb_dump {
    /// Dump-filter flags attribute (`BRIDGE_VLANDB_DUMP_FLAGS`, u32).
    pub const FLAGS: u16 = 1;

    /// Include per-VLAN stats in the dump (`BRIDGE_VLANDB_DUMPF_STATS`).
    pub const DUMPF_STATS: u32 = 1 << 0;
    /// Dump bridge-global VLAN options only (`BRIDGE_VLANDB_DUMPF_GLOBAL`).
    pub const DUMPF_GLOBAL: u32 = 1 << 1;
}

/// Bridge-global per-VLAN option attributes
/// (`BRIDGE_VLANDB_GLOBAL_OPTIONS` → `BRIDGE_VLANDB_GOPTS_*`).
///
/// These are the per-VLAN settings that live on the bridge device
/// itself, chiefly per-VLAN multicast snooping.
pub mod bridge_vlandb_gopts {
    /// VLAN ID this option block applies to (u16).
    pub const ID: u16 = 1;
    /// Upper VLAN ID of a range (u16); present with [`ID`] for ranges.
    pub const RANGE: u16 = 2;
    /// Per-VLAN multicast snooping enabled (u8 bool).
    pub const MCAST_SNOOPING: u16 = 3;
    /// IGMP query version (u8).
    pub const MCAST_IGMP_VERSION: u16 = 4;
    /// MLD query version (u8).
    pub const MCAST_MLD_VERSION: u16 = 5;
    /// Last-member query count (u32).
    pub const MCAST_LAST_MEMBER_CNT: u16 = 6;
    /// Startup query count (u32).
    pub const MCAST_STARTUP_QUERY_CNT: u16 = 7;
    /// Last-member query interval, centiseconds (u64).
    pub const MCAST_LAST_MEMBER_INTVL: u16 = 8;
    /// Padding attribute for 64-bit alignment (`BRIDGE_VLANDB_GOPTS_PAD`).
    pub const PAD: u16 = 9;
    /// Membership interval, centiseconds (u64).
    pub const MCAST_MEMBERSHIP_INTVL: u16 = 10;
    /// Querier interval, centiseconds (u64).
    pub const MCAST_QUERIER_INTVL: u16 = 11;
    /// Query interval, centiseconds (u64).
    pub const MCAST_QUERY_INTVL: u16 = 12;
    /// Query response interval, centiseconds (u64).
    pub const MCAST_QUERY_RESPONSE_INTVL: u16 = 13;
    /// Startup query interval, centiseconds (u64).
    pub const MCAST_STARTUP_QUERY_INTVL: u16 = 14;
    /// Per-VLAN multicast querier enabled (u8 bool).
    pub const MCAST_QUERIER: u16 = 15;
    /// Multicast router ports list (nested, dump-only). Older mainline
    /// headers name this attribute `BRIDGE_VLANDB_GOPTS_MCAST_ROUTER`;
    /// the index is stable. Recognized but not modelled by
    /// `BridgeVlanGlobalOptions` (see module docs).
    pub const MCAST_ROUTER_PORTS: u16 = 16;
    /// Multicast querier state (nested, read-only). Not modelled.
    pub const MCAST_QUERIER_STATE: u16 = 17;
    /// MST instance id this VLAN maps to (u16).
    pub const MSTI: u16 = 18;
}

/// Extended filter mask for requesting additional link info.
pub mod rtext_filter {
    /// Request VLAN info
    pub const VF: u32 = 1 << 0;
    /// Request bridge VLAN info
    pub const BRVLAN: u32 = 1 << 1;
    /// Request compressed bridge VLAN info
    pub const BRVLAN_COMPRESSED: u32 = 1 << 2;
    /// Skip statistics
    pub const SKIP_STATS: u32 = 1 << 3;
    /// Request MRP info
    pub const MRP: u32 = 1 << 4;
    /// Request CFM info
    pub const CFM_CONFIG: u32 = 1 << 5;
    /// Request CFM status
    pub const CFM_STATUS: u32 = 1 << 6;
    /// Request MST info
    pub const MST: u32 = 1 << 7;
}
