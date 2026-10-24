//! Route message types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::netlink::error::{Error, Result};

/// Route message (struct rtmsg).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct RtMsg {
    /// Address family.
    pub rtm_family: u8,
    /// Destination prefix length.
    pub rtm_dst_len: u8,
    /// Source prefix length.
    pub rtm_src_len: u8,
    /// TOS filter.
    pub rtm_tos: u8,
    /// Routing table ID.
    pub rtm_table: u8,
    /// Routing protocol (RTPROT_*).
    pub rtm_protocol: u8,
    /// Route scope (RT_SCOPE_*).
    pub rtm_scope: u8,
    /// Route type (RTN_*).
    pub rtm_type: u8,
    /// Route flags.
    pub rtm_flags: u32,
}

impl RtMsg {
    /// Size of this structure.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create a new route message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the address family.
    pub fn with_family(mut self, family: u8) -> Self {
        self.rtm_family = family;
        self
    }

    /// Set the destination prefix length.
    pub fn with_dst_len(mut self, len: u8) -> Self {
        self.rtm_dst_len = len;
        self
    }

    /// Set the routing table.
    pub fn with_table(mut self, table: u8) -> Self {
        self.rtm_table = table;
        self
    }

    /// Set the protocol.
    pub fn with_protocol(mut self, protocol: u8) -> Self {
        self.rtm_protocol = protocol;
        self
    }

    /// Set the scope.
    pub fn with_scope(mut self, scope: u8) -> Self {
        self.rtm_scope = scope;
        self
    }

    /// Set the route type.
    pub fn with_type(mut self, rtype: u8) -> Self {
        self.rtm_type = rtype;
        self
    }

    /// Set the `RTNH_F_*` / `RTM_F_*` flags (`rtm_flags`).
    pub fn with_flags(mut self, flags: u32) -> Self {
        self.rtm_flags = flags;
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

/// Route attributes (RTA_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
pub enum RtaAttr {
    Unspec = 0,
    Dst = 1,
    Src = 2,
    Iif = 3,
    Oif = 4,
    Gateway = 5,
    Priority = 6,
    Prefsrc = 7,
    Metrics = 8,
    Multipath = 9,
    Protoinfo = 10, // Deprecated
    Flow = 11,
    Cacheinfo = 12,
    Session = 13, // Deprecated
    MpAlgo = 14,  // Deprecated
    Table = 15,
    Mark = 16,
    MfcStats = 17,
    Via = 18,
    Newdst = 19,
    Pref = 20,
    EncapType = 21,
    Encap = 22,
    Expires = 23,
    Pad = 24,
    Uid = 25,
    TtlPropagate = 26,
    IpProto = 27,
    Sport = 28,
    Dport = 29,
    NhId = 30,
}

impl From<u16> for RtaAttr {
    fn from(val: u16) -> Self {
        match val {
            0 => Self::Unspec,
            1 => Self::Dst,
            2 => Self::Src,
            3 => Self::Iif,
            4 => Self::Oif,
            5 => Self::Gateway,
            6 => Self::Priority,
            7 => Self::Prefsrc,
            8 => Self::Metrics,
            9 => Self::Multipath,
            10 => Self::Protoinfo,
            11 => Self::Flow,
            12 => Self::Cacheinfo,
            15 => Self::Table,
            16 => Self::Mark,
            17 => Self::MfcStats,
            18 => Self::Via,
            19 => Self::Newdst,
            20 => Self::Pref,
            21 => Self::EncapType,
            22 => Self::Encap,
            23 => Self::Expires,
            24 => Self::Pad,
            25 => Self::Uid,
            26 => Self::TtlPropagate,
            27 => Self::IpProto,
            28 => Self::Sport,
            29 => Self::Dport,
            30 => Self::NhId,
            _ => Self::Unspec,
        }
    }
}

/// Route types (RTN_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum RouteType {
    Unspec = 0,
    Unicast = 1,
    Local = 2,
    Broadcast = 3,
    Anycast = 4,
    Multicast = 5,
    Blackhole = 6,
    Unreachable = 7,
    Prohibit = 8,
    Throw = 9,
    Nat = 10,
    ExternalResolver = 11,
}

impl From<u8> for RouteType {
    fn from(val: u8) -> Self {
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
            11 => Self::ExternalResolver,
            _ => Self::Unspec,
        }
    }
}

impl RouteType {
    /// Get the name of this route type.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unspec => "unspec",
            Self::Unicast => "unicast",
            Self::Local => "local",
            Self::Broadcast => "broadcast",
            Self::Anycast => "anycast",
            Self::Multicast => "multicast",
            Self::Blackhole => "blackhole",
            Self::Unreachable => "unreachable",
            Self::Prohibit => "prohibit",
            Self::Throw => "throw",
            Self::Nat => "nat",
            Self::ExternalResolver => "xresolve",
        }
    }
}

/// Route protocols (RTPROT_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum RouteProtocol {
    Unspec = 0,
    Redirect = 1,
    Kernel = 2,
    Boot = 3,
    Static = 4,
    // Routing daemons
    Gated = 8,
    Ra = 9,
    Mrt = 10,
    Zebra = 11,
    Bird = 12,
    Dnrouted = 13,
    Xorp = 14,
    Ntk = 15,
    Dhcp = 16,
    Mrouted = 17,
    Keepalived = 18,
    Babel = 42,
    Bgp = 186,
    Isis = 187,
    Ospf = 188,
    Rip = 189,
    Eigrp = 192,
    /// A number nlink has no name for: a routing daemon's own, or the one
    /// a `NetworkConfig` installs its routes with (#512). Never one of the
    /// numbers above, which `From<u8>` names; it read back as `Unspec`
    /// before 0.32.
    Other(u8),
}

impl From<u8> for RouteProtocol {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::Unspec,
            1 => Self::Redirect,
            2 => Self::Kernel,
            3 => Self::Boot,
            4 => Self::Static,
            8 => Self::Gated,
            9 => Self::Ra,
            10 => Self::Mrt,
            11 => Self::Zebra,
            12 => Self::Bird,
            13 => Self::Dnrouted,
            14 => Self::Xorp,
            15 => Self::Ntk,
            16 => Self::Dhcp,
            17 => Self::Mrouted,
            18 => Self::Keepalived,
            42 => Self::Babel,
            186 => Self::Bgp,
            187 => Self::Isis,
            188 => Self::Ospf,
            189 => Self::Rip,
            192 => Self::Eigrp,
            other => Self::Other(other),
        }
    }
}

impl From<RouteProtocol> for u8 {
    fn from(p: RouteProtocol) -> u8 {
        p.number()
    }
}

impl std::fmt::Display for RouteProtocol {
    /// The name `ip route` prints, or the number for one without a name.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Other(n) => write!(f, "{n}"),
            named => f.write_str(named.name()),
        }
    }
}

impl RouteProtocol {
    /// The `RTPROT_*` number.
    pub fn number(self) -> u8 {
        match self {
            Self::Unspec => 0,
            Self::Redirect => 1,
            Self::Kernel => 2,
            Self::Boot => 3,
            Self::Static => 4,
            Self::Gated => 8,
            Self::Ra => 9,
            Self::Mrt => 10,
            Self::Zebra => 11,
            Self::Bird => 12,
            Self::Dnrouted => 13,
            Self::Xorp => 14,
            Self::Ntk => 15,
            Self::Dhcp => 16,
            Self::Mrouted => 17,
            Self::Keepalived => 18,
            Self::Babel => 42,
            Self::Bgp => 186,
            Self::Isis => 187,
            Self::Ospf => 188,
            Self::Rip => 189,
            Self::Eigrp => 192,
            Self::Other(n) => n,
        }
    }

    /// Get the name of this protocol; `"unknown"` for
    /// [`Other`](Self::Other), whose `Display` is its number.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unspec => "unspec",
            Self::Redirect => "redirect",
            Self::Kernel => "kernel",
            Self::Boot => "boot",
            Self::Static => "static",
            Self::Gated => "gated",
            Self::Ra => "ra",
            Self::Mrt => "mrt",
            Self::Zebra => "zebra",
            Self::Bird => "bird",
            Self::Dnrouted => "dnrouted",
            Self::Xorp => "xorp",
            Self::Ntk => "ntk",
            Self::Dhcp => "dhcp",
            Self::Mrouted => "mrouted",
            Self::Keepalived => "keepalived",
            Self::Babel => "babel",
            Self::Bgp => "bgp",
            Self::Isis => "isis",
            Self::Ospf => "ospf",
            Self::Rip => "rip",
            Self::Eigrp => "eigrp",
            Self::Other(_) => "unknown",
        }
    }
}

/// Route scope (RT_SCOPE_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum RouteScope {
    Universe = 0,
    Site = 200,
    Link = 253,
    Host = 254,
    Nowhere = 255,
}

impl From<u8> for RouteScope {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::Universe,
            200 => Self::Site,
            253 => Self::Link,
            254 => Self::Host,
            255 => Self::Nowhere,
            _ => Self::Universe,
        }
    }
}

impl RouteScope {
    /// Get the name of this scope.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Universe => "global",
            Self::Site => "site",
            Self::Link => "link",
            Self::Host => "host",
            Self::Nowhere => "nowhere",
        }
    }

    /// Parse scope from name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "global" | "universe" => Some(Self::Universe),
            "site" => Some(Self::Site),
            "link" => Some(Self::Link),
            "host" => Some(Self::Host),
            "nowhere" => Some(Self::Nowhere),
            _ => None,
        }
    }
}

/// Route table IDs.
pub mod rt_table {
    pub const UNSPEC: u8 = 0;
    pub const COMPAT: u8 = 252;
    pub const DEFAULT: u8 = 253;
    pub const MAIN: u8 = 254;
    pub const LOCAL: u8 = 255;
}

/// Route flags.
pub mod rtm_flags {
    pub const NOTIFY: u32 = 0x100;
    pub const CLONED: u32 = 0x200;
    pub const EQUALIZE: u32 = 0x400;
    pub const PREFIX: u32 = 0x800;
    pub const LOOKUP_TABLE: u32 = 0x1000;
    pub const FIB_MATCH: u32 = 0x2000;
    pub const OFFLOAD: u32 = 0x4000;
    pub const TRAP: u32 = 0x8000;
    pub const OFFLOAD_FAILED: u32 = 0x20000000;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every protocol number round-trips; one nlink has no name for is
    /// `Other` and prints as its number. It read back as `Unspec` (#512).
    #[test]
    fn every_protocol_number_round_trips() {
        for n in 0..=u8::MAX {
            assert_eq!(RouteProtocol::from(n).number(), n);
            assert_eq!(u8::from(RouteProtocol::from(n)), n);
        }
        assert_eq!(RouteProtocol::from(3), RouteProtocol::Boot);
        assert_eq!(RouteProtocol::from(250), RouteProtocol::Other(250));
        assert_eq!(RouteProtocol::Other(250).to_string(), "250");
        assert_eq!(RouteProtocol::Bgp.to_string(), "bgp");
    }
}
