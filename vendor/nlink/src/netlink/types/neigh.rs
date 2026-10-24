//! Neighbor (ARP/NDP) message types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::netlink::error::{Error, Result};

/// Neighbor message (struct ndmsg).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NdMsg {
    /// Address family.
    pub ndm_family: u8,
    /// Padding.
    pub ndm_pad1: u8,
    /// Padding.
    pub ndm_pad2: u16,
    /// Interface index.
    pub ndm_ifindex: i32,
    /// Neighbor state (NUD_*).
    pub ndm_state: u16,
    /// Neighbor flags (NTF_*).
    pub ndm_flags: u8,
    /// Neighbor type.
    pub ndm_type: u8,
}

impl NdMsg {
    /// Size of this structure.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create a new neighbor message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the address family.
    pub fn with_family(mut self, family: u8) -> Self {
        self.ndm_family = family;
        self
    }

    /// Set the interface index.
    pub fn with_ifindex(mut self, ifindex: i32) -> Self {
        self.ndm_ifindex = ifindex;
        self
    }

    /// Set the neighbor state.
    pub fn with_state(mut self, state: u16) -> Self {
        self.ndm_state = state;
        self
    }

    /// Set the neighbor flags.
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.ndm_flags = flags;
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

/// Neighbor attributes (NDA_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
pub enum NdaAttr {
    Unspec = 0,
    Dst = 1,
    Lladdr = 2,
    Cacheinfo = 3,
    Probes = 4,
    Vlan = 5,
    Port = 6,
    Vni = 7,
    Ifindex = 8,
    Master = 9,
    LinkNetnsid = 10,
    SrcVni = 11,
    Protocol = 12,
    NhId = 13,
    FdbExtAttrs = 14,
    Flags = 15,
}

impl From<u16> for NdaAttr {
    fn from(val: u16) -> Self {
        match val {
            0 => Self::Unspec,
            1 => Self::Dst,
            2 => Self::Lladdr,
            3 => Self::Cacheinfo,
            4 => Self::Probes,
            5 => Self::Vlan,
            6 => Self::Port,
            7 => Self::Vni,
            8 => Self::Ifindex,
            9 => Self::Master,
            10 => Self::LinkNetnsid,
            11 => Self::SrcVni,
            12 => Self::Protocol,
            13 => Self::NhId,
            14 => Self::FdbExtAttrs,
            15 => Self::Flags,
            _ => Self::Unspec,
        }
    }
}

/// Neighbor state (NUD_*).
pub mod nud {
    pub const INCOMPLETE: u16 = 0x01;
    pub const REACHABLE: u16 = 0x02;
    pub const STALE: u16 = 0x04;
    pub const DELAY: u16 = 0x08;
    pub const PROBE: u16 = 0x10;
    pub const FAILED: u16 = 0x20;
    pub const NOARP: u16 = 0x40;
    pub const PERMANENT: u16 = 0x80;
    pub const NONE: u16 = 0x00;
}

/// Get the name of a neighbor state.
pub fn nud_state_name(state: u16) -> &'static str {
    match state {
        nud::INCOMPLETE => "INCOMPLETE",
        nud::REACHABLE => "REACHABLE",
        nud::STALE => "STALE",
        nud::DELAY => "DELAY",
        nud::PROBE => "PROBE",
        nud::FAILED => "FAILED",
        nud::NOARP => "NOARP",
        nud::PERMANENT => "PERMANENT",
        nud::NONE => "NONE",
        _ => "UNKNOWN",
    }
}

/// Neighbor state as an enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
pub enum NeighborState {
    None = 0x00,
    Incomplete = 0x01,
    Reachable = 0x02,
    Stale = 0x04,
    Delay = 0x08,
    Probe = 0x10,
    Failed = 0x20,
    Noarp = 0x40,
    Permanent = 0x80,
}

impl From<u16> for NeighborState {
    fn from(val: u16) -> Self {
        match val {
            0x01 => Self::Incomplete,
            0x02 => Self::Reachable,
            0x04 => Self::Stale,
            0x08 => Self::Delay,
            0x10 => Self::Probe,
            0x20 => Self::Failed,
            0x40 => Self::Noarp,
            0x80 => Self::Permanent,
            _ => Self::None,
        }
    }
}

impl NeighborState {
    /// Get the name of this state.
    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Incomplete => "INCOMPLETE",
            Self::Reachable => "REACHABLE",
            Self::Stale => "STALE",
            Self::Delay => "DELAY",
            Self::Probe => "PROBE",
            Self::Failed => "FAILED",
            Self::Noarp => "NOARP",
            Self::Permanent => "PERMANENT",
        }
    }
}

/// Neighbor flags (NTF_*).
pub mod ntf {
    pub const USE: u8 = 0x01;
    pub const SELF: u8 = 0x02;
    pub const MASTER: u8 = 0x04;
    pub const PROXY: u8 = 0x08;
    pub const EXT_LEARNED: u8 = 0x10;
    pub const OFFLOADED: u8 = 0x20;
    pub const STICKY: u8 = 0x40;
    pub const ROUTER: u8 = 0x80;
}

/// Neighbor cache info (struct nda_cacheinfo).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, Immutable, KnownLayout)]
pub struct NdaCacheinfo {
    pub ndm_confirmed: u32,
    pub ndm_used: u32,
    pub ndm_updated: u32,
    pub ndm_refcnt: u32,
}

impl NdaCacheinfo {
    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }
}
