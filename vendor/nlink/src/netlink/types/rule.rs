//! Routing rule message types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::netlink::error::{Error, Result};

/// FIB rule header (struct fib_rule_hdr).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FibRuleHdr {
    /// Address family.
    pub family: u8,
    /// Destination prefix length.
    pub dst_len: u8,
    /// Source prefix length.
    pub src_len: u8,
    /// TOS.
    pub tos: u8,
    /// Routing table ID.
    pub table: u8,
    /// Reserved.
    pub res1: u8,
    /// Reserved.
    pub res2: u8,
    /// Action (FR_ACT_*).
    pub action: u8,
    /// Flags.
    pub flags: u32,
}

impl FibRuleHdr {
    /// Size of this structure.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create a new rule header.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the address family.
    pub fn with_family(mut self, family: u8) -> Self {
        self.family = family;
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

/// FIB rule attributes (FRA_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
pub enum FraAttr {
    Unspec = 0,
    Dst = 1,
    Src = 2,
    Iifname = 3,
    Goto = 4,
    Unused2 = 5,
    Priority = 6,
    Unused3 = 7,
    Unused4 = 8,
    Unused5 = 9,
    Fwmark = 10,
    Flow = 11,
    TunId = 12,
    SuppressIfgroup = 13,
    SuppressPrefixlen = 14,
    Table = 15,
    Fwmask = 16,
    Oifname = 17,
    Pad = 18,
    L3Mdev = 19,
    UidRange = 20,
    Protocol = 21,
    IpProto = 22,
    Sport = 23,
    Dport = 24,
}

impl From<u16> for FraAttr {
    fn from(val: u16) -> Self {
        match val {
            0 => Self::Unspec,
            1 => Self::Dst,
            2 => Self::Src,
            3 => Self::Iifname,
            4 => Self::Goto,
            6 => Self::Priority,
            10 => Self::Fwmark,
            11 => Self::Flow,
            12 => Self::TunId,
            13 => Self::SuppressIfgroup,
            14 => Self::SuppressPrefixlen,
            15 => Self::Table,
            16 => Self::Fwmask,
            17 => Self::Oifname,
            18 => Self::Pad,
            19 => Self::L3Mdev,
            20 => Self::UidRange,
            21 => Self::Protocol,
            22 => Self::IpProto,
            23 => Self::Sport,
            24 => Self::Dport,
            _ => Self::Unspec,
        }
    }
}

/// FIB rule actions (FR_ACT_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum FibRuleAction {
    Unspec = 0,
    ToTbl = 1,
    Goto = 2,
    Nop = 3,
    Res3 = 4,
    Res4 = 5,
    Blackhole = 6,
    Unreachable = 7,
    Prohibit = 8,
}

impl From<u8> for FibRuleAction {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::Unspec,
            1 => Self::ToTbl,
            2 => Self::Goto,
            3 => Self::Nop,
            6 => Self::Blackhole,
            7 => Self::Unreachable,
            8 => Self::Prohibit,
            _ => Self::Unspec,
        }
    }
}

impl FibRuleAction {
    /// Get the name of this action.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unspec => "unspec",
            Self::ToTbl => "lookup",
            Self::Goto => "goto",
            Self::Nop => "nop",
            Self::Res3 => "res3",
            Self::Res4 => "res4",
            Self::Blackhole => "blackhole",
            Self::Unreachable => "unreachable",
            Self::Prohibit => "prohibit",
        }
    }
}

/// UID range for FRA_UID_RANGE.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, Immutable, KnownLayout)]
pub struct FibRuleUidRange {
    pub start: u32,
    pub end: u32,
}

impl FibRuleUidRange {
    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }
}

/// Port range for FRA_SPORT/FRA_DPORT.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, Immutable, KnownLayout)]
pub struct FibRulePortRange {
    pub start: u16,
    pub end: u16,
}

impl FibRulePortRange {
    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }
}
