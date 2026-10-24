//! Address message types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::netlink::error::{Error, Result};

/// Interface address message (struct ifaddrmsg).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct IfAddrMsg {
    /// Address family (AF_INET, AF_INET6).
    pub ifa_family: u8,
    /// Prefix length.
    pub ifa_prefixlen: u8,
    /// Address flags (IFA_F_*).
    pub ifa_flags: u8,
    /// Address scope.
    pub ifa_scope: u8,
    /// Interface index.
    pub ifa_index: u32,
}

impl IfAddrMsg {
    /// Size of this structure.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create a new address message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the address family.
    pub fn with_family(mut self, family: u8) -> Self {
        self.ifa_family = family;
        self
    }

    /// Set the prefix length.
    pub fn with_prefixlen(mut self, prefixlen: u8) -> Self {
        self.ifa_prefixlen = prefixlen;
        self
    }

    /// Set the interface index.
    pub fn with_index(mut self, index: u32) -> Self {
        self.ifa_index = index;
        self
    }

    /// Set the scope.
    pub fn with_scope(mut self, scope: u8) -> Self {
        self.ifa_scope = scope;
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

/// Interface address attributes (IFA_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
pub enum IfaAttr {
    Unspec = 0,
    Address = 1,
    Local = 2,
    Label = 3,
    Broadcast = 4,
    Anycast = 5,
    Cacheinfo = 6,
    Multicast = 7,
    Flags = 8,
    RtPriority = 9,
    TargetNetnsid = 10,
    Proto = 11,
}

impl From<u16> for IfaAttr {
    fn from(val: u16) -> Self {
        match val {
            0 => Self::Unspec,
            1 => Self::Address,
            2 => Self::Local,
            3 => Self::Label,
            4 => Self::Broadcast,
            5 => Self::Anycast,
            6 => Self::Cacheinfo,
            7 => Self::Multicast,
            8 => Self::Flags,
            9 => Self::RtPriority,
            10 => Self::TargetNetnsid,
            11 => Self::Proto,
            _ => Self::Unspec,
        }
    }
}

/// Address flags (IFA_F_*).
pub mod ifa_flags {
    pub const SECONDARY: u32 = 0x01;
    pub const TEMPORARY: u32 = 0x01; // Alias for SECONDARY
    pub const NODAD: u32 = 0x02;
    pub const OPTIMISTIC: u32 = 0x04;
    pub const DADFAILED: u32 = 0x08;
    pub const HOMEADDRESS: u32 = 0x10;
    pub const DEPRECATED: u32 = 0x20;
    pub const TENTATIVE: u32 = 0x40;
    pub const PERMANENT: u32 = 0x80;
    pub const MANAGETEMPADDR: u32 = 0x100;
    pub const NOPREFIXROUTE: u32 = 0x200;
    pub const MCAUTOJOIN: u32 = 0x400;
    pub const STABLE_PRIVACY: u32 = 0x800;
}

/// Address scope values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum Scope {
    Universe = 0,
    Site = 200,
    Link = 253,
    Host = 254,
    Nowhere = 255,
}

impl From<u8> for Scope {
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

impl Scope {
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

/// Address cache info (struct ifa_cacheinfo).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, Immutable, KnownLayout)]
pub struct IfaCacheinfo {
    pub ifa_prefered: u32,
    pub ifa_valid: u32,
    pub cstamp: u32,
    pub tstamp: u32,
}

impl IfaCacheinfo {
    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }
}
