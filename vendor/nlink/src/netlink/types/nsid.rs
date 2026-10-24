//! Namespace ID netlink message types and constants.
//!
//! These constants and types are used for RTM_NEWNSID, RTM_DELNSID, and RTM_GETNSID
//! messages which track network namespace IDs.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// RTM_NEWNSID - New namespace ID notification
pub const RTM_NEWNSID: u16 = 88;
/// RTM_DELNSID - Delete namespace ID notification
pub const RTM_DELNSID: u16 = 89;
/// RTM_GETNSID - Get namespace ID request
pub const RTM_GETNSID: u16 = 90;

/// Netlink namespace ID message attributes (NETNSA_*)
pub mod netnsa {
    /// Unspec (unused)
    pub const UNSPEC: u16 = 0;
    /// Namespace ID (u32)
    pub const NSID: u16 = 1;
    /// Process ID (u32)
    pub const PID: u16 = 2;
    /// File descriptor (u32)
    pub const FD: u16 = 3;
    /// Target namespace ID for queries (u32)
    pub const TARGET_NSID: u16 = 4;
    /// Current namespace ID (u32)
    pub const CURRENT_NSID: u16 = 5;
}

/// Multicast group for namespace events.
///
/// Note: Reliable multicast for NSID events requires Linux 4.9+.
/// On older kernels (3.8-4.8), events may be unreliable.
pub const RTNLGRP_NSID: u32 = 28;

/// rtgenmsg structure for namespace messages.
///
/// This is the header used for RTM_*NSID messages.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct RtGenMsg {
    /// Address family (usually AF_UNSPEC = 0)
    pub rtgen_family: u8,
}

impl RtGenMsg {
    /// Create a new rtgenmsg with AF_UNSPEC family.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a specific address family.
    pub fn with_family(family: u8) -> Self {
        Self {
            rtgen_family: family,
        }
    }

    /// Convert to bytes for netlink message building.
    pub fn as_bytes(&self) -> &[u8] {
        // rtgenmsg is 1 byte
        <Self as IntoBytes>::as_bytes(self)
    }

    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }

    /// Size of this struct for message building (includes padding to 4 bytes).
    pub const fn padded_size() -> usize {
        4 // 1 byte + 3 bytes padding
    }
}
