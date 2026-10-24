//! MPLS structures for netlink.
//!
//! This module provides the kernel-level structures for MPLS routing.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// MPLS label entry (struct mpls_label).
///
/// The entry is a big-endian 32-bit value with:
/// - Bits 31-12: Label (20 bits)
/// - Bits 11-9: Traffic Class (3 bits)
/// - Bit 8: Bottom-of-Stack (S bit)
/// - Bits 7-0: TTL (8 bits)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct MplsLabelEntry {
    /// Big-endian encoded label entry.
    pub entry: u32,
}

impl MplsLabelEntry {
    /// Size of this structure.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create a new label entry (not bottom of stack).
    ///
    /// Creates an entry with TC=0, S=0, TTL=0.
    pub fn new(label: u32) -> Self {
        Self {
            entry: ((label & 0xFFFFF) << 12).to_be(),
        }
    }

    /// Create a bottom-of-stack entry with TTL.
    ///
    /// Creates an entry with TC=0, S=1, and specified TTL.
    pub fn bottom(label: u32, ttl: u8) -> Self {
        let entry = ((label & 0xFFFFF) << 12) | (1 << 8) | (ttl as u32);
        Self {
            entry: entry.to_be(),
        }
    }

    /// Create a label entry with all fields.
    pub fn with_fields(label: u32, tc: u8, bos: bool, ttl: u8) -> Self {
        let entry = ((label & 0xFFFFF) << 12)
            | (((tc & 0x7) as u32) << 9)
            | (if bos { 1 << 8 } else { 0 })
            | (ttl as u32);
        Self {
            entry: entry.to_be(),
        }
    }

    /// Get the label value (20 bits).
    pub fn label(&self) -> u32 {
        (u32::from_be(self.entry) >> 12) & 0xFFFFF
    }

    /// Get the traffic class (3 bits).
    pub fn tc(&self) -> u8 {
        ((u32::from_be(self.entry) >> 9) & 0x7) as u8
    }

    /// Check if this is the bottom of stack.
    pub fn is_bos(&self) -> bool {
        (u32::from_be(self.entry) & 0x100) != 0
    }

    /// Get the TTL value.
    pub fn ttl(&self) -> u8 {
        (u32::from_be(self.entry) & 0xFF) as u8
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

/// RTA_VIA structure for MPLS routes.
///
/// Used to specify the next hop for MPLS routes with address family.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct RtVia {
    /// Address family (AF_INET or AF_INET6).
    pub rtvia_family: u16,
    // Address follows (variable length)
}

impl RtVia {
    /// Size of the header (without address).
    pub const HEADER_SIZE: usize = std::mem::size_of::<Self>();

    /// Create for IPv4.
    pub fn ipv4() -> Self {
        Self {
            rtvia_family: libc::AF_INET as u16,
        }
    }

    /// Create for IPv6.
    pub fn ipv6() -> Self {
        Self {
            rtvia_family: libc::AF_INET6 as u16,
        }
    }

    /// Convert to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }
}

/// MPLS tunnel attributes (MPLS_IPTUNNEL_*).
pub mod mpls_tunnel {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Destination label stack.
    pub const DST: u16 = 1;
    /// TTL propagation.
    pub const TTL: u16 = 2;
}

/// Lightweight tunnel encapsulation types (LWTUNNEL_ENCAP_*).
pub mod lwtunnel_encap {
    /// No encapsulation.
    pub const NONE: u16 = 0;
    /// MPLS encapsulation.
    pub const MPLS: u16 = 1;
    /// IP encapsulation.
    pub const IP: u16 = 2;
    /// ILA encapsulation.
    pub const ILA: u16 = 3;
    /// IPv6 encapsulation.
    pub const IP6: u16 = 4;
    /// Segment Routing IPv6.
    pub const SEG6: u16 = 5;
    /// BPF encapsulation.
    pub const BPF: u16 = 6;
    /// Segment Routing IPv6 local.
    pub const SEG6_LOCAL: u16 = 7;
    /// RPL encapsulation.
    pub const RPL: u16 = 8;
    /// IOAM IPv6.
    pub const IOAM6: u16 = 9;
    /// XFRM encapsulation.
    pub const XFRM: u16 = 10;
}

/// Special MPLS label values.
pub mod mpls_label {
    /// IPv4 Explicit NULL.
    pub const IPV4_EXPLICIT_NULL: u32 = 0;
    /// Router Alert.
    pub const ROUTER_ALERT: u32 = 1;
    /// IPv6 Explicit NULL.
    pub const IPV6_EXPLICIT_NULL: u32 = 2;
    /// Implicit NULL (penultimate hop popping).
    pub const IMPLICIT_NULL: u32 = 3;
    /// Entropy Label Indicator.
    pub const ENTROPY_INDICATOR: u32 = 7;
    /// Generic Associated Channel.
    pub const GAL: u32 = 13;
    /// OAM Alert.
    pub const OAM_ALERT: u32 = 14;
    /// Extension.
    pub const EXTENSION: u32 = 15;
    /// Maximum valid label value.
    pub const MAX: u32 = 0xFFFFF; // 2^20 - 1 = 1048575
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpls_label_entry_size() {
        assert_eq!(MplsLabelEntry::SIZE, 4);
    }

    #[test]
    fn test_mpls_label_entry_new() {
        let entry = MplsLabelEntry::new(100);
        assert_eq!(entry.label(), 100);
        assert_eq!(entry.tc(), 0);
        assert!(!entry.is_bos());
        assert_eq!(entry.ttl(), 0);
    }

    #[test]
    fn test_mpls_label_entry_bottom() {
        let entry = MplsLabelEntry::bottom(200, 64);
        assert_eq!(entry.label(), 200);
        assert_eq!(entry.tc(), 0);
        assert!(entry.is_bos());
        assert_eq!(entry.ttl(), 64);
    }

    #[test]
    fn test_mpls_label_entry_with_fields() {
        let entry = MplsLabelEntry::with_fields(300, 5, true, 128);
        assert_eq!(entry.label(), 300);
        assert_eq!(entry.tc(), 5);
        assert!(entry.is_bos());
        assert_eq!(entry.ttl(), 128);
    }

    #[test]
    fn test_mpls_label_entry_max_label() {
        let entry = MplsLabelEntry::new(mpls_label::MAX);
        assert_eq!(entry.label(), mpls_label::MAX);
    }

    #[test]
    fn test_rtvia_size() {
        assert_eq!(RtVia::HEADER_SIZE, 2);
    }

    // Parser-robustness rule 1 (accept-larger-than-expected on fixed
    // structs). These pin `from_bytes` to `ref_from_prefix`; they fail
    // if it regresses to an exact-size (`len() == SIZE`) guard.
    #[test]
    fn mpls_label_entry_from_bytes_accepts_trailing_bytes() {
        let entry = MplsLabelEntry::new(12345);
        let mut buf = entry.as_bytes().to_vec();
        buf.extend_from_slice(&[0xAB; 8]); // bytes a future kernel may append
        let parsed = MplsLabelEntry::from_bytes(&buf).expect("prefix parse");
        assert_eq!(parsed.label(), 12345);
    }

    #[test]
    fn mpls_label_entry_from_bytes_rejects_undersized() {
        let entry = MplsLabelEntry::new(1);
        assert!(
            MplsLabelEntry::from_bytes(&entry.as_bytes()[..MplsLabelEntry::SIZE - 1]).is_none()
        );
        assert!(MplsLabelEntry::from_bytes(&[]).is_none());
        // Arbitrary short inputs never panic.
        for len in 0..MplsLabelEntry::SIZE {
            let _ = MplsLabelEntry::from_bytes(&vec![0xCD; len]);
        }
    }
}
