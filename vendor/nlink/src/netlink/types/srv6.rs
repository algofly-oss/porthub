//! SRv6 (Segment Routing over IPv6) structures for netlink.
//!
//! This module provides the kernel-level structures for SRv6 routing.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Segment Routing Header (SRH).
///
/// This is the IPv6 extension header for segment routing.
/// RFC 8754 defines the format.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct Ipv6SrHdr {
    /// Next header type.
    pub nexthdr: u8,
    /// Header length in 8-byte units (not including first 8 bytes).
    pub hdrlen: u8,
    /// Routing type (must be 4 for SRH).
    pub sr_type: u8,
    /// Number of segments remaining.
    pub segments_left: u8,
    /// Index of the first segment (last segment in memory order).
    pub first_segment: u8,
    /// Flags.
    pub flags: u8,
    /// Tag for grouping packets.
    pub tag: u16,
    // Followed by segments array: [Ipv6Addr; first_segment + 1]
}

impl Ipv6SrHdr {
    /// Size of the header (not including segments).
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// SRH routing type value.
    pub const SR_TYPE: u8 = 4;

    /// Create a new SRH header.
    ///
    /// # Arguments
    ///
    /// * `num_segments` - Number of segments in the list
    pub fn new(num_segments: u8) -> Self {
        // hdrlen = (8 + 16*n - 8) / 8 = 2*n for n segments
        let hdrlen = num_segments.saturating_mul(2);
        Self {
            nexthdr: 0, // Will be set based on encapsulated protocol
            hdrlen,
            sr_type: Self::SR_TYPE,
            segments_left: num_segments.saturating_sub(1),
            first_segment: num_segments.saturating_sub(1),
            flags: 0,
            tag: 0,
        }
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

/// SRv6 encapsulation modes.
pub mod seg6_mode {
    /// Inline mode: insert SRH into existing IPv6 packet.
    pub const INLINE: u32 = 0;
    /// Encap mode: encapsulate in new IPv6 header with SRH.
    pub const ENCAP: u32 = 1;
    /// L2 encap: encapsulate L2 frame.
    pub const L2ENCAP: u32 = 2;
    /// Encap with reduced SRH (first segment is destination).
    pub const ENCAP_RED: u32 = 3;
    /// L2 encap with reduced SRH.
    pub const L2ENCAP_RED: u32 = 4;
}

/// Seg6 iptunnel attributes (SEG6_IPTUNNEL_*).
pub mod seg6_iptunnel {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Segment Routing Header.
    pub const SRH: u16 = 1;
}

/// Seg6 local action types (SEG6_LOCAL_ACTION_*).
pub mod seg6_local_action {
    /// Unknown action.
    pub const UNSPEC: u32 = 0;
    /// End: pop and continue.
    pub const END: u32 = 1;
    /// End.X: pop and forward to nexthop.
    pub const END_X: u32 = 2;
    /// End.T: pop and lookup in table.
    pub const END_T: u32 = 3;
    /// End.DX2: decap and forward L2 frame.
    pub const END_DX2: u32 = 4;
    /// End.DX6: decap and forward IPv6 packet.
    pub const END_DX6: u32 = 5;
    /// End.DX4: decap and forward IPv4 packet.
    pub const END_DX4: u32 = 6;
    /// End.DT6: decap and lookup IPv6 in table.
    pub const END_DT6: u32 = 7;
    /// End.DT4: decap and lookup IPv4 in table.
    pub const END_DT4: u32 = 8;
    /// End.B6: insert SRH and forward.
    pub const END_B6: u32 = 9;
    /// End.B6.Encaps: encap with new header and SRH.
    pub const END_B6_ENCAP: u32 = 10;
    /// End.BM: forward to binding SID.
    pub const END_BM: u32 = 11;
    /// End.S: source address lookup.
    pub const END_S: u32 = 12;
    /// End.AS: source address lookup with SRH.
    pub const END_AS: u32 = 13;
    /// End.AM: masquerade.
    pub const END_AM: u32 = 14;
    /// End.BPF: BPF program.
    pub const END_BPF: u32 = 15;
    /// End.DT46: decap and lookup IPv4 or IPv6 in table.
    pub const END_DT46: u32 = 16;
}

/// Seg6 local attributes (SEG6_LOCAL_*).
pub mod seg6_local {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Action type.
    pub const ACTION: u16 = 1;
    /// SRH for B6 actions.
    pub const SRH: u16 = 2;
    /// Table for End.T/End.DT*.
    pub const TABLE: u16 = 3;
    /// IPv4 nexthop for End.DX4.
    pub const NH4: u16 = 4;
    /// IPv6 nexthop for End.X/DX6.
    pub const NH6: u16 = 5;
    /// Input interface.
    pub const IIF: u16 = 6;
    /// Output interface.
    pub const OIF: u16 = 7;
    /// BPF program.
    pub const BPF: u16 = 8;
    /// VRF table.
    pub const VRFTABLE: u16 = 9;
    /// Statistics counters.
    pub const COUNTERS: u16 = 10;
    /// SRv6 flavors.
    pub const FLAVORS: u16 = 11;
}

/// SRv6 flavors (SEG6_LOCAL_FLV_*).
pub mod seg6_local_flv {
    /// Unknown flavor.
    pub const UNSPEC: u16 = 0;
    /// Flavor operation.
    pub const OPERATION: u16 = 1;
    /// Local carrier block length.
    pub const LCBLOCK_BITS: u16 = 2;
    /// Local carrier node function length.
    pub const LCNODE_FN_BITS: u16 = 3;
}

/// SRv6 flavor operations (bitmask).
// UNVERIFIED — do not "fix" these without reading the kernel source (#265).
//
// `seg6_local.h` enumerates the flavor operations as ordinals:
// UNSPEC=0, PSP=1, USP=2, USD=3, NEXT_CSID=4. The values below are shifted one
// bit low *if* the `SEG6_LOCAL_FLV_OPERATION` payload is a bitmask of
// `BIT(ordinal)` — in which case PSP is `1 << 1`, not `1 << 0`, because bit 0
// belongs to UNSPEC.
//
// That premise is strongly implied (nlink stores a bitmask, and the header
// gives no explicit bit values) but the `SEG6_F_LOCAL_FLV_OP` macro that would
// settle it lives in the kernel tree, not in the UAPI headers, so it could not
// be confirmed here. Left as-is deliberately: changing a wire value on
// inference risks breaking working code to fix a bug that may not exist.
//
// The audit gate cannot cover this module either — nlink stores `1 << N` where
// the kernel stores `N`, so the representations differ by design and a value
// comparison is meaningless.
pub mod seg6_local_flv_op {
    /// PSP (Penultimate Segment Pop).
    pub const PSP: u32 = 1 << 0;
    /// USP (Ultimate Segment Pop).
    pub const USP: u32 = 1 << 1;
    /// USD (Ultimate Segment Decapsulation).
    pub const USD: u32 = 1 << 2;
    /// NEXT-C-SID (next compressed SID).
    pub const NEXT_CSID: u32 = 1 << 3;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_sr_hdr_size() {
        assert_eq!(Ipv6SrHdr::SIZE, 8);
    }

    #[test]
    fn test_ipv6_sr_hdr_new() {
        let hdr = Ipv6SrHdr::new(3);
        assert_eq!(hdr.sr_type, 4);
        assert_eq!(hdr.hdrlen, 6); // 2 * 3 segments
        assert_eq!(hdr.segments_left, 2);
        assert_eq!(hdr.first_segment, 2);
    }

    #[test]
    fn test_ipv6_sr_hdr_single_segment() {
        let hdr = Ipv6SrHdr::new(1);
        assert_eq!(hdr.hdrlen, 2);
        assert_eq!(hdr.segments_left, 0);
        assert_eq!(hdr.first_segment, 0);
    }

    // Parser-robustness rule 1 (accept-larger-than-expected on fixed
    // structs). The 8-byte SRH is always followed by the segment list
    // in real packets, so accept-larger is the load-bearing behaviour.
    #[test]
    fn ipv6_sr_hdr_from_bytes_accepts_trailing_segments() {
        let hdr = Ipv6SrHdr::new(3);
        let mut buf = hdr.as_bytes().to_vec();
        buf.extend_from_slice(&[0x11; 48]); // 3 x 16-byte segments follow
        let parsed = Ipv6SrHdr::from_bytes(&buf).expect("prefix parse");
        assert_eq!(parsed.first_segment, hdr.first_segment);
        assert_eq!(parsed.sr_type, hdr.sr_type);
    }

    #[test]
    fn ipv6_sr_hdr_from_bytes_rejects_undersized() {
        let hdr = Ipv6SrHdr::new(1);
        assert!(Ipv6SrHdr::from_bytes(&hdr.as_bytes()[..Ipv6SrHdr::SIZE - 1]).is_none());
        assert!(Ipv6SrHdr::from_bytes(&[]).is_none());
        for len in 0..Ipv6SrHdr::SIZE {
            let _ = Ipv6SrHdr::from_bytes(&vec![0u8; len]);
        }
    }
}
