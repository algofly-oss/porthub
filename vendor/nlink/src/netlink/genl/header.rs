//! Generic Netlink message header.
//!
//! GENL messages have an additional header after the standard netlink header:
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │ nlmsghdr (16 bytes)                     │
//! │   nlmsg_len, nlmsg_type (family_id),    │
//! │   nlmsg_flags, nlmsg_seq, nlmsg_pid     │
//! ├─────────────────────────────────────────┤
//! │ genlmsghdr (4 bytes)                    │
//! │   cmd (u8), version (u8), reserved (u16)│
//! ├─────────────────────────────────────────┤
//! │ Attributes (TLV format)                 │
//! └─────────────────────────────────────────┘
//! ```

use std::mem;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Generic Netlink message header.
///
/// This header immediately follows the standard netlink header in GENL messages.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct GenlMsgHdr {
    /// Command identifier (family-specific)
    pub cmd: u8,
    /// Interface version
    pub version: u8,
    /// Reserved for future use
    pub reserved: u16,
}

/// Size of the GENL header in bytes.
pub const GENL_HDRLEN: usize = mem::size_of::<GenlMsgHdr>();

impl GenlMsgHdr {
    /// Create a new GENL header with the given command and version.
    #[inline]
    pub const fn new(cmd: u8, version: u8) -> Self {
        Self {
            cmd,
            version,
            reserved: 0,
        }
    }

    /// Create a header from a byte slice.
    ///
    /// Returns `None` if the slice is too short.
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }

    /// Get the header as a byte slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genl_header_size() {
        assert_eq!(GENL_HDRLEN, 4);
    }

    #[test]
    fn test_genl_header_new() {
        let hdr = GenlMsgHdr::new(1, 2);
        assert_eq!(hdr.cmd, 1);
        assert_eq!(hdr.version, 2);
        assert_eq!(hdr.reserved, 0);
    }

    #[test]
    fn test_genl_header_from_bytes() {
        let data = [0x03, 0x01, 0x00, 0x00]; // cmd=3, version=1
        let hdr = GenlMsgHdr::from_bytes(&data).unwrap();
        assert_eq!(hdr.cmd, 3);
        assert_eq!(hdr.version, 1);
    }

    #[test]
    fn test_genl_header_from_bytes_too_short() {
        let data = [0x03, 0x01, 0x00]; // Only 3 bytes
        assert!(GenlMsgHdr::from_bytes(&data).is_none());
    }

    #[test]
    fn test_genl_header_roundtrip() {
        let hdr = GenlMsgHdr::new(5, 2);
        let bytes = hdr.as_bytes();
        let parsed = GenlMsgHdr::from_bytes(bytes).unwrap();
        assert_eq!(parsed.cmd, 5);
        assert_eq!(parsed.version, 2);
    }
}
