//! Namespace ID message parsing.
//!
//! Parses RTM_NEWNSID and RTM_DELNSID netlink messages.

use crate::netlink::{attr::AttrIter, types::nsid::netnsa};

/// Parsed namespace ID message from RTM_NEWNSID/RTM_DELNSID.
///
/// Fields are `pub(crate)`; consumers read via the per-field
/// accessor methods. The struct is `#[non_exhaustive]` so the
/// kernel can grow new `NETNSA_*` attribute fields without it
/// being a breaking change.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct NsIdMessage {
    /// Address family (usually AF_UNSPEC = 0)
    pub(crate) family: u8,
    /// Namespace ID
    pub(crate) nsid: Option<u32>,
    /// Process ID that owns/triggered the namespace
    pub(crate) pid: Option<u32>,
    /// File descriptor (for fd-based references)
    pub(crate) fd: Option<i32>,
    /// Target namespace ID (for queries)
    pub(crate) target_nsid: Option<u32>,
    /// Current namespace ID
    pub(crate) current_nsid: Option<u32>,
}

impl NsIdMessage {
    /// Address family byte (typically `AF_UNSPEC = 0`).
    pub fn family(&self) -> u8 {
        self.family
    }

    /// Namespace ID (`NETNSA_NSID`), if reported.
    pub fn nsid(&self) -> Option<u32> {
        self.nsid
    }

    /// Owning / triggering process ID (`NETNSA_PID`), if reported.
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// File descriptor reference (`NETNSA_FD`), if reported.
    pub fn fd(&self) -> Option<i32> {
        self.fd
    }

    /// Target namespace ID (`NETNSA_TARGET_NSID`), if reported.
    pub fn target_nsid(&self) -> Option<u32> {
        self.target_nsid
    }

    /// Current namespace ID (`NETNSA_CURRENT_NSID`), if reported.
    pub fn current_nsid(&self) -> Option<u32> {
        self.current_nsid
    }

    /// Parse a namespace ID message from raw bytes.
    ///
    /// The input should be the payload after the netlink header (16 bytes).
    /// Format: rtgenmsg (1 byte family + 3 padding) + attributes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        // Parse rtgenmsg header (1 byte family, 3 bytes padding)
        let family = data[0];

        // Attributes start at offset 4 (after rtgenmsg + padding)
        let attr_data = data.get(4..)?;

        let mut msg = NsIdMessage {
            family,
            ..Default::default()
        };

        // Parse attributes using existing AttrIter
        for (attr_type, payload) in AttrIter::new(attr_data) {
            match attr_type {
                x if x == netnsa::NSID && payload.len() >= 4 => {
                    msg.nsid = Some(u32::from_ne_bytes(payload[..4].try_into().ok()?));
                }
                x if x == netnsa::PID && payload.len() >= 4 => {
                    msg.pid = Some(u32::from_ne_bytes(payload[..4].try_into().ok()?));
                }
                x if x == netnsa::FD && payload.len() >= 4 => {
                    msg.fd = Some(i32::from_ne_bytes(payload[..4].try_into().ok()?));
                }
                x if x == netnsa::TARGET_NSID && payload.len() >= 4 => {
                    msg.target_nsid = Some(u32::from_ne_bytes(payload[..4].try_into().ok()?));
                }
                x if x == netnsa::CURRENT_NSID && payload.len() >= 4 => {
                    msg.current_nsid = Some(u32::from_ne_bytes(payload[..4].try_into().ok()?));
                }
                _ => {}
            }
        }

        Some(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nsid_message_parsing() {
        // rtgenmsg (1 byte family + 3 padding) + NETNSA_NSID attribute
        let data = [
            0x00, 0x00, 0x00, 0x00, // rtgenmsg: family=0, padding
            0x08, 0x00, // attr len=8
            0x01, 0x00, // attr type=NETNSA_NSID
            0x42, 0x00, 0x00, 0x00, // nsid=66
        ];

        let msg = NsIdMessage::parse(&data).unwrap();
        assert_eq!(msg.family(), 0);
        assert_eq!(msg.nsid(), Some(66));
        assert_eq!(msg.pid(), None);
    }

    #[test]
    fn test_nsid_message_with_pid() {
        let data = [
            0x00, 0x00, 0x00, 0x00, // rtgenmsg
            0x08, 0x00, 0x01, 0x00, // NETNSA_NSID
            0x01, 0x00, 0x00, 0x00, // nsid=1
            0x08, 0x00, 0x02, 0x00, // NETNSA_PID
            0xe8, 0x03, 0x00, 0x00, // pid=1000
        ];

        let msg = NsIdMessage::parse(&data).unwrap();
        assert_eq!(msg.nsid(), Some(1));
        assert_eq!(msg.pid(), Some(1000));
    }

    #[test]
    fn test_empty_message() {
        assert!(NsIdMessage::parse(&[]).is_none());
    }

    #[test]
    fn test_minimal_message() {
        // Just the rtgenmsg header, no attributes
        let data = [0x00, 0x00, 0x00, 0x00];
        let msg = NsIdMessage::parse(&data).unwrap();
        assert_eq!(msg.family(), 0);
        assert_eq!(msg.nsid(), None);
    }
}
