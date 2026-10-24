//! Generic Netlink family information.
//!
//! This module provides the `FamilyInfo` struct which contains information
//! about a Generic Netlink family resolved from the kernel.

use std::collections::HashMap;

/// Information about a Generic Netlink family.
///
/// This struct contains the information returned by the kernel when
/// resolving a family by name via `CTRL_CMD_GETFAMILY`.
#[derive(Debug, Clone)]
pub struct FamilyInfo {
    /// Dynamically assigned family ID (used as nlmsg_type).
    pub id: u16,
    /// Family version.
    pub version: u8,
    /// Header size (additional bytes after genlmsghdr).
    pub hdr_size: u32,
    /// Maximum attribute number.
    pub max_attr: u32,
    /// Multicast groups: name -> group ID.
    pub mcast_groups: HashMap<String, u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_family_info_default() {
        let info = FamilyInfo {
            id: 21,
            version: 1,
            hdr_size: 0,
            max_attr: 10,
            mcast_groups: HashMap::new(),
        };
        assert_eq!(info.id, 21);
        assert_eq!(info.version, 1);
    }
}
