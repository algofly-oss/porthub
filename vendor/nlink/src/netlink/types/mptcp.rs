//! MPTCP (Multipath TCP) kernel constants.
//!
//! These constants match the Linux kernel's MPTCP Path Manager Generic Netlink interface
//! definitions from `include/uapi/linux/mptcp.h`.

/// MPTCP Path Manager GENL commands.
///
/// These commands are used to manage MPTCP endpoints and limits.
pub mod mptcp_pm_cmd {
    /// Add an endpoint address.
    pub const ADD_ADDR: u8 = 1;
    /// Delete an endpoint address.
    pub const DEL_ADDR: u8 = 2;
    /// Get endpoint address(es).
    pub const GET_ADDR: u8 = 3;
    /// Flush all endpoint addresses.
    pub const FLUSH_ADDRS: u8 = 4;
    /// Set MPTCP limits.
    pub const SET_LIMITS: u8 = 5;
    /// Get MPTCP limits.
    pub const GET_LIMITS: u8 = 6;
    /// Set endpoint flags.
    pub const SET_FLAGS: u8 = 7;
    /// Announce address to peers.
    pub const ANNOUNCE: u8 = 8;
    /// Remove address announcement.
    pub const REMOVE: u8 = 9;
    /// Create a subflow.
    pub const SUBFLOW_CREATE: u8 = 10;
    /// Destroy a subflow.
    pub const SUBFLOW_DESTROY: u8 = 11;
}

/// MPTCP Path Manager top-level attributes.
pub mod mptcp_pm_attr {
    /// Unspecified attribute.
    pub const UNSPEC: u16 = 0;
    /// Address entry (nested).
    pub const ADDR: u16 = 1;
    /// Max addresses to accept from peers.
    pub const RCV_ADD_ADDRS: u16 = 2;
    /// Max subflows per connection.
    pub const SUBFLOWS: u16 = 3;
    /// Connection token (for per-connection operations).
    pub const TOKEN: u16 = 4;
    /// Local address ID.
    pub const LOC_ID: u16 = 5;
    /// Remote address entry (nested).
    pub const ADDR_REMOTE: u16 = 6;
}

/// MPTCP Path Manager address attributes.
///
/// Used within nested MPTCP_PM_ATTR_ADDR and MPTCP_PM_ATTR_ADDR_REMOTE.
pub mod mptcp_pm_addr_attr {
    /// Unspecified attribute.
    pub const UNSPEC: u16 = 0;
    /// Address family (AF_INET or AF_INET6).
    pub const FAMILY: u16 = 1;
    /// Address ID (u8).
    pub const ID: u16 = 2;
    /// IPv4 address (4 bytes).
    pub const ADDR4: u16 = 3;
    /// IPv6 address (16 bytes).
    pub const ADDR6: u16 = 4;
    /// Port number (u16, network byte order).
    pub const PORT: u16 = 5;
    /// Endpoint flags (u32).
    pub const FLAGS: u16 = 6;
    /// Interface index (u32).
    pub const IF_IDX: u16 = 7;
}

/// MPTCP event/subflow attributes.
///
/// Used for per-connection operations (ANNOUNCE, REMOVE, SUBFLOW_CREATE, SUBFLOW_DESTROY).
/// These attributes are from the mptcp_event_attr enum.
pub mod mptcp_attr {
    /// Connection token (u32) - identifies the MPTCP connection.
    pub const TOKEN: u16 = 1;
    /// Address family (u16).
    pub const FAMILY: u16 = 2;
    /// Local address ID (u8).
    pub const LOC_ID: u16 = 3;
    /// Remote address ID (u8).
    pub const REM_ID: u16 = 4;
    /// Source IPv4 address (4 bytes).
    pub const SADDR4: u16 = 5;
    /// Source IPv6 address (16 bytes).
    pub const SADDR6: u16 = 6;
    /// Destination IPv4 address (4 bytes).
    pub const DADDR4: u16 = 7;
    /// Destination IPv6 address (16 bytes).
    pub const DADDR6: u16 = 8;
    /// Source port (u16, network byte order).
    pub const SPORT: u16 = 9;
    /// Destination port (u16, network byte order).
    pub const DPORT: u16 = 10;
    /// Backup flag (u8).
    pub const BACKUP: u16 = 11;
    /// Error code (i32).
    pub const ERROR: u16 = 12;
    /// Flags (u16).
    pub const FLAGS: u16 = 13;
    /// Timeout (u32).
    pub const TIMEOUT: u16 = 14;
    /// Interface index (u32).
    pub const IF_IDX: u16 = 15;
    /// Reset reason (u32).
    pub const RESET_REASON: u16 = 16;
    /// Reset flags (u32).
    pub const RESET_FLAGS: u16 = 17;
    /// Server side flag (u8).
    pub const SERVER_SIDE: u16 = 18;
}

/// MPTCP endpoint flags.
///
/// These flags control how an endpoint is used for MPTCP connections.
pub mod mptcp_pm_flags {
    /// Announce this address to peers via ADD_ADDR.
    pub const SIGNAL: u32 = 1 << 0;
    /// Use this address for creating new subflows.
    pub const SUBFLOW: u32 = 1 << 1;
    /// Mark as backup path (lower priority).
    pub const BACKUP: u32 = 1 << 2;
    /// Create subflows to all peer addresses (fullmesh).
    pub const FULLMESH: u32 = 1 << 3;
    /// Implicitly created endpoint (by kernel).
    pub const IMPLICIT: u32 = 1 << 4;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_values() {
        assert_eq!(mptcp_pm_cmd::ADD_ADDR, 1);
        assert_eq!(mptcp_pm_cmd::DEL_ADDR, 2);
        assert_eq!(mptcp_pm_cmd::GET_ADDR, 3);
        assert_eq!(mptcp_pm_cmd::FLUSH_ADDRS, 4);
        assert_eq!(mptcp_pm_cmd::SET_LIMITS, 5);
        assert_eq!(mptcp_pm_cmd::GET_LIMITS, 6);
    }

    #[test]
    fn test_flag_values() {
        assert_eq!(mptcp_pm_flags::SIGNAL, 1);
        assert_eq!(mptcp_pm_flags::SUBFLOW, 2);
        assert_eq!(mptcp_pm_flags::BACKUP, 4);
        assert_eq!(mptcp_pm_flags::FULLMESH, 8);
        assert_eq!(mptcp_pm_flags::IMPLICIT, 16);
    }
}
