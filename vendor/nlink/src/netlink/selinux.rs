//! SELinux implementation for `Connection<SELinux>`.
//!
//! This module provides methods for receiving SELinux event notifications
//! via the NETLINK_SELINUX protocol.
//!
//! # Overview
//!
//! NETLINK_SELINUX provides notifications when:
//! - SELinux enforcement mode changes (setenforce 0/1)
//! - A new SELinux policy is loaded
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, SELinux};
//! use nlink::netlink::selinux::SELinuxEvent;
//!
//! let conn = Connection::<SELinux>::new()?;
//!
//! // Receive SELinux events
//! loop {
//!     let event = conn.recv().await?;
//!     match event {
//!         SELinuxEvent::SetEnforce { enforcing } => {
//!             println!("SELinux mode changed: {}",
//!                 if enforcing { "enforcing" } else { "permissive" });
//!         }
//!         SELinuxEvent::PolicyLoad { seqno } => {
//!             println!("Policy loaded, sequence: {}", seqno);
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::{
    connection::Connection,
    error::{Error, Result},
    protocol::{ProtocolState, SELinux},
    socket::NetlinkSocket,
};

// Netlink header size
const NLMSG_HDRLEN: usize = 16;

// SELinux netlink message types (from linux/selinux_netlink.h)
/// Policy enforcement status change.
const SELNL_MSG_SETENFORCE: u16 = 0x10;
/// Policy was (re)loaded.
const SELNL_MSG_POLICYLOAD: u16 = 0x11;

// SELinux netlink multicast group
/// AVC decisions group (receives all events).
const SELNLGRP_AVC: u32 = 1;

/// SELinux setenforce message payload.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct SelnlMsgSetenforce {
    /// 1 = enforcing, 0 = permissive.
    pub val: i32,
}

/// SELinux policyload message payload.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct SelnlMsgPolicyload {
    /// Policy sequence number.
    pub seqno: u32,
}

/// SELinux event received from the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SELinuxEvent {
    /// SELinux enforcement mode changed.
    SetEnforce {
        /// True if now in enforcing mode, false if permissive.
        enforcing: bool,
    },
    /// SELinux policy was loaded.
    PolicyLoad {
        /// Policy sequence number.
        seqno: u32,
    },
}

#[nlink_macros::send_futures]
impl Connection<SELinux> {
    /// Create a new SELinux connection.
    ///
    /// This creates a netlink socket bound to the SELNLGRP_AVC multicast group
    /// to receive SELinux event notifications.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, SELinux};
    ///
    /// let conn = Connection::<SELinux>::new()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Result<Self> {
        let socket = NetlinkSocket::new(SELinux::PROTOCOL)?;

        // Bind to the AVC multicast group to receive events
        socket.add_membership(SELNLGRP_AVC)?;

        Ok(Self::from_parts(socket, SELinux))
    }

    /// Receive the next SELinux event.
    ///
    /// This method blocks until an event is received from the kernel.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, SELinux};
    /// use nlink::netlink::selinux::SELinuxEvent;
    ///
    /// let conn = Connection::<SELinux>::new()?;
    ///
    /// loop {
    ///     match conn.recv().await? {
    ///         SELinuxEvent::SetEnforce { enforcing } => {
    ///             if enforcing {
    ///                 println!("SELinux now enforcing");
    ///             } else {
    ///                 println!("SELinux now permissive");
    ///             }
    ///         }
    ///         SELinuxEvent::PolicyLoad { seqno } => {
    ///             println!("New policy loaded (seqno: {})", seqno);
    ///         }
    ///         _ => {}
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "recv"))]
    pub async fn recv(&self) -> Result<SELinuxEvent> {
        loop {
            let data = self.socket().recv_msg().await?;

            if data.len() < NLMSG_HDRLEN {
                continue; // Invalid message, skip
            }

            let nlmsg_type = u16::from_ne_bytes([data[4], data[5]]);
            let payload = &data[NLMSG_HDRLEN..];

            match nlmsg_type {
                SELNL_MSG_SETENFORCE => {
                    if payload.len() < std::mem::size_of::<SelnlMsgSetenforce>() {
                        return Err(Error::invalid_message("setenforce payload too short"));
                    }

                    let (msg, _) = SelnlMsgSetenforce::ref_from_prefix(payload)
                        .map_err(|_| Error::invalid_message("failed to parse setenforce"))?;

                    return Ok(SELinuxEvent::SetEnforce {
                        enforcing: msg.val != 0,
                    });
                }
                SELNL_MSG_POLICYLOAD => {
                    if payload.len() < std::mem::size_of::<SelnlMsgPolicyload>() {
                        return Err(Error::invalid_message("policyload payload too short"));
                    }

                    let (msg, _) = SelnlMsgPolicyload::ref_from_prefix(payload)
                        .map_err(|_| Error::invalid_message("failed to parse policyload"))?;

                    return Ok(SELinuxEvent::PolicyLoad { seqno: msg.seqno });
                }
                _ => {
                    // Unknown message type, skip
                    continue;
                }
            }
        }
    }

    /// Check if SELinux is available on this system.
    ///
    /// This checks if the SELinux filesystem is mounted.
    pub fn is_available() -> bool {
        std::path::Path::new("/sys/fs/selinux").exists()
    }

    /// Get the current SELinux enforcement mode.
    ///
    /// Returns `true` if enforcing, `false` if permissive,
    /// or an error if SELinux is not available.
    pub fn get_enforce() -> Result<bool> {
        let content = std::fs::read_to_string("/sys/fs/selinux/enforce")?;

        Ok(content.trim() == "1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setenforce_size() {
        assert_eq!(std::mem::size_of::<SelnlMsgSetenforce>(), 4);
    }

    #[test]
    fn policyload_size() {
        assert_eq!(std::mem::size_of::<SelnlMsgPolicyload>(), 4);
    }

    #[test]
    fn event_eq() {
        assert_eq!(
            SELinuxEvent::SetEnforce { enforcing: true },
            SELinuxEvent::SetEnforce { enforcing: true }
        );

        assert_ne!(
            SELinuxEvent::SetEnforce { enforcing: true },
            SELinuxEvent::SetEnforce { enforcing: false }
        );

        assert_eq!(
            SELinuxEvent::PolicyLoad { seqno: 42 },
            SELinuxEvent::PolicyLoad { seqno: 42 }
        );
    }
}
