//! Netlink-based namespace event subscriber.
//!
//! **Deprecated since 0.32.0** (#532): it duplicates `NetworkEvent::NewNsId`
//! and `NetworkEvent::DelNsId`. Subscribe a connection to
//! `RtnetlinkGroup::NsId` and match those instead.
//!
//! Receives RTM_NEWNSID and RTM_DELNSID events from the kernel.
//!
//! # Kernel Version Requirements
//!
//! - Linux 3.8+: Basic RTM_*NSID support
//! - Linux 4.9+: Reliable multicast delivery (recommended)
//!
//! # Limitations
//!
//! NSID events are triggered when namespace IDs are assigned or removed,
//! which doesn't always correspond to named namespace creation via `ip netns add`.
//! For tracking named namespaces, use `NamespaceWatcher` (filesystem-based) instead.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::namespace_events::{NamespaceEventSubscriber, NamespaceNetlinkEvent};
//!
//! let mut subscriber = NamespaceEventSubscriber::new().await?;
//!
//! while let Some(event) = subscriber.recv().await? {
//!     match event {
//!         NamespaceNetlinkEvent::NewNsId { nsid, pid, .. } => {
//!             println!("New namespace ID {} from pid {:?}", nsid, pid);
//!         }
//!         NamespaceNetlinkEvent::DelNsId { nsid } => {
//!             println!("Namespace ID {} removed", nsid);
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```

// The module's own items use each other.
#![allow(deprecated)]

use super::{
    error::Result,
    messages::NsIdMessage,
    socket::{NetlinkSocket, Protocol},
    types::nsid::{RTM_DELNSID, RTM_NEWNSID, RTNLGRP_NSID},
};

/// Namespace-related netlink events.
#[deprecated(
    since = "0.32.0",
    note = "subscribe to `RtnetlinkGroup::NsId` and match `NetworkEvent::{NewNsId, DelNsId}` (#532)"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NamespaceNetlinkEvent {
    /// A new namespace ID was assigned.
    NewNsId {
        /// The namespace ID (local to this netns)
        nsid: u32,
        /// Process ID that triggered this (if available)
        pid: Option<u32>,
        /// File descriptor reference (if available)
        fd: Option<i32>,
    },
    /// A namespace ID was removed.
    DelNsId {
        /// The namespace ID that was removed
        nsid: u32,
    },
}

#[deprecated(
    since = "0.32.0",
    note = "subscribe to `RtnetlinkGroup::NsId` and match `NetworkEvent::{NewNsId, DelNsId}` (#532)"
)]
/// Subscribe to namespace netlink events.
///
/// Listens for RTM_NEWNSID and RTM_DELNSID multicast messages.
pub struct NamespaceEventSubscriber {
    socket: NetlinkSocket,
}

#[nlink_macros::send_futures]
impl NamespaceEventSubscriber {
    /// Create a new subscriber for namespace events.
    ///
    /// Subscribes to the RTNLGRP_NSID multicast group.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Socket creation fails
    /// - Multicast group subscription fails (may require CAP_NET_ADMIN)
    pub async fn new() -> Result<Self> {
        let socket = NetlinkSocket::new(Protocol::Route)?;

        // Subscribe to namespace ID multicast group
        socket.add_membership(RTNLGRP_NSID)?;

        Ok(Self { socket })
    }

    /// Receive the next namespace event.
    ///
    /// Blocks until a namespace event is received or an error occurs.
    /// Returns `Ok(None)` if the socket is closed.
    pub async fn recv(&mut self) -> Result<Option<NamespaceNetlinkEvent>> {
        loop {
            let data = self.socket.recv_msg().await?;
            if data.is_empty() {
                return Ok(None);
            }

            if let Some(event) = self.parse_message(&data) {
                return Ok(Some(event));
            }
            // Not a namespace event, continue waiting
        }
    }

    /// Parse a netlink message into a namespace event.
    fn parse_message(&self, data: &[u8]) -> Option<NamespaceNetlinkEvent> {
        // Netlink header is 16 bytes
        if data.len() < 16 {
            return None;
        }

        let msg_len = u32::from_ne_bytes(data[0..4].try_into().ok()?) as usize;
        let msg_type = u16::from_ne_bytes(data[4..6].try_into().ok()?);

        if msg_len > data.len() || msg_len < 16 {
            return None;
        }

        let payload = &data[16..msg_len];

        match msg_type {
            RTM_NEWNSID => {
                let msg = NsIdMessage::parse(payload)?;
                let nsid = msg.nsid?; // NSID is required
                Some(NamespaceNetlinkEvent::NewNsId {
                    nsid,
                    pid: msg.pid,
                    fd: msg.fd,
                })
            }
            RTM_DELNSID => {
                let msg = NsIdMessage::parse(payload)?;
                let nsid = msg.nsid?;
                Some(NamespaceNetlinkEvent::DelNsId { nsid })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_subscriber_creation() {
        // May require CAP_NET_ADMIN
        let result = NamespaceEventSubscriber::new().await;
        // Don't assert - depends on permissions
        if result.is_err() {
            eprintln!(
                "Subscriber creation failed (may need CAP_NET_ADMIN): {:?}",
                result.err()
            );
        }
    }

    #[test]
    fn test_event_equality() {
        let event1 = NamespaceNetlinkEvent::NewNsId {
            nsid: 1,
            pid: Some(1234),
            fd: None,
        };
        let event2 = NamespaceNetlinkEvent::NewNsId {
            nsid: 1,
            pid: Some(1234),
            fd: None,
        };
        assert_eq!(event1, event2);

        let event3 = NamespaceNetlinkEvent::DelNsId { nsid: 5 };
        let event4 = NamespaceNetlinkEvent::DelNsId { nsid: 5 };
        assert_eq!(event3, event4);
    }
}
