//! Kernel connector implementation for `Connection<Connector>`.
//!
//! This module provides methods for receiving process events via the
//! NETLINK_CONNECTOR protocol. Process events include fork, exec, exit,
//! and credential changes.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Connector};
//! use nlink::netlink::connector::ProcEvent;
//!
//! // Requires CAP_NET_ADMIN
//! let conn = Connection::<Connector>::new().await?;
//!
//! loop {
//!     match conn.recv().await? {
//!         ProcEvent::Fork { parent_pid, child_pid, .. } => {
//!             println!("fork: {} -> {}", parent_pid, child_pid);
//!         }
//!         ProcEvent::Exec { pid, .. } => {
//!             println!("exec: {}", pid);
//!         }
//!         ProcEvent::Exit { pid, exit_code, .. } => {
//!             println!("exit: {} ({})", pid, exit_code);
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
    error::Result,
    parse::{PResult, parse_string_from_bytes, parse_u32_ne, parse_u64_ne},
    protocol::{Connector, ProtocolState},
    socket::NetlinkSocket,
};

// Connector constants
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;

// Process event types
const PROC_EVENT_NONE: u32 = 0x00000000;
const PROC_EVENT_FORK: u32 = 0x00000001;
const PROC_EVENT_EXEC: u32 = 0x00000002;
const PROC_EVENT_UID: u32 = 0x00000004;
const PROC_EVENT_GID: u32 = 0x00000040;
const PROC_EVENT_SID: u32 = 0x00000080;
const PROC_EVENT_PTRACE: u32 = 0x00000100;
const PROC_EVENT_COMM: u32 = 0x00000200;
const PROC_EVENT_COREDUMP: u32 = 0x40000000;
const PROC_EVENT_EXIT: u32 = 0x80000000;

// Connector message operation
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_CN_MCAST_IGNORE: u32 = 2;

// Netlink header size
const NLMSG_HDRLEN: usize = 16;

/// A process lifecycle event.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ProcEvent {
    /// No event (acknowledgment).
    None,

    /// Process forked.
    Fork {
        /// Parent process ID.
        parent_pid: u32,
        /// Parent thread group ID.
        parent_tgid: u32,
        /// Child process ID.
        child_pid: u32,
        /// Child thread group ID.
        child_tgid: u32,
    },

    /// Process executed a new program.
    Exec {
        /// Process ID.
        pid: u32,
        /// Thread group ID.
        tgid: u32,
    },

    /// Process changed UID.
    Uid {
        /// Process ID.
        pid: u32,
        /// Thread group ID.
        tgid: u32,
        /// Real UID.
        ruid: u32,
        /// Effective UID.
        euid: u32,
    },

    /// Process changed GID.
    Gid {
        /// Process ID.
        pid: u32,
        /// Thread group ID.
        tgid: u32,
        /// Real GID.
        rgid: u32,
        /// Effective GID.
        egid: u32,
    },

    /// Process started a new session.
    Sid {
        /// Process ID.
        pid: u32,
        /// Thread group ID.
        tgid: u32,
    },

    /// Process changed its comm (command name).
    Comm {
        /// Process ID.
        pid: u32,
        /// Thread group ID.
        tgid: u32,
        /// New command name.
        comm: String,
    },

    /// Process is being traced (ptrace).
    Ptrace {
        /// Process ID.
        pid: u32,
        /// Thread group ID.
        tgid: u32,
        /// Tracer process ID.
        tracer_pid: u32,
        /// Tracer thread group ID.
        tracer_tgid: u32,
    },

    /// Process dumped core.
    Coredump {
        /// Process ID.
        pid: u32,
        /// Thread group ID.
        tgid: u32,
        /// Parent process ID.
        parent_pid: u32,
        /// Parent thread group ID.
        parent_tgid: u32,
    },

    /// Process exited.
    Exit {
        /// Process ID.
        pid: u32,
        /// Thread group ID.
        tgid: u32,
        /// Exit code.
        exit_code: u32,
        /// Exit signal.
        exit_signal: u32,
        /// Parent process ID.
        parent_pid: u32,
        /// Parent thread group ID.
        parent_tgid: u32,
    },

    /// Unknown event type.
    Unknown {
        /// Event type code.
        what: u32,
    },
}

impl ProcEvent {
    /// Get the process ID for this event, if applicable.
    pub fn pid(&self) -> Option<u32> {
        match self {
            ProcEvent::Fork { child_pid, .. } => Some(*child_pid),
            ProcEvent::Exec { pid, .. } => Some(*pid),
            ProcEvent::Uid { pid, .. } => Some(*pid),
            ProcEvent::Gid { pid, .. } => Some(*pid),
            ProcEvent::Sid { pid, .. } => Some(*pid),
            ProcEvent::Comm { pid, .. } => Some(*pid),
            ProcEvent::Ptrace { pid, .. } => Some(*pid),
            ProcEvent::Coredump { pid, .. } => Some(*pid),
            ProcEvent::Exit { pid, .. } => Some(*pid),
            ProcEvent::None | ProcEvent::Unknown { .. } => None,
        }
    }

    /// Get the thread group ID for this event, if applicable.
    pub fn tgid(&self) -> Option<u32> {
        match self {
            ProcEvent::Fork { child_tgid, .. } => Some(*child_tgid),
            ProcEvent::Exec { tgid, .. } => Some(*tgid),
            ProcEvent::Uid { tgid, .. } => Some(*tgid),
            ProcEvent::Gid { tgid, .. } => Some(*tgid),
            ProcEvent::Sid { tgid, .. } => Some(*tgid),
            ProcEvent::Comm { tgid, .. } => Some(*tgid),
            ProcEvent::Ptrace { tgid, .. } => Some(*tgid),
            ProcEvent::Coredump { tgid, .. } => Some(*tgid),
            ProcEvent::Exit { tgid, .. } => Some(*tgid),
            ProcEvent::None | ProcEvent::Unknown { .. } => None,
        }
    }

    /// Parse a process event from the payload after the cn_msg header.
    ///
    /// The input should be the data after the connector message header (20 bytes).
    /// Used by the stream implementation.
    pub fn parse_from_bytes(input: &[u8]) -> Option<Self> {
        let mut input = input;

        // Parse proc_event header
        let header = ProcEventHeader::parse(&mut input).ok()?;

        // Parse event-specific data based on type
        match header.what {
            PROC_EVENT_NONE => Some(ProcEvent::None),

            PROC_EVENT_FORK => {
                let parent_pid = parse_u32_ne(&mut input).ok()?;
                let parent_tgid = parse_u32_ne(&mut input).ok()?;
                let child_pid = parse_u32_ne(&mut input).ok()?;
                let child_tgid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Fork {
                    parent_pid,
                    parent_tgid,
                    child_pid,
                    child_tgid,
                })
            }

            PROC_EVENT_EXEC => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Exec { pid, tgid })
            }

            PROC_EVENT_UID => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                let ruid = parse_u32_ne(&mut input).ok()?;
                let euid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Uid {
                    pid,
                    tgid,
                    ruid,
                    euid,
                })
            }

            PROC_EVENT_GID => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                let rgid = parse_u32_ne(&mut input).ok()?;
                let egid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Gid {
                    pid,
                    tgid,
                    rgid,
                    egid,
                })
            }

            PROC_EVENT_SID => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Sid { pid, tgid })
            }

            PROC_EVENT_COMM => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                // comm is 16 bytes
                if input.len() < 16 {
                    return None;
                }
                let comm = parse_string_from_bytes(&input[..16]);
                Some(ProcEvent::Comm { pid, tgid, comm })
            }

            PROC_EVENT_PTRACE => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                let tracer_pid = parse_u32_ne(&mut input).ok()?;
                let tracer_tgid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Ptrace {
                    pid,
                    tgid,
                    tracer_pid,
                    tracer_tgid,
                })
            }

            PROC_EVENT_COREDUMP => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                let parent_pid = parse_u32_ne(&mut input).ok()?;
                let parent_tgid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Coredump {
                    pid,
                    tgid,
                    parent_pid,
                    parent_tgid,
                })
            }

            PROC_EVENT_EXIT => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                let exit_code = parse_u32_ne(&mut input).ok()?;
                let exit_signal = parse_u32_ne(&mut input).ok()?;
                let parent_pid = parse_u32_ne(&mut input).ok()?;
                let parent_tgid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Exit {
                    pid,
                    tgid,
                    exit_code,
                    exit_signal,
                    parent_pid,
                    parent_tgid,
                })
            }

            _ => Some(ProcEvent::Unknown { what: header.what }),
        }
    }
}

/// cn_msg header structure (20 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct CnMsg {
    /// Connector ID (idx, val)
    idx: u32,
    val: u32,
    /// Sequence number
    seq: u32,
    /// Acknowledgment sequence
    ack: u32,
    /// Payload length
    len: u16,
    /// Flags
    flags: u16,
}

impl CnMsg {
    /// Safe serialization using zerocopy.
    fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    /// Parse a cn_msg from bytes using zerocopy.
    /// Returns the parsed struct and the remaining bytes.
    fn from_bytes(data: &[u8]) -> Option<(&Self, &[u8])> {
        Self::ref_from_prefix(data).ok()
    }
}

/// proc_event header (what + cpu + timestamp).
#[derive(Debug, Clone, Copy)]
struct ProcEventHeader {
    what: u32,
    #[allow(dead_code)]
    cpu: u32,
    #[allow(dead_code)]
    timestamp_ns: u64,
}

impl ProcEventHeader {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        let what = parse_u32_ne(input)?;
        let cpu = parse_u32_ne(input)?;
        let timestamp_ns = parse_u64_ne(input)?;
        Ok(Self {
            what,
            cpu,
            timestamp_ns,
        })
    }
}

#[nlink_macros::send_futures]
impl Connection<Connector> {
    /// Create a new connector and register for process events.
    ///
    /// This requires `CAP_NET_ADMIN` capability.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Connector};
    ///
    /// let conn = Connection::<Connector>::new().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "new"))]
    pub async fn new() -> Result<Self> {
        let socket = NetlinkSocket::new(Connector::PROTOCOL)?;

        // Join the proc connector multicast group
        socket.add_membership(CN_IDX_PROC)?;

        let conn = Self::from_parts(socket, Connector);

        // Send registration message to enable proc events
        conn.send_proc_control(PROC_CN_MCAST_LISTEN).await?;

        Ok(conn)
    }

    /// Unregister from process events.
    ///
    /// After calling this, no more events will be received.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "unregister"))]
    pub async fn unregister(&self) -> Result<()> {
        self.send_proc_control(PROC_CN_MCAST_IGNORE).await
    }

    /// Send a process connector control message.
    async fn send_proc_control(&self, op: u32) -> Result<()> {
        let seq = self.socket().next_seq();
        // Held for the send: serializes it in mutex mode, registers the
        // seq in dispatcher mode (#466). Nothing answers a control message.
        let _session = self.recv_session(seq).await?;
        let pid = self.socket().pid();

        // Build the message
        let mut buf = Vec::with_capacity(64);

        // Netlink header (16 bytes)
        let msg_len = NLMSG_HDRLEN + std::mem::size_of::<CnMsg>() + 4;
        buf.extend_from_slice(&(msg_len as u32).to_ne_bytes()); // nlmsg_len
        // 0.19 Finding D — was misleadingly commented "NLMSG_DONE".
        // The actual value is NLMSG_NOOP (0); cn_proc dispatches
        // on the (idx, val) tuple in the CnMsg body and is
        // permissive about nlmsg_type as long as it's not an
        // error frame.
        buf.extend_from_slice(&0x0u16.to_ne_bytes()); // nlmsg_type (NLMSG_NOOP)
        buf.extend_from_slice(&0x0u16.to_ne_bytes()); // nlmsg_flags
        buf.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
        buf.extend_from_slice(&pid.to_ne_bytes()); // nlmsg_pid

        // cn_msg header
        let cn_msg = CnMsg {
            idx: CN_IDX_PROC,
            val: CN_VAL_PROC,
            seq: 0,
            ack: 0,
            len: 4,
            flags: 0,
        };
        buf.extend_from_slice(cn_msg.as_bytes());

        // Payload: operation
        buf.extend_from_slice(&op.to_ne_bytes());

        self.socket().send(&buf).await?;
        Ok(())
    }

    /// Receive the next process event.
    ///
    /// This method blocks until an event is available.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Connector};
    /// use nlink::netlink::connector::ProcEvent;
    ///
    /// let conn = Connection::<Connector>::new().await?;
    ///
    /// loop {
    ///     let event = conn.recv().await?;
    ///     if let Some(pid) = event.pid() {
    ///         println!("Event for PID {}: {:?}", pid, event);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "recv"))]
    pub async fn recv(&self) -> Result<ProcEvent> {
        loop {
            let data = self.socket().recv_msg().await?;

            if let Some(event) = self.parse_proc_event(&data) {
                return Ok(event);
            }
            // Invalid message, try again
        }
    }

    /// Parse a process event from raw message data.
    fn parse_proc_event(&self, data: &[u8]) -> Option<ProcEvent> {
        // Skip netlink header (16 bytes)
        if data.len() < NLMSG_HDRLEN {
            return None;
        }
        let after_nlhdr = &data[NLMSG_HDRLEN..];

        // Parse cn_msg header using zerocopy
        let (_cn_msg, mut input) = CnMsg::from_bytes(after_nlhdr)?;

        // Parse proc_event header
        let header = ProcEventHeader::parse(&mut input).ok()?;

        // Parse event-specific data based on type
        match header.what {
            PROC_EVENT_NONE => Some(ProcEvent::None),

            PROC_EVENT_FORK => {
                let parent_pid = parse_u32_ne(&mut input).ok()?;
                let parent_tgid = parse_u32_ne(&mut input).ok()?;
                let child_pid = parse_u32_ne(&mut input).ok()?;
                let child_tgid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Fork {
                    parent_pid,
                    parent_tgid,
                    child_pid,
                    child_tgid,
                })
            }

            PROC_EVENT_EXEC => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Exec { pid, tgid })
            }

            PROC_EVENT_UID => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                let ruid = parse_u32_ne(&mut input).ok()?;
                let euid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Uid {
                    pid,
                    tgid,
                    ruid,
                    euid,
                })
            }

            PROC_EVENT_GID => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                let rgid = parse_u32_ne(&mut input).ok()?;
                let egid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Gid {
                    pid,
                    tgid,
                    rgid,
                    egid,
                })
            }

            PROC_EVENT_SID => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Sid { pid, tgid })
            }

            PROC_EVENT_COMM => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                // comm is 16 bytes
                if input.len() < 16 {
                    return None;
                }
                let comm = parse_string_from_bytes(&input[..16]);
                Some(ProcEvent::Comm { pid, tgid, comm })
            }

            PROC_EVENT_PTRACE => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                let tracer_pid = parse_u32_ne(&mut input).ok()?;
                let tracer_tgid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Ptrace {
                    pid,
                    tgid,
                    tracer_pid,
                    tracer_tgid,
                })
            }

            PROC_EVENT_COREDUMP => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                let parent_pid = parse_u32_ne(&mut input).ok()?;
                let parent_tgid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Coredump {
                    pid,
                    tgid,
                    parent_pid,
                    parent_tgid,
                })
            }

            PROC_EVENT_EXIT => {
                let pid = parse_u32_ne(&mut input).ok()?;
                let tgid = parse_u32_ne(&mut input).ok()?;
                let exit_code = parse_u32_ne(&mut input).ok()?;
                let exit_signal = parse_u32_ne(&mut input).ok()?;
                let parent_pid = parse_u32_ne(&mut input).ok()?;
                let parent_tgid = parse_u32_ne(&mut input).ok()?;
                Some(ProcEvent::Exit {
                    pid,
                    tgid,
                    exit_code,
                    exit_signal,
                    parent_pid,
                    parent_tgid,
                })
            }

            _ => Some(ProcEvent::Unknown { what: header.what }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_event_pid() {
        let fork = ProcEvent::Fork {
            parent_pid: 1,
            parent_tgid: 1,
            child_pid: 100,
            child_tgid: 100,
        };
        assert_eq!(fork.pid(), Some(100));
        assert_eq!(fork.tgid(), Some(100));

        let exit = ProcEvent::Exit {
            pid: 200,
            tgid: 200,
            exit_code: 0,
            exit_signal: 17,
            parent_pid: 1,
            parent_tgid: 1,
        };
        assert_eq!(exit.pid(), Some(200));
    }
}
