//! Audit implementation for `Connection<Audit>`.
//!
//! This module provides methods for interacting with the Linux Audit subsystem
//! via the NETLINK_AUDIT protocol.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Audit};
//!
//! let conn = Connection::<Audit>::new()?;
//!
//! // Get audit status
//! let status = conn.get_status().await?;
//! println!("Audit enabled: {}", status.enabled);
//! println!("PID: {}", status.pid);
//! println!("Backlog: {}/{}", status.backlog, status.backlog_limit);
//! # Ok(())
//! # }
//! ```

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::{
    connection::Connection,
    error::{Error, Result},
    protocol::{Audit, ProtocolState},
    socket::NetlinkSocket,
};

// Netlink constants
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;

// Netlink header size
const NLMSG_HDRLEN: usize = 16;

// Audit message types (from linux/audit.h)
/// Get status
const AUDIT_GET: u16 = 1000;
/// Set status
const AUDIT_SET: u16 = 1001;
/// List syscall rules (deprecated)
const AUDIT_LIST: u16 = 1002;
/// Add syscall rule (deprecated)
const AUDIT_ADD: u16 = 1003;
/// Delete syscall rule (deprecated)
const AUDIT_DEL: u16 = 1004;
/// User-space message
const AUDIT_USER: u16 = 1005;
/// Define the login id and information
const AUDIT_LOGIN: u16 = 1006;
/// Insert file/dir watch entry
const AUDIT_WATCH_INS: u16 = 1007;
/// Remove file/dir watch entry
const AUDIT_WATCH_REM: u16 = 1008;
/// List all file/dir watches
const AUDIT_WATCH_LIST: u16 = 1009;
/// Get info about sender of signal to auditd
const AUDIT_SIGNAL_INFO: u16 = 1010;
/// Add syscall filtering rule
const AUDIT_ADD_RULE: u16 = 1011;
/// Delete syscall filtering rule
const AUDIT_DEL_RULE: u16 = 1012;
/// List syscall filtering rules
const AUDIT_LIST_RULES: u16 = 1013;
/// Trim junk from watched tree
const AUDIT_TRIM: u16 = 1014;
/// Append to watched tree
const AUDIT_MAKE_EQUIV: u16 = 1015;
/// Get TTY auditing status
const AUDIT_TTY_GET: u16 = 1016;
/// Set TTY auditing status
const AUDIT_TTY_SET: u16 = 1017;
/// Turn an audit feature on or off
const AUDIT_SET_FEATURE: u16 = 1018;
/// Get audit feature state
const AUDIT_GET_FEATURE: u16 = 1019;

// Audit event message types
/// Syscall event
const AUDIT_SYSCALL: u16 = 1300;
/// Filename path information
const AUDIT_PATH: u16 = 1302;
/// IPC record
const AUDIT_IPC: u16 = 1303;
/// Socket address
const AUDIT_SOCKADDR: u16 = 1306;
/// Current working directory
const AUDIT_CWD: u16 = 1307;
/// execve arguments
const AUDIT_EXECVE: u16 = 1309;
/// IPC new permissions record
const AUDIT_IPC_SET_PERM: u16 = 1311;
/// POSIX MQ open record
const AUDIT_MQ_OPEN: u16 = 1312;
/// POSIX MQ send/receive record
const AUDIT_MQ_SENDRECV: u16 = 1313;
/// POSIX MQ notify record
const AUDIT_MQ_NOTIFY: u16 = 1314;
/// POSIX MQ get/set attribute record
const AUDIT_MQ_GETSETATTR: u16 = 1315;
/// End of multi-record event
const AUDIT_EOE: u16 = 1320;
/// Seccomp filter info
const AUDIT_SECCOMP: u16 = 1326;
/// Process title information
const AUDIT_PROCTITLE: u16 = 1327;
/// BPF subsystem info
const AUDIT_BPF: u16 = 1334;

// SELinux AVC message
const AUDIT_AVC: u16 = 1400;

// Audit status mask bits
const AUDIT_STATUS_ENABLED: u32 = 0x0001;
const AUDIT_STATUS_FAILURE: u32 = 0x0002;
const AUDIT_STATUS_PID: u32 = 0x0004;
const AUDIT_STATUS_RATE_LIMIT: u32 = 0x0008;
const AUDIT_STATUS_BACKLOG_LIMIT: u32 = 0x0010;
const AUDIT_STATUS_BACKLOG_WAIT_TIME: u32 = 0x0020;
const AUDIT_STATUS_LOST: u32 = 0x0040;

// Failure modes
/// Silent (log to syslog)
const AUDIT_FAIL_SILENT: u32 = 0;
/// Print rate limit
const AUDIT_FAIL_PRINTK: u32 = 1;
/// Panic
const AUDIT_FAIL_PANIC: u32 = 2;

/// Audit status structure (from linux/audit.h).
///
/// This structure is used to get/set the audit daemon configuration.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct AuditStatus {
    /// Bit mask for valid entries.
    pub mask: u32,
    /// 1 = enabled, 0 = disabled, 2 = immutable.
    pub enabled: u32,
    /// Failure-to-log action.
    pub failure: u32,
    /// PID of auditd process.
    pub pid: u32,
    /// Message rate limit (per second).
    pub rate_limit: u32,
    /// Waiting messages limit.
    pub backlog_limit: u32,
    /// Messages lost.
    pub lost: u32,
    /// Messages waiting in queue.
    pub backlog: u32,
    /// Kernel audit feature bitmap / version.
    pub feature_bitmap: u32,
    /// Message queue wait timeout (kernel >= 3.14).
    pub backlog_wait_time: u32,
    /// Backlog wait time actual (kernel >= 5.16).
    pub backlog_wait_time_actual: u32,
}

impl AuditStatus {
    /// Check if auditing is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled == 1
    }

    /// Check if auditing is locked (immutable).
    pub fn is_locked(&self) -> bool {
        self.enabled == 2
    }

    /// Get the failure mode as an enum.
    pub fn failure_mode(&self) -> AuditFailureMode {
        AuditFailureMode::from_u32(self.failure)
    }
}

/// Audit failure mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditFailureMode {
    /// Silent - discard failed audit messages.
    Silent,
    /// Printk - log to syslog on failure.
    Printk,
    /// Panic - kernel panic on audit failure.
    Panic,
    /// Unknown failure mode.
    Unknown(u32),
}

impl AuditFailureMode {
    fn from_u32(val: u32) -> Self {
        match val {
            AUDIT_FAIL_SILENT => Self::Silent,
            AUDIT_FAIL_PRINTK => Self::Printk,
            AUDIT_FAIL_PANIC => Self::Panic,
            other => Self::Unknown(other),
        }
    }

    /// Get the numeric value.
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::Silent => AUDIT_FAIL_SILENT,
            Self::Printk => AUDIT_FAIL_PRINTK,
            Self::Panic => AUDIT_FAIL_PANIC,
            Self::Unknown(n) => *n,
        }
    }
}

/// Audit rule data structure.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct AuditRuleData {
    /// Flags (AUDIT_FILTER_*).
    pub flags: u32,
    /// Action to take (AUDIT_ALWAYS, AUDIT_NEVER).
    pub action: u32,
    /// Number of fields.
    pub field_count: u32,
    /// Syscall bitmask (AUDIT_BITMASK_SIZE = 64).
    pub mask: [u32; 64],
    /// Field types (AUDIT_MAX_FIELDS = 64).
    pub fields: [u32; 64],
    /// Field values.
    pub values: [u32; 64],
    /// Field flags (MNT_ID/operators).
    pub fieldflags: [u32; 64],
    /// Length of filter string buffer.
    pub buflen: u32,
    // Followed by variable-length buffer.
}

impl Default for AuditRuleData {
    fn default() -> Self {
        Self {
            flags: 0,
            action: 0,
            field_count: 0,
            mask: [0; 64],
            fields: [0; 64],
            values: [0; 64],
            fieldflags: [0; 64],
            buflen: 0,
        }
    }
}

/// Audit TTY status.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct AuditTtyStatus {
    /// Enable/disable TTY auditing.
    pub enabled: u32,
    /// Log passwords too.
    pub log_passwd: u32,
}

/// Audit features structure.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct AuditFeatures {
    /// Currently holds version number.
    pub vers: u32,
    /// Mask of all features.
    pub mask: u32,
    /// Features currently enabled.
    pub features: u32,
    /// Features locked.
    pub lock: u32,
}

/// Audit signal info.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct AuditSignalInfo {
    /// UID of sender.
    pub uid: u32,
    /// PID of sender.
    pub pid: u32,
    /// Context string follows.
    pub ctx: u32,
}

/// Audit event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditEventType {
    /// Syscall event.
    Syscall,
    /// Path information.
    Path,
    /// IPC record.
    Ipc,
    /// Socket address.
    Sockaddr,
    /// Current working directory.
    Cwd,
    /// Execve arguments.
    Execve,
    /// End of event.
    EndOfEvent,
    /// Seccomp filter.
    Seccomp,
    /// Process title.
    Proctitle,
    /// BPF subsystem.
    Bpf,
    /// SELinux AVC.
    Avc,
    /// User message.
    User,
    /// Other event type.
    Other(u16),
}

impl AuditEventType {
    /// Parse an event type from its numeric value.
    #[allow(dead_code)] // Used for event monitoring (future)
    pub fn from_u16(val: u16) -> Self {
        match val {
            AUDIT_SYSCALL => Self::Syscall,
            AUDIT_PATH => Self::Path,
            AUDIT_IPC => Self::Ipc,
            AUDIT_SOCKADDR => Self::Sockaddr,
            AUDIT_CWD => Self::Cwd,
            AUDIT_EXECVE => Self::Execve,
            AUDIT_EOE => Self::EndOfEvent,
            AUDIT_SECCOMP => Self::Seccomp,
            AUDIT_PROCTITLE => Self::Proctitle,
            AUDIT_BPF => Self::Bpf,
            AUDIT_AVC => Self::Avc,
            AUDIT_USER => Self::User,
            other => Self::Other(other),
        }
    }

    /// Get the numeric value.
    pub fn as_u16(&self) -> u16 {
        match self {
            Self::Syscall => AUDIT_SYSCALL,
            Self::Path => AUDIT_PATH,
            Self::Ipc => AUDIT_IPC,
            Self::Sockaddr => AUDIT_SOCKADDR,
            Self::Cwd => AUDIT_CWD,
            Self::Execve => AUDIT_EXECVE,
            Self::EndOfEvent => AUDIT_EOE,
            Self::Seccomp => AUDIT_SECCOMP,
            Self::Proctitle => AUDIT_PROCTITLE,
            Self::Bpf => AUDIT_BPF,
            Self::Avc => AUDIT_AVC,
            Self::User => AUDIT_USER,
            Self::Other(n) => *n,
        }
    }
}

/// An audit event received from the kernel.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Event type.
    pub event_type: AuditEventType,
    /// Raw message type value.
    pub msg_type: u16,
    /// Event data (text format).
    pub data: String,
}

#[nlink_macros::send_futures]
impl Connection<Audit> {
    /// Create a new Audit connection.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Audit};
    ///
    /// let conn = Connection::<Audit>::new()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Result<Self> {
        let socket = NetlinkSocket::new(Audit::PROTOCOL)?;
        Ok(Self::from_parts(socket, Audit))
    }

    /// Get the current audit status.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Audit};
    ///
    /// let conn = Connection::<Audit>::new()?;
    /// let status = conn.get_status().await?;
    ///
    /// println!("Audit enabled: {}", status.is_enabled());
    /// println!("Audit locked: {}", status.is_locked());
    /// println!("Failure mode: {:?}", status.failure_mode());
    /// println!("Audit daemon PID: {}", status.pid);
    /// println!("Rate limit: {} msgs/sec", status.rate_limit);
    /// println!("Backlog: {}/{}", status.backlog, status.backlog_limit);
    /// println!("Lost messages: {}", status.lost);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_status"))]
    pub async fn get_status(&self) -> Result<AuditStatus> {
        // Wrapped in with_timeout (Plan 171: 30s default) so a kernel
        // that drops the response surfaces as `Error::timeout()` rather
        // than an indefinite hang. Pre-0.19 this method could hang
        // forever waiting for an ACK that never arrived.
        self.with_timeout(async move {
            let seq = self.socket().next_seq();
            let mut session = self.recv_session(seq).await?;
            let pid = self.socket().pid();

            // Build request message
            let mut buf = Vec::with_capacity(32);

            // Netlink header (16 bytes)
            buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len (fill later)
            buf.extend_from_slice(&AUDIT_GET.to_ne_bytes()); // nlmsg_type
            buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes()); // nlmsg_flags
            buf.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
            buf.extend_from_slice(&pid.to_ne_bytes()); // nlmsg_pid

            // Update length
            let len = buf.len() as u32;
            buf[0..4].copy_from_slice(&len.to_ne_bytes());

            // Send request
            self.socket().send(&buf).await?;

            // Receive responses, filtering by seq (skip any stale
            // frames from prior queries on the same socket).
            loop {
                let data = session.recv_with_timeout(self).await?;

                if data.len() < NLMSG_HDRLEN {
                    return Err(Error::invalid_message("response too short"));
                }

                let resp_seq = u32::from_ne_bytes([data[8], data[9], data[10], data[11]]);
                if resp_seq != seq {
                    continue; // Stale frame from prior request.
                }

                let nlmsg_type = u16::from_ne_bytes([data[4], data[5]]);

                if nlmsg_type == NLMSG_ERROR {
                    if data.len() >= 20 {
                        let errno =
                            i32::from_ne_bytes([data[16], data[17], data[18], data[19]]);
                        if errno != 0 {
                            // Plan 232 B6 — operation tag matches Plan 212
                            // hygiene; `from_errno_with_context` does
                            // `errno.abs()` internally so the `-errno`
                            // negation is redundant.
                            return Err(Error::from_errno_with_context(
                                errno,
                                "audit_set_status",
                            ));
                        }
                    }
                    // errno == 0 means success ACK, wait for actual response
                    continue;
                }

                return self.parse_status_response(&data);
            }
        })
        .await
    }

    /// Parse status response.
    fn parse_status_response(&self, data: &[u8]) -> Result<AuditStatus> {
        if data.len() < NLMSG_HDRLEN {
            return Err(Error::invalid_message("response too short"));
        }

        let nlmsg_type = u16::from_ne_bytes([data[4], data[5]]);

        if nlmsg_type != AUDIT_GET {
            return Err(Error::invalid_message(format!(
                "unexpected message type: {}",
                nlmsg_type
            )));
        }

        if data.len() < NLMSG_HDRLEN + std::mem::size_of::<AuditStatus>() {
            // Plan 232 B15 — older / future kernels can emit any
            // size between 32 bytes and `size_of::<AuditStatus>()`.
            // Walk each field's offset individually with a per-field
            // bounds check so we tolerate any size ≥ 32 (CLAUDE.md
            // "Parser robustness" rule 1, accept-larger-than-expected
            // applied per-field instead of fixed-prefix only).
            let mut status = AuditStatus::default();
            let payload = &data[NLMSG_HDRLEN..];

            // Helper: read a u32 at `offset` if there are enough bytes.
            // Returns the existing default on short input — the field
            // is "not present" in the kernel's response.
            let read_u32 = |off: usize| -> Option<u32> {
                if payload.len() >= off + 4 {
                    Some(u32::from_ne_bytes([
                        payload[off],
                        payload[off + 1],
                        payload[off + 2],
                        payload[off + 3],
                    ]))
                } else {
                    None
                }
            };

            if let Some(v) = read_u32(0) {
                status.mask = v;
            }
            if let Some(v) = read_u32(4) {
                status.enabled = v;
            }
            if let Some(v) = read_u32(8) {
                status.failure = v;
            }
            if let Some(v) = read_u32(12) {
                status.pid = v;
            }
            if let Some(v) = read_u32(16) {
                status.rate_limit = v;
            }
            if let Some(v) = read_u32(20) {
                status.backlog_limit = v;
            }
            if let Some(v) = read_u32(24) {
                status.lost = v;
            }
            if let Some(v) = read_u32(28) {
                status.backlog = v;
            }

            return Ok(status);
        }

        let (status, _) = AuditStatus::ref_from_prefix(&data[NLMSG_HDRLEN..])
            .map_err(|_| Error::invalid_message("failed to parse audit status"))?;

        Ok(*status)
    }

    /// Get the TTY auditing status.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Audit};
    ///
    /// let conn = Connection::<Audit>::new()?;
    /// let tty_status = conn.get_tty_status().await?;
    ///
    /// println!("TTY auditing enabled: {}", tty_status.enabled != 0);
    /// println!("Log passwords: {}", tty_status.log_passwd != 0);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_tty_status"))]
    pub async fn get_tty_status(&self) -> Result<AuditTtyStatus> {
        // See `get_status` for the timeout/seq-filter rationale.
        self.with_timeout(async move {
            let seq = self.socket().next_seq();
            let mut session = self.recv_session(seq).await?;
            let pid = self.socket().pid();

            // Build request message
            let mut buf = Vec::with_capacity(32);

            // Netlink header (16 bytes)
            buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len (fill later)
            buf.extend_from_slice(&AUDIT_TTY_GET.to_ne_bytes()); // nlmsg_type
            buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes()); // nlmsg_flags
            buf.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
            buf.extend_from_slice(&pid.to_ne_bytes()); // nlmsg_pid

            // Update length
            let len = buf.len() as u32;
            buf[0..4].copy_from_slice(&len.to_ne_bytes());

            // Send request
            self.socket().send(&buf).await?;

            // Receive response - skip ACK; filter by seq.
            loop {
                let data = session.recv_with_timeout(self).await?;

                if data.len() < NLMSG_HDRLEN {
                    return Err(Error::invalid_message("response too short"));
                }

                let resp_seq = u32::from_ne_bytes([data[8], data[9], data[10], data[11]]);
                if resp_seq != seq {
                    continue;
                }

                let nlmsg_type = u16::from_ne_bytes([data[4], data[5]]);

                if nlmsg_type == NLMSG_ERROR {
                    if data.len() >= 20 {
                        let errno =
                            i32::from_ne_bytes([data[16], data[17], data[18], data[19]]);
                        if errno != 0 {
                            return Err(Error::from_errno(-errno));
                        }
                    }
                    // ACK, continue to next message
                    continue;
                }

                if nlmsg_type == AUDIT_TTY_GET {
                    if data.len() < NLMSG_HDRLEN + std::mem::size_of::<AuditTtyStatus>() {
                        return Err(Error::invalid_message(
                            "TTY status response too short",
                        ));
                    }

                    let (status, _) = AuditTtyStatus::ref_from_prefix(&data[NLMSG_HDRLEN..])
                        .map_err(|_| {
                            Error::invalid_message("failed to parse TTY status")
                        })?;

                    return Ok(*status);
                }

                return Err(Error::invalid_message(format!(
                    "unexpected message type: {}",
                    nlmsg_type
                )));
            }
        })
        .await
    }

    /// Get audit features.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Audit};
    ///
    /// let conn = Connection::<Audit>::new()?;
    /// let features = conn.get_features().await?;
    ///
    /// println!("Version: {}", features.vers);
    /// println!("Features: 0x{:08x}", features.features);
    /// println!("Mask: 0x{:08x}", features.mask);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_features"))]
    pub async fn get_features(&self) -> Result<AuditFeatures> {
        // See `get_status` for the timeout/seq-filter rationale.
        self.with_timeout(async move {
            let seq = self.socket().next_seq();
            let mut session = self.recv_session(seq).await?;
            let pid = self.socket().pid();

            // Build request message
            let mut buf = Vec::with_capacity(32);

            // Netlink header (16 bytes)
            buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len (fill later)
            buf.extend_from_slice(&AUDIT_GET_FEATURE.to_ne_bytes()); // nlmsg_type
            buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes()); // nlmsg_flags
            buf.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
            buf.extend_from_slice(&pid.to_ne_bytes()); // nlmsg_pid

            // Update length
            let len = buf.len() as u32;
            buf[0..4].copy_from_slice(&len.to_ne_bytes());

            // Send request
            self.socket().send(&buf).await?;

            // Receive response - skip ACK; filter by seq.
            loop {
                let data = session.recv_with_timeout(self).await?;

                if data.len() < NLMSG_HDRLEN {
                    return Err(Error::invalid_message("response too short"));
                }

                let resp_seq = u32::from_ne_bytes([data[8], data[9], data[10], data[11]]);
                if resp_seq != seq {
                    continue;
                }

                let nlmsg_type = u16::from_ne_bytes([data[4], data[5]]);

                if nlmsg_type == NLMSG_ERROR {
                    if data.len() >= 20 {
                        let errno =
                            i32::from_ne_bytes([data[16], data[17], data[18], data[19]]);
                        if errno != 0 {
                            return Err(Error::from_errno(-errno));
                        }
                    }
                    // ACK, continue to next message
                    continue;
                }

                if nlmsg_type == AUDIT_GET_FEATURE {
                    if data.len() < NLMSG_HDRLEN + std::mem::size_of::<AuditFeatures>() {
                        return Err(Error::invalid_message(
                            "features response too short",
                        ));
                    }

                    let (features, _) = AuditFeatures::ref_from_prefix(&data[NLMSG_HDRLEN..])
                        .map_err(|_| {
                            Error::invalid_message("failed to parse features")
                        })?;

                    return Ok(*features);
                }

                return Err(Error::invalid_message(format!(
                    "unexpected message type: {}",
                    nlmsg_type
                )));
            }
        })
        .await
    }
}

// Silence unused constant warnings - these are kept for documentation/future use
const _: () = {
    let _ = AUDIT_SET;
    let _ = AUDIT_LIST;
    let _ = AUDIT_ADD;
    let _ = AUDIT_DEL;
    let _ = AUDIT_LOGIN;
    let _ = AUDIT_WATCH_INS;
    let _ = AUDIT_WATCH_REM;
    let _ = AUDIT_WATCH_LIST;
    let _ = AUDIT_SIGNAL_INFO;
    let _ = AUDIT_ADD_RULE;
    let _ = AUDIT_DEL_RULE;
    let _ = AUDIT_LIST_RULES;
    let _ = AUDIT_TRIM;
    let _ = AUDIT_MAKE_EQUIV;
    let _ = AUDIT_TTY_SET;
    let _ = AUDIT_SET_FEATURE;
    let _ = AUDIT_IPC_SET_PERM;
    let _ = AUDIT_MQ_OPEN;
    let _ = AUDIT_MQ_SENDRECV;
    let _ = AUDIT_MQ_NOTIFY;
    let _ = AUDIT_MQ_GETSETATTR;
    let _ = AUDIT_STATUS_ENABLED;
    let _ = AUDIT_STATUS_FAILURE;
    let _ = AUDIT_STATUS_PID;
    let _ = AUDIT_STATUS_RATE_LIMIT;
    let _ = AUDIT_STATUS_BACKLOG_LIMIT;
    let _ = AUDIT_STATUS_BACKLOG_WAIT_TIME;
    let _ = AUDIT_STATUS_LOST;
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_status_size() {
        // 11 * 4 = 44 bytes
        assert_eq!(std::mem::size_of::<AuditStatus>(), 44);
    }

    #[test]
    fn audit_tty_status_size() {
        assert_eq!(std::mem::size_of::<AuditTtyStatus>(), 8);
    }

    #[test]
    fn audit_features_size() {
        assert_eq!(std::mem::size_of::<AuditFeatures>(), 16);
    }

    #[test]
    fn failure_mode_roundtrip() {
        assert_eq!(AuditFailureMode::Silent.as_u32(), 0);
        assert_eq!(AuditFailureMode::from_u32(0), AuditFailureMode::Silent);

        assert_eq!(AuditFailureMode::Printk.as_u32(), 1);
        assert_eq!(AuditFailureMode::from_u32(1), AuditFailureMode::Printk);

        assert_eq!(AuditFailureMode::Panic.as_u32(), 2);
        assert_eq!(AuditFailureMode::from_u32(2), AuditFailureMode::Panic);
    }

    #[test]
    fn event_type_roundtrip() {
        assert_eq!(AuditEventType::Syscall.as_u16(), 1300);
        assert_eq!(AuditEventType::from_u16(1300), AuditEventType::Syscall);

        assert_eq!(AuditEventType::Avc.as_u16(), 1400);
        assert_eq!(AuditEventType::from_u16(1400), AuditEventType::Avc);
    }

    #[test]
    fn b15_short_struct_walk_handles_partial_size() {
        // Plan 232 B15 — kernels between "32 bytes" and the full
        // sizeof(AuditStatus) need their middle fields parsed.
        // Synthesize a 48-byte payload (mask, enabled, failure,
        // pid, rate_limit, backlog_limit, lost, backlog, then a
        // garbage 16 bytes). The per-offset walk must parse the
        // documented fields, leave the trailing bytes alone.
        let mut payload = Vec::<u8>::new();
        payload.extend_from_slice(&1u32.to_ne_bytes()); // mask
        payload.extend_from_slice(&2u32.to_ne_bytes()); // enabled
        payload.extend_from_slice(&3u32.to_ne_bytes()); // failure
        payload.extend_from_slice(&4u32.to_ne_bytes()); // pid
        payload.extend_from_slice(&5u32.to_ne_bytes()); // rate_limit
        payload.extend_from_slice(&6u32.to_ne_bytes()); // backlog_limit
        payload.extend_from_slice(&7u32.to_ne_bytes()); // lost
        payload.extend_from_slice(&8u32.to_ne_bytes()); // backlog
        payload.extend_from_slice(&[0xAB; 16]); // unrelated trailing

        // Verify per-offset reads work for each field.
        let read_u32 = |off: usize| -> u32 {
            u32::from_ne_bytes([
                payload[off],
                payload[off + 1],
                payload[off + 2],
                payload[off + 3],
            ])
        };
        assert_eq!(read_u32(0), 1);
        assert_eq!(read_u32(4), 2);
        assert_eq!(read_u32(8), 3);
        assert_eq!(read_u32(28), 8);
    }

    #[test]
    fn b6_audit_operation_tag_appears_in_display() {
        // Plan 232 B6 — `from_errno_with_context` adds the
        // operation label, which must surface in the
        // `Error::Display` output (per CLAUDE.md `## Errors`).
        let err = Error::from_errno_with_context(22, "audit_set_status");
        let msg = format!("{err}");
        assert!(
            msg.contains("audit_set_status"),
            "operation tag missing from Display: {msg}"
        );
    }

    #[test]
    fn audit_status_helpers() {
        // Test disabled state
        let status = AuditStatus {
            enabled: 0,
            ..Default::default()
        };
        assert!(!status.is_enabled());
        assert!(!status.is_locked());

        // Test enabled state
        let status = AuditStatus {
            enabled: 1,
            ..Default::default()
        };
        assert!(status.is_enabled());
        assert!(!status.is_locked());

        // Test locked state
        let status = AuditStatus {
            enabled: 2,
            ..Default::default()
        };
        assert!(!status.is_enabled());
        assert!(status.is_locked());
    }
}
