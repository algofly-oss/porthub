//! Core types for socket diagnostics.
//!
//! This module provides strongly-typed representations of socket states,
//! address families, protocols, and diagnostic information.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Socket address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AddressFamily {
    /// Unix domain sockets.
    Unix = libc::AF_UNIX as u8,
    /// IPv4.
    Inet = libc::AF_INET as u8,
    /// IPv6.
    Inet6 = libc::AF_INET6 as u8,
    /// Netlink.
    Netlink = libc::AF_NETLINK as u8,
    /// Packet (raw).
    Packet = libc::AF_PACKET as u8,
    /// VSOCK (virtual machine sockets).
    Vsock = 40, // AF_VSOCK
    /// TIPC.
    Tipc = 30, // AF_TIPC
    /// XDP (eXpress Data Path).
    Xdp = 44, // AF_XDP
}

impl AddressFamily {
    /// Parse from a raw u8 value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value as i32 {
            libc::AF_UNIX => Some(Self::Unix),
            libc::AF_INET => Some(Self::Inet),
            libc::AF_INET6 => Some(Self::Inet6),
            libc::AF_NETLINK => Some(Self::Netlink),
            libc::AF_PACKET => Some(Self::Packet),
            40 => Some(Self::Vsock),
            30 => Some(Self::Tipc),
            44 => Some(Self::Xdp),
            _ => None,
        }
    }

    /// Get the netid string (used by ss).
    pub fn netid(&self) -> &'static str {
        match self {
            Self::Unix => "u_str",
            Self::Inet => "tcp",
            Self::Inet6 => "tcp6",
            Self::Netlink => "nl",
            Self::Packet => "p_raw",
            Self::Vsock => "v_str",
            Self::Tipc => "tipc",
            Self::Xdp => "xdp",
        }
    }
}

/// Transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// SCTP.
    Sctp,
    /// DCCP.
    Dccp,
    /// MPTCP.
    Mptcp,
    /// Raw IP.
    Raw,
}

impl Protocol {
    /// The real IP protocol number.
    ///
    /// `IPPROTO_MPTCP` is **262**, which is why this is a `u32` and why
    /// [`Self::number`] is not enough on its own: `inet_diag_req_v2`'s
    /// `sdiag_protocol` is a `__u8`, so MPTCP does not fit in it. The kernel's
    /// answer is the `INET_DIAG_REQ_PROTOCOL` request attribute, which carries
    /// the protocol as a `u32` and overrides the header field — nlink now
    /// emits it whenever [`Self::fits_in_u8`] is false (#225).
    pub fn number_u32(&self) -> u32 {
        match self {
            Self::Tcp => libc::IPPROTO_TCP as u32,
            Self::Udp => libc::IPPROTO_UDP as u32,
            Self::Sctp => 132,
            Self::Dccp => 33,
            Self::Mptcp => 262, // IPPROTO_MPTCP — does not fit sdiag_protocol
            Self::Raw => libc::IPPROTO_RAW as u32,
        }
    }

    /// Does the protocol number fit `inet_diag_req_v2.sdiag_protocol` (a `u8`)?
    ///
    /// False only for MPTCP today. When false the caller **must** also emit
    /// `INET_DIAG_REQ_PROTOCOL`, or the kernel dispatches on the truncated
    /// header byte — 262 truncates to 6, i.e. plain TCP, which is how
    /// `SocketFilter::mptcp()` used to return every TCP socket on the box,
    /// each one stamped `Protocol::Mptcp`.
    pub fn fits_in_u8(&self) -> bool {
        self.number_u32() <= u8::MAX as u32
    }

    /// The protocol number truncated to the `sdiag_protocol` header field.
    ///
    /// For MPTCP this is 6 (262 & 0xff) — meaningful only alongside an
    /// `INET_DIAG_REQ_PROTOCOL` attribute. See [`Self::fits_in_u8`].
    pub fn number(&self) -> u8 {
        self.number_u32() as u8
    }

    /// Parse from a raw u8 value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value as i32 {
            libc::IPPROTO_TCP => Some(Self::Tcp),
            libc::IPPROTO_UDP => Some(Self::Udp),
            132 => Some(Self::Sctp),
            33 => Some(Self::Dccp),
            libc::IPPROTO_RAW => Some(Self::Raw),
            _ => None,
        }
    }

    /// Get the protocol name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
            Self::Dccp => "dccp",
            Self::Mptcp => "mptcp",
            Self::Raw => "raw",
        }
    }
}

/// TCP socket states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TcpState {
    /// Unknown state.
    Unknown = 0,
    /// Connection established.
    Established = 1,
    /// SYN sent, waiting for matching SYN.
    SynSent = 2,
    /// SYN received, waiting for ACK.
    SynRecv = 3,
    /// FIN sent, waiting for FIN or FIN-ACK.
    FinWait1 = 4,
    /// FIN received, waiting for FIN.
    FinWait2 = 5,
    /// In TIME-WAIT state.
    TimeWait = 6,
    /// Socket is closed.
    Close = 7,
    /// FIN received, close pending.
    CloseWait = 8,
    /// Close wait acknowledged, waiting for FIN.
    LastAck = 9,
    /// Socket is listening.
    Listen = 10,
    /// Both sides sent FIN simultaneously.
    Closing = 11,
    /// New SYN received (kernel only).
    NewSynRecv = 12,
    /// Bound but inactive (MPTCP).
    BoundInactive = 13,
}

impl TcpState {
    /// Parse from a raw u8 value.
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Established,
            2 => Self::SynSent,
            3 => Self::SynRecv,
            4 => Self::FinWait1,
            5 => Self::FinWait2,
            6 => Self::TimeWait,
            7 => Self::Close,
            8 => Self::CloseWait,
            9 => Self::LastAck,
            10 => Self::Listen,
            11 => Self::Closing,
            12 => Self::NewSynRecv,
            13 => Self::BoundInactive,
            _ => Self::Unknown,
        }
    }

    /// Get the state name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::Established => "ESTAB",
            Self::SynSent => "SYN-SENT",
            Self::SynRecv => "SYN-RECV",
            Self::FinWait1 => "FIN-WAIT-1",
            Self::FinWait2 => "FIN-WAIT-2",
            Self::TimeWait => "TIME-WAIT",
            Self::Close => "UNCONN",
            Self::CloseWait => "CLOSE-WAIT",
            Self::LastAck => "LAST-ACK",
            Self::Listen => "LISTEN",
            Self::Closing => "CLOSING",
            Self::NewSynRecv => "NEW-SYN-RECV",
            Self::BoundInactive => "BOUND-INACTIVE",
        }
    }

    /// Create a bitmask for this state.
    pub fn mask(&self) -> u32 {
        1 << (*self as u32)
    }

    /// All connection states (excludes LISTEN, CLOSE, TIME-WAIT, SYN-RECV).
    pub fn connected_mask() -> u32 {
        Self::all_mask()
            & !(Self::Listen.mask()
                | Self::Close.mask()
                | Self::TimeWait.mask()
                | Self::SynRecv.mask())
    }

    /// All states mask.
    pub fn all_mask() -> u32 {
        (1 << 14) - 1
    }
}

/// Generic socket state (for non-TCP sockets).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SocketState {
    /// TCP state (for TCP/MPTCP/DCCP sockets).
    Tcp(TcpState),
    /// Closed (for UDP, Unix, etc.).
    Close,
    /// Established (for UDP, Unix stream).
    Established,
    /// Listening (for Unix stream/seqpacket).
    Listen,
}

impl SocketState {
    /// Get the state name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tcp(state) => state.name(),
            Self::Close => "UNCONN",
            Self::Established => "ESTAB",
            Self::Listen => "LISTEN",
        }
    }
}

/// Extensions to request in inet_diag query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum InetExtension {
    /// Memory info (idiag_rmem, idiag_wmem, etc.).
    MemInfo = 1,
    /// TCP info structure.
    Info = 2,
    /// Vegas congestion info.
    VegasInfo = 3,
    /// Congestion algorithm name.
    Cong = 4,
    /// Type of service.
    Tos = 5,
    /// Traffic class (IPv6).
    TClass = 6,
    /// Socket memory info array.
    SkMemInfo = 7,
    /// Shutdown state.
    Shutdown = 8,
}

impl InetExtension {
    /// Get the request bitmask for this extension.
    ///
    /// The kernel checks `ext & (1 << (attr - 1))`
    /// (`inet_diag_msg_attrs_fill` / `inet_sk_diag_fill`), so the bit
    /// for extension N is `1 << (N - 1)`. Before 0.24 this returned
    /// `1 << N` — off by one, so e.g. `with_mem_info()` actually
    /// requested `INET_DIAG_INFO` (#163).
    pub fn mask(&self) -> u8 {
        1 << (*self as u8 - 1)
    }
}

/// What to show in Unix socket queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum UnixShow {
    /// Show socket name.
    Name = 0x00000001,
    /// Show VFS inode info.
    Vfs = 0x00000002,
    /// Show peer socket info.
    Peer = 0x00000004,
    /// Show pending connections.
    Icons = 0x00000008,
    /// Show receive queue length.
    RqLen = 0x00000010,
    /// Show memory info.
    MemInfo = 0x00000020,
    /// Show socket UID.
    Uid = 0x00000040,
}

impl UnixShow {
    /// Get the bitmask for this show option.
    pub fn mask(&self) -> u32 {
        *self as u32
    }

    /// Combine multiple show options into a bitmask.
    pub fn combine(options: &[UnixShow]) -> u32 {
        options.iter().fold(0, |acc, opt| acc | opt.mask())
    }
}

/// Vegas congestion-control state (`struct tcpvegas_info`,
/// `INET_DIAG_VEGASINFO`). Times in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VegasInfo {
    /// Whether Vegas is active on this socket.
    pub enabled: bool,
    /// Number of RTT samples in the current interval.
    pub rttcnt: u32,
    /// Most recent RTT (µs).
    pub rtt: u32,
    /// Minimum RTT observed (µs).
    pub minrtt: u32,
}

/// DCTCP congestion-control state (`struct tcp_dctcp_info`,
/// `INET_DIAG_DCTCPINFO`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DctcpInfo {
    /// Whether DCTCP is active on this socket.
    pub enabled: bool,
    /// Current CE state.
    pub ce_state: u16,
    /// ECN-fraction EWMA (alpha), scaled by 1024.
    pub alpha: u32,
    /// Bytes acked with ECN marks in the last window.
    pub ab_ecn: u32,
    /// Total bytes acked in the last window.
    pub ab_tot: u32,
}

/// BBR congestion-control state (`struct tcp_bbr_info`,
/// `INET_DIAG_BBRINFO`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BbrInfo {
    /// Max-filtered bottleneck bandwidth estimate, bytes/sec
    /// (assembled from the wire's `bbr_bw_lo | bbr_bw_hi << 32`).
    pub bw: u64,
    /// Min-filtered RTT (µs).
    pub min_rtt_us: u32,
    /// Pacing gain, fixed-point shifted left 8 bits (256 = 1.0).
    pub pacing_gain: u32,
    /// Cwnd gain, fixed-point shifted left 8 bits (256 = 1.0).
    pub cwnd_gain: u32,
}

/// Congestion-control–specific state (#163). Which variant a socket
/// reports depends on its CC algorithm (join against
/// [`InetSocket::congestion`](super::InetSocket)); algorithms without
/// a diag `get_info` hook (cubic, reno) report nothing. Request via
/// [`InetFilterBuilder::with_cc_info`](super::filter::InetFilterBuilder::with_cc_info)
/// — one kernel extension bit gates all three variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CcInfo {
    /// Vegas (`INET_DIAG_VEGASINFO`).
    Vegas(VegasInfo),
    /// DCTCP (`INET_DIAG_DCTCPINFO`).
    Dctcp(DctcpInfo),
    /// BBR (`INET_DIAG_BBRINFO`).
    Bbr(BbrInfo),
}

/// TCP information structure (from tcp_info).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpInfo {
    /// State.
    pub state: u8,
    /// CA state.
    pub ca_state: u8,
    /// Retransmits.
    pub retransmits: u8,
    /// Probes.
    pub probes: u8,
    /// Backoff.
    pub backoff: u8,
    /// Options.
    pub options: u8,
    /// Send/receive window scale.
    pub wscale: u8,
    /// Delivery rate app limited flag.
    pub delivery_rate_app_limited: bool,

    /// Retransmit timeout (usec).
    pub rto: u32,
    /// Estimated RTT (usec).
    pub rtt: u32,
    /// RTT variance (usec).
    pub rttvar: u32,
    /// Send MSS.
    pub snd_mss: u32,
    /// Receive MSS.
    pub rcv_mss: u32,

    /// Unacked packets.
    pub unacked: u32,
    /// Sacked packets.
    pub sacked: u32,
    /// Lost packets.
    pub lost: u32,
    /// Retransmitted packets.
    pub retrans: u32,
    /// Forward acknowledged packets.
    pub fackets: u32,

    /// Last data sent timestamp.
    pub last_data_sent: u32,
    /// Last ACK sent timestamp.
    pub last_ack_sent: u32,
    /// Last data received timestamp.
    pub last_data_recv: u32,
    /// Last ACK received timestamp.
    pub last_ack_recv: u32,

    /// Path MTU.
    pub pmtu: u32,
    /// Receive SSTHRESH.
    pub rcv_ssthresh: u32,
    /// Send SSTHRESH.
    pub snd_ssthresh: u32,
    /// Send CWND.
    pub snd_cwnd: u32,
    /// Advertised MSS.
    pub advmss: u32,
    /// Reordering.
    pub reordering: u32,

    /// Receive RTT (usec).
    pub rcv_rtt: u32,
    /// Receive space.
    pub rcv_space: u32,

    /// Total retransmits.
    pub total_retrans: u32,

    /// Pacing rate (bytes/sec).
    pub pacing_rate: u64,
    /// Max pacing rate (bytes/sec).
    pub max_pacing_rate: u64,
    /// Bytes ACKed.
    pub bytes_acked: u64,
    /// Bytes received.
    pub bytes_received: u64,
    /// Segments out.
    pub segs_out: u32,
    /// Segments in.
    pub segs_in: u32,

    /// Not sent bytes.
    pub notsent_bytes: u32,
    /// Minimum RTT (usec).
    pub min_rtt: u32,
    /// Data segments in.
    pub data_segs_in: u32,
    /// Data segments out.
    pub data_segs_out: u32,

    /// Delivery rate (bytes/sec).
    pub delivery_rate: u64,

    /// Busy time (usec).
    pub busy_time: u64,
    /// RWnd limited time (usec).
    pub rwnd_limited: u64,
    /// Sndbuf limited time (usec).
    pub sndbuf_limited: u64,

    /// Delivered packets.
    pub delivered: u32,
    /// Delivered with CE mark.
    pub delivered_ce: u32,

    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes retransmitted.
    pub bytes_retrans: u64,
    /// Duplicate SACKs received.
    pub dsack_dups: u32,
    /// Reordering seen.
    pub reord_seen: u32,

    /// Receive out-of-order rate.
    pub rcv_ooopack: u32,
    /// Send window.
    pub snd_wnd: u32,
    /// The receive window this end advertises, after scaling (bytes).
    pub rcv_wnd: u32,
    /// Rehash attempts, by PLB or after a timeout.
    pub rehash: u32,
    /// RTO timeouts, SYN/SYN-ACK and recurring ones included.
    pub total_rto: u16,
    /// RTO recoveries, an unfinished one included.
    pub total_rto_recoveries: u16,
    /// Time spent in RTO recoveries (ms), an unfinished one included.
    pub total_rto_time: u32,

    /// Accurate ECN (kernel 6.18+, #166): CE marks received.
    pub received_ce: u32,
    /// Accurate ECN: bytes delivered marked ECT(1).
    pub delivered_e1_bytes: u32,
    /// Accurate ECN: bytes delivered marked ECT(0).
    pub delivered_e0_bytes: u32,
    /// Accurate ECN: bytes delivered marked CE.
    pub delivered_ce_bytes: u32,
    /// Accurate ECN: bytes received marked ECT(1).
    pub received_e1_bytes: u32,
    /// Accurate ECN: bytes received marked ECT(0).
    pub received_e0_bytes: u32,
    /// Accurate ECN: bytes received marked CE.
    pub received_ce_bytes: u32,
    /// Accurate ECN: why it fell back, if it did (`TCP_ACCECN_*_FAIL_*` bits).
    pub accecn_fail_mode: u16,
    /// Accurate ECN: whether the AccECN option has been seen, and how.
    pub accecn_opt_seen: u16,
}

impl TcpInfo {
    /// Format as ss-style string with all non-zero metrics.
    ///
    /// This produces output similar to `ss -i`:
    /// ```text
    /// rtt:0.123/0.050 ato:40 mss:1448 cwnd:10 ssthresh:7 bytes_acked:12345
    /// ```
    pub fn format_ss(&self) -> String {
        let mut parts = Vec::new();

        // RTT (in milliseconds with 3 decimal places)
        if self.rtt > 0 {
            let rtt_ms = self.rtt as f64 / 1000.0;
            let rttvar_ms = self.rttvar as f64 / 1000.0;
            parts.push(format!("rtt:{:.3}/{:.3}", rtt_ms, rttvar_ms));
        }

        // RTO
        if self.rto > 0 && self.rto != 200_000 {
            // Skip default RTO
            parts.push(format!("rto:{}", self.rto / 1000));
        }

        // MSS
        if self.snd_mss > 0 {
            parts.push(format!("mss:{}", self.snd_mss));
        }

        // Congestion window
        if self.snd_cwnd > 0 {
            parts.push(format!("cwnd:{}", self.snd_cwnd));
        }

        // Slow-start threshold
        if self.snd_ssthresh > 0 && self.snd_ssthresh < u32::MAX {
            parts.push(format!("ssthresh:{}", self.snd_ssthresh));
        }

        // Bytes metrics
        if self.bytes_acked > 0 {
            parts.push(format!("bytes_acked:{}", self.bytes_acked));
        }
        if self.bytes_received > 0 {
            parts.push(format!("bytes_received:{}", self.bytes_received));
        }

        // Segments
        if self.segs_out > 0 {
            parts.push(format!("segs_out:{}", self.segs_out));
        }
        if self.segs_in > 0 {
            parts.push(format!("segs_in:{}", self.segs_in));
        }

        // Retransmissions
        if self.retrans > 0 {
            parts.push(format!("retrans:{}/{}", self.retrans, self.total_retrans));
        } else if self.total_retrans > 0 {
            parts.push(format!("retrans:0/{}", self.total_retrans));
        }

        // Delivery rate
        if self.delivery_rate > 0 {
            parts.push(format!(
                "delivery_rate:{}{}",
                format_rate_bps(self.delivery_rate * 8),
                if self.delivery_rate_app_limited {
                    "app_limited"
                } else {
                    ""
                }
            ));
        }

        // Pacing rate
        if self.pacing_rate > 0 && self.pacing_rate < u64::MAX {
            parts.push(format!(
                "pacing_rate:{}",
                format_rate_bps(self.pacing_rate * 8)
            ));
        }

        // Minimum RTT
        if self.min_rtt > 0 {
            parts.push(format!("minrtt:{:.3}", self.min_rtt as f64 / 1000.0));
        }

        // Receive window
        if self.rcv_space > 0 {
            parts.push(format!("rcv_space:{}", self.rcv_space));
        }

        parts.join(" ")
    }

    /// Format RTT as "rtt/rttvar" in milliseconds.
    pub fn rtt_str(&self) -> String {
        if self.rtt > 0 {
            format!(
                "{:.3}/{:.3}",
                self.rtt as f64 / 1000.0,
                self.rttvar as f64 / 1000.0
            )
        } else {
            String::new()
        }
    }

    /// Format congestion window.
    pub fn cwnd_str(&self) -> String {
        if self.snd_cwnd > 0 {
            format!("{}", self.snd_cwnd)
        } else {
            String::new()
        }
    }

    /// Format delivery rate as human-readable string.
    pub fn delivery_rate_str(&self) -> String {
        if self.delivery_rate > 0 {
            format_rate_bps(self.delivery_rate * 8)
        } else {
            String::new()
        }
    }

    /// Format pacing rate as human-readable string.
    pub fn pacing_rate_str(&self) -> String {
        if self.pacing_rate > 0 && self.pacing_rate < u64::MAX {
            format_rate_bps(self.pacing_rate * 8)
        } else {
            String::new()
        }
    }

    /// Get the send window scale (high nibble of wscale).
    pub fn snd_wscale(&self) -> u8 {
        self.wscale >> 4
    }

    /// Get the receive window scale (low nibble of wscale).
    pub fn rcv_wscale(&self) -> u8 {
        self.wscale & 0x0f
    }
}

/// Format bits per second as human-readable string.
fn format_rate_bps(bps: u64) -> String {
    if bps >= 1_000_000_000 {
        format!("{:.1}Gbps", bps as f64 / 1_000_000_000.0)
    } else if bps >= 1_000_000 {
        format!("{:.1}Mbps", bps as f64 / 1_000_000.0)
    } else if bps >= 1_000 {
        format!("{:.1}Kbps", bps as f64 / 1_000.0)
    } else {
        format!("{}bps", bps)
    }
}

/// Socket memory information.
///
/// Two different kernel attributes fill this struct, and they carry different
/// fields (#197):
///
/// - `INET_DIAG_MEMINFO` (requested by [`InetFilterBuilder::with_mem_info`]) is
///   `struct inet_diag_meminfo` — **four** counters, the four `u32` fields
///   below.
/// - `INET_DIAG_SKMEMINFO` (requested by [`InetFilterBuilder::with_sk_mem_info`]) is
///   `enum sk_meminfo_stats` — a superset that also carries the buffer sizes,
///   option memory, backlog and drops.
///
/// The five SKMEMINFO-only fields are therefore `Option<u32>`: `None` means
/// *you did not request `SKMEMINFO`*, which is a different statement from
/// `Some(0)`. They used to be a plain `u32` with no builder able to fill them,
/// so they read as a flat `0` forever and downstream dashboards graphed a
/// clean, believable, permanently-zero line.
///
/// Requesting both extensions is fine — the two arms **merge** into one
/// `MemInfo` rather than the later one clobbering the earlier.
///
/// [`InetFilterBuilder::with_mem_info`]: crate::sockdiag::filter::InetFilterBuilder::with_mem_info
/// [`InetFilterBuilder::with_sk_mem_info`]: crate::sockdiag::filter::InetFilterBuilder::with_sk_mem_info
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemInfo {
    /// Receive memory allocated (`sk_rmem_alloc`). Both extensions.
    pub rmem_alloc: u32,
    /// Write memory allocated (`sk_wmem_alloc`). Both extensions.
    pub wmem_alloc: u32,
    /// Forward allocation. Both extensions.
    pub fwd_alloc: u32,
    /// Write memory queued (`sk_wmem_queued`). Both extensions.
    pub wmem_queued: u32,
    /// Receive buffer size (`sk_rcvbuf`). `SKMEMINFO` only.
    pub rcvbuf: Option<u32>,
    /// Send buffer size (`sk_sndbuf`). `SKMEMINFO` only.
    pub sndbuf: Option<u32>,
    /// Option memory. `SKMEMINFO` only.
    pub optmem: Option<u32>,
    /// Backlog. `SKMEMINFO` only.
    pub backlog: Option<u32>,
    /// Drops. `SKMEMINFO` only.
    pub drops: Option<u32>,
}

impl MemInfo {
    /// Format as skmem style string.
    ///
    /// This produces output like ss's skmem() format:
    /// ```text
    /// skmem:(r0,rb131072,t0,tb16384,f0,w0,o0,bl0,d0)
    /// ```
    ///
    /// A field the kernel was never asked for prints as `-`; ss always
    /// requests `SKMEMINFO`, so its own output never has one.
    pub fn format_skmem(&self) -> String {
        fn f(v: Option<u32>) -> String {
            v.map_or_else(|| "-".to_string(), |v| v.to_string())
        }
        format!(
            "skmem:(r{},rb{},t{},tb{},f{},w{},o{},bl{},d{})",
            self.rmem_alloc,
            f(self.rcvbuf),
            self.wmem_alloc,
            f(self.sndbuf),
            self.fwd_alloc,
            self.wmem_queued,
            f(self.optmem),
            f(self.backlog),
            f(self.drops)
        )
    }

    /// Format as compact skmem string (only non-zero, present values).
    pub fn format_skmem_compact(&self) -> String {
        let mut parts = Vec::new();

        let mut push = |tag: &str, v: u32| {
            if v > 0 {
                parts.push(format!("{tag}{v}"));
            }
        };
        push("r", self.rmem_alloc);
        push("rb", self.rcvbuf.unwrap_or(0));
        push("t", self.wmem_alloc);
        push("tb", self.sndbuf.unwrap_or(0));
        push("f", self.fwd_alloc);
        push("w", self.wmem_queued);
        push("o", self.optmem.unwrap_or(0));
        push("bl", self.backlog.unwrap_or(0));
        push("d", self.drops.unwrap_or(0));

        if parts.is_empty() {
            "skmem:()".to_string()
        } else {
            format!("skmem:({})", parts.join(","))
        }
    }

    /// Are there any drops? `false` if `SKMEMINFO` was not requested.
    pub fn has_drops(&self) -> bool {
        self.drops.is_some_and(|d| d > 0)
    }

    /// Total memory in use (rmem + wmem).
    pub fn total_mem(&self) -> u64 {
        self.rmem_alloc as u64 + self.wmem_alloc as u64
    }
}

/// Timer information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Timer {
    /// No timer active.
    Off,
    /// Retransmit timer.
    On { expires_ms: u32, retrans: u8 },
    /// Keepalive timer.
    Keepalive { expires_ms: u32, probes: u8 },
    /// TIME-WAIT timer.
    TimeWait { expires_ms: u32 },
    /// Zero window probe timer.
    Probe { expires_ms: u32, retrans: u8 },
}

impl Timer {
    /// Parse timer info from idiag_timer, idiag_expires, idiag_retrans.
    pub fn from_raw(timer: u8, expires: u32, retrans: u8) -> Self {
        match timer {
            0 => Self::Off,
            1 => Self::On {
                expires_ms: expires,
                retrans,
            },
            2 => Self::Keepalive {
                expires_ms: expires,
                probes: retrans,
            },
            3 => Self::TimeWait {
                expires_ms: expires,
            },
            4 => Self::Probe {
                expires_ms: expires,
                retrans,
            },
            _ => Self::Off,
        }
    }

    /// Format like `ss -o`: `timer:(<name>,<expires>,<count>)`.
    ///
    /// Returns `None` when no timer is active ([`Timer::Off`]), so
    /// callers can skip the field entirely. The expiry is rendered
    /// in `ss(8)`'s `<hr>hr<min>min<sec>sec` / `<sec>.<ms>sec` style.
    pub fn describe(&self) -> Option<String> {
        let (name, expires_ms, count) = match self {
            Timer::Off => return None,
            Timer::On {
                expires_ms,
                retrans,
            } => ("on", *expires_ms, *retrans),
            Timer::Keepalive { expires_ms, probes } => ("keepalive", *expires_ms, *probes),
            Timer::TimeWait { expires_ms } => ("timewait", *expires_ms, 0),
            Timer::Probe {
                expires_ms,
                retrans,
            } => ("persist", *expires_ms, *retrans),
        };
        Some(format!(
            "timer:({name},{},{count})",
            format_timer_expires(expires_ms)
        ))
    }
}

/// Render a millisecond timer expiry the way `ss(8)` does.
fn format_timer_expires(msecs: u32) -> String {
    let total_secs = msecs / 1000;
    let ms = msecs % 1000;
    let secs = total_secs % 60;
    let total_min = total_secs / 60;
    let minutes = total_min % 60;
    let hrs = total_min / 60;
    if hrs > 0 {
        format!("{hrs}hr{minutes:02}min{secs:02}sec")
    } else if minutes > 0 {
        format!("{minutes}min{secs:02}sec")
    } else {
        format!("{secs}.{ms:03}sec")
    }
}

/// Aggregated socket statistics across all families.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::{Connection, SockDiag};
///
/// let conn = Connection::<SockDiag>::new()?;
/// let summary = conn.socket_summary().await?;
/// println!("{}", summary);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SocketSummary {
    /// TCP socket summary.
    pub tcp: TcpSummary,
    /// Total UDP sockets.
    pub udp: u32,
    /// Total raw sockets.
    pub raw: u32,
    /// Total Unix domain sockets.
    pub unix: u32,
}

impl fmt::Display for SocketSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total = self.tcp.total + self.udp + self.raw + self.unix;
        writeln!(f, "Total: {total}")?;
        writeln!(
            f,
            "TCP:   {} (estab {}, closed {}, orphaned 0, timewait {})",
            self.tcp.total, self.tcp.established, self.tcp.close, self.tcp.time_wait
        )?;
        writeln!(f, "UDP:   {}", self.udp)?;
        writeln!(f, "RAW:   {}", self.raw)?;
        write!(f, "UNIX:  {}", self.unix)
    }
}

/// Result of a batch socket destruction operation.
///
/// Contains the count of successfully destroyed sockets and any errors.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::netlink::SockDiag>::new()?;
/// # use nlink::sockdiag::{SocketFilter, TcpState};
/// let filter = SocketFilter::tcp()
///     .states(&[TcpState::Established])
///     .build_inet();
/// let result = conn.destroy_matching(&filter).await?;
/// println!("Destroyed {} sockets", result.destroyed);
/// for err in &result.errors {
///     eprintln!("Failed to destroy {:?}: {}", err.socket, err.error);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct DestroyResult {
    /// Number of sockets successfully destroyed.
    pub destroyed: u32,
    /// Errors encountered during destruction.
    pub errors: Vec<DestroyError>,
}

impl DestroyResult {
    /// True if all sockets were destroyed successfully.
    pub fn all_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Error from destroying a specific socket.
#[derive(Debug)]
pub struct DestroyError {
    /// The socket that failed to be destroyed (local -> remote).
    pub socket: std::net::SocketAddr,
    /// The error that occurred.
    pub error: crate::netlink::Error,
}

/// TCP socket statistics broken down by state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpSummary {
    /// Total TCP sockets.
    pub total: u32,
    /// ESTABLISHED state.
    pub established: u32,
    /// SYN-SENT state.
    pub syn_sent: u32,
    /// SYN-RECV state.
    pub syn_recv: u32,
    /// FIN-WAIT-1 state.
    pub fin_wait1: u32,
    /// FIN-WAIT-2 state.
    pub fin_wait2: u32,
    /// TIME-WAIT state.
    pub time_wait: u32,
    /// CLOSE state.
    pub close: u32,
    /// CLOSE-WAIT state.
    pub close_wait: u32,
    /// LAST-ACK state.
    pub last_ack: u32,
    /// LISTEN state.
    pub listen: u32,
    /// CLOSING state.
    pub closing: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_describe_matches_ss_format() {
        assert_eq!(Timer::Off.describe(), None);
        assert_eq!(
            Timer::Keepalive {
                expires_ms: 29_000,
                probes: 0
            }
            .describe()
            .as_deref(),
            Some("timer:(keepalive,29.000sec,0)")
        );
        assert_eq!(
            Timer::On {
                expires_ms: 62_500,
                retrans: 3
            }
            .describe()
            .as_deref(),
            Some("timer:(on,1min02sec,3)")
        );
        assert_eq!(
            Timer::TimeWait {
                expires_ms: 3_661_000
            }
            .describe()
            .as_deref(),
            Some("timer:(timewait,1hr01min01sec,0)")
        );
        assert_eq!(
            Timer::Probe {
                expires_ms: 200,
                retrans: 1
            }
            .describe()
            .as_deref(),
            Some("timer:(persist,0.200sec,1)")
        );
    }

    #[test]
    fn default_socket_summary_is_all_zeros() {
        let summary = SocketSummary::default();
        assert_eq!(summary.tcp.total, 0);
        assert_eq!(summary.tcp.established, 0);
        assert_eq!(summary.tcp.syn_sent, 0);
        assert_eq!(summary.tcp.syn_recv, 0);
        assert_eq!(summary.tcp.fin_wait1, 0);
        assert_eq!(summary.tcp.fin_wait2, 0);
        assert_eq!(summary.tcp.time_wait, 0);
        assert_eq!(summary.tcp.close, 0);
        assert_eq!(summary.tcp.close_wait, 0);
        assert_eq!(summary.tcp.last_ack, 0);
        assert_eq!(summary.tcp.listen, 0);
        assert_eq!(summary.tcp.closing, 0);
        assert_eq!(summary.udp, 0);
        assert_eq!(summary.raw, 0);
        assert_eq!(summary.unix, 0);
    }

    #[test]
    fn display_format_matches_expected_output() {
        let summary = SocketSummary {
            tcp: TcpSummary {
                total: 15,
                established: 8,
                syn_sent: 1,
                syn_recv: 0,
                fin_wait1: 0,
                fin_wait2: 1,
                time_wait: 3,
                close: 2,
                close_wait: 0,
                last_ack: 0,
                listen: 0,
                closing: 0,
            },
            udp: 5,
            raw: 1,
            unix: 10,
        };

        let output = format!("{}", summary);
        let lines: Vec<&str> = output.lines().collect();

        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "Total: 31");
        assert_eq!(
            lines[1],
            "TCP:   15 (estab 8, closed 2, orphaned 0, timewait 3)"
        );
        assert_eq!(lines[2], "UDP:   5");
        assert_eq!(lines[3], "RAW:   1");
        assert_eq!(lines[4], "UNIX:  10");
    }

    #[test]
    fn display_total_is_sum_of_all_socket_types() {
        let summary = SocketSummary {
            tcp: TcpSummary {
                total: 10,
                ..Default::default()
            },
            udp: 20,
            raw: 3,
            unix: 7,
        };

        let output = format!("{}", summary);
        let first_line = output.lines().next().unwrap();
        assert_eq!(first_line, "Total: 40");
    }
}
