//! Netfilter implementation for `Connection<Netfilter>`.
//!
//! This module provides methods for querying and managing connection tracking
//! entries via the NETLINK_NETFILTER protocol.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Netfilter};
//!
//! let conn = Connection::<Netfilter>::new()?;
//!
//! // List all connection tracking entries
//! let entries = conn.get_conntrack().await?;
//! for entry in &entries {
//!     println!("{:?} {:?}:{} -> {:?}:{}",
//!         entry.proto,
//!         entry.orig.src_ip,
//!         entry.orig.src_port.unwrap_or(0),
//!         entry.orig.dst_ip,
//!         entry.orig.dst_port.unwrap_or(0));
//! }
//! # Ok(())
//! # }
//! ```

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use winnow::{binary::be_u16, prelude::*};

use super::{
    builder::MessageBuilder,
    connection::Connection,
    error::{Error, Result},
    message::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST as NLMF_REQUEST},
    parse::PResult,
    protocol::Netfilter,
    types::AddressFamily,
};

// Netlink constants
use super::dump_frame::done_result;

const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300;

// Netfilter subsystem IDs
const NFNL_SUBSYS_CTNETLINK: u8 = 1;

// Conntrack message types
const IPCTNL_MSG_CT_NEW: u8 = 0;
const IPCTNL_MSG_CT_GET: u8 = 1;
const IPCTNL_MSG_CT_DELETE: u8 = 2;

// Conntrack attributes
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_STATUS: u16 = 3;
const CTA_PROTOINFO: u16 = 4;
const CTA_TIMEOUT: u16 = 7;
const CTA_MARK: u16 = 8;
const CTA_COUNTERS_ORIG: u16 = 9;
const CTA_COUNTERS_REPLY: u16 = 10;
const CTA_ID: u16 = 12;
const CTA_ZONE: u16 = 18;
const CTA_MARK_MASK: u16 = 21;
const CTA_FILTER: u16 = 25;
const CTA_STATUS_MASK: u16 = 26;

// CTA_FILTER nested attributes (enum ctattr_filter)
const CTA_FILTER_ORIG_FLAGS: u16 = 1;
const CTA_FILTER_REPLY_FLAGS: u16 = 2;

// Which fields of a CTA_FILTER tuple must match. The kernel keeps these in
// `net/netfilter/nf_internals.h` (`CTA_FILTER_F_*`), not in a UAPI header,
// so they have names of their own here: the UAPI audit looks up every
// kernel name in the headers.
const FILTER_IP_SRC: u32 = 1 << 0;
const FILTER_IP_DST: u32 = 1 << 1;
const FILTER_PROTO_NUM: u32 = 1 << 3;
const FILTER_PROTO_SRC_PORT: u32 = 1 << 4;
const FILTER_PROTO_DST_PORT: u32 = 1 << 5;

// Tuple attributes
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;

// IP attributes
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;

// Proto attributes
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;
const CTA_PROTO_ICMP_ID: u16 = 4;
const CTA_PROTO_ICMP_TYPE: u16 = 5;
const CTA_PROTO_ICMP_CODE: u16 = 6;

// Protoinfo attributes
const CTA_PROTOINFO_TCP: u16 = 1;
const CTA_PROTOINFO_TCP_STATE: u16 = 1;

// Counter attributes
const CTA_COUNTERS_PACKETS: u16 = 1;
const CTA_COUNTERS_BYTES: u16 = 2;

// Netlink header size
const NLMSG_HDRLEN: usize = 16;

/// IP protocol numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpProtocol {
    /// TCP (6)
    Tcp,
    /// UDP (17)
    Udp,
    /// ICMP (1)
    Icmp,
    /// ICMPv6 (58)
    Icmpv6,
    /// Other protocol
    Other(u8),
}

impl IpProtocol {
    fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            58 => Self::Icmpv6,
            other => Self::Other(other),
        }
    }

    /// Get the protocol number.
    pub fn number(&self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmpv6 => 58,
            Self::Other(n) => *n,
        }
    }
}

/// TCP connection tracking state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TcpConntrackState {
    None,
    SynSent,
    SynRecv,
    Established,
    FinWait,
    CloseWait,
    LastAck,
    TimeWait,
    Close,
    Listen,
    SynSent2,
    Max,
    Ignore,
    Retrans,
    Unack,
    Unknown(u8),
}

impl TcpConntrackState {
    fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::None,
            1 => Self::SynSent,
            2 => Self::SynRecv,
            3 => Self::Established,
            4 => Self::FinWait,
            5 => Self::CloseWait,
            6 => Self::LastAck,
            7 => Self::TimeWait,
            8 => Self::Close,
            9 => Self::Listen,
            10 => Self::SynSent2,
            11 => Self::Max,
            12 => Self::Ignore,
            13 => Self::Retrans,
            14 => Self::Unack,
            other => Self::Unknown(other),
        }
    }
}

/// A connection tracking tuple (source/destination).
#[derive(Debug, Clone, Default)]
pub struct ConntrackTuple {
    /// Source IP address.
    pub src_ip: Option<IpAddr>,
    /// Destination IP address.
    pub dst_ip: Option<IpAddr>,
    /// Source port (TCP/UDP).
    pub src_port: Option<u16>,
    /// Destination port (TCP/UDP).
    pub dst_port: Option<u16>,
    /// ICMP ID.
    pub icmp_id: Option<u16>,
    /// ICMP type.
    pub icmp_type: Option<u8>,
    /// ICMP code.
    pub icmp_code: Option<u8>,
}

impl ConntrackTuple {
    /// IPv4 tuple with source + destination addresses (no L4 ports yet).
    pub fn v4(src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        Self {
            src_ip: Some(IpAddr::V4(src)),
            dst_ip: Some(IpAddr::V4(dst)),
            ..Default::default()
        }
    }

    /// IPv6 tuple with source + destination addresses (no L4 ports yet).
    pub fn v6(src: Ipv6Addr, dst: Ipv6Addr) -> Self {
        Self {
            src_ip: Some(IpAddr::V6(src)),
            dst_ip: Some(IpAddr::V6(dst)),
            ..Default::default()
        }
    }

    /// Set TCP/UDP source + destination ports.
    pub fn ports(mut self, src: u16, dst: u16) -> Self {
        self.src_port = Some(src);
        self.dst_port = Some(dst);
        self
    }

    /// Set ICMP type / code / id (for ICMP / ICMPv6 tuples).
    pub fn icmp(mut self, icmp_type: u8, code: u8, id: u16) -> Self {
        self.icmp_type = Some(icmp_type);
        self.icmp_code = Some(code);
        self.icmp_id = Some(id);
        self
    }

    /// Return the mirrored tuple — src/dst swapped, ports swapped. Useful
    /// for synthesising the reply tuple of a NAT-less injection.
    pub fn mirror(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            icmp_id: self.icmp_id,
            icmp_type: self.icmp_type,
            icmp_code: self.icmp_code,
        }
    }
}

/// Connection-tracking status flags. Mirrors the kernel's
/// `enum ip_conntrack_status` (IPS_*).
///
/// At least `CONFIRMED` is required for `add_conntrack` — the kernel
/// rejects unconfirmed entries on the netlink path with `-EINVAL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConntrackStatus(u32);

impl ConntrackStatus {
    pub const EXPECTED: Self = Self(0x0001);
    pub const SEEN_REPLY: Self = Self(0x0002);
    pub const ASSURED: Self = Self(0x0004);
    pub const CONFIRMED: Self = Self(0x0008);
    pub const SRC_NAT: Self = Self(0x0010);
    pub const DST_NAT: Self = Self(0x0020);
    pub const SEQ_ADJUST: Self = Self(0x0040);
    pub const SRC_NAT_DONE: Self = Self(0x0080);
    pub const DST_NAT_DONE: Self = Self(0x0100);
    pub const DYING: Self = Self(0x0200);
    pub const FIXED_TIMEOUT: Self = Self(0x0400);
    pub const TEMPLATE: Self = Self(0x0800);
    pub const NAT_CLASH: Self = Self(0x1000);
    pub const HELPER: Self = Self(0x2000);
    pub const OFFLOAD: Self = Self(0x4000);
    pub const HW_OFFLOAD: Self = Self(0x8000);

    pub const fn empty() -> Self {
        Self(0)
    }
    pub const fn bits(self) -> u32 {
        self.0
    }
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for ConntrackStatus {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for ConntrackStatus {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl TcpConntrackState {
    /// Encode as the wire byte the kernel expects in
    /// `CTA_PROTOINFO_TCP_STATE`.
    fn to_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::SynSent => 1,
            Self::SynRecv => 2,
            Self::Established => 3,
            Self::FinWait => 4,
            Self::CloseWait => 5,
            Self::LastAck => 6,
            Self::TimeWait => 7,
            Self::Close => 8,
            Self::Listen => 9,
            Self::SynSent2 => 10,
            Self::Max => 11,
            Self::Ignore => 12,
            Self::Retrans => 13,
            Self::Unack => 14,
            Self::Unknown(v) => v,
        }
    }
}

/// Packet/byte counters.
#[derive(Debug, Clone, Default)]
pub struct ConntrackCounters {
    /// Number of packets.
    pub packets: u64,
    /// Number of bytes.
    pub bytes: u64,
}

/// A connection tracking entry, as a dump or an event returns it.
///
/// Delete one with [`Connection::del_conntrack_entry`], or start a
/// builder from it with [`ConntrackBuilder::from_entry`].
/// `#[non_exhaustive]`, so that the next field the kernel reports is not
/// a break (#883).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConntrackEntry {
    /// Address family: [`AddressFamily::Inet`] or
    /// [`AddressFamily::Inet6`], from the message's nfgenmsg.
    pub family: AddressFamily,
    /// IP protocol (TCP, UDP, ICMP, etc.).
    pub proto: IpProtocol,
    /// Original direction tuple.
    pub orig: ConntrackTuple,
    /// Reply direction tuple.
    pub reply: ConntrackTuple,
    /// TCP connection state (if TCP).
    pub tcp_state: Option<TcpConntrackState>,
    /// Timeout in seconds.
    pub timeout: Option<u32>,
    /// Connection mark.
    pub mark: Option<u32>,
    /// Connection status flags.
    pub status: Option<u32>,
    /// Connection ID.
    pub id: Option<u32>,
    /// Conntrack zone (`CTA_ZONE`). `None` is the default zone, 0: the
    /// kernel reports a zone only when it is another one. A zone set for
    /// one direction only (`CTA_TUPLE_ZONE`) is not read.
    pub zone: Option<u16>,
    /// Original direction counters.
    pub counters_orig: Option<ConntrackCounters>,
    /// Reply direction counters.
    pub counters_reply: Option<ConntrackCounters>,
}

impl Default for ConntrackEntry {
    fn default() -> Self {
        Self {
            family: AddressFamily::Unspec,
            proto: IpProtocol::Other(0),
            orig: ConntrackTuple::default(),
            reply: ConntrackTuple::default(),
            tcp_state: None,
            timeout: None,
            mark: None,
            status: None,
            id: None,
            zone: None,
            counters_orig: None,
            counters_reply: None,
        }
    }
}

/// Conntrack multicast group — passed to
/// [`Connection::<Netfilter>::subscribe`].
///
/// The kernel exposes six conntrack-related groups; the three
/// "expectation" ones (`ExpNew` / `ExpUpdate` / `ExpDestroy`) carry
/// `ct_expect` messages, not regular entries — `subscribe_all`
/// skips them since the parser doesn't understand the expectation
/// shape yet (Plan 137 PR C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConntrackGroup {
    /// `NFNLGRP_CONNTRACK_NEW` (1) — new conntrack entries.
    New,
    /// `NFNLGRP_CONNTRACK_UPDATE` (2) — updates to existing entries.
    /// Note: kernel uses the same `IPCTNL_MSG_CT_NEW` wire type for
    /// both NEW and UPDATE, so a stream that subscribes to both
    /// can't tell them apart from message-type alone — they all
    /// surface as [`ConntrackEvent::New`]. To monitor *only* updates,
    /// subscribe to `Update` alone.
    Update,
    /// `NFNLGRP_CONNTRACK_DESTROY` (3) — entry destroyed.
    Destroy,
    /// `NFNLGRP_CONNTRACK_EXP_NEW` (4) — new expectation. Today the
    /// stream parser ignores expectation messages; subscribing here
    /// just buffers them in the kernel queue. Wired up under Plan 137
    /// PR C.
    ExpNew,
    /// `NFNLGRP_CONNTRACK_EXP_DESTROY` (6).
    ExpDestroy,
}

impl ConntrackGroup {
    /// Map to the kernel multicast group ID (1-indexed).
    pub fn to_kernel_group(self) -> u32 {
        match self {
            Self::New => 1,
            Self::Update => 2,
            Self::Destroy => 3,
            Self::ExpNew => 4,
            Self::ExpDestroy => 6,
        }
    }
}

/// An event delivered on a conntrack multicast stream.
///
/// `New` covers both fresh entries and update notifications — the
/// kernel uses the same `IPCTNL_MSG_CT_NEW` wire shape for both, so a
/// stream that subscribed to both groups can't distinguish them from
/// the message alone. To monitor only updates, subscribe to
/// [`ConntrackGroup::Update`] in isolation. `Destroy` is unambiguous:
/// it always corresponds to `IPCTNL_MSG_CT_DELETE`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ConntrackEvent {
    /// A new entry was added, or an existing one was updated. See
    /// the type-level docs for the New-vs-Update caveat.
    New(ConntrackEntry),
    /// An entry was destroyed (timed out, deleted, connection closed).
    Destroy(ConntrackEntry),
}

/// Build a `ConntrackEvent` from the netlink message type byte +
/// the body (post-nlmsghdr). Returns `None` for messages we don't
/// recognise (e.g. expectation messages, error frames).
pub(crate) fn parse_conntrack_event(msg_type: u16, body: &[u8]) -> Option<ConntrackEvent> {
    // Subsystem must be ctnetlink.
    if (msg_type >> 8) != NFNL_SUBSYS_CTNETLINK as u16 {
        return None;
    }
    let entry = parse_conntrack_body(body)?;
    match msg_type & 0xFF {
        t if t == IPCTNL_MSG_CT_NEW as u16 => Some(ConntrackEvent::New(entry)),
        t if t == IPCTNL_MSG_CT_DELETE as u16 => Some(ConntrackEvent::Destroy(entry)),
        _ => None,
    }
}

/// Builder for a conntrack entry — used by `add_conntrack`,
/// `update_conntrack`, and `del_conntrack`.
///
/// Address family is fixed at construction (`new_v4` / `new_v6`); the
/// builder validates that any IP supplied matches that family.
///
/// For `add_conntrack` the kernel requires a non-empty `orig` tuple
/// with src + dst + proto fields, plus `status(ConntrackStatus::CONFIRMED)`
/// — without it the kernel will reject the message with `-EINVAL`.
/// `del_conntrack` only needs enough of the tuple to identify the entry;
/// [`Self::from_entry`] builds that from a dumped entry.
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless submitted to the connection"]
pub struct ConntrackBuilder {
    family: u8,
    proto: IpProtocol,
    orig: ConntrackTuple,
    reply: Option<ConntrackTuple>,
    status: Option<ConntrackStatus>,
    timeout: Option<Duration>,
    mark: Option<u32>,
    tcp_state: Option<TcpConntrackState>,
    id: Option<u32>,
    zone: Option<u16>,
}

impl ConntrackBuilder {
    /// IPv4 conntrack entry for the given L4 protocol.
    pub fn new_v4(proto: IpProtocol) -> Self {
        Self {
            family: libc::AF_INET as u8,
            proto,
            orig: ConntrackTuple::default(),
            reply: None,
            status: None,
            timeout: None,
            mark: None,
            tcp_state: None,
            id: None,
            zone: None,
        }
    }

    /// IPv6 conntrack entry for the given L4 protocol.
    pub fn new_v6(proto: IpProtocol) -> Self {
        Self {
            family: libc::AF_INET6 as u8,
            proto,
            ..Self::new_v4(proto)
        }
    }

    /// A builder naming `entry`, as a dump or an event returned it: its
    /// family, protocol, original tuple, zone and id (#883). That is what
    /// [`Connection::del_conntrack`] needs, and what
    /// [`Connection::del_conntrack_entry`] sends.
    ///
    /// It names the entry; it does not copy it. The reply tuple, status,
    /// mark, timeout and TCP state stay unset, so set what an
    /// `update_conntrack` should change.
    ///
    /// An entry with no family (one not from the kernel) takes it from
    /// its original tuple's addresses.
    pub fn from_entry(entry: &ConntrackEntry) -> Self {
        Self {
            family: entry.effective_family().into(),
            orig: entry.orig.clone(),
            id: entry.id,
            zone: entry.zone,
            ..Self::new_v4(entry.proto)
        }
    }

    /// The address family of this entry: [`AddressFamily::Inet`] or
    /// [`AddressFamily::Inet6`].
    pub fn family(&self) -> AddressFamily {
        AddressFamily::from(self.family)
    }

    /// Set the original-direction tuple (client → server).
    pub fn orig(mut self, tuple: ConntrackTuple) -> Self {
        self.orig = tuple;
        self
    }

    /// Set the reply-direction tuple. If omitted, `add_conntrack`
    /// auto-mirrors `orig` (which is correct for symmetric flows
    /// without NAT).
    pub fn reply(mut self, tuple: ConntrackTuple) -> Self {
        self.reply = Some(tuple);
        self
    }

    /// Set the status flag bitmask. `ConntrackStatus::CONFIRMED` is the
    /// minimum the kernel accepts; for an entry the firewall should
    /// short-circuit, also include `SEEN_REPLY`.
    pub fn status(mut self, s: ConntrackStatus) -> Self {
        self.status = Some(s);
        self
    }

    /// Set the entry timeout.
    ///
    /// **Required for TCP injections that also set
    /// [`tcp_state`](Self::tcp_state).** The kernel's TCP state machine
    /// won't accept an entry without a timeout — `add_conntrack`
    /// returns `Error::InvalidArgument` (EINVAL). For UDP / ICMP it's
    /// optional but recommended (kernel defaults are protocol-specific
    /// and surprisingly long, e.g. 30 s for unreplied UDP).
    ///
    /// The kernel keeps whole seconds and expires an entry whose timeout
    /// is 0 at once, so a fraction rounds up: 500 ms is 1 s (#603).
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = Some(d);
        self
    }

    /// Set the connection mark.
    pub fn mark(mut self, mark: u32) -> Self {
        self.mark = Some(mark);
        self
    }

    /// Set the TCP state (encoded under `CTA_PROTOINFO/CTA_PROTOINFO_TCP`).
    /// Only meaningful when `proto = IpProtocol::Tcp`.
    ///
    /// **Pair with [`timeout`](Self::timeout)** — the kernel rejects a
    /// TCP add that has `tcp_state` set but no timeout (EINVAL). The
    /// state machine needs the timeout for its bookkeeping.
    pub fn tcp_state(mut self, state: TcpConntrackState) -> Self {
        self.tcp_state = Some(state);
        self
    }

    /// Set the conntrack ID. Used by `del_conntrack` when identifying
    /// by ID rather than tuple.
    pub fn id(mut self, id: u32) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the conntrack zone (default 0).
    pub fn zone(mut self, zone: u16) -> Self {
        self.zone = Some(zone);
        self
    }

    /// Emit this entry's attributes into a request `MessageBuilder`
    /// after the nfgenmsg header has been appended.
    ///
    /// `for_delete = true` skips fields the kernel ignores on
    /// `IPCTNL_MSG_CT_DELETE` (status / timeout / protoinfo / mark).
    /// `mirror_reply = true` synthesises a reply tuple from `orig` if
    /// the builder has none — handy for `add_conntrack` of symmetric
    /// flows without explicit NAT.
    fn append_attrs(&self, b: &mut MessageBuilder, for_delete: bool, mirror_reply: bool) {
        if !self.orig.is_empty() {
            append_tuple(b, CTA_TUPLE_ORIG, self.proto, &self.orig);
        }

        let mirrored;
        let reply: Option<&ConntrackTuple> = match (&self.reply, mirror_reply) {
            (Some(r), _) => Some(r),
            (None, true) if !self.orig.is_empty() => {
                mirrored = self.orig.mirror();
                Some(&mirrored)
            }
            _ => None,
        };
        if let Some(r) = reply {
            append_tuple(b, CTA_TUPLE_REPLY, self.proto, r);
        }

        if for_delete {
            // For DELETE, only the tuple (or ID) and zone matter.
            if let Some(z) = self.zone {
                b.append_attr_u16_be(CTA_ZONE, z);
            }
            if let Some(id) = self.id {
                b.append_attr_u32_be(CTA_ID, id);
            }
            return;
        }

        if let Some(s) = self.status {
            b.append_attr_u32_be(CTA_STATUS, s.bits());
        }
        if let Some(t) = self.timeout {
            // CTA_TIMEOUT is a u32 of seconds. `as u32` on the u64 from
            // as_secs() *wraps*, so a Duration beyond ~136 years silently
            // became a tiny timeout rather than a large one. Saturate (#211).
            // A fraction rounds up: the kernel expires an entry whose
            // timeout is 0 at once, which is what truncating made of any
            // sub-second timeout (#603).
            let secs = t.as_secs() + u64::from(t.subsec_nanos() > 0);
            let secs = secs.min(u64::from(u32::MAX)) as u32;
            b.append_attr_u32_be(CTA_TIMEOUT, secs);
        }
        if let Some(m) = self.mark {
            b.append_attr_u32_be(CTA_MARK, m);
        }
        if let Some(state) = self.tcp_state
            && self.proto == IpProtocol::Tcp
        {
            let outer = b.nest_start(CTA_PROTOINFO);
            let tcp = b.nest_start(CTA_PROTOINFO_TCP);
            b.append_attr_u8(CTA_PROTOINFO_TCP_STATE, state.to_u8());
            b.nest_end(tcp);
            b.nest_end(outer);
        }
        if let Some(z) = self.zone {
            b.append_attr_u16_be(CTA_ZONE, z);
        }
        if let Some(id) = self.id {
            b.append_attr_u32_be(CTA_ID, id);
        }
    }
}

/// Which conntrack entries a filtered dump or flush touches (#882), like
/// the options of `conntrack -L` and `conntrack -D`. Every criterion set
/// must match.
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// use nlink::netlink::netfilter::{ConntrackFilter, IpProtocol};
/// use nlink::netlink::{Connection, Netfilter};
///
/// let nf = Connection::<Netfilter>::new()?;
/// // conntrack -D -p udp --dport 5000
/// let video = ConntrackFilter::new().proto(IpProtocol::Udp).orig_dst_port(5000);
/// nf.flush_conntrack_matching(&video).await?;
/// # Ok(())
/// # }
/// ```
///
/// The kernel is given the filter where it can apply it, and nlink applies
/// it again to every entry the kernel returns, so a kernel that ignores it
/// costs time, not entries: see
/// [`get_conntrack_matching`](Connection::get_conntrack_matching) and
/// [`flush_conntrack_matching`](Connection::flush_conntrack_matching).
/// Ports match exactly: a range is one filter per port, or one dump
/// checked with [`matches`](Self::matches).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use = "a filter does nothing until a dump or a flush is given it"]
pub struct ConntrackFilter {
    family: Option<AddressFamily>,
    proto: Option<IpProtocol>,
    orig: TupleMatch,
    reply: TupleMatch,
    zone: Option<u16>,
    mark: Option<(u32, u32)>,
    status: Option<(u32, u32)>,
}

/// The fields of one direction's tuple a [`ConntrackFilter`] compares.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TupleMatch {
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
}

impl TupleMatch {
    fn has_ports(&self) -> bool {
        self.src_port.is_some() || self.dst_port.is_some()
    }

    fn matches(&self, tuple: &ConntrackTuple) -> bool {
        self.src.is_none_or(|a| tuple.src_ip == Some(a))
            && self.dst.is_none_or(|a| tuple.dst_ip == Some(a))
            && self.src_port.is_none_or(|p| tuple.src_port == Some(p))
            && self.dst_port.is_none_or(|p| tuple.dst_port == Some(p))
    }

    /// The `CTA_FILTER` flags for this tuple, `proto` asking for the
    /// protocol too. An IPv6 address is left out: see
    /// [`ConntrackFilter::append_kernel_filter`].
    fn kernel_flags(&self, v6: bool, proto: bool) -> u32 {
        let mut flags = 0;
        if self.src.is_some() && !v6 {
            flags |= FILTER_IP_SRC;
        }
        if self.dst.is_some() && !v6 {
            flags |= FILTER_IP_DST;
        }
        if proto {
            flags |= FILTER_PROTO_NUM;
        }
        if self.src_port.is_some() {
            flags |= FILTER_PROTO_SRC_PORT;
        }
        if self.dst_port.is_some() {
            flags |= FILTER_PROTO_DST_PORT;
        }
        flags
    }
}

impl ConntrackFilter {
    /// A filter with no criterion yet, which matches every entry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Only entries of `family`: [`AddressFamily::Inet`] or
    /// [`AddressFamily::Inet6`]. An address sets it too; with neither, a
    /// dump or a flush covers both families.
    pub fn family(mut self, family: AddressFamily) -> Self {
        self.family = Some(family);
        self
    }

    /// Only entries of this protocol. A port needs TCP or UDP.
    pub fn proto(mut self, proto: IpProtocol) -> Self {
        self.proto = Some(proto);
        self
    }

    /// Only entries whose original source address is `addr`: `--orig-src`.
    pub fn orig_src(mut self, addr: impl Into<IpAddr>) -> Self {
        self.orig.src = Some(addr.into());
        self
    }

    /// Only entries whose original destination address is `addr`:
    /// `--orig-dst`.
    pub fn orig_dst(mut self, addr: impl Into<IpAddr>) -> Self {
        self.orig.dst = Some(addr.into());
        self
    }

    /// Only entries whose original source port is `port`: `--sport`.
    pub fn orig_src_port(mut self, port: u16) -> Self {
        self.orig.src_port = Some(port);
        self
    }

    /// Only entries whose original destination port is `port`: `--dport`.
    pub fn orig_dst_port(mut self, port: u16) -> Self {
        self.orig.dst_port = Some(port);
        self
    }

    /// Only entries whose reply source address is `addr`: `--reply-src`.
    pub fn reply_src(mut self, addr: impl Into<IpAddr>) -> Self {
        self.reply.src = Some(addr.into());
        self
    }

    /// Only entries whose reply destination address is `addr`:
    /// `--reply-dst`.
    pub fn reply_dst(mut self, addr: impl Into<IpAddr>) -> Self {
        self.reply.dst = Some(addr.into());
        self
    }

    /// Only entries whose reply source port is `port`: `--reply-port-src`.
    pub fn reply_src_port(mut self, port: u16) -> Self {
        self.reply.src_port = Some(port);
        self
    }

    /// Only entries whose reply destination port is `port`:
    /// `--reply-port-dst`.
    pub fn reply_dst_port(mut self, port: u16) -> Self {
        self.reply.dst_port = Some(port);
        self
    }

    /// Only entries in `zone`. 0 is the default zone.
    pub fn zone(mut self, zone: u16) -> Self {
        self.zone = Some(zone);
        self
    }

    /// Only entries whose mark, masked with `mask`, is `value`:
    /// `--mark value/mask`. An entry with no mark has mark 0.
    pub fn mark(mut self, value: u32, mask: u32) -> Self {
        self.mark = Some((value, mask));
        self
    }

    /// Only entries whose status, masked with `mask`, is `value`: with
    /// `ConntrackStatus::ASSURED` for both, the assured ones.
    pub fn status(mut self, value: ConntrackStatus, mask: ConntrackStatus) -> Self {
        self.status = Some((value.bits(), mask.bits()));
        self
    }

    /// Whether the filter sets no criterion, and so matches every entry.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Whether `entry` matches. A dump checks this on every entry the
    /// kernel returns, whatever the kernel filtered.
    pub fn matches(&self, entry: &ConntrackEntry) -> bool {
        self.family.is_none_or(|f| entry.effective_family() == f)
            && self.proto.is_none_or(|p| entry.proto == p)
            && self.orig.matches(&entry.orig)
            && self.reply.matches(&entry.reply)
            && self.zone.is_none_or(|z| entry.zone.unwrap_or(0) == z)
            && self
                .mark
                .is_none_or(|(value, mask)| entry.mark.unwrap_or(0) & mask == value)
            && self
                .status
                .is_none_or(|(value, mask)| entry.status.unwrap_or(0) & mask == value)
    }

    /// The families a dump or a flush asks for, after checking that the
    /// kernel and nlink would read the filter alike.
    fn families(&self) -> Result<Vec<u8>> {
        let invalid = |why: &str| Err(Error::invalid_message(format!("conntrack filter: {why}")));
        let tcp_or_udp = matches!(self.proto, Some(IpProtocol::Tcp | IpProtocol::Udp));
        if (self.orig.has_ports() || self.reply.has_ports()) && !tcp_or_udp {
            // The kernel compares ports for TCP and UDP only: with any other
            // protocol it would match every port.
            return invalid("a port needs `proto(IpProtocol::Tcp)` or `proto(IpProtocol::Udp)`");
        }
        if self.status.is_some_and(|(_, mask)| mask == 0) {
            return invalid("a status mask of 0 matches every entry, and the kernel refuses it");
        }
        let mut family = match self.family {
            None => None,
            Some(f @ (AddressFamily::Inet | AddressFamily::Inet6)) => Some(f),
            Some(other) => {
                return invalid(&format!("family {other:?}: conntrack is Inet or Inet6"));
            }
        };
        let addresses = [self.orig.src, self.orig.dst, self.reply.src, self.reply.dst];
        for addr in addresses.into_iter().flatten() {
            let of_addr = if addr.is_ipv4() {
                AddressFamily::Inet
            } else {
                AddressFamily::Inet6
            };
            match family {
                Some(f) if f != of_addr => {
                    return invalid(&format!("address {addr} is not of family {f:?}"));
                }
                _ => family = Some(of_addr),
            }
        }
        Ok(match family {
            Some(f) => vec![u8::from(f)],
            None => vec![libc::AF_INET as u8, libc::AF_INET6 as u8],
        })
    }

    /// Whether a kernel that filters a flush can be given this filter.
    /// Not one with an IPv6 address: see
    /// [`append_kernel_filter`](Self::append_kernel_filter).
    fn kernel_can_flush(&self) -> bool {
        let addresses = [self.orig.src, self.orig.dst, self.reply.src, self.reply.dst];
        !addresses.into_iter().flatten().any(|a| a.is_ipv6())
    }

    /// Append the filter, for `family`, to a ctnetlink dump or delete.
    ///
    /// An IPv6 address is left out. The kernel compares one with
    /// `!ipv6_addr_cmp()`, which is true when the two are *equal*
    /// (`ctnetlink_filter_match_tuple`, in every kernel since 5.8, which
    /// added `CTA_FILTER`, through 6.12 and the mainline #882 was checked
    /// against), so it keeps every entry but the ones the filter names. nlink
    /// compares IPv6 addresses itself.
    fn append_kernel_filter(&self, b: &mut MessageBuilder, family: u8) {
        let v6 = family == libc::AF_INET6 as u8;
        let orig_flags = self.orig.kernel_flags(v6, self.proto.is_some());
        // A port needs the protocol in its own tuple's flags.
        let reply_flags = self.reply.kernel_flags(v6, self.reply.has_ports());
        let proto = self.proto.unwrap_or(IpProtocol::Other(0));
        for (attr, tuple, flags) in [
            (CTA_TUPLE_ORIG, &self.orig, orig_flags),
            (CTA_TUPLE_REPLY, &self.reply, reply_flags),
        ] {
            if flags == 0 {
                continue;
            }
            let outer = b.nest_start(attr);
            if flags & (FILTER_IP_SRC | FILTER_IP_DST) != 0 {
                let ip = b.nest_start(CTA_TUPLE_IP);
                for (addr, v4_attr) in [(tuple.src, CTA_IP_V4_SRC), (tuple.dst, CTA_IP_V4_DST)] {
                    if let Some(IpAddr::V4(a)) = addr {
                        b.append_attr(v4_attr, &a.octets());
                    }
                }
                b.nest_end(ip);
            }
            if flags & FILTER_PROTO_NUM != 0 {
                let p = b.nest_start(CTA_TUPLE_PROTO);
                b.append_attr_u8(CTA_PROTO_NUM, proto.number());
                if let Some(port) = tuple.src_port {
                    b.append_attr_u16_be(CTA_PROTO_SRC_PORT, port);
                }
                if let Some(port) = tuple.dst_port {
                    b.append_attr_u16_be(CTA_PROTO_DST_PORT, port);
                }
                b.nest_end(p);
            }
            b.nest_end(outer);
        }
        if orig_flags | reply_flags != 0 {
            let filter = b.nest_start(CTA_FILTER);
            if orig_flags != 0 {
                b.append_attr_u32(CTA_FILTER_ORIG_FLAGS, orig_flags);
            }
            if reply_flags != 0 {
                b.append_attr_u32(CTA_FILTER_REPLY_FLAGS, reply_flags);
            }
            b.nest_end(filter);
        }
        if let Some(zone) = self.zone {
            b.append_attr_u16_be(CTA_ZONE, zone);
        }
        if let Some((value, mask)) = self.mark {
            b.append_attr_u32_be(CTA_MARK, value);
            b.append_attr_u32_be(CTA_MARK_MASK, mask);
        }
        if let Some((value, mask)) = self.status {
            b.append_attr_u32_be(CTA_STATUS, value);
            b.append_attr_u32_be(CTA_STATUS_MASK, mask);
        }
    }
}

/// Whether the running kernel filters a ctnetlink flush by `CTA_FILTER`
/// (6.12+). Before 6.12 it refuses `CTA_FILTER` on a flush (5.8 to 6.11,
/// `EOPNOTSUPP`), or does not know it and flushes every entry (before 5.8).
/// And before 6.8 its filter parses `CTA_ZONE` but never compares it, so a
/// zone matched every zone. A flush is sent there only when it is known to
/// filter.
fn kernel_filters_flush() -> bool {
    filters_a_flush(crate::netlink::kernel_version())
}

fn filters_a_flush(kernel: (u32, u32)) -> bool {
    kernel >= (6, 12)
}

impl ConntrackEntry {
    /// The entry's family, or, for one not from the kernel, its original
    /// tuple's.
    fn effective_family(&self) -> AddressFamily {
        match self.family {
            AddressFamily::Inet | AddressFamily::Inet6 => self.family,
            _ => match self.orig.src_ip.or(self.orig.dst_ip) {
                Some(IpAddr::V6(_)) => AddressFamily::Inet6,
                _ => AddressFamily::Inet,
            },
        }
    }
}

impl ConntrackTuple {
    /// True iff every Option field is `None` — used to detect a
    /// builder that hasn't had its `orig` set.
    fn is_empty(&self) -> bool {
        self.src_ip.is_none()
            && self.dst_ip.is_none()
            && self.src_port.is_none()
            && self.dst_port.is_none()
            && self.icmp_id.is_none()
            && self.icmp_type.is_none()
            && self.icmp_code.is_none()
    }
}

/// Append the 4-byte nfgenmsg header onto a request builder.
fn append_nfgenmsg(b: &mut MessageBuilder, family: u8) {
    append_nfgenmsg_version(b, family, 0); // NFNETLINK_V0
}

/// [`append_nfgenmsg`] with an explicit version. ctnetlink reads it on a
/// flush, where only a version that is not 0 makes it honour the family
/// (#880). The headers name no version but `NFNETLINK_V0`.
fn append_nfgenmsg_version(b: &mut MessageBuilder, family: u8, version: u8) {
    b.append_bytes(&[family, version, 0, 0]); // family, version, res_id=0
}

/// Append a `CTA_TUPLE_*` nested attribute (one of `CTA_TUPLE_ORIG` /
/// `CTA_TUPLE_REPLY`). Emits IP and proto sub-trees from `tuple`.
fn append_tuple(b: &mut MessageBuilder, attr_type: u16, proto: IpProtocol, tuple: &ConntrackTuple) {
    let outer = b.nest_start(attr_type);

    // IP sub-tree
    let ip = b.nest_start(CTA_TUPLE_IP);
    if let Some(IpAddr::V4(addr)) = tuple.src_ip {
        b.append_attr(CTA_IP_V4_SRC, &addr.octets());
    }
    if let Some(IpAddr::V4(addr)) = tuple.dst_ip {
        b.append_attr(CTA_IP_V4_DST, &addr.octets());
    }
    if let Some(IpAddr::V6(addr)) = tuple.src_ip {
        b.append_attr(CTA_IP_V6_SRC, &addr.octets());
    }
    if let Some(IpAddr::V6(addr)) = tuple.dst_ip {
        b.append_attr(CTA_IP_V6_DST, &addr.octets());
    }
    b.nest_end(ip);

    // PROTO sub-tree
    let p = b.nest_start(CTA_TUPLE_PROTO);
    b.append_attr_u8(CTA_PROTO_NUM, proto.number());
    if let Some(port) = tuple.src_port {
        b.append_attr_u16_be(CTA_PROTO_SRC_PORT, port);
    }
    if let Some(port) = tuple.dst_port {
        b.append_attr_u16_be(CTA_PROTO_DST_PORT, port);
    }
    if let Some(id) = tuple.icmp_id {
        b.append_attr_u16_be(CTA_PROTO_ICMP_ID, id);
    }
    if let Some(t) = tuple.icmp_type {
        b.append_attr_u8(CTA_PROTO_ICMP_TYPE, t);
    }
    if let Some(c) = tuple.icmp_code {
        b.append_attr_u8(CTA_PROTO_ICMP_CODE, c);
    }
    b.nest_end(p);

    b.nest_end(outer);
}

/// Build the netlink message-type word for a ctnetlink op.
const fn ctnl_msg_type(msg: u8) -> u16 {
    ((NFNL_SUBSYS_CTNETLINK as u16) << 8) | (msg as u16)
}

/// nfgenmsg header (4 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct NfGenMsg {
    family: u8,
    version: u8,
    res_id: u16,
}

impl NfGenMsg {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        let family = winnow::binary::le_u8.parse_next(input)?;
        let version = winnow::binary::le_u8.parse_next(input)?;
        let res_id = be_u16.parse_next(input)?;
        Ok(Self {
            family,
            version,
            res_id,
        })
    }
}

#[nlink_macros::send_futures]
impl Connection<Netfilter> {
    /// Get all connection tracking entries.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Netfilter};
    ///
    /// let conn = Connection::<Netfilter>::new()?;
    /// let entries = conn.get_conntrack().await?;
    ///
    /// for entry in &entries {
    ///     println!("{:?}: {:?} -> {:?}",
    ///         entry.proto,
    ///         entry.orig.src_ip,
    ///         entry.orig.dst_ip);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_conntrack"))]
    pub async fn get_conntrack(&self) -> Result<Vec<ConntrackEntry>> {
        self.get_conntrack_family(libc::AF_INET as u8, None).await
    }

    /// Get connection tracking entries for IPv6.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_conntrack_v6"))]
    pub async fn get_conntrack_v6(&self) -> Result<Vec<ConntrackEntry>> {
        self.get_conntrack_family(libc::AF_INET6 as u8, None).await
    }

    /// The entries `filter` matches, of both families unless it names one
    /// (#882): `conntrack -L` with options.
    ///
    /// The kernel filters the dump where it can (5.8+), and nlink checks
    /// every entry it returns with [`ConntrackFilter::matches`]. A kernel
    /// that ignores part of the filter returns more, and nlink drops the
    /// rest; one that cannot filter a mark (no `CONFIG_NF_CONNTRACK_MARK`)
    /// is asked again without the filter.
    ///
    /// # Errors
    /// [`ErrorKind::Invalid`](crate::ErrorKind::Invalid) for a filter the
    /// kernel would read differently: a port without TCP or UDP, an address
    /// of another family, a status mask of 0.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_conntrack_matching"))]
    pub async fn get_conntrack_matching(
        &self,
        filter: &ConntrackFilter,
    ) -> Result<Vec<ConntrackEntry>> {
        let mut entries = Vec::new();
        for family in filter.families()? {
            let dumped = match self.get_conntrack_family(family, Some(filter)).await {
                // Of what nlink sends, only a mark makes the kernel refuse a
                // filter: one built without `CONFIG_NF_CONNTRACK_MARK`.
                Err(e) if e.is_not_supported() && filter.mark.is_some() => {
                    self.get_conntrack_family(family, None).await?
                }
                other => other?,
            };
            entries.extend(dumped.into_iter().filter(|e| filter.matches(e)));
        }
        Ok(entries)
    }

    /// Delete the entries `filter` matches one by one, and return how many
    /// went (#882).
    ///
    /// It dumps them with [`get_conntrack_matching`](Self::get_conntrack_matching)
    /// and deletes each by its tuple, zone and id
    /// ([`del_conntrack_entry`](Self::del_conntrack_entry)). An entry that
    /// expired or was replaced in between is skipped. It works on every
    /// kernel; [`flush_conntrack_matching`](Self::flush_conntrack_matching)
    /// is one request where the kernel can filter a flush.
    ///
    /// It is not atomic: it costs a request per entry, and a flow that
    /// starts after the dump is not deleted.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_conntrack_matching"))]
    pub async fn del_conntrack_matching(&self, filter: &ConntrackFilter) -> Result<usize> {
        let mut deleted = 0;
        for entry in self.get_conntrack_matching(filter).await? {
            match self.del_conntrack_entry(&entry).await {
                Ok(()) => deleted += 1,
                Err(e) if e.is_not_found() => {}
                Err(e) => return Err(e),
            }
        }
        Ok(deleted)
    }

    /// Delete every entry `filter` matches: `conntrack -D` with options
    /// (#882).
    ///
    /// On a kernel that filters a flush (6.12+), it is one delete per
    /// family that carries the filter. Anywhere else it is
    /// [`del_conntrack_matching`](Self::del_conntrack_matching): a kernel
    /// before 6.12 refuses a filter on a flush, or, before 5.8, does not
    /// know it and would flush everything. So is a filter with an IPv6
    /// address, which no kernel compares correctly (see
    /// [`ConntrackFilter`]). That path is a request per entry, and a flow
    /// that starts after its dump is not deleted.
    ///
    /// Neither path is atomic across families. A filter with no family
    /// deletes IPv4's entries, then IPv6's, and when the second fails the
    /// first are already gone.
    ///
    /// # Errors
    /// [`ErrorKind::Invalid`](crate::ErrorKind::Invalid) for an empty
    /// filter, which would match every entry: flush those with
    /// [`flush_conntrack_all`](Self::flush_conntrack_all). And for a filter
    /// the kernel would read differently, as for
    /// [`get_conntrack_matching`](Self::get_conntrack_matching).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_conntrack_matching"))]
    pub async fn flush_conntrack_matching(&self, filter: &ConntrackFilter) -> Result<()> {
        if filter.is_empty() {
            return Err(Error::invalid_message(
                "flush_conntrack_matching: an empty filter matches every entry; \
                 flush them with `flush_conntrack_all`",
            ));
        }
        let families = filter.families()?;
        if !(kernel_filters_flush() && filter.kernel_can_flush()) {
            return self.del_conntrack_matching(filter).await.map(drop);
        }
        for family in families {
            let mut b = MessageBuilder::new(
                ctnl_msg_type(IPCTNL_MSG_CT_DELETE),
                NLMF_REQUEST | NLM_F_ACK,
            );
            // Version 1, so that the kernel keeps to the family (#880).
            append_nfgenmsg_version(&mut b, family, 1);
            filter.append_kernel_filter(&mut b, family);
            match self.send_ack(b).await {
                // A kernel without the mark filter refuses it before it
                // deletes anything: `ctnetlink_flush_conntrack` builds the
                // filter, and returns its error, before it walks the table.
                Err(e) if e.is_not_supported() && filter.mark.is_some() => {
                    self.del_conntrack_matching(&filter.clone().family(family.into()))
                        .await?;
                }
                other => other?,
            }
        }
        Ok(())
    }

    /// Inject a new conntrack entry.
    ///
    /// The kernel requires `status(ConntrackStatus::CONFIRMED)` plus a
    /// non-empty `orig` tuple — the call returns `Error::InvalidArgument`
    /// from the kernel otherwise. If `reply` is unset, the original
    /// tuple is mirrored automatically (correct for symmetric flows
    /// without NAT).
    ///
    /// # Errors
    /// - `EINVAL` — missing `CONFIRMED` status, missing tuple fields,
    ///   or proto/family mismatch.
    /// - `EEXIST` — an entry with that tuple already exists.
    /// - `ENOENT` — `nf_conntrack_netlink` module not loaded.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_conntrack"))]
    pub async fn add_conntrack(&self, entry: ConntrackBuilder) -> Result<()> {
        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_NEW),
            NLMF_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        append_nfgenmsg(&mut b, entry.family);
        entry.append_attrs(&mut b, false, true);
        self.send_ack(b).await
    }

    /// Replace an existing conntrack entry — same wire shape as
    /// `add_conntrack` but with `NLM_F_CREATE | NLM_F_REPLACE`, so the
    /// kernel updates a matching entry in place. Useful for nudging
    /// timeout / mark / TCP state without a delete-then-add.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "update_conntrack"))]
    pub async fn update_conntrack(&self, entry: ConntrackBuilder) -> Result<()> {
        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_NEW),
            NLMF_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        append_nfgenmsg(&mut b, entry.family);
        entry.append_attrs(&mut b, false, false);
        self.send_ack(b).await
    }

    /// Delete a conntrack entry identified by tuple.
    ///
    /// The orig tuple plus `family` are enough; reply / status / mark
    /// are ignored by the kernel for delete. The kernel looks the tuple up
    /// in the builder's zone (0 unless set), and when the builder carries
    /// an id, deletes the entry only if its id matches.
    ///
    /// # Errors
    /// - [`Error::is_not_found`] — no entry with that tuple in that zone,
    ///   or one whose id is not the builder's.
    /// - [`ErrorKind::Invalid`](crate::ErrorKind::Invalid) — the builder
    ///   has no tuple. The kernel would take that for a flush of the whole
    ///   table, every family and zone, so it is never sent (#878).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_conntrack"))]
    pub async fn del_conntrack(&self, entry: ConntrackBuilder) -> Result<()> {
        if entry.orig.is_empty() && entry.reply.as_ref().is_none_or(ConntrackTuple::is_empty) {
            return Err(Error::invalid_message(
                "del_conntrack: the builder has no tuple, and the kernel takes a delete \
                 without one for a flush of the whole table; set `orig`, or flush with \
                 `flush_conntrack_all`",
            ));
        }
        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_DELETE),
            NLMF_REQUEST | NLM_F_ACK,
        );
        append_nfgenmsg(&mut b, entry.family);
        entry.append_attrs(&mut b, true, false);
        self.send_ack(b).await
    }

    /// Delete an entry a dump or an event returned (#878).
    ///
    /// Sends its family, original tuple, zone and id
    /// ([`ConntrackBuilder::from_entry`]). The kernel finds the entry by
    /// the tuple in that zone, then checks the id. An entry that has
    /// expired, or been replaced by a new flow with the same tuple, is
    /// left alone, and the call fails with [`Error::is_not_found`].
    ///
    /// This replaces `del_conntrack_by_id`, which sent the id alone. The
    /// kernel cannot find an entry by its id, and took that request for a
    /// flush of the whole table.
    ///
    /// ```no_run
    /// # async fn example() -> nlink::Result<()> {
    /// use nlink::netlink::{Connection, Netfilter};
    ///
    /// let nf = Connection::<Netfilter>::new()?;
    /// for entry in nf.get_conntrack().await? {
    ///     if entry.orig.dst_port == Some(5000) {
    ///         match nf.del_conntrack_entry(&entry).await {
    ///             Err(e) if e.is_not_found() => {} // gone meanwhile
    ///             other => other?,
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_conntrack_entry"))]
    pub async fn del_conntrack_entry(&self, entry: &ConntrackEntry) -> Result<()> {
        self.del_conntrack(ConntrackBuilder::from_entry(entry))
            .await
    }

    /// Flush every IPv4 conntrack entry in the connection's namespace,
    /// in every zone. IPv6 entries stay: until 0.33 this flushed both
    /// families (#880), which [`Self::flush_conntrack_all`] still does.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_conntrack"))]
    pub async fn flush_conntrack(&self) -> Result<()> {
        self.flush_conntrack_family(libc::AF_INET as u8).await
    }

    /// Flush every IPv6 conntrack entry in the connection's namespace, in
    /// every zone. IPv4 entries stay (#880).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_conntrack_v6"))]
    pub async fn flush_conntrack_v6(&self) -> Result<()> {
        self.flush_conntrack_family(libc::AF_INET6 as u8).await
    }

    /// Flush every conntrack entry in the connection's namespace: both
    /// families, every zone.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_conntrack_all"))]
    pub async fn flush_conntrack_all(&self) -> Result<()> {
        self.flush_conntrack_family(libc::AF_UNSPEC as u8).await
    }

    async fn flush_conntrack_family(&self, family: u8) -> Result<()> {
        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_DELETE),
            NLMF_REQUEST | NLM_F_ACK,
        );
        // Version 1, not NFNETLINK_V0: a flush honours `nfgen_family` only
        // when the version is not 0, and with 0 flushes every family
        // (`ctnetlink_del_conntrack`, kept that way for old userspace,
        // #880).
        append_nfgenmsg_version(&mut b, family, 1);
        self.send_ack(b).await
    }

    /// Subscribe to one or more conntrack multicast groups.
    ///
    /// Once subscribed, use [`Self::events`] / [`Self::into_events`] to
    /// consume the resulting `Stream<Item = Result<ConntrackEvent>>`.
    /// See [`ConntrackGroup`] for the available groups.
    ///
    /// # Example
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Netfilter};
    /// use nlink::netlink::netfilter::ConntrackGroup;
    /// use tokio_stream::StreamExt;
    ///
    /// let mut nf = Connection::<Netfilter>::new()?;
    /// nf.subscribe(&[ConntrackGroup::New, ConntrackGroup::Destroy])?;
    /// let mut events = nf.events().await;
    /// while let Some(evt) = events.next().await {
    ///     println!("{:?}", evt?);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "info", skip(self), fields(groups = ?groups))]
    pub fn subscribe(&self, groups: &[ConntrackGroup]) -> Result<()> {
        for g in groups {
            self.socket().add_membership(g.to_kernel_group())?;
        }
        Ok(())
    }

    /// Subscribe to all conntrack multicast groups (`New` + `Update` +
    /// `Destroy`). Skips the expectation groups (`ExpNew` /
    /// `ExpDestroy`) — those carry expectation messages, not entry
    /// messages, and can't be parsed as `ConntrackEntry`.
    pub fn subscribe_all(&self) -> Result<()> {
        self.subscribe(&[
            ConntrackGroup::New,
            ConntrackGroup::Update,
            ConntrackGroup::Destroy,
        ])
    }

    /// Get connection tracking entries for a specific address family, the
    /// kernel given `filter` when there is one.
    async fn get_conntrack_family(
        &self,
        family: u8,
        filter: Option<&ConntrackFilter>,
    ) -> Result<Vec<ConntrackEntry>> {
        // #134 — dual-mode recv (dump). Mutex mode: hold the request lock
        // for the whole send+recv (the F1 fix). Dispatcher mode: register
        // the seq (+ dump-serialization lock) so the loop coexists with
        // the driver instead of racing its recv_msg. Built BEFORE
        // with_timeout so it spans the timeout window.
        let seq = self.socket().next_seq();
        let pid = self.socket().pid();
        let mut session = self.recv_session_dump(seq).await?;
        // Plan 208 Phase 1+2 — wrap in with_timeout, seq filter,
        // NLM_F_DUMP_INTR detection.
        self.with_timeout(async move {
            let mut b =
                MessageBuilder::new(ctnl_msg_type(IPCTNL_MSG_CT_GET), NLM_F_REQUEST | NLM_F_DUMP);
            b.set_seq(seq);
            b.set_pid(pid);
            append_nfgenmsg(&mut b, family);
            if let Some(filter) = filter {
                filter.append_kernel_filter(&mut b, family);
            }

            self.socket().send(&b.finish()).await?;

            let mut entries = Vec::new();

            loop {
                let data = session.recv_with_timeout(self).await?;

                let mut offset = 0;
                while offset + 16 <= data.len() {
                    let nlmsg_len = u32::from_ne_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]) as usize;

                    let nlmsg_type = u16::from_ne_bytes([data[offset + 4], data[offset + 5]]);
                    let nlmsg_flags = u16::from_ne_bytes([data[offset + 6], data[offset + 7]]);
                    let nlmsg_seq = u32::from_ne_bytes([
                        data[offset + 8],
                        data[offset + 9],
                        data[offset + 10],
                        data[offset + 11],
                    ]);

                    if nlmsg_len < 16 || offset + nlmsg_len > data.len() {
                        break;
                    }
                    if nlmsg_seq != seq {
                        offset += (nlmsg_len + 3) & !3;
                        continue;
                    }
                    if nlmsg_flags & 0x10 != 0 {
                        return Err(crate::netlink::Error::dump_interrupted());
                    }

                    match nlmsg_type {
                        // The dump's result code is in the DONE
                        // payload; ignoring it turned a failed dump
                        // into a short, successful-looking list (#267).
                        NLMSG_DONE => {
                            done_result(&data[offset + 16..offset + nlmsg_len])?;
                            return Ok(entries);
                        }
                        NLMSG_ERROR => {
                            if nlmsg_len >= 20 {
                                let errno = i32::from_ne_bytes([
                                    data[offset + 16],
                                    data[offset + 17],
                                    data[offset + 18],
                                    data[offset + 19],
                                ]);
                                if errno != 0 {
                                    return Err(super::error::Error::from_errno(-errno));
                                }
                            }
                        }
                        _ => {
                            let subsys = (nlmsg_type >> 8) as u8;
                            if subsys == NFNL_SUBSYS_CTNETLINK
                                && let Some(entry) =
                                    self.parse_conntrack(&data[offset..offset + nlmsg_len])
                            {
                                entries.push(entry);
                            }
                        }
                    }

                    offset += (nlmsg_len + 3) & !3;
                }
            }
        })
        .await
    }

    /// Parse a conntrack message (full netlink frame including the
    /// 16-byte nlmsghdr).
    fn parse_conntrack(&self, data: &[u8]) -> Option<ConntrackEntry> {
        if data.len() < NLMSG_HDRLEN {
            return None;
        }
        parse_conntrack_body(&data[NLMSG_HDRLEN..])
    }
}

/// Parse a conntrack message body — everything after the 16-byte
/// nlmsghdr. Used by both the dump path (where we strip the header
/// ourselves) and the multicast event path (where `MessageIter` has
/// already stripped it).
pub(crate) fn parse_conntrack_body(body: &[u8]) -> Option<ConntrackEntry> {
    if body.len() < 4 {
        return None;
    }
    let mut input = body;
    let nfmsg = NfGenMsg::parse(&mut input).ok()?;

    let mut entry = ConntrackEntry {
        family: AddressFamily::from(nfmsg.family),
        ..ConntrackEntry::default()
    };

    while input.len() >= 4 {
        let (attr_type, attr_data) = parse_nla(&mut input)?;

        match attr_type & 0x7FFF {
            // Remove NLA_F_NESTED flag
            CTA_TUPLE_ORIG => {
                if let Some((tuple, proto)) = parse_tuple(attr_data) {
                    entry.orig = tuple;
                    entry.proto = proto;
                }
            }
            CTA_TUPLE_REPLY => {
                if let Some((tuple, _)) = parse_tuple(attr_data) {
                    entry.reply = tuple;
                }
            }
            CTA_STATUS if attr_data.len() >= 4 => {
                entry.status = Some(u32::from_be_bytes([
                    attr_data[0],
                    attr_data[1],
                    attr_data[2],
                    attr_data[3],
                ]));
            }
            CTA_TIMEOUT if attr_data.len() >= 4 => {
                entry.timeout = Some(u32::from_be_bytes([
                    attr_data[0],
                    attr_data[1],
                    attr_data[2],
                    attr_data[3],
                ]));
            }
            CTA_MARK if attr_data.len() >= 4 => {
                entry.mark = Some(u32::from_be_bytes([
                    attr_data[0],
                    attr_data[1],
                    attr_data[2],
                    attr_data[3],
                ]));
            }
            CTA_ID if attr_data.len() >= 4 => {
                entry.id = Some(u32::from_be_bytes([
                    attr_data[0],
                    attr_data[1],
                    attr_data[2],
                    attr_data[3],
                ]));
            }
            CTA_ZONE if attr_data.len() >= 2 => {
                entry.zone = Some(u16::from_be_bytes([attr_data[0], attr_data[1]]));
            }
            CTA_PROTOINFO => {
                entry.tcp_state = parse_protoinfo(attr_data);
            }
            CTA_COUNTERS_ORIG => {
                entry.counters_orig = parse_counters(attr_data);
            }
            CTA_COUNTERS_REPLY => {
                entry.counters_reply = parse_counters(attr_data);
            }
            _ => {}
        }
    }

    Some(entry)
}

/// Parse a netlink attribute.
fn parse_nla<'a>(input: &mut &'a [u8]) -> Option<(u16, &'a [u8])> {
    if input.len() < 4 {
        return None;
    }

    // Plan 223 — netlink attribute nla_len / nla_type are kernel
    // native-endian (per `struct nlattr` in include/uapi/linux/netlink.h
    // and nlink's canonical `NlAttr` in `attr.rs` using zerocopy
    // native-endian). Was `from_le_bytes` — silently broken on
    // BE platforms.
    let len = u16::from_ne_bytes([input[0], input[1]]) as usize;
    let attr_type = u16::from_ne_bytes([input[2], input[3]]);
    *input = &input[4..];

    if len < 4 {
        return None;
    }

    let payload_len = len.saturating_sub(4);
    if input.len() < payload_len {
        return None;
    }

    let payload = &input[..payload_len];
    *input = &input[payload_len..];

    // Align to 4 bytes
    let aligned = (len + 3) & !3;
    let padding = aligned.saturating_sub(len);
    if input.len() >= padding {
        *input = &input[padding..];
    }

    Some((attr_type, payload))
}

/// Parse a conntrack tuple.
fn parse_tuple(data: &[u8]) -> Option<(ConntrackTuple, IpProtocol)> {
    let mut input = data;
    let mut tuple = ConntrackTuple::default();
    let mut proto = IpProtocol::Other(0);

    while input.len() >= 4 {
        let (attr_type, attr_data) = parse_nla(&mut input)?;

        match attr_type & 0x7FFF {
            CTA_TUPLE_IP => {
                parse_tuple_ip(attr_data, &mut tuple);
            }
            CTA_TUPLE_PROTO => {
                proto = parse_tuple_proto(attr_data, &mut tuple);
            }
            _ => {}
        }
    }

    Some((tuple, proto))
}

/// Parse IP addresses from tuple.
fn parse_tuple_ip(data: &[u8], tuple: &mut ConntrackTuple) {
    let mut input = data;

    while input.len() >= 4 {
        if let Some((attr_type, attr_data)) = parse_nla(&mut input) {
            match attr_type {
                CTA_IP_V4_SRC if attr_data.len() >= 4 => {
                    tuple.src_ip = Some(IpAddr::V4(Ipv4Addr::new(
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    )));
                }
                CTA_IP_V4_DST if attr_data.len() >= 4 => {
                    tuple.dst_ip = Some(IpAddr::V4(Ipv4Addr::new(
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    )));
                }
                CTA_IP_V6_SRC if attr_data.len() >= 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&attr_data[..16]);
                    tuple.src_ip = Some(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                CTA_IP_V6_DST if attr_data.len() >= 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&attr_data[..16]);
                    tuple.dst_ip = Some(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        } else {
            break;
        }
    }
}

/// Parse protocol info from tuple.
fn parse_tuple_proto(data: &[u8], tuple: &mut ConntrackTuple) -> IpProtocol {
    let mut input = data;
    let mut proto = IpProtocol::Other(0);

    while input.len() >= 4 {
        if let Some((attr_type, attr_data)) = parse_nla(&mut input) {
            match attr_type {
                CTA_PROTO_NUM if !attr_data.is_empty() => {
                    proto = IpProtocol::from_u8(attr_data[0]);
                }
                CTA_PROTO_SRC_PORT if attr_data.len() >= 2 => {
                    tuple.src_port = Some(u16::from_be_bytes([attr_data[0], attr_data[1]]));
                }
                CTA_PROTO_DST_PORT if attr_data.len() >= 2 => {
                    tuple.dst_port = Some(u16::from_be_bytes([attr_data[0], attr_data[1]]));
                }
                CTA_PROTO_ICMP_ID if attr_data.len() >= 2 => {
                    tuple.icmp_id = Some(u16::from_be_bytes([attr_data[0], attr_data[1]]));
                }
                CTA_PROTO_ICMP_TYPE if !attr_data.is_empty() => {
                    tuple.icmp_type = Some(attr_data[0]);
                }
                CTA_PROTO_ICMP_CODE if !attr_data.is_empty() => {
                    tuple.icmp_code = Some(attr_data[0]);
                }
                _ => {}
            }
        } else {
            break;
        }
    }

    proto
}

/// Parse protoinfo for TCP state.
fn parse_protoinfo(data: &[u8]) -> Option<TcpConntrackState> {
    let mut input = data;

    while input.len() >= 4 {
        let (attr_type, attr_data) = parse_nla(&mut input)?;

        if (attr_type & 0x7FFF) == CTA_PROTOINFO_TCP {
            // Parse TCP protoinfo
            let mut tcp_input = attr_data;
            while tcp_input.len() >= 4 {
                if let Some((tcp_attr, tcp_data)) = parse_nla(&mut tcp_input) {
                    if tcp_attr == CTA_PROTOINFO_TCP_STATE && !tcp_data.is_empty() {
                        return Some(TcpConntrackState::from_u8(tcp_data[0]));
                    }
                } else {
                    break;
                }
            }
        }
    }

    None
}

/// Parse counters.
fn parse_counters(data: &[u8]) -> Option<ConntrackCounters> {
    let mut input = data;
    let mut counters = ConntrackCounters::default();

    while input.len() >= 4 {
        if let Some((attr_type, attr_data)) = parse_nla(&mut input) {
            match attr_type {
                CTA_COUNTERS_PACKETS if attr_data.len() >= 8 => {
                    counters.packets = u64::from_be_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                        attr_data[4],
                        attr_data[5],
                        attr_data[6],
                        attr_data[7],
                    ]);
                }
                CTA_COUNTERS_BYTES if attr_data.len() >= 8 => {
                    counters.bytes = u64::from_be_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                        attr_data[4],
                        attr_data[5],
                        attr_data[6],
                        attr_data[7],
                    ]);
                }
                _ => {}
            }
        } else {
            break;
        }
    }

    Some(counters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::message::NlMsgHdr;

    #[test]
    fn ip_protocol_roundtrip() {
        assert_eq!(IpProtocol::Tcp.number(), 6);
        assert_eq!(IpProtocol::from_u8(6), IpProtocol::Tcp);

        assert_eq!(IpProtocol::Udp.number(), 17);
        assert_eq!(IpProtocol::from_u8(17), IpProtocol::Udp);
    }

    #[test]
    fn tcp_state_from_u8() {
        assert_eq!(
            TcpConntrackState::from_u8(3),
            TcpConntrackState::Established
        );
        assert_eq!(TcpConntrackState::from_u8(7), TcpConntrackState::TimeWait);
    }

    #[test]
    fn tcp_state_roundtrip() {
        for s in [
            TcpConntrackState::SynSent,
            TcpConntrackState::Established,
            TcpConntrackState::TimeWait,
            TcpConntrackState::Close,
            TcpConntrackState::Unknown(99),
        ] {
            assert_eq!(TcpConntrackState::from_u8(s.to_u8()), s);
        }
    }

    #[test]
    fn status_flags_bitor() {
        let s = ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY;
        assert!(s.contains(ConntrackStatus::CONFIRMED));
        assert!(s.contains(ConntrackStatus::SEEN_REPLY));
        assert!(!s.contains(ConntrackStatus::ASSURED));
        assert_eq!(s.bits(), 0x000A);
    }

    #[test]
    fn tuple_mirror_swaps_src_dst() {
        let orig = ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
            .ports(1234, 80);
        let r = orig.mirror();
        assert_eq!(r.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        assert_eq!(r.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(r.src_port, Some(80));
        assert_eq!(r.dst_port, Some(1234));
    }

    /// Parse a conntrack mutation request the same way the kernel
    /// would: skip nlmsghdr + nfgenmsg, run the existing dump-side
    /// parser. Returns the round-tripped `ConntrackEntry`.
    fn roundtrip(buf: &[u8]) -> ConntrackEntry {
        let hdr = NlMsgHdr::from_bytes(buf).expect("nlmsghdr");
        // Body: after nlmsghdr, then nfgenmsg (4 bytes).
        let body = &buf[16..hdr.nlmsg_len as usize];
        let mut input = body;
        let _ = NfGenMsg::parse(&mut input).expect("nfgenmsg");
        let mut entry = ConntrackEntry::default();
        while input.len() >= 4 {
            let Some((attr_type, attr_data)) = parse_nla(&mut input) else {
                break;
            };
            match attr_type & 0x7FFF {
                CTA_TUPLE_ORIG => {
                    if let Some((t, p)) = parse_tuple(attr_data) {
                        entry.orig = t;
                        entry.proto = p;
                    }
                }
                CTA_TUPLE_REPLY => {
                    if let Some((t, _)) = parse_tuple(attr_data) {
                        entry.reply = t;
                    }
                }
                CTA_STATUS if attr_data.len() >= 4 => {
                    entry.status = Some(u32::from_be_bytes(attr_data[..4].try_into().unwrap()));
                }
                CTA_TIMEOUT if attr_data.len() >= 4 => {
                    entry.timeout = Some(u32::from_be_bytes(attr_data[..4].try_into().unwrap()));
                }
                CTA_MARK if attr_data.len() >= 4 => {
                    entry.mark = Some(u32::from_be_bytes(attr_data[..4].try_into().unwrap()));
                }
                CTA_ID if attr_data.len() >= 4 => {
                    entry.id = Some(u32::from_be_bytes(attr_data[..4].try_into().unwrap()));
                }
                CTA_PROTOINFO => {
                    entry.tcp_state = parse_protoinfo(attr_data);
                }
                _ => {}
            }
        }
        entry
    }

    #[test]
    fn add_conntrack_v4_tcp_wire_roundtrip() {
        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_NEW),
            NLMF_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        append_nfgenmsg(&mut b, libc::AF_INET as u8);
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(
                ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
                    .ports(40000, 80),
            )
            .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
            .timeout(Duration::from_secs(120))
            .mark(0x42)
            .tcp_state(TcpConntrackState::Established)
            .append_attrs(&mut b, false, true);
        let buf = b.finish();

        let entry = roundtrip(&buf);
        assert_eq!(entry.proto, IpProtocol::Tcp);
        assert_eq!(
            entry.orig.src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            entry.orig.dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
        assert_eq!(entry.orig.src_port, Some(40000));
        assert_eq!(entry.orig.dst_port, Some(80));
        // Reply tuple was auto-mirrored.
        assert_eq!(
            entry.reply.src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
        assert_eq!(
            entry.reply.dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(entry.reply.src_port, Some(80));
        assert_eq!(entry.reply.dst_port, Some(40000));
        assert_eq!(entry.status, Some(0x000A));
        assert_eq!(entry.timeout, Some(120));
        assert_eq!(entry.mark, Some(0x42));
        assert_eq!(entry.tcp_state, Some(TcpConntrackState::Established));
    }

    /// A delete built from a dumped entry carries what identifies it, and
    /// the parser a dump and an event go through reads it back (#883).
    #[test]
    fn delete_from_an_entry_carries_its_family_zone_and_id() {
        let entry = ConntrackEntry {
            family: AddressFamily::Inet6,
            proto: IpProtocol::Udp,
            orig: ConntrackTuple::v6("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap())
                .ports(40000, 5000),
            id: Some(42),
            zone: Some(7),
            mark: Some(0x10),
            ..ConntrackEntry::default()
        };
        let builder = ConntrackBuilder::from_entry(&entry);
        assert_eq!(builder.family(), AddressFamily::Inet6);

        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_DELETE),
            NLMF_REQUEST | NLM_F_ACK,
        );
        append_nfgenmsg(&mut b, builder.family);
        builder.append_attrs(&mut b, true, false);
        let buf = b.finish();

        let back = parse_conntrack_body(&buf[NLMSG_HDRLEN..]).expect("parses");
        assert_eq!(back.family, AddressFamily::Inet6);
        assert_eq!(back.proto, IpProtocol::Udp);
        assert_eq!(back.orig.dst_port, Some(5000));
        assert_eq!((back.zone, back.id), (Some(7), Some(42)));
        assert_eq!(
            back.mark, None,
            "a delete sends only what identifies the entry"
        );
    }

    fn udp(family: AddressFamily, src: &str, dport: u16) -> ConntrackEntry {
        let src: IpAddr = src.parse().unwrap();
        let dst: IpAddr = if src.is_ipv4() {
            "10.0.0.2".parse().unwrap()
        } else {
            "fd00::2".parse().unwrap()
        };
        ConntrackEntry {
            family,
            proto: IpProtocol::Udp,
            orig: ConntrackTuple {
                src_ip: Some(src),
                dst_ip: Some(dst),
                src_port: Some(40000),
                dst_port: Some(dport),
                ..ConntrackTuple::default()
            },
            ..ConntrackEntry::default()
        }
    }

    /// #882 — a filter matches an entry when every criterion it sets does.
    #[test]
    fn a_filter_matches_what_it_names() {
        let v4 = udp(AddressFamily::Inet, "10.0.0.1", 5000);
        let video = ConntrackFilter::new()
            .proto(IpProtocol::Udp)
            .orig_dst_port(5000);
        assert!(video.matches(&v4));
        assert!(
            !video.matches(&udp(AddressFamily::Inet, "10.0.0.1", 5001)),
            "another port"
        );
        assert!(
            !video.matches(&ConntrackEntry {
                proto: IpProtocol::Tcp,
                ..v4.clone()
            }),
            "another protocol"
        );
        assert!(!video.clone().zone(7).matches(&v4), "zone 0 is not zone 7");
        assert!(video.clone().zone(0).matches(&v4), "no zone is zone 0");
        assert!(video.clone().zone(7).matches(&ConntrackEntry {
            zone: Some(7),
            ..v4.clone()
        }));
        assert!(
            !video.clone().family(AddressFamily::Inet6).matches(&v4),
            "the other family"
        );
        assert!(
            video.matches(&udp(AddressFamily::Inet6, "fd00::1", 5000)),
            "no family is both"
        );

        let marked = ConntrackFilter::new().mark(0x10, 0xf0);
        assert!(marked.matches(&ConntrackEntry {
            mark: Some(0x1f),
            ..v4.clone()
        }));
        assert!(!marked.matches(&ConntrackEntry {
            mark: Some(0x20),
            ..v4.clone()
        }));
        assert!(!marked.matches(&v4), "no mark is mark 0");

        let src = ConntrackFilter::new().orig_src("fd00::1".parse::<IpAddr>().unwrap());
        assert!(src.matches(&udp(AddressFamily::Inet6, "fd00::1", 1)));
        assert!(!src.matches(&udp(AddressFamily::Inet6, "fd00::9", 1)));
        let assured =
            ConntrackFilter::new().status(ConntrackStatus::ASSURED, ConntrackStatus::ASSURED);
        assert!(assured.matches(&ConntrackEntry {
            status: Some(0x0e),
            ..v4.clone()
        }));
        assert!(!assured.matches(&ConntrackEntry {
            status: Some(0x0a),
            ..v4
        }));
        assert!(ConntrackFilter::new().is_empty() && !video.is_empty());
    }

    /// #882 — what the kernel would read differently from nlink is refused,
    /// and the families follow from the filter.
    #[test]
    fn a_filter_the_kernel_would_read_differently_is_refused() {
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        let v6: IpAddr = "fd00::1".parse().unwrap();
        for (filter, why) in [
            (ConntrackFilter::new().orig_dst_port(5000), "a port needs"),
            (
                ConntrackFilter::new()
                    .proto(IpProtocol::Icmp)
                    .orig_dst_port(5000),
                "a port needs",
            ),
            // SCTP has ports, but the kernel's filter compares them for TCP
            // and UDP only.
            (
                ConntrackFilter::new()
                    .proto(IpProtocol::Other(132))
                    .reply_src_port(1),
                "a port needs",
            ),
            (
                ConntrackFilter::new()
                    .family(AddressFamily::Inet6)
                    .orig_src(v4),
                "is not of family",
            ),
            (
                ConntrackFilter::new().orig_src(v4).reply_dst(v6),
                "is not of family",
            ),
            (
                ConntrackFilter::new().family(AddressFamily::Bridge),
                "conntrack is Inet or Inet6",
            ),
            (
                ConntrackFilter::new().status(ConntrackStatus::empty(), ConntrackStatus::empty()),
                "status mask of 0",
            ),
        ] {
            let err = filter.families().unwrap_err();
            assert!(err.to_string().contains(why), "{filter:?}: {err}");
            assert_eq!(err.kind(), crate::ErrorKind::Invalid);
        }
        let both = vec![libc::AF_INET as u8, libc::AF_INET6 as u8];
        assert_eq!(ConntrackFilter::new().zone(3).families().unwrap(), both);
        assert_eq!(
            ConntrackFilter::new().reply_dst(v6).families().unwrap(),
            [libc::AF_INET6 as u8]
        );
        assert_eq!(
            ConntrackFilter::new()
                .family(AddressFamily::Inet)
                .families()
                .unwrap(),
            [libc::AF_INET as u8]
        );
    }

    /// The attributes of a ctnetlink request after its nfgenmsg, by type.
    fn top_attrs(buf: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut input = &buf[NLMSG_HDRLEN + 4..];
        let mut out = Vec::new();
        while let Some((ty, payload)) = parse_nla(&mut input) {
            out.push((ty & !crate::netlink::attr::NLA_F_NESTED, payload.to_vec()));
        }
        out
    }

    /// #882 — the kernel is given the filter as `ctnetlink_alloc_filter`
    /// reads it: the tuple's fields, the `CTA_FILTER` flags saying which of
    /// them count, the zone, and mark and status each with its mask. An
    /// IPv6 address stays out, and keeps a flush on the client.
    #[test]
    fn the_kernel_filter_names_what_the_filter_does() {
        let request = |filter: &ConntrackFilter, family: u8| {
            let mut b = MessageBuilder::new(
                ctnl_msg_type(IPCTNL_MSG_CT_DELETE),
                NLMF_REQUEST | NLM_F_ACK,
            );
            append_nfgenmsg_version(&mut b, family, 1);
            filter.append_kernel_filter(&mut b, family);
            b.finish()
        };
        let filter = ConntrackFilter::new()
            .proto(IpProtocol::Udp)
            .orig_src(Ipv4Addr::new(10, 0, 0, 1))
            .orig_dst_port(5000)
            .reply_src_port(5000)
            .zone(7)
            .mark(0x10, 0xff)
            .status(ConntrackStatus::ASSURED, ConntrackStatus::ASSURED);
        let buf = request(&filter, libc::AF_INET as u8);
        let back = parse_conntrack_body(&buf[NLMSG_HDRLEN..]).expect("parses");
        assert_eq!(
            back.orig.src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!((back.orig.dst_port, back.orig.src_port), (Some(5000), None));
        assert_eq!(back.reply.src_port, Some(5000));
        assert_eq!(
            (back.proto, back.zone, back.mark),
            (IpProtocol::Udp, Some(7), Some(0x10))
        );

        let attrs = top_attrs(&buf);
        let get = |ty: u16| attrs.iter().find(|(t, _)| *t == ty).map(|(_, p)| p.clone());
        assert_eq!(get(CTA_MARK_MASK), Some(0xffu32.to_be_bytes().to_vec()));
        assert_eq!(get(CTA_STATUS_MASK), Some(0x04u32.to_be_bytes().to_vec()));
        let mut nested = &get(CTA_FILTER).expect("CTA_FILTER")[..];
        let mut flags = Vec::new();
        while let Some((ty, payload)) = parse_nla(&mut nested) {
            flags.push((ty, u32::from_ne_bytes(payload.try_into().unwrap())));
        }
        assert_eq!(
            flags,
            [
                (
                    CTA_FILTER_ORIG_FLAGS,
                    FILTER_IP_SRC | FILTER_PROTO_NUM | FILTER_PROTO_DST_PORT
                ),
                (
                    CTA_FILTER_REPLY_FLAGS,
                    FILTER_PROTO_NUM | FILTER_PROTO_SRC_PORT
                ),
            ]
        );
        assert!(filter.kernel_can_flush());

        let v6 = ConntrackFilter::new()
            .proto(IpProtocol::Udp)
            .orig_src("fd00::1".parse::<IpAddr>().unwrap())
            .orig_dst_port(5000);
        let buf = request(&v6, libc::AF_INET6 as u8);
        let back = parse_conntrack_body(&buf[NLMSG_HDRLEN..]).expect("parses");
        assert_eq!(
            back.orig.src_ip, None,
            "the kernel compares IPv6 addresses inverted"
        );
        assert_eq!(back.orig.dst_port, Some(5000));
        assert!(!v6.kernel_can_flush());

        // A filter with nothing for the tuples sends no CTA_FILTER.
        let buf = request(&ConntrackFilter::new().zone(7), libc::AF_INET as u8);
        assert_eq!(
            top_attrs(&buf).iter().map(|(t, _)| *t).collect::<Vec<_>>(),
            [CTA_ZONE]
        );
    }

    /// #882 — the kernel is sent a filtered flush from 6.12 on, and below
    /// that the flush is a dump and a delete per entry.
    #[test]
    fn a_flush_is_filtered_by_the_kernel_from_6_12() {
        use crate::netlink::parse_kernel_version as v;
        assert_eq!(v("6.12.48+deb13-cloud-amd64"), (6, 12));
        assert_eq!(v("5.8.0-63-generic"), (5, 8));
        assert_eq!(v("7.0-rc1"), (7, 0));
        assert_eq!(v(""), (0, 0));
        for (kernel, filters) in [
            ((5, 7), false),
            ((6, 11), false),
            ((6, 12), true),
            ((7, 0), true),
            ((0, 0), false),
        ] {
            assert_eq!(filters_a_flush(kernel), filters, "{kernel:?}");
        }
    }

    /// An entry with no family takes it from its addresses.
    #[test]
    fn from_entry_infers_a_missing_family() {
        let v6 = ConntrackEntry {
            orig: ConntrackTuple::v6("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap()),
            ..ConntrackEntry::default()
        };
        assert_eq!(
            ConntrackBuilder::from_entry(&v6).family(),
            AddressFamily::Inet6
        );
        let v4 = ConntrackEntry {
            orig: ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)),
            ..ConntrackEntry::default()
        };
        assert_eq!(
            ConntrackBuilder::from_entry(&v4).family(),
            AddressFamily::Inet
        );
    }

    /// A sub-second timeout is 1 s on the wire, not the 0 that expires the
    /// entry at once (#603).
    #[test]
    fn sub_second_timeout_rounds_up() {
        let encoded = |d| {
            let mut b = MessageBuilder::new(
                ctnl_msg_type(IPCTNL_MSG_CT_NEW),
                NLMF_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            );
            append_nfgenmsg(&mut b, libc::AF_INET as u8);
            ConntrackBuilder::new_v4(IpProtocol::Udp)
                .orig(ConntrackTuple::v4(
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 2),
                ))
                .timeout(d)
                .append_attrs(&mut b, false, true);
            roundtrip(&b.finish()).timeout
        };
        assert_eq!(encoded(Duration::from_millis(500)), Some(1));
        assert_eq!(encoded(Duration::from_millis(1_500)), Some(2));
        assert_eq!(encoded(Duration::from_secs(30)), Some(30));
    }

    #[test]
    fn add_conntrack_v6_udp_wire_roundtrip() {
        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_NEW),
            NLMF_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        append_nfgenmsg(&mut b, libc::AF_INET6 as u8);
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();
        ConntrackBuilder::new_v6(IpProtocol::Udp)
            .orig(ConntrackTuple::v6(src, dst).ports(5000, 5001))
            .status(ConntrackStatus::CONFIRMED)
            .append_attrs(&mut b, false, true);
        let buf = b.finish();

        let entry = roundtrip(&buf);
        assert_eq!(entry.proto, IpProtocol::Udp);
        assert_eq!(entry.orig.src_ip, Some(IpAddr::V6(src)));
        assert_eq!(entry.orig.dst_ip, Some(IpAddr::V6(dst)));
        assert_eq!(entry.orig.src_port, Some(5000));
        assert_eq!(entry.orig.dst_port, Some(5001));
        assert_eq!(entry.reply.src_ip, Some(IpAddr::V6(dst)));
        assert_eq!(entry.reply.dst_ip, Some(IpAddr::V6(src)));
    }

    #[test]
    fn del_conntrack_skips_status_and_timeout() {
        let mut b = MessageBuilder::new(
            ctnl_msg_type(IPCTNL_MSG_CT_DELETE),
            NLMF_REQUEST | NLM_F_ACK,
        );
        append_nfgenmsg(&mut b, libc::AF_INET as u8);
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(
                ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
                    .ports(40000, 80),
            )
            // These should be elided on the delete path.
            .status(ConntrackStatus::CONFIRMED)
            .timeout(Duration::from_secs(120))
            .mark(0x42)
            .id(0xdead_beef)
            .append_attrs(&mut b, true, false);
        let buf = b.finish();

        let entry = roundtrip(&buf);
        assert_eq!(entry.status, None);
        assert_eq!(entry.timeout, None);
        assert_eq!(entry.mark, None);
        assert_eq!(entry.id, Some(0xdead_beef));
    }

    #[test]
    fn ctnl_msg_type_layout() {
        // Subsystem in high byte, message type in low byte.
        assert_eq!(ctnl_msg_type(IPCTNL_MSG_CT_NEW), 0x0100);
        assert_eq!(ctnl_msg_type(IPCTNL_MSG_CT_GET), 0x0101);
        assert_eq!(ctnl_msg_type(IPCTNL_MSG_CT_DELETE), 0x0102);
    }

    #[test]
    fn conntrack_group_kernel_ids() {
        assert_eq!(ConntrackGroup::New.to_kernel_group(), 1);
        assert_eq!(ConntrackGroup::Update.to_kernel_group(), 2);
        assert_eq!(ConntrackGroup::Destroy.to_kernel_group(), 3);
        assert_eq!(ConntrackGroup::ExpNew.to_kernel_group(), 4);
        assert_eq!(ConntrackGroup::ExpDestroy.to_kernel_group(), 6);
    }

    /// Build a fake multicast frame: nlmsghdr(msg_type) + nfgenmsg +
    /// CTA_TUPLE_ORIG with one v4 TCP tuple. Used by the
    /// parse_events tests below.
    fn build_event_frame(msg_type: u16) -> Vec<u8> {
        let mut b = MessageBuilder::new(msg_type, 0);
        append_nfgenmsg(&mut b, libc::AF_INET as u8);
        append_tuple(
            &mut b,
            CTA_TUPLE_ORIG,
            IpProtocol::Tcp,
            &ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
                .ports(40000, 80),
        );
        b.append_attr_u32_be(CTA_ID, 0xdead_beef);
        b.finish()
    }

    #[test]
    fn parse_event_new_classifies_as_new() {
        use crate::netlink::stream::EventSource;

        let frame = build_event_frame(ctnl_msg_type(IPCTNL_MSG_CT_NEW));
        let events = <Netfilter as EventSource>::parse_events(&frame);
        assert_eq!(events.len(), 1);
        match &events[0] {
            ConntrackEvent::New(entry) => {
                assert_eq!(entry.proto, IpProtocol::Tcp);
                assert_eq!(entry.orig.src_port, Some(40000));
                assert_eq!(entry.orig.dst_port, Some(80));
                assert_eq!(entry.id, Some(0xdead_beef));
            }
            ConntrackEvent::Destroy(_) => panic!("expected New, got Destroy"),
        }
    }

    #[test]
    fn parse_event_delete_classifies_as_destroy() {
        use crate::netlink::stream::EventSource;

        let frame = build_event_frame(ctnl_msg_type(IPCTNL_MSG_CT_DELETE));
        let events = <Netfilter as EventSource>::parse_events(&frame);
        assert_eq!(events.len(), 1);
        match &events[0] {
            ConntrackEvent::Destroy(entry) => {
                assert_eq!(entry.id, Some(0xdead_beef));
            }
            ConntrackEvent::New(_) => panic!("expected Destroy, got New"),
        }
    }

    #[test]
    fn parse_event_ignores_unknown_subsystem() {
        use crate::netlink::stream::EventSource;

        // Subsystem 99 ≠ NFNL_SUBSYS_CTNETLINK → parser drops it.
        let frame = build_event_frame(99u16 << 8);
        let events = <Netfilter as EventSource>::parse_events(&frame);
        assert!(
            events.is_empty(),
            "events from unknown subsys should be ignored"
        );
    }

    #[test]
    fn parse_event_ignores_unknown_ctnetlink_msg() {
        use crate::netlink::stream::EventSource;

        // Subsystem matches, but message type 99 isn't NEW or DELETE.
        let frame = build_event_frame(ctnl_msg_type(99));
        let events = <Netfilter as EventSource>::parse_events(&frame);
        assert!(
            events.is_empty(),
            "unknown ctnetlink msg type should be ignored"
        );
    }

    #[test]
    fn parse_event_back_to_back_frames() {
        use crate::netlink::stream::EventSource;

        // Concat a NEW frame and a DELETE frame in the same buffer
        // (the kernel coalesces multicast deliveries this way).
        let mut buf = build_event_frame(ctnl_msg_type(IPCTNL_MSG_CT_NEW));
        buf.extend_from_slice(&build_event_frame(ctnl_msg_type(IPCTNL_MSG_CT_DELETE)));
        let events = <Netfilter as EventSource>::parse_events(&buf);
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], ConntrackEvent::New(_)));
        assert!(matches!(events[1], ConntrackEvent::Destroy(_)));
    }
}

// =========================================================================
// Streaming dump support — Plan 149 closeout
// =========================================================================

use super::{dump_stream::DumpStream, parse::FromNetlink};

impl FromNetlink for ConntrackEntry {
    /// Default body: AF_UNSPEC nfgenmsg ("dump everything,
    /// any family"). Callers who want family-filtered dumps use
    /// [`stream_conntrack`](Connection::stream_conntrack).
    fn write_dump_header(buf: &mut Vec<u8>) {
        buf.push(libc::AF_UNSPEC as u8); // family
        buf.push(0); // version (NFNETLINK_V0)
        buf.extend_from_slice(&0u16.to_be_bytes()); // res_id
    }

    /// Trait-required but not used by the dump-stream path
    /// (overrides `from_bytes` directly). Consumes the entire input.
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        let consumed = *input;
        *input = &input[input.len()..];
        Self::from_bytes(consumed)
            .map_err(|_| winnow::error::ErrMode::Cut(winnow::error::ContextError::new()))
    }

    /// Parse a post-nlmsghdr conntrack frame: `nfgenmsg + attrs`.
    /// Delegates to the existing `parse_conntrack_body` so the
    /// dump path and the multicast-event path share one parser.
    fn from_bytes(payload: &[u8]) -> Result<Self> {
        parse_conntrack_body(payload)
            .ok_or_else(|| super::error::Error::invalid_message("malformed conntrack entry"))
    }
}

#[nlink_macros::send_futures]
impl Connection<Netfilter> {
    /// Stream conntrack entries for `family` —
    /// [`libc::AF_INET`] / [`libc::AF_INET6`] / [`libc::AF_UNSPEC`]
    /// (the last dumps both v4 and v6). One parsed
    /// [`ConntrackEntry`] per `next().await`, bounded-memory.
    /// Preferred over the eager
    /// [`get_conntrack`](Self::get_conntrack) on hosts with large
    /// conntrack tables (busy NAT gateways, anycast load-balancers
    /// — millions of entries is routine).
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::Connection;
    /// # use nlink::netlink::Netfilter;
    /// use tokio_stream::StreamExt;
    /// let conn = Connection::<Netfilter>::new()?;
    /// let mut stream = conn.stream_conntrack(libc::AF_INET as u8).await?;
    /// while let Some(entry) = stream.next().await {
    ///     let entry = entry?;
    ///     println!("{:?}", entry.proto);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn stream_conntrack(
        &self,
        family: u8,
    ) -> Result<DumpStream<'_, Netfilter, ConntrackEntry>> {
        let mut body = Vec::with_capacity(4);
        body.push(family);
        body.push(0); // version
        body.extend_from_slice(&0u16.to_be_bytes()); // res_id
        let msg_type = ctnl_msg_type(IPCTNL_MSG_CT_GET);
        self.dump_stream_with_body::<ConntrackEntry>(msg_type, &body)
            .await
    }

    /// Convenience: `stream_conntrack(AF_INET)`.
    pub async fn stream_conntrack_v4(&self) -> Result<DumpStream<'_, Netfilter, ConntrackEntry>> {
        self.stream_conntrack(libc::AF_INET as u8).await
    }

    /// Convenience: `stream_conntrack(AF_INET6)`.
    pub async fn stream_conntrack_v6(&self) -> Result<DumpStream<'_, Netfilter, ConntrackEntry>> {
        self.stream_conntrack(libc::AF_INET6 as u8).await
    }
}

#[cfg(test)]
mod conntrack_stream_tests {
    use super::*;

    #[test]
    fn from_netlink_write_dump_header_emits_4byte_nfgenmsg() {
        let mut buf = Vec::new();
        <ConntrackEntry as FromNetlink>::write_dump_header(&mut buf);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf[0], libc::AF_UNSPEC as u8);
        assert_eq!(buf[1], 0); // version
        // res_id = 0 (big-endian)
        assert_eq!(&buf[2..4], &[0, 0]);
    }

    #[test]
    fn from_bytes_rejects_truncated() {
        let payload = vec![0u8; 3]; // shorter than nfgenmsg
        assert!(<ConntrackEntry as FromNetlink>::from_bytes(&payload).is_err());
    }
}
