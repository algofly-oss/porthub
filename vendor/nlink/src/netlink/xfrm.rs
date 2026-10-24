//! XFRM implementation for `Connection<Xfrm>`.
//!
//! This module provides methods for querying and managing IPsec Security
//! Associations (SAs) and Security Policies (SPs) via the NETLINK_XFRM protocol.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Xfrm};
//!
//! let conn = Connection::<Xfrm>::new()?;
//!
//! // List all Security Associations
//! let sas = conn.get_security_associations().await?;
//! for sa in &sas {
//!     println!("{:?} -> {:?} SPI={:08x}",
//!         sa.src_addr, sa.dst_addr, sa.spi);
//! }
//!
//! // List all Security Policies
//! let policies = conn.get_security_policies().await?;
//! for pol in &policies {
//!     println!("{:?} dir={:?} action={:?}",
//!         pol.selector, pol.direction, pol.action);
//! }
//! # Ok(())
//! # }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::{builder::MessageBuilder, connection::Connection, error::Result, protocol::Xfrm};

// Netlink constants
use super::dump_frame::done_result;

const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;
// Plan 221: production code no longer sets NLM_F_REPLACE (XFRM ignores it
// and dispatches by nlmsg_type alone); kept for the regression test that
// asserts it's never accidentally re-added to the dispatch flags.
#[allow(dead_code)]
const NLM_F_REPLACE: u16 = 0x100;

// XFRM message types (from linux/xfrm.h enum, counted from XFRM_MSG_BASE = 0x10 = 16)
const XFRM_MSG_NEWSA: u16 = 16;
pub(crate) const XFRM_MSG_DELSA: u16 = 17;
pub(crate) const XFRM_MSG_GETSA: u16 = 18;
const XFRM_MSG_NEWPOLICY: u16 = 19;
const XFRM_MSG_DELPOLICY: u16 = 20;
const XFRM_MSG_GETPOLICY: u16 = 21;
// Plan 221: UPDPOLICY=25 (was missing; nlink had value 25 mis-assigned to FLUSHSA),
// UPDSA=26 (was missing). Needed for the corrected update_sp / update_sa dispatch.
const XFRM_MSG_UPDPOLICY: u16 = 25;
pub(crate) const XFRM_MSG_UPDSA: u16 = 26;
// Plan 221: FLUSHSA was hardcoded to 25 (which is UPDPOLICY); flush_sa() was sending
// XFRM_MSG_UPDPOLICY with an 8-byte xfrm_usersa_flush body the kernel expected to be a
// 168-byte xfrm_userpolicy_info. Corrected to the kernel UAPI value 28.
const XFRM_MSG_FLUSHSA: u16 = 28;
// Plan 221: FLUSHPOLICY was hardcoded to 28 (which is FLUSHSA); flush_policy() was
// SILENTLY FLUSHING ALL SAs instead of all SPs. Corrected to the kernel UAPI value 29.
const XFRM_MSG_FLUSHPOLICY: u16 = 29;
// Notification-only message types (delivered on the XFRM multicast groups,
// never sent by nlink). Values from the same linux/xfrm.h enum.
const XFRM_MSG_ACQUIRE: u16 = 23;
const XFRM_MSG_EXPIRE: u16 = 24;
const XFRM_MSG_POLEXPIRE: u16 = 27;
const XFRM_MSG_REPORT: u16 = 32;

// XFRM attribute types (from linux/xfrm.h enum xfrm_attr_type_t)
const XFRMA_ALG_AUTH: u16 = 1;
const XFRMA_ALG_CRYPT: u16 = 2;
const XFRMA_ALG_COMP: u16 = 3;
const XFRMA_ENCAP: u16 = 4;
const XFRMA_TMPL: u16 = 5;
// Plan 221: SRCADDR was hardcoded to 9 (which is XFRMA_LTIME_VAL); every del_sa/get_sa
// with a src-addr filter was attaching a 16-byte address under the lifetime-attr ID.
// Corrected to the kernel UAPI value 13.
const XFRMA_SRCADDR: u16 = 13;
#[allow(dead_code)] // for the future "main vs sub" policy-type slice
const XFRMA_POLICY_TYPE: u16 = 16;
const XFRMA_ALG_AEAD: u16 = 18;
const XFRMA_ALG_AUTH_TRUNC: u16 = 20;
const XFRMA_MARK: u16 = 21;
// Plan 221: OFFLOAD_DEV was hardcoded to 26 (which is XFRMA_ADDRESS_FILTER); every
// Plan 153.1 offload(...) call was emitting an 8-byte xfrm_user_offload under the
// address-filter attr ID. Corrected to the kernel UAPI value 28.
const XFRMA_OFFLOAD_DEV: u16 = 28;
const XFRMA_IF_ID: u16 = 31;
/// `XFRMA_SA_PCPU` — the CPU a per-CPU SA serves (u32, RFC 9611, kernel
/// 6.13+, #166).
const XFRMA_SA_PCPU: u16 = 35;

// XFRM modes
const XFRM_MODE_TRANSPORT: u8 = 0;
const XFRM_MODE_TUNNEL: u8 = 1;
const XFRM_MODE_BEET: u8 = 4;

// XFRM protocols
const IPPROTO_ESP: u8 = 50;
const IPPROTO_AH: u8 = 51;
const IPPROTO_COMP: u8 = 108;

// Policy directions
const XFRM_POLICY_IN: u8 = 0;
const XFRM_POLICY_OUT: u8 = 1;
const XFRM_POLICY_FWD: u8 = 2;

// Policy actions
const XFRM_POLICY_ALLOW: u8 = 0;
const XFRM_POLICY_BLOCK: u8 = 1;

// Netlink header size
const NLMSG_HDRLEN: usize = 16;

/// XFRM address (16 bytes, can hold IPv4 or IPv6).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmAddress {
    /// Raw address bytes (4 bytes for IPv4, 16 for IPv6).
    pub bytes: [u8; 16],
}

impl XfrmAddress {
    /// Create from an IPv4 address.
    pub fn from_v4(addr: Ipv4Addr) -> Self {
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&addr.octets());
        Self { bytes }
    }

    /// Create from an IPv6 address.
    pub fn from_v6(addr: Ipv6Addr) -> Self {
        Self {
            bytes: addr.octets(),
        }
    }

    /// Convert to an IP address based on the address family.
    pub fn to_ip(&self, family: u16) -> Option<IpAddr> {
        match family {
            2 => {
                // AF_INET
                Some(IpAddr::V4(Ipv4Addr::new(
                    self.bytes[0],
                    self.bytes[1],
                    self.bytes[2],
                    self.bytes[3],
                )))
            }
            10 => {
                // AF_INET6
                Some(IpAddr::V6(Ipv6Addr::from(self.bytes)))
            }
            _ => None,
        }
    }
}

/// XFRM ID (identifies an SA by destination, SPI, and protocol).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmId {
    /// Destination address.
    pub daddr: XfrmAddress,
    /// Security Parameter Index (network byte order).
    pub spi: u32,
    /// IPsec protocol (ESP, AH, COMP).
    pub proto: u8,
    /// Padding.
    pub _pad: [u8; 3],
}

/// `xfrm_usersa_id` — body of `XFRM_MSG_DELSA` / `GETSA` requests.
/// 24 bytes (16 daddr + 4 spi + 2 family + 1 proto + 1 align).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUsersaId {
    pub daddr: XfrmAddress,
    pub spi: u32,
    pub family: u16,
    pub proto: u8,
    pub _pad: u8,
}

/// `xfrm_usersa_flush` — body of `XFRM_MSG_FLUSHSA`. Just the
/// `proto` byte (0 = IPSEC_PROTO_ANY → flush everything); padded
/// to 8 bytes for the kernel's `sizeof`-rounded read.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUsersaFlush {
    pub proto: u8,
    pub _pad: [u8; 7],
}

/// `xfrm_userpolicy_id` — body of `XFRM_MSG_DELPOLICY` /
/// `GETPOLICY` requests. Selector + index + direction byte.
///
/// Wire size: 64 bytes (verified against `include/uapi/linux/xfrm.h`
/// `struct xfrm_userpolicy_id` — 56 (selector) + 4 (index) + 1 (dir) +
/// 3 (pad to u32 align)). Pre-0.19 nlink used `_pad: [u8; 7]` (68
/// bytes total); strict-checking kernels (≥5.0 with
/// `NETLINK_GET_STRICT_CHK`, enableable via Plan 155.2's
/// `enable_strict_checking`) rejected the oversized body with EINVAL.
/// Lenient kernels silently skipped the trailing 4 bytes as a
/// malformed nlattr. Plan 204 C3 trim.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUserpolicyId {
    pub sel: XfrmSelector,
    pub index: u32,
    pub dir: u8,
    pub _pad: [u8; 3],
}

/// `xfrm_user_tmpl` — one entry in an SP's `XFRMA_TMPL` array.
/// Tells the kernel which SA(s) to look up to satisfy the policy:
/// the (daddr, spi, proto) triple plus mode/reqid + algorithm
/// bitmasks (typically 0xFFFFFFFF = "any algorithm").
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUserTmpl {
    pub id: XfrmId,
    pub family: u16,
    /// Padding between `family` (u16, offset 24) and the natural-alignment
    /// boundary that the kernel's non-packed C struct enforces for
    /// `saddr`. (`saddr` is `[u8; 16]` with align 1, but the kernel
    /// header originally declared a 2-byte gap here as part of the
    /// architecturally-stable layout.) Without this pad the total
    /// size is 62 instead of the kernel's 64; strict-checking kernels
    /// reject the message. Discovered by Plan 213's sizeof regression
    /// test.
    pub _pad_saddr: [u8; 2],
    pub saddr: XfrmAddress,
    pub reqid: u32,
    pub mode: u8,
    pub share: u8,
    pub optional: u8,
    pub _pad: u8,
    pub aalgos: u32,
    pub ealgos: u32,
    pub calgos: u32,
}

/// XFRM selector (traffic selector for policies/SAs).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmSelector {
    /// Destination address.
    pub daddr: XfrmAddress,
    /// Source address.
    pub saddr: XfrmAddress,
    /// Destination port (network byte order).
    pub dport: u16,
    /// Destination port mask.
    pub dport_mask: u16,
    /// Source port (network byte order).
    pub sport: u16,
    /// Source port mask.
    pub sport_mask: u16,
    /// Address family.
    pub family: u16,
    /// Destination prefix length.
    pub prefixlen_d: u8,
    /// Source prefix length.
    pub prefixlen_s: u8,
    /// IP protocol.
    pub proto: u8,
    /// Padding to align ifindex to 4 bytes.
    pub _pad1: [u8; 3],
    /// Interface index.
    pub ifindex: i32,
    /// User ID.
    pub user: u32,
}

/// XFRM lifetime configuration.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmLifetimeCfg {
    /// Soft byte limit.
    pub soft_byte_limit: u64,
    /// Hard byte limit.
    pub hard_byte_limit: u64,
    /// Soft packet limit.
    pub soft_packet_limit: u64,
    /// Hard packet limit.
    pub hard_packet_limit: u64,
    /// Soft add expiry (seconds).
    pub soft_add_expires_seconds: u64,
    /// Hard add expiry (seconds).
    pub hard_add_expires_seconds: u64,
    /// Soft use expiry (seconds).
    pub soft_use_expires_seconds: u64,
    /// Hard use expiry (seconds).
    pub hard_use_expires_seconds: u64,
}

/// XFRM lifetime current values.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmLifetimeCur {
    /// Bytes processed.
    pub bytes: u64,
    /// Packets processed.
    pub packets: u64,
    /// Time added.
    pub add_time: u64,
    /// Time last used.
    pub use_time: u64,
}

/// XFRM statistics.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmStats {
    /// Replay window.
    pub replay_window: u32,
    /// Replay count.
    pub replay: u32,
    /// Integrity check failures.
    pub integrity_failed: u32,
}

/// XFRM usersa_info (main SA structure).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUsersaInfo {
    /// Traffic selector.
    pub sel: XfrmSelector,
    /// SA identifier.
    pub id: XfrmId,
    /// Source address.
    pub saddr: XfrmAddress,
    /// Lifetime configuration.
    pub lft: XfrmLifetimeCfg,
    /// Current lifetime values.
    pub curlft: XfrmLifetimeCur,
    /// Statistics.
    pub stats: XfrmStats,
    /// Sequence number.
    pub seq: u32,
    /// Request ID.
    pub reqid: u32,
    /// Address family.
    pub family: u16,
    /// Mode (transport/tunnel/beet).
    pub mode: u8,
    /// Replay window size.
    pub replay_window: u8,
    /// Flags.
    pub flags: u8,
    /// Padding to align to 8 bytes.
    pub _pad: [u8; 7],
}

/// XFRM userpolicy_info (main policy structure).
///
/// Wire size: 168 bytes (verified against `include/uapi/linux/xfrm.h`
/// `struct xfrm_userpolicy_info`). The kernel struct uses natural
/// alignment (not packed); after the four trailing `__u8` fields
/// (`dir, action, flags, share`) the struct pads to the next u64
/// boundary (alignment requirement from the u64 fields in
/// `xfrm_lifetime_*`) — that's 4 trailing pad bytes for a 168-byte
/// total. Pre-0.19 nlink had no trailing pad and emitted a 164-byte
/// body; the kernel's `xfrm_add_policy()` called
/// `nlmsg_parse_deprecated(nlh, sizeof(*p), ...)` requiring
/// `nlmsg_len >= NLMSG_HDRLEN + 168` and rejected `add_sp` with
/// EINVAL on every kernel version since the XFRM family shipped.
/// Plan 204 C2 — add `_pad: [u8; 4]`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUserpolicyInfo {
    /// Traffic selector.
    pub sel: XfrmSelector,
    /// Lifetime configuration.
    pub lft: XfrmLifetimeCfg,
    /// Current lifetime values.
    pub curlft: XfrmLifetimeCur,
    /// Priority.
    pub priority: u32,
    /// Policy index.
    pub index: u32,
    /// Direction (in/out/fwd).
    pub dir: u8,
    /// Action (allow/block).
    pub action: u8,
    /// Flags.
    pub flags: u8,
    /// Share mode.
    pub share: u8,
    /// Padding to natural u64 alignment — kernel struct uses natural
    /// (non-packed) alignment, padding the trailing four `__u8`
    /// fields to the next 8-byte boundary. Without this nlink emits
    /// a 164-byte body and the kernel rejects `add_sp` with EINVAL.
    pub _pad: [u8; 4],
}

/// XFRM algorithm.
#[derive(Clone)]
pub struct XfrmAlgorithm {
    /// Algorithm name.
    pub name: String,
    /// Key length in bits.
    pub key_len: u32,
    /// Key data.
    pub key: Vec<u8>,
}

impl std::fmt::Debug for XfrmAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("XfrmAlgorithm")
            .field("name", &self.name)
            .field("key_len", &self.key_len)
            .field("key", &crate::util::SecretBytes(&self.key))
            .finish()
    }
}

/// XFRM AEAD algorithm.
#[derive(Clone)]
pub struct XfrmAlgorithmAead {
    /// Algorithm name.
    pub name: String,
    /// Key length in bits.
    pub key_len: u32,
    /// ICV length in bits.
    pub icv_len: u32,
    /// Key data.
    pub key: Vec<u8>,
}

impl std::fmt::Debug for XfrmAlgorithmAead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("XfrmAlgorithmAead")
            .field("name", &self.name)
            .field("key_len", &self.key_len)
            .field("icv_len", &self.icv_len)
            .field("key", &crate::util::SecretBytes(&self.key))
            .finish()
    }
}

/// XFRM authentication algorithm with truncation.
#[derive(Clone)]
pub struct XfrmAlgorithmAuthTrunc {
    /// Algorithm name.
    pub name: String,
    /// Key length in bits.
    pub key_len: u32,
    /// Truncation length in bits.
    pub trunc_len: u32,
    /// Key data.
    pub key: Vec<u8>,
}

impl std::fmt::Debug for XfrmAlgorithmAuthTrunc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("XfrmAlgorithmAuthTrunc")
            .field("name", &self.name)
            .field("key_len", &self.key_len)
            .field("trunc_len", &self.trunc_len)
            .field("key", &crate::util::SecretBytes(&self.key))
            .finish()
    }
}

/// XFRM encapsulation template.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmEncapTmpl {
    /// Encapsulation type.
    pub encap_type: u16,
    /// Source port (network byte order).
    pub encap_sport: u16,
    /// Destination port (network byte order).
    pub encap_dport: u16,
    /// Padding.
    pub _pad: u16,
    /// Original address.
    pub encap_oa: XfrmAddress,
}

/// XFRM mark.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmMark {
    /// Mark value.
    pub v: u32,
    /// Mark mask.
    pub m: u32,
}

/// `XFRMA_OFFLOAD_DEV` payload — `struct xfrm_user_offload`.
///
/// Used to request hardware offload of an SA's crypto and/or
/// packet path onto a NIC (mlx5, hns3, etc.). Carries the
/// offload-target ifindex + the offload-shape flags.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct XfrmUserOffload {
    /// Interface index to offload to.
    pub ifindex: u32,
    /// Bitmask of [`XfrmOffloadFlag`] values.
    pub flags: u8,
    /// Padding to match the kernel struct layout (the C struct
    /// has natural padding after the u8 to keep the next field —
    /// none in this case — at u32 alignment).
    pub _pad: [u8; 3],
}

impl XfrmUserOffload {
    pub fn new(ifindex: u32, flags: XfrmOffloadFlag) -> Self {
        Self {
            ifindex,
            flags: flags.bits(),
            _pad: [0; 3],
        }
    }
}

/// Flags for [`XfrmUserOffload`] / [`XfrmSaBuilder::offload`].
///
/// Kernel reference: `include/uapi/linux/xfrm.h`:
/// `XFRM_OFFLOAD_IPV6` / `XFRM_OFFLOAD_INBOUND` / `XFRM_OFFLOAD_PACKET`.
///
/// `PACKET` requires kernel 6.0+ and full packet-mode-capable NIC
/// (mlx5 ConnectX-7 + later). Crypto-only offload works on older
/// kernels with simpler hardware.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XfrmOffloadFlag(u8);

impl XfrmOffloadFlag {
    /// Offload an IPv6 SA. Required for IPv6 ESP / IPv6 UDP-encap
    /// ESP offload.
    pub const IPV6: Self = Self(0x1);
    /// Inbound SA (decrypt path). Default is outbound (encrypt).
    pub const INBOUND: Self = Self(0x2);
    /// Full packet-mode offload (kernel 6.0+). Without this flag,
    /// only the crypto path is offloaded; the kernel still
    /// handles packet framing.
    pub const PACKET: Self = Self(0x4);

    /// Empty / outbound + crypto-only — the default.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Compose multiple flags. Idiomatic bit-or via `|` is also
    /// supported.
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Underlying bitmask value.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// `true` if `other` is fully contained in `self`.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for XfrmOffloadFlag {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for XfrmOffloadFlag {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// IPsec protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpsecProtocol {
    /// Encapsulating Security Payload.
    Esp,
    /// Authentication Header.
    Ah,
    /// IP Compression.
    Comp,
    /// Other protocol.
    Other(u8),
}

impl IpsecProtocol {
    fn from_u8(val: u8) -> Self {
        match val {
            IPPROTO_ESP => Self::Esp,
            IPPROTO_AH => Self::Ah,
            IPPROTO_COMP => Self::Comp,
            other => Self::Other(other),
        }
    }

    /// Get the protocol number.
    pub fn number(&self) -> u8 {
        match self {
            Self::Esp => IPPROTO_ESP,
            Self::Ah => IPPROTO_AH,
            Self::Comp => IPPROTO_COMP,
            Self::Other(n) => *n,
        }
    }
}

/// XFRM mode (transport, tunnel, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum XfrmMode {
    /// Transport mode.
    Transport,
    /// Tunnel mode.
    Tunnel,
    /// BEET mode.
    Beet,
    /// Other mode.
    Other(u8),
}

impl XfrmMode {
    fn from_u8(val: u8) -> Self {
        match val {
            XFRM_MODE_TRANSPORT => Self::Transport,
            XFRM_MODE_TUNNEL => Self::Tunnel,
            XFRM_MODE_BEET => Self::Beet,
            other => Self::Other(other),
        }
    }

    /// Convert back to the wire-format `u8`.
    pub fn number(&self) -> u8 {
        match self {
            Self::Transport => XFRM_MODE_TRANSPORT,
            Self::Tunnel => XFRM_MODE_TUNNEL,
            Self::Beet => XFRM_MODE_BEET,
            Self::Other(n) => *n,
        }
    }
}

/// Policy direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyDirection {
    /// Incoming traffic.
    In,
    /// Outgoing traffic.
    Out,
    /// Forwarded traffic.
    Forward,
    /// Unknown direction.
    Unknown(u8),
}

impl PolicyDirection {
    fn from_u8(val: u8) -> Self {
        match val {
            XFRM_POLICY_IN => Self::In,
            XFRM_POLICY_OUT => Self::Out,
            XFRM_POLICY_FWD => Self::Forward,
            other => Self::Unknown(other),
        }
    }

    /// Convert back to the wire-format `u8`.
    pub fn number(&self) -> u8 {
        match self {
            Self::In => XFRM_POLICY_IN,
            Self::Out => XFRM_POLICY_OUT,
            Self::Forward => XFRM_POLICY_FWD,
            Self::Unknown(n) => *n,
        }
    }
}

/// Policy action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyAction {
    /// Allow traffic.
    Allow,
    /// Block traffic.
    Block,
    /// Unknown action.
    Unknown(u8),
}

impl PolicyAction {
    fn from_u8(val: u8) -> Self {
        match val {
            XFRM_POLICY_ALLOW => Self::Allow,
            XFRM_POLICY_BLOCK => Self::Block,
            other => Self::Unknown(other),
        }
    }

    /// Convert back to the wire-format `u8`.
    pub fn number(&self) -> u8 {
        match self {
            Self::Allow => XFRM_POLICY_ALLOW,
            Self::Block => XFRM_POLICY_BLOCK,
            Self::Unknown(n) => *n,
        }
    }
}

/// A traffic selector.
#[derive(Debug, Clone)]
pub struct TrafficSelector {
    /// Source address.
    pub src_addr: Option<IpAddr>,
    /// Destination address.
    pub dst_addr: Option<IpAddr>,
    /// Source prefix length.
    pub src_prefix_len: u8,
    /// Destination prefix length.
    pub dst_prefix_len: u8,
    /// Source port.
    pub src_port: Option<u16>,
    /// Destination port.
    pub dst_port: Option<u16>,
    /// IP protocol.
    pub proto: u8,
}

impl TrafficSelector {
    fn from_selector(sel: XfrmSelector) -> Self {
        Self {
            src_addr: sel.saddr.to_ip(sel.family),
            dst_addr: sel.daddr.to_ip(sel.family),
            src_prefix_len: sel.prefixlen_s,
            dst_prefix_len: sel.prefixlen_d,
            src_port: if sel.sport != 0 {
                Some(u16::from_be(sel.sport))
            } else {
                None
            },
            dst_port: if sel.dport != 0 {
                Some(u16::from_be(sel.dport))
            } else {
                None
            },
            proto: sel.proto,
        }
    }
}

/// A Security Association (SA).
///
/// `#[non_exhaustive]` since 0.32 (#166): the kernel keeps adding SA
/// attributes worth reading back.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SecurityAssociation {
    /// Source address.
    pub src_addr: Option<IpAddr>,
    /// Destination address.
    pub dst_addr: Option<IpAddr>,
    /// Security Parameter Index.
    pub spi: u32,
    /// IPsec protocol.
    pub protocol: IpsecProtocol,
    /// Mode (transport/tunnel).
    pub mode: XfrmMode,
    /// Request ID.
    pub reqid: u32,
    /// Traffic selector.
    pub selector: TrafficSelector,
    /// Encryption algorithm.
    pub enc_alg: Option<XfrmAlgorithm>,
    /// Authentication algorithm.
    pub auth_alg: Option<XfrmAlgorithm>,
    /// AEAD algorithm.
    pub aead_alg: Option<XfrmAlgorithmAead>,
    /// Authentication algorithm with truncation.
    pub auth_trunc_alg: Option<XfrmAlgorithmAuthTrunc>,
    /// Compression algorithm.
    pub comp_alg: Option<XfrmAlgorithm>,
    /// Encapsulation template (UDP encap).
    pub encap: Option<XfrmEncapTmpl>,
    /// Mark.
    pub mark: Option<XfrmMark>,
    /// Interface ID.
    pub if_id: Option<u32>,
    /// The CPU a per-CPU SA serves (`XFRMA_SA_PCPU`, kernel 6.13+).
    pub pcpu: Option<u32>,
    /// Bytes processed.
    pub bytes: u64,
    /// Packets processed.
    pub packets: u64,
    /// Replay window size.
    pub replay_window: u8,
    /// Flags.
    pub flags: u8,
}

/// A Security Policy (SP).
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Traffic selector.
    pub selector: TrafficSelector,
    /// Policy direction.
    pub direction: PolicyDirection,
    /// Policy action.
    pub action: PolicyAction,
    /// Priority.
    pub priority: u32,
    /// Policy index.
    pub index: u32,
    /// Flags.
    pub flags: u8,
    /// Mark.
    pub mark: Option<XfrmMark>,
    /// Interface ID.
    pub if_id: Option<u32>,
}

// ============================================================================
// Write-path builder (Plan 141 PR A, Plan 142 Phase 2)
// ============================================================================

/// Authentication algorithm spec for an [`XfrmSaBuilder`].
///
/// `name` is a kernel algorithm string like `"hmac(sha256)"`; the
/// kernel's crypto subsystem decides which combinations are valid.
/// `key` is the raw key bytes; `key_len_bits` is set automatically
/// from `key.len() * 8` by the helper constructors.
#[derive(Clone)]
pub struct XfrmAlgoAuth {
    pub name: String,
    pub key: Vec<u8>,
}

impl std::fmt::Debug for XfrmAlgoAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("XfrmAlgoAuth")
            .field("name", &self.name)
            .field("key", &crate::util::SecretBytes(&self.key))
            .finish()
    }
}

/// Encryption algorithm spec.
#[derive(Clone)]
pub struct XfrmAlgoEncr {
    pub name: String,
    pub key: Vec<u8>,
}

impl std::fmt::Debug for XfrmAlgoEncr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("XfrmAlgoEncr")
            .field("name", &self.name)
            .field("key", &crate::util::SecretBytes(&self.key))
            .finish()
    }
}

/// AEAD algorithm spec (combined auth + encrypt with ICV).
///
/// `icv_truncbits` is the ICV length in bits (e.g. 128 for
/// AES-GCM-128).
#[derive(Clone)]
pub struct XfrmAlgoAead {
    pub name: String,
    pub key: Vec<u8>,
    pub icv_truncbits: u32,
}

impl std::fmt::Debug for XfrmAlgoAead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("XfrmAlgoAead")
            .field("name", &self.name)
            .field("key", &crate::util::SecretBytes(&self.key))
            .field("icv_truncbits", &self.icv_truncbits)
            .finish()
    }
}

/// Builder for a Security Association write request.
///
/// Construct via [`XfrmSaBuilder::new`], chain the relevant setters,
/// and pass to [`Connection::add_sa`]. The kernel validates the
/// combination of `proto` / `mode` / algorithm specs; mismatches
/// surface as `EINVAL` from `add_sa`.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// use nlink::netlink::{Connection, Xfrm};
/// use nlink::netlink::xfrm::{XfrmSaBuilder, XfrmMode, IpsecProtocol};
///
/// let conn = Connection::<Xfrm>::new()?;
/// let sa = XfrmSaBuilder::new(
///     "10.0.0.1".parse().unwrap(),
///     "10.0.0.2".parse().unwrap(),
///     0xdead_beef,
///     IpsecProtocol::Esp,
/// )
/// .mode(XfrmMode::Tunnel)
/// .reqid(42)
/// .auth_hmac_sha256(&[0u8; 32])
/// .encr_aes_cbc(&[0u8; 16]);
/// conn.add_sa(sa).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless submitted to the connection"]
pub struct XfrmSaBuilder {
    src: IpAddr,
    dst: IpAddr,
    spi: u32,
    proto: IpsecProtocol,
    mode: XfrmMode,
    reqid: u32,
    flags: u8,
    replay_window: u8,
    auth: Option<XfrmAlgoAuth>,
    encr: Option<XfrmAlgoEncr>,
    aead: Option<XfrmAlgoAead>,
    encap: Option<XfrmEncapTmpl>,
    mark: Option<(u32, u32)>,
    if_id: Option<u32>,
    pcpu: Option<u32>,
    offload: Option<XfrmUserOffload>,
}

impl XfrmSaBuilder {
    /// Create a new SA builder for the given (src, dst, spi, proto)
    /// tuple. Defaults to transport mode, reqid 0, replay window 32.
    pub fn new(src: IpAddr, dst: IpAddr, spi: u32, proto: IpsecProtocol) -> Self {
        Self {
            src,
            dst,
            spi,
            proto,
            mode: XfrmMode::Transport,
            reqid: 0,
            flags: 0,
            // Default replay window — kernel default is 0 (replay
            // protection disabled), which surprises users; pick 32
            // packets like iproute2 does for `ip xfrm`.
            replay_window: 32,
            auth: None,
            encr: None,
            aead: None,
            encap: None,
            mark: None,
            if_id: None,
            pcpu: None,
            offload: None,
        }
    }

    /// Request hardware offload of this SA to the given device
    /// (by ifindex) with the given offload shape.
    ///
    /// Kernel 6.11+ extended offload to IPv6 ESP and IPv4 UDP-encap
    /// ESP; earlier kernels support IPv4 ESP only. NIC support
    /// varies — mlx5, hns3, and a few others; check
    /// `ethtool -k <dev> | grep esp` on the target NIC. If the
    /// NIC doesn't support the requested shape the kernel returns
    /// `EOPNOTSUPP` on the add; callers can dispatch via
    /// `Error::is_not_supported()` and retry without offload.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::net::IpAddr;
    /// use std::net::Ipv4Addr;
    /// use nlink::netlink::xfrm::{XfrmSaBuilder, IpsecProtocol, XfrmOffloadFlag};
    ///
    /// let mlx5_ifindex = 3;
    /// let sa = XfrmSaBuilder::new(
    ///     IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    ///     IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
    ///     0x12345678,
    ///     IpsecProtocol::Esp,
    /// )
    /// .auth_hmac_sha256(&[0u8; 32])
    /// .offload(mlx5_ifindex, XfrmOffloadFlag::PACKET);
    /// ```
    pub fn offload(mut self, ifindex: u32, flags: XfrmOffloadFlag) -> Self {
        self.offload = Some(XfrmUserOffload::new(ifindex, flags));
        self
    }

    pub fn mode(mut self, mode: XfrmMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn reqid(mut self, id: u32) -> Self {
        self.reqid = id;
        self
    }

    pub fn replay_window(mut self, w: u8) -> Self {
        self.replay_window = w;
        self
    }

    /// Set the auth algorithm by name + raw key bytes. Most users
    /// want one of the named helpers ([`Self::auth_hmac_sha256`]).
    pub fn auth(mut self, name: impl Into<String>, key: &[u8]) -> Self {
        self.auth = Some(XfrmAlgoAuth {
            name: name.into(),
            key: key.to_vec(),
        });
        self
    }

    /// Convenience: HMAC-SHA256. Key must be 32 bytes.
    pub fn auth_hmac_sha256(self, key: &[u8]) -> Self {
        self.auth("hmac(sha256)", key)
    }

    /// Set the encryption algorithm by name + raw key bytes.
    pub fn encr(mut self, name: impl Into<String>, key: &[u8]) -> Self {
        self.encr = Some(XfrmAlgoEncr {
            name: name.into(),
            key: key.to_vec(),
        });
        self
    }

    /// Convenience: AES-CBC. Key length determines variant
    /// (16 → AES-128, 24 → AES-192, 32 → AES-256).
    pub fn encr_aes_cbc(self, key: &[u8]) -> Self {
        self.encr("cbc(aes)", key)
    }

    /// Set the AEAD algorithm. Pass `icv_truncbits` in BITS
    /// (e.g. 128 for the standard AES-GCM-128 ICV).
    pub fn aead(mut self, name: impl Into<String>, key: &[u8], icv_truncbits: u32) -> Self {
        self.aead = Some(XfrmAlgoAead {
            name: name.into(),
            key: key.to_vec(),
            icv_truncbits,
        });
        self
    }

    /// Convenience: AES-GCM (RFC 4106). Key includes the 4-byte
    /// salt suffix per RFC; pass `icv_truncbits` 128 for the
    /// standard ICV length.
    pub fn aead_aes_gcm(self, key: &[u8], icv_truncbits: u32) -> Self {
        self.aead("rfc4106(gcm(aes))", key, icv_truncbits)
    }

    /// Configure NAT-T UDP encapsulation. Picks the encap type
    /// based on `dport` (4500 → IKE-compatible variant, anything
    /// else → non-IKE).
    pub fn nat_t_udp_encap(mut self, sport: u16, dport: u16) -> Self {
        // UDP_ENCAP_ESPINUDP_NON_IKE = 1, UDP_ENCAP_ESPINUDP = 2
        // (from include/uapi/linux/udp.h)
        let encap_type: u16 = if dport == 4500 { 2 } else { 1 };
        self.encap = Some(XfrmEncapTmpl {
            encap_type,
            encap_sport: sport.to_be(),
            encap_dport: dport.to_be(),
            _pad: 0,
            encap_oa: XfrmAddress::default(),
        });
        self
    }

    /// Filter which policies/SAs apply by skb mark.
    pub fn mark(mut self, mark: u32, mask: u32) -> Self {
        self.mark = Some((mark, mask));
        self
    }

    /// XFRM interface ID (XFRMA_IF_ID).
    pub fn if_id(mut self, id: u32) -> Self {
        self.if_id = Some(id);
        self
    }

    /// Make it the per-CPU SA for `cpu` (`XFRMA_SA_PCPU`, RFC 9611, #166):
    /// with one per CPU, each encrypts in parallel with its own sequence
    /// numbers. Kernel 6.13+; an older kernel ignores the attribute, so
    /// read the SA back and check [`SecurityAssociation::pcpu`].
    pub fn pcpu(mut self, cpu: u32) -> Self {
        self.pcpu = Some(cpu);
        self
    }

    /// Address family inferred from `src`/`dst` (must match).
    fn family(&self) -> u16 {
        family_for_pair(self.src, self.dst)
    }

    /// Populate the request's `xfrm_usersa_info` header bytes.
    fn build_usersa_info(&self) -> XfrmUsersaInfo {
        let saddr = ip_to_xfrm_addr(self.src);
        let daddr = ip_to_xfrm_addr(self.dst);
        let family = self.family();
        XfrmUsersaInfo {
            sel: XfrmSelector {
                family,
                ..Default::default()
            },
            id: XfrmId {
                daddr,
                spi: self.spi.to_be(),
                proto: self.proto.number(),
                _pad: [0; 3],
            },
            saddr,
            lft: XfrmLifetimeCfg {
                soft_byte_limit: u64::MAX,
                hard_byte_limit: u64::MAX,
                soft_packet_limit: u64::MAX,
                hard_packet_limit: u64::MAX,
                soft_add_expires_seconds: 0,
                hard_add_expires_seconds: 0,
                soft_use_expires_seconds: 0,
                hard_use_expires_seconds: 0,
            },
            curlft: XfrmLifetimeCur::default(),
            stats: XfrmStats::default(),
            seq: 0,
            reqid: self.reqid,
            family,
            mode: self.mode.number(),
            replay_window: self.replay_window,
            flags: self.flags,
            _pad: [0; 7],
        }
    }

    /// Append the SA to a [`MessageBuilder`]: header bytes followed
    /// by algorithm + encap + mark + if_id attributes.
    fn write_into(&self, b: &mut MessageBuilder) {
        let info = self.build_usersa_info();
        b.append_bytes(info.as_bytes());

        if let Some(a) = &self.auth {
            let bytes = encode_xfrm_algo(&a.name, &a.key);
            b.append_attr(XFRMA_ALG_AUTH, &bytes);
        }
        if let Some(e) = &self.encr {
            let bytes = encode_xfrm_algo(&e.name, &e.key);
            b.append_attr(XFRMA_ALG_CRYPT, &bytes);
        }
        if let Some(a) = &self.aead {
            let bytes = encode_xfrm_algo_aead(&a.name, &a.key, a.icv_truncbits);
            b.append_attr(XFRMA_ALG_AEAD, &bytes);
        }
        if let Some(encap) = &self.encap {
            b.append_attr(XFRMA_ENCAP, encap.as_bytes());
        }
        if let Some((mark, mask)) = self.mark {
            let m = XfrmMark { v: mark, m: mask };
            b.append_attr(XFRMA_MARK, m.as_bytes());
        }
        if let Some(id) = self.if_id {
            b.append_attr_u32(XFRMA_IF_ID, id);
        }
        if let Some(cpu) = self.pcpu {
            b.append_attr_u32(XFRMA_SA_PCPU, cpu);
        }
        if let Some(off) = &self.offload {
            // XFRMA_OFFLOAD_DEV carries `struct xfrm_user_offload`
            // (4 bytes ifindex + 1 byte flags + 3 bytes pad).
            b.append_attr(XFRMA_OFFLOAD_DEV, off.as_bytes());
        }
    }
}

/// Encode the `xfrm_algo` wire layout: 64-byte zero-padded name
/// + 4-byte key_len (BITS) + key bytes.
fn encode_xfrm_algo(name: &str, key: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(68 + key.len());
    let mut name_field = [0u8; 64];
    let n = name.len().min(63);
    name_field[..n].copy_from_slice(&name.as_bytes()[..n]);
    buf.extend_from_slice(&name_field);
    let key_len_bits = (key.len() * 8) as u32;
    // `xfrm_algo.alg_key_len` is `unsigned int` — kernel-native, not
    // little-endian. Writing it LE is correct by accident on x86 and
    // silently wrong on s390x/ppc64be, which is the platform the
    // big-endian CI lane exists to protect (#278).
    buf.extend_from_slice(&key_len_bits.to_ne_bytes());
    buf.extend_from_slice(key);
    buf
}

/// Encode `xfrm_algo_aead`: 64-byte name + 4-byte key_len (BITS)
/// + 4-byte icv_len (BITS) + key bytes.
fn encode_xfrm_algo_aead(name: &str, key: &[u8], icv_truncbits: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(72 + key.len());
    let mut name_field = [0u8; 64];
    let n = name.len().min(63);
    name_field[..n].copy_from_slice(&name.as_bytes()[..n]);
    buf.extend_from_slice(&name_field);
    let key_len_bits = (key.len() * 8) as u32;
    buf.extend_from_slice(&key_len_bits.to_ne_bytes());
    buf.extend_from_slice(&icv_truncbits.to_ne_bytes());
    buf.extend_from_slice(key);
    buf
}

/// Convert a Rust `IpAddr` into the kernel's 16-byte
/// `xfrm_address_t` (IPv4 in the first 4 bytes, network order).
fn ip_to_xfrm_addr(ip: IpAddr) -> XfrmAddress {
    match ip {
        IpAddr::V4(v4) => XfrmAddress::from_v4(v4),
        IpAddr::V6(v6) => XfrmAddress::from_v6(v6),
    }
}

/// Address family for a `(src, dst)` pair. Mismatched families
/// return 0 — the kernel will reject the request with EINVAL.
fn family_for_pair(src: IpAddr, dst: IpAddr) -> u16 {
    match (src, dst) {
        (IpAddr::V4(_), IpAddr::V4(_)) => libc::AF_INET as u16,
        (IpAddr::V6(_), IpAddr::V6(_)) => libc::AF_INET6 as u16,
        _ => 0,
    }
}

impl XfrmUsersaId {
    fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }
}

impl XfrmUsersaFlush {
    fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }
}

impl XfrmUserpolicyId {
    fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }
}

impl XfrmUserTmpl {
    fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    /// Build a typical "match-any-algo" template: forward to a
    /// specific destination via `proto`/`mode`, no SPI constraint.
    pub fn match_any(
        src: IpAddr,
        dst: IpAddr,
        proto: IpsecProtocol,
        mode: XfrmMode,
        reqid: u32,
    ) -> Self {
        Self {
            id: XfrmId {
                daddr: ip_to_xfrm_addr(dst),
                spi: 0,
                proto: proto.number(),
                _pad: [0; 3],
            },
            family: family_for_pair(src, dst),
            _pad_saddr: [0; 2],
            saddr: ip_to_xfrm_addr(src),
            reqid,
            mode: mode.number(),
            share: 0,
            optional: 0,
            _pad: 0,
            // Default: any algorithm acceptable (kernel matches any
            // SA whose algorithms intersect this bitmask).
            aalgos: u32::MAX,
            ealgos: u32::MAX,
            calgos: u32::MAX,
        }
    }
}

// ============================================================================
// Security Policy write-path builder (Plan 141 PR B)
// ============================================================================

/// Builder for a Security Policy write request.
///
/// SPs steer traffic into / out of the IPsec subsystem: each
/// matching packet is checked against the policy's templates and
/// either encrypted/decrypted via the resolved SA, blocked, or
/// passed through. Construct via [`XfrmSpBuilder::new`], chain
/// the relevant setters (and any number of [`Self::template`]
/// calls), and pass to [`Connection::add_sp`].
///
/// # Example
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// use nlink::netlink::{Connection, Xfrm};
/// use nlink::netlink::xfrm::{
///     XfrmSpBuilder, XfrmSelector, XfrmUserTmpl, IpsecProtocol,
///     PolicyDirection, XfrmMode,
/// };
///
/// let conn = Connection::<Xfrm>::new()?;
/// let sel = XfrmSelector { family: libc::AF_INET as u16, ..Default::default() };
/// let tmpl = XfrmUserTmpl::match_any(
///     "10.0.0.1".parse().unwrap(),
///     "10.0.0.2".parse().unwrap(),
///     IpsecProtocol::Esp, XfrmMode::Tunnel, 42,
/// );
/// let sp = XfrmSpBuilder::new(sel, PolicyDirection::Out)
///     .priority(100)
///     .template(tmpl);
/// conn.add_sp(sp).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless submitted to the connection"]
pub struct XfrmSpBuilder {
    sel: XfrmSelector,
    direction: PolicyDirection,
    action: PolicyAction,
    priority: u32,
    index: u32,
    flags: u8,
    share: u8,
    tmpls: Vec<XfrmUserTmpl>,
    mark: Option<(u32, u32)>,
    if_id: Option<u32>,
}

impl XfrmSpBuilder {
    /// New SP for the given selector + direction. Defaults to
    /// `Allow` action, priority 0, kernel-assigned index.
    pub fn new(sel: XfrmSelector, direction: PolicyDirection) -> Self {
        Self {
            sel,
            direction,
            action: PolicyAction::Allow,
            priority: 0,
            index: 0,
            flags: 0,
            share: 0,
            tmpls: Vec::new(),
            mark: None,
            if_id: None,
        }
    }

    /// Set action to `Allow` (default).
    pub fn allow(mut self) -> Self {
        self.action = PolicyAction::Allow;
        self
    }

    /// Set action to `Block` — packets matching this selector are
    /// dropped.
    pub fn block(mut self) -> Self {
        self.action = PolicyAction::Block;
        self
    }

    pub fn priority(mut self, p: u32) -> Self {
        self.priority = p;
        self
    }

    /// Pre-pin a policy index. Default 0 = kernel assigns one.
    pub fn index(mut self, idx: u32) -> Self {
        self.index = idx;
        self
    }

    /// Append a template to the policy. Each template references
    /// an SA the kernel must look up to satisfy the policy. Order
    /// matters for nested transforms (e.g. AH inside ESP).
    pub fn template(mut self, tmpl: XfrmUserTmpl) -> Self {
        self.tmpls.push(tmpl);
        self
    }

    /// Filter which policies apply by skb mark.
    pub fn mark(mut self, mark: u32, mask: u32) -> Self {
        self.mark = Some((mark, mask));
        self
    }

    /// XFRM interface ID (XFRMA_IF_ID).
    pub fn if_id(mut self, id: u32) -> Self {
        self.if_id = Some(id);
        self
    }

    fn build_userpolicy_info(&self) -> XfrmUserpolicyInfo {
        XfrmUserpolicyInfo {
            sel: self.sel,
            lft: XfrmLifetimeCfg {
                soft_byte_limit: u64::MAX,
                hard_byte_limit: u64::MAX,
                soft_packet_limit: u64::MAX,
                hard_packet_limit: u64::MAX,
                soft_add_expires_seconds: 0,
                hard_add_expires_seconds: 0,
                soft_use_expires_seconds: 0,
                hard_use_expires_seconds: 0,
            },
            curlft: XfrmLifetimeCur::default(),
            priority: self.priority,
            index: self.index,
            dir: self.direction.number(),
            action: self.action.number(),
            flags: self.flags,
            share: self.share,
            _pad: [0; 4],
        }
    }

    fn write_into(&self, b: &mut MessageBuilder) {
        let info = self.build_userpolicy_info();
        b.append_bytes(info.as_bytes());

        if !self.tmpls.is_empty() {
            // XFRMA_TMPL is a single attribute carrying a packed
            // array of xfrm_user_tmpl entries (no per-entry
            // attribute header — just the structs back-to-back).
            let mut payload =
                Vec::with_capacity(self.tmpls.len() * std::mem::size_of::<XfrmUserTmpl>());
            for t in &self.tmpls {
                payload.extend_from_slice(t.as_bytes());
            }
            b.append_attr(XFRMA_TMPL, &payload);
        }
        if let Some((mark, mask)) = self.mark {
            let m = XfrmMark { v: mark, m: mask };
            b.append_attr(XFRMA_MARK, m.as_bytes());
        }
        if let Some(id) = self.if_id {
            b.append_attr_u32(XFRMA_IF_ID, id);
        }
    }
}

#[nlink_macros::send_futures]
impl Connection<Xfrm> {
    /// Subscribe to XFRM multicast notification groups.
    ///
    /// After subscribing, drive the stream with
    /// [`Connection::events`](super::Connection::events) /
    /// [`into_events`](super::Connection::into_events); each frame
    /// parses to an [`XfrmEvent`]. Like every multicast subscription
    /// this is namespace-local to the connection's netns.
    ///
    /// ```no_run
    /// # async fn example() -> nlink::Result<()> {
    /// use nlink::netlink::{Connection, Xfrm};
    /// use nlink::netlink::xfrm::XfrmGroup;
    /// use tokio_stream::StreamExt;
    ///
    /// let conn = Connection::<Xfrm>::new()?;
    /// conn.subscribe(&[XfrmGroup::Sa, XfrmGroup::Expire])?;
    /// let mut events = conn.events().await;
    /// while let Some(evt) = events.next().await {
    ///     println!("{:?}", evt?);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "info", skip(self), fields(groups = ?groups))]
    pub fn subscribe(&self, groups: &[XfrmGroup]) -> Result<()> {
        for group in groups {
            self.socket().add_membership(group.to_group())?;
        }
        Ok(())
    }

    /// Subscribe to every XFRM notification group (SA, policy, expire,
    /// acquire, report, migrate, mapping) — the equivalent of
    /// `ip xfrm monitor` with no type filter.
    #[tracing::instrument(level = "info", skip_all)]
    pub fn subscribe_all(&self) -> Result<()> {
        self.subscribe(&[
            XfrmGroup::Acquire,
            XfrmGroup::Expire,
            XfrmGroup::Sa,
            XfrmGroup::Policy,
            XfrmGroup::Report,
            XfrmGroup::Migrate,
            XfrmGroup::Mapping,
        ])
    }

    /// Create a Security Association.
    ///
    /// Sends `XFRM_MSG_NEWSA` with `NLM_F_CREATE | NLM_F_EXCL`.
    /// Returns `Err` (`EEXIST`) if an SA with the same
    /// (dst, spi, proto) already exists; use [`Self::update_sa`]
    /// (lands in a follow-up slice) to replace in place.
    ///
    /// Common failure modes:
    /// - `EINVAL` — algorithm/key length mismatch, or src/dst
    ///   address-family mismatch.
    /// - `EEXIST` — SA tuple already present.
    /// - `EPROTONOSUPPORT` — kernel lacks the requested algorithm.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_sa"))]
    pub async fn add_sa(&self, sa: XfrmSaBuilder) -> Result<()> {
        let mut b = MessageBuilder::new(
            XFRM_MSG_NEWSA,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        sa.write_into(&mut b);
        self.send_ack(b).await
    }

    /// Delete a Security Association identified by its tuple.
    ///
    /// Sends `XFRM_MSG_DELSA`. The kernel matches on
    /// (`daddr`, `spi`, `proto`, `family`); the source address is
    /// not part of the lookup key.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_sa"))]
    pub async fn del_sa(
        &self,
        src: IpAddr,
        dst: IpAddr,
        spi: u32,
        proto: IpsecProtocol,
    ) -> Result<()> {
        let mut b = MessageBuilder::new(XFRM_MSG_DELSA, NLM_F_REQUEST | NLM_F_ACK);

        // xfrm_usersa_id { daddr, spi, family, proto, _pad }
        let id = XfrmUsersaId {
            daddr: ip_to_xfrm_addr(dst),
            spi: spi.to_be(),
            family: family_for_pair(src, dst),
            proto: proto.number(),
            _pad: 0,
        };
        b.append_bytes(id.as_bytes());

        // Optional XFRMA_SRCADDR — kernel doesn't require it for
        // the lookup but iproute2 includes it for clarity.
        let saddr = ip_to_xfrm_addr(src);
        b.append_attr(XFRMA_SRCADDR, &saddr.bytes);

        self.send_ack(b).await
    }

    /// Delete a Security Association if it exists (#718). `Ok(true)` when
    /// one was deleted, `Ok(false)` when none matched. The kernel answers
    /// that with `ESRCH`, which [`Error::is_not_found`](crate::Error::is_not_found) reads as such for
    /// an xfrm SA request.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_sa_if_exists"))]
    pub async fn del_sa_if_exists(
        &self,
        src: IpAddr,
        dst: IpAddr,
        spi: u32,
        proto: IpsecProtocol,
    ) -> Result<bool> {
        match self.del_sa(src, dst, spi, proto).await {
            Ok(()) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Replace an existing Security Association in place — same
    /// wire shape as [`Self::add_sa`] but with
    /// `NLM_F_CREATE | NLM_F_REPLACE`. The kernel matches on the
    /// (`daddr`, `spi`, `proto`, `family`) tuple from the body and
    /// updates the matching SA's algorithms / encap / mark / etc.
    /// Useful for rotating keys or nudging an SA's mark without a
    /// delete-then-add (which would briefly leave traffic
    /// unprotected).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "update_sa"))]
    pub async fn update_sa(&self, sa: XfrmSaBuilder) -> Result<()> {
        // Plan 221: was XFRM_MSG_NEWSA + NLM_F_CREATE | NLM_F_REPLACE. XFRM dispatches
        // by `nlmsg_type` alone (net/xfrm/xfrm_user.c:917-921) and IGNORES NLM_F_REPLACE,
        // so NEWSA always called xfrm_state_add → EEXIST whenever the target SA existed.
        // The correct dispatch for "replace in place" is XFRM_MSG_UPDSA, no REPLACE flag.
        let mut b = MessageBuilder::new(XFRM_MSG_UPDSA, NLM_F_REQUEST | NLM_F_ACK);
        sa.write_into(&mut b);
        self.send_ack(b).await
    }

    /// Flush every Security Association in the kernel's database.
    ///
    /// Sends `XFRM_MSG_FLUSHSA` with `proto = 0` (which the kernel
    /// reads as IPSEC_PROTO_ANY → all protocols).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_sa"))]
    pub async fn flush_sa(&self) -> Result<()> {
        self.flush_sa_inner(0).await
    }

    /// Flush every Security Association of a specific protocol
    /// (e.g. ESP only). Useful for narrow cleanup that leaves
    /// other-protocol SAs in place.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_sa_proto"))]
    pub async fn flush_sa_proto(&self, proto: IpsecProtocol) -> Result<()> {
        self.flush_sa_inner(proto.number()).await
    }

    async fn flush_sa_inner(&self, proto: u8) -> Result<()> {
        let mut b = MessageBuilder::new(XFRM_MSG_FLUSHSA, NLM_F_REQUEST | NLM_F_ACK);
        let body = XfrmUsersaFlush {
            proto,
            _pad: [0; 7],
        };
        b.append_bytes(body.as_bytes());
        self.send_ack(b).await
    }

    /// Fetch a single Security Association by its tuple. Returns
    /// `Ok(None)` if no SA matches (kernel returns ENOENT).
    ///
    /// Sends `XFRM_MSG_GETSA` with an `XfrmUsersaId` body — same
    /// shape as [`Self::del_sa`]'s lookup key. The response is a
    /// single `XFRM_MSG_NEWSA`-style message carrying the SA, or a
    /// `NLMSG_ERROR` with `errno=ENOENT` when nothing matches.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_sa"))]
    pub async fn get_sa(
        &self,
        src: IpAddr,
        dst: IpAddr,
        spi: u32,
        proto: IpsecProtocol,
    ) -> Result<Option<SecurityAssociation>> {
        let mut b = MessageBuilder::new(XFRM_MSG_GETSA, NLM_F_REQUEST);
        let id = XfrmUsersaId {
            daddr: ip_to_xfrm_addr(dst),
            spi: spi.to_be(),
            family: family_for_pair(src, dst),
            proto: proto.number(),
            _pad: 0,
        };
        b.append_bytes(id.as_bytes());
        let saddr = ip_to_xfrm_addr(src);
        b.append_attr(XFRMA_SRCADDR, &saddr.bytes);

        match self.send_request(b).await {
            Ok(response) => Ok(Self::parse_sa_msg(&response)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Create a Security Policy.
    ///
    /// Sends `XFRM_MSG_NEWPOLICY` with `NLM_F_CREATE | NLM_F_EXCL`.
    /// Returns `EEXIST` if a policy with the same (selector, dir,
    /// index) already exists; use [`Self::update_sp`] to replace.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_sp"))]
    pub async fn add_sp(&self, sp: XfrmSpBuilder) -> Result<()> {
        let mut b = MessageBuilder::new(
            XFRM_MSG_NEWPOLICY,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        sp.write_into(&mut b);
        self.send_ack(b).await
    }

    /// Replace an existing Security Policy in place — same wire
    /// shape as [`Self::add_sp`] but with
    /// `NLM_F_CREATE | NLM_F_REPLACE`. Match key is the
    /// `(selector, dir)` from the body.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "update_sp"))]
    pub async fn update_sp(&self, sp: XfrmSpBuilder) -> Result<()> {
        // Plan 221: same bug class as update_sa above — was XFRM_MSG_NEWPOLICY with
        // NLM_F_CREATE | NLM_F_REPLACE; XFRM ignores NLM_F_REPLACE and dispatches by
        // nlmsg_type, so NEWPOLICY called xfrm_policy_insert(excl=1) → EEXIST. The
        // correct dispatch for "replace in place" is XFRM_MSG_UPDPOLICY.
        let mut b = MessageBuilder::new(XFRM_MSG_UPDPOLICY, NLM_F_REQUEST | NLM_F_ACK);
        sp.write_into(&mut b);
        self.send_ack(b).await
    }

    /// Delete a Security Policy by `(selector, direction)`.
    /// Sends `XFRM_MSG_DELPOLICY` with an `XfrmUserpolicyId` body.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_sp"))]
    pub async fn del_sp(&self, sel: XfrmSelector, direction: PolicyDirection) -> Result<()> {
        let mut b = MessageBuilder::new(XFRM_MSG_DELPOLICY, NLM_F_REQUEST | NLM_F_ACK);
        let id = XfrmUserpolicyId {
            sel,
            index: 0,
            dir: direction.number(),
            _pad: [0; 3],
        };
        b.append_bytes(id.as_bytes());
        self.send_ack(b).await
    }

    /// Delete a Security Policy if it exists (#718). `Ok(true)` when one
    /// was deleted, `Ok(false)` when none matched: the kernel answers that
    /// with `ENOENT`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_sp_if_exists"))]
    pub async fn del_sp_if_exists(&self, sel: XfrmSelector, direction: PolicyDirection) -> Result<bool> {
        match self.del_sp(sel, direction).await {
            Ok(()) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Flush every Security Policy in the kernel's database.
    /// Sends `XFRM_MSG_FLUSHPOLICY`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_sp"))]
    pub async fn flush_sp(&self) -> Result<()> {
        let b = MessageBuilder::new(XFRM_MSG_FLUSHPOLICY, NLM_F_REQUEST | NLM_F_ACK);
        self.send_ack(b).await
    }

    /// Fetch a single Security Policy by `(selector, direction)`.
    /// Returns `Ok(None)` if no policy matches.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_sp"))]
    pub async fn get_sp(
        &self,
        sel: XfrmSelector,
        direction: PolicyDirection,
    ) -> Result<Option<SecurityPolicy>> {
        let mut b = MessageBuilder::new(XFRM_MSG_GETPOLICY, NLM_F_REQUEST);
        let id = XfrmUserpolicyId {
            sel,
            index: 0,
            dir: direction.number(),
            _pad: [0; 3],
        };
        b.append_bytes(id.as_bytes());

        match self.send_request(b).await {
            Ok(response) => Ok(Self::parse_policy_msg(&response)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Get all Security Associations.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Xfrm};
    ///
    /// let conn = Connection::<Xfrm>::new()?;
    /// let sas = conn.get_security_associations().await?;
    ///
    /// for sa in &sas {
    ///     println!("{:?} -> {:?} SPI={:08x} proto={:?}",
    ///         sa.src_addr, sa.dst_addr, sa.spi, sa.protocol);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_security_associations")
    )]
    pub async fn get_security_associations(&self) -> Result<Vec<SecurityAssociation>> {
        // #134 — dual-mode recv. Mutex mode: the session holds the
        // request lock for the whole send+recv (the F1 fix). Dispatcher
        // mode: it registers the seq (+ dump-serialization lock) so the
        // driver routes frames here instead of the loop racing the
        // driver's recv_msg. Built BEFORE with_timeout so it spans the
        // timeout window.
        let seq = self.socket().next_seq();
        let pid = self.socket().pid();
        let mut session = self.recv_session_dump(seq).await?;
        // Plan 208 Phase 1+2 — wrap in with_timeout, add seq filter,
        // detect NLM_F_DUMP_INTR.
        self.with_timeout(async move {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&0u32.to_ne_bytes());
            buf.extend_from_slice(&XFRM_MSG_GETSA.to_ne_bytes());
            buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
            buf.extend_from_slice(&seq.to_ne_bytes());
            buf.extend_from_slice(&pid.to_ne_bytes());

            // Header-only body (#160): the XFRM dump callbacks parse the
            // entire body as netlink attributes (hdrlen = 0), so a raw
            // xfrm_usersa_info struct here is unparsed trailing data and
            // triggers the kernel's ratelimited "N bytes leftover after
            // parsing attributes" warning. Filters, if ever wanted, must
            // be expressed as attributes (XFRMA_ADDRESS_FILTER, ...).

            let len = buf.len() as u32;
            buf[0..4].copy_from_slice(&len.to_ne_bytes());

            self.socket().send(&buf).await?;

            let mut sas = Vec::new();

            loop {
                let data = session.recv_with_timeout(self).await?;

                let mut offset = 0;
                while offset + NLMSG_HDRLEN <= data.len() {
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

                    if nlmsg_len < NLMSG_HDRLEN || offset + nlmsg_len > data.len() {
                        break;
                    }
                    if nlmsg_seq != seq {
                        offset += (nlmsg_len + 3) & !3;
                        continue;
                    }
                    // NLM_F_DUMP_INTR = 0x10
                    if nlmsg_flags & 0x10 != 0 {
                        return Err(crate::netlink::Error::dump_interrupted());
                    }

                    match nlmsg_type {
                        // The dump's result code is in the DONE
                        // payload; ignoring it turned a failed dump
                        // into a short, successful-looking list (#267).
                        NLMSG_DONE => {
                            done_result(&data[offset + 16..offset + nlmsg_len])?;
                            return Ok(sas);
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
                            if let Some(sa) = self.parse_sa(&data[offset..offset + nlmsg_len]) {
                                sas.push(sa);
                            }
                        }
                    }

                    offset += (nlmsg_len + 3) & !3;
                }
            }
        })
        .await
    }

    /// Get all Security Policies.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Xfrm};
    ///
    /// let conn = Connection::<Xfrm>::new()?;
    /// let policies = conn.get_security_policies().await?;
    ///
    /// for pol in &policies {
    ///     println!("dir={:?} action={:?} priority={}",
    ///         pol.direction, pol.action, pol.priority);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_security_policies"))]
    pub async fn get_security_policies(&self) -> Result<Vec<SecurityPolicy>> {
        // #134 — dual-mode recv (dump); see `get_security_associations`.
        let seq = self.socket().next_seq();
        let pid = self.socket().pid();
        let mut session = self.recv_session_dump(seq).await?;
        // Plan 208 Phase 1+2 — wrap in with_timeout, seq filter,
        // NLM_F_DUMP_INTR detection.
        self.with_timeout(async move {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&0u32.to_ne_bytes());
            buf.extend_from_slice(&XFRM_MSG_GETPOLICY.to_ne_bytes());
            buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
            buf.extend_from_slice(&seq.to_ne_bytes());
            buf.extend_from_slice(&pid.to_ne_bytes());

            // Header-only body (#160) — see get_security_associations.

            let len = buf.len() as u32;
            buf[0..4].copy_from_slice(&len.to_ne_bytes());

            self.socket().send(&buf).await?;

            let mut policies = Vec::new();

            loop {
                let data = session.recv_with_timeout(self).await?;

                let mut offset = 0;
                while offset + NLMSG_HDRLEN <= data.len() {
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

                    if nlmsg_len < NLMSG_HDRLEN || offset + nlmsg_len > data.len() {
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
                            return Ok(policies);
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
                            if let Some(pol) = self.parse_policy(&data[offset..offset + nlmsg_len])
                            {
                                policies.push(pol);
                            }
                        }
                    }

                    offset += (nlmsg_len + 3) & !3;
                }
            }
        })
        .await
    }

    /// Parse a Security Association from a netlink message.
    fn parse_sa(&self, data: &[u8]) -> Option<SecurityAssociation> {
        Self::parse_sa_msg(data)
    }

    /// Parse a Security Association from a netlink message buffer
    /// (`nlmsghdr` + `xfrm_usersa_info` + attributes). Associated
    /// function (no `&self`) so unit tests can call it via
    /// `Connection::<Xfrm>::parse_sa_msg(...)` without needing a
    /// live socket.
    fn parse_sa_msg(data: &[u8]) -> Option<SecurityAssociation> {
        if data.len() < NLMSG_HDRLEN {
            return None;
        }
        parse_sa_payload(&data[NLMSG_HDRLEN..])
    }

    /// Parse a Security Policy from a netlink message.
    fn parse_policy(&self, data: &[u8]) -> Option<SecurityPolicy> {
        Self::parse_policy_msg(data)
    }

    /// Parse a Security Policy from a netlink message buffer.
    /// Associated function so unit tests can call it via
    /// `Connection::<Xfrm>::parse_policy_msg(...)` without a live
    /// socket.
    fn parse_policy_msg(data: &[u8]) -> Option<SecurityPolicy> {
        if data.len() < NLMSG_HDRLEN {
            return None;
        }
        parse_sp_payload(&data[NLMSG_HDRLEN..])
    }
}

/// Parse a Security Association from a `xfrm_usersa_info`-prefixed
/// payload (everything after `nlmsghdr` in a `XFRM_MSG_NEWSA` /
/// `_GETSA` reply or `XFRM_MSG_EXPIRE` notification). Plumbed via
/// [`FromNetlink`] for the streaming-dump path
/// ([`Connection::stream_sas`](super::Connection::stream_sas)).
pub(crate) fn parse_sa_payload(msg_data: &[u8]) -> Option<SecurityAssociation> {
    if msg_data.len() < std::mem::size_of::<XfrmUsersaInfo>() {
        return None;
    }
    let (info, _) = XfrmUsersaInfo::ref_from_prefix(msg_data).ok()?;

    let mut sa = SecurityAssociation {
        src_addr: info.saddr.to_ip(info.family),
        dst_addr: info.id.daddr.to_ip(info.family),
        spi: u32::from_be(info.id.spi),
        protocol: IpsecProtocol::from_u8(info.id.proto),
        mode: XfrmMode::from_u8(info.mode),
        reqid: info.reqid,
        selector: TrafficSelector::from_selector(info.sel),
        enc_alg: None,
        auth_alg: None,
        aead_alg: None,
        auth_trunc_alg: None,
        comp_alg: None,
        encap: None,
        mark: None,
        if_id: None,
        pcpu: None,
        bytes: info.curlft.bytes,
        packets: info.curlft.packets,
        replay_window: info.replay_window,
        flags: info.flags,
    };

    let attr_start = std::mem::size_of::<XfrmUsersaInfo>();
    if msg_data.len() > attr_start {
        let mut input = &msg_data[attr_start..];
        while let Some((attr_type, attr_data)) = parse_nla(&mut input) {
            match attr_type {
                XFRMA_ALG_CRYPT => {
                    sa.enc_alg = parse_algorithm(attr_data);
                }
                XFRMA_ALG_AUTH => {
                    sa.auth_alg = parse_algorithm(attr_data);
                }
                XFRMA_ALG_AEAD => {
                    sa.aead_alg = parse_aead_algorithm(attr_data);
                }
                XFRMA_ALG_AUTH_TRUNC => {
                    sa.auth_trunc_alg = parse_auth_trunc_algorithm(attr_data);
                }
                XFRMA_ALG_COMP => {
                    sa.comp_alg = parse_algorithm(attr_data);
                }
                XFRMA_ENCAP => {
                    if attr_data.len() >= std::mem::size_of::<XfrmEncapTmpl>()
                        && let Ok((encap, _)) = XfrmEncapTmpl::ref_from_prefix(attr_data)
                    {
                        sa.encap = Some(*encap);
                    }
                }
                XFRMA_MARK => {
                    if attr_data.len() >= std::mem::size_of::<XfrmMark>()
                        && let Ok((mark, _)) = XfrmMark::ref_from_prefix(attr_data)
                    {
                        sa.mark = Some(*mark);
                    }
                }
                XFRMA_SA_PCPU if attr_data.len() >= 4 => {
                    sa.pcpu = Some(u32::from_ne_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                }
                XFRMA_IF_ID if attr_data.len() >= 4 => {
                    sa.if_id = Some(u32::from_ne_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                }
                _ => {}
            }
        }
    }

    Some(sa)
}

/// Parse a Security Policy from a `xfrm_userpolicy_info`-prefixed
/// payload (everything after `nlmsghdr` in a
/// `XFRM_MSG_NEWPOLICY` / `_GETPOLICY` reply). Plumbed via
/// [`FromNetlink`] for the streaming-dump path
/// ([`Connection::stream_sps`](super::Connection::stream_sps)).
pub(crate) fn parse_sp_payload(msg_data: &[u8]) -> Option<SecurityPolicy> {
    if msg_data.len() < std::mem::size_of::<XfrmUserpolicyInfo>() {
        return None;
    }
    let (info, _) = XfrmUserpolicyInfo::ref_from_prefix(msg_data).ok()?;

    let mut policy = SecurityPolicy {
        selector: TrafficSelector::from_selector(info.sel),
        direction: PolicyDirection::from_u8(info.dir),
        action: PolicyAction::from_u8(info.action),
        priority: info.priority,
        index: info.index,
        flags: info.flags,
        mark: None,
        if_id: None,
    };

    let attr_start = std::mem::size_of::<XfrmUserpolicyInfo>();
    if msg_data.len() > attr_start {
        let mut input = &msg_data[attr_start..];
        while let Some((attr_type, attr_data)) = parse_nla(&mut input) {
            match attr_type {
                XFRMA_MARK => {
                    if attr_data.len() >= std::mem::size_of::<XfrmMark>()
                        && let Ok((mark, _)) = XfrmMark::ref_from_prefix(attr_data)
                    {
                        policy.mark = Some(*mark);
                    }
                }
                XFRMA_IF_ID if attr_data.len() >= 4 => {
                    policy.if_id = Some(u32::from_ne_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]));
                }
                _ => {}
            }
        }
    }

    Some(policy)
}

/// Parse a netlink attribute.
fn parse_nla<'a>(input: &mut &'a [u8]) -> Option<(u16, &'a [u8])> {
    if input.len() < 4 {
        return None;
    }

    // 0.19 N3 — netlink attribute nla_len / nla_type are kernel
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

// ============================================================================
// Monitor / event stream (XFRM multicast notifications) — #137
// ============================================================================

/// An XFRM multicast notification group (`XFRMNLGRP_*` in
/// `linux/xfrm.h`). Pass to [`Connection::subscribe`] to receive the
/// matching [`XfrmEvent`]s on the connection's event stream.
///
/// The kernel multicast-group *number* (what `NETLINK_ADD_MEMBERSHIP`
/// takes) equals the `XFRMNLGRP_*` enum value directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum XfrmGroup {
    /// SA-negotiation requests (`XFRM_MSG_ACQUIRE`) — the trigger an
    /// IKE daemon watches.
    Acquire,
    /// SA / policy lifetime expiry (`XFRM_MSG_EXPIRE`, `_POLEXPIRE`).
    Expire,
    /// SA add / delete / update (`XFRM_MSG_NEWSA`/`DELSA`/`UPDSA`,
    /// plus `FLUSHSA`).
    Sa,
    /// Policy add / delete / update (`XFRM_MSG_NEWPOLICY`/`DELPOLICY`/
    /// `UPDPOLICY`, plus `FLUSHPOLICY`).
    Policy,
    /// Async-event reports (`XFRM_MSG_REPORT`).
    Report,
    /// Policy migration (`XFRM_MSG_MIGRATE`).
    Migrate,
    /// NAT mapping changes (`XFRM_MSG_MAPPING`).
    Mapping,
}

impl XfrmGroup {
    /// Raw `XFRMNLGRP_*` multicast group number.
    fn to_group(self) -> u32 {
        match self {
            Self::Acquire => 1, // XFRMNLGRP_ACQUIRE
            Self::Expire => 2,  // XFRMNLGRP_EXPIRE
            Self::Sa => 3,      // XFRMNLGRP_SA
            Self::Policy => 4,  // XFRMNLGRP_POLICY
            Self::Report => 6,  // XFRMNLGRP_REPORT
            Self::Migrate => 7, // XFRMNLGRP_MIGRATE
            Self::Mapping => 8, // XFRMNLGRP_MAPPING
        }
    }
}

/// Compact identifier for a deleted SA (`XFRM_MSG_DELSA` carries
/// `xfrm_usersa_id`, not the full SA state).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct XfrmSaId {
    /// Destination address.
    pub dst_addr: Option<IpAddr>,
    /// Security Parameter Index.
    pub spi: u32,
    /// IPsec protocol.
    pub protocol: IpsecProtocol,
}

/// Compact identifier for a deleted policy (`XFRM_MSG_DELPOLICY`
/// carries `xfrm_userpolicy_id`).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct XfrmPolicyId {
    /// Traffic selector the policy matched.
    pub selector: TrafficSelector,
    /// Policy index.
    pub index: u32,
    /// Policy direction.
    pub direction: PolicyDirection,
}

/// `xfrm_user_acquire` — body of an `XFRM_MSG_ACQUIRE` notification.
/// Fixed-layout prefix (no trailing attrs are parsed here). Wire size
/// 280 bytes: `xfrm_id`(24) + `xfrm_address_t`(16) +
/// `xfrm_selector`(56) + `xfrm_userpolicy_info`(168) + 4×u32(16).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct XfrmUserAcquire {
    id: XfrmId,
    saddr: XfrmAddress,
    sel: XfrmSelector,
    policy: XfrmUserpolicyInfo,
    aalgos: u32,
    ealgos: u32,
    calgos: u32,
    seq: u32,
}

/// An XFRM notification delivered on a subscribed multicast group.
///
/// Obtain a stream with [`Connection::subscribe`] (or
/// [`Connection::subscribe_all`]) followed by
/// [`Connection::events`](super::Connection::events). The enum is
/// `#[non_exhaustive]`: the kernel's `XFRM_MSG_*` notification set
/// grows, and unmodelled types surface as [`XfrmEvent::Other`] rather
/// than being silently dropped.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum XfrmEvent {
    /// SA added or updated (`XFRM_MSG_NEWSA` / `UPDSA`).
    NewSa(SecurityAssociation),
    /// SA deleted (`XFRM_MSG_DELSA`) — compact id only.
    DelSa(XfrmSaId),
    /// SA lifetime threshold crossed (`XFRM_MSG_EXPIRE`). `hard`
    /// distinguishes the soft (rekey-soon) from the hard (SA dead)
    /// limit.
    ExpireSa {
        /// The expiring SA (identity + counters; algorithms omitted).
        sa: SecurityAssociation,
        /// `true` for the hard limit, `false` for the soft limit.
        hard: bool,
    },
    /// Policy added or updated (`XFRM_MSG_NEWPOLICY` / `UPDPOLICY`).
    NewPolicy(SecurityPolicy),
    /// Policy deleted (`XFRM_MSG_DELPOLICY`) — compact id only.
    DelPolicy(XfrmPolicyId),
    /// Policy lifetime threshold crossed (`XFRM_MSG_POLEXPIRE`).
    ExpirePolicy {
        /// The expiring policy.
        policy: SecurityPolicy,
        /// `true` for the hard limit, `false` for the soft limit.
        hard: bool,
    },
    /// Kernel requests SA negotiation for matching traffic
    /// (`XFRM_MSG_ACQUIRE`).
    Acquire {
        /// Traffic selector that triggered the acquire.
        selector: TrafficSelector,
        /// Policy demanding the SA.
        policy: SecurityPolicy,
    },
    /// Async-event report (`XFRM_MSG_REPORT`).
    Report {
        /// IPsec protocol the report concerns.
        protocol: IpsecProtocol,
        /// Affected traffic selector.
        selector: TrafficSelector,
    },
    /// All SAs flushed (`XFRM_MSG_FLUSHSA`).
    FlushSa,
    /// All policies flushed (`XFRM_MSG_FLUSHPOLICY`).
    FlushPolicy,
    /// A notification nlink does not model in detail (e.g.
    /// `XFRM_MSG_MIGRATE`, `XFRM_MSG_MAPPING`). Surfaced by message
    /// type so monitors can still report it.
    Other {
        /// The raw `XFRM_MSG_*` message type.
        msg_type: u16,
    },
}

/// Parse one XFRM notification message body (everything after the
/// `nlmsghdr`) into an [`XfrmEvent`]. Returns `None` for messages that
/// carry no actionable notification (e.g. an `NLMSG_DONE` / error
/// frame whose type we ignore) or that are too short to parse.
fn parse_xfrm_event(msg_type: u16, body: &[u8]) -> Option<XfrmEvent> {
    match msg_type {
        XFRM_MSG_NEWSA | XFRM_MSG_UPDSA => parse_sa_payload(body).map(XfrmEvent::NewSa),
        XFRM_MSG_DELSA => {
            let (id, _) = XfrmUsersaId::ref_from_prefix(body).ok()?;
            Some(XfrmEvent::DelSa(XfrmSaId {
                dst_addr: id.daddr.to_ip(id.family),
                spi: u32::from_be(id.spi),
                protocol: IpsecProtocol::from_u8(id.proto),
            }))
        }
        XFRM_MSG_EXPIRE => {
            // xfrm_user_expire = xfrm_usersa_info + u8 hard. Parse the
            // SA from just the fixed prefix (so the attr-walk sees no
            // input), then read the trailing `hard` byte.
            let info_size = std::mem::size_of::<XfrmUsersaInfo>();
            let sa = parse_sa_payload(body.get(..info_size)?)?;
            let hard = body.get(info_size).copied().unwrap_or(0) != 0;
            Some(XfrmEvent::ExpireSa { sa, hard })
        }
        XFRM_MSG_NEWPOLICY | XFRM_MSG_UPDPOLICY => parse_sp_payload(body).map(XfrmEvent::NewPolicy),
        XFRM_MSG_DELPOLICY => {
            let (id, _) = XfrmUserpolicyId::ref_from_prefix(body).ok()?;
            Some(XfrmEvent::DelPolicy(XfrmPolicyId {
                selector: TrafficSelector::from_selector(id.sel),
                index: id.index,
                direction: PolicyDirection::from_u8(id.dir),
            }))
        }
        XFRM_MSG_POLEXPIRE => {
            // xfrm_user_polexpire = xfrm_userpolicy_info + u8 hard.
            let info_size = std::mem::size_of::<XfrmUserpolicyInfo>();
            let policy = parse_sp_payload(body.get(..info_size)?)?;
            let hard = body.get(info_size).copied().unwrap_or(0) != 0;
            Some(XfrmEvent::ExpirePolicy { policy, hard })
        }
        XFRM_MSG_ACQUIRE => {
            let (acq, _) = XfrmUserAcquire::ref_from_prefix(body).ok()?;
            let selector = TrafficSelector::from_selector(acq.sel);
            // The embedded policy is followed by the algorithm bitmasks,
            // not attrs — slice to exactly the policy struct so
            // parse_sp_payload's attr-walk sees nothing.
            let pol_off = std::mem::size_of::<XfrmId>()
                + std::mem::size_of::<XfrmAddress>()
                + std::mem::size_of::<XfrmSelector>();
            let pol_end = pol_off + std::mem::size_of::<XfrmUserpolicyInfo>();
            let policy = parse_sp_payload(body.get(pol_off..pol_end)?)?;
            Some(XfrmEvent::Acquire { selector, policy })
        }
        XFRM_MSG_REPORT => {
            // xfrm_user_report = u8 proto + xfrm_selector. The selector
            // is u32-aligned, so it begins at offset 4 (3 pad bytes).
            let proto = *body.first()?;
            let (sel, _) = XfrmSelector::ref_from_prefix(body.get(4..)?).ok()?;
            Some(XfrmEvent::Report {
                protocol: IpsecProtocol::from_u8(proto),
                selector: TrafficSelector::from_selector(*sel),
            })
        }
        XFRM_MSG_FLUSHSA => Some(XfrmEvent::FlushSa),
        XFRM_MSG_FLUSHPOLICY => Some(XfrmEvent::FlushPolicy),
        // GETSA/GETPOLICY/ALLOCSPI etc. are request types, never
        // multicast notifications; ignore. Everything else we don't
        // model (MIGRATE, MAPPING, *AE, *INFO) surfaces by type.
        XFRM_MSG_GETSA | XFRM_MSG_GETPOLICY => None,
        t if (XFRM_MSG_NEWSA..=XFRM_MSG_REPORT + 6).contains(&t) => {
            Some(XfrmEvent::Other { msg_type: t })
        }
        _ => None,
    }
}

/// Parse all XFRM notifications from a received buffer. Walks
/// [`MessageIter`], skipping malformed frames (Parser-robustness
/// rule 3 — one bad frame must not kill a long-lived subscriber).
pub(crate) fn parse_xfrm_events(data: &[u8]) -> Vec<XfrmEvent> {
    let mut events = Vec::new();
    for (header, payload) in super::message::MessageIter::new(data).flatten() {
        if let Some(event) = parse_xfrm_event(header.nlmsg_type, payload) {
            events.push(event);
        }
    }
    events
}

/// Parse an XFRM algorithm.
fn parse_algorithm(data: &[u8]) -> Option<XfrmAlgorithm> {
    // Algorithm structure: 64-byte name + 4-byte key_len + key data
    if data.len() < 68 {
        return None;
    }

    let name = parse_cstring(&data[..64]);
    // 0.19 N3 — `unsigned int alg_key_len` in xfrm.h is host-order.
    let key_len = u32::from_ne_bytes([data[64], data[65], data[66], data[67]]);
    let key_bytes = (key_len as usize).div_ceil(8);
    let key = if data.len() >= 68 + key_bytes {
        data[68..68 + key_bytes].to_vec()
    } else {
        Vec::new()
    };

    Some(XfrmAlgorithm { name, key_len, key })
}

/// Parse an XFRM AEAD algorithm.
fn parse_aead_algorithm(data: &[u8]) -> Option<XfrmAlgorithmAead> {
    // AEAD structure: 64-byte name + 4-byte key_len + 4-byte icv_len + key data
    if data.len() < 72 {
        return None;
    }

    let name = parse_cstring(&data[..64]);
    // 0.19 N3 — `alg_key_len` / `alg_icv_len` are host-order.
    let key_len = u32::from_ne_bytes([data[64], data[65], data[66], data[67]]);
    let icv_len = u32::from_ne_bytes([data[68], data[69], data[70], data[71]]);
    let key_bytes = (key_len as usize).div_ceil(8);
    let key = if data.len() >= 72 + key_bytes {
        data[72..72 + key_bytes].to_vec()
    } else {
        Vec::new()
    };

    Some(XfrmAlgorithmAead {
        name,
        key_len,
        icv_len,
        key,
    })
}

/// Parse an XFRM authentication algorithm with truncation.
fn parse_auth_trunc_algorithm(data: &[u8]) -> Option<XfrmAlgorithmAuthTrunc> {
    // Auth trunc structure: 64-byte name + 4-byte key_len + 4-byte trunc_len + key data
    if data.len() < 72 {
        return None;
    }

    let name = parse_cstring(&data[..64]);
    // 0.19 N3 — `alg_key_len` / `alg_trunc_len` are host-order.
    let key_len = u32::from_ne_bytes([data[64], data[65], data[66], data[67]]);
    let trunc_len = u32::from_ne_bytes([data[68], data[69], data[70], data[71]]);
    let key_bytes = (key_len as usize).div_ceil(8);
    let key = if data.len() >= 72 + key_bytes {
        data[72..72 + key_bytes].to_vec()
    } else {
        Vec::new()
    };

    Some(XfrmAlgorithmAuthTrunc {
        name,
        key_len,
        trunc_len,
        key,
    })
}

/// Parse a C string from a fixed-size buffer.
fn parse_cstring(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xfrm_address_ipv4() {
        let addr = XfrmAddress::from_v4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(
            addr.to_ip(2),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn xfrm_address_ipv6() {
        let addr = XfrmAddress::from_v6(Ipv6Addr::LOCALHOST);
        assert_eq!(addr.to_ip(10), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn ipsec_protocol_roundtrip() {
        assert_eq!(IpsecProtocol::Esp.number(), 50);
        assert_eq!(IpsecProtocol::from_u8(50), IpsecProtocol::Esp);

        assert_eq!(IpsecProtocol::Ah.number(), 51);
        assert_eq!(IpsecProtocol::from_u8(51), IpsecProtocol::Ah);
    }

    #[test]
    fn xfrm_mode_from_u8() {
        assert_eq!(XfrmMode::from_u8(0), XfrmMode::Transport);
        assert_eq!(XfrmMode::from_u8(1), XfrmMode::Tunnel);
        assert_eq!(XfrmMode::from_u8(4), XfrmMode::Beet);
    }

    #[test]
    fn policy_direction_from_u8() {
        assert_eq!(PolicyDirection::from_u8(0), PolicyDirection::In);
        assert_eq!(PolicyDirection::from_u8(1), PolicyDirection::Out);
        assert_eq!(PolicyDirection::from_u8(2), PolicyDirection::Forward);
    }

    #[test]
    fn zerocopy_sizes() {
        assert_eq!(std::mem::size_of::<XfrmAddress>(), 16);
        assert_eq!(std::mem::size_of::<XfrmId>(), 24);
        assert_eq!(std::mem::size_of::<XfrmMark>(), 8);
        // New write-path structs:
        assert_eq!(std::mem::size_of::<XfrmUsersaId>(), 24);
        assert_eq!(std::mem::size_of::<XfrmUsersaFlush>(), 8);
        // Plan 153.1 XFRMA_OFFLOAD_DEV — 4-byte ifindex + 1 byte
        // flags + 3 bytes pad = 8 bytes per kernel UAPI.
        assert_eq!(std::mem::size_of::<XfrmUserOffload>(), 8);
    }

    #[test]
    fn xfrm_offload_flag_bitops() {
        let combined = XfrmOffloadFlag::IPV6 | XfrmOffloadFlag::PACKET;
        assert!(combined.contains(XfrmOffloadFlag::IPV6));
        assert!(combined.contains(XfrmOffloadFlag::PACKET));
        assert!(!combined.contains(XfrmOffloadFlag::INBOUND));
        assert_eq!(combined.bits(), 0x1 | 0x4);

        let mut acc = XfrmOffloadFlag::empty();
        acc |= XfrmOffloadFlag::INBOUND;
        assert!(acc.contains(XfrmOffloadFlag::INBOUND));
        assert!(!acc.contains(XfrmOffloadFlag::IPV6));
    }

    #[test]
    fn xfrm_offload_kernel_constants() {
        // Values from include/uapi/linux/xfrm.h. Stable ABI; must
        // not drift. Plan 221: XFRMA_OFFLOAD_DEV was previously
        // hardcoded to 26 — which is XFRMA_ADDRESS_FILTER, a 24-byte
        // struct, not the 8-byte xfrm_user_offload. Every offload(...)
        // call was silently emitting under the wrong attribute id and
        // the kernel was either rejecting it with EINVAL (strict-check
        // kernels) or silently dropping the offload (lenient kernels).
        // Correct value is 28.
        assert_eq!(XfrmOffloadFlag::IPV6.bits(), 0x1);
        assert_eq!(XfrmOffloadFlag::INBOUND.bits(), 0x2);
        assert_eq!(XfrmOffloadFlag::PACKET.bits(), 0x4);
        assert_eq!(XFRMA_OFFLOAD_DEV, 28);
    }

    /// Plan 221: lock all 5 XFRM constants that were mis-counted from
    /// the kernel UAPI enum. Without this assertion-bundle, a future
    /// commit could re-introduce the off-by-N error.
    /// `scripts/audit-uapi-constants.sh` also checks every constant in
    /// this file against the kernel headers (#167).
    #[test]
    fn xfrm_msg_and_attr_constants_match_kernel_uapi() {
        // Kernel UAPI v6.13 — include/uapi/linux/xfrm.h.
        assert_eq!(XFRM_MSG_NEWSA, 16);
        assert_eq!(XFRM_MSG_DELSA, 17);
        assert_eq!(XFRM_MSG_GETSA, 18);
        assert_eq!(XFRM_MSG_NEWPOLICY, 19);
        assert_eq!(XFRM_MSG_DELPOLICY, 20);
        assert_eq!(XFRM_MSG_GETPOLICY, 21);
        assert_eq!(XFRM_MSG_UPDPOLICY, 25);
        assert_eq!(XFRM_MSG_UPDSA, 26);
        assert_eq!(XFRM_MSG_FLUSHSA, 28);
        assert_eq!(XFRM_MSG_FLUSHPOLICY, 29);
        assert_eq!(XFRMA_SRCADDR, 13);
        assert_eq!(XFRMA_OFFLOAD_DEV, 28);
    }

    #[test]
    fn xfrm_user_offload_struct_init() {
        let off = XfrmUserOffload::new(7, XfrmOffloadFlag::IPV6 | XfrmOffloadFlag::PACKET);
        assert_eq!(off.ifindex, 7);
        assert_eq!(off.flags, 0x5);
        assert_eq!(off._pad, [0, 0, 0]);
    }

    // ==========================================================
    // XfrmSaBuilder — Plan 141 PR A wire-format round-trip tests
    // ==========================================================

    use super::{Connection, Xfrm};

    /// Build an `add_sa` request via XfrmSaBuilder + MessageBuilder
    /// and return the full netlink frame (header + body + attrs).
    fn build_add_sa_frame(sa: XfrmSaBuilder) -> Vec<u8> {
        let mut b = MessageBuilder::new(
            XFRM_MSG_NEWSA,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        sa.write_into(&mut b);
        b.finish()
    }

    #[test]
    fn xfrm_sa_v4_esp_separate_auth_encr_roundtrips_through_parse_sa() {
        let sa = XfrmSaBuilder::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            0xdead_beef,
            IpsecProtocol::Esp,
        )
        .mode(XfrmMode::Tunnel)
        .reqid(42)
        .auth_hmac_sha256(&[0u8; 32])
        .encr_aes_cbc(&[0u8; 16]);

        let frame = build_add_sa_frame(sa);
        let parsed = Connection::<Xfrm>::parse_sa_msg(&frame)
            .expect("parse_sa must round-trip XfrmSaBuilder output");

        assert_eq!(
            parsed.src_addr,
            Some(IpAddr::V4("10.0.0.1".parse().unwrap()))
        );
        assert_eq!(
            parsed.dst_addr,
            Some(IpAddr::V4("10.0.0.2".parse().unwrap()))
        );
        assert_eq!(parsed.spi, 0xdead_beef);
        assert_eq!(parsed.protocol, IpsecProtocol::Esp);
        assert_eq!(parsed.mode, XfrmMode::Tunnel);
        assert_eq!(parsed.reqid, 42);
        assert_eq!(parsed.replay_window, 32, "default replay window");

        let auth = parsed.auth_alg.expect("auth alg present");
        assert_eq!(auth.name, "hmac(sha256)");
        assert_eq!(auth.key_len, 32 * 8, "key_len_bits");
        assert_eq!(auth.key.len(), 32);

        let encr = parsed.enc_alg.expect("encr alg present");
        assert_eq!(encr.name, "cbc(aes)");
        assert_eq!(encr.key_len, 16 * 8);
        assert_eq!(encr.key.len(), 16);
    }

    #[test]
    fn xfrm_sa_v4_esp_aead_aes_gcm_roundtrips() {
        // AEAD AES-GCM-128: 16-byte key + 4-byte salt = 20 bytes;
        // ICV truncbits = 128.
        let key = [0xAAu8; 20];
        let sa = XfrmSaBuilder::new(
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            0x12345678,
            IpsecProtocol::Esp,
        )
        .mode(XfrmMode::Transport)
        .reqid(7)
        .aead_aes_gcm(&key, 128);

        let frame = build_add_sa_frame(sa);
        let parsed =
            Connection::<Xfrm>::parse_sa_msg(&frame).expect("parse_sa must round-trip AEAD SA");

        assert_eq!(parsed.spi, 0x12345678);
        assert_eq!(parsed.mode, XfrmMode::Transport);
        let aead = parsed.aead_alg.expect("aead alg present");
        assert_eq!(aead.name, "rfc4106(gcm(aes))");
        assert_eq!(aead.key_len, key.len() as u32 * 8);
        assert_eq!(aead.icv_len, 128);
        assert_eq!(aead.key.len(), 20);
        assert!(parsed.auth_alg.is_none());
        assert!(parsed.enc_alg.is_none());
    }

    #[test]
    fn xfrm_sa_v6_separate_auth_encr_roundtrips() {
        let sa = XfrmSaBuilder::new(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            0xCAFEBABE,
            IpsecProtocol::Esp,
        )
        .mode(XfrmMode::Tunnel)
        .reqid(99)
        .auth_hmac_sha256(&[0xBBu8; 32])
        .encr_aes_cbc(&[0xCCu8; 32]); // AES-256

        let frame = build_add_sa_frame(sa);
        let parsed =
            Connection::<Xfrm>::parse_sa_msg(&frame).expect("parse_sa must round-trip v6 SA");

        assert_eq!(
            parsed.src_addr,
            Some(IpAddr::V6("2001:db8::1".parse().unwrap()))
        );
        assert_eq!(
            parsed.dst_addr,
            Some(IpAddr::V6("2001:db8::2".parse().unwrap()))
        );
        assert_eq!(parsed.spi, 0xCAFEBABE);
        let encr = parsed.enc_alg.unwrap();
        assert_eq!(encr.key_len, 256, "AES-256 key length in bits");
    }

    #[test]
    fn xfrm_sa_nat_t_udp_encap_roundtrips() {
        let sa = XfrmSaBuilder::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            0x1000,
            IpsecProtocol::Esp,
        )
        .nat_t_udp_encap(4500, 4500) // both 4500 → IKE-compatible
        .auth_hmac_sha256(&[0u8; 32])
        .encr_aes_cbc(&[0u8; 16]);

        let frame = build_add_sa_frame(sa);
        let parsed =
            Connection::<Xfrm>::parse_sa_msg(&frame).expect("parse_sa must round-trip NAT-T SA");

        let encap = parsed.encap.expect("XFRMA_ENCAP must be present");
        // sport/dport are stored network-byte-order on the wire; the
        // parser doesn't byte-swap them. Compare the wire form.
        assert_eq!(encap.encap_sport, 4500u16.to_be());
        assert_eq!(encap.encap_dport, 4500u16.to_be());
        assert_eq!(encap.encap_type, 2, "dport=4500 → ESPINUDP (IKE)");
    }

    /// A per-CPU SA's CPU goes out as XFRMA_SA_PCPU (35) and reads back
    /// (#166); an SA without one has none.
    #[test]
    fn xfrm_sa_pcpu_roundtrips() {
        let sa = |pcpu: Option<u32>| {
            let sa = XfrmSaBuilder::new(
                "10.0.0.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
                0x1000,
                IpsecProtocol::Esp,
            )
            .aead_aes_gcm(&[0u8; 20], 128);
            match pcpu {
                Some(cpu) => sa.pcpu(cpu),
                None => sa,
            }
        };
        let parsed = Connection::<Xfrm>::parse_sa_msg(&build_add_sa_frame(sa(Some(3))))
            .expect("parse_sa must round-trip a per-CPU SA");
        assert_eq!(parsed.pcpu, Some(3));
        let plain = Connection::<Xfrm>::parse_sa_msg(&build_add_sa_frame(sa(None))).unwrap();
        assert_eq!(plain.pcpu, None);
        assert_eq!(XFRMA_SA_PCPU, 35);
    }

    #[test]
    fn xfrm_del_sa_emits_correct_tuple() {
        let mut b = MessageBuilder::new(XFRM_MSG_DELSA, NLM_F_REQUEST | NLM_F_ACK);
        let id = XfrmUsersaId {
            daddr: ip_to_xfrm_addr("10.0.0.2".parse().unwrap()),
            spi: 0xdead_beef_u32.to_be(),
            family: libc::AF_INET as u16,
            proto: IpsecProtocol::Esp.number(),
            _pad: 0,
        };
        b.append_bytes(id.as_bytes());
        let frame = b.finish();

        // Frame layout: 16-byte nlmsghdr + 24-byte XfrmUsersaId.
        assert!(frame.len() >= 16 + 24);
        let id_bytes = &frame[16..16 + 24];
        let (got, _) = XfrmUsersaId::ref_from_prefix(id_bytes).unwrap();
        assert_eq!(
            got.daddr.to_ip(libc::AF_INET as u16),
            Some(IpAddr::V4("10.0.0.2".parse().unwrap()))
        );
        assert_eq!(u32::from_be(got.spi), 0xdead_beef);
        assert_eq!(got.family, libc::AF_INET as u16);
        assert_eq!(got.proto, IpsecProtocol::Esp.number());
    }

    #[test]
    fn xfrm_flush_sa_proto_zero_means_all() {
        let mut b = MessageBuilder::new(XFRM_MSG_FLUSHSA, NLM_F_REQUEST | NLM_F_ACK);
        let body = XfrmUsersaFlush {
            proto: 0,
            _pad: [0; 7],
        };
        b.append_bytes(body.as_bytes());
        let frame = b.finish();

        assert!(frame.len() >= 16 + 8);
        assert_eq!(frame[16], 0, "proto=0 = IPSEC_PROTO_ANY");
    }

    #[test]
    fn xfrm_sa_default_replay_window_is_32() {
        // The kernel's default of 0 disables replay protection,
        // which is a footgun. Builder defaults to 32 like iproute2.
        let sa = XfrmSaBuilder::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            1,
            IpsecProtocol::Esp,
        );
        let info = sa.build_usersa_info();
        assert_eq!(info.replay_window, 32);
    }

    // ==========================================================
    // Slice 2 — update_sa, flush_sa_proto, get_sa
    // ==========================================================

    fn build_update_sa_frame(sa: XfrmSaBuilder) -> Vec<u8> {
        // Plan 221: mirror the corrected update_sa shape (XFRM_MSG_UPDSA,
        // no NLM_F_CREATE | NLM_F_REPLACE — XFRM dispatches by nlmsg_type
        // alone and ignores those flags).
        let mut b = MessageBuilder::new(XFRM_MSG_UPDSA, NLM_F_REQUEST | NLM_F_ACK);
        sa.write_into(&mut b);
        b.finish()
    }

    #[test]
    fn xfrm_update_sa_uses_upds_a_message_type() {
        // Plan 221: the previous version of this test asserted that
        // update_sa set CREATE+REPLACE. That LOCKED THE BUG — XFRM
        // dispatches by nlmsg_type alone (net/xfrm/xfrm_user.c:917-921);
        // NLM_F_REPLACE is ignored. The correct dispatch is
        // XFRM_MSG_UPDSA with no extra flags.
        let sa = XfrmSaBuilder::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            0xdead_beef,
            IpsecProtocol::Esp,
        )
        .auth_hmac_sha256(&[0u8; 32])
        .encr_aes_cbc(&[0u8; 16]);

        let frame = build_update_sa_frame(sa);

        // nlmsghdr.type is at offset 4..6, flags is 6..8.
        let nlmsg_type = u16::from_ne_bytes([frame[4], frame[5]]);
        let flags = u16::from_ne_bytes([frame[6], frame[7]]);
        assert_eq!(
            nlmsg_type, XFRM_MSG_UPDSA,
            "update_sa MUST send XFRM_MSG_UPDSA (26), not NEWSA — XFRM dispatches by type"
        );
        assert_eq!(
            flags & NLM_F_REPLACE,
            0,
            "update_sa MUST NOT set NLM_F_REPLACE — XFRM ignores it; dispatch is by type"
        );
        assert_eq!(flags & NLM_F_EXCL, 0, "EXCL must NOT be set");
    }

    #[test]
    fn xfrm_update_sa_body_round_trips_like_add_sa() {
        // The body bytes are identical to add_sa — only nlmsghdr
        // flags differ. Verify the SA payload still parses.
        let sa = XfrmSaBuilder::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            0xCAFE,
            IpsecProtocol::Esp,
        )
        .reqid(11)
        .aead_aes_gcm(&[0xAAu8; 20], 128);

        let frame = build_update_sa_frame(sa);
        let parsed = Connection::<Xfrm>::parse_sa_msg(&frame)
            .expect("parse_sa must round-trip update_sa body");
        assert_eq!(parsed.spi, 0xCAFE);
        assert_eq!(parsed.reqid, 11);
        assert!(parsed.aead_alg.is_some());
    }

    #[test]
    fn xfrm_flush_sa_proto_writes_specific_proto_byte() {
        // Frame layout: 16-byte nlmsghdr + 8-byte XfrmUsersaFlush;
        // the proto byte sits at offset 16.
        let mut b = MessageBuilder::new(XFRM_MSG_FLUSHSA, NLM_F_REQUEST | NLM_F_ACK);
        let body = XfrmUsersaFlush {
            proto: IpsecProtocol::Esp.number(),
            _pad: [0; 7],
        };
        b.append_bytes(body.as_bytes());
        let frame = b.finish();

        assert!(frame.len() >= 16 + 8);
        assert_eq!(frame[16], 50, "proto=ESP=50");
        // Padding bytes stay zero.
        for &b in &frame[17..24] {
            assert_eq!(b, 0, "flush body padding must be zero");
        }
    }

    // ==========================================================
    // XfrmSpBuilder — Plan 141 PR B SP CRUD wire-format tests
    // ==========================================================

    fn ipv4_subnet_selector(family: u16) -> XfrmSelector {
        XfrmSelector {
            family,
            ..Default::default()
        }
    }

    fn build_add_sp_frame(sp: XfrmSpBuilder) -> Vec<u8> {
        let mut b = MessageBuilder::new(
            XFRM_MSG_NEWPOLICY,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        sp.write_into(&mut b);
        b.finish()
    }

    #[test]
    fn xfrm_sp_out_with_one_tmpl_roundtrips() {
        let sel = ipv4_subnet_selector(libc::AF_INET as u16);
        let tmpl = XfrmUserTmpl::match_any(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            IpsecProtocol::Esp,
            XfrmMode::Tunnel,
            42,
        );
        let sp = XfrmSpBuilder::new(sel, PolicyDirection::Out)
            .priority(100)
            .template(tmpl);

        let frame = build_add_sp_frame(sp);
        let parsed = Connection::<Xfrm>::parse_policy_msg(&frame)
            .expect("parse_policy must round-trip XfrmSpBuilder output");

        assert_eq!(parsed.direction, PolicyDirection::Out);
        assert_eq!(parsed.action, PolicyAction::Allow, "default action");
        assert_eq!(parsed.priority, 100);
    }

    #[test]
    fn xfrm_sp_in_with_two_tmpls_packs_array() {
        // Inbound chain: ESP outer + AH inner.
        let sel = ipv4_subnet_selector(libc::AF_INET as u16);
        let esp = XfrmUserTmpl::match_any(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            IpsecProtocol::Esp,
            XfrmMode::Tunnel,
            1,
        );
        let ah = XfrmUserTmpl::match_any(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            IpsecProtocol::Ah,
            XfrmMode::Tunnel,
            2,
        );
        let sp = XfrmSpBuilder::new(sel, PolicyDirection::In)
            .template(esp)
            .template(ah);

        let frame = build_add_sp_frame(sp);
        let parsed = Connection::<Xfrm>::parse_policy_msg(&frame)
            .expect("parse_policy must round-trip nested-tmpl SP");

        assert_eq!(parsed.direction, PolicyDirection::In);
        // The current parse_policy doesn't expose the templates list,
        // but we can verify XFRMA_TMPL is present in the wire bytes
        // and that it carries 2 * size_of::<XfrmUserTmpl>() bytes.
        let tmpl_size = std::mem::size_of::<XfrmUserTmpl>();
        let want_attr_payload_len = 2 * tmpl_size;
        let attr_present = frame.windows(2).any(|w| {
            // Look for the XFRMA_TMPL nlattr type byte. nlattr is
            // {len: u16, type: u16}; type is at +2.
            u16::from_ne_bytes([w[0], w[1]]) == want_attr_payload_len as u16 + 4
        });
        assert!(
            attr_present,
            "XFRMA_TMPL attr should carry 2*sizeof(XfrmUserTmpl) bytes"
        );
    }

    #[test]
    fn xfrm_sp_block_action_no_templates() {
        let sel = ipv4_subnet_selector(libc::AF_INET as u16);
        let sp = XfrmSpBuilder::new(sel, PolicyDirection::Out).block();

        let frame = build_add_sp_frame(sp);
        let parsed = Connection::<Xfrm>::parse_policy_msg(&frame)
            .expect("parse_policy must round-trip block SP");
        assert_eq!(parsed.action, PolicyAction::Block);
    }

    #[test]
    fn xfrm_del_sp_emits_selector_plus_dir() {
        let sel = ipv4_subnet_selector(libc::AF_INET as u16);
        let mut b = MessageBuilder::new(XFRM_MSG_DELPOLICY, NLM_F_REQUEST | NLM_F_ACK);
        let id = XfrmUserpolicyId {
            sel,
            index: 0,
            dir: PolicyDirection::Out.number(),
            _pad: [0; 3],
        };
        b.append_bytes(id.as_bytes());
        let frame = b.finish();

        // nlmsg_type = DELPOLICY (offset 4..6)
        assert_eq!(u16::from_ne_bytes([frame[4], frame[5]]), XFRM_MSG_DELPOLICY);

        // XfrmUserpolicyId starts at offset 16. Direction byte
        // sits at offset 16 + size_of::<XfrmSelector>() + 4 (index).
        let sel_size = std::mem::size_of::<XfrmSelector>();
        let dir_off = 16 + sel_size + 4;
        assert_eq!(frame[dir_off], XFRM_POLICY_OUT);
    }

    #[test]
    fn xfrm_get_sp_request_uses_request_only_flags() {
        let sel = ipv4_subnet_selector(libc::AF_INET as u16);
        let mut b = MessageBuilder::new(XFRM_MSG_GETPOLICY, NLM_F_REQUEST);
        let id = XfrmUserpolicyId {
            sel,
            index: 0,
            dir: PolicyDirection::In.number(),
            _pad: [0; 3],
        };
        b.append_bytes(id.as_bytes());
        let frame = b.finish();

        let nlmsg_type = u16::from_ne_bytes([frame[4], frame[5]]);
        assert_eq!(nlmsg_type, XFRM_MSG_GETPOLICY);
        let flags = u16::from_ne_bytes([frame[6], frame[7]]);
        assert_eq!(flags & NLM_F_DUMP, 0, "get_sp must NOT use DUMP");
        assert_eq!(flags & NLM_F_ACK, 0, "get_sp must NOT use ACK");
        assert!(flags & NLM_F_REQUEST != 0);
    }

    #[test]
    fn xfrm_flush_sp_has_no_body() {
        let b = MessageBuilder::new(XFRM_MSG_FLUSHPOLICY, NLM_F_REQUEST | NLM_F_ACK);
        let frame = b.finish();
        // Just the 16-byte nlmsghdr — no XfrmUserpolicyId body.
        assert_eq!(frame.len(), 16);
        assert_eq!(
            u16::from_ne_bytes([frame[4], frame[5]]),
            XFRM_MSG_FLUSHPOLICY
        );
    }

    #[test]
    fn xfrm_user_tmpl_sets_default_algo_bitmasks_to_max() {
        // The "any algorithm" default is u32::MAX on all three
        // bitmasks — the kernel matches any SA whose algorithms
        // intersect this mask.
        let t = XfrmUserTmpl::match_any(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            IpsecProtocol::Esp,
            XfrmMode::Tunnel,
            0,
        );
        let aalgos = t.aalgos;
        let ealgos = t.ealgos;
        let calgos = t.calgos;
        assert_eq!(aalgos, u32::MAX);
        assert_eq!(ealgos, u32::MAX);
        assert_eq!(calgos, u32::MAX);
    }

    #[test]
    fn policy_direction_to_u8_round_trips() {
        for dir in [
            PolicyDirection::In,
            PolicyDirection::Out,
            PolicyDirection::Forward,
        ] {
            assert_eq!(PolicyDirection::from_u8(dir.number()), dir);
        }
    }

    #[test]
    fn xfrm_get_sa_request_carries_lookup_tuple() {
        // get_sa builds the same XfrmUsersaId body as del_sa, but
        // with XFRM_MSG_GETSA + NLM_F_REQUEST (no DUMP, no ACK).
        let mut b = MessageBuilder::new(XFRM_MSG_GETSA, NLM_F_REQUEST);
        let id = XfrmUsersaId {
            daddr: ip_to_xfrm_addr("192.0.2.10".parse().unwrap()),
            spi: 0x1234_5678_u32.to_be(),
            family: libc::AF_INET as u16,
            proto: IpsecProtocol::Ah.number(),
            _pad: 0,
        };
        b.append_bytes(id.as_bytes());
        let saddr = ip_to_xfrm_addr("192.0.2.1".parse().unwrap());
        b.append_attr(XFRMA_SRCADDR, &saddr.bytes);
        let frame = b.finish();

        // nlmsg_type at offset 4..6
        let nlmsg_type = u16::from_ne_bytes([frame[4], frame[5]]);
        assert_eq!(nlmsg_type, XFRM_MSG_GETSA);

        // nlmsg_flags at offset 6..8 — REQUEST only, no DUMP / ACK.
        let flags = u16::from_ne_bytes([frame[6], frame[7]]);
        assert_eq!(flags & NLM_F_DUMP, 0, "get_sa must NOT use DUMP");
        assert_eq!(flags & NLM_F_ACK, 0, "get_sa must NOT use ACK");
        assert!(flags & NLM_F_REQUEST != 0);

        // XfrmUsersaId at offset 16..40
        let (got, _) = XfrmUsersaId::ref_from_prefix(&frame[16..16 + 24]).unwrap();
        assert_eq!(u32::from_be(got.spi), 0x1234_5678);
        assert_eq!(got.proto, IpsecProtocol::Ah.number());
    }
}

// =========================================================================
// Streaming dump support — Plan 149 typed-config streams for XFRM
// =========================================================================

use super::{
    dump_stream::DumpStream,
    parse::{FromNetlink, PResult},
};

impl FromNetlink for SecurityAssociation {
    /// Header-only dump request (#160). The XFRM dump callbacks parse
    /// the whole body as netlink attributes (hdrlen = 0); a raw
    /// `xfrm_usersa_info` struct is reported as unparsed trailing data
    /// via a ratelimited kernel warning. No body means "dump all".
    fn write_dump_header(_buf: &mut Vec<u8>) {}

    /// `parse` isn't used by the dump-stream path (it overrides
    /// `from_bytes` instead), but the trait requires it. Consume
    /// the entire input via `from_bytes` and advance the cursor
    /// past it — semantically equivalent on a single-message body.
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        let consumed = *input;
        *input = &input[input.len()..];
        Self::from_bytes(consumed)
            .map_err(|_| winnow::error::ErrMode::Cut(winnow::error::ContextError::new()))
    }

    /// Parse from the post-nlmsghdr body (`xfrm_usersa_info` +
    /// attrs). Returns `Error::invalid_message` on a truncated body.
    fn from_bytes(payload: &[u8]) -> Result<Self> {
        parse_sa_payload(payload).ok_or_else(|| {
            super::error::Error::invalid_message("truncated xfrm_usersa_info body")
        })
    }
}

impl FromNetlink for SecurityPolicy {
    /// Header-only dump request (#160) — see the
    /// [`SecurityAssociation`] impl for the rationale.
    fn write_dump_header(_buf: &mut Vec<u8>) {}

    fn parse(input: &mut &[u8]) -> PResult<Self> {
        let consumed = *input;
        *input = &input[input.len()..];
        Self::from_bytes(consumed)
            .map_err(|_| winnow::error::ErrMode::Cut(winnow::error::ContextError::new()))
    }

    fn from_bytes(payload: &[u8]) -> Result<Self> {
        parse_sp_payload(payload).ok_or_else(|| {
            super::error::Error::invalid_message("truncated xfrm_userpolicy_info body")
        })
    }
}

#[nlink_macros::send_futures]
impl Connection<Xfrm> {
    /// Stream every IPsec Security Association the kernel knows
    /// about, one parsed [`SecurityAssociation`] per `next().await`.
    /// Bounded memory (one batch in flight) — preferred over the
    /// eager [`get_security_associations`](Self::get_security_associations)
    /// on hosts with thousands of SAs (IPsec scale-out gateways,
    /// telco aggregation routers).
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::Connection;
    /// # use nlink::netlink::Xfrm;
    /// use tokio_stream::StreamExt;
    /// let conn = Connection::<Xfrm>::new()?;
    /// let mut stream = conn.stream_sas().await?;
    /// while let Some(sa) = stream.next().await {
    ///     let sa = sa?;
    ///     println!("SPI {:x} → {:?}", sa.spi, sa.dst_addr);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn stream_sas(&self) -> Result<DumpStream<'_, Xfrm, SecurityAssociation>> {
        self.dump_stream::<SecurityAssociation>(XFRM_MSG_GETSA)
            .await
    }

    /// Stream every IPsec Security Policy the kernel knows about.
    /// Same shape as [`stream_sas`](Self::stream_sas) — bounded
    /// memory, parsed per-frame; preferred over
    /// [`get_security_policies`](Self::get_security_policies)
    /// on policy-heavy hosts.
    pub async fn stream_sps(&self) -> Result<DumpStream<'_, Xfrm, SecurityPolicy>> {
        self.dump_stream::<SecurityPolicy>(XFRM_MSG_GETPOLICY).await
    }
}

#[cfg(test)]
mod stream_tests {
    //! Unit tests for the `FromNetlink` impls on `SecurityAssociation`
    //! and `SecurityPolicy`. Live-socket dump tests need root +
    //! conntrack/xfrm state; those are covered manually.

    use super::*;

    /// `write_dump_header` must write NOTHING (#160): the XFRM dump
    /// callbacks parse the whole body as netlink attributes, so any
    /// fixed-struct body is unparsed trailing data and triggers the
    /// kernel's "N bytes leftover after parsing attributes" warning.
    #[test]
    fn sa_write_dump_header_is_empty() {
        let mut buf = Vec::new();
        <SecurityAssociation as FromNetlink>::write_dump_header(&mut buf);
        assert!(
            buf.is_empty(),
            "SA dump body must be header-only (#160), got {} bytes",
            buf.len()
        );
    }

    #[test]
    fn sp_write_dump_header_is_empty() {
        let mut buf = Vec::new();
        <SecurityPolicy as FromNetlink>::write_dump_header(&mut buf);
        assert!(
            buf.is_empty(),
            "SP dump body must be header-only (#160), got {} bytes",
            buf.len()
        );
    }

    #[test]
    fn sa_from_bytes_rejects_truncated_body() {
        // Just shy of the XfrmUsersaInfo body length.
        let payload = vec![0u8; std::mem::size_of::<XfrmUsersaInfo>() - 1];
        let err = <SecurityAssociation as FromNetlink>::from_bytes(&payload);
        assert!(err.is_err());
    }

    #[test]
    fn sp_from_bytes_rejects_truncated_body() {
        let payload = vec![0u8; std::mem::size_of::<XfrmUserpolicyInfo>() - 1];
        let err = <SecurityPolicy as FromNetlink>::from_bytes(&payload);
        assert!(err.is_err());
    }

    #[test]
    fn sa_from_bytes_round_trips_zeroed_body() {
        // All-zero body should parse to a default-ish SA — zero
        // IPs, zero SPI. Exercises the parse path without needing
        // a real kernel dump frame.
        let payload = vec![0u8; std::mem::size_of::<XfrmUsersaInfo>()];
        let sa = <SecurityAssociation as FromNetlink>::from_bytes(&payload)
            .expect("zero body should parse");
        assert_eq!(sa.spi, 0);
        assert_eq!(sa.bytes, 0);
    }

    #[test]
    fn sp_from_bytes_round_trips_zeroed_body() {
        let payload = vec![0u8; std::mem::size_of::<XfrmUserpolicyInfo>()];
        let sp =
            <SecurityPolicy as FromNetlink>::from_bytes(&payload).expect("zero body should parse");
        assert_eq!(sp.priority, 0);
        assert_eq!(sp.index, 0);
    }
}

#[cfg(test)]
mod xfrm_event_tests {
    use super::*;
    use std::net::Ipv4Addr;
    use zerocopy::IntoBytes;

    /// `XfrmGroup` maps to the kernel `XFRMNLGRP_*` group numbers.
    #[test]
    fn group_numbers_match_kernel() {
        assert_eq!(XfrmGroup::Acquire.to_group(), 1);
        assert_eq!(XfrmGroup::Expire.to_group(), 2);
        assert_eq!(XfrmGroup::Sa.to_group(), 3);
        assert_eq!(XfrmGroup::Policy.to_group(), 4);
        assert_eq!(XfrmGroup::Report.to_group(), 6);
        assert_eq!(XfrmGroup::Migrate.to_group(), 7);
        assert_eq!(XfrmGroup::Mapping.to_group(), 8);
    }

    /// `xfrm_user_acquire` wire size is 280 bytes (pins the embedded
    /// struct offsets used by the ACQUIRE parser).
    #[test]
    fn acquire_struct_size() {
        assert_eq!(std::mem::size_of::<XfrmUserAcquire>(), 280);
    }

    fn sa_info(spi: u32) -> XfrmUsersaInfo {
        let mut info = XfrmUsersaInfo {
            family: 2, // AF_INET
            mode: 1,   // tunnel
            reqid: 42,
            ..Default::default()
        };
        info.id.daddr = XfrmAddress::from_v4(Ipv4Addr::new(10, 0, 0, 1));
        info.id.spi = spi.to_be();
        info.id.proto = IPPROTO_ESP;
        info.saddr = XfrmAddress::from_v4(Ipv4Addr::new(10, 0, 0, 2));
        info.sel.family = 2;
        info
    }

    /// NEWSA / UPDSA bodies parse into a full SA.
    #[test]
    fn parse_newsa() {
        let body = sa_info(0x1000).as_bytes().to_vec();
        for ty in [XFRM_MSG_NEWSA, XFRM_MSG_UPDSA] {
            match parse_xfrm_event(ty, &body) {
                Some(XfrmEvent::NewSa(sa)) => {
                    assert_eq!(sa.spi, 0x1000);
                    assert_eq!(sa.protocol, IpsecProtocol::Esp);
                    assert_eq!(sa.dst_addr, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
                }
                other => panic!("expected NewSa, got {other:?}"),
            }
        }
    }

    /// DELSA carries the compact `xfrm_usersa_id`, not the full state.
    #[test]
    fn parse_delsa() {
        let id = XfrmUsersaId {
            daddr: XfrmAddress::from_v4(Ipv4Addr::new(192, 168, 1, 1)),
            spi: 0xABCDu32.to_be(),
            family: 2,
            proto: IPPROTO_ESP,
            _pad: 0,
        };
        match parse_xfrm_event(XFRM_MSG_DELSA, id.as_bytes()) {
            Some(XfrmEvent::DelSa(sa_id)) => {
                assert_eq!(sa_id.spi, 0xABCD);
                assert_eq!(sa_id.protocol, IpsecProtocol::Esp);
                assert_eq!(
                    sa_id.dst_addr,
                    Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
                );
            }
            other => panic!("expected DelSa, got {other:?}"),
        }
    }

    /// EXPIRE is `xfrm_usersa_info` + a trailing `hard` byte.
    #[test]
    fn parse_expire_reads_hard_flag() {
        let mut body = sa_info(0x2000).as_bytes().to_vec();
        body.push(1); // hard = true
        match parse_xfrm_event(XFRM_MSG_EXPIRE, &body) {
            Some(XfrmEvent::ExpireSa { sa, hard }) => {
                assert_eq!(sa.spi, 0x2000);
                assert!(hard);
            }
            other => panic!("expected ExpireSa, got {other:?}"),
        }

        // Soft limit: hard byte = 0.
        let mut soft = sa_info(0x2001).as_bytes().to_vec();
        soft.push(0);
        match parse_xfrm_event(XFRM_MSG_EXPIRE, &soft) {
            Some(XfrmEvent::ExpireSa { hard, .. }) => assert!(!hard),
            other => panic!("expected ExpireSa, got {other:?}"),
        }
    }

    /// FLUSH notifications carry no body.
    #[test]
    fn parse_flush() {
        assert!(matches!(
            parse_xfrm_event(XFRM_MSG_FLUSHSA, &[]),
            Some(XfrmEvent::FlushSa)
        ));
        assert!(matches!(
            parse_xfrm_event(XFRM_MSG_FLUSHPOLICY, &[]),
            Some(XfrmEvent::FlushPolicy)
        ));
    }

    /// Unmodelled notification types surface as `Other`, not dropped.
    #[test]
    fn unmodelled_types_surface_as_other() {
        // 33 = XFRM_MSG_MIGRATE, 38 = XFRM_MSG_MAPPING.
        for ty in [33u16, 38u16] {
            assert!(matches!(
                parse_xfrm_event(ty, &[]),
                Some(XfrmEvent::Other { msg_type }) if msg_type == ty
            ));
        }
        // A request-only type and an out-of-range type are ignored.
        assert!(parse_xfrm_event(XFRM_MSG_GETSA, &[]).is_none());
        assert!(parse_xfrm_event(999, &[]).is_none());
    }

    /// Truncated bodies return `None` rather than panicking
    /// (Parser-robustness).
    #[test]
    fn truncated_bodies_dont_panic() {
        assert!(parse_xfrm_event(XFRM_MSG_NEWSA, &[1, 2, 3]).is_none());
        assert!(parse_xfrm_event(XFRM_MSG_DELSA, &[1, 2]).is_none());
        assert!(parse_xfrm_event(XFRM_MSG_EXPIRE, &[0u8; 4]).is_none());
        assert!(parse_xfrm_event(XFRM_MSG_ACQUIRE, &[0u8; 10]).is_none());
        assert!(parse_xfrm_event(XFRM_MSG_REPORT, &[]).is_none());
    }

    /// The buffer-level walker skips malformed frames (rule 3) — a
    /// truncated frame must not abort the stream.
    #[test]
    fn parse_events_skips_garbage() {
        // Not a valid netlink message; MessageIter yields nothing.
        let events = parse_xfrm_events(&[0xFF, 0x00, 0x01]);
        assert!(events.is_empty());
    }
}
