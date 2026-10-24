//! Netlink message header and parsing.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::{
    attr::AttrIter,
    error::{Error, Result},
};

/// Netlink message header alignment.
pub const NLMSG_ALIGNTO: usize = 4;

/// Align a length to NLMSG_ALIGNTO boundary.
///
/// Plan 232 B18 — `len + 3` debug-panicked on `usize::MAX`-ish
/// inputs. The kernel can't emit a >`u32::MAX` netlink frame so
/// the panic is unreachable in production, but a misbehaving
/// builder appending to a 2 GiB+ `Vec` could trip it. Switched to
/// `saturating_add` so overflow returns `usize::MAX` (which then
/// trips downstream `<= data.len()` guards naturally) instead
/// of debug-panicking.
#[inline]
pub const fn nlmsg_align(len: usize) -> usize {
    let bumped = len.saturating_add(NLMSG_ALIGNTO - 1);
    bumped & !(NLMSG_ALIGNTO - 1)
}

/// Checked variant of [`nlmsg_align`]. Returns `None` if the
/// alignment would overflow.
///
/// Plan 232 B18 — additive helper for callers that want to
/// surface the overflow as an error rather than relying on the
/// saturating fallback.
#[inline]
pub const fn nlmsg_align_checked(len: usize) -> Option<usize> {
    match len.checked_add(NLMSG_ALIGNTO - 1) {
        Some(bumped) => Some(bumped & !(NLMSG_ALIGNTO - 1)),
        None => None,
    }
}

/// Size of the netlink message header.
pub const NLMSG_HDRLEN: usize = nlmsg_align(std::mem::size_of::<NlMsgHdr>());

/// Netlink message header (mirrors struct nlmsghdr).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NlMsgHdr {
    /// Length of message including header.
    pub nlmsg_len: u32,
    /// Message type.
    pub nlmsg_type: u16,
    /// Additional flags.
    pub nlmsg_flags: u16,
    /// Sequence number.
    pub nlmsg_seq: u32,
    /// Sending process port ID.
    pub nlmsg_pid: u32,
}

impl NlMsgHdr {
    /// Create a new message header.
    pub fn new(msg_type: u16, flags: u16) -> Self {
        Self {
            nlmsg_len: NLMSG_HDRLEN as u32,
            nlmsg_type: msg_type,
            nlmsg_flags: flags,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        }
    }

    /// Get the payload length (total length minus header).
    pub fn payload_len(&self) -> usize {
        self.nlmsg_len as usize - NLMSG_HDRLEN
    }

    /// Check if this is an error message.
    pub fn is_error(&self) -> bool {
        self.nlmsg_type == NlMsgType::ERROR
    }

    /// Check if this is a done message.
    pub fn is_done(&self) -> bool {
        self.nlmsg_type == NlMsgType::DONE
    }

    /// Check if this message has the multi flag.
    pub fn is_multi(&self) -> bool {
        self.nlmsg_flags & NLM_F_MULTI != 0
    }

    /// Check if the kernel signaled that the dump was interrupted —
    /// the snapshot iterator's underlying data structure was mutated
    /// between dump frames, so the returned data is inconsistent.
    ///
    /// The kernel sets `NLM_F_DUMP_INTR` on whichever message in the
    /// dump stream was generated after the mutation; `iproute2` warns,
    /// `vishvananda/netlink` retries up to N times, Cilium's
    /// `safenetlink` wrapper retries up to 30. nlink surfaces this as
    /// [`Error::dump_interrupted()`] from `Connection::send_dump` so
    /// callers can choose their own retry policy via the
    /// [`Error::is_dump_interrupted`] predicate.
    ///
    /// Reference: [kernel netlink intro docs][1], `vishvananda #1163`,
    /// `pyroute2 #874`. Tracks the bug class Cilium issue #40280
    /// classified as "the dump never told us its data is stale."
    ///
    /// [1]: https://docs.kernel.org/userspace-api/netlink/intro.html
    pub fn is_dump_interrupted(&self) -> bool {
        self.nlmsg_flags & NLM_F_DUMP_INTR != 0
    }

    /// Convert header to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    /// Parse header from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(data)
            .map(|(r, _)| r)
            .map_err(|_| Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: std::mem::size_of::<Self>(),
                actual: data.len(),
            }))
    }
}

/// Standard netlink message types.
pub struct NlMsgType;

impl NlMsgType {
    /// No operation, message must be discarded.
    pub const NOOP: u16 = 1;
    /// Error message or ACK.
    pub const ERROR: u16 = 2;
    /// End of multipart message.
    pub const DONE: u16 = 3;
    /// Data lost, request resend.
    pub const OVERRUN: u16 = 4;

    /// RTNetlink base (for link/addr/route/etc).
    pub const RTM_BASE: u16 = 16;

    // Link messages
    pub const RTM_NEWLINK: u16 = 16;
    pub const RTM_DELLINK: u16 = 17;
    pub const RTM_GETLINK: u16 = 18;
    pub const RTM_SETLINK: u16 = 19;

    // Address messages
    pub const RTM_NEWADDR: u16 = 20;
    pub const RTM_DELADDR: u16 = 21;
    pub const RTM_GETADDR: u16 = 22;

    // Route messages
    pub const RTM_NEWROUTE: u16 = 24;
    pub const RTM_DELROUTE: u16 = 25;
    pub const RTM_GETROUTE: u16 = 26;

    // Neighbor messages
    pub const RTM_NEWNEIGH: u16 = 28;
    pub const RTM_DELNEIGH: u16 = 29;
    pub const RTM_GETNEIGH: u16 = 30;

    // Rule messages
    pub const RTM_NEWRULE: u16 = 32;
    pub const RTM_DELRULE: u16 = 33;
    pub const RTM_GETRULE: u16 = 34;

    // Qdisc messages
    pub const RTM_NEWQDISC: u16 = 36;
    pub const RTM_DELQDISC: u16 = 37;
    pub const RTM_GETQDISC: u16 = 38;

    // Traffic class messages
    pub const RTM_NEWTCLASS: u16 = 40;
    pub const RTM_DELTCLASS: u16 = 41;
    pub const RTM_GETTCLASS: u16 = 42;

    // Traffic filter messages
    pub const RTM_NEWTFILTER: u16 = 44;
    pub const RTM_DELTFILTER: u16 = 45;
    pub const RTM_GETTFILTER: u16 = 46;

    // Traffic action messages
    pub const RTM_NEWACTION: u16 = 48;
    pub const RTM_DELACTION: u16 = 49;
    pub const RTM_GETACTION: u16 = 50;

    // Per-interface IP configuration (netconf, #523)
    pub const RTM_NEWNETCONF: u16 = 80;
    pub const RTM_DELNETCONF: u16 = 81;
    pub const RTM_GETNETCONF: u16 = 82;

    // Bridge multicast database (MDB) messages
    pub const RTM_NEWMDB: u16 = 84;
    pub const RTM_DELMDB: u16 = 85;
    pub const RTM_GETMDB: u16 = 86;

    // Netns messages
    pub const RTM_NEWNSID: u16 = 88;
    pub const RTM_DELNSID: u16 = 89;
    pub const RTM_GETNSID: u16 = 90;

    // Link statistics (Linux 4.7+): `struct if_stats_msg`, then the
    // `IFLA_STATS_*` attributes the filter mask asks for.
    pub const RTM_NEWSTATS: u16 = 92;
    pub const RTM_GETSTATS: u16 = 94;

    // Chain messages (Linux 4.1+)
    pub const RTM_NEWCHAIN: u16 = 100;
    pub const RTM_DELCHAIN: u16 = 101;
    pub const RTM_GETCHAIN: u16 = 102;

    // Link properties (Linux 5.5+): alternative names, in IFLA_PROP_LIST.
    pub const RTM_NEWLINKPROP: u16 = 108;
    pub const RTM_DELLINKPROP: u16 = 109;

    // Nexthop messages (Linux 5.3+)
    pub const RTM_NEWNEXTHOP: u16 = 104;
    pub const RTM_DELNEXTHOP: u16 = 105;
    pub const RTM_GETNEXTHOP: u16 = 106;

    // Bridge VLAN-DB messages (Linux 5.10+) — per-VLAN entries and
    // bridge-global VLAN options over `struct br_vlan_msg`.
    pub const RTM_NEWVLAN: u16 = 112;
    pub const RTM_DELVLAN: u16 = 113;
    pub const RTM_GETVLAN: u16 = 114;
}

/// Netlink message flags.
pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_ECHO: u16 = 0x08;
pub const NLM_F_DUMP_INTR: u16 = 0x10;
pub const NLM_F_DUMP_FILTERED: u16 = 0x20;

// Modifiers to GET request
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_ATOMIC: u16 = 0x400;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

// Modifiers to NEW request
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;

// Flags on an NLMSG_ERROR (an error or an ACK)
/// The error carries only the request's header, not the whole request
/// (`NETLINK_CAP_ACK`).
pub const NLM_F_CAPPED: u16 = 0x100;
/// Extended-ack TLVs follow the error (`NETLINK_EXT_ACK`).
pub const NLM_F_ACK_TLVS: u16 = 0x200;

/// Iterator over netlink messages in a buffer.
pub struct MessageIter<'a> {
    data: &'a [u8],
}

impl<'a> MessageIter<'a> {
    /// Create a new message iterator.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl<'a> Iterator for MessageIter<'a> {
    type Item = Result<(&'a NlMsgHdr, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() < NLMSG_HDRLEN {
            return None;
        }

        let header = match NlMsgHdr::from_bytes(self.data) {
            Ok(h) => h,
            Err(e) => {
                // Plan 193 §2.3 / rule 2 — exhaust the iterator
                // on parse error so a subsequent `next()` call
                // returns None instead of looping forever on the
                // same malformed prefix.
                self.data = &[];
                return Some(Err(e));
            }
        };

        let msg_len = header.nlmsg_len as usize;
        if msg_len < NLMSG_HDRLEN || msg_len > self.data.len() {
            // Same exhaustion contract as above — without this
            // sentinel, a truncated frame from the kernel (or
            // any malformed header advertising more bytes than
            // present) would re-emit the Err on every poll,
            // hanging long-lived multicast subscribers (Plan
            // 193 §2.3, CLAUDE.md §"Parser robustness" rule 2).
            self.data = &[];
            return Some(Err(Error::invalid_message(format!(
                "invalid message length: {}",
                msg_len
            ))));
        }

        let payload = &self.data[NLMSG_HDRLEN..msg_len];
        let aligned_len = nlmsg_align(msg_len);

        // Move to next message. Edge case: `aligned_len == 0`
        // would mean the header advertises zero bytes (rejected
        // above by the `msg_len < NLMSG_HDRLEN` guard) — so this
        // branch always advances at least NLMSG_HDRLEN bytes.
        if aligned_len >= self.data.len() {
            self.data = &[];
        } else {
            self.data = &self.data[aligned_len..];
        }

        Some(Ok((header, payload)))
    }
}

/// Netlink error message payload.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct NlMsgError {
    /// Error code (negative errno or 0 for ACK).
    pub error: i32,
    /// Original message header that caused the error.
    pub msg: NlMsgHdr,
}

/// `NLMSGERR_ATTR_*` enum from `include/uapi/linux/netlink.h`. Kernel
/// populates these as nlattr TLVs after the embedded `nlmsghdr` in an
/// error response, when `NETLINK_EXT_ACK` is enabled on the listening
/// socket (on by default in nlink — see `socket.rs`).
pub mod nlmsgerr_attr {
    /// Human-readable error message string (NUL-terminated).
    pub const MSG: u16 = 1;
    /// Offset of the offending attribute inside the original request,
    /// in bytes from the start of the netlink message.
    pub const OFFS: u16 = 2;
    /// Opaque cookie for matching error to request (rarely useful).
    pub const COOKIE: u16 = 3;
    /// Nested policy info (rarely useful at the lib level).
    pub const POLICY: u16 = 4;
    /// Type of a missing required attribute.
    pub const MISS_TYPE: u16 = 5;
    /// Offset, in the request, of the nest the missing attribute belongs
    /// in; absent when it is missing at the top level.
    pub const MISS_NEST: u16 = 6;
}

/// `NL_POLICY_TYPE_ATTR_*` from `include/uapi/linux/netlink.h`: what an
/// `NLMSGERR_ATTR_POLICY` nest says the rejected attribute had to be.
mod policy_attr {
    pub const MIN_VALUE_S: u16 = 2;
    pub const MAX_VALUE_S: u16 = 3;
    pub const MIN_VALUE_U: u16 = 4;
    pub const MAX_VALUE_U: u16 = 5;
    pub const MIN_LENGTH: u16 = 6;
    pub const MAX_LENGTH: u16 = 7;
}

/// Parsed extended-ack TLVs from a netlink error response.
///
/// The kernel attaches these after the embedded `nlmsghdr` when
/// `NETLINK_EXT_ACK` is enabled. They turn `errno = 22 (EINVAL)`
/// into actionable diagnostics like
/// `"attribute IFLA_MTU rejected: value 0 out of range"`.
///
/// Most fields are `Option` because not every kernel error path
/// populates them — older kernels and some subsystems still return
/// bare errno. Absence is normal, not error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParsedExtAck {
    /// Human-readable kernel error string. `None` if the kernel did
    /// not include `NLMSGERR_ATTR_MSG` or it was empty / malformed.
    ///
    /// On a successful ACK this is a **warning** — the change was made,
    /// and the kernel has something to say about it (`sch_htb: quantum of
    /// class 10002 is big`).
    pub message: Option<String>,
    /// Byte offset into the original request where the kernel
    /// detected the problem. `None` if the kernel did not include
    /// `NLMSGERR_ATTR_OFFS`.
    pub offset: Option<u32>,
    /// The type of a required attribute the request did not carry
    /// (`NLMSGERR_ATTR_MISS_TYPE`). Generic netlink families report a
    /// missing attribute this way and with no message at all, so without
    /// it the error is a bare `EINVAL`.
    pub missing_type: Option<u32>,
    /// The offset of the nest the missing attribute belongs in
    /// (`NLMSGERR_ATTR_MISS_NEST`); `None` when it is missing at the top
    /// level.
    pub missing_nest: Option<u32>,
    /// The raw `NLMSGERR_ATTR_POLICY` nest: what the rejected attribute
    /// had to be. [`Self::describe`] renders its bounds.
    pub policy: Option<Vec<u8>>,
}

impl ParsedExtAck {
    /// `true` when the kernel sent nothing this struct models.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// One line saying everything the TLVs say: the message, a missing
    /// attribute, the policy's bounds. `None` when there is nothing.
    ///
    /// The offset is left out; [`Error`] renders it on its own.
    pub fn describe(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        if let Some(msg) = &self.message {
            parts.push(msg.clone());
        }
        if let Some(ty) = self.missing_type {
            let mut missing = format!("missing required attribute (type {ty})");
            if let Some(nest) = self.missing_nest {
                missing.push_str(&format!(" in the nest at request offset {nest}"));
            }
            parts.push(missing);
        }
        if let Some(bounds) = self.policy.as_deref().and_then(describe_policy) {
            parts.push(bounds);
        }
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

/// The bounds an `NLMSGERR_ATTR_POLICY` nest gives, as `policy: value in
/// 1..=4096, length 4..=16`, or `None` if it gives none.
fn describe_policy(nest: &[u8]) -> Option<String> {
    let (mut min, mut max, mut min_len, mut max_len) = (None, None, None, None);
    for (ty, payload) in AttrIter::new(nest) {
        let u64_of = |p: &[u8]| {
            p.get(..8)
                .map(|b| u64::from_ne_bytes(b.try_into().unwrap()))
        };
        let u32_of = |p: &[u8]| {
            p.get(..4)
                .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
        };
        match ty & 0x7FFF {
            policy_attr::MIN_VALUE_U => min = u64_of(payload).map(|v| v.to_string()),
            policy_attr::MAX_VALUE_U => max = u64_of(payload).map(|v| v.to_string()),
            policy_attr::MIN_VALUE_S => min = u64_of(payload).map(|v| (v as i64).to_string()),
            policy_attr::MAX_VALUE_S => max = u64_of(payload).map(|v| (v as i64).to_string()),
            policy_attr::MIN_LENGTH => min_len = u32_of(payload),
            policy_attr::MAX_LENGTH => max_len = u32_of(payload),
            _ => {}
        }
    }
    let mut bounds = Vec::new();
    if min.is_some() || max.is_some() {
        bounds.push(format!(
            "value in {}..={}",
            min.unwrap_or_default(),
            max.unwrap_or_default()
        ));
    }
    if min_len.is_some() || max_len.is_some() {
        let min_len = min_len.map(|v| v.to_string()).unwrap_or_default();
        let max_len = max_len.map(|v| v.to_string()).unwrap_or_default();
        bounds.push(format!("length {min_len}..={max_len}"));
    }
    (!bounds.is_empty()).then(|| format!("policy: {}", bounds.join(", ")))
}

impl NlMsgError {
    /// Parse error message from payload.
    pub fn from_bytes(data: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(data)
            .map(|(r, _)| r)
            .map_err(|_| Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: std::mem::size_of::<Self>(),
                actual: data.len(),
            }))
    }

    /// Check if this is an ACK (no error).
    pub fn is_ack(&self) -> bool {
        self.error == 0
    }

    /// The extended-ack TLVs of this error or ACK, found by the header's
    /// flags: none unless `NLM_F_ACK_TLVS` is set; right after the echoed
    /// header when `NLM_F_CAPPED` is (or on an ACK, which never echoes the
    /// request); after the whole echoed request otherwise.
    ///
    /// `flags` is the `nlmsg_flags` of the `NLMSG_ERROR` message whose
    /// body is `payload`.
    pub fn ext_ack_attrs<'a>(&self, flags: u16, payload: &'a [u8]) -> AttrIter<'a> {
        if flags & NLM_F_ACK_TLVS == 0 {
            return AttrIter::new(&[]);
        }
        let header_end = std::mem::size_of::<Self>();
        let start = if flags & NLM_F_CAPPED != 0 || self.is_ack() {
            header_end
        } else {
            // The echoed request: its header is already in `self.msg`,
            // its body follows. The TLVs start at the next 4-byte boundary.
            let echoed = (self.msg.nlmsg_len as usize).max(NLMSG_HDRLEN);
            4 + nlmsg_align(echoed)
        };
        AttrIter::new(payload.get(start..).unwrap_or(&[]))
    }

    /// Parse the extended-ack TLVs, located by the header's flags (see
    /// [`Self::ext_ack_attrs`]): the message, offset, missing attribute
    /// and policy.
    pub fn ext_ack(&self, flags: u16, payload: &[u8]) -> ParsedExtAck {
        parse_ext_ack(self.ext_ack_attrs(flags, payload))
    }

    /// Construct an [`Error`] from this error message, reading the
    /// extended-ack TLVs where the header's flags say they are.
    ///
    /// A missing attribute and the policy's bounds go into the error's
    /// ext-ack text along with the kernel's message, so a generic netlink
    /// family's bare `EINVAL` says what was missing.
    pub fn to_error(&self, flags: u16, payload: &[u8]) -> Error {
        let ext = self.ext_ack(flags, payload);
        Error::from_kernel_reply(self.error, Some(self.msg.nlmsg_type), ext.describe(), ext.offset)
    }

    /// This ACK's value, for the generic-netlink families that put one
    /// where an ACK has 0 — `mac80211_hwsim` answers `NEW_RADIO` with the
    /// new radio's id (#530). Only a negative value is an error.
    pub(crate) fn ack_value(&self, flags: u16, payload: &[u8]) -> Result<i32> {
        if self.error < 0 {
            return Err(self.to_error(flags, payload));
        }
        self.warn_if_ack_warns(flags, payload);
        Ok(self.error)
    }

    /// Log the warning a successful ACK carries, if any.
    ///
    /// The kernel reports what it did but would rather not have —
    /// `sch_htb: quantum of class 10002 is big. Consider r2q change.` — as
    /// an `NLMSGERR_ATTR_MSG` on the ACK. `tc(8)` prints it; nlink used to
    /// drop it.
    pub(crate) fn warn_if_ack_warns(&self, flags: u16, payload: &[u8]) {
        if self.error < 0 || flags & NLM_F_ACK_TLVS == 0 {
            return;
        }
        if let Some(warning) = self.ext_ack(flags, payload).describe() {
            tracing::warn!(
                warning = %warning,
                request_type = self.msg.nlmsg_type,
                "the kernel accepted the request with a warning"
            );
        }
    }

    /// Get attributes after the error message (extended ACK).
    ///
    /// Reads them right after the echoed header, which is where they are
    /// only when the error is capped (nlink's default; see
    /// [`Self::ext_ack_attrs`], which checks).
    pub fn attrs<'a>(&self, payload: &'a [u8]) -> AttrIter<'a> {
        let offset = std::mem::size_of::<Self>();
        if payload.len() > offset {
            AttrIter::new(&payload[offset..])
        } else {
            AttrIter::new(&[])
        }
    }

    /// Construct an [`Error`] from this error message plus the
    /// extended-ack TLVs in `payload`. Caller is responsible for
    /// checking `!is_ack()` before calling (this method assumes the
    /// response represents a real error, not an ACK).
    ///
    /// Centralizes the "parse ext-ack + build Error" pattern that's
    /// repeated across every protocol's response-handling loop.
    ///
    /// Assumes a capped error (nlink's default); prefer
    /// [`Self::to_error`], which reads the header's flags.
    pub fn into_error(&self, payload: &[u8]) -> Error {
        let ext = self.parsed_ext_ack(payload);
        Error::from_kernel_reply(self.error, Some(self.msg.nlmsg_type), ext.describe(), ext.offset)
    }

    /// Parse the extended-ack TLVs from an error-response payload,
    /// assuming a capped error (nlink's default). Prefer
    /// [`Self::ext_ack`], which reads the header's flags.
    ///
    /// Returns an all-`None` [`ParsedExtAck`] if no recognized TLVs
    /// are present.
    pub fn parsed_ext_ack(&self, payload: &[u8]) -> ParsedExtAck {
        parse_ext_ack(self.attrs(payload))
    }
}

/// Read the `NLMSGERR_ATTR_*` TLVs nlink models. `COOKIE` and unknown
/// types are ignored.
fn parse_ext_ack(attrs: AttrIter<'_>) -> ParsedExtAck {
    let mut out = ParsedExtAck::default();
    let u32_of = |p: &[u8]| {
        p.get(..4)
            .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
    };
    for (attr_type, attr_payload) in attrs {
        match attr_type & 0x7FFF {
            nlmsgerr_attr::MSG => {
                // Kernel strings are typically NUL-terminated;
                // strip the NUL + tolerate non-UTF8 by lossy
                // decode (we'd rather show "?" than swallow the
                // whole message).
                let trimmed = attr_payload
                    .iter()
                    .position(|&b| b == 0)
                    .map(|n| &attr_payload[..n])
                    .unwrap_or(attr_payload);
                if !trimmed.is_empty() {
                    out.message = Some(String::from_utf8_lossy(trimmed).into_owned());
                }
            }
            nlmsgerr_attr::OFFS => out.offset = u32_of(attr_payload),
            nlmsgerr_attr::MISS_TYPE => out.missing_type = u32_of(attr_payload),
            nlmsgerr_attr::MISS_NEST => out.missing_nest = u32_of(attr_payload),
            nlmsgerr_attr::POLICY => out.policy = Some(attr_payload.to_vec()),
            _ => {} // COOKIE + unknown
        }
    }
    out
}

#[cfg(test)]
mod nlmsgerr_tests {
    use super::*;
    use crate::netlink::attr::nla_align;

    fn synth_payload_with_ext_ack(error: i32, msg: Option<&str>, offset: Option<u32>) -> Vec<u8> {
        // NlMsgError: error(i32) + NlMsgHdr (fixed 16 bytes)
        let mut buf = Vec::new();
        buf.extend_from_slice(&error.to_ne_bytes());
        // Zero NlMsgHdr — the test doesn't care about the embedded
        // original-request header.
        buf.extend_from_slice(&[0u8; 16]);

        // NLMSGERR_ATTR_MSG TLV
        if let Some(s) = msg {
            let mut payload = s.as_bytes().to_vec();
            payload.push(0); // NUL-terminate
            let attr_len = 4 + payload.len();
            buf.extend_from_slice(&(attr_len as u16).to_ne_bytes());
            buf.extend_from_slice(&nlmsgerr_attr::MSG.to_ne_bytes());
            buf.extend_from_slice(&payload);
            // Pad to 4-byte alignment.
            while buf.len() < nla_align(buf.len()) {
                buf.push(0);
            }
        }

        // NLMSGERR_ATTR_OFFS TLV
        if let Some(off) = offset {
            let attr_len: u16 = 4 + 4;
            buf.extend_from_slice(&attr_len.to_ne_bytes());
            buf.extend_from_slice(&nlmsgerr_attr::OFFS.to_ne_bytes());
            buf.extend_from_slice(&off.to_ne_bytes());
        }

        buf
    }

    #[test]
    fn parses_msg_and_offs() {
        let payload = synth_payload_with_ext_ack(
            -22,
            Some("attribute IFLA_MTU rejected: value 0 out of range"),
            Some(42),
        );
        let err = NlMsgError::from_bytes(&payload).expect("parse");
        assert_eq!(err.error, -22);
        let parsed = err.parsed_ext_ack(&payload);
        assert_eq!(
            parsed.message.as_deref(),
            Some("attribute IFLA_MTU rejected: value 0 out of range")
        );
        assert_eq!(parsed.offset, Some(42));
    }

    #[test]
    fn parses_msg_only_when_offs_missing() {
        let payload = synth_payload_with_ext_ack(-22, Some("policy violation"), None);
        let err = NlMsgError::from_bytes(&payload).expect("parse");
        let parsed = err.parsed_ext_ack(&payload);
        assert_eq!(parsed.message.as_deref(), Some("policy violation"));
        assert_eq!(parsed.offset, None);
    }

    #[test]
    fn empty_payload_yields_all_none() {
        let payload = synth_payload_with_ext_ack(-22, None, None);
        let err = NlMsgError::from_bytes(&payload).expect("parse");
        let parsed = err.parsed_ext_ack(&payload);
        assert_eq!(parsed.message, None);
        assert_eq!(parsed.offset, None);
    }

    #[test]
    fn malformed_utf8_decodes_lossily_rather_than_failing() {
        let mut payload = synth_payload_with_ext_ack(-22, None, None);
        // Inject a NLMSGERR_ATTR_MSG with invalid UTF-8.
        let bad_bytes = b"\xFF\xFE\xFD\x00"; // NUL-terminated invalid utf-8
        let attr_len: u16 = 4 + bad_bytes.len() as u16;
        payload.extend_from_slice(&attr_len.to_ne_bytes());
        payload.extend_from_slice(&nlmsgerr_attr::MSG.to_ne_bytes());
        payload.extend_from_slice(bad_bytes);
        let err = NlMsgError::from_bytes(&payload).expect("parse");
        let parsed = err.parsed_ext_ack(&payload);
        // Lossy decode produces replacement characters; what we
        // actually care about is "we didn't crash / return None".
        assert!(parsed.message.is_some());
    }

    /// One TLV, aligned.
    fn tlv(ty: u16, value: &[u8]) -> Vec<u8> {
        let mut out = ((4 + value.len()) as u16).to_ne_bytes().to_vec();
        out.extend_from_slice(&ty.to_ne_bytes());
        out.extend_from_slice(value);
        out.resize(nla_align(out.len()), 0);
        out
    }

    /// An error response carrying `request` whole (uncapped) or only its
    /// header (capped), then `tlvs`.
    fn error_payload(error: i32, request: &[u8], capped: bool, tlvs: &[Vec<u8>]) -> Vec<u8> {
        let mut out = error.to_ne_bytes().to_vec();
        out.extend_from_slice(if capped { &request[..16] } else { request });
        out.resize(4 + nla_align(out.len() - 4), 0);
        for t in tlvs {
            out.extend_from_slice(t);
        }
        out
    }

    /// A 40-byte request whose body is itself shaped like an `OFFS` TLV,
    /// so reading it as ext-ack finds an offset there is none of.
    fn request() -> Vec<u8> {
        let mut req = 40u32.to_ne_bytes().to_vec();
        req.extend_from_slice(&[0u8; 12]);
        req.extend_from_slice(&tlv(nlmsgerr_attr::OFFS, &99u32.to_ne_bytes()));
        req.resize(40, 0);
        req
    }

    /// Uncapped (`NETLINK_CAP_ACK` off), the request is echoed whole and
    /// the TLVs follow it. Reading them at the fixed capped offset parsed
    /// the request's own body as ext-ack (#507).
    #[test]
    fn uncapped_tlvs_are_found_after_the_echoed_request() {
        let msg = tlv(nlmsgerr_attr::MSG, b"the real message\0");
        let payload = error_payload(-22, &request(), false, &[msg]);
        let err = NlMsgError::from_bytes(&payload).unwrap();
        let parsed = err.ext_ack(NLM_F_ACK_TLVS, &payload);
        assert_eq!(parsed.message.as_deref(), Some("the real message"));
        assert_eq!(parsed.offset, None);
        // The fixed-offset reader takes the request's body for TLVs.
        assert_eq!(err.parsed_ext_ack(&payload).offset, Some(99));
    }

    #[test]
    fn capped_tlvs_are_found_after_the_header() {
        let msg = tlv(nlmsgerr_attr::MSG, b"capped\0");
        let payload = error_payload(-22, &request(), true, &[msg]);
        let err = NlMsgError::from_bytes(&payload).unwrap();
        let parsed = err.ext_ack(NLM_F_ACK_TLVS | NLM_F_CAPPED, &payload);
        assert_eq!(parsed.message.as_deref(), Some("capped"));
    }

    /// Without `NLM_F_ACK_TLVS` there are no TLVs, whatever the bytes say.
    #[test]
    fn no_ack_tlvs_flag_means_no_tlvs() {
        let msg = tlv(nlmsgerr_attr::MSG, b"not ext-ack\0");
        let payload = error_payload(-22, &request(), true, &[msg]);
        let err = NlMsgError::from_bytes(&payload).unwrap();
        assert!(err.ext_ack(NLM_F_CAPPED, &payload).is_empty());
    }

    /// A generic netlink family reports a missing attribute with
    /// `MISS_TYPE`/`MISS_NEST` and no message; the error says so instead of
    /// a bare EINVAL.
    #[test]
    fn a_missing_attribute_is_described() {
        let payload = error_payload(
            -22,
            &request(),
            true,
            &[
                tlv(nlmsgerr_attr::MISS_TYPE, &3u32.to_ne_bytes()),
                tlv(nlmsgerr_attr::MISS_NEST, &24u32.to_ne_bytes()),
            ],
        );
        let err = NlMsgError::from_bytes(&payload).unwrap();
        let flags = NLM_F_ACK_TLVS | NLM_F_CAPPED;
        let parsed = err.ext_ack(flags, &payload);
        assert_eq!(
            (parsed.missing_type, parsed.missing_nest),
            (Some(3), Some(24))
        );
        let shown = err.to_error(flags, &payload).to_string();
        assert!(
            shown.contains("missing required attribute (type 3) in the nest at request offset 24"),
            "{shown}"
        );
    }

    #[test]
    fn policy_bounds_are_described() {
        let mut policy = tlv(policy_attr::MIN_VALUE_U, &1u64.to_ne_bytes());
        policy.extend(tlv(policy_attr::MAX_VALUE_U, &4096u64.to_ne_bytes()));
        let payload = error_payload(
            -34,
            &request(),
            true,
            &[
                tlv(nlmsgerr_attr::MSG, b"integer out of range\0"),
                tlv(nlmsgerr_attr::POLICY, &policy),
            ],
        );
        let err = NlMsgError::from_bytes(&payload).unwrap();
        let described = err
            .ext_ack(NLM_F_ACK_TLVS | NLM_F_CAPPED, &payload)
            .describe();
        assert_eq!(
            described.as_deref(),
            Some("integer out of range; policy: value in 1..=4096")
        );
    }

    /// #526: an errno is read against the request it refused. ESRCH to a
    /// route delete and EADDRNOTAVAIL to an address delete mean "not
    /// there"; to anything else they do not. #722: only on rtnetlink, where
    /// those type numbers mean those requests.
    #[test]
    fn an_errno_is_read_against_its_request() {
        use crate::netlink::{ErrorKind, Protocol};
        let refusal = |request_type: u16, errno: i32| {
            let mut req = request();
            req[4..6].copy_from_slice(&request_type.to_ne_bytes());
            let payload = error_payload(-errno, &req, false, &[]);
            NlMsgError::from_bytes(&payload).unwrap().to_error(0, &payload)
        };
        let gone_route = refusal(NlMsgType::RTM_DELROUTE, libc::ESRCH).in_protocol(Protocol::Route);
        assert!(gone_route.is_not_found(), "{gone_route}");
        assert_eq!(gone_route.kind(), ErrorKind::NotFound);
        assert_eq!(gone_route.request_type(), Some(NlMsgType::RTM_DELROUTE));
        assert_eq!(gone_route.protocol(), Some(Protocol::Route));
        let gone_addr =
            refusal(NlMsgType::RTM_DELADDR, libc::EADDRNOTAVAIL).in_protocol(Protocol::Route);
        assert!(gone_addr.is_not_found(), "{gone_addr}");
        let other = refusal(NlMsgType::RTM_NEWROUTE, libc::ESRCH).in_protocol(Protocol::Route);
        assert!(!other.is_not_found(), "ESRCH to an add is not \"not there\"");
        assert_eq!(other.kind(), ErrorKind::Other);

        // Type 25 is XFRM_MSG_UPDPOLICY on xfrm, and can be a family id on
        // generic netlink; 21 is XFRM_MSG_GETPOLICY.
        for protocol in [Protocol::Xfrm, Protocol::Generic] {
            let e = refusal(25, libc::ESRCH).in_protocol(protocol);
            assert!(!e.is_not_found(), "{protocol:?}: {e}");
            let e = refusal(21, libc::EADDRNOTAVAIL).in_protocol(protocol);
            assert!(!e.is_not_found(), "{protocol:?}: {e}");
        }
        // Where the socket was not known, nothing is assumed.
        assert!(!refusal(NlMsgType::RTM_DELROUTE, libc::ESRCH).is_not_found());

        // #718: xfrm answers a request for an SA it does not have with
        // ESRCH. 17, 18 and 26 are its DELSA, GETSA and UPDSA, and on
        // rtnetlink RTM_DELLINK, RTM_GETLINK and RTM_SETLINK, where ESRCH
        // means nothing of the kind.
        use crate::netlink::xfrm::{XFRM_MSG_DELSA, XFRM_MSG_GETSA, XFRM_MSG_UPDSA};
        for ty in [XFRM_MSG_DELSA, XFRM_MSG_GETSA, XFRM_MSG_UPDSA] {
            let sa = refusal(ty, libc::ESRCH).in_protocol(Protocol::Xfrm);
            assert!(sa.is_not_found(), "xfrm {ty}: {sa}");
            let link = refusal(ty, libc::ESRCH).in_protocol(Protocol::Route);
            assert!(!link.is_not_found(), "rtnetlink {ty}: {link}");
        }
        let policy = refusal(25, libc::ESRCH).in_protocol(Protocol::Xfrm);
        assert!(!policy.is_not_found(), "ESRCH to a policy update: {policy}");
    }

    /// #530: a positive value in an ACK is that value, not an errno; a
    /// negative one is still the error.
    #[test]
    fn an_ack_can_carry_a_value() {
        let value = error_payload(3, &request(), false, &[]);
        assert_eq!(NlMsgError::from_bytes(&value).unwrap().ack_value(0, &value).unwrap(), 3);
        let ack = error_payload(0, &request(), false, &[]);
        assert_eq!(NlMsgError::from_bytes(&ack).unwrap().ack_value(0, &ack).unwrap(), 0);
        let error = error_payload(-19, &request(), false, &[]);
        let err = NlMsgError::from_bytes(&error).unwrap().ack_value(0, &error).unwrap_err();
        assert!(err.is_no_device(), "{err}");
    }

    /// A successful ACK can carry a warning; it is parsed like an error's
    /// message (an ACK never echoes the request, capped or not).
    #[test]
    fn a_warning_on_an_ack_is_read() {
        let warning = tlv(
            nlmsgerr_attr::MSG,
            b"sch_htb: quantum of class 10002 is big.\0",
        );
        let payload = error_payload(0, &request(), true, &[warning]);
        let err = NlMsgError::from_bytes(&payload).unwrap();
        assert!(err.is_ack());
        let parsed = err.ext_ack(NLM_F_ACK_TLVS, &payload);
        assert_eq!(
            parsed.message.as_deref(),
            Some("sch_htb: quantum of class 10002 is big.")
        );
    }
}

#[cfg(test)]
mod dump_intr_tests {
    use super::*;

    #[test]
    fn nlmsghdr_reports_dump_interrupted_when_flag_set() {
        let h = NlMsgHdr {
            nlmsg_len: NLMSG_HDRLEN as u32,
            nlmsg_type: NlMsgType::DONE,
            nlmsg_flags: NLM_F_MULTI | NLM_F_DUMP_INTR,
            nlmsg_seq: 42,
            nlmsg_pid: 0,
        };
        assert!(h.is_dump_interrupted());
        assert!(h.is_done());
    }

    #[test]
    fn nlmsghdr_does_not_report_dump_interrupted_for_clean_done() {
        let h = NlMsgHdr {
            nlmsg_len: NLMSG_HDRLEN as u32,
            nlmsg_type: NlMsgType::DONE,
            nlmsg_flags: NLM_F_MULTI,
            nlmsg_seq: 42,
            nlmsg_pid: 0,
        };
        assert!(!h.is_dump_interrupted());
    }

    #[test]
    fn nlmsghdr_reports_dump_interrupted_on_data_frame_too() {
        // The kernel may set NLM_F_DUMP_INTR on any frame in the
        // dump stream, not just NLMSG_DONE. Pin that we detect it
        // on a mid-dump RTM_NEWLINK frame.
        let h = NlMsgHdr {
            nlmsg_len: NLMSG_HDRLEN as u32,
            nlmsg_type: NlMsgType::RTM_NEWLINK,
            nlmsg_flags: NLM_F_MULTI | NLM_F_DUMP_INTR,
            nlmsg_seq: 42,
            nlmsg_pid: 0,
        };
        assert!(h.is_dump_interrupted());
        assert!(!h.is_done());
        assert!(h.is_multi());
    }
}

#[cfg(test)]
mod nlmsg_align_overflow_tests {
    use super::*;

    /// Plan 232 B18 — pre-fix `nlmsg_align(usize::MAX)`
    /// debug-panicked on the `len + 3` overflow. Post-fix it
    /// saturates and `nlmsg_align_checked` returns None.
    #[test]
    fn b18_nlmsg_align_saturates_on_overflow() {
        // Pre-fix this would panic in debug; post-fix it
        // saturates to usize::MAX (which downstream
        // `<= data.len()` checks will reject naturally).
        let aligned = nlmsg_align(usize::MAX);
        // The exact value is `usize::MAX & !3`; verify no
        // panic and the value is at least `usize::MAX - 3`.
        assert!(aligned >= usize::MAX - 3);
    }

    #[test]
    fn b18_nlmsg_align_checked_returns_none_on_overflow() {
        assert_eq!(nlmsg_align_checked(usize::MAX), None);
        assert_eq!(nlmsg_align_checked(usize::MAX - 2), None);
        // A "valid" small length still aligns correctly.
        assert_eq!(nlmsg_align_checked(0), Some(0));
        assert_eq!(nlmsg_align_checked(1), Some(4));
        assert_eq!(nlmsg_align_checked(5), Some(8));
        assert_eq!(nlmsg_align_checked(8), Some(8));
    }
}
