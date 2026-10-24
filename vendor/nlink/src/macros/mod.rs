//! Re-exports + runtime substrate for the proc-macro derives
//! from `nlink-macros`.
//!
//! Downstream code typically writes `use nlink::macros::*;` to
//! pull in both the derives and the supporting traits in one
//! shot — no need to depend on `nlink-macros` directly.
//!
//! # What's here
//!
//! - The proc-macro derives [`GenlCommand`], [`GenlAttribute`],
//!   [`GenlEnum`] re-exported from [`nlink-macros`][nlink-macros].
//!   `GenlMessage` and `NetlinkAttrs` derives + the
//!   `#[genl_family]` attribute macro ship in Plan 154 Phase 3b
//!   / Phase 4.
//! - Public traits [`GenlMessage`] and [`NetlinkAttrs`] defining
//!   the wire-protocol contract that the derives implement.
//!   Authors writing a GENL family by hand can implement these
//!   traits directly until the derives ship.
//! - The [`__rt`] runtime module — small helpers the macros
//!   emit calls into. Documented `#[doc(hidden)]` as internal
//!   API; reach for the public surface above instead.
//!
//! [nlink-macros]: https://docs.rs/nlink-macros
//!
//! # Plan 154 progress (the long view)
//!
//! | Phase | Ships | Status |
//! |---|---|---|
//! | 1 | Crate scaffold + `#[derive(GenlCommand)]` | ✓ |
//! | 2 | `#[derive(GenlAttribute)]` + `#[derive(GenlEnum)]` | ✓ |
//! | 3a | `nlink::macros` substrate (this module) | ✓ |
//! | 3b | `#[derive(GenlMessage)]` (NetlinkAttrs deferred) | ✓ |
//! | 4 | `#[genl_family(...)]` attribute macro | ✓ |
//! | 5 | `Connection::<F>::send_typed<M, R>` + `dump_typed_stream` | ✓ |
//! | 6 | Worked example + recipe | ✓ |
//! | 7 | Final re-export polish + CHANGELOG framing | ✓ |
//! | 8.1 | `i32` field support | ✓ |
//! | 8.2 | `Option<GenlEnum>` via `repr = "..."` hint | ✓ |
//! | 8.3 | `Vec<GenlEnum>` repeated-attribute fields | ✓ |
//! | 8.4 | `bitflags`-newtype fields via `bitflags = "..."` hint | ✓ |
//! | 8.5 | `#[derive(NetlinkAttrs)]` + `nested` field hint for nested attribute groups | ✓ |

pub use nlink_macros::{
    genl_family, GenlAttribute, GenlCommand, GenlEnum, GenlMessage, NetlinkAttrs,
};

mod genl_dispatch;

pub use genl_dispatch::GenlTypedDumpStream;

use crate::netlink::MessageBuilder;
use crate::Result;

/// A GENL message that knows how to serialize itself onto the
/// wire and deserialize from an attribute-iterator payload.
///
/// Implemented automatically by `#[derive(GenlMessage)]` (Plan
/// 154 Phase 3b). Can also be implemented by hand against the
/// runtime helpers in [`__rt`] for cases the derive doesn't yet
/// cover.
///
/// # Wire contract
///
/// - `CMD` is the kernel-side command byte (used to populate the
///   GENL header's `cmd` field).
/// - `to_bytes` writes the message body — `MessageBuilder` is
///   positioned after the netlink header + GENL header; the impl
///   appends the message's `nlattr`s.
/// - `from_bytes` parses the attribute payload (already past the
///   netlink + GENL headers).
pub trait GenlMessage: Sized {
    /// Kernel command code for this message (e.g.
    /// `DPLL_CMD_DEVICE_GET = 2`).
    const CMD: u8;

    /// Serialize the message body into the builder. The builder
    /// is already positioned after the netlink + GENL headers;
    /// this impl appends the message's `nlattr`s.
    fn to_bytes(&self, builder: &mut MessageBuilder) -> Result<()>;

    /// Parse the message body from an attribute payload (i.e. the
    /// bytes after the GENL header).
    fn from_bytes(payload: &[u8]) -> Result<Self>;
}

/// Connection-facing trait for a Generic Netlink family marker.
///
/// Implemented automatically by [`macro@genl_family`]. Carries
/// the runtime-resolved kernel family ID + the compile-time
/// version constant the GENL header needs on every outbound
/// message. This is what
/// [`Connection::<F>::send_typed`](crate::netlink::Connection) +
/// [`dump_typed_stream`](crate::netlink::Connection)
/// (Plan 154 Phase 5) bound their generic dispatch on.
///
/// # Hand-implementation
///
/// Hand-implementing this trait is supported for the rare case
/// where the macro doesn't fit (e.g. a family marker that needs
/// extra fields beyond `family_id`). Match the shape:
///
/// ```no_run
/// # use nlink::macros::GenlFamily;
/// # struct SomeCache;
/// pub struct MyFamily { family_id: u16, extra: SomeCache }
/// impl GenlFamily for MyFamily {
///     const VERSION: u8 = 1;
///     const NAME: &'static str = "my_family";
///     fn family_id(&self) -> u16 { self.family_id }
/// }
/// ```
///
/// Family ID resolution still goes through
/// [`AsyncProtocolInit`](crate::netlink::AsyncProtocolInit); the
/// `GenlFamily` trait is the *send-time* contract, not the
/// construction-time one.
pub trait GenlFamily {
    /// Family version (the GENL header's `version` field).
    /// Compile-time constant per Generic Netlink convention.
    const VERSION: u8;

    /// Family name (the kernel-side string registered via
    /// `CTRL_CMD_NEWFAMILY`). Compile-time constant; mirrors
    /// the `NAME` const that `#[genl_family]` already emits as an
    /// inherent associated constant on the marker struct.
    const NAME: &'static str;

    /// Kernel-assigned family ID, resolved at connection
    /// construction time and stored on the marker.
    fn family_id(&self) -> u16;

    /// Look up a multicast-group ID by name.
    ///
    /// Returns the kernel-assigned `u32` group ID for the named
    /// group (e.g., `"monitor"` on DPLL, `"rate"` on Devlink),
    /// or `None` if the family doesn't expose that group.
    ///
    /// The map is populated at construction time by the
    /// [`AsyncProtocolInit::resolve_async`](crate::netlink::AsyncProtocolInit)
    /// step, which parses `CTRL_ATTR_MCAST_GROUPS` out of the
    /// `CTRL_CMD_GETFAMILY` response. Plan 156 Phase 5.
    ///
    /// Default impl returns `None` for families that don't carry
    /// a group map (legacy callers using
    /// [`__rt::resolve_genl_family`] instead of
    /// [`__rt::resolve_genl_family_with_groups`]). The
    /// `#[genl_family]` macro always uses the with-groups
    /// variant, so macro-generated markers override this
    /// method with a real lookup.
    fn mcast_group(&self, _name: &str) -> ::core::option::Option<u32> {
        ::core::option::Option::None
    }
}

/// A nested-attribute group — a payload struct that doesn't carry
/// a command code but is encoded as the contents of a single
/// `NLA_F_NESTED` attribute.
///
/// Used as the building block for nested fields inside a
/// [`GenlMessage`]; e.g. the DPLL `pin-parent-device` block that
/// lives inside `DPLL_A_PIN_PARENT_DEVICE`.
///
/// Implemented automatically by `#[derive(NetlinkAttrs)]` (Plan
/// 154 Phase 3b).
pub trait NetlinkAttrs: Sized {
    /// Serialize this group's attributes into the builder.
    /// The builder is positioned inside the enclosing nested
    /// attribute; this impl appends the inner `nlattr`s.
    fn write_attrs(&self, builder: &mut MessageBuilder) -> Result<()>;

    /// Parse the inner attribute payload (bytes inside the
    /// enclosing nested attribute, after its header).
    fn read_attrs(payload: &[u8]) -> Result<Self>;
}

/// Runtime helpers that the proc-macro derives emit calls into.
///
/// **Documented as internal API.** Treat as part of the
/// `#[derive(GenlMessage)]` machinery; downstream code that
/// wants to manipulate attributes directly should use
/// [`MessageBuilder`] + [`AttrIter`][crate::netlink::attr::AttrIter]
/// instead.
///
/// The helpers are stable across patch releases but new
/// helpers may be added in minor releases as the derive's
/// type-mapping table grows.
#[doc(hidden)]
pub mod __rt {
    use crate::netlink::{attr::AttrIter, MessageBuilder};
    use crate::{Error, Result};

    // -- emit_* helpers (called by the derived to_bytes) --
    //
    // All emit the attribute in native byte order. For
    // big-endian attributes (rare — mostly netfilter / nftables)
    // the user explicitly opts in via `#[genl_attr_be(...)]`
    // (Phase 3b syntax), which routes through `_be` variants.

    pub fn emit_u8_attr(b: &mut MessageBuilder, attr_type: u16, v: u8) {
        b.append_attr_u8(attr_type, v);
    }
    pub fn emit_u16_attr(b: &mut MessageBuilder, attr_type: u16, v: u16) {
        b.append_attr_u16(attr_type, v);
    }
    pub fn emit_u32_attr(b: &mut MessageBuilder, attr_type: u16, v: u32) {
        b.append_attr_u32(attr_type, v);
    }
    pub fn emit_u64_attr(b: &mut MessageBuilder, attr_type: u16, v: u64) {
        b.append_attr_u64(attr_type, v);
    }
    /// Signed-int emit (kernel encodes `i32` as a 4-byte LE int —
    /// same wire shape as `u32`, just reinterpreted on the parse
    /// side). Used by fields like DPLL `temp_mdeg` (`Option<i32>`).
    pub fn emit_i32_attr(b: &mut MessageBuilder, attr_type: u16, v: i32) {
        b.append_attr_u32(attr_type, v as u32);
    }
    /// Plan 206 — emit a signed 64-bit attribute (kernel `s64`).
    /// Used by DPLL `phase_offset` (attoseconds × 1000, can
    /// exceed `i32::MAX` easily).
    pub fn emit_i64_attr(b: &mut MessageBuilder, attr_type: u16, v: i64) {
        b.append_attr_u64(attr_type, v as u64);
    }
    pub fn emit_str_attr(b: &mut MessageBuilder, attr_type: u16, v: &str) {
        b.append_attr_str(attr_type, v);
    }
    pub fn emit_bytes_attr(b: &mut MessageBuilder, attr_type: u16, v: &[u8]) {
        b.append_attr(attr_type, v);
    }
    pub fn emit_flag_attr(b: &mut MessageBuilder, attr_type: u16) {
        b.append_attr_empty(attr_type);
    }

    // Big-endian variants for nftables-style attributes.
    pub fn emit_u16_be_attr(b: &mut MessageBuilder, attr_type: u16, v: u16) {
        b.append_attr_u16_be(attr_type, v);
    }
    pub fn emit_u32_be_attr(b: &mut MessageBuilder, attr_type: u16, v: u32) {
        b.append_attr_u32_be(attr_type, v);
    }
    pub fn emit_u64_be_attr(b: &mut MessageBuilder, attr_type: u16, v: u64) {
        b.append_attr_u64_be(attr_type, v);
    }

    // -- parse_* helpers (called by the derived from_bytes) --
    //
    // All take the attribute *payload* bytes (already past the
    // nlattr header) and return the typed value.

    pub fn parse_u8_attr(payload: &[u8]) -> Result<u8> {
        if payload.is_empty() {
            return Err(Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: 1,
                actual: 0,
            }));
        }
        Ok(payload[0])
    }
    pub fn parse_u16_attr(payload: &[u8]) -> Result<u16> {
        if payload.len() < 2 {
            return Err(Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: 2,
                actual: payload.len(),
            }));
        }
        Ok(u16::from_ne_bytes([payload[0], payload[1]]))
    }
    pub fn parse_u32_attr(payload: &[u8]) -> Result<u32> {
        if payload.len() < 4 {
            return Err(Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: 4,
                actual: payload.len(),
            }));
        }
        Ok(u32::from_ne_bytes([
            payload[0], payload[1], payload[2], payload[3],
        ]))
    }
    /// A `u64`, or a YNL `uint` (`NLA_UINT`, kernel 6.6+), which
    /// `nla_put_uint` writes as 4 bytes when the value fits (#763). A
    /// fixed-width `u64` is always 8 bytes, so nothing parses differently.
    pub fn parse_u64_attr(payload: &[u8]) -> Result<u64> {
        if let Ok(word) = <[u8; 4]>::try_from(payload) {
            return Ok(u32::from_ne_bytes(word).into());
        }
        if payload.len() < 8 {
            return Err(Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: 8,
                actual: payload.len(),
            }));
        }
        let mut a = [0u8; 8];
        a.copy_from_slice(&payload[..8]);
        Ok(u64::from_ne_bytes(a))
    }
    /// Signed-int parse — same on-wire layout as `u32`, sign-aware
    /// reinterpretation on read (kernel emits signed ints native-endian
    /// per its `nla_get_s32` helper).
    pub fn parse_i32_attr(payload: &[u8]) -> Result<i32> {
        if payload.len() < 4 {
            return Err(Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: 4,
                actual: payload.len(),
            }));
        }
        Ok(i32::from_ne_bytes([
            payload[0], payload[1], payload[2], payload[3],
        ]))
    }
    /// Plan 206 — parse a signed 64-bit attribute (kernel `s64`).
    /// Accepts payloads >= 8 bytes per CLAUDE.md `## Parser robustness`
    /// rule 1 (kernel may grow the attribute in future versions; we
    /// take the prefix and ignore trailing bytes). Pre-0.19 DPLL's
    /// `phase_offset` was incorrectly typed as `i32` and routed
    /// through `parse_i32_attr` — the high 4 bytes of the kernel's
    /// 8-byte payload were silently dropped on LE platforms, yielding
    /// nonsense readings for any value > ~2.147 seconds in
    /// attoseconds × 1000 (essentially always for real PTP/SyncE).
    pub fn parse_i64_attr(payload: &[u8]) -> Result<i64> {
        if payload.len() < 8 {
            return Err(Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: 8,
                actual: payload.len(),
            }));
        }
        let mut a = [0u8; 8];
        a.copy_from_slice(&payload[..8]);
        Ok(i64::from_ne_bytes(a))
    }

    // ============================================================
    // Plan 226 (0.20.1) — kernel `nla_get_sint` / `nla_put_sint`
    // helpers. Variable-length signed integer: 4 bytes if the value
    // fits in s32, 8 bytes otherwise. The kernel uses this for DPLL
    // FFO, phase_offset, and other "natural-i32-but-occasionally-i64"
    // fields. Without sint-aware parsing, an 8-byte payload routed
    // through `parse_i32_attr` silently truncates to the low 32 bits
    // (the bug Plan 226 closes for the i32 field; the full i64
    // widening is queued for 0.21 when nlink can take a breaking
    // type change).
    // ============================================================

    /// Plan 226 — read a kernel `sint` attribute as `i64`.
    ///
    /// Returns `Ok` for 4-byte (`s32` widened to `i64`) and 8-byte
    /// payloads. Returns `Err(Truncated)` for any other length.
    pub fn parse_sint_attr_as_i64(payload: &[u8]) -> Result<i64> {
        match payload.len() {
            4 => {
                let bytes: [u8; 4] = [payload[0], payload[1], payload[2], payload[3]];
                Ok(i32::from_ne_bytes(bytes) as i64)
            }
            n if n >= 8 => {
                let mut a = [0u8; 8];
                a.copy_from_slice(&payload[..8]);
                Ok(i64::from_ne_bytes(a))
            }
            actual => Err(Error::from(crate::netlink::ErrorDetail::Truncated { expected: 4, actual })),
        }
    }

    /// Plan 226 — read a kernel `sint` attribute as `i32`.
    ///
    /// Returns the value cast as `i32` when it fits, returns
    /// `Err(InvalidMessage)` (with a descriptive message) when the
    /// kernel's 8-byte payload doesn't fit in `i32`. The caller
    /// derives `Option<i32>` semantics via the macro: out-of-range
    /// becomes `None`.
    ///
    /// **Backward-compat note**: the previous `parse_i32_attr` path
    /// silently truncated the low 32 bits of an 8-byte payload.
    /// Routing the FFO field through this helper changes the
    /// silently-wrong behaviour to a clean parse error — the macro
    /// surfaces it as a `Truncated`-class error, which the derived
    /// `from_bytes` propagates via `?` so the message parse fails
    /// outright. That's the correct semantics: it surfaces the
    /// overflow rather than burying it in a junk reading.
    pub fn parse_sint_attr_as_i32(payload: &[u8]) -> Result<i32> {
        let widened = parse_sint_attr_as_i64(payload)?;
        i32::try_from(widened).map_err(|_| {
            Error::invalid_message(format!(
                "sint attribute value {widened} does not fit in i32 (kernel emitted 8-byte sint; \
                 field needs i64 widening — see Plan 226 / Plan 226 follow-on 0.21)"
            ))
        })
    }

    /// Plan 226 — write a kernel `sint` attribute (minimum-width on
    /// the wire). Mirrors `nla_put_sint`. Values in `i32` range emit
    /// 4 bytes; everything else emits 8 bytes.
    pub fn emit_sint_attr(b: &mut MessageBuilder, attr_type: u16, value: i64) {
        if (i32::MIN as i64..=i32::MAX as i64).contains(&value) {
            b.append_attr_u32(attr_type, value as i32 as u32);
        } else {
            b.append_attr_u64(attr_type, value as u64);
        }
    }
    pub fn parse_str_attr(payload: &[u8]) -> Result<String> {
        // Kernel strings are NUL-terminated; strip and decode
        // lossily so non-UTF8 doesn't poison the whole parse.
        let trimmed = payload
            .iter()
            .position(|&b| b == 0)
            .map(|n| &payload[..n])
            .unwrap_or(payload);
        Ok(String::from_utf8_lossy(trimmed).into_owned())
    }
    pub fn parse_bytes_attr(payload: &[u8]) -> Result<Vec<u8>> {
        Ok(payload.to_vec())
    }

    // Big-endian parse variants.
    pub fn parse_u16_be_attr(payload: &[u8]) -> Result<u16> {
        if payload.len() < 2 {
            return Err(Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: 2,
                actual: payload.len(),
            }));
        }
        Ok(u16::from_be_bytes([payload[0], payload[1]]))
    }
    pub fn parse_u32_be_attr(payload: &[u8]) -> Result<u32> {
        if payload.len() < 4 {
            return Err(Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: 4,
                actual: payload.len(),
            }));
        }
        Ok(u32::from_be_bytes([
            payload[0], payload[1], payload[2], payload[3],
        ]))
    }
    pub fn parse_u64_be_attr(payload: &[u8]) -> Result<u64> {
        if payload.len() < 8 {
            return Err(Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: 8,
                actual: payload.len(),
            }));
        }
        let mut a = [0u8; 8];
        a.copy_from_slice(&payload[..8]);
        Ok(u64::from_be_bytes(a))
    }

    /// Walk the attribute payload bytes via the existing
    /// [`AttrIter`][crate::netlink::attr::AttrIter]. Re-exported
    /// here so derived code doesn't have to know the full path.
    pub fn attr_iter(payload: &[u8]) -> AttrIter<'_> {
        AttrIter::new(payload)
    }

    // ============================================================
    // GENL family resolution helper (Plan 154 Phase 4)
    // ============================================================
    //
    // `#[genl_family(name = "...", version = N)]` emits an
    // AsyncProtocolInit impl whose body calls
    // `resolve_genl_family(socket, "...")` to look up the
    // kernel-assigned family ID at connection construction.
    //
    // The in-tree families (wireguard, macsec, mptcp, nl80211, devlink,
    // ethtool) resolve through these too. Both read to the request's ACK
    // under the default operation timeout (#496): the connection that
    // would carry a configured timeout does not exist yet.

    use crate::netlink::{
        genl::{CtrlAttr, CtrlAttrMcastGrp, CtrlCmd, GenlMsgHdr, GENL_HDRLEN, GENL_ID_CTRL},
        message::{MessageIter, NlMsgError, NLM_F_ACK, NLM_F_REQUEST},
        NetlinkSocket,
    };
    use std::collections::HashMap;

    /// Resolve the kernel-assigned family ID for a Generic
    /// Netlink family by name.
    ///
    /// Emits `CTRL_CMD_GETFAMILY` with the family name and parses
    /// the response's `CTRL_ATTR_FAMILY_ID`. Returns
    /// a not-found error ([`ErrorObject::GenlFamily`](crate::ErrorObject::GenlFamily)) if the kernel reports the family
    /// doesn't exist (typically: required kernel module isn't
    /// loaded, or kernel is too old for the feature).
    ///
    /// Emitted by `#[genl_family]`-expanded `AsyncProtocolInit::resolve_async`
    /// impls. Downstream code shouldn't call this directly — let
    /// the macro handle it.
    #[nlink_macros::send_futures]
    pub async fn resolve_genl_family(
        socket: &NetlinkSocket,
        name: &str,
    ) -> Result<u16> {
        Ok(resolve_genl_family_with_groups(socket, name).await?.0)
    }

    /// Resolve the kernel-assigned family ID **and** the family's
    /// multicast group map for a Generic Netlink family by name.
    ///
    /// Same request as [`resolve_genl_family`] but additionally
    /// walks the response's `CTRL_ATTR_MCAST_GROUPS` nested list,
    /// extracting every `(name, id)` pair into a `HashMap<String, u32>`.
    /// Families with no multicast groups return an empty map.
    ///
    /// Emitted by `#[genl_family]`-expanded
    /// `AsyncProtocolInit::resolve_async` impls (Plan 156 Phase 5).
    /// Downstream code shouldn't call this directly — let the macro
    /// handle it. The `mcast_groups` field on the macro-generated
    /// family marker stores the map; the
    /// [`GenlFamily::mcast_group(name)`](crate::macros::GenlFamily)
    /// accessor reads it.
    #[nlink_macros::send_futures]
    pub async fn resolve_genl_family_with_groups(
        socket: &NetlinkSocket,
        name: &str,
    ) -> Result<(u16, HashMap<String, u32>)> {
        // An error carries the socket's protocol and namespace (#718).
        resolve_family_unstamped(socket, name)
            .await
            .map_err(|e| socket.stamp(e))
    }

    async fn resolve_family_unstamped(
        socket: &NetlinkSocket,
        name: &str,
    ) -> Result<(u16, HashMap<String, u32>)> {
        let mut builder = MessageBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(CtrlCmd::GetFamily as u8, 1);
        builder.append(&genl_hdr);
        builder.append_attr_str(CtrlAttr::FamilyName as u16, name);

        let seq = socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(socket.pid());

        let msg = builder.finish();
        socket.send(&msg).await?;

        let mut family_id: Option<u16> = None;
        let mut mcast_groups: HashMap<String, u32> = HashMap::new();

        // Read to this request's ACK, under the operation timeout (#496).
        // The reply and its ACK arrive as two datagrams; reading only the
        // first left the ACK queued for whatever used the socket next,
        // and a reply that never came hung the constructor for good.
        let read = async {
            loop {
                let response: Vec<u8> = socket.recv_unicast().await?;
                if read_family_reply(&response, seq, name, &mut family_id, &mut mcast_groups)? {
                    return Ok::<(), Error>(());
                }
            }
        };
        tokio::time::timeout(crate::netlink::connection::DEFAULT_OPERATION_TIMEOUT, read)
            .await
            .map_err(|_| Error::timeout())??;

        match family_id {
            Some(id) => Ok((id, mcast_groups)),
            None => Err(Error::family_not_found(name)),
        }
    }

    /// Fold one datagram of a `CTRL_CMD_GETFAMILY` reply into `family_id`
    /// and `mcast_groups`. Returns `true` once this request's ACK has
    /// arrived.
    fn read_family_reply(
        response: &[u8],
        seq: u32,
        name: &str,
        family_id: &mut Option<u16>,
        mcast_groups: &mut HashMap<String, u32>,
    ) -> Result<bool> {
        for result in MessageIter::new(response) {
            let (header, payload) = result?;

            if header.nlmsg_seq != seq {
                continue;
            }

            if header.is_error() {
                let err = NlMsgError::from_bytes(payload)?;
                err.warn_if_ack_warns(header.nlmsg_flags, payload);
                if !err.is_ack() {
                    if err.error == -libc::ENOENT {
                        return Err(Error::family_not_found(name));
                    }
                    return Err(err.to_error(header.nlmsg_flags, payload));
                }
                return Ok(true);
            }

            if header.is_done() {
                return Ok(true);
            }

            if payload.len() < GENL_HDRLEN {
                return Err(Error::invalid_message(
                    "GENL header too short in CTRL_CMD_GETFAMILY response",
                ));
            }

            let attrs_data = &payload[GENL_HDRLEN..];
            for (attr_type, attr_payload) in AttrIter::new(attrs_data) {
                if attr_type == CtrlAttr::FamilyId as u16 {
                    *family_id = Some(parse_u16_attr(attr_payload)?);
                } else if attr_type == CtrlAttr::McastGroups as u16 {
                    // CTRL_ATTR_MCAST_GROUPS is a nested list of
                    // anonymous index attrs; each inner element
                    // carries CtrlAttrMcastGrp::Name (string) +
                    // CtrlAttrMcastGrp::Id (u32). Walk all of
                    // them and assemble the map.
                    for (_idx, grp_data) in AttrIter::new(attr_payload) {
                        let mut grp_name: Option<String> = None;
                        let mut grp_id: Option<u32> = None;
                        for (grp_attr_type, grp_attr_payload) in AttrIter::new(grp_data) {
                            if grp_attr_type == CtrlAttrMcastGrp::Name as u16 {
                                grp_name = Some(
                                    ::std::str::from_utf8(grp_attr_payload)
                                        .unwrap_or("")
                                        .trim_end_matches('\0')
                                        .to_string(),
                                );
                            } else if grp_attr_type == CtrlAttrMcastGrp::Id as u16
                                && grp_attr_payload.len() >= 4
                            {
                                grp_id = Some(u32::from_ne_bytes(
                                    grp_attr_payload[..4].try_into().unwrap(),
                                ));
                            }
                        }
                        if let (Some(n), Some(i)) = (grp_name, grp_id) {
                            mcast_groups.insert(n, i);
                        }
                    }
                }
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-rolled GenlMessage impl exercising the trait shape +
    /// the runtime helpers. Stand-in for what the derive will
    /// generate in Phase 3b.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TinyMsg {
        id: u32,
        label: String,
    }

    const ATTR_ID: u16 = 1;
    const ATTR_LABEL: u16 = 2;

    impl GenlMessage for TinyMsg {
        const CMD: u8 = 7;

        fn to_bytes(&self, builder: &mut MessageBuilder) -> Result<()> {
            __rt::emit_u32_attr(builder, ATTR_ID, self.id);
            __rt::emit_str_attr(builder, ATTR_LABEL, &self.label);
            Ok(())
        }

        fn from_bytes(payload: &[u8]) -> Result<Self> {
            let mut id: u32 = 0;
            let mut label = String::new();
            for (ty, p) in __rt::attr_iter(payload) {
                match ty {
                    ATTR_ID => id = __rt::parse_u32_attr(p)?,
                    ATTR_LABEL => label = __rt::parse_str_attr(p)?,
                    _ => {}
                }
            }
            Ok(TinyMsg { id, label })
        }
    }

    #[test]
    fn hand_rolled_message_round_trips_via_runtime_helpers() {
        let original = TinyMsg {
            id: 0xDEADBEEF,
            label: "hello".to_string(),
        };

        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let bytes = builder.as_bytes();

        let parsed = TinyMsg::from_bytes(&bytes[body_start..]).expect("parse");
        assert_eq!(parsed, original);
    }

    /// A `uint` (`NLA_UINT`) comes as 4 bytes when it fits in 32 bits, and
    /// as 8 when it does not; a `u64` field reads both (#763).
    #[test]
    fn a_u64_field_reads_a_four_byte_uint() {
        assert_eq!(__rt::parse_u64_attr(&7u32.to_ne_bytes()).unwrap(), 7);
        assert_eq!(__rt::parse_u64_attr(&(1u64 << 40).to_ne_bytes()).unwrap(), 1 << 40);
    }

    #[test]
    fn parse_helpers_reject_truncated_payloads() {
        let short_u32: &[u8] = &[0, 1, 2];
        let err = __rt::parse_u32_attr(short_u32).unwrap_err();
        assert!(matches!(err.detail(), crate::netlink::ErrorDetail::Truncated { expected: 4, actual: 3 }));

        let short_u64: &[u8] = &[0, 0, 0, 0, 0, 0];
        let err = __rt::parse_u64_attr(short_u64).unwrap_err();
        assert!(matches!(err.detail(), crate::netlink::ErrorDetail::Truncated { expected: 8, actual: 6 }));

        let empty: &[u8] = &[];
        let err = __rt::parse_u8_attr(empty).unwrap_err();
        assert!(matches!(err.detail(), crate::netlink::ErrorDetail::Truncated { expected: 1, actual: 0 }));
    }

    #[test]
    fn parse_str_handles_nul_termination_and_invalid_utf8() {
        let s = __rt::parse_str_attr(b"hello\0").unwrap();
        assert_eq!(s, "hello");

        let s = __rt::parse_str_attr(b"abc").unwrap();
        assert_eq!(s, "abc");

        let s = __rt::parse_str_attr(b"\xFF\xFE\0").unwrap();
        assert!(!s.is_empty());
    }

    // -- Plan 226 sint helpers ---------------------------------

    #[test]
    fn plan_226_parse_sint_as_i64_handles_4_and_8_byte_payloads() {
        // 4-byte: sign-extends to i64.
        let four = (-1_i32).to_ne_bytes();
        assert_eq!(__rt::parse_sint_attr_as_i64(&four).unwrap(), -1);

        let four = i32::MIN.to_ne_bytes();
        assert_eq!(
            __rt::parse_sint_attr_as_i64(&four).unwrap(),
            i32::MIN as i64
        );

        let four = i32::MAX.to_ne_bytes();
        assert_eq!(
            __rt::parse_sint_attr_as_i64(&four).unwrap(),
            i32::MAX as i64
        );

        // 8-byte: parses as i64.
        let eight = (i32::MAX as i64 + 1).to_ne_bytes();
        assert_eq!(
            __rt::parse_sint_attr_as_i64(&eight).unwrap(),
            i32::MAX as i64 + 1
        );

        let eight = i64::MAX.to_ne_bytes();
        assert_eq!(__rt::parse_sint_attr_as_i64(&eight).unwrap(), i64::MAX);

        // Pathological lengths.
        for n in [0_usize, 1, 2, 3, 5, 6, 7] {
            let buf = vec![0u8; n];
            assert!(__rt::parse_sint_attr_as_i64(&buf).is_err(),
                "sint parser should reject {n}-byte payload");
        }

        // Larger-than-expected (>=8): accept prefix per CLAUDE.md
        // parser-robustness rule 1.
        let eleven = vec![0u8; 11];
        assert!(__rt::parse_sint_attr_as_i64(&eleven).is_ok());
    }

    #[test]
    fn plan_226_parse_sint_as_i32_handles_4_and_8_byte_in_range() {
        // 4-byte: exact i32.
        let four = (-42_i32).to_ne_bytes();
        assert_eq!(__rt::parse_sint_attr_as_i32(&four).unwrap(), -42);

        // 8-byte that fits: in-range cast.
        let eight = (1_000_000_i64).to_ne_bytes();
        assert_eq!(
            __rt::parse_sint_attr_as_i32(&eight).unwrap(),
            1_000_000_i32
        );

        // 8-byte that overflows i32: surfaces error rather than
        // silent truncation (the Plan 226 fix).
        let overflow = (i32::MAX as i64 + 1).to_ne_bytes();
        let err = __rt::parse_sint_attr_as_i32(&overflow).unwrap_err();
        assert!(
            matches!(err.detail(), crate::netlink::ErrorDetail::InvalidMessage(_)),
            "expected InvalidMessage for i32-overflow sint payload"
        );
    }

    #[test]
    fn plan_226_emit_sint_picks_minimum_width() {
        use crate::netlink::MessageBuilder;

        // In-range -> 4-byte attr (NLA hdr 4 + payload 4 = 8 bytes,
        // with NLA padding rounding to 4-byte boundary).
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        __rt::emit_sint_attr(&mut b, 99, 1_000_000_i64);
        let bytes = &b.as_bytes()[start..];
        // First u16 is the NLA length (header + payload, pre-padding).
        let len = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        assert_eq!(len, 8, "in-range sint should emit 4-byte payload");

        // Out-of-range -> 8-byte attr.
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        __rt::emit_sint_attr(&mut b, 99, i64::MAX);
        let bytes = &b.as_bytes()[start..];
        let len = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        assert_eq!(len, 12, "out-of-range sint should emit 8-byte payload");
    }

    #[test]
    fn plan_226_sint_round_trip_via_runtime_helpers() {
        use crate::netlink::MessageBuilder;

        for value in [
            0_i64,
            1,
            -1,
            i32::MAX as i64,
            i32::MIN as i64,
            i32::MAX as i64 + 1,
            i32::MIN as i64 - 1,
            i64::MAX,
            i64::MIN,
        ] {
            let mut b = MessageBuilder::new(0, 0);
            let start = b.len();
            __rt::emit_sint_attr(&mut b, 42, value);
            let bytes = &b.as_bytes()[start..];
            let mut found = None;
            for (ty, payload) in __rt::attr_iter(bytes) {
                if ty == 42 {
                    found = Some(
                        __rt::parse_sint_attr_as_i64(payload)
                            .expect("round-trip parse"),
                    );
                }
            }
            assert_eq!(
                found,
                Some(value),
                "round-trip failed for value {value}"
            );
        }
    }

    #[test]
    fn big_endian_helpers_round_trip_against_native_endian_layout() {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        __rt::emit_u32_be_attr(&mut b, 99, 0x1234_5678);
        let bytes = &b.as_bytes()[start..];

        let mut found = None;
        for (ty, payload) in __rt::attr_iter(bytes) {
            if ty == 99 {
                found = Some(__rt::parse_u32_be_attr(payload).unwrap());
            }
        }
        assert_eq!(found, Some(0x1234_5678));
    }

    // -- Phase 3b derive tests ---------------------------------
    //
    // The crate-root re-export `nlink_macros::GenlMessage` lives
    // in the macro namespace; the trait `GenlMessage` lives in
    // the type namespace. Both share the name without colliding.
    //
    // These tests use the derive (`#[derive(GenlMessage)]`)
    // against the trait + runtime helpers defined in this same
    // module — the proof that the macro expansion's
    // `::nlink::macros::__rt::*` path resolves correctly.

    use crate::macros::GenlMessage as GenlMessageDerive;
    // ^ Cargo doc-test's macro/trait dual-namespace works fine
    //   in normal test compilation; this alias is only here to
    //   make the derive macro's identity unambiguous if a future
    //   rustc warning forces one or the other.

    #[derive(GenlMessageDerive, Debug, Clone, PartialEq, Eq)]
    #[genl_message(cmd = 7u8)]
    struct DerivedSimple {
        #[genl_attr(1u16)]
        id: u32,
        #[genl_attr(2u16)]
        label: String,
    }

    #[test]
    fn derived_simple_round_trips() {
        let original = DerivedSimple {
            id: 0xCAFEBABE,
            label: "world".to_string(),
        };
        assert_eq!(DerivedSimple::CMD, 7);

        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let bytes = builder.as_bytes();

        let parsed = DerivedSimple::from_bytes(&bytes[body_start..]).expect("parse");
        assert_eq!(parsed, original);
    }

    #[derive(GenlMessageDerive, Debug, Clone, PartialEq, Eq)]
    #[genl_message(cmd = 9u8)]
    struct DerivedOptional {
        #[genl_attr(1u16)]
        id: u32,
        #[genl_attr(2u16)]
        description: Option<String>,
        #[genl_attr(3u16)]
        priority: Option<u16>,
    }

    #[test]
    fn derived_optional_omits_none_on_emit() {
        let with_none = DerivedOptional {
            id: 1,
            description: None,
            priority: None,
        };
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        with_none.to_bytes(&mut builder).expect("emit");
        let bytes = &builder.as_bytes()[body_start..];

        // Only the id attribute should be present.
        let mut attrs_seen: Vec<u16> = Vec::new();
        for (ty, _) in __rt::attr_iter(bytes) {
            attrs_seen.push(ty);
        }
        assert_eq!(attrs_seen, vec![1u16]);

        let parsed = DerivedOptional::from_bytes(bytes).expect("parse");
        assert_eq!(parsed, with_none);
    }

    #[test]
    fn derived_optional_round_trips_some() {
        let original = DerivedOptional {
            id: 42,
            description: Some("hello".to_string()),
            priority: Some(99),
        };
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let parsed = DerivedOptional::from_bytes(&builder.as_bytes()[body_start..])
            .expect("parse");
        assert_eq!(parsed, original);
    }

    // Verify the derive interoperates with the typed-enum
    // codec derives — the realistic shape downstream code uses.

    use crate::macros::{GenlAttribute, GenlCommand};

    #[derive(GenlCommand, Debug, Clone, Copy, PartialEq, Eq)]
    #[genl_command(repr = "u8")]
    enum TestCmd {
        Unspec = 0,
        Get = 2,
    }

    #[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
    #[genl_attribute(repr = "u16")]
    enum TestAttr {
        Id = 1,
        Name = 2,
    }

    #[derive(GenlMessageDerive, Debug, Clone, PartialEq, Eq)]
    #[genl_message(cmd = TestCmd::Get)]
    struct TypedGetReq {
        #[genl_attr(TestAttr::Id)]
        id: u32,
        #[genl_attr(TestAttr::Name)]
        name: String,
    }

    // ---- GenlEnum-typed field tests (Phase 8.2) ----------------

    use crate::macros::GenlEnum;

    #[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
    #[genl_enum(repr = "u32")]
    enum TestMode {
        Manual = 1,
        Automatic = 2,
    }

    #[derive(GenlMessageDerive, Debug, Default, Clone, PartialEq, Eq)]
    #[genl_message(cmd = 13u8)]
    struct DerivedEnumField {
        #[genl_attr(1u16)]
        id: u32,
        #[genl_attr(2u16, repr = "u32")]
        mode: Option<TestMode>,
    }

    #[test]
    fn derived_genl_enum_field_round_trips() {
        let original = DerivedEnumField {
            id: 7,
            mode: Some(TestMode::Automatic),
        };
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let parsed = DerivedEnumField::from_bytes(&builder.as_bytes()[body_start..])
            .expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn derived_genl_enum_missing_attr_yields_none() {
        // No attrs at all → mode defaults to None.
        let parsed = DerivedEnumField::from_bytes(&[]).expect("parse");
        assert_eq!(parsed.id, 0);
        assert_eq!(parsed.mode, None);
    }

    // ---- NetlinkAttrs nested-group tests (Phase 8.5) -----------

    use crate::macros::NetlinkAttrs as NetlinkAttrsDerive;

    #[derive(NetlinkAttrsDerive, Debug, Default, Clone, PartialEq, Eq)]
    struct DerivedNestedBlock {
        #[genl_attr(1u16)]
        device_id: u32,
        #[genl_attr(2u16)]
        label: String,
    }

    #[derive(GenlMessageDerive, Debug, Default, Clone, PartialEq, Eq)]
    #[genl_message(cmd = 17u8)]
    struct DerivedWithNested {
        #[genl_attr(1u16)]
        id: u32,
        #[genl_attr(2u16, nested)]
        parent: Option<DerivedNestedBlock>,
    }

    #[test]
    fn derived_nested_group_round_trips() {
        let original = DerivedWithNested {
            id: 100,
            parent: Some(DerivedNestedBlock {
                device_id: 0xDEAD_BEEF,
                label: "wg0".to_string(),
            }),
        };
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let parsed = DerivedWithNested::from_bytes(&builder.as_bytes()[body_start..])
            .expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn derived_nested_group_missing_attr_yields_none() {
        let parsed = DerivedWithNested::from_bytes(&[]).expect("parse");
        assert_eq!(parsed.id, 0);
        assert_eq!(parsed.parent, None);
    }

    #[test]
    fn nested_attrs_carry_nla_f_nested_flag_on_wire() {
        // The emitted attribute type should include 0x8000
        // (NLA_F_NESTED) on the wire. AttrIter strips it on read,
        // so to observe it we walk the raw bytes — find the second
        // attribute header and check its nla_type word directly.
        //
        // Per nlattr layout: each attribute is `[u16 len, u16 type,
        // payload..., padding]` aligned to 4 bytes.
        let original = DerivedWithNested {
            id: 1,
            parent: Some(DerivedNestedBlock {
                device_id: 7,
                label: String::new(),
            }),
        };
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let bytes = &builder.as_bytes()[body_start..];

        // First attr: u16 len + u16 type (=1, id, u32 payload).
        let first_len = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        let aligned_first = (first_len + 3) & !3;
        // Second attr header starts at aligned_first.
        let second_type =
            u16::from_ne_bytes([bytes[aligned_first + 2], bytes[aligned_first + 3]]);
        assert_eq!(
            second_type & 0x8000,
            0x8000,
            "NLA_F_NESTED flag missing on wire (got 0x{second_type:04x})"
        );
        assert_eq!(
            second_type & 0x7FFF,
            2,
            "wrong masked-off attr type (got 0x{second_type:04x})"
        );
    }

    #[derive(GenlMessageDerive, Debug, Default, Clone, PartialEq, Eq)]
    #[genl_message(cmd = 14u8)]
    struct DerivedRepeatedEnum {
        #[genl_attr(1u16)]
        id: u32,
        #[genl_attr(2u16, repr = "u32")]
        modes_supported: Vec<TestMode>,
    }

    // ---- Bitflags-newtype field tests (Phase 8.4) --------------

    bitflags::bitflags! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        struct TestCapabilities: u32 {
            const READ      = 0b0000_0001;
            const WRITE     = 0b0000_0010;
            const EXECUTE   = 0b0000_0100;
        }
    }

    #[derive(GenlMessageDerive, Debug, Clone, PartialEq, Eq)]
    #[genl_message(cmd = 15u8)]
    struct DerivedBitflagsField {
        #[genl_attr(1u16)]
        id: u32,
        #[genl_attr(2u16, bitflags = "u32")]
        caps: TestCapabilities,
    }

    #[test]
    fn derived_bitflags_field_round_trips_combined_bits() {
        let original = DerivedBitflagsField {
            id: 11,
            caps: TestCapabilities::READ | TestCapabilities::EXECUTE,
        };
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let parsed = DerivedBitflagsField::from_bytes(&builder.as_bytes()[body_start..])
            .expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn derived_bitflags_field_missing_attr_yields_empty_flags() {
        // No attrs at all → caps defaults to empty (from_bits_retain(0)).
        let parsed = DerivedBitflagsField::from_bytes(&[]).expect("parse");
        assert_eq!(parsed.id, 0);
        assert_eq!(parsed.caps, TestCapabilities::empty());
    }

    #[test]
    fn derived_bitflags_field_preserves_unknown_bits() {
        // Synthesize a frame where the kernel set a bit this binary
        // doesn't know about (0x80). from_bits_retain must keep it
        // so the next emit round-trips back unchanged.
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        __rt::emit_u32_attr(&mut builder, 2, 0x80 | TestCapabilities::READ.bits());
        let parsed = DerivedBitflagsField::from_bytes(&builder.as_bytes()[body_start..])
            .expect("parse");
        // The unknown 0x80 bit and the READ bit are both present.
        assert_eq!(parsed.caps.bits(), 0x80 | TestCapabilities::READ.bits());
        assert!(parsed.caps.contains(TestCapabilities::READ));
    }

    #[test]
    fn derived_repeated_enum_round_trips_multiple_elements() {
        // Realistic shape: kernel emits the same attribute type
        // once per element. Verify all elements arrive in order
        // on the parse side.
        let original = DerivedRepeatedEnum {
            id: 42,
            modes_supported: vec![TestMode::Manual, TestMode::Automatic],
        };
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let parsed =
            DerivedRepeatedEnum::from_bytes(&builder.as_bytes()[body_start..]).expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn derived_repeated_enum_empty_vec_emits_no_attrs() {
        // An empty Vec emits zero attrs of that type — the parse
        // side sees no matching attr, leaves the Vec at default.
        let original = DerivedRepeatedEnum {
            id: 1,
            modes_supported: Vec::new(),
        };
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let bytes = &builder.as_bytes()[body_start..];
        // Only the id attribute should be present.
        let mut attrs_seen: Vec<u16> = Vec::new();
        for (ty, _) in __rt::attr_iter(bytes) {
            attrs_seen.push(ty);
        }
        assert_eq!(attrs_seen, vec![1u16]);
        let parsed = DerivedRepeatedEnum::from_bytes(bytes).expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn derived_genl_enum_unknown_value_reads_as_absent() {
        // A value (=99) outside every TestMode variant: what a kernel
        // newer than the enum sends. It reads as an absent attribute,
        // and the rest of the message survives (#727).
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        __rt::emit_u32_attr(&mut builder, 1, 7);
        __rt::emit_u32_attr(&mut builder, 2, 99); // attr=2, value=99 (not a variant)
        let parsed = DerivedEnumField::from_bytes(&builder.as_bytes()[body_start..])
            .expect("an unknown enum value must not fail the message");
        assert_eq!(parsed.id, 7);
        assert_eq!(parsed.mode, None);
    }

    #[test]
    fn derived_repeated_enum_skips_an_unknown_element() {
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        __rt::emit_u32_attr(&mut builder, 1, 42);
        __rt::emit_u32_attr(&mut builder, 2, TestMode::Manual as u32);
        __rt::emit_u32_attr(&mut builder, 2, 99);
        __rt::emit_u32_attr(&mut builder, 2, TestMode::Automatic as u32);
        let parsed = DerivedRepeatedEnum::from_bytes(&builder.as_bytes()[body_start..])
            .expect("an unknown enum element must not fail the message");
        assert_eq!(parsed.id, 42);
        assert_eq!(parsed.modes_supported, vec![TestMode::Manual, TestMode::Automatic]);
    }

    #[test]
    fn typed_enums_compose_with_message_derive() {
        // CMD comes from TestCmd::Get (= 2) via `as u8`.
        assert_eq!(TypedGetReq::CMD, 2);

        let original = TypedGetReq {
            id: 7,
            name: "device-0".to_string(),
        };
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let parsed = TypedGetReq::from_bytes(&builder.as_bytes()[body_start..])
            .expect("parse");
        assert_eq!(parsed, original);
    }

    #[derive(GenlMessageDerive, Debug, Clone, PartialEq, Eq)]
    #[genl_message(cmd = 5u8)]
    struct DerivedBytes {
        #[genl_attr(1u16)]
        payload: Vec<u8>,
    }

    #[derive(GenlMessageDerive, Debug, Default, Clone, PartialEq, Eq)]
    #[genl_message(cmd = 11u8)]
    struct DerivedSigned {
        #[genl_attr(1u16)]
        temp_mdeg: i32,
        #[genl_attr(2u16)]
        delta: Option<i32>,
    }

    #[test]
    fn derived_i32_round_trips_positive_and_negative() {
        // Positive + Some(negative) — exercises the signed parse
        // path on both sides of zero.
        let original = DerivedSigned {
            temp_mdeg: 47_500,
            delta: Some(-12_345),
        };
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let parsed = DerivedSigned::from_bytes(&builder.as_bytes()[body_start..])
            .expect("parse");
        assert_eq!(parsed, original);

        // Default (zero) + None — the from_bytes-default-seed path.
        let parsed = DerivedSigned::from_bytes(&[]).expect("parse");
        assert_eq!(parsed.temp_mdeg, 0);
        assert_eq!(parsed.delta, None);
    }

    #[test]
    fn signed_int_runtime_helpers_round_trip_negatives() {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        __rt::emit_i32_attr(&mut b, 50, -98_765);
        let bytes = &b.as_bytes()[start..];
        let mut found = None;
        for (ty, payload) in __rt::attr_iter(bytes) {
            if ty == 50 {
                found = Some(__rt::parse_i32_attr(payload).unwrap());
            }
        }
        assert_eq!(found, Some(-98_765));
    }

    #[test]
    fn derived_vec_u8_round_trips() {
        let original = DerivedBytes {
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02],
        };
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        original.to_bytes(&mut builder).expect("emit");
        let parsed = DerivedBytes::from_bytes(&builder.as_bytes()[body_start..])
            .expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn derived_from_bytes_fills_defaults_for_missing_attrs() {
        // Empty payload — every field comes back as its default.
        let parsed = DerivedSimple::from_bytes(&[]).expect("parse");
        assert_eq!(parsed.id, 0);
        assert_eq!(parsed.label, "");
    }

    #[test]
    fn derived_from_bytes_skips_unknown_attrs() {
        // Emit a known attr (id=1) + an unknown attr (id=99).
        let mut builder = MessageBuilder::new(0, 0);
        let body_start = builder.len();
        __rt::emit_u32_attr(&mut builder, 1, 42);
        __rt::emit_u32_attr(&mut builder, 99, 0xDEAD_BEEF);
        let parsed =
            DerivedSimple::from_bytes(&builder.as_bytes()[body_start..]).expect("parse");
        // Only id is consumed; label stays default.
        assert_eq!(parsed.id, 42);
        assert_eq!(parsed.label, "");
    }

    // -- Phase 4: #[genl_family] attribute macro ---------------

    use crate::macros::genl_family;
    use crate::netlink::construction::AsyncConstructible;
    use crate::netlink::{AsyncProtocolInit, Protocol, ProtocolState};

    #[genl_family(name = "my_family", version = 1)]
    pub struct MyFamily;

    #[test]
    fn genl_family_macro_generates_constants() {
        assert_eq!(MyFamily::NAME, "my_family");
        assert_eq!(MyFamily::VERSION, 1);
    }

    #[test]
    fn genl_family_macro_default_constructs_with_zero_family_id() {
        let f = MyFamily::default();
        assert_eq!(f.family_id(), 0);
    }

    #[test]
    fn genl_family_macro_implements_protocol_state() {
        // Compile-time check: PROTOCOL is the Generic variant.
        const _: () = {
            assert!(matches!(MyFamily::PROTOCOL, Protocol::Generic));
        };
    }

    /// Helper that's only valid for types implementing
    /// AsyncConstructible — proves the macro adds the right
    /// sealed-trait impl. If `MyFamily` didn't get the impl,
    /// this generic function would fail to compile.
    fn assert_async_constructible<P: AsyncConstructible>() {}

    /// Same for the AsyncProtocolInit trait (the kernel-resolved
    /// family-ID setup that runs at Connection::new_async time).
    fn assert_async_protocol_init<P: AsyncProtocolInit>() {}

    #[test]
    fn genl_family_macro_satisfies_trait_bounds_required_by_connection() {
        // These calls only compile if MyFamily impls both
        // traits. They're the substantive contract of the macro:
        // any family defined via #[genl_family] plugs into
        // Connection::<F>::new_async() the same way the in-tree
        // hand-written families do.
        assert_async_constructible::<MyFamily>();
        assert_async_protocol_init::<MyFamily>();
    }

    #[test]
    fn genl_family_macro_provides_debug() {
        let f = MyFamily::default();
        let s = format!("{f:?}");
        assert!(s.contains("MyFamily"));
        assert!(s.contains("my_family"));
        assert!(s.contains("version"));
        assert!(s.contains("family_id"));
    }

    // Second family declaration to verify the macro is reusable
    // (a hand-written family + a macro-defined one can coexist).
    #[genl_family(name = "second_family", version = 2)]
    pub struct SecondFamily;

    #[test]
    fn two_macro_defined_families_coexist() {
        assert_eq!(SecondFamily::NAME, "second_family");
        assert_eq!(SecondFamily::VERSION, 2);
        assert_async_constructible::<SecondFamily>();
    }

    /// #496: the reply and the ACK are two datagrams. Resolution read the
    /// first and left the ACK queued for whatever used the socket next.
    #[tokio::test]
    async fn family_resolution_reads_through_its_ack() {
        use crate::netlink::{NetlinkSocket, Protocol, genl::GENL_ID_CTRL};
        let socket = NetlinkSocket::new(Protocol::Generic).expect("socket");
        let (id, groups) = __rt::resolve_genl_family_with_groups(&socket, "nlctrl")
            .await
            .expect("nlctrl is always there");
        assert_eq!(id, GENL_ID_CTRL);
        assert!(groups.contains_key("notify"), "{groups:?}");
        assert_eq!(
            socket.try_recv_msg().expect("recv"),
            None,
            "the ACK must not be left queued"
        );
        let err = __rt::resolve_genl_family(&socket, "no-such-family")
            .await
            .expect_err("unknown family");
        assert!(matches!(err.detail(), crate::netlink::ErrorDetail::NotFound { object: crate::ErrorObject::GenlFamily { .. } }), "{err}");
        assert_eq!(socket.try_recv_msg().expect("recv"), None);
    }
}
