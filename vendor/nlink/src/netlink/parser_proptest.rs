//! Property-based parser-robustness harnesses (Plan 193 phase 2-3,
//! #137).
//!
//! These feed **arbitrary bytes** to the protocol-stack parsers and
//! assert the invariants from CLAUDE.md `## Parser robustness` hold —
//! no panics, bounded termination (no infinite loop), and the Plan 193
//! rule-2 exhaustion contract. They complement the hand-written
//! adversarial unit tests: a property test explores the input space the
//! audit scripts and example-driven tests can't enumerate.
//!
//! Dev-only (`proptest` is a dev-dependency); runs under
//! `cargo test -p nlink --lib`, no root required.
//!
//! Invariants pinned here:
//! 1. `MessageIter` / `AttrIter` never panic on any byte slice.
//! 2. They always terminate, yielding at most one item per minimum
//!    header's worth of input (catches the infinite-loop bug class —
//!    netlink-packet-route #152, the real 0.19 MessageIter bug).
//! 3. Rule 2: once `MessageIter` yields an `Err`, it is exhausted (the
//!    next `next()` returns `None`) so a malformed frame can't re-emit
//!    forever and stall a long-lived subscriber.
//! 4. The fixed-size struct parsers and the `get::*` typed extractors
//!    return `Result`/`Option` on arbitrary bytes — never panic
//!    (no out-of-bounds slice, no unwrap).

use proptest::prelude::*;

use super::{
    attr::{AttrIter, NlAttr, get},
    message::{MessageIter, NLMSG_HDRLEN, NlMsgHdr},
    messages::{
        AddressMessage, LinkMessage, NeighborMessage, RouteMessage, RuleMessage, TcMessage,
    },
    parse::FromNetlink,
};

/// Upper bound on items a correct iterator can yield for `len` bytes:
/// every yielded item consumes at least one aligned minimum-header
/// (>= 4 bytes) or exhausts the iterator, so `len + 2` is a generous
/// cap that a correct impl always finishes strictly under. If the
/// iterator looped forever, `.take(cap)` would still terminate the test
/// at exactly `cap`, and the assertion `count < cap` would fail.
fn loop_cap(len: usize) -> usize {
    len + 2
}

proptest! {
    /// `MessageIter` never panics and always terminates on arbitrary
    /// bytes (invariants 1 + 2).
    #[test]
    fn message_iter_terminates_without_panic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let cap = loop_cap(data.len());
        let count = MessageIter::new(&data).take(cap).count();
        prop_assert!(count < cap, "MessageIter did not terminate within bound (possible infinite loop)");
    }

    /// Plan 193 rule 2: once `MessageIter` yields an `Err`, it must be
    /// exhausted — the next poll returns `None` (invariant 3).
    #[test]
    fn message_iter_exhausts_after_error(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let cap = loop_cap(data.len());
        let mut it = MessageIter::new(&data);
        let mut polled = 0;
        let mut saw_err = false;
        // `while let` (not `for`) on purpose: we keep `it` by-ref to poll
        // it again *after* the loop and assert it stays exhausted.
        #[allow(clippy::while_let_on_iterator)]
        while let Some(item) = it.next() {
            polled += 1;
            prop_assert!(polled <= cap, "iterator exceeded the termination bound");
            if item.is_err() {
                saw_err = true;
                break;
            }
        }
        if saw_err {
            prop_assert!(
                it.next().is_none(),
                "MessageIter must be exhausted after yielding an error (Plan 193 rule 2)"
            );
        }
    }

    /// `AttrIter` never panics and always terminates on arbitrary bytes.
    #[test]
    fn attr_iter_terminates_without_panic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let cap = loop_cap(data.len());
        let count = AttrIter::new(&data).take(cap).count();
        prop_assert!(count < cap, "AttrIter did not terminate within bound (possible infinite loop)");
    }

    /// Walk arbitrary bytes as a full netlink message stream, then walk
    /// each message payload as an attribute chain, then run every typed
    /// extractor over each attribute payload. The whole nested walk must
    /// complete without panicking (invariants 1 + 4 combined — the real
    /// kernel-response parse path).
    #[test]
    fn nested_message_attr_walk_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let mut messages = 0;
        for item in MessageIter::new(&data).take(loop_cap(data.len())) {
            messages += 1;
            prop_assert!(messages <= loop_cap(data.len()));
            let Ok((_hdr, payload)) = item else { break };
            let mut attrs = 0;
            for (_kind, attr_payload) in AttrIter::new(payload).take(loop_cap(payload.len())) {
                attrs += 1;
                prop_assert!(attrs <= loop_cap(payload.len()));
                // Every typed extractor must tolerate arbitrary payloads.
                let _ = get::u8(attr_payload);
                let _ = get::u16_ne(attr_payload);
                let _ = get::u32_ne(attr_payload);
                let _ = get::u64_ne(attr_payload);
                let _ = get::i32_ne(attr_payload);
                let _ = get::string(attr_payload);
                let _ = get::bytes(attr_payload);
            }
        }
    }

    /// The fixed-size struct parsers return `Result` on any input —
    /// never panic, never slice out of bounds (invariant 4).
    #[test]
    fn struct_from_bytes_never_panics(data in proptest::collection::vec(any::<u8>(), 0..128)) {
        let _ = NlMsgHdr::from_bytes(&data);
        let _ = NlAttr::from_bytes(&data);
    }

    /// Plan 193 rule 1 (accept-larger-than-expected): a byte slice at
    /// least header-sized parses; trailing bytes are ignored, never
    /// rejected. `NlMsgHdr::from_bytes` reads the fixed prefix.
    #[test]
    fn nlmsghdr_accepts_oversized_input(extra in proptest::collection::vec(any::<u8>(), 0..64)) {
        let mut buf = vec![0u8; NLMSG_HDRLEN];
        // A well-formed minimal header: nlmsg_len = NLMSG_HDRLEN.
        buf[0..4].copy_from_slice(&(NLMSG_HDRLEN as u32).to_ne_bytes());
        buf.extend_from_slice(&extra);
        prop_assert!(
            NlMsgHdr::from_bytes(&buf).is_ok(),
            "header-sized-or-larger input must parse (Plan 193 rule 1: accept trailing bytes)"
        );
    }

    /// The typed RTNetlink message parsers (`FromNetlink::from_bytes`) —
    /// the real kernel-response attack surface — must return `Result` on
    /// arbitrary bytes, never panic. Each walks a fixed-size struct
    /// prefix plus an attribute chain, so this exercises rules 1 + 2 at
    /// the typed layer over the same input.
    #[test]
    fn typed_message_parsers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = LinkMessage::from_bytes(&data);
        let _ = RouteMessage::from_bytes(&data);
        let _ = AddressMessage::from_bytes(&data);
        let _ = NeighborMessage::from_bytes(&data);
        let _ = RuleMessage::from_bytes(&data);
        let _ = TcMessage::from_bytes(&data);
    }
}

// =============================================================================
// #279 — the rest of the kernel-facing parsers
// =============================================================================
//
// The harness above fuzzed the shared walkers and six typed RTNetlink
// parsers. The crate has roughly 377 parse functions, and the ones that
// were not covered are the least-exercised code in it: nftables
// `RuleExpr` decoding (the newest and most intricate), sockdiag, xfrm,
// conntrack, uevent, connector, and every `parse_events` — the
// multicast entry points, where one malformed frame from a future
// kernel would take the whole consumer down.
//
// The yield is not expected to come from the walkers. `AttrIter` has
// the rule-2 guards and is already fuzzed. It comes from what a parser
// does *after* `AttrIter` hands it a payload: fixed-size struct reads,
// enum conversions, nested re-walks, arithmetic on attribute values.

use super::{
    EventSource,
    netfilter::ConntrackEntry,
    nftables::{RuleInfo, expr::parse_expressions},
    protocol::{KobjectUevent, Netfilter, Route, Xfrm},
    xfrm::{SecurityAssociation, SecurityPolicy},
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The typed parsers for the non-RTNetlink protocols. Each walks a
    /// fixed-size header plus an attribute chain, like the six above,
    /// but none of them was covered.
    #[test]
    fn non_rtnetlink_typed_parsers_never_panic(
        data in proptest::collection::vec(any::<u8>(), 0..1024)
    ) {
        let _ = ConntrackEntry::from_bytes(&data);
        let _ = SecurityAssociation::from_bytes(&data);
        let _ = SecurityPolicy::from_bytes(&data);
        let _ = RuleInfo::from_bytes(&data);
    }

    /// nftables expression decoding — the newest and most intricate
    /// parser in the crate. It re-walks nested attribute lists and
    /// interprets register numbers and lengths from the payload, which
    /// is exactly the shape the walker guards do not protect.
    #[test]
    fn nftables_expression_decoding_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..2048)
    ) {
        let exprs = parse_expressions(&data);
        // Bounded: one expression cannot come from fewer than a nested
        // attribute header's worth of bytes.
        prop_assert!(exprs.len() <= loop_cap(data.len()));
    }

    /// `EventSource::parse_events` — the multicast entry points. The
    /// parser-robustness policy is explicit that one malformed frame
    /// must not kill a long-lived subscriber, and these are where that
    /// is decided.
    #[test]
    fn event_parsers_never_panic(
        data in proptest::collection::vec(any::<u8>(), 0..2048)
    ) {
        let _ = <Route as EventSource>::parse_events(&data);
        let _ = <Xfrm as EventSource>::parse_events(&data);
        let _ = <Netfilter as EventSource>::parse_events(&data);
        let _ = <KobjectUevent as EventSource>::parse_events(&data);
    }

    /// A uevent is *text*, not TLVs — NUL-separated `KEY=VALUE` after an
    /// `"<action>@<devpath>"` prefix — so it has a different failure
    /// surface from everything else here: index arithmetic on separator
    /// positions rather than length fields.
    #[test]
    fn uevent_parsing_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..512)
    ) {
        let _ = super::uevent::Uevent::parse(&data);
    }

    /// Arbitrary bytes are the *unlikely* input for a text parser; a
    /// uevent-shaped one with adversarial separators is the likely one.
    #[test]
    fn uevent_parsing_never_panics_on_uevent_shaped_input(
        action in "[a-z@=\u{0}]{0,16}",
        devpath in "[a-z/@=\u{0}]{0,32}",
        rest in proptest::collection::vec("[A-Z=\u{0}]{0,12}", 0..8),
    ) {
        let mut buf = Vec::new();
        buf.extend_from_slice(action.as_bytes());
        buf.push(b'@');
        buf.extend_from_slice(devpath.as_bytes());
        buf.push(0);
        for kv in &rest {
            buf.extend_from_slice(kv.as_bytes());
            buf.push(0);
        }
        let _ = super::uevent::Uevent::parse(&buf);
    }
}

// -----------------------------------------------------------------------
// Structurally valid input with adversarial values
// -----------------------------------------------------------------------
//
// Arbitrary bytes almost never look like a well-formed netlink message,
// so the walkers reject them early and the parser code *after*
// `AttrIter` is barely reached — which is exactly where #279 predicts
// the yield. These generators build chains the walkers accept and then
// make the attribute ids, lengths and payloads adversarial.

/// A well-formed `nlattr` chain: each entry has a correct `nla_len`,
/// an arbitrary type, an arbitrary payload, and correct 4-byte
/// alignment padding. This is what the parsers actually see.
fn valid_attr_chain() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(
        (any::<u16>(), proptest::collection::vec(any::<u8>(), 0..40)),
        0..24,
    )
    .prop_map(|attrs| {
        let mut buf = Vec::new();
        for (ty, payload) in attrs {
            let len = (4 + payload.len()) as u16;
            buf.extend_from_slice(&len.to_ne_bytes());
            buf.extend_from_slice(&ty.to_ne_bytes());
            buf.extend_from_slice(&payload);
            while buf.len() % 4 != 0 {
                buf.push(0);
            }
        }
        buf
    })
}

/// A fixed-size header of `hdr_len` arbitrary bytes followed by a valid
/// attribute chain — the shape of every RTNetlink and nfnetlink
/// message body.
fn header_plus_attrs(hdr_len: usize) -> impl Strategy<Value = Vec<u8>> {
    (
        proptest::collection::vec(any::<u8>(), hdr_len..=hdr_len),
        valid_attr_chain(),
    )
        .prop_map(|(hdr, attrs)| {
            let mut buf = hdr;
            buf.extend_from_slice(&attrs);
            buf
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Every typed parser, over input the attribute walker accepts.
    ///
    /// The header bytes are arbitrary, so enum conversions and family
    /// dispatch see values the kernel would never send; the attribute
    /// ids are arbitrary, so every `match attr_type` arm is reachable;
    /// and the payloads are arbitrary-length, so every fixed-size read
    /// behind an id gets a payload of the wrong size.
    #[test]
    fn typed_parsers_survive_well_formed_but_hostile_input(
        // 16 covers ifinfomsg/ifaddrmsg/rtmsg/ndmsg/tcmsg/nfgenmsg and
        // then some; a longer header just means more of the chain is
        // read as header, which is itself worth exercising.
        body in header_plus_attrs(16),
    ) {
        let _ = LinkMessage::from_bytes(&body);
        let _ = RouteMessage::from_bytes(&body);
        let _ = AddressMessage::from_bytes(&body);
        let _ = NeighborMessage::from_bytes(&body);
        let _ = RuleMessage::from_bytes(&body);
        let _ = TcMessage::from_bytes(&body);
        let _ = ConntrackEntry::from_bytes(&body);
        let _ = SecurityAssociation::from_bytes(&body);
        let _ = SecurityPolicy::from_bytes(&body);
        let _ = RuleInfo::from_bytes(&body);
    }

    /// The same for expression decoding, where the payload of each
    /// attribute is itself a nested chain the parser re-walks.
    #[test]
    fn expression_decoding_survives_nested_hostile_input(
        outer in valid_attr_chain(),
    ) {
        // One level of real nesting: wrap the chain in an attribute so
        // the decoder's inner walk is exercised, not just the outer.
        let mut nested = Vec::new();
        let len = (4 + outer.len()) as u16;
        nested.extend_from_slice(&len.to_ne_bytes());
        nested.extend_from_slice(&(1u16 | 0x8000).to_ne_bytes()); // NLA_F_NESTED
        nested.extend_from_slice(&outer);
        while nested.len() % 4 != 0 {
            nested.push(0);
        }
        let exprs = parse_expressions(&nested);
        prop_assert!(exprs.len() <= loop_cap(nested.len()));
    }

    /// And the multicast entry points, over a whole well-formed netlink
    /// message rather than a bare body — `parse_events` walks
    /// `MessageIter` first.
    #[test]
    fn event_parsers_survive_well_formed_messages(
        msg_type in any::<u16>(),
        flags in any::<u16>(),
        body in header_plus_attrs(16),
    ) {
        let total = NLMSG_HDRLEN + body.len();
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&(total as u32).to_ne_bytes());
        frame.extend_from_slice(&msg_type.to_ne_bytes());
        frame.extend_from_slice(&flags.to_ne_bytes());
        frame.extend_from_slice(&0u32.to_ne_bytes()); // seq
        frame.extend_from_slice(&0u32.to_ne_bytes()); // pid
        frame.extend_from_slice(&body);

        let _ = <Route as EventSource>::parse_events(&frame);
        let _ = <Xfrm as EventSource>::parse_events(&frame);
        let _ = <Netfilter as EventSource>::parse_events(&frame);
        let _ = <KobjectUevent as EventSource>::parse_events(&frame);
    }
}
