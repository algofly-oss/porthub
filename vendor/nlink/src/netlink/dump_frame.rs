//! One classifier for every dump frame — #267, #271.
//!
//! The dump recv-loop is copy-pasted across seven files in three
//! shapes, and the copies disagree. The pattern is diagnostic: the two
//! *older* invariants — filter by `nlmsg_seq`, terminate on
//! `NLMSG_DONE` — are in every loop, and the two *newer* ones are in
//! some and not others.
//!
//! **`NLMSG_DONE` carries the dump's result code** as an `int` payload,
//! and nothing read it. A dump that failed partway reported success
//! with a truncated result set. Measured on this kernel:
//!
//! ```text
//! RTM_GETLINK           -> NLMSG_DONE nlmsg_len=20, payload i32 = 0
//! SOCK_DIAG_BY_FAMILY   -> NLMSG_DONE payload i32 = -2   (-ENOENT)
//! ```
//!
//! Not `NLMSG_ERROR` — `NLMSG_DONE`. The failure is reported *only*
//! there. `sockdiag.rs` turned that into `Ok(vec![])`: "no sockets
//! found", for a query the kernel refused. iproute2 reads it in
//! `rtnl_dump_done()` and aborts on a negative value.
//!
//! **`NLM_F_DUMP_INTR`** says the snapshot is torn — the dump
//! iterator's data structure was mutated mid-dump. The crate already
//! decided this matters (there is an `Error::dump_interrupted()` and tests
//! for it) and then checked it in four loops out of nine. The
//! unchecked ones include `dump_stream` (which feeds the `Store`
//! watch-cache) and the nftables dumps that `diff()` builds an
//! **atomic** apply from.
//!
//! Both bugs live in the same place, so both are fixed in the same
//! place. A `Classification` says what a frame is; the caller decides
//! what to do with the data, because the shapes callers want differ
//! (whole frames, payloads only, nfgenmsg-split, typed values with
//! post-filters) but the *termination rules* do not.

use super::{
    error::{Error, Result},
    message::{NlMsgError, NlMsgHdr},
};

/// What a single frame in a dump stream means.
#[derive(Debug)]
pub(crate) enum Classification<'a> {
    /// Not ours — a stale response from an earlier request on the same
    /// fd, or a multicast notification interleaved with the replies.
    /// Skip it and keep reading.
    SkipSeq,
    /// A zero-errno `NLMSG_ERROR`, i.e. an ACK.
    Ack,
    /// A real `NLMSG_ERROR`.
    Error(Error),
    /// `NLMSG_DONE`. The dump is over; the payload says whether it
    /// finished or gave up.
    Done(Result<()>),
    /// A data frame. `payload` is the message body after the header.
    Data { payload: &'a [u8] },
}

/// Classify one frame of a dump.
///
/// `expected_seq` is the sequence number this dump was sent with;
/// anything else is [`Classification::SkipSeq`].
pub(crate) fn classify<'a>(
    header: &NlMsgHdr,
    payload: &'a [u8],
    expected_seq: u32,
) -> Classification<'a> {
    // (1) Sequence filter, before anything else. The kernel may deliver
    //     stale responses from earlier requests on the same fd.
    if header.nlmsg_seq != expected_seq {
        return Classification::SkipSeq;
    }

    // (2) A torn snapshot is not usable, whatever else the frame says.
    //     The kernel sets NLM_F_DUMP_INTR on whichever frame was
    //     generated after the mutation.
    if header.is_dump_interrupted() {
        return Classification::Error(Error::dump_interrupted());
    }

    if header.is_error() {
        return match NlMsgError::from_bytes(payload) {
            Ok(err) if err.is_ack() => {
                err.warn_if_ack_warns(header.nlmsg_flags, payload);
                Classification::Ack
            }
            Ok(err) => Classification::Error(err.to_error(header.nlmsg_flags, payload)),
            Err(e) => Classification::Error(e),
        };
    }

    if header.is_done() {
        return Classification::Done(done_result(payload));
    }

    Classification::Data { payload }
}

/// Does this frame end the dump sent with `seq` — its `NLMSG_DONE`, or an
/// error that ends it?
///
/// For reading an interrupted dump to its end (#494): once
/// [`classify`] has said [`Error::dump_interrupted()`], the frames that follow
/// are skipped up to this one, whatever flags they carry (the `DONE` itself
/// can carry `NLM_F_DUMP_INTR`).
pub(crate) fn ends_dump(header: &NlMsgHdr, seq: u32) -> bool {
    header.nlmsg_seq == seq && (header.is_done() || header.is_error())
}

/// Read the result code out of an `NLMSG_DONE` payload.
///
/// Tolerates both shapes the kernel sends. `netlink_dump()` appends a
/// 4-byte `int` after the header, but a dump that ends without one —
/// `nlmsg_len == 16`, which `MessageIter` yields as an empty payload —
/// is a plain success. A short-but-nonempty payload is treated the same
/// way rather than as a parse error: refusing a dump the kernel
/// considers finished would be worse than the bug being fixed.
pub(crate) fn done_result(payload: &[u8]) -> Result<()> {
    let Ok(bytes) = payload.get(..4).map(<[u8; 4]>::try_from).transpose() else {
        return Ok(());
    };
    match bytes {
        None => Ok(()),
        Some(b) => {
            let code = i32::from_ne_bytes(b);
            if code < 0 {
                // Same shape as any other kernel error, so the `is_X()`
                // predicates work on it: a dump refused with -ENOENT is
                // `is_not_found()`, not a special case.
                Err(Error::from_errno_ext_ack(code, None, None))
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::message::{NLM_F_DUMP_INTR, NlMsgType};

    fn hdr(nlmsg_type: u16, seq: u32, flags: u16) -> NlMsgHdr {
        NlMsgHdr {
            nlmsg_len: 16,
            nlmsg_type,
            nlmsg_flags: flags,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        }
    }

    /// An interrupted dump is read to its `DONE` — flagged or not — or to
    /// an error with its seq; a data frame or another dump's `DONE` does
    /// not end it (#494).
    #[test]
    fn ends_dump_is_this_dumps_done_or_error() {
        let done = NlMsgType::DONE;
        let error = NlMsgType::ERROR;
        assert!(ends_dump(&hdr(done, 7, 0), 7));
        assert!(ends_dump(&hdr(done, 7, NLM_F_DUMP_INTR), 7));
        assert!(ends_dump(&hdr(error, 7, 0), 7));
        assert!(!ends_dump(&hdr(done, 8, 0), 7));
        assert!(!ends_dump(&hdr(16, 7, NLM_F_DUMP_INTR), 7));
    }

    #[test]
    fn a_frame_from_another_request_is_skipped() {
        let h = hdr(NlMsgType::DONE, 7, 0);
        assert!(matches!(
            classify(&h, &[], 9),
            Classification::SkipSeq
        ));
    }

    #[test]
    fn done_with_a_zero_payload_is_success() {
        // `RTM_GETLINK` on this kernel: nlmsg_len=20, payload 00000000.
        let h = hdr(NlMsgType::DONE, 1, 0);
        match classify(&h, &0i32.to_ne_bytes(), 1) {
            Classification::Done(Ok(())) => {}
            other => panic!("expected Done(Ok), got {other:?}"),
        }
    }

    #[test]
    fn done_with_an_empty_payload_is_success() {
        // A dump that ends with nlmsg_len == 16 carries no result code.
        let h = hdr(NlMsgType::DONE, 1, 0);
        match classify(&h, &[], 1) {
            Classification::Done(Ok(())) => {}
            other => panic!("expected Done(Ok), got {other:?}"),
        }
    }

    #[test]
    fn done_with_a_negative_payload_is_the_dumps_failure() {
        // `SOCK_DIAG_BY_FAMILY` with no diag handler: DONE, payload -2.
        // This became `Ok(vec![])` — "no sockets found" — for a query
        // the kernel refused (#267).
        let h = hdr(NlMsgType::DONE, 1, 0);
        match classify(&h, &(-2i32).to_ne_bytes(), 1) {
            Classification::Done(Err(e)) => {
                assert!(e.is_not_found(), "expected ENOENT, got {e:?}");
            }
            other => panic!("expected Done(Err), got {other:?}"),
        }
    }

    #[test]
    fn a_positive_done_payload_is_not_an_error() {
        // Only a negative code is a failure; `netlink_dump` can leave a
        // non-negative byte count there.
        let h = hdr(NlMsgType::DONE, 1, 0);
        match classify(&h, &17i32.to_ne_bytes(), 1) {
            Classification::Done(Ok(())) => {}
            other => panic!("expected Done(Ok), got {other:?}"),
        }
    }

    #[test]
    fn a_torn_snapshot_is_an_error_whatever_else_the_frame_is() {
        for ty in [NlMsgType::DONE, NlMsgType::ERROR, 16 /* RTM_NEWLINK */] {
            let h = hdr(ty, 1, NLM_F_DUMP_INTR);
            match classify(&h, &[], 1) {
                Classification::Error(e) => assert!(e.is_dump_interrupted()),
                other => panic!("type {ty}: expected Error, got {other:?}"),
            }
        }
    }

    #[test]
    fn dump_intr_on_a_frame_we_are_not_reading_is_still_skipped() {
        // The seq filter comes first: another request's torn dump is
        // not this dump's problem.
        let h = hdr(16, 7, NLM_F_DUMP_INTR);
        assert!(matches!(classify(&h, &[], 9), Classification::SkipSeq));
    }

    #[test]
    fn a_zero_errno_error_frame_is_an_ack() {
        let h = hdr(NlMsgType::ERROR, 1, 0);
        let mut payload = 0i32.to_ne_bytes().to_vec();
        payload.extend_from_slice(hdr(16, 1, 0).as_bytes());
        assert!(matches!(
            classify(&h, &payload, 1),
            Classification::Ack
        ));
    }

    #[test]
    fn a_nonzero_errno_error_frame_is_an_error() {
        let h = hdr(NlMsgType::ERROR, 1, 0);
        let mut payload = (-22i32).to_ne_bytes().to_vec();
        payload.extend_from_slice(hdr(16, 1, 0).as_bytes());
        match classify(&h, &payload, 1) {
            Classification::Error(e) => assert!(e.is_invalid_argument()),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn anything_else_is_data() {
        let h = hdr(16, 1, 0);
        match classify(&h, &[1, 2, 3, 4], 1) {
            Classification::Data { payload } => assert_eq!(payload, &[1, 2, 3, 4]),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn done_result_never_panics_on_a_short_payload() {
        // Rule 2 of the parser-robustness policy: a truncated payload
        // must not index out of bounds.
        for n in 0..4 {
            assert!(done_result(&vec![0xff; n]).is_ok());
        }
    }
}
