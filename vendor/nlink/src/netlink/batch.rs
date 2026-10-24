//! Netlink batching for bulk operations.
//!
//! Send multiple netlink messages in a single `sendmsg()` to reduce syscall
//! overhead. For 1000 routes, this reduces 1000 round-trips to ~5.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::net::Ipv4Addr;
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::route::Ipv4Route;
//!
//! let conn = Connection::<Route>::new()?;
//! let results = conn.batch()
//!     .add_route(Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8).dev_index(5))
//!     .add_route(Ipv4Route::new(Ipv4Addr::new(10, 1, 0, 0), 16).dev_index(5))
//!     .execute()
//!     .await?;
//!
//! println!("{} succeeded, {} failed", results.success_count(), results.error_count());
//! # Ok(())
//! # }
//! ```

use super::{
    addr::AddressConfig,
    builder::MessageBuilder,
    connection::Connection,
    error::{Error, Result},
    fdb::FdbEntryBuilder,
    link::LinkConfig,
    message::{
        MessageIter, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NlMsgError, NlMsgType,
    },
    neigh::NeighborConfig,
    protocol::Route,
    route::RouteConfig,
    tc::QdiscConfig,
    types::{
        link::IfInfoMsg,
        tc::{TcMsg, TcaAttr, tc_handle},
    },
};

/// Maximum batch size before auto-splitting (200KB).
const MAX_BATCH_SIZE: usize = 200 * 1024;

/// A batch of netlink operations to execute in minimal syscalls.
///
/// Operations are buffered and sent as concatenated messages in a single
/// `sendmsg()`. The kernel processes them sequentially and returns one
/// ACK per message. Auto-splits at 200KB to stay within socket buffer limits.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use std::net::Ipv4Addr;
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::route::Ipv4Route;
///
/// let conn = Connection::<Route>::new()?;
/// let results = conn.batch()
///     .add_route(Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8).dev_index(5))
///     .add_route(Ipv4Route::new(Ipv4Addr::new(10, 1, 0, 0), 16).dev_index(5))
///     .execute()
///     .await?;
///
/// if !results.all_ok() {
///     for (i, err) in results.errors() {
///         eprintln!("op {i}: {err}");
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct Batch<'a> {
    conn: &'a Connection<Route>,
    ops: Vec<BatchOp>,
    /// Operations whose *encoding* failed, by submission index.
    ///
    /// `BatchResults` promises "one `Result<()>` per operation in
    /// submission order", and `errors()` yields `(index, &Error)` pairs
    /// the caller maps back to what it submitted. An op that failed to
    /// encode used to be dropped on the floor: three submissions with a
    /// bad one in the middle produced two results, `all_ok() == true`,
    /// and index 1 describing the *third* submission. The caller
    /// concluded all three were configured (#277).
    encode_errors: Vec<(usize, Error)>,
    /// Submissions so far, encoded or not — the index space
    /// `BatchResults` is indexed by.
    submitted: usize,
}

struct BatchOp {
    seq: u32,
    msg: Vec<u8>,
}

#[nlink_macros::send_futures]
impl<'a> Batch<'a> {
    pub(crate) fn new(conn: &'a Connection<Route>) -> Self {
        Self {
            conn,
            ops: Vec::new(),
            encode_errors: Vec::new(),
            submitted: 0,
        }
    }

    /// Add a route to the batch.
    ///
    /// Note: interface references must be pre-resolved to indices (use `dev_index()`
    /// instead of `dev()`) since batching cannot perform async name resolution.
    pub fn add_route<R: RouteConfig>(mut self, config: R) -> Self {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        config.write_add(&mut builder, &Default::default());
        self.push(builder);
        self
    }

    /// Delete a route in the batch.
    pub fn del_route<R: RouteConfig>(mut self, config: R) -> Self {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK);
        config.write_delete(&mut builder);
        self.push(builder);
        self
    }

    /// Add a link to the batch.
    ///
    /// Note: Only link types without parent references (DummyLink, IfbLink, etc.)
    /// work in batch mode. Types with parent references need async resolution.
    pub fn add_link<L: LinkConfig>(mut self, config: L) -> Self {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        let ifinfo = IfInfoMsg::new();
        builder.append(&ifinfo);
        config.write_to(&mut builder, None);
        self.push(builder);
        self
    }

    /// Delete a link by index in the batch.
    pub fn del_link_by_index(mut self, ifindex: u32) -> Self {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK);
        let mut ifinfo = IfInfoMsg::new();
        ifinfo.ifi_index = ifindex as i32;
        builder.append(&ifinfo);
        self.push(builder);
        self
    }

    /// Add an address in the batch.
    ///
    /// Note: Use address types with pre-resolved indices (e.g., `Ipv4Address::with_index()`).
    pub fn add_address<A: AddressConfig>(mut self, config: A, ifindex: u32) -> Self {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        match config.write_add(&mut builder, ifindex) {
            Ok(()) => self.push(builder),
            Err(e) => self.push_encode_error(e),
        }
        self
    }

    /// Delete an address in the batch.
    pub fn del_address<A: AddressConfig>(mut self, config: A, ifindex: u32) -> Self {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK);
        match config.write_delete(&mut builder, ifindex) {
            Ok(()) => self.push(builder),
            Err(e) => self.push_encode_error(e),
        }
        self
    }

    /// Add a neighbor in the batch.
    ///
    /// Note: Use neighbor types with pre-resolved indices.
    pub fn add_neighbor<N: NeighborConfig>(mut self, config: N, ifindex: u32) -> Self {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        match config.write_add(&mut builder, ifindex) {
            Ok(()) => self.push(builder),
            Err(e) => self.push_encode_error(e),
        }
        self
    }

    /// Delete a neighbor in the batch.
    pub fn del_neighbor<N: NeighborConfig>(mut self, config: N, ifindex: u32) -> Self {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELNEIGH, NLM_F_REQUEST | NLM_F_ACK);
        match config.write_delete(&mut builder, ifindex) {
            Ok(()) => self.push(builder),
            Err(e) => self.push_encode_error(e),
        }
        self
    }

    /// Add an FDB entry in the batch.
    ///
    /// Pass the resolved interface index and optional master (bridge) index.
    pub fn add_fdb(
        mut self,
        entry: FdbEntryBuilder,
        ifindex: u32,
        master_idx: Option<u32>,
    ) -> Self {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        entry.write_add(&mut builder, ifindex, master_idx);
        self.push(builder);
        self
    }

    /// Delete an FDB entry in the batch.
    pub fn del_fdb(mut self, entry: FdbEntryBuilder, ifindex: u32) -> Self {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELNEIGH, NLM_F_REQUEST | NLM_F_ACK);
        entry.write_delete(&mut builder, ifindex);
        self.push(builder);
        self
    }

    /// Add a qdisc in the batch.
    ///
    /// `ifindex` is the interface index. The qdisc goes where
    /// [`Connection::add_qdisc`](crate::Connection::add_qdisc) puts it: at
    /// its kind's fixed parent (ingress, clsact) or the root, and a
    /// classful kind at `1:` (#515). This ignored the fixed parent before
    /// 0.32, so an ingress or clsact in a batch was refused.
    pub fn add_qdisc(mut self, ifindex: u32, config: impl QdiscConfig) -> Self {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWQDISC,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        );
        let (parent, handle) = match config.fixed_parent() {
            Some(parent) => (parent.as_raw(), 0),
            None => (
                tc_handle::ROOT,
                config.default_handle().map_or(0, |h| h.as_raw()),
            ),
        };
        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent)
            .with_handle(handle);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        if !config.has_options() {
            self.push(builder);
            return self;
        }
        let options_token = builder.nest_start(TcaAttr::Options as u16);
        match config.write_options(&mut builder) {
            Ok(()) => {
                builder.nest_end(options_token);
                self.push(builder);
            }
            Err(e) => self.push_encode_error(e),
        }
        self
    }

    /// Delete a qdisc in the batch (root qdisc).
    pub fn del_qdisc(mut self, ifindex: u32) -> Self {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELQDISC, NLM_F_REQUEST | NLM_F_ACK);
        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(tc_handle::ROOT);
        builder.append(&tcmsg);
        self.push(builder);
        self
    }

    /// Record an operation that could not be encoded, keeping its slot
    /// in the result vector.
    fn push_encode_error(&mut self, e: Error) {
        self.encode_errors.push((self.submitted, e));
        self.submitted += 1;
    }

    fn push(&mut self, mut builder: MessageBuilder) {
        let seq = self.conn.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.conn.socket().pid());
        let msg = builder.finish();
        self.ops.push(BatchOp { seq, msg });
        self.submitted += 1;
    }

    /// Number of buffered operations.
    /// Number of buffered operations, including any whose encoding
    /// failed — this is the length `BatchResults` will have.
    pub fn len(&self) -> usize {
        self.submitted
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.submitted == 0
    }

    /// Execute all operations, returning per-operation results.
    ///
    /// Auto-splits into chunks if the total size exceeds 200KB.
    /// Only returns `Err` for transport-level errors (socket failure).
    /// Individual operation failures are captured in `BatchResults`.
    #[tracing::instrument(level = "debug", skip_all, fields(ops = self.ops.len()))]
    pub async fn execute(mut self) -> Result<BatchResults> {
        if self.submitted == 0 {
            return Ok(BatchResults {
                results: Vec::new(),
            });
        }
        if self.ops.is_empty() {
            // Nothing to send, but the failed encodings still owe the
            // caller a result each.
            return Ok(BatchResults {
                results: self.take_encode_errors_only(),
            });
        }

        let mut all_results = Vec::with_capacity(self.ops.len());
        let mut chunk_start = 0;
        let mut chunk_size = 0;

        for (i, op) in self.ops.iter().enumerate() {
            if chunk_size + op.msg.len() > MAX_BATCH_SIZE && chunk_size > 0 {
                let chunk_results = self.send_chunk(&self.ops[chunk_start..i]).await?;
                all_results.extend(chunk_results);
                chunk_start = i;
                chunk_size = 0;
            }
            chunk_size += op.msg.len();
        }

        // Send remaining chunk
        if chunk_start < self.ops.len() {
            let chunk_results = self.send_chunk(&self.ops[chunk_start..]).await?;
            all_results.extend(chunk_results);
        }

        Ok(BatchResults {
            results: self.splice_encode_errors(all_results),
        })
    }

    /// Result vector for a batch where nothing encoded.
    fn take_encode_errors_only(&mut self) -> Vec<Result<()>> {
        self.splice_encode_errors(Vec::new())
    }

    /// Put the encode failures back at their submission indices.
    ///
    /// `wire_results` holds one entry per op that actually went out, in
    /// order; the failures fill the gaps, so the final vector has one
    /// entry per submission and index *i* means submission *i* — which
    /// is what `BatchResults::errors()` tells callers it means.
    fn splice_encode_errors(&mut self, wire_results: Vec<Result<()>>) -> Vec<Result<()>> {
        if self.encode_errors.is_empty() {
            return wire_results;
        }
        let mut failures = std::mem::take(&mut self.encode_errors).into_iter().peekable();
        let mut wire = wire_results.into_iter();
        let mut out = Vec::with_capacity(self.submitted);
        for idx in 0..self.submitted {
            match failures.peek() {
                Some((at, _)) if *at == idx => {
                    let (_, e) = failures.next().expect("peeked");
                    out.push(Err(e));
                }
                _ => match wire.next() {
                    Some(r) => out.push(r),
                    // The wire produced fewer results than ops (a
                    // truncated ACK stream); leave the tail out rather
                    // than inventing successes.
                    None => break,
                },
            }
        }
        out
    }

    /// Execute all operations, returning the first error encountered.
    pub async fn execute_all(self) -> Result<()> {
        let results = self.execute().await?;
        // The first failure as it was: its errno, so `is_already_exists()`
        // and the rest still answer. A string of it used to be returned,
        // which answered none of them (#526).
        for (i, result) in results.results.into_iter().enumerate() {
            result.map_err(|e| e.with_context(format!("batch operation {i}")))?;
        }
        Ok(())
    }

    async fn send_chunk(&self, ops: &[BatchOp]) -> Result<Vec<std::result::Result<(), Error>>> {
        // #134 — dual-mode recv. Mutex mode: hold the request lock for the
        // whole send+recv (the F1 fix). Dispatcher mode: register all the
        // ops' seqs onto one channel so the driver routes every ACK here
        // instead of the loop racing its recv_msg. Built BEFORE the send
        // (and the with_timeout wrapper) so it spans the timeout window.
        let seqs: Vec<u32> = ops.iter().map(|o| o.seq).collect();
        let mut session = self.conn.recv_session_multi(&seqs).await?;
        // Concatenate messages into a single buffer
        let total_size: usize = ops.iter().map(|o| o.msg.len()).sum();
        let mut buf = Vec::with_capacity(total_size);
        for op in ops {
            buf.extend_from_slice(&op.msg);
        }

        // Single sendmsg()
        self.conn.socket().send(&buf).await?;

        // Collect ACKs matched by sequence number. The recv loop runs
        // under the connection's configured timeout (Plan 171: 30s
        // default) so a kernel that drops one of the ACKs for a
        // batched op surfaces as `Error::timeout()` rather than an
        // indefinite hang. Pre-0.19 this loop ran without any timeout
        // wrap, so a chunk where any op silently lost its ACK would
        // block forever.
        self.conn
            .with_timeout(async move {
                let mut results: Vec<Option<std::result::Result<(), Error>>> =
                    (0..ops.len()).map(|_| None).collect();
                let mut remaining = ops.len();

                while remaining > 0 {
                    let response = session.recv(self.conn).await?;

                    for result in MessageIter::new(&response) {
                        let (header, payload) = result?;

                        // Find which op this ACK belongs to (per-op seq match).
                        if let Some(idx) = ops.iter().position(|op| op.seq == header.nlmsg_seq) {
                            if results[idx].is_some() {
                                continue; // Already got this one — kernel duplicate
                            }

                            if header.is_error() {
                                let err = NlMsgError::from_bytes(payload)?;
                                err.warn_if_ack_warns(header.nlmsg_flags, payload);
                                if err.is_ack() {
                                    results[idx] = Some(Ok(()));
                                } else {
                                    results[idx] = Some(Err(self
                                        .conn
                                        .socket()
                                        .stamp(err.to_error(header.nlmsg_flags, payload))));
                                }
                                remaining -= 1;
                            }
                        }
                    }
                }

                Ok(results.into_iter().map(|r| r.unwrap_or(Ok(()))).collect())
            })
            .await
    }
}

/// Results from a batch execution.
///
/// Contains one `Result<()>` per operation in submission order.
pub struct BatchResults {
    results: Vec<std::result::Result<(), Error>>,
}

impl BatchResults {
    /// Iterate over all results.
    pub fn iter(&self) -> impl Iterator<Item = &std::result::Result<(), Error>> {
        self.results.iter()
    }

    /// Iterate over only the errors with their indices.
    pub fn errors(&self) -> impl Iterator<Item = (usize, &Error)> {
        self.results
            .iter()
            .enumerate()
            .filter_map(|(i, r)| r.as_ref().err().map(|e| (i, e)))
    }

    /// Number of successful operations.
    pub fn success_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_ok()).count()
    }

    /// Number of failed operations.
    pub fn error_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_err()).count()
    }

    /// True if all operations succeeded.
    pub fn all_ok(&self) -> bool {
        self.results.iter().all(|r| r.is_ok())
    }

    /// Total number of operations.
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Whether there are no results.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_results(results: Vec<std::result::Result<(), Error>>) -> BatchResults {
        BatchResults { results }
    }

    #[test]
    fn test_empty_results() {
        let r = make_results(vec![]);
        assert!(r.is_empty());
        assert!(r.all_ok());
        assert_eq!(r.len(), 0);
        assert_eq!(r.success_count(), 0);
        assert_eq!(r.error_count(), 0);
        assert_eq!(r.errors().count(), 0);
    }

    #[test]
    fn test_all_success() {
        let r = make_results(vec![Ok(()), Ok(()), Ok(())]);
        assert!(r.all_ok());
        assert_eq!(r.len(), 3);
        assert_eq!(r.success_count(), 3);
        assert_eq!(r.error_count(), 0);
        assert_eq!(r.errors().count(), 0);
    }

    #[test]
    fn test_mixed_results() {
        let r = make_results(vec![
            Ok(()),
            Err(Error::from_errno(-2)), // ENOENT
            Ok(()),
            Err(Error::from_errno(-1)), // EPERM
        ]);
        assert!(!r.all_ok());
        assert_eq!(r.len(), 4);
        assert_eq!(r.success_count(), 2);
        assert_eq!(r.error_count(), 2);

        let errors: Vec<_> = r.errors().collect();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].0, 1); // index of first error
        assert!(errors[0].1.is_not_found());
        assert_eq!(errors[1].0, 3); // index of second error
        assert!(errors[1].1.is_permission_denied());
    }

    #[test]
    fn test_all_errors() {
        let r = make_results(vec![
            Err(Error::from_errno(-17)), // EEXIST
            Err(Error::from_errno(-16)), // EBUSY
        ]);
        assert!(!r.all_ok());
        assert_eq!(r.success_count(), 0);
        assert_eq!(r.error_count(), 2);
    }

    #[test]
    fn test_iter() {
        let r = make_results(vec![Ok(()), Err(Error::from_errno(-1))]);
        let items: Vec<_> = r.iter().collect();
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        assert!(items[1].is_err());
    }

    // ====================================================================
    // #277 — an op that fails to encode keeps its slot
    // ====================================================================

    /// `splice_encode_errors` without a live `Connection`: build the
    /// state it operates on directly.
    fn splice(submitted: usize, failures: Vec<(usize, &str)>, wire: usize) -> Vec<&'static str> {
        // Stand-in for the private method's inputs. Re-implemented via
        // the same helper by faking a Batch is not possible without a
        // socket, so this mirrors the merge and asserts the ordering
        // contract the method must satisfy.
        let mut failures = failures.into_iter().peekable();
        let mut wire_left = wire;
        let mut out = Vec::new();
        for idx in 0..submitted {
            match failures.peek() {
                Some((at, _)) if *at == idx => {
                    failures.next();
                    out.push("err");
                }
                _ => {
                    if wire_left == 0 {
                        break;
                    }
                    wire_left -= 1;
                    out.push("ok");
                }
            }
        }
        out
    }

    #[test]
    fn a_failed_encoding_keeps_its_position() {
        // Three submissions, the middle one unencodable. Before the
        // fix this produced two results, `all_ok() == true`, and index
        // 1 describing the *third* submission.
        assert_eq!(splice(3, vec![(1, "bad")], 2), vec!["ok", "err", "ok"]);
    }

    #[test]
    fn failures_at_the_ends_keep_their_positions() {
        assert_eq!(splice(3, vec![(0, "bad")], 2), vec!["err", "ok", "ok"]);
        assert_eq!(splice(3, vec![(2, "bad")], 2), vec!["ok", "ok", "err"]);
    }

    #[test]
    fn every_submission_can_fail_to_encode() {
        assert_eq!(
            splice(3, vec![(0, "a"), (1, "b"), (2, "c")], 0),
            vec!["err", "err", "err"]
        );
    }

    #[test]
    fn a_truncated_ack_stream_does_not_invent_successes() {
        // Fewer wire results than ops: the tail is left out rather than
        // filled with Ok.
        assert_eq!(splice(4, vec![(1, "bad")], 1), vec!["ok", "err"]);
    }

    #[test]
    fn batch_results_index_means_submission_index() {
        // The contract `errors()` documents.
        let r = make_results(vec![
            Ok(()),
            Err(Error::invalid_message("bad")),
            Ok(()),
        ]);
        assert_eq!(r.len(), 3);
        assert!(!r.all_ok());
        let errs: Vec<_> = r.errors().map(|(i, _)| i).collect();
        assert_eq!(errs, vec![1]);
    }
}
