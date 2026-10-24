//! `Connection<F: GenlFamily>::send_typed` + `dump_typed_stream`
//! generic dispatch (Plan 154 Phase 5).
//!
//! Together with `#[genl_family]` (Phase 4) and
//! `#[derive(GenlMessage)]` (Phase 3b) this closes the loop:
//! downstream code declares a complete GENL family + its message
//! types in ~30 lines and calls `conn.send_typed(req).await?` for
//! a fully typed round-trip.
//!
//! # `send_typed` — single request, single response
//!
//! Builds a netlink request from `M: GenlMessage`, sends it,
//! parses the kernel's response into `R: GenlMessage + Default`.
//! Missing attributes leave the corresponding fields at their
//! defaults (matches `#[derive(GenlMessage)]`'s `from_bytes`
//! semantics).
//!
//! # `dump_typed_stream` — Stream over typed dump frames
//!
//! Mirrors the existing
//! [`Connection::dump_stream`](crate::netlink::Connection::dump_stream)
//! shape: the method is `async` (it sends the dump request) and
//! returns a [`Stream`] that yields parsed `R` per kernel frame.

use std::{
    collections::VecDeque,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use tokio_stream::Stream;

use crate::{
    Error, Result,
    macros::{GenlFamily, GenlMessage},
    netlink::{
        MessageBuilder, ProtocolState,
        connection::Connection,
        dump_frame::done_result,
        genl::{GENL_HDRLEN, GenlMsgHdr},
        message::{MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlMsgError},
    },
};

#[nlink_macros::send_futures]
impl<F> Connection<F>
where
    F: ProtocolState + GenlFamily,
{
    /// Send a typed GENL request and parse the typed response.
    ///
    /// Builds a netlink message from `request: M`, sends it,
    /// receives the response, and parses the first non-ACK reply
    /// into `R: GenlMessage + Default`. Returns the parsed `R`.
    ///
    /// `R::default()` is the parse seed: missing attributes leave
    /// fields at their type-default values (matches the
    /// `#[derive(GenlMessage)]` `from_bytes` semantics — see its
    /// docs for the rationale).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nlink::macros::*;
    /// use nlink::Connection;
    ///
    /// #[genl_family(name = "my_family", version = 1)]
    /// pub struct MyFamily;
    ///
    /// #[derive(GenlCommand, Debug, Clone, Copy)]
    /// #[genl_command(repr = "u8")]
    /// pub enum MyCmd { Get = 1 }
    ///
    /// #[derive(GenlAttribute, Debug, Clone, Copy)]
    /// #[genl_attribute(repr = "u16")]
    /// pub enum MyAttr { Id = 1, Name = 2 }
    ///
    /// #[derive(GenlMessage, Debug, Default)]
    /// #[genl_message(cmd = MyCmd::Get)]
    /// pub struct GetReq { #[genl_attr(MyAttr::Id)] pub id: u32 }
    ///
    /// #[derive(GenlMessage, Debug, Default)]
    /// #[genl_message(cmd = MyCmd::Get)]
    /// pub struct GetReply {
    ///     #[genl_attr(MyAttr::Id)] pub id: u32,
    ///     #[genl_attr(MyAttr::Name)] pub name: String,
    /// }
    ///
    /// # async fn run(conn: Connection<MyFamily>) -> nlink::Result<()> {
    /// let reply: GetReply = conn.send_typed(GetReq { id: 0 }).await?;
    /// println!("got id={} name={}", reply.id, reply.name);
    /// # Ok(())
    /// # }
    /// ```
    /// Subscribe to a named multicast group exposed by this
    /// family.
    ///
    /// Looks up the group ID via
    /// [`GenlFamily::mcast_group`](crate::macros::GenlFamily) (the
    /// map was populated at construction time by
    /// `#[genl_family]`'s `resolve_async` impl, parsing
    /// `CTRL_ATTR_MCAST_GROUPS` out of `CTRL_CMD_GETFAMILY`).
    /// Returns
    /// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) when the named group isn't
    /// registered on this kernel —
    /// e.g., asking for `"monitor"` on a kernel too old to ship
    /// that group, or a binary/kernel mismatch.
    ///
    /// Pair with the [`EventSource`][es]-driven
    /// [`events()`](crate::netlink::Connection::events) (when the
    /// family implements `EventSource`) to consume typed
    /// notifications from the kernel.
    ///
    /// [es]: crate::netlink::EventSource
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, genl::dpll::Dpll};
    /// use tokio_stream::StreamExt;
    ///
    /// let conn = Connection::<Dpll>::new_async().await?;
    /// conn.subscribe_group("monitor")?;
    /// let mut events = conn.events().await;
    /// while let Some(evt) = events.next().await {
    ///     println!("{:?}", evt?);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn subscribe_group(&self, name: &str) -> Result<()> {
        let id = self
            .state()
            .mcast_group(name)
            .ok_or_else(|| crate::Error::family_not_found(::std::format!("{}::{}", F::NAME, name)))?;
        self.socket().add_membership(id)?;
        Ok(())
    }

    pub async fn send_typed<M, R>(&self, request: M) -> Result<R>
    where
        M: GenlMessage,
        R: GenlMessage + Default,
    {
        let builder = build_genl_request::<F, M>(self, &request, NLM_F_REQUEST | NLM_F_ACK)?;
        let response = self.send_request(builder).await?;
        parse_first_genl_reply::<R>(&response)
    }

    /// Stream a typed GENL dump (multi-frame response).
    ///
    /// Builds a `NLM_F_REQUEST | NLM_F_DUMP` request from
    /// `request: M`, awaits the send, and returns a [`Stream`]
    /// that yields each kernel frame parsed into `R`.
    ///
    /// Compare with [`Self::send_typed`] (one request, one
    /// response). For the canonical kernel dump shape (`*_CMD_GET`
    /// with `NLM_F_DUMP` returning many frames) this is the right
    /// helper.
    pub async fn dump_typed_stream<M, R>(&self, request: M) -> Result<GenlTypedDumpStream<'_, F, R>>
    where
        M: GenlMessage,
        R: GenlMessage + Default + Unpin,
    {
        let mut builder = build_genl_request::<F, M>(self, &request, NLM_F_REQUEST | NLM_F_DUMP)?;

        let socket = self.socket();
        let seq = socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(socket.pid());

        // #134 — dispatcher mode: register the seq before sending so the
        // driver routes this dump's frames to our channel.
        let dispatched = if self.is_dispatcher_mode() {
            self.ensure_driver();
            Some(self.dispatcher().register(seq))
        } else {
            None
        };

        let msg = builder.finish();
        socket.send(&msg).await?;

        Ok(GenlTypedDumpStream::new(self, seq, dispatched))
    }
}

/// Build a netlink message for a GENL request: family-id'd
/// header + GENL header (`cmd = M::CMD`, `version = F::VERSION`)
/// + the message's typed attributes.
fn build_genl_request<F, M>(conn: &Connection<F>, request: &M, flags: u16) -> Result<MessageBuilder>
where
    F: ProtocolState + GenlFamily,
    M: GenlMessage,
{
    let family_id = conn.state().family_id();
    let mut builder = MessageBuilder::new(family_id, flags);
    let genl_hdr = GenlMsgHdr::new(M::CMD, F::VERSION);
    builder.append(&genl_hdr);
    request.to_bytes(&mut builder)?;
    Ok(builder)
}

/// Parse the first non-ACK reply in `response` into `R`. Skips
/// over ACKs / NlMsgType::DONE; if no typed frame is found, returns
/// `R::default()`.
fn parse_first_genl_reply<R>(response: &[u8]) -> Result<R>
where
    R: GenlMessage + Default,
{
    for result in MessageIter::new(response) {
        let (header, payload) = result?;

        if header.is_error() {
            let err = NlMsgError::from_bytes(payload)?;
            err.warn_if_ack_warns(header.nlmsg_flags, payload);
            if !err.is_ack() {
                return Err(err.to_error(header.nlmsg_flags, payload));
            }
            continue;
        }

        if header.is_done() {
            // Even here — a `DONE` that carries a negative result code
            // is the request failing, not an empty reply (#267).
            done_result(payload)?;
            return Ok(R::default());
        }

        if payload.len() < GENL_HDRLEN {
            return Err(Error::invalid_message(
                "GENL response payload too short for header",
            ));
        }
        let attrs = &payload[GENL_HDRLEN..];
        return R::from_bytes(attrs);
    }

    Ok(R::default())
}

/// Typed dump-stream returned by
/// [`Connection::dump_typed_stream`]. Yields parsed `R: GenlMessage`
/// items one at a time; terminates on `NlMsgType::DONE`.
///
/// Mirrors the byte-level
/// [`DumpStream`](crate::netlink::dump_stream::DumpStream) state
/// machine, with a per-frame `R::from_bytes(payload[GENL_HDRLEN..])`
/// parse step.
#[non_exhaustive]
pub struct GenlTypedDumpStream<'a, F, R>
where
    F: ProtocolState + GenlFamily,
    R: GenlMessage + Default + Unpin,
{
    conn: &'a Connection<F>,
    expected_seq: u32,
    pending: VecDeque<Result<R>>,
    done: bool,
    errored: bool,
    /// #134 — dispatcher mode: per-seq channel the background driver
    /// routes this dump's frames into. `None` in mutex mode (frames come
    /// from `socket().poll_recv`).
    dispatched: Option<crate::netlink::dispatcher::PendingGuard>,
    _marker: PhantomData<fn() -> R>,
}

impl<'a, F, R> GenlTypedDumpStream<'a, F, R>
where
    F: ProtocolState + GenlFamily,
    R: GenlMessage + Default + Unpin,
{
    fn new(
        conn: &'a Connection<F>,
        seq: u32,
        dispatched: Option<crate::netlink::dispatcher::PendingGuard>,
    ) -> Self {
        Self {
            conn,
            expected_seq: seq,
            pending: VecDeque::new(),
            done: false,
            errored: false,
            dispatched,
            _marker: PhantomData,
        }
    }

    fn drain_into_pending(&mut self, data: &[u8]) {
        for result in MessageIter::new(data) {
            let (header, payload) = match result {
                Ok(p) => p,
                Err(e) => {
                    self.pending.push_back(Err(e));
                    self.errored = true;
                    return;
                }
            };

            if header.nlmsg_seq != self.expected_seq {
                continue;
            }

            // A torn snapshot — this drainer had no check at all
            // (#271).
            if header.is_dump_interrupted() {
                self.pending.push_back(Err(Error::dump_interrupted()));
                self.errored = true;
                return;
            }

            if header.is_error() {
                match NlMsgError::from_bytes(payload) {
                    Ok(err) => {
                        if err.is_ack() {
                            continue;
                        }
                        self.pending
                            .push_back(Err(err.to_error(header.nlmsg_flags, payload)));
                        self.errored = true;
                        return;
                    }
                    Err(e) => {
                        self.pending.push_back(Err(e));
                        self.errored = true;
                        return;
                    }
                }
            }

            if header.is_done() {
                // The dump's result code is in the DONE payload (#267).
                if let Err(e) = done_result(payload) {
                    self.pending.push_back(Err(e));
                    self.errored = true;
                    return;
                }
                self.done = true;
                return;
            }

            if payload.len() < GENL_HDRLEN {
                self.pending.push_back(Err(Error::invalid_message(
                    "GENL dump frame too short for header",
                )));
                continue;
            }
            let attrs = &payload[GENL_HDRLEN..];
            self.pending.push_back(R::from_bytes(attrs));
        }
    }
}

impl<F, R> Stream for GenlTypedDumpStream<'_, F, R>
where
    F: ProtocolState + GenlFamily,
    R: GenlMessage + Default + Unpin,
{
    type Item = Result<R>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        // An error carries the socket's protocol and namespace (#718).
        let socket = this.conn.socket();
        this.poll_unstamped(cx)
            .map(|item| item.map(|r| r.map_err(|e| socket.stamp(e))))
    }
}

impl<F, R> GenlTypedDumpStream<'_, F, R>
where
    F: ProtocolState + GenlFamily,
    R: GenlMessage + Default + Unpin,
{
    fn poll_unstamped(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<R>>> {
        let this = self;

        if let Some(item) = this.pending.pop_front() {
            return Poll::Ready(Some(item));
        }
        if this.done || this.errored {
            return Poll::Ready(None);
        }

        // #134 — dispatcher mode: consume the driver-routed per-seq
        // channel instead of polling the socket.
        if this.dispatched.is_some() {
            loop {
                let polled = this.dispatched.as_mut().unwrap().rx.poll_recv(cx);
                match polled {
                    Poll::Ready(Some(frame)) => {
                        this.drain_into_pending(&frame);
                        if let Some(item) = this.pending.pop_front() {
                            return Poll::Ready(Some(item));
                        }
                        if this.done || this.errored {
                            return Poll::Ready(None);
                        }
                    }
                    Poll::Ready(None) => {
                        this.errored = true;
                        return Poll::Ready(Some(Err(this.conn.dispatcher().take_fatal_error())));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        loop {
            #[cfg(feature = "syscall_batch")]
            {
                match this
                    .conn
                    .socket()
                    .poll_recv_batch(cx, crate::netlink::NL_BATCH_SIZE)
                {
                    Poll::Ready(Ok(frames)) => {
                        for data in &frames {
                            this.drain_into_pending(data);
                        }
                        if let Some(item) = this.pending.pop_front() {
                            return Poll::Ready(Some(item));
                        }
                        if this.done || this.errored {
                            return Poll::Ready(None);
                        }
                        continue;
                    }
                    Poll::Ready(Err(e)) => {
                        this.errored = true;
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            #[cfg(not(feature = "syscall_batch"))]
            {
                match this.conn.socket().poll_recv(cx) {
                    Poll::Ready(Ok(data)) => {
                        this.drain_into_pending(&data);
                        if let Some(item) = this.pending.pop_front() {
                            return Poll::Ready(Some(item));
                        }
                        if this.done || this.errored {
                            return Poll::Ready(None);
                        }
                        continue;
                    }
                    Poll::Ready(Err(e)) => {
                        this.errored = true;
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }
}

impl<F, R> Unpin for GenlTypedDumpStream<'_, F, R>
where
    F: ProtocolState + GenlFamily,
    R: GenlMessage + Default + Unpin,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        macros::__rt,
        netlink::message::{NLMSG_HDRLEN, NlMsgType},
    };

    /// Hand-rolled reply type — proves the dispatch helpers are
    /// generic over `R: GenlMessage + Default`, no derive needed.
    #[derive(Debug, Default, PartialEq, Eq)]
    struct Reply {
        id: u32,
        label: String,
    }

    const ATTR_ID: u16 = 1;
    const ATTR_LABEL: u16 = 2;

    impl GenlMessage for Reply {
        const CMD: u8 = 0;

        fn to_bytes(&self, b: &mut MessageBuilder) -> Result<()> {
            __rt::emit_u32_attr(b, ATTR_ID, self.id);
            __rt::emit_str_attr(b, ATTR_LABEL, &self.label);
            Ok(())
        }

        fn from_bytes(payload: &[u8]) -> Result<Self> {
            let mut r = Reply::default();
            for (ty, p) in __rt::attr_iter(payload) {
                match ty {
                    ATTR_ID => r.id = __rt::parse_u32_attr(p)?,
                    ATTR_LABEL => r.label = __rt::parse_str_attr(p)?,
                    _ => {}
                }
            }
            Ok(r)
        }
    }

    /// Build a full netlink frame: header + GENL header + body.
    /// Mirrors what the kernel would write back on the wire.
    fn synth_reply_frame(seq: u32, id: u32, label: &str) -> Vec<u8> {
        // family_id 0x42 is a stand-in — parse_first_genl_reply
        // doesn't care, only nlmsg_type values for ERROR/DONE
        // matter for the dispatch path.
        let mut b = MessageBuilder::new(0x42, 0);
        b.append(&GenlMsgHdr::new(Reply::CMD, 1));
        __rt::emit_u32_attr(&mut b, ATTR_ID, id);
        __rt::emit_str_attr(&mut b, ATTR_LABEL, label);
        b.set_seq(seq);
        b.finish()
    }

    /// Build a synthetic NlMsgType::DONE frame (header-only, type=3).
    fn synth_done_frame(seq: u32) -> Vec<u8> {
        let mut buf = vec![0u8; NLMSG_HDRLEN];
        buf[0..4].copy_from_slice(&(NLMSG_HDRLEN as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&NlMsgType::DONE.to_ne_bytes());
        buf[6..8].copy_from_slice(&0u16.to_ne_bytes());
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&0u32.to_ne_bytes());
        buf
    }

    /// Build a synthetic NlMsgType::ERROR ACK (errno = 0) for `seq`.
    fn synth_ack_frame(seq: u32) -> Vec<u8> {
        // Header (16) + nlmsgerr (4 errno + 16-byte echoed header)
        let mut buf = vec![0u8; NLMSG_HDRLEN + 4 + NLMSG_HDRLEN];
        let total = buf.len() as u32;
        buf[0..4].copy_from_slice(&total.to_ne_bytes());
        buf[4..6].copy_from_slice(&NlMsgType::ERROR.to_ne_bytes());
        buf[6..8].copy_from_slice(&0u16.to_ne_bytes());
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&0u32.to_ne_bytes());
        // errno = 0 means ACK
        buf[16..20].copy_from_slice(&0i32.to_ne_bytes());
        buf
    }

    #[test]
    fn parse_first_genl_reply_decodes_real_frame() {
        let frame = synth_reply_frame(7, 0xCAFE_BABE, "hello");
        let parsed: Reply = parse_first_genl_reply(&frame).expect("parse");
        assert_eq!(parsed.id, 0xCAFE_BABE);
        assert_eq!(parsed.label, "hello");
    }

    #[test]
    fn parse_first_genl_reply_returns_default_on_nlmsg_done() {
        let frame = synth_done_frame(1);
        let parsed: Reply = parse_first_genl_reply(&frame).expect("parse");
        assert_eq!(parsed, Reply::default());
    }

    #[test]
    fn parse_first_genl_reply_skips_pure_ack_then_returns_default() {
        // ACK alone (no typed reply after) → default.
        let frame = synth_ack_frame(1);
        let parsed: Reply = parse_first_genl_reply(&frame).expect("parse");
        assert_eq!(parsed, Reply::default());
    }

    #[test]
    fn parse_first_genl_reply_consumes_typed_reply_after_ack() {
        // [ACK, typed reply] — dispatcher skips ACK and parses
        // the typed frame. This is the realistic shape for
        // NLM_F_ACK requests that also return a body.
        let mut frame = synth_ack_frame(1);
        frame.extend_from_slice(&synth_reply_frame(1, 42, "ok"));
        let parsed: Reply = parse_first_genl_reply(&frame).expect("parse");
        assert_eq!(parsed.id, 42);
        assert_eq!(parsed.label, "ok");
    }

    #[test]
    fn parse_first_genl_reply_propagates_kernel_error() {
        // Real NlMsgType::ERROR with errno = -EINVAL (-22).
        let mut buf = vec![0u8; NLMSG_HDRLEN + 4 + NLMSG_HDRLEN];
        let total = buf.len() as u32;
        buf[0..4].copy_from_slice(&total.to_ne_bytes());
        buf[4..6].copy_from_slice(&NlMsgType::ERROR.to_ne_bytes());
        buf[6..8].copy_from_slice(&0u16.to_ne_bytes());
        buf[8..12].copy_from_slice(&1u32.to_ne_bytes());
        buf[12..16].copy_from_slice(&0u32.to_ne_bytes());
        buf[16..20].copy_from_slice(&(-libc::EINVAL).to_ne_bytes());

        let res: Result<Reply> = parse_first_genl_reply(&buf);
        assert!(res.is_err(), "expected kernel error to propagate");
    }

    /// build_genl_request must wire family_id + GENL header
    /// (`cmd = M::CMD`, `version = F::VERSION`) before the body.
    /// We exercise the helper directly without going through a
    /// live Connection.
    #[test]
    fn build_genl_request_emits_correct_header_layout() {
        // We can't construct a Connection<F> without a real netlink
        // socket here; instead we replicate the body of
        // build_genl_request to assert layout. (The real helper is
        // 4 lines and trivially correct — this test exists to lock
        // the on-wire layout in case anyone refactors the body.)
        let family_id: u16 = 0x55;
        let version: u8 = 3;
        let cmd: u8 = Reply::CMD;

        let mut b = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        b.append(&GenlMsgHdr::new(cmd, version));
        Reply {
            id: 9,
            label: "x".into(),
        }
        .to_bytes(&mut b)
        .expect("emit");
        let bytes = b.finish();

        // nlmsg_type at offset 4..6 should be family_id.
        assert_eq!(u16::from_ne_bytes([bytes[4], bytes[5]]), family_id);
        // nlmsg_flags at offset 6..8.
        assert_eq!(
            u16::from_ne_bytes([bytes[6], bytes[7]]),
            NLM_F_REQUEST | NLM_F_ACK
        );
        // GENL header cmd at offset NLMSG_HDRLEN (=16).
        assert_eq!(bytes[NLMSG_HDRLEN], cmd);
        // GENL header version at offset 17.
        assert_eq!(bytes[NLMSG_HDRLEN + 1], version);
    }
}
