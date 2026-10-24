//! High-level netlink connection with request/response handling.

use std::{path::Path, time::Duration};

use tracing::{instrument, warn};

use super::{
    builder::MessageBuilder,
    dispatcher::Dispatcher,
    dump_frame::{Classification, classify, ends_dump},
    error::{Error, Result},
    interface_ref::InterfaceRef,
    message::{
        MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_HDRLEN, NlMsgError, NlMsgHdr,
        NlMsgType, nlmsg_align,
    },
    parse::FromNetlink,
    protocol::{ProtocolState, Route},
    socket::NetlinkSocket,
    tc_handle::TcHandle,
};
use crate::util::AddressFamily;

/// High-level netlink connection parameterized by protocol state.
///
/// The type parameter `P` determines which protocol this connection uses
/// and which methods are available:
///
/// - [`Connection<Route>`]: RTNetlink for interfaces, addresses, routes, TC
/// - [`Connection<Generic>`]: Generic netlink for WireGuard, MACsec, etc.
///
/// # Construction
///
/// **Sync protocols** — use [`Connection::new()`]:
/// `Route`, `SockDiag`, `Generic`, `Nftables`
///
/// **GENL protocols** — use `Connection::new_async().await`:
/// `Wireguard`, `Macsec`, `Mptcp`, `Ethtool`, `Nl80211`, `Devlink`
///
/// These require async construction to resolve their Generic Netlink family ID.
/// While `Connection::new()` compiles for them (they implement `Default`), the
/// resulting connection will have an unresolved family ID and will not work.
///
/// **Other protocols** have their own constructors (e.g., `Connector`, `KobjectUevent`).
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::{Connection, Route, Generic, Wireguard};
///
/// // Sync construction (Route, Generic, Nftables, SockDiag)
/// let route = Connection::<Route>::new()?;
/// let genl = Connection::<Generic>::new()?;
///
/// // Async construction (Wireguard, Macsec, Mptcp, Ethtool, Nl80211, Devlink)
/// let wg = Connection::<Wireguard>::new_async().await?;
/// # Ok(())
/// # }
/// ```
///
/// # Concurrency
///
/// `Connection<P>` is `Send + Sync` and safe to share across
/// tokio tasks via `Arc<Connection<P>>`. As of 0.19 (closing the
/// F1 architectural concurrency issue), each request/response
/// pair acquires an internal `tokio::sync::Mutex` so concurrent
/// callers on a shared `Arc<Connection>` serialize cleanly
/// instead of racing on the recv side.
///
/// The lock is held for one send + one drain-until-DONE/ACK
/// cycle, so concurrent dumps on a shared connection complete
/// in sequence rather than in parallel. For true parallel
/// throughput, use [`crate::netlink::pool::ConnectionPool<P>`]
/// — each task acquires its own connection (and therefore its
/// own netlink socket, which the kernel processes in parallel).
///
/// What the lock fixes — without it, two tasks calling
/// `get_links()` on a shared connection would race on `recv_msg`:
/// task A could consume task B's response from the socket
/// buffer, the seq filter would `continue` past it (correct
/// from A's view) but B then blocks forever waiting for a
/// response that's gone. The seq filter remains as a defensive
/// backstop against stale multicast/cross-process frames, but
/// no longer load-bears against multi-task races.
///
/// A multicast `events()` stream on a plain connection holds the
/// request lock for as long as it lives, so requests wait for it (or
/// fail with [`Error::event_stream_active()`]
/// where they cannot wait). For events and requests on one connection at
/// once, opt into the per-seq response router with
/// [`with_dispatcher`](Self::with_dispatcher) (#134), or use a second
/// connection.
pub struct Connection<P: ProtocolState> {
    /// `Arc` so the #134 dispatcher driver task can hold the recv side
    /// while `Connection` methods keep using the send side. The
    /// `socket()` accessor still returns `&NetlinkSocket` via deref.
    socket: std::sync::Arc<NetlinkSocket>,
    state: P,
    timeout: Option<Duration>,
    /// #134 — when `true`, request inners route through the per-seq
    /// dispatcher registry + a background recv-driver task instead of
    /// the F1 `request_lock`, so concurrent requests on a shared
    /// `Arc<Connection>` pipeline instead of serializing. Opt-in via
    /// [`Connection::with_dispatcher`]; default `false` (unchanged
    /// mutex path). The streaming APIs are not yet supported in this
    /// mode (the driver owns recv) — they return a clear error.
    dispatcher_mode: bool,
    /// Serialize concurrent request/response cycles on a shared
    /// `Arc<Connection<P>>`. Held by every higher-level method
    /// that does `socket.send(...) + recv-loop-until-DONE`.
    /// Closes the F1 concurrency bug (rtnetlink #131 shape) where
    /// task A's recv loop would consume task B's response from
    /// the socket buffer and drop it. See `Concurrency` above.
    ///
    /// `Arc<Mutex<()>>` (rather than `Mutex<()>`) so streams
    /// (`DumpStream`, `EventSubscription`) can take an
    /// [`tokio::sync::OwnedMutexGuard`] that lives independent
    /// of the Connection's borrow scope — see 0.19 Finding B.
    ///
    /// Plan 234 (0.21.0) — kept alongside the new
    /// [`Dispatcher`] foundation. The dispatcher handles
    /// multicast fan-out + `ResyncMarker::ResyncStart` ENOBUFS
    /// routing today; the full per-seq unicast router that
    /// retires this mutex lands incrementally on top of the
    /// dispatcher's infrastructure (see `dispatcher.rs`).
    request_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    /// #505 — whether a mutex-mode event stream holds `request_lock`,
    /// so a request fails fast instead of waiting out the stream.
    event_claim: std::sync::Arc<EventClaim>,
    /// Plan 234 — per-Connection dispatcher. Routes ENOBUFS into
    /// `ResyncMarker::ResyncStart` for every active multicast
    /// subscriber and fans out multicast frames to per-group
    /// broadcast channels. The recv path on `NetlinkSocket`
    /// consults the connection's dispatcher when it sees ENOBUFS
    /// so the marker reaches the right place (Plan 234 §4).
    dispatcher: Dispatcher,
}

impl<P: ProtocolState> Drop for Connection<P> {
    fn drop(&mut self) {
        // #134 — if a dispatcher driver task was spawned, signal it to
        // exit so it stops polling recv and drops its
        // `Arc<NetlinkSocket>` (the last Arc then closes the fd). A
        // no-op for default-mode connections (no driver) and for
        // dispatcher-mode connections that never issued a request.
        if self.dispatcher.driver_started() {
            self.dispatcher.shutdown();
        }
    }
}

/// Whether a mutex-mode event stream owns the connection (#505). Shared
/// between the [`Connection`] and the stream's [`EventLock`].
#[derive(Default)]
pub(crate) struct EventClaim {
    active: std::sync::atomic::AtomicBool,
    /// Wakes requests queued on the request lock when a stream claims it.
    claimed: tokio::sync::Notify,
}

/// The request lock as a mutex-mode event stream holds it. Dropping it
/// clears the claim before releasing the lock, so a request that sees
/// the claim cleared never then waits behind the stream.
pub(crate) struct EventLock {
    claim: std::sync::Arc<EventClaim>,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl Drop for EventLock {
    fn drop(&mut self) {
        self.claim
            .active
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

/// Dual-mode frame source for hand-rolled subsystem `send + recv-loop`
/// cycles (#134). Construct via [`Connection::recv_session`].
///
/// `Direct` holds the request lock and reads the socket (mutex mode — the
/// pre-#134 behavior). `Dispatched` holds a per-seq registration on the
/// background driver and reads the channel the driver routes this seq's
/// frames into (dispatcher mode — coexists with the driver instead of
/// racing its `recv_msg`).
pub(crate) enum RecvSession {
    /// Mutex mode — guard held purely for its `Drop` (lock release).
    Direct(#[allow(dead_code)] tokio::sync::OwnedMutexGuard<()>),
    Dispatched {
        guard: super::dispatcher::PendingGuard,
        /// `Some` for dump cycles: the kernel serializes dumps per socket
        /// (`netlink_dump_start` → `EBUSY`), so a dispatcher-mode dump
        /// still holds the dump-serialization lock for its lifetime.
        /// `None` for single-message cycles (those pipeline freely).
        _dump_lock: Option<tokio::sync::OwnedMutexGuard<()>>,
    },
}

impl RecvSession {
    /// Receive the next datagram for this cycle, **bounded by the
    /// connection's inactivity timeout**.
    ///
    /// This is the `recv_with_timeout` the canonical recv-loop template
    /// in CLAUDE.md has always named. It did not exist — zero
    /// occurrences crate-wide — so code written by following the
    /// documented template did not compile, and the name described
    /// per-recv semantics the implementation did not have (#272).
    ///
    /// The distinction matters. `Connection::with_timeout` wraps the
    /// *whole* future, which for a multi-message dump is a total
    /// duration budget: a legitimately large dump — conntrack with
    /// millions of entries, a full BGP table — failed with
    /// `Error::timeout()` while the kernel was streaming perfectly well,
    /// and the caller could not tell "the kernel hung" from "this table
    /// is big", which is the distinction the timeout exists to draw. A
    /// per-recv deadline, reset by every frame that arrives, catches a
    /// genuine stall promptly *and* lets a big dump finish.
    pub(crate) async fn recv_with_timeout<P: ProtocolState>(
        &mut self,
        conn: &Connection<P>,
    ) -> Result<Vec<u8>> {
        match conn.timeout {
            Some(dur) => tokio::time::timeout(dur, self.recv(conn))
                .await
                .map_err(|_| conn.socket().stamp(Error::timeout()))?,
            None => self.recv(conn).await,
        }
    }

    /// The next datagram for this cycle if the kernel has already queued
    /// one, without waiting for the kernel — for draining what it queued
    /// inside the request's `sendmsg`, as nfnetlink does for a batch.
    ///
    /// `None` means the socket held nothing more for this cycle. In
    /// dispatcher mode an empty channel means only that the driver has not
    /// routed it yet, so an empty channel waits for the driver to read the
    /// socket dry ([`Dispatcher::settle`](super::dispatcher::Dispatcher))
    /// and looks again.
    pub(crate) async fn recv_queued<P: ProtocolState>(
        &mut self,
        conn: &Connection<P>,
    ) -> Result<Option<Vec<u8>>> {
        use tokio::sync::mpsc::error::TryRecvError;
        match self {
            RecvSession::Direct(_) => conn.socket().try_recv_unicast(),
            RecvSession::Dispatched { guard, .. } => {
                let mut settled = false;
                loop {
                    match guard.rx.try_recv() {
                        Ok(buf) => return Ok(Some((*buf).clone())),
                        Err(TryRecvError::Empty) if !settled => {
                            conn.dispatcher().settle().await;
                            settled = true;
                        }
                        Err(TryRecvError::Empty) => return Ok(None),
                        Err(TryRecvError::Disconnected) => {
                            return Err(conn.socket().stamp(conn.dispatcher().take_fatal_error()));
                        }
                    }
                }
            }
        }
    }

    /// Receive the next datagram for this cycle with no deadline.
    /// Prefer [`recv_with_timeout`](Self::recv_with_timeout); this is
    /// for callers that impose their own bound.
    pub(crate) async fn recv<P: ProtocolState>(&mut self, conn: &Connection<P>) -> Result<Vec<u8>> {
        match self {
            RecvSession::Direct(_) => conn.socket().recv_unicast().await,
            RecvSession::Dispatched { guard, .. } => match guard.rx.recv().await {
                Some(buf) => Ok((*buf).clone()),
                None => Err(conn.socket().stamp(conn.dispatcher().take_fatal_error())),
            },
        }
    }
}

/// Default operation timeout for `Connection<P>` (Plan 171).
///
/// 30 seconds — long enough that legitimate slow operations don't
/// trip it (kernel dumps on huge route tables: ~5-10s; nft batch
/// commits on thousands of rules: ~2-3s), short enough to fail
/// fast on the "hidden hang" class of bugs (kernel response
/// anomaly, missing DONE marker, etc.) that would otherwise block
/// indefinitely. Tunable via [`Connection::timeout`]; opt out via
/// [`Connection::no_timeout`].
///
/// The number aligns with the integration suite's existing 30s
/// explicit cap on root-gated tests — same budget, same intuition.
pub(crate) const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

// ============================================================================
// Shared methods for protocol types that implement Default
// ============================================================================

impl<P> Connection<P>
where
    P: ProtocolState + Default + crate::netlink::protocol::construction::SyncConstructible,
{
    /// Create a new connection for this protocol type.
    ///
    /// Bounded `where P: SyncConstructible` so the GENL protocol
    /// markers (`Wireguard`, `Macsec`, `Mptcp`, `Ethtool`, `Nl80211`,
    /// `Devlink`) are a **compile error** here — those families need
    /// async family-ID resolution and must use `new_async().await`.
    /// Sync-constructible markers are: `Route`, `SockDiag`, `Generic`,
    /// `KobjectUevent`, `Connector`, `Netfilter`, `Xfrm`, `FibLookup`,
    /// `SELinux`, `Audit`, `Nftables`.
    ///
    /// Before 0.16.0 this method took only `P: ProtocolState + Default`,
    /// which let `Connection::<Wireguard>::new()` compile and return a
    /// connection with `family_id = 0`; the first operation then failed
    /// with a confusing kernel error. The new bound prevents that
    /// class of bug at the type level.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Route, Generic};
    ///
    /// let route = Connection::<Route>::new()?;
    /// let genl = Connection::<Generic>::new()?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(level = "info", skip_all, fields(protocol = std::any::type_name::<P>()))]
    pub fn new() -> Result<Self> {
        let socket = NetlinkSocket::new(P::PROTOCOL)?;
        let dispatcher = Dispatcher::new();
        // Plan 234 — install dispatcher hook so socket.recv_msg's
        // ENOBUFS path fans out ResyncMarker::ResyncStart to active
        // multicast subscribers.
        socket.install_dispatcher(dispatcher.clone());
        let socket = std::sync::Arc::new(socket);
        Ok(Self {
            socket,
            dispatcher_mode: false,
            state: P::default(),
            timeout: Some(DEFAULT_OPERATION_TIMEOUT),
            request_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            event_claim: Default::default(),
            dispatcher,
        })
    }

    /// A connection in a network namespace (#532): an open
    /// [`Netns`](super::namespace::Netns), a
    /// [`NetnsRef`](super::namespace::NetnsRef), an `ip netns` name, a
    /// path, a [`NamespaceSpec`](super::namespace::NamespaceSpec), a
    /// borrowed namespace fd — anything
    /// [`Into<NetnsTarget>`](super::namespace::NetnsTarget).
    ///
    /// The socket is made inside the namespace and works from any thread.
    /// A stream on it ends with [`ErrorDetail::NamespaceDeleted`](crate::ErrorDetail::NamespaceDeleted) once a
    /// namespace opened by name or path is deleted.
    ///
    /// ```no_run
    /// # async fn example() -> nlink::Result<()> {
    /// use nlink::netlink::{Connection, Route};
    ///
    /// let conn = Connection::<Route>::new_in("myns")?;
    /// let links = conn.get_links().await?;
    /// # let _ = links;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(level = "info", skip_all, fields(protocol = std::any::type_name::<P>(), netns))]
    pub fn new_in<'a>(ns: impl Into<super::namespace::NetnsTarget<'a>>) -> Result<Self> {
        let ns = ns.into();
        tracing::Span::current().record("netns", tracing::field::display(&ns));
        ns.connection()
    }

    /// [`new_in_namespace`](Self::new_in_namespace), which takes `AsFd`
    /// itself now (#532).
    #[deprecated(since = "0.32.0", note = "use `Connection::new_in(fd.as_fd())` (#532)")]
    pub fn new_in_namespace_fd(ns_fd: impl std::os::fd::AsFd) -> Result<Self> {
        Self::new_in(ns_fd.as_fd())
    }

    /// Create a connection that operates in a specific network namespace.
    ///
    /// The namespace is specified by an open file descriptor to a namespace file
    /// (e.g., `/proc/<pid>/ns/net` or `/var/run/netns/<name>`): a `File`, a
    /// [`NamespaceFd`](super::namespace::NamespaceFd), a
    /// [`Netns`](super::namespace::Netns), anything `AsFd`. It only has to
    /// stay open for the call.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use std::fs::File;
    /// use nlink::netlink::{Connection, Route};
    ///
    /// let ns_file = File::open("/var/run/netns/myns")?;
    /// let conn = Connection::<Route>::new_in_namespace(&ns_file)?;
    ///
    /// // All operations now occur in the "myns" namespace
    /// let links = conn.get_links().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[deprecated(since = "0.32.0", note = "use `Connection::new_in(fd.as_fd())` (#532)")]
    #[instrument(level = "info", skip_all, fields(protocol = std::any::type_name::<P>(), ns_fd))]
    pub fn new_in_namespace(ns_fd: impl std::os::fd::AsFd) -> Result<Self> {
        let ns_fd = ns_fd.as_fd();
        tracing::Span::current().record("ns_fd", std::os::fd::AsRawFd::as_raw_fd(&ns_fd));
        let socket = NetlinkSocket::new_in_namespace(P::PROTOCOL, ns_fd)?;
        let dispatcher = Dispatcher::new();
        socket.install_dispatcher(dispatcher.clone());
        let socket = std::sync::Arc::new(socket);
        Ok(Self {
            socket,
            dispatcher_mode: false,
            state: P::default(),
            timeout: Some(DEFAULT_OPERATION_TIMEOUT),
            request_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            event_claim: Default::default(),
            dispatcher,
        })
    }

    /// Create a connection that operates in a network namespace specified by path.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Route};
    ///
    /// // For a named namespace (created via `ip netns add myns`)
    /// let conn = Connection::<Route>::new_in(std::path::Path::new("/var/run/netns/myns"))?;
    ///
    /// // For a container's namespace
    /// let conn = Connection::<Route>::new_in(std::path::Path::new("/proc/1234/ns/net"))?;
    ///
    /// // Query interfaces in that namespace
    /// let links = conn.get_links().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[deprecated(since = "0.32.0", note = "use `Connection::new_in(path)` (#532)")]
    #[instrument(level = "info", skip_all, fields(protocol = std::any::type_name::<P>(), ns_path = %ns_path.as_ref().display()))]
    pub fn new_in_namespace_path<T: AsRef<Path>>(ns_path: T) -> Result<Self> {
        let socket = NetlinkSocket::new_in_namespace_path(P::PROTOCOL, ns_path)?;
        let dispatcher = Dispatcher::new();
        socket.install_dispatcher(dispatcher.clone());
        let socket = std::sync::Arc::new(socket);
        Ok(Self {
            socket,
            dispatcher_mode: false,
            state: P::default(),
            timeout: Some(DEFAULT_OPERATION_TIMEOUT),
            request_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            event_claim: Default::default(),
            dispatcher,
        })
    }
}

// ============================================================================
// Generic async constructor for GENL families
// ============================================================================
//
// `new_async()` was hand-rolled per-family in 0.15 (one inherent
// `impl Connection<Wireguard>::new_async()`, one for `Macsec`, etc.).
// 0.16's `#[genl_family(...)]` macro emits the `AsyncProtocolInit`
// impl that this generic constructor needs, so macro-defined
// families plug into the canonical API automatically. The
// hand-rolled per-family `new_async()` impls remain for backwards
// compatibility (the inherent versions take priority over this
// generic one when both apply).

#[nlink_macros::send_futures]
impl<P> Connection<P>
where
    P: super::protocol::AsyncProtocolInit + super::protocol::construction::AsyncConstructible,
{
    /// Create a connection for a GENL family whose ID must be
    /// resolved at construction time.
    ///
    /// Generic over any `P: AsyncConstructible + AsyncProtocolInit`
    /// — the in-tree GENL family markers (`Wireguard`, `Macsec`,
    /// `Mptcp`, `Devlink`, `Nl80211`, `Ethtool`) and every family
    /// declared via `#[genl_family(name = ..., version = ...)]`
    /// satisfy the bound.
    ///
    /// Bounded so that sync-only markers (`Route`, `Generic`,
    /// `SockDiag`, `Netfilter`, etc.) are a **compile error** here
    /// — those don't need async setup and should call
    /// [`Self::new`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Wireguard};
    ///
    /// let wg = Connection::<Wireguard>::new_async().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(level = "info", skip_all, fields(protocol = std::any::type_name::<P>()))]
    pub async fn new_async() -> Result<Self> {
        let socket = NetlinkSocket::new(P::PROTOCOL)?;
        let state = P::resolve_async(&socket).await?;
        Ok(Self::from_parts(socket, state))
    }

    /// [`new_in`](Connection::new_in) for a GENL family: a connection in a
    /// network namespace, its family id resolved there (#532).
    ///
    /// ```no_run
    /// # async fn example() -> nlink::Result<()> {
    /// use nlink::netlink::{Connection, Wireguard};
    ///
    /// let wg = Connection::<Wireguard>::new_in_async("myns").await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(level = "info", skip_all, fields(protocol = std::any::type_name::<P>(), netns))]
    pub async fn new_in_async<'a>(
        ns: impl Into<super::namespace::NetnsTarget<'a>>,
    ) -> Result<Self> {
        let ns = ns.into();
        tracing::Span::current().record("netns", tracing::field::display(&ns));
        ns.connection_async().await
    }
}

// ============================================================================
// Shared methods for all protocol types
// ============================================================================

#[nlink_macros::send_futures]
impl<P: ProtocolState> Connection<P> {
    /// Get the underlying socket.
    pub fn socket(&self) -> &NetlinkSocket {
        &self.socket
    }

    /// An interface this connection's namespace has none of (#718):
    /// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound),
    /// carrying the namespace like the kernel's own errors.
    pub(crate) fn interface_not_found(&self, name: impl Into<String>) -> Error {
        self.socket.stamp(Error::interface_not_found(name))
    }

    /// Opt this connection into **dispatcher mode** (#134).
    ///
    /// In dispatcher mode, request/ack/dump operations route through a
    /// per-`nlmsg_seq` registry served by a single background
    /// recv-driver task instead of the F1 `request_lock`. Single-message
    /// unicast requests on a shared `Arc<Connection>` then **pipeline**
    /// (each awaits its own response channel) rather than serializing
    /// through the mutex, and a long-lived `recv` no longer blocks
    /// unrelated requests.
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::Connection;
    /// # use nlink::Route;
    /// let conn = std::sync::Arc::new(Connection::<Route>::new()?.with_dispatcher());
    /// // Single-message lookups pipeline (not serialized):
    /// let (a, b) = tokio::join!(
    ///     conn.get_link_by_index(1),
    ///     conn.get_link_by_index(2),
    /// );
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Dumps still serialize (kernel constraint)
    ///
    /// The kernel serializes **dumps** per socket — `netlink_dump_start`
    /// returns `EBUSY` if a dump is already in flight on the same fd. So
    /// the eager `get_*`-style dumps (which use `send_dump`, e.g.
    /// `get_links`/`get_routes`) still complete in sequence in dispatcher
    /// mode; the dispatcher can't change a kernel rule. For genuinely
    /// parallel dumps, use [`ConnectionPool<P>`](crate::netlink::pool::ConnectionPool)
    /// — one socket per task.
    ///
    /// # Event streams coexist with requests (the headline fix)
    ///
    /// [`events`](Self::events) / [`into_events`](Self::into_events) work
    /// in dispatcher mode: they register a listener on the driver and
    /// consume driver-routed multicast frames instead of holding a lock.
    /// So a long-lived event subscriber and concurrent requests on the
    /// **same** connection both make progress — the exact regression #134
    /// was filed for. (Multicast membership is still added the usual way
    /// via [`subscribe`](Self::subscribe) / `subscribe_all`.)
    ///
    /// # What still serializes
    ///
    /// **Dumps**, because the kernel serializes them per socket
    /// (`netlink_dump_start` returns `EBUSY` on a second in-flight
    /// dump), so a dump holds the dump-serialization lock for its
    /// lifetime in this mode too. For genuinely parallel dumps use
    /// [`ConnectionPool`](crate::netlink::pool::ConnectionPool) — one
    /// fd per task, parallel kernel-side.
    ///
    /// This used to claim that [`dump_stream`](Self::dump_stream) and
    /// the `*_with_resync` wrappers were "not yet supported" here and
    /// "return a clear `Error::NotSupported`". Both halves were false:
    /// `DumpStream::new` handles dispatcher mode explicitly, the
    /// crate's own `dispatcher_mode_dump_stream_streams_links` test
    /// asserts it end to end, and no streaming path constructs
    /// `Error::NotSupported` anywhere. The cost was the mirror image of
    /// the `try_recv` bug: readers avoided a working feature, opening a
    /// second socket per netns or materialising whole route tables
    /// eagerly — and anyone who wrote `if e.is_not_supported()` around
    /// it has unreachable code (#276).
    #[must_use]
    pub fn with_dispatcher(mut self) -> Self {
        self.dispatcher_mode = true;
        self
    }

    /// Whether this connection is in dispatcher mode (#134).
    pub fn is_dispatcher_mode(&self) -> bool {
        self.dispatcher_mode
    }

    /// Ensure the background recv-driver is running. Idempotent; only
    /// meaningful in dispatcher mode. Called by the request inners and
    /// by the event-stream constructors (#134 streams).
    pub(crate) fn ensure_driver(&self) {
        self.dispatcher.ensure_driver(self.socket.clone());
    }

    /// Get the protocol state.
    pub fn state(&self) -> &P {
        &self.state
    }

    /// Override the operation timeout.
    ///
    /// Operations that exceed the configured duration return
    /// [`Error::timeout()`]. As of 0.17 (Plan 171) the **default is
    /// 30 seconds** — long enough for legitimate slow ops, short
    /// enough to fail fast on the "hidden hang" class of bugs
    /// (kernel response anomaly, missing DONE marker, etc.).
    /// Use this method to set a different bound; use
    /// [`Self::no_timeout`] to opt out entirely.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::{Connection, Route};
    /// use std::time::Duration;
    ///
    /// let conn = Connection::<Route>::new()?
    ///     .timeout(Duration::from_secs(5));
    /// # Ok(())
    /// # }
    /// ```
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Opt out of the default operation timeout. Use sparingly —
    /// without a timeout, any kernel response anomaly hangs the
    /// call indefinitely (the failure mode that caused the 0.16
    /// cycle's `send_batch` CI hang; see Plan 170).
    pub fn no_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    /// The network namespace this connection's socket lives in (#520).
    ///
    /// Exact for a connection made in a namespace (by [`Netns`], fd or
    /// path). For one made with `new()` the kernel is asked
    /// (`SIOCGSKNS`, which wants `CAP_NET_ADMIN`); without the privilege
    /// it is the calling thread's namespace, which is the socket's unless
    /// the thread has moved since.
    ///
    /// [`Netns`]: crate::netlink::namespace::Netns
    pub fn netns(&self) -> Result<crate::netlink::namespace::Netns> {
        use crate::netlink::namespace::Netns;
        if let Some(fd) = self.socket.origin_netns() {
            return Netns::from_fd(fd.try_clone().map_err(Error::from)?);
        }
        match self.socket.netns_fd() {
            Ok(fd) => Netns::from_fd(fd),
            Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => {
                Netns::current()
            }
            Err(e) => Err(Error::from(e)),
        }
    }

    /// A connection of another protocol in the same namespace (#520):
    /// `conn.sibling::<Nftables>()` next to a `Connection<Route>` opened in
    /// a namespace, without naming the namespace again. A connection made
    /// with `new()` gets a sibling made with `new()`.
    pub fn sibling<Q>(&self) -> Result<Connection<Q>>
    where
        Q: ProtocolState + Default + super::protocol::construction::SyncConstructible,
    {
        match self.socket.origin_netns() {
            Some(fd) => {
                let mut socket = NetlinkSocket::new_in_namespace(Q::PROTOCOL, fd.as_ref())?;
                socket.set_namespace(
                    fd.clone(),
                    self.socket.namespace_marker().cloned(),
                    self.socket.netns_label().cloned(),
                );
                Ok(Connection::from_parts(socket, Q::default()))
            }
            None => Connection::<Q>::new(),
        }
    }

    /// [`sibling`](Self::sibling) for a generic-netlink family, whose id is
    /// resolved inside the namespace.
    pub async fn sibling_async<Q>(&self) -> Result<Connection<Q>>
    where
        Q: super::protocol::AsyncProtocolInit + super::protocol::construction::AsyncConstructible,
    {
        let socket = match self.socket.origin_netns() {
            Some(fd) => {
                let mut socket = NetlinkSocket::new_in_namespace(Q::PROTOCOL, fd.as_ref())?;
                socket.set_namespace(
                    fd.clone(),
                    self.socket.namespace_marker().cloned(),
                    self.socket.netns_label().cloned(),
                );
                socket
            }
            None => NetlinkSocket::new(Q::PROTOCOL)?,
        };
        let state = Q::resolve_async(&socket).await?;
        Ok(Connection::from_parts(socket, state))
    }

    /// The operation timeout: 30 seconds unless set with
    /// [`timeout`](Self::timeout), `None` after
    /// [`no_timeout`](Self::no_timeout). On a dump it is the per-frame
    /// deadline (#272).
    pub fn operation_timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// The operation timeout.
    #[deprecated(since = "0.32.0", note = "renamed to `operation_timeout` (#532)")]
    pub fn get_timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Enable kernel-side strict checking (`NETLINK_GET_STRICT_CHK`,
    /// kernel 5.0+). When enabled, the kernel validates dump request
    /// filters strictly and returns an error if they reference
    /// unknown attributes — useful for catching client/kernel-version
    /// mismatches early during development.
    ///
    /// Off by default for backwards compatibility with older
    /// kernels. The setsockopt is silently a no-op on pre-5.0
    /// kernels (returns `Ok(())` on `ENOPROTOOPT`), so calling
    /// `enable_strict_checking(true)` unconditionally is safe.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::{Connection, Route};
    /// let conn = Connection::<Route>::new()?;
    /// conn.enable_strict_checking(true)?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(level = "debug", skip(self), fields(method = "enable_strict_checking"))]
    pub fn enable_strict_checking(&self, on: bool) -> Result<()> {
        self.socket.set_strict_checking(on)
    }

    /// Receive the events of every namespace that has an id in this
    /// connection's (`NETLINK_LISTEN_ALL_NSID`, kernel 4.6+; #523), not
    /// only its own. Which one each came from is
    /// [`EventMeta::nsid`](super::EventMeta::nsid), through a stream's
    /// `with_meta()`; without it they are indistinguishable. A namespace
    /// gets an id with [`set_nsid`](Connection::<Route>::set_nsid) or
    /// `ip netns set`. Needs `CAP_NET_BROADCAST` over each namespace.
    ///
    /// ```no_run
    /// # async fn example() -> nlink::Result<()> {
    /// use nlink::netlink::{Connection, Route, RtnetlinkGroup};
    /// use tokio_stream::StreamExt;
    ///
    /// let conn = Connection::<Route>::new()?;
    /// conn.listen_all_nsid(true)?;
    /// conn.subscribe(&[RtnetlinkGroup::Link])?;
    /// let mut events = conn.events().await.with_meta();
    /// while let Some((meta, event)) = events.next().await.transpose()? {
    ///     println!("nsid {:?}: {event:?}", meta.nsid);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(level = "debug", skip(self), fields(method = "listen_all_nsid"))]
    pub fn listen_all_nsid(&self, on: bool) -> Result<()> {
        self.socket.set_listen_all_nsid(on)
    }

    /// Toggle extended-ack reception (`NETLINK_EXT_ACK`, kernel
    /// 4.12+). **Enabled by default** during socket construction —
    /// disabling is rarely useful in practice. Exposed for parity
    /// with neli's API and for callers that explicitly want to
    /// suppress the trailing TLVs in error responses.
    ///
    /// Silently a no-op on pre-4.12 kernels (returns `Ok(())` on
    /// `ENOPROTOOPT`).
    ///
    /// See [`ErrorDetail::Kernel::ext_ack`](crate::ErrorDetail::Kernel::ext_ack) for what these TLVs contain
    /// once parsed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::{Connection, Route};
    /// let conn = Connection::<Route>::new()?;
    /// conn.set_ext_ack(false)?;  // disable; rarely useful
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(level = "debug", skip(self), fields(method = "set_ext_ack"))]
    pub fn set_ext_ack(&self, on: bool) -> Result<()> {
        self.socket.set_ext_ack(on)
    }

    /// A `Connection<Route>` in the network namespace this connection's
    /// socket lives in — which is not necessarily the process's (#497).
    ///
    /// A GENL connection opened in a lab namespace that needs a link name
    /// or index resolved, or a diagnostics run that wants an event socket
    /// beside its own, used `Connection::<Route>::new()`: the *process's*
    /// namespace, so the host's ifindex 2 named the host's `eth0`. This
    /// opens the sibling through `SIOCGSKNS`. Without `CAP_NET_ADMIN` over
    /// that namespace the ioctl is refused; the process's own namespace is
    /// then used if, and only if, its cookie matches.
    pub(crate) fn route_sibling(&self) -> Result<Connection<super::protocol::Route>> {
        use super::protocol::Route;
        match self.socket.netns_fd() {
            Ok(ns) => Connection::<Route>::new_in(std::os::fd::AsFd::as_fd(&ns)),
            Err(refused) => {
                let here = Connection::<Route>::new()?;
                match (self.socket.netns_cookie(), here.socket.netns_cookie()) {
                    (Ok(ours), Ok(theirs)) if ours == theirs => Ok(here),
                    _ => Err(Error::from(refused)),
                }
            }
        }
    }

    /// Acquire the request lock as an *owned* guard, for one mutex-mode
    /// request/response cycle or a `DumpStream`'s lifetime (0.19 Finding
    /// B: the owned guard outlives the `&Connection` borrow, so a stream
    /// can store it).
    ///
    /// Fails fast with [`Error::event_stream_active()`] while an event stream
    /// holds the lock (#505): it keeps it until it is dropped, so waiting
    /// could only end in the operation timeout, which reads as a kernel
    /// hang. A request already queued when a stream takes the lock is
    /// woken and fails the same way.
    pub(crate) async fn lock_request(&self) -> Result<tokio::sync::OwnedMutexGuard<()>> {
        // Registered before the check, so a stream that claims the lock
        // after it still wakes this request.
        let claimed = self.event_claim.claimed.notified();
        if self
            .event_claim
            .active
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(Error::event_stream_active());
        }
        tokio::select! {
            biased;
            guard = self.request_lock.clone().lock_owned() => Ok(guard),
            () = claimed => Err(Error::event_stream_active()),
        }
    }

    /// Take the request lock for a mutex-mode event stream's lifetime.
    /// Until the returned guard drops, requests on this connection fail
    /// with [`Error::event_stream_active()`] instead of queueing behind it
    /// (#505). Requests already in flight finish first: the lock is fair.
    pub(crate) async fn claim_for_events(&self) -> EventLock {
        let guard = self.request_lock.clone().lock_owned().await;
        self.event_claim
            .active
            .store(true, std::sync::atomic::Ordering::Release);
        self.event_claim.claimed.notify_waiters();
        EventLock {
            claim: self.event_claim.clone(),
            _guard: guard,
        }
    }

    /// Begin a hand-rolled `send + recv-loop` cycle (#134 dual-mode).
    ///
    /// Returns a [`RecvSession`] the caller drives with
    /// [`RecvSession::recv`] in place of `socket().recv_msg()`. In mutex
    /// mode the session holds the request lock for the loop's lifetime
    /// (the old `lock_request` behavior); in dispatcher mode it registers
    /// `seq` on the driver and the loop consumes the driver-routed
    /// channel — so the bespoke loop coexists with the background driver
    /// instead of racing its `recv_msg`.
    ///
    /// **Call after computing `seq` and before sending** — dispatcher mode
    /// requires register-before-send so the driver never sees a response
    /// for an unregistered seq.
    pub(crate) async fn recv_session(&self, seq: u32) -> Result<RecvSession> {
        if self.dispatcher_mode {
            self.ensure_driver();
            Ok(RecvSession::Dispatched {
                guard: self.dispatcher.register(seq),
                _dump_lock: None,
            })
        } else {
            Ok(RecvSession::Direct(self.lock_request().await?))
        }
    }

    /// Like [`recv_session`](Self::recv_session) but registers **several**
    /// seqs onto one channel (#134 batch path). The batch sends N messages
    /// with N distinct seqs in one `sendmsg` and collects their ACKs in a
    /// single loop; in dispatcher mode the driver routes all of them to
    /// the one channel. No dump-serialization lock — a batch isn't a dump,
    /// and its distinct seqs demux cleanly, so concurrent batches pipeline.
    pub(crate) async fn recv_session_multi(&self, seqs: &[u32]) -> Result<RecvSession> {
        if self.dispatcher_mode {
            self.ensure_driver();
            Ok(RecvSession::Dispatched {
                guard: self.dispatcher.register_many(seqs),
                _dump_lock: None,
            })
        } else {
            Ok(RecvSession::Direct(self.lock_request().await?))
        }
    }

    /// Like [`recv_session`](Self::recv_session) but for a **dump** cycle.
    /// In dispatcher mode it additionally holds the dump-serialization
    /// lock for the cycle's lifetime — the kernel serializes dumps per
    /// socket (`EBUSY` on a 2nd in-flight dump), so concurrent
    /// dispatcher-mode dumps must still serialize even though unicast
    /// requests pipeline. In mutex mode it's identical to `recv_session`
    /// (the lock already serializes everything).
    pub(crate) async fn recv_session_dump(&self, seq: u32) -> Result<RecvSession> {
        if self.dispatcher_mode {
            let dump_lock = self.request_lock.clone().lock_owned().await;
            self.ensure_driver();
            Ok(RecvSession::Dispatched {
                guard: self.dispatcher.register(seq),
                _dump_lock: Some(dump_lock),
            })
        } else {
            Ok(RecvSession::Direct(self.lock_request().await?))
        }
    }

    /// Plan 234 — access this Connection's dispatcher.
    ///
    /// The dispatcher routes ENOBUFS into
    /// [`ResyncMarker::ResyncStart`](super::resync::ResyncMarker)
    /// for every active multicast subscriber and fans out multicast
    /// frames to per-group broadcast channels. Public so subscriber
    /// constructors (events, conntrack, nftables, devlink, dpll,
    /// nl80211 multicast) can register their broadcast receivers
    /// alongside the kernel-side `add_membership` call.
    ///
    /// The dispatcher is cheap to clone (`Arc`-wrapped internally);
    /// returning `&Dispatcher` keeps the ownership story simple
    /// (the Connection owns the canonical handle).
    pub fn dispatcher(&self) -> &Dispatcher {
        &self.dispatcher
    }

    /// Wrap a future with the configured timeout.
    ///
    /// If no timeout is set, the future runs without time limit.
    /// On timeout, returns [`Error::timeout()`]. Whatever error leaves it
    /// is stamped with the socket's protocol and namespace (#718), so
    /// every request that runs inside it reports where it ran.
    pub(crate) async fn with_timeout<F, T>(&self, fut: F) -> Result<T>
    where
        F: std::future::Future<Output = Result<T>>,
    {
        let result = match self.timeout {
            Some(dur) => tokio::time::timeout(dur, fut)
                .await
                .unwrap_or_else(|_| Err(Error::timeout())),
            None => fut.await,
        };
        result.map_err(|e| self.socket.stamp(e))
    }

    /// Create a connection from its parts.
    ///
    /// This is primarily used internally for protocols that require
    /// async initialization (like WireGuard which needs family ID resolution).
    pub(crate) fn from_parts(socket: NetlinkSocket, state: P) -> Self {
        let dispatcher = Dispatcher::new();
        socket.install_dispatcher(dispatcher.clone());
        let socket = std::sync::Arc::new(socket);
        Self {
            socket,
            state,
            timeout: Some(DEFAULT_OPERATION_TIMEOUT),
            request_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            event_claim: Default::default(),
            dispatcher,
            dispatcher_mode: false,
        }
    }

    // ========================================================================
    // Internal request methods (pub(crate) - not part of public API)
    // ========================================================================

    /// Send a request and wait for a response.
    ///
    /// Respects the configured timeout. This is a low-level method.
    /// Prefer using typed methods like `get_links()`, `add_route()`, etc.
    pub(crate) async fn send_request(&self, builder: MessageBuilder) -> Result<Vec<u8>> {
        builder.check_size()?;
        self.with_timeout(self.send_request_inner(builder)).await
    }

    /// Send a request that expects an ACK only (no data response).
    ///
    /// Respects the configured timeout. This is a low-level method.
    /// Prefer using typed methods like `add_link()`, `del_route()`, etc.
    pub(crate) async fn send_ack(&self, builder: MessageBuilder) -> Result<()> {
        builder.check_size()?;
        self.with_timeout(self.send_ack_inner(builder)).await
    }

    /// Send `builder` and wait for its ACK, returning the value some
    /// generic-netlink families put there (#530): `mac80211_hwsim`
    /// answers `NEW_RADIO` with the new radio's id where an ACK has 0. Only
    /// a negative value is an error.
    pub(crate) async fn send_ack_value(&self, mut builder: MessageBuilder) -> Result<i32> {
        builder.check_size()?;
        let seq = self.socket.next_seq();
        let mut session = self.recv_session(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());
        self.socket.send(&builder.finish()).await?;
        self.with_timeout(async {
            loop {
                let data = session.recv_with_timeout(self).await?;
                for message in MessageIter::new(&data) {
                    let (header, payload) = message?;
                    if header.nlmsg_seq != seq || !header.is_error() {
                        continue;
                    }
                    return NlMsgError::from_bytes(payload)?.ack_value(header.nlmsg_flags, payload);
                }
            }
        })
        .await
    }

    /// Send a dump request and collect all responses.
    ///
    /// The configured timeout applies **per received frame**, not to
    /// the dump as a whole. Wrapping the whole future made it a total
    /// duration budget, so a legitimately large dump — conntrack with
    /// millions of entries, a full BGP table, a big nftables ruleset —
    /// failed with `Error::timeout()` while the kernel was streaming
    /// perfectly well, and the caller could not tell "the kernel hung"
    /// from "this table is big". Resetting the deadline on every frame
    /// still catches a genuine stall promptly, which is the failure the
    /// default was introduced to close (#272).
    ///
    /// This is a low-level method. Prefer typed methods like
    /// `get_links()`, `get_routes()`, etc.
    pub(crate) async fn send_dump(&self, builder: MessageBuilder) -> Result<Vec<Vec<u8>>> {
        builder.check_size()?;
        // `Box::pin` ends the future-layout recursion here, and this is the
        // one place it has to happen. Every `async fn` that awaits another
        // embeds the callee's future in its own, so rustc computes a
        // caller's layout by recursing once per level, and the dump path is
        // where nlink's depth lives — every mutating helper reaches it too,
        // resolving an interface name before it sends anything.
        //
        // Without this, a *small* program calling a convenience wrapper
        // (`del_netem`, `RateLimiter::apply`, …) failed to compile with
        // `error: queries overflow the depth limit!` — pointing at the
        // caller's own async block, never mentioning nlink, and fixable
        // only by a `recursion_limit` attribute in the caller's crate
        // (#310, #315).
        //
        // Measured: `send_request` and `send_ack` do not need it (removing
        // a box there does not overflow), and boxing per-wrapper does not
        // work — those helpers await several deep chains, so lowering one
        // sibling leaves the maximum where it was. Guarded by the
        // `route_tc_minimal_caller` example, which fails to build without
        // this line. One allocation on a path about to make a syscall.
        //
        // A dump the kernel marks `NLM_F_DUMP_INTR` is a torn snapshot: the
        // state changed under it. It is re-sent, a bounded number of times
        // — any concurrent change in the namespace (a routing daemon, DAD
        // finishing, a link flap) used to abort the caller's whole
        // operation instead of costing one re-dump (#494). The dump loops
        // read an interrupted dump to its end first, so the retry starts on
        // an empty socket.
        let mut attempt = 0;
        loop {
            match Box::pin(self.send_dump_inner(builder.clone())).await {
                Err(e) if e.is_dump_interrupted() && attempt + 1 < DUMP_INTR_ATTEMPTS => {
                    attempt += 1;
                    tracing::debug!(
                        attempt,
                        "dump interrupted by a concurrent change; re-dumping"
                    );
                }
                other => return other.map_err(|e| self.socket.stamp(e)),
            }
        }
    }

    #[instrument(level = "trace", skip_all, fields(seq))]
    async fn send_request_inner(&self, builder: MessageBuilder) -> Result<Vec<u8>> {
        // #134 — dispatcher mode pipelines through the per-seq registry
        // instead of the F1 mutex.
        if self.dispatcher_mode {
            return self.send_request_dispatch(builder).await;
        }
        self.send_request_mutex(builder).await
    }

    async fn send_request_mutex(&self, mut builder: MessageBuilder) -> Result<Vec<u8>> {
        // F1 fix — serialize the send + recv-loop pair so concurrent
        // tasks on a shared `Arc<Connection>` don't race on the recv
        // side. See struct-level "Concurrency" docstring.
        let _guard = self.lock_request().await?;

        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());
        tracing::Span::current().record("seq", seq);

        let msg = builder.finish();
        self.socket.send(&msg).await?;

        // Loop until a frame containing a message with the expected
        // seq arrives. Multicast events delivered while subscribed
        // (e.g. when this `Connection` is also `subscribe()`d to a
        // group the request mutates) carry `seq=0` and would
        // otherwise be mistaken for the response. The 30s default
        // operation timeout (`with_timeout` in `send_request`)
        // bounds the loop so a never-ack'd request still surfaces
        // as `Error::timeout()` instead of hanging.
        loop {
            let response = self.socket.recv_unicast().await?;
            let mut found_seq = false;
            for result in MessageIter::new(&response) {
                // 0.19 N2 — Plan 193 §2.3 rule 3 extension. When a
                // `Connection<P>` is both subscribed (multicast) and
                // performing requests, the recv loop sees BOTH our
                // unicast reply AND unrelated multicast frames. A
                // malformed multicast frame (corrupted kernel, future
                // protocol extension) used to kill the unrelated
                // request via `?`. Skip parse failures silently so
                // long-lived subscribers + requests on the same
                // socket survive a single malformed frame.
                let Ok((header, payload)) = result else {
                    tracing::trace!("send_request: skipping malformed frame in shared recv loop");
                    continue;
                };
                if header.nlmsg_seq != seq {
                    continue;
                }
                found_seq = true;
                if header.is_error() {
                    let err = NlMsgError::from_bytes(payload)?;
                    err.warn_if_ack_warns(header.nlmsg_flags, payload);
                    if !err.is_ack() {
                        warn!(errno = err.error, "kernel returned error for request");
                        return Err(err.to_error(header.nlmsg_flags, payload));
                    }
                }
            }
            if found_seq {
                return Ok(response);
            }
            // No matching seq in this frame — stale multicast or
            // delayed reply for a previous request. Keep reading.
        }
    }

    #[instrument(level = "trace", skip_all, fields(seq))]
    async fn send_ack_inner(&self, builder: MessageBuilder) -> Result<()> {
        if self.dispatcher_mode {
            return self.send_ack_dispatch(builder).await;
        }
        self.send_ack_mutex(builder).await
    }

    async fn send_ack_mutex(&self, mut builder: MessageBuilder) -> Result<()> {
        // F1 fix — see send_request_inner.
        let _guard = self.lock_request().await?;

        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());
        tracing::Span::current().record("seq", seq);

        let msg = builder.finish();
        self.socket.send(&msg).await?;

        // Same shape as `send_request_inner` — loop until the ACK
        // with the expected seq lands, skipping unrelated multicast
        // frames.
        loop {
            let response = self.socket.recv_unicast().await?;
            for result in MessageIter::new(&response) {
                // 0.19 N2 — see send_request_inner.
                let Ok((header, payload)) = result else {
                    tracing::trace!("send_ack: skipping malformed frame in shared recv loop");
                    continue;
                };
                if header.nlmsg_seq != seq {
                    continue;
                }
                if header.is_error() {
                    let err = NlMsgError::from_bytes(payload)?;
                    err.warn_if_ack_warns(header.nlmsg_flags, payload);
                    if !err.is_ack() {
                        warn!(errno = err.error, "kernel returned error for ack");
                        return Err(err.to_error(header.nlmsg_flags, payload));
                    }
                    return Ok(());
                }
                // Matching seq + non-error response on an ack-only
                // operation is unexpected (kernel returned a data
                // message for what nlink considered a SET-style
                // request). Pre-0.19 this fell through and looped to
                // the next recv, blocking until the 30s timeout. Now
                // we surface explicitly so the caller can react
                // (Plan 212 M16).
                return Err(Error::invalid_message(format!(
                    "send_ack: expected ACK or error for seq {}, got nlmsg_type {} \
                     (kernel returned data on an ack-only request)",
                    seq, header.nlmsg_type
                )));
            }
        }
    }

    #[instrument(level = "trace", skip_all, fields(seq, responses))]
    async fn send_dump_inner(&self, builder: MessageBuilder) -> Result<Vec<Vec<u8>>> {
        if self.dispatcher_mode {
            return self.send_dump_dispatch(builder).await;
        }
        self.send_dump_mutex(builder).await
    }

    async fn send_dump_mutex(&self, mut builder: MessageBuilder) -> Result<Vec<Vec<u8>>> {
        // F1 fix — see send_request_inner.
        let _guard = self.lock_request().await?;

        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());
        tracing::Span::current().record("seq", seq);

        let msg = builder.finish();
        self.socket.send(&msg).await?;

        let mut responses = Vec::new();
        let mut interrupted = false;

        // Per-batch frame buffer. When the `syscall_batch` feature
        // is on we collect up to NL_BATCH_SIZE frames per syscall
        // via recvmmsg(2); otherwise we fall back to per-frame
        // recv_msg. The frame-processing loop below is identical
        // either way — it just sees a 1-frame batch vs an N-frame
        // batch.
        #[cfg(feature = "syscall_batch")]
        let mut batch: Vec<Vec<u8>> = Vec::with_capacity(crate::netlink::socket::NL_BATCH_SIZE);

        'outer: loop {
            // Per-frame deadline, reset by every batch that arrives —
            // an inactivity timeout, not a total budget (#272).
            #[cfg(feature = "syscall_batch")]
            {
                batch.clear();
                self.with_timeout(
                    self.socket
                        .recv_batch(&mut batch, crate::netlink::socket::NL_BATCH_SIZE),
                )
                .await?;
            }
            #[cfg(not(feature = "syscall_batch"))]
            let batch = {
                let data = self.with_timeout(self.socket.recv_unicast()).await?;
                vec![data]
            };

            for data in batch.iter() {
                // Plan 232 B9 — track msg_start with an explicit
                // counter that advances alongside `MessageIter`
                // instead of the original raw-pointer subtraction.
                // Each MessageIter step consumes `nlmsg_align(msg_len)`
                // bytes; advancing the counter in the same shape
                // keeps it within `data` by construction.
                let mut msg_start: usize = 0;
                for result in MessageIter::new(data) {
                    // 0.19 N2 — see send_request_inner.
                    let Ok((header, payload)) = result else {
                        tracing::trace!("send_dump: skipping malformed frame in shared recv loop");
                        break;
                    };

                    let msg_len = header.nlmsg_len as usize;
                    let aligned = nlmsg_align(msg_len);

                    // Seq filter, torn-snapshot check, error handling
                    // and the DONE result code all live in one place
                    // now — they used to be copy-pasted per loop and
                    // the copies disagreed (#267, #271).
                    // An interrupted dump is read to its end, so the retry
                    // in `send_dump` does not find its frames (#494).
                    if interrupted {
                        if ends_dump(header, seq) {
                            return Err(Error::dump_interrupted());
                        }
                        msg_start = msg_start.saturating_add(aligned);
                        continue;
                    }
                    match classify(header, payload, seq) {
                        Classification::SkipSeq => {
                            msg_start = msg_start.saturating_add(aligned);
                            continue;
                        }
                        Classification::Ack => {}
                        Classification::Error(e) if e.is_dump_interrupted() => {
                            if ends_dump(header, seq) {
                                return Err(Error::dump_interrupted());
                            }
                            interrupted = true;
                        }
                        Classification::Error(e) => return Err(e),
                        // A dump that gave up says so in the DONE
                        // payload, not with NLMSG_ERROR. Returning the
                        // frames collected so far would be a truncated
                        // result indistinguishable from a complete one.
                        Classification::Done(result) => {
                            result?;
                            break 'outer;
                        }
                        Classification::Data { .. } => {
                            // Collect the full message (header + payload).
                            if msg_start + msg_len <= data.len() {
                                responses.push(data[msg_start..msg_start + msg_len].to_vec());
                            }
                        }
                    }
                    msg_start = msg_start.saturating_add(aligned);
                }
            }
        }

        tracing::Span::current().record("responses", responses.len());
        Ok(responses)
    }

    // ========================================================================
    // #134 — dispatcher-mode request paths (per-seq registry + driver)
    // ========================================================================

    /// Register a pending seq, send, then consume the driver-routed
    /// datagrams until the response with the matching seq arrives. No
    /// `request_lock` — concurrent calls pipeline.
    #[instrument(level = "trace", skip_all, fields(seq))]
    async fn send_request_dispatch(&self, mut builder: MessageBuilder) -> Result<Vec<u8>> {
        self.ensure_driver();
        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());
        tracing::Span::current().record("seq", seq);

        // Register BEFORE send so the driver never sees a response for
        // an unregistered seq.
        let mut guard = self.dispatcher.register(seq);
        let msg = builder.finish();
        self.socket.send(&msg).await?;

        loop {
            let Some(buf) = guard.rx.recv().await else {
                return Err(self.dispatcher.take_fatal_error());
            };
            let mut found_seq = false;
            for result in MessageIter::new(&buf) {
                let Ok((header, payload)) = result else {
                    continue;
                };
                if header.nlmsg_seq != seq {
                    continue;
                }
                found_seq = true;
                if header.is_error() {
                    let err = NlMsgError::from_bytes(payload)?;
                    err.warn_if_ack_warns(header.nlmsg_flags, payload);
                    if !err.is_ack() {
                        warn!(errno = err.error, "kernel returned error for request");
                        return Err(err.to_error(header.nlmsg_flags, payload));
                    }
                }
            }
            if found_seq {
                return Ok((*buf).clone());
            }
        }
    }

    #[instrument(level = "trace", skip_all, fields(seq))]
    async fn send_ack_dispatch(&self, mut builder: MessageBuilder) -> Result<()> {
        self.ensure_driver();
        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());
        tracing::Span::current().record("seq", seq);

        let mut guard = self.dispatcher.register(seq);
        let msg = builder.finish();
        self.socket.send(&msg).await?;

        loop {
            let Some(buf) = guard.rx.recv().await else {
                return Err(self.dispatcher.take_fatal_error());
            };
            for result in MessageIter::new(&buf) {
                let Ok((header, payload)) = result else {
                    continue;
                };
                if header.nlmsg_seq != seq {
                    continue;
                }
                if header.is_error() {
                    let err = NlMsgError::from_bytes(payload)?;
                    err.warn_if_ack_warns(header.nlmsg_flags, payload);
                    if !err.is_ack() {
                        warn!(errno = err.error, "kernel returned error for ack");
                        return Err(err.to_error(header.nlmsg_flags, payload));
                    }
                    return Ok(());
                }
                return Err(Error::invalid_message(format!(
                    "send_ack: expected ACK or error for seq {}, got nlmsg_type {} \
                     (kernel returned data on an ack-only request)",
                    seq, header.nlmsg_type
                )));
            }
        }
    }

    #[instrument(level = "trace", skip_all, fields(seq, responses))]
    async fn send_dump_dispatch(&self, mut builder: MessageBuilder) -> Result<Vec<Vec<u8>>> {
        self.ensure_driver();

        // The kernel serializes dumps **per socket**: `netlink_dump_start`
        // returns `EBUSY` if a dump is already in flight on this fd. The
        // per-seq driver demuxes responses but can't change that kernel
        // constraint, so dumps in dispatcher mode still serialize through
        // `request_lock` (held only for this dump's send→DONE lifetime).
        // Unicast `send_request`/`send_ack` don't take it — they pipeline
        // freely, which is the headline #134 win. For genuinely parallel
        // dumps, use `ConnectionPool<P>` (one socket per task).
        let _dump_guard = self.request_lock.lock().await;

        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());
        tracing::Span::current().record("seq", seq);

        let mut guard = self.dispatcher.register(seq);
        let msg = builder.finish();
        self.socket.send(&msg).await?;

        let mut responses = Vec::new();
        let mut interrupted = false;
        'outer: loop {
            // Per-frame deadline, as in the mutex path above (#272).
            let next = match self.timeout {
                Some(dur) => tokio::time::timeout(dur, guard.rx.recv())
                    .await
                    .map_err(|_| Error::timeout())?,
                None => guard.rx.recv().await,
            };
            let Some(buf) = next else {
                return Err(self.dispatcher.take_fatal_error());
            };
            let data: &[u8] = &buf;
            let mut msg_start: usize = 0;
            for result in MessageIter::new(data) {
                let Ok((header, payload)) = result else {
                    break;
                };
                let msg_len = header.nlmsg_len as usize;
                let aligned = nlmsg_align(msg_len);
                // As in the mutex path: read an interrupted dump to its end.
                if interrupted {
                    if ends_dump(header, seq) {
                        return Err(Error::dump_interrupted());
                    }
                    msg_start = msg_start.saturating_add(aligned);
                    continue;
                }
                match classify(header, payload, seq) {
                    Classification::SkipSeq => {
                        msg_start = msg_start.saturating_add(aligned);
                        continue;
                    }
                    Classification::Ack => {}
                    Classification::Error(e) if e.is_dump_interrupted() => {
                        if ends_dump(header, seq) {
                            return Err(Error::dump_interrupted());
                        }
                        interrupted = true;
                    }
                    Classification::Error(e) => return Err(e),
                    Classification::Done(result) => {
                        result?;
                        break 'outer;
                    }
                    Classification::Data { .. } => {
                        if msg_start + msg_len <= data.len() {
                            responses.push(data[msg_start..msg_start + msg_len].to_vec());
                        }
                    }
                }
                msg_start = msg_start.saturating_add(aligned);
            }
        }

        tracing::Span::current().record("responses", responses.len());
        Ok(responses)
    }
}

// ============================================================================
// Route protocol multicast groups
// ============================================================================

/// Multicast groups for Route protocol event notifications.
///
/// Use with [`Connection<Route>::subscribe`] to receive specific event types.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::{Connection, Route, RtnetlinkGroup};
///
/// let conn = Connection::<Route>::new()?;
/// conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Tc])?;
/// let mut events = conn.events().await;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RtnetlinkGroup {
    /// Link (interface) state changes (RTM_NEWLINK, RTM_DELLINK).
    Link,
    /// IPv4 address changes (RTM_NEWADDR, RTM_DELADDR).
    Ipv4Addr,
    /// IPv6 address changes (RTM_NEWADDR, RTM_DELADDR).
    Ipv6Addr,
    /// IPv4 route changes (RTM_NEWROUTE, RTM_DELROUTE).
    Ipv4Route,
    /// IPv6 route changes (RTM_NEWROUTE, RTM_DELROUTE).
    Ipv6Route,
    /// Neighbor (ARP/NDP) cache changes (RTM_NEWNEIGH, RTM_DELNEIGH).
    Neigh,
    /// Traffic control changes (qdiscs, classes, filters, actions).
    Tc,
    /// Namespace ID changes (RTM_NEWNSID, RTM_DELNSID).
    NsId,
    /// IPv4 routing rule changes (RTM_NEWRULE, RTM_DELRULE).
    Ipv4Rule,
    /// IPv6 routing rule changes (RTM_NEWRULE, RTM_DELRULE).
    Ipv6Rule,
    /// Nexthop-object changes (RTM_NEWNEXTHOP, RTM_DELNEXTHOP).
    Nexthop,
    /// Bridge multicast-database changes (RTM_NEWMDB, RTM_DELMDB).
    Mdb,
    /// IPv4 netconf changes (RTM_NEWNETCONF): forwarding, rp_filter, …,
    /// through `/proc/sys` too (#523).
    Ipv4Netconf,
    /// IPv6 netconf changes (RTM_NEWNETCONF) (#523).
    Ipv6Netconf,
}

impl RtnetlinkGroup {
    /// Convert to the raw netlink multicast group number.
    fn to_group(self) -> u32 {
        use super::socket::rtnetlink_groups::*;
        match self {
            Self::Link => RTNLGRP_LINK,
            Self::Ipv4Addr => RTNLGRP_IPV4_IFADDR,
            Self::Ipv6Addr => RTNLGRP_IPV6_IFADDR,
            Self::Ipv4Route => RTNLGRP_IPV4_ROUTE,
            Self::Ipv6Route => RTNLGRP_IPV6_ROUTE,
            Self::Neigh => RTNLGRP_NEIGH,
            Self::Tc => RTNLGRP_TC,
            Self::NsId => RTNLGRP_NSID,
            Self::Ipv4Rule => RTNLGRP_IPV4_RULE,
            Self::Ipv6Rule => RTNLGRP_IPV6_RULE,
            Self::Nexthop => RTNLGRP_NEXTHOP,
            Self::Mdb => RTNLGRP_MDB,
            Self::Ipv4Netconf => RTNLGRP_IPV4_NETCONF,
            Self::Ipv6Netconf => RTNLGRP_IPV6_NETCONF,
        }
    }
}

// ============================================================================
// Route protocol specific methods
// ============================================================================

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Create a connection for the specified namespace.
    ///
    /// This is a convenience method that creates a Route protocol connection
    /// for any namespace specification.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Route};
    /// use nlink::netlink::namespace::NamespaceSpec;
    ///
    /// // For a named namespace
    /// let conn = Connection::<Route>::for_namespace(NamespaceSpec::Named("myns"))?;
    ///
    /// // For a container by PID
    /// let conn = Connection::<Route>::for_namespace(NamespaceSpec::Pid(1234))?;
    ///
    /// // For the default namespace
    /// let conn = Connection::<Route>::for_namespace(NamespaceSpec::Default)?;
    /// # Ok(())
    /// # }
    /// ```
    #[deprecated(since = "0.32.0", note = "use `Connection::new_in(spec)` (#532)")]
    #[instrument(level = "info", skip_all, fields(protocol = "Route"))]
    pub fn for_namespace(spec: super::namespace::NamespaceSpec<'_>) -> Result<Self> {
        Self::new_in(spec)
    }

    /// Subscribe to multicast groups for event notifications.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Route, RtnetlinkGroup};
    ///
    /// let conn = Connection::<Route>::new()?;
    /// conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Tc])?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(level = "info", skip(self), fields(groups = ?groups))]
    pub fn subscribe(&self, groups: &[RtnetlinkGroup]) -> Result<()> {
        for group in groups {
            self.socket.add_membership(group.to_group())?;
        }
        Ok(())
    }

    /// Subscribe to all event groups with a typed [`NetworkEvent`]
    /// representation.
    ///
    /// Subscribes to: Link, Ipv4Addr, Ipv6Addr, Ipv4Route, Ipv6Route,
    /// Neigh, Tc, NsId, Ipv4Rule, Ipv6Rule, Nexthop, Mdb, Ipv4Netconf,
    /// Ipv6Netconf. The netconf groups joined in 0.32 (#523).
    ///
    /// Before 0.24 this omitted NsId/Ipv4Rule/Ipv6Rule (and the
    /// Nexthop/Mdb groups didn't exist) — rule, nexthop, namespace-ID
    /// and bridge-MDB changes were silent under `subscribe_all()`.
    ///
    /// [`NetworkEvent`]: super::events::NetworkEvent
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Route};
    ///
    /// let conn = Connection::<Route>::new()?;
    /// conn.subscribe_all()?;
    /// let mut events = conn.events().await;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(level = "info", skip_all)]
    pub fn subscribe_all(&self) -> Result<()> {
        self.subscribe(&[
            RtnetlinkGroup::Link,
            RtnetlinkGroup::Ipv4Addr,
            RtnetlinkGroup::Ipv6Addr,
            RtnetlinkGroup::Ipv4Route,
            RtnetlinkGroup::Ipv6Route,
            RtnetlinkGroup::Neigh,
            RtnetlinkGroup::Tc,
            RtnetlinkGroup::NsId,
            RtnetlinkGroup::Ipv4Rule,
            RtnetlinkGroup::Ipv6Rule,
            RtnetlinkGroup::Nexthop,
            RtnetlinkGroup::Mdb,
            RtnetlinkGroup::Ipv4Netconf,
            RtnetlinkGroup::Ipv6Netconf,
        ])
    }

    // ========================================================================
    // Strongly-typed API for Route protocol
    // ========================================================================

    /// Send a dump request and parse all responses into typed messages.
    ///
    /// This is a convenience method that combines `dump()` with parsing.
    /// The type T must implement `FromNetlink::write_dump_header` to provide
    /// the required message header (e.g., IfInfoMsg for links, IfAddrMsg for addresses).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::messages::AddressMessage;
    /// use nlink::netlink::message::NlMsgType;
    ///
    /// let addresses: Vec<AddressMessage> = conn.dump_typed(NlMsgType::RTM_GETADDR).await?;
    /// for addr in addresses {
    ///     println!("{}: {:?}", addr.ifindex(), addr.address());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(level = "debug", skip(self), fields(method = "dump_typed", msg_type))]
    pub async fn dump_typed<T: FromNetlink>(&self, msg_type: u16) -> Result<Vec<T>> {
        let mut builder = dump_request(msg_type);

        // Get the header from the type and append it to the request
        let mut header_buf = Vec::new();
        T::write_dump_header(&mut header_buf);
        builder.append_bytes(&header_buf);

        let responses = self.send_dump(builder).await?;

        let mut parsed = Vec::with_capacity(responses.len());
        for response in responses {
            if response.len() < NLMSG_HDRLEN {
                continue;
            }
            let payload = &response[NLMSG_HDRLEN..];
            if let Ok(mut msg) = T::from_bytes(payload) {
                // Hand the message its nlmsg_type: some payloads (tcmsg) are
                // byte-identical across message kinds and cannot classify
                // themselves without it (#214).
                if let Ok(header) = NlMsgHdr::from_bytes(&response[..NLMSG_HDRLEN]) {
                    msg.set_msg_type(header.nlmsg_type);
                }
                parsed.push(msg);
            }
        }

        Ok(parsed)
    }

    /// Parse a single response into a typed message.
    pub fn parse_response<T: FromNetlink>(&self, response: &[u8]) -> Result<T> {
        if response.len() < NLMSG_HDRLEN {
            return Err(Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: NLMSG_HDRLEN,
                actual: response.len(),
            }));
        }
        let payload = &response[NLMSG_HDRLEN..];
        let mut msg = T::from_bytes(payload)?;
        if let Ok(header) = NlMsgHdr::from_bytes(&response[..NLMSG_HDRLEN]) {
            msg.set_msg_type(header.nlmsg_type);
        }
        Ok(msg)
    }
}

/// Helper to build a dump request.
/// How many times [`Connection::send_dump`] sends a dump the kernel keeps
/// marking `NLM_F_DUMP_INTR` before it gives up with
/// [`Error::dump_interrupted()`] (#494). Cilium allows about 30; a dump torn
/// that often is a namespace that will not hold still.
const DUMP_INTR_ATTEMPTS: usize = 10;

pub(crate) fn dump_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_DUMP)
}

/// Helper to build a request expecting ACK.
pub(crate) fn ack_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK)
}

/// Helper to build a create request.
pub(crate) fn create_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK | 0x400) // NLM_F_CREATE
}

/// Helper to build a create-or-replace request.
pub(crate) fn replace_request(msg_type: u16) -> MessageBuilder {
    MessageBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK | 0x400 | 0x100) // NLM_F_CREATE | NLM_F_REPLACE
}

// ============================================================================
// Batch Operations
// ============================================================================

impl Connection<Route> {
    /// Create a batch for executing multiple operations in minimal syscalls.
    ///
    /// Operations are buffered and sent as concatenated messages in a single
    /// `sendmsg()`. The kernel processes them sequentially and returns one
    /// ACK per message.
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
    /// # Ok(())
    /// # }
    /// ```
    pub fn batch(&self) -> super::batch::Batch<'_> {
        super::batch::Batch::new(self)
    }
}

// ============================================================================
// Convenience Query Methods
// ============================================================================

use super::messages::{
    AddressMessage, LinkCond, LinkMessage, NeighborMessage, RouteMessage, RuleMessage, TcMessage,
};

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Get all network interfaces.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let links = conn.get_links().await?;
    /// for link in links {
    ///     println!("{}: {}", link.ifindex(), link.name().as_deref().unwrap_or("?"));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// **Scale note**: this eager variant collects the full kernel
    /// response into a `Vec<LinkMessage>` before returning. For
    /// hosts with thousands of interfaces (containers, VM hosts),
    /// prefer [`Self::stream_links`] — same data, O(1) memory.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_links"))]
    pub async fn get_links(&self) -> Result<Vec<LinkMessage>> {
        self.dump_typed(NlMsgType::RTM_GETLINK).await
    }

    /// Stream a link dump frame-by-frame.
    ///
    /// O(1) memory in the number of links, vs `get_links` which
    /// buffers the full response. See [`Self::dump_stream`] for
    /// the full semantics. On hosts with thousands of interfaces
    /// (containers, VM hosts), this is the cliff-fix.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use tokio_stream::StreamExt;
    /// let mut s = conn.stream_links().await?;
    /// while let Some(link) = s.next().await {
    ///     let link = link?;
    ///     // process one link with O(1) memory
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(level = "debug", skip_all, fields(method = "stream_links"))]
    pub async fn stream_links(
        &self,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, LinkMessage>> {
        self.dump_stream::<LinkMessage>(NlMsgType::RTM_GETLINK)
            .await
    }

    /// Stream a route dump frame-by-frame. See [`Self::stream_links`].
    #[instrument(level = "debug", skip_all, fields(method = "stream_routes"))]
    pub async fn stream_routes(
        &self,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, RouteMessage>> {
        self.dump_stream::<RouteMessage>(NlMsgType::RTM_GETROUTE)
            .await
    }

    /// Stream a neighbor-table dump frame-by-frame. See
    /// [`Self::stream_links`].
    ///
    /// Note: the kernel returns both unicast neighbors and the
    /// bridge FDB entries together when AF_BRIDGE isn't filtered;
    /// use the typed-config Connection (`stream_fdb` on
    /// `Connection<Route>` when added in 0.17) for FDB-only.
    #[instrument(level = "debug", skip_all, fields(method = "stream_neighbors"))]
    pub async fn stream_neighbors(
        &self,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, NeighborMessage>> {
        self.dump_stream::<NeighborMessage>(NlMsgType::RTM_GETNEIGH)
            .await
    }

    /// Stream an address dump frame-by-frame. See [`Self::stream_links`].
    #[instrument(level = "debug", skip_all, fields(method = "stream_addresses"))]
    pub async fn stream_addresses(
        &self,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, AddressMessage>> {
        self.dump_stream::<AddressMessage>(NlMsgType::RTM_GETADDR)
            .await
    }

    /// Get a network interface by name.
    ///
    /// Returns `None` if the interface doesn't exist.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_link_by_name"))]
    pub async fn get_link_by_name(
        &self,
        name: impl Into<InterfaceRef>,
    ) -> Result<Option<LinkMessage>> {
        match name.into() {
            InterfaceRef::Name(name) => self.get_one_link(0, Some(&name)).await,
            InterfaceRef::Index(idx) => self.get_link_by_index(idx).await,
        }
    }

    /// The ifindex of each of `names` in this connection's namespace: the
    /// devices a filter or action names rather than indexes (#645). One
    /// that does not exist is [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound).
    pub(crate) async fn ifindexes_of(
        &self,
        names: &[&str],
    ) -> Result<std::collections::HashMap<String, u32>> {
        let mut out = std::collections::HashMap::new();
        for name in names {
            if out.contains_key(*name) {
                continue;
            }
            let link = self
                .get_link_by_name(*name)
                .await?
                .ok_or_else(|| self.interface_not_found(*name))?;
            out.insert(name.to_string(), link.ifindex());
        }
        Ok(out)
    }

    /// Get a network interface by index.
    ///
    /// Returns `None` if the interface doesn't exist.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_link_by_index"))]
    pub async fn get_link_by_index(&self, index: u32) -> Result<Option<LinkMessage>> {
        self.get_one_link(index, None).await
    }

    /// One `RTM_GETLINK` for one link, by index or name (#495).
    ///
    /// Both lookups used to dump every link and search the result: O(links)
    /// per call behind every name-taking method, each dump open to
    /// `DumpInterrupted` from an unrelated change. A name also matches the
    /// link's alternative names (`ip link property add … altname`): the
    /// kernel looks names up in one table. One longer than `IFNAMSIZ - 1`
    /// can only be an altname, and goes as `IFLA_ALT_IFNAME`, which
    /// `IFLA_IFNAME`'s policy would refuse.
    async fn get_one_link(&self, index: u32, name: Option<&str>) -> Result<Option<LinkMessage>> {
        const IFNAMSIZ: usize = 16;
        const ALTIFNAMSIZ: usize = 128;

        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETLINK, NLM_F_REQUEST);
        let Ok(index) = i32::try_from(index) else {
            return Ok(None);
        };
        builder.append(&IfInfoMsg::new().with_index(index));
        let by_altname = match name {
            None if index == 0 => return Ok(None),
            None => false,
            Some(name) if name.len() >= ALTIFNAMSIZ => return Ok(None),
            Some(name) if name.len() >= IFNAMSIZ => {
                builder.append_attr_str(super::types::link::IflaAttr::AltIfname as u16, name);
                true
            }
            Some(name) => {
                builder.append_attr_str(super::types::link::IflaAttr::Ifname as u16, name);
                false
            }
        };
        // Boxed for the reason `send_dump` is: every name-taking helper
        // resolves through here before it sends anything, so this sits on
        // nlink's deepest await chains. Unboxed, the facade's
        // `apply::network` overflowed rustc's query depth (#310, #315).
        match Box::pin(self.send_request(builder)).await {
            Ok(response) => self.parse_response(&response).map(Some),
            Err(e) if e.is_no_device() => Ok(None),
            // A kernel without altnames (< 5.5) ignores IFLA_ALT_IFNAME and
            // finds no name at all; no link of that name can exist there.
            Err(e) if by_altname && e.is_invalid_argument() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Wait for an interface's `IFF_UP` flag: [`wait_link`](Self::wait_link)
    /// with [`LinkCond::AdminUp`].
    ///
    /// `IFF_UP` is the administrative state, which
    /// [`set_link_up`](Self::set_link_up) sets before it returns, so after
    /// your own `set_link_up` this waits for nothing. To wait until the
    /// link can carry traffic, wait for [`LinkCond::Running`] or
    /// [`LinkCond::Carrier`] (#524).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::time::Duration;
    ///
    /// use nlink::{Connection, Route};
    /// # async fn f() -> nlink::Result<()> {
    /// let conn = Connection::<Route>::new()?;
    /// // Wait for someone else to bring eth0 up.
    /// conn.wait_link_up("eth0", Duration::from_secs(5)).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "wait_link_up"))]
    pub async fn wait_link_up(
        &self,
        iface: impl Into<InterfaceRef>,
        timeout: Duration,
    ) -> Result<()> {
        self.wait_link(iface, LinkCond::AdminUp, timeout)
            .await
            .map(drop)
    }

    /// Wait until an interface meets `cond`, and return it as it then is.
    ///
    /// Polls with exponential backoff (10 ms, doubling, capped at 100 ms)
    /// until `cond` holds or `timeout` elapses. A poll of a dump cannot
    /// miss a change the way a subscription opened too late can, and
    /// leaves no multicast socket behind.
    ///
    /// Returns `Err(Timeout)` on deadline, and an interface not-found error if
    /// the interface goes away during the wait.
    ///
    /// # Namespace safety
    ///
    /// Takes `impl Into<InterfaceRef>`. A `Name` resolves through netlink,
    /// in the connection's namespace.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::time::Duration;
    ///
    /// use nlink::{Connection, LinkCond, Route};
    /// # async fn f() -> nlink::Result<()> {
    /// let conn = Connection::<Route>::new()?;
    /// conn.set_link_up("veth0").await?;
    /// // Up is immediate; a carrier comes when the peer is up too.
    /// conn.wait_link("veth0", LinkCond::Carrier, Duration::from_secs(5)).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "wait_link"))]
    pub async fn wait_link(
        &self,
        iface: impl Into<InterfaceRef>,
        cond: LinkCond,
        timeout: Duration,
    ) -> Result<LinkMessage> {
        let iface = iface.into();
        let label = match &iface {
            InterfaceRef::Name(n) => n.clone(),
            InterfaceRef::Index(i) => i.to_string(),
        };
        let deadline = std::time::Instant::now() + timeout;
        let mut backoff = Duration::from_millis(10);
        // Resolve once to ifindex so subsequent polls are
        // namespace-correct + cheaper.
        let ifindex = self.resolve_interface(&iface).await?;

        loop {
            let link =
                self.get_link_by_index(ifindex)
                    .await?
                    .ok_or_else(|| self.interface_not_found(label.clone()))?;
            if cond.holds(&link) {
                return Ok(link);
            }
            if std::time::Instant::now() >= deadline {
                return Err(self.socket.stamp(Error::timeout()));
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_millis(100));
        }
    }

    /// Wait until IPv6 duplicate address detection has settled — no
    /// address tentative any more — on `iface`, or on every interface
    /// when `None` (#524).
    ///
    /// An address that DAD found in use elsewhere ends in
    /// [`ErrorDetail::DadFailed`](crate::ErrorDetail::DadFailed), naming every such address: it will never
    /// become usable. Until DAD is done, an address is tentative, and
    /// binding or sending from it fails (`EADDRNOTAVAIL`), which is why
    /// a test that pings over IPv6 straight after configuring it fails.
    /// Polled, like [`wait_link`](Self::wait_link).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::time::Duration;
    ///
    /// use nlink::{Connection, Route};
    /// # async fn f() -> nlink::Result<()> {
    /// let conn = Connection::<Route>::new()?;
    /// conn.wait_addresses_settled(Some("eth0".into()), Duration::from_secs(5)).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "wait_addresses_settled"))]
    pub async fn wait_addresses_settled(
        &self,
        iface: Option<InterfaceRef>,
        timeout: Duration,
    ) -> Result<()> {
        let ifindex = match &iface {
            Some(iface) => Some(self.resolve_interface(iface).await?),
            None => None,
        };
        let deadline = std::time::Instant::now() + timeout;
        let mut backoff = Duration::from_millis(10);
        loop {
            let addresses: Vec<AddressMessage> = self
                .get_addresses()
                .await?
                .into_iter()
                .filter(|a| a.is_ipv6() && ifindex.is_none_or(|i| a.ifindex() == i))
                .collect();
            let failed: Vec<std::net::IpAddr> = addresses
                .iter()
                .filter(|a| a.is_dad_failed())
                .filter_map(|a| a.address)
                .collect();
            if !failed.is_empty() {
                return Err(self.socket.stamp(Error::from(
                    crate::netlink::ErrorDetail::DadFailed { addresses: failed },
                )));
            }
            if !addresses.iter().any(|a| a.is_tentative()) {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(self.socket.stamp(Error::timeout()));
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_millis(100));
        }
    }

    /// Get the kernel-reported per-link statistics for the named or
    /// indexed interface.
    ///
    /// Convenience wrapper around `get_link_by_*` + `LinkMessage::stats()`.
    /// Returns an interface not-found error if no interface matches, and
    /// `Err(InvalidMessage)` if the kernel response didn't include a
    /// stats attribute (rare — most interfaces always report stats).
    ///
    /// # Namespace safety
    ///
    /// Takes `impl Into<InterfaceRef>`. With a `Name` variant, the
    /// initial lookup reads from the namespace this connection is
    /// bound to (via netlink, not `/sys/class/net/`) — so name
    /// resolution is namespace-correct.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::{Connection, Route};
    ///
    /// let conn = Connection::<Route>::new()?;
    /// let stats = conn.get_link_stats("eth0").await?;
    /// println!("rx: {} bytes / {} packets", stats.rx_bytes(), stats.rx_packets());
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_link_stats"))]
    pub async fn get_link_stats(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<crate::netlink::messages::LinkStats> {
        let iface = iface.into();
        let label = match &iface {
            InterfaceRef::Name(n) => n.clone(),
            InterfaceRef::Index(i) => i.to_string(),
        };
        let link = self
            .get_link_by_name(iface)
            .await?
            .ok_or_else(|| self.interface_not_found(label.clone()))?;
        link.stats().copied().ok_or_else(|| {
            Error::invalid_message(format!(
                "interface {label} response did not include link-stats attribute"
            ))
        })
    }

    /// Resolve an interface reference to an index.
    ///
    /// This method is namespace-safe: it uses netlink to resolve interface names,
    /// which queries the namespace that this connection is bound to.
    ///
    /// - If the reference is already an index, returns it directly.
    /// - If the reference is a name, queries the kernel via netlink.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) if the interface name doesn't exist.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Route, InterfaceRef};
    ///
    /// let conn = Connection::<Route>::new()?;
    ///
    /// // Resolve a name
    /// let ifindex = conn.resolve_interface(&InterfaceRef::name("eth0")).await?;
    ///
    /// // Pass-through an index
    /// let ifindex = conn.resolve_interface(&InterfaceRef::index(2)).await?;
    /// assert_eq!(ifindex, 2);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "resolve_interface"))]
    pub async fn resolve_interface(&self, iface: &InterfaceRef) -> Result<u32> {
        match iface {
            InterfaceRef::Index(idx) => Ok(*idx),
            InterfaceRef::Name(name) => {
                let link = self
                    .get_link_by_name(name)
                    .await?
                    .ok_or_else(|| self.interface_not_found(name))?;
                Ok(link.ifindex())
            }
        }
    }

    /// Resolve an optional interface reference.
    ///
    /// Returns `None` if the input is `None`, otherwise resolves the reference.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "resolve_interface_opt"))]
    pub async fn resolve_interface_opt(&self, iface: Option<&InterfaceRef>) -> Result<Option<u32>> {
        match iface {
            Some(iface) => Ok(Some(self.resolve_interface(iface).await?)),
            None => Ok(None),
        }
    }

    /// Build a map of interface index to name.
    ///
    /// This is a convenience method for code that needs to look up interface
    /// names by index (e.g., when displaying addresses, routes, or TC objects).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let names = conn.get_interface_names().await?;
    /// let addresses = conn.get_addresses().await?;
    /// for addr in addresses {
    ///     let name = names.get(&addr.ifindex()).map(|s| s.as_str()).unwrap_or("?");
    ///     println!("{}: {:?}", name, addr.address());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_interface_names"))]
    pub async fn get_interface_names(&self) -> Result<std::collections::HashMap<u32, String>> {
        let links = self.get_links().await?;
        Ok(links
            .into_iter()
            .filter_map(|l| l.name.clone().map(|n| (l.ifindex(), n)))
            .collect())
    }

    /// Get interface name by index.
    ///
    /// This is a convenience method for getting a single interface name.
    /// For looking up multiple names, prefer [`Connection::get_interface_names()`]
    /// to build a lookup map.
    ///
    /// Returns `None` if no interface with that index exists.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # let route = conn.get_routes().await?.into_iter().next().unwrap();
    /// if let Some(name) = conn.interface_name(route.oif().unwrap()).await? {
    ///     println!("Route via {}", name);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "interface_name"))]
    pub async fn interface_name(&self, ifindex: u32) -> Result<Option<String>> {
        let link = self.get_link_by_index(ifindex).await?;
        Ok(link.and_then(|l| l.name))
    }

    /// Get interface name by index, or return a default value.
    ///
    /// This is a convenience method for display purposes when you want
    /// a fallback value like "-" or "?" for unknown interfaces.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # let route = conn.get_routes().await?.into_iter().next().unwrap();
    /// let dev = conn.interface_name_or(route.oif().unwrap_or(0), "-").await?;
    /// println!("Route via {}", dev);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "interface_name_or"))]
    pub async fn interface_name_or(&self, ifindex: u32, default: &str) -> Result<String> {
        Ok(self
            .interface_name(ifindex)
            .await?
            .unwrap_or_else(|| default.to_string()))
    }

    /// Get bond information for a bond interface.
    ///
    /// Returns the bond configuration as reported by the kernel.
    ///
    /// # Errors
    ///
    /// Returns an error if the interface doesn't exist or is not a bond.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let info = conn.get_bond_info("bond0").await?;
    /// println!("Mode: {:?}, miimon: {}ms", info.bond_mode(), info.miimon);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_bond_info"))]
    pub async fn get_bond_info(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<crate::netlink::messages::BondInfo> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        let link = self
            .get_link_by_index(ifindex)
            .await?
            .ok_or_else(|| self.interface_not_found(format!("ifindex {ifindex}")))?;
        link.bond_info()
            .ok_or_else(|| Error::invalid_message("not a bond interface"))
    }

    /// List all slaves of a bond interface with their status.
    ///
    /// Returns a list of `(LinkMessage, BondSlaveInfo)` pairs for each slave.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let slaves = conn.get_bond_slaves("bond0").await?;
    /// for (link, info) in &slaves {
    ///     println!("{}: state={:?}, mii={:?}",
    ///         link.name_or("?"), info.state, info.mii_status);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_bond_slaves"))]
    pub async fn get_bond_slaves(
        &self,
        bond: impl Into<InterfaceRef>,
    ) -> Result<Vec<(LinkMessage, crate::netlink::messages::BondSlaveInfo)>> {
        let bond_ifindex = self.resolve_interface(&bond.into()).await?;
        let all_links = self.get_links().await?;
        let mut slaves = Vec::new();

        for link in all_links {
            if link.master() == Some(bond_ifindex)
                && let Some(info) = link.bond_slave_info()
            {
                slaves.push((link, info));
            }
        }

        Ok(slaves)
    }

    /// Get all IP addresses.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let addresses = conn.get_addresses().await?;
    /// for addr in addresses {
    ///     println!("{:?}/{} on idx {}", addr.address(), addr.prefix_len(), addr.ifindex());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_addresses"))]
    pub async fn get_addresses(&self) -> Result<Vec<AddressMessage>> {
        self.dump_typed(NlMsgType::RTM_GETADDR).await
    }

    /// Get IP addresses for a specific interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_addresses_by_name"))]
    pub async fn get_addresses_by_name(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<Vec<AddressMessage>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_addresses_by_index(ifindex).await
    }

    /// Get IP addresses for a specific interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_addresses_by_index"))]
    pub async fn get_addresses_by_index(&self, ifindex: u32) -> Result<Vec<AddressMessage>> {
        let addresses = self.get_addresses().await?;
        Ok(addresses
            .into_iter()
            .filter(|a| a.ifindex() == ifindex)
            .collect())
    }

    /// Get an address entry by IP address.
    ///
    /// Returns `None` if no address entry matches the given IP.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use std::net::IpAddr;
    ///
    /// let ip: IpAddr = "192.168.1.100".parse()?;
    /// if let Some(addr) = conn.get_address_by_ip(ip).await? {
    ///     println!("Found on interface index {}", addr.ifindex());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_address_by_ip"))]
    pub async fn get_address_by_ip(
        &self,
        addr: std::net::IpAddr,
    ) -> Result<Option<AddressMessage>> {
        let addresses = self.get_addresses().await?;
        Ok(addresses.into_iter().find(|a| a.address == Some(addr)))
    }

    /// Get all routes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let routes = conn.get_routes().await?;
    /// for route in routes {
    ///     println!("{:?}/{}", route.destination(), route.dst_len());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_routes"))]
    pub async fn get_routes(&self) -> Result<Vec<RouteMessage>> {
        self.dump_typed(NlMsgType::RTM_GETROUTE).await
    }

    /// Get routes for a specific table.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_routes_for_table"))]
    pub async fn get_routes_for_table(&self, table_id: u32) -> Result<Vec<RouteMessage>> {
        let routes = self.get_routes().await?;
        Ok(routes
            .into_iter()
            .filter(|r| r.table_id() == table_id)
            .collect())
    }

    /// The route the kernel would use to reach `dest`: a FIB lookup, what
    /// `ip route get` does — policy rules, the longest prefix, the route's
    /// type — rather than a search of the dump.
    ///
    /// The kernel answers a lookup that ends in a route it will not use
    /// with an error, and nlink passes it on: `ENETUNREACH` when nothing
    /// matches ([`Error::is_network_unreachable`]), `EHOSTUNREACH` for an
    /// `unreachable` route, `EACCES` for `prohibit`
    /// ([`Error::is_permission_denied`]), `EINVAL` for `blackhole`.
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let route = conn.lookup_route("192.0.2.1".parse()?).await?;
    /// println!("via {:?} dev {:?}", route.gateway(), route.oif());
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "lookup_route"))]
    pub async fn lookup_route(&self, dest: std::net::IpAddr) -> Result<RouteMessage> {
        use crate::netlink::types::route::{RtMsg, RtaAttr};
        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETROUTE, NLM_F_REQUEST);
        let (family, len, addr) = match dest {
            std::net::IpAddr::V4(a) => (libc::AF_INET, 32, a.octets().to_vec()),
            std::net::IpAddr::V6(a) => (libc::AF_INET6, 128, a.octets().to_vec()),
        };
        builder.append(&RtMsg::new().with_family(family as u8).with_dst_len(len));
        builder.append_attr(RtaAttr::Dst as u16, &addr);
        let response = self.send_request(builder).await?;
        self.parse_response(&response)
    }

    /// The route the kernel would use for `destination`: a FIB lookup,
    /// [`lookup_route`](Self::lookup_route) for one family.
    ///
    /// It was documented as "a specific route by destination and prefix
    /// length", and it never was one (#510): `RTM_GETROUTE` without a dump
    /// is a lookup of the address. `prefix_len` was sent as the request's
    /// `dst_len`, which the kernel ignores — or, with strict checking,
    /// refuses unless it is 32. It is ignored now. `None` when the
    /// kernel reports no such route (`ENOENT`); an unreachable destination
    /// is the error [`lookup_route`](Self::lookup_route) describes.
    #[deprecated(
        since = "0.31.0",
        note = "a FIB lookup of the address, not an exact-prefix get; use `lookup_route`"
    )]
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_route_v4"))]
    pub async fn get_route_v4(
        &self,
        destination: std::net::Ipv4Addr,
        prefix_len: u8,
    ) -> Result<Option<RouteMessage>> {
        let _ = prefix_len;
        match self.lookup_route(destination.into()).await {
            Ok(route) => Ok(Some(route)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The route the kernel would use for `destination`: a FIB lookup,
    /// [`lookup_route`](Self::lookup_route) for one family.
    ///
    /// It was documented as "a specific route by destination and prefix
    /// length", and it never was one (#510): `RTM_GETROUTE` without a dump
    /// is a lookup of the address. `prefix_len` was sent as the request's
    /// `dst_len`, which the kernel ignores — or, with strict checking,
    /// refuses unless it is 128. It is ignored now. `None` when the
    /// kernel reports no such route (`ENOENT`); an unreachable destination
    /// is the error [`lookup_route`](Self::lookup_route) describes.
    #[deprecated(
        since = "0.31.0",
        note = "a FIB lookup of the address, not an exact-prefix get; use `lookup_route`"
    )]
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_route_v6"))]
    pub async fn get_route_v6(
        &self,
        destination: std::net::Ipv6Addr,
        prefix_len: u8,
    ) -> Result<Option<RouteMessage>> {
        let _ = prefix_len;
        match self.lookup_route(destination.into()).await {
            Ok(route) => Ok(Some(route)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Get all neighbor entries.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let neighbors = conn.get_neighbors().await?;
    /// for neigh in neighbors {
    ///     println!("{:?} -> {:?}", neigh.destination(), neigh.lladdr());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_neighbors"))]
    pub async fn get_neighbors(&self) -> Result<Vec<NeighborMessage>> {
        self.dump_typed(NlMsgType::RTM_GETNEIGH).await
    }

    /// Get neighbor entries for a specific interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// See also [`get_neighbors_by_index`](Self::get_neighbors_by_index) in the neighbor module.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_neighbors_by_name"))]
    pub async fn get_neighbors_by_name(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<Vec<NeighborMessage>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_neighbors_by_index(ifindex).await
    }

    /// Get all routing rules.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let rules = conn.get_rules().await?;
    /// for rule in rules {
    ///     println!("{}: {:?} -> table {}", rule.priority(), rule.source(), rule.table_id());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_rules"))]
    pub async fn get_rules(&self) -> Result<Vec<RuleMessage>> {
        self.dump_typed(NlMsgType::RTM_GETRULE).await
    }

    /// Get routing rules for a specific address family.
    ///
    /// Pass `AddressFamily::unspec()` to dump every family.
    ///
    /// (Renamed from `get_rules_for_family_typed` in 0.21 — the raw-`u8`
    /// sibling was removed in the same release.)
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_rules_for_family"))]
    pub async fn get_rules_for_family(&self, family: AddressFamily) -> Result<Vec<RuleMessage>> {
        let raw = family.as_u8();
        let rules = self.get_rules().await?;
        // AF_UNSPEC (0) is the "no filter" form: return everything.
        if raw == 0 {
            return Ok(rules);
        }
        Ok(rules.into_iter().filter(|r| r.family() == raw).collect())
    }

    /// Get IPv4 routing rules.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_rules_v4"))]
    pub async fn get_rules_v4(&self) -> Result<Vec<RuleMessage>> {
        self.get_rules_for_family(AddressFamily::v4()).await
    }

    /// Get IPv6 routing rules.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_rules_v6"))]
    pub async fn get_rules_v6(&self) -> Result<Vec<RuleMessage>> {
        self.get_rules_for_family(AddressFamily::v6()).await
    }

    /// Add a routing rule.
    ///
    /// Use the [`super::rule::RuleBuilder`] to construct the rule.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::rule::RuleBuilder;
    ///
    /// // Add a rule to lookup table 100 for traffic from 10.0.0.0/8
    /// conn.add_rule(
    ///     RuleBuilder::v4()
    ///         .priority(100)
    ///         .from_v4("10.0.0.0".parse()?, 8)
    ///         .table(100)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_rule"))]
    pub async fn add_rule(&self, rule: super::rule::RuleBuilder) -> Result<()> {
        let builder = rule.build()?;
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_rule"))
    }

    /// [`add_rule`](Self::add_rule) without `NLM_F_EXCL`, beside a rule the
    /// kernel's lenient check takes for it (#793).
    pub(crate) async fn add_rule_alongside(&self, rule: super::rule::RuleBuilder) -> Result<()> {
        let builder = rule.build_alongside()?;
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_rule"))
    }

    /// Delete a routing rule.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::rule::RuleBuilder;
    ///
    /// conn.del_rule(
    ///     RuleBuilder::v4()
    ///         .priority(100)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_rule"))]
    pub async fn del_rule(&self, rule: super::rule::RuleBuilder) -> Result<()> {
        let builder = rule.build_delete()?;
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_rule"))
    }

    /// Delete a routing rule if it exists (#718). `Ok(true)` when one was
    /// deleted, `Ok(false)` when none matched: the kernel answers that
    /// with `ENOENT`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_rule_if_exists"))]
    pub async fn del_rule_if_exists(&self, rule: super::rule::RuleBuilder) -> Result<bool> {
        match self.del_rule(rule).await {
            Ok(()) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Delete a rule by priority: the first at it, whatever it does. Until
    /// 0.32 only a rule looking the main table up was found (#667).
    ///
    /// (Renamed from `del_rule_by_priority_typed` in 0.21 — the raw-`u8`
    /// sibling was removed in the same release.)
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_rule_by_priority"))]
    pub async fn del_rule_by_priority(&self, family: AddressFamily, priority: u32) -> Result<()> {
        let rule = super::rule::RuleBuilder::new(family.as_u8()).priority(priority);
        self.del_rule(rule).await
    }

    /// Flush all non-default routing rules for a family.
    ///
    /// This deletes all rules except the default ones (priority 0, 32766, 32767).
    ///
    /// (Renamed from `flush_rules_typed` in 0.21 — the raw-`u8` sibling
    /// was removed in the same release.)
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_rules"))]
    pub async fn flush_rules(&self, family: AddressFamily) -> Result<()> {
        let rules = self.get_rules_for_family(family).await?;

        for rule in rules {
            // Skip default rules
            if rule.is_default() {
                continue;
            }
            // Gone already is what a flush wants; anything else is an
            // error, which this used to swallow (#667).
            match self.del_rule_by_priority(family, rule.priority()).await {
                Err(e) if !e.is_not_found() => return Err(e),
                _ => {}
            }
        }

        Ok(())
    }

    /// Get all qdiscs.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let qdiscs = conn.get_qdiscs().await?;
    /// for qdisc in qdiscs {
    ///     println!("{}: {}", qdisc.ifindex(), qdisc.kind().unwrap_or("?"));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_qdiscs"))]
    pub async fn get_qdiscs(&self) -> Result<Vec<TcMessage>> {
        self.dump_typed(NlMsgType::RTM_GETQDISC).await
    }

    /// Get all qdiscs, optionally including "invisible" ones.
    ///
    /// The kernel hides auto-created default qdiscs (e.g. the implicit
    /// `pfifo_fast` / `mq` on a fresh device) from `RTM_GETQDISC` dumps
    /// unless the request carries the `TCA_DUMP_INVISIBLE` flag. Passing
    /// `invisible = true` appends that flag, matching
    /// `tc qdisc show invisible`. With `invisible = false` this is
    /// identical to [`get_qdiscs`](Self::get_qdiscs).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_qdiscs_full"))]
    pub async fn get_qdiscs_full(&self, invisible: bool) -> Result<Vec<TcMessage>> {
        if !invisible {
            return self.get_qdiscs().await;
        }

        // TCA_DUMP_INVISIBLE is an empty flag attribute (rtnetlink.h).
        const TCA_DUMP_INVISIBLE: u16 = 10;

        let mut builder = dump_request(NlMsgType::RTM_GETQDISC);
        let mut header_buf = Vec::new();
        TcMessage::write_dump_header(&mut header_buf);
        builder.append_bytes(&header_buf);
        builder.append_attr_empty(TCA_DUMP_INVISIBLE);

        let responses = self.send_dump(builder).await?;
        let mut parsed = Vec::with_capacity(responses.len());
        for response in responses {
            if response.len() < NLMSG_HDRLEN {
                continue;
            }
            if let Ok(msg) = TcMessage::from_bytes(&response[NLMSG_HDRLEN..]) {
                parsed.push(msg);
            }
        }
        Ok(parsed)
    }

    /// Get qdiscs for a specific interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_qdiscs_by_name"))]
    pub async fn get_qdiscs_by_name(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<Vec<TcMessage>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_qdiscs_by_index(ifindex).await
    }

    /// Get qdiscs for a specific interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_qdiscs_by_index"))]
    pub async fn get_qdiscs_by_index(&self, ifindex: u32) -> Result<Vec<TcMessage>> {
        let qdiscs = self.get_qdiscs().await?;
        Ok(qdiscs
            .into_iter()
            .filter(|q| q.ifindex() == ifindex)
            .collect())
    }


    /// Dump TC entities for **one** interface.
    ///
    /// `tc_dump_tclass` and `tc_dump_tfilter` both open with
    ///
    /// ```c
    /// dev = dev_get_by_index(net, tcm->tcm_ifindex);
    /// if (!dev)
    ///     return 0;
    /// ```
    ///
    /// so a request carrying `tcm_ifindex == 0` — which is what a
    /// zeroed [`TcMsg`] dump header produces — ends the dump straight
    /// away with `NLMSG_DONE` and no entries. Not an error: an empty,
    /// successful dump. Class and filter dumps must name their device
    /// (#286); qdisc dumps are the exception and work either way.
    ///
    /// A **filter** dump additionally needs `tcm_parent`: with it unset
    /// `tc_dump_tfilter` falls back to `dev->qdisc` and walks the root
    /// qdisc alone, so filters on the ingress/clsact hooks never appear.
    #[instrument(level = "debug", skip(self), fields(method = "dump_tc_for_index"))]
    async fn dump_tc_for_index(
        &self,
        msg_type: u16,
        ifindex: u32,
        parent: Option<TcHandle>,
    ) -> Result<Vec<TcMessage>> {
        let mut builder = dump_request(msg_type);
        let mut header = crate::netlink::types::tc::TcMsg::new().with_ifindex(ifindex as i32);
        if let Some(parent) = parent {
            header = header.with_parent(parent.as_raw());
        }
        builder.append_bytes(header.as_bytes());

        let responses = self.send_dump(builder).await?;
        let mut parsed = Vec::with_capacity(responses.len());
        for response in responses {
            if response.len() < NLMSG_HDRLEN {
                continue;
            }
            let Ok(mut msg) = TcMessage::from_bytes(&response[NLMSG_HDRLEN..]) else {
                continue;
            };
            if let Ok(header) = NlMsgHdr::from_bytes(&response[..NLMSG_HDRLEN]) {
                msg.set_msg_type(header.nlmsg_type);
            }
            // A filter dump opens each (parent, priority, protocol)
            // chain with the `tcf_proto` itself: handle 0, the right
            // kind, and no `TCA_OPTIONS`. `tc filter show` prints it as
            // the bare "filter protocol ip pref 1 flower chain 0" line
            // above the real entries. It is not a filter — it carries
            // no match criteria and cannot be deleted — so returning it
            // just doubles every count and hands callers a message with
            // nothing in it.
            if msg_type == NlMsgType::RTM_GETTFILTER && msg.handle_raw() == 0 {
                continue;
            }
            parsed.push(msg);
        }
        Ok(parsed)
    }

    /// Every interface index in this connection's namespace.
    async fn all_ifindexes(&self) -> Result<Vec<u32>> {
        Ok(self
            .get_links()
            .await?
            .into_iter()
            .map(|l| l.ifindex())
            .collect())
    }

    /// Get all TC classes.
    ///
    /// The kernel has no "all devices" class dump, so this walks every
    /// interface and dumps each one (#286). Prefer
    /// [`get_classes_by_index`](Self::get_classes_by_index) when you
    /// know the device — it is one dump instead of N+1.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_classes"))]
    pub async fn get_classes(&self) -> Result<Vec<TcMessage>> {
        let mut out = Vec::new();
        for ifindex in self.all_ifindexes().await? {
            out.extend(
                self.dump_tc_for_index(NlMsgType::RTM_GETTCLASS, ifindex, None)
                    .await?,
            );
        }
        Ok(out)
    }

    /// Get TC classes for a specific interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_classes_by_name"))]
    pub async fn get_classes_by_name(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<Vec<TcMessage>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_classes_by_index(ifindex).await
    }

    /// Get TC classes for a specific interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_classes_by_index"))]
    pub async fn get_classes_by_index(&self, ifindex: u32) -> Result<Vec<TcMessage>> {
        self.dump_tc_for_index(NlMsgType::RTM_GETTCLASS, ifindex, None)
            .await
    }

    /// Get all TC filters.
    ///
    /// Like [`get_classes`](Self::get_classes), one dump per interface
    /// — the kernel refuses to enumerate filters device-lessly (#286).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_filters"))]
    pub async fn get_filters(&self) -> Result<Vec<TcMessage>> {
        let mut out = Vec::new();
        for ifindex in self.all_ifindexes().await? {
            out.extend(
                self.dump_filters_everywhere(ifindex).await?,
            );
        }
        Ok(out)
    }

    /// Get TC filters for a specific interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_filters_by_name"))]
    pub async fn get_filters_by_name(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<Vec<TcMessage>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_filters_by_index(ifindex).await
    }

    /// Get TC filters for a specific interface by index.
    ///
    /// Sweeps the root qdisc **and** the ingress/clsact hooks — a
    /// parent-less filter dump only sees the root qdisc, which is why
    /// `list_bpf_programs` (clsact) and the `RateLimiter` ingress
    /// reconcile (ingress) both read back nothing (#286).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_filters_by_index"))]
    pub async fn get_filters_by_index(&self, ifindex: u32) -> Result<Vec<TcMessage>> {
        self.dump_filters_everywhere(ifindex).await
    }

    /// Every parent a filter can hang off on one interface.
    ///
    /// `None` is the root qdisc; the three hook handles cover classic
    /// `ingress` and both clsact hooks. `clsact_find` rejects a parent
    /// whose minor is neither `TC_H_MIN_INGRESS` nor `TC_H_MIN_EGRESS`,
    /// so the two hooks have to be asked for separately.
    const FILTER_DUMP_PARENTS: [Option<TcHandle>; 4] = [
        None,
        Some(TcHandle::INGRESS),
        Some(TcHandle::CLSACT_INGRESS),
        Some(TcHandle::CLSACT_EGRESS),
    ];

    async fn dump_filters_everywhere(&self, ifindex: u32) -> Result<Vec<TcMessage>> {
        let mut out = Vec::new();
        for parent in Self::FILTER_DUMP_PARENTS {
            match self
                .dump_tc_for_index(NlMsgType::RTM_GETTFILTER, ifindex, parent)
                .await
            {
                Ok(filters) => out.extend(filters),
                // No qdisc at that hook: the kernel answers EINVAL
                // ("Parent Qdisc doesn't exists"), which for a sweep
                // just means there is nothing there.
                Err(e) if e.is_invalid_argument() || e.is_not_found() => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Stream a qdisc dump frame-by-frame.
    ///
    /// O(1) memory in the number of qdiscs, vs `get_qdiscs` which
    /// buffers the full response. See [`Self::stream_links`] for
    /// the full semantics. Right answer on hosts with many TC-heavy
    /// interfaces (BGP peers per-route TC, telecom DPDK fanout,
    /// per-pod CNI plugins).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use tokio_stream::StreamExt;
    /// let mut s = conn.stream_qdiscs().await?;
    /// while let Some(q) = s.next().await {
    ///     let q = q?;
    ///     // process one qdisc with O(1) memory
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(level = "debug", skip_all, fields(method = "stream_qdiscs"))]
    pub async fn stream_qdiscs(
        &self,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, TcMessage>> {
        self.dump_stream::<TcMessage>(NlMsgType::RTM_GETQDISC).await
    }

    /// Was: stream a TC class dump. The kernel's class dump answers for one
    /// interface (`tc_dump_tclass` looks up `tcm_ifindex`), and this sent
    /// none, so the stream always ended empty (#778).
    #[deprecated(
        since = "0.32.0",
        note = "always empty: a class dump is per interface; use `stream_classes_by_index` (#778)"
    )]
    #[instrument(level = "debug", skip_all, fields(method = "stream_classes"))]
    pub async fn stream_classes(
        &self,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, TcMessage>> {
        self.dump_stream::<TcMessage>(NlMsgType::RTM_GETTCLASS)
            .await
    }

    /// Stream one interface's TC classes frame by frame (#778): what
    /// [`get_classes_by_index`](Self::get_classes_by_index) returns, without
    /// buffering the dump. See [`Self::stream_qdiscs`].
    #[instrument(level = "debug", skip_all, fields(method = "stream_classes_by_index"))]
    pub async fn stream_classes_by_index(
        &self,
        ifindex: u32,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, TcMessage>> {
        let header = crate::netlink::types::tc::TcMsg::new().with_ifindex(ifindex as i32);
        self.dump_stream_with_body::<TcMessage>(NlMsgType::RTM_GETTCLASS, header.as_bytes())
            .await
    }

    /// Was: stream a TC filter dump. The kernel's filter dump answers for
    /// one interface and one parent (`tc_dump_tfilter`), and this sent
    /// neither, so the stream always ended empty (#778).
    #[deprecated(
        since = "0.32.0",
        note = "always empty: a filter dump is per interface and parent; use `stream_filters_by_index` (#778)"
    )]
    #[instrument(level = "debug", skip_all, fields(method = "stream_filters"))]
    pub async fn stream_filters(
        &self,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, TcMessage>> {
        self.dump_stream::<TcMessage>(NlMsgType::RTM_GETTFILTER)
            .await
    }

    /// Stream the TC filters under one parent of one interface frame by
    /// frame (#778): the root qdisc's with `parent` `None`, a hook's with
    /// [`TcHandle::INGRESS`], [`TcHandle::CLSACT_INGRESS`] or
    /// [`TcHandle::CLSACT_EGRESS`]. See [`Self::stream_qdiscs`].
    ///
    /// The kernel opens each priority's filters with the classifier itself,
    /// as `tc filter show` prints it: handle 0 and no options. It is not a
    /// filter; [`get_filters_by_index`](Self::get_filters_by_index) leaves
    /// it out, and a stream's reader skips `handle_raw() == 0`. A parent
    /// with no qdisc ends the stream with `EINVAL`.
    #[instrument(level = "debug", skip_all, fields(method = "stream_filters_by_index"))]
    pub async fn stream_filters_by_index(
        &self,
        ifindex: u32,
        parent: Option<TcHandle>,
    ) -> Result<crate::netlink::dump_stream::DumpStream<'_, Route, TcMessage>> {
        let mut header = crate::netlink::types::tc::TcMsg::new().with_ifindex(ifindex as i32);
        if let Some(parent) = parent {
            header = header.with_parent(parent.as_raw());
        }
        self.dump_stream_with_body::<TcMessage>(NlMsgType::RTM_GETTFILTER, header.as_bytes())
            .await
    }

    /// Get TC filters for a specific interface, filtered by parent handle.
    ///
    /// Equivalent to `get_filters_by_name(...).await?` followed by a
    /// client-side `.filter(|f| f.parent() == parsed_parent)`. Useful for
    /// reconcile-style consumers that need targeted teardown without
    /// scanning every filter on the interface.
    ///
    /// `parent` accepts the standard `tc` handle syntax: `"1:"`, `"1:5"`,
    /// `"root"`, `"ingress"`, `"clsact"`. Returns `Error::invalid_message`
    /// for unparseable handles.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_filters_by_parent"))]
    pub async fn get_filters_by_parent(
        &self,
        iface: impl Into<InterfaceRef>,
        parent: TcHandle,
    ) -> Result<Vec<TcMessage>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_filters_by_parent_index(ifindex, parent).await
    }

    /// Get TC filters by interface index, filtered by parent handle.
    ///
    /// Namespace-safe variant of [`Connection::get_filters_by_parent`].
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_filters_by_parent_index")
    )]
    pub async fn get_filters_by_parent_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
    ) -> Result<Vec<TcMessage>> {
        self.dump_tc_for_index(NlMsgType::RTM_GETTFILTER, ifindex, Some(parent))
            .await
    }

    /// Get all TC filter chains for an interface.
    ///
    /// Filter chains provide logical grouping of filters for better
    /// performance and organization (Linux 4.1+).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let chains = conn.get_tc_chains("eth0", TcHandle::INGRESS).await?;
    /// for chain in chains {
    ///     println!("Chain: {}", chain);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_tc_chains"))]
    pub async fn get_tc_chains(
        &self,
        ifname: impl Into<InterfaceRef>,
        parent: TcHandle,
    ) -> Result<Vec<u32>> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        self.get_tc_chains_by_index(ifindex, parent).await
    }

    /// Get all TC filter chains for an interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_tc_chains_by_index"))]
    pub async fn get_tc_chains_by_index(&self, ifindex: u32, parent: TcHandle) -> Result<Vec<u32>> {
        use super::types::tc::TcMsg;

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent.as_raw());

        let mut builder = dump_request(NlMsgType::RTM_GETCHAIN);
        builder.append(&tcmsg);

        let responses = self.send_dump(builder).await?;
        let mut chains = Vec::new();

        for response in responses {
            if response.len() < NLMSG_HDRLEN {
                continue;
            }
            let payload = &response[NLMSG_HDRLEN..];
            if let Ok(tc) = TcMessage::from_bytes(payload)
                && let Some(chain) = tc.chain()
            {
                chains.push(chain);
            }
        }

        Ok(chains)
    }

    /// Add a TC filter chain.
    ///
    /// Chains provide logical grouping of filters (Linux 4.1+).
    /// Chain 0 is created automatically when adding filters.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// // Create chain 100 on ingress qdisc
    /// conn.add_tc_chain("eth0", TcHandle::INGRESS, 100).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_tc_chain"))]
    pub async fn add_tc_chain(
        &self,
        ifname: impl Into<InterfaceRef>,
        parent: TcHandle,
        chain: u32,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        self.add_tc_chain_by_index(ifindex, parent, chain).await
    }

    /// Add a TC filter chain by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_tc_chain_by_index"))]
    pub async fn add_tc_chain_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        chain: u32,
    ) -> Result<()> {
        use super::types::tc::{TcMsg, TcaAttr};

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent.as_raw());

        let mut builder = create_request(NlMsgType::RTM_NEWCHAIN);
        builder.append(&tcmsg);
        builder.append_attr_u32(TcaAttr::Chain as u16, chain);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_tc_chain"))
    }

    /// Delete a TC filter chain.
    ///
    /// All filters in the chain must be deleted before the chain can be removed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.del_tc_chain("eth0", TcHandle::INGRESS, 100).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_tc_chain"))]
    pub async fn del_tc_chain(
        &self,
        ifname: impl Into<InterfaceRef>,
        parent: TcHandle,
        chain: u32,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&ifname.into()).await?;
        self.del_tc_chain_by_index(ifindex, parent, chain).await
    }

    /// Delete a TC filter chain by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_tc_chain_by_index"))]
    pub async fn del_tc_chain_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        chain: u32,
    ) -> Result<()> {
        use super::types::tc::{TcMsg, TcaAttr};

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent.as_raw());

        let mut builder = create_request(NlMsgType::RTM_DELCHAIN);
        builder.append(&tcmsg);
        builder.append_attr_u32(TcaAttr::Chain as u16, chain);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_tc_chain"))
    }

    /// Get the root qdisc for an interface (parent == ROOT).
    ///
    /// Returns `None` if no root qdisc is configured.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// if let Some(root) = conn.get_root_qdisc_by_name("eth0").await? {
    ///     println!("Root qdisc: {}", root.kind().unwrap_or("?"));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_root_qdisc_by_name"))]
    pub async fn get_root_qdisc_by_name(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<Option<TcMessage>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_root_qdisc_by_index(ifindex).await
    }

    /// Get the root qdisc for an interface by index.
    ///
    /// Returns `None` if no root qdisc is configured.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_root_qdisc_by_index"))]
    pub async fn get_root_qdisc_by_index(&self, ifindex: u32) -> Result<Option<TcMessage>> {
        let qdiscs = self.get_qdiscs().await?;
        Ok(qdiscs
            .into_iter()
            .find(|q| q.ifindex() == ifindex && q.is_root()))
    }

    /// Get a qdisc by interface name and handle.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// // Get the qdisc with handle 1:0 on eth0
    /// if let Some(qdisc) = conn.get_qdisc_by_handle("eth0", TcHandle::major_only(1)).await? {
    ///     println!("Found qdisc: {}", qdisc.kind().unwrap_or("?"));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_qdisc_by_handle"))]
    pub async fn get_qdisc_by_handle(
        &self,
        ifname: &str,
        handle: TcHandle,
    ) -> Result<Option<TcMessage>> {
        let ifindex = self
            .resolve_interface(&InterfaceRef::Name(ifname.to_string()))
            .await?;
        self.get_qdisc_by_handle_index(ifindex, handle).await
    }

    /// Get a qdisc by interface index and handle.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// // Get the qdisc with handle 1:0 on interface index 2
    /// if let Some(qdisc) = conn.get_qdisc_by_handle_index(2, TcHandle::major_only(1)).await? {
    ///     println!("Found qdisc: {}", qdisc.kind().unwrap_or("?"));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_qdisc_by_handle_index")
    )]
    pub async fn get_qdisc_by_handle_index(
        &self,
        ifindex: u32,
        handle: TcHandle,
    ) -> Result<Option<TcMessage>> {
        let qdiscs = self.get_qdiscs().await?;
        Ok(qdiscs
            .into_iter()
            .find(|q| q.ifindex() == ifindex && q.handle() == handle))
    }

    /// Get netem options for an interface, if a netem qdisc is configured at root.
    ///
    /// This is a convenience method that returns `Some` only if a netem qdisc
    /// is the root qdisc and its options can be parsed.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// if let Some(netem) = conn.get_netem_by_name("eth0").await? {
    ///     if let Some(delay) = netem.delay() {
    ///         println!("Delay: {:?}", delay);
    ///     }
    ///     if let Some(loss) = netem.loss() {
    ///         println!("Loss: {:.2}%", loss);
    ///     }
    ///     if let Some(rate) = netem.rate_bps() {
    ///         println!("Rate limit: {} bytes/sec", rate);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_netem_by_name"))]
    pub async fn get_netem_by_name(
        &self,
        iface: impl Into<InterfaceRef>,
    ) -> Result<Option<super::tc_options::NetemOptions>> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_netem_by_index(ifindex).await
    }

    /// Get netem options for an interface by index.
    ///
    /// Returns `None` if no netem qdisc is configured at root.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_netem_by_index"))]
    pub async fn get_netem_by_index(
        &self,
        ifindex: u32,
    ) -> Result<Option<super::tc_options::NetemOptions>> {
        use super::tc_options::QdiscOptions;
        let root = self.get_root_qdisc_by_index(ifindex).await?;
        Ok(match root.and_then(|q| q.options()) {
            Some(QdiscOptions::Netem(opts)) => Some(opts),
            _ => None,
        })
    }
}

// ============================================================================
// Link State Management
// ============================================================================

use super::types::link::{IfInfoMsg, iff};

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Bring a network interface up.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.set_link_up("eth0").await?;
    /// conn.set_link_up(5u32).await?;  // by index
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_up"))]
    pub async fn set_link_up(&self, iface: impl Into<InterfaceRef>) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_up_by_index(ifindex).await
    }

    /// Bring a network interface up by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_up_by_index"))]
    pub async fn set_link_up_by_index(&self, ifindex: u32) -> Result<()> {
        self.set_link_state_by_index(ifindex, true).await
    }

    /// Bring a network interface down.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.set_link_down("eth0").await?;
    /// conn.set_link_down(5u32).await?;  // by index
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_down"))]
    pub async fn set_link_down(&self, iface: impl Into<InterfaceRef>) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_down_by_index(ifindex).await
    }

    /// Bring a network interface down by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_down_by_index"))]
    pub async fn set_link_down_by_index(&self, ifindex: u32) -> Result<()> {
        self.set_link_state_by_index(ifindex, false).await
    }

    /// Set the state of a network interface (up or down).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Arguments
    ///
    /// * `iface` - The interface name or index
    /// * `up` - `true` to bring the interface up, `false` to bring it down
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// // Bring interface up
    /// conn.set_link_state("eth0", true).await?;
    ///
    /// // Bring interface down by index
    /// conn.set_link_state(5u32, false).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_state"))]
    pub async fn set_link_state(&self, iface: impl Into<InterfaceRef>, up: bool) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_state_by_index(ifindex, up).await
    }

    /// Set the state of a network interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_state_by_index"))]
    pub async fn set_link_state_by_index(&self, ifindex: u32, up: bool) -> Result<()> {
        let mut ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        if up {
            ifinfo.ifi_flags = iff::UP;
            ifinfo.ifi_change = iff::UP;
        } else {
            ifinfo.ifi_flags = 0;
            ifinfo.ifi_change = iff::UP;
        }

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);

        let state = if up { "up" } else { "down" };
        self.send_ack(builder).await.map_err(|e| {
            if e.is_not_found() {
                self.interface_not_found(format!("ifindex {ifindex}"))
            } else {
                e.with_context(format!("set_link_{state}(ifindex {ifindex})"))
            }
        })
    }

    /// Set the MTU of a network interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.set_link_mtu("eth0", 9000).await?;
    /// conn.set_link_mtu(5u32, 9000).await?;  // by index
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_mtu"))]
    pub async fn set_link_mtu(&self, iface: impl Into<InterfaceRef>, mtu: u32) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_mtu_by_index(ifindex, mtu).await
    }

    /// Set the MTU of a network interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_mtu_by_index"))]
    pub async fn set_link_mtu_by_index(&self, ifindex: u32, mtu: u32) -> Result<()> {
        use super::types::link::IflaAttr;

        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_link_mtu"))
    }

    /// Set a network interface's alias (`ip link set dev X alias Y`); an
    /// empty `alias` clears it.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_alias"))]
    pub async fn set_link_alias(&self, iface: impl Into<InterfaceRef>, alias: &str) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_alias_by_index(ifindex, alias).await
    }

    /// Set a network interface's alias by index; an empty `alias` clears it.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_alias_by_index"))]
    pub async fn set_link_alias_by_index(&self, ifindex: u32, alias: &str) -> Result<()> {
        use super::types::link::IflaAttr;

        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);
        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        // `IFLA_IFALIAS` is an `NLA_STRING` (no NUL needed), and a
        // zero-length one clears the alias (`dev_set_alias`).
        builder.append_attr(IflaAttr::Ifalias as u16, alias.as_bytes());
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_link_alias"))
    }

    /// Delete a network interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.del_link("veth0").await?;
    /// conn.del_link(5u32).await?;  // by index
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_link"))]
    pub async fn del_link(&self, iface: impl Into<InterfaceRef>) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.del_link_by_index(ifindex).await
    }

    /// Delete a network interface if it exists. Returns `Ok(true)`
    /// if the link was deleted, `Ok(false)` if it didn't exist.
    /// Unlike [`Self::del_link`], does NOT error on `ENOENT`/
    /// `ENODEV` — the cleanup shape nearly all callers want (#169;
    /// mirrors the nftables `del_*_if_exists` family).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_link_if_exists"))]
    pub async fn del_link_if_exists(&self, iface: impl Into<InterfaceRef>) -> Result<bool> {
        match self.del_link(iface).await {
            Ok(()) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Delete a network interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_link_by_index"))]
    pub async fn del_link_by_index(&self, ifindex: u32) -> Result<()> {
        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_DELLINK);
        builder.append(&ifinfo);

        self.send_ack(builder).await.map_err(|e| {
            if e.is_not_found() {
                self.interface_not_found(format!("ifindex {ifindex}"))
            } else {
                e.with_context(format!("del_link(ifindex {ifindex})"))
            }
        })
    }

    /// Set the TX queue length of a network interface.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.set_link_txqlen("eth0", 1000).await?;
    /// conn.set_link_txqlen(5u32, 1000).await?;  // by index
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_txqlen"))]
    pub async fn set_link_txqlen(&self, iface: impl Into<InterfaceRef>, txqlen: u32) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_txqlen_by_index(ifindex, txqlen).await
    }

    /// Set the TX queue length of a network interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_txqlen_by_index"))]
    pub async fn set_link_txqlen_by_index(&self, ifindex: u32, txqlen: u32) -> Result<()> {
        use super::types::link::IflaAttr;

        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        builder.append_attr_u32(IflaAttr::TxqLen as u16, txqlen);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_link_txqlen"))
    }

    /// One `RTM_SETLINK` carrying a single u32 attribute.
    async fn set_link_u32_by_index(
        &self,
        ifindex: u32,
        attr: super::types::link::IflaAttr,
        value: u32,
        what: &'static str,
    ) -> Result<()> {
        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&IfInfoMsg::new().with_index(ifindex as i32));
        builder.append_attr_u32(attr as u16, value);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context(what))
    }

    /// Set a link's group (`ip link set … group N`, `IFLA_GROUP`).
    pub async fn set_link_group(&self, iface: impl Into<InterfaceRef>, group: u32) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.set_link_group_by_index(ifindex, group).await
    }

    /// [`Self::set_link_group`] by index.
    pub async fn set_link_group_by_index(&self, ifindex: u32, group: u32) -> Result<()> {
        use super::types::link::IflaAttr;
        self.set_link_u32_by_index(ifindex, IflaAttr::Group, group, "set_link_group")
            .await
    }

    /// Set the largest GSO packet a link builds (`gso_max_size`), in bytes.
    pub async fn set_link_gso_max_size_by_index(&self, ifindex: u32, bytes: u32) -> Result<()> {
        use super::types::link::IflaAttr;
        self.set_link_u32_by_index(ifindex, IflaAttr::GsoMaxSize, bytes, "set_link_gso_max_size")
            .await
    }

    /// Set the most segments a GSO packet has (`gso_max_segs`).
    pub async fn set_link_gso_max_segs_by_index(&self, ifindex: u32, segs: u32) -> Result<()> {
        use super::types::link::IflaAttr;
        self.set_link_u32_by_index(ifindex, IflaAttr::GsoMaxSegs, segs, "set_link_gso_max_segs")
            .await
    }

    /// Set the largest packet GRO builds (`gro_max_size`), in bytes.
    pub async fn set_link_gro_max_size_by_index(&self, ifindex: u32, bytes: u32) -> Result<()> {
        use super::types::link::IflaAttr;
        self.set_link_u32_by_index(ifindex, IflaAttr::GroMaxSize, bytes, "set_link_gro_max_size")
            .await
    }

    /// Turn a link's promiscuous mode on or off (`ip link set … promisc`):
    /// `IFF_PROMISC` in `ifi_change`, the flag a user sets, which the
    /// kernel reports back in the link's flags.
    pub async fn set_link_promisc_by_index(&self, ifindex: u32, on: bool) -> Result<()> {
        const IFF_PROMISC: u32 = libc::IFF_PROMISC as u32;
        let mut ifinfo = IfInfoMsg::new().with_index(ifindex as i32);
        ifinfo.ifi_flags = if on { IFF_PROMISC } else { 0 };
        ifinfo.ifi_change = IFF_PROMISC;
        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_link_promisc"))
    }

    /// Hold a link down for a control plane, or release it (`ip link set …
    /// protodown`). Only devices that implement it take it (vxlan,
    /// macvlan, …); others answer `EOPNOTSUPP`.
    pub async fn set_link_protodown_by_index(&self, ifindex: u32, on: bool) -> Result<()> {
        use super::types::link::IflaAttr;
        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&IfInfoMsg::new().with_index(ifindex as i32));
        builder.append_attr_u8(IflaAttr::ProtoDown as u16, u8::from(on));
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_link_protodown"))
    }

    /// Give a link an alternative name (`ip link property add … altname`,
    /// Linux 5.5+): up to 127 bytes, usable wherever its name is.
    pub async fn add_link_altname_by_index(&self, ifindex: u32, altname: &str) -> Result<()> {
        self.link_altname(NlMsgType::RTM_NEWLINKPROP, ifindex, altname)
            .await
            .map_err(|e| e.with_context("add_link_altname"))
    }

    /// Take an alternative name off a link (`ip link property del`).
    pub async fn del_link_altname_by_index(&self, ifindex: u32, altname: &str) -> Result<()> {
        self.link_altname(NlMsgType::RTM_DELLINKPROP, ifindex, altname)
            .await
            .map_err(|e| e.with_context("del_link_altname"))
    }

    /// Set IPv4 per-device settings (`/proc/sys/net/ipv4/conf/<dev>/…`)
    /// over netlink: one `RTM_SETLINK` with `IFLA_AF_SPEC` / `AF_INET` /
    /// `IFLA_INET_CONF`, each setting nested by its id (#516).
    pub async fn set_ipv4_devconf_by_index(
        &self,
        ifindex: u32,
        settings: &[(crate::netlink::devconf::Ipv4Devconf, u32)],
    ) -> Result<()> {
        use super::types::link::IflaAttr;
        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&IfInfoMsg::new().with_index(ifindex as i32));
        let spec = builder.nest_start(IflaAttr::AfSpec as u16);
        let inet = builder.nest_start(libc::AF_INET as u16);
        let conf = builder.nest_start(crate::netlink::devconf::af::IFLA_INET_CONF);
        for (d, v) in settings {
            builder.append_attr_u32(d.id(), *v);
        }
        builder.nest_end(conf);
        builder.nest_end(inet);
        builder.nest_end(spec);
        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("set_ipv4_devconf"))
    }

    /// Set how the kernel makes a link's IPv6 link-local address
    /// (`ip link set … addrgenmode`, #516). It takes effect when the link
    /// next comes up.
    pub async fn set_addr_gen_mode_by_index(
        &self,
        ifindex: u32,
        mode: crate::netlink::devconf::AddrGenMode,
    ) -> Result<()> {
        self.set_inet6_af(ifindex, |b| {
            b.append_attr_u8(crate::netlink::devconf::af::IFLA_INET6_ADDR_GEN_MODE, mode as u8)
        })
        .await
        .map_err(|e| e.with_context("set_addr_gen_mode"))
    }

    /// Set a link's IPv6 interface identifier token (`ip token set`,
    /// #516): SLAAC addresses use it in place of the MAC-derived one.
    pub async fn set_ipv6_token_by_index(&self, ifindex: u32, token: std::net::Ipv6Addr) -> Result<()> {
        self.set_inet6_af(ifindex, |b| {
            b.append_attr(crate::netlink::devconf::af::IFLA_INET6_TOKEN, &token.octets())
        })
        .await
        .map_err(|e| e.with_context("set_ipv6_token"))
    }

    async fn set_inet6_af(
        &self,
        ifindex: u32,
        f: impl FnOnce(&mut super::builder::MessageBuilder),
    ) -> Result<()> {
        use super::types::link::IflaAttr;
        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&IfInfoMsg::new().with_index(ifindex as i32));
        let spec = builder.nest_start(IflaAttr::AfSpec as u16);
        let inet6 = builder.nest_start(libc::AF_INET6 as u16);
        f(&mut builder);
        builder.nest_end(inet6);
        builder.nest_end(spec);
        self.send_ack(builder).await
    }

    async fn link_altname(&self, msg_type: u16, ifindex: u32, altname: &str) -> Result<()> {
        use super::types::link::IflaAttr;
        let mut builder = ack_request(msg_type);
        builder.append(&IfInfoMsg::new().with_index(ifindex as i32));
        let list = builder.nest_start(IflaAttr::PropList as u16);
        builder.append_attr_str(IflaAttr::AltIfname as u16, altname);
        builder.nest_end(list);
        self.send_ack(builder).await
    }
}

// ============================================================================
// Namespace ID Queries
// ============================================================================

use super::{
    messages::NsIdMessage,
    types::nsid::{RTM_GETNSID, RTM_NEWNSID, RtGenMsg, netnsa},
};

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Get the namespace ID for a given file descriptor.
    ///
    /// The file descriptor should be an open reference to a network namespace
    /// (e.g., from opening `/proc/<pid>/ns/net`).
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace ID cannot be determined.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use std::fs::File;
    ///
    /// let ns_file = File::open("/var/run/netns/myns")?;
    /// let nsid = conn.get_nsid(&ns_file).await?;
    /// println!("Namespace ID: {}", nsid);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_nsid"))]
    pub async fn get_nsid(&self, ns_fd: impl std::os::fd::AsFd) -> Result<u32> {
        let mut builder = ack_request(RTM_GETNSID);

        // The one-byte rtgenmsg, which `append` pads to four: the kernel
        // reads the attributes from there. Three more bytes of padding put
        // them where it never looked (#669).
        builder.append(&RtGenMsg::new());

        // Add NETNSA_FD attribute
        builder.append_attr_u32(netnsa::FD, std::os::fd::AsRawFd::as_raw_fd(&ns_fd.as_fd()) as u32);

        let response = self.send_request(builder).await?;

        // Parse the response
        if response.len() >= super::message::NLMSG_HDRLEN {
            let payload = &response[super::message::NLMSG_HDRLEN..];
            if let Some(nsid_msg) = NsIdMessage::parse(payload)
                && let Some(nsid) = nsid_msg.nsid
            {
                return Ok(nsid);
            }
        }

        Err(Error::invalid_message(
            "namespace ID not found in response",
        ))
    }

    /// Get the namespace ID for a given process's network namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace ID cannot be determined.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// // Get the namespace ID for process 1234
    /// let nsid = conn.get_nsid_for_pid(1234).await?;
    /// println!("Namespace ID for PID 1234: {}", nsid);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_nsid_for_pid"))]
    pub async fn get_nsid_for_pid(&self, pid: u32) -> Result<u32> {
        let mut builder = ack_request(RTM_GETNSID);

        // The one-byte rtgenmsg, which `append` pads to four: the kernel
        // reads the attributes from there. Three more bytes of padding put
        // them where it never looked (#669).
        builder.append(&RtGenMsg::new());

        // Add NETNSA_PID attribute
        builder.append_attr_u32(netnsa::PID, pid);

        let response = self.send_request(builder).await?;

        // Parse the response
        if response.len() >= super::message::NLMSG_HDRLEN {
            let payload = &response[super::message::NLMSG_HDRLEN..];
            if let Some(nsid_msg) = NsIdMessage::parse(payload)
                && let Some(nsid) = nsid_msg.nsid
            {
                return Ok(nsid);
            }
        }

        Err(Error::invalid_message(
            "namespace ID not found in response",
        ))
    }

    /// Assign a namespace ID to the network namespace referenced by an
    /// open file descriptor (`RTM_NEWNSID`).
    ///
    /// `ns_fd` is an open reference to a network namespace (e.g. from
    /// opening `/var/run/netns/<name>`). Pass `nsid >= 0` to request a
    /// specific id, or `-1` to let the kernel auto-allocate the next
    /// free id (matching `ip netns set <name> auto`).
    ///
    /// The kernel rejects re-assigning an id to a namespace that already
    /// has one (`EEXIST`); each namespace gets at most one id per peer
    /// namespace.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_nsid"))]
    pub async fn set_nsid(&self, ns_fd: impl std::os::fd::AsFd, nsid: i32) -> Result<()> {
        let mut builder = ack_request(RTM_NEWNSID);

        // rtgenmsg header (1 byte + 3 padding).
        builder.append(&RtGenMsg::new());

        // NETNSA_NSID carries an i32; -1 means "auto-allocate".
        builder.append_attr_u32(netnsa::NSID, nsid as u32);
        builder.append_attr_u32(netnsa::FD, std::os::fd::AsRawFd::as_raw_fd(&ns_fd.as_fd()) as u32);

        self.send_ack(builder).await
    }
}

// ============================================================================
// Generic Netlink protocol methods
// ============================================================================

use std::collections::HashMap;

use super::{
    genl::{
        CtrlAttr, CtrlAttrMcastGrp, CtrlCmd, FamilyInfo, GENL_HDRLEN, GENL_ID_CTRL, GenlMsgHdr,
    },
    protocol::Generic,
};

#[nlink_macros::send_futures]
impl Connection<Generic> {
    /// Get information about a Generic Netlink family.
    ///
    /// The result is cached, so subsequent calls for the same family
    /// do not require kernel communication.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Generic};
    ///
    /// let conn = Connection::<Generic>::new()?;
    /// let wg = conn.get_family("wireguard").await?;
    /// println!("WireGuard family ID: {}", wg.id);
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(level = "info", skip(self), fields(family = %name, id, cached))]
    pub async fn get_family(&self, name: &str) -> Result<FamilyInfo> {
        // Check cache first. Poison-tolerant unwrap (Plan 212 M17)
        // — the locked region is panic-free, so poisoning is
        // unreachable; the `unwrap_or_else(into_inner)` recovers if
        // a future panic surfaces (hardening rather than fix).
        {
            let cache = self.state.cache.read().unwrap_or_else(|p| p.into_inner());
            if let Some(info) = cache.get(name) {
                let span = tracing::Span::current();
                span.record("id", info.id);
                span.record("cached", true);
                return Ok(info.clone());
            }
        }

        // Query kernel for family info
        let info = self.query_family(name).await?;
        let span = tracing::Span::current();
        span.record("id", info.id);
        span.record("cached", false);

        // Cache the result
        {
            let mut cache = self.state.cache.write().unwrap_or_else(|p| p.into_inner());
            cache.insert(name.to_string(), info.clone());
        }

        Ok(info)
    }

    /// Get the family ID for a given family name.
    ///
    /// This is a convenience method that returns just the ID.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_family_id"))]
    pub async fn get_family_id(&self, name: &str) -> Result<u16> {
        Ok(self.get_family(name).await?.id)
    }

    /// Clear the family cache.
    ///
    /// This is rarely needed, but may be useful if families are
    /// dynamically loaded/unloaded.
    pub fn clear_cache(&self) {
        let mut cache = self.state.cache.write().unwrap_or_else(|p| p.into_inner());
        cache.clear();
    }

    /// Query the kernel for family information.
    async fn query_family(&self, name: &str) -> Result<FamilyInfo> {
        // Build CTRL_CMD_GETFAMILY request
        let mut builder = MessageBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK);

        // Append GENL header
        let genl_hdr = GenlMsgHdr::new(CtrlCmd::GetFamily as u8, 1);
        builder.append(&genl_hdr);

        // Append family name attribute
        builder.append_attr_str(CtrlAttr::FamilyName as u16, name);

        // Through the request session, to this request's ACK (#496). It
        // read one datagram straight off the socket: with no request lock
        // in mutex mode and racing the driver in dispatcher mode, and
        // leaving the ACK, which comes as a second datagram, for the next
        // call — which then took it for its reply and said
        // `FamilyNotFound`.
        let (seq, datagrams) = self.genl_request(builder).await.map_err(|e| {
            if e.errno() == Some(libc::ENOENT) {
                self.socket.stamp(Error::family_not_found(name))
            } else {
                e
            }
        })?;
        for data in &datagrams {
            for msg in MessageIter::new(data) {
                let (header, payload) = msg?;
                if header.nlmsg_seq != seq || header.is_error() || header.is_done() {
                    continue;
                }
                if payload.len() < GENL_HDRLEN {
                    return Err(Error::invalid_message("GENL header too short"));
                }
                return self.parse_family_attrs(&payload[GENL_HDRLEN..]);
            }
        }
        Err(self.socket.stamp(Error::family_not_found(name)))
    }

    /// Send a GENL request with `NLM_F_ACK` and read every datagram that
    /// answers it, through its ACK (#496). Returns the request's seq and
    /// those datagrams, in order.
    ///
    /// A `doit` reply and its ACK are two datagrams: `genlmsg_reply`
    /// unicasts the reply, then `netlink_rcv_skb` sends the ACK. A caller
    /// that read one left the ACK queued, and the next request on the
    /// socket took it for its own response.
    async fn genl_request(&self, mut builder: MessageBuilder) -> Result<(u32, Vec<Vec<u8>>)> {
        builder.check_size()?;
        // Session before the timeout, so the lock (mutex mode) or the seq
        // registration (dispatcher mode) spans the whole window.
        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());
        let mut session = self.recv_session(seq).await?;

        self.with_timeout(async move {
            self.socket.send(&builder.finish()).await?;

            let mut datagrams = Vec::new();
            loop {
                let data = session.recv_with_timeout(self).await?;
                let mut ours = false;
                let mut acked = false;
                for msg in MessageIter::new(&data) {
                    let (header, payload) = msg?;
                    match classify(header, payload, seq) {
                        Classification::SkipSeq => continue,
                        Classification::Error(e) => return Err(e),
                        Classification::Done(result) => {
                            result?;
                            (ours, acked) = (true, true);
                        }
                        Classification::Ack => (ours, acked) = (true, true),
                        Classification::Data { .. } => ours = true,
                    }
                }
                if ours {
                    datagrams.push(data);
                }
                if acked {
                    return Ok((seq, datagrams));
                }
            }
        })
        .await
    }

    /// Parse family attributes from a CTRL_CMD_GETFAMILY response.
    fn parse_family_attrs(&self, data: &[u8]) -> Result<FamilyInfo> {
        use super::attr::{AttrIter, get};

        let mut id: Option<u16> = None;
        let mut version: u8 = 0;
        let mut hdr_size: u32 = 0;
        let mut max_attr: u32 = 0;
        let mut mcast_groups = HashMap::new();

        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == CtrlAttr::FamilyId as u16 => {
                    id = Some(get::u16_ne(payload)?);
                }
                t if t == CtrlAttr::Version as u16 => {
                    version = get::u32_ne(payload)? as u8;
                }
                t if t == CtrlAttr::HdrSize as u16 => {
                    hdr_size = get::u32_ne(payload)?;
                }
                t if t == CtrlAttr::MaxAttr as u16 => {
                    max_attr = get::u32_ne(payload)?;
                }
                t if t == CtrlAttr::McastGroups as u16 => {
                    mcast_groups = self.parse_mcast_groups(payload)?;
                }
                _ => {}
            }
        }

        let id = id.ok_or_else(|| Error::invalid_message("missing family ID"))?;

        Ok(FamilyInfo {
            id,
            version,
            hdr_size,
            max_attr,
            mcast_groups,
        })
    }

    /// Parse multicast groups from CTRL_ATTR_MCAST_GROUPS.
    fn parse_mcast_groups(&self, data: &[u8]) -> Result<HashMap<String, u32>> {
        use super::attr::{AttrIter, get};

        let mut groups = HashMap::new();

        // The mcast_groups attribute contains nested arrays
        for (_group_idx, group_payload) in AttrIter::new(data) {
            let mut name: Option<String> = None;
            let mut grp_id: Option<u32> = None;

            // Parse the nested group attributes
            for (attr_type, payload) in AttrIter::new(group_payload) {
                match attr_type {
                    t if t == CtrlAttrMcastGrp::Name as u16 => {
                        name = Some(get::string(payload)?.to_string());
                    }
                    t if t == CtrlAttrMcastGrp::Id as u16 => {
                        grp_id = Some(get::u32_ne(payload)?);
                    }
                    _ => {}
                }
            }

            if let (Some(name), Some(id)) = (name, grp_id) {
                groups.insert(name, id);
            }
        }

        Ok(groups)
    }

    /// Send a GENL command and wait for a response.
    ///
    /// This is a low-level method for sending arbitrary GENL commands.
    /// Family-specific wrappers (like `Connection<Wireguard>`) should use this.
    ///
    /// Returns every datagram the kernel sent for this request through its
    /// ACK, back to back: the reply, if the command has one, then the ACK.
    /// Walk it with [`MessageIter`].
    /// It used to return the first datagram that arrived, which could be
    /// an earlier call's ACK (#496).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "command"))]
    pub async fn command(
        &self,
        family_id: u16,
        cmd: u8,
        version: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<u8>> {
        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(cmd, version);
        builder.append(&genl_hdr);
        build_attrs(&mut builder);

        let (_, datagrams) = self.genl_request(builder).await?;
        let mut response = Vec::new();
        for data in datagrams {
            // Datagrams end aligned; pad anyway so the next one starts
            // where `MessageIter` looks for it.
            response.resize(response.len().next_multiple_of(4), 0);
            response.extend_from_slice(&data);
        }
        Ok(response)
    }

    /// Send a GENL dump command and collect all responses.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "dump_command"))]
    pub async fn dump_command(
        &self,
        family_id: u16,
        cmd: u8,
        version: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<Vec<u8>>> {
        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);
        let genl_hdr = GenlMsgHdr::new(cmd, version);
        builder.append(&genl_hdr);
        build_attrs(&mut builder);

        // #134 — dual-mode recv; see `command()` above. Dumps still
        // serialize per socket in dispatcher mode (the registration
        // doesn't change the kernel's per-fd EBUSY rule), but the loop no
        // longer races the driver's recv_msg.
        let seq = self.socket.next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket.pid());
        let mut session = self.recv_session_dump(seq).await?;

        // Plan 208 Phase 1+2 — wrap in with_timeout, add
        // NLM_F_DUMP_INTR detection. Pre-0.19 every custom GENL
        // dump could hang indefinitely on a dropped response AND
        // silently use an inconsistent snapshot when the kernel
        // signaled mid-dump mutation.
        self.with_timeout(async move {
            let msg = builder.finish();
            self.socket.send(&msg).await?;

            let mut responses = Vec::new();

            loop {
                let data = session.recv_with_timeout(self).await?;
                let mut done = false;

                for result in MessageIter::new(&data) {
                    let (header, payload) = result?;

                    match classify(header, payload, seq) {
                        Classification::SkipSeq | Classification::Ack => continue,
                        Classification::Error(e) => return Err(e),
                        Classification::Done(result) => {
                            result?;
                            done = true;
                            break;
                        }
                        Classification::Data { payload } => responses.push(payload.to_vec()),
                    }
                }

                if done {
                    break;
                }
            }

            Ok(responses)
        })
        .await
    }
}

#[cfg(test)]
mod send_sync_tests {
    use super::*;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn connection_is_send_sync() {
        assert_send::<Connection<Route>>();
        assert_sync::<Connection<Route>>();
    }

    /// Plan 171 — every fresh Connection<P> ships with the default
    /// 30s operation timeout. Caller can override via
    /// `.timeout(d)` or opt out via `.no_timeout()`.
    #[tokio::test]
    async fn connection_default_timeout_is_30s() {
        let conn = Connection::<Route>::new().expect("socket open");
        assert_eq!(
            conn.operation_timeout(),
            Some(DEFAULT_OPERATION_TIMEOUT),
            "Plan 171: fresh Connection<P> must default to 30s timeout"
        );
        assert_eq!(
            DEFAULT_OPERATION_TIMEOUT,
            Duration::from_secs(30),
            "Plan 171: documented constant value",
        );
    }

    #[tokio::test]
    async fn connection_no_timeout_clears_default() {
        let conn = Connection::<Route>::new()
            .expect("socket open")
            .no_timeout();
        assert_eq!(
            conn.operation_timeout(),
            None,
            "Plan 171: .no_timeout() must opt out of the default"
        );
    }

    #[tokio::test]
    async fn connection_timeout_override_replaces_default() {
        let conn = Connection::<Route>::new()
            .expect("socket open")
            .timeout(Duration::from_secs(5));
        assert_eq!(conn.operation_timeout(), Some(Duration::from_secs(5)));
    }

    // -- #134 — dispatcher-mode end-to-end (non-root; reads only) ----

    #[tokio::test]
    async fn dispatcher_mode_flag_defaults_off() {
        let conn = Connection::<Route>::new().expect("socket open");
        assert!(!conn.is_dispatcher_mode());
        let conn = conn.with_dispatcher();
        assert!(conn.is_dispatcher_mode());
    }

    /// The headline #134 validation: a request issued in dispatcher
    /// mode goes register → send → driver-demux → response, with no
    /// `request_lock`. `get_links()` is a read, so this runs as a
    /// regular user in CI.
    #[tokio::test]
    async fn dispatcher_mode_single_request_round_trips() {
        let conn = Connection::<Route>::new()
            .expect("socket open")
            .with_dispatcher();
        let links = conn
            .get_links()
            .await
            .expect("get_links in dispatcher mode");
        assert!(!links.is_empty(), "host always has at least `lo`");
        // The driver was spawned, and the request deregistered its seq.
        assert!(conn.dispatcher().driver_started());
        assert_eq!(
            conn.dispatcher().pending_count(),
            0,
            "completed request must leave no pending seq"
        );
    }

    /// Concurrent requests on a shared `Arc<Connection>` in dispatcher
    /// mode demux independently — the whole point of retiring the F1
    /// mutex. Each task gets its own correct result.
    #[tokio::test]
    async fn dispatcher_mode_concurrent_requests_demux() {
        let conn = std::sync::Arc::new(
            Connection::<Route>::new()
                .expect("socket open")
                .with_dispatcher(),
        );
        let mut handles = Vec::new();
        for _ in 0..16 {
            let c = conn.clone();
            handles.push(tokio::spawn(async move { c.get_links().await }));
        }
        for h in handles {
            let links = h.await.expect("task join").expect("get_links");
            assert!(!links.is_empty());
        }
        assert_eq!(
            conn.dispatcher().pending_count(),
            0,
            "all concurrent requests must drain their pending seqs"
        );
    }

    /// `dump_stream` works in dispatcher mode (#134 Stage 2): it
    /// registers its seq, the driver routes frames to its channel, and it
    /// streams `lo` and friends to completion (`NLMSG_DONE`). Runs as a
    /// regular user (reads only).
    #[tokio::test]
    async fn dispatcher_mode_dump_stream_streams_links() {
        use tokio_stream::StreamExt;
        let conn = Connection::<Route>::new()
            .expect("socket open")
            .with_dispatcher();
        let mut stream = conn
            .dump_stream::<LinkMessage>(super::super::message::NlMsgType::RTM_GETLINK)
            .await
            .expect("dump_stream starts in dispatcher mode");
        let mut count = 0usize;
        while let Some(item) = stream.next().await {
            item.expect("each frame parses");
            count += 1;
        }
        assert!(count >= 1, "host always has at least `lo`");
        drop(stream);
        assert_eq!(
            conn.dispatcher().pending_count(),
            0,
            "completed dump_stream must deregister its seq"
        );
    }

    /// The #134 headline fix: in dispatcher mode an `events()` stream and
    /// concurrent requests on the **same** connection both make progress
    /// (the events stream no longer holds a lock that blocks requests).
    /// Creating the stream registers an event listener + starts the
    /// driver; `get_links()` then completes while the stream is live.
    #[tokio::test]
    async fn dispatcher_mode_events_coexist_with_requests() {
        let conn = std::sync::Arc::new(
            Connection::<Route>::new()
                .expect("socket open")
                .with_dispatcher(),
        );
        // Hold a live events stream for the duration.
        let events = conn.events().await;
        assert!(conn.dispatcher().driver_started());
        assert_eq!(
            conn.dispatcher().event_listener_count(),
            1,
            "events() must register a driver event listener in dispatcher mode"
        );
        // Requests still complete while the stream is held — the headline
        // fix (pre-#134 the events lock would block this forever).
        for _ in 0..4 {
            let links = conn.get_links().await.expect("get_links while events live");
            assert!(!links.is_empty());
        }
        // Dropping the stream deregisters the listener.
        drop(events);
        assert_eq!(conn.dispatcher().event_listener_count(), 0);
    }

    /// #505: in mutex mode an events stream holds the request lock for its
    /// life, so a request on the same connection waited out the 30 s
    /// operation timeout and read like a kernel hang. It fails at once now,
    /// with an error that says why, and works again once the stream drops.
    #[tokio::test]
    async fn mutex_mode_requests_fail_fast_while_events_own_the_connection() {
        let conn = Connection::<Route>::new().expect("socket open");
        let events = conn.events().await;

        let got = tokio::time::timeout(Duration::from_secs(2), conn.get_links())
            .await
            .expect("a request must not wait behind an events stream");
        let err = got.expect_err("the events stream owns the connection");
        assert!(err.is_event_stream_active(), "{err}");

        let dump = conn
            .dump_stream::<LinkMessage>(super::super::message::NlMsgType::RTM_GETLINK)
            .await;
        assert!(dump.is_err_and(|e| e.is_event_stream_active()));

        drop(events);
        let links = conn
            .get_links()
            .await
            .expect("usable once the stream drops");
        assert!(!links.is_empty());
    }

    /// A request already queued on the lock when a stream claims it is
    /// woken with the error rather than left waiting (#505). One queued
    /// *before* the stream finishes first: the lock is fair.
    #[tokio::test]
    async fn a_queued_request_is_woken_when_a_stream_claims_the_lock() {
        let conn = std::sync::Arc::new(Connection::<Route>::new().expect("socket open"));
        // Hold the lock as an in-flight request would, so what follows
        // queues behind it in a known order.
        let held = conn.lock_request().await.expect("free");

        let first = tokio::spawn({
            let conn = conn.clone();
            async move { conn.get_links().await }
        });
        tokio::task::yield_now().await;
        let stream = tokio::spawn({
            let conn = conn.clone();
            async move { conn.claim_for_events().await }
        });
        tokio::task::yield_now().await;
        let late = tokio::spawn({
            let conn = conn.clone();
            async move { conn.get_links().await }
        });
        tokio::task::yield_now().await;

        drop(held);
        let within = Duration::from_secs(2);
        let first = tokio::time::timeout(within, first).await.expect("first");
        assert!(first.expect("join").is_ok(), "queued before the stream");
        let claim = tokio::time::timeout(within, stream).await.expect("stream");
        let late = tokio::time::timeout(within, late)
            .await
            .expect("a queued request must be woken, not left waiting");
        let err = late.expect("join").expect_err("queued behind the stream");
        assert!(err.is_event_stream_active(), "{err}");

        drop(claim.expect("join"));
        conn.get_links().await.expect("usable once the claim drops");
    }

    /// GETFAMILY for `nlctrl` as a raw [`Connection::command`].
    fn get_nlctrl(b: &mut MessageBuilder) {
        b.append_attr_str(CtrlAttr::FamilyName as u16, "nlctrl");
    }

    /// The data frames (not ACKs) in a `command()` response.
    fn replies(response: &[u8]) -> usize {
        MessageIter::new(response)
            .flatten()
            .filter(|(h, _)| !h.is_error() && !h.is_done())
            .count()
    }

    /// #496: `command()` read one datagram. The reply and its ACK are two,
    /// so the next call read the stale ACK and returned it as its result.
    #[tokio::test]
    async fn command_returns_its_own_reply_not_the_last_calls_ack() {
        let conn = Connection::<Generic>::new().expect("socket open");
        for call in 0..3 {
            let cmd = conn.command(GENL_ID_CTRL, CtrlCmd::GetFamily as u8, 1, get_nlctrl);
            let response = tokio::time::timeout(Duration::from_secs(5), cmd)
                .await
                .expect("in time")
                .expect("command");
            assert_eq!(replies(&response), 1, "call {call}: its own reply");
        }
    }

    /// #496: `query_family` read one datagram too, so a second lookup
    /// read the first one's ACK and reported `FamilyNotFound`.
    #[tokio::test]
    async fn a_family_is_found_every_time_it_is_looked_up() {
        let conn = Connection::<Generic>::new().expect("socket open");
        for lookup in 0..3 {
            conn.clear_cache();
            let info = tokio::time::timeout(Duration::from_secs(5), conn.get_family("nlctrl"))
                .await
                .expect("in time")
                .unwrap_or_else(|e| panic!("lookup {lookup}: {e}"));
            assert_eq!(info.id, GENL_ID_CTRL);
        }
        conn.clear_cache();
        let err = conn
            .get_family("no-such-family")
            .await
            .expect_err("unknown");
        assert!(matches!(err.detail(), crate::netlink::ErrorDetail::NotFound { object: crate::ErrorObject::GenlFamily { .. } }), "{err}");
    }

    /// #496: `query_family` read the socket directly, so in dispatcher
    /// mode it raced the driver for its own reply. Two worker threads, so
    /// the driver really runs beside the lookup.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_family_lookup_goes_through_the_dispatcher() {
        let conn = Connection::<Generic>::new()
            .expect("socket open")
            .with_dispatcher();
        for lookup in 0..3 {
            // A command first, so the driver is running.
            conn.command(GENL_ID_CTRL, CtrlCmd::GetFamily as u8, 1, get_nlctrl)
                .await
                .expect("command");
            conn.clear_cache();
            let info = tokio::time::timeout(Duration::from_secs(5), conn.get_family("nlctrl"))
                .await
                .unwrap_or_else(|_| panic!("lookup {lookup} lost its reply to the driver"))
                .expect("found");
            assert_eq!(info.id, GENL_ID_CTRL);
        }
    }

    /// #495: a link by index or name is one `RTM_GETLINK`, and a name the
    /// kernel does not know — or cannot hold — is `None`, not an error.
    #[tokio::test]
    async fn a_link_is_fetched_by_index_or_name() {
        let conn = Connection::<Route>::new().expect("socket open");
        let lo = conn.get_link_by_name("lo").await.unwrap().expect("lo");
        assert_eq!(lo.ifindex(), 1, "lo is the first device in every netns");
        let again = conn
            .get_link_by_index(1)
            .await
            .unwrap()
            .expect("lo by index");
        assert_eq!(again.name(), Some("lo"));
        assert!(again.stats.is_some(), "the reply carries what a dump does");
        for missing in ["nosuch0", "nlink-no-such-iface", &"x".repeat(200)] {
            let got = conn.get_link_by_name(missing).await;
            assert!(
                got.as_ref().is_ok_and(Option::is_none),
                "{missing}: {got:?}"
            );
        }
        for missing in [0, 0x7fff_fff0, u32::MAX] {
            let got = conn.get_link_by_index(missing).await;
            assert!(
                got.as_ref().is_ok_and(Option::is_none),
                "{missing}: {got:?}"
            );
        }
    }

    /// #497: a sibling Route connection is in this connection's namespace.
    /// As a regular user `SIOCGSKNS` is refused, and the namespaces'
    /// cookies decide; here both are the host's, so the sibling is too.
    #[tokio::test]
    async fn a_route_sibling_is_in_the_same_namespace() {
        let conn = Connection::<Route>::new().expect("socket open");
        let sibling = conn.route_sibling().expect("sibling");
        assert_eq!(
            sibling.socket().netns_cookie().unwrap(),
            conn.socket().netns_cookie().unwrap()
        );
        let lo = sibling.get_link_by_index(1).await.unwrap().expect("lo");
        assert_eq!(lo.name(), Some("lo"));
    }
}
