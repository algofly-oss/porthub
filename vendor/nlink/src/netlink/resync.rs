//! ENOBUFS-resync helper types.
//!
//! When a multicast subscriber falls behind the kernel's event
//! production rate, the kernel drops events and returns `ENOBUFS`
//! on the next `recvmsg`. The subscriber's view of state is now
//! incomplete. The correct recovery (per kernel maintainers'
//! guidance) is:
//!
//! 1. Re-dump current state via the matching `get_*` method.
//! 2. Resume the multicast stream from where the read left off.
//!
//! Downstream consumers of this pattern keep reinventing it, often
//! badly (the well-known
//! [Cilium issue #40280](https://github.com/cilium/cilium/issues/40280)
//! is the same gap in Go). This module ships the **types** that
//! make the pattern explicit:
//!
//! - [`ResyncedEvent<T>`] — sum type yielded by a resync-aware
//!   consumer: `Event(T)` for normal events, `Resynced(T)` for
//!   replayed items, `Marker(...)` for state-machine boundaries.
//! - [`ResyncMarker`] — `ResyncStart` and `ResyncEnd` boundaries
//!   so consumers can coordinate state-rebuild logic with the
//!   replay window.
//!
//! See `docs/recipes/events-with-resync.md` for the canonical
//! event-loop pattern using these types. The [`events_with_resync`]
//! Stream wrapper (Plan 151 §4.2 — landed in 0.16 after design
//! soak) drives the state machine internally so the consumer
//! just `next().await`s `ResyncedEvent<T>` items.
//!
//! # Example loop
//!
//! ```no_run
//! use nlink::netlink::resync::{ResyncedEvent, ResyncMarker};
//! use tokio_stream::StreamExt;
//!
//! # async fn run(
//! #     mut events: nlink::netlink::EventSubscription<'_, nlink::Route>,
//! #     dump_conn: &nlink::Connection<nlink::Route>,
//! #     mut handle: impl FnMut(ResyncedEvent<nlink::NetworkEvent>),
//! # ) -> nlink::Result<()> {
//! while let Some(item) = events.next().await {
//!     match item {
//!         Ok(ev) => handle(ResyncedEvent::Event(ev)),
//!         Err(e) if e.is_no_buffer_space() => {
//!             handle(ResyncedEvent::Marker(ResyncMarker::ResyncStart));
//!             for link in dump_conn.get_links().await? {
//!                 handle(ResyncedEvent::Resynced(nlink::NetworkEvent::NewLink(link)));
//!             }
//!             handle(ResyncedEvent::Marker(ResyncMarker::ResyncEnd));
//!         }
//!         Err(other) => return Err(other),
//!     }
//! }
//! # Ok(())
//! # }
//! ```

/// Boundary markers emitted around a resync window so consumers
/// can coordinate state-rebuild logic with the replay.
///
/// `ResyncStart` is the cue to invalidate any incremental state
/// the consumer has been accumulating from `Event(T)`s (it's now
/// stale).
///
/// `ResyncEnd` is the cue that the replay is complete — the
/// consumer's state now reflects current kernel state, and
/// subsequent `Event(T)`s are real-time deltas again.
///
/// # One source where `ResyncEnd` means less than that
///
/// The guarantee above rests on the factory running a *dump*, which
/// every protocol here has — except `NETLINK_KOBJECT_UEVENT`, which
/// is broadcast-only with no `GETUEVENT` (#252). Its stand-in,
/// [`crate::util::uevent_trigger::resync_factory`], writes to
/// `/sys/.../uevent` to ask the kernel to *re-broadcast*, and returns
/// an empty batch: the re-announcements come back through the live
/// stream as ordinary `Event(T)`s, racing with genuinely new events
/// and describing each device as of re-emission rather than as of the
/// event that was lost.
///
/// So on a uevent stream, read `ResyncEnd` as "a re-announcement has
/// been requested", not "state is rebuilt", and expect no
/// [`ResyncedEvent::Resynced`] items at all. A consumer needing a
/// consistent snapshot of network devices should take it from
/// rtnetlink, which has a real dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ResyncMarker {
    /// Resync is starting. The next items will be
    /// [`ResyncedEvent::Resynced`] until [`Self::ResyncEnd`].
    ResyncStart,
    /// The initial snapshot is starting: the stream begins with the state
    /// as it is, as [`ResyncedEvent::Resynced`] items, until
    /// [`Self::ResyncEnd`] — so a mirror built from the stream is complete
    /// from the start, not only after the first overflow (#503). See
    /// [`ResyncStream::initial_snapshot`].
    InitialSyncStart,
    /// Resync is complete. Subsequent items resume as
    /// [`ResyncedEvent::Event`].
    ResyncEnd,
}

/// A stream item produced by a resync-aware event consumer.
///
/// Distinguishes multicast event deltas (`Event`) from
/// post-overflow state replay (`Resynced`), with explicit
/// boundary markers so the consumer's state-rebuild logic can
/// trigger at the right moment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ResyncedEvent<T> {
    /// A real-time multicast event from the kernel.
    Event(T),
    /// A state-snapshot item from the post-`ENOBUFS` redump.
    Resynced(T),
    /// A boundary marker. See [`ResyncMarker`].
    Marker(ResyncMarker),
}

impl<T> ResyncedEvent<T> {
    /// Convenience: is this a `Marker(InitialSyncStart)`?
    pub fn is_initial_sync_start(&self) -> bool {
        matches!(self, Self::Marker(ResyncMarker::InitialSyncStart))
    }

    /// Convenience: is this a `Marker(ResyncStart)`?
    pub fn is_resync_start(&self) -> bool {
        matches!(self, Self::Marker(ResyncMarker::ResyncStart))
    }

    /// Convenience: is this a `Marker(ResyncEnd)`?
    pub fn is_resync_end(&self) -> bool {
        matches!(self, Self::Marker(ResyncMarker::ResyncEnd))
    }

    /// Extract the inner `T`, regardless of whether it arrived as
    /// a real-time event or a replay item. Returns `None` for
    /// marker variants (callers usually want to handle markers
    /// separately).
    pub fn into_inner(self) -> Option<T> {
        match self {
            Self::Event(t) | Self::Resynced(t) => Some(t),
            Self::Marker(_) => None,
        }
    }

    /// Borrow the inner `T`. `None` for markers.
    pub fn as_inner(&self) -> Option<&T> {
        match self {
            Self::Event(t) | Self::Resynced(t) => Some(t),
            Self::Marker(_) => None,
        }
    }
}

// ============================================================
// Plan 151 §4.2 — `events_with_resync` Stream wrapper
// ============================================================

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio_stream::Stream;

// ============================================================
// ConnectionFactory<P> — generic factory for opening fresh
// `Connection<P>` during ENOBUFS recovery. Used by protocol-
// specific resync wrappers (e.g. nftables) so the consumer
// can carry netns context / extra setup into every retry.
// ============================================================

/// Boxed future producing a fresh `Connection<P>`. Defaults to
/// `'static` so the resulting stream is spawn-friendly.
///
/// This is the building block for [`ConnectionFactory<P>`].
pub type ConnectionFuture<P> =
    Pin<Box<dyn Future<Output = crate::Result<crate::Connection<P>>> + Send + 'static>>;

/// User-supplied closure that opens a fresh `Connection<P>` each
/// time a resync wrapper needs to re-dump after an `ENOBUFS`.
///
/// Mirrors the `kube_rs::watcher(api, cfg)` pattern: the wrapper
/// captures the factory, clones it across resync invocations, and
/// invokes it to materialise a clean unicast connection (Plan
/// 178's "subscribe + unicast on one socket" race makes this the
/// only correct shape).
///
/// `Arc`-wrapped so it's cheap to clone across `poll_next` calls.
/// Most callers wrap a plain closure in `Arc::new(...)`:
///
/// ```no_run
/// use std::sync::Arc;
/// use nlink::netlink::{Connection, Nftables};
/// use nlink::netlink::resync::ConnectionFactory;
///
/// let factory: ConnectionFactory<Nftables> = Arc::new(|| {
///     Box::pin(async { Connection::<Nftables>::new() })
/// });
/// ```
///
/// Namespace-aware code substitutes
/// [`namespace::connection_for`](crate::netlink::namespace::connection_for)
/// (or `_async` for GENL families) inside the closure.
pub type ConnectionFactory<P> =
    Arc<dyn Fn() -> ConnectionFuture<P> + Send + Sync + 'static>;

/// How a restarting event stream waits between attempts (#523): from
/// `initial`, doubling each time, up to `max`. After `max_attempts`
/// restarts in a row without an event delivered it gives up (`None`:
/// never). A run that delivered an event starts the count again.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Backoff {
    /// The first wait.
    pub initial: std::time::Duration,
    /// The longest wait.
    pub max: std::time::Duration,
    /// Restarts in a row before giving up; `None` for never.
    pub max_attempts: Option<u32>,
}

impl Default for Backoff {
    /// From 100 ms to 30 s, never giving up.
    fn default() -> Self {
        Self {
            initial: std::time::Duration::from_millis(100),
            max: std::time::Duration::from_secs(30),
            max_attempts: None,
        }
    }
}

impl Backoff {
    /// From `initial` to `max`, never giving up.
    pub fn new(initial: std::time::Duration, max: std::time::Duration) -> Self {
        Self {
            initial,
            max,
            max_attempts: None,
        }
    }

    /// Give up after `attempts` restarts in a row.
    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = Some(attempts);
        self
    }

    /// The wait before restart number `attempt` (1-based).
    pub fn delay(&self, attempt: u32) -> std::time::Duration {
        let factor = 2u32.saturating_pow(attempt.saturating_sub(1));
        self.initial.saturating_mul(factor).min(self.max)
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::netlink::Route {}
    impl Sealed for crate::netlink::Nftables {}
}

/// A protocol with a resync event stream, which a
/// [restarting stream](crate::Connection::events_restarting) can run:
/// [`Route`](crate::netlink::Route) and
/// [`Nftables`](crate::netlink::Nftables) (#523). Sealed.
pub trait Restartable:
    crate::netlink::stream::EventSource + sealed::Sealed + Send + Sync + Sized + 'static
{
    #[doc(hidden)]
    type Resync: Stream<Item = crate::Result<ResyncedEvent<Self::Event>>> + Send + 'static;

    #[doc(hidden)]
    fn resync(
        conn: crate::Connection<Self>,
        factory: ConnectionFactory<Self>,
    ) -> Pin<Box<dyn Future<Output = crate::Result<Self::Resync>> + Send>>;
}

impl Restartable for crate::netlink::Route {
    type Resync = crate::netlink::route_resync::OwnedResyncStream;

    fn resync(
        conn: crate::Connection<Self>,
        factory: ConnectionFactory<Self>,
    ) -> Pin<Box<dyn Future<Output = crate::Result<Self::Resync>> + Send>> {
        Box::pin(conn.into_events_with_resync(factory))
    }
}

impl Restartable for crate::netlink::Nftables {
    type Resync = crate::netlink::nftables::resync::OwnedResyncStream;

    fn resync(
        conn: crate::Connection<Self>,
        factory: ConnectionFactory<Self>,
    ) -> Pin<Box<dyn Future<Output = crate::Result<Self::Resync>> + Send>> {
        Box::pin(conn.into_events_with_resync(factory))
    }
}

/// Whether no restart can get past `e`: the namespace is gone.
pub(crate) fn ends_restarting(e: &crate::Error) -> bool {
    e.is_namespace_deleted()
        || matches!(
            e.detail(),
            crate::ErrorDetail::NotFound {
                object: crate::ErrorObject::Namespace { .. }
            }
        )
}

impl<P: Restartable> crate::Connection<P> {
    /// An event stream that does not end (#523): every group of the
    /// protocol, resynced after an overflow as `into_events_with_resync`
    /// is, on a connection from `factory` — and when that stream ends or
    /// fails, the error is yielded and a new one is made after `backoff`.
    /// For [`Route`](crate::netlink::Route) and
    /// [`Nftables`](crate::netlink::Nftables).
    ///
    /// Each run begins with an initial snapshot
    /// ([`ResyncMarker::InitialSyncStart`]), so a mirror rebuilds itself
    /// after a restart. A namespace deleted under it, or one the factory
    /// cannot find, ends the stream: no restart can bring it back. So
    /// does [`Backoff::max_attempts`] restarts in a row without an event.
    ///
    /// ```no_run
    /// # async fn example() -> nlink::Result<()> {
    /// use std::sync::Arc;
    /// use nlink::netlink::{Connection, Route};
    /// use nlink::netlink::resync::{Backoff, ConnectionFactory};
    /// use tokio_stream::StreamExt;
    ///
    /// let factory: ConnectionFactory<Route> =
    ///     Arc::new(|| Box::pin(async { nlink::Connection::new_in("lab-r1") }));
    /// let mut events = Connection::<Route>::events_restarting(factory, Backoff::default());
    /// while let Some(item) = events.next().await {
    ///     match item {
    ///         Ok(event) => println!("{event:?}"),
    ///         // Reported, and the stream goes on.
    ///         Err(e) => eprintln!("watch restarting: {e}"),
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn events_restarting(factory: ConnectionFactory<P>, backoff: Backoff) -> RestartingStream<P> {
        RestartingStream {
            factory,
            backoff,
            rcvbuf: None,
            state: RestartState::New,
            attempts: 0,
        }
    }
}

type StartFuture<P> = Pin<Box<dyn Future<Output = crate::Result<<P as Restartable>::Resync>> + Send>>;

enum RestartState<P: Restartable> {
    New,
    Starting(StartFuture<P>),
    Running(Pin<Box<P::Resync>>),
    Waiting(Pin<Box<tokio::time::Sleep>>),
    Done,
}

/// The stream of [`Connection::events_restarting`](crate::Connection::events_restarting)
/// (#523).
pub struct RestartingStream<P: Restartable> {
    factory: ConnectionFactory<P>,
    backoff: Backoff,
    rcvbuf: Option<usize>,
    state: RestartState<P>,
    /// Restarts since an event was last delivered.
    attempts: u32,
}

impl<P: Restartable> RestartingStream<P> {
    /// The receive buffer of each run's event socket, in bytes
    /// (`SO_RCVBUFFORCE`, falling back to `SO_RCVBUF`). A larger one
    /// overflows, and resyncs, less often.
    pub fn rcvbuf(mut self, bytes: usize) -> Self {
        self.rcvbuf = Some(bytes);
        self
    }

    fn start(&self) -> StartFuture<P> {
        let factory = self.factory.clone();
        let rcvbuf = self.rcvbuf;
        Box::pin(async move {
            let conn = (factory)().await?;
            if let Some(bytes) = rcvbuf {
                conn.socket().set_rcvbuf(bytes)?;
            }
            P::resync(conn, factory).await
        })
    }

    /// After a failure: wait and start again, or end.
    fn restart_or_end(&mut self, e: &crate::Error) {
        self.attempts += 1;
        let spent = self.backoff.max_attempts.is_some_and(|max| self.attempts > max);
        self.state = if ends_restarting(e) || spent {
            tracing::info!(error = %e, "restarting event stream: giving up");
            RestartState::Done
        } else {
            let delay = self.backoff.delay(self.attempts);
            tracing::warn!(error = %e, ?delay, attempt = self.attempts, "restarting event stream");
            RestartState::Waiting(Box::pin(tokio::time::sleep(delay)))
        };
    }
}

impl<P: Restartable> Unpin for RestartingStream<P> {}

impl<P: Restartable> Stream for RestartingStream<P> {
    type Item = crate::Result<ResyncedEvent<P::Event>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                RestartState::Done => return Poll::Ready(None),
                RestartState::New => this.state = RestartState::Starting(this.start()),
                RestartState::Waiting(sleep) => {
                    if sleep.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    this.state = RestartState::Starting(this.start());
                }
                RestartState::Starting(fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(stream)) => this.state = RestartState::Running(Box::pin(stream)),
                    Poll::Ready(Err(e)) => {
                        this.restart_or_end(&e);
                        return Poll::Ready(Some(Err(e)));
                    }
                },
                RestartState::Running(stream) => match stream.as_mut().poll_next(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Ok(item))) => {
                        if matches!(item, ResyncedEvent::Event(_)) {
                            this.attempts = 0;
                        }
                        return Poll::Ready(Some(Ok(item)));
                    }
                    Poll::Ready(Some(Err(e))) => {
                        this.restart_or_end(&e);
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Ready(None) => {
                        let e = crate::Error::invalid_message("the event stream ended");
                        this.restart_or_end(&e);
                    }
                },
            }
        }
    }
}

/// Internal state-machine state for [`ResyncStream`].
///
/// The `'a` lifetime threads through to the boxed snapshot
/// future. Plan 185 (0.18) made `events_with_resync`
/// lifetime-generic so the snapshot closure can borrow from
/// its environment — required for the borrowed-stream
/// `Connection<P>::subscribe_all_with_resync(&mut self, ...)`
/// shape. Closures that produce `'static` futures (the prior
/// shape) still satisfy `'static: 'a` for any `'a`, so they
/// keep compiling unchanged.
/// How many times a post-`ENOBUFS` redump may be retried when the
/// kernel reports the snapshot was torn (`NLM_F_DUMP_INTR`).
///
/// The redump races the mutations that caused the overflow, so a torn
/// snapshot is expected rather than exceptional. `vishvananda/netlink`
/// retries a handful of times and Cilium's `safenetlink` wrapper up to
/// 30. Thirty here too, and for the reason Cilium picked it: the
/// mutation storm that overflowed the socket is still running while the
/// redump is trying to land, so a handful of attempts loses the race
/// outright.
///
/// Spread over [`REDUMP_RETRY_DELAY`] rather than spun: retrying a dump
/// in a tight loop against a mutating kernel is not a retry, it is a
/// spin that burns the whole budget in microseconds and then reports
/// failure while the storm is still going. Thirty attempts at 50 ms is
/// about a second and a half of tolerance, which outlasts an ordinary
/// burst; a host churning faster than it can be dumped for that long is
/// telling the caller something, and that is when the error surfaces.
const MAX_REDUMP_ATTEMPTS: u8 = 30;

/// Pause between redump attempts. See [`MAX_REDUMP_ATTEMPTS`].
const REDUMP_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

enum ResyncState<'a, T> {
    /// Pulling items from the inner event stream; each item is
    /// yielded as `Event(T)` or — on ENOBUFS — kicks the state
    /// machine into `RunningSnapshot`.
    Forwarding,
    /// Not polled yet, with an initial snapshot to take first
    /// ([`ResyncStream::initial_snapshot`]).
    Initial,
    /// After an ENOBUFS: discarding what the inner stream had already
    /// queued, until it returns `Pending`, before the snapshot is taken.
    ///
    /// The kernel reports the overflow before it dequeues anything, so
    /// every frame queued *before* the overflow is still there. Taken
    /// first, the snapshot was followed by those older frames: a
    /// `NewAddress` whose matching `DelAddress` the overflow dropped was
    /// replayed on top of a snapshot that correctly lacked the address,
    /// and a `Store` kept it forever (#464). Draining also empties the
    /// socket, which the kernel requires before it delivers broadcasts
    /// again (`netlink_rcv_wake`).
    Draining,
    /// Snapshot future is being driven. When it resolves, we
    /// flush `Marker(ResyncStart)` + each item as `Resynced(t)` +
    /// `Marker(ResyncEnd)` via the `Replaying` state.
    RunningSnapshot {
        fut: Pin<Box<dyn Future<Output = crate::Result<Vec<T>>> + Send + 'a>>,
        /// The marker the replay opens with.
        start: ResyncMarker,
        /// Redump attempts already spent on this recovery.
        ///
        /// A redump races the very mutations that caused the
        /// `ENOBUFS`, so `NLM_F_DUMP_INTR` here is the expected case,
        /// not an exceptional one. Fusing the stream on it would mean
        /// a watch-cache gives up precisely when it is busiest. The
        /// kernel's advice is to retry, so we do — a bounded number of
        /// times, then surface the error and let the caller decide.
        attempts: u8,
    },
    /// Snapshot resolved; draining the queue of yet-to-emit items.
    /// `did_emit_start` flips true after the leading marker is
    /// yielded; the trailing marker is yielded when the queue
    /// empties.
    Replaying {
        items: VecDeque<T>,
        did_emit_start: bool,
        start: ResyncMarker,
    },
    /// Waiting out [`REDUMP_RETRY_DELAY`] before the next redump.
    RetryBackoff {
        sleep: Pin<Box<tokio::time::Sleep>>,
        start: ResyncMarker,
        /// Attempts already spent; the next one is `attempts + 1`.
        attempts: u8,
    },
    /// Stream fused after a non-recoverable error.
    Done,
    /// Phantom variant to express the `'a` parameter even when
    /// no live state holds an `'a`-bound future.
    #[doc(hidden)]
    _Phantom(std::marker::PhantomData<&'a ()>),
}

/// Stream wrapper around an inner event stream that handles
/// `ENOBUFS` (multicast overflow) transparently — yields
/// [`ResyncedEvent<T>`] items, automatically running the
/// caller-supplied snapshot closure when the kernel reports a
/// dropped-events condition.
///
/// Construct via [`events_with_resync`]. Implements
/// [`Stream<Item = Result<ResyncedEvent<T>>>`][Stream].
///
/// The state machine emitted on each ENOBUFS recovery:
///
/// 1. `Ok(Marker(ResyncMarker::ResyncStart))` — cue to invalidate
///    incremental state.
/// 2. `Ok(Resynced(item))` for each item the snapshot returned.
/// 3. `Ok(Marker(ResyncMarker::ResyncEnd))` — cue that the replay
///    is complete.
/// 4. Resume `Ok(Event(item))` for subsequent live deltas.
///
/// Non-ENOBUFS errors propagate as `Err(e)` and fuse the stream
/// (subsequent polls return `None`). The closure's own errors
/// (e.g. snapshot failed) also propagate + fuse.
#[must_use = "streams do nothing unless polled"]
#[non_exhaustive]
pub struct ResyncStream<'a, S, T, F>
where
    S: Stream<Item = crate::Result<T>>,
    F: FnMut() -> Pin<Box<dyn Future<Output = crate::Result<Vec<T>>> + Send + 'a>>,
{
    inner: S,
    resync: F,
    state: ResyncState<'a, T>,
}

impl<'a, S, T, F> Stream for ResyncStream<'a, S, T, F>
where
    S: Stream<Item = crate::Result<T>> + Unpin,
    F: FnMut() -> Pin<Box<dyn Future<Output = crate::Result<Vec<T>>> + Send + 'a>> + Unpin,
    T: Unpin,
{
    type Item = crate::Result<ResyncedEvent<T>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            // Take the state out so we can match-and-replace
            // without borrow-checker friction.
            let state = std::mem::replace(&mut this.state, ResyncState::Done);
            match state {
                ResyncState::Done => return Poll::Ready(None),
                // Phantom variant — never constructed; the
                // outer enum carries it only to anchor the `'a`
                // parameter. If we ever land here, treat as
                // fused.
                ResyncState::_Phantom(_) => return Poll::Ready(None),

                ResyncState::Forwarding => {
                    match Pin::new(&mut this.inner).poll_next(cx) {
                        Poll::Ready(Some(Ok(item))) => {
                            this.state = ResyncState::Forwarding;
                            return Poll::Ready(Some(Ok(ResyncedEvent::Event(item))));
                        }
                        Poll::Ready(Some(Err(e))) if e.is_no_buffer_space() => {
                            // ENOBUFS — drain what predates it, then
                            // snapshot (#464).
                            this.state = ResyncState::Draining;
                        }
                        Poll::Ready(Some(Err(e))) => {
                            this.state = ResyncState::Done;
                            return Poll::Ready(Some(Err(e)));
                        }
                        Poll::Ready(None) => {
                            this.state = ResyncState::Done;
                            return Poll::Ready(None);
                        }
                        Poll::Pending => {
                            this.state = ResyncState::Forwarding;
                            return Poll::Pending;
                        }
                    }
                }

                ResyncState::Initial => {
                    // Subscribed before this snapshot is taken, so what
                    // changes during it is queued and follows `ResyncEnd`.
                    let fut = (this.resync)();
                    this.state = ResyncState::RunningSnapshot {
                        fut,
                        start: ResyncMarker::InitialSyncStart,
                        attempts: 1,
                    };
                }

                ResyncState::Draining => match Pin::new(&mut this.inner).poll_next(cx) {
                    // Older than the overflow: superseded by the snapshot.
                    Poll::Ready(Some(Ok(_))) => this.state = ResyncState::Draining,
                    Poll::Ready(Some(Err(e))) if e.is_no_buffer_space() => {
                        this.state = ResyncState::Draining;
                    }
                    Poll::Ready(Some(Err(e))) => {
                        this.state = ResyncState::Done;
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Ready(None) => {
                        this.state = ResyncState::Done;
                        return Poll::Ready(None);
                    }
                    // Nothing queued any more: snapshot now.
                    Poll::Pending => {
                        let fut = (this.resync)();
                        this.state = ResyncState::RunningSnapshot {
                            fut,
                            start: ResyncMarker::ResyncStart,
                            attempts: 1,
                        };
                    }
                },

                ResyncState::RunningSnapshot {
                    mut fut,
                    start,
                    attempts,
                } => {
                    match fut.as_mut().poll(cx) {
                        Poll::Ready(Ok(items)) => {
                            // Flush start marker, then drain.
                            this.state = ResyncState::Replaying {
                                items: items.into(),
                                did_emit_start: false,
                                start,
                            };
                            // Loop to emit the start marker.
                        }
                        // A torn snapshot is the ordinary outcome here:
                        // the redump is racing the same mutations that
                        // overflowed the socket. Retry rather than fuse
                        // — a `Store` rebuilt from a torn dump would
                        // `replace_all` its map with a partial one.
                        Poll::Ready(Err(e))
                            if e.is_dump_interrupted() && attempts < MAX_REDUMP_ATTEMPTS =>
                        {
                            tracing::debug!(
                                attempt = attempts,
                                "resync redump interrupted by concurrent mutation; retrying"
                            );
                            this.state = ResyncState::RetryBackoff {
                                sleep: Box::pin(tokio::time::sleep(REDUMP_RETRY_DELAY)),
                                start,
                                attempts,
                            };
                        }
                        Poll::Ready(Err(e)) => {
                            // Snapshot failed — fuse.
                            this.state = ResyncState::Done;
                            return Poll::Ready(Some(Err(e)));
                        }
                        Poll::Pending => {
                            this.state = ResyncState::RunningSnapshot {
                                fut,
                                start,
                                attempts,
                            };
                            return Poll::Pending;
                        }
                    }
                }

                ResyncState::RetryBackoff {
                    mut sleep,
                    start,
                    attempts,
                } => match sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        let fut = (this.resync)();
                        this.state = ResyncState::RunningSnapshot {
                            fut,
                            start,
                            attempts: attempts + 1,
                        };
                    }
                    Poll::Pending => {
                        this.state = ResyncState::RetryBackoff {
                            sleep,
                            start,
                            attempts,
                        };
                        return Poll::Pending;
                    }
                },

                ResyncState::Replaying {
                    mut items,
                    did_emit_start,
                    start,
                } => {
                    if !did_emit_start {
                        this.state = ResyncState::Replaying {
                            items,
                            did_emit_start: true,
                            start,
                        };
                        return Poll::Ready(Some(Ok(ResyncedEvent::Marker(start))));
                    }
                    if let Some(item) = items.pop_front() {
                        this.state = ResyncState::Replaying {
                            items,
                            did_emit_start: true,
                            start,
                        };
                        return Poll::Ready(Some(Ok(ResyncedEvent::Resynced(item))));
                    }
                    // Queue empty — emit end marker, return to Forwarding.
                    this.state = ResyncState::Forwarding;
                    return Poll::Ready(Some(Ok(ResyncedEvent::Marker(
                        ResyncMarker::ResyncEnd,
                    ))));
                }
            }
        }
    }
}

impl<'a, S, T, F> ResyncStream<'a, S, T, F>
where
    S: Stream<Item = crate::Result<T>>,
    F: FnMut() -> Pin<Box<dyn Future<Output = crate::Result<Vec<T>>> + Send + 'a>>,
{
    /// Begin with a snapshot of the current state: `InitialSyncStart`, the
    /// state as [`ResyncedEvent::Resynced`] items, `ResyncEnd`, then live
    /// events — so a mirror built from the stream is complete from the
    /// start (#503). Takes effect only before the stream is first polled.
    ///
    /// The rtnetlink and nftables resync constructors turn this on; pass
    /// `false` to start from live events only.
    pub fn initial_snapshot(mut self, on: bool) -> Self {
        match (&self.state, on) {
            (ResyncState::Forwarding, true) => self.state = ResyncState::Initial,
            (ResyncState::Initial, false) => self.state = ResyncState::Forwarding,
            _ => {}
        }
        self
    }
}

/// Wrap an event stream so ENOBUFS overflows trigger an
/// automatic snapshot + boundary-marker replay. Returns a
/// [`ResyncStream`] yielding [`ResyncedEvent<T>`] items.
///
/// The `resync` closure is invoked each time the inner stream
/// reports `ENOBUFS`. It returns a future yielding the snapshot
/// items (typically by calling the matching `get_*` method on a
/// fresh connection). Wrap the async body in `Box::pin(...)` so
/// the future is `Pin<Box<dyn Future + Send>>`.
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::ResyncMarker;
/// use nlink::{Connection, Route};
/// use nlink::netlink::resync::{events_with_resync, ResyncedEvent};
/// use tokio_stream::StreamExt;
///
/// let mut events_conn = Connection::<Route>::new()?;
/// events_conn.subscribe_all()?;
/// let raw_events = events_conn.events().await;
///
/// // dump_conn is a separate connection so the resync dump
/// // doesn't interleave with the live events on the same socket.
/// let dump_conn = std::sync::Arc::new(Connection::<Route>::new()?);
///
/// let mut stream = events_with_resync(raw_events, move || {
///     let conn = dump_conn.clone();
///     Box::pin(async move {
///         let links = conn.get_links().await?;
///         Ok(links.into_iter().map(nlink::NetworkEvent::NewLink).collect())
///     })
/// });
///
/// while let Some(item) = stream.next().await {
///     match item? {
///         ResyncedEvent::Event(ev) => { /* live delta */ }
///         ResyncedEvent::Marker(ResyncMarker::ResyncStart) => {
///             /* invalidate incremental state */
///         }
///         ResyncedEvent::Resynced(item) => { /* replay item */ }
///         ResyncedEvent::Marker(ResyncMarker::ResyncEnd) => {
///             /* state is fully rebuilt; resume normal processing */
///         }
///         _ => {}
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub fn events_with_resync<'a, S, T, F>(
    events: S,
    resync: F,
) -> ResyncStream<'a, S, T, F>
where
    S: Stream<Item = crate::Result<T>> + Unpin,
    F: FnMut() -> Pin<Box<dyn Future<Output = crate::Result<Vec<T>>> + Send + 'a>> + Unpin,
    T: Unpin,
{
    ResyncStream {
        inner: events,
        resync,
        state: ResyncState::Forwarding,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restarting_streams_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<RestartingStream<crate::netlink::Route>>();
        assert_send::<RestartingStream<crate::netlink::Nftables>>();
    }

    /// A factory that never succeeds: an error per attempt, the waits
    /// growing, then the end after `max_attempts` restarts.
    #[tokio::test]
    async fn a_restarting_stream_gives_up_after_max_attempts() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::time::Duration;
        use tokio_stream::StreamExt;

        use crate::netlink::Route;

        let calls = Arc::new(AtomicU32::new(0));
        let counted = calls.clone();
        let factory: ConnectionFactory<Route> = Arc::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(crate::Error::invalid_message("not yet")) })
        });
        let backoff = Backoff::new(Duration::from_millis(5), Duration::from_millis(20)).max_attempts(2);
        let mut stream = crate::Connection::<Route>::events_restarting(factory, backoff);
        let mut errors = 0;
        while let Some(item) = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("the stream ends")
        {
            assert!(item.is_err(), "{item:?}");
            errors += 1;
        }
        assert_eq!(errors, 3, "the first attempt and two restarts");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn backoff_doubles_up_to_its_max() {
        use std::time::Duration;
        let b = Backoff::new(Duration::from_millis(100), Duration::from_secs(1));
        let waits: Vec<_> = (1..=6).map(|n| b.delay(n).as_millis()).collect();
        assert_eq!(waits, [100, 200, 400, 800, 1000, 1000]);
        assert_eq!(b.delay(u32::MAX), Duration::from_secs(1), "no overflow");
        assert_eq!(Backoff::default().max_attempts, None);
    }

    #[test]
    fn marker_predicates() {
        let start: ResyncedEvent<u32> = ResyncedEvent::Marker(ResyncMarker::ResyncStart);
        let end: ResyncedEvent<u32> = ResyncedEvent::Marker(ResyncMarker::ResyncEnd);
        let event = ResyncedEvent::Event(42u32);
        let resynced = ResyncedEvent::Resynced(7u32);

        assert!(start.is_resync_start());
        assert!(!start.is_resync_end());
        assert!(end.is_resync_end());
        assert!(!end.is_resync_start());
        assert!(!event.is_resync_start());
        assert!(!resynced.is_resync_end());
    }

    #[test]
    fn inner_extraction_skips_markers() {
        let start: ResyncedEvent<u32> = ResyncedEvent::Marker(ResyncMarker::ResyncStart);
        let event = ResyncedEvent::Event(42u32);
        let resynced = ResyncedEvent::Resynced(7u32);

        assert_eq!(start.clone().into_inner(), None);
        assert_eq!(event.clone().into_inner(), Some(42));
        assert_eq!(resynced.clone().into_inner(), Some(7));

        assert_eq!(start.as_inner(), None);
        assert_eq!(event.as_inner(), Some(&42));
        assert_eq!(resynced.as_inner(), Some(&7));
    }

    // ---- Plan 151 §4.2 — `events_with_resync` Stream wrapper ----

    use tokio_stream::StreamExt;

    /// Synthetic event stream — yields a scripted sequence of
    /// `Result<u32>` items so we can drive the state machine
    /// through every branch without a kernel.
    struct ScriptedStream {
        items: VecDeque<Step>,
    }

    /// One step of a script: an item, or a moment with nothing queued.
    enum Step {
        Item(crate::Result<u32>),
        Pending,
    }

    impl ScriptedStream {
        /// The items as a socket delivers them: with nothing queued right
        /// after each overflow, so what follows one is newer than the
        /// snapshot.
        fn new(items: Vec<crate::Result<u32>>) -> Self {
            let mut steps = VecDeque::new();
            for item in items {
                let overflow = matches!(&item, Err(e) if e.is_no_buffer_space());
                steps.push_back(Step::Item(item));
                if overflow {
                    steps.push_back(Step::Pending);
                }
            }
            Self { items: steps }
        }

        /// The steps exactly as given.
        fn steps(steps: Vec<Step>) -> Self {
            Self {
                items: steps.into(),
            }
        }
    }

    impl Stream for ScriptedStream {
        type Item = crate::Result<u32>;
        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.items.pop_front() {
                Some(Step::Item(item)) => Poll::Ready(Some(item)),
                Some(Step::Pending) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                None => Poll::Ready(None),
            }
        }
    }

    fn enobufs() -> crate::Error {
        crate::Error::from_errno(-libc::ENOBUFS)
    }

    #[tokio::test]
    async fn resync_stream_passes_events_through() {
        let s = ScriptedStream::new(vec![Ok(1u32), Ok(2), Ok(3)]);
        let mut stream = events_with_resync(s, || {
            Box::pin(async move { Ok::<Vec<u32>, crate::Error>(vec![]) })
        });
        let mut got = Vec::new();
        while let Some(item) = stream.next().await {
            got.push(item.unwrap());
        }
        assert_eq!(got.len(), 3);
        assert!(matches!(got[0], ResyncedEvent::Event(1)));
        assert!(matches!(got[1], ResyncedEvent::Event(2)));
        assert!(matches!(got[2], ResyncedEvent::Event(3)));
    }

    #[tokio::test]
    async fn resync_stream_handles_enobufs_with_replay() {
        let s = ScriptedStream::new(vec![Ok(1u32), Err(enobufs()), Ok(99)]);
        let mut stream = events_with_resync(s, || {
            Box::pin(async move { Ok::<Vec<u32>, crate::Error>(vec![10, 20, 30]) })
        });
        let mut got = Vec::new();
        while let Some(item) = stream.next().await {
            got.push(item.unwrap());
        }
        // Expected:
        //   Event(1)
        //   Marker(ResyncStart)
        //   Resynced(10) Resynced(20) Resynced(30)
        //   Marker(ResyncEnd)
        //   Event(99)
        assert_eq!(got.len(), 7);
        assert!(matches!(got[0], ResyncedEvent::Event(1)));
        assert!(got[1].is_resync_start());
        assert!(matches!(got[2], ResyncedEvent::Resynced(10)));
        assert!(matches!(got[3], ResyncedEvent::Resynced(20)));
        assert!(matches!(got[4], ResyncedEvent::Resynced(30)));
        assert!(got[5].is_resync_end());
        assert!(matches!(got[6], ResyncedEvent::Event(99)));
    }

    #[tokio::test]
    async fn a_torn_redump_is_retried_not_fused() {
        use std::sync::atomic::{AtomicU8, Ordering};

        // The redump races the mutations that overflowed the socket,
        // so `NLM_F_DUMP_INTR` is the ordinary outcome. Before the
        // dump-termination work nftables never even checked the flag;
        // once it did, the resync integration test — which fires 2000
        // rule inserts at a 256-byte rcvbuf — started failing with
        // `DumpInterrupted` (#271).
        let attempts = std::sync::Arc::new(AtomicU8::new(0));
        let a = attempts.clone();
        let s = ScriptedStream::new(vec![Ok(1u32), Err(enobufs())]);
        let mut stream = events_with_resync(s, move || {
            let a = a.clone();
            Box::pin(async move {
                // Torn twice, then a clean snapshot.
                if a.fetch_add(1, Ordering::SeqCst) < 2 {
                    Err(crate::Error::dump_interrupted())
                } else {
                    Ok::<Vec<u32>, crate::Error>(vec![7])
                }
            })
        });
        let mut got = Vec::new();
        while let Some(item) = stream.next().await {
            got.push(item.unwrap());
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 3, "should have retried twice");
        assert!(matches!(got[0], ResyncedEvent::Event(1)));
        assert!(got[1].is_resync_start());
        assert!(matches!(got[2], ResyncedEvent::Resynced(7)));
        assert!(got[3].is_resync_end());
    }

    #[tokio::test]
    async fn a_redump_that_stays_torn_eventually_surfaces_the_error() {
        // Retrying forever would hide a host churning faster than it
        // can be dumped. After MAX_REDUMP_ATTEMPTS the caller hears
        // about it and picks its own policy.
        use std::sync::atomic::{AtomicU8, Ordering};

        let attempts = std::sync::Arc::new(AtomicU8::new(0));
        let a = attempts.clone();
        let s = ScriptedStream::new(vec![Err(enobufs())]);
        let mut stream = events_with_resync(s, move || {
            let a = a.clone();
            Box::pin(async move {
                a.fetch_add(1, Ordering::SeqCst);
                Err::<Vec<u32>, crate::Error>(crate::Error::dump_interrupted())
            })
        });
        let first = stream.next().await.expect("an item");
        assert!(first.unwrap_err().is_dump_interrupted());
        assert_eq!(attempts.load(Ordering::SeqCst), MAX_REDUMP_ATTEMPTS);
        // …and the stream fuses.
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn resync_stream_replay_with_empty_snapshot_still_emits_markers() {
        let s = ScriptedStream::new(vec![Err(enobufs()), Ok(1u32)]);
        let mut stream = events_with_resync(s, || {
            Box::pin(async move { Ok::<Vec<u32>, crate::Error>(vec![]) })
        });
        let mut got = Vec::new();
        while let Some(item) = stream.next().await {
            got.push(item.unwrap());
        }
        // Even with empty snapshot, both markers must fire so the
        // consumer can rebuild its state-machine boundary.
        assert_eq!(got.len(), 3);
        assert!(got[0].is_resync_start());
        assert!(got[1].is_resync_end());
        assert!(matches!(got[2], ResyncedEvent::Event(1)));
    }

    #[tokio::test]
    async fn resync_stream_propagates_non_enobufs_error_and_fuses() {
        let s = ScriptedStream::new(vec![
            Ok(1u32),
            Err(crate::Error::from_errno(-libc::EPERM)),
            Ok(99), // should NOT be yielded
        ]);
        let mut stream = events_with_resync(s, || {
            Box::pin(async move { Ok::<Vec<u32>, crate::Error>(vec![]) })
        });
        let mut results = Vec::new();
        while let Some(item) = stream.next().await {
            results.push(item);
        }
        // Expected:
        //   Ok(Event(1))
        //   Err(EPERM)
        //   None (fused)
        assert_eq!(results.len(), 2);
        assert!(matches!(results[0].as_ref().unwrap(), ResyncedEvent::Event(1)));
        assert!(results[1].as_ref().unwrap_err().is_permission_denied());
    }

    #[tokio::test]
    async fn resync_stream_propagates_snapshot_failure_and_fuses() {
        let s = ScriptedStream::new(vec![Err(enobufs())]);
        let mut stream = events_with_resync(s, || {
            Box::pin(async move {
                Err::<Vec<u32>, crate::Error>(crate::Error::from_errno(-libc::ENODEV))
            })
        });
        let mut results = Vec::new();
        while let Some(item) = stream.next().await {
            results.push(item);
        }
        // Snapshot failed → fuse with the snapshot's error.
        assert_eq!(results.len(), 1);
        assert!(results[0].as_ref().unwrap_err().errno() == Some(libc::ENODEV));
    }

    /// With an initial snapshot the stream begins with the state as it is,
    /// marked `InitialSyncStart` … `ResyncEnd`, then live events (#503).
    #[tokio::test]
    async fn an_initial_snapshot_comes_first() {
        let s = ScriptedStream::new(vec![Ok(5u32)]);
        let mut stream = events_with_resync(s, || {
            Box::pin(async move { Ok::<Vec<u32>, crate::Error>(vec![1, 2]) })
        })
        .initial_snapshot(true);
        let mut got = Vec::new();
        while let Some(item) = stream.next().await {
            got.push(item.unwrap());
        }
        assert!(got[0].is_initial_sync_start());
        assert!(matches!(got[1], ResyncedEvent::Resynced(1)));
        assert!(matches!(got[2], ResyncedEvent::Resynced(2)));
        assert!(got[3].is_resync_end());
        assert!(matches!(got[4], ResyncedEvent::Event(5)));
        assert_eq!(got.len(), 5);
    }

    /// What the stream had queued when the overflow was reported is
    /// older than the snapshot and is dropped; only what arrives after the
    /// queue emptied is delivered after `ResyncEnd` (#464). Taken first,
    /// the snapshot was followed by the stale `NewAddress` of an address
    /// whose `DelAddress` the overflow had dropped.
    #[tokio::test]
    async fn frames_queued_before_an_overflow_are_not_replayed() {
        let s = ScriptedStream::steps(vec![
            Step::Item(Ok(1u32)),
            Step::Item(Err(enobufs())),
            Step::Item(Ok(2)), // queued before the overflow: stale
            Step::Item(Ok(3)), // stale
            Step::Pending,     // the queue is empty
            Step::Item(Ok(4)), // after the snapshot
        ]);
        let mut stream = events_with_resync(s, || {
            Box::pin(async move { Ok::<Vec<u32>, crate::Error>(vec![10]) })
        });
        let mut got = Vec::new();
        while let Some(item) = stream.next().await {
            got.push(item.unwrap());
        }
        assert!(matches!(got[0], ResyncedEvent::Event(1)));
        assert!(got[1].is_resync_start());
        assert!(matches!(got[2], ResyncedEvent::Resynced(10)));
        assert!(got[3].is_resync_end());
        assert!(matches!(got[4], ResyncedEvent::Event(4)));
        assert_eq!(got.len(), 5, "the stale 2 and 3 were dropped");
    }

    #[tokio::test]
    async fn resync_stream_handles_multiple_enobufs_recoveries() {
        let s = ScriptedStream::new(vec![Ok(1u32), Err(enobufs()), Ok(2), Err(enobufs()), Ok(3)]);
        let mut call_count = 0;
        let mut stream = events_with_resync(s, move || {
            call_count += 1;
            let count = call_count;
            Box::pin(async move { Ok::<Vec<u32>, crate::Error>(vec![count * 100]) })
        });
        let mut got = Vec::new();
        while let Some(item) = stream.next().await {
            got.push(item.unwrap());
        }
        // Expected:
        //   Event(1)
        //   Start, Resynced(100), End  (first recovery)
        //   Event(2)
        //   Start, Resynced(200), End  (second recovery)
        //   Event(3)
        assert_eq!(got.len(), 9);
        assert!(matches!(got[0], ResyncedEvent::Event(1)));
        assert!(got[1].is_resync_start());
        assert!(matches!(got[2], ResyncedEvent::Resynced(100)));
        assert!(got[3].is_resync_end());
        assert!(matches!(got[4], ResyncedEvent::Event(2)));
        assert!(got[5].is_resync_start());
        assert!(matches!(got[6], ResyncedEvent::Resynced(200)));
        assert!(got[7].is_resync_end());
        assert!(matches!(got[8], ResyncedEvent::Event(3)));
    }
}
