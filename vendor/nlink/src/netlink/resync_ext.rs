//! Composable combinators on top of resync streams —
//! kube-rs-style stream extensions.
//!
//! Plan 195 ships a small `ResyncStreamExt` trait providing
//! composable adapters mirroring `kube_rs::utils::WatchStreamExt`:
//!
//! - [`ResyncStreamExt::predicate_filter`] — drop consecutive
//!   events whose key matches the previous one. Useful when
//!   the underlying stream re-emits on unrelated changes.
//! - [`ResyncStreamExt::map_event`] — project the inner payload
//!   of `Event(T)` / `Resynced(T)` to a domain-specific type;
//!   `Marker` items pass through unchanged.
//!
//! - [`ResyncStreamExt::with_gap_deltas`] — report what went missing
//!   while the stream was not looking: a synthetic deletion, before the
//!   resync closes, for each object the snapshot no longer has (#523).
//!
//! The combinators apply uniformly to the nftables (Plan 185)
//! and Route (Plan 191) resync streams — no per-protocol
//! duplication.
//!
//! `default_backoff()` + `StreamBackoff` are deferred to a
//! follow-up commit if a consumer needs in-stream backoff
//! (the resync wrapper handles ENOBUFS internally; most
//! consumers handle restart backoff at the spawn-loop level
//! via `tokio::time::sleep`).
//!
//! Like [`ResyncStream`](super::resync::ResyncStream) itself,
//! the adapters require `Unpin` on the inner stream — a bound
//! that holds for the watcher streams nlink ships today.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let conn = nlink::Connection::<nlink::Route>::new()?;
//! use std::sync::Arc;
//!
//! use nlink::netlink::resync::ResyncedEvent;
//! use nlink::netlink::resync_ext::ResyncStreamExt;
//! use nlink::{Connection, Route};
//! use tokio_stream::StreamExt;
//!
//! // Resync needs a second connection to dump from, built on demand.
//! let factory: nlink::netlink::resync::ConnectionFactory<Route> =
//!     Arc::new(|| Box::pin(async { Connection::<Route>::new() }));
//!
//! // Collapse runs of events that carry the same key — here, the
//! // interface the event is about.
//! let mut watch = conn
//!     .into_events_with_resync(factory)
//!     .await?
//!     .predicate_filter(|ev| match ev {
//!         ResyncedEvent::Event(e) | ResyncedEvent::Resynced(e) => format!("{e:?}"),
//!         ResyncedEvent::Marker(m) => format!("{m:?}"),
//!         _ => String::new(),
//!     });
//!
//! while let Some(ev) = watch.next().await {
//!     println!("{:?}", ev?);
//! }
//! # Ok(())
//! # }
//! ```

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio_stream::Stream;

use std::collections::{BTreeMap, VecDeque};

use super::resync::{ResyncMarker, ResyncedEvent};

/// Extension trait providing composable combinators on top of
/// [`ResyncStream`](super::resync::ResyncStream) and any other
/// `Stream<Item = Result<ResyncedEvent<T>>>` that's also
/// `Unpin`.
///
/// Mirrors the shape of [`kube-rs`' `WatchStreamExt`][kube-watch-stream]:
/// small composable adapters that don't couple filter / map
/// policy to the underlying watcher infrastructure.
///
/// Plan 195.
///
/// [kube-watch-stream]: https://docs.rs/kube-runtime/latest/kube_runtime/utils/trait.WatchStreamExt.html
pub trait ResyncStreamExt<T>:
    Stream<Item = crate::Result<ResyncedEvent<T>>> + Sized + Unpin
{
    /// Drop consecutive `Event(T)` / `Resynced(T)` items whose
    /// key matches the previously-emitted item's key. Markers
    /// pass through unchanged.
    ///
    /// The key function picks the fields that constitute a
    /// "meaningful change". Useful when the underlying stream
    /// re-emits events on unrelated changes (e.g. a neighbor
    /// event on every neighbor-cache update).
    ///
    /// Mirrors `WatchStreamExt::predicate_filter`. Plan 195.
    fn predicate_filter<K, F>(self, key: F) -> PredicateFilter<Self, T, K, F>
    where
        K: PartialEq + Clone,
        F: FnMut(&ResyncedEvent<T>) -> K,
    {
        PredicateFilter::new(self, key)
    }

    /// Map the inner `T` of every `Event(T)` / `Resynced(T)`
    /// item via the closure. `Marker` items pass through
    /// untouched.
    ///
    /// Convenience for consumers projecting the kernel event
    /// payload to a domain-specific type once at the watcher
    /// boundary. Plan 195.
    fn map_event<U, F>(self, f: F) -> MapEvent<Self, T, U, F>
    where
        F: FnMut(T) -> U,
    {
        MapEvent::new(self, f)
    }

    /// Report what changed while the stream was not looking (#523).
    ///
    /// A resync replays the state as it is, which says what exists but
    /// not what went away: an object deleted during the overflow — or
    /// while a [restarting](crate::netlink::Connection::events_restarting)
    /// stream was down — is simply absent from the snapshot. This adapter
    /// remembers every object the stream has reported, keyed by `key`,
    /// and when a snapshot ends without one it yields that object's
    /// removal ([`GapDelta::removal`]) as a `Resynced` item, just before
    /// the closing [`ResyncEnd`](super::resync::ResyncMarker::ResyncEnd).
    /// They come in key order.
    ///
    /// So a consumer that applies events as they come — upserting `New*`,
    /// removing `Del*`, `Resynced` or not — stays equal to the kernel
    /// without clearing anything at `ResyncStart`.
    ///
    /// `key` names the object an event is about, or `None` for one not to
    /// track; [`NetworkEvent::object_key`](super::events::NetworkEvent::object_key)
    /// and [`NftablesEvent::object_key`](super::nftables::NftablesEvent::object_key)
    /// are ready-made. It holds a copy of every tracked object.
    ///
    /// ```no_run
    /// # async fn example(factory: nlink::netlink::resync::ConnectionFactory<nlink::Route>) -> nlink::Result<()> {
    /// use nlink::netlink::{Connection, NetworkEvent};
    /// use nlink::netlink::resync::Backoff;
    /// use nlink::netlink::resync_ext::ResyncStreamExt;
    /// use tokio_stream::StreamExt;
    ///
    /// let mut events = Connection::events_restarting(factory, Backoff::default())
    ///     .with_gap_deltas(NetworkEvent::object_key);
    /// while let Some(item) = events.next().await {
    ///     // A link deleted during an overflow arrives as a `DelLink`.
    ///     println!("{:?}", item?);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    fn with_gap_deltas<K, F>(self, key: F) -> GapDeltas<Self, T, K, F>
    where
        T: GapDelta + Clone,
        K: Ord,
        F: FnMut(&T) -> Option<K>,
    {
        GapDeltas {
            inner: self,
            key,
            live: BTreeMap::new(),
            staging: None,
            pending: VecDeque::new(),
        }
    }
}

/// An event that can say how its object's removal is reported, for
/// [`ResyncStreamExt::with_gap_deltas`] (#523).
pub trait GapDelta: Sized {
    /// Whether this event reports a removal (`Del*`).
    fn is_removal(&self) -> bool;

    /// The event that reports the removal of the object this one is
    /// about: `NewLink(l)` → `DelLink(l)`. `None` for an event that is
    /// itself a removal, or one with no removal counterpart.
    fn removal(&self) -> Option<Self>;
}

/// What an event is about, for [`ResyncStreamExt::with_gap_deltas`]
/// (#523): a kind and an identity within it, as the kernel tells two
/// objects apart.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectKey {
    kind: &'static str,
    id: String,
}

impl ObjectKey {
    /// A key of `kind` (`"link"`, `"route"`, …) identified by `id`.
    pub fn new(kind: &'static str, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
    }

    /// The kind of object: `"link"`, `"address"`, `"table"`, ….
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    /// The object's identity within its kind.
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl std::fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.kind, self.id)
    }
}

/// Stream adapter that reports objects a resync found gone. Created via
/// [`ResyncStreamExt::with_gap_deltas`].
pub struct GapDeltas<S, T, K, F> {
    inner: S,
    key: F,
    /// Every object reported so far.
    live: BTreeMap<K, T>,
    /// Inside a snapshot: the objects it has reported.
    staging: Option<BTreeMap<K, T>>,
    /// Removals to yield, then the `ResyncEnd` they precede.
    pending: VecDeque<ResyncedEvent<T>>,
}

impl<S, T, K, F> Unpin for GapDeltas<S, T, K, F> where S: Unpin {}

impl<S, T, K, F> Stream for GapDeltas<S, T, K, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    T: GapDelta + Clone,
    K: Ord,
    F: FnMut(&T) -> Option<K>,
{
    type Item = crate::Result<ResyncedEvent<T>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(item) = this.pending.pop_front() {
            return Poll::Ready(Some(Ok(item)));
        }
        let item = match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(item))) => item,
            Poll::Ready(Some(Err(e))) => {
                // A snapshot cut short says nothing about what is gone.
                this.staging = None;
                return Poll::Ready(Some(Err(e)));
            }
            other => return other,
        };
        match &item {
            ResyncedEvent::Marker(ResyncMarker::ResyncStart | ResyncMarker::InitialSyncStart) => {
                this.staging = Some(BTreeMap::new());
            }
            ResyncedEvent::Marker(ResyncMarker::ResyncEnd) => {
                if let Some(next) = this.staging.take() {
                    let before = std::mem::replace(&mut this.live, next);
                    for (key, value) in before {
                        if !this.live.contains_key(&key)
                            && let Some(removal) = value.removal()
                        {
                            this.pending.push_back(ResyncedEvent::Resynced(removal));
                        }
                    }
                    if let Some(first) = this.pending.pop_front() {
                        this.pending.push_back(item);
                        return Poll::Ready(Some(Ok(first)));
                    }
                }
            }
            ResyncedEvent::Event(value) | ResyncedEvent::Resynced(value) => {
                if let Some(key) = (this.key)(value) {
                    let objects = this.staging.as_mut().unwrap_or(&mut this.live);
                    if value.is_removal() {
                        objects.remove(&key);
                    } else {
                        objects.insert(key, value.clone());
                    }
                }
            }
        }
        Poll::Ready(Some(Ok(item)))
    }
}

// Blanket impl over every Stream of the right shape.
impl<S, T> ResyncStreamExt<T> for S where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin
{
}

// =============================================================
// PredicateFilter
// =============================================================

/// Stream adapter that drops `Event(T)` / `Resynced(T)` items
/// whose key matches the previously-emitted item's key.
/// Created via [`ResyncStreamExt::predicate_filter`].
pub struct PredicateFilter<S, T, K, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    K: PartialEq + Clone,
    F: FnMut(&ResyncedEvent<T>) -> K,
{
    inner: S,
    key_fn: F,
    last_key: Option<K>,
    _phantom: std::marker::PhantomData<T>,
}

impl<S, T, K, F> PredicateFilter<S, T, K, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    K: PartialEq + Clone,
    F: FnMut(&ResyncedEvent<T>) -> K,
{
    fn new(inner: S, key_fn: F) -> Self {
        Self {
            inner,
            key_fn,
            last_key: None,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<S, T, K, F> Unpin for PredicateFilter<S, T, K, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    K: PartialEq + Clone,
    F: FnMut(&ResyncedEvent<T>) -> K,
{
}

impl<S, T, K, F> Stream for PredicateFilter<S, T, K, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    K: PartialEq + Clone,
    F: FnMut(&ResyncedEvent<T>) -> K,
{
    type Item = crate::Result<ResyncedEvent<T>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(Some(Ok(item))) => {
                    // Markers always pass through — they're
                    // state-machine signals, not delta payloads.
                    if matches!(item, ResyncedEvent::Marker(_)) {
                        // …and `ResyncStart` clears the dedup memory.
                        //
                        // `last_key` used to be carried across the
                        // marker, so if the last live event before
                        // ENOBUFS and the redump's first item were for
                        // the same object, the *replayed* copy was
                        // deduped away — immediately after the consumer
                        // had been told to invalidate its state, which
                        // is precisely when it needs that item most
                        // (#281).
                        //
                        // The old test pinned the old behaviour
                        // ("post-marker — still drops"), so this is a
                        // deliberate contract change, not an oversight
                        // being corrected: a resync replay is a fresh
                        // snapshot and nothing before it is a duplicate
                        // of anything in it.
                        if item.is_resync_start() {
                            this.last_key = None;
                        }
                        return Poll::Ready(Some(Ok(item)));
                    }
                    let key = (this.key_fn)(&item);
                    if this.last_key.as_ref() == Some(&key) {
                        // Duplicate — silently drop, loop for next.
                        continue;
                    }
                    this.last_key = Some(key);
                    return Poll::Ready(Some(Ok(item)));
                }
            }
        }
    }
}

// =============================================================
// MapEvent
// =============================================================

/// Stream adapter that maps the inner `T` of every `Event(T)` /
/// `Resynced(T)` item via a closure. `Marker` items are passed
/// through untouched. Created via [`ResyncStreamExt::map_event`].
pub struct MapEvent<S, T, U, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    F: FnMut(T) -> U,
{
    inner: S,
    map_fn: F,
    _phantom: std::marker::PhantomData<(T, U)>,
}

impl<S, T, U, F> MapEvent<S, T, U, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    F: FnMut(T) -> U,
{
    fn new(inner: S, map_fn: F) -> Self {
        Self {
            inner,
            map_fn,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<S, T, U, F> Unpin for MapEvent<S, T, U, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    F: FnMut(T) -> U,
{
}

impl<S, T, U, F> Stream for MapEvent<S, T, U, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin,
    F: FnMut(T) -> U,
{
    type Item = crate::Result<ResyncedEvent<U>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Some(Ok(item))) => {
                let mapped = match item {
                    ResyncedEvent::Event(t) => ResyncedEvent::Event((this.map_fn)(t)),
                    ResyncedEvent::Resynced(t) => ResyncedEvent::Resynced((this.map_fn)(t)),
                    ResyncedEvent::Marker(m) => ResyncedEvent::Marker(m),
                };
                Poll::Ready(Some(Ok(mapped)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    /// `(key, alive)`: `false` reports a removal.
    impl GapDelta for (u32, bool) {
        fn is_removal(&self) -> bool {
            !self.1
        }
        fn removal(&self) -> Option<Self> {
            self.1.then_some((self.0, false))
        }
    }

    #[tokio::test]
    async fn gap_deltas_report_what_a_snapshot_lost() {
        use ResyncMarker::*;
        let items = vec![
            Ok(ResyncedEvent::Marker(InitialSyncStart)),
            Ok(ResyncedEvent::Resynced((1, true))),
            Ok(ResyncedEvent::Resynced((2, true))),
            Ok(ResyncedEvent::Marker(ResyncEnd)),
            Ok(ResyncedEvent::Event((3, true))),
            Ok(ResyncedEvent::Event((4, true))),
            Ok(ResyncedEvent::Event((4, false))),
            // The overflow: 2 and 3 went, 5 came.
            Ok(ResyncedEvent::Marker(ResyncStart)),
            Ok(ResyncedEvent::Resynced((1, true))),
            Ok(ResyncedEvent::Resynced((5, true))),
            Ok(ResyncedEvent::Marker(ResyncEnd)),
            Ok(ResyncedEvent::Event((6, true))),
        ];
        let out: Vec<_> = synth_stream(items)
            .with_gap_deltas(|e: &(u32, bool)| Some(e.0))
            .map(|r| r.unwrap())
            .collect()
            .await;
        let tail: Vec<_> = out[7..].iter().map(|e| format!("{e:?}")).collect();
        assert_eq!(
            tail,
            [
                "Marker(ResyncStart)",
                "Resynced((1, true))",
                "Resynced((5, true))",
                "Resynced((2, false))",
                "Resynced((3, false))",
                "Marker(ResyncEnd)",
                "Event((6, true))",
            ]
        );
        // The initial snapshot finds nothing gone: nothing was known.
        assert_eq!(format!("{:?}", out[3]), "Marker(ResyncEnd)");
    }

    #[tokio::test]
    async fn gap_deltas_ignore_a_snapshot_cut_short() {
        use ResyncMarker::*;
        let items = vec![
            Ok(ResyncedEvent::Event((1, true))),
            Ok(ResyncedEvent::Marker(ResyncStart)),
            Err(crate::Error::invalid_message("cut")),
            Ok(ResyncedEvent::Marker(ResyncEnd)),
        ];
        let out: Vec<_> = synth_stream(items)
            .with_gap_deltas(|e: &(u32, bool)| Some(e.0))
            .collect()
            .await;
        assert_eq!(out.len(), 4, "no removal of 1: {out:?}");
    }

    fn synth_stream<T: 'static>(
        items: Vec<crate::Result<ResyncedEvent<T>>>,
    ) -> impl Stream<Item = crate::Result<ResyncedEvent<T>>> + Unpin {
        tokio_stream::iter(items)
    }

    #[tokio::test]
    async fn predicate_filter_dedupes_consecutive_equal_keys() {
        let items = vec![
            Ok(ResyncedEvent::Event(("a", 1))),
            Ok(ResyncedEvent::Event(("a", 2))), // same key, drop
            Ok(ResyncedEvent::Event(("b", 1))),
            Ok(ResyncedEvent::Event(("a", 3))), // key changed back
        ];
        let s = synth_stream(items);
        let filtered: Vec<_> = s
            .predicate_filter(|e| match e {
                ResyncedEvent::Event((k, _)) => *k,
                ResyncedEvent::Resynced((k, _)) => *k,
                _ => "",
            })
            .collect()
            .await;
        assert_eq!(filtered.len(), 3, "duplicate ('a', 2) must drop");
    }

    #[tokio::test]
    async fn predicate_filter_passes_markers_unchanged() {
        // Markers are state-machine signals — never deduped,
        // regardless of the surrounding key sequence.
        //
        // And `ResyncStart` *clears* the dedup memory. This test used
        // to assert the opposite ("same key as first, post-marker —
        // still drops"), which pinned a real bug: the replayed copy of
        // an object was swallowed immediately after the consumer had
        // been told to invalidate its state (#281). A resync replay is
        // a fresh snapshot; nothing before it is a duplicate of
        // anything in it.
        let items: Vec<crate::Result<ResyncedEvent<&'static str>>> = vec![
            Ok(ResyncedEvent::Event("a")),
            Ok(ResyncedEvent::Marker(ResyncMarker::ResyncStart)),
            Ok(ResyncedEvent::Marker(ResyncMarker::ResyncStart)), // even adjacent markers stay
            Ok(ResyncedEvent::Resynced("a")), // the replayed copy — must survive
            Ok(ResyncedEvent::Resynced("a")), // …but a real repeat still drops
        ];
        let s = synth_stream(items);
        let filtered: Vec<_> = s
            .predicate_filter(|e| match e {
                ResyncedEvent::Event(s) => *s,
                ResyncedEvent::Resynced(s) => *s,
                _ => "",
            })
            .collect()
            .await;
        // First "a", both markers, and the first replayed "a".
        assert_eq!(filtered.len(), 4, "got {filtered:?}");
        assert!(matches!(
            filtered[1].as_ref().unwrap(),
            ResyncedEvent::Marker(ResyncMarker::ResyncStart)
        ));
        assert!(matches!(
            filtered[2].as_ref().unwrap(),
            ResyncedEvent::Marker(ResyncMarker::ResyncStart)
        ));
        assert!(
            matches!(filtered[3].as_ref().unwrap(), ResyncedEvent::Resynced("a")),
            "the replayed copy must survive the marker"
        );
    }

    #[tokio::test]
    async fn map_event_transforms_event_and_resynced_variants() {
        let items = vec![
            Ok(ResyncedEvent::Event(5_i32)),
            Ok(ResyncedEvent::Resynced(10_i32)),
            Ok(ResyncedEvent::Marker(ResyncMarker::ResyncStart)),
        ];
        let s = synth_stream(items);
        let mapped: Vec<_> = s.map_event(|i: i32| i * 2).collect().await;
        match mapped[0].as_ref().unwrap() {
            ResyncedEvent::Event(v) => assert_eq!(*v, 10),
            other => panic!("expected Event, got {other:?}"),
        }
        match mapped[1].as_ref().unwrap() {
            ResyncedEvent::Resynced(v) => assert_eq!(*v, 20),
            other => panic!("expected Resynced, got {other:?}"),
        }
        assert!(matches!(
            mapped[2].as_ref().unwrap(),
            ResyncedEvent::Marker(ResyncMarker::ResyncStart)
        ));
    }

    #[tokio::test]
    async fn map_event_propagates_errors() {
        let items: Vec<crate::Result<ResyncedEvent<i32>>> = vec![
            Ok(ResyncedEvent::Event(1)),
            Err(crate::Error::invalid_message("synth")),
        ];
        let s = synth_stream(items);
        let mapped: Vec<_> = s.map_event(|i: i32| i + 100).collect().await;
        assert_eq!(mapped.len(), 2);
        assert!(matches!(
            mapped[0].as_ref().unwrap(),
            ResyncedEvent::Event(101)
        ));
        assert!(mapped[1].is_err());
    }
}
