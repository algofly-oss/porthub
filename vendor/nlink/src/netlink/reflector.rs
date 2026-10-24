//! A `kube-rs`-style reflector: keep an in-memory [`Store`]
//! continuously up to date from a resync-aware event stream.
//!
//! Plan 195. Builds directly on the resync types
//! ([`ResyncedEvent`]) and the
//! [`ResyncStreamExt`](super::resync_ext::ResyncStreamExt)
//! combinators — no new dependency.
//!
//! # The shape
//!
//! - [`Store<K, V>`] is a cheap-to-clone, read-only handle over a
//!   shared `HashMap<K, V>`. Clone it freely; every clone observes
//!   the same backing map.
//! - [`ReflectExt::reflect`] wraps any
//!   `Stream<Item = Result<ResyncedEvent<V>>>` (e.g. the output of
//!   `into_events_with_resync`) into a **pass-through** stream that
//!   applies each item to a `Store` *before* re-yielding it. You
//!   still drive the returned stream — typically in a spawned task —
//!   and read the `Store` from anywhere else.
//! - A caller-supplied closure maps each event payload to a
//!   [`StoreOp`] (`Upsert` / `Remove` / `Ignore`), so the reflector
//!   stays generic over the protocol. For the route protocol's
//!   [`NetworkEvent`](super::events::NetworkEvent), that closure is
//!   a `match` on `NewLink => Upsert`, `DelLink => Remove`, …
//!
//! During a resync window (`Marker(ResyncStart)` …
//! `Marker(ResyncEnd)`) the reflector stages a *fresh* snapshot from
//! the `Resynced(V)` replay and swaps it in atomically at
//! `ResyncEnd`, so a post-`ENOBUFS` redump replaces stale state
//! rather than merging into it.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let conn = nlink::Connection::<nlink::Route>::new()?;
//! use std::sync::Arc;
//!
//! use nlink::NetworkEvent;
//! use nlink::netlink::reflector::{ReflectExt, Store, StoreOp};
//! use nlink::netlink::resync::{ConnectionFactory, ResyncMarker, ResyncedEvent};
//! use tokio_stream::StreamExt;
//!
//! let factory: ConnectionFactory<nlink::Route> =
//!     Arc::new(|| Box::pin(async { nlink::Connection::<nlink::Route>::new() }));
//! let store: Store<u32, NetworkEvent> = Store::new();
//! let reader = store.clone();
//!
//! let mut watch = conn.into_events_with_resync(factory).await?.reflect(store, |ev| {
//!     match ev {
//!         NetworkEvent::NewLink(l) => StoreOp::Upsert(l.ifindex()),
//!         NetworkEvent::DelLink(l) => StoreOp::Remove(l.ifindex()),
//!         _ => StoreOp::Ignore,
//!     }
//! });
//!
//! // The stream opens with the state as it is, closed by `ResyncEnd`
//! // (#503); the cache is empty until it has been read.
//! while let Some(item) = watch.next().await {
//!     if matches!(item?, ResyncedEvent::Marker(ResyncMarker::ResyncEnd)) {
//!         break;
//!     }
//! }
//!
//! // Drive the reflector in the background…
//! tokio::spawn(async move {
//!     while let Some(item) = watch.next().await {
//!         let _ = item; // pass-through; handle/log if you like
//!     }
//! });
//!
//! // …and read the cache from elsewhere.
//! println!("{} links currently tracked", reader.len());
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::hash::Hash;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};

use tokio_stream::Stream;

use super::resync::{ResyncMarker, ResyncedEvent};

/// What a reflector should do to its [`Store`] for a given event.
///
/// Returned by the closure passed to [`ReflectExt::reflect`]. The
/// closure inspects the event payload (which, for nlink's typed
/// event enums, already encodes add-vs-delete) and picks the op.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreOp<K> {
    /// Insert or replace the value under this key.
    Upsert(K),
    /// Remove the entry under this key, if present.
    Remove(K),
    /// Leave the store unchanged (event not relevant to this cache).
    Ignore,
}

/// A cheap-to-clone, read-only view over a `HashMap<K, V>` kept up
/// to date by a [reflector](ReflectExt::reflect).
///
/// Cloning a `Store` shares the backing map (it's an `Arc` inside),
/// so a reflector task and any number of readers all observe the
/// same state. All accessors take a brief read lock; they never
/// block on the reflector except for the lock's own critical
/// section (no `.await` is ever held across the lock).
pub struct Store<K, V> {
    inner: Arc<RwLock<HashMap<K, V>>>,
}

// Manual `Clone` so a `Store` clones by sharing the `Arc`, with no
// `K: Clone` / `V: Clone` bound (a derived `Clone` would demand them).
impl<K, V> Clone for Store<K, V> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<K, V> Default for Store<K, V> {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl<K, V> Store<K, V> {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<K: Eq + Hash, V> Store<K, V> {
    /// Number of entries currently held.
    pub fn len(&self) -> usize {
        self.read(|m| m.len())
    }

    /// Whether the store currently holds no entries.
    pub fn is_empty(&self) -> bool {
        self.read(|m| m.is_empty())
    }

    /// Whether an entry exists under `key`.
    pub fn contains_key(&self, key: &K) -> bool {
        self.read(|m| m.contains_key(key))
    }

    /// Clone of the value under `key`, if present.
    pub fn get(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        self.read(|m| m.get(key).cloned())
    }

    /// Snapshot of all keys (cloned).
    pub fn keys(&self) -> Vec<K>
    where
        K: Clone,
    {
        self.read(|m| m.keys().cloned().collect())
    }

    /// Snapshot of all values (cloned).
    pub fn values(&self) -> Vec<V>
    where
        V: Clone,
    {
        self.read(|m| m.values().cloned().collect())
    }

    /// Insert or replace one entry.
    ///
    /// The reflector path ([`ReflectExt::reflect`]) drives a store
    /// from a resync-aware stream, where the redump defines what a
    /// consistent snapshot is. Not every useful event source has that
    /// shape — [`NetdevLifecycle`] joins two sockets and owns its own
    /// notion of when a device exists — so the two write primitives
    /// are public for sources that maintain the cache themselves.
    ///
    /// Mixing a hand-driven writer with a reflector on the same store
    /// is a mistake: a reflector's `ResyncEnd` atomically replaces the
    /// whole map and would discard the hand-written entries.
    ///
    /// [`NetdevLifecycle`]: crate::netlink::netdev::NetdevLifecycle
    pub fn upsert(&self, key: K, value: V) {
        self.write(|m| {
            m.insert(key, value);
        });
    }

    /// Remove one entry, reporting whether it was there.
    ///
    /// See [`Self::upsert`] for when to reach for this.
    pub fn remove(&self, key: &K) -> bool {
        self.write(|m| m.remove(key).is_some())
    }

    /// Snapshot of every `(key, value)` pair (cloned).
    pub fn snapshot(&self) -> Vec<(K, V)>
    where
        K: Clone,
        V: Clone,
    {
        self.read(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    /// Run `f` against the backing map under a read lock without
    /// cloning. Use for ad-hoc queries (counts, filtered scans)
    /// that would be wasteful via [`snapshot`](Self::snapshot).
    ///
    /// Keep `f` short and non-blocking — it runs while the read
    /// lock is held.
    pub fn with_read<R>(&self, f: impl FnOnce(&HashMap<K, V>) -> R) -> R {
        self.read(f)
    }

    // --- internal helpers (used by the Reflect adapter) ---

    fn read<R>(&self, f: impl FnOnce(&HashMap<K, V>) -> R) -> R {
        // Recover from a poisoned lock rather than propagating the
        // panic: a reflector that panicked mid-write shouldn't brick
        // every future read. The map may be missing that one update,
        // but the next resync rebuilds it.
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        f(&guard)
    }

    fn write<R>(&self, f: impl FnOnce(&mut HashMap<K, V>) -> R) -> R {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    fn apply(&self, op: StoreOp<K>, value: V) {
        match op {
            StoreOp::Upsert(k) => self.write(|m| {
                m.insert(k, value);
            }),
            StoreOp::Remove(k) => self.write(|m| {
                m.remove(&k);
            }),
            StoreOp::Ignore => {}
        }
    }

    fn replace_all(&self, next: HashMap<K, V>) {
        self.write(|m| *m = next);
    }
}

/// Extension trait adding [`reflect`](Self::reflect) to any
/// resync-aware event stream.
///
/// Blanket-implemented for every
/// `Stream<Item = Result<ResyncedEvent<V>>> + Unpin`, matching the
/// bound used by [`ResyncStreamExt`](super::resync_ext::ResyncStreamExt).
pub trait ReflectExt<V>:
    Stream<Item = crate::Result<ResyncedEvent<V>>> + Sized + Unpin
{
    /// Mirror this stream into `store`, classifying each event via
    /// `op`. Returns a **pass-through** stream that yields the same
    /// items unchanged after updating the store — so you can chain
    /// further combinators or just drive it to keep the store fresh.
    ///
    /// `Resynced(V)` items arriving inside a resync window
    /// (`Marker(ResyncStart)` … `Marker(ResyncEnd)`) build a fresh
    /// snapshot that atomically replaces the store at `ResyncEnd`;
    /// `Remove`/`Ignore` ops are not meaningful for a redump and are
    /// skipped while staging.
    fn reflect<K, F>(self, store: Store<K, V>, op: F) -> Reflect<Self, K, V, F>
    where
        K: Eq + Hash,
        V: Clone,
        F: FnMut(&V) -> StoreOp<K>,
    {
        Reflect::new(self, store, op)
    }
}

impl<S, V> ReflectExt<V> for S where S: Stream<Item = crate::Result<ResyncedEvent<V>>> + Unpin {}

/// Pass-through stream adapter created by [`ReflectExt::reflect`].
/// Updates a [`Store`] from every item it forwards.
pub struct Reflect<S, K, V, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<V>>> + Unpin,
    K: Eq + Hash,
    V: Clone,
    F: FnMut(&V) -> StoreOp<K>,
{
    inner: S,
    store: Store<K, V>,
    op: F,
    // `Some` while inside a resync window — accumulates the fresh
    // snapshot to swap in at `ResyncEnd`.
    staging: Option<HashMap<K, V>>,
}

impl<S, K, V, F> Reflect<S, K, V, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<V>>> + Unpin,
    K: Eq + Hash,
    V: Clone,
    F: FnMut(&V) -> StoreOp<K>,
{
    fn new(inner: S, store: Store<K, V>, op: F) -> Self {
        Self {
            inner,
            store,
            op,
            staging: None,
        }
    }
}

impl<S, K, V, F> Unpin for Reflect<S, K, V, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<V>>> + Unpin,
    K: Eq + Hash,
    V: Clone,
    F: FnMut(&V) -> StoreOp<K>,
{
}

impl<S, K, V, F> Stream for Reflect<S, K, V, F>
where
    S: Stream<Item = crate::Result<ResyncedEvent<V>>> + Unpin,
    K: Eq + Hash,
    V: Clone,
    F: FnMut(&V) -> StoreOp<K>,
{
    type Item = crate::Result<ResyncedEvent<V>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => {
                // Drop any half-built snapshot. With a resync window
                // left open, every subsequent event diverts into
                // `staging` instead of the store and the cache silently
                // freezes — it keeps answering, with stale data, and
                // nothing says so.
                //
                // Not reachable through the crate's own `ResyncStream`,
                // which only emits `ResyncStart` after the snapshot
                // future succeeds and fuses on any other error. But
                // `reflect` is blanket-implemented for any
                // `Stream<Item = Result<ResyncedEvent<V>>>`, so a caller
                // composing their own is exposed (#281). Defensive.
                if this.staging.take().is_some() {
                    tracing::debug!(
                        "reflect: dropping a partial resync snapshot after a stream error"
                    );
                }
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(Some(Ok(item))) => {
                match &item {
                    ResyncedEvent::Marker(
                        ResyncMarker::ResyncStart | ResyncMarker::InitialSyncStart,
                    ) => {
                        // Begin staging a fresh snapshot — after an
                        // overflow, or the initial one (#503).
                        this.staging = Some(HashMap::new());
                    }
                    ResyncedEvent::Marker(ResyncMarker::ResyncEnd) => {
                        // Atomically swap the snapshot in. If we never
                        // saw a ResyncStart (defensive), this is a no-op.
                        if let Some(next) = this.staging.take() {
                            this.store.replace_all(next);
                        }
                    }
                    ResyncedEvent::Event(v) | ResyncedEvent::Resynced(v) => {
                        let op = (this.op)(v);
                        match &mut this.staging {
                            // Inside a resync window: only upserts build
                            // the snapshot (a redump is all-live state).
                            Some(stage) => {
                                if let StoreOp::Upsert(k) = op {
                                    stage.insert(k, v.clone());
                                }
                            }
                            // Normal real-time delta.
                            None => this.store.apply(op, v.clone()),
                        }
                    }
                }
                Poll::Ready(Some(Ok(item)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    fn synth(
        items: Vec<crate::Result<ResyncedEvent<(u32, &'static str)>>>,
    ) -> impl Stream<Item = crate::Result<ResyncedEvent<(u32, &'static str)>>> + Unpin {
        tokio_stream::iter(items)
    }

    // Classify a (key, tag) payload: tag "del" removes, anything
    // else upserts; tag "skip" is ignored.
    fn op(ev: &(u32, &'static str)) -> StoreOp<u32> {
        match ev.1 {
            "del" => StoreOp::Remove(ev.0),
            "skip" => StoreOp::Ignore,
            _ => StoreOp::Upsert(ev.0),
        }
    }

    #[tokio::test]
    async fn upsert_remove_ignore_apply_to_store() {
        let store: Store<u32, (u32, &'static str)> = Store::new();
        let reader = store.clone();
        let items = vec![
            Ok(ResyncedEvent::Event((1, "a"))),
            Ok(ResyncedEvent::Event((2, "b"))),
            Ok(ResyncedEvent::Event((1, "a2"))), // upsert overwrites
            Ok(ResyncedEvent::Event((3, "skip"))), // ignored
            Ok(ResyncedEvent::Event((2, "del"))), // removes key 2
        ];
        let drained: Vec<_> = synth(items).reflect(store, op).collect().await;

        // Pass-through preserved every item.
        assert_eq!(drained.len(), 5);
        assert_eq!(reader.len(), 1, "only key 1 remains");
        assert_eq!(reader.get(&1), Some((1, "a2")), "upsert overwrote");
        assert!(!reader.contains_key(&2), "key 2 removed");
        assert!(!reader.contains_key(&3), "ignored event never inserted");
    }

    #[tokio::test]
    async fn resync_window_replaces_snapshot_atomically() {
        let store: Store<u32, (u32, &'static str)> = Store::new();
        let reader = store.clone();
        let items = vec![
            // Pre-resync state: keys 1, 2.
            Ok(ResyncedEvent::Event((1, "a"))),
            Ok(ResyncedEvent::Event((2, "b"))),
            // Resync: the redump only contains keys 2, 3 — key 1 is gone.
            Ok(ResyncedEvent::Marker(ResyncMarker::ResyncStart)),
            Ok(ResyncedEvent::Resynced((2, "b2"))),
            Ok(ResyncedEvent::Resynced((3, "c"))),
            // A stray Remove during staging must be ignored (redump
            // is all-live; removals are not meaningful here).
            Ok(ResyncedEvent::Resynced((9, "del"))),
            Ok(ResyncedEvent::Marker(ResyncMarker::ResyncEnd)),
        ];
        let _ = synth(items).reflect(store, op).collect::<Vec<_>>().await;

        assert_eq!(reader.len(), 2, "snapshot replaced, not merged");
        assert!(!reader.contains_key(&1), "key 1 dropped by resync");
        assert_eq!(reader.get(&2), Some((2, "b2")), "key 2 refreshed");
        assert!(reader.contains_key(&3), "key 3 added by resync");
        assert!(!reader.contains_key(&9), "Remove ignored during staging");
    }

    #[tokio::test]
    async fn post_resync_deltas_apply_again() {
        let store: Store<u32, (u32, &'static str)> = Store::new();
        let reader = store.clone();
        let items = vec![
            Ok(ResyncedEvent::Marker(ResyncMarker::ResyncStart)),
            Ok(ResyncedEvent::Resynced((1, "a"))),
            Ok(ResyncedEvent::Marker(ResyncMarker::ResyncEnd)),
            // Real-time delta after the window resumes.
            Ok(ResyncedEvent::Event((1, "del"))),
            Ok(ResyncedEvent::Event((4, "d"))),
        ];
        let _ = synth(items).reflect(store, op).collect::<Vec<_>>().await;
        assert!(!reader.contains_key(&1), "post-resync delete applied");
        assert_eq!(reader.get(&4), Some((4, "d")), "post-resync insert applied");
        assert_eq!(reader.len(), 1);
    }

    #[tokio::test]
    async fn errors_pass_through_without_touching_store() {
        let store: Store<u32, (u32, &'static str)> = Store::new();
        let reader = store.clone();
        let items = vec![
            Ok(ResyncedEvent::Event((1, "a"))),
            Err(crate::Error::invalid_message("synth")),
            Ok(ResyncedEvent::Event((2, "b"))),
        ];
        let drained: Vec<_> = synth(items).reflect(store, op).collect().await;
        assert_eq!(drained.len(), 3);
        assert!(drained[1].is_err(), "error forwarded");
        assert_eq!(reader.len(), 2, "both ok events still applied");
    }

    #[tokio::test]
    async fn cloned_store_shares_state() {
        let store: Store<u32, (u32, &'static str)> = Store::new();
        let a = store.clone();
        let b = store.clone();
        let _ = synth(vec![Ok(ResyncedEvent::Event((7, "x")))])
            .reflect(store, op)
            .collect::<Vec<_>>()
            .await;
        assert_eq!(a.get(&7), Some((7, "x")));
        assert_eq!(b.get(&7), Some((7, "x")), "clones observe same map");
    }

    /// The write primitives exist for event sources that aren't
    /// resync streams (`NetdevLifecycle` joins two sockets and owns
    /// its own notion of when a device exists), so they need coverage
    /// independent of the `Reflect` adapter.
    #[test]
    fn hand_driven_writes_go_through_every_clone() {
        let store: Store<u32, &str> = Store::new();
        let reader = store.clone();

        store.upsert(7, "veth0");
        assert_eq!(reader.get(&7), Some("veth0"));
        assert_eq!(reader.len(), 1);

        // Upsert replaces rather than duplicating.
        store.upsert(7, "veth1");
        assert_eq!(reader.get(&7), Some("veth1"));
        assert_eq!(reader.len(), 1);

        // Remove reports whether the entry was there, so a caller can
        // tell an eviction from a no-op.
        assert!(store.remove(&7));
        assert!(!store.remove(&7));
        assert!(reader.is_empty());
    }

    #[test]
    fn empty_store_accessors() {
        let store: Store<u32, u32> = Store::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert_eq!(store.get(&1), None);
        assert!(store.keys().is_empty());
        assert!(store.values().is_empty());
        assert!(store.snapshot().is_empty());
        assert_eq!(store.with_read(|m| m.len()), 0);
    }

    // ====================================================================
    // #281 — a stream error must not leave a resync window open
    // ====================================================================

    #[tokio::test]
    async fn a_stream_error_mid_resync_drops_the_partial_snapshot() {
        use tokio_stream::StreamExt;

        // `reflect` is blanket-implemented for any
        // `Stream<Item = Result<ResyncedEvent<V>>>`, so a caller can
        // compose one that errors between ResyncStart and ResyncEnd.
        // With `staging` left populated, every later event diverts into
        // it instead of the store and the cache silently freezes.
        let items: Vec<crate::Result<ResyncedEvent<u32>>> = vec![
            Ok(ResyncedEvent::Event(1)),
            Ok(ResyncedEvent::Marker(ResyncMarker::ResyncStart)),
            Ok(ResyncedEvent::Resynced(2)),
            Err(crate::Error::invalid_message("boom")),
            // …and the consumer keeps going, as a supervisor loop does.
            Ok(ResyncedEvent::Event(3)),
        ];
        let store: Store<u32, u32> = Store::new();
        let mut stream = tokio_stream::iter(items).reflect(store.clone(), |v: &u32| StoreOp::Upsert(*v));

        let mut errors = 0;
        while let Some(item) = stream.next().await {
            if item.is_err() {
                errors += 1;
            }
        }
        assert_eq!(errors, 1);

        // The event after the error must have reached the store, not a
        // stranded staging map.
        assert!(
            store.get(&3).is_some(),
            "events after the error went into a stranded resync window; \
             the cache is frozen (#281)"
        );
    }
}
