//! ENOBUFS-resilient nftables event watching.
//!
//! Wraps [`Connection<Nftables>::events`] / `into_events` with the
//! same resync state machine ENOBUFS-aware consumers must
//! otherwise hand-roll: when the kernel drops events under
//! pressure (`-ENOBUFS`), the typed wrapper transparently
//! re-dumps the current ruleset via a freshly-constructed
//! connection and emits `Resynced(...)` items between
//! [`ResyncMarker::ResyncStart`](crate::netlink::resync::ResyncMarker::ResyncStart)
//! and [`ResyncMarker::ResyncEnd`](crate::netlink::resync::ResyncMarker::ResyncEnd)
//! markers.
//!
//! The shape mirrors `kube_rs::watcher(api, cfg) -> Stream` —
//! `watcher`-style fanout has proven the right primitive for
//! "long-lived self-resyncing watcher" across multiple
//! ecosystems. The key invariant: the resync **must** dump from
//! a freshly-resolved connection so the subscribe socket's
//! pending traffic doesn't race the snapshot read (Plan 178's
//! "subscribe + unicast on one socket" gotcha).
//!
//! # Why a factory closure
//!
//! ENOBUFS can fire at any moment. The wrapper needs to be able
//! to *open a fresh* `Connection<Nftables>` each time it
//! recovers — that's why the user hands in a closure rather than
//! a pre-built second connection. The factory is `Send + Sync +
//! 'static` so the stream is spawnable.
//!
//! # Example — owned, spawn-friendly
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use nlink::netlink::{Connection, Nftables};
//! use nlink::netlink::resync::{ConnectionFactory, ResyncedEvent, ResyncMarker};
//! use nlink::netlink::nftables::NftablesEvent;
//! use tokio_stream::StreamExt;
//!
//! let factory: ConnectionFactory<Nftables> = Arc::new(|| Box::pin(async {
//!     Connection::<Nftables>::new()
//! }));
//!
//! let conn = Connection::<Nftables>::new()?;
//! let mut events = conn.into_events_with_resync(factory).await?;
//!
//! while let Some(item) = events.next().await {
//!     match item? {
//!         ResyncedEvent::Event(NftablesEvent::NewTable(t)) => println!("+t {}", t.name),
//!         ResyncedEvent::Event(NftablesEvent::DelTable(t)) => println!("-t {}", t.name),
//!         ResyncedEvent::Marker(ResyncMarker::ResyncStart) => println!("== resync start =="),
//!         ResyncedEvent::Resynced(ev) => println!("?? snapshot: {ev:?}"),
//!         ResyncedEvent::Marker(ResyncMarker::ResyncEnd) => println!("== resync end =="),
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::pin::Pin;

use tokio_stream::Stream;

use super::events::NftablesEvent;
use super::types::Family;
use crate::netlink::protocol::Nftables;
use crate::netlink::resync::{ConnectionFactory, ResyncStream, events_with_resync};
use crate::netlink::stream::{EventSubscription, OwnedEventStream};
use crate::{Connection, Result};

/// Walk the full ruleset on a freshly-opened connection,
/// returning everything as `NewX(...)` events.
///
/// The walk order is: tables → chains → flowtables → named objects →
/// sets → set elements → rules, per table — what a rule or a map element
/// names comes before it. Named objects and set elements were missing:
/// the live stream reports both (`NewObject`, `NewSetElements`), so a
/// mirror lost every named counter and set element on its first overflow
/// (#503).
///
/// The dumps are taken between two reads of the ruleset generation and
/// taken again if it moved — a commit in between would leave a snapshot
/// of two rulesets. After several tries the error is
/// [`Error::dump_interrupted()`](crate::Error::dump_interrupted()), which the
/// resync wrapper retries.
///
/// Used internally by the resync wrapper; exposed here so
/// callers building bespoke ENOBUFS handling can reuse it.
#[nlink_macros::send_futures]
pub async fn nftables_snapshot(conn: &Connection<Nftables>) -> Result<Vec<NftablesEvent>> {
    const ATTEMPTS: usize = 5;
    for _ in 0..ATTEMPTS {
        let before = conn.generation().await?;
        let out = walk_ruleset(conn).await?;
        if conn.generation().await? == before {
            return Ok(out);
        }
    }
    Err(crate::Error::dump_interrupted())
}

async fn walk_ruleset(conn: &Connection<Nftables>) -> Result<Vec<NftablesEvent>> {
    let mut out = Vec::new();

    let tables = conn.list_tables().await?;
    for t in &tables {
        out.push(NftablesEvent::NewTable(t.clone()));
    }

    // chains, flowtables, objects, sets, rules per-table — server-side
    // family filtering is unsound on these dump types (Plan 181
    // finding), so we walk per-table by-name with client-side
    // matching via list_*_in.
    for t in &tables {
        for c in conn.list_chains_in(t.name.as_str(), t.family).await? {
            out.push(NftablesEvent::NewChain(c));
        }
        for f in conn.list_flowtables_in(&t.name, t.family).await? {
            out.push(NftablesEvent::NewFlowtable(f));
        }
        for o in conn.list_objects_in(&t.name, t.family).await? {
            out.push(NftablesEvent::NewObject(o));
        }
        for s in conn.list_sets_in(&t.name, t.family).await? {
            let elements = conn.list_set_elements(&t.name, &s.name, t.family).await?;
            let set_name = s.name.clone();
            out.push(NftablesEvent::NewSet(s));
            if !elements.is_empty() {
                out.push(NftablesEvent::NewSetElements(
                    super::events::SetElementsEvent {
                        family: t.family,
                        table: t.name.to_string(),
                        set: set_name,
                        elements,
                    },
                ));
            }
        }
        // list_rules takes the table name — already family-scoped.
        let _: Family = t.family;
        for r in conn.list_rules(&t.name, t.family).await? {
            out.push(NftablesEvent::NewRule(r));
        }
    }

    Ok(out)
}

/// Boxed snapshot future — what the resync closure produces.
type SnapshotFuture =
    Pin<Box<dyn Future<Output = Result<Vec<NftablesEvent>>> + Send + 'static>>;

/// Boxed snapshot closure — what `events_with_resync` consumes.
type SnapshotFn = Box<dyn FnMut() -> SnapshotFuture + Send + Unpin + 'static>;

/// Build the resync closure passed to [`events_with_resync`].
/// Each invocation opens a fresh `Connection<Nftables>` via the
/// factory + walks the ruleset via [`nftables_snapshot`].
fn make_snapshot_fn(factory: ConnectionFactory<Nftables>) -> SnapshotFn {
    Box::new(move || {
        let factory = factory.clone();
        Box::pin(async move {
            let conn = (factory)().await?;
            nftables_snapshot(&conn).await
        }) as SnapshotFuture
    })
}

/// Resync-wrapped `OwnedEventStream<Nftables>`. Returned by
/// [`Connection::<Nftables>::into_events_with_resync`]. `'static`
/// + `Send` — spawn-friendly with `tokio::spawn`.
pub type OwnedResyncStream =
    ResyncStream<'static, OwnedEventStream<Nftables>, NftablesEvent, SnapshotFn>;

/// Resync-wrapped `EventSubscription<'a, Nftables>`. Returned by
/// [`Connection::<Nftables>::subscribe_all_with_resync`].
/// Borrows the connection for `'a`.
pub type BorrowedResyncStream<'a> =
    ResyncStream<'static, EventSubscription<'a, Nftables>, NftablesEvent, SnapshotFn>;

#[nlink_macros::send_futures]
impl Connection<Nftables> {
    /// Subscribe to every nftables multicast group + return an
    /// ENOBUFS-resilient event stream that **owns** the connection.
    ///
    /// The factory is invoked whenever the kernel drops events
    /// under pressure (`-ENOBUFS`); the wrapper re-dumps the
    /// ruleset via a fresh connection + emits the snapshot as
    /// `Resynced(...)` items between
    /// [`ResyncMarker::ResyncStart`](crate::netlink::resync::ResyncMarker::ResyncStart)
    /// and [`ResyncMarker::ResyncEnd`](crate::netlink::resync::ResyncMarker::ResyncEnd)
    /// markers.
    ///
    /// **Important** — the fresh connection MUST be on the same
    /// netns. Use
    /// [`namespace::connection_for`](crate::netlink::namespace::connection_for)
    /// inside the factory for namespace-aware code; in the host
    /// netns plain `Connection::<Nftables>::new()` is fine.
    ///
    /// Subscribes to `NftablesGroup::All` before returning. Use
    /// [`Self::subscribe_all_with_resync`] if you need to retain
    /// borrowed access to the connection.
    /// 0.19 Finding B — now `async` to acquire the request lock
    /// via `into_events().await`.
    #[tracing::instrument(level = "info", skip_all)]
    pub async fn into_events_with_resync(
        self,
        factory: ConnectionFactory<Nftables>,
    ) -> Result<OwnedResyncStream> {
        self.subscribe_all()?;
        let stream = self.into_events().await;
        Ok(events_with_resync(stream, make_snapshot_fn(factory)).initial_snapshot(true))
    }

    /// Same as [`Self::into_events_with_resync`] but borrows the
    /// connection, which is yours again once the stream is dropped.
    ///
    /// While the stream is alive the connection serves requests only in
    /// dispatcher mode ([`Connection::with_dispatcher`]). In the default
    /// mutex mode the stream holds its request lock, and a request fails
    /// at once with [`Error::event_stream_active()`](crate::Error::event_stream_active())
    /// (#505). The snapshot itself never uses this connection: it runs on
    /// one from the factory.
    ///
    /// Returns a stream that holds `&self` for `'a`. If you need
    /// to spawn the stream onto a tokio task, prefer
    /// [`Self::into_events_with_resync`] (the owned form is
    /// `'static + Send`).
    ///
    /// 0.19 Finding A — `&self` (was `&mut self`). Finding B — now `async`.
    #[tracing::instrument(level = "info", skip_all)]
    pub async fn subscribe_all_with_resync(
        &self,
        factory: ConnectionFactory<Nftables>,
    ) -> Result<BorrowedResyncStream<'_>> {
        self.subscribe_all()?;
        let stream = self.events().await;
        Ok(events_with_resync(stream, make_snapshot_fn(factory)).initial_snapshot(true))
    }
}

// Anchor `Stream`-trait users without leaking `tokio_stream` —
// `ResyncStream` implements `Stream`; `OwnedResyncStream` /
// `BorrowedResyncStream` inherit it through the alias.
#[allow(dead_code)]
fn _streams_are_streams() {
    fn assert_stream<S: Stream + ?Sized>() {}
    assert_stream::<OwnedResyncStream>();
    assert_stream::<BorrowedResyncStream<'static>>();
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::netlink::resync::ConnectionFuture;

    #[test]
    fn factory_is_clone_and_send() {
        let factory: ConnectionFactory<Nftables> = Arc::new(|| {
            Box::pin(async { Connection::<Nftables>::new() })
                as Pin<Box<dyn Future<Output = Result<Connection<Nftables>>> + Send + 'static>>
        });
        let _f2 = factory.clone();
        // Doesn't actually open a socket — just exercises the
        // type bounds so a regression caught at compile time.
        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_send<T: Send>() {}
        assert_send_sync::<ConnectionFactory<Nftables>>();
        // ConnectionFuture is `Send` (not `Sync`) — a future
        // held by a single executor doesn't need Sync.
        assert_send::<ConnectionFuture<Nftables>>();
    }
}
