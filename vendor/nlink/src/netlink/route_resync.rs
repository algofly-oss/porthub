//! ENOBUFS-resilient rtnetlink event watching.
//!
//! RTNETLINK twin of `nlink::netlink::nftables::resync` (Plan
//! 185). Same shape, different protocol: subscribe to multicast
//! groups + transparently re-dump state when the kernel drops
//! events under pressure (`-ENOBUFS`).
//!
//! Mirrors how `kube_rs::watcher(api, cfg) -> Stream` works —
//! `watcher`-style fanout has proven the right primitive for
//! long-lived self-resyncing watchers. Plan 191.
//!
//! # Example — owned, spawn-friendly
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::resync::{ConnectionFactory, ResyncedEvent, ResyncMarker};
//! use nlink::NetworkEvent;
//! use tokio_stream::StreamExt;
//!
//! let factory: ConnectionFactory<Route> = Arc::new(|| Box::pin(async {
//!     Connection::<Route>::new()
//! }));
//!
//! let conn = Connection::<Route>::new()?;
//! let mut events = conn.into_events_with_resync(factory).await?;
//!
//! while let Some(item) = events.next().await {
//!     match item? {
//!         ResyncedEvent::Event(NetworkEvent::NewLink(l)) => {
//!             println!("+l {:?}", l.name());
//!         }
//!         ResyncedEvent::Marker(ResyncMarker::ResyncStart) => {
//!             println!("== resync start ==");
//!         }
//!         ResyncedEvent::Resynced(ev) => {
//!             println!("?? snapshot: {ev:?}");
//!         }
//!         ResyncedEvent::Marker(ResyncMarker::ResyncEnd) => {
//!             println!("== resync end ==");
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::pin::Pin;

use tokio_stream::Stream;

use super::events::NetworkEvent;
use crate::netlink::protocol::Route;
use crate::netlink::resync::{ConnectionFactory, ResyncStream, events_with_resync};
use crate::netlink::stream::{EventSubscription, OwnedEventStream};
use crate::{Connection, Result};

/// Walk the current rtnetlink state and return one `NewX(...)` event per
/// existing entity. Used internally by
/// [`Connection::<Route>::into_events_with_resync`] for ENOBUFS recovery
/// and the initial sync; exposed publicly so callers wiring their own
/// resync can re-use it. Plan 191 §2.5.
///
/// It covers what [`subscribe_all`](Connection::subscribe_all) joins and
/// the kernel can dump: links → netconf → addresses → nexthops → routes →
/// rules → neighbours → qdiscs → classes → filters → bridge MDB. It used to stop
/// at neighbours, so a mirror of qdiscs, rules or nexthops was emptied by
/// its first overflow and stayed empty (#503). Nexthops come before the
/// routes that use them. Network-namespace ids are subscribed to but have
/// no dump, so they are not here.
#[nlink_macros::send_futures]
pub async fn rtnetlink_snapshot(conn: &Connection<Route>) -> Result<Vec<NetworkEvent>> {
    let mut out = Vec::new();

    let links = conn.get_links().await?;
    let bridges: Vec<u32> = links
        .iter()
        .filter(|l| l.kind() == Some("bridge"))
        .map(|l| l.ifindex())
        .collect();
    out.extend(links.into_iter().map(NetworkEvent::NewLink));
    // Each family's netconf (#523); a kernel without IPv6 has none of it.
    for family in [crate::AddressFamily::v4(), crate::AddressFamily::v6()] {
        match conn.get_netconf(family).await {
            Ok(nc) => out.extend(nc.into_iter().map(NetworkEvent::NewNetconf)),
            Err(e) if e.is_not_supported() || e.is_invalid_argument() => {}
            Err(e) => return Err(e),
        }
    }
    out.extend(
        conn.get_addresses()
            .await?
            .into_iter()
            .map(NetworkEvent::NewAddress),
    );
    // A kernel without nexthop objects says so; that is an empty dump.
    match conn.get_nexthops().await {
        Ok(nhs) => out.extend(nhs.into_iter().map(NetworkEvent::NewNexthop)),
        Err(e) if e.is_not_supported() || e.is_invalid_argument() => {}
        Err(e) => return Err(e),
    }
    out.extend(
        conn.get_routes()
            .await?
            .into_iter()
            .map(NetworkEvent::NewRoute),
    );
    out.extend(
        conn.get_rules()
            .await?
            .into_iter()
            .map(NetworkEvent::NewRule),
    );
    out.extend(
        conn.get_neighbors()
            .await?
            .into_iter()
            .map(NetworkEvent::NewNeighbor),
    );
    out.extend(
        conn.get_qdiscs()
            .await?
            .into_iter()
            .map(NetworkEvent::NewQdisc),
    );
    out.extend(
        conn.get_classes()
            .await?
            .into_iter()
            .map(NetworkEvent::NewClass),
    );
    out.extend(
        conn.get_filters()
            .await?
            .into_iter()
            .map(NetworkEvent::NewFilter),
    );
    for bridge in bridges {
        out.extend(
            conn.get_mdb_by_index(bridge)
                .await?
                .into_iter()
                .map(NetworkEvent::NewMdb),
        );
    }

    Ok(out)
}

/// Boxed snapshot future — what the resync closure produces.
type SnapshotFuture =
    Pin<Box<dyn Future<Output = Result<Vec<NetworkEvent>>> + Send + 'static>>;

/// Boxed snapshot closure — what `events_with_resync` consumes.
type SnapshotFn = Box<dyn FnMut() -> SnapshotFuture + Send + Unpin + 'static>;

/// Build the resync closure passed to [`events_with_resync`].
/// Each invocation opens a fresh `Connection<Route>` via the
/// factory + walks the kernel state via [`rtnetlink_snapshot`].
fn make_snapshot_fn(factory: ConnectionFactory<Route>) -> SnapshotFn {
    Box::new(move || {
        let factory = factory.clone();
        Box::pin(async move {
            let conn = (factory)().await?;
            rtnetlink_snapshot(&conn).await
        }) as SnapshotFuture
    })
}

/// Resync-wrapped `OwnedEventStream<Route>`. Returned by
/// [`Connection::<Route>::into_events_with_resync`]. `'static`
/// + `Send` — spawn-friendly with `tokio::spawn`.
pub type OwnedResyncStream =
    ResyncStream<'static, OwnedEventStream<Route>, NetworkEvent, SnapshotFn>;

/// Resync-wrapped `EventSubscription<'a, Route>`. Returned by
/// [`Connection::<Route>::subscribe_all_with_resync`].
/// Borrows the connection for `'a`.
pub type BorrowedResyncStream<'a> =
    ResyncStream<'static, EventSubscription<'a, Route>, NetworkEvent, SnapshotFn>;

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Subscribe to every rtnetlink multicast group + return an
    /// ENOBUFS-resilient event stream that **owns** the
    /// connection.
    ///
    /// Mirrors [`Connection::<Nftables>::into_events_with_resync`]
    /// (Plan 185). The factory is invoked on every ENOBUFS
    /// overflow; the wrapper re-dumps state via
    /// [`rtnetlink_snapshot`] on a fresh connection and emits
    /// the snapshot items between
    /// [`ResyncMarker::ResyncStart`](crate::netlink::resync::ResyncMarker::ResyncStart)
    /// and [`ResyncMarker::ResyncEnd`](crate::netlink::resync::ResyncMarker::ResyncEnd)
    /// markers.
    ///
    /// **Important** — the fresh connection MUST be on the same
    /// netns. Use
    /// [`namespace::connection_for`](crate::netlink::namespace::connection_for)
    /// inside the factory for namespace-aware code; in the host
    /// netns plain `Connection::<Route>::new()` is fine.
    ///
    /// Subscribes to every rtnetlink multicast group before
    /// returning. Use [`Self::subscribe_all_with_resync`] if you
    /// need to retain borrowed access to the connection.
    ///
    /// Plan 191 §2.6.
    /// 0.19 Finding B — now `async` to acquire the request lock
    /// via the underlying `into_events().await`.
    #[tracing::instrument(level = "info", skip_all)]
    pub async fn into_events_with_resync(
        self,
        factory: ConnectionFactory<Route>,
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
    /// Plan 191 §2.6. 0.19 Finding A — `&self` (was `&mut self`).
    /// 0.19 Finding B — now `async`.
    #[tracing::instrument(level = "info", skip_all)]
    pub async fn subscribe_all_with_resync(
        &self,
        factory: ConnectionFactory<Route>,
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
        let factory: ConnectionFactory<Route> = Arc::new(|| {
            Box::pin(async { Connection::<Route>::new() })
                as Pin<Box<dyn Future<Output = Result<Connection<Route>>> + Send + 'static>>
        });
        let _f2 = factory.clone();
        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_send<T: Send>() {}
        assert_send_sync::<ConnectionFactory<Route>>();
        assert_send::<ConnectionFuture<Route>>();
    }

    #[test]
    fn snapshot_fn_is_send() {
        let factory: ConnectionFactory<Route> = Arc::new(|| {
            Box::pin(async { Connection::<Route>::new() })
        });
        // Make sure the snapshot-fn type bound is what
        // events_with_resync needs. Cannot exercise without a
        // socket; this is purely a compile-time check.
        let _fn = make_snapshot_fn(factory);
    }
}
