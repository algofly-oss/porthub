//! One-line watch wrappers — ENOBUFS-resilient event
//! subscription. Plan 200 §2.3.
//!
//! Each entry point opens a `Connection<P>` + builds the
//! `ConnectionFactory<P>` + returns the resync stream, so
//! callers don't write the same 8-line factory closure
//! every time. For the polling-based WG watcher (which has
//! no native multicast — see Plan 199's kernel research),
//! the wrapper builds a `WireguardWatcher` instead.

use std::hash::Hash;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio_stream::{Stream, StreamMap};

use crate::netlink::genl::wireguard::{WireguardWatchOptions, WireguardWatcher};
use crate::netlink::namespace;
use crate::netlink::nftables::NftablesEvent;
use crate::netlink::nftables::resync::OwnedResyncStream as NftablesResyncStream;
use crate::netlink::resync::{
    Backoff, ConnectionFactory, Restartable, RestartingStream, ResyncedEvent,
};
use crate::netlink::resync_ext::ResyncStreamExt;
use crate::netlink::{NetworkEvent, Nftables, Route, Wireguard};
use crate::netlink::route_resync::OwnedResyncStream as RouteResyncStream;
use crate::{Connection, Result};

// =============================================================================
// RTNETLINK — Plan 191
// =============================================================================

/// Watch RTNETLINK changes in the host's default namespace.
///
/// Returns a `ResyncStream` of `NetworkEvent`s with ENOBUFS
/// recovery built in. The factory closure (which opens a
/// fresh connection on every overflow) is constructed for
/// you.
///
/// 0.19 Finding B — now `async`.
#[nlink_macros::send_futures]
pub async fn route_changes() -> Result<RouteResyncStream> {
    let conn = Connection::<Route>::new()?;
    let factory: ConnectionFactory<Route> =
        Arc::new(|| Box::pin(async { Connection::<Route>::new() }));
    conn.into_events_with_resync(factory).await
}

/// Watch RTNETLINK changes inside a named namespace.
#[deprecated(since = "0.32.0", note = "use `route_changes_in(ns)`, which takes a name (#532)")]
#[nlink_macros::send_futures]
pub async fn route_changes_in_namespace(ns: &str) -> Result<RouteResyncStream> {
    route_changes_in(ns).await
}

/// Watch RTNETLINK changes inside a namespace: anything
/// [`Into<NetnsTarget>`](namespace::NetnsTarget) — an `ip netns` name, an
/// open `Netns`, a `NetnsRef`, … (#532).
///
/// The namespace is opened once. Every resync reconnects to that one, and
/// ends the stream with `NamespaceDeleted` once its name is gone, rather
/// than connect to a namespace created later under the same name (#520).
#[nlink_macros::send_futures]
pub async fn route_changes_in<'a>(
    ns: impl Into<namespace::NetnsTarget<'a>>,
) -> Result<RouteResyncStream> {
    let Some(netns) = ns.into().open()? else {
        return route_changes().await;
    };
    let netns = Arc::new(netns);
    let conn = netns.connection::<Route>()?;
    let factory: ConnectionFactory<Route> = Arc::new(move || {
        let netns = netns.clone();
        Box::pin(async move { reconnect::<Route>(&netns) })
    });
    conn.into_events_with_resync(factory).await
}

/// A resync's new connection, in the namespace the stream started in.
fn reconnect<P>(netns: &namespace::Netns) -> Result<Connection<P>>
where
    P: crate::netlink::ProtocolState + Default + crate::netlink::construction::SyncConstructible,
{
    if !netns.is_live() {
        return Err(netns.deleted());
    }
    netns.connection::<P>()
}

// =============================================================================
// nftables — Plan 185
// =============================================================================

/// Watch nftables ruleset mutations in the host's default
/// namespace.
///
/// 0.19 Finding B — now `async`.
#[nlink_macros::send_futures]
pub async fn nftables_changes() -> Result<NftablesResyncStream> {
    let conn = Connection::<Nftables>::new()?;
    let factory: ConnectionFactory<Nftables> =
        Arc::new(|| Box::pin(async { Connection::<Nftables>::new() }));
    conn.into_events_with_resync(factory).await
}

/// Watch nftables ruleset mutations inside a named namespace.
#[deprecated(since = "0.32.0", note = "use `nftables_changes_in(ns)`, which takes a name (#532)")]
#[nlink_macros::send_futures]
pub async fn nftables_changes_in_namespace(ns: &str) -> Result<NftablesResyncStream> {
    nftables_changes_in(ns).await
}

/// Watch nftables ruleset mutations inside a namespace (#532).
///
/// Resyncs reconnect to the namespace the stream started in, as
/// [`route_changes_in`] does (#520).
#[nlink_macros::send_futures]
pub async fn nftables_changes_in<'a>(
    ns: impl Into<namespace::NetnsTarget<'a>>,
) -> Result<NftablesResyncStream> {
    let Some(netns) = ns.into().open()? else {
        return nftables_changes().await;
    };
    let netns = Arc::new(netns);
    let conn = netns.connection::<Nftables>()?;
    let factory: ConnectionFactory<Nftables> = Arc::new(move || {
        let netns = netns.clone();
        Box::pin(async move { reconnect::<Nftables>(&netns) })
    });
    conn.into_events_with_resync(factory).await
}

// =============================================================================
// WireGuard — Plan 199 (polling watcher; kernel has no mcast)
// =============================================================================

/// Build a WireGuard polling watcher for the host's default
/// namespace.
///
/// **WireGuard has no native multicast** — the kernel module
/// declares `n_mcgrps = 0` (verified upstream). Every WG
/// monitoring tool polls; this wrapper opens the GENL
/// connection + returns a [`WireguardWatcher`] you drive via
/// [`WireguardWatcher::next_events`]. See Plan 199's
/// migration-guide section for the kernel-source ground
/// truth + the deferred-multicast patch history.
#[nlink_macros::send_futures]
pub async fn wireguard_changes(opts: WireguardWatchOptions) -> Result<WireguardWatcher> {
    let conn = Connection::<Wireguard>::new_async().await?;
    WireguardWatcher::new(conn, opts)
}

/// Same as [`wireguard_changes`] inside a named namespace.
#[deprecated(since = "0.32.0", note = "use `wireguard_changes_in(ns, opts)`, which takes a name (#532)")]
#[nlink_macros::send_futures]
pub async fn wireguard_changes_in_namespace(
    ns: &str,
    opts: WireguardWatchOptions,
) -> Result<WireguardWatcher> {
    wireguard_changes_in(ns, opts).await
}

/// Same as [`wireguard_changes`] inside a namespace (#532).
#[nlink_macros::send_futures]
pub async fn wireguard_changes_in<'a>(
    ns: impl Into<namespace::NetnsTarget<'a>>,
    opts: WireguardWatchOptions,
) -> Result<WireguardWatcher> {
    let conn = Connection::<Wireguard>::new_in_async(ns).await?;
    WireguardWatcher::new(conn, opts)
}

// =============================================================================
// Many namespaces at once — #523
// =============================================================================

/// The event families a [`MultiNsWatch`] follows in each namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Families(u8);

impl Families {
    /// rtnetlink: links, addresses, routes, neighbours, qdiscs, …
    pub const ROUTE: Self = Self(1);
    /// nftables: tables, chains, rules, sets, objects.
    pub const NFTABLES: Self = Self(2);

    /// Whether every family in `other` is in this set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for Families {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// What a [`MultiNsWatch`] yields for one namespace, with its key.
// The per-family streams yield these events unboxed already; boxing here
// would only add an allocation per event.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
#[non_exhaustive]
pub enum NsEvent {
    /// An rtnetlink event, snapshot item or marker. Each family has its
    /// own initial snapshot and resyncs.
    Route(ResyncedEvent<NetworkEvent>),
    /// An nftables event, snapshot item or marker.
    Nftables(ResyncedEvent<NftablesEvent>),
    /// A failure. That family's stream starts again after the backoff,
    /// with a fresh initial snapshot.
    Error(crate::Error),
    /// The last item for this key: the namespace was deleted
    /// ([`is_namespace_deleted`](crate::Error::is_namespace_deleted)),
    /// or every family gave up after
    /// [`Backoff::max_attempts`](crate::netlink::resync::Backoff::max_attempts).
    /// The watch has already dropped the key.
    Gone(crate::Error),
}

type FamilyStream<T> = Pin<Box<dyn Stream<Item = Result<ResyncedEvent<T>>> + Send>>;

/// One namespace's streams, merged.
struct NsStreams {
    route: Option<FamilyStream<NetworkEvent>>,
    nftables: Option<FamilyStream<NftablesEvent>>,
    /// The last error a family gave up after.
    last_error: Option<String>,
    /// Which family is polled first, alternating so neither starves.
    route_first: bool,
    gone: bool,
}

impl NsStreams {
    fn poll_route(&mut self, cx: &mut Context<'_>) -> Poll<Option<NsEvent>> {
        let Some(stream) = self.route.as_mut() else {
            return Poll::Pending;
        };
        match stream.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(item))) => Poll::Ready(Some(NsEvent::Route(item))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(self.failure(e))),
            Poll::Ready(None) => {
                self.route = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_nftables(&mut self, cx: &mut Context<'_>) -> Poll<Option<NsEvent>> {
        let Some(stream) = self.nftables.as_mut() else {
            return Poll::Pending;
        };
        match stream.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(item))) => Poll::Ready(Some(NsEvent::Nftables(item))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(self.failure(e))),
            Poll::Ready(None) => {
                self.nftables = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn failure(&mut self, e: crate::Error) -> NsEvent {
        if crate::netlink::resync::ends_restarting(&e) {
            self.gone = true;
            NsEvent::Gone(e)
        } else {
            self.last_error = Some(e.to_string());
            NsEvent::Error(e)
        }
    }
}

impl Stream for NsStreams {
    type Item = NsEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<NsEvent>> {
        let this = self.get_mut();
        if this.gone {
            return Poll::Ready(None);
        }
        this.route_first = !this.route_first;
        for route in [this.route_first, !this.route_first] {
            let polled = if route {
                this.poll_route(cx)
            } else {
                this.poll_nftables(cx)
            };
            if let Poll::Ready(Some(event)) = polled {
                return Poll::Ready(Some(event));
            }
        }
        if this.route.is_none() && this.nftables.is_none() {
            this.gone = true;
            let why = this.last_error.take().unwrap_or_else(|| "no family left".into());
            return Poll::Ready(Some(NsEvent::Gone(crate::Error::invalid_message(format!(
                "the namespace's watch gave up: {why}"
            )))));
        }
        Poll::Pending
    }
}

/// Events from many namespaces in one stream (#523): each namespace's
/// families on [restarting](crate::Connection::events_restarting)
/// streams, keyed by what the caller named it.
///
/// Every family in every namespace starts with an initial snapshot, is
/// resynced after an overflow, and restarts after a failure — reported
/// as [`NsEvent::Error`]. A namespace that is deleted yields
/// [`NsEvent::Gone`] and is dropped from the watch; the others go on.
///
/// The stream ends when it holds no namespace. [`add`](Self::add) one
/// and poll again.
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// use nlink::facade::watch::{Families, MultiNsWatch, NsEvent};
/// use nlink::netlink::namespace::Netns;
/// use tokio_stream::StreamExt;
///
/// let mut watch = MultiNsWatch::new(Families::ROUTE | Families::NFTABLES);
/// for node in ["r1", "r2", "h1"] {
///     watch.add(node, &Netns::open(&format!("lab-{node}"))?)?;
/// }
/// while let Some((node, event)) = watch.next().await {
///     match event {
///         NsEvent::Gone(why) => println!("{node}: gone ({why})"),
///         other => println!("{node}: {other:?}"),
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct MultiNsWatch<K> {
    families: Families,
    backoff: Backoff,
    rcvbuf: Option<usize>,
    gap_deltas: bool,
    streams: StreamMap<K, NsStreams>,
}

impl<K> MultiNsWatch<K>
where
    K: Clone + Hash + Eq + Unpin,
{
    /// A watch of `families` with no namespace in it yet, restarting
    /// after the default [`Backoff`].
    pub fn new(families: Families) -> Self {
        Self {
            families,
            backoff: Backoff::default(),
            rcvbuf: None,
            gap_deltas: false,
            streams: StreamMap::new(),
        }
    }

    /// The waits between restarts, for namespaces added from now on.
    pub fn backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// The receive buffer of each event socket, in bytes, for namespaces
    /// added from now on. A larger one overflows, and resyncs, less often.
    pub fn rcvbuf(mut self, bytes: usize) -> Self {
        self.rcvbuf = Some(bytes);
        self
    }

    /// Report what a resync or restart found gone as `Del*` events
    /// ([`with_gap_deltas`](crate::netlink::resync_ext::ResyncStreamExt::with_gap_deltas)),
    /// for namespaces added from now on.
    pub fn gap_deltas(mut self, on: bool) -> Self {
        self.gap_deltas = on;
        self
    }

    /// Watch `ns` under `key`, replacing whatever `key` watched. `ns` is
    /// an open `Netns`, an `ip netns` name, a `NetnsRef`, … (#532). The
    /// watch holds its own handle to the namespace, which keeps the
    /// namespace alive until its key is dropped.
    pub fn add<'a>(&mut self, key: K, ns: impl Into<namespace::NetnsTarget<'a>>) -> Result<()> {
        let netns = match ns.into().open()? {
            Some(netns) => Arc::new(netns),
            None => Arc::new(namespace::Netns::current()?),
        };
        let route = self.families.contains(Families::ROUTE).then(|| {
            let netns = netns.clone();
            let factory: ConnectionFactory<Route> = Arc::new(move || {
                let netns = netns.clone();
                Box::pin(async move { reconnect::<Route>(&netns) })
            });
            let stream = self.restarting(factory);
            if self.gap_deltas {
                Box::pin(stream.with_gap_deltas(NetworkEvent::object_key)) as FamilyStream<_>
            } else {
                Box::pin(stream)
            }
        });
        let nftables = self.families.contains(Families::NFTABLES).then(|| {
            let factory: ConnectionFactory<Nftables> = Arc::new(move || {
                let netns = netns.clone();
                Box::pin(async move { reconnect::<Nftables>(&netns) })
            });
            let stream = self.restarting(factory);
            if self.gap_deltas {
                Box::pin(stream.with_gap_deltas(NftablesEvent::object_key)) as FamilyStream<_>
            } else {
                Box::pin(stream)
            }
        });
        self.streams.insert(
            key,
            NsStreams {
                route,
                nftables,
                last_error: None,
                route_first: false,
                gone: false,
            },
        );
        Ok(())
    }

    fn restarting<P: Restartable>(&self, factory: ConnectionFactory<P>) -> RestartingStream<P> {
        let stream = Connection::<P>::events_restarting(factory, self.backoff.clone());
        match self.rcvbuf {
            Some(bytes) => stream.rcvbuf(bytes),
            None => stream,
        }
    }

    /// Stop watching `key`. Whether it was watched.
    pub fn remove(&mut self, key: &K) -> bool {
        self.streams.remove(key).is_some()
    }

    /// Whether `key` is watched.
    pub fn contains(&self, key: &K) -> bool {
        self.streams.contains_key(key)
    }

    /// The keys watched.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.streams.keys()
    }

    /// How many namespaces are watched.
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Whether no namespace is watched.
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }
}

impl<K> Stream for MultiNsWatch<K>
where
    K: Clone + Hash + Eq + Unpin,
{
    type Item = (K, NsEvent);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.streams).poll_next(cx);
        if let Poll::Ready(Some((key, NsEvent::Gone(_)))) = &polled {
            this.streams.remove(key);
        }
        polled
    }
}
