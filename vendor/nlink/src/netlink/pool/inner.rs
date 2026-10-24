//! `ConnectionPool<P>` and its builder.

use std::{future::Future, marker::PhantomData, pin::Pin, sync::Arc, time::Duration};

use tokio::sync::{mpsc, Mutex};

use super::pooled::PooledConnection;
use crate::netlink::{
    connection::Connection,
    error::{Error, Result},
    namespace,
    protocol::{
        construction::{AsyncConstructible, SyncConstructible},
        AsyncProtocolInit, ProtocolState,
    },
};

/// Boxed future returned by [`Factory::build`]. 0.19 Finding C —
/// invalidate-then-refill closes the silent pool capacity decay
/// that left long-running pools degraded to zero.
pub(super) type FactoryFuture<P> =
    Pin<Box<dyn Future<Output = Result<Connection<P>>> + Send>>;

/// Async factory used by [`PooledConnection::invalidate`] to
/// reconstruct a replacement connection. Erases the
/// `SyncConstructible` / `AsyncConstructible` split so the
/// `PoolInner` carries one trait object for either case.
pub(super) trait Factory<P: ProtocolState>: Send + Sync + 'static {
    fn build(&self) -> FactoryFuture<P>;
}

pub(super) struct PoolInner<P: ProtocolState> {
    /// Bounded mpsc channel — capacity == pool size. `acquire` is
    /// `recv()` (waits when the pool is exhausted); `release` is
    /// `try_send()` (non-blocking — capacity is exactly N so it
    /// always succeeds for the same N pooled connections).
    pub(super) available: mpsc::Sender<Connection<P>>,
    pub(super) receiver: Mutex<mpsc::Receiver<Connection<P>>>,
    pub(super) namespace: Option<String>,
    pub(super) size: usize,
    pub(super) acquire_timeout: Duration,
    /// 0.19 Finding C — async factory invoked by
    /// `PooledConnection::invalidate` to rebuild the dropped
    /// connection off the drop path. Without this the pool's
    /// effective capacity decayed with each invalidate, eventually
    /// blocking every `acquire()` indefinitely.
    pub(super) factory: Arc<dyn Factory<P>>,
}

/// A bounded async pool of [`Connection<P>`] instances.
///
/// See the [module-level docs][crate::netlink::pool] for the design
/// rationale, sizing guidance, and the relationship to neli's
/// deferred-to-0.17 NlRouter-style multiplexing.
#[non_exhaustive]
pub struct ConnectionPool<P: ProtocolState> {
    pub(super) inner: Arc<PoolInner<P>>,
}

#[nlink_macros::send_futures]
impl<P: ProtocolState> ConnectionPool<P> {
    /// Acquire a connection from the pool.
    ///
    /// Waits up to the configured `acquire_timeout` for a connection
    /// to become available. Returns:
    ///
    /// - `Err(Error::PoolExhausted)` if no connection is returned to
    ///   the pool within the timeout.
    /// - `Err(Error::pool_closed())` if the last `ConnectionPool`
    ///   handle has been dropped while this acquire was waiting.
    ///
    /// The returned [`PooledConnection`] derefs to `&Connection<P>`,
    /// so every typed Connection method Just Works. On drop the
    /// connection is returned to the pool — unless
    /// [`PooledConnection::invalidate`] was called first.
    pub async fn acquire(&self) -> Result<PooledConnection<'_, P>> {
        let recv_fut = async {
            let mut rx = self.inner.receiver.lock().await;
            rx.recv().await
        };
        match tokio::time::timeout(self.inner.acquire_timeout, recv_fut).await {
            Ok(Some(conn)) => Ok(PooledConnection::new(self, conn)),
            Ok(None) => Err(Error::pool_closed()),
            Err(_) => Err(Error::from(crate::netlink::ErrorDetail::PoolExhausted {
                size: self.inner.size,
                timeout: self.inner.acquire_timeout,
            })),
        }
    }

    /// Pool size (the channel capacity = total number of
    /// connections held by the pool, busy or idle).
    pub fn size(&self) -> usize {
        self.inner.size
    }

    /// Configured acquire timeout.
    pub fn acquire_timeout(&self) -> Duration {
        self.inner.acquire_timeout
    }

    /// The namespace this pool is bound to, if any: its name for a named
    /// one, else how it was opened (a path, a pid). `None` is the default
    /// (calling-process) netns.
    pub fn namespace(&self) -> Option<&str> {
        self.inner.namespace.as_deref()
    }
}

#[nlink_macros::send_futures]
impl<P: ProtocolState + Default + SyncConstructible + 'static> ConnectionPool<P> {
    /// Convenience: build a pool bound to a named network namespace.
    /// Equivalent to:
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::pool::ConnectionPoolBuilder;
    /// # let (ns, size) = ("myns", 4);
    /// let pool = ConnectionPoolBuilder::<nlink::Route>::new()
    ///     .namespace(ns)
    ///     .size(size)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[deprecated(since = "0.32.0", note = "use `ConnectionPool::new_in(ns, size)` (#532)")]
    pub async fn for_namespace(
        ns: impl Into<String>,
        size: usize,
    ) -> Result<Self> {
        Self::new_in(ns.into(), size).await
    }

    /// A pool of `size` connections in a network namespace: an `ip netns`
    /// name, an open [`Netns`](namespace::Netns), a
    /// [`NetnsRef`](namespace::NetnsRef), … (#532). Equivalent to
    /// [`ConnectionPoolBuilder::namespace`] with
    /// [`size`](ConnectionPoolBuilder::size).
    pub async fn new_in<'a>(
        ns: impl Into<namespace::NetnsTarget<'a>>,
        size: usize,
    ) -> Result<Self> {
        ConnectionPoolBuilder::new()
            .namespace(ns)
            .size(size)
            .build()
            .await
    }
}

/// Builder for [`ConnectionPool<P>`].
///
/// Two `build` overloads exist: one for synchronously-constructible
/// protocols (sealed `SyncConstructible`), one for GENL families
/// (sealed `AsyncConstructible`). See Plan 148 §4.5 for the sealed
/// trait split.
#[non_exhaustive]
pub struct ConnectionPoolBuilder<P: ProtocolState> {
    size: usize,
    acquire_timeout: Duration,
    namespace: Option<PoolNamespace>,
    _phantom: PhantomData<fn() -> P>,
}

/// The builder's namespace: where one is, opened at `build`, or one
/// already open (or the error opening it gave).
enum PoolNamespace {
    Ref(namespace::NetnsRef),
    Open(Result<Arc<namespace::Netns>>),
}

impl PoolNamespace {
    /// The namespace, opened once: every connection, and every
    /// replacement, is made in that one, never in a namespace created
    /// later under the same name (#520).
    fn open(this: Option<Self>) -> Result<Option<Arc<namespace::Netns>>> {
        match this {
            None => Ok(None),
            Some(Self::Ref(r)) => Ok(Some(Arc::new(r.open()?))),
            Some(Self::Open(netns)) => netns.map(Some),
        }
    }
}

impl<P: ProtocolState> Default for ConnectionPoolBuilder<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: ProtocolState> ConnectionPoolBuilder<P> {
    /// Construct a new builder with sensible defaults.
    ///
    /// Defaults:
    /// - `size = std::thread::available_parallelism()` (or 4 if
    ///   unavailable)
    /// - `acquire_timeout = 5 seconds`
    /// - `namespace = None` (default / calling-process netns)
    pub fn new() -> Self {
        let size = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Self {
            size,
            acquire_timeout: Duration::from_secs(5),
            namespace: None,
            _phantom: PhantomData,
        }
    }

    /// Set the pool size (number of pooled `Connection<P>`).
    ///
    /// Clamped to ≥ 1 — a pool of 0 would deadlock on first acquire.
    /// No upper clamp: caller is responsible for not requesting an
    /// absurd size (each pooled Connection holds one netlink socket
    /// fd plus ~1 MB of recv buffers when `syscall_batch` is on).
    pub fn size(mut self, size: usize) -> Self {
        self.size = size.max(1);
        self
    }

    /// Maximum time `acquire()` will wait for a connection to become
    /// available before returning [`ErrorDetail::PoolExhausted`](crate::ErrorDetail::PoolExhausted).
    pub fn acquire_timeout(mut self, timeout: Duration) -> Self {
        self.acquire_timeout = timeout;
        self
    }

    /// Bind the pool to a network namespace: an `ip netns` name, an open
    /// [`Netns`](namespace::Netns), a [`NetnsRef`](namespace::NetnsRef),
    /// a path, a namespace fd (#532). A handle or fd is duplicated now; a
    /// name or path is opened by `build`.
    pub fn namespace<'a>(mut self, ns: impl Into<namespace::NetnsTarget<'a>>) -> Self {
        self.namespace = match ns.into() {
            namespace::NetnsTarget::Ref(r) if r.is_default() => None,
            namespace::NetnsTarget::Ref(r) => Some(PoolNamespace::Ref(r)),
            other => match other.open() {
                Ok(None) => None,
                Ok(Some(netns)) => Some(PoolNamespace::Open(Ok(Arc::new(netns)))),
                Err(e) => Some(PoolNamespace::Open(Err(e))),
            },
        };
        self
    }
}

#[nlink_macros::send_futures]
impl<P> ConnectionPoolBuilder<P>
where
    P: ProtocolState + Default + SyncConstructible + 'static,
{
    /// Build the pool, seeding it with `size` freshly-constructed
    /// synchronously-constructible connections.
    ///
    /// For GENL families (Wireguard, Macsec, etc.) use the
    /// `build_async` overload — that branch lives below this impl
    /// block and gets selected automatically by the trait bound.
    pub async fn build(self) -> Result<ConnectionPool<P>> {
        let (tx, rx) = mpsc::channel(self.size);
        let netns = PoolNamespace::open(self.namespace)?;
        let namespace = netns.as_ref().map(|ns| ns.label().to_string());
        for _ in 0..self.size {
            let conn = make_sync::<P>(netns.as_deref())?;
            tx.send(conn).await.map_err(|_| Error::pool_closed())?;
        }
        let factory: Arc<dyn Factory<P>> = Arc::new(SyncFactory {
            netns,
            _phantom: PhantomData,
        });
        Ok(ConnectionPool {
            inner: Arc::new(PoolInner {
                available: tx,
                receiver: Mutex::new(rx),
                namespace,
                size: self.size,
                acquire_timeout: self.acquire_timeout,
                factory,
            }),
        })
    }
}

/// 0.19 Finding C — concrete factory for SyncConstructible protocols.
struct SyncFactory<P: ProtocolState + Default + SyncConstructible + 'static> {
    netns: Option<Arc<namespace::Netns>>,
    _phantom: PhantomData<fn() -> P>,
}

/// A connection in the pool's namespace, or `NamespaceDeleted` once its
/// name no longer names it (#520).
fn make_sync<P>(netns: Option<&namespace::Netns>) -> Result<Connection<P>>
where
    P: ProtocolState + Default + SyncConstructible + 'static,
{
    match netns {
        Some(ns) if !ns.is_live() => Err(ns.deleted()),
        Some(ns) => ns.connection::<P>(),
        None => Connection::<P>::new(),
    }
}

impl<P> Factory<P> for SyncFactory<P>
where
    P: ProtocolState + Default + SyncConstructible + 'static,
{
    fn build(&self) -> FactoryFuture<P> {
        let netns = self.netns.clone();
        Box::pin(async move { make_sync::<P>(netns.as_deref()) })
    }
}

#[nlink_macros::send_futures]
impl<P> ConnectionPoolBuilder<P>
where
    P: ProtocolState + AsyncProtocolInit + AsyncConstructible + 'static,
{
    /// Build a pool of GENL-family connections (each Connection
    /// resolves its family ID via async setup before joining the
    /// pool).
    ///
    /// Use this overload when `P` is one of `Wireguard`, `Macsec`,
    /// `Mptcp`, `Ethtool`, `Nl80211`, or `Devlink`. The sealed
    /// trait split (Plan 148 §4.5) means a single `build()` call
    /// picks the right overload from the bound.
    pub async fn build_async(self) -> Result<ConnectionPool<P>> {
        let (tx, rx) = mpsc::channel(self.size);
        let netns = PoolNamespace::open(self.namespace)?;
        let namespace = netns.as_ref().map(|ns| ns.label().to_string());
        for _ in 0..self.size {
            let conn = make_async::<P>(netns.clone()).await?;
            tx.send(conn).await.map_err(|_| Error::pool_closed())?;
        }
        let factory: Arc<dyn Factory<P>> = Arc::new(AsyncFactory {
            netns,
            _phantom: PhantomData,
        });
        Ok(ConnectionPool {
            inner: Arc::new(PoolInner {
                available: tx,
                receiver: Mutex::new(rx),
                namespace,
                size: self.size,
                acquire_timeout: self.acquire_timeout,
                factory,
            }),
        })
    }
}

/// 0.19 Finding C — concrete factory for AsyncConstructible
/// (GENL-family) protocols. Each replacement Connection
/// re-resolves the family ID, just like the initial seed.
struct AsyncFactory<P: ProtocolState + AsyncProtocolInit + AsyncConstructible + 'static> {
    netns: Option<Arc<namespace::Netns>>,
    _phantom: PhantomData<fn() -> P>,
}

/// A GENL connection in the pool's namespace, its family resolved there, or
/// `NamespaceDeleted` once the namespace's name no longer names it (#520).
async fn make_async<P>(netns: Option<Arc<namespace::Netns>>) -> Result<Connection<P>>
where
    P: ProtocolState + AsyncProtocolInit + AsyncConstructible + 'static,
{
    match netns {
        Some(ns) if !ns.is_live() => Err(ns.deleted()),
        Some(ns) => ns.connection_async::<P>().await,
        None => {
            let socket = crate::netlink::socket::NetlinkSocket::new(P::PROTOCOL)?;
            let state = P::resolve_async(&socket).await?;
            Ok(Connection::from_parts(socket, state))
        }
    }
}

impl<P> Factory<P> for AsyncFactory<P>
where
    P: ProtocolState + AsyncProtocolInit + AsyncConstructible + 'static,
{
    fn build(&self) -> FactoryFuture<P> {
        Box::pin(make_async::<P>(self.netns.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::protocol::Route;

    #[test]
    fn builder_defaults() {
        let b = ConnectionPoolBuilder::<Route>::new();
        assert!(b.size >= 1);
        assert_eq!(b.acquire_timeout, Duration::from_secs(5));
        assert!(b.namespace.is_none());
    }

    #[test]
    fn builder_size_clamped_to_at_least_one() {
        let b = ConnectionPoolBuilder::<Route>::new().size(0);
        assert_eq!(b.size, 1);
    }

    #[test]
    fn builder_namespace_setter() {
        let b = ConnectionPoolBuilder::<Route>::new().namespace("myns");
        assert!(
            matches!(&b.namespace, Some(PoolNamespace::Ref(namespace::NetnsRef::Named(n))) if n == "myns")
        );
        let b = ConnectionPoolBuilder::<Route>::new().namespace(namespace::NetnsRef::Default);
        assert!(b.namespace.is_none(), "the default namespace needs nothing opened");
    }
}
