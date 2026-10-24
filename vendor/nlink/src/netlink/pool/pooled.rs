//! `PooledConnection<'p, P>` — RAII guard that derefs to
//! `&Connection<P>` and returns the connection on drop.

use std::ops::Deref;

use super::inner::ConnectionPool;
use crate::netlink::{connection::Connection, protocol::ProtocolState};

/// A pooled connection borrowed from a [`ConnectionPool`].
///
/// Implements `Deref<Target = Connection<P>>` so every typed
/// connection method is callable directly on the guard. On drop the
/// underlying `Connection` is returned to the pool. Use
/// [`Self::invalidate`] to mark the connection as bad and have it
/// dropped (instead of returned) on guard drop.
#[non_exhaustive]
pub struct PooledConnection<'p, P: ProtocolState> {
    pool: &'p ConnectionPool<P>,
    conn: Option<Connection<P>>,
}

impl<'p, P: ProtocolState> PooledConnection<'p, P> {
    pub(super) fn new(pool: &'p ConnectionPool<P>, conn: Connection<P>) -> Self {
        Self {
            pool,
            conn: Some(conn),
        }
    }
}

impl<'p, P: ProtocolState + Send + Sync + 'static> PooledConnection<'p, P> {

    /// Mark this connection as unhealthy. On drop, the connection
    /// is closed AND the pool schedules an async task to build a
    /// replacement and put it back into the pool (0.19 Finding C
    /// — closes the silent capacity decay where every `invalidate`
    /// permanently shrank the pool by one connection).
    ///
    /// Use when you've observed a recoverable error that suggests
    /// the socket may be in a bad state (rare; most kernel errors
    /// are per-request, not per-socket).
    ///
    /// **Replenish race window.** The replacement is built on a
    /// `tokio::spawn` (off the drop path because it's async).
    /// Between invalidate and the new connection landing in the
    /// pool there is a brief window where `acquire()` may block —
    /// up to the `acquire_timeout`. If replacement construction
    /// itself fails (kernel module missing, namespace gone,
    /// permission revoked), the failure is `tracing::error!`-logged
    /// and the pool's effective capacity drops by one. Subsequent
    /// invalidates that succeed restore capacity.
    ///
    /// **Consumes the guard** (Plan 162) so a subsequent `&*p`
    /// is a compile error (E0382 — use of moved value) instead
    /// of a runtime panic.
    ///
    /// ```compile_fail
    /// # use nlink::netlink::pool::PooledConnection;
    /// # async fn run<P: nlink::netlink::ProtocolState>(p: PooledConnection<'_, P>) {
    /// p.invalidate();
    /// let _ = &*p;  // compile error: borrow of moved value `p`
    /// # }
    /// ```
    pub fn invalidate(mut self) {
        if let Some(conn) = self.conn.take() {
            tracing::warn!(
                ns = ?self.pool.namespace(),
                "PooledConnection::invalidate: dropping pooled connection, replenishing in background"
            );
            // Close the broken fd first so the kernel reclaims it
            // before we attempt to spawn a replacement that may
            // share the same protocol fd quota.
            drop(conn);

            // 0.19 Finding C — schedule a replenish on the tokio
            // runtime. We capture the Arc<PoolInner> not the
            // `&'p ConnectionPool<P>` so the spawned task
            // outlives the guard's borrow scope.
            let inner = self.pool.inner.clone();
            tokio::spawn(async move {
                match inner.factory.build().await {
                    Ok(fresh) => match inner.available.try_send(fresh) {
                        Ok(()) => {
                            tracing::debug!(
                                ns = ?inner.namespace,
                                "PooledConnection::invalidate: replacement connection added to pool"
                            );
                        }
                        Err(_) => {
                            // Channel closed (pool dropped) — fine,
                            // the replacement drops here.
                            tracing::debug!(
                                "PooledConnection::invalidate: pool closed before replenish"
                            );
                        }
                    },
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            ns = ?inner.namespace,
                            "PooledConnection::invalidate: replenish failed; pool capacity reduced by one"
                        );
                    }
                }
            });
        }
        // `self` drops here; Drop sees conn == None and is a no-op.
    }
}

impl<P: ProtocolState> Deref for PooledConnection<'_, P> {
    type Target = Connection<P>;

    fn deref(&self) -> &Connection<P> {
        // INVARIANT: `conn` is set on construction and only
        // cleared by `invalidate(self)` which consumes the guard.
        // So any live `&self` borrow proves the guard hasn't
        // been moved, which proves `conn` is still `Some`.
        // The `debug_assert!` documents the invariant; the
        // `expect` is statically unreachable from safe code.
        debug_assert!(
            self.conn.is_some(),
            "PooledConnection::conn cleared without consuming \
             the guard — would imply a use-after-move past the \
             Rust borrow checker. Bug."
        );
        self.conn
            .as_ref()
            .expect("PooledConnection holds a Connection until drop (see invariant above)")
    }
}

impl<P: ProtocolState> Drop for PooledConnection<'_, P> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            // try_send is non-blocking. Capacity == pool size, so
            // for the exact set of pooled connections this can
            // only fail if the receiver was dropped (pool closed)
            // — in which case dropping `conn` here is the correct
            // teardown.
            let _ = self.pool.inner.available.try_send(conn);
        }
    }
}
