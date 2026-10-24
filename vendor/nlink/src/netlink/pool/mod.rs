//! Bounded connection pools for high-fanout consumers.
//!
//! [`ConnectionPool<P>`] is the partial alternative to the
//! NlRouter-style multi-request-per-socket fanout that lives in
//! `neli` — instead of multiplexing N requests over one socket via
//! sequence-number demux, we hold N sockets and round-robin requests
//! across them. For the documented use cases (concurrent route
//! lookups, parallel multi-namespace work, high-fanout dump pipelines)
//! the pool gives ≥80% of the throughput benefit at <10% of the
//! implementation risk. Sockets are file descriptors — cheap.
//!
//! # Single-flight invariant carries through
//!
//! Each pooled `Connection<P>` retains the **single-flight**
//! semantic — only one request in-flight per Connection at a time.
//! The pool gives you concurrency by handing out *different*
//! Connections to different tasks, not by allowing one Connection
//! to multiplex.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//! use nlink::{Connection, ConnectionPoolBuilder, Route};
//!
//! # async fn run() -> nlink::Result<()> {
//! let pool = Arc::new(
//!     ConnectionPoolBuilder::<Route>::new()
//!         .size(8)
//!         .acquire_timeout(Duration::from_secs(2))
//!         .build()
//!         .await?,
//! );
//!
//! // Parallel link dumps across the pool:
//! let mut joins = Vec::new();
//! for _ in 0..16 {
//!     let pool = Arc::clone(&pool);
//!     joins.push(tokio::spawn(async move {
//!         let conn = pool.acquire().await?;
//!         conn.get_links().await
//!     }));
//! }
//! for j in joins { let _ = j.await; }
//! # Ok(())
//! # }
//! ```
//!
//! # Sizing guidance
//!
//! - **I/O-bound bursty**: `pool size ≈ 2 × num_cpus`
//! - **Steady-state**: `pool size ≈ max-expected-concurrent-requests`
//! - **Memory cost**: each pooled Connection owns its own netlink
//!   socket fd. Cheap. With `syscall_batch` feature enabled
//!   (Plan 158, 0.16+), each Connection lazily allocates ~1 MB of
//!   recv buffers on first batched recv — bear in mind for pools
//!   sized in the hundreds.
//!
//! # Drop semantics
//!
//! Dropping the last `Arc<ConnectionPool>` closes all underlying
//! sockets in pool order. Outstanding [`PooledConnection`] guards
//! stay valid until their own drop — their Connection is owned, not
//! borrowed.
//!
//! Per-acquire `PooledConnection::invalidate()` is the escape hatch
//! for "this connection is unhealthy; rebuild on drop instead of
//! returning to the pool."

mod inner;
mod pooled;

pub use inner::{ConnectionPool, ConnectionPoolBuilder};
pub use pooled::PooledConnection;
