//! `ConnectionPool` parallel fanout (Plan 159).
//!
//! Run: `cargo run --example pool_parallel_dump`
//!
//! Spawns 16 tasks that each `acquire()` a pooled connection
//! from a 4-slot pool and dump links. The pool's bounded mpsc
//! channel keeps at most 4 connections in-flight; the other 12
//! tasks block on `acquire()` until a slot frees. Drop semantics
//! return the connection to the pool automatically.
//!
//! Demonstrates the canonical pattern for high-fanout netlink
//! workloads (metric exporters scraping every namespace,
//! controllers reconciling N parallel objects) without
//! socket-per-task overhead.

use std::sync::Arc;
use std::time::Instant;

use nlink::{ConnectionPoolBuilder, Route};

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> nlink::Result<()> {
    let pool = Arc::new(
        ConnectionPoolBuilder::<Route>::new()
            .size(4)
            .build()
            .await?,
    );
    println!("pool built: 4 connections, 16 tasks to dispatch");

    let start = Instant::now();

    let handles: Vec<_> = (0..16)
        .map(|i| {
            let p = Arc::clone(&pool);
            tokio::spawn(async move {
                let conn = p.acquire().await?;
                let links = conn.get_links().await?;
                Ok::<(usize, usize), nlink::Error>((i, links.len()))
            })
        })
        .collect();

    let mut total_dumps = 0usize;
    for h in handles {
        match h.await.expect("task panicked") {
            Ok((i, n)) => {
                total_dumps += 1;
                if i < 4 || i % 4 == 0 {
                    println!("  task {i:>2}: dumped {n} links");
                }
            }
            Err(e) => eprintln!("  task error: {e}"),
        }
    }

    let elapsed = start.elapsed();
    println!(
        "\n{} tasks completed in {:?} via 4 pooled connections",
        total_dumps, elapsed,
    );
    println!(
        "Per-task acquire→dump→release latency: {:?} avg",
        elapsed / total_dumps as u32,
    );
    Ok(())
}
