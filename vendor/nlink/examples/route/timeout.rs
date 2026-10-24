//! Operation timeouts for netlink requests.
//!
//! As of 0.17, every `Connection<P>` starts with a 30-second
//! default timeout on every netlink round-trip — a "hidden hang"
//! safety net so a kernel that never responds surfaces as
//! `Error::timeout()` instead of blocking forever. This example
//! covers the three knobs:
//!
//! 1. Default-30s (no opt-in needed).
//! 2. Override per-Connection via `.timeout(Duration)`.
//! 3. Opt out entirely via `.no_timeout()` (rarely useful —
//!    typically only for streaming dumps that legitimately take
//!    minutes; even then, `dump_stream*` apply the timeout
//!    per-chunk).
//!
//! Run with: cargo run -p nlink --example route_timeout
//!
//! Sudo isn't required — only read-only `get_links` is exercised.

use std::time::Duration;

use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    // Default — 30s safety net (Plan 171, shipped in 0.17).
    let conn = Connection::<Route>::new()?;
    println!("Default timeout: {:?}", conn.operation_timeout());
    assert_eq!(conn.operation_timeout(), Some(Duration::from_secs(30)));

    // Override to something tighter for a known-fast operation.
    let conn = conn.timeout(Duration::from_secs(5));
    println!("Tightened timeout: {:?}", conn.operation_timeout());
    let links = conn.get_links().await?;
    println!("Found {} interfaces (within timeout)", links.len());

    // Force a timeout to demonstrate the failure shape.
    let fast_conn = Connection::<Route>::new()?.timeout(Duration::from_nanos(1));
    match fast_conn.get_links().await {
        Ok(links) => println!("Got {} links (fast system!)", links.len()),
        Err(e) if e.is_timeout() => println!("Operation timed out (expected with 1ns timeout)"),
        Err(e) => return Err(e),
    }

    // Opt out entirely. Rare; only useful when you have your own
    // higher-level watchdog or are running a known-very-slow op.
    let conn = conn.no_timeout();
    assert_eq!(conn.operation_timeout(), None);
    println!("Timeout cleared (opt-out form).");

    Ok(())
}
