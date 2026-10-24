//! Netlink batching for bulk operations.
//!
//! Demonstrates using conn.batch() to execute multiple operations
//! in a single batch, reducing syscall overhead.
//!
//! Run with: cargo run -p nlink --example route_batch
//!
//! Requires root privileges.

use std::net::{IpAddr, Ipv4Addr};

use nlink::netlink::{Connection, Route, link::DummyLink, route::Ipv4Route};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;

    // Create a dummy interface for the example
    let _ = conn.add_link(DummyLink::new("batch-demo")).await;
    conn.set_link_up("batch-demo").await?;
    let link = conn.get_link_by_name("batch-demo").await?.unwrap();
    conn.add_address_by_index(link.ifindex(), IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1)), 24)
        .await?;

    // Batch multiple route additions
    println!("=== Batch Route Addition ===\n");

    let results = conn
        .batch()
        .add_route(
            Ipv4Route::new(Ipv4Addr::new(10, 99, 1, 0), 24).gateway(Ipv4Addr::new(10, 99, 0, 2)),
        )
        .add_route(
            Ipv4Route::new(Ipv4Addr::new(10, 99, 2, 0), 24).gateway(Ipv4Addr::new(10, 99, 0, 3)),
        )
        .add_route(
            Ipv4Route::new(Ipv4Addr::new(10, 99, 3, 0), 24).gateway(Ipv4Addr::new(10, 99, 0, 4)),
        )
        .execute()
        .await?;

    println!(
        "{}/{} operations succeeded",
        results.success_count(),
        results.len()
    );

    if !results.all_ok() {
        for (i, err) in results.errors() {
            eprintln!("  Operation {} failed: {}", i, err);
        }
    }

    // Verify routes were added
    let routes = conn.get_routes().await?;
    let batch_routes: Vec<_> = routes
        .iter()
        .filter(|r| r.destination_str().starts_with("10.99."))
        .collect();
    println!("Routes in 10.99.0.0/16: {}", batch_routes.len());

    // Cleanup
    let _ = conn.del_link("batch-demo").await;
    println!("\nCleaned up.");

    Ok(())
}
