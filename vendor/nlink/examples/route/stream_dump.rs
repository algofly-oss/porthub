//! Streaming dump showcase — O(1)-memory iteration over kernel
//! dumps via `Connection::stream_*` (Plan 149).
//!
//! Run: `cargo run --example route_stream_dump`
//!
//! Demonstrates `stream_links` + `stream_routes` (which would
//! otherwise pull every dumped frame into a single `Vec<Vec<u8>>`
//! before parsing the first one). The first 5 items of each
//! stream are printed; the rest are drained without storing.
//!
//! The same pattern works for: `stream_neighbors`,
//! `stream_addresses`, `stream_qdiscs`, `stream_classes_by_index`,
//! `stream_filters_by_index`, `Connection<Xfrm>::stream_sas`,
//! `Connection<Xfrm>::stream_sps`,
//! `Connection<Netfilter>::stream_conntrack` (`_v4` / `_v6`),
//! `Connection<Nftables>::stream_rules`.

use nlink::netlink::{Connection, Route};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;

    // -- Links --------------------------------------------------
    let mut count = 0usize;
    let mut stream = conn.stream_links().await?;
    while let Some(link) = stream.next().await {
        let link = link?;
        count += 1;
        if count <= 5 {
            println!(
                "link {:>3}: {:<16} mtu={}",
                link.ifindex(),
                link.name_or("?"),
                link.mtu().map(|m| m.to_string()).unwrap_or_else(|| "-".into()),
            );
        }
    }
    println!("link stream: {count} total\n");

    // -- Routes -------------------------------------------------
    count = 0;
    let mut stream = conn.stream_routes().await?;
    while let Some(route) = stream.next().await {
        let route = route?;
        count += 1;
        if count <= 5 {
            println!(
                "route: dst={:?} oif={:?} table={}",
                route.destination(),
                route.oif(),
                route.table_id(),
            );
        }
    }
    println!("route stream: {count} total");

    println!("\nMemory note: peak buffer use is one socket batch \
              (~8KiB by default), not the full dump. For BGP-scale \
              route tables (1M+ routes) this is the difference \
              between a working tool and an OOM kill.");

    Ok(())
}
