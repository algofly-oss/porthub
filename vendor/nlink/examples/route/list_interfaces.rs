//! List all network interfaces.
//!
//! This example demonstrates how to query and display network interfaces
//! using the high-level Connection API.
//!
//! Run with: cargo run -p nlink --example route_list_interfaces

use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;

    let links = conn.get_links().await?;

    println!(
        "{:<4} {:<16} {:<6} {:<18} {:<10}",
        "IDX", "NAME", "STATE", "MAC", "MTU"
    );
    println!("{}", "-".repeat(60));

    for link in links {
        // Use the name_or() helper for cleaner code
        let name = link.name_or("?");
        let state = if link.is_up() { "UP" } else { "DOWN" };
        let mac = link
            .address()
            .map(|m| {
                m.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(":")
            })
            .unwrap_or_else(|| "-".into());
        let mtu = link
            .mtu()
            .map(|m| m.to_string())
            .unwrap_or_else(|| "-".into());

        println!(
            "{:<4} {:<16} {:<6} {:<18} {:<10}",
            link.ifindex(),
            name,
            state,
            mac,
            mtu
        );
    }

    Ok(())
}
