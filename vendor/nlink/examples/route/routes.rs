//! List routes.
//!
//! This example demonstrates how to query routes
//! using the high-level Connection API.
//!
//! Run with: cargo run -p nlink --example route_routes
//!
//! Filter by address family:
//!   cargo run -p nlink --example route_routes -- v4
//!   cargo run -p nlink --example route_routes -- v6

use std::env;

use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("v4") => {
            list_routes(&conn, Some(true)).await?;
        }
        Some("v6") => {
            list_routes(&conn, Some(false)).await?;
        }
        _ => {
            list_routes(&conn, None).await?;
        }
    }

    Ok(())
}

async fn list_routes(
    conn: &Connection<Route>,
    ipv4_only: Option<bool>,
) -> nlink::netlink::Result<()> {
    let routes = conn.get_routes().await?;

    // Use the get_interface_names() helper to build ifindex -> name map
    let names = conn.get_interface_names().await?;

    println!(
        "{:<6} {:<24} {:<20} {:<16} {:>8}",
        "TABLE", "DESTINATION", "GATEWAY", "DEV", "METRIC"
    );
    println!("{}", "-".repeat(80));

    for route in routes {
        // Filter by address family if requested
        if let Some(v4) = ipv4_only
            && v4 != route.is_ipv4()
        {
            continue;
        }

        let table = match route.table_id() {
            254 => "main".to_string(),
            255 => "local".to_string(),
            253 => "default".to_string(),
            0 => "unspec".to_string(),
            t => t.to_string(),
        };

        let dst = route
            .destination()
            .map(|a| format!("{}/{}", a, route.dst_len()))
            .unwrap_or_else(|| "default".into());

        let gw = route
            .gateway()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "-".into());

        let dev = route
            .oif()
            .and_then(|idx| names.get(&idx))
            .map(|s| s.as_str())
            .unwrap_or("-");

        let metric = route
            .priority()
            .map(|m| m.to_string())
            .unwrap_or_else(|| "-".into());

        println!(
            "{:<6} {:<24} {:<20} {:<16} {:>8}",
            table, dst, gw, dev, metric
        );
    }

    Ok(())
}
