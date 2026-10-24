//! List ARP/neighbor entries.
//!
//! This example demonstrates how to query neighbor (ARP/NDP) entries
//! using the high-level Connection API.
//!
//! Run with: cargo run -p nlink --example route_neighbors
//!
//! Filter by interface:
//!   cargo run -p nlink --example route_neighbors -- eth0

use std::env;

use nlink::netlink::{Connection, Route, messages::NeighborMessage, neigh::State as NeighborState};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some(dev) => {
            // List neighbors for specific interface
            list_neighbors_for(&conn, dev).await?;
        }
        None => {
            // List all neighbors
            list_neighbors(&conn).await?;
        }
    }

    Ok(())
}

async fn list_neighbors(conn: &Connection<Route>) -> nlink::netlink::Result<()> {
    let neighbors = conn.get_neighbors().await?;

    // Use the get_interface_names() helper to build ifindex -> name map
    let names = conn.get_interface_names().await?;

    println!(
        "{:<16} {:<20} {:<20} {:<10}",
        "INTERFACE", "ADDRESS", "LLADDR", "STATE"
    );
    println!("{}", "-".repeat(70));

    for neigh in neighbors {
        print_neighbor(&neigh, &names);
    }

    Ok(())
}

async fn list_neighbors_for(conn: &Connection<Route>, dev: &str) -> nlink::netlink::Result<()> {
    let link = conn.get_link_by_name(dev).await?;
    let link = match link {
        Some(l) => l,
        None => {
            eprintln!("Interface '{}' not found", dev);
            return Ok(());
        }
    };

    let neighbors = conn.get_neighbors().await?;

    println!("Neighbors on {}:", dev);
    println!("{}", "-".repeat(50));
    println!("{:<20} {:<20} {:<10}", "ADDRESS", "LLADDR", "STATE");

    let names = std::collections::HashMap::from([(link.ifindex(), dev.to_string())]);

    for neigh in neighbors {
        if neigh.ifindex() == link.ifindex() {
            print_neighbor(&neigh, &names);
        }
    }

    Ok(())
}

fn print_neighbor(neigh: &NeighborMessage, names: &std::collections::HashMap<u32, String>) {
    let ifname = names
        .get(&neigh.ifindex())
        .map(|s| s.as_str())
        .unwrap_or("?");

    let ip = neigh
        .destination()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "?".into());

    let mac = neigh.lladdr().map(format_mac).unwrap_or_else(|| "-".into());

    let state = neighbor_state_str(neigh.state());

    println!("{:<16} {:<20} {:<20} {:<10}", ifname, ip, mac, state);
}

fn neighbor_state_str(state: NeighborState) -> &'static str {
    match state {
        NeighborState::Incomplete => "INCOMPLETE",
        NeighborState::Reachable => "REACHABLE",
        NeighborState::Stale => "STALE",
        NeighborState::Delay => "DELAY",
        NeighborState::Probe => "PROBE",
        NeighborState::Failed => "FAILED",
        NeighborState::Noarp => "NOARP",
        NeighborState::Permanent => "PERMANENT",
        NeighborState::None => "NONE",
        _ => "UNKNOWN",
    }
}

fn format_mac(mac: &[u8]) -> String {
    if mac.len() >= 6 {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    } else {
        mac.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    }
}
