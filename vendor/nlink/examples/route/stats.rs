//! Monitor interface statistics and calculate rates.
//!
//! This example demonstrates how to use StatsTracker to calculate
//! bandwidth usage in real-time.
//!
//! Run with: cargo run -p nlink --example route_stats

use std::time::Duration;

use nlink::netlink::{
    Connection, Route,
    stats::{StatsSnapshot, StatsTracker},
};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    let mut tracker = StatsTracker::new();

    println!("Monitoring interface statistics (Ctrl+C to stop)...\n");

    loop {
        let links = conn.get_links().await?;
        let snapshot = StatsSnapshot::from_links(&links);

        if let Some(rates) = tracker.update(snapshot) {
            // Clear screen and move cursor to top
            print!("\x1b[2J\x1b[H");

            println!(
                "{:<16} {:>12} {:>12} {:>12} {:>12}",
                "INTERFACE", "RX bytes/s", "TX bytes/s", "RX pkt/s", "TX pkt/s"
            );
            println!("{}", "-".repeat(68));

            for link in &links {
                if let Some(rate) = rates.links.get(&link.ifindex()) {
                    let name = link.name_or("?");

                    // Format rates with appropriate units
                    let rx_bps = format_rate(rate.rx_bytes_per_sec);
                    let tx_bps = format_rate(rate.tx_bytes_per_sec);

                    println!(
                        "{:<16} {:>12} {:>12} {:>12.0} {:>12.0}",
                        name, rx_bps, tx_bps, rate.rx_packets_per_sec, rate.tx_packets_per_sec
                    );
                }
            }
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn format_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec >= 1_000_000_000.0 {
        format!("{:.2} GB/s", bytes_per_sec / 1_000_000_000.0)
    } else if bytes_per_sec >= 1_000_000.0 {
        format!("{:.2} MB/s", bytes_per_sec / 1_000_000.0)
    } else if bytes_per_sec >= 1_000.0 {
        format!("{:.2} KB/s", bytes_per_sec / 1_000.0)
    } else {
        format!("{:.0} B/s", bytes_per_sec)
    }
}
