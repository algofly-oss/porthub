//! Monitor TC qdisc statistics in real-time.
//!
//! This example demonstrates how to track TC statistics and calculate
//! throughput rates over time.
//!
//! Run with: cargo run -p nlink --example route_tc_stats
//!
//! Examples:
//!   cargo run -p nlink --example route_tc_stats
//!   cargo run -p nlink --example route_tc_stats -- eth0

use std::{
    collections::HashMap,
    env,
    time::{Duration, Instant},
};

use nlink::netlink::{Connection, Route, messages::TcMessage};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    let args: Vec<String> = env::args().collect();

    let dev = args.get(1).map(|s| s.as_str());

    println!("Monitoring TC statistics (Ctrl+C to stop)...\n");

    let mut prev_stats: HashMap<(u32, u32), QdiscStats> = HashMap::new();
    let mut prev_time = Instant::now();

    loop {
        let qdiscs = if let Some(d) = dev {
            conn.get_qdiscs_by_name(d).await?
        } else {
            conn.get_qdiscs().await?
        };

        let now = Instant::now();
        let elapsed = now.duration_since(prev_time).as_secs_f64();

        // Clear screen
        print!("\x1b[2J\x1b[H");

        println!(
            "{:<8} {:<12} {:<10} {:>12} {:>12} {:>10} {:>10} {:>8}",
            "IFACE", "QDISC", "HANDLE", "BYTES", "PACKETS", "BPS", "PPS", "DROPS"
        );
        println!("{}", "-".repeat(90));

        // Get interface names using the helper
        let names = conn.get_interface_names().await?;

        for qdisc in &qdiscs {
            let ifname = names
                .get(&qdisc.ifindex())
                .map(|s| s.as_str())
                .unwrap_or("?");

            let kind = qdisc.kind().unwrap_or("?");
            let handle = qdisc.handle().to_string();

            // Calculate rates from deltas
            let key = (qdisc.ifindex(), qdisc.handle_raw());
            let current = QdiscStats::from_message(qdisc);

            let (bps, pps) = if let Some(prev) = prev_stats.get(&key) {
                let bytes_delta = current.bytes.saturating_sub(prev.bytes);
                let pkts_delta = current.packets.saturating_sub(prev.packets);
                (
                    (bytes_delta as f64 * 8.0 / elapsed) as u64, // bits per second
                    (pkts_delta as f64 / elapsed) as u64,
                )
            } else {
                // Use kernel's rate estimator for first sample
                (qdisc.bps(), qdisc.pps())
            };

            println!(
                "{:<8} {:<12} {:<10} {:>12} {:>12} {:>10} {:>10} {:>8}",
                ifname,
                kind,
                handle,
                format_bytes(current.bytes),
                current.packets,
                format_rate(bps),
                pps,
                current.drops
            );

            prev_stats.insert(key, current);
        }

        // Show legend
        println!();
        println!("BPS = bits per second (calculated from delta)");
        println!("PPS = packets per second");

        prev_time = now;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[derive(Clone)]
struct QdiscStats {
    bytes: u64,
    packets: u64,
    drops: u64,
}

impl QdiscStats {
    fn from_message(msg: &TcMessage) -> Self {
        Self {
            bytes: msg.bytes(),
            packets: msg.packets(),
            drops: msg.drops() as u64,
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000_000 {
        format!("{:.1}TB", bytes as f64 / 1_000_000_000_000.0)
    } else if bytes >= 1_000_000_000 {
        format!("{:.1}GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1}MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1}KB", bytes as f64 / 1_000.0)
    } else {
        format!("{}B", bytes)
    }
}

fn format_rate(bps: u64) -> String {
    if bps >= 1_000_000_000 {
        format!("{:.1}Gbps", bps as f64 / 1_000_000_000.0)
    } else if bps >= 1_000_000 {
        format!("{:.1}Mbps", bps as f64 / 1_000_000.0)
    } else if bps >= 1_000 {
        format!("{:.1}Kbps", bps as f64 / 1_000.0)
    } else {
        format!("{}bps", bps)
    }
}
