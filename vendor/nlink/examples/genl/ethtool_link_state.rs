//! Query link state and speed for a network interface.
//!
//! This example demonstrates how to use the ethtool netlink interface
//! to query the link state (up/down), speed, and duplex of a network
//! interface.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example ethtool_link_state -- eth0
//! ```
//!
//! # Requirements
//!
//! - Linux kernel 5.6+ with ethtool netlink support
//! - No special privileges required for read operations

use nlink::netlink::{Connection, Ethtool};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let ifname = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "eth0".to_string());

    println!("Querying ethtool info for {}...\n", ifname);

    let conn = Connection::<Ethtool>::new_async().await?;

    // Get link state
    let state = conn.get_link_state(&ifname).await?;
    println!("Link State:");
    match state.link {
        Some(link) => println!("  Link detected: {}", if link { "yes" } else { "no" }),
        None => println!("  Link detected: unknown (the driver does not report it)"),
    }

    if let Some(sqi) = state.sqi {
        let max = state.sqi_max.unwrap_or(100);
        println!("  Signal Quality Index: {}/{}", sqi, max);
    }

    if let Some(ext_state) = &state.ext_state {
        println!("  Extended state: {:?}", ext_state);
    }

    // Get link modes
    println!("\nLink Modes:");
    let modes = conn.get_link_modes(&ifname).await?;

    if let Some(speed) = modes.speed {
        println!("  Speed: {} Mb/s", speed);
    } else {
        println!("  Speed: Unknown");
    }

    if let Some(duplex) = modes.duplex {
        println!("  Duplex: {:?}", duplex);
    }

    println!(
        "  Auto-negotiation: {}",
        if modes.autoneg { "on" } else { "off" }
    );

    if let Some(lanes) = modes.lanes {
        println!("  Lanes: {}", lanes);
    }

    // Show supported modes
    let supported = modes.supported_modes();
    if !supported.is_empty() {
        println!("\n  Supported link modes:");
        for mode in supported {
            println!("    - {}", mode);
        }
    }

    // Show advertised modes
    let advertised = modes.advertised_modes();
    if !advertised.is_empty() {
        println!("\n  Advertised link modes:");
        for mode in advertised {
            println!("    - {}", mode);
        }
    }

    // Get link info
    println!("\nLink Info:");
    let info = conn.get_link_info(&ifname).await?;

    if let Some(port) = info.port {
        println!("  Port: {:?}", port);
    }

    if let Some(transceiver) = info.transceiver {
        println!("  Transceiver: {:?}", transceiver);
    }

    if let Some(mdix) = info.tp_mdix {
        println!("  MDI-X: {:?}", mdix);
    }

    Ok(())
}
