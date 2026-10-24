//! Monitor ethtool events in real-time.
//!
//! This example demonstrates how to subscribe to the ethtool netlink
//! monitor multicast group and receive notifications about configuration
//! changes.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example ethtool_monitor
//! ```
//!
//! Then in another terminal, change interface settings:
//! ```bash
//! sudo ethtool -s eth0 speed 100 duplex full
//! ```
//!
//! # Requirements
//!
//! - Linux kernel 5.6+ with ethtool netlink support
//! - No special privileges required for monitoring

use nlink::netlink::{Connection, Ethtool, genl::ethtool::EthtoolEvent};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    println!("Monitoring ethtool events (Ctrl+C to stop)...\n");

    let conn = Connection::<Ethtool>::new_async().await?;

    // Subscribe to the monitor multicast group
    conn.subscribe()?;
    println!("Subscribed to ethtool monitor group\n");

    // Receive and display events using the Stream API
    let mut events = conn.events().await;
    while let Some(result) = events.next().await {
        match result {
            Ok(event) => {
                print_event(&event);
            }
            Err(e) => {
                eprintln!("Error receiving event: {}", e);
            }
        }
    }

    Ok(())
}

fn print_event(event: &EthtoolEvent) {
    match event {
        EthtoolEvent::LinkStateChanged { ifname, state } => {
            let name = ifname.as_deref().unwrap_or("?");
            println!(
                "[{}] Link state: {}",
                name,
                match state.link {
                    Some(true) => "UP",
                    Some(false) => "DOWN",
                    None => "UNKNOWN",
                }
            );
            if let Some(sqi) = state.sqi {
                println!("       SQI: {}/{}", sqi, state.sqi_max.unwrap_or(100));
            }
        }
        EthtoolEvent::LinkModesChanged { ifname, modes } => {
            let name = ifname.as_deref().unwrap_or("?");
            println!("[{}] Link modes changed:", name);
            if let Some(speed) = modes.speed {
                println!("       Speed: {} Mb/s", speed);
            }
            if let Some(duplex) = &modes.duplex {
                println!("       Duplex: {:?}", duplex);
            }
            println!(
                "       Autoneg: {}",
                if modes.autoneg { "on" } else { "off" }
            );
        }
        EthtoolEvent::LinkInfoChanged { ifname, info } => {
            let name = ifname.as_deref().unwrap_or("?");
            println!("[{}] Link info changed:", name);
            if let Some(port) = &info.port {
                println!("       Port: {:?}", port);
            }
            if let Some(transceiver) = &info.transceiver {
                println!("       Transceiver: {:?}", transceiver);
            }
        }
        EthtoolEvent::FeaturesChanged { ifname, features } => {
            let name = ifname.as_deref().unwrap_or("?");
            let active_count = features.active_features().len();
            println!("[{}] Features changed: {} active", name, active_count);
        }
        EthtoolEvent::RingsChanged { ifname, rings } => {
            let name = ifname.as_deref().unwrap_or("?");
            println!("[{}] Ring sizes changed:", name);
            if let Some(rx) = rings.rx {
                println!("       RX: {}", rx);
            }
            if let Some(tx) = rings.tx {
                println!("       TX: {}", tx);
            }
        }
        EthtoolEvent::ChannelsChanged { ifname, channels } => {
            let name = ifname.as_deref().unwrap_or("?");
            println!("[{}] Channels changed:", name);
            if let Some(combined) = channels.combined_count {
                println!("       Combined: {}", combined);
            }
        }
        EthtoolEvent::CoalesceChanged { ifname, coalesce } => {
            let name = ifname.as_deref().unwrap_or("?");
            println!("[{}] Coalesce changed:", name);
            if let Some(rx_usecs) = coalesce.rx_usecs {
                println!("       RX usecs: {}", rx_usecs);
            }
            if let Some(tx_usecs) = coalesce.tx_usecs {
                println!("       TX usecs: {}", tx_usecs);
            }
        }
        EthtoolEvent::PauseChanged { ifname, pause } => {
            let name = ifname.as_deref().unwrap_or("?");
            println!("[{}] Pause changed:", name);
            if let Some(rx) = pause.rx {
                println!("       RX: {}", if rx { "on" } else { "off" });
            }
            if let Some(tx) = pause.tx {
                println!("       TX: {}", if tx { "on" } else { "off" });
            }
        }
        EthtoolEvent::Unknown { cmd } => {
            println!("[?] Unknown event: cmd={}", cmd);
        }
        _ => {}
    }
    println!();
}
