//! Monitor device hotplug events using the Stream API.
//!
//! This example demonstrates how to use the `EventSource` stream-based API
//! for receiving kernel object events. The Stream API integrates with
//! tokio-stream combinators and tokio::select!.
//!
//! Run with: cargo run -p nlink --example uevent_device_monitor_stream
//!
//! Try plugging in a USB device to see events.

use nlink::netlink::{Connection, KobjectUevent};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<KobjectUevent>::new()?;

    println!("Monitoring device events using Stream API...");
    println!("Press Ctrl+C to exit.\n");

    // Use events() to get a borrowed stream - connection remains usable
    let mut events = conn.events().await;

    while let Some(result) = events.next().await {
        let event = result?;

        // Show action and basic info
        println!(
            "[{}] {} ({})",
            event.action.to_uppercase(),
            event.devpath,
            event.subsystem
        );

        // Show device name if available
        if let Some(devname) = event.devname() {
            println!("  Device: /dev/{}", devname);
        }

        // Show device type
        if let Some(devtype) = event.devtype() {
            println!("  Type: {}", devtype);
        }

        // Show driver
        if let Some(driver) = event.driver() {
            println!("  Driver: {}", driver);
        }

        println!();
    }

    Ok(())
}
