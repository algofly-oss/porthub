//! Monitor device hotplug events.
//!
//! This example demonstrates how to receive kernel object events (uevents)
//! for device hotplugging. These are the same events that udev uses.
//!
//! Run with: cargo run -p nlink --example uevent_device_monitor
//!
//! Try plugging in a USB device to see events.

use nlink::netlink::{Connection, KobjectUevent};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<KobjectUevent>::new()?;

    println!("Monitoring device events (plug/unplug USB, etc.)...");
    println!("Press Ctrl+C to exit.\n");

    loop {
        let event = conn.recv().await?;

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

        // Show device numbers for block/char devices
        if let (Some(major), Some(minor)) = (event.major(), event.minor()) {
            println!("  Major:Minor: {}:{}", major, minor);
        }

        // Show sequence number
        if let Some(seqnum) = event.seqnum() {
            println!("  Seqnum: {}", seqnum);
        }

        println!();
    }
}
