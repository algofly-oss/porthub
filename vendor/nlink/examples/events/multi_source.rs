//! Monitor multiple event sources using tokio::select!
//!
//! This example demonstrates how to use the `EventSource` stream-based API
//! to monitor multiple netlink protocols simultaneously using tokio::select!.
//!
//! Run with: sudo cargo run -p nlink --example events_multi_source
//!
//! This example monitors:
//! - Device hotplug events (KobjectUevent)
//! - Process lifecycle events (Connector, requires root)
//!
//! Try plugging in a USB device or running commands to see events.

use std::pin::pin;

use nlink::netlink::{Connection, Connector, KobjectUevent, connector::ProcEvent, uevent::Uevent};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    println!("Monitoring multiple event sources...");
    println!("- Device events (plug/unplug USB)");
    println!("- Process events (requires root)");
    println!("Press Ctrl+C to exit.\n");

    // Create connections for each protocol
    let uevent_conn = Connection::<KobjectUevent>::new()?;

    // Connector requires async initialization (registration handshake)
    let connector_conn = match Connection::<Connector>::new().await {
        Ok(conn) => Some(conn),
        Err(e) => {
            eprintln!("Note: Process events unavailable ({})", e);
            eprintln!("      Run with sudo for process monitoring.\n");
            None
        }
    };

    // Get event streams - using events() borrows the connection
    let mut uevent_stream = pin!(uevent_conn.events().await);

    if let Some(ref conn) = connector_conn {
        let mut proc_stream = pin!(conn.events().await);

        // Monitor both sources with select!
        loop {
            tokio::select! {
                Some(result) = uevent_stream.next() => {
                    if let Ok(event) = result {
                        print_uevent(&event);
                    }
                }
                Some(result) = proc_stream.next() => {
                    if let Ok(event) = result {
                        print_proc_event(&event);
                    }
                }
            }
        }
    } else {
        // Only monitor uevents
        while let Some(result) = uevent_stream.next().await {
            if let Ok(event) = result {
                print_uevent(&event);
            }
        }
    }

    Ok(())
}

fn print_uevent(event: &Uevent) {
    println!(
        "[DEVICE] {} {} ({})",
        event.action.to_uppercase(),
        event.devpath,
        event.subsystem
    );
    if let Some(devname) = event.devname() {
        println!("         /dev/{}", devname);
    }
}

fn print_proc_event(event: &ProcEvent) {
    match event {
        ProcEvent::Fork {
            parent_pid,
            child_pid,
            ..
        } => {
            println!("[PROC]   FORK {} -> {}", parent_pid, child_pid);
        }
        ProcEvent::Exec { pid, .. } => {
            println!("[PROC]   EXEC {}", pid);
        }
        ProcEvent::Exit { pid, exit_code, .. } => {
            println!("[PROC]   EXIT {} (code {})", pid, exit_code);
        }
        ProcEvent::Comm { pid, comm, .. } => {
            println!("[PROC]   COMM {} -> \"{}\"", pid, comm);
        }
        _ => {}
    }
}
