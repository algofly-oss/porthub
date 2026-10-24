//! Monitor SELinux events using the Stream API.
//!
//! This example demonstrates how to use the `EventSource` stream-based API
//! for receiving SELinux notifications. The Stream API integrates nicely
//! with tokio-stream combinators.
//!
//! Run with: cargo run --example selinux_monitor_stream
//!
//! To test, run in another terminal:
//!   sudo setenforce 0
//!   sudo setenforce 1

use nlink::netlink::{Connection, SELinux, selinux::SELinuxEvent};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    // Check if SELinux is available
    if !Connection::<SELinux>::is_available() {
        eprintln!("SELinux is not available on this system");
        eprintln!("(No /sys/fs/selinux filesystem found)");
        return Ok(());
    }

    // Show current enforcement mode
    match Connection::<SELinux>::get_enforce() {
        Ok(enforcing) => {
            println!(
                "Current SELinux mode: {}",
                if enforcing { "enforcing" } else { "permissive" }
            );
        }
        Err(e) => {
            eprintln!("Could not read SELinux mode: {}", e);
        }
    }

    println!();
    println!("Monitoring SELinux events using Stream API...");
    println!("(Use 'setenforce 0/1' or reload policy to generate events)");
    println!();

    let conn = Connection::<SELinux>::new()?;

    // Use events() to get a borrowed stream
    let mut events = conn.events().await;

    while let Some(result) = events.next().await {
        match result {
            Ok(event) => match event {
                SELinuxEvent::SetEnforce { enforcing } => {
                    let mode = if enforcing { "enforcing" } else { "permissive" };
                    println!("[SETENFORCE] SELinux mode changed to {}", mode);
                }
                SELinuxEvent::PolicyLoad { seqno } => {
                    println!("[POLICYLOAD] SELinux policy loaded (seqno: {})", seqno);
                }
                _ => {
                    println!("[UNKNOWN] Unrecognized SELinux event: {:?}", event);
                }
            },
            Err(e) => {
                eprintln!("Error receiving event: {}", e);
                break;
            }
        }
    }

    Ok(())
}
