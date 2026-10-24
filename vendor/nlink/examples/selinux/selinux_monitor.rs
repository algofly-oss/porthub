//! Monitor SELinux events via netlink.
//!
//! This example listens for SELinux kernel notifications:
//! - Enforcement mode changes (setenforce 0/1)
//! - Policy loads/reloads
//!
//! Run with: cargo run --example selinux_monitor
//!
//! To test, run in one terminal:
//!   sudo setenforce 0
//!   sudo setenforce 1
//!
//! Or reload the policy:
//!   sudo semodule -r some_module && sudo semodule -i some_module.pp

use nlink::netlink::{Connection, SELinux, selinux::SELinuxEvent};

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
    println!("Monitoring SELinux events...");
    println!("(Use 'setenforce 0/1' or reload policy to generate events)");
    println!();

    let conn = Connection::<SELinux>::new()?;

    loop {
        match conn.recv().await {
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
