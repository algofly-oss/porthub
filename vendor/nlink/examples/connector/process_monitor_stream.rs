//! Monitor process lifecycle events using the Stream API.
//!
//! This example demonstrates how to use the `EventSource` stream-based API
//! for receiving process events. Requires CAP_NET_ADMIN capability (typically root).
//!
//! Run with: sudo cargo run -p nlink --example connector_process_monitor_stream
//!
//! Try running commands in another terminal to see events.

use nlink::netlink::{Connection, Connector, connector::ProcEvent};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Connector>::new().await?;

    println!("Monitoring process events using Stream API (requires root)...");
    println!("Press Ctrl+C to exit.\n");

    // Use events() to get a borrowed stream
    let mut events = conn.events().await;

    while let Some(result) = events.next().await {
        let event = result?;

        match event {
            ProcEvent::Fork {
                parent_pid,
                parent_tgid,
                child_pid,
                child_tgid,
            } => {
                if parent_pid == parent_tgid && child_pid == child_tgid {
                    println!("FORK: {} -> {}", parent_pid, child_pid);
                } else {
                    println!(
                        "FORK: {} (tgid {}) -> {} (tgid {})",
                        parent_pid, parent_tgid, child_pid, child_tgid
                    );
                }
            }
            ProcEvent::Exec { pid, tgid } => {
                if pid == tgid {
                    println!("EXEC: {}", pid);
                } else {
                    println!("EXEC: {} (tgid {})", pid, tgid);
                }
            }
            ProcEvent::Exit {
                pid,
                tgid,
                exit_code,
                ..
            } => {
                if pid == tgid {
                    println!("EXIT: {} (code {})", pid, exit_code);
                } else {
                    println!("EXIT: {} (tgid {}) (code {})", pid, tgid, exit_code);
                }
            }
            ProcEvent::Comm { pid, comm, .. } => {
                println!("COMM: {} -> \"{}\"", pid, comm);
            }
            ProcEvent::None => {}
            _ => {}
        }
    }

    Ok(())
}
