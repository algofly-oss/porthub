//! Monitor process lifecycle events.
//!
//! This example demonstrates how to receive process events (fork, exec, exit)
//! via the proc connector. Requires CAP_NET_ADMIN capability (typically root).
//!
//! Run with: sudo cargo run -p nlink --example connector_process_monitor
//!
//! Try running commands in another terminal to see events.

use nlink::netlink::{Connection, Connector, connector::ProcEvent};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Connector>::new().await?;

    println!("Monitoring process events (requires root)...");
    println!("Press Ctrl+C to exit.\n");

    loop {
        let event = conn.recv().await?;

        match event {
            ProcEvent::Fork {
                parent_pid,
                parent_tgid,
                child_pid,
                child_tgid,
            } => {
                if parent_pid == parent_tgid && child_pid == child_tgid {
                    // Main process fork
                    println!("FORK: {} -> {}", parent_pid, child_pid);
                } else {
                    // Thread creation
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
            ProcEvent::Uid {
                pid, ruid, euid, ..
            } => {
                println!("UID:  {} ruid={} euid={}", pid, ruid, euid);
            }
            ProcEvent::Gid {
                pid, rgid, egid, ..
            } => {
                println!("GID:  {} rgid={} egid={}", pid, rgid, egid);
            }
            ProcEvent::Sid { pid, .. } => {
                println!("SID:  {} (new session)", pid);
            }
            ProcEvent::Comm { pid, comm, .. } => {
                println!("COMM: {} -> \"{}\"", pid, comm);
            }
            ProcEvent::Ptrace {
                pid, tracer_pid, ..
            } => {
                if tracer_pid == 0 {
                    println!("PTRACE: {} detached", pid);
                } else {
                    println!("PTRACE: {} attached by {}", pid, tracer_pid);
                }
            }
            ProcEvent::Coredump { pid, .. } => {
                println!("COREDUMP: {}", pid);
            }
            ProcEvent::None => {
                // Acknowledgment, ignore
            }
            ProcEvent::Unknown { what, .. } => {
                println!("UNKNOWN: event type 0x{:08x}", what);
            }
            _ => {}
        }
    }
}
