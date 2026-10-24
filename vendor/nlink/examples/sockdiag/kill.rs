//! Destroy TCP sockets matching a filter.
//!
//! Demonstrates using SOCK_DESTROY to force-close sockets,
//! similar to `ss -K`.
//!
//! Run with: cargo run -p nlink --example sockdiag_kill --features sockdiag
//!
//! Requires root (CAP_NET_ADMIN).
//!
//! Examples:
//!   sudo cargo run -p nlink --example sockdiag_kill --features sockdiag -- 8080

use std::env;

use nlink::netlink::{Connection, SockDiag};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let args: Vec<String> = env::args().collect();
    let port: u16 = match args.get(1) {
        Some(p) => p.parse().expect("invalid port number"),
        None => {
            println!("Usage: sockdiag_kill <port>");
            println!("Destroys all TCP sockets with the given remote port.");
            return Ok(());
        }
    };

    let conn = Connection::<SockDiag>::new()?;

    // Find matching sockets
    let sockets = conn.query_tcp().await?;
    let mut destroyed = 0;

    for sock in &sockets {
        if sock.remote.port() == port {
            match conn.destroy_tcp_socket(sock).await {
                Ok(()) => {
                    println!("Destroyed: {} -> {}", sock.local, sock.remote);
                    destroyed += 1;
                }
                Err(e) => eprintln!("Failed to destroy {} -> {}: {}", sock.local, sock.remote, e),
            }
        }
    }

    println!(
        "\nDestroyed {} socket(s) with remote port {}",
        destroyed, port
    );

    Ok(())
}
