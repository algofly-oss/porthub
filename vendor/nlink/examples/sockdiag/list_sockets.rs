//! List all sockets (similar to `ss -a`).
//!
//! This example demonstrates how to query TCP, UDP, and Unix sockets
//! using the Connection<SockDiag> API.
//!
//! Run with: cargo run -p nlink --features sockdiag --example sockdiag_list_sockets

use nlink::{
    netlink::{Connection, SockDiag},
    sockdiag::SocketFilter,
};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<SockDiag>::new()?;

    // Query TCP sockets
    println!("=== TCP Sockets ===");
    let tcp_sockets = conn.query_tcp().await?;
    println!(
        "{:<12} {:<25} {:<25} {:<12}",
        "STATE", "LOCAL", "REMOTE", "UID"
    );
    for sock in &tcp_sockets {
        println!(
            "{:<12} {:<25} {:<25} {:<12}",
            sock.state.name(),
            sock.local.to_string(),
            sock.remote.to_string(),
            sock.uid
        );
    }
    println!("Total: {} TCP sockets\n", tcp_sockets.len());

    // Query UDP sockets
    println!("=== UDP Sockets ===");
    let udp_sockets = conn.query_udp().await?;
    println!(
        "{:<12} {:<25} {:<25} {:<12}",
        "STATE", "LOCAL", "REMOTE", "UID"
    );
    for sock in &udp_sockets {
        println!(
            "{:<12} {:<25} {:<25} {:<12}",
            sock.state.name(),
            sock.local.to_string(),
            sock.remote.to_string(),
            sock.uid
        );
    }
    println!("Total: {} UDP sockets\n", udp_sockets.len());

    // Query Unix sockets
    println!("=== Unix Sockets ===");
    let unix_sockets = conn.query_unix_sockets().await?;
    println!("{:<8} {:<10} {:<10} PATH", "TYPE", "STATE", "INODE");
    for sock in &unix_sockets {
        let path = sock
            .path
            .as_deref()
            .or(sock.abstract_name.as_deref())
            .unwrap_or("-");
        let path_display = if sock.abstract_name.is_some() {
            format!("@{}", path)
        } else {
            path.to_string()
        };
        println!(
            "{:<8} {:<10} {:<10} {}",
            sock.socket_type.netid(),
            sock.state.name(),
            sock.inode,
            path_display
        );
    }
    println!("Total: {} Unix sockets\n", unix_sockets.len());

    // Using the generic query with SocketFilter
    println!("=== All Sockets via SocketFilter ===");
    let filter = SocketFilter::tcp().all_states().build();
    let sockets = conn.query(&filter).await?;
    println!("TCP sockets via filter: {}", sockets.len());

    let filter = SocketFilter::udp().build();
    let sockets = conn.query(&filter).await?;
    println!("UDP sockets via filter: {}", sockets.len());

    let filter = SocketFilter::unix().build();
    let sockets = conn.query(&filter).await?;
    println!("Unix sockets via filter: {}", sockets.len());

    Ok(())
}
