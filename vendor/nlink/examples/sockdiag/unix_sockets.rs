//! Query Unix domain sockets.
//!
//! This example demonstrates how to query Unix sockets with various filters.
//!
//! Run with: cargo run -p nlink --features sockdiag --example sockdiag_unix_sockets

use nlink::{
    netlink::{Connection, SockDiag},
    sockdiag::SocketFilter,
};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<SockDiag>::new()?;

    // Query all Unix sockets
    println!("=== All Unix Sockets ===");
    let sockets = conn.query_unix_sockets().await?;
    println!(
        "{:<8} {:<10} {:<10} {:<10} PATH",
        "TYPE", "STATE", "INODE", "PEER"
    );
    println!("{}", "-".repeat(80));

    for sock in &sockets {
        let path = format_path(&sock.path, &sock.abstract_name);
        let peer = sock
            .peer_inode
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".into());
        println!(
            "{:<8} {:<10} {:<10} {:<10} {}",
            sock.socket_type.netid(),
            sock.state.name(),
            sock.inode,
            peer,
            path
        );
    }
    println!("Total: {} Unix sockets\n", sockets.len());

    // Query stream sockets only (SOCK_STREAM)
    println!("=== Stream Unix Sockets ===");
    let filter = SocketFilter::unix().stream().show_all().build();
    let sockets = conn.query(&filter).await?;
    let count = sockets
        .iter()
        .filter(|s| matches!(s, nlink::sockdiag::SocketInfo::Unix(_)))
        .count();
    println!("Found {} stream sockets\n", count);

    // Query listening Unix sockets
    println!("=== Listening Unix Sockets ===");
    let filter = SocketFilter::unix().listening().show_all().build();
    let sockets = conn.query(&filter).await?;
    println!("{:<8} {:<10} {:<8} PATH", "TYPE", "INODE", "PENDING");
    println!("{}", "-".repeat(70));

    for sock in &sockets {
        if let nlink::sockdiag::SocketInfo::Unix(unix) = sock {
            let path = format_path(&unix.path, &unix.abstract_name);
            let pending = unix
                .pending_connections
                .as_ref()
                .map(|v| v.len())
                .unwrap_or(0);
            println!(
                "{:<8} {:<10} {:<8} {}",
                unix.socket_type.netid(),
                unix.inode,
                pending,
                path
            );
        }
    }
    println!();

    // Query datagram sockets (SOCK_DGRAM)
    println!("=== Datagram Unix Sockets ===");
    let filter = SocketFilter::unix().dgram().build();
    let sockets = conn.query(&filter).await?;
    let count = sockets
        .iter()
        .filter(|s| matches!(s, nlink::sockdiag::SocketInfo::Unix(_)))
        .count();
    println!("Found {} datagram sockets\n", count);

    // Show sockets with memory info
    println!("=== Unix Sockets with Memory Info ===");
    let filter = SocketFilter::unix().show_meminfo().build();
    let sockets = conn.query(&filter).await?;
    println!(
        "{:<10} {:<10} {:<10} {:<10}",
        "INODE", "RMEM", "WMEM", "SNDBUF"
    );
    println!("{}", "-".repeat(45));

    let mut shown = 0;
    for sock in &sockets {
        if let nlink::sockdiag::SocketInfo::Unix(unix) = sock
            && let Some(mem) = &unix.mem_info
        {
            println!(
                "{:<10} {:<10} {:<10} {:<10}",
                unix.inode,
                mem.rmem_alloc,
                mem.wmem_alloc,
                // SKMEMINFO-only, so it is an Option now (#197): `-` means the
                // kernel was never asked, which is not the same as zero.
                mem.sndbuf
                    .map_or_else(|| "-".to_string(), |v| v.to_string())
            );
            shown += 1;
            if shown >= 10 {
                println!("... (showing first 10)");
                break;
            }
        }
    }

    Ok(())
}

fn format_path(path: &Option<String>, abstract_name: &Option<String>) -> String {
    if let Some(name) = abstract_name {
        format!("@{}", name)
    } else if let Some(p) = path {
        p.clone()
    } else {
        "-".to_string()
    }
}
