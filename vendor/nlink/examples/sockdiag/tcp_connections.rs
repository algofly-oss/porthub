//! Query TCP connections with detailed information.
//!
//! This example demonstrates how to query TCP sockets with filters
//! and request extended information like TCP_INFO, memory stats, etc.
//!
//! Run with: cargo run -p nlink --features sockdiag --example sockdiag_tcp_connections

use nlink::{
    netlink::{Connection, SockDiag},
    sockdiag::{SocketFilter, TcpState},
};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<SockDiag>::new()?;

    // Query listening TCP sockets with TCP_INFO
    println!("=== Listening TCP Sockets ===");
    let filter = SocketFilter::tcp()
        .listening()
        .with_tcp_info()
        .with_mem_info()
        .build();

    let sockets = conn.query(&filter).await?;
    println!(
        "{:<25} {:<8} {:<8} {:<12}",
        "LOCAL", "RECV-Q", "SEND-Q", "UID"
    );
    println!("{}", "-".repeat(60));

    for sock in &sockets {
        if let nlink::sockdiag::SocketInfo::Inet(inet) = sock {
            println!(
                "{:<25} {:<8} {:<8} {:<12}",
                inet.local.to_string(),
                inet.recv_q,
                inet.send_q,
                inet.uid
            );
        }
    }
    println!();

    // Query established TCP connections with full details
    println!("=== Established TCP Connections ===");
    let filter = SocketFilter::tcp()
        .states(&[TcpState::Established])
        .with_tcp_info()
        .with_congestion()
        .build();

    let sockets = conn.query(&filter).await?;
    println!(
        "{:<22} {:<22} {:<10} {:<10}",
        "LOCAL", "REMOTE", "RTT(us)", "CWND"
    );
    println!("{}", "-".repeat(70));

    for sock in &sockets {
        if let nlink::sockdiag::SocketInfo::Inet(inet) = sock {
            let rtt = inet.tcp_info.as_ref().map(|ti| ti.rtt).unwrap_or(0);
            let cwnd = inet.tcp_info.as_ref().map(|ti| ti.snd_cwnd).unwrap_or(0);
            println!(
                "{:<22} {:<22} {:<10} {:<10}",
                inet.local.to_string(),
                inet.remote.to_string(),
                rtt,
                cwnd
            );

            // Show congestion control if available
            if let Some(cc) = &inet.congestion {
                println!("    Congestion: {}", cc);
            }
        }
    }
    println!();

    // Query IPv4 only
    println!("=== IPv4 TCP Sockets Only ===");
    let filter = SocketFilter::tcp().ipv4().all_states().build();
    let sockets = conn.query(&filter).await?;
    println!("Found {} IPv4 TCP sockets", sockets.len());

    // Query IPv6 only
    println!("\n=== IPv6 TCP Sockets Only ===");
    let filter = SocketFilter::tcp().ipv6().all_states().build();
    let sockets = conn.query(&filter).await?;
    println!("Found {} IPv6 TCP sockets", sockets.len());

    // Query by multiple states
    println!("\n=== TCP Sockets in TIME_WAIT or CLOSE_WAIT ===");
    let filter = SocketFilter::tcp()
        .states(&[TcpState::TimeWait, TcpState::CloseWait])
        .build();
    let sockets = conn.query(&filter).await?;
    println!("Found {} sockets in TIME_WAIT or CLOSE_WAIT", sockets.len());
    for sock in &sockets {
        if let nlink::sockdiag::SocketInfo::Inet(inet) = sock {
            println!(
                "  {} -> {} ({})",
                inet.local,
                inet.remote,
                inet.state.name()
            );
        }
    }

    Ok(())
}
