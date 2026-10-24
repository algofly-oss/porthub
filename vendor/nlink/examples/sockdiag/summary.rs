//! Socket summary statistics.
//!
//! Demonstrates querying aggregated socket counts similar to `ss -s`.
//!
//! Run with: cargo run -p nlink --example sockdiag_summary --features sockdiag

use nlink::netlink::{Connection, SockDiag};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<SockDiag>::new()?;
    let summary = conn.socket_summary().await?;

    println!("{}", summary);

    // Access individual counts
    println!("\nDetailed TCP breakdown:");
    println!("  Established: {}", summary.tcp.established);
    println!("  SYN-SENT:    {}", summary.tcp.syn_sent);
    println!("  SYN-RECV:    {}", summary.tcp.syn_recv);
    println!("  FIN-WAIT-1:  {}", summary.tcp.fin_wait1);
    println!("  FIN-WAIT-2:  {}", summary.tcp.fin_wait2);
    println!("  TIME-WAIT:   {}", summary.tcp.time_wait);
    println!("  CLOSE-WAIT:  {}", summary.tcp.close_wait);
    println!("  LISTEN:      {}", summary.tcp.listen);
    println!("  CLOSING:     {}", summary.tcp.closing);

    Ok(())
}
