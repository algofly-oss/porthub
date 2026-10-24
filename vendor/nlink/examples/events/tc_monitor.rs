//! Monitor traffic control events.
//!
//! This example demonstrates how to monitor TC (qdisc, class, filter) changes
//! in real-time, similar to `tc monitor`.
//!
//! Run with: cargo run -p nlink --example events_tc_monitor
//!
//! Then in another terminal, try:
//!   sudo tc qdisc add dev lo root netem delay 100ms
//!   sudo tc qdisc change dev lo root netem delay 50ms
//!   sudo tc qdisc del dev lo root

use nlink::netlink::{Connection, NetworkEvent, Route, RtnetlinkGroup};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    println!("Monitoring TC events (Ctrl+C to stop)...");
    println!("Try: sudo tc qdisc add dev lo root netem delay 100ms\n");

    let conn = Connection::<Route>::new()?;
    conn.subscribe(&[RtnetlinkGroup::Tc])?;

    let mut events = conn.events().await;

    while let Some(result) = events.next().await {
        let event = result?;

        // Get action string
        let action = event.action();

        match event {
            NetworkEvent::NewQdisc(tc) | NetworkEvent::DelQdisc(tc) => {
                let parent = format_parent(tc.parent());
                let handle = tc.handle().to_string();
                println!(
                    "[qdisc {}] dev {} parent {} handle {} {}",
                    action,
                    tc.name_or(&format!("if{}", tc.ifindex())),
                    parent,
                    handle,
                    tc.kind().unwrap_or("?")
                );

                // Show qdisc-specific options if available
                if let Some(opts) = tc.options() {
                    use nlink::netlink::tc_options::QdiscOptions;
                    match opts {
                        QdiscOptions::Netem(netem) => {
                            if let Some(delay) = netem.delay() {
                                print!("    delay {:?}", delay);
                                if let Some(jitter) = netem.jitter() {
                                    print!(" {:?}", jitter);
                                }
                                println!();
                            }
                            if let Some(loss) = netem.loss() {
                                println!("    loss {:.2}%", loss);
                            }
                        }
                        QdiscOptions::FqCodel(fq) => {
                            println!(
                                "    limit {} target {}us interval {}us",
                                fq.limit, fq.target_us, fq.interval_us
                            );
                        }
                        QdiscOptions::Htb(htb) => {
                            println!("    default {:x}", htb.default_class);
                        }
                        _ => {}
                    }
                }
            }

            NetworkEvent::NewClass(tc) | NetworkEvent::DelClass(tc) => {
                let parent = format_parent(tc.parent());
                let handle = tc.handle().to_string();
                println!(
                    "[class {}] dev {} parent {} classid {} {}",
                    action,
                    tc.name_or(&format!("if{}", tc.ifindex())),
                    parent,
                    handle,
                    tc.kind().unwrap_or("?")
                );
            }

            NetworkEvent::NewFilter(tc) | NetworkEvent::DelFilter(tc) => {
                let parent = format_parent(tc.parent());
                println!(
                    "[filter {}] dev {} parent {} pref {} protocol {:x} {}",
                    action,
                    tc.name_or(&format!("if{}", tc.ifindex())),
                    parent,
                    tc.info() >> 16,    // priority
                    tc.info() & 0xFFFF, // protocol
                    tc.kind().unwrap_or("?")
                );
            }

            NetworkEvent::NewAction(tc) | NetworkEvent::DelAction(tc) => {
                println!("[action {}] {}", action, tc.kind().unwrap_or("?"));
            }

            _ => {}
        }
    }

    Ok(())
}

fn format_parent(parent: nlink::TcHandle) -> String {
    if parent.is_root() {
        "root".to_string()
    } else if parent.is_ingress() {
        "ingress".to_string()
    } else {
        parent.to_string()
    }
}
