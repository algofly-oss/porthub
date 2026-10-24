//! Monitor events in a specific network namespace.
//!
//! This example demonstrates namespace-aware event monitoring
//! using Connection with namespace support.
//!
//! Run with: cargo run -p nlink --example events_monitor_namespace -- myns
//!
//! First create a namespace: sudo ip netns add myns
//! Then make changes: sudo ip netns exec myns ip link add dummy0 type dummy

use std::{env, path::PathBuf};

use nlink::netlink::{Connection, NetworkEvent, Route, RtnetlinkGroup};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let args: Vec<String> = env::args().collect();

    let conn = match args.get(1).map(|s| s.as_str()) {
        Some("--pid") => {
            let pid: u32 = args
                .get(2)
                .expect("usage: --pid <pid>")
                .parse()
                .expect("invalid PID");
            let path = PathBuf::from(format!("/proc/{}/ns/net", pid));
            println!("Monitoring events in namespace of PID {}...", pid);
            Connection::<Route>::new_in(path.as_path())?
        }
        Some("--path") => {
            let path = args.get(2).expect("usage: --path <path>");
            println!("Monitoring events in namespace at {}...", path);
            Connection::<Route>::new_in(std::path::Path::new(path))?
        }
        Some(ns_name) => {
            println!("Monitoring events in namespace '{}'...", ns_name);
            Connection::<Route>::new_in(ns_name)?
        }
        None => {
            println!("Monitoring events in default namespace...");
            println!();
            println!("Tip: Specify a namespace:");
            println!("  --pid <pid>   - Monitor by process ID");
            println!("  --path <path> - Monitor by namespace path");
            println!("  <name>        - Monitor named namespace");
            Connection::<Route>::new()?
        }
    };

    conn.subscribe(&[
        RtnetlinkGroup::Link,
        RtnetlinkGroup::Ipv4Addr,
        RtnetlinkGroup::Ipv6Addr,
        RtnetlinkGroup::Ipv4Route,
        RtnetlinkGroup::Ipv6Route,
    ])?;

    println!("{}", "-".repeat(50));

    let mut events = conn.events().await;

    while let Some(result) = events.next().await {
        let event = result?;
        match event {
            NetworkEvent::NewLink(link) => {
                println!(
                    "[LINK+] {} idx={} mtu={:?}",
                    link.name_or("?"),
                    link.ifindex(),
                    link.mtu()
                );
            }
            NetworkEvent::DelLink(link) => {
                println!("[LINK-] {} idx={}", link.name_or("?"), link.ifindex());
            }
            NetworkEvent::NewAddress(addr) => {
                let ip = addr
                    .address()
                    .or(addr.local())
                    .map(|a| format!("{}/{}", a, addr.prefix_len()))
                    .unwrap_or_else(|| "?".into());
                println!("[ADDR+] {} on idx={}", ip, addr.ifindex());
            }
            NetworkEvent::DelAddress(addr) => {
                let ip = addr
                    .address()
                    .or(addr.local())
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "?".into());
                println!("[ADDR-] {} on idx={}", ip, addr.ifindex());
            }
            NetworkEvent::NewRoute(route) => {
                let dst = route
                    .destination()
                    .map(|a| format!("{}/{}", a, route.dst_len()))
                    .unwrap_or_else(|| "default".into());
                println!("[ROUTE+] {}", dst);
            }
            NetworkEvent::DelRoute(route) => {
                let dst = route
                    .destination()
                    .map(|a| format!("{}/{}", a, route.dst_len()))
                    .unwrap_or_else(|| "default".into());
                println!("[ROUTE-] {}", dst);
            }
            _ => {}
        }
    }

    Ok(())
}
