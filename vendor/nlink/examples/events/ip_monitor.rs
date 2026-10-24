//! Monitor network events similar to `ip monitor`.
//!
//! This example demonstrates monitoring link, address, route, and neighbor
//! changes in a format similar to the iproute2 `ip monitor` command.
//!
//! Run with: cargo run -p nlink --example events_ip_monitor
//!
//! Then in another terminal, try:
//!   sudo ip link add dummy0 type dummy
//!   sudo ip addr add 10.0.0.1/24 dev dummy0
//!   sudo ip link set dummy0 up
//!   sudo ip route add 192.168.100.0/24 dev dummy0
//!   sudo ip link del dummy0

use nlink::netlink::{Connection, NetworkEvent, Route, RtnetlinkGroup, types::link::iff};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    println!("Monitoring network events (Ctrl+C to stop)...");
    println!("Try: sudo ip link add dummy0 type dummy\n");

    let conn = Connection::<Route>::new()?;

    // Subscribe to all IP-related events (like `ip monitor all`)
    conn.subscribe(&[
        RtnetlinkGroup::Link,
        RtnetlinkGroup::Ipv4Addr,
        RtnetlinkGroup::Ipv6Addr,
        RtnetlinkGroup::Ipv4Route,
        RtnetlinkGroup::Ipv6Route,
        RtnetlinkGroup::Neigh,
    ])?;

    let mut events = conn.events().await;

    while let Some(result) = events.next().await {
        let event = result?;
        let action = event.action();

        match event {
            // Link events
            NetworkEvent::NewLink(link) | NetworkEvent::DelLink(link) => {
                let flags = format_link_flags(link.flags());
                let state = if link.is_up() { "UP" } else { "DOWN" };

                println!(
                    "{}: {}: <{}> mtu {} state {}",
                    link.ifindex(),
                    link.name_or("?"),
                    flags,
                    link.mtu().unwrap_or(0),
                    state
                );

                // Show link type if available
                if let Some(info) = link.link_info()
                    && let Some(kind) = info.kind()
                {
                    println!("    link/{}", kind);
                }

                // Show MAC address if available
                if let Some(mac) = link.address()
                    && mac.len() == 6
                {
                    println!(
                        "    link/ether {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                    );
                }

                if action == "del" {
                    println!("Deleted");
                }
            }

            // Address events
            NetworkEvent::NewAddress(addr) | NetworkEvent::DelAddress(addr) => {
                let ip = addr
                    .address()
                    .or(addr.local())
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "?".into());

                let scope = addr.scope().name();
                let label = addr.label().unwrap_or("");

                if action == "new" {
                    println!(
                        "{}: {} {}/{} scope {} {}",
                        addr.ifindex(),
                        if addr.family() == 2 { "inet" } else { "inet6" },
                        ip,
                        addr.prefix_len(),
                        scope,
                        label
                    );
                } else {
                    println!(
                        "Deleted {}: {} {}/{}",
                        addr.ifindex(),
                        if addr.family() == 2 { "inet" } else { "inet6" },
                        ip,
                        addr.prefix_len()
                    );
                }
            }

            // Route events
            NetworkEvent::NewRoute(route) | NetworkEvent::DelRoute(route) => {
                let dst = route
                    .destination()
                    .map(|a| format!("{}/{}", a, route.dst_len()))
                    .unwrap_or_else(|| "default".into());

                let via = route
                    .gateway()
                    .map(|a| format!(" via {}", a))
                    .unwrap_or_default();

                let dev = route
                    .oif()
                    .map(|idx| format!(" dev if{}", idx))
                    .unwrap_or_default();

                let proto = route.protocol().name();
                let scope = route.scope().name();

                if action == "new" {
                    println!("{}{}{} proto {} scope {}", dst, via, dev, proto, scope);
                } else {
                    println!("Deleted {}{}{}", dst, via, dev);
                }
            }

            // Neighbor events
            NetworkEvent::NewNeighbor(neigh) | NetworkEvent::DelNeighbor(neigh) => {
                let ip = neigh
                    .destination()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "?".into());

                let lladdr = neigh
                    .lladdr()
                    .map(|m| {
                        format!(
                            " lladdr {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            m[0], m[1], m[2], m[3], m[4], m[5]
                        )
                    })
                    .unwrap_or_default();

                let state = neigh.state().name();

                if action == "new" {
                    println!("{} dev if{}{} {}", ip, neigh.ifindex(), lladdr, state);
                } else {
                    println!("Deleted {} dev if{}", ip, neigh.ifindex());
                }
            }

            // TC events are not shown by ip monitor
            _ => {}
        }
    }

    Ok(())
}

fn format_link_flags(flags: u32) -> String {
    let mut parts = Vec::new();

    if flags & iff::UP != 0 {
        parts.push("UP");
    }
    if flags & iff::BROADCAST != 0 {
        parts.push("BROADCAST");
    }
    if flags & iff::LOOPBACK != 0 {
        parts.push("LOOPBACK");
    }
    if flags & iff::POINTOPOINT != 0 {
        parts.push("POINTOPOINT");
    }
    if flags & iff::MULTICAST != 0 {
        parts.push("MULTICAST");
    }
    if flags & iff::LOWER_UP != 0 {
        parts.push("LOWER_UP");
    }

    parts.join(",")
}
