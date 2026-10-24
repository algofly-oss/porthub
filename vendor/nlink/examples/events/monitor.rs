//! Monitor network events using the Stream API.
//!
//! This example demonstrates how to use Connection<Route>::events()
//! to monitor network changes in real-time.
//!
//! Run with: cargo run -p nlink --example events_monitor
//!
//! Then in another terminal, try:
//!   ip link add dummy test0 type dummy
//!   ip addr add 10.0.0.1/24 dev test0
//!   ip link set test0 up
//!   ip link del test0
//!   ip rule add from 10.9.9.9 lookup 100     # policy-rule event (0.24)
//!   ip nexthop add id 7 dev test0            # nexthop event (0.24)

use nlink::netlink::{Connection, NetworkEvent, Route};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    println!("Monitoring network events (Ctrl+C to stop)...\n");

    let conn = Connection::<Route>::new()?;
    // subscribe_all() joins every typed-event group — since 0.24 that
    // includes policy rules, nexthop objects, namespace IDs and the
    // bridge multicast DB (#165). Use subscribe(&[...]) to narrow.
    conn.subscribe_all()?;

    let mut events = conn.events().await;

    while let Some(result) = events.next().await {
        let event = result?;
        match event {
            // Link events
            NetworkEvent::NewLink(link) => {
                println!(
                    "[LINK+] {} (index={}, mtu={:?}, up={})",
                    link.name_or("?"),
                    link.ifindex(),
                    link.mtu(),
                    link.is_up()
                );
            }
            NetworkEvent::DelLink(link) => {
                println!("[LINK-] {} (index={})", link.name_or("?"), link.ifindex());
            }

            // Address events
            NetworkEvent::NewAddress(addr) => {
                let ip = addr
                    .address()
                    .or(addr.local())
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "?".into());
                println!(
                    "[ADDR+] {}/{} on ifindex={}",
                    ip,
                    addr.prefix_len(),
                    addr.ifindex()
                );
            }
            NetworkEvent::DelAddress(addr) => {
                let ip = addr
                    .address()
                    .or(addr.local())
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "?".into());
                println!(
                    "[ADDR-] {}/{} on ifindex={}",
                    ip,
                    addr.prefix_len(),
                    addr.ifindex()
                );
            }

            // Route events
            NetworkEvent::NewRoute(route) => {
                let dst = route
                    .destination()
                    .map(|a| format!("{}/{}", a, route.dst_len()))
                    .unwrap_or_else(|| "default".into());
                let via = route
                    .gateway()
                    .map(|a| format!(" via {}", a))
                    .unwrap_or_default();
                println!("[ROUTE+] {}{}", dst, via);
            }
            NetworkEvent::DelRoute(route) => {
                let dst = route
                    .destination()
                    .map(|a| format!("{}/{}", a, route.dst_len()))
                    .unwrap_or_else(|| "default".into());
                println!("[ROUTE-] {}", dst);
            }

            // Neighbor events
            NetworkEvent::NewNeighbor(neigh) => {
                let ip = neigh
                    .destination()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "?".into());
                let mac = neigh
                    .lladdr()
                    .map(|m| {
                        format!(
                            " lladdr {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            m[0], m[1], m[2], m[3], m[4], m[5]
                        )
                    })
                    .unwrap_or_default();
                println!("[NEIGH+] {}{} on ifindex={}", ip, mac, neigh.ifindex());
            }
            NetworkEvent::DelNeighbor(neigh) => {
                let ip = neigh
                    .destination()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "?".into());
                println!("[NEIGH-] {} on ifindex={}", ip, neigh.ifindex());
            }

            // TC events
            NetworkEvent::NewQdisc(tc) => {
                println!(
                    "[QDISC+] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }
            NetworkEvent::DelQdisc(tc) => {
                println!(
                    "[QDISC-] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }
            NetworkEvent::NewClass(tc) => {
                println!(
                    "[CLASS+] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }
            NetworkEvent::DelClass(tc) => {
                println!(
                    "[CLASS-] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }

            // Filter and action events
            NetworkEvent::NewFilter(tc) => {
                println!(
                    "[FILTER+] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }
            NetworkEvent::DelFilter(tc) => {
                println!(
                    "[FILTER-] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }
            NetworkEvent::NewAction(tc) => {
                println!(
                    "[ACTION+] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }
            NetworkEvent::DelAction(tc) => {
                println!(
                    "[ACTION-] {} on ifindex={}",
                    tc.kind().unwrap_or("?"),
                    tc.ifindex()
                );
            }

            // FDB events (bridge forwarding database)
            NetworkEvent::NewFdb(fdb) => {
                println!(
                    "[FDB+] {} on ifindex={} vlan={:?}",
                    fdb.mac_str(),
                    fdb.ifindex(),
                    fdb.vlan()
                );
            }
            NetworkEvent::DelFdb(fdb) => {
                println!(
                    "[FDB-] {} on ifindex={} vlan={:?}",
                    fdb.mac_str(),
                    fdb.ifindex(),
                    fdb.vlan()
                );
            }

            // Policy-routing rule events (0.24, #165)
            NetworkEvent::NewRule(rule) => {
                println!(
                    "[RULE+] prio={} table={} src={:?}",
                    rule.priority(),
                    rule.table_id(),
                    rule.source()
                );
            }
            NetworkEvent::DelRule(rule) => {
                println!("[RULE-] prio={} table={}", rule.priority(), rule.table_id());
            }

            // Nexthop-object events (0.24, #165)
            NetworkEvent::NewNexthop(nh) => {
                println!(
                    "[NEXTHOP+] id={} gateway={:?} oif={:?}",
                    nh.id(),
                    nh.gateway(),
                    nh.ifindex()
                );
            }
            NetworkEvent::DelNexthop(nh) => {
                println!("[NEXTHOP-] id={}", nh.id());
            }

            // Network-namespace ID events (0.24, #165)
            NetworkEvent::NewNsId(ns) => {
                println!("[NSID+] nsid={:?} pid={:?}", ns.nsid(), ns.pid());
            }
            NetworkEvent::DelNsId(ns) => {
                println!("[NSID-] nsid={:?}", ns.nsid());
            }

            // Bridge multicast-database events (0.24, #165)
            NetworkEvent::NewMdb(mdb) => {
                println!(
                    "[MDB+] group={} port_ifindex={} vid={}",
                    mdb.group, mdb.port_ifindex, mdb.vid
                );
            }
            NetworkEvent::DelMdb(mdb) => {
                println!(
                    "[MDB-] group={} port_ifindex={} vid={}",
                    mdb.group, mdb.port_ifindex, mdb.vid
                );
            }

            _ => {}
        }
    }

    Ok(())
}
