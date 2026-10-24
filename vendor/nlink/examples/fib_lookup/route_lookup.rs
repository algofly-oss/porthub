//! FIB route lookup example.
//!
//! This example demonstrates how to perform FIB (Forwarding Information Base)
//! lookups to determine how packets would be routed for specific destinations.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example fib_lookup_route_lookup
//! cargo run --example fib_lookup_route_lookup -- 8.8.8.8 1.1.1.1 10.0.0.1
//! ```
//!
//! # Note
//!
//! FIB lookups query the kernel's routing table to determine:
//! - Route type (unicast, local, blackhole, etc.)
//! - Prefix length of the matching route
//! - Routing table where the route was found

use std::{env, net::Ipv4Addr};

use nlink::netlink::{
    Connection, FibLookup,
    fib_lookup::{RouteScope, RouteType},
};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<FibLookup>::new()?;

    // Get addresses from command line or use defaults
    let args: Vec<String> = env::args().collect();
    let addresses: Vec<Ipv4Addr> = if args.len() > 1 {
        args[1..].iter().filter_map(|s| s.parse().ok()).collect()
    } else {
        vec![
            Ipv4Addr::new(8, 8, 8, 8),         // Google DNS (should be unicast)
            Ipv4Addr::new(127, 0, 0, 1),       // Localhost (should be local)
            Ipv4Addr::new(10, 0, 0, 1),        // Private network
            Ipv4Addr::new(192, 168, 1, 1),     // Common gateway
            Ipv4Addr::new(224, 0, 0, 1),       // Multicast
            Ipv4Addr::new(255, 255, 255, 255), // Broadcast
        ]
    };

    println!("FIB Route Lookups");
    println!("=================\n");

    for addr in addresses {
        match conn.lookup(addr).await {
            Ok(result) => {
                println!("Address: {}", result.addr);
                println!(
                    "  Type: {} ({})",
                    route_type_name(&result.route_type),
                    result.route_type.number()
                );
                println!(
                    "  Scope: {} ({})",
                    route_scope_name(&result.scope),
                    result.scope.number()
                );
                println!("  Table: {}", result.table_id);
                println!("  Prefix: /{}", result.prefix_len);

                if result.error != 0 {
                    println!("  Error: {}", result.error);
                }

                // Interpretation
                print!("  -> ");
                if result.is_local() {
                    println!("Local address (packets delivered locally)");
                } else if result.is_unicast() {
                    println!("Routable (packets forwarded via gateway)");
                } else if result.is_blackhole() {
                    println!("Blackhole (packets silently dropped)");
                } else if result.is_unreachable() {
                    println!("Unreachable (ICMP unreachable sent)");
                } else {
                    println!("{:?}", result.route_type);
                }

                println!();
            }
            Err(e) => {
                println!("Address: {}", addr);
                println!("  Error: {}\n", e);
            }
        }
    }

    // Demonstrate lookup in specific table
    println!("--- Lookup in specific table ---\n");
    let addr = Ipv4Addr::new(8, 8, 8, 8);

    // Table 254 is the "main" table
    match conn.lookup_in_table(addr, 254).await {
        Ok(result) => {
            println!("Lookup {} in table 254 (main):", addr);
            println!(
                "  Result: {} via table {} (/{}) ",
                route_type_name(&result.route_type),
                result.table_id,
                result.prefix_len
            );
        }
        Err(e) => {
            println!("Lookup {} in table 254: {}", addr, e);
        }
    }

    Ok(())
}

fn route_type_name(rt: &RouteType) -> &'static str {
    match rt {
        RouteType::Unspec => "unspec",
        RouteType::Unicast => "unicast",
        RouteType::Local => "local",
        RouteType::Broadcast => "broadcast",
        RouteType::Anycast => "anycast",
        RouteType::Multicast => "multicast",
        RouteType::Blackhole => "blackhole",
        RouteType::Unreachable => "unreachable",
        RouteType::Prohibit => "prohibit",
        RouteType::Throw => "throw",
        RouteType::Nat => "nat",
        RouteType::XResolve => "xresolve",
        RouteType::Unknown(_) => "unknown",
        _ => "unknown",
    }
}

fn route_scope_name(scope: &RouteScope) -> &'static str {
    match scope {
        RouteScope::Universe => "universe",
        RouteScope::Site => "site",
        RouteScope::Link => "link",
        RouteScope::Host => "host",
        RouteScope::Nowhere => "nowhere",
        RouteScope::Unknown(_) => "unknown",
        _ => "unknown",
    }
}
