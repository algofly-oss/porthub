//! List and manage IP addresses.
//!
//! This example demonstrates how to query, add, and delete IP addresses
//! using the high-level Connection API.
//!
//! Run with: cargo run -p nlink --example route_addresses
//!
//! To add/delete addresses (requires root):
//!   cargo run -p nlink --example route_addresses -- add 10.0.0.1/24 eth0
//!   cargo run -p nlink --example route_addresses -- del 10.0.0.1/24 eth0

use std::{env, net::IpAddr};

use nlink::netlink::{
    Connection, Route,
    addr::{Ipv4Address, Ipv6Address},
    types::addr::Scope,
};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("add") => {
            let (addr, prefix) =
                parse_addr_prefix(args.get(2).expect("usage: add <ip/prefix> <dev>"))?;
            let dev = args.get(3).expect("usage: add <ip/prefix> <dev>");

            match addr {
                IpAddr::V4(ip) => {
                    let config = Ipv4Address::new(dev, ip, prefix);
                    conn.add_address(config).await?;
                }
                IpAddr::V6(ip) => {
                    let config = Ipv6Address::new(dev, ip, prefix);
                    conn.add_address(config).await?;
                }
            }
            println!("Added {}/{} to {}", addr, prefix, dev);
        }
        Some("del") => {
            let (addr, prefix) =
                parse_addr_prefix(args.get(2).expect("usage: del <ip/prefix> <dev>"))?;
            let dev = args.get(3).expect("usage: del <ip/prefix> <dev>");

            conn.del_address(dev, addr, prefix).await?;
            println!("Deleted {}/{} from {}", addr, prefix, dev);
        }
        _ => {
            // List all addresses
            list_addresses(&conn).await?;
        }
    }

    Ok(())
}

async fn list_addresses(conn: &Connection<Route>) -> nlink::netlink::Result<()> {
    let addrs = conn.get_addresses().await?;

    // Use the get_interface_names() helper to build ifindex -> name map
    let names = conn.get_interface_names().await?;

    println!(
        "{:<4} {:<16} {:<8} {:<40}",
        "IDX", "INTERFACE", "FAMILY", "ADDRESS"
    );
    println!("{}", "-".repeat(72));

    for addr in addrs {
        // addr.ifindex() returns u32, names keys are i32
        let ifname = names
            .get(&(addr.ifindex()))
            .map(|s| s.as_str())
            .unwrap_or("?");

        let family = if addr.is_ipv4() { "inet" } else { "inet6" };

        let ip = addr
            .address()
            .or(addr.local())
            .map(|a| format!("{}/{}", a, addr.prefix_len()))
            .unwrap_or_else(|| "?".into());

        let scope = match addr.scope() {
            Scope::Universe => "",
            Scope::Link => " link",
            Scope::Host => " host",
            Scope::Site => " site",
            Scope::Nowhere => " nowhere",
            _ => "",
        };

        println!(
            "{:<4} {:<16} {:<8} {}{}",
            addr.ifindex(),
            ifname,
            family,
            ip,
            scope
        );
    }

    Ok(())
}

fn parse_addr_prefix(s: &str) -> nlink::netlink::Result<(IpAddr, u8)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err(nlink::netlink::Error::invalid_message(
            "expected format: ip/prefix",
        ));
    }

    let addr: IpAddr = parts[0]
        .parse()
        .map_err(|e| nlink::netlink::Error::invalid_message(format!("invalid IP: {}", e)))?;

    let prefix: u8 = parts[1]
        .parse()
        .map_err(|e| nlink::netlink::Error::invalid_message(format!("invalid prefix: {}", e)))?;

    Ok((addr, prefix))
}
