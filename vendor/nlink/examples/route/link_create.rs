//! Create and manage virtual network interfaces.
//!
//! This example demonstrates how to create various types of virtual
//! network interfaces using the high-level Connection API.
//!
//! Run with: cargo run -p nlink --example route_link_create
//!
//! Requires root privileges.
//!
//! Examples:
//!   sudo cargo run -p nlink --example route_link_create -- dummy test0
//!   sudo cargo run -p nlink --example route_link_create -- veth veth0 veth1
//!   sudo cargo run -p nlink --example route_link_create -- bridge br0
//!   sudo cargo run -p nlink --example route_link_create -- del test0

use std::env;

use nlink::netlink::{
    Connection, Route,
    link::{BridgeLink, DummyLink, VethLink},
};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("dummy") => {
            let name = args.get(2).expect("usage: dummy <name>");
            create_dummy(&conn, name).await?;
        }
        Some("veth") => {
            let name = args.get(2).expect("usage: veth <name> <peer>");
            let peer = args.get(3).expect("usage: veth <name> <peer>");
            create_veth(&conn, name, peer).await?;
        }
        Some("bridge") => {
            let name = args.get(2).expect("usage: bridge <name>");
            create_bridge(&conn, name).await?;
        }
        Some("del") => {
            let name = args.get(2).expect("usage: del <name>");
            delete_link(&conn, name).await?;
        }
        Some("up") => {
            let name = args.get(2).expect("usage: up <name>");
            conn.set_link_up(name).await?;
            println!("Set {} up", name);
        }
        Some("down") => {
            let name = args.get(2).expect("usage: down <name>");
            conn.set_link_down(name).await?;
            println!("Set {} down", name);
        }
        Some("mtu") => {
            let name = args.get(2).expect("usage: mtu <name> <size>");
            let mtu: u32 = args
                .get(3)
                .expect("usage: mtu <name> <size>")
                .parse()
                .expect("invalid MTU");
            conn.set_link_mtu(name, mtu).await?;
            println!("Set {} mtu to {}", name, mtu);
        }
        _ => {
            println!("Usage:");
            println!("  dummy <name>         - Create dummy interface");
            println!("  veth <name> <peer>   - Create veth pair");
            println!("  bridge <name>        - Create bridge");
            println!("  del <name>           - Delete interface");
            println!("  up <name>            - Bring interface up");
            println!("  down <name>          - Bring interface down");
            println!("  mtu <name> <size>    - Set interface MTU");
        }
    }

    Ok(())
}

async fn create_dummy(conn: &Connection<Route>, name: &str) -> nlink::netlink::Result<()> {
    let link = DummyLink::new(name);

    conn.add_link(link).await?;
    println!("Created dummy interface: {}", name);

    // Show the created interface
    if let Some(created) = conn.get_link_by_name(name).await? {
        println!("  ifindex: {}", created.ifindex());
        println!("  mtu: {:?}", created.mtu());
        println!("  state: {}", if created.is_up() { "UP" } else { "DOWN" });
    }

    Ok(())
}

async fn create_veth(
    conn: &Connection<Route>,
    name: &str,
    peer: &str,
) -> nlink::netlink::Result<()> {
    let link = VethLink::new(name, peer);

    conn.add_link(link).await?;
    println!("Created veth pair: {} <-> {}", name, peer);

    // Show both interfaces
    if let (Some(link1), Some(link2)) = (
        conn.get_link_by_name(name).await?,
        conn.get_link_by_name(peer).await?,
    ) {
        println!(
            "  {}: ifindex={}, mtu={:?}",
            name,
            link1.ifindex(),
            link1.mtu()
        );
        println!(
            "  {}: ifindex={}, mtu={:?}",
            peer,
            link2.ifindex(),
            link2.mtu()
        );
    }

    Ok(())
}

async fn create_bridge(conn: &Connection<Route>, name: &str) -> nlink::netlink::Result<()> {
    let link = BridgeLink::new(name);

    conn.add_link(link).await?;
    println!("Created bridge: {}", name);

    if let Some(created) = conn.get_link_by_name(name).await? {
        println!("  ifindex: {}", created.ifindex());
    }

    println!();
    println!("To add interfaces to the bridge:");
    println!("  ip link set eth0 master {}", name);

    Ok(())
}

async fn delete_link(conn: &Connection<Route>, name: &str) -> nlink::netlink::Result<()> {
    match conn.del_link(name).await {
        Ok(()) => println!("Deleted interface: {}", name),
        Err(e) if e.is_not_found() => println!("Interface {} not found", name),
        Err(e) => return Err(e),
    }
    Ok(())
}
