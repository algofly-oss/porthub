//! Create and manage bonded (link aggregation) interfaces.
//!
//! Demonstrates creating bonds with different modes, adding
//! slaves, and querying bond status.
//!
//! Run with: cargo run -p nlink --example route_bond
//!
//! Requires root privileges.
//!
//! Examples:
//!   sudo cargo run -p nlink --example route_bond -- create bond0 802.3ad
//!   sudo cargo run -p nlink --example route_bond -- add-slave bond0 eth0
//!   sudo cargo run -p nlink --example route_bond -- show bond0
//!   sudo cargo run -p nlink --example route_bond -- del bond0

use std::env;

use nlink::netlink::{
    Connection, Route,
    link::{BondLink, BondMode},
};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("create") => {
            let name = args.get(2).expect("usage: create <name> [mode]");
            let mode = match args.get(3).map(|s| s.as_str()) {
                Some("balance-rr") | Some("0") => BondMode::BalanceRr,
                Some("active-backup") | Some("1") => BondMode::ActiveBackup,
                Some("balance-xor") | Some("2") => BondMode::BalanceXor,
                Some("broadcast") | Some("3") => BondMode::Broadcast,
                Some("802.3ad") | Some("4") => BondMode::Lacp,
                Some("balance-tlb") | Some("5") => BondMode::BalanceTlb,
                Some("balance-alb") | Some("6") => BondMode::BalanceAlb,
                _ => BondMode::BalanceRr,
            };

            let bond = BondLink::new(name).mode(mode).miimon(100);
            conn.add_link(bond).await?;
            println!("Created bond {} with mode {:?}", name, mode);
        }
        Some("add-slave") => {
            let bond = args.get(2).expect("usage: add-slave <bond> <iface>");
            let iface = args.get(3).expect("usage: add-slave <bond> <iface>");
            // enslave() handles the required down/master/up sequence automatically
            conn.enslave(iface.as_str(), bond.as_str()).await?;
            println!("Added {} as slave of {}", iface, bond);
        }
        Some("show") => {
            let name = args.get(2).expect("usage: show <name>");
            match conn.get_link_by_name(name).await? {
                Some(link) => {
                    println!(
                        "{}: mtu={:?} state={}",
                        name,
                        link.mtu(),
                        if link.is_up() { "UP" } else { "DOWN" }
                    );
                }
                None => println!("Bond {} not found", name),
            }
        }
        Some("del") => {
            let name = args.get(2).expect("usage: del <name>");
            conn.del_link(name).await?;
            println!("Deleted bond {}", name);
        }
        _ => {
            println!("Usage:");
            println!(
                "  create <name> [mode]       - Create bond (modes: balance-rr, active-backup, balance-xor, broadcast, 802.3ad, balance-tlb, balance-alb)"
            );
            println!("  add-slave <bond> <iface>   - Add interface as slave");
            println!("  show <name>                - Show bond info");
            println!("  del <name>                 - Delete bond");
        }
    }

    Ok(())
}
