//! Bridge FDB (Forwarding Database) Example
//!
//! Demonstrates how to manage MAC address entries in Linux bridges.
//! Shows querying, adding, and deleting FDB entries.
//!
//! Run: cargo run -p nlink --example bridge_fdb

use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;

    println!("=== Bridge FDB Entries ===\n");

    // Find bridge interfaces
    let links = conn.get_links().await?;
    let bridges: Vec<_> = links
        .iter()
        .filter(|l| l.kind() == Some("bridge"))
        .collect();

    if bridges.is_empty() {
        println!("No bridge interfaces found.\n");
        println!("Create a bridge with:");
        println!("  sudo ip link add br0 type bridge");
        println!("  sudo ip link set br0 up");
        println!();
    } else {
        for bridge in &bridges {
            let name = bridge.name_or("?");
            println!("Bridge: {}", name);

            // Get FDB entries for all ports
            match conn.get_fdb(name).await {
                Ok(entries) => {
                    if entries.is_empty() {
                        println!("  No FDB entries\n");
                    } else {
                        for entry in &entries {
                            print!("  {} ", entry.mac_str());
                            if let Some(vlan) = entry.vlan() {
                                print!("vlan {} ", vlan);
                            }
                            if let Some(dst) = entry.dst() {
                                print!("dst {} ", dst);
                            }
                            if entry.is_permanent() {
                                print!("permanent ");
                            } else if entry.is_static() {
                                print!("static ");
                            }
                            if entry.is_self() {
                                print!("self ");
                            }
                            if entry.is_master() {
                                print!("master ");
                            }
                            if entry.is_extern_learn() {
                                print!("extern_learn ");
                            }
                            println!();
                        }
                        println!();
                    }
                }
                Err(e) => println!("  Error: {}\n", e),
            }
        }
    }

    // Example FDB operations
    println!("=== FDB Management Examples ===\n");

    println!("--- Query FDB entries ---");
    println!(
        r#"
    use nlink::netlink::{{Connection, Route}};

    let conn = Connection::<Route>::new()?;

    // Get all FDB entries for a bridge
    let entries = conn.get_fdb("br0").await?;
    for entry in &entries {{
        println!("{{}} vlan={{:?}}", entry.mac_str(), entry.vlan());
    }}

    // Get entries for a specific port
    let port_entries = conn.get_fdb_for_port("br0", "veth0").await?;
"#
    );

    println!("--- Add static FDB entry ---");
    println!(
        r#"
    use nlink::netlink::fdb::FdbEntryBuilder;

    // Parse MAC address
    let mac = FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff")?;

    // Add a static entry: frames for the MAC leave through veth0
    conn.add_fdb(
        FdbEntryBuilder::new(mac)
            .dev("veth0")      // Bridge port
            .master("br0")     // Bridge interface
            .vlan(100)         // Optional VLAN
            .static_()         // Static; .permanent() is a local entry
    ).await?;
"#
    );

    println!("--- Add VXLAN FDB entry (remote VTEP) ---");
    println!(
        r#"
    use std::net::Ipv4Addr;

    // Add entry for BUM (broadcast/unknown/multicast) traffic
    conn.add_fdb(
        FdbEntryBuilder::new([0x00; 6])  // All-zeros for BUM
            .dev("vxlan0")
            .dst(Ipv4Addr::new(192, 168, 1, 100).into())
            .self_()                     // The VXLAN device's own table
    ).await?;

    // Add specific MAC -> VTEP mapping
    let mac = FdbEntryBuilder::parse_mac("00:11:22:33:44:55")?;
    conn.add_fdb(
        FdbEntryBuilder::new(mac)
            .dev("vxlan0")
            .dst(Ipv4Addr::new(192, 168, 1, 101).into())
            .self_()
    ).await?;
"#
    );

    println!("--- Delete FDB entry ---");
    println!(
        r#"
    let mac = FdbEntryBuilder::parse_mac("aa:bb:cc:dd:ee:ff")?;

    // Delete without VLAN
    conn.del_fdb("veth0", mac, None).await?;

    // Delete with specific VLAN
    conn.del_fdb("veth0", mac, Some(100)).await?;
"#
    );

    println!("--- Replace FDB entry ---");
    println!(
        r#"
    // Add or update an entry
    conn.replace_fdb(
        FdbEntryBuilder::new(mac)
            .dev("veth0")
            .master("br0")
            .static_()
    ).await?;
"#
    );

    println!("--- Flush FDB entries ---");
    println!(
        r#"
    // Flush all dynamic entries (keeps static and permanent ones)
    conn.flush_fdb("br0").await?;
"#
    );

    Ok(())
}
