//! Bridge VLAN Filtering Example
//!
//! Demonstrates how to manage per-port VLAN configuration on Linux bridges.
//! Shows adding tagged/untagged VLANs and setting PVID.
//!
//! Run: cargo run -p nlink --example bridge_vlan

use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;

    println!("=== Bridge VLAN Configuration ===\n");

    // Find bridge interfaces
    let links = conn.get_links().await?;
    let bridges: Vec<_> = links
        .iter()
        .filter(|l| l.kind() == Some("bridge"))
        .collect();

    if bridges.is_empty() {
        println!("No bridge interfaces found.\n");
        println!("Create a VLAN-aware bridge with:");
        println!("  sudo ip link add br0 type bridge vlan_filtering 1");
        println!("  sudo ip link set br0 up");
        println!();
    } else {
        for bridge in &bridges {
            let name = bridge.name_or("?");
            println!("Bridge: {}", name);

            // Get VLAN configuration for all ports
            match conn.get_bridge_vlans_all(name).await {
                Ok(vlans) => {
                    if vlans.is_empty() {
                        println!("  No VLAN configuration (VLAN filtering may be disabled)\n");
                    } else {
                        // Group by interface
                        let mut current_ifindex = 0;
                        for vlan in &vlans {
                            if vlan.ifindex() != current_ifindex {
                                current_ifindex = vlan.ifindex();
                                let ifname = links
                                    .iter()
                                    .find(|l| l.ifindex() == current_ifindex)
                                    .and_then(|l| l.name())
                                    .unwrap_or("?");
                                println!("  Port: {}", ifname);
                            }
                            print!("    VLAN {}", vlan.vid());
                            if vlan.flags().pvid {
                                print!(" PVID");
                            }
                            if vlan.flags().untagged {
                                print!(" Egress Untagged");
                            }
                            println!();
                        }
                        println!();
                    }
                }
                Err(e) => println!("  Error: {}\n", e),
            }

            // Bridge-global per-VLAN options (multicast snooping, etc.)
            match conn.get_bridge_vlan_global_options(name).await {
                Ok(opts) if !opts.is_empty() => {
                    println!("  Global VLAN options:");
                    for o in &opts {
                        let vid = match o.vid_end() {
                            Some(end) => format!("{}-{}", o.vid(), end),
                            None => o.vid().to_string(),
                        };
                        println!(
                            "    VLAN {}: mcast_snooping={:?} mcast_querier={:?} msti={:?}",
                            vid,
                            o.mcast_snooping(),
                            o.mcast_querier(),
                            o.msti(),
                        );
                    }
                    println!();
                }
                Ok(_) => {}
                Err(e) => println!("  Global options error: {}\n", e),
            }
        }
    }

    // Example VLAN operations
    println!("=== VLAN Management Examples ===\n");

    println!("--- Query VLAN configuration ---");
    println!(
        r#"
    use nlink::netlink::{{Connection, Route}};

    let conn = Connection::<Route>::new()?;

    // Get VLANs for a specific port
    let vlans = conn.get_bridge_vlans("eth0").await?;
    for vlan in &vlans {{
        println!("VLAN {{}}: pvid={{}} untagged={{}}",
            vlan.vid(), vlan.flags().pvid, vlan.flags().untagged);
    }}

    // Get VLANs for all ports of a bridge
    let all_vlans = conn.get_bridge_vlans_all("br0").await?;
"#
    );

    println!("--- Set PVID (native VLAN) ---");
    println!(
        r#"
    use nlink::netlink::bridge_vlan::BridgeVlanBuilder;

    // Add VLAN 100 as PVID and untagged (native VLAN)
    conn.add_bridge_vlan(
        BridgeVlanBuilder::new(100)
            .dev("eth0")
            .pvid()
            .untagged()
    ).await?;

    // Or use the convenience method
    conn.set_bridge_pvid("eth0", 100).await?;
"#
    );

    println!("--- Add tagged VLAN ---");
    println!(
        r#"
    // Add VLAN 200 as tagged (trunk)
    conn.add_bridge_vlan(
        BridgeVlanBuilder::new(200)
            .dev("eth0")
    ).await?;

    // Or use convenience method
    conn.add_bridge_vlan_tagged("eth0", 200).await?;
"#
    );

    println!("--- Add VLAN range ---");
    println!(
        r#"
    // Add VLANs 300-310 as tagged
    conn.add_bridge_vlan_range("eth0", 300, 310).await?;
"#
    );

    println!("--- Delete VLANs ---");
    println!(
        r#"
    // Delete a single VLAN
    conn.del_bridge_vlan("eth0", 100).await?;

    // Delete a VLAN range
    conn.del_bridge_vlan_range("eth0", 300, 310).await?;
"#
    );

    println!("--- Bridge-global per-VLAN options (multicast snooping) ---");
    println!(
        r#"
    use nlink::netlink::bridge_vlan::BridgeVlanGlobalOptionsBuilder;

    // Enable per-VLAN multicast snooping on VLAN 100 of bridge br0.
    // These options live on the bridge device itself (VLAN-DB API).
    conn.set_bridge_vlan_global_options(
        BridgeVlanGlobalOptionsBuilder::new(100)
            .dev("br0")
            .mcast_snooping(true)
            .mcast_igmp_version(3)
    ).await?;

    // Apply to a VLAN range, then read the options back.
    conn.set_bridge_vlan_global_options(
        BridgeVlanGlobalOptionsBuilder::new(200)
            .dev("br0")
            .range(210)
            .mcast_snooping(false)
    ).await?;

    for o in conn.get_bridge_vlan_global_options("br0").await? {{
        println!("VLAN {{}}: snooping={{:?}}", o.vid(), o.mcast_snooping());
    }}
"#
    );

    println!("--- Namespace-aware operations ---");
    println!(
        r#"
    // Use ifindex to avoid reading /sys from wrong namespace
    let link = conn.get_link_by_name("eth0").await?.unwrap();

    conn.get_bridge_vlans_by_index(link.ifindex()).await?;
    conn.set_bridge_pvid_by_index(link.ifindex(), 100).await?;
"#
    );

    println!("=== VLAN Filtering Setup ===\n");
    println!(
        r#"
    # Enable VLAN filtering on bridge creation
    sudo ip link add br0 type bridge vlan_filtering 1

    # Or enable on existing bridge
    sudo ip link set br0 type bridge vlan_filtering 1

    # Add ports to bridge
    sudo ip link set eth0 master br0
    sudo ip link set eth1 master br0

    # Configure VLANs using nlink...
"#
    );

    Ok(())
}
