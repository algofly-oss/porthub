//! SRv6 (Segment Routing over IPv6) Example
//!
//! Demonstrates SRv6 configuration with segment lists and local SIDs.
//! SRv6 enables source-routed paths using IPv6 addresses as segments.
//!
//! Run: cargo run -p nlink --example route_srv6

use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;

    println!("=== SRv6 Local Routes ===\n");

    // Check SRv6 local routes
    match conn.get_srv6_local_routes().await {
        Ok(routes) => {
            if routes.is_empty() {
                println!("No SRv6 local SIDs configured.\n");
            } else {
                for route in &routes {
                    println!(
                        "SID {:?}: {} (proto {})",
                        route.sid,
                        route.action.name(),
                        route.protocol
                    );
                    if let Some(idx) = route.oif {
                        println!("  dev ifindex {}", idx);
                    }
                }
                println!();
            }
        }
        Err(e) => {
            println!("SRv6 not available: {}\n", e);
            println!("Enable SRv6 with:");
            println!("  sudo sysctl net.ipv6.conf.all.seg6_enabled=1");
            println!("  sudo sysctl net.ipv6.conf.eth0.seg6_enabled=1");
            println!();
        }
    }

    // Example SRv6 configurations
    println!("=== SRv6 Configuration Examples ===\n");

    println!("--- Enable SRv6 ---");
    println!(
        r#"
    # Enable SRv6 globally
    sudo sysctl net.ipv6.conf.all.seg6_enabled=1

    # Enable on specific interface
    sudo sysctl net.ipv6.conf.eth0.seg6_enabled=1
"#
    );

    println!("--- SRv6 encapsulation (encap mode) ---");
    println!(
        r#"
    use nlink::netlink::route::Ipv4Route;
    use nlink::netlink::srv6::Srv6Encap;

    // Encapsulate IPv4 traffic in SRv6 (IPv4oIPv6)
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
            .dev("eth0")
            .srv6_encap(
                Srv6Encap::encap()
                    .segment("fc00:1::1".parse()?)
            )
    ).await?;

    // With multiple segments (segment list)
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 1, 0, 0), 16)
            .dev("eth0")
            .srv6_encap(
                Srv6Encap::encap()
                    .segments(&[
                        "fc00:1::1".parse()?,  // Final destination
                        "fc00:2::1".parse()?,  // Intermediate
                    ])
            )
    ).await?;
"#
    );

    println!("--- SRv6 inline mode ---");
    println!(
        r#"
    use nlink::netlink::route::Ipv6Route;

    // Insert SRH into existing IPv6 packet (no outer header)
    conn.add_route(
        Ipv6Route::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32)
            .dev("eth0")
            .srv6_encap(
                Srv6Encap::inline()
                    .segment("fc00:1::1".parse()?)
            )
    ).await?;
"#
    );

    println!("--- SRv6 End (simple transit) ---");
    println!(
        r#"
    use nlink::netlink::srv6::Srv6LocalBuilder;

    // End: Decrement SL, update DA, forward
    conn.add_srv6_local(
        Srv6LocalBuilder::end("fc00:1::1".parse()?)
            .dev("eth0")
    ).await?;
"#
    );

    println!("--- SRv6 End.X (forward to nexthop) ---");
    println!(
        r#"
    // End.X: Pop and forward to specific nexthop
    conn.add_srv6_local(
        Srv6LocalBuilder::end_x(
            "fc00:1::1".parse()?,   // SID
            "fe80::1".parse()?      // Nexthop
        )
        .dev("eth0")
    ).await?;
"#
    );

    println!("--- SRv6 End.DT4 (decap to IPv4 VRF) ---");
    println!(
        r#"
    // End.DT4: Decapsulate and lookup in IPv4 table
    conn.add_srv6_local(
        Srv6LocalBuilder::end_dt4(
            "fc00:1::100".parse()?,
            100  // VRF table ID
        )
        .dev("eth0")
    ).await?;
"#
    );

    println!("--- SRv6 End.DT6 (decap to IPv6 VRF) ---");
    println!(
        r#"
    // End.DT6: Decapsulate and lookup in IPv6 table
    conn.add_srv6_local(
        Srv6LocalBuilder::end_dt6(
            "fc00:1::200".parse()?,
            100  // VRF table ID
        )
        .dev("eth0")
    ).await?;
"#
    );

    println!("--- SRv6 End.B6.Encaps (binding SID) ---");
    println!(
        r#"
    // End.B6.Encaps: Encapsulate with new SRH
    conn.add_srv6_local(
        Srv6LocalBuilder::end_b6_encaps(
            "fc00:1::300".parse()?,
            &[
                "fc00:2::1".parse()?,
                "fc00:3::1".parse()?,
            ]
        )
        .dev("eth0")
    ).await?;
"#
    );

    println!("--- Query and delete SRv6 routes ---");
    println!(
        r#"
    // List SRv6 local SIDs
    let routes = conn.get_srv6_local_routes().await?;
    for route in &routes {{
        println!("SID {{:?}}: {{}}", route.sid, route.action.name());
    }}

    // Delete SRv6 local route
    conn.del_srv6_local("fc00:1::100".parse()?).await?;
"#
    );

    println!("=== SRv6 Use Cases ===\n");
    println!("1. Traffic Engineering - Steer traffic through specific paths");
    println!("2. Service Chaining - Route through network functions");
    println!("3. VPN Services - End.DT4/DT6 for VRF termination");
    println!("4. Fast Reroute - Pre-computed backup paths");
    println!();

    println!("=== SRv6 Topology Example ===\n");
    println!(
        r#"
    # SRv6 path: Host A - R1 - R2 - R3 - Host B
    #
    #  Host A (10.1.0.1)              Host B (10.2.0.1)
    #       |                              |
    #      R1 ----- R2 ----- R3
    #
    # SIDs:
    #   fc00:1::1 (R1 End)
    #   fc00:2::1 (R2 End)
    #   fc00:3::1 (R3 End.DT4)
    #
    # Host A sends to 10.2.0.1:
    # R1: Encap with segments [fc00:3::1, fc00:2::1]
    # R2: End - forward to R3
    # R3: End.DT4 - decap, lookup in IPv4, deliver to Host B
"#
    );

    Ok(())
}
