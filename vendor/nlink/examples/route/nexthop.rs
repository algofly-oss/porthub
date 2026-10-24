//! Nexthop Objects and Groups Example
//!
//! Demonstrates Linux nexthop objects and ECMP groups (Linux 5.3+).
//! Nexthops provide efficient route updates and weighted load balancing.
//!
//! Run: cargo run -p nlink --example route_nexthop

use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;

    println!("=== Nexthop Objects ===\n");

    // List existing nexthops
    match conn.get_nexthops().await {
        Ok(nexthops) => {
            if nexthops.is_empty() {
                println!("No nexthop objects configured.\n");
            } else {
                for nh in &nexthops {
                    if nh.is_group() {
                        print!("Nexthop Group {}: ", nh.id());
                        if let Some(group) = nh.group() {
                            let members: Vec<_> = group
                                .iter()
                                .map(|m| format!("{}(weight={})", m.id(), m.weight()))
                                .collect();
                            println!("{}", members.join(", "));
                        }
                        if nh.resilient().is_some() {
                            println!("  Type: resilient");
                        }
                    } else {
                        print!("Nexthop {}: ", nh.id());
                        if let Some(gw) = nh.gateway() {
                            print!("via {} ", gw);
                        }
                        if let Some(idx) = nh.ifindex() {
                            print!("dev ifindex {} ", idx);
                        }
                        if nh.is_blackhole() {
                            print!("blackhole");
                        }
                        println!();
                    }
                }
                println!();
            }
        }
        Err(e) if e.is_not_supported() => {
            println!("Nexthop objects not supported (requires Linux 5.3+)\n");
        }
        Err(e) => println!("Error: {}\n", e),
    }

    // Example nexthop configurations
    println!("=== Nexthop Configuration Examples ===\n");

    println!("--- Create individual nexthops ---");
    println!(
        r#"
    use nlink::netlink::nexthop::NexthopBuilder;
    use std::net::Ipv4Addr;

    // Create nexthop via gateway
    conn.add_nexthop(
        NexthopBuilder::new(1)
            .gateway(Ipv4Addr::new(192, 168, 1, 1).into())
            .dev("eth0")
    ).await?;

    // Create nexthop on different interface
    conn.add_nexthop(
        NexthopBuilder::new(2)
            .gateway(Ipv4Addr::new(192, 168, 2, 1).into())
            .dev("eth1")
    ).await?;

    // Create blackhole nexthop
    conn.add_nexthop(
        NexthopBuilder::new(3)
            .blackhole()
    ).await?;
"#
    );

    println!("--- Create ECMP group (equal-cost multipath) ---");
    println!(
        r#"
    use nlink::netlink::nexthop::NexthopGroupBuilder;

    // Equal-weight load balancing between two nexthops
    conn.add_nexthop_group(
        NexthopGroupBuilder::new(100)
            .member(1, 1)  // nexthop 1, weight 1
            .member(2, 1)  // nexthop 2, weight 1
    ).await?;
"#
    );

    println!("--- Create weighted multipath group ---");
    println!(
        r#"
    // 2:1 traffic split (66% to NH1, 33% to NH2)
    conn.add_nexthop_group(
        NexthopGroupBuilder::new(101)
            .member(1, 2)  // weight 2
            .member(2, 1)  // weight 1
    ).await?;
"#
    );

    println!("--- Create resilient group ---");
    println!(
        r#"
    // Resilient groups maintain flow affinity during changes
    conn.add_nexthop_group(
        NexthopGroupBuilder::new(102)
            .resilient()
            .member(1, 1)
            .member(2, 1)
            .buckets(128)        // Hash buckets
            .idle_timer(120)     // Seconds before reassignment
    ).await?;
"#
    );

    println!("--- Use nexthop group in route ---");
    println!(
        r#"
    use nlink::netlink::route::Ipv4Route;

    // Add route using nexthop group
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
            .nexthop_group(100)  // Reference group ID
    ).await?;
"#
    );

    println!("--- Query nexthops ---");
    println!(
        r#"
    // Get all nexthops
    let nexthops = conn.get_nexthops().await?;

    // Get only groups
    let groups = conn.get_nexthop_groups().await?;

    // Get specific nexthop
    if let Some(nh) = conn.get_nexthop(1).await? {{
        println!("NH 1: gateway={{:?}}", nh.gateway());
    }}
"#
    );

    println!("--- Update nexthop ---");
    println!(
        r#"
    // Replace a nexthop (updates gateway)
    conn.replace_nexthop(
        NexthopBuilder::new(1)
            .gateway(Ipv4Addr::new(192, 168, 1, 254).into())
            .dev("eth0")
    ).await?;
"#
    );

    println!("--- Delete nexthops ---");
    println!(
        r#"
    // Delete group first (if routes depend on it)
    conn.del_nexthop_group(100).await?;

    // Delete individual nexthops
    conn.del_nexthop(1).await?;
    conn.del_nexthop(2).await?;
"#
    );

    println!("=== Benefits of Nexthop Objects ===\n");
    println!("1. Atomic updates - Change gateway without deleting routes");
    println!("2. Deduplication - Multiple routes share same nexthop");
    println!("3. Weighted ECMP - Fine-grained traffic distribution");
    println!("4. Resilient hashing - Flow affinity during changes");
    println!();

    Ok(())
}
