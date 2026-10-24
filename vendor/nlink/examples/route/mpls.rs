//! MPLS Routes and Encapsulation Example
//!
//! Demonstrates MPLS (Multi-Protocol Label Switching) configuration.
//! Shows label-based forwarding with push/pop/swap operations.
//!
//! Run: cargo run -p nlink --example route_mpls

use nlink::netlink::{Connection, Route};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;

    println!("=== MPLS Routes ===\n");

    // Check if MPLS is available
    match conn.get_mpls_routes().await {
        Ok(routes) => {
            if routes.is_empty() {
                println!("No MPLS routes configured.\n");
            } else {
                for route in &routes {
                    print!("Label {}: ", route.label().0);
                    match route.action() {
                        nlink::netlink::mpls::MplsAction::Pop => print!("pop "),
                        nlink::netlink::mpls::MplsAction::Swap(labels) => {
                            print!("swap ");
                            for l in labels {
                                print!("{} ", l.0);
                            }
                        }
                        // MplsAction is #[non_exhaustive]; future kernel
                        // actions (e.g., push-stack) print as a debug fallback.
                        other => print!("{:?} ", other),
                    }
                    if let Some(via) = route.via() {
                        print!("via {} ", via);
                    }
                    if let Some(idx) = route.oif() {
                        print!("dev ifindex {} ", idx);
                    }
                    println!();
                }
                println!();
            }
        }
        Err(e) => {
            println!("MPLS not available: {}\n", e);
            println!("Enable MPLS with:");
            println!("  sudo modprobe mpls_router");
            println!("  sudo sysctl net.mpls.platform_labels=1048575");
            println!("  sudo sysctl net.mpls.conf.eth0.input=1");
            println!();
        }
    }

    // Example MPLS configurations
    println!("=== MPLS Configuration Examples ===\n");

    println!("--- Enable MPLS on interface ---");
    println!(
        r#"
    # Enable MPLS on system
    sudo modprobe mpls_router
    sudo sysctl net.mpls.platform_labels=1048575

    # Enable MPLS input on interface
    sudo sysctl net.mpls.conf.eth0.input=1
"#
    );

    println!("--- IP route with MPLS encapsulation ---");
    println!(
        r#"
    use nlink::netlink::route::Ipv4Route;
    use nlink::netlink::mpls::MplsEncap;
    use std::net::Ipv4Addr;

    // Push single MPLS label onto IP packets
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
            .gateway(Ipv4Addr::new(192, 168, 1, 1))
            .dev("eth0")
            .mpls_encap(MplsEncap::new().label(100))
    ).await?;
"#
    );

    println!("--- MPLS label stack (multiple labels) ---");
    println!(
        r#"
    // Push multiple labels (outer to inner)
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 1, 0, 0), 16)
            .gateway(Ipv4Addr::new(192, 168, 1, 1))
            .mpls_encap(
                MplsEncap::new()
                    .labels(&[100, 200, 300])  // Label stack
                    .ttl(64)
            )
    ).await?;
"#
    );

    println!("--- MPLS pop route (egress PE) ---");
    println!(
        r#"
    use nlink::netlink::mpls::MplsRouteBuilder;

    // Pop label and forward to IP layer
    conn.add_mpls_route(
        MplsRouteBuilder::pop(100)
            .dev("eth0")
    ).await?;
"#
    );

    println!("--- MPLS swap route (transit LSR) ---");
    println!(
        r#"
    // Swap label 100 -> 200 and forward
    conn.add_mpls_route(
        MplsRouteBuilder::swap(100, 200)
            .via("192.168.2.1".parse()?)
            .dev("eth1")
    ).await?;
"#
    );

    println!("--- MPLS swap with label stack ---");
    println!(
        r#"
    // Swap incoming label for multiple outgoing labels
    conn.add_mpls_route(
        MplsRouteBuilder::swap_stack(100, &[200, 300])
            .via("192.168.2.1".parse()?)
            .dev("eth1")
    ).await?;
"#
    );

    println!("--- Query and delete MPLS routes ---");
    println!(
        r#"
    // List all MPLS routes
    let routes = conn.get_mpls_routes().await?;
    for route in &routes {{
        println!("Label {{}}: {{:?}}", route.label().0, route.action);
    }}

    // Delete MPLS route
    conn.del_mpls_route(100).await?;
"#
    );

    println!("--- Special MPLS labels ---");
    println!(
        r#"
    use nlink::netlink::mpls::MplsLabel;

    // Reserved labels
    let implicit_null = MplsLabel::IMPLICIT_NULL;  // 3 - PHP
    let explicit_null_v4 = MplsLabel::EXPLICIT_NULL_V4;  // 0
    let explicit_null_v6 = MplsLabel::EXPLICIT_NULL_V6;  // 2

    // Penultimate hop popping (PHP)
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 2, 0, 0), 16)
            .gateway(Ipv4Addr::new(192, 168, 1, 1))
            .mpls_encap(MplsEncap::new().label(implicit_null.0))
    ).await?;
"#
    );

    println!("=== MPLS Topology Example ===\n");
    println!(
        r#"
    # Simple MPLS path: CE1 - PE1 - P - PE2 - CE2
    #
    #  CE1 (10.1.0.0/16)     CE2 (10.2.0.0/16)
    #       |                      |
    #      PE1 -- (label 100) -- P -- (label 200) -- PE2
    #
    # PE1: Encapsulate with label 100
    # P:   Swap 100 -> 200
    # PE2: Pop label, deliver to CE2
"#
    );

    Ok(())
}
