//! Per-Peer Impairment Example
//!
//! Demonstrates `PerPeerImpairer` — applying different netem
//! (delay/loss) settings to different destinations on a single
//! interface, useful for emulating shared L2 segments where each
//! peer-to-peer path needs distinct RTT/loss characteristics.
//!
//! Run modes:
//!
//! ```bash
//! # Print usage patterns and explain the tree shape (no privileges)
//! cargo run -p nlink --example impair_per_peer
//!
//! # Apply a 3-peer impairment in a temporary namespace, dump the
//! # resulting qdisc/class/filter tree, then clean up. Requires root,
//! # CAP_NET_ADMIN, and the `cls_flower` and `sch_netem` modules.
//! sudo cargo run -p nlink --example impair_per_peer -- --apply
//! ```
//!
//! See `docs/recipes/per-peer-impairment.md` for the full recipe.
//!
//! See also: `nlink::netlink::impair::PerPeerImpairer`,
//! `nlink::netlink::tc::NetemConfig`.

use std::{net::Ipv4Addr, time::Duration};

use nlink::netlink::{
    Connection, Route,
    impair::{PeerImpairment, PerPeerImpairer},
    link::DummyLink,
    namespace,
    tc::NetemConfig,
};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let do_apply = args.iter().any(|a| a == "--apply");

    print_overview();

    if !do_apply {
        println!();
        println!("Re-run with `--apply` (as root) to actually exercise the kernel paths.");
        return Ok(());
    }

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("--apply requires root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }

    println!();
    println!("=== Live demo (creating temporary namespace) ===");

    let ns_name = format!("nlink-impair-demo-{}", std::process::id());
    namespace::create(&ns_name)?;

    let result: nlink::Result<()> = (async {
        let conn: Connection<Route> = nlink::Connection::new_in(&ns_name)?;

        // Set up a dummy interface to apply the impairment to.
        conn.add_link(DummyLink::new("dummy0")).await?;
        conn.set_link_up("dummy0").await?;
        let link = conn
            .get_link_by_name("dummy0")
            .await?
            .expect("just created");
        let ifindex = link.ifindex();
        println!("  Created dummy0 (ifindex {ifindex}) in namespace `{ns_name}`.");

        // Build a 3-peer impairment with mixed configurations:
        //  - Close peer: small delay
        //  - Far peer:   bigger delay + loss + a per-peer rate cap
        //  - Subnet:     fallback for a whole /24
        //  - Default:    everything else gets a tiny baseline delay
        let imp = PerPeerImpairer::new_by_index(ifindex)
            .impair_dst_ip(
                Ipv4Addr::new(10, 0, 0, 1).into(),
                NetemConfig::new()
                    .delay(Duration::from_millis(15))
                    .jitter(Duration::from_millis(3))
                    .loss(nlink::Percent::new(1.0))
                    .build(),
            )
            .impair_dst_ip(
                Ipv4Addr::new(10, 0, 0, 2).into(),
                PeerImpairment::new(
                    NetemConfig::new()
                        .delay(Duration::from_millis(120))
                        .jitter(Duration::from_millis(40))
                        .loss(nlink::Percent::new(7.5))
                        .build(),
                )
                .rate_cap(nlink::Rate::mbit(100)),
            )
            .impair_dst_subnet(
                "10.0.99.0/24",
                NetemConfig::new().delay(Duration::from_millis(60)).build(),
            )?
            .default_impairment(NetemConfig::new().delay(Duration::from_millis(2)).build());

        println!(
            "  Applying impairment ({} rules + default)...",
            imp.rule_count()
        );
        imp.apply(&conn).await?;

        dump_tree(&conn, ifindex).await?;

        println!();
        println!("  Removing impairment via clear()...");
        imp.clear(&conn).await?;

        let qdiscs_after = conn.get_qdiscs_by_index(ifindex).await?;
        let htb_left = qdiscs_after
            .iter()
            .filter(|q| q.kind() == Some("htb"))
            .count();
        let netem_left = qdiscs_after
            .iter()
            .filter(|q| q.kind() == Some("netem"))
            .count();
        println!(
            "  After clear: {} HTB qdisc(s), {} netem leaf/leaves remaining.",
            htb_left, netem_left
        );

        Ok(())
    })
    .await;

    let _ = namespace::delete(&ns_name);
    result?;

    println!();
    println!("Done. Namespace `{ns_name}` removed.");
    Ok(())
}

fn print_overview() {
    println!("=== PerPeerImpairer ===\n");
    println!("Per-destination netem on a single interface, used to emulate");
    println!("shared L2 segments (bridges, multipoint radio fabrics) where");
    println!("each peer-to-peer path has distinct RTT and loss.\n");

    println!("--- Topology built by apply() ---\n");
    println!(
        "    dev -> HTB root (1:) -> HTB class 1:1 (parent)
                              ├── HTB class 1:2 -> netem (peer 1)   <- flower(dst=peer1)
                              ├── HTB class 1:3 -> netem (peer 2)   <- flower(dst=peer2)
                              ├── HTB class 1:N+1 -> netem (peer N) <- flower(dst=peerN)
                              └── HTB class 1:N+2 -> netem (default, optional)
"
    );

    println!("--- Code ---\n");
    println!(
        r#"    use nlink::netlink::{{Connection, Route, namespace}};
    use nlink::netlink::impair::{{PerPeerImpairer, PeerImpairment}};
    use nlink::netlink::tc::NetemConfig;
    use std::time::Duration;

    let conn: Connection<Route> = nlink::Connection::new_in("lab-mgmt")?;

    PerPeerImpairer::new("vethA-br")
        // Close peer.
        .impair_dst_ip(
            "172.100.3.18".parse()?,
            NetemConfig::new()
                .delay(Duration::from_millis(15))
                .loss(1.0)
                .build(),
        )
        // Far peer with a 100 Mbps cap on top of the impairment.
        .impair_dst_ip(
            "172.100.3.19".parse()?,
            PeerImpairment::new(
                NetemConfig::new()
                    .delay(Duration::from_millis(40))
                    .loss(5.0)
                    .build(),
            )
            .rate_cap("100mbit")?,
        )
        // Subnet match for everything else on the /24.
        .impair_dst_subnet(
            "172.100.4.0/24",
            NetemConfig::new().delay(Duration::from_millis(80)).build(),
        )?
        // Optional default for unmatched traffic.
        .default_impairment(NetemConfig::new().delay(Duration::from_millis(2)).build())
        .apply(&conn).await?;

    // Symmetric pair impairment requires applying on both ends:
    //   On hq's bridge-port veth:    .impair_dst_ip(alpha_addr, ...)
    //   On alpha's bridge-port veth: .impair_dst_ip(hq_addr,    ...)

    // Source-side matching also available:
    //   .impair_src_ip(...) / .impair_src_subnet(...) / .impair_src_mac(...)

    // Remove with:
    PerPeerImpairer::new("vethA-br").clear(&conn).await?;
"#
    );

    println!("--- Caveats ---\n");
    println!("  * apply() is destructive on the device's root qdisc.");
    println!("  * cls_flower must be loaded in the target namespace.");
    println!("  * Filters match egress; symmetric impairment = apply on both ends.");
    println!("  * Built on HTB (not PRIO) so peers don't starve each other under load.");
    println!();

    println!("--- get_filters_by_parent (companion convenience) ---\n");
    println!(
        r#"    // Filter the dump server-side by parent handle.
    let helper_filters = conn.get_filters_by_parent("vethA-br", "1:").await?;
    let by_index = conn.get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1)).await?;
"#
    );
}

async fn dump_tree(conn: &Connection<Route>, ifindex: u32) -> nlink::Result<()> {
    println!();
    println!("  --- Resulting qdisc tree on dummy0 ---");

    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    for q in &qdiscs {
        let kind = q.kind().unwrap_or("?");
        let parent = if q.is_root() {
            "root".to_string()
        } else {
            q.parent_str()
        };
        let handle = q.handle_str();
        println!("    qdisc {kind:<10} handle={handle} parent={parent}");
    }

    println!();
    println!("  --- HTB classes ---");
    let classes = conn.get_classes_by_index(ifindex).await?;
    for c in classes.iter().filter(|c| c.kind() == Some("htb")) {
        let parent = if c.parent().is_unspec() {
            "root".to_string()
        } else {
            c.parent_str()
        };
        println!(
            "    class htb       handle={} parent={parent}",
            c.handle_str()
        );
    }

    println!();
    println!("  --- Filters at parent 1: ---");
    let filters = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1))
        .await?;
    for f in &filters {
        let kind = f.kind().unwrap_or("?");
        println!(
            "    filter {kind:<8} handle={} parent={}",
            f.handle_str(),
            f.parent_str()
        );
    }

    Ok(())
}
