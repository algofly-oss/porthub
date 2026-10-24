//! Hierarchical Token Bucket (HTB) traffic shaping — full pipeline.
//!
//! Demonstrates building an HTB classful shaping tree with child
//! classes and flower filters, then querying the resulting state.
//!
//! Run modes:
//!
//! ```bash
//! # Print usage patterns and the tree shape (no privileges)
//! cargo run -p nlink --example route_tc_htb
//!
//! # Inspect an existing HTB tree on a real device (no privileges
//! # required beyond netlink read access)
//! cargo run -p nlink --example route_tc_htb -- show eth0
//! cargo run -p nlink --example route_tc_htb -- classes eth0
//!
//! # Build a 3-class HTB tree + flower filters in a temporary
//! # namespace, dump the resulting state, tear down. Requires root
//! # (CAP_NET_ADMIN) and the `cls_flower` + `sch_htb` modules.
//! sudo cargo run -p nlink --example route_tc_htb -- --apply
//! ```
//!
//! See also: `nlink::netlink::tc::{HtbQdiscConfig, HtbClassConfig}`,
//! `nlink::netlink::filter::FlowerFilter`, and the
//! `PerPeerImpairer` / `PerHostLimiter` recipes that build on the same
//! HTB-plus-flower shape.

use std::env;

use nlink::{
    Bytes, Rate, TcHandle,
    netlink::{
        Connection, Route,
        filter::FlowerFilter,
        link::DummyLink,
        namespace,
        tc::{HtbClassConfig, HtbQdiscConfig},
        tc_options::QdiscOptions,
    },
};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("show") => {
            let dev = args.get(2).map(|s| s.as_str()).unwrap_or("eth0");
            let conn = Connection::<Route>::new()?;
            show_htb(&conn, dev).await?;
        }
        Some("classes") => {
            let dev = args.get(2).map(|s| s.as_str()).unwrap_or("eth0");
            let conn = Connection::<Route>::new()?;
            show_classes(&conn, dev).await?;
        }
        Some("--apply") => {
            run_apply().await?;
        }
        _ => {
            print_overview();
        }
    }

    Ok(())
}

fn print_overview() {
    println!("=== HTB (Hierarchical Token Bucket) ===\n");
    println!("Classful egress shaper. Rates borrow down the tree: a child");
    println!("class can use its siblings' unused capacity up to its `ceil`.\n");

    println!("--- Topology built by --apply ---\n");
    println!(
        "    dummy0 -> HTB root (1:) default=1:30
                   └── 1:1 parent (1 gbit)
                        ├── 1:10 (voice, 100 mbit, prio 1)  <- flower udp dport 5060
                        ├── 1:20 (video, 200 mbit, prio 2)  <- flower tcp dport 1935
                        └── 1:30 (bulk,   50 mbit, prio 3)    (default, no filter)
"
    );

    println!("--- Code ---\n");
    println!(
        r#"    use nlink::{{Rate, TcHandle}};
    use nlink::netlink::{{Connection, Route}};
    use nlink::netlink::tc::{{HtbQdiscConfig, HtbClassConfig}};
    use nlink::netlink::filter::FlowerFilter;

    let conn = Connection::<Route>::new()?;

    // 1. Attach HTB at the root; default-class for unmatched traffic.
    conn.add_qdisc_full(
        "eth0",
        TcHandle::ROOT,
        Some(TcHandle::major_only(1)),
        HtbQdiscConfig::new().default_class(0x30).build(),
    ).await?;

    // 2. Parent class (total link capacity).
    conn.add_class(
        "eth0",
        TcHandle::major_only(1),
        TcHandle::new(1, 1),
        HtbClassConfig::new(Rate::gbit(1)).ceil(Rate::gbit(1)).build(),
    ).await?;

    // 3. Child class with priority.
    conn.add_class(
        "eth0",
        TcHandle::new(1, 1),
        TcHandle::new(1, 0x10),
        HtbClassConfig::new(Rate::mbit(100))
            .ceil(Rate::mbit(500))
            .prio(1)
            .build(),
    ).await?;

    // 4. Flower filter: UDP dport 5060 (SIP) -> class 1:10.
    conn.add_filter(
        "eth0",
        TcHandle::major_only(1),
        FlowerFilter::new()
            .ipv4()
            .ip_proto_udp()
            .dst_port(5060)
            .classid(TcHandle::new(1, 0x10))
            .priority(100)
            .build(),
    ).await?;

    // Tear down the whole tree by deleting the root qdisc — the kernel
    // removes child classes and filters automatically.
    conn.del_qdisc("eth0", TcHandle::ROOT).await?;
"#
    );

    println!("--- Re-run with `--apply` (as root) ---");
    println!("  Builds the tree above inside a temporary namespace, dumps,");
    println!("  and cleans up. Never touches the host's real interfaces.");
    println!();
    println!("--- Query modes (no root needed) ---");
    println!("  show <dev>     — Show HTB qdisc configuration + stats");
    println!("  classes <dev>  — Show HTB classes + stats");
}

async fn run_apply() -> nlink::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("--apply requires root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }

    println!("=== HTB live demo (temporary namespace) ===");

    let ns_name = format!("nlink-htb-demo-{}", std::process::id());
    namespace::create(&ns_name)?;

    let result = run_demo(&ns_name).await;

    let _ = namespace::delete(&ns_name);
    result?;

    println!();
    println!("Done. Namespace `{ns_name}` removed.");
    Ok(())
}

async fn run_demo(ns_name: &str) -> nlink::Result<()> {
    let conn: Connection<Route> = nlink::Connection::new_in(ns_name)?;

    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;
    let link = conn
        .get_link_by_name("dummy0")
        .await?
        .expect("just created");
    let ifindex = link.ifindex();
    println!("  Created dummy0 (ifindex {ifindex}) in namespace `{ns_name}`.");

    // 1. HTB qdisc at the root. default-class 0x30 sends unmatched
    //    traffic to the bulk class.
    println!();
    println!("  Attaching HTB root qdisc 1: (default-class 1:30)...");
    conn.add_qdisc_by_index_full(
        ifindex,
        TcHandle::ROOT,
        Some(TcHandle::major_only(1)),
        HtbQdiscConfig::new().default_class(0x30).r2q(10).build(),
    )
    .await?;

    // 2. Parent class: the whole link capacity (1 Gbit).
    println!("  Adding parent class 1:1 (1 gbit rate+ceil)...");
    conn.add_class_by_index(
        ifindex,
        TcHandle::major_only(1),
        TcHandle::new(1, 1),
        HtbClassConfig::new(Rate::gbit(1))
            .ceil(Rate::gbit(1))
            .burst(Bytes::kib(64))
            .build(),
    )
    .await?;

    // 3. Three child classes with different priorities.
    let children: &[(u16, &str, Rate, Rate, u32)] = &[
        (0x10, "voice", Rate::mbit(100), Rate::mbit(500), 1),
        (0x20, "video", Rate::mbit(200), Rate::mbit(800), 2),
        (0x30, "bulk", Rate::mbit(50), Rate::mbit(500), 3),
    ];
    for &(minor, label, rate, ceil, prio) in children {
        println!(
            "  Adding child class 1:{minor:x} ({label}, rate={rate} ceil={ceil} prio={prio})..."
        );
        conn.add_class_by_index(
            ifindex,
            TcHandle::new(1, 1),
            TcHandle::new(1, minor),
            HtbClassConfig::new(rate).ceil(ceil).prio(prio).build(),
        )
        .await?;
    }

    // 4. Flower filters steer matching traffic to the voice + video
    //    classes. Anything unmatched falls through to the default
    //    class (1:30, bulk).
    println!();
    println!("  Adding flower filter: UDP dport 5060 (SIP) -> 1:10 ...");
    conn.add_filter_by_index(
        ifindex,
        TcHandle::major_only(1),
        FlowerFilter::new()
            .ipv4()
            .ip_proto_udp()
            .dst_port(5060)
            .classid(TcHandle::new(1, 0x10))
            .priority(nlink::FilterPriority::new(100))
            .build(),
    )
    .await?;

    println!("  Adding flower filter: TCP dport 1935 (RTMP) -> 1:20 ...");
    conn.add_filter_by_index(
        ifindex,
        TcHandle::major_only(1),
        FlowerFilter::new()
            .ipv4()
            .ip_proto_tcp()
            .dst_port(1935)
            .classid(TcHandle::new(1, 0x20))
            .priority(nlink::FilterPriority::new(200))
            .build(),
    )
    .await?;

    dump_tree(&conn, ifindex).await?;

    // 5. Delete the root qdisc. The kernel tears down every child
    //    class and filter atomically; one syscall replaces four.
    println!();
    println!("  Deleting root qdisc (kernel cleans up classes + filters)...");
    conn.del_qdisc_by_index(ifindex, TcHandle::ROOT).await?;

    let qdiscs_after = conn.get_qdiscs_by_index(ifindex).await?;
    let htb_left = qdiscs_after
        .iter()
        .filter(|q| q.kind() == Some("htb"))
        .count();
    let classes_after = conn.get_classes_by_index(ifindex).await?;
    let filters_after = conn
        .get_filters_by_parent_index(ifindex, TcHandle::major_only(1))
        .await?;
    println!(
        "  After delete: {htb_left} HTB qdisc(s), {} class(es), {} filter(s) remaining.",
        classes_after.len(),
        filters_after.len()
    );

    Ok(())
}

async fn dump_tree(conn: &Connection<Route>, ifindex: u32) -> nlink::Result<()> {
    println!();
    println!("  --- qdiscs ---");
    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    for q in &qdiscs {
        let kind = q.kind().unwrap_or("?");
        let parent = if q.is_root() {
            "root".to_string()
        } else {
            q.parent_str()
        };
        let extra = match q.options() {
            Some(QdiscOptions::Htb(h)) => {
                format!(" default=1:{:x} r2q={}", h.default_class, h.rate2quantum)
            }
            _ => String::new(),
        };
        println!(
            "    qdisc {kind:<10} handle={} parent={parent}{extra}",
            q.handle_str()
        );
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
        .get_filters_by_parent_index(ifindex, TcHandle::major_only(1))
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

async fn show_htb(conn: &Connection<Route>, dev: &str) -> nlink::Result<()> {
    let qdiscs = conn.get_qdiscs_by_name(dev).await?;

    println!("TC qdiscs on {dev}:");
    println!("{}", "-".repeat(60));

    let mut found_htb = false;

    for qdisc in &qdiscs {
        let kind = qdisc.kind().unwrap_or("?");

        if kind == "htb" {
            found_htb = true;
            println!("qdisc htb handle {}", qdisc.handle_str());

            if let Some(QdiscOptions::Htb(htb)) = qdisc.options() {
                println!("  default class: {:x}", htb.default_class);
                println!("  r2q: {}", htb.rate2quantum);
                if let Some(qlen) = htb.direct_qlen {
                    println!("  direct_qlen: {qlen}");
                }
            }

            println!("  stats:");
            println!("    bytes: {}", qdisc.bytes());
            println!("    packets: {}", qdisc.packets());
            println!("    drops: {}", qdisc.drops());
            println!("    overlimits: {}", qdisc.overlimits());
            println!(
                "    rate: {} ({} pps)",
                Rate::bytes_per_sec(qdisc.bps()),
                qdisc.pps()
            );
        } else {
            let parent = if qdisc.is_root() {
                "root".to_string()
            } else {
                qdisc.parent_str()
            };
            println!("qdisc {kind} parent {parent}");
        }
    }

    if !found_htb {
        println!("No HTB qdisc found on {dev}");
        println!();
        println!("To build one in a temporary namespace, run:");
        println!("  sudo cargo run -p nlink --example route_tc_htb -- --apply");
    }

    Ok(())
}

async fn show_classes(conn: &Connection<Route>, dev: &str) -> nlink::Result<()> {
    let classes = conn.get_classes_by_name(dev).await?;

    println!("TC classes on {dev}:");
    println!("{}", "-".repeat(80));
    println!(
        "{:<12} {:<12} {:<12} {:>12} {:>12} {:>10}",
        "CLASSID", "PARENT", "TYPE", "BYTES", "PACKETS", "RATE"
    );

    for class in &classes {
        let kind = class.kind().unwrap_or("?");
        let classid = class.handle_str();

        let parent = if class.parent().is_root() {
            "root".to_string()
        } else {
            class.parent_str()
        };

        let rate = if class.bps() > 0 {
            Rate::bytes_per_sec(class.bps()).to_string()
        } else {
            "-".to_string()
        };

        println!(
            "{:<12} {:<12} {:<12} {:>12} {:>12} {:>10}",
            classid,
            parent,
            kind,
            class.bytes(),
            class.packets(),
            rate
        );
    }

    if classes.is_empty() {
        println!("No classes found on {dev}");
    }

    Ok(())
}
