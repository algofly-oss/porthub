//! Rate Limiting Example — `RateLimiter` + `PerHostLimiter` + reconcile.
//!
//! Run modes:
//!
//! ```bash
//! # Print usage patterns (no privileges required)
//! cargo run -p nlink --example ratelimit_simple
//!
//! # Apply rate limits in a temporary namespace, dump the resulting
//! # qdisc/class tree, exercise reconcile(), and clean up. Requires
//! # root and CAP_NET_ADMIN.
//! sudo cargo run -p nlink --example ratelimit_simple -- --apply
//! ```
//!
//! See also: `nlink::netlink::ratelimit::{RateLimiter, PerHostLimiter}`,
//! `docs/recipes/per-peer-impairment.md` for the companion impairment
//! recipe.
//!
//! # What the `--apply` mode does
//!
//! 1. Creates a temporary network namespace + dummy interface.
//! 2. Applies a `RateLimiter` (egress-only), dumps the resulting tree,
//!    and removes it.
//! 3. Applies a 3-rule `PerHostLimiter`, dumps, calls `reconcile()` a
//!    second time to show the no-op property, then removes it.
//! 4. Deletes the namespace.
//!
//! The flow never touches the host's real network state — everything
//! lives inside the transient namespace.

use std::{net::IpAddr, time::Duration};

use nlink::netlink::{
    Connection, Route,
    link::DummyLink,
    namespace,
    ratelimit::{PerHostLimiter, RateLimiter},
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

    let ns_name = format!("nlink-ratelimit-demo-{}", std::process::id());
    namespace::create(&ns_name)?;

    let result: nlink::Result<()> = run_demo(&ns_name).await;

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
    println!("  Created dummy0 in namespace `{ns_name}`.");

    demo_rate_limiter(&conn).await?;
    demo_per_host_limiter(&conn).await?;

    Ok(())
}

async fn demo_rate_limiter(conn: &Connection<Route>) -> nlink::Result<()> {
    println!();
    println!("--- RateLimiter (interface-wide egress shaping) ---");

    let limiter = RateLimiter::new("dummy0")
        .egress(nlink::Rate::mbit(100))
        .burst_to(nlink::Rate::mbit(150))
        .latency(Duration::from_millis(20));

    println!("  Applying 100 Mbps egress cap with 150 Mbps ceil...");
    limiter.apply(conn).await?;

    dump_qdiscs(conn, "dummy0", "after RateLimiter::apply").await?;

    // reconcile() (0.24, #169) mirrors PerHostLimiter: idempotent
    // convergence that only mutates drift. Right after apply() it
    // must be a no-op; a changed rate converges in place instead of
    // tearing the tree down.
    let report = limiter.reconcile(conn).await?;
    println!(
        "  reconcile() right after apply(): {} change(s) (expect 0)",
        report.changes_made
    );
    let drifted = RateLimiter::new("dummy0")
        .egress(nlink::Rate::mbit(200))
        .burst_to(nlink::Rate::mbit(250))
        .latency(Duration::from_millis(20));
    let plan = drifted.reconcile_dry_run(conn).await?;
    println!(
        "  reconcile_dry_run() for a 200 Mbps target: {} pending change(s)",
        plan.changes_made
    );

    println!();
    println!("  Removing...");
    limiter.remove(conn).await?;

    let q_after = conn.get_qdiscs_by_name("dummy0").await?;
    let htb_left = q_after.iter().filter(|q| q.kind() == Some("htb")).count();
    println!("  After remove(): {htb_left} HTB qdisc(s) remaining.");

    Ok(())
}

async fn demo_per_host_limiter(conn: &Connection<Route>) -> nlink::Result<()> {
    println!();
    println!("--- PerHostLimiter (per-IP/subnet shaping) ---");

    let vip: IpAddr = "10.0.0.100".parse().unwrap();
    let limiter = PerHostLimiter::new("dummy0", nlink::Rate::mbit(10))
        .limit_ip(vip, nlink::Rate::mbit(100))
        .limit_subnet("10.0.0.0/24", nlink::Rate::mbit(50))?
        .limit_port(80, nlink::Rate::mbit(500))
        .latency(Duration::from_millis(10));

    println!(
        "  Applying 3-rule PerHostLimiter (default 10 Mbps, VIP 100 Mbps, \
         /24 subnet 50 Mbps, port 80 → 500 Mbps)..."
    );
    limiter.apply(conn).await?;

    dump_qdiscs(conn, "dummy0", "after PerHostLimiter::apply").await?;
    dump_classes(conn, "dummy0").await?;

    // reconcile() is the idempotent-by-construction verb for repeated
    // calls — re-applying the same config makes zero kernel mutations
    // the second time. Compare against re-running apply(), which would
    // destructively rebuild the whole tree (packet-drop hiccup).
    println!();
    println!("  Calling reconcile() — should be a no-op (0 kernel calls):");
    let report = limiter.reconcile(conn).await?;
    println!(
        "    report: changes_made={} is_noop={} (rules_added/modified/removed={}, {}, {})",
        report.changes_made,
        report.is_noop(),
        report.rules_added,
        report.rules_modified,
        report.rules_removed,
    );

    println!();
    println!("  Removing...");
    limiter.remove(conn).await?;

    Ok(())
}

async fn dump_qdiscs(conn: &Connection<Route>, dev: &str, label: &str) -> nlink::Result<()> {
    println!();
    println!("  --- qdiscs on {dev} ({label}) ---");
    let qdiscs = conn.get_qdiscs_by_name(dev).await?;
    for q in &qdiscs {
        let kind = q.kind().unwrap_or("?");
        let parent = if q.is_root() {
            "root".to_string()
        } else {
            q.parent_str()
        };
        println!(
            "    qdisc {kind:<10} handle={} parent={parent}",
            q.handle_str()
        );
    }
    Ok(())
}

async fn dump_classes(conn: &Connection<Route>, dev: &str) -> nlink::Result<()> {
    println!();
    println!("  --- HTB classes on {dev} ---");
    let classes = conn.get_classes_by_name(dev).await?;
    let htb: Vec<_> = classes.iter().filter(|c| c.kind() == Some("htb")).collect();
    for c in &htb {
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
    println!(
        "  ({} HTB classes total — 1 parent + N rules + 1 default)",
        htb.len()
    );
    Ok(())
}

fn print_overview() {
    println!("=== Rate Limiting ===\n");
    println!("Two high-level helpers on top of TC:\n");
    println!("  * RateLimiter      — interface-wide egress/ingress shaping");
    println!("                       (HTB + fq_codel; IFB on ingress)");
    println!("  * PerHostLimiter   — per-IP/subnet/port rate limits");
    println!("                       (HTB tree + flower filters)");
    println!();

    println!("--- RateLimiter usage ---\n");
    println!(
        r#"    use nlink::Rate;
    use nlink::netlink::ratelimit::RateLimiter;
    use std::time::Duration;

    // Typed Rate — no unit confusion (100 Mbps decimal, not Mebibits).
    RateLimiter::new("eth0")
        .egress(Rate::mbit(100))
        .ingress(Rate::gbit(1))
        .burst_to(Rate::mbit(150))
        .latency(Duration::from_millis(20))
        .apply(&conn)
        .await?;

    // Or parse tc-style strings:
    RateLimiter::new("eth0").egress("100mbit".parse()?).apply(&conn).await?;

    // Remove:
    RateLimiter::new("eth0").remove(&conn).await?;
"#
    );

    println!("--- PerHostLimiter usage ---\n");
    println!(
        r#"    use nlink::Rate;
    use nlink::netlink::ratelimit::PerHostLimiter;

    PerHostLimiter::new("eth0", Rate::mbit(10))        // default rate
        .limit_ip("192.168.1.100".parse()?, Rate::mbit(100))  // VIP
        .limit_subnet("10.0.0.0/8", Rate::mbit(50))?         // internal
        .limit_port(80, Rate::mbit(500))                     // HTTP boost
        .apply(&conn)
        .await?;
"#
    );

    println!("--- Caveats ---\n");
    println!("  * apply() is destructive on the device's root qdisc.");
    println!("  * Ingress limiting needs an IFB device (auto-created as");
    println!("    `ifb_<dev>`). cls_flower must be loaded for PerHostLimiter.");
    println!("  * For a reconcile loop (k8s operators, lab controllers),");
    println!("    both `RateLimiter`-adjacent recipes —");
    println!("    `PerPeerImpairer::reconcile()` and");
    println!("    `PerHostLimiter::reconcile()` — give you the no-op");
    println!("    idempotency property: zero kernel calls when the config");
    println!("    hasn't changed. See Plan 131 and");
    println!("    `docs/recipes/per-peer-impairment.md`.");
}
