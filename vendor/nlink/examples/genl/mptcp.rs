//! MPTCP (Multipath TCP) path-manager — full endpoint lifecycle.
//!
//! Demonstrates the write-path of `Connection::<Mptcp>`: adding
//! endpoints bound to an interface, setting per-namespace limits,
//! dumping, updating flags, and cleaning up — all inside a temporary
//! namespace with a dummy interface.
//!
//! Run modes:
//!
//! ```bash
//! # Print usage patterns + API overview (no privileges)
//! cargo run -p nlink --example genl_mptcp
//!
//! # Read-only probe of endpoints + limits in the current namespace
//! cargo run -p nlink --example genl_mptcp -- show
//!
//! # Create dummy + add endpoints + set limits + dump + cleanup in a
//! # temporary namespace. Requires root (CAP_NET_ADMIN) and a Linux
//! # 5.6+ kernel with CONFIG_MPTCP=y / CONFIG_MPTCP_IPV6=y.
//! sudo cargo run -p nlink --example genl_mptcp -- --apply
//! ```
//!
//! See also: `nlink::netlink::genl::mptcp::{MptcpEndpointBuilder,
//! MptcpLimits, MptcpFlags}`.

use std::net::Ipv4Addr;

use nlink::netlink::{
    Connection, Mptcp, Route,
    genl::mptcp::{MptcpEndpoint, MptcpEndpointBuilder, MptcpFlags, MptcpLimits},
    link::DummyLink,
    namespace,
};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("show") => run_show().await?,
        Some("--apply") => run_apply().await?,
        _ => print_overview(),
    }

    Ok(())
}

fn print_overview() {
    println!("=== MPTCP path-manager ===\n");
    println!("Endpoints tell the kernel which local addresses to advertise");
    println!("(signal) and which to initiate subflows from (subflow). The");
    println!("same API also sets per-namespace limits.\n");

    println!("--- What --apply does ---\n");
    println!(
        "    1. Create a temporary namespace.
    2. Create dummy0 + add 10.200.0.1/24 + bring up.
    3. add_endpoint #1 bound to dummy0 (signal+subflow).
    4. add_endpoint #2 (signal+backup) — backup path.
    5. set_limits: subflows=4, add_addr_accepted=4.
    6. get_endpoints + get_limits to verify the round-trip.
    7. Update endpoint #1 flags (flip to backup).
    8. del_endpoint(#1), then flush_endpoints.
    9. Delete the namespace.
"
    );

    println!("--- Code ---\n");
    println!(
        r#"    use nlink::netlink::{{Connection, Mptcp, namespace}};
    use nlink::netlink::genl::mptcp::{{MptcpEndpointBuilder, MptcpLimits}};

    let conn: Connection<Mptcp> =
        nlink::Connection::new_in_async("lab").await?;

    conn.add_endpoint(
        MptcpEndpointBuilder::new("10.200.0.1".parse()?)
            .id(1)
            .ifindex(dummy_ifindex)   // resolved via a Connection<Route> in the same netns
            .signal()
            .subflow(),
    ).await?;

    conn.set_limits(
        MptcpLimits::new().subflows(4).add_addr_accepted(4),
    ).await?;

    let endpoints = conn.get_endpoints().await?;
    for ep in &endpoints {{ /* ... */ }}

    conn.del_endpoint(1).await?;
    conn.flush_endpoints().await?;
"#
    );

    println!("--- Flag cheat sheet ---");
    println!("  signal   — advertise this address to the peer");
    println!("  subflow  — initiate subflows from this address");
    println!("  backup   — only used when primary paths fail");
    println!("  fullmesh — initiate subflows to every peer address");
    println!();
    println!("--- Re-run with `--apply` (as root) ---");
    println!("  Runs the lifecycle above in a temporary namespace.");
}

async fn run_show() -> nlink::Result<()> {
    let conn = match Connection::<Mptcp>::new_async().await {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("Failed to open MPTCP GENL: {e}");
            eprintln!("Requires Linux 5.6+ with CONFIG_MPTCP enabled.");
            eprintln!("Check: cat /proc/sys/net/mptcp/enabled");
            return Ok(());
        }
    };

    println!("MPTCP PM family_id={}\n", conn.family_id());

    match conn.get_limits().await {
        Ok(limits) => {
            println!("limits:");
            println!("  subflows:           {:?}", limits.subflows);
            println!("  add_addr_accepted:  {:?}", limits.add_addr_accepted);
            println!();
        }
        Err(e) => println!("get_limits failed: {e}\n"),
    }

    match conn.get_endpoints().await {
        Ok(endpoints) if endpoints.is_empty() => println!("No endpoints configured."),
        Ok(endpoints) => {
            println!("endpoints:");
            for ep in &endpoints {
                print_endpoint(ep);
            }
        }
        Err(e) => eprintln!("get_endpoints failed: {e}"),
    }

    Ok(())
}

async fn run_apply() -> nlink::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("--apply requires root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }

    println!("=== MPTCP live demo (temporary namespace) ===");

    let ns_name = format!("nlink-mptcp-demo-{}", std::process::id());
    namespace::create(&ns_name)?;

    let result = run_demo(&ns_name).await;

    let _ = namespace::delete(&ns_name);
    result?;

    println!();
    println!("Done. Namespace `{ns_name}` removed.");
    Ok(())
}

async fn run_demo(ns_name: &str) -> nlink::Result<()> {
    // Dummy interface + address inside the namespace.
    let route: Connection<Route> = nlink::Connection::new_in(ns_name)?;
    route.add_link(DummyLink::new("dummy0")).await?;
    route
        .add_address_by_name("dummy0", Ipv4Addr::new(10, 200, 0, 1).into(), 24)
        .await?;
    route.set_link_up("dummy0").await?;
    let link = route
        .get_link_by_name("dummy0")
        .await?
        .expect("just created");
    println!(
        "  Created dummy0 (ifindex {}) with 10.200.0.1/24 in `{ns_name}`.",
        link.ifindex()
    );

    let mptcp: Connection<Mptcp> = match nlink::Connection::new_in_async(ns_name).await {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("\n  Failed to open MPTCP GENL in namespace: {e}");
            eprintln!("  Requires Linux 5.6+ with CONFIG_MPTCP=y.");
            return Err(e);
        }
    };
    println!(
        "  Opened MPTCP GENL connection (family_id={}).",
        mptcp.family_id()
    );

    // Start clean in case the PM has stale state from an earlier run.
    let _ = mptcp.flush_endpoints().await;

    // Resolve the interface through a connection in *this namespace*.
    // `MptcpEndpointBuilder` takes an ifindex, not a name: a
    // `Connection<Mptcp>` cannot resolve a name in its own netns, and
    // resolving it in the calling process's netns would silently bind
    // the endpoint to a different interface (#275).
    let dummy_ifindex = route
        .get_link_by_name("dummy0")
        .await?
        .ok_or_else(|| nlink::Error::interface_not_found("dummy0"))?
        .ifindex();

    println!();
    println!("  add_endpoint #1: 10.200.0.1 dev=dummy0 flags=signal,subflow");
    mptcp
        .add_endpoint(
            MptcpEndpointBuilder::new(Ipv4Addr::new(10, 200, 0, 1).into())
                .id(1)
                .ifindex(dummy_ifindex)
                .signal()
                .subflow(),
        )
        .await?;

    println!("  add_endpoint #2: 10.200.0.2 dev=dummy0 flags=signal,backup");
    mptcp
        .add_endpoint(
            MptcpEndpointBuilder::new(Ipv4Addr::new(10, 200, 0, 2).into())
                .id(2)
                .ifindex(dummy_ifindex)
                .signal()
                .backup(),
        )
        .await?;

    println!("  set_limits: subflows=4 add_addr_accepted=4");
    mptcp
        .set_limits(MptcpLimits::new().subflows(4).add_addr_accepted(4))
        .await?;

    println!();
    println!("  --- get_limits ---");
    let limits = mptcp.get_limits().await?;
    println!(
        "    subflows={:?} add_addr_accepted={:?}",
        limits.subflows, limits.add_addr_accepted
    );

    println!();
    println!("  --- get_endpoints ---");
    for ep in &mptcp.get_endpoints().await? {
        print_endpoint(ep);
    }

    println!();
    println!("  Flipping endpoint #1 flags to backup-only...");
    mptcp
        .set_endpoint_flags(
            1,
            MptcpFlags {
                backup: true,
                ..Default::default()
            },
        )
        .await?;

    println!("  del_endpoint(1)...");
    mptcp.del_endpoint(1).await?;

    let after_del = mptcp.get_endpoints().await?;
    println!("  After del: {} endpoint(s) remaining.", after_del.len());

    println!("  flush_endpoints()...");
    mptcp.flush_endpoints().await?;

    let after_flush = mptcp.get_endpoints().await?;
    println!(
        "  After flush: {} endpoint(s) remaining.",
        after_flush.len()
    );

    Ok(())
}

fn print_endpoint(ep: &MptcpEndpoint) {
    let mut flags = Vec::new();
    if ep.flags.signal {
        flags.push("signal");
    }
    if ep.flags.subflow {
        flags.push("subflow");
    }
    if ep.flags.backup {
        flags.push("backup");
    }
    if ep.flags.fullmesh {
        flags.push("fullmesh");
    }
    let flag_str = if flags.is_empty() {
        "-".to_string()
    } else {
        flags.join(",")
    };

    let mut line = format!("    id={} addr={}", ep.id, ep.address);
    if let Some(port) = ep.port {
        line.push_str(&format!(":{port}"));
    }
    if let Some(ifindex) = ep.ifindex {
        line.push_str(&format!(" ifindex={ifindex}"));
    }
    line.push_str(&format!(" flags=[{flag_str}]"));
    println!("{line}");
}
