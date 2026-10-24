//! `net_shaper` enumeration via the typed `Connection<NetShaper>`
//! API.
//!
//! On hosts with kernel 6.13+ and a shaper-capable NIC (Intel
//! `ice` E810 / E830, Mellanox `mlx5` ConnectX-7+, NVIDIA
//! BlueField, …) this prints every TX shaper installed on the
//! given interface plus the driver-reported capabilities at each
//! scope (netdev / queue / node). On hosts without shaper
//! hardware it prints a brief notice and exits cleanly.
//!
//! Run modes:
//!
//! ```bash
//! # Print overview + API walkthrough (no kernel call).
//! cargo run -p nlink --example genl_net_shaper
//!
//! # Probe interface <ifname> and dump shapers + caps.
//! # Read paths only — no CAP_NET_ADMIN required.
//! cargo run -p nlink --example genl_net_shaper -- show <ifname>
//! ```
//!
//! See `docs/recipes/tx-hw-shaping.md` for the canonical
//! "rate-limit a SR-IOV VF's TX queues" pattern.

use nlink::netlink::{
    genl::net_shaper::{NetShaper, NetShaperScope},
    Connection, Route,
};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("show"), Some(ifname)) => run_show(ifname).await,
        _ => {
            print_overview();
            Ok(())
        }
    }
}

fn print_overview() {
    println!("=== net_shaper via nlink-macros (Plan 153 §4.3) ===\n");
    println!("Reads the kernel's TX hardware shaping family. Full");
    println!("per-queue rate-limiting setup in under 20 lines:\n");
    println!("    use nlink::netlink::{{Connection, genl::net_shaper::*}};");
    println!();
    println!("    let conn = Connection::<NetShaper>::new_async().await?;");
    println!("    let caps = conn.get_caps(ifindex, NetShaperScope::Queue).await?;");
    println!("    if caps.support_bw_max {{");
    println!("        conn.set_shaper(");
    println!("            NetShaperSetRequest::new(ifindex, NetShaperHandle::queue(0))");
    println!("                .metric(NetShaperMetric::Bps)");
    println!("                .bw_max(1_000_000_000)   // 1 Gbit/s cap",);
    println!("                .burst(1 << 16),");
    println!("        ).await?;");
    println!("    }}\n");
    println!("--- What `show <ifname>` does ---\n");
    println!("    1. Connects to NETLINK_GENERIC + resolves the");
    println!("       \"net-shaper\" family ID via CTRL_CMD_GETFAMILY.");
    println!("    2. Resolves <ifname> → ifindex via rtnetlink.");
    println!("    3. Streams every shaper installed on the interface");
    println!("       (dump_shapers). Prints scope, id, parent, metric,");
    println!("       bw_min/max, burst, priority, weight.");
    println!("    4. Dumps the driver-supported feature set per scope");
    println!("       (dump_caps).\n");
    println!("    Both read paths are unprivileged. set/del/group");
    println!("    require CAP_NET_ADMIN; this example never mutates.\n");
    println!("    On kernels without net_shaper (< 6.13 or");
    println!("    CONFIG_NET_SHAPER=n) this prints a notice and exits.");
}

async fn run_show(ifname: &str) -> nlink::Result<()> {
    println!("→ Connection::<NetShaper>::new_async()");
    let conn = match Connection::<NetShaper>::new_async().await {
        Ok(c) => c,
        Err(e) if e.is_not_found() => {
            eprintln!(
                "net-shaper family not registered on this kernel — needs Linux \
                 6.13+ with CONFIG_NET_SHAPER. (Stock distro kernels rarely \
                 enable it yet.)"
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    println!("  family_id resolved\n");

    println!("→ resolve {ifname} → ifindex");
    let route = Connection::<Route>::new()?;
    let link = match route.get_link_by_name(ifname).await? {
        Some(l) => l,
        None => {
            eprintln!("  no interface named {ifname:?}");
            return Ok(());
        }
    };
    let ifindex = link.ifindex();
    println!("  ifindex = {ifindex}\n");

    println!("=== shapers on {ifname} ===");
    let mut stream = match conn.dump_shapers(ifindex).await {
        Ok(s) => s,
        Err(e) if e.is_permission_denied() => {
            eprintln!("  EPERM — net-shaper queries require CAP_NET_ADMIN here");
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    let mut shaper_count = 0;
    while let Some(s) = stream.next().await {
        let s = match s {
            Ok(s) => s,
            Err(e) if e.is_not_supported() => {
                println!(
                    "  EOPNOTSUPP — driver for {ifname} doesn't expose shapers \
                     (common on loopback, virtual ifaces, and older NICs)"
                );
                print_caps(&conn, ifindex).await?;
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        shaper_count += 1;
        let scope = s
            .handle
            .as_ref()
            .and_then(|h| h.scope)
            .map(|sc| format!("{sc:?}"))
            .unwrap_or_else(|| "?".into());
        let id = s.handle.as_ref().and_then(|h| h.id).unwrap_or(0);
        let parent = s
            .parent
            .as_ref()
            .map(|p| format!("{:?}/{}", p.scope, p.id.unwrap_or(0)))
            .unwrap_or_else(|| "(root)".into());
        println!(
            "  [{scope:>6}/{id}] parent={parent} metric={:?} bw_min={:?} bw_max={:?} \
             burst={:?} prio={:?} weight={:?}",
            s.metric, s.bw_min, s.bw_max, s.burst, s.priority, s.weight,
        );
    }
    if shaper_count == 0 {
        println!("  (no shapers installed)");
    }
    println!();

    print_caps(&conn, ifindex).await?;

    let _ = NetShaperScope::Node;
    Ok(())
}

async fn print_caps(conn: &Connection<NetShaper>, ifindex: u32) -> nlink::Result<()> {
    println!("=== driver capabilities (per scope) ===");
    let mut caps = conn.dump_caps(ifindex).await?;
    let mut cap_count = 0;
    while let Some(c) = caps.next().await {
        let c = match c {
            Ok(c) => c,
            Err(e) if e.is_not_supported() => {
                println!("  EOPNOTSUPP — driver doesn't implement cap-get");
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        cap_count += 1;
        let scope = c
            .scope
            .map(|sc| format!("{sc:?}"))
            .unwrap_or_else(|| "?".into());
        let mut supported: Vec<&str> = Vec::new();
        if c.support_metric_bps {
            supported.push("bps");
        }
        if c.support_metric_pps {
            supported.push("pps");
        }
        if c.support_nesting {
            supported.push("nesting");
        }
        if c.support_bw_min {
            supported.push("bw_min");
        }
        if c.support_bw_max {
            supported.push("bw_max");
        }
        if c.support_burst {
            supported.push("burst");
        }
        if c.support_priority {
            supported.push("priority");
        }
        if c.support_weight {
            supported.push("weight");
        }
        println!("  [{scope:>6}] supports: {}", supported.join(", "));
    }
    if cap_count == 0 {
        println!(
            "  (driver reports no shaper capabilities — most often means the \
             driver lacks net_shaper integration)"
        );
    }
    Ok(())
}
