//! Connection tracking — full lifecycle demo.
//!
//! Demonstrates the ctnetlink mutation API on top of the existing dump
//! path: inject a synthetic TCP entry, query it back, update mark +
//! timeout in place, delete the dumped entry, inject a UDP entry,
//! delete it by tuple, then flush.
//!
//! Run modes:
//!
//! ```bash
//! # Print usage and a code skeleton (no privileges)
//! cargo run -p nlink --example netfilter_conntrack
//!
//! # Dump the current host conntrack table (no privileges beyond
//! # netlink read access)
//! cargo run -p nlink --example netfilter_conntrack -- show
//!
//! # Run the full inject/query/update/delete/flush lifecycle inside a
//! # temporary namespace. Requires root (CAP_NET_ADMIN) plus the
//! # `nf_conntrack` and `nf_conntrack_netlink` kernel modules.
//! sudo cargo run -p nlink --example netfilter_conntrack -- --apply
//! ```
//!
//! See also: `nlink::netlink::netfilter::ConntrackBuilder`,
//! `docs/recipes/conntrack-programmatic.md`, and the
//! `nftables-stateful-fw` recipe that pairs nftables `ct state` rules
//! with this dump path.

use std::{env, net::Ipv4Addr, time::Duration};

use nlink::netlink::{
    Connection, Netfilter, namespace,
    netfilter::{ConntrackBuilder, ConntrackStatus, ConntrackTuple, IpProtocol, TcpConntrackState},
};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("show") => {
            let conn = Connection::<Netfilter>::new()?;
            show_table(&conn).await?;
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
    println!("=== Conntrack lifecycle (ctnetlink mutation API) ===\n");
    println!("Connection<Netfilter> exposes both the dump path");
    println!("(get_conntrack / get_conntrack_v6) and the mutation path");
    println!("(add / update / del / flush) on the same socket.\n");

    println!("--- Code skeleton ---\n");
    println!(
        r#"    use std::time::Duration;
    use std::net::Ipv4Addr;
    use nlink::netlink::{{Connection, Netfilter}};
    use nlink::netlink::netfilter::{{
        ConntrackBuilder, ConntrackStatus, ConntrackTuple,
        IpProtocol, TcpConntrackState,
    }};

    let nf = Connection::<Netfilter>::new()?;

    // Inject a TCP/ESTABLISHED entry. CONFIRMED is mandatory; the
    // reply tuple is auto-mirrored from orig.
    nf.add_conntrack(
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(
                ConntrackTuple::v4(
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 2),
                ).ports(40000, 80),
            )
            .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
            .timeout(Duration::from_secs(120))
            .mark(0x42)
            .tcp_state(TcpConntrackState::Established),
    ).await?;

    // Find it in the dump.
    let entries = nf.get_conntrack().await?;
    let injected = entries.iter().find(|e| e.orig.dst_port == Some(80)).unwrap();

    // Delete exactly that entry: its tuple, zone and id.
    nf.del_conntrack_entry(injected).await?;
"#
    );

    println!("--- Modes ---\n");
    println!("  show          — Dump the host's current conntrack table");
    println!("  --apply       — Run the full lifecycle inside a temp namespace");
    println!();
    println!("--- Required kernel modules ---\n");
    println!("  modprobe nf_conntrack");
    println!("  modprobe nf_conntrack_netlink   # autoloaded on first request");
    println!();
    println!("See docs/recipes/conntrack-programmatic.md for a full walk-through.");
}

async fn run_apply() -> nlink::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("--apply requires root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }

    println!("=== Conntrack live demo (temporary namespace) ===");

    let ns_name = format!("nlink-conntrack-demo-{}", std::process::id());
    namespace::create(&ns_name)?;

    let result = run_demo(&ns_name).await;

    let _ = namespace::delete(&ns_name);
    result?;

    println!();
    println!("Done. Namespace `{ns_name}` removed.");
    Ok(())
}

async fn run_demo(ns_name: &str) -> nlink::Result<()> {
    let nf: Connection<Netfilter> = nlink::Connection::new_in(ns_name)?;
    println!("  Opened Connection<Netfilter> in namespace `{ns_name}`.");

    // 1. Inject — TCP/ESTABLISHED with auto-mirrored reply tuple.
    let orig =
        ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)).ports(40000, 80);
    println!();
    println!("  Step 1: inject TCP 10.0.0.1:40000 -> 10.0.0.2:80 (state=ESTABLISHED, mark=0x42)");
    nf.add_conntrack(
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(orig.clone())
            .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
            .timeout(Duration::from_secs(120))
            .mark(0x42)
            .tcp_state(TcpConntrackState::Established),
    )
    .await
    .map_err(|e| {
        eprintln!(
            "  ! add_conntrack failed: {e}\n  ! is `nf_conntrack` loaded?  modprobe nf_conntrack"
        );
        e
    })?;
    println!("    add_conntrack OK");

    // 2. Dump and find it.
    println!();
    println!("  Step 2: dump the table and locate the injected entry");
    let entries = nf.get_conntrack().await?;
    let injected = entries
        .iter()
        .find(|e| {
            e.proto == IpProtocol::Tcp
                && e.orig.src_port == Some(40000)
                && e.orig.dst_port == Some(80)
        })
        .ok_or_else(|| {
            nlink::Error::invalid_message("injected TCP entry not found in dump")
        })?;
    let id = injected.id.expect("kernel always assigns an id");
    println!(
        "    found id={id} mark={:?} state={:?} timeout={:?}s",
        injected.mark, injected.tcp_state, injected.timeout
    );
    assert_eq!(injected.mark, Some(0x42), "mark should round-trip");
    assert_eq!(
        injected.tcp_state,
        Some(TcpConntrackState::Established),
        "tcp_state should round-trip"
    );

    // 3. Update mark + timeout in place.
    println!();
    println!("  Step 3: update mark (0x42 -> 0x99) and shrink timeout (120s -> 60s)");
    nf.update_conntrack(
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(orig.clone())
            .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
            .timeout(Duration::from_secs(60))
            .mark(0x99)
            .tcp_state(TcpConntrackState::Established),
    )
    .await?;
    let updated = find_entry(&nf, IpProtocol::Tcp, 40000, 80).await?;
    println!(
        "    after update: mark={:?} timeout={:?}s (kernel may have already counted down a bit)",
        updated.mark, updated.timeout
    );
    assert_eq!(updated.mark, Some(0x99), "updated mark should round-trip");

    // 4. Delete the dumped entry: its tuple, zone and id.
    println!();
    println!("  Step 4: delete the dumped entry (id {id})");
    nf.del_conntrack_entry(&updated).await?;
    let still_there = find_entry(&nf, IpProtocol::Tcp, 40000, 80).await.ok();
    assert!(still_there.is_none(), "entry should be gone after delete");
    println!("    confirmed: TCP entry no longer in dump");

    // 5. Inject a UDP entry, delete by tuple this time.
    let udp_orig =
        ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)).ports(53000, 53);
    println!();
    println!("  Step 5: inject UDP 10.0.0.1:53000 -> 10.0.0.2:53, then delete by tuple");
    nf.add_conntrack(
        ConntrackBuilder::new_v4(IpProtocol::Udp)
            .orig(udp_orig.clone())
            .status(ConntrackStatus::CONFIRMED)
            .timeout(Duration::from_secs(30)),
    )
    .await?;
    nf.del_conntrack(ConntrackBuilder::new_v4(IpProtocol::Udp).orig(udp_orig.clone()))
        .await?;
    let udp_left = find_entry(&nf, IpProtocol::Udp, 53000, 53).await.ok();
    assert!(
        udp_left.is_none(),
        "UDP entry should be gone after del_conntrack"
    );
    println!("    UDP entry deleted by tuple");

    // 6. Inject two more, then flush the IPv4 table. Note the
    //    explicit timeout — the kernel rejects a TCP add with
    //    `tcp_state` set but no timeout (EINVAL). It needs the
    //    timeout for the state-machine bookkeeping.
    println!();
    println!("  Step 6: inject 2 fresh entries, then flush_conntrack()");
    for src_port in [41000u16, 41001] {
        nf.add_conntrack(
            ConntrackBuilder::new_v4(IpProtocol::Tcp)
                .orig(
                    ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
                        .ports(src_port, 8080),
                )
                .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
                .timeout(Duration::from_secs(60))
                .tcp_state(TcpConntrackState::Established),
        )
        .await
        .map_err(|e| {
            eprintln!("  ! add_conntrack(src_port={src_port}) failed: {e}");
            e
        })?;
    }
    let before_flush = nf.get_conntrack().await?.len();
    nf.flush_conntrack().await?;
    let after_flush = nf.get_conntrack().await?.len();
    println!("    entries before flush: {before_flush}, after flush: {after_flush}");
    assert!(
        after_flush <= 1,
        "flush should empty the v4 table (kernel-internal placeholder may remain)"
    );

    Ok(())
}

async fn find_entry(
    nf: &Connection<Netfilter>,
    proto: IpProtocol,
    src_port: u16,
    dst_port: u16,
) -> nlink::Result<nlink::netlink::netfilter::ConntrackEntry> {
    let entries = nf.get_conntrack().await?;
    entries
        .into_iter()
        .find(|e| {
            e.proto == proto
                && e.orig.src_port == Some(src_port)
                && e.orig.dst_port == Some(dst_port)
        })
        .ok_or_else(|| {
            nlink::Error::invalid_message("expected conntrack entry not found in dump")
        })
}

async fn show_table(nf: &Connection<Netfilter>) -> nlink::Result<()> {
    println!("=== Host conntrack table (IPv4) ===\n");
    let entries = nf.get_conntrack().await?;
    if entries.is_empty() {
        println!("(empty — generate some traffic, or run `--apply` for an injected entry)");
        return Ok(());
    }
    println!(
        "{:<6} {:<22} {:<22} {:<12} {:<8}",
        "PROTO", "SOURCE", "DESTINATION", "STATE", "TIMEOUT"
    );
    println!("{}", "-".repeat(75));
    for entry in &entries {
        let proto = match entry.proto {
            IpProtocol::Tcp => "tcp",
            IpProtocol::Udp => "udp",
            IpProtocol::Icmp => "icmp",
            IpProtocol::Icmpv6 => "icmpv6",
            IpProtocol::Other(_) => "other",
            _ => "?",
        };
        let src = format!(
            "{}:{}",
            entry
                .orig
                .src_ip
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            entry.orig.src_port.unwrap_or(0)
        );
        let dst = format!(
            "{}:{}",
            entry
                .orig
                .dst_ip
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            entry.orig.dst_port.unwrap_or(0)
        );
        let state = entry
            .tcp_state
            .map(|s| match s {
                TcpConntrackState::Established => "ESTABLISHED",
                TcpConntrackState::SynSent => "SYN_SENT",
                TcpConntrackState::SynRecv => "SYN_RECV",
                TcpConntrackState::FinWait => "FIN_WAIT",
                TcpConntrackState::CloseWait => "CLOSE_WAIT",
                TcpConntrackState::LastAck => "LAST_ACK",
                TcpConntrackState::TimeWait => "TIME_WAIT",
                TcpConntrackState::Close => "CLOSE",
                TcpConntrackState::Listen => "LISTEN",
                _ => "-",
            })
            .unwrap_or("-");
        let timeout = entry.timeout.map(|t| format!("{}s", t)).unwrap_or_default();
        println!(
            "{:<6} {:<22} {:<22} {:<12} {:<8}",
            proto, src, dst, state, timeout
        );
    }
    println!("\nTotal: {} entries", entries.len());
    Ok(())
}
