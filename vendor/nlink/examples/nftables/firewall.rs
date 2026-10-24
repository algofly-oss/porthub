//! nftables firewall management example.
//!
//! Demonstrates creating tables, chains, rules, and sets using
//! the Connection<Nftables> API.
//!
//! Run with: cargo run -p nlink --example nftables_firewall
//!
//! Requires root privileges.

use std::net::Ipv4Addr;

use nlink::netlink::{
    Connection, Nftables,
    nftables::{
        BaseChain, Chain, CtState, Family, FilterHook, LimitUnit, Policy, Priority, Rule, Set,
        SetElement, SetKeyType,
    },
};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    // Plan 210 H10 — pre-0.19 this example had no root check;
    // non-root invocation got partway through then errored with
    // EPERM, leaving the `example` nftables table behind on any
    // host that already had the unprivileged_ports sysctl
    // permissive. Now skip cleanly.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "nftables_firewall example requires root (CAP_NET_ADMIN). \
             Run with `sudo` to actually create the firewall, or skip."
        );
        return Ok(());
    }

    let conn = Connection::<Nftables>::new()?;

    // List existing tables
    println!("=== Existing Tables ===");
    let tables = conn.list_tables().await?;
    for table in &tables {
        println!("  {} ({:?})", table.name, table.family);
    }

    // Plan 210 H10 — wrap the demo body so cleanup runs even if
    // a mid-flight op fails (leaving the `example` table in the
    // kernel). Pre-0.19 the example used `?` throughout and the
    // teardown was unreachable on partial failure.
    let result = run_demo(&conn).await;

    // Cleanup unconditionally — `flush_table` + `del_table` are
    // best-effort, so failures here don't override the body's
    // result.
    let _ = conn.flush_table("example", Family::Inet).await;
    let _ = conn.del_table("example", Family::Inet).await;
    println!("\nCleaned up example table.");

    result
}

async fn run_demo(conn: &Connection<Nftables>) -> nlink::netlink::Result<()> {
    // Create a filter table with input chain
    println!("\n=== Creating Firewall ===");

    conn.add_table("example", Family::Inet).await?;
    println!("Created table: example");

    conn.add_chain(
        Chain::new("example", "input")?
            .family(Family::Inet)
            .base(BaseChain::filter(FilterHook::Input, Priority::Filter).policy(Policy::Drop)),
    )
    .await?;
    println!("Created chain: input (policy drop)");

    // Allow established/related connections
    conn.add_rule(
        Rule::new("example", "input")
            .family(Family::Inet)
            .match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
            .accept(),
    )
    .await?;
    println!("Added rule: allow established/related");

    // Allow SSH
    conn.add_rule(
        Rule::new("example", "input")
            .family(Family::Inet)
            .match_tcp_dport(22)
            .counter()
            .accept(),
    )
    .await?;
    println!("Added rule: allow SSH (port 22)");

    // Allow ICMP echo requests (ping)
    conn.add_rule(
        Rule::new("example", "input")
            .family(Family::Inet)
            .match_icmp_type(8) // echo-request
            .accept(),
    )
    .await?;
    println!("Added rule: allow ICMP echo-request");

    // Allow ICMPv6 neighbor discovery
    conn.add_rule(
        Rule::new("example", "input")
            .family(Family::Inet)
            .match_icmpv6_type(135) // neighbor solicitation
            .accept(),
    )
    .await?;
    println!("Added rule: allow ICMPv6 neighbor solicitation");

    // Rate-limit HTTP traffic
    conn.add_rule(
        Rule::new("example", "input")
            .family(Family::Inet)
            .match_tcp_dport(80)
            .limit(100, LimitUnit::Second)
            .accept(),
    )
    .await?;
    println!("Added rule: rate-limit HTTP (100/sec)");

    // Block traffic NOT from 10.0.0.0/8 on port 443
    conn.add_rule(
        Rule::new("example", "input")
            .family(Family::Inet)
            .match_saddr_v4_not(Ipv4Addr::new(10, 0, 0, 0), 8)
            .match_tcp_dport(443)
            .log(Some("blocked-https: "))
            .drop(),
    )
    .await?;
    println!("Added rule: block non-10.0.0.0/8 on HTTPS");

    // Match by packet mark
    conn.add_rule(
        Rule::new("example", "input")
            .family(Family::Inet)
            .match_mark(0x42)
            .accept(),
    )
    .await?;
    println!("Added rule: accept marked packets (0x42)");

    // Create a set of allowed IPs. The element calls take the `Set`, since
    // how an element is written depends on the set's key type and flags.
    let allowed = Set::new("example", "allowed_ips")
        .family(Family::Inet)
        .key_type(SetKeyType::Ipv4Addr);
    conn.add_set(allowed.clone()).await?;

    conn.add_set_elements(
        &allowed,
        &[
            SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            SetElement::ipv4(Ipv4Addr::new(192, 168, 1, 0)),
        ],
    )
    .await?;
    println!("Created set: allowed_ips with 2 entries");

    // List rules with decoded expressions (#164). Dumped rules carry
    // their expressions as raw bytes; `RuleInfo::expressions()`
    // decodes them into typed `RuleExpr`s — most usefully the live
    // counter values — and `RuleInfo::counter()` is the shortcut for
    // per-rule hit/byte counters.
    println!("\n=== Rules (decoded) ===");
    let rules = conn.list_rules("example", Family::Inet).await?;
    for rule in &rules {
        let counter = rule
            .counter()
            .map(|(packets, bytes)| format!("{packets} pkts / {bytes} bytes"))
            .unwrap_or_else(|| "no counter".into());
        let kinds: Vec<&str> = rule
            .expressions()
            .iter()
            .map(|e| match e {
                nlink::netlink::nftables::RuleExpr::Counter { .. } => "counter",
                nlink::netlink::nftables::RuleExpr::Verdict(_) => "verdict",
                nlink::netlink::nftables::RuleExpr::Meta { .. } => "meta",
                nlink::netlink::nftables::RuleExpr::Cmp { .. } => "cmp",
                nlink::netlink::nftables::RuleExpr::Immediate { .. } => "immediate",
                nlink::netlink::nftables::RuleExpr::Payload { .. } => "payload",
                _ => "other",
            })
            .collect();
        println!(
            "  chain={} handle={} [{}] — {}",
            rule.chain,
            rule.handle,
            kinds.join(" "),
            counter
        );
    }

    Ok(())
}
