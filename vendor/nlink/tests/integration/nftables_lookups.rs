//! Set lookups by packet field — IPv6 addresses, ports, `!= @set` — the raw
//! escape hatch, set-element / generation events, and sets whose elements
//! count what they match, each checked against real traffic or real
//! notifications.

use std::net::{Ipv4Addr, Ipv6Addr};

use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    BaseChain, Chain, CtState, Family, FilterHook, LimitUnit, PacketField, Priority, Rule, Set,
    SetElement, SetKeyType, SetPolicy,
};
use nlink::netlink::nftables::{
    ElementStatement, LimitExpr, NftablesEvent, QuotaExpr, RawExpr, RuleExpr,
};
use nlink::netlink::{Connection, Nftables};
use tokio_stream::StreamExt;

use crate::common::converge::assert_transition;
use crate::common::traffic::{lo_up, send_udp};
use crate::common::{TestNamespace, with_timeout};

/// An `inet t` table with an `output` filter chain `out`.
async fn add_output_chain(conn: &Connection<Nftables>) -> nlink::Result<()> {
    conn.add_table("t", Family::Inet).await?;
    conn.add_chain(
        Chain::new("t", "out")?
            .family(Family::Inet)
            .base(BaseChain::filter(FilterHook::Output, Priority::Filter)),
    )
    .await
}

async fn counted(conn: &Connection<Nftables>, index: usize) -> nlink::Result<u64> {
    let rules = conn.list_rules("t", Family::Inet).await?;
    Ok(rules[index].counter().expect("rule has a counter").0)
}

/// `ip6 daddr @s6` matches IPv6 traffic to a member — and the `meta nfproto
/// ipv6` guard keeps IPv4 traffic out of the lookup.
#[tokio::test]
async fn ip6_set_lookup_matches_ipv6_traffic() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-lk-ip6")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        add_output_chain(&conn).await?;
        let set = Set::new("t", "s6").key_type(SetKeyType::Ipv6Addr);
        conn.add_set(set.clone()).await?;
        conn.add_set_elements(&set, &[SetElement::ipv6(Ipv6Addr::LOCALHOST)])
            .await?;
        // UDP only: nothing listens on [::1]:9, so each datagram draws an
        // ICMPv6 port-unreachable to ::1 that would match too.
        conn.add_rule(
            Rule::new("t", "out")
                .match_l4proto(17)
                .match_in_set(PacketField::Ip6Daddr, "s6")
                .counter(),
        )
        .await?;

        send_udp(&ns, &["[::1]:9"], 3);
        send_udp(&ns, &["127.0.0.1:9"], 2);
        assert_eq!(counted(&conn, 0).await?, 3, "only the IPv6 datagrams match");
        Ok(())
    })
    .await
}

/// `udp dport @ports` counts traffic to member ports only.
#[tokio::test]
async fn port_set_lookup_matches_member_ports() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-lk-port")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        add_output_chain(&conn).await?;
        let set = Set::new("t", "ports").key_type(SetKeyType::InetService);
        conn.add_set(set.clone()).await?;
        conn.add_set_elements(&set, &[SetElement::port(9)]).await?;
        conn.add_rule(
            Rule::new("t", "out")
                .match_in_set(PacketField::UdpDport, "ports")
                .counter(),
        )
        .await?;

        send_udp(&ns, &["127.0.0.1:9"], 2);
        send_udp(&ns, &["127.0.0.1:10"], 4);
        assert_eq!(counted(&conn, 0).await?, 2);
        Ok(())
    })
    .await
}

/// `ip daddr != @s` counts only traffic to non-members.
#[tokio::test]
async fn inverted_lookup_counts_only_non_members() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-lk-inv")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        add_output_chain(&conn).await?;
        let set = Set::new("t", "s4").key_type(SetKeyType::Ipv4Addr);
        conn.add_set(set.clone()).await?;
        conn.add_set_elements(&set, &[SetElement::ipv4(Ipv4Addr::new(127, 0, 0, 2))])
            .await?;
        conn.add_rule(
            Rule::new("t", "out")
                .match_l4proto(17)
                .match_not_in_set(PacketField::Ip4Daddr, "s4")
                .counter(),
        )
        .await?;

        send_udp(&ns, &["127.0.0.1:9"], 3);
        send_udp(&ns, &["127.0.0.2:9"], 2);
        assert_eq!(counted(&conn, 0).await?, 3, "the member's datagrams must not count");
        Ok(())
    })
    .await
}

/// Adding elements is notified as `NewSetElements`, and every commit as
/// `NewGen` with a growing generation.
#[tokio::test]
async fn set_element_and_generation_events_arrive() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-lk-events")?;
    let conn = ns.connection_for::<Nftables>()?;
    let watcher = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        watcher.subscribe_all()?;
        let mut events = watcher.events().await;

        conn.add_table("t", Family::Inet).await?;
        let set = Set::new("t", "s").key_type(SetKeyType::Ipv4Addr);
        conn.add_set(set.clone()).await?;
        conn.add_set_elements(&set, &[SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 7))])
            .await?;

        let mut gens = Vec::new();
        let mut added = None;
        while added.is_none() || gens.len() < 2 {
            match events.next().await {
                Some(Ok(NftablesEvent::NewGen(g))) => gens.push(g.id),
                Some(Ok(NftablesEvent::NewSetElements(e))) => added = Some(e),
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e),
                None => break,
            }
        }
        let added = added.expect("no NewSetElements event");
        assert_eq!((added.table.as_str(), added.set.as_str()), ("t", "s"));
        assert_eq!(added.elements[0].key(), [10, 0, 0, 7]);
        assert!(gens.windows(2).all(|w| w[1] > w[0]), "generations grow: {gens:?}");
        Ok(())
    })
    .await
}

/// The raw escape hatch installs an expression nlink does not model —
/// `notrack`, which has no data nest at all — and a declared rule built
/// with it converges. Traffic proves it took effect: the packets leave
/// untracked.
#[tokio::test]
async fn a_raw_notrack_untracks_and_converges() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_ct");

    let ns = TestNamespace::new("nft-lk-raw")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let cfg = NftablesConfig::new().table("t", Family::Inet, |t| {
            t.chain("raw", |c| {
                c.base(BaseChain::filter(FilterHook::Output, Priority::Raw))
            })
            .chain("out", |c| {
                c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
            })
            .rule_keyed("raw", "notrack", |r| {
                r.match_udp_dport(9).expr(RawExpr::without_data("notrack"))
            })
            .rule_keyed("out", "untracked", |r| {
                r.match_udp_dport(9)
                    .match_ct_state(CtState::UNTRACKED)
                    .counter()
            })
        });
        cfg.diff(&conn).await?.apply(&conn).await?;
        let again = cfg.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");

        send_udp(&ns, &["127.0.0.1:9"], 3);
        let rules = conn.list_rules("t", Family::Inet).await?;
        let untracked = rules
            .iter()
            .find(|r| r.key.as_deref() == Some("untracked"))
            .unwrap();
        assert!(untracked.counter().unwrap().0 >= 3, "packets were tracked");
        Ok(())
    })
    .await
}

// ============================================================================
// #703 — statements on every element, and the set policy
// ============================================================================

/// #703: sets whose elements each get a counter, a counter and a quota, or
/// a limit, one with `policy memory`, as nft writes them, decode typed, and
/// nlink installs the same: `nft` lists the two tables alike, before
/// traffic and after, when each element has counted what its lookup
/// matched — which nlink reads back too.
#[tokio::test]
async fn set_statements_and_policy_read_and_write_as_nft_does() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_quota", "nft_limit");

    let ns = TestNamespace::new("nft-setstmt")?;
    lo_up(&ns).await?;
    let script = "table inet a {
 set c { type ipv4_addr; counter; elements = { 127.0.0.1 } }
 set m { type ipv4_addr; size 100; policy memory; counter; quota 1000 bytes; elements = { 127.0.0.1 } }
 set l { type ipv4_addr; flags dynamic; limit rate 10/second; }
 chain out {
  type filter hook output priority 0;
  meta l4proto udp ip daddr @c
  meta l4proto udp ip daddr @m
 }
}
";
    let file = std::env::temp_dir().join(format!("nlink-setstmt-{}.nft", std::process::id()));
    std::fs::write(&file, script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed?;

    let conn = ns.connection_for::<Nftables>()?;
    conn.add_table("b", Family::Inet).await?;
    let quota = QuotaExpr::new(1000);
    for set in [
        Set::new("b", "c").counter(),
        Set::new("b", "m")
            .size(100)
            .policy(SetPolicy::Memory)
            .counter()
            .statement(quota.clone()),
        Set::new("b", "l")
            .dynamic()
            .statement(LimitExpr::packets(10, LimitUnit::Second)),
    ] {
        let set = set.family(Family::Inet);
        conn.add_set(set.clone()).await?;
        if set.name() != "l" {
            conn.add_set_elements(&set, &[SetElement::ipv4(Ipv4Addr::LOCALHOST)]).await?;
        }
    }
    conn.add_chain(
        Chain::new("b", "out")?
            .family(Family::Inet)
            .base(BaseChain::filter(FilterHook::Output, Priority::Filter)),
    )
    .await?;
    for set in ["c", "m"] {
        let rule = Rule::new("b", "out").family(Family::Inet).match_l4proto(17);
        conn.add_rule(rule.match_in_set(PacketField::Ip4Daddr, set)).await?;
    }
    let listed = |table: &str| -> nlink::Result<String> {
        let out = ns.exec("nft", &["list", "table", "inet", table])?;
        Ok(out.replacen(&format!("table inet {table}"), "table inet T", 1))
    };
    assert_eq!(listed("b")?, listed("a")?, "nlink's table b, nft's table a");

    send_udp(&ns, &["127.0.0.1:9"], 3);
    assert_eq!(listed("b")?, listed("a")?, "after traffic");
    for table in ["a", "b"] {
        let elements = conn.list_set_elements(table, "m", Family::Inet).await?;
        assert_eq!(elements.len(), 1);
        assert_eq!(elements[0].counter().map(|(packets, _)| packets), Some(3), "{table}");
        let (_, bytes) = elements[0].counter().unwrap();
        assert_eq!(elements[0].quota_used(), Some(bytes), "{table}");
    }

    let sets = conn.list_sets_in("a", Family::Inet).await?;
    let m = sets.iter().find(|s| s.name == "m").expect("set m");
    assert_eq!(m.policy, SetPolicy::Memory);
    let decoded: Vec<_> = m.statements.iter().filter(|e| !matches!(e, RuleExpr::Unknown { .. })).collect();
    assert_eq!(decoded.len(), 2, "{:?}", m.statements);
    Ok(())
}

/// `inet t`: UDP to a member of `hosts` is counted, and every member counts
/// its own, with a quota of `quota` bytes of its own.
fn counted_hosts(quota: u64, policy: Option<SetPolicy>) -> NftablesConfig {
    NftablesConfig::new().table("t", Family::Inet, move |t| {
        t.chain("out", |c| {
            c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
        })
        .set("hosts", move |s| {
            let s = s
                .key_type(SetKeyType::Ipv4Addr)
                .counter()
                .statement(ElementStatement::from(QuotaExpr::new(quota)))
                .ipv4(Ipv4Addr::new(127, 0, 0, 2))
                .ipv4(Ipv4Addr::new(127, 0, 0, 3));
            match policy {
                Some(policy) => s.policy(policy),
                None => s,
            }
        })
        .rule_keyed("out", "hosts", |r| {
            r.match_l4proto(17)
                .match_in_set(PacketField::Ip4Daddr, "hosts")
                .counter()
        })
    })
}

/// #703: a declared set with a counter and a quota on every element
/// converges, its members count their own traffic without making a diff,
/// and a changed quota, then a changed policy, each recreate it — with the
/// rule using it moved back — so its members count from zero again.
#[tokio::test]
async fn declared_set_statements_count_per_member_and_recreate_on_change() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_quota");

    let ns = TestNamespace::new("nft-setstmt-decl")?;
    lo_up(&ns).await?;
    let steps = [
        counted_hosts(1 << 20, None),
        counted_hosts(2 << 20, None),
        counted_hosts(2 << 20, Some(SetPolicy::Memory)),
    ];
    assert_transition(&ns, &steps, false, async |i, conn| {
        send_udp(&ns, &["127.0.0.2:9", "127.0.0.2:9"], 1);
        let elements = conn
            .list_set_elements("t", "hosts", Family::Inet)
            .await
            .map_err(|e| e.to_string())?;
        let two = elements
            .iter()
            .find(|e| e.key() == [127, 0, 0, 2])
            .ok_or("127.0.0.2 is gone")?;
        // Two packets: the set (and its elements) is new at every step.
        if two.counter().map(|(packets, _)| packets) != Some(2) {
            return Err(format!("step {}: 127.0.0.2 counted {:?}", i + 1, two.counter()));
        }
        if two.quota_used() != two.counter().map(|(_, bytes)| bytes) {
            return Err(format!("step {}: quota used {:?}", i + 1, two.quota_used()));
        }
        let sets = conn
            .list_sets_in("t", Family::Inet)
            .await
            .map_err(|e| e.to_string())?;
        let policy = sets.iter().find(|s| s.name == "hosts").map(|s| s.policy);
        let want = if i == 2 { SetPolicy::Memory } else { SetPolicy::Performance };
        if policy != Some(want) {
            return Err(format!("step {}: policy {policy:?}", i + 1));
        }
        Ok(())
    })
    .await?;
    let conn = ns.connection_for::<Nftables>()?;
    let again = steps[2].diff(&conn).await?;
    assert!(again.is_empty(), "traffic must not make a diff: {again}");
    Ok(())
}
