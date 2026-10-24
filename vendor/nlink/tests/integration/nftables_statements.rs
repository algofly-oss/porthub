//! Live-kernel verification of the nftables write statements: `meta mark
//! set` (plain and masked), `meta priority set`, `ct mark set` and the
//! connmark save/restore pair, `tcp option maxseg size set` (a constant or
//! the path MTU), and the set size.
//!
//! The unit tests pin the bytes nlink emits. These pin that the kernel
//! accepts them, echoes back the same expressions, and — sending real
//! packets through a netns and reading rule counters and TC class stats —
//! that the statements do to a packet what they claim to.

use std::net::Ipv4Addr;
use std::time::Duration;

use nlink::netlink::nftables::config::{Change, NftablesConfig};
use nlink::netlink::nftables::types::{
    BaseChain, Chain, ExthdrOp, Family, FilterHook, MetaKey, NatHook, Priority, Rule, Set,
    SetElement, SetFlags, SetKeyType, TCPOPT_MAXSEG, TcpFlags,
};
use nlink::netlink::nftables::{CmpOp, Expr, Register, RuleExpr};
use nlink::netlink::addr::Ipv4Address;
use nlink::netlink::filter::FwFilter;
use nlink::netlink::link::DummyLink;
use nlink::netlink::route::{Ipv4Route, RouteMetrics};
use nlink::netlink::tc::{HtbClassConfig, HtbQdiscConfig};
use nlink::netlink::{Connection, Nftables, Route};
use nlink::{Rate, TcHandle};

use crate::common::counters::{class_stats, rule_packets};
use crate::common::traffic::{lo_up, send_tcp_syns, send_udp};
use crate::common::{TestNamespace, nft, with_timeout};

async fn add_mangle_chain(conn: &Connection<Nftables>, hook: FilterHook) -> nlink::Result<()> {
    conn.add_table("t", Family::Ip).await?;
    conn.add_chain(
        Chain::new("t", "c")?
            .family(Family::Ip)
            .base(BaseChain::filter(hook, Priority::Mangle)),
    )
    .await
}

/// A `dummy0` inside `ns`, up, with 10.98.0.1/24 — an egress device with
/// no peer: what leaves through it is counted and dropped.
async fn add_dummy(ns: &TestNamespace) -> nlink::Result<Connection<Route>> {
    let route = ns.connection()?;
    route.add_link(DummyLink::new("dummy0")).await?;
    route.set_link_up("dummy0").await?;
    route
        .add_address(Ipv4Address::new("dummy0", Ipv4Addr::new(10, 98, 0, 1), 24))
        .await?;
    Ok(route)
}

/// An `output` and a `postrouting` mangle chain in table `ip t`.
async fn add_output_and_postrouting(conn: &Connection<Nftables>) -> nlink::Result<()> {
    conn.add_table("t", Family::Ip).await?;
    for (name, hook) in [
        ("out", FilterHook::Output),
        ("post", FilterHook::Postrouting),
    ] {
        conn.add_chain(
            Chain::new("t", name)?
                .family(Family::Ip)
                .base(BaseChain::filter(hook, Priority::Mangle)),
        )
        .await?;
    }
    Ok(())
}

/// [`add_dummy`] plus an HTB tree on `dummy0`: root `1:`, parent class
/// `1:1`, leaves `1:10` and `1:20`, default `1:20`.
async fn add_dummy_with_htb(ns: &TestNamespace) -> nlink::Result<Connection<Route>> {
    let route = add_dummy(ns).await?;
    route
        .add_qdisc_full(
            "dummy0",
            TcHandle::ROOT,
            Some(TcHandle::major_only(1)),
            HtbQdiscConfig::new().default_class(0x20).build(),
        )
        .await?;
    route
        .add_class(
            "dummy0",
            TcHandle::major_only(1),
            TcHandle::new(1, 1),
            HtbClassConfig::new(Rate::mbit(100)).build(),
        )
        .await?;
    for minor in [0x10, 0x20] {
        route
            .add_class(
                "dummy0",
                TcHandle::new(1, 1),
                TcHandle::new(1, minor),
                HtbClassConfig::new(Rate::mbit(10))
                    .ceil(Rate::mbit(100))
                    .build(),
            )
            .await?;
    }
    Ok(route)
}

/// `tcp option maxseg size == <mss> counter` in `chain`, as raw
/// expressions — the load form of `exthdr`, which no `Rule` helper emits.
fn count_mss(chain: &str, mss: u16) -> Rule {
    Rule::new("t", chain)
        .family(Family::Ip)
        .expressions(vec![
            Expr::Meta {
                dreg: Register::R0,
                key: MetaKey::L4Proto,
            },
            Expr::Cmp {
                sreg: Register::R0,
                op: CmpOp::Eq,
                data: vec![6],
            },
            Expr::Exthdr {
                dreg: Register::R0,
                op: ExthdrOp::TcpOpt,
                exthdr_type: TCPOPT_MAXSEG,
                offset: 2,
                len: 2,
            },
            Expr::Cmp {
                sreg: Register::R0,
                op: CmpOp::Eq,
                data: mss.to_be_bytes().to_vec(),
            },
        ])
        .counter()
}

/// `ip daddr @s meta mark set 1` installs, and dumps back as a meta *set*
/// (source register), not a meta load.
#[tokio::test]
async fn meta_mark_set_round_trips_through_the_kernel() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-markset")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        add_mangle_chain(&conn, FilterHook::Postrouting).await?;
        conn.add_set(
            Set::new("t", "s")
                .family(Family::Ip)
                .key_type(SetKeyType::Ipv4Addr),
        )
        .await?;
        conn.add_rule(
            Rule::new("t", "c")
                .family(Family::Ip)
                .match_daddr_in_set("s")
                .set_mark(1),
        )
        .await?;

        let rules = conn.list_rules("t", Family::Ip).await?;
        let exprs = rules[0].expressions();
        assert!(
            exprs.iter().any(|e| matches!(
                e,
                RuleExpr::MetaSet {
                    key: MetaKey::Mark,
                    sreg: Register::R0,
                    ..
                }
            )),
            "kernel did not echo `meta mark set`: {exprs:?}",
        );
        Ok(())
    })
    .await
}

/// `tcp flags syn / syn,rst tcp option maxseg size set 1360` installs and
/// dumps back as exactly what was sent: immediate + exthdr write.
#[tokio::test]
async fn tcp_mss_clamp_round_trips_through_the_kernel() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-mss")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        add_mangle_chain(&conn, FilterHook::Forward).await?;
        conn.add_rule(
            Rule::new("t", "c")
                .family(Family::Ip)
                .match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                .clamp_tcp_mss(1360),
        )
        .await?;

        let rules = conn.list_rules("t", Family::Ip).await?;
        let exprs = rules[0].expressions();
        assert!(
            matches!(
                &exprs[exprs.len() - 2..],
                [
                    RuleExpr::Immediate {
                        dreg: Register::R0,
                        data,
                        ..
                    },
                    RuleExpr::ExthdrSet {
                        sreg: Register::R0,
                        op: ExthdrOp::TcpOpt,
                        exthdr_type: TCPOPT_MAXSEG,
                        offset: 2,
                        len: 2,
                        ..
                    },
                ] if data.as_slice() == 1360u16.to_be_bytes()
            ),
            "kernel did not echo the maxseg write: {exprs:?}",
        );
        Ok(())
    })
    .await
}

/// What the clamp does to a real SYN. The loopback SYN carries MSS 65495.
///
/// Clamping to 1360 lowers it; a second clamp to 65535 must not raise it
/// back (the kernel never increases an MSS), and must not end the rule
/// either — its trailing counter still sees the packet. A clamp built as
/// load + `cmp >` + write would skip that counter.
#[tokio::test]
async fn tcp_mss_clamp_lowers_a_syn_and_never_raises_it() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-mss-live")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        add_output_and_postrouting(&conn).await?;
        let syn = || {
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
        };
        conn.add_rule(syn().clamp_tcp_mss(1360).counter()).await?;
        conn.add_rule(syn().clamp_tcp_mss(u16::MAX).counter())
            .await?;
        conn.add_rule(count_mss("post", 1360)).await?;

        send_tcp_syns(&ns, &["127.0.0.1:9"], 1, Duration::from_secs(1));

        assert!(
            rule_packets(&conn, "t", Family::Ip, "out", 0).await? >= 1,
            "clamp to 1360 never saw the SYN"
        );
        assert!(
            rule_packets(&conn, "t", Family::Ip, "out", 1).await? >= 1,
            "a clamp that does not lower the MSS ended rule evaluation",
        );
        assert!(
            rule_packets(&conn, "t", Family::Ip, "post", 0).await? >= 1,
            "the SYN left with an MSS other than 1360",
        );
        Ok(())
    })
    .await
}

/// `meta mark set` marks the packet: a postrouting `meta mark` match sees it.
#[tokio::test]
async fn meta_mark_set_marks_the_packet() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-mark-live")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        add_output_and_postrouting(&conn).await?;
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_tcp_dport(9)
                .set_mark(0x10),
        )
        .await?;
        conn.add_rule(
            Rule::new("t", "post")
                .family(Family::Ip)
                .match_mark(0x10)
                .counter(),
        )
        .await?;

        send_tcp_syns(&ns, &["127.0.0.1:9"], 1, Duration::from_secs(1));

        assert!(
            rule_packets(&conn, "t", Family::Ip, "post", 0).await? >= 1,
            "no packet left with mark 0x10",
        );
        Ok(())
    })
    .await
}

/// A set created with `size(1)` refuses its second element.
#[tokio::test]
async fn set_size_is_enforced_by_the_kernel() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-setsize")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        conn.add_table("t", Family::Ip).await?;
        let set = Set::new("t", "s")
            .family(Family::Ip)
            .key_type(SetKeyType::Ipv4Addr)
            .size(1);
        conn.add_set(set.clone()).await?;
        conn.add_set_elements(&set, &[SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 1))])
            .await?;
        let full = conn
            .add_set_elements(&set, &[SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 2))])
            .await;
        let err = full.expect_err("a size(1) set accepted a second element");
        assert_eq!(
            err.errno(),
            Some(libc::ENFILE),
            "a full set is ENFILE, got {err}"
        );
        Ok(())
    })
    .await
}

/// A declared MSS clamp + mark rule must not show up as changed on every
/// reconcile: the kernel dumps `NFTA_EXTHDR_FLAGS` for the exthdr set form
/// although it rejects it in the request.
#[tokio::test]
async fn reconcile_statements_are_idempotent() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-stmt-rec")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let cfg = NftablesConfig::new().table("mangle", Family::Ip, |t| {
            t.chain("forward", |c| {
                c.base(BaseChain::filter(FilterHook::Forward, Priority::Mangle))
            })
            .rule_keyed("forward", "mss", |r| {
                r.match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                    .clamp_tcp_mss(1360)
            })
            .rule_keyed("forward", "mark", |r| r.match_tcp_dport(80).set_mark(1))
        });

        cfg.diff(&conn).await?.apply(&conn).await?;
        let again = cfg.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}

/// `set_mark_masked` sets the bits under the mask and keeps the others;
/// `match_mark_masked` sees only the bits under the mask.
#[tokio::test]
async fn masked_mark_set_keeps_the_foreign_bits() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-xmark-live")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        add_output_and_postrouting(&conn).await?;
        let out = || Rule::new("t", "out").family(Family::Ip).match_tcp_dport(9);
        // Someone else's bits first, then ours under 0xff.
        conn.add_rule(out().set_mark(0xff00_0000)).await?;
        conn.add_rule(out().set_mark_masked(0x1234, 0xff)).await?;
        let post = || Rule::new("t", "post").family(Family::Ip);
        conn.add_rule(post().match_mark(0xff00_0034).counter()).await?;
        conn.add_rule(post().match_mark_masked(0x34, 0xff).counter())
            .await?;

        send_tcp_syns(&ns, &["127.0.0.1:9"], 1, Duration::from_secs(1));

        assert!(
            rule_packets(&conn, "t", Family::Ip, "post", 0).await? >= 1,
            "the mark is not 0xff000034: the foreign bits were lost or ours not set",
        );
        assert!(
            rule_packets(&conn, "t", Family::Ip, "post", 1).await? >= 1,
            "match_mark_masked(0x34, 0xff) missed mark 0xff000034",
        );
        Ok(())
    })
    .await
}

/// `ct mark set mark` saves the packet mark on the connection, and
/// `meta mark set ct mark` restores a connection mark onto the packet.
#[tokio::test]
async fn connmark_save_and_restore_carry_the_mark() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_ct");

    with_timeout(async {
        // Save: packet mark -> conntrack mark.
        let ns = TestNamespace::new("nft-ctsave")?;
        let conn = ns.connection_for::<Nftables>()?;
        lo_up(&ns).await?;
        add_output_and_postrouting(&conn).await?;
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_tcp_dport(9)
                .set_mark(0x20)
                .save_mark_to_ct(),
        )
        .await?;
        conn.add_rule(
            Rule::new("t", "post")
                .family(Family::Ip)
                .match_ct_mark(0x20)
                .counter(),
        )
        .await?;
        send_tcp_syns(&ns, &["127.0.0.1:9"], 1, Duration::from_secs(1));
        assert!(
            rule_packets(&conn, "t", Family::Ip, "post", 0).await? >= 1,
            "the connection did not carry the saved mark 0x20",
        );

        // Restore: conntrack mark -> packet mark.
        let ns = TestNamespace::new("nft-ctrestore")?;
        let conn = ns.connection_for::<Nftables>()?;
        lo_up(&ns).await?;
        add_output_and_postrouting(&conn).await?;
        let out = || Rule::new("t", "out").family(Family::Ip).match_tcp_dport(9);
        conn.add_rule(out().set_ct_mark(0x30)).await?;
        conn.add_rule(out().restore_mark_from_ct()).await?;
        conn.add_rule(
            Rule::new("t", "post")
                .family(Family::Ip)
                .match_mark(0x30)
                .counter(),
        )
        .await?;
        send_tcp_syns(&ns, &["127.0.0.1:9"], 1, Duration::from_secs(1));
        assert!(
            rule_packets(&conn, "t", Family::Ip, "post", 0).await? >= 1,
            "the packet did not get the connection's mark 0x30",
        );
        Ok(())
    })
    .await
}

/// `meta priority set 1:10` puts packets in HTB leaf class 1:10 with no
/// `tc` filter: without it they would go to the default class 1:20.
#[tokio::test]
async fn meta_priority_set_classifies_into_an_htb_class() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "sch_htb");

    let ns = TestNamespace::new("nft-prio-htb")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let route = add_dummy_with_htb(&ns).await?;
        add_output_and_postrouting(&conn).await?;
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_daddr_v4(Ipv4Addr::new(10, 98, 0, 3), 32)
                .set_priority(TcHandle::new(1, 0x10)),
        )
        .await?;

        assert_eq!(send_udp(&ns, &["10.98.0.3:9"], 5), 5);

        let dummy0 = route.get_link_by_name("dummy0").await?.expect("dummy0 exists").ifindex();
        let (sent, _) = class_stats(&route, dummy0, TcHandle::new(1, 0x10))
            .await?
            .expect("class 1:10 exists");
        assert!(
            sent >= 5,
            "class 1:10 saw {sent} packets, not the 5 priority-1:10 datagrams",
        );
        Ok(())
    })
    .await
}

/// A masked mark set by nftables, matched by a `tc` `fw` filter with the
/// same mask, lands in the filter's class — the recipe's Option 2.
#[tokio::test]
async fn masked_mark_classifies_through_a_fw_filter() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "sch_htb", "cls_fw");

    let ns = TestNamespace::new("nft-fw-htb")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let route = add_dummy_with_htb(&ns).await?;
        // tc filter add dev dummy0 parent 1: handle 0x10/0xff fw classid 1:10
        route
            .add_filter_full(
                "dummy0",
                TcHandle::major_only(1),
                Some(TcHandle::from(0x10u32)),
                nlink::EthProto::new(0x0003),
                nlink::FilterPriority::new(
                    // ETH_P_ALL
                    100,
                ),
                FwFilter::new()
                    .mask(0xff)
                    .classid(TcHandle::new(1, 0x10))
                    .build(),
            )
            .await?;

        add_output_and_postrouting(&conn).await?;
        let to_target = || {
            Rule::new("t", "post")
                .family(Family::Ip)
                .match_daddr_v4(Ipv4Addr::new(10, 98, 0, 3), 32)
        };
        // Foreign bits above ours: only the masked byte decides the class.
        conn.add_rule(to_target().set_mark(0xab00_0000)).await?;
        conn.add_rule(to_target().set_mark_masked(0x10, 0xff)).await?;

        assert_eq!(send_udp(&ns, &["10.98.0.3:9"], 5), 5);

        let dummy0 = route.get_link_by_name("dummy0").await?.expect("dummy0 exists").ifindex();
        let (sent, _) = class_stats(&route, dummy0, TcHandle::new(1, 0x10))
            .await?
            .expect("class 1:10 exists");
        assert!(
            sent >= 5,
            "class 1:10 saw {sent} packets: mark 0xab000010 did not reach it through fw 0x10/0xff",
        );
        Ok(())
    })
    .await
}

/// `tcp option maxseg size set rt mtu`. The route to 10.98.0.2 has MTU
/// 1400 but advertises MSS 1460, so the SYN leaves `output` claiming more
/// than the path carries; the clamp brings it to 1400 - 40 = 1360.
#[tokio::test]
async fn tcp_mss_clamp_to_pmtu_uses_the_route_mtu() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-pmtu-live")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let route = add_dummy(&ns).await?;
        route
            .add_route(
                Ipv4Route::new(Ipv4Addr::new(10, 98, 0, 2), 32)
                    .dev("dummy0")
                    .metrics(RouteMetrics::new().mtu(1400).advmss(1460)),
            )
            .await?;

        add_output_and_postrouting(&conn).await?;
        // Before the clamp: the SYN really does claim 1460.
        conn.add_rule(count_mss("out", 1460)).await?;
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                .clamp_tcp_mss_to_pmtu(),
        )
        .await?;
        conn.add_rule(count_mss("post", 1360)).await?;

        send_tcp_syns(&ns, &["10.98.0.2:9"], 1, Duration::from_millis(300));

        assert!(
            rule_packets(&conn, "t", Family::Ip, "out", 0).await? >= 1,
            "the SYN did not advertise 1460 — the test setup is not what it claims",
        );
        assert!(
            rule_packets(&conn, "t", Family::Ip, "post", 0).await? >= 1,
            "the SYN was not clamped to the path MSS 1360",
        );
        Ok(())
    })
    .await
}

/// A throttle config the way a UPF would declare it: a bounded set of
/// addresses and a rule marking traffic to them.
fn throttle_cfg(size: u32, addrs: &[Ipv4Addr]) -> NftablesConfig {
    let addrs = addrs.to_vec();
    NftablesConfig::new().table("t", Family::Ip, move |t| {
        t.set("throttled", move |mut s| {
            s = s.key_type(SetKeyType::Ipv4Addr).size(size);
            for a in addrs {
                s = s.ipv4(a);
            }
            s
        })
        .chain("post", |c| {
            c.base(BaseChain::filter(FilterHook::Postrouting, Priority::Mangle))
        })
        .rule_keyed("post", "throttle", |r| {
            r.match_daddr_in_set("throttled")
                .set_mark_masked(0x10, 0xff)
                .counter()
        })
    })
}

fn addrs(n: u8) -> Vec<Ipv4Addr> {
    (1..=n).map(|i| Ipv4Addr::new(10, 45, 0, i)).collect()
}

/// A declared set size reaches the kernel, reads back, and reconciles to
/// an empty diff.
#[tokio::test]
async fn declared_set_size_applies_and_reconciles() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-dsize")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let cfg = throttle_cfg(2, &addrs(2));
        cfg.diff(&conn).await?.apply(&conn).await?;

        let sets = conn.list_sets_in("t", Family::Ip).await?;
        assert_eq!(sets[0].size, Some(2), "SetInfo::size reads the kernel's size");

        let again = cfg.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}

/// Growing a declared set's size is applied in place — the set keeps its
/// elements and the rule bound to it keeps its handle — and the elements
/// the larger size admits go in during the same apply.
///
/// The kernel checks element adds against the size a set has *before*
/// the commit, so this only works because the resize is committed first;
/// in one batch the two new elements would be ENFILE.
#[tokio::test]
async fn declared_set_resize_is_in_place_and_admits_new_elements() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-dresize")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        throttle_cfg(2, &addrs(2))
            .diff(&conn)
            .await?
            .apply(&conn)
            .await?;
        let handle_before = conn.list_rules("t", Family::Ip).await?[0].handle;

        let grown = throttle_cfg(4, &addrs(4));
        let diff = grown.diff(&conn).await?;
        let sets: Vec<_> = diff.sets().collect();
        assert!(
            matches!(sets[..], [Change::Update { .. }]),
            "a size change must not recreate the set: {diff}"
        );
        diff.apply(&conn).await?;

        let sets = conn.list_sets_in("t", Family::Ip).await?;
        assert_eq!(sets[0].size, Some(4));
        assert_eq!(
            conn.list_set_elements("t", "throttled", Family::Ip)
                .await?
                .len(),
            4
        );
        assert_eq!(
            conn.list_rules("t", Family::Ip).await?[0].handle,
            handle_before,
            "the rule bound to the set was replaced",
        );

        let again = grown.diff(&conn).await?;
        assert!(again.is_empty(), "the resize must converge: {again}");
        Ok(())
    })
    .await
}

/// A set whose key type or flags change has to be deleted and recreated —
/// and a rule that still references it pins it: `DELSET` on a set with
/// bindings is EBUSY. The rule itself has not changed, so the diff left it
/// alone and the whole apply failed, every time.
#[tokio::test]
async fn recreating_a_set_a_rule_references_converges() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-recreate")?;
    let conn = ns.connection_for::<Nftables>()?;

    // Rules bound to the set first, last, two in a row, and between plain
    // ones; `mark` is the value one bound rule sets, so a second config can
    // also change that rule's body.
    let cfg = |flags: SetFlags, mark: u32| {
        NftablesConfig::new().table("t", Family::Ip, move |t| {
            t.set("s", move |s| {
                s.key_type(SetKeyType::Ipv4Addr)
                    .flags(flags)
                    .ipv4(Ipv4Addr::new(10, 45, 0, 1))
            })
            .chain("post", |c| {
                c.base(BaseChain::filter(FilterHook::Postrouting, Priority::Mangle))
            })
            .rule_keyed("post", "bound-first", |r| r.match_saddr_in_set("s").counter())
            .rule_keyed("post", "plain-1", |r| r.match_tcp_dport(1).counter())
            .rule_keyed("post", "bound-a", move |r| {
                r.match_daddr_in_set("s").set_mark(mark).counter()
            })
            .rule_keyed("post", "bound-b", |r| r.match_daddr_in_set("s").counter())
            .rule_keyed("post", "plain-2", |r| r.match_tcp_dport(2).counter())
            .rule_keyed("post", "bound-last", |r| r.match_saddr_in_set("s").drop())
        })
    };
    let order = ["bound-first", "plain-1", "bound-a", "bound-b", "plain-2", "bound-last"];

    with_timeout(async {
        cfg(SetFlags::empty(), 1).diff(&conn).await?.apply(&conn).await?;

        // Constant now, and `bound-a` sets a different mark: its pending
        // in-place replace has to become a re-insert too.
        let constant = cfg(SetFlags::CONSTANT, 2);
        let diff = constant.diff(&conn).await?;
        assert_eq!(
            nft::count(&diff, "set", "recreate"),
            1,
            "flags drift recreates: {diff}"
        );
        assert_eq!(nft::moved(&diff).len(), 4, "{diff}");
        assert!(nft::replaced(&diff).is_empty(), "{diff}");
        diff.apply(&conn).await?;

        let sets = conn.list_sets_in("t", Family::Ip).await?;
        assert_eq!(sets[0].flags, SetFlags::CONSTANT);
        // Rule order survives the recreate.
        let keys: Vec<_> = conn
            .list_rules("t", Family::Ip)
            .await?
            .into_iter()
            .map(|r| r.key.unwrap_or_default())
            .collect();
        assert_eq!(keys, order);

        let again = constant.diff(&conn).await?;
        assert!(again.is_empty(), "the recreate must converge: {again}");
        Ok(())
    })
    .await
}

/// `Rule::position(h)` places the rule right *after* rule `h`:
/// `add_rule` always sends NLM_F_APPEND (#195), and with it the kernel
/// links a positioned rule after the one named.
#[tokio::test]
async fn rule_position_inserts_after_the_named_rule() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-position")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        add_mangle_chain(&conn, FilterHook::Postrouting).await?;
        let rule = |port: u16, comment: &str| {
            Rule::new("t", "c")
                .family(Family::Ip)
                .match_tcp_dport(port)
                .comment(comment)
        };
        conn.add_rule(rule(1, "a")).await?;
        conn.add_rule(rule(2, "b")).await?;
        let a = conn.list_rules("t", Family::Ip).await?[0].handle;
        conn.add_rule(rule(3, "c").position(a)).await?;

        let order: Vec<_> = conn
            .list_rules("t", Family::Ip)
            .await?
            .into_iter()
            .map(|r| r.comment_text.unwrap_or_default())
            .collect();
        assert_eq!(order, ["a", "c", "b"]);
        Ok(())
    })
    .await
}

/// #528: what `nft` itself installs — limit, log, reject, every NAT form,
/// flow offload — decodes as its typed `RuleExpr`, never `Unknown`. Each
/// rule is written in nft's syntax and read back through nlink, so the
/// decoders are checked against the reference tool's encoding, not only
/// nlink's own.
#[tokio::test]
async fn statements_nft_installs_decode_typed() -> nlink::Result<()> {
    use nlink::netlink::nftables::{NatFlags, NatType};
    nlink::require_root!();
    nlink::require_modules!(
        "nf_tables", "nft_limit", "nft_log", "nft_reject_inet", "nft_nat", "nft_masq",
        "nft_redir", "nf_flow_table", "nft_flow_offload", "dummy"
    );
    let ns = TestNamespace::new("nft-decode")?;
    ns.add_dummy("d0")?;
    let script = "table inet t {
        flowtable ft { hook ingress priority 0; devices = { d0 }; }
        chain filt { type filter hook forward priority 0;
            limit rate 10/minute burst 3 packets
            log prefix \"x: \" group 2
            log
            reject with icmpx type port-unreachable
            meta l4proto tcp reject with tcp reset
            flow add @ft
        }
    }
    table ip n {
        chain post { type nat hook postrouting priority 100;
            oifname \"d0\" masquerade random
            meta l4proto tcp oifname \"d0\" masquerade to :1024-2048
            snat to 10.0.0.1-10.0.0.9 fully-random
        }
        chain pre { type nat hook prerouting priority -100;
            tcp dport 80 dnat to 10.0.0.1:8080
            tcp dport 81 redirect to :3128
        }
    }";
    let file = std::env::temp_dir().join(format!("nlink-decode-{}.nft", std::process::id()));
    std::fs::write(&file, script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed?;

    let nft = ns.connection_for::<Nftables>()?;
    let mut exprs = Vec::new();
    for (table, family) in [("t", Family::Inet), ("n", Family::Ip)] {
        for rule in nft.list_rules(table, family).await? {
            exprs.extend(rule.expressions());
        }
    }
    let unknown: Vec<_> = exprs.iter().filter(|e| matches!(e, RuleExpr::Unknown { .. })).collect();
    assert!(unknown.is_empty(), "undecoded: {unknown:?}");

    let has = |f: &dyn Fn(&RuleExpr) -> bool| exprs.iter().any(f);
    assert!(has(&|e| matches!(e, RuleExpr::Limit(l) if l.rate == 10 && l.burst == 3)));
    assert!(has(&|e| matches!(e, RuleExpr::Log(l) if l.prefix.as_deref() == Some("x: ") && l.group == Some(2))));
    assert!(has(&|e| matches!(e, RuleExpr::Log(l) if l.prefix.is_none() && l.group.is_none())));
    assert!(has(&|e| matches!(e, RuleExpr::Reject { icmp_code: Some(_), .. })));
    assert!(has(&|e| matches!(e, RuleExpr::Reject { icmp_code: None, .. })), "tcp reset");
    assert!(has(&|e| matches!(e, RuleExpr::FlowOffload { flowtable, .. } if flowtable == "ft")));
    assert!(has(&|e| matches!(e, RuleExpr::Masq { proto: None, flags, .. } if flags.contains(NatFlags::PROTO_RANDOM))));
    assert!(has(&|e| matches!(e, RuleExpr::Masq { proto: Some((lo, hi)), .. } if lo != hi)), "a port range: two registers");
    assert!(has(&|e| matches!(e, RuleExpr::Nat { nat_type: NatType::Snat, family: Family::Ip, addr: Some((lo, hi)), flags, .. }
        if lo != hi && flags.contains(NatFlags::MAP_IPS | NatFlags::PROTO_RANDOM_FULLY))));
    assert!(has(&|e| matches!(e, RuleExpr::Nat { nat_type: NatType::Dnat, addr: Some(_), proto: Some(_), .. })));
    assert!(has(&|e| matches!(e, RuleExpr::Redir { proto: Some(_), flags, .. } if flags.contains(NatFlags::PROTO_SPECIFIED))));
    Ok(())
}

/// Bind `listen_port` in `pair.b`, send `count` datagrams from `pair.a`
/// to `b:send_port`, and return the source of each that arrived.
fn arrivals(
    pair: &crate::common::topo::NsPair,
    send_port: u16,
    listen_port: u16,
    count: usize,
) -> nlink::Result<Vec<std::net::SocketAddr>> {
    use std::net::{SocketAddr, UdpSocket};
    let socket = crate::common::traffic::in_ns(&pair.b, move || {
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, listen_port))
    })
    .map_err(nlink::Error::from)?;
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(nlink::Error::from)?;
    send_udp(&pair.a, &[SocketAddr::from((pair.b_addr, send_port))], count);
    let mut buf = [0u8; 64];
    let mut from = Vec::new();
    while let Ok((_, source)) = socket.recv_from(&mut buf) {
        from.push(source);
    }
    Ok(from)
}

/// #528: NAT ranges rewrite real traffic as declared. From `a`: a snat to
/// an address and port range, a masquerade to a port range, a port-only
/// dnat; in `b`, a redirect to another port. Each is checked by where the
/// datagrams arrive and with what source.
#[tokio::test]
async fn nat_ranges_rewrite_traffic_as_declared() -> nlink::Result<()> {
    use nlink::netlink::nftables::NatStatement;
    use std::net::IpAddr;
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_nat", "nft_masq", "nft_redir", "veth");

    let pair = crate::common::topo::NsPair::new("nat-range", 93).await?;
    let (lo, hi) = (Ipv4Addr::new(10, 93, 0, 100), Ipv4Addr::new(10, 93, 0, 101));
    let nat_chain = |hook, priority| {
        move |c: nlink::netlink::nftables::config::DeclaredChainBuilder| {
            c.base(BaseChain::nat(hook, priority))
        }
    };
    let a = NftablesConfig::new().table("n", Family::Ip, |t| {
        t.chain("post", nat_chain(NatHook::Postrouting, Priority::SrcNat))
            .chain("out", nat_chain(NatHook::Output, Priority::DstNat))
            .rule_keyed("post", "snat", |r| {
                r.match_udp_dport(7000).nat(NatStatement::snat(lo).to(hi).ports(40000, 40010))
            })
            .rule_keyed("post", "masq", |r| {
                r.match_udp_dport(7003).nat(NatStatement::masquerade().ports(41000, 41010))
            })
            .rule_keyed("out", "dnat-port", |r| {
                r.match_udp_dport(7001).nat(NatStatement::dnat_to_port(Family::Ip, 7002))
            })
    });
    let nft = pair.a.connection_for::<Nftables>()?;
    a.diff(&nft).await?.apply(&nft).await?;
    let b = NftablesConfig::new().table("n", Family::Ip, |t| {
        t.chain("pre", nat_chain(NatHook::Prerouting, Priority::DstNat))
            .rule_keyed("pre", "redir", |r| {
                r.match_udp_dport(7004).nat(NatStatement::redirect().port(7005))
            })
    });
    let nft = pair.b.connection_for::<Nftables>()?;
    b.diff(&nft).await?.apply(&nft).await?;

    let from = arrivals(&pair, 7000, 7000, 5)?;
    assert!(!from.is_empty(), "nothing arrived through the snat");
    for source in &from {
        let IpAddr::V4(ip) = source.ip() else { panic!("{source}") };
        assert!((lo..=hi).contains(&ip) && (40000..=40010).contains(&source.port()), "{source}");
    }

    let from = arrivals(&pair, 7003, 7003, 5)?;
    assert!(!from.is_empty(), "nothing arrived through the masquerade");
    for source in &from {
        assert_eq!(source.ip(), IpAddr::V4(pair.a_addr), "{source}");
        assert!((41000..=41010).contains(&source.port()), "{source}");
    }

    assert!(!arrivals(&pair, 7001, 7002, 5)?.is_empty(), "the port-only dnat did not reach :7002");
    assert!(!arrivals(&pair, 7004, 7005, 5)?.is_empty(), "the redirect did not reach :7005");
    Ok(())
}

/// #528: a byte-rate limit counts bytes. 100 bytes a second with a
/// 100-byte burst lets a handful of ~33-byte datagrams through, then
/// `over` drops the rest; the same numbers as a packet limit — 100 a
/// second, a burst of 100 — let all 50 through.
#[tokio::test]
async fn a_byte_limit_drops_by_bytes() -> nlink::Result<()> {
    use nlink::Bytes;
    use nlink::netlink::nftables::{LimitExpr, LimitUnit};
    use std::net::SocketAddr;
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_limit", "veth");

    let pair = crate::common::topo::NsPair::new("nft-bytes", 94).await?;
    let with = |limit: LimitExpr| {
        NftablesConfig::new().table("f", Family::Inet, |t| {
            t.chain("in", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
            })
            .rule_keyed("in", "limit", move |r| r.match_udp_dport(7100).expr(limit).drop())
        })
    };
    let nft = pair.b.connection_for::<Nftables>()?;
    let dst = SocketAddr::from((pair.b_addr, 7100));

    let packets = with(LimitExpr::packets(100, LimitUnit::Second).burst(100).over());
    packets.diff(&nft).await?.apply(&nft).await?;
    let delivered = crate::common::traffic::deliver_udp(&pair.a, &pair.b, dst, 50);
    assert_eq!(delivered, 50, "100 packets/s, burst 100, drops none of 50");

    let bytes = with(LimitExpr::bytes(Bytes::new(100), LimitUnit::Second).burst(100).over());
    bytes.diff(&nft).await?.apply(&nft).await?;
    let delivered = crate::common::traffic::deliver_udp(&pair.a, &pair.b, dst, 50);
    assert!(
        (1..=15).contains(&delivered),
        "100 bytes/s, burst 100: {delivered} of 50 datagrams got through"
    );
    Ok(())
}

/// #528: ranges decide what passes. In `b`'s input, a port range and a
/// negated one drop; in `a`'s output, a mark range drops what an earlier
/// rule marked inside it — a range that only works if the host-order mark
/// is turned to network order first, as `nft` does.
#[tokio::test]
async fn ranges_match_traffic() -> nlink::Result<()> {
    use nlink::netlink::nftables::PacketField;
    use std::net::SocketAddr;
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "veth");

    let pair = crate::common::topo::NsPair::new("nft-range", 95).await?;
    let chain = |hook| {
        move |c: nlink::netlink::nftables::config::DeclaredChainBuilder| {
            c.base(BaseChain::filter(hook, Priority::Filter))
        }
    };
    let b = NftablesConfig::new().table("f", Family::Inet, |t| {
        t.chain("in", chain(FilterHook::Input))
            .rule_keyed("in", "range", |r| r.match_range(PacketField::UdpDport, 7200u16, 7210u16).drop())
            .rule_keyed("in", "not-range", |r| {
                r.match_udp_sport_not(0)
                    .match_range_not(PacketField::UdpDport, 7200u16, 7400u16)
                    .drop()
            })
    });
    let nft = pair.b.connection_for::<Nftables>()?;
    b.diff(&nft).await?.apply(&nft).await?;
    let to = |port| SocketAddr::from((pair.b_addr, port));
    let deliver = |port| crate::common::traffic::deliver_udp(&pair.a, &pair.b, to(port), 3);
    assert_eq!(deliver(7205), 0, "inside 7200-7210: dropped");
    assert_eq!(deliver(7300), 3, "outside 7200-7210, inside 7200-7400: passes");
    assert_eq!(deliver(7500), 0, "outside 7200-7400: the != range drops it");

    // Marks, in a's output: 0x15 is inside 0x10-0x20, 0x25 is not.
    let a = |mark: u32| {
        NftablesConfig::new().table("m", Family::Inet, move |t| {
            t.chain("out", chain(FilterHook::Output))
                .rule_keyed("out", "mark", move |r| r.match_udp_dport(7300).set_mark(mark))
                .rule_keyed("out", "range", |r| r.match_range(PacketField::Mark, 0x10u32, 0x20u32).drop())
        })
    };
    let nft = pair.a.connection_for::<Nftables>()?;
    a(0x15).diff(&nft).await?.apply(&nft).await?;
    // 7300 is a port b lets through (above).
    assert_eq!(deliver(7300), 0, "mark 0x15 is in 0x10-0x20");
    a(0x25).diff(&nft).await?.apply(&nft).await?;
    assert_eq!(deliver(7300), 3, "mark 0x25 is not");
    Ok(())
}

/// #528: `fib saddr . iif oif missing drop` drops a source `b` has no
/// route back to — here `a`'s traffic snat'ed to an address outside every
/// route — and passes `a`'s own; `notrack` leaves a flow out of conntrack,
/// so `ct state untracked` counts exactly its packets.
#[tokio::test]
async fn fib_and_notrack_act_on_traffic() -> nlink::Result<()> {
    use nlink::netlink::nftables::{CtState, FibFlags, NatStatement};
    use std::net::SocketAddr;
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_fib_inet", "nft_ct", "nft_nat", "veth");

    let pair = crate::common::topo::NsPair::new("nft-fib", 96).await?;
    // The kernel's own reverse-path filter drops a spoofed source too,
    // after the prerouting hook. Turn it off where /proc/sys can be
    // written, so the control below can show the spoofed traffic arriving;
    // where it cannot (a rootless container), the fib rule's own counter
    // still shows the rule matched first.
    let mut rp_off = true;
    for dev in ["all", pair.b_if] {
        let key = format!("net.ipv4.conf.{dev}.rp_filter");
        if pair.b.netns().sysctl().get(&key)? != "0" && pair.b.netns().sysctl().set(&key, "0").is_err() {
            rp_off = false;
        }
    }
    let chain = |hook, priority| {
        move |c: nlink::netlink::nftables::config::DeclaredChainBuilder| {
            c.base(BaseChain::filter(hook, priority))
        }
    };
    let b = |rpf: bool| {
        NftablesConfig::new().table("f", Family::Inet, move |t| {
            let t = t
                .chain("raw", chain(FilterHook::Prerouting, Priority::Raw))
                .chain("pre", chain(FilterHook::Prerouting, Priority::Filter))
                .chain("in", chain(FilterHook::Input, Priority::Filter))
                .rule_keyed("raw", "notrack", |r| r.match_udp_dport(7700).notrack())
                .rule_keyed("in", "untracked", |r| {
                    r.match_ct_state(CtState::UNTRACKED).counter().accept()
                });
            if rpf {
                t.rule_keyed("pre", "rpf", |r| {
                    r.match_fib_missing(FibFlags::SADDR | FibFlags::IIF).counter().drop()
                })
            } else {
                t
            }
        })
    };
    let nft_b = pair.b.connection_for::<Nftables>()?;
    let to = |port| SocketAddr::from((pair.b_addr, port));
    let deliver = |port| crate::common::traffic::deliver_udp(&pair.a, &pair.b, to(port), 3);
    let untracked = || crate::common::counters::rule_packets(&nft_b, "f", Family::Inet, "in", 0);

    // a's traffic to 7702 leaves from 192.0.2.1, which b has no route to.
    let a = NftablesConfig::new().table("n", Family::Ip, |t| {
        t.chain("post", |c| {
            c.base(BaseChain::nat(NatHook::Postrouting, Priority::SrcNat))
        })
        .rule_keyed("post", "spoof", |r| {
            r.match_udp_dport(7702).nat(NatStatement::snat(Ipv4Addr::new(192, 0, 2, 1)))
        })
    });
    let nft_a = pair.a.connection_for::<Nftables>()?;
    a.diff(&nft_a).await?.apply(&nft_a).await?;
    if rp_off {
        b(false).diff(&nft_b).await?.apply(&nft_b).await?;
        assert_eq!(deliver(7702), 3, "without the fib check the spoofed source gets through");
    }

    b(true).diff(&nft_b).await?.apply(&nft_b).await?;
    let rpf = || crate::common::counters::rule_packets(&nft_b, "f", Family::Inet, "pre", 0);
    assert_eq!(deliver(7702), 0, "no route back to 192.0.2.1: the fib check drops it");
    assert_eq!(rpf().await?, 3, "the fib rule is what dropped all three");
    assert_eq!(deliver(7700), 3, "a's own source has a route back");
    assert_eq!(rpf().await?, 3, "and the fib rule let it be");
    assert_eq!(untracked().await?, 3, "notrack left all three untracked");
    assert_eq!(deliver(7701), 3);
    assert_eq!(untracked().await?, 3, "7701 was tracked");
    Ok(())
}

/// #528: the conntrack keys act on traffic. In `b`: a zone set in raw is
/// the zone input sees; a dnat'ed flow has `ct status dnat`; a label set
/// on a connection is read back by the next rule; the original tuple's
/// destination is `b`'s address; and `ct count over 1` drops the second
/// flow while the first passes.
#[tokio::test]
async fn ct_keys_act_on_traffic() -> nlink::Result<()> {
    use nlink::netlink::nftables::{CtDirection, CtStatus, NatStatement};
    use std::net::SocketAddr;
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_ct", "nft_nat", "nft_connlimit", "veth");

    let pair = crate::common::topo::NsPair::new("nft-ct", 97).await?;
    let filter = |hook, priority| {
        move |c: nlink::netlink::nftables::config::DeclaredChainBuilder| {
            c.base(BaseChain::filter(hook, priority))
        }
    };
    let b_addr = std::net::IpAddr::V4(pair.b_addr);
    let b = NftablesConfig::new().table("c", Family::Ip, |t| {
        t.chain("raw", filter(FilterHook::Prerouting, Priority::Raw))
            .chain("nat", |c| {
                c.base(BaseChain::nat(NatHook::Prerouting, Priority::DstNat))
            })
            .chain("in", filter(FilterHook::Input, Priority::Filter))
            .rule_keyed("raw", "zone", |r| r.match_udp_dport(7900).set_ct_zone(9))
            .rule_keyed("nat", "dnat", |r| {
                r.match_udp_dport(7901).nat(NatStatement::dnat_to_port(Family::Ip, 7911))
            })
            .rule_keyed("in", "zone-seen", |r| r.match_ct_zone(9).counter())
            .rule_keyed("in", "dnat-seen", |r| r.match_ct_status(CtStatus::DST_NAT).counter())
            .rule_keyed("in", "label-set", |r| r.match_udp_dport(7902).set_ct_label(42))
            .rule_keyed("in", "label-seen", |r| r.match_ct_label(42).counter())
            .rule_keyed("in", "orig-daddr", |r| {
                r.match_udp_dport(7903).match_ct_addr(CtDirection::Original, false, b_addr).counter()
            })
            .rule_keyed("in", "count", |r| r.match_udp_dport(7904).match_ct_count_over(1).drop())
    });
    let nft = pair.b.connection_for::<Nftables>()?;
    b.diff(&nft).await?.apply(&nft).await?;
    let to = |port| SocketAddr::from((pair.b_addr, port));
    let deliver = |port, listen| {
        if port == listen {
            crate::common::traffic::deliver_udp(&pair.a, &pair.b, to(port), 3)
        } else {
            arrivals(&pair, port, listen, 3).map(|v| v.len()).unwrap_or(0)
        }
    };
    let counted = |nth| crate::common::counters::rule_packets(&nft, "c", Family::Ip, "in", nth);

    assert_eq!(deliver(7900, 7900), 3);
    assert_eq!(counted(0).await?, 3, "the zone raw set is the zone input sees");
    assert_eq!(deliver(7901, 7911), 3, "dnat'ed to 7911");
    assert_eq!(counted(1).await?, 3, "ct status dnat counts the dnat'ed flow only");
    assert_eq!(deliver(7902, 7902), 3);
    assert_eq!(counted(3).await?, 3, "the label one rule set, the next reads");
    assert_eq!(deliver(7903, 7903), 3);
    assert_eq!(counted(4).await?, 3, "the original tuple's destination is b");
    assert_eq!(deliver(7904, 7904), 3, "the first flow is the one allowed");
    assert_eq!(deliver(7904, 7904), 0, "a second flow is over the count");
    Ok(())
}

/// #528: a `log group` rule's packets reach a `Connection<Nflog>` bound to
/// the group in that namespace — with the rule's prefix, the input
/// interface, and the packet itself — where a syslog `log` would write
/// nothing outside the initial namespace.
#[tokio::test]
async fn nflog_reads_what_a_log_group_rule_sends() -> nlink::Result<()> {
    use nlink::netlink::Nflog;
    use nlink::netlink::nftables::LogExpr;
    use std::net::SocketAddr;
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_log", "nfnetlink_log", "veth");

    let pair = crate::common::topo::NsPair::new("nflog", 98).await?;
    let b = NftablesConfig::new().table("f", Family::Inet, |t| {
        t.chain("in", |c| {
            c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
        })
        .rule_keyed("in", "log", |r| {
            r.match_udp_dport(7990).expr(LogExpr::new().group(5).prefix("lab: "))
        })
    });
    let nft = pair.b.connection_for::<Nftables>()?;
    b.diff(&nft).await?.apply(&nft).await?;

    let nflog = pair.b.connection_for::<Nflog>()?;
    nflog.bind_group(5, 0xffff).await?;
    let mut packets = nflog.events().await;
    let delivered = crate::common::traffic::deliver_udp(&pair.a, &pair.b, SocketAddr::from((pair.b_addr, 7990)), 1);
    assert_eq!(delivered, 1);

    let packet = crate::common::events::expect_event(
        &mut packets,
        Duration::from_secs(5),
        "the logged datagram",
        |p: &nlink::netlink::nflog::NflogPacket| p.prefix.as_deref() == Some("lab: "),
    )
    .await?;
    assert_eq!((packet.family, packet.group), (2, 5), "NFPROTO_IPV4, group 5");
    assert_eq!(packet.indev, Some(pair.b_ifindex));
    let ip = &packet.payload;
    assert_eq!(ip[0] >> 4, 4, "an IPv4 packet");
    assert_eq!(ip[9], 17, "UDP");
    assert_eq!(ip[16..20], pair.b_addr.octets());
    let udp = usize::from(ip[0] & 0xf) * 4;
    assert_eq!(u16::from_be_bytes([ip[udp + 2], ip[udp + 3]]), 7990);
    Ok(())
}

/// The rule lines of `nft list chain <family> <table> <chain>`.
fn listed_rules(ns: &TestNamespace, family: &str, table: &str, chain: &str) -> nlink::Result<Vec<String>> {
    let out = ns.exec("nft", &["list", "chain", family, table, chain])?;
    Ok(out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("table") && !l.starts_with("chain") && !l.starts_with("type") && *l != "}")
        .map(str::to_string)
        .collect())
}

/// #703: a `log`'s level, flags, snaplen and queue threshold, as nft
/// writes them, decode typed, and nlink installs the same rules: `nft`
/// lists the two chains alike.
#[tokio::test]
async fn log_options_read_and_write_as_nft_does() -> nlink::Result<()> {
    use nlink::netlink::nftables::{LogExpr, LogFlags, LogLevel};
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_log", "nf_log_syslog");

    let ns = TestNamespace::new("nft-log")?;
    let lines = [
        "log prefix \"a \" level info flags tcp sequence,options",
        "log level debug flags all",
        "log flags skuid",
        "log group 2 snaplen 64 queue-threshold 10",
        "log group 3",
    ];
    let mut script = String::from("table inet t {\n chain a {\n");
    for l in lines {
        script.push_str(&format!("  {l}\n"));
    }
    script.push_str(" }\n chain b {\n }\n}\n");
    let file = std::env::temp_dir().join(format!("nlink-log-{}.nft", std::process::id()));
    std::fs::write(&file, &script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed?;

    let nft = ns.connection_for::<Nftables>()?;
    let logs: Vec<LogExpr> = nft
        .list_rules("t", Family::Inet)
        .await?
        .iter()
        .flat_map(|r| r.expressions())
        .filter_map(|e| match e {
            RuleExpr::Log(l) => Some(l),
            _ => None,
        })
        .collect();
    let want = [
        LogExpr::new()
            .prefix("a ")
            .level(LogLevel::Info)
            .flags(LogFlags::TCP_SEQUENCE | LogFlags::TCP_OPTIONS),
        LogExpr::new().level(LogLevel::Debug).flags(LogFlags::ALL),
        LogExpr::new().flags(LogFlags::SKUID),
        LogExpr::new().group(2).snaplen(64).queue_threshold(10),
        LogExpr::new().group(3),
    ];
    assert_eq!(logs, want);

    for log in want {
        nft.add_rule(Rule::new("t", "b").family(Family::Inet).expr(log)).await?;
    }
    assert_eq!(
        listed_rules(&ns, "inet", "t", "b")?,
        listed_rules(&ns, "inet", "t", "a")?,
        "nlink's chain b, nft's chain a"
    );
    Ok(())
}

/// #703: an nflog group's snaplen is what the listener gets: a 33-byte
/// datagram logged with `snaplen 24` arrives cut to its IP header and
/// ports.
#[tokio::test]
async fn a_log_snaplen_cuts_what_nflog_reads() -> nlink::Result<()> {
    use nlink::netlink::Nflog;
    use nlink::netlink::nftables::LogExpr;
    use std::net::SocketAddr;
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_log", "nfnetlink_log", "veth");

    let pair = crate::common::topo::NsPair::new("nflogsl", 97).await?;
    let b = NftablesConfig::new().table("f", Family::Inet, |t| {
        t.chain("in", |c| {
            c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
        })
        .rule_keyed("in", "log", |r| {
            r.match_udp_dport(7991).expr(LogExpr::new().group(6).prefix("cut: ").snaplen(24))
        })
    });
    let nft = pair.b.connection_for::<Nftables>()?;
    b.diff(&nft).await?.apply(&nft).await?;
    assert!(b.diff(&nft).await?.is_empty(), "the declared snaplen does not converge");

    let nflog = pair.b.connection_for::<Nflog>()?;
    nflog.bind_group(6, 0xffff).await?;
    let mut packets = nflog.events().await;
    let delivered = crate::common::traffic::deliver_udp(&pair.a, &pair.b, SocketAddr::from((pair.b_addr, 7991)), 1);
    assert_eq!(delivered, 1);
    let packet = crate::common::events::expect_event(
        &mut packets,
        Duration::from_secs(5),
        "the logged datagram",
        |p: &nlink::netlink::nflog::NflogPacket| p.prefix.as_deref() == Some("cut: "),
    )
    .await?;
    assert_eq!(packet.payload.len(), 24, "the snaplen");
    assert_eq!(u16::from_be_bytes([packet.payload[22], packet.payload[23]]), 7991, "up to the ports");
    Ok(())
}

/// #703: header writes as nft writes them. nft installs eight `set`
/// statements in one chain, nlink the same writes in another; `nft` lists
/// the two alike, and nlink decodes nft's typed.
#[tokio::test]
async fn header_writes_read_and_write_as_nft_does() -> nlink::Result<()> {
    use nlink::netlink::nftables::HeaderWrite;
    nlink::require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-pset")?;
    let pairs: [(&str, HeaderWrite); 8] = [
        ("ip dscp set cs1", HeaderWrite::IpDscp(8)),
        ("ip ttl set 64", HeaderWrite::IpTtl(64)),
        ("ip saddr set 10.0.0.9", HeaderWrite::IpSaddr(Ipv4Addr::new(10, 0, 0, 9))),
        ("ip6 dscp set af21", HeaderWrite::Ip6Dscp(18)),
        ("ip6 hoplimit set 9", HeaderWrite::Ip6HopLimit(9)),
        ("ip6 daddr set 2001:db8::1", HeaderWrite::Ip6Daddr("2001:db8::1".parse().unwrap())),
        ("tcp dport set 8080", HeaderWrite::TcpDport(8080)),
        ("udp sport set 53", HeaderWrite::UdpSport(53)),
    ];
    let mut script = String::from("table inet t {\n chain a { type filter hook output priority 0;\n");
    for (line, _) in &pairs {
        script.push_str(&format!("  {line}\n"));
    }
    script.push_str(" }\n chain b { type filter hook output priority 0; }\n}\n");
    let file = std::env::temp_dir().join(format!("nlink-pset-{}.nft", std::process::id()));
    std::fs::write(&file, &script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed?;

    let nft = ns.connection_for::<Nftables>()?;
    let writes = nft
        .list_rules("t", Family::Inet)
        .await?
        .iter()
        .flat_map(|r| r.expressions())
        .filter(|e| matches!(e, RuleExpr::PayloadSet { .. }))
        .count();
    assert_eq!(writes, pairs.len(), "nft's writes decode typed");
    for (_, write) in pairs {
        nft.add_rule(Rule::new("t", "b").family(Family::Inet).set_header(write)).await?;
    }
    assert_eq!(
        listed_rules(&ns, "inet", "t", "b")?,
        listed_rules(&ns, "inet", "t", "a")?,
        "nlink's chain b, nft's chain a"
    );
    Ok(())
}

/// #703: a header write acts on the packet, checksums included. `a`
/// sends with its checksums computed (no tx offload) and `b` checks them
/// (no rx offload, which would mark them good unread); `b`'s prerouting
/// moves datagrams for port 7992 to 7993, and they arrive there only if
/// the write updated the UDP checksum for the new port.
#[tokio::test]
async fn a_port_write_moves_the_datagram() -> nlink::Result<()> {
    use nlink::netlink::Ethtool;
    use nlink::netlink::nftables::HeaderWrite;
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "veth");

    let pair = crate::common::topo::NsPair::new("nftpset", 96).await?;
    let ethtool = pair.a.connection_for_async::<Ethtool>().await?;
    ethtool.set_features(pair.a_if, |f| f.disable("tx-checksum-ip-generic")).await?;
    let ethtool = pair.b.connection_for_async::<Ethtool>().await?;
    ethtool.set_features(pair.b_if, |f| f.disable("rx-checksum")).await?;

    let b = NftablesConfig::new().table("w", Family::Inet, |t| {
        t.chain("pre", |c| {
            c.base(BaseChain::filter(FilterHook::Prerouting, Priority::Filter))
        })
        .rule_keyed("pre", "move", |r| {
            r.match_udp_dport(7992).set_header(HeaderWrite::UdpDport(7993))
        })
    });
    let nft = pair.b.connection_for::<Nftables>()?;
    b.diff(&nft).await?.apply(&nft).await?;
    assert!(b.diff(&nft).await?.is_empty(), "the declared write does not converge");
    assert_eq!(arrivals(&pair, 7992, 7993, 3)?.len(), 3, "rewritten to 7993");
    assert_eq!(arrivals(&pair, 7992, 7992, 3)?.len(), 0, "nothing left for 7992");
    Ok(())
}

/// #703: `queue`, `dup` and `fwd` as nft writes them: nft installs each in
/// one chain, nlink in another, and `nft` lists the two alike.
#[tokio::test]
async fn queue_dup_and_fwd_read_and_write_as_nft_does() -> nlink::Result<()> {
    use nlink::netlink::nftables::{QueueExpr, QueueFlags};
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_queue", "nft_dup_ipv4", "nft_dup_netdev", "nft_fwd_netdev", "dummy");

    let ns = TestNamespace::new("nft-qdf")?;
    ns.add_dummy("d0")?;
    let route = ns.connection()?;
    let d0 = route.get_link_by_name("d0").await?.expect("d0").ifindex();
    let script = "table ip t {
        chain a { type filter hook output priority 0;
            queue num 3 bypass
            queue num 1-4 fanout
            queue flags bypass,fanout num 2-5
            dup to 10.0.0.1 device \"d0\"
            dup to 10.0.0.2
        }
        chain b { type filter hook output priority 0; }
    }
    table netdev n {
        chain a { type filter hook ingress device \"d0\" priority 0;
            fwd to \"d0\"
            fwd ip to 10.0.0.1 device \"d0\"
            dup to \"d0\"
        }
        chain b { type filter hook ingress device \"d0\" priority 0; }
    }";
    let file = std::env::temp_dir().join(format!("nlink-qdf-{}.nft", std::process::id()));
    std::fs::write(&file, script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed?;

    let nft = ns.connection_for::<Nftables>()?;
    let ip = |r: Rule| r.family(Family::Ip);
    for rule in [
        Rule::new("t", "b").expr(QueueExpr::num(3).flags(QueueFlags::BYPASS)),
        Rule::new("t", "b").expr(QueueExpr::range(1, 4).flags(QueueFlags::FANOUT)),
        Rule::new("t", "b").expr(QueueExpr::range(2, 5).flags(QueueFlags::BYPASS | QueueFlags::FANOUT)),
        Rule::new("t", "b").dup_to(Ipv4Addr::new(10, 0, 0, 1).into(), Some(d0)),
        Rule::new("t", "b").dup_to(Ipv4Addr::new(10, 0, 0, 2).into(), None),
    ] {
        nft.add_rule(ip(rule)).await?;
    }
    let netdev = |r: Rule| r.family(Family::Netdev);
    for rule in [
        Rule::new("n", "b").fwd_to(d0),
        Rule::new("n", "b").fwd_ip_to(Ipv4Addr::new(10, 0, 0, 1).into(), d0),
        Rule::new("n", "b").dup_to_device(d0),
    ] {
        nft.add_rule(netdev(rule)).await?;
    }
    for (family, table) in [("ip", "t"), ("netdev", "n")] {
        assert_eq!(
            listed_rules(&ns, family, table, "b")?,
            listed_rules(&ns, family, table, "a")?,
            "{family} {table}: nlink's chain b, nft's chain a"
        );
    }
    let decoded = nft
        .list_rules("t", Family::Ip)
        .await?
        .iter()
        .chain(nft.list_rules("n", Family::Netdev).await?.iter())
        .flat_map(|r| r.expressions())
        .filter(|e| matches!(e, RuleExpr::Queue(_) | RuleExpr::Dup { .. } | RuleExpr::Fwd { .. }))
        .count();
    assert_eq!(decoded, 2 * 8, "both chains decode typed");
    Ok(())
}

/// #703: `queue`, `dup` and `fwd` act on traffic. A datagram queued with
/// no program listening is dropped, and with `bypass` it is not; one
/// duplicated to `b` arrives twice; one forwarded at `b`'s ingress to a
/// dummy never reaches the socket and leaves the dummy instead.
#[tokio::test]
async fn queue_dup_and_fwd_act_on_traffic() -> nlink::Result<()> {
    use nlink::netlink::nftables::{QueueExpr, QueueFlags};
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_queue", "nfnetlink_queue", "nft_dup_ipv4", "nft_fwd_netdev", "veth", "dummy");

    let pair = crate::common::topo::NsPair::new("nftqdf", 95).await?;
    let b_route = pair.b.connection()?;
    b_route.add_link(DummyLink::new("x0")).await?;
    b_route.set_link_up("x0").await?;
    let x0 = b_route.get_link_by_name("x0").await?.expect("x0").ifindex();
    let b = NftablesConfig::new()
        .table("q", Family::Inet, |t| {
            t.chain("in", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
            })
            .rule_keyed("in", "drop-queue", |r| {
                r.match_udp_dport(7997).expr(QueueExpr::num(7))
            })
            .rule_keyed("in", "bypass-queue", |r| {
                r.match_udp_dport(7996)
                    .expr(QueueExpr::num(8).flags(QueueFlags::BYPASS))
            })
        })
        .table("f", Family::Netdev, |t| {
            t.chain("in", |c| {
                c.base(BaseChain::filter(
                    FilterHook::ingress(pair.b_if),
                    Priority::Filter,
                ))
            })
            .rule_keyed("in", "fwd", |r| r.match_udp_dport(7999).fwd_to(x0))
        });
    let nft = pair.b.connection_for::<Nftables>()?;
    b.diff(&nft).await?.apply(&nft).await?;
    assert!(b.diff(&nft).await?.is_empty(), "the declared statements do not converge");
    let a = NftablesConfig::new().table("d", Family::Ip, |t| {
        t.chain("out", |c| {
            c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
        })
        .rule_keyed("out", "dup", |r| {
            r.match_udp_dport(7998)
                .dup_to(pair.b_addr.into(), Some(pair.a_ifindex))
        })
    });
    let a_nft = pair.a.connection_for::<Nftables>()?;
    a.diff(&a_nft).await?.apply(&a_nft).await?;

    assert_eq!(arrivals(&pair, 7997, 7997, 3)?.len(), 0, "queued with no listener: dropped");
    assert_eq!(arrivals(&pair, 7996, 7996, 3)?.len(), 3, "queued with bypass: accepted");
    assert_eq!(arrivals(&pair, 7998, 7998, 3)?.len(), 6, "each datagram and its copy");
    let before = b_route.get_link_by_name("x0").await?.expect("x0").stats().map_or(0, |s| s.tx_packets());
    assert_eq!(arrivals(&pair, 7999, 7999, 3)?.len(), 0, "forwarded away at ingress");
    let after = b_route.get_link_by_name("x0").await?.expect("x0").stats().map_or(0, |s| s.tx_packets());
    assert!(after >= before + 3, "x0 sent {} of the 3", after - before);
    Ok(())
}

/// #703: `numgen`, `jhash` and `symhash` as nft writes them: nft installs
/// six statements in one chain, nlink in another, and `nft` lists them
/// alike.
#[tokio::test]
async fn numgen_and_hash_read_and_write_as_nft_does() -> nlink::Result<()> {
    use nlink::netlink::nftables::{Generated, NumgenKind, PacketField};
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_numgen", "nft_hash", "nft_ct");

    let ns = TestNamespace::new("nft-ngh")?;
    let lines = [
        "meta mark set numgen inc mod 2",
        "meta mark set numgen random mod 10 offset 5",
        "meta mark set jhash ip saddr mod 4 seed 0xdead offset 2",
        "meta mark set jhash ip saddr . tcp dport mod 8",
        "meta mark set symhash mod 2",
        "ct mark set numgen inc mod 3 offset 100",
    ];
    // An inet table, where nft guards each address with `meta nfproto` as
    // nlink does in every family; nft 1.0.6 cannot list a guarded hash
    // input in an ip table, where nft writes none.
    let mut script = String::from("table inet t {\n chain a { type filter hook output priority 0;\n");
    for l in lines {
        script.push_str(&format!("  {l}\n"));
    }
    script.push_str(" }\n chain b { type filter hook output priority 0; }\n}\n");
    let file = std::env::temp_dir().join(format!("nlink-ngh-{}.nft", std::process::id()));
    std::fs::write(&file, &script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed?;

    let nft = ns.connection_for::<Nftables>()?;
    let mark = |g| Rule::new("t", "b").family(Family::Inet).generate(g).set_meta_from(MetaKey::Mark);
    for rule in [
        mark(Generated::Numgen { kind: NumgenKind::Incremental, modulus: 2, offset: 0 }),
        mark(Generated::Numgen { kind: NumgenKind::Random, modulus: 10, offset: 5 }),
        mark(Generated::Jhash { fields: vec![PacketField::Ip4Saddr], modulus: 4, seed: Some(0xdead), offset: 2 }),
        mark(Generated::Jhash {
            fields: vec![PacketField::Ip4Saddr, PacketField::TcpDport],
            modulus: 8,
            seed: None,
            offset: 0,
        }),
        mark(Generated::Symhash { modulus: 2, offset: 0 }),
        Rule::new("t", "b")
            .family(Family::Inet)
            .generate(Generated::Numgen { kind: NumgenKind::Incremental, modulus: 3, offset: 100 })
            .set_ct_from(nlink::netlink::nftables::CtKey::Mark),
    ] {
        nft.add_rule(rule).await?;
    }
    assert_eq!(
        listed_rules(&ns, "inet", "t", "b")?,
        listed_rules(&ns, "inet", "t", "a")?,
        "nlink's chain b, nft's chain a"
    );
    let unknown = nft
        .list_rules("t", Family::Inet)
        .await?
        .iter()
        .flat_map(|r| r.expressions())
        .filter(|e| matches!(e, RuleExpr::Unknown { .. }))
        .count();
    assert_eq!(unknown, 0, "every numgen and hash decodes typed");
    Ok(())
}

/// #703: a `numgen inc mod 2` mark alternates, and a `jhash … mod 1 offset
/// 7` mark is 7 for every packet: counters on each mark see it.
#[tokio::test]
async fn numgen_and_hash_marks_packets() -> nlink::Result<()> {
    use nlink::netlink::nftables::{Generated, NumgenKind, PacketField};
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_numgen", "nft_hash", "dummy");

    let ns = TestNamespace::new("nft-nghtr")?;
    lo_up(&ns).await?;
    let _route = add_dummy(&ns).await?;
    let cfg = NftablesConfig::new().table("t", Family::Ip, |t| {
        t.chain("out", |c| {
            c.base(BaseChain::filter(FilterHook::Output, Priority::Mangle))
        })
        .rule_keyed("out", "gen", |r| {
            r.match_udp_dport(7990)
                .generate(Generated::Numgen {
                    kind: NumgenKind::Incremental,
                    modulus: 2,
                    offset: 0,
                })
                .set_meta_from(MetaKey::Mark)
        })
        .rule_keyed("out", "hash", |r| {
            r.match_udp_dport(7991)
                .generate(Generated::Jhash {
                    fields: vec![PacketField::Ip4Saddr],
                    modulus: 1,
                    seed: None,
                    offset: 7,
                })
                .set_meta_from(MetaKey::Mark)
        })
        .rule_keyed("out", "m0", |r| {
            r.match_udp_dport(7990).match_mark(0).counter()
        })
        .rule_keyed("out", "m1", |r| {
            r.match_udp_dport(7990).match_mark(1).counter()
        })
        .rule_keyed("out", "m7", |r| {
            r.match_udp_dport(7991).match_mark(7).counter()
        })
    });
    let nft = ns.connection_for::<Nftables>()?;
    cfg.diff(&nft).await?.apply(&nft).await?;
    assert!(cfg.diff(&nft).await?.is_empty(), "the declared generators do not converge");
    let to = |port| std::net::SocketAddr::from((Ipv4Addr::new(10, 98, 0, 2), port));
    send_udp(&ns, &[to(7990)], 4);
    send_udp(&ns, &[to(7991)], 3);
    let count = |nth| rule_packets(&nft, "t", Family::Ip, "out", nth);
    assert_eq!((count(2).await?, count(3).await?), (2, 2), "inc mod 2 alternates");
    assert_eq!(count(4).await?, 3, "jhash mod 1 offset 7 is 7");
    Ok(())
}

/// #703: `tproxy`, `socket` and `synproxy` as nft writes them: nft
/// installs each in one chain, nlink in another, and `nft` lists them
/// alike.
#[tokio::test]
async fn tproxy_socket_and_synproxy_read_and_write_as_nft_does() -> nlink::Result<()> {
    use nlink::netlink::nftables::{SocketMatch, SynproxyExpr};
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_tproxy", "nft_socket", "nft_synproxy");

    let ns = TestNamespace::new("nft-tps")?;
    let script = "table ip t {
        chain a { type filter hook prerouting priority -150;
            tcp dport 80 tproxy to 10.0.0.1:8080
            tcp dport 81 tproxy to :8081
            socket transparent 1 meta mark set 1
            socket wildcard 0 accept
            socket mark 7 accept
        }
        chain b { type filter hook prerouting priority -150; }
        chain sa { type filter hook input priority 0;
            synproxy mss 1460 wscale 7 timestamp sack-perm
            synproxy mss 1400
        }
        chain sb { type filter hook input priority 0; }
    }
    table inet i {
        chain a { type filter hook prerouting priority -150;
            tcp dport 82 tproxy ip to 10.0.0.1:8082
        }
        chain b { type filter hook prerouting priority -150; }
    }";
    let file = std::env::temp_dir().join(format!("nlink-tps-{}.nft", std::process::id()));
    std::fs::write(&file, script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed?;

    let nft = ns.connection_for::<Nftables>()?;
    let ten = Some(Ipv4Addr::new(10, 0, 0, 1).into());
    let r = |table: &str, chain: &str, family| Rule::new(table, chain).family(family);
    for rule in [
        r("t", "b", Family::Ip).match_tcp_dport(80).tproxy(Family::Ip, ten, Some(8080)),
        r("t", "b", Family::Ip).match_tcp_dport(81).tproxy(Family::Ip, None, Some(8081)),
        r("t", "b", Family::Ip).match_socket(SocketMatch::Transparent(true)).set_mark(1),
        r("t", "b", Family::Ip).match_socket(SocketMatch::Wildcard(false)).accept(),
        r("t", "b", Family::Ip).match_socket(SocketMatch::Mark(7)).accept(),
        r("t", "sb", Family::Ip).expr(SynproxyExpr::new().mss(1460).wscale(7).timestamp().sack_perm()),
        r("t", "sb", Family::Ip).expr(SynproxyExpr::new().mss(1400)),
        r("i", "b", Family::Inet).match_tcp_dport(82).tproxy(Family::Inet, ten, Some(8082)),
    ] {
        nft.add_rule(rule).await?;
    }
    for (family, table, ours, theirs) in [("ip", "t", "b", "a"), ("ip", "t", "sb", "sa"), ("inet", "i", "b", "a")] {
        assert_eq!(
            listed_rules(&ns, family, table, ours)?,
            listed_rules(&ns, family, table, theirs)?,
            "{family} {table}: nlink's {ours}, nft's {theirs}"
        );
    }
    Ok(())
}

/// #703: `tproxy` hands a datagram to a transparent socket on another
/// port: one sent to `b`'s port 7980 arrives at its `IP_TRANSPARENT`
/// socket on 7981, which nothing else would deliver it to.
#[tokio::test]
async fn tproxy_hands_the_datagram_to_a_transparent_socket() -> nlink::Result<()> {
    use std::net::{SocketAddr, UdpSocket};
    use std::os::fd::AsRawFd;
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_tproxy", "veth");

    let pair = crate::common::topo::NsPair::new("nfttp", 94).await?;
    let b = NftablesConfig::new().table("t", Family::Ip, |t| {
        t.chain("pre", |c| {
            c.base(BaseChain::filter(FilterHook::Prerouting, Priority::Mangle))
        })
        .rule_keyed("pre", "tproxy", |r| {
            r.match_udp_dport(7980).tproxy(Family::Ip, None, Some(7981))
        })
    });
    let nft = pair.b.connection_for::<Nftables>()?;
    b.diff(&nft).await?.apply(&nft).await?;
    assert!(b.diff(&nft).await?.is_empty(), "the declared tproxy does not converge");

    let socket = crate::common::traffic::in_ns(&pair.b, || -> std::io::Result<UdpSocket> {
        let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 7981))?;
        let on: libc::c_int = 1;
        // SAFETY: a valid fd and a c_int option of its size.
        let rc = unsafe {
            libc::setsockopt(
                s.as_raw_fd(),
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                (&on as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(s)
    })
    .map_err(nlink::Error::from)?;
    socket.set_read_timeout(Some(Duration::from_millis(500))).map_err(nlink::Error::from)?;
    send_udp(&pair.a, &[SocketAddr::from((pair.b_addr, 7980))], 3);
    let mut got = 0;
    let mut buf = [0u8; 64];
    while socket.recv_from(&mut buf).is_ok() {
        got += 1;
    }
    assert_eq!(got, 3, "sent to 7980, delivered to the transparent socket on 7981");
    Ok(())
}

/// #703: `osf` as nft writes it — a name, `ttl skip`, `ttl loose` with the
/// version — decodes typed, and nlink installs the same rules: `nft` lists
/// the two chains alike.
#[tokio::test]
async fn osf_reads_and_writes_as_nft_does() -> nlink::Result<()> {
    use nlink::netlink::nftables::OsfTtl;
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_osf");

    let ns = TestNamespace::new("nft-osf")?;
    let script = "table inet t {
        chain a { type filter hook input priority 0;
            osf name \"unknown\" counter
            osf ttl skip name \"Linux\" counter
            osf ttl loose version \"Linux:3.11\" counter
        }
        chain b { type filter hook input priority 0; }
    }";
    let file = std::env::temp_dir().join(format!("nlink-osf-{}.nft", std::process::id()));
    std::fs::write(&file, script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed?;

    let nft = ns.connection_for::<Nftables>()?;
    let r = || Rule::new("t", "b").family(Family::Inet);
    for rule in [
        r().match_osf("unknown", OsfTtl::Exact, false).counter(),
        r().match_osf("Linux", OsfTtl::Skip, false).counter(),
        r().match_osf("Linux:3.11", OsfTtl::Loose, true).counter(),
    ] {
        nft.add_rule(rule).await?;
    }
    assert_eq!(
        listed_rules(&ns, "inet", "t", "b")?,
        listed_rules(&ns, "inet", "t", "a")?,
        "nlink's chain b, nft's chain a"
    );
    let unknown = nft
        .list_rules("t", Family::Inet)
        .await?
        .iter()
        .flat_map(|r| r.expressions())
        .filter(|e| matches!(e, RuleExpr::Unknown { .. }))
        .count();
    assert_eq!(unknown, 0, "every osf decodes typed");
    Ok(())
}

/// #703: with no fingerprints loaded, `osf` names every TCP SYN
/// `unknown`, and looks at nothing else: three SYNs to a closed port count
/// three on `osf name "unknown"`, none on `osf name "Linux"`, and the RSTs
/// that answer them count nowhere. Declared, the rules converge.
#[tokio::test]
async fn osf_names_each_syn() -> nlink::Result<()> {
    use nlink::netlink::nftables::OsfTtl;
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_osf");

    let ns = TestNamespace::new("nft-osftr")?;
    lo_up(&ns).await?;
    let nft = ns.connection_for::<Nftables>()?;
    let cfg = NftablesConfig::new().table("t", Family::Inet, |t| {
        t.chain("in", |c| {
            c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
        })
        .rule_keyed("in", "unknown", |r| r.match_osf("unknown", OsfTtl::Exact, false).counter())
        .rule_keyed("in", "linux", |r| r.match_osf("Linux", OsfTtl::Skip, false).counter())
    });
    cfg.diff(&nft).await?.apply(&nft).await?;
    let again = cfg.diff(&nft).await?;
    assert!(again.is_empty(), "second diff must be empty: {again}");

    send_tcp_syns(&ns, &["127.0.0.1:9"], 3, Duration::from_millis(200));
    assert_eq!(rule_packets(&nft, "t", Family::Inet, "in", 0).await?, 3);
    assert_eq!(rule_packets(&nft, "t", Family::Inet, "in", 1).await?, 0);
    Ok(())
}
