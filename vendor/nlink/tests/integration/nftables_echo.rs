//! Every rule shape nlink can write must reconcile to an empty diff.
//!
//! The declarative diff byte-compares a declared rule against the kernel's
//! echo of it (after `normalize_tlv`, which reorders but cannot add). So
//! every attribute the kernel always dumps has to be in what nlink writes,
//! and nothing the kernel drops may be. A writer that gets this wrong
//! installs fine and then has its rule replaced on every apply, forever —
//! visible only to a second `diff()`.
//!
//! `reconcile_idempotent_reapply_yields_empty_diff` only ever declared
//! `match_tcp_dport` rules, so the masquerade nest (#362) and the lookup /
//! limit / log / reject writers were never in an `is_empty()` assertion.
//! This file declares one keyed rule per `Rule` helper and `Expr` writer
//! arm instead.

use std::net::{Ipv4Addr, Ipv6Addr};

use nlink::netlink::nftables::config::{Change, NftablesConfig};
use nlink::netlink::nftables::types::{
    BaseChain, ChainName, CtState, Family, FilterHook, LimitUnit, NatHook, Priority, SetKeyType,
    TcpFlags,
};
use nlink::netlink::nftables::{
    CmpOp, Expr, LogExpr, LookupExpr, MetaKey, NFT_REJECT_TCP_RST, PayloadBase, Register, Verdict,
};
use nlink::netlink::{Connection, Nftables};
use nlink::TcHandle;

use crate::common::converge::converges;
use crate::common::{TestNamespace, with_timeout};

/// Apply `cfg`; the diffs after it, and a second apply, must all be empty.
async fn assert_reconciles(conn: &Connection<Nftables>, cfg: &NftablesConfig) -> nlink::Result<()> {
    if let Err(why) = converges(conn, cfg, false).await {
        panic!(
            "every rule here was written by nlink and echoed by the kernel \
             unchanged, so nothing may be left to do after an apply. A rule \
             the diff lists is one whose writer disagrees with the kernel's \
             dump: {why}"
        );
    }
    Ok(())
}

/// Matchers, verdicts and statements in a filter chain.
#[tokio::test]
async fn every_filter_rule_shape_reconciles() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_limit", "nft_log", "nft_reject_inet", "nft_ct");

    let ns = TestNamespace::new("nft-echo-filter")?;
    let conn = ns.connection_for::<Nftables>()?;

    let v4: Ipv4Addr = "192.0.2.0".parse().unwrap();
    let v6: Ipv6Addr = "2001:db8::".parse().unwrap();

    with_timeout(async {
        let cfg = NftablesConfig::new().table("shapes", Family::Inet, |t| {
            t.chain("input", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
            })
            .chain("sub", |c| c)
            .chain("forward", |c| {
                c.base(BaseChain::filter(FilterHook::Forward, Priority::Mangle))
            })
            .set("allow4", |s| s.key_type(SetKeyType::Ipv4Addr).ipv4(v4))
            // Transport matchers.
            .rule_keyed("input", "tcp-dport", |r| r.match_tcp_dport(22).accept())
            .rule_keyed("input", "udp-dport", |r| r.match_udp_dport(53).accept())
            .rule_keyed("input", "tcp-sport", |r| r.match_tcp_sport(1024).accept())
            .rule_keyed("input", "udp-sport", |r| r.match_udp_sport(1024).accept())
            .rule_keyed("input", "tcp-dport-not", |r| r.match_tcp_dport_not(22).drop())
            .rule_keyed("input", "udp-dport-not", |r| r.match_udp_dport_not(53).drop())
            .rule_keyed("input", "l4proto", |r| r.match_l4proto(17).accept())
            .rule_keyed("input", "icmp", |r| r.match_icmp_type(8).accept())
            .rule_keyed("input", "icmpv6", |r| r.match_icmpv6_type(128).accept())
            .rule_keyed("input", "tcp-flags", |r| {
                r.match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                    .accept()
            })
            // Address matchers, exact and prefix, plain and negated.
            .rule_keyed("input", "saddr4", |r| r.match_saddr_v4(v4, 24).accept())
            .rule_keyed("input", "daddr4", |r| r.match_daddr_v4(v4, 32).accept())
            .rule_keyed("input", "saddr6", |r| r.match_saddr_v6(v6, 64).accept())
            .rule_keyed("input", "daddr6", |r| r.match_daddr_v6(v6, 128).accept())
            .rule_keyed("input", "saddr4-not", |r| r.match_saddr_v4_not(v4, 24).drop())
            .rule_keyed("input", "daddr4-not", |r| r.match_daddr_v4_not(v4, 32).drop())
            .rule_keyed("input", "saddr6-not", |r| r.match_saddr_v6_not(v6, 64).drop())
            .rule_keyed("input", "daddr6-not", |r| r.match_daddr_v6_not(v6, 128).drop())
            // Set lookups.
            .rule_keyed("input", "saddr-in-set", |r| {
                r.match_saddr_in_set("allow4").accept()
            })
            .rule_keyed("input", "daddr-in-set", |r| {
                r.match_daddr_in_set("allow4").accept()
            })
            // `ip saddr != @allow4`: NFT_LOOKUP_F_INV round-trips.
            .rule_keyed("input", "saddr-not-in-set", |r| {
                r.expressions(vec![
                    Expr::Meta {
                        dreg: Register::R0,
                        key: MetaKey::NfProto,
                    },
                    Expr::Cmp {
                        sreg: Register::R0,
                        op: CmpOp::Eq,
                        data: vec![2],
                    },
                    Expr::Payload {
                        dreg: Register::R0,
                        base: PayloadBase::Network,
                        offset: 12,
                        len: 4,
                    },
                    LookupExpr::new("allow4", Register::R0).invert().into(),
                ])
                .drop()
            })
            // Meta / conntrack.
            .rule_keyed("input", "iif", |r| r.match_iif("lo").accept())
            .rule_keyed("input", "oif", |r| r.match_oif("lo").accept())
            .rule_keyed("input", "mark", |r| r.match_mark(0x10).accept())
            .rule_keyed("input", "ct-state", |r| {
                r.match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
                    .accept()
            })
            // Statements.
            .rule_keyed("input", "counter", |r| r.match_tcp_dport(80).counter())
            .rule_keyed("input", "limit", |r| {
                r.match_tcp_dport(81).limit(10, LimitUnit::Second).accept()
            })
            .rule_keyed("input", "log-prefix", |r| {
                r.match_tcp_dport(82).log(Some("nlink: "))
            })
            .rule_keyed("input", "log-bare", |r| r.match_tcp_dport(83).log(None))
            .rule_keyed("input", "log-group", |r| {
                r.expr(LogExpr::new().prefix("nlink-group: ").group(5))
            })
            .rule_keyed("input", "set-mark", |r| r.match_tcp_dport(84).set_mark(1))
            .rule_keyed("input", "set-mark-masked", |r| {
                r.match_tcp_dport(89).set_mark_masked(0x10, 0xff)
            })
            .rule_keyed("input", "mark-masked", |r| {
                r.match_mark_masked(0x10, 0xff).accept()
            })
            .rule_keyed("input", "set-priority", |r| {
                r.match_tcp_dport(90).set_priority(TcHandle::new(1, 0x10))
            })
            .rule_keyed("input", "set-ct-mark", |r| r.match_tcp_dport(91).set_ct_mark(7))
            .rule_keyed("input", "ct-mark", |r| r.match_ct_mark(7).accept())
            .rule_keyed("input", "save-mark", |r| r.match_tcp_dport(92).save_mark_to_ct())
            .rule_keyed("input", "restore-mark", |r| {
                r.match_tcp_dport(93).restore_mark_from_ct()
            })
            // `rt tcpmss` is only valid in forward/output/postrouting.
            .rule_keyed("forward", "mss-pmtu", |r| {
                r.match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                    .clamp_tcp_mss_to_pmtu()
            })
            .rule_keyed("input", "mss", |r| {
                r.match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                    .clamp_tcp_mss(1360)
            })
            // Verdicts.
            .rule_keyed("input", "reject", |r| r.match_tcp_dport(85).reject())
            .rule_keyed("input", "reject-rst", |r| {
                r.match_tcp_dport(86).reject_with(NFT_REJECT_TCP_RST, 0)
            })
            .rule_keyed("input", "jump", |r| {
                r.match_tcp_dport(87).jump(ChainName::new("sub").unwrap())
            })
            .rule_keyed("input", "goto", |r| {
                r.match_tcp_dport(88).goto(ChainName::new("sub").unwrap())
            })
            .rule_keyed("sub", "return", |r| {
                r.expressions(vec![Expr::Verdict(Verdict::Return)])
            })
        });

        assert_reconciles(&conn, &cfg).await
    })
    .await
}

/// #480: every reject form, in `ip`, `ip6` and `inet` tables. In `ip` and
/// `ip6` nlink sends `reject()` as the family's ICMP code, not ICMPX; the
/// diff renders it the same way, or a declared reject would never converge.
/// Interface-name matches — exact, `!=`, and nft's `"prefix*"` — install
/// as nft writes them and reconcile. A name over 15 bytes was cut to 15,
/// which no interface has, so the rule never matched; it is an error now
/// (#484).
#[tokio::test]
async fn interface_name_matches_are_what_nft_writes() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-echo-ifname")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_timeout(async {
        let cfg = NftablesConfig::new().table("t", Family::Inet, |t| {
            t.chain("ifn", |c| {
                c.base(BaseChain::filter(FilterHook::Forward, Priority::Filter))
            })
            .rule_keyed("ifn", "iif", |r| r.match_iif("d0").accept())
            .rule_keyed("ifn", "iif-not", |r| r.match_iif_not("d0").drop())
            .rule_keyed("ifn", "iif-prefix", |r| r.match_iif_prefix("veth").accept())
            .rule_keyed("ifn", "oif-not", |r| r.match_oif_not("d1").accept())
            .rule_keyed("ifn", "oif-prefix", |r| r.match_oif_prefix("br").accept())
        });
        assert_reconciles(&conn, &cfg).await?;
        let shown = ns.exec("nft", &["list", "chain", "inet", "t", "ifn"])?;
        for line in [
            "iifname \"d0\" accept",
            "iifname != \"d0\" drop",
            "iifname \"veth*\" accept",
            "oifname != \"d1\" accept",
            "oifname \"br*\" accept",
        ] {
            assert!(shown.contains(line), "nft does not show `{line}`:\n{shown}");
        }

        let long = NftablesConfig::new().table("t", Family::Inet, |t| {
            t.chain("ifn", |c| c)
                .rule("ifn", |r| r.match_iif("a-sixteen-byte-n").accept())
        });
        let err = long
            .diff(&conn)
            .await
            .expect_err("a 16-byte interface name");
        assert!(err.to_string().contains("longer than 15 bytes"), "{err}");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reject_rules_reconcile_in_every_family() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "nf_tables",
        "nft_reject_ipv4",
        "nft_reject_ipv6",
        "nft_reject_inet"
    );

    let ns = TestNamespace::new("nft-echo-reject")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let mut cfg = NftablesConfig::new();
        for (name, family) in [
            ("r4", Family::Ip),
            ("r6", Family::Ip6),
            ("rx", Family::Inet),
        ] {
            cfg = cfg.table(name, family, |t| {
                let t = t
                    .chain("input", |c| {
                        c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
                    })
                    .rule_keyed("input", "reject", |r| r.match_tcp_dport(85).reject())
                    .rule_keyed("input", "rst", |r| r.reject_tcp_reset())
                    .rule_keyed("input", "rst-after-dport", |r| {
                        r.match_tcp_dport(86).reject_tcp_reset()
                    });
                match family {
                    Family::Ip => t.rule_keyed("input", "icmp", |r| r.reject_icmp(13)),
                    Family::Ip6 => t.rule_keyed("input", "icmpv6", |r| r.reject_icmpv6(1)),
                    _ => t
                        .rule_keyed("input", "icmp", |r| r.reject_icmp(13))
                        .rule_keyed("input", "icmpv6", |r| r.reject_icmpv6(1)),
                }
            });
        }
        assert_reconciles(&conn, &cfg).await
    })
    .await
}

/// NAT statements, which need `nat`-type chains.
#[tokio::test]
async fn every_nat_rule_shape_reconciles() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_nat", "nft_masq", "nft_redir");

    let ns = TestNamespace::new("nft-echo-nat")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let cfg = NftablesConfig::new().table("nat_shapes", Family::Inet, |t| {
            t.chain("postrouting", |c| {
                c.base(BaseChain::nat(NatHook::Postrouting, Priority::SrcNat))
            })
            .chain("prerouting", |c| {
                c.base(BaseChain::nat(NatHook::Prerouting, Priority::DstNat))
            })
            .rule_keyed("postrouting", "masq", |r| {
                r.match_saddr_v4("10.0.0.0".parse().unwrap(), 8).masquerade()
            })
            .rule_keyed("postrouting", "snat", |r| {
                r.match_saddr_v4("10.1.0.0".parse().unwrap(), 16)
                    .snat("192.0.2.1".parse().unwrap(), None)
            })
            .rule_keyed("postrouting", "snat-port", |r| {
                r.match_saddr_v4("10.2.0.0".parse().unwrap(), 16)
                    .snat("192.0.2.1".parse().unwrap(), Some(4000))
            })
            .rule_keyed("postrouting", "snat6", |r| {
                r.match_saddr_v6("fd00::".parse().unwrap(), 64)
                    .snat_v6("2001:db8::1".parse().unwrap(), None)
            })
            .rule_keyed("prerouting", "dnat", |r| {
                r.match_tcp_dport(8080)
                    .dnat("192.0.2.2".parse().unwrap(), Some(80))
            })
            .rule_keyed("prerouting", "dnat6", |r| {
                r.match_tcp_dport(8081)
                    .dnat_v6("2001:db8::2".parse().unwrap(), Some(80))
            })
            .rule_keyed("prerouting", "redir", |r| {
                r.match_tcp_dport(8082).redirect(None)
            })
            .rule_keyed("prerouting", "redir-port", |r| {
                r.match_tcp_dport(8083).redirect(Some(3128))
            })
        });

        assert_reconciles(&conn, &cfg).await
    })
    .await
}

/// `flow add @ft` against a declared flowtable.
#[tokio::test]
async fn flow_offload_rule_installs_and_reconciles() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nf_flow_table", "nft_flow_offload");

    let ns = TestNamespace::new("nft-echo-flow")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let cfg = NftablesConfig::new().table("flow", Family::Inet, |t| {
            t.flowtable("ft", |f| f)
                .chain("forward", |c| {
                    c.base(BaseChain::filter(FilterHook::Forward, Priority::Filter))
                })
                .rule_keyed("forward", "offload", |r| {
                    r.match_ct_state(CtState::ESTABLISHED).flow_offload("ft")
                })
        });

        assert_reconciles(&conn, &cfg).await
    })
    .await
}

/// #528: NAT with address and port ranges and flags — what nlink-lab's
/// firewall writes as `dnat … to 10.0.1.10:8000-8999` and `masquerade
/// random` — reconciles, and `nft` lists each statement as written.
#[tokio::test]
async fn nat_ranges_and_flags_reconcile_and_list_as_nft_writes_them() -> nlink::Result<()> {
    use nlink::netlink::nftables::NatStatement;
    require_root!();
    nlink::require_modules!("nf_tables", "nft_nat", "nft_masq", "nft_redir");

    let ns = TestNamespace::new("nft-echo-natrange")?;
    let conn = ns.connection_for::<Nftables>()?;
    let ip = |s: &str| -> std::net::IpAddr { s.parse().unwrap() };

    with_timeout(async {
        let cfg = NftablesConfig::new().table("natr", Family::Inet, |t| {
            t.chain("post", |c| {
                c.base(BaseChain::nat(NatHook::Postrouting, Priority::SrcNat))
            })
            .chain("pre", |c| {
                c.base(BaseChain::nat(NatHook::Prerouting, Priority::DstNat))
            })
            .rule_keyed("post", "snat-range", |r| {
                r.match_tcp_dport(1).nat(
                    NatStatement::snat(ip("10.0.0.1"))
                        .to(ip("10.0.0.9"))
                        .ports(40000, 40010)
                        .fully_random()
                        .persistent(),
                )
            })
            .rule_keyed("post", "snat6-range", |r| {
                r.match_tcp_dport(2)
                    .nat(NatStatement::snat(ip("2001:db8::1")).to(ip("2001:db8::9")))
            })
            .rule_keyed("post", "netmap", |r| {
                r.match_tcp_dport(3)
                    .nat(NatStatement::snat(ip("10.9.0.0")).to(ip("10.9.0.255")).netmap())
            })
            .rule_keyed("post", "masq-ports", |r| {
                r.match_tcp_dport(4).nat(NatStatement::masquerade().ports(1024, 2048).random())
            })
            .rule_keyed("pre", "dnat-port", |r| {
                r.match_tcp_dport(5).nat(NatStatement::dnat_to_port(Family::Ip, 8080))
            })
            .rule_keyed("pre", "dnat-range", |r| {
                r.match_tcp_dport(6)
                    .nat(NatStatement::dnat(ip("10.0.1.10")).ports(8000, 8999))
            })
            .rule_keyed("pre", "redir-range", |r| {
                r.match_tcp_dport(7).nat(NatStatement::redirect().ports(3000, 3010))
            })
        });
        assert_reconciles(&conn, &cfg).await?;

        let listed = ns.exec("nft", &["list", "table", "inet", "natr"])?;
        for want in [
            "snat ip to 10.0.0.1-10.0.0.9:40000-40010",
            "fully-random",
            "persistent",
            "snat ip6 to 2001:db8::1-2001:db8::9",
            // nft writes NF_NAT_RANGE_NETMAP as `prefix`. (This said
            // "netmap", which matched the rule's old `nlink:netmap` comment
            // whatever the flags were.)
            "snat ip prefix to 10.9.0.0/24",
            "masquerade to :1024-2048 random",
            "dnat ip to :8080",
            "dnat ip to 10.0.1.10:8000-8999",
            "redirect to :3000-3010",
        ] {
            assert!(listed.contains(want), "nft does not list {want:?}:\n{listed}");
        }
        Ok(())
    })
    .await
}

/// #528: byte-rate limits — in a rule, `over`, and as a named limit — and
/// the named ICMPX reject codes reconcile, and `nft` lists them as written.
#[tokio::test]
async fn byte_limits_and_icmpx_codes_reconcile_and_list() -> nlink::Result<()> {
    use nlink::netlink::nftables::{IcmpxCode, LimitExpr, LimitUnit};
    use nlink::Bytes;
    require_root!();
    nlink::require_modules!("nf_tables", "nft_limit", "nft_reject_inet");

    let ns = TestNamespace::new("nft-echo-bytes")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_timeout(async {
        let cfg = NftablesConfig::new().table("b", Family::Inet, |t| {
            t.chain("input", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
            })
            .object("tenk", nlink::netlink::nftables::ObjectConfig::Limit(LimitExpr::bytes(Bytes::kib(10), LimitUnit::Second).burst(2048)))
            .rule_keyed("input", "bytes", |r| {
                r.match_tcp_dport(1)
                    .expr(LimitExpr::bytes(Bytes::mib(10), LimitUnit::Second))
                    .accept()
            })
            .rule_keyed("input", "bytes-over", |r| {
                r.match_tcp_dport(2)
                    .expr(LimitExpr::bytes(Bytes::kib(1), LimitUnit::Minute).burst(4096).over())
                    .drop()
            })
            .rule_keyed("input", "host", |r| r.match_tcp_dport(3).reject_icmpx(IcmpxCode::HostUnreachable))
            .rule_keyed("input", "admin", |r| r.match_tcp_dport(4).reject_icmpx(IcmpxCode::AdminProhibited))
            .rule_keyed("input", "noroute", |r| r.match_tcp_dport(5).reject_icmpx(IcmpxCode::NoRoute))
        });
        assert_reconciles(&conn, &cfg).await?;

        let listed = ns.exec("nft", &["list", "table", "inet", "b"])?;
        for want in [
            "limit rate 10 mbytes/second",
            "limit rate over 1 kbytes/minute burst 4 kbytes",
            "rate 10 kbytes/second burst 2 kbytes",
            "icmpx",
            "host-unreachable",
            "admin-prohibited",
            "no-route",
        ] {
            assert!(listed.contains(want), "nft does not list {want:?}:\n{listed}");
        }
        Ok(())
    })
    .await
}

/// #528: ranges and the `!=`/`IpAddr` matchers reconcile, `nft` lists the
/// ranges as it writes them, and the ranges `nft` itself installs decode
/// as `RuleExpr::Range`.
#[tokio::test]
async fn ranges_and_negations_reconcile_and_match_nft() -> nlink::Result<()> {
    use nlink::netlink::nftables::{PacketField, RangeOp, RuleExpr};
    use std::net::IpAddr;
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-echo-range")?;
    let conn = ns.connection_for::<Nftables>()?;
    let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
    with_timeout(async {
        let cfg = NftablesConfig::new().table("r", Family::Inet, |t| {
            t.chain("input", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
            })
            .rule_keyed("input", "dports", |r| {
                r.match_range(PacketField::TcpDport, 1000u16, 2000u16).accept()
            })
            .rule_keyed("input", "not-dports", |r| {
                r.match_range_not(PacketField::UdpDport, 3000u16, 3010u16).accept()
            })
            .rule_keyed("input", "saddrs", |r| {
                r.match_range(PacketField::Ip4Saddr, ip("10.0.0.1"), ip("10.0.0.9")).accept()
            })
            .rule_keyed("input", "daddrs6", |r| {
                r.match_range_not(PacketField::Ip6Daddr, ip("fd00::1"), ip("fd00::ff")).accept()
            })
            .rule_keyed("input", "marks", |r| r.match_range(PacketField::Mark, 0x10u32, 0x20u32).accept())
            .rule_keyed("input", "generic", |r| {
                r.match_saddr(ip("192.0.2.0"), 24)
                    .match_daddr_not(ip("2001:db8::"), 32)
                    .match_tcp_sport_not(22)
                    .match_mark_not(7)
                    .match_l4proto_not(17)
                    .accept()
            })
        });
        assert_reconciles(&conn, &cfg).await?;
        let listed = ns.exec("nft", &["list", "table", "inet", "r"])?;
        for want in [
            "tcp dport 1000-2000",
            "udp dport != 3000-3010",
            "ip saddr 10.0.0.1-10.0.0.9",
            "ip6 daddr != fd00::1-fd00::ff",
            "meta mark 0x00000010-0x00000020",
            "tcp sport != 22",
            "meta mark != 0x00000007",
        ] {
            assert!(listed.contains(want), "nft does not list {want:?}:\n{listed}");
        }

        // And what nft writes, nlink reads.
        ns.exec("nft", &["add rule inet r input udp sport 5000-6000 meta mark != 0x1-0x2 accept"])?;
        let exprs: Vec<RuleExpr> = conn
            .list_rules("r", Family::Inet)
            .await?
            .into_iter()
            .flat_map(|r| r.expressions())
            .collect();
        let range = |op, from: Vec<u8>, to: Vec<u8>| {
            exprs.iter().any(|e| {
                matches!(e, RuleExpr::Range { op: o, from: f, to: t, .. } if *o == op && *f == from && *t == to)
            })
        };
        assert!(range(RangeOp::Neq, vec![0, 0, 0, 1], vec![0, 0, 0, 2]), "{exprs:?}");
        // nft 1.1 writes a port range as `range`; 1.0.6 (bookworm) as a
        // `cmp gte` and a `cmp lte`, which decode as they are.
        let cmp = |op, data: Vec<u8>| {
            exprs
                .iter()
                .any(|e| matches!(e, RuleExpr::Cmp { op: o, data: d, .. } if *o == op && *d == data))
        };
        assert!(
            range(RangeOp::Eq, vec![0x13, 0x88], vec![0x17, 0x70])
                || (cmp(CmpOp::Gte, vec![0x13, 0x88]) && cmp(CmpOp::Lte, vec![0x17, 0x70])),
            "{exprs:?}"
        );
        Ok(())
    })
    .await
}

/// #528: `fib`, `meta pkttype` and `notrack` are written exactly as `nft`
/// writes them — each rule nlink builds decodes to the same expressions
/// as the one `nft` installs from the same statement — and they reconcile.
/// The meta keys nlink did not name decode typed.
#[tokio::test]
async fn fib_pkttype_and_notrack_are_what_nft_writes() -> nlink::Result<()> {
    use nlink::netlink::nftables::{FibFlags, MetaKey, PktType, RuleExpr};
    use nlink::netlink::types::route::RouteType;
    require_root!();
    nlink::require_modules!("nf_tables", "nft_fib_inet", "nft_ct");

    let ns = TestNamespace::new("nft-echo-fib")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_timeout(async {
        let chain = |hook, priority| {
            move |c: nlink::netlink::nftables::config::DeclaredChainBuilder| {
                c.base(BaseChain::filter(hook, priority))
            }
        };
        let cfg = NftablesConfig::new().table("f", Family::Inet, |t| {
            t.chain("pre", chain(FilterHook::Prerouting, Priority::Filter))
                .chain("raw", chain(FilterHook::Prerouting, Priority::Raw))
                .rule_keyed("pre", "rpf", |r| {
                    r.match_fib_missing(FibFlags::SADDR | FibFlags::IIF).drop()
                })
                .rule_keyed("pre", "local", |r| {
                    r.match_fib_type(FibFlags::DADDR, RouteType::Local).accept()
                })
                .rule_keyed("pre", "bcast", |r| r.match_pkttype(PktType::Broadcast).drop())
                .rule_keyed("pre", "not-host", |r| r.match_pkttype_not(PktType::Host).drop())
                .rule_keyed("raw", "notrack", |r| r.match_udp_dport(53).notrack())
        });
        assert_reconciles(&conn, &cfg).await?;

        // The same statements, through nft, into a chain of their own.
        ns.exec("nft", &["add chain inet f theirs"])?;
        for statement in [
            "fib saddr . iif oif missing drop",
            "fib daddr type local accept",
            "meta pkttype broadcast drop",
            "meta pkttype != host drop",
            "udp dport 53 notrack",
        ] {
            ns.exec("nft", &[&format!("add rule inet f theirs {statement}")])?;
        }
        let rules = conn.list_rules("f", Family::Inet).await?;
        let exprs = |chain: &str| -> Vec<Vec<RuleExpr>> {
            rules.iter().filter(|r| r.chain == chain).map(|r| r.expressions()).collect()
        };
        let mine: Vec<_> = exprs("pre").into_iter().chain(exprs("raw")).collect();
        assert_eq!(mine, exprs("theirs"), "nlink writes what nft writes");

        // Keys nlink had no name for decode typed now.
        ns.exec("nft", &["add rule inet f theirs meta cpu 0 meta iifgroup 0 meta iifkind \"veth\" meta day \"Monday\" accept"])?;
        let keys: Vec<MetaKey> = conn
            .list_rules("f", Family::Inet)
            .await?
            .iter()
            .flat_map(|r| r.expressions())
            .filter_map(|e| match e {
                RuleExpr::Meta { key, .. } => Some(key),
                _ => None,
            })
            .collect();
        for key in [MetaKey::Cpu, MetaKey::IifGroup, MetaKey::IifKind, MetaKey::TimeDay] {
            assert!(keys.contains(&key), "{key:?} in {keys:?}");
        }
        Ok(())
    })
    .await
}

/// #528: the conntrack matches and sets nlink builds are what `nft`
/// installs from the same statements, and they reconcile.
#[tokio::test]
async fn ct_keys_are_what_nft_writes() -> nlink::Result<()> {
    use nlink::netlink::nftables::{CtDirection, CtStatus, RuleExpr};
    require_root!();
    nlink::require_modules!("nf_tables", "nft_ct", "nft_connlimit");

    let ns = TestNamespace::new("nft-echo-ct")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_timeout(async {
        let chain = |priority| {
            move |c: nlink::netlink::nftables::config::DeclaredChainBuilder| {
                c.base(BaseChain::filter(FilterHook::Prerouting, priority))
            }
        };
        let ip = "10.0.0.1".parse().unwrap();
        let cfg = NftablesConfig::new().table("c", Family::Inet, |t| {
            t.chain("raw", chain(Priority::Raw))
                .chain("pre", chain(Priority::Filter))
                .rule_keyed("raw", "zone-set", |r| r.set_ct_zone(7))
                .rule_keyed("pre", "status", |r| r.match_ct_status(CtStatus::DST_NAT).accept())
                .rule_keyed("pre", "direction", |r| r.match_ct_direction(CtDirection::Reply).accept())
                .rule_keyed("pre", "zone", |r| r.match_ct_zone(5).accept())
                .rule_keyed("pre", "orig-saddr", |r| r.match_ct_addr(CtDirection::Original, true, ip).accept())
                // nft 1.0.6 needs the protocol in context to parse a port.
                .rule_keyed("pre", "reply-dport", |r| {
                    r.match_l4proto(6).match_ct_port(CtDirection::Reply, false, 22).accept()
                })
                .rule_keyed("pre", "count", |r| r.match_ct_count_over(3).drop())
                .rule_keyed("pre", "label", |r| r.match_ct_label(5).accept())
                .rule_keyed("pre", "label-set", |r| r.set_ct_label(5))
        });
        assert_reconciles(&conn, &cfg).await?;

        ns.exec("nft", &["add chain inet c theirs-raw"])?;
        ns.exec("nft", &["add chain inet c theirs"])?;
        ns.exec("nft", &["add rule inet c theirs-raw ct zone set 7"])?;
        for statement in [
            "ct status dnat accept",
            "ct direction reply accept",
            "ct zone 5 accept",
            "ct original ip saddr 10.0.0.1 accept",
            "meta l4proto tcp ct reply proto-dst 22 accept",
            "ct count over 3 drop",
            "ct label 5 accept",
            "ct label set 5",
        ] {
            ns.exec("nft", &[&format!("add rule inet c theirs {statement}")])?;
        }
        let rules = conn.list_rules("c", Family::Inet).await?;
        let exprs = |chain: &str| -> Vec<Vec<RuleExpr>> {
            rules.iter().filter(|r| r.chain == chain).map(|r| r.expressions()).collect()
        };
        assert_eq!(exprs("raw"), exprs("theirs-raw"), "ct zone set");
        let (mine, theirs) = (exprs("pre"), exprs("theirs"));
        for (i, (m, t)) in mine.iter().zip(&theirs).enumerate() {
            assert_eq!(m, t, "rule {i}");
        }
        assert_eq!(mine.len(), theirs.len());
        Ok(())
    })
    .await
}

/// #528: comments on tables, chains, sets, set elements and objects — the
/// ones `nft list` shows — are written, read back and reconciled, and the
/// ones `nft` writes read back too. One longer than libnftnl allows fails.
#[tokio::test]
async fn comments_on_every_object_are_written_and_read() -> nlink::Result<()> {
    use nlink::netlink::nftables::{Chain, Object, SetElement};
    use std::net::Ipv4Addr;
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-echo-comment")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_timeout(async {
        let cfg = NftablesConfig::new().table("c", Family::Inet, |t| {
            t.comment("lab table")
                .chain("input", |c| {
                    c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
                        .comment("inbound")
                })
                .set("blocked", |s| {
                    s.key_type(SetKeyType::Ipv4Addr)
                        .comment("blocked hosts")
                        .element(SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 1)).with_comment("bad host"))
                        .ipv4(Ipv4Addr::new(10, 0, 0, 2))
                })
        });
        assert_reconciles(&conn, &cfg).await?;
        conn.add_object(&Object::counter("c", "pkts").comment("counted").family(Family::Inet))
            .await?;

        let listed = ns.exec("nft", &["list", "table", "inet", "c"])?;
        for want in [
            "comment \"lab table\"",
            "comment \"inbound\"",
            "comment \"blocked hosts\"",
            "10.0.0.1 comment \"bad host\"",
            "comment \"counted\"",
        ] {
            assert!(listed.contains(want), "nft does not list {want:?}:\n{listed}");
        }

        let table = conn.list_tables_in(Family::Inet).await?.into_iter().find(|t| t.name == "c");
        assert_eq!(table.and_then(|t| t.comment).as_deref(), Some("lab table"));
        let chains = conn.list_chains_in("c", Family::Inet).await?;
        assert_eq!(chains[0].comment.as_deref(), Some("inbound"));
        let sets = conn.list_sets_in("c", Family::Inet).await?;
        assert_eq!(sets[0].comment.as_deref(), Some("blocked hosts"));
        let elements = conn.list_set_elements("c", "blocked", Family::Inet).await?;
        let mut comments: Vec<_> = elements.iter().map(|e| e.comment()).collect();
        comments.sort();
        assert_eq!(comments, [None, Some("bad host")]);
        let objects = conn.list_objects_in("c", Family::Inet).await?;
        assert_eq!(objects[0].comment.as_deref(), Some("counted"));

        // What nft writes, nlink reads.
        ns.exec("nft", &["add table inet n { comment \"from nft\"; }"])?;
        ns.exec("nft", &["add chain inet n x { comment \"nft chain\"; }"])?;
        let table = conn.list_tables_in(Family::Inet).await?.into_iter().find(|t| t.name == "n");
        assert_eq!(table.and_then(|t| t.comment).as_deref(), Some("from nft"));
        let chains = conn.list_chains_in("n", Family::Inet).await?;
        assert_eq!(chains[0].comment.as_deref(), Some("nft chain"));

        // libnftnl's limit is 127 bytes and the NUL.
        let long = Chain::new("c", "long")?.family(Family::Inet).comment("x".repeat(128));
        let err = conn.add_chain(long).await.unwrap_err();
        assert!(err.to_string().contains("at most 127"), "{err}");
        Ok(())
    })
    .await
}

/// #703: the kernel keeps a comment as it was created. With
/// `recreate_on_comment_change`, a changed comment on a chain, a set or a
/// table is applied by creating it again — with its rules, its elements,
/// everything declared in the table — and the next diff is empty. Without
/// the option the diff does not compare comments, as before.
#[tokio::test]
async fn a_changed_comment_is_applied_by_recreating_with_the_option() -> nlink::Result<()> {
    use nlink::netlink::nftables::config::NftDiffOptions;
    use nlink::netlink::nftables::types::PacketField;
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-echo-recomment")?;
    let conn = ns.connection_for::<Nftables>()?;
    let cfg = |table: &str, chain: &str, set: &str| {
        let (table, chain, set) = (table.to_string(), chain.to_string(), set.to_string());
        NftablesConfig::new().table("c", Family::Inet, move |t| {
            t.comment(table)
                .chain("input", move |c| {
                    c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
                        .comment(chain)
                })
                .set("blocked", move |s| {
                    s.key_type(SetKeyType::Ipv4Addr)
                        .comment(set)
                        .ipv4(Ipv4Addr::new(10, 0, 0, 1))
                })
                .rule_keyed("input", "drop", |r| {
                    r.match_in_set(PacketField::Ip4Saddr, "blocked").drop()
                })
        })
    };
    let on = NftDiffOptions::default().recreate_on_comment_change(true);
    with_timeout(async {
        let first = cfg("t1", "c1", "s1");
        first.diff(&conn).await?.apply(&conn).await?;
        assert!(first.diff_with_options(&conn, &on).await?.is_empty());

        // Without the option, a changed comment is not seen.
        let chain = cfg("t1", "c2", "s1");
        assert!(chain.diff(&conn).await?.is_empty());

        let diff = chain.diff_with_options(&conn, &on).await?;
        // The chain, and its rule put back with it.
        let chains: Vec<_> = diff.chains().collect();
        let [Change::Recreate { cascade, .. }] = chains[..] else {
            panic!("one chain recreate: {diff}");
        };
        assert_eq!(cascade.len(), 1, "{diff}");
        assert_eq!(diff.change_count(), 1, "{diff}");
        diff.apply(&conn).await?;
        let again = chain.diff_with_options(&conn, &on).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");

        let set = cfg("t1", "c2", "s2");
        let diff = set.diff_with_options(&conn, &on).await?;
        assert_eq!(
            diff.sets().filter(|c| c.op() == "recreate").count(),
            1,
            "{diff}"
        );
        diff.apply(&conn).await?;
        let again = set.diff_with_options(&conn, &on).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");

        let table = cfg("t2", "c2", "s2");
        let diff = table.diff_with_options(&conn, &on).await?;
        assert_eq!(
            diff.tables().filter(|c| c.op() == "recreate").count(),
            1,
            "{diff}"
        );
        diff.apply(&conn).await?;
        let again = table.diff_with_options(&conn, &on).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");

        let listed = ns.exec("nft", &["list", "table", "inet", "c"])?;
        for want in [
            "comment \"t2\"",
            "comment \"c2\"",
            "comment \"s2\"",
            "elements = { 10.0.0.1 }",
            "ip saddr @blocked drop",
        ] {
            assert!(listed.contains(want), "nft does not list {want:?}:\n{listed}");
        }
        Ok(())
    })
    .await
}

// ============================================================================
// #708 — protocol guards as each family needs them
// ============================================================================

/// The protocol guards `nft --debug=netlink` shows for a chain's rules:
/// each `meta load` and the compare after it. (nft merges adjacent payload
/// loads, which nlink does not, so the rest of the rules differ.)
fn debug_guards(ns: &TestNamespace, family: &str, table: &str, chain: &str) -> nlink::Result<Vec<String>> {
    let lines = debug_exprs(ns, family, table, chain)?;
    Ok(lines
        .windows(2)
        .filter(|w| w[0].contains("meta load"))
        .map(|w| format!("{} {}", w[0], w[1]))
        .collect())
}

/// The expressions `nft --debug=netlink` shows for a chain's rules.
fn debug_exprs(ns: &TestNamespace, family: &str, table: &str, chain: &str) -> nlink::Result<Vec<String>> {
    let out = ns.exec("nft", &["--debug=netlink", "list", "chain", family, table, chain])?;
    Ok(out
        .lines()
        .filter(|l| l.trim_start().starts_with('['))
        .map(|l| l.trim().to_string())
        .collect())
}

/// #708: an address and two ports, matched in ip, inet, bridge and netdev
/// tables: nlink writes the protocol guards nft writes — once each, none an
/// ip table implies, the ethertype in bridge and netdev.
#[tokio::test]
async fn guards_are_written_as_nft_writes_them() -> nlink::Result<()> {
    use nlink::netlink::link::DummyLink;
    use nlink::netlink::nftables::Rule;
    use nlink::netlink::Route;
    require_root!();
    nlink::require_modules!("nf_tables", "dummy", "bridge");

    let ns = TestNamespace::new("nft-guards")?;
    let route: Connection<Route> = ns.connection()?;
    route.add_link(DummyLink::new("d0")).await?;
    let nft = ns.connection_for::<Nftables>()?;
    let line = "ip saddr 10.0.0.1 tcp dport 22 tcp sport 1 counter";
    for (family, hook) in [
        ("ip", "type filter hook input priority 0;"),
        ("inet", "type filter hook input priority 0;"),
        ("bridge", "type filter hook input priority 0;"),
        ("netdev", "type filter hook ingress device d0 priority 0;"),
    ] {
        let script = format!(
            "table {family} t {{\n chain a {{ {hook} {line}; }}\n chain b {{ {hook} }}\n}}\n"
        );
        let file = std::env::temp_dir().join(format!("nlink-guards-{family}-{}.nft", std::process::id()));
        std::fs::write(&file, script).map_err(nlink::Error::from)?;
        let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
        let _ = std::fs::remove_file(&file);
        installed?;
        let fam = match family {
            "ip" => Family::Ip,
            "inet" => Family::Inet,
            "bridge" => Family::Bridge,
            _ => Family::Netdev,
        };
        nft.add_rule(
            Rule::new("t", "b")
                .family(fam)
                .match_saddr_v4(Ipv4Addr::new(10, 0, 0, 1), 32)
                .match_tcp_dport(22)
                .match_tcp_sport(1)
                .counter(),
        )
        .await?;
        assert_eq!(
            debug_guards(&ns, family, "t", "b")?,
            debug_guards(&ns, family, "t", "a")?,
            "{family}: nlink's chain b, nft's chain a"
        );
    }
    Ok(())
}

/// #708: in a netdev table `meta nfproto` is the table's family, so the
/// IPv4 guard nlink put in front of an address never matched: an `ip
/// saddr` rule at ingress counted nothing. With the ethertype it counts
/// what the peer sends.
#[tokio::test]
async fn an_address_match_at_netdev_ingress_matches() -> nlink::Result<()> {
    use crate::common::counters::rule_packets;
    use crate::common::traffic::send_udp;
    require_root!();
    nlink::require_modules!("nf_tables", "veth");

    let pair = crate::common::topo::NsPair::new("nftguard", 97).await?;
    let a_addr = pair.a_addr;
    let cfg = NftablesConfig::new().table("t", Family::Netdev, |t| {
        t.chain("in", |c| {
            c.base(BaseChain::filter(
                FilterHook::ingress(pair.b_if),
                Priority::Filter,
            ))
        })
        .rule_keyed("in", "from-a", move |r| {
            r.match_saddr_v4(a_addr, 32).match_l4proto(17).counter()
        })
    });
    let nft = pair.b.connection_for::<Nftables>()?;
    cfg.diff(&nft).await?.apply(&nft).await?;
    let again = cfg.diff(&nft).await?;
    assert!(again.is_empty(), "second diff must be empty: {again}");
    send_udp(&pair.a, &[format!("{}:9", pair.b_addr)], 3);
    assert_eq!(rule_packets(&nft, "t", Family::Netdev, "in", 0).await?, 3);
    Ok(())
}

/// #708: a rule an older nlink installed with the guards it no longer
/// writes — here an `ip` table's implied `meta nfproto ipv4`, written raw so
/// that nothing drops it — is the rule declared without them: the diff is
/// empty and nothing is replaced on upgrade. (Applying the declaration
/// would replace nothing either; nft 1.0.6 cannot list such a rule at all.)
#[tokio::test]
async fn a_rule_installed_with_redundant_guards_diffs_empty() -> nlink::Result<()> {
    use nlink::netlink::nftables::{RawExpr, Rule, RuleExpr};
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-guards-old")?;
    let nft = ns.connection_for::<Nftables>()?;
    // `meta load nfproto => reg 1`, as attributes: DREG 1, KEY 15.
    let mut meta = Vec::new();
    for (ty, value) in [(1u16, 1u32), (2, 15)] {
        meta.extend_from_slice(&8u16.to_ne_bytes());
        meta.extend_from_slice(&ty.to_ne_bytes());
        meta.extend_from_slice(&value.to_be_bytes());
    }
    let declare = |old: bool| {
        let meta = meta.clone();
        NftablesConfig::new().table("t", Family::Ip, move |t| {
            t.chain("in", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
            })
            .rule_keyed("in", "k", move |r: Rule| {
                let r = if old {
                    r.expr(RawExpr::new("meta", meta.clone())).expr(Expr::Cmp {
                        sreg: Register::R0,
                        op: CmpOp::Eq,
                        data: vec![2],
                    })
                } else {
                    r
                };
                r.match_saddr_v4(Ipv4Addr::new(10, 0, 0, 1), 32)
                    .match_tcp_dport(22)
                    .accept()
            })
        })
    };
    declare(true).diff(&nft).await?.apply(&nft).await?;
    // Read through nlink: nft 1.0.6 aborts listing this very rule, an ip
    // table's payload behind a `meta nfproto` guard.
    let installed = nft.list_rules("t", Family::Ip).await?;
    let guarded = installed[0]
        .expressions()
        .iter()
        .any(|e| matches!(e, RuleExpr::Meta { key: MetaKey::NfProto, .. }));
    assert!(guarded, "{:?}", installed[0].expressions());
    let diff = declare(false).diff(&nft).await?;
    assert!(diff.is_empty(), "upgrading nlink must not replace the rule: {diff}");
    Ok(())
}
