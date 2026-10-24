//! #708: a rule built as a `RuleSpec` is the rule nft writes.
//!
//! nft is the reference encoder. For each case nft installs the rule from
//! its text in one table, nlink installs the spec in another table of the
//! same family, and the kernel must dump the two alike. The cases are mostly
//! matches no `Rule` method writes, which only the spec's own lowering
//! does: an order on a port or a mark, `!=` on a flag set or a name prefix,
//! a range on a conntrack field. Then rules declared as data converge.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nlink::netlink::Nftables;
use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    BaseChain, CtDirection, CtState, CtStatus, Family, FibFlags, FibResult, FilterHook, NatHook,
    NatStatement, PacketField, PktType, Priority, Rule, TcpFlags,
};
use nlink::netlink::nftables::{
    CmpOp, Field, Match, MatchOp, RuleExpr, RuleSpec, SocketKey, Stmt, Value, Verdict,
};
use nlink::netlink::types::route::RouteType;

use crate::common::TestNamespace;
use crate::common::converge::{assert_converges, case};

/// A table with the sets the cases look up, and a chain per case.
fn table(family: Family, name: &str, chains: usize) -> String {
    let sets = match family {
        Family::Bridge => "",
        _ => {
            "set sp { type inet_service; }
             set sm { type mark; flags interval; }"
        }
    };
    let chains: String = (0..chains).map(|i| format!("chain c{i} {{ }}\n")).collect();
    format!(
        "table {family} {name} {{
            {sets}
            {chains}
        }}\n"
    )
}

fn install(ns: &TestNamespace, script: &str) -> nlink::Result<()> {
    let file = std::env::temp_dir().join(format!("nlink-spec-{}.nft", std::process::id()));
    std::fs::write(&file, script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed.map(drop)
}

/// Each case: the rule as nft writes it, and as a spec.
fn cases(family: Family) -> Vec<(&'static str, RuleSpec)> {
    let v4 = |s: &str| IpAddr::V4(s.parse::<Ipv4Addr>().unwrap());
    let v6 = |s: &str| IpAddr::V6(s.parse::<Ipv6Addr>().unwrap());
    let one = |m: Match| RuleSpec::new().then(m);
    let mut cases = vec![
        (
            "tcp dport >= 1024",
            one(Match::new(Field::TcpDport, MatchOp::Ge, 1024u16)),
        ),
        (
            "tcp dport < 1024",
            one(Match::new(Field::TcpDport, MatchOp::Lt, 1024u16)),
        ),
        (
            "udp sport > 53",
            one(Match::new(Field::UdpSport, MatchOp::Gt, 53u16)),
        ),
        (
            "udp dport <= 53",
            one(Match::new(Field::UdpDport, MatchOp::Le, 53u16)),
        ),
        (
            "udp sport != 1000-2000",
            one(Match::ne(Field::UdpSport, Value::range(1000u16, 2000u16))),
        ),
        (
            "tcp sport 1000-2000",
            one(Match::eq(Field::TcpSport, Value::range(1000u16, 2000u16))),
        ),
        (
            "tcp dport != @sp",
            one(Match::ne(Field::TcpDport, Value::set("sp"))),
        ),
        (
            "iifname != \"veth*\"",
            one(Match::ne(Field::Iifname, Value::NamePrefix("veth".into()))),
        ),
        ("oifname != \"lo\"", one(Match::ne(Field::Oifname, "lo"))),
        (
            "ct state != established",
            one(Match::ne(Field::CtState, CtState::ESTABLISHED)),
        ),
        (
            "ct state established,related",
            one(Match::eq(
                Field::CtState,
                CtState::ESTABLISHED | CtState::RELATED,
            )),
        ),
        (
            "ct status != dnat",
            one(Match::ne(Field::CtStatus, CtStatus::DST_NAT)),
        ),
        (
            "ct direction != reply",
            one(Match::ne(Field::CtDirection, CtDirection::Reply)),
        ),
        ("ct zone != 3", one(Match::ne(Field::CtZone, 3u16))),
        (
            "ct zone > 3",
            one(Match::new(Field::CtZone, MatchOp::Gt, 3u16)),
        ),
        (
            "ct mark 0x10-0x20",
            one(Match::eq(Field::CtMark, Value::range(0x10u32, 0x20u32))),
        ),
        ("ct mark != 0x5", one(Match::ne(Field::CtMark, 5u32))),
        (
            "ct mark < 0x100",
            one(Match::new(Field::CtMark, MatchOp::Lt, 0x100u32)),
        ),
        ("ct label != 3", one(Match::ne(Field::CtLabel, 3u8))),
        ("ct label 3", one(Match::eq(Field::CtLabel, 3u8))),
        (
            "ct state != established,related",
            one(Match::ne(
                Field::CtState,
                CtState::ESTABLISHED | CtState::RELATED,
            )),
        ),
        (
            "ct state == established",
            one(Match::eq(Field::CtState, 2u32)),
        ),
        (
            "ct state & (established | related) == 0",
            one(Match::eq(
                Field::CtState,
                Value::Masked { value: 0, mask: 6 },
            )),
        ),
        (
            "ct status dnat,snat",
            one(Match::eq(
                Field::CtStatus,
                CtStatus::DST_NAT | CtStatus::SRC_NAT,
            )),
        ),
        (
            "meta mark > 0x10",
            one(Match::new(Field::Mark, MatchOp::Gt, 0x10u32)),
        ),
        (
            "meta mark <= 0x10000",
            one(Match::new(Field::Mark, MatchOp::Le, 0x10000u32)),
        ),
        (
            "meta mark & 0xff00 != 0x100",
            one(Match::ne(
                Field::Mark,
                Value::Masked {
                    value: 0x100,
                    mask: 0xff00,
                },
            )),
        ),
        (
            "meta mark != 0x10-0x20",
            one(Match::ne(Field::Mark, Value::range(0x10u32, 0x20u32))),
        ),
        (
            "meta mark @sm",
            one(Match::eq(Field::Mark, Value::IntervalSet("sm".into()))),
        ),
        ("meta l4proto != tcp", one(Match::ne(Field::L4Proto, 6u8))),
        (
            "meta l4proto 6-17",
            one(Match::eq(Field::L4Proto, Value::range(6u8, 17u8))),
        ),
        (
            "meta pkttype != broadcast",
            one(Match::ne(Field::PktType, PktType::Broadcast)),
        ),
        (
            "tcp flags & (syn | ack) != syn",
            one(Match::ne(
                Field::TcpFlags,
                Value::Masked {
                    value: TcpFlags::SYN.bits().into(),
                    mask: (TcpFlags::SYN | TcpFlags::ACK).bits().into(),
                },
            )),
        ),
        (
            "tcp flags == syn",
            one(Match::eq(Field::TcpFlags, TcpFlags::SYN.bits())),
        ),
        (
            "tcp flags syn,ack",
            one(Match::eq(Field::TcpFlags, TcpFlags::SYN | TcpFlags::ACK)),
        ),
        (
            "tcp flags != syn",
            one(Match::ne(Field::TcpFlags, TcpFlags::SYN)),
        ),
        (
            "meta l4proto udp ct original proto-src 1000-2000",
            RuleSpec::new()
                .then(Match::eq(Field::L4Proto, 17u8))
                .then(Match::eq(
                    Field::CtSport(CtDirection::Original),
                    Value::range(1000u16, 2000u16),
                )),
        ),
        (
            "meta l4proto tcp ct reply proto-dst != 80",
            RuleSpec::new()
                .then(Match::eq(Field::L4Proto, 6u8))
                .then(Match::ne(Field::CtDport(CtDirection::Reply), 80u16)),
        ),
        (
            "socket wildcard 1",
            one(Match::eq(Field::Socket(SocketKey::Wildcard), true)),
        ),
        (
            "socket mark 0x7",
            one(Match::eq(Field::Socket(SocketKey::Mark), 7u32)),
        ),
        (
            "tcp dport 22 counter accept",
            RuleSpec::new()
                .then(Match::eq(Field::TcpDport, 22u16))
                .then(Stmt::Counter)
                .then(Verdict::Accept),
        ),
    ];
    if matches!(family, Family::Inet | Family::Ip) {
        cases.extend([
            // A prefix not on a byte boundary: nft shortens a /8, /16 or
            // /24 to a load of its bytes, where nlink has always masked the
            // whole address. Both list alike.
            (
                "ip saddr != 10.16.0.0/12",
                one(Match::ne(
                    Field::Ip4Saddr,
                    Value::Prefix(v4("10.16.0.0"), 12),
                )),
            ),
            (
                "ip daddr 10.0.0.0/23",
                one(Match::eq(
                    Field::Ip4Daddr,
                    Value::Prefix(v4("10.0.0.0"), 23),
                )),
            ),
            (
                "ip daddr >= 10.0.0.9",
                one(Match::new(Field::Ip4Daddr, MatchOp::Ge, v4("10.0.0.9"))),
            ),
            (
                "ip daddr != 10.0.0.1-10.0.0.9",
                one(Match::ne(
                    Field::Ip4Daddr,
                    Value::range(v4("10.0.0.1"), v4("10.0.0.9")),
                )),
            ),
            (
                "icmp type != echo-request",
                one(Match::ne(Field::IcmpType, 8u8)),
            ),
            (
                "ct reply ip daddr != 1.2.3.4",
                one(Match::ne(Field::CtDaddr(CtDirection::Reply), v4("1.2.3.4"))),
            ),
            (
                "fib daddr oif exists",
                one(Match::eq(
                    Field::Fib {
                        flags: FibFlags::DADDR,
                        result: FibResult::Oif,
                    },
                    true,
                )),
            ),
            (
                "fib daddr type != local",
                one(Match::ne(
                    Field::Fib {
                        flags: FibFlags::DADDR,
                        result: FibResult::AddrType,
                    },
                    RouteType::Local,
                )),
            ),
        ]);
    }
    if matches!(family, Family::Inet | Family::Ip6) {
        cases.extend([
            (
                "ip6 daddr != fc00::/7",
                one(Match::ne(Field::Ip6Daddr, Value::Prefix(v6("fc00::"), 7))),
            ),
            (
                "ip6 saddr < ::9",
                one(Match::new(Field::Ip6Saddr, MatchOp::Lt, v6("::9"))),
            ),
            (
                "icmpv6 type != echo-request",
                one(Match::ne(Field::Icmp6Type, 128u8)),
            ),
        ]);
    }
    if family == Family::Bridge {
        cases.extend([
            (
                "ip saddr 10.0.0.1",
                one(Match::eq(Field::Ip4Saddr, v4("10.0.0.1"))),
            ),
            (
                "ip6 daddr != ::1",
                one(Match::ne(Field::Ip6Daddr, v6("::1"))),
            ),
            (
                "tcp dport >= 1024",
                one(Match::new(Field::TcpDport, MatchOp::Ge, 1024u16)),
            ),
        ]);
        cases.retain(|(text, _)| !text.contains('@') && !text.starts_with("socket"));
    }
    cases
}

const FAMILIES: [Family; 4] = [Family::Inet, Family::Ip, Family::Ip6, Family::Bridge];

#[tokio::test]
async fn a_spec_is_the_rule_nft_writes() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_ct", "nft_fib_inet", "nft_socket");

    let ns = TestNamespace::new("nft-spec")?;
    let nft = ns.connection_for::<Nftables>()?;
    let mut wrong = Vec::new();
    for family in FAMILIES {
        let cases = cases(family);
        install(
            &ns,
            &(table(family, "theirs", cases.len()) + &table(family, "ours", cases.len())),
        )?;
        for (i, (text, spec)) in cases.iter().enumerate() {
            let chain = format!("c{i}");
            ns.exec(
                "nft",
                &["add", "rule", family.name(), "theirs", &chain, text],
            )?;
            let rule = Rule::from_spec("ours", &chain, spec.clone()).family(family);
            if let Err(e) = nft.add_rule(rule).await {
                wrong.push(format!("{family} {text}: {e}"));
            }
        }
        let theirs = nft.list_rules("theirs", family).await?;
        let ours = nft.list_rules("ours", family).await?;
        for (i, (text, spec)) in cases.iter().enumerate() {
            let chain = format!("c{i}");
            let one = |rules: &[nlink::netlink::nftables::types::RuleInfo]| {
                rules
                    .iter()
                    .find(|r| r.chain == chain)
                    .map(|r| (r.expression_bytes.clone(), r.expressions()))
            };
            match (one(&theirs), one(&ours)) {
                (Some((a, _)), Some((b, _))) if a == b => {}
                (Some((_, a)), Some((_, b))) if as_nft_1_1(&a) == as_nft_1_1(&b) => {}
                (Some((_, a)), Some((_, b))) => wrong.push(format!(
                    "{family} {text}:\n   nft: {a:?}\n  ours: {b:?}\n  spec: {spec:?}"
                )),
                (_, None) => {}
                (None, _) => wrong.push(format!("{family} {text}: nft installed nothing")),
            }
            // The rule nft wrote lifts back to the spec (#708), or where nft
            // 1.0 wrote it otherwise, the rule nlink wrote does.
            let rule = |rules: &[nlink::netlink::nftables::types::RuleInfo]| {
                rules.iter().find(|r| r.chain == chain).cloned()
            };
            if let (Some(theirs), Some(ours)) = (rule(&theirs), rule(&ours)) {
                let lifted = if theirs.expression_bytes == ours.expression_bytes {
                    theirs.spec()
                } else {
                    ours.spec()
                };
                if lifted.items() != spec.items() {
                    wrong.push(format!(
                        "{family} {text}: lifts to {:?}\n  not {:?}",
                        lifted.items(),
                        spec.items()
                    ));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} specs are not the rule nft writes:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    Ok(())
}

/// A rule's expressions as nft 1.1 writes them. nft 1.0 (the CI lane's,
/// from Debian bookworm) writes a `==` range on a conntrack or meta field
/// as two compares, `>= first` and `<= last`, where 1.1 writes `range eq`,
/// as nlink does. The two match alike.
fn as_nft_1_1(exprs: &[RuleExpr]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < exprs.len() {
        if let (
            RuleExpr::Cmp {
                sreg,
                op: CmpOp::Gte,
                data: from,
                ..
            },
            Some(RuleExpr::Cmp {
                sreg: last,
                op: CmpOp::Lte,
                data: to,
                ..
            }),
        ) = (&exprs[i], exprs.get(i + 1))
            && sreg == last
        {
            out.push(format!(
                "Range {{ sreg: {sreg:?}, op: Eq, from: {from:?}, to: {to:?} }}"
            ));
            i += 2;
            continue;
        }
        out.push(format!("{:?}", exprs[i]));
        i += 1;
    }
    out
}

/// What nlink-lab writes by hand today (#527): a port range with `!=`, an
/// interface with `!=`, an address of either family from one value, and a
/// NAT rule whose parts are parsed before the rule exists. Declared as data,
/// each converges.
#[tokio::test]
async fn rules_declared_as_data_converge() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_nat", "nft_ct");

    let addr = |s: &str| -> nlink::Result<(IpAddr, u8)> {
        let (a, p) = s.split_once('/').unwrap_or((s, ""));
        let a: IpAddr = a
            .parse()
            .map_err(|_| nlink::Error::invalid_message(format!("{s}: no address")))?;
        let p = if p.is_empty() {
            if a.is_ipv4() { 32 } else { 128 }
        } else {
            p.parse().unwrap()
        };
        Ok((a, p))
    };
    let saddr = |s: &str| -> nlink::Result<Match> {
        let (a, p) = addr(s)?;
        let field = if a.is_ipv4() {
            Field::Ip4Saddr
        } else {
            Field::Ip6Saddr
        };
        Ok(Match::eq(field, Value::Prefix(a, p)))
    };
    let filter = |family, specs: Vec<(&'static str, RuleSpec)>| {
        NftablesConfig::new().table("t", family, move |mut t| {
            t = t.chain("input", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
            });
            for (key, spec) in specs {
                t = t.push_rule_keyed("input", key, spec);
            }
            t
        })
    };
    let ports = |lo: u16, hi: u16| {
        RuleSpec::new()
            .then(Match::ne(Field::TcpDport, Value::range(lo, hi)))
            .then(Match::ne(Field::Iifname, "lo"))
            .then(Stmt::Counter)
            .then(Verdict::Drop)
    };
    let from = |s: &str| -> nlink::Result<RuleSpec> {
        Ok(RuleSpec::new()
            .then(saddr(s)?)
            .then(Verdict::Accept)
            .comment("trusted"))
    };
    let nat = |src: &str, to: &str| -> nlink::Result<RuleSpec> {
        let (to, _) = addr(to)?;
        Ok(RuleSpec::new()
            .then(saddr(src)?)
            .then(Match::ne(Field::Oifname, "lo"))
            .then(Stmt::Nat(NatStatement::snat(to).ports(1024, 65535))))
    };
    let nat_table = |spec: RuleSpec| {
        NftablesConfig::new().table("n", Family::Ip, move |t| {
            t.chain("post", |c| {
                c.base(BaseChain::nat(NatHook::Postrouting, Priority::SrcNat))
            })
            .push_rule_keyed("post", "snat", spec)
        })
    };

    assert_converges(
        "nft-spec-conv",
        vec![
            case(
                "a port range and an interface, then another range",
                vec![
                    filter(Family::Inet, vec![("ports", ports(1000, 2000))]),
                    filter(Family::Inet, vec![("ports", ports(3000, 4000))]),
                ],
            ),
            case(
                "an address of each family, from one parser",
                vec![
                    filter(
                        Family::Inet,
                        vec![("v4", from("10.0.0.0/8")?), ("v6", from("fd00::/8")?)],
                    ),
                    filter(
                        Family::Inet,
                        vec![("v4", from("10.1.0.0/16")?), ("v6", from("fd00::1")?)],
                    ),
                ],
            ),
            case(
                "a set lookup and a range on a mark",
                vec![filter(
                    Family::Ip,
                    vec![
                        (
                            "mark",
                            RuleSpec::new()
                                .then(Match::eq(Field::Mark, Value::range(0x10u32, 0x20u32)))
                                .then(Match::new(Field::CtMark, MatchOp::Gt, 3u32))
                                .then(Verdict::Accept),
                        ),
                        (
                            "established",
                            RuleSpec::new()
                                .then(Match::eq(
                                    Field::CtState,
                                    CtState::ESTABLISHED | CtState::RELATED,
                                ))
                                .then(Match::eq(PacketField::TcpDport, 22u16))
                                .then(Verdict::Accept),
                        ),
                    ],
                )],
            ),
            case(
                "a NAT rule parsed before it exists",
                vec![
                    nat_table(nat("10.0.0.0/24", "192.0.2.1")?),
                    nat_table(nat("10.0.1.0/24", "192.0.2.2")?),
                ],
            ),
        ],
    )
    .await
}

/// A rule whose parts do not parse fails `validate()`, with the closure's
/// error, rather than being built wrong or panicking.
#[test]
fn a_rule_that_fails_to_build_fails_the_config() {
    let parse = |s: &str| -> nlink::Result<IpAddr> {
        s.parse()
            .map_err(|_| nlink::Error::invalid_message(format!("`{s}` is no address")))
    };
    let cfg = NftablesConfig::new().table("t", Family::Inet, |t| {
        t.chain("input", |c| c).try_rule_keyed("input", "k", |r| {
            Ok(r.match_saddr(parse("10.0.0.300")?, 32).accept())
        })
    });
    let e = cfg.validate().unwrap_err().to_string();
    assert!(e.contains("t/input: `10.0.0.300` is no address"), "{e}");
    assert_eq!(e.matches("invalid message").count(), 1, "{e}");

    // An error with a context keeps it, once.
    let cfg = NftablesConfig::new().table("t", Family::Inet, |t| {
        t.chain("input", |c| c).try_rule("input", |r| {
            let addr = parse("::g").map_err(|e| e.with_context("reading trusted"))?;
            Ok(r.match_saddr(addr, 128).accept())
        })
    });
    let e = cfg.validate().unwrap_err().to_string();
    assert!(
        e.contains("t/input: reading trusted: `::g` is no address"),
        "{e}"
    );
    assert_eq!(e.matches("invalid message").count(), 1, "{e}");

    let cfg = NftablesConfig::new().table("t", Family::Inet, |t| {
        t.chain("input", |c| c).push_rule(
            "input",
            RuleSpec::new().then(Match::eq(Field::TcpDport, 70000u32)),
        )
    });
    let e = cfg.validate().unwrap_err().to_string();
    assert!(
        e.contains("t/input: tcp dport: 70000 does not fit in 16 bits"),
        "{e}"
    );
}
