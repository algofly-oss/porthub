//! Transition matrices: every declared field changed from one value to
//! another in a single apply, which must converge (the diff empty after
//! it, a second apply changing nothing). Most of 0.30's bugs needed a
//! change in place to show (#534); the cases here cover the fields no
//! issue named.

use std::net::{IpAddr, Ipv4Addr};

use nlink::netlink::config::{
    BondAdSelect, BondLacpRate, BondMode, BondXmitHashPolicy, MacvlanMode, NetworkConfig,
    VlanProtocol,
};

use crate::common::TestNamespace;
use crate::common::converge::{assert_converges, case, ip_json};

const MAC_A: [u8; 6] = [0x02, 0x00, 0x5e, 0x20, 0x00, 0x01];
const MAC_B: [u8; 6] = [0x02, 0x00, 0x5e, 0x20, 0x00, 0x02];

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// The kernel's `ip -j -d link show dev <dev>` object, through `ip`, not
/// nlink: a diff that does not compare a field agrees with anything.
fn link_json(ns: &TestNamespace, dev: &str) -> Result<serde_json::Value, String> {
    let all = ip_json(ns, &["-d", "link", "show", "dev", dev])?;
    Ok(all[0].clone())
}

/// A check that `dev`'s `ip -j -d link` holds each `(path, value)`, with
/// `path` dotted (`linkinfo.info_data.mode`).
fn expect_link(
    dev: &'static str,
    want: &'static [(&'static str, &'static str)],
) -> impl Fn(&TestNamespace) -> Result<(), String> + 'static {
    move |ns| {
        let link = link_json(ns, dev)?;
        for (path, value) in want {
            let mut at = &link;
            for key in path.split('.') {
                at = &at[key];
            }
            let got = match at {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if got != *value {
                return Err(format!("{dev} {path}: want {value}, the kernel has {got}"));
            }
        }
        Ok(())
    }
}

/// A check that `ip -j route show table all <dst>` lists exactly one route,
/// whose fields hold each `(key, value)` — `type` is "unicast" when `ip`
/// leaves it out.
fn expect_route(
    family: &'static str,
    dst: &'static str,
    want: &'static [(&'static str, &'static str)],
) -> impl Fn(&TestNamespace) -> Result<(), String> + 'static {
    move |ns| {
        let routes = ip_json(ns, &[family, "route", "show", "table", "all", dst])?;
        let routes = routes.as_array().cloned().unwrap_or_default();
        let [route] = routes.as_slice() else {
            return Err(format!("{dst}: want one route, the kernel has {routes:?}"));
        };
        for (key, value) in want {
            let got = match &route[*key] {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null if *key == "type" => "unicast".to_string(),
                other => other.to_string(),
            };
            if got != *value {
                return Err(format!("{dst} {key}: want {value}, the kernel has {got}"));
            }
        }
        Ok(())
    }
}

/// A check that `d0`'s root qdisc is `kind`, with each `(option, value)`
/// in `tc -j qdisc show`'s options.
fn expect_qdisc(
    kind: &'static str,
    want: &'static [(&'static str, &'static str)],
) -> impl Fn(&TestNamespace) -> Result<(), String> + 'static {
    move |ns| {
        let out = ns
            .exec("tc", &["-j", "qdisc", "show", "dev", "d0"])
            .map_err(|e| e.to_string())?;
        let qdiscs: serde_json::Value = serde_json::from_str(&out).map_err(|e| e.to_string())?;
        let root = qdiscs
            .as_array()
            .and_then(|q| {
                q.iter()
                    .find(|q| q["root"] == serde_json::Value::Bool(true))
            })
            .ok_or_else(|| format!("no root qdisc: {out}"))?;
        if root["kind"] != kind {
            return Err(format!("root is {}, not {kind}", root["kind"]));
        }
        for (key, value) in want {
            let got = match &root["options"][*key] {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if got != *value {
                return Err(format!("{kind} {key}: want {value}, the kernel has {got}"));
            }
        }
        Ok(())
    }
}

/// A dummy `d0` up, plus whatever `f` declares on it.
fn dummy(
    f: impl FnOnce(nlink::netlink::config::LinkBuilder) -> nlink::netlink::config::LinkBuilder + 'static,
) -> NetworkConfig {
    NetworkConfig::new().link("d0", move |l| f(l.dummy().up()))
}

#[tokio::test]
async fn link_fields_change_in_place() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "dummy", "bridge", "8021q", "vxlan", "macvlan", "bonding", "vrf"
    );

    let two_bridges = |master: Option<&'static str>| {
        NetworkConfig::new()
            .link("br0", |l| l.bridge().up())
            .link("br1", |l| l.bridge().up())
            .link("d0", move |l| match master {
                Some(m) => l.dummy().up().master(m),
                None => l.dummy().up().nomaster(),
            })
    };
    let vlan = |proto: VlanProtocol| {
        dummy(|l| l).link("v0", move |l| l.vlan("d0", 10).vlan_protocol(proto).up())
    };
    let vxlan = |remote: IpAddr, local: IpAddr, port: u16, under: &'static str| {
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("d1", |l| l.dummy().up())
            .address("d0", "10.30.0.1/24")
            .unwrap()
            .address("d1", "10.31.0.1/24")
            .unwrap()
            .link("vx0", move |l| {
                l.vxlan(100)
                    .vxlan_remote(remote)
                    .vxlan_local(local)
                    .vxlan_port(port)
                    .vxlan_underlay_dev(under)
                    .up()
            })
    };
    let macvlan = |mode: MacvlanMode| {
        dummy(|l| l).link("mv0", move |l| l.macvlan("d0").macvlan_mode(mode).up())
    };
    let bond =
        |f: fn(nlink::netlink::config::LinkBuilder) -> nlink::netlink::config::LinkBuilder| {
            NetworkConfig::new().link("bond0", move |l| f(l.bond()).up())
        };

    let cases = vec![
        case(
            "mtu",
            vec![
                dummy(|l| l.mtu(1400)),
                dummy(|l| l.mtu(1500)),
                dummy(|l| l.mtu(9000)),
            ],
        )
        .check(expect_link("d0", &[("mtu", "9000")])),
        case(
            "state",
            vec![
                NetworkConfig::new().link("d0", |l| l.dummy().up()),
                NetworkConfig::new().link("d0", |l| l.dummy().down()),
                NetworkConfig::new().link("d0", |l| l.dummy().up()),
            ],
        ),
        case(
            "mac",
            vec![dummy(|l| l.address(MAC_A)), dummy(|l| l.address(MAC_B))],
        )
        .check(expect_link("d0", &[("address", "02:00:5e:20:00:02")])),
        case(
            "master",
            vec![
                two_bridges(Some("br0")),
                two_bridges(Some("br1")),
                two_bridges(None),
            ],
        )
        .check(expect_link("d0", &[("master", "null")])),
        case(
            "vlan-protocol",
            vec![vlan(VlanProtocol::Dot1q), vlan(VlanProtocol::Dot1ad)],
        )
        .check(expect_link(
            "v0",
            &[("linkinfo.info_data.protocol", "802.1ad")],
        )),
        case(
            "vxlan-remote",
            vec![
                vxlan(v4(10, 30, 0, 2), v4(10, 30, 0, 1), 4789, "d0"),
                vxlan(v4(10, 30, 0, 3), v4(10, 30, 0, 1), 4789, "d0"),
            ],
        )
        .check(expect_link(
            "vx0",
            &[("linkinfo.info_data.remote", "10.30.0.3")],
        )),
        case(
            "vxlan-local-and-underlay",
            vec![
                vxlan(v4(10, 30, 0, 2), v4(10, 30, 0, 1), 4789, "d0"),
                vxlan(v4(10, 31, 0, 2), v4(10, 31, 0, 1), 4789, "d1"),
            ],
        )
        .check(expect_link(
            "vx0",
            &[
                ("linkinfo.info_data.local", "10.31.0.1"),
                ("linkinfo.info_data.link", "d1"),
            ],
        )),
        case(
            "vxlan-port",
            vec![
                vxlan(v4(10, 30, 0, 2), v4(10, 30, 0, 1), 4789, "d0"),
                vxlan(v4(10, 30, 0, 2), v4(10, 30, 0, 1), 4790, "d0"),
            ],
        )
        .check(expect_link("vx0", &[("linkinfo.info_data.port", "4790")])),
        case(
            "macvlan-mode",
            vec![
                macvlan(MacvlanMode::Bridge),
                macvlan(MacvlanMode::Private),
                macvlan(MacvlanMode::Vepa),
            ],
        )
        .check(expect_link("mv0", &[("linkinfo.info_data.mode", "vepa")])),
        case(
            "bond-miimon-and-delays",
            vec![
                bond(|b| b.bond_mode(BondMode::ActiveBackup).miimon(100)),
                bond(|b| {
                    b.bond_mode(BondMode::ActiveBackup)
                        .miimon(200)
                        .bond_updelay(400)
                        .bond_downdelay(200)
                }),
            ],
        )
        .check(expect_link(
            "bond0",
            &[
                ("linkinfo.info_data.miimon", "200"),
                ("linkinfo.info_data.updelay", "400"),
                ("linkinfo.info_data.downdelay", "200"),
            ],
        )),
        case(
            "bond-hash-policy-and-min-links",
            vec![
                bond(|b| {
                    b.bond_mode(BondMode::BalanceXor)
                        .xmit_hash_policy(BondXmitHashPolicy::Layer2)
                }),
                bond(|b| {
                    b.bond_mode(BondMode::BalanceXor)
                        .xmit_hash_policy(BondXmitHashPolicy::Layer34)
                        .min_links(1)
                }),
            ],
        )
        .check(expect_link(
            "bond0",
            &[
                ("linkinfo.info_data.xmit_hash_policy", "layer3+4"),
                ("linkinfo.info_data.min_links", "1"),
            ],
        )),
        case(
            "bond-lacp",
            vec![
                bond(|b| {
                    b.bond_mode(BondMode::Ieee802_3ad)
                        .bond_lacp_rate(BondLacpRate::Slow)
                        .bond_ad_select(BondAdSelect::Stable)
                }),
                bond(|b| {
                    b.bond_mode(BondMode::Ieee802_3ad)
                        .bond_lacp_rate(BondLacpRate::Fast)
                        .bond_ad_select(BondAdSelect::Bandwidth)
                }),
            ],
        )
        .check(expect_link(
            "bond0",
            &[
                ("linkinfo.info_data.ad_lacp_rate", "fast"),
                ("linkinfo.info_data.ad_select", "bandwidth"),
            ],
        )),
        case(
            "bond-resend-igmp",
            vec![
                bond(|b| b.bond_mode(BondMode::ActiveBackup).bond_resend_igmp(1)),
                bond(|b| b.bond_mode(BondMode::ActiveBackup).bond_resend_igmp(3)),
            ],
        )
        .check(expect_link(
            "bond0",
            &[("linkinfo.info_data.resend_igmp", "3")],
        )),
        case(
            "vrf-table",
            vec![
                NetworkConfig::new().link("vrf0", |l| l.vrf(10).up()),
                NetworkConfig::new().link("vrf0", |l| l.vrf(20).up()),
            ],
        )
        .check(expect_link("vrf0", &[("linkinfo.info_data.table", "20")])),
    ];
    assert_converges("tm-link", cases).await
}

#[tokio::test]
async fn route_fields_change_in_place() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let base = || {
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("d1", |l| l.dummy().up())
            .address("d0", "10.40.0.1/24")
            .unwrap()
            .address("d1", "10.41.0.1/24")
            .unwrap()
            .address("d0", "fd00:40::1/64")
            .unwrap()
    };
    let via = |gw: &'static str| base().route("10.99.0.0/16", move |r| r.via(gw)).unwrap();
    let through = |dev: &'static str| base().route("10.99.0.0/16", move |r| r.dev(dev)).unwrap();
    let table = |t: u32| {
        base()
            .route("10.99.0.0/16", move |r| r.via("10.40.0.254").table(t))
            .unwrap()
    };
    let kind = |k: &'static str| {
        base()
            .route("10.99.0.0/16", move |r| match k {
                "blackhole" => r.blackhole(),
                "unreachable" => r.unreachable(),
                "prohibit" => r.prohibit(),
                _ => r.via("10.40.0.254"),
            })
            .unwrap()
    };
    let default = |gw: &'static str| base().route("0.0.0.0/0", move |r| r.via(gw)).unwrap();
    let v6 = |gw: &'static str| {
        base()
            .route("2001:db8:99::/48", move |r| r.via(gw))
            .unwrap()
    };

    let cases = vec![
        case("gateway", vec![via("10.40.0.254"), via("10.40.0.253")]).check(expect_route(
            "-4",
            "10.99.0.0/16",
            &[("gateway", "10.40.0.253")],
        )),
        case("device", vec![through("d0"), through("d1")]).check(expect_route(
            "-4",
            "10.99.0.0/16",
            &[("dev", "d1")],
        )),
        case("gateway-to-device", vec![via("10.40.0.254"), through("d1")]).check(expect_route(
            "-4",
            "10.99.0.0/16",
            &[("dev", "d1"), ("gateway", "null")],
        )),
        // The route in table 100 stays: once nothing declares into a table
        // it is out of the purge's scope (#333/#335, `purge_tables`), and
        // which tables a config owns is #512's question.
        case("table", vec![table(100), table(200)]).purging(),
        case(
            "type",
            vec![
                kind("unicast"),
                kind("blackhole"),
                kind("unreachable"),
                kind("prohibit"),
                kind("unicast"),
            ],
        )
        .purging()
        .check(expect_route("-4", "10.99.0.0/16", &[("type", "unicast")])),
        case(
            "default-gateway",
            vec![default("10.40.0.254"), default("10.40.0.253")],
        )
        .check(expect_route("-4", "default", &[("gateway", "10.40.0.253")])),
        case("v6-gateway", vec![v6("fd00:40::fe"), v6("fd00:40::fd")]).check(expect_route(
            "-6",
            "2001:db8:99::/48",
            &[("gateway", "fd00:40::fd")],
        )),
    ];
    assert_converges("tm-route", cases).await
}

#[tokio::test]
async fn qdisc_fields_change_in_place() -> nlink::Result<()> {
    use std::time::Duration;
    require_root!();
    nlink::require_modules!(
        "dummy",
        "sch_netem",
        "sch_htb",
        "sch_tbf",
        "sch_sfq",
        "sch_prio"
    );

    let q =
        |f: fn(nlink::netlink::config::QdiscBuilder) -> nlink::netlink::config::QdiscBuilder| {
            dummy(|l| l).qdisc("d0", f)
        };
    let cases = vec![
        case(
            "fq-codel",
            vec![
                q(|q| q.fq_codel().limit(nlink::Packets::new(1000)).flows(512).quantum(1514)),
                q(|q| {
                    q.fq_codel()
                        .limit(nlink::Packets::new(2000))
                        .flows(1024)
                        .quantum(3028)
                        .target(Duration::from_millis(10))
                        .interval(Duration::from_millis(200))
                }),
            ],
        )
        // A `flows` change recreates the qdisc (#596).
        .check(expect_qdisc(
            "fq_codel",
            // In µs after codel's 2^-10 s round trip: 10 ms, 200 ms.
            &[
                ("limit", "2000"),
                ("flows", "1024"),
                ("quantum", "3028"),
                ("target", "9999"),
                ("interval", "199999"),
            ],
        )),
        case(
            "sfq",
            vec![
                q(|q| q.sfq().perturb(Duration::from_secs(10)).quantum(1514)),
                q(|q| q.sfq().perturb(Duration::from_secs(20)).quantum(3028)),
                // Half a second is 1 s, not 0, which is "off" (#597).
                q(|q| q.sfq().perturb(Duration::from_millis(500)).quantum(3028)),
            ],
        )
        .check(expect_qdisc(
            "sfq",
            &[("perturb", "1"), ("quantum", "3028")],
        )),
        case(
            "prio-bands-and-priomap",
            vec![
                q(|q| q.prio().bands(3)),
                q(|q| {
                    q.prio()
                        .bands(4)
                        .priomap([1, 2, 3, 0, 1, 2, 3, 0, 1, 1, 1, 1, 1, 1, 1, 1])
                }),
            ],
        )
        .check(expect_qdisc("prio", &[("bands", "4")])),
        case(
            "kind-changes",
            vec![
                q(|q| q.netem().delay_ms(5)),
                q(|q| q.fq_codel()),
                q(|q| q.sfq()),
                q(|q| q.prio().bands(3)),
                q(|q| q.htb()),
                q(|q| q.netem().delay_ms(5)),
            ],
        )
        .check(expect_qdisc("netem", &[])),
        case(
            "ingress-to-clsact",
            vec![
                dummy(|l| l).qdisc("d0", |q| q.ingress()),
                dummy(|l| l).qdisc("d0", |q| q.clsact()),
            ],
        ),
        // #515: a declared netem is a `NetemConfig`, so what has no builder
        // setter declares through `spec`, and leaving it out of the next
        // step takes it off: ECN and the slot go, the overheads go to 0,
        // and the seed — compared only when set — stays the kernel's.
        case(
            "netem-spec",
            vec![
                q(|q| {
                    use nlink::netlink::tc::{NetemConfig, NetemSlot};
                    q.spec(
                        NetemConfig::new()
                            .delay(Duration::from_millis(10))
                            .rate(nlink::Rate::mbit(1))
                            .rate_overhead(20, 53, 5)
                            .ecn(true)
                            .seed(7)
                            .slot(NetemSlot::new(
                                Duration::from_millis(1),
                                Duration::from_millis(2),
                            )),
                    )
                }),
                q(|q| {
                    q.spec(nlink::netlink::tc::NetemConfig::new().delay(Duration::from_millis(10)))
                }),
            ],
        ),
    ];
    assert_converges("tm-qdisc", cases).await
}

// ============================================================================
// nftables
// ============================================================================

/// `nft list <what>` inside `ns`.
fn nft_list(ns: &TestNamespace, what: &[&str]) -> Result<String, String> {
    let mut args = vec!["list"];
    args.extend_from_slice(what);
    ns.exec("nft", &args).map_err(|e| e.to_string())
}

/// A check that `nft list <what>` shows every one of `want`.
fn expect_nft(
    what: &'static [&'static str],
    want: &'static [&'static str],
) -> impl Fn(&TestNamespace) -> Result<(), String> + 'static {
    move |ns| {
        let shown = nft_list(ns, what)?;
        for line in want {
            if !shown.contains(line) {
                return Err(format!("nft does not show `{line}`:\n{shown}"));
            }
        }
        Ok(())
    }
}

#[tokio::test]
async fn nftables_fields_change_in_place() -> nlink::Result<()> {
    use std::time::Duration;

    use nlink::netlink::nftables::config::NftablesConfig;
    use nlink::netlink::nftables::types::{
        BaseChain, Family, FilterHook, Priority, SetDataType, SetElement, SetKeyType,
    };
    use nlink::netlink::nftables::{LimitExpr, ObjectConfig, QuotaExpr};
    require_root!();
    nlink::require_modules!("nf_tables", "nft_quota", "nft_limit");

    let table = |f: fn(
        nlink::netlink::nftables::config::DeclaredTableBuilder,
    ) -> nlink::netlink::nftables::config::DeclaredTableBuilder| {
        NftablesConfig::new().table("t", Family::Ip, move |t| {
            f(t.chain("out", |c| {
                c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
            }))
        })
    };

    let cases = vec![
        case(
            "set-size-timeout-gc",
            vec![
                table(|t| {
                    t.set("s", |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .size(64)
                            .timeout(Duration::from_secs(60))
                            .gc_interval(Duration::from_secs(10))
                    })
                }),
                table(|t| {
                    t.set("s", |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .size(128)
                            .timeout(Duration::from_secs(120))
                            .gc_interval(Duration::from_secs(20))
                    })
                }),
            ],
        )
        .check(expect_nft(
            &["set", "ip", "t", "s"],
            &["size 128", "timeout 2m", "gc-interval 20s"],
        )),
        case(
            "set-flags-recreate",
            vec![
                table(|t| {
                    t.set("s", |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .element(SetElement::ipv4(Ipv4Addr::new(10, 50, 0, 1)))
                    })
                }),
                table(|t| {
                    t.set("s", |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .interval()
                            .element(SetElement::ipv4(Ipv4Addr::new(10, 50, 0, 1)))
                    })
                }),
            ],
        )
        .check(expect_nft(
            &["set", "ip", "t", "s"],
            &["flags interval", "10.50.0.1"],
        )),
        case(
            "set-key-type-recreate",
            vec![
                table(|t| t.set("s", |s| s.key_type(SetKeyType::Ipv4Addr))),
                table(|t| t.set("s", |s| s.key_type(SetKeyType::InetService).port(80))),
            ],
        )
        .check(expect_nft(
            &["set", "ip", "t", "s"],
            &["type inet_service", "80"],
        )),
        case(
            "map-data",
            vec![
                table(|t| {
                    t.set("m", |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .map(SetDataType::Value(SetKeyType::Mark))
                            .element(
                                SetElement::ipv4(Ipv4Addr::new(10, 50, 0, 1))
                                    .value(SetElement::new(1u32.to_be_bytes().to_vec())),
                            )
                    })
                }),
                table(|t| {
                    t.set("m", |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .map(SetDataType::Value(SetKeyType::Mark))
                            .element(
                                SetElement::ipv4(Ipv4Addr::new(10, 50, 0, 1))
                                    .value(SetElement::new(2u32.to_be_bytes().to_vec())),
                            )
                    })
                }),
            ],
        )
        .check(expect_nft(
            &["map", "ip", "t", "m"],
            &["10.50.0.1 : 0x00000002"],
        )),
        case(
            "quota-size-and-over",
            vec![
                table(|t| t.object("q", ObjectConfig::Quota(QuotaExpr::new(1_000_000)))),
                table(|t| t.object("q", ObjectConfig::Quota(QuotaExpr::new(2_000_000).over()))),
            ],
        )
        .check(expect_nft(
            &["quota", "ip", "t", "q"],
            &["over 2000000 bytes"],
        )),
        case(
            "limit-rate",
            vec![
                table(|t| {
                    t.object(
                        "l",
                        ObjectConfig::Limit(LimitExpr::packets(
                            10,
                            nlink::netlink::nftables::types::LimitUnit::Second,
                        )),
                    )
                }),
                table(|t| {
                    t.object(
                        "l",
                        ObjectConfig::Limit(LimitExpr::packets(
                            20,
                            nlink::netlink::nftables::types::LimitUnit::Minute,
                        )),
                    )
                }),
            ],
        )
        .check(expect_nft(&["limit", "ip", "t", "l"], &["rate 20/minute"])),
        case(
            "rule-body-and-comment",
            vec![
                table(|t| t.rule_keyed("out", "r", |r| r.match_tcp_dport(22).accept())),
                table(|t| {
                    t.rule_keyed("out", "r", |r| {
                        r.match_tcp_dport(2222).drop().comment("moved")
                    })
                }),
            ],
        )
        .check(expect_nft(
            &["chain", "ip", "t", "out"],
            &["tcp dport 2222 drop"],
        )),
    ];
    assert_converges("tm-nft", cases).await
}

// ============================================================================
// Boundaries
// ============================================================================

/// The edges of the inputs that take numbers and names. Each bad input is
/// refused before the kernel sees it, by the imperative call and by
/// `NetworkConfig::validate()` (#598).
#[tokio::test]
async fn boundaries() -> nlink::Result<()> {
    use nlink::netlink::link::{DummyLink, VlanLink};
    use nlink::netlink::tc::NetemConfig;
    require_root!();
    nlink::require_modules!("dummy", "8021q", "sch_netem");

    let ns = TestNamespace::new("boundaries")?;
    let conn = ns.connection()?;

    // Interface names: what the kernel's `dev_valid_name` refuses is
    // refused before the kernel (`à` is `C3 A0`, and 0xA0 is a space to
    // the kernel), and what it takes is created, a Unicode space included.
    for name in ["", ".", "..", "a/b", "a b", "a:b", "à0", "sixteen-bytes-xx"] {
        let err = conn.add_link(DummyLink::new(name)).await.expect_err(name);
        assert!(matches!(err.detail(), nlink::ErrorDetail::Interface(_)), "{name:?}: {err}");
        let declared = NetworkConfig::new().link(name, |l| l.dummy());
        assert!(declared.validate().is_err(), "validate() took {name:?}");
    }
    conn.add_link(DummyLink::new("fifteen-bytes-x")).await?;
    conn.add_link(DummyLink::new("a\u{2003}b")).await?;
    conn.add_link(DummyLink::new("d0")).await?;

    // VLAN ids 0 (priority-tagged) and 4094 are VLANs; 4095 is refused
    // before the kernel's ERANGE.
    for id in [0u16, 4094] {
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy())
            .link(format!("v{id}").as_str(), move |l| l.vlan("d0", id));
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "vlan {id}: {applied:?}");
    }
    let err = conn
        .add_link(VlanLink::new("v4095", "d0", 4095))
        .await
        .expect_err("vlan 4095");
    assert!(err.errno().is_none(), "the kernel should not see it: {err}");
    let declared = NetworkConfig::new()
        .link("d0", |l| l.dummy())
        .link("v4095", |l| l.vlan("d0", 4095));
    assert!(declared.validate().is_err(), "validate() took vlan 4095");

    // Prefix lengths are checked as they parse.
    for (route, ok) in [
        ("0.0.0.0/0", true),
        ("10.0.0.1/32", true),
        ("10.0.0.0/33", false),
        ("::/0", true),
        ("2001:db8::/128", true),
        ("2001:db8::/129", false),
    ] {
        let parsed = NetworkConfig::new().route(route, |r| r.dev("d0"));
        assert_eq!(parsed.is_ok(), ok, "{route}");
    }

    // Percentages clamp to 0..=100, and NaN is 0.
    assert_eq!(nlink::Percent::new(150.0).as_percent(), 100.0);
    assert_eq!(nlink::Percent::new(-5.0).as_percent(), 0.0);
    assert_eq!(nlink::Percent::new(f64::NAN).as_percent(), 0.0);

    // `ffff:` is the ingress/clsact handle, refused at the root.
    let err = conn
        .add_qdisc_full(
            "d0",
            nlink::TcHandle::ROOT,
            Some(nlink::TcHandle::major_only(0xffff)),
            NetemConfig::new().build(),
        )
        .await
        .expect_err("ffff: at the root");
    assert!(err.to_string().contains("reserved"), "{err}");
    Ok(())
}

// ============================================================================
// Reference parity: the same tc(8) lines through tc and through nlink
// ============================================================================

/// Thirteen ordinary flower lines, installed with `tc` in one namespace
/// and with `FlowerFilter::parse_params` in another, must dump the same:
/// the 0.30 cycle found three silent disagreements this way by hand
/// (#432, #433, #447). A filter's options are compared as `tc -j` prints
/// them.
#[tokio::test]
async fn flower_lines_install_the_same_through_tc_and_nlink() -> nlink::Result<()> {
    use nlink::TcHandle;
    use nlink::netlink::filter::FlowerFilter;
    use nlink::netlink::link::DummyLink;
    use nlink::netlink::tc::{HtbClassConfig, HtbQdiscConfig};
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "cls_flower");

    const LINES: &[(&str, u16, &str)] = &[
        ("ip", 0x0800, "dst_ip 10.0.0.1"),
        ("ip", 0x0800, "src_ip 10.0.0.0/24"),
        ("ip", 0x0800, "ip_proto tcp dst_port 80"),
        ("ip", 0x0800, "ip_proto udp src_port 53"),
        ("ip", 0x0800, "ip_proto tcp dst_port 1000-2000"),
        ("ip", 0x0800, "ip_tos 0x10/0xfc"),
        ("ip", 0x0800, "ip_ttl 64"),
        ("ip", 0x0800, "ip_proto tcp tcp_flags 0x02/0x12"),
        ("ipv6", 0x86dd, "dst_ip fd00::1"),
        ("ipv6", 0x86dd, "src_ip fd00::/64"),
        ("ipv6", 0x86dd, "ip_proto tcp src_port 443"),
        ("all", 0x0003, "dst_mac 02:00:00:00:00:01"),
        ("802.1q", 0x8100, "vlan_id 10 vlan_prio 3"),
    ];

    let build = |label: &str| -> nlink::Result<(TestNamespace, nlink::Connection<nlink::Route>)> {
        let ns = TestNamespace::new(label)?;
        let conn = ns.connection()?;
        Ok((ns, conn))
    };
    let (by_tc, tc_conn) = build("parity-tc")?;
    let (by_nlink, conn) = build("parity-nlink")?;
    for c in [&tc_conn, &conn] {
        c.add_link(DummyLink::new("d0")).await?;
        c.set_link_up("d0").await?;
        c.add_qdisc_full(
            "d0",
            TcHandle::ROOT,
            Some(TcHandle::major_only(1)),
            HtbQdiscConfig::new().build(),
        )
        .await?;
        c.add_class(
            "d0",
            TcHandle::major_only(1),
            TcHandle::new(1, 0x10),
            HtbClassConfig::new(nlink::Rate::mbit(10)).build(),
        )
        .await?;
    }
    for (i, (proto, proto_id, params)) in LINES.iter().enumerate() {
        let prio = (i + 1).to_string();
        let mut args = vec![
            "filter", "add", "dev", "d0", "parent", "1:", "protocol", proto, "prio", &prio,
            "flower",
        ];
        args.extend(params.split_whitespace());
        args.extend(["classid", "1:10"]);
        by_tc.exec("tc", &args)?;

        let mut tokens: Vec<&str> = params.split_whitespace().collect();
        tokens.extend(["classid", "1:10"]);
        let filter = FlowerFilter::parse_params(&tokens)?;
        conn.add_filter_full(
            "d0",
            TcHandle::major_only(1),
            None,
            nlink::EthProto::new(*proto_id),
            nlink::FilterPriority::new((i + 1) as u16),
            filter,
        )
        .await?;
    }

    let dump = |ns: &TestNamespace| -> nlink::Result<Vec<serde_json::Value>> {
        let out = ns.exec("tc", &["-j", "filter", "show", "dev", "d0", "parent", "1:"])?;
        let all: serde_json::Value =
            serde_json::from_str(&out).map_err(|e| nlink::Error::invalid_message(e.to_string()))?;
        // The per-priority chain heads carry no options; compare filters.
        Ok(all
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|f| f.get("options").is_some())
            .collect())
    };
    let (want, got) = (dump(&by_tc)?, dump(&by_nlink)?);
    assert_eq!(
        want.len(),
        LINES.len(),
        "tc installed {} filters",
        want.len()
    );
    let mut differ = Vec::new();
    for (i, (w, g)) in want.iter().zip(&got).enumerate() {
        if w != g {
            differ.push(format!("{}\n  tc:    {w}\n  nlink: {g}", LINES[i].2));
        }
    }
    assert_eq!(
        got.len(),
        want.len(),
        "nlink installed {} filters",
        got.len()
    );
    assert!(
        differ.is_empty(),
        "{} line(s) differ:\n{}",
        differ.len(),
        differ.join("\n")
    );
    Ok(())
}

// ============================================================================
// Offline prediction against the kernel
// ============================================================================

/// `diff_against` predicts, from declarations alone, the recreates a live
/// diff finds once the first config is applied: every certain prediction
/// is recreated, and nothing is recreated that was not at least a maybe
/// (#513).
#[tokio::test]
async fn offline_recreate_predictions_match_the_kernel() -> nlink::Result<()> {
    use nlink::netlink::config::{BondMode, Certainty, MacvlanMode};
    use nlink::netlink::link::VlanProtocol;
    use std::collections::BTreeSet;
    require_root!();
    nlink::require_modules!("dummy", "8021q", "vxlan", "bonding", "macvlan", "vrf");

    let base = || NetworkConfig::new().link("d0", |l| l.dummy().up());
    let cases: Vec<(&str, NetworkConfig, NetworkConfig)> = vec![
        (
            "vlan-id",
            base().link("v1", |l| l.vlan("d0", 10)),
            base().link("v1", |l| l.vlan("d0", 20)),
        ),
        (
            "vlan-protocol",
            base().link("v1", |l| l.vlan("d0", 10)),
            base().link("v1", |l| {
                l.vlan("d0", 10).vlan_protocol(VlanProtocol::Dot1ad)
            }),
        ),
        (
            "vxlan-vni-and-stacked-vlan",
            base()
                .link("vx0", |l| {
                    l.vxlan(100).vxlan_underlay_dev("d0").vxlan_port(4789)
                })
                .link("v1", |l| l.vlan("vx0", 5)),
            base()
                .link("vx0", |l| {
                    l.vxlan(200).vxlan_underlay_dev("d0").vxlan_port(4789)
                })
                .link("v1", |l| l.vlan("vx0", 5)),
        ),
        (
            "vxlan-port-from-default-to-another",
            base().link("vx0", |l| l.vxlan(100).vxlan_underlay_dev("d0")),
            base().link("vx0", |l| {
                l.vxlan(100).vxlan_underlay_dev("d0").vxlan_port(4789)
            }),
        ),
        (
            "vxlan-port-from-default-to-the-default",
            base().link("vx0", |l| l.vxlan(100).vxlan_underlay_dev("d0")),
            base().link("vx0", |l| {
                l.vxlan(100).vxlan_underlay_dev("d0").vxlan_port(8472)
            }),
        ),
        (
            "bond-mode",
            NetworkConfig::new().link("b0", |l| l.bond().bond_mode(BondMode::ActiveBackup)),
            NetworkConfig::new().link("b0", |l| l.bond().bond_mode(BondMode::BalanceRr)),
        ),
        (
            "macvlan-mode-changes-in-place",
            base().link("m0", |l| l.macvlan("d0").macvlan_mode(MacvlanMode::Bridge)),
            base().link("m0", |l| l.macvlan("d0").macvlan_mode(MacvlanMode::Private)),
        ),
        (
            "vrf-table",
            NetworkConfig::new().link("vrf0", |l| l.vrf(100)),
            NetworkConfig::new().link("vrf0", |l| l.vrf(200)),
        ),
        (
            "mtu-changes-in-place",
            base().link("v1", |l| l.vlan("d0", 10).mtu(1400)),
            base().link("v1", |l| l.vlan("d0", 10).mtu(1300)),
        ),
    ];
    let mut failures = Vec::new();
    for (name, before, after) in cases {
        let ns = TestNamespace::new(&format!("off-{}", &name[..name.len().min(8)]))?;
        let conn = ns.connection()?;
        let applied = before.apply(&conn).await?;
        assert!(applied.is_success(), "{name}: {applied:?}");
        let live: BTreeSet<String> = after
            .diff(&conn)
            .await?
            .links_to_recreate
            .into_iter()
            .map(|r| r.name)
            .collect();
        let offline = after.diff_against(&before);
        let certain: BTreeSet<String> = offline
            .recreates
            .iter()
            .filter(|r| r.certainty == Certainty::Certain)
            .map(|r| r.name.clone())
            .collect();
        let any: BTreeSet<String> = offline.recreates.iter().map(|r| r.name.clone()).collect();
        if !certain.is_subset(&live) || !live.is_subset(&any) {
            failures.push(format!(
                "{name}: live {live:?}, offline certain {certain:?}, offline any {any:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    Ok(())
}

/// A declared handle is the handle the kernel holds, a classful kind sits at
/// `1:` where its classes can name it, and the kernel's own root comes back
/// when declared. Each step converges (#514).
#[tokio::test]
async fn qdisc_handles_change_in_place() -> nlink::Result<()> {
    use nlink::TcHandle;
    use nlink::netlink::config::QdiscBuilder;
    require_root!();
    nlink::require_modules!("dummy", "sch_netem", "sch_prio");

    let q = |f: fn(QdiscBuilder) -> QdiscBuilder| dummy(|l| l).qdisc("d0", f);
    let steps = [
        q(|q| q.netem().handle(TcHandle::major_only(0x10))),
        q(|q| q.netem().handle(TcHandle::major_only(0x20))),
        q(|q| q.prio()),
        q(|q| q.kernel_default()),
    ];
    let want = ["netem 10:", "netem 20:", "prio 1:", "default"];
    let ns = TestNamespace::new("tr-handles")?;
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let out = ns
            .exec("tc", &["-j", "qdisc", "show", "dev", "d0", "root"])
            .map_err(|e| e.to_string())?;
        let qdiscs: serde_json::Value = serde_json::from_str(&out).map_err(|e| e.to_string())?;
        let root = &qdiscs[0];
        let shown = format!(
            "{} {}",
            root["kind"].as_str().unwrap_or("?"),
            root["handle"].as_str().unwrap_or("?")
        );
        let ok = match want[i] {
            // The kernel's default root has handle 0: — `noqueue` on a
            // dummy.
            "default" => root["handle"] == "0:",
            w => shown == w,
        };
        if ok {
            Ok(())
        } else {
            Err(format!("want {}, the kernel has {shown}: {out}", want[i]))
        }
    })
    .await
}

/// Address attributes changed A→B→none (#516): an IPv4 metric and label
/// (the label only a recreate changes), IPv6 flags and metric (changed in
/// place), lifetimes from finite to forever. Every step converges, and
/// `ip -j addr` shows what each declares.
#[tokio::test]
async fn address_attributes_change_in_place() -> nlink::Result<()> {
    use std::time::Duration;
    require_root!();
    nlink::require_modules!("dummy");

    type Want = (Option<u64>, &'static str, bool, bool, bool);
    let step = |a: fn(nlink::netlink::config::AddressBuilder) -> nlink::netlink::config::AddressBuilder,
                b: fn(nlink::netlink::config::AddressBuilder) -> nlink::netlink::config::AddressBuilder,
                c: fn(nlink::netlink::config::AddressBuilder) -> nlink::netlink::config::AddressBuilder| {
        dummy(|l| l)
            .address_with("d0", "10.70.0.1/24", a)
            .and_then(|cfg| cfg.address_with("d0", "fd70::1/64", b))
            .and_then(|cfg| cfg.address_with("d0", "10.71.0.1/24", c))
            .expect("valid addresses")
    };
    let steps = [
        step(
            |a| a.metric(100).label("d0:a"),
            |a| a.nodad().metric(100),
            |a| a.lifetime(Duration::from_secs(3600), Duration::from_secs(1800)),
        ),
        step(
            |a| a.metric(200).label("d0:b"),
            |a| a.noprefixroute().metric(200),
            |a| a,
        ),
        step(|a| a, |a| a, |a| a),
    ];
    // (10.70 metric, 10.70 label, fd70 nodad, fd70 noprefixroute, 10.71 dynamic)
    let want: [Want; 3] = [
        (Some(100), "d0:a", true, false, true),
        (Some(200), "d0:b", false, true, false),
        (None, "d0", false, false, false),
    ];
    let ns = TestNamespace::new("tr-addr")?;
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let links = ip_json(&ns, &["addr", "show", "dev", "d0"])?;
        let info = links[0]["addr_info"].as_array().cloned().unwrap_or_default();
        let find = |local: &str| {
            info.iter()
                .find(|a| a["local"] == local)
                .cloned()
                .ok_or_else(|| format!("{local} missing: {info:?}"))
        };
        let (v4, v6, life) = (find("10.70.0.1")?, find("fd70::1")?, find("10.71.0.1")?);
        let flag = |a: &serde_json::Value, k: &str| a[k].as_bool().unwrap_or(false);
        let have: Want = (
            v4["metric"].as_u64(),
            if v4["label"] == "d0:a" { "d0:a" } else if v4["label"] == "d0:b" { "d0:b" } else { "d0" },
            flag(&v6, "nodad"),
            flag(&v6, "noprefixroute"),
            flag(&life, "dynamic"),
        );
        let fd70_metric = v6["metric"].as_u64();
        let want_fd70 = want[i].0;
        if have != want[i] || fd70_metric != want_fd70 {
            return Err(format!(
                "step {}: want {:?} (fd70 metric {want_fd70:?}), have {have:?} (fd70 metric {fd70_metric:?}): {info:?}",
                i + 1,
                want[i]
            ));
        }
        // One 10.70.0.1, whatever the label: a recreate, not a second one.
        let copies = info.iter().filter(|a| a["local"] == "10.70.0.1").count();
        if copies != 1 {
            return Err(format!("{copies} copies of 10.70.0.1"));
        }
        Ok(())
    })
    .await
}

/// Route attributes changed A→B→none (#516): source, on-link and metrics
/// for IPv4, source and metrics for IPv6. A replace drops what it is not
/// sent, so each step converges and `ip -j -d route` shows exactly what
/// it declares.
#[tokio::test]
async fn route_attributes_change_in_place() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    type RB = nlink::netlink::config::RouteBuilder;
    let step = |v4: fn(RB) -> RB, v6: fn(RB) -> RB| {
        dummy(|l| l)
            .address("d0", "10.80.0.1/24")
            .and_then(|c| c.address("d0", "10.80.0.9/24"))
            .expect("addresses")
            .address_with("d0", "fd80::1/64", |a| a.nodad())
            .and_then(|c| c.address_with("d0", "fd80::9/64", |a| a.nodad()))
            .expect("v6 addresses")
            .route("10.81.0.0/16", move |r| v4(r.via("10.80.0.2").dev("d0")))
            .and_then(|c| c.route("fd81::/64", move |r| v6(r.via("fd80::2").dev("d0"))))
            .expect("routes")
    };
    let steps = [
        step(
            |r| r.src("10.80.0.1").onlink().mtu(1400).advmss(1300),
            |r| r.src("fd80::1").hoplimit(10),
        ),
        step(
            |r| r.src("10.80.0.9").mtu(1500).initcwnd(10),
            |r| r.src("fd80::9").hoplimit(20).mtu(1280),
        ),
        step(|r| r, |r| r),
    ];
    // (prefsrc, onlink, metrics) as `ip -j -d route` shows them.
    let want: [[(&str, bool, &str); 2]; 3] = [
        [
            ("10.80.0.1", true, r#"[{"mtu":1400,"advmss":1300}]"#),
            ("fd80::1", false, r#"[{"hoplimit":10}]"#),
        ],
        [
            ("10.80.0.9", false, r#"[{"mtu":1500,"initcwnd":10}]"#),
            ("fd80::9", false, r#"[{"mtu":1280,"hoplimit":20}]"#),
        ],
        [("", false, "null"), ("", false, "null")],
    ];
    let ns = TestNamespace::new("tr-rtattr")?;
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        for (k, (family, dst)) in [("-4", "10.81.0.0/16"), ("-6", "fd81::/64")].into_iter().enumerate() {
            let routes = ip_json(&ns, &[family, "-d", "route", "show", dst])?;
            let r = &routes[0];
            let have = (
                r["prefsrc"].as_str().unwrap_or(""),
                r["flags"].as_array().is_some_and(|f| f.iter().any(|x| x == "onlink")),
                r["metrics"].clone(),
            );
            let (src, onlink, metrics) = want[i][k];
            let metrics: serde_json::Value = serde_json::from_str(metrics).expect("json");
            if have != (src, onlink, metrics) {
                return Err(format!("{dst} step {}: want {:?}, have {have:?}: {r}", i + 1, want[i][k]));
            }
        }
        Ok(())
    })
    .await
}

/// Link attributes changed A→B (#516): queue length, alias, group, the
/// GSO/GRO limits, promiscuous mode, alternative names, and protodown on a
/// vxlan (dummy and veth refuse it). A third step that declares none
/// leaves them as they are: an attribute not declared is not managed.
#[tokio::test]
async fn link_attributes_change_in_place() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "vxlan");

    struct Want {
        txqlen: u64,
        alias: &'static str,
        group: &'static str,
        gso: (u64, u64, u64),
        promisc: bool,
        altnames: &'static [&'static str],
        protodown: bool,
    }
    let declare = |w: Option<&Want>| {
        let mut cfg = NetworkConfig::new();
        cfg = match w {
            Some(w) => {
                let (size, segs, gro) = w.gso;
                cfg.link("d0", |l| {
                    let mut l = l
                        .dummy()
                        .txqlen(w.txqlen as u32)
                        .alias(w.alias)
                        .group(w.group.parse().unwrap())
                        .gso_max_size(size as u32)
                        .gso_max_segs(segs as u32)
                        .gro_max_size(gro as u32)
                        .promisc(w.promisc);
                    for a in w.altnames {
                        l = l.altname(a);
                    }
                    l
                })
                .link("vx0", |l| l.vxlan(42).vxlan_local(v4(10, 0, 0, 1)).protodown(w.protodown))
            }
            None => cfg
                .link("d0", |l| l.dummy())
                .link("vx0", |l| l.vxlan(42).vxlan_local(v4(10, 0, 0, 1))),
        };
        cfg
    };
    let a = Want {
        txqlen: 500,
        alias: "lab-a",
        group: "7",
        gso: (32000, 50, 32000),
        promisc: true,
        altnames: &["d0-a", "d0-b"],
        protodown: true,
    };
    let b = Want {
        txqlen: 1000,
        alias: "lab-b",
        group: "9",
        gso: (16000, 20, 16000),
        promisc: false,
        altnames: &["d0-b", "d0-c"],
        protodown: false,
    };
    let steps = [declare(Some(&a)), declare(Some(&b)), declare(None)];
    let ns = TestNamespace::new("tr-linkattr")?;
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let w = if i == 0 { &a } else { &b };
        let d0 = &ip_json(&ns, &["-d", "link", "show", "d0"])?[0];
        let vx0 = &ip_json(&ns, &["-d", "link", "show", "vx0"])?[0];
        let flags: Vec<&str> = d0["flags"].as_array().into_iter().flatten().filter_map(|f| f.as_str()).collect();
        let mut altnames: Vec<&str> = d0["altnames"].as_array().into_iter().flatten().filter_map(|a| a.as_str()).collect();
        altnames.sort();
        let have = (
            d0["txqlen"].as_u64(),
            d0["ifalias"].as_str(),
            d0["group"].as_str(),
            (d0["gso_max_size"].as_u64(), d0["gso_max_segs"].as_u64(), d0["gro_max_size"].as_u64()),
            flags.contains(&"PROMISC"),
            altnames.clone(),
            vx0["proto_down"].as_bool().unwrap_or(false),
        );
        let want = (
            Some(w.txqlen),
            Some(w.alias),
            Some(w.group),
            (Some(w.gso.0), Some(w.gso.1), Some(w.gso.2)),
            w.promisc,
            w.altnames.to_vec(),
            w.protodown,
        );
        if have != want {
            return Err(format!("step {}: want {want:?}, have {have:?}", i + 1));
        }
        Ok(())
    })
    .await
}

/// IPv4 devconf, the IPv6 address generation mode and the token changed
/// A→B on a veth (#516): set over netlink, before the link comes up, and
/// read back from `/proc/sys`, `ip -d link` and `ip token`. A dummy is
/// `NOARP`, which the kernel refuses a token on.
#[tokio::test]
async fn devconf_changes_in_place() -> nlink::Result<()> {
    use nlink::netlink::devconf::{AddrGenMode, Ipv4Devconf};
    use std::net::Ipv6Addr;
    require_root!();
    nlink::require_modules!("veth");

    let step = |rp: u32, fwd: u32, arp_ignore: u32, mode: AddrGenMode, token: &str| {
        let token: Ipv6Addr = token.parse().unwrap();
        NetworkConfig::new()
            .link("v0", move |l| {
                l.veth("v1")
                    .ipv4_conf(Ipv4Devconf::RpFilter, rp)
                    .ipv4_conf(Ipv4Devconf::Forwarding, fwd)
                    .ipv4_conf(Ipv4Devconf::ArpIgnore, arp_ignore)
                    .addr_gen_mode(mode)
                    .ipv6_token(token)
                    .up()
            })
            .link("v1", |l| l.up())
    };
    let steps = [
        step(1, 1, 1, AddrGenMode::None, "::1:2"),
        step(0, 0, 2, AddrGenMode::Eui64, "::3:4"),
    ];
    let want = [("1", "1", "1", "none", "::1:2"), ("0", "0", "2", "eui64", "::3:4")];
    let ns = TestNamespace::new("tr-devconf")?;
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let conf = |name: &str| {
            ns.exec("cat", &[&format!("/proc/sys/net/ipv4/conf/v0/{name}")])
                .map(|s| s.trim().to_string())
                .map_err(|e| e.to_string())
        };
        let link = &ip_json(&ns, &["-d", "link", "show", "v0"])?[0];
        let tokens = ns
            .exec("ip", &["-j", "token", "get", "dev", "v0"])
            .map_err(|e| e.to_string())?;
        let tokens: serde_json::Value = serde_json::from_str(&tokens).map_err(|e| e.to_string())?;
        let token: Option<Ipv6Addr> = tokens[0]["token"].as_str().and_then(|t| t.parse().ok());
        let (rp, fwd, ign, mode, want_token) = want[i];
        let have = (
            conf("rp_filter")?,
            conf("forwarding")?,
            conf("arp_ignore")?,
            link["inet6_addr_gen_mode"].as_str().unwrap_or("").to_string(),
            token,
        );
        let want = (rp.into(), fwd.into(), ign.into(), mode.to_string(), want_token.parse().ok());
        if have != want {
            return Err(format!("step {}: want {want:?}, have {have:?}", i + 1));
        }
        Ok(())
    })
    .await
}

/// IPv6 devconf changed A→B on a veth the first step creates (#516): the
/// kernel takes it only through `/proc/sys`, so the apply writes it from a
/// thread in the namespace, before the link comes up; the diff reads it
/// back from the link dump.
#[tokio::test]
async fn ipv6_devconf_changes_in_place() -> nlink::Result<()> {
    use nlink::netlink::devconf::Ipv6Devconf;
    require_root!();
    nlink::require_modules!("veth");
    // The privileged CI lane's containers mount /proc/sys read-only, and
    // the kernel takes these settings no other way.
    nlink::require_writable_sysctl!("/proc/sys/net/ipv6/conf/all/accept_dad");

    let settings = [
        (Ipv6Devconf::AcceptDad, [0, 1]),
        (Ipv6Devconf::AcceptRa, [0, 2]),
        (Ipv6Devconf::Forwarding, [1, 0]),
        (Ipv6Devconf::Hoplimit, [32, 64]),
        (Ipv6Devconf::KeepAddrOnDown, [1, -1]),
    ];
    let step = |i: usize| {
        NetworkConfig::new()
            .link("v0", move |mut l| {
                l = l.veth("v1");
                for (d, values) in settings {
                    l = l.ipv6_conf(d, values[i]);
                }
                l.up()
            })
            .link("v1", |l| l.up())
    };
    let ns = TestNamespace::new("tr-devconf6")?;
    crate::common::converge::assert_transition(&ns, &[step(0), step(1)], false, async |i, _conn| {
        for (d, values) in settings {
            let have = ns
                .exec("cat", &[&format!("/proc/sys/net/ipv6/conf/v0/{}", d.name())])
                .map_err(|e| e.to_string())?;
            if have.trim() != values[i].to_string() {
                return Err(format!("step {}: {d} is {}, want {}", i + 1, have.trim(), values[i]));
            }
        }
        Ok(())
    })
    .await
}

/// A bridge's options and a port's changed A→B (#516): VLAN filtering, the
/// default PVID, STP, priority and ageing on the bridge, changed in place
/// with `changelink`; learning, flooding, isolation, ARP suppression,
/// hairpin and cost on the port. `ip -d link` shows each step.
#[tokio::test]
async fn bridge_and_port_options_change_in_place() -> nlink::Result<()> {
    use std::time::Duration;
    require_root!();
    nlink::require_modules!("dummy", "bridge");

    let step = |on: bool| {
        let (pvid, prio, ageing, cost) = if on { (10, 100, 100, 50) } else { (20, 200, 200, 100) };
        NetworkConfig::new()
            .link("br0", move |l| {
                l.bridge().up().bridge_options(|b| {
                    b.vlan_filtering(on)
                        .vlan_default_pvid(pvid)
                        .stp(on)
                        .priority(prio)
                        .ageing_time(Duration::from_secs(ageing))
                })
            })
            .link("d0", move |l| {
                l.dummy().master("br0").up().port_options(|p| {
                    p.learning(!on)
                        .isolated(on)
                        .neigh_suppress(on)
                        .hairpin(on)
                        .flood(!on)
                        .cost(cost)
                })
            })
    };
    let ns = TestNamespace::new("tr-bridgeopt")?;
    crate::common::converge::assert_transition(&ns, &[step(true), step(false)], false, async |i, _conn| {
        let on = i == 0;
        let br = &ip_json(&ns, &["-d", "link", "show", "br0"])?[0]["linkinfo"]["info_data"];
        let port = &ip_json(&ns, &["-d", "link", "show", "d0"])?[0]["linkinfo"]["info_slave_data"];
        let (pvid, prio, ageing, cost) = if on { (10, 100, 10000, 50) } else { (20, 200, 20000, 100) };
        let have = (
            br["vlan_filtering"].as_u64(),
            br["vlan_default_pvid"].as_u64(),
            br["stp_state"].as_u64().map(|s| s != 0),
            br["priority"].as_u64(),
            br["ageing_time"].as_u64(),
            (port["learning"].as_bool(), port["isolated"].as_bool(), port["neigh_suppress"].as_bool()),
            (port["hairpin"].as_bool(), port["flood"].as_bool(), port["cost"].as_u64()),
        );
        let want = (
            Some(u64::from(on)),
            Some(pvid),
            Some(on),
            Some(prio),
            Some(ageing),
            (Some(!on), Some(on), Some(on)),
            (Some(on), Some(!on), Some(cost)),
        );
        if have != want {
            return Err(format!("step {}: want {want:?}, have {have:?}", i + 1));
        }
        Ok(())
    })
    .await
}

/// A bridge port's VLANs changed A→B→C (#516): the access VLAN moves, a
/// tagged one becomes untagged, one goes and another comes. The declared
/// set is the port's: the default PVID a port gets when it joins goes
/// too. `bridge -j vlan` shows each step.
#[tokio::test]
async fn port_vlans_change_in_place() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "bridge");

    type P = nlink::netlink::config::PortOptions;
    let step = |vlans: fn(P) -> P| {
        NetworkConfig::new()
            .link("br0", |l| l.bridge().up().bridge_options(|b| b.vlan_filtering(true)))
            .link("d0", move |l| l.dummy().master("br0").up().port_options(vlans))
    };
    let steps = [
        step(|p| p.pvid(10).vlan(20).vlan(30)),
        step(|p| p.untagged(20).vlan(40)),
        step(|p| p.pvid(1)),
    ];
    let want: [&[(u64, bool, bool)]; 3] = [
        &[(10, true, true), (20, false, false), (30, false, false)],
        &[(20, false, true), (40, false, false)],
        &[(1, true, true)],
    ];
    let ns = TestNamespace::new("tr-portvlan")?;
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let out = ns
            .exec("bridge", &["-j", "vlan", "show", "dev", "d0"])
            .map_err(|e| e.to_string())?;
        let shown: serde_json::Value = serde_json::from_str(&out).map_err(|e| e.to_string())?;
        let have: Vec<(u64, bool, bool)> = shown[0]["vlans"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|v| {
                let flags: Vec<&str> = v["flags"].as_array().into_iter().flatten().filter_map(|f| f.as_str()).collect();
                (
                    v["vlan"].as_u64().unwrap_or(0),
                    flags.contains(&"PVID"),
                    flags.contains(&"Egress Untagged"),
                )
            })
            .collect();
        if have != want[i] {
            return Err(format!("step {}: want {:?}, have {have:?}: {out}", i + 1, want[i]));
        }
        Ok(())
    })
    .await
}

/// Ipvlan and macvtap declared and changed in place (#516): an ipvlan's
/// mode and isolation, a macvtap's mode, each through three values.
/// `ip -d link` shows each step. (A device hosts ipvlans or
/// macvlans/macvtaps, not both: two parents.)
#[tokio::test]
async fn ipvlan_and_macvtap_change_in_place() -> nlink::Result<()> {
    use nlink::netlink::config::{IpvlanIsolation, IpvlanMode};
    require_root!();
    nlink::require_modules!("dummy", "ipvlan", "macvtap");

    let step = |mode: IpvlanMode, iso: IpvlanIsolation, tap: MacvlanMode| {
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("d1", |l| l.dummy().up())
            .link("iv0", move |l| l.ipvlan("d0").ipvlan_mode(mode).ipvlan_isolation(iso))
            .link("mt0", move |l| l.macvtap("d1").macvtap_mode(tap))
    };
    let steps = [
        step(IpvlanMode::L2, IpvlanIsolation::Bridge, MacvlanMode::Bridge),
        step(IpvlanMode::L3, IpvlanIsolation::Private, MacvlanMode::Vepa),
        step(IpvlanMode::L3s, IpvlanIsolation::Vepa, MacvlanMode::Private),
    ];
    let want = [("l2", "bridge", "bridge"), ("l3", "private", "vepa"), ("l3s", "vepa", "private")];
    let ns = TestNamespace::new("tr-ipvlan")?;
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let iv = &ip_json(&ns, &["-d", "link", "show", "iv0"])?[0]["linkinfo"]["info_data"];
        let mt = &ip_json(&ns, &["-d", "link", "show", "mt0"])?[0]["linkinfo"]["info_data"];
        let (mode, iso, tap) = want[i];
        let have = (
            iv["mode"].as_str(),
            iv[iso].as_bool(),
            mt["mode"].as_str(),
        );
        if have != (Some(mode), Some(true), Some(tap)) {
            return Err(format!("step {}: want {:?}, have {have:?}: {iv} {mt}", i + 1, want[i]));
        }
        Ok(())
    })
    .await
}

/// IPv4 tunnels declared and changed in place (#516): gre, gretap, ipip,
/// sit and vti, each with its ends, TTL, key and underlay device as its
/// kind has them. A tunnel's `changelink` takes its whole configuration
/// from the request, so a change of one parameter must not lose the
/// others: each step checks all of them through `ip -d link`.
#[tokio::test]
async fn ipv4_tunnels_change_in_place() -> nlink::Result<()> {
    use std::net::Ipv4Addr;
    require_root!();
    nlink::require_modules!("dummy", "ip_gre", "ipip", "sit", "ip_vti");

    let a = |n: u8, h: u8| Ipv4Addr::new(10, 90, n, h);
    let step = |b: bool| {
        let (r, ttl, key) = if b { (3, 32, 200) } else { (2, 64, 100) };
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("gr1", move |l| {
                l.gre().tunnel_local(a(0, 1)).tunnel_remote(a(0, r)).tunnel_ttl(ttl).tunnel_key(key).tunnel_underlay_dev("d0")
            })
            .link("gt1", move |l| l.gretap().tunnel_local(a(1, 1)).tunnel_remote(a(1, 2)).tunnel_key(key + 1))
            .link("ip1", move |l| l.ipip().tunnel_local(a(2, 1)).tunnel_remote(a(2, r)).tunnel_ttl(ttl))
            .link("st1", move |l| l.sit().tunnel_local(a(3, 1)).tunnel_remote(a(3, r)))
            .link("vt1", move |l| l.vti().tunnel_local(a(4, 1)).tunnel_remote(a(4, 2)).tunnel_key(key + 2))
    };
    let ns = TestNamespace::new("tr-tunnels")?;
    crate::common::converge::assert_transition(&ns, &[step(false), step(true)], false, async |i, _conn| {
        let b = i == 1;
        let (r, ttl, key) = if b { (3, 32, 200u32) } else { (2, 64, 100u32) };
        let data = |dev: &str| -> Result<serde_json::Value, String> {
            Ok(ip_json(&ns, &["-d", "link", "show", dev])?[0]["linkinfo"]["info_data"].clone())
        };
        let dotted = |k: u32| Ipv4Addr::from(k).to_string();
        let gre = data("gr1")?;
        let checks = [
            ("gr1 remote", gre["remote"].clone(), serde_json::json!(a(0, r).to_string())),
            ("gr1 local", gre["local"].clone(), serde_json::json!(a(0, 1).to_string())),
            ("gr1 ttl", gre["ttl"].clone(), serde_json::json!(ttl)),
            ("gr1 key", gre["ikey"].clone(), serde_json::json!(dotted(key))),
            ("gr1 dev", gre["link"].clone(), serde_json::json!("d0")),
            ("gt1 key", data("gt1")?["okey"].clone(), serde_json::json!(dotted(key + 1))),
            ("ip1 remote", data("ip1")?["remote"].clone(), serde_json::json!(a(2, r).to_string())),
            ("ip1 ttl", data("ip1")?["ttl"].clone(), serde_json::json!(ttl)),
            ("st1 remote", data("st1")?["remote"].clone(), serde_json::json!(a(3, r).to_string())),
            ("vt1 key", data("vt1")?["ikey"].clone(), serde_json::json!(dotted(key + 2))),
        ];
        for (what, have, want) in checks {
            if have != want {
                return Err(format!("step {}: {what} is {have}, want {want}", i + 1));
            }
        }
        Ok(())
    })
    .await
}

/// An ip6tnl tunnel and an XFRM interface A→B→C (#516). Step 2 changes the
/// tunnel's remote, hop limit, encapsulation limit, mode and underlay, and
/// the interface's if_id, all in place; `ip6_tnl_changelink` rebuilds the
/// whole configuration from the request, so each step checks every
/// parameter through `ip -d link`. Step 3 moves the interface to another
/// underlay, which `xfrmi_changelink` refuses: it is recreated.
#[tokio::test]
async fn ip6tnl_and_xfrm_change_in_place() -> nlink::Result<()> {
    use nlink::netlink::link::Ip6tnlMode;
    use std::net::Ipv6Addr;
    require_root!();
    nlink::require_modules!("dummy", "ip6_tunnel", "xfrm_interface");

    let a = |h: u16| Ipv6Addr::new(0xfd00, 0x90, 0, 0, 0, 0, 0, h);
    let tunnel = |b: bool| if b { (3, 32, 2, Ip6tnlMode::Any, "d1") } else { (2, 64, 4, Ip6tnlMode::Ip6ip6, "d0") };
    let step = |b: bool, id: u32, xdev: &'static str| {
        let (r, hl, el, mode, dev) = tunnel(b);
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("d1", |l| l.dummy().up())
            .link("t61", move |l| {
                l.ip6tnl()
                    .ip6tnl_local(a(1))
                    .ip6tnl_remote(a(r))
                    .ip6tnl_hoplimit(hl)
                    .ip6tnl_encap_limit(el)
                    .ip6tnl_mode(mode)
                    .tunnel_underlay_dev(dev)
            })
            .link("xf1", move |l| l.xfrm(id).tunnel_underlay_dev(xdev))
    };
    let steps = [step(false, 7, "d0"), step(true, 8, "d0"), step(true, 8, "d1")];
    let xwant = [("0x7", "d0"), ("0x8", "d0"), ("0x8", "d1")];
    let ns = TestNamespace::new("tr-ip6tnl")?;
    let mut ifindexes = Vec::new();
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let (r, hl, el, _, dev) = tunnel(i > 0);
        let mode = if i > 0 { "any" } else { "ip6ip6" };
        let (id, xdev) = xwant[i];
        let t6 = &ip_json(&ns, &["-d", "link", "show", "t61"])?[0];
        let xf = &ip_json(&ns, &["-d", "link", "show", "xf1"])?[0];
        let data = &t6["linkinfo"]["info_data"];
        let checks = [
            ("t61 local", data["local"].clone(), serde_json::json!(a(1).to_string())),
            ("t61 remote", data["remote"].clone(), serde_json::json!(a(r).to_string())),
            ("t61 hoplimit", data["ttl"].clone(), serde_json::json!(hl)),
            ("t61 encaplimit", data["encap_limit"].clone(), serde_json::json!(el)),
            ("t61 mode", data["proto"].clone(), serde_json::json!(mode)),
            ("t61 dev", data["link"].clone(), serde_json::json!(dev)),
            ("xf1 if_id", xf["linkinfo"]["info_data"]["if_id"].clone(), serde_json::json!(id)),
            ("xf1 dev", xf["link"].clone(), serde_json::json!(xdev)),
        ];
        for (what, have, want) in checks {
            if have != want {
                return Err(format!("step {}: {what} is {have}, want {want}", i + 1));
            }
        }
        ifindexes.push((t6["ifindex"].as_u64(), xf["ifindex"].as_u64()));
        Ok(())
    })
    .await?;
    assert_eq!(ifindexes[0], ifindexes[1], "step 2 changes both in place");
    assert_eq!(ifindexes[1].0, ifindexes[2].0, "the tunnel is not touched");
    assert_ne!(ifindexes[1].1, ifindexes[2].1, "a new underlay recreates the xfrm interface");
    Ok(())
}

/// Declared neighbours A→B→C→D (#516), on a VLAN: a permanent IPv4 and
/// IPv6 entry and a proxy entry. Step 2 gives the IPv4 and IPv6 entries
/// other link-layer addresses. Step 3 changes the VLAN id, which recreates
/// the link and deletes them; the recreate does not count them among what
/// it destroys, and puts them back. Step 4 takes the VLAN down, which
/// flushes them all, permanent ones included; the apply puts them back on
/// the down link. `ip -j neigh` shows each step.
#[tokio::test]
async fn neighbours_change_and_come_back_after_a_recreate_or_flush() -> nlink::Result<()> {
    use std::net::Ipv6Addr;
    require_root!();
    nlink::require_modules!("dummy", "8021q");

    let mac = |n: u8| [0x02, 0, 0, 0, 0x80, n];
    let six = Ipv6Addr::new(0xfd00, 0x80, 0, 0, 0, 0, 0, 2);
    let step = |id: u16, up: bool, m: u8| {
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("v0", move |l| {
                let l = l.vlan("d0", id);
                if up { l.up() } else { l.down() }
            })
            .neighbour("v0", Ipv4Addr::new(10, 80, 0, 2), mac(m))
            .neighbour("v0", six, mac(m + 1))
            .proxy_neighbour("v0", Ipv4Addr::new(10, 80, 0, 9))
    };
    let steps = [step(10, true, 1), step(10, true, 3), step(11, true, 3), step(11, false, 3)];
    let ns = TestNamespace::new("tr-neigh")?;
    let mut ifindexes = Vec::new();
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let m = if i == 0 { 1 } else { 3 };
        let shown = |m: [u8; 6]| {
            m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
        };
        let neigh = ip_json(&ns, &["neigh", "show", "dev", "v0"])?;
        let entry = |dst: &str| {
            neigh
                .as_array()
                .and_then(|a| a.iter().find(|n| n["dst"] == dst))
                .map(|n| (n["lladdr"].clone(), n["state"].clone()))
        };
        let want = |m: [u8; 6]| Some((serde_json::json!(shown(m)), serde_json::json!(["PERMANENT"])));
        if entry("10.80.0.2") != want(mac(m)) || entry(&six.to_string()) != want(mac(m + 1)) {
            return Err(format!("step {}: {neigh}", i + 1));
        }
        let proxies = ip_json(&ns, &["neigh", "show", "proxy", "dev", "v0"])?;
        if proxies != serde_json::json!([{"dst": "10.80.0.9", "proxy": null}]) {
            return Err(format!("step {}: proxies {proxies}", i + 1));
        }
        ifindexes.push(link_json(&ns, "v0")?["ifindex"].as_u64());
        Ok(())
    })
    .await?;
    assert_eq!(ifindexes[0], ifindexes[1], "a new lladdr changes the entry, not the link");
    assert_ne!(ifindexes[1], ifindexes[2], "a new VLAN id recreates the link");
    Ok(())
}

/// Declared FDB entries A→B→C→D (#516): a static and a local bridge entry,
/// two flood remotes and a unicast remote on a VXLAN device. Step 2 moves
/// the static entry to the other port, makes the other one local and
/// points the unicast remote elsewhere. Step 3 changes the VNI, which
/// recreates the VXLAN device; its remotes come back, and the recreate is
/// not refused over them. Step 4 moves a port to another bridge, which
/// deletes its entries; the apply puts them in the new one. `bridge -j fdb`
/// shows each step.
#[tokio::test]
async fn fdb_entries_change_and_come_back_after_a_move_or_recreate() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "bridge", "vxlan");

    let mac = |n: u8| [0x02, 0, 0, 0, 0x5d, n];
    let ip = |n: u8| v4(10, 85, 0, n);
    let step = |p0_master: &'static str, m1_dev: &'static str, local: bool, vni: u32, uni: u8| {
        NetworkConfig::new()
            .link("br0", |l| l.bridge().up())
            .link("br1", |l| l.bridge().up())
            .link("p0", move |l| l.dummy().master(p0_master).up())
            .link("p1", |l| l.dummy().master("br0").up())
            .link("vx0", move |l| l.vxlan(vni).vxlan_local(ip(1)).vxlan_port(4789))
            .fdb(m1_dev, mac(1), |e| e)
            .fdb("p0", mac(2), move |e| if local { e.local() } else { e })
            .fdb("vx0", [0; 6], move |e| e.dst(ip(2)))
            .fdb("vx0", [0; 6], move |e| e.dst(ip(3)))
            .fdb("vx0", mac(5), move |e| e.dst(ip(uni)))
    };
    let steps = [
        step("br0", "p0", false, 5, 4),
        step("br0", "p1", true, 5, 6),
        step("br0", "p1", true, 6, 6),
        step("br1", "p1", true, 6, 6),
    ];
    // (mac 1's port, mac 2's bridge, mac 2's state, the unicast remote)
    let want = [
        ("p0", "br0", "static", "10.85.0.4"),
        ("p1", "br0", "permanent", "10.85.0.6"),
        ("p1", "br0", "permanent", "10.85.0.6"),
        ("p1", "br1", "permanent", "10.85.0.6"),
    ];
    let ns = TestNamespace::new("tr-fdb")?;
    let mut vx = Vec::new();
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let out = ns.exec("bridge", &["-j", "fdb", "show"]).map_err(|e| e.to_string())?;
        let all: serde_json::Value = serde_json::from_str(&out).map_err(|e| e.to_string())?;
        let entries = all.as_array().cloned().unwrap_or_default();
        let find = |mac: &str, dev: &str, dst: Option<&str>| {
            entries.iter().find(|e| {
                e["mac"] == mac && e["ifname"] == dev && dst.is_none_or(|d| e["dst"] == d)
            })
        };
        let (m1_dev, m2_bridge, m2_state, uni) = want[i];
        let m1 = find("02:00:00:00:5d:01", m1_dev, None);
        let m2 = find("02:00:00:00:5d:02", "p0", None);
        let checks = [
            ("mac 1", m1.map(|e| (e["master"].clone(), e["state"].clone())), ("br0", "static")),
            ("mac 2", m2.map(|e| (e["master"].clone(), e["state"].clone())), (m2_bridge, m2_state)),
        ];
        for (what, have, (master, state)) in checks {
            if have != Some((serde_json::json!(master), serde_json::json!(state))) {
                return Err(format!("step {}: {what} is {have:?}: {out}", i + 1));
            }
        }
        for (m, dst) in [("00:00:00:00:00:00", "10.85.0.2"), ("00:00:00:00:00:00", "10.85.0.3"), ("02:00:00:00:5d:05", uni)] {
            if find(m, "vx0", Some(dst)).is_none() {
                return Err(format!("step {}: no remote {m} dst {dst}: {out}", i + 1));
            }
        }
        let remotes = entries.iter().filter(|e| e["ifname"] == "vx0" && e["mac"] == "02:00:00:00:5d:05").count();
        if remotes != 1 {
            return Err(format!("step {}: the unicast MAC has {remotes} remotes: {out}", i + 1));
        }
        vx.push(link_json(&ns, "vx0")?["ifindex"].as_u64());
        Ok(())
    })
    .await?;
    assert_eq!(vx[0], vx[1], "step 2 changes entries, not the device");
    assert_ne!(vx[1], vx[2], "a new VNI recreates the VXLAN device");
    Ok(())
}

/// The policy rules with protocol `boot` — the config's — in one family, as
/// `ip -j -d rule` shows them, one line each.
fn boot_rules(ns: &TestNamespace, family: &str) -> Result<Vec<String>, String> {
    let all = ip_json(ns, &[family, "-d", "rule", "show"])?;
    let field = |r: &serde_json::Value, k: &str| match &r[k] {
        serde_json::Value::Null if r.get(k).is_some() => "yes".to_string(),
        serde_json::Value::Null => "-".to_string(),
        serde_json::Value::String(v) => v.clone(),
        v => v.to_string(),
    };
    let mut out: Vec<String> = all
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["protocol"] == "boot")
        .map(|r| {
            let keys = [
                "priority", "not", "src", "srclen", "fwmark", "fwmask", "iif", "ipproto", "dport_start",
                "dport_end", "table", "action", "suppress_prefixlen", "iif_detached",
            ];
            keys.iter().map(|k| format!("{k}={}", field(r, k))).collect::<Vec<_>>().join(" ")
        })
        .collect();
    out.sort();
    Ok(out)
}

/// Declared policy rules A→B→C (#516), each step applied with the one
/// before as the previous config. Step 2 changes a rule's table and
/// another's prefix (the old ones go), drops one, adds an IPv6 one with a
/// masked mark. Step 3 recreates the device a rule names as its input: the
/// rule follows the name, attached again. An identical rule another tool
/// added first — protocol `unspec`, ahead of the config's in the list — is
/// neither taken for the config's nor removed with it. `ip -j -d rule`
/// shows each step.
#[tokio::test]
async fn rules_change_and_go_with_the_previous_config() -> nlink::Result<()> {
    use std::net::Ipv6Addr;
    require_root!();
    nlink::require_modules!("dummy", "bridge");

    let v6 = |third: u16| Ipv6Addr::new(0xfd00, 0x87, third, 0, 0, 0, 0, 0);
    let a = NetworkConfig::new()
        .link("d0", |l| l.dummy().up())
        .rule(100, |r| r.from(Ipv4Addr::new(10, 87, 0, 0), 16).table(100))
        .rule(110, |r| r.invert().fwmark(0x10).table(200))
        .rule(120, |r| r.table(254).suppress_prefixlen(0))
        .rule(130, |r| r.iif("d0").ipproto(6).dport(80, 89).prohibit())
        .rule(100, move |r| r.from(v6(0), 64).table(100));
    let b = |kind: fn(nlink::netlink::config::LinkBuilder) -> nlink::netlink::config::LinkBuilder| {
        NetworkConfig::new()
            .link("d0", move |l| kind(l).up())
            .rule(100, |r| r.from(Ipv4Addr::new(10, 87, 0, 0), 16).table(101))
            .rule(120, |r| r.table(254).suppress_prefixlen(0))
            .rule(130, |r| r.iif("d0").ipproto(6).dport(80, 89).prohibit())
            .rule(100, move |r| r.from(v6(1), 64).table(100))
            .rule(140, |r| r.ipv6().fwmark_masked(0x1, 0xff).blackhole())
    };
    let steps = [a, b(|l| l.dummy()), b(|l| l.bridge())];
    let line = |p: u32, rest: &str| {
        let mut fields: std::collections::BTreeMap<&str, String> = [
            "not", "src", "srclen", "fwmark", "fwmask", "iif", "ipproto", "dport_start", "dport_end",
            "table", "action", "suppress_prefixlen", "iif_detached",
        ]
        .iter()
        .map(|k| (*k, "-".to_string()))
        .collect();
        for kv in rest.split_whitespace() {
            let (k, v) = kv.split_once('=').unwrap();
            *fields.get_mut(k).unwrap() = v.to_string();
        }
        let keys = [
            "not", "src", "srclen", "fwmark", "fwmask", "iif", "ipproto", "dport_start", "dport_end",
            "table", "action", "suppress_prefixlen", "iif_detached",
        ];
        let mut s = format!("priority={p}");
        for k in keys {
            s.push_str(&format!(" {k}={}", fields[k]));
        }
        s
    };
    let sorted = |mut v: Vec<String>| {
        v.sort();
        v
    };
    let want_v4 = [
        sorted(vec![
            line(100, "src=10.87.0.0 srclen=16 table=100"),
            line(110, "not=yes src=all fwmark=0x10 table=200"),
            line(120, "src=all table=main suppress_prefixlen=0"),
            line(130, "src=all iif=d0 ipproto=tcp dport_start=80 dport_end=89 action=prohibit"),
        ]),
        sorted(vec![
            line(100, "src=10.87.0.0 srclen=16 table=101"),
            line(120, "src=all table=main suppress_prefixlen=0"),
            line(130, "src=all iif=d0 ipproto=tcp dport_start=80 dport_end=89 action=prohibit"),
        ]),
    ];
    let want_v6 = [
        vec![line(100, "src=fd00:87:: srclen=64 table=100")],
        sorted(vec![
            line(100, "src=fd00:87:1:: srclen=64 table=100"),
            line(140, "src=all fwmark=0x1 fwmask=0xff action=blackhole"),
        ]),
    ];
    let ns = TestNamespace::new("tr-rules")?;
    // Another tool's copy of rule 100, which is not the config's.
    ns.exec("ip", &["rule", "add", "pref", "100", "from", "10.87.0.0/16", "table", "100"])?;
    crate::common::converge::assert_transition_with_previous(&ns, &steps, async |i, _conn| {
        let w = i.min(1);
        let (v4, v6) = (boot_rules(&ns, "-4")?, boot_rules(&ns, "-6")?);
        if v4 != want_v4[w] || v6 != want_v6[w] {
            return Err(format!("step {}:\n{v4:#?}\n{v6:#?}", i + 1));
        }
        let theirs = ip_json(&ns, &["-4", "-d", "rule", "show", "pref", "100"])?;
        let kept = theirs.as_array().into_iter().flatten().any(|r| {
            r["protocol"] == "unspec" && r["table"] == "100" && r["src"] == "10.87.0.0"
        });
        if !kept {
            return Err(format!("step {}: the other tool's rule went: {theirs}", i + 1));
        }
        Ok(())
    })
    .await
}

/// A veth whose peer lives in another namespace, A→B→C→D (#516). Step 1
/// creates the peer in namespace B; step 2 declares it in C, which
/// recreates the pair — not refused over the peer, whose namespace the
/// config declares; step 3 declares it here. Then the peer is moved to B by
/// hand, as a CNI moves one into a container, and step 4 — the peer's
/// namespace undeclared — leaves it there. `ip link` in each namespace
/// shows where the peer is.
#[tokio::test]
async fn a_veth_peer_lives_in_its_declared_namespace() -> nlink::Result<()> {
    use nlink::netlink::namespace::NetnsRef;
    require_root!();
    nlink::require_modules!("veth");

    let ns = TestNamespace::new("tr-peer")?;
    let b = TestNamespace::new("tr-peer-b")?;
    let c = TestNamespace::new("tr-peer-c")?;
    let step = |netns: Option<NetnsRef>| {
        NetworkConfig::new().link("v0", move |l| {
            let l = l.veth("p0").up();
            match netns {
                Some(r) => l.veth_peer_netns(r),
                None => l,
            }
        })
    };
    let named = |t: &TestNamespace| NetnsRef::Named(t.name().to_string());
    let steps = [
        step(Some(named(&b))),
        step(Some(named(&c))),
        step(Some(NetnsRef::Default)),
        step(None),
    ];
    let has_p0 = |t: &TestNamespace| t.exec("ip", &["link", "show", "p0"]).is_ok();
    let mut v0 = Vec::new();
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let place = [has_p0(&ns), has_p0(&b), has_p0(&c)];
        let want = [[false, true, false], [false, false, true], [true, false, false], [false, true, false]];
        if place != want[i] {
            return Err(format!("step {}: p0 here/b/c = {place:?}, want {:?}", i + 1, want[i]));
        }
        v0.push(link_json(&ns, "v0")?["ifindex"].as_u64());
        if i == 2 {
            // A CNI moving the peer into a container.
            ns.exec("ip", &["link", "set", "p0", "netns", b.name()]).map_err(|e| e.to_string())?;
        }
        Ok(())
    })
    .await?;
    assert_ne!(v0[0], v0[1], "a peer declared elsewhere recreates the pair");
    assert_ne!(v0[1], v0[2]);
    assert_eq!(v0[2], v0[3], "an undeclared namespace leaves the peer where it was moved");
    Ok(())
}

/// A veth peer's MAC, MTU and state in its namespace, A→B→C (#680): step
/// 1 creates the pair with them; step 2 changes all three in place, through
/// a connection in the peer's namespace, and the pair keeps its ifindexes;
/// step 3 declares none, and the peer keeps what it has. `ip link` in the
/// peer's namespace shows each step.
#[tokio::test]
async fn a_veth_peer_is_set_in_its_namespace() -> nlink::Result<()> {
    use nlink::netlink::namespace::NetnsRef;
    require_root!();
    nlink::require_modules!("veth");

    let ns = TestNamespace::new("tr-peerset")?;
    let b = TestNamespace::new("tr-peerset-b")?;
    let there = NetnsRef::Named(b.name().to_string());
    let step = |set: Option<(u8, u32, bool)>| {
        let there = there.clone();
        NetworkConfig::new().link("v0", move |l| {
            let l = l.veth("p0").up().veth_peer_netns(there);
            match set {
                Some((last, mtu, up)) => {
                    let l = l.veth_peer_address([2, 0, 0, 0, 0x68, last]).veth_peer_mtu(mtu);
                    if up { l.veth_peer_up() } else { l.veth_peer_down() }
                }
                None => l,
            }
        })
    };
    let steps = [step(Some((1, 1400, true))), step(Some((2, 1300, false))), step(None)];
    let want: [(&str, u32, bool); 3] =
        [("02:00:00:00:68:01", 1400, true), ("02:00:00:00:68:02", 1300, false), ("02:00:00:00:68:02", 1300, false)];
    let mut ifindexes = Vec::new();
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let p0 = &ip_json(&b, &["link", "show", "p0"])?[0];
        let up = p0["flags"].as_array().is_some_and(|f| f.iter().any(|f| f == "UP"));
        let have = (p0["address"].as_str(), p0["mtu"].as_u64(), up);
        let (mac, mtu, want_up) = want[i];
        if have != (Some(mac), Some(u64::from(mtu)), want_up) {
            return Err(format!("step {}: p0 is {have:?}, want {:?}", i + 1, want[i]));
        }
        ifindexes.push((link_json(&ns, "v0")?["ifindex"].as_u64(), p0["ifindex"].as_u64()));
        Ok(())
    })
    .await?;
    assert_eq!(ifindexes[0], ifindexes[1], "the peer changes in place");
    assert_eq!(ifindexes[1], ifindexes[2]);
    Ok(())
}

/// VRF strict mode around the links, A→B→C (#680): step 1 turns it on
/// with two VRFs on their own tables; step 2 turns it off and moves green
/// onto red's table, which needs it off before green is created again;
/// step 3 moves green away and turns it on after. The namespace's
/// `/proc/sys/net/vrf/strict_mode` and `ip -d link` show each step.
#[tokio::test]
async fn vrf_strict_mode_is_set_around_the_links() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("vrf");
    nlink::require_writable_sysctl!("/proc/sys/net/ipv4/ip_forward");

    let step = |strict: bool, green: u32| {
        NetworkConfig::new()
            .vrf_strict_mode(strict)
            .link("red", |l| l.vrf(10).up())
            .link("green", move |l| l.vrf(green).up())
    };
    let steps = [step(true, 20), step(false, 10), step(true, 30)];
    let want = [("1", 20), ("0", 10), ("1", 30)];
    let ns = TestNamespace::new("tr-vrfstrict")?;
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let strict = ns
            .exec("cat", &["/proc/sys/net/vrf/strict_mode"])
            .map_err(|e| e.to_string())?;
        let table = link_json(&ns, "green")?["linkinfo"]["info_data"]["table"].as_u64();
        let (want_strict, want_table) = want[i];
        if (strict.trim(), table) != (want_strict, Some(want_table)) {
            return Err(format!(
                "step {}: strict_mode {} and green's table {table:?}, want {want_strict} and {want_table}",
                i + 1,
                strict.trim()
            ));
        }
        Ok(())
    })
    .await
}

/// Declared nexthop objects and the routes through them, A→B→C→D (#516),
/// each step applied with the one before as the previous config. Step 2
/// gives a nexthop another gateway and its group other weights, in place.
/// Step 3 changes the VLAN id of the link they are on, which recreates it:
/// the kernel deletes the nexthops on it, the group made of them and every
/// route through any of them, and the apply puts them all back — not
/// refused over them. Step 4 drops the group, the blackhole and their
/// routes. `ip -j nexthop` and `ip -j route` show each step.
#[tokio::test]
async fn nexthops_change_and_come_back_after_a_recreate() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "8021q");

    let gw = |h: u8| v4(10, 96, 0, h);
    let step = |vlan: u16, gw1: u8, weights: (u16, u16), all: bool| {
        let c = NetworkConfig::new()
            .link("lo", |l| l.up())
            .link("b0", |l| l.dummy().up())
            .link("d0", move |l| l.vlan("b0", vlan).up())
            .address("d0", "10.96.0.1/24")
            .unwrap()
            .nexthop(1, move |n| n.via(gw(gw1)).dev("d0"))
            .nexthop(2, move |n| n.via(gw(3)).dev("d0"))
            .route("10.94.0.0/16", |r| r.nhid(1))
            .unwrap();
        if !all {
            return c;
        }
        c.nexthop(3, |n| n.blackhole())
            .nexthop(10, move |n| n.group(&[(1, weights.0), (2, weights.1)]))
            .route("10.95.0.0/16", |r| r.nhid(10))
            .unwrap()
            .route("10.93.0.0/16", |r| r.nhid(3))
            .unwrap()
    };
    let steps = [
        step(10, 2, (1, 3), true),
        step(10, 4, (2, 1), true),
        step(11, 4, (2, 1), true),
        step(11, 4, (2, 1), false),
    ];
    let ns = TestNamespace::new("tr-nexthop")?;
    let mut d0 = Vec::new();
    crate::common::converge::assert_transition_with_previous(&ns, &steps, async |i, _conn| {
        let nh = ip_json(&ns, &["nexthop", "show"])?;
        let by_id = |id: u64| nh.as_array().and_then(|a| a.iter().find(|n| n["id"] == id)).cloned();
        let gw1 = if i == 0 { "10.96.0.2" } else { "10.96.0.4" };
        if by_id(1).map(|n| n["gateway"].clone()) != Some(serde_json::json!(gw1)) {
            return Err(format!("step {}: nexthop 1: {nh}", i + 1));
        }
        let group = if i == 0 {
            serde_json::json!([{"id": 1}, {"id": 2, "weight": 3}])
        } else {
            serde_json::json!([{"id": 1, "weight": 2}, {"id": 2}])
        };
        let want_group = (i < 3).then_some(group);
        if by_id(10).map(|n| n["group"].clone()) != want_group {
            return Err(format!("step {}: group 10: {nh}", i + 1));
        }
        if by_id(3).is_some() != (i < 3) || by_id(2).is_none() {
            return Err(format!("step {}: nexthops 2 and 3: {nh}", i + 1));
        }
        for (dst, id, present) in [("10.94.0.0/16", 1, true), ("10.95.0.0/16", 10, i < 3), ("10.93.0.0/16", 3, i < 3)] {
            let routes = ip_json(&ns, &["route", "show", dst])?;
            let have = routes.as_array().is_some_and(|a| a.iter().any(|r| r["nhid"] == id));
            if have != present {
                return Err(format!("step {}: route {dst} nhid {id}: {routes}", i + 1));
            }
        }
        d0.push(link_json(&ns, "d0")?["ifindex"].as_u64());
        Ok(())
    })
    .await?;
    assert_eq!(d0[0], d0[1], "step 2 changes the nexthops in place");
    assert_ne!(d0[1], d0[2], "a new VLAN id recreates the link");
    Ok(())
}

/// Declared multipath routes A→B→C→D (#516), IPv4 and IPv6, each step with
/// the one before as the previous config. Step 2 changes the weights in
/// place. Step 3 recreates the link one hop is on (a new VLAN id): the
/// kernel deletes the IPv4 route with it and the IPv6 route's hop, and the
/// apply puts both back whole — not refused over them. Step 4 makes them
/// single-gateway routes. `ip -j route` shows the hops each step.
#[tokio::test]
async fn multipath_routes_change_and_come_back_after_a_recreate() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "8021q");

    let step = |vlan: u16, weights: (u16, u16), multipath: bool| {
        let c = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("b1", |l| l.dummy().up())
            .link("d1", move |l| l.vlan("b1", vlan).up())
            .address_with("d0", "10.92.0.1/24", |a| a)
            .unwrap()
            .address_with("d1", "10.92.1.1/24", |a| a)
            .unwrap()
            .address_with("d0", "fd00:92::1/64", |a| a.nodad())
            .unwrap()
            .address_with("d1", "fd00:92:1::1/64", |a| a.nodad())
            .unwrap();
        if !multipath {
            return c
                .route("10.91.0.0/16", |r| r.via("10.92.0.2").dev("d0"))
                .unwrap()
                .route("fd00:91::/48", |r| r.via("fd00:92::2").dev("d0"))
                .unwrap();
        }
        // The IPv4 route's second hop names no device: the kernel picks
        // d1, and only the link's recreate says the route went with it.
        c.route("10.91.0.0/16", move |r| {
            r.nexthop(|h| h.via("10.92.0.2").dev("d0").weight(weights.0))
                .nexthop(|h| h.via("10.92.1.2").weight(weights.1))
        })
        .unwrap()
        .route("fd00:91::/48", move |r| {
            r.nexthop(|h| h.via("fd00:92::2").dev("d0").weight(weights.0))
                .nexthop(|h| h.via("fd00:92:1::2").dev("d1").weight(weights.1))
        })
        .unwrap()
    };
    let steps = [step(20, (1, 3), true), step(20, (2, 1), true), step(21, (2, 1), true), step(21, (2, 1), false)];
    let ns = TestNamespace::new("tr-multipath")?;
    let mut d1 = Vec::new();
    crate::common::converge::assert_transition_with_previous(&ns, &steps, async |i, _conn| {
        let hops = |family: &str, dst: &str| -> Result<serde_json::Value, String> {
            let routes = ip_json(&ns, &[family, "route", "show", dst])?;
            Ok(routes[0].clone())
        };
        let (w0, w1) = if i == 0 { (1, 3) } else { (2, 1) };
        for (family, dst, gw0, gw1) in [
            ("-4", "10.91.0.0/16", "10.92.0.2", "10.92.1.2"),
            ("-6", "fd00:91::/48", "fd00:92::2", "fd00:92:1::2"),
        ] {
            let r = hops(family, dst)?;
            let want = if i < 3 {
                serde_json::json!([[gw0, "d0", w0], [gw1, "d1", w1]])
            } else {
                serde_json::json!([])
            };
            let have: Vec<serde_json::Value> = r["nexthops"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|h| serde_json::json!([h["gateway"], h["dev"], h["weight"].as_u64().unwrap_or(1)]))
                .collect();
            if serde_json::json!(have) != want {
                return Err(format!("step {}: {dst}: {r}", i + 1));
            }
            if i == 3 && (r["gateway"] != gw0 || r["dev"] != "d0") {
                return Err(format!("step 4: {dst} is not via {gw0}: {r}"));
            }
        }
        d1.push(link_json(&ns, "d1")?["ifindex"].as_u64());
        Ok(())
    })
    .await?;
    assert_eq!(d1[0], d1[1], "step 2 changes the routes in place");
    assert_ne!(d1[1], d1[2], "a new VLAN id recreates the link");
    Ok(())
}

/// An IPv4 route via an IPv6 gateway (RFC 5549, `RTA_VIA`) and one with
/// an MPLS encapsulation, A→B→C (#516). Step 2 moves the gateway and
/// changes the labels; step 3 makes both plain IPv4 routes, which drops
/// the encapsulation. `ip -j route` shows each step.
#[tokio::test]
async fn routes_via_ipv6_and_with_mpls_encap_change() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "mpls_iptunnel");

    let step = |i: usize| {
        let base = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .address_with("d0", "10.90.0.1/24", |a| a)
            .unwrap()
            .address_with("d0", "fd00:90::1/64", |a| a.nodad())
            .unwrap();
        match i {
            0 | 1 => {
                let (gw6, labels): (&str, &[u32]) = if i == 0 { ("fd00:90::2", &[100, 200]) } else { ("fd00:90::3", &[300]) };
                base.route("10.89.0.0/16", move |r| r.via(gw6).dev("d0"))
                    .unwrap()
                    .route("10.88.0.0/16", move |r| r.via("10.90.0.2").dev("d0").encap_mpls(labels))
                    .unwrap()
            }
            _ => base
                .route("10.89.0.0/16", |r| r.via("10.90.0.2").dev("d0"))
                .unwrap()
                .route("10.88.0.0/16", |r| r.via("10.90.0.2").dev("d0"))
                .unwrap(),
        }
    };
    let steps = [step(0), step(1), step(2)];
    let ns = TestNamespace::new("tr-via")?;
    crate::common::converge::assert_transition_with_previous(&ns, &steps, async |i, _conn| {
        // Text: iproute2 6.1's JSON puts the labels in the route's `dst`.
        let show = |dst: &str| ns.exec("ip", &["route", "show", dst]).map_err(|e| e.to_string());
        let (via, encap) = (show("10.89.0.0/16")?, show("10.88.0.0/16")?);
        let (want_via, want_encap) = match i {
            0 => ("via inet6 fd00:90::2 dev d0", "encap mpls  100/200 via 10.90.0.2 dev d0"),
            1 => ("via inet6 fd00:90::3 dev d0", "encap mpls  300 via 10.90.0.2 dev d0"),
            _ => ("via 10.90.0.2 dev d0", "10.88.0.0/16 via 10.90.0.2 dev d0"),
        };
        if !via.contains(want_via) {
            return Err(format!("step {}: via route: {via}", i + 1));
        }
        if !encap.contains(want_encap) {
            return Err(format!("step {}: encap route: {encap}", i + 1));
        }
        Ok(())
    })
    .await
}

/// ip6gre and ip6gretap tunnels changed in place (#516): ends, hop limit,
/// encapsulation limit, key and underlay. `ip6gre_netlink_parms` rebuilds
/// the whole configuration from the request, so each step checks every
/// parameter through `ip -d link`, and both keep their ifindexes.
#[tokio::test]
async fn ip6gre_tunnels_change_in_place() -> nlink::Result<()> {
    use std::net::Ipv6Addr;
    require_root!();
    nlink::require_modules!("dummy", "ip6_gre");

    let a = |n: u16, h: u16| Ipv6Addr::new(0xfd00, 0x95, n, 0, 0, 0, 0, h);
    let params = |b: bool| if b { (3, 32, 2, 8, "d1") } else { (2, 64, 4, 7, "d0") };
    let step = |b: bool| {
        let (r, hl, el, key, dev) = params(b);
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("d1", |l| l.dummy().up())
            .link("g61", move |l| {
                l.ip6gre()
                    .ip6tnl_local(a(0, 1))
                    .ip6tnl_remote(a(0, r))
                    .ip6tnl_hoplimit(hl)
                    .ip6tnl_encap_limit(el)
                    .tunnel_key(key)
                    .tunnel_underlay_dev(dev)
            })
            .link("g62", move |l| {
                l.ip6gretap().ip6tnl_local(a(1, 1)).ip6tnl_remote(a(1, r)).tunnel_key(key + 10)
            })
    };
    let ns = TestNamespace::new("tr-ip6gre")?;
    let mut ifindexes = Vec::new();
    crate::common::converge::assert_transition(&ns, &[step(false), step(true)], false, async |i, _conn| {
        let (r, hl, el, key, dev) = params(i == 1);
        let dotted = |k: u32| std::net::Ipv4Addr::from(k).to_string();
        let g61 = link_json(&ns, "g61")?;
        let g62 = link_json(&ns, "g62")?;
        let (d61, d62) = (&g61["linkinfo"]["info_data"], &g62["linkinfo"]["info_data"]);
        let checks = [
            ("g61 local", d61["local"].clone(), serde_json::json!(a(0, 1).to_string())),
            ("g61 remote", d61["remote"].clone(), serde_json::json!(a(0, r).to_string())),
            ("g61 hoplimit", d61["ttl"].clone(), serde_json::json!(hl)),
            ("g61 encaplimit", d61["encap_limit"].clone(), serde_json::json!(el)),
            ("g61 key", d61["ikey"].clone(), serde_json::json!(dotted(key))),
            ("g61 dev", d61["link"].clone(), serde_json::json!(dev)),
            ("g62 remote", d62["remote"].clone(), serde_json::json!(a(1, r).to_string())),
            ("g62 key", d62["okey"].clone(), serde_json::json!(dotted(key + 10))),
        ];
        for (what, have, want) in checks {
            if have != want {
                return Err(format!("step {}: {what} is {have}, want {want}", i + 1));
            }
        }
        ifindexes.push((g61["ifindex"].as_u64(), g62["ifindex"].as_u64()));
        Ok(())
    })
    .await?;
    assert_eq!(ifindexes[0], ifindexes[1], "both change in place");
    Ok(())
}

/// vti6, erspan and ip6erspan tunnels changed in place (#680): ends, key or
/// session, TTL, underlay, and an ERSPAN header from type II to type III.
/// Each kind's netlink parms rebuild the configuration from the request, so
/// each step checks every parameter through `ip -d link`, and every tunnel
/// keeps its ifindex.
#[tokio::test]
async fn vti6_and_erspan_tunnels_change_in_place() -> nlink::Result<()> {
    use nlink::netlink::link::{ErspanDirection, ErspanVersion};
    use std::net::{Ipv4Addr, Ipv6Addr};
    require_root!();
    nlink::require_modules!("dummy", "ip_gre", "ip6_gre", "ip6_vti");

    let a6 = |n: u16, h: u16| Ipv6Addr::new(0xfd00, 0x96, n, 0, 0, 0, 0, h);
    let a4 = |h: u16| Ipv4Addr::new(10, 96, 0, u8::try_from(h).unwrap());
    let version = |b: bool| {
        if b {
            ErspanVersion::V2 { direction: ErspanDirection::Egress, hwid: 7 }
        } else {
            ErspanVersion::V1 { index: 123 }
        }
    };
    let params = |b: bool| if b { (3, 9, 32, "d1") } else { (2, 5, 64, "d0") };
    let step = |b: bool| {
        let (r, key, ttl, dev) = params(b);
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("d1", |l| l.dummy().up())
            .link("v61", move |l| {
                l.vti6()
                    .ip6tnl_local(a6(0, 1))
                    .ip6tnl_remote(a6(0, r))
                    .tunnel_key(key)
                    .tunnel_underlay_dev(dev)
            })
            .link("es1", move |l| {
                l.erspan(u16::try_from(key).unwrap() + 100)
                    .erspan_local(a4(1))
                    .erspan_remote(a4(r))
                    .erspan_ttl(ttl)
                    .erspan_version(version(b))
                    .tunnel_underlay_dev(dev)
            })
            .link("es6", move |l| {
                l.ip6erspan(u16::try_from(key).unwrap())
                    .erspan_local(a6(1, 1))
                    .erspan_remote(a6(1, r))
                    .erspan_version(version(!b))
            })
    };
    let ns = TestNamespace::new("tr-erspan")?;
    let mut ifindexes = Vec::new();
    crate::common::converge::assert_transition(&ns, &[step(false), step(true)], false, async |i, _conn| {
        let b = i == 1;
        let (r, key, ttl, dev) = params(b);
        let dotted = |k: u32| Ipv4Addr::from(k).to_string();
        let v61 = link_json(&ns, "v61")?;
        let es1 = link_json(&ns, "es1")?;
        let es6 = link_json(&ns, "es6")?;
        let (dv, d1, d6) = (
            &v61["linkinfo"]["info_data"],
            &es1["linkinfo"]["info_data"],
            &es6["linkinfo"]["info_data"],
        );
        let header = |d: &serde_json::Value, v: ErspanVersion| match v {
            ErspanVersion::V1 { index } => {
                (d["erspan_ver"] == 1 && d["erspan_index"] == index).then_some(())
            }
            ErspanVersion::V2 { .. } => {
                (d["erspan_ver"] == 2 && d["erspan_dir"] == "egress" && d["erspan_hwid"] == "0x7")
                    .then_some(())
            }
            _ => None,
        };
        let checks = [
            ("v61 remote", dv["remote"].clone(), serde_json::json!(a6(0, r).to_string())),
            ("v61 key", dv["ikey"].clone(), serde_json::json!(dotted(key))),
            ("v61 dev", dv["link"].clone(), serde_json::json!(dev)),
            ("es1 remote", d1["remote"].clone(), serde_json::json!(a4(r).to_string())),
            ("es1 session", d1["okey"].clone(), serde_json::json!(dotted(key + 100))),
            ("es1 ttl", d1["ttl"].clone(), serde_json::json!(ttl)),
            ("es1 dev", d1["link"].clone(), serde_json::json!(dev)),
            ("es6 remote", d6["remote"].clone(), serde_json::json!(a6(1, r).to_string())),
            ("es6 session", d6["ikey"].clone(), serde_json::json!(dotted(key))),
        ];
        for (what, have, want) in checks {
            if have != want {
                return Err(format!("step {}: {what} is {have}, want {want}", i + 1));
            }
        }
        header(d1, version(b)).ok_or_else(|| format!("step {}: es1 header {d1}", i + 1))?;
        header(d6, version(!b)).ok_or_else(|| format!("step {}: es6 header {d6}", i + 1))?;
        ifindexes.push((v61["ifindex"].as_u64(), es1["ifindex"].as_u64(), es6["ifindex"].as_u64()));
        Ok(())
    })
    .await?;
    assert_eq!(ifindexes[0], ifindexes[1], "all three change in place");
    Ok(())
}

/// A Geneve tunnel A→B→C (#516): a new remote and TTL change in place, and
/// the link keeps its ifindex; a new VNI, which `geneve_changelink`
/// refuses, recreates it. `ip -d link` shows each step.
#[tokio::test]
async fn geneve_changes_in_place_and_recreates_for_the_vni() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("geneve");

    let step = |vni: u32, last: u8, ttl: u8| {
        NetworkConfig::new().link("gn1", move |l| {
            l.geneve(vni).geneve_remote(v4(10, 70, 0, last)).geneve_ttl(ttl)
        })
    };
    let steps = [step(5, 2, 10), step(5, 3, 20), step(6, 3, 20)];
    let want = [(5, "10.70.0.2", 10), (5, "10.70.0.3", 20), (6, "10.70.0.3", 20)];
    let ns = TestNamespace::new("tr-geneve")?;
    let mut ifindexes = Vec::new();
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let link = &ip_json(&ns, &["-d", "link", "show", "gn1"])?[0];
        let data = &link["linkinfo"]["info_data"];
        let have = (data["id"].as_u64(), data["remote"].as_str(), data["ttl"].as_u64());
        let (id, remote, ttl) = want[i];
        if have != (Some(id), Some(remote), Some(ttl)) {
            return Err(format!("step {}: want {:?}, have {have:?}", i + 1, want[i]));
        }
        ifindexes.push(link["ifindex"].as_u64());
        Ok(())
    })
    .await?;
    assert_eq!(ifindexes[0], ifindexes[1], "a new remote and TTL change in place");
    assert_ne!(ifindexes[1], ifindexes[2], "a new VNI recreates");
    Ok(())
}

/// A MACsec link A→B→C (#516): encryption, SCI inclusion and the replay
/// window change in place (same ifindex); a new SCI, which
/// `macsec_changelink` refuses, recreates it.
#[tokio::test]
async fn macsec_changes_in_place_and_recreates_for_the_sci() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "macsec");

    let step = |sci: u64, encrypt: bool, protect: bool, window: u32| {
        NetworkConfig::new().link("d0", |l| l.dummy().up()).link("ms1", move |l| {
            l.macsec("d0")
                .macsec_sci(sci)
                .macsec_encrypt(encrypt)
                .macsec_protect(protect)
                .macsec_replay_window(window)
        })
    };
    let (a, b) = (0x0200_0000_0001_0001u64, 0x0200_0000_0001_0002u64);
    let steps = [step(a, true, true, 16), step(a, false, true, 64), step(b, false, true, 64)];
    let want = [
        ("0200000000010001", true, true, 16),
        ("0200000000010001", false, true, 64),
        ("0200000000010002", false, true, 64),
    ];
    let ns = TestNamespace::new("tr-macsec")?;
    let mut ifindexes = Vec::new();
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let link = &ip_json(&ns, &["-d", "link", "show", "ms1"])?[0];
        let data = &link["linkinfo"]["info_data"];
        let have = (
            data["sci"].as_str(),
            data["encrypt"].as_bool(),
            data["protect"].as_bool(),
            data["window"].as_u64(),
        );
        let (sci, encrypt, protect, window) = want[i];
        if have != (Some(sci), Some(encrypt), Some(protect), Some(window)) {
            return Err(format!("step {}: want {:?}, have {have:?}", i + 1, want[i]));
        }
        ifindexes.push(link["ifindex"].as_u64());
        Ok(())
    })
    .await?;
    assert_eq!(ifindexes[0], ifindexes[1], "encryption and the window change in place");
    assert_ne!(ifindexes[1], ifindexes[2], "a new SCI recreates");
    Ok(())
}
