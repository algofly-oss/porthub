//! An undo puts back a link the apply deleted (#745): recreated, because a
//! kind parameter changed, or removed, because the previous config
//! declared it and this one does not. The link comes back as it was, with
//! the links stacked on it, the ports it had, and what was on all of them.
//!
//! Each test reads the kernel through `ip`, `bridge` and `tc` before the
//! apply and after its undo, and the two must be the same: a diff that
//! converges only shows that nlink agrees with itself.

use std::sync::Arc;

use nlink::Result;
use nlink::netlink::{
    Connection, Route,
    config::{ApplyOptions, NetworkConfig, RecreatePolicy, Step},
};

use crate::common::{TestNamespace, converge::ip_json, with_timeout};

/// The namespace's links, addresses, routes, nexthops, neighbours, FDB and
/// TC, as `ip`, `bridge` and `tc` report them: one sorted line each, with
/// what a recreate renumbers (ifindexes, a bridge's port numbers) and what
/// moves on its own (operational state, timers, counters) left out. So are
/// the IPv6 link-local addresses and the multicast addresses they join: the
/// kernel makes them from the MAC a link had when it came up, which on a
/// VLAN created before its bridge had ports is not the MAC it has now.
fn kernel_state(ns: &TestNamespace) -> std::result::Result<Vec<String>, String> {
    use serde_json::Value;
    let pick = |v: &Value, keys: &[&str]| -> Value {
        // A line of text, where a tool printed no JSON.
        if !v.is_object() {
            return v.clone();
        }
        let mut out = serde_json::Map::new();
        for k in keys {
            if let Some(x) = v.get(*k) {
                out.insert((*k).to_string(), x.clone());
            }
        }
        Value::Object(out)
    };
    let list = |v: Value| v.as_array().cloned().unwrap_or_default();
    let json = |cmd: &str, args: &[&str]| -> std::result::Result<Value, String> {
        let mut full = vec!["-j"];
        full.extend_from_slice(args);
        let out = ns.exec(cmd, &full).map_err(|e| format!("{cmd} {}: {e}", args.join(" ")))?;
        if out.trim().is_empty() {
            return Ok(Value::Array(Vec::new()));
        }
        // iproute2 6.1's `tc -j class show` prints HTB classes as text: one
        // line each, which compares as well.
        Ok(serde_json::from_str(&out)
            .unwrap_or_else(|_| Value::from(out.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>())))
    };
    let mut lines = Vec::new();
    let mut devs = Vec::new();
    for l in list(ip_json(ns, &["-d", "link", "show"])?) {
        let name = l["ifname"].as_str().unwrap_or("?").to_string();
        let mut link = pick(&l, &["ifname", "mtu", "address", "master", "ifalias", "txqlen", "link"]);
        let flags: Vec<Value> = list(l["flags"].clone())
            .into_iter()
            .filter(|f| f != "LOWER_UP" && f != "NO-CARRIER")
            .collect();
        link["flags"] = Value::from(flags);
        if let Some(info) = l.get("linkinfo") {
            link["kind"] = info["info_kind"].clone();
            let mut data = info.get("info_data").cloned().unwrap_or(Value::Null);
            if let Some(d) = data.as_object_mut() {
                d.retain(|k, _| !k.ends_with("_timer"));
            }
            link["data"] = data;
            if let Some(port) = info.get("info_slave_data") {
                link["port"] = pick(
                    port,
                    &[
                        "learning", "flood", "mcast_flood", "bcast_flood", "hairpin", "proxy_arp",
                        "guard", "root_block", "cost", "priority", "isolated", "neigh_suppress",
                    ],
                );
            }
        }
        lines.push(format!("link {link}"));
        devs.push(name);
    }
    for l in list(ip_json(ns, &["addr", "show"])?) {
        for a in list(l["addr_info"].clone()) {
            if a["local"].as_str().is_some_and(|x| x.starts_with("fe80:")) {
                continue;
            }
            let a = pick(
                &a,
                &["family", "local", "address", "prefixlen", "scope", "label", "metric", "noprefixroute", "nodad", "home", "mngtmpaddr"],
            );
            lines.push(format!("addr {} {a}", l["ifname"]));
        }
    }
    for family in ["-4", "-6"] {
        for r in list(ip_json(ns, &[family, "route", "show", "table", "all"])?) {
            let r = pick(&r, &["type", "dst", "gateway", "dev", "protocol", "scope", "prefsrc", "table", "metric", "nhid", "via"]);
            lines.push(format!("route {r}"));
        }
        for n in list(ip_json(ns, &[family, "neigh", "show", "nud", "permanent"])?) {
            lines.push(format!("neigh {}", pick(&n, &["dst", "dev", "lladdr", "state"])));
        }
        for n in list(ip_json(ns, &[family, "neigh", "show", "proxy"])?) {
            lines.push(format!("proxy {}", pick(&n, &["dst", "dev"])));
        }
    }
    for n in list(ip_json(ns, &["nexthop", "show"])?) {
        lines.push(format!("nexthop {}", pick(&n, &["id", "gateway", "dev", "group", "protocol", "blackhole"])));
    }
    for e in list(json("bridge", &["fdb", "show"])?) {
        if e["mac"].as_str().is_some_and(|m| m.starts_with("33:33:") || m.starts_with("01:00:5e:")) {
            continue;
        }
        lines.push(format!("fdb {}", pick(&e, &["mac", "dev", "dst", "vlan", "master", "state", "flags"])));
    }
    for v in list(json("bridge", &["vlan", "show"])?) {
        lines.push(format!("vlan {}", pick(&v, &["ifname", "vlans"])));
    }
    for q in list(json("tc", &["qdisc", "show"])?) {
        let mut q = pick(&q, &["kind", "handle", "parent", "dev", "options"]);
        // A counter: what the qdisc has sent past its classes.
        if let Some(o) = q.get_mut("options").and_then(Value::as_object_mut) {
            o.remove("direct_packets_stat");
        }
        lines.push(format!("qdisc {q}"));
    }
    for dev in &devs {
        for c in list(json("tc", &["class", "show", "dev", dev])?) {
            lines.push(format!("class {dev} {}", pick(&c, &["class", "handle", "parent", "leaf", "options"])));
        }
        for parent in ["root", "ingress"] {
            // `tc filter show` fails on a device without the hook.
            let Ok(filters) = json("tc", &["filter", "show", "dev", dev, parent]) else {
                continue;
            };
            for f in list(filters) {
                lines.push(format!(
                    "filter {dev} {parent} {}",
                    pick(&f, &["protocol", "pref", "kind", "chain", "options"])
                ));
            }
        }
    }
    lines.sort();
    Ok(lines)
}

/// What differs between two states, for a failure message.
fn state_diff(before: &[String], after: &[String]) -> String {
    let gone = before.iter().filter(|l| !after.contains(l)).map(|l| format!("- {l}"));
    let new = after.iter().filter(|l| !before.contains(l)).map(|l| format!("+ {l}"));
    gone.chain(new).collect::<Vec<_>>().join("\n")
}

fn run(ns: &TestNamespace, cmd: &str, args: &[&str]) -> Result<()> {
    ns.exec(cmd, args).map(drop)
}

/// A recreated VXLAN comes back as it was (#745): its VNI, port, local
/// address, underlay, MTU, MAC, alias and queue length; the VLAN the kernel
/// deleted with it; the addresses on both; a route through the VLAN and
/// one through a nexthop object on it; a permanent neighbour; two FDB
/// remotes; and an HTB tree with an ingress filter. Only the VXLAN and an
/// address are declared: everything else is another tool's, which the
/// recreate is allowed to destroy.
#[tokio::test]
async fn the_undo_puts_a_recreated_link_back() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "vxlan", "8021q", "sch_htb", "sch_ingress", "cls_matchall", "cls_flower", "act_gact");

    with_timeout(async {
        let ns = TestNamespace::new("undo-recreate")?;
        let conn = Connection::<Route>::new_in(ns.name())?;
        let cfg = |vni: u32| -> Result<NetworkConfig> {
            NetworkConfig::new()
                .link("u0", |l| l.dummy().up())
                .address("u0", "10.70.0.1/24")?
                .link("vx0", move |l| {
                    l.vxlan(vni)
                        .vxlan_local("10.70.0.1".parse().unwrap())
                        .vxlan_port(4789)
                        .vxlan_underlay_dev("u0")
                        .mtu(1400)
                        .up()
                })
                .address("vx0", "10.71.0.1/24")
                .map_err(|e| nlink::Error::invalid_message(e.to_string()))
        };
        let applied = cfg(100)?.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        for (cmd, args) in [
            ("ip", &["link", "set", "vx0", "alias", "edge", "txqueuelen", "500"][..]),
            ("ip", &["addr", "add", "fd71::1/64", "dev", "vx0", "nodad"]),
            ("ip", &["link", "add", "link", "vx0", "name", "vx0.7", "type", "vlan", "id", "7"]),
            ("ip", &["link", "set", "vx0.7", "up"]),
            ("ip", &["addr", "add", "10.72.0.1/24", "dev", "vx0.7"]),
            ("ip", &["route", "add", "10.73.0.0/16", "via", "10.72.0.2", "proto", "static"]),
            ("ip", &["neigh", "add", "10.72.0.9", "lladdr", "02:00:00:00:00:09", "dev", "vx0.7", "nud", "permanent"]),
            ("ip", &["nexthop", "add", "id", "71", "via", "10.72.0.3", "dev", "vx0.7"]),
            ("ip", &["route", "add", "10.74.0.0/16", "nhid", "71"]),
            ("bridge", &["fdb", "append", "00:00:00:00:00:00", "dev", "vx0", "dst", "192.0.2.1", "permanent"]),
            ("bridge", &["fdb", "add", "02:00:00:00:00:aa", "dev", "vx0", "dst", "192.0.2.2", "permanent"]),
            ("tc", &["qdisc", "add", "dev", "vx0", "root", "handle", "1:", "htb", "default", "10"]),
            ("tc", &["class", "add", "dev", "vx0", "parent", "1:", "classid", "1:10", "htb", "rate", "10mbit"]),
            ("tc", &["filter", "add", "dev", "vx0", "parent", "1:", "prio", "1", "protocol", "ip", "matchall", "classid", "1:10"]),
            ("tc", &["qdisc", "add", "dev", "vx0", "ingress"]),
            ("tc", &["filter", "add", "dev", "vx0", "ingress", "prio", "2", "protocol", "ip", "flower", "dst_ip", "10.9.9.9", "action", "drop"]),
        ] {
            run(&ns, cmd, args)?;
        }
        let before = kernel_state(&ns).map_err(nlink::Error::invalid_message)?;

        let applied = cfg(200)?
            .apply_with_options(&conn, ApplyOptions::default().with_recreate_policy(RecreatePolicy::Allow))
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        assert!(applied.recreated.iter().any(|r| r.name == "vx0"), "{:?}", applied.recreated);
        let vni = ip_json(&ns, &["-d", "link", "show", "vx0"]).map_err(nlink::Error::invalid_message)?;
        assert_eq!(vni[0]["linkinfo"]["info_data"]["id"], 200);
        let stuck: Vec<String> = applied.irreversible().map(|s| s.to_string()).collect();
        assert!(stuck.is_empty(), "a recreate has an inverse now: {stuck:?}");

        let undo = applied.undo();
        assert!(
            undo.steps.iter().any(|s| matches!(s, Step::RestoreLink(_))),
            "{undo}"
        );
        let undone = undo.apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        let after = kernel_state(&ns).map_err(nlink::Error::invalid_message)?;
        assert!(before == after, "the undo left:\n{}", state_diff(&before, &after));
        assert!(cfg(100)?.diff(&conn).await?.is_empty());
        Ok(())
    })
    .await
}

/// A removed bridge comes back as it was (#745): its options, MTU and
/// address; the VLAN on it the kernel deleted with it, and that VLAN's
/// route; its ports, back in it with their port options and VLANs; and
/// the static FDB entry in its database.
#[tokio::test]
async fn the_undo_puts_a_removed_bridge_back() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "bridge", "8021q");

    with_timeout(async {
        let ns = TestNamespace::new("undo-remove")?;
        let conn = Connection::<Route>::new_in(ns.name())?;
        let ports = |c: NetworkConfig| c.link("p1", |l| l.dummy().up()).link("p2", |l| l.dummy().up());
        let a = Arc::new(
            ports(NetworkConfig::new())
                .link("br1", |l| {
                    l.bridge()
                        .bridge_options(|b| b.vlan_filtering(true).stp(false).priority(4096))
                        .mtu(1450)
                        .up()
                })
                .link("p1", |l| {
                    l.dummy()
                        .master("br1")
                        .up()
                        .port_options(|p| p.learning(false).pvid(10).vlan(20))
                })
                .link("p2", |l| l.dummy().master("br1").up())
                .address("br1", "10.75.0.1/24")?
                .link("br1.10", |l| l.vlan("br1", 10).up())
                .address("br1.10", "10.76.0.1/24")?
                .route("10.77.0.0/16", |r| r.via("10.76.0.2"))?,
        );
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        run(&ns, "bridge", &["fdb", "add", "02:00:00:00:00:bb", "dev", "p1", "master", "static", "vlan", "10"])?;
        let before = kernel_state(&ns).map_err(nlink::Error::invalid_message)?;

        let b = ports(NetworkConfig::new());
        let applied = b
            .apply_with_options(
                &conn,
                ApplyOptions::default()
                    .with_previous(a.clone())
                    .with_recreate_policy(RecreatePolicy::Allow),
            )
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        assert!(ip_json(&ns, &["link", "show", "br1"]).is_err(), "br1 was removed");
        let stuck: Vec<String> = applied.irreversible().map(|s| s.to_string()).collect();
        assert!(stuck.is_empty(), "a removal has an inverse now: {stuck:?}");

        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        let after = kernel_state(&ns).map_err(nlink::Error::invalid_message)?;
        assert!(before == after, "the undo left:\n{}", state_diff(&before, &after));
        assert!(a.diff(&conn).await?.is_empty());
        Ok(())
    })
    .await
}

/// A removed VRF comes back with its port (#745), and the port gets back
/// what leaving the VRF flushed: its IPv6 address, and the route in the
/// VRF's table through it.
#[tokio::test]
async fn the_undo_puts_back_what_a_vrf_port_lost() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "vrf");

    with_timeout(async {
        let ns = TestNamespace::new("undo-vrf")?;
        let conn = Connection::<Route>::new_in(ns.name())?;
        let a = Arc::new(
            NetworkConfig::new()
                .link("vrf1", |l| l.vrf(100).up())
                .link("q1", |l| l.dummy().master("vrf1").up())
                .address("q1", "10.78.0.1/24")?
                .route("10.79.0.0/16", |r| r.via("10.78.0.2").table(100))?,
        );
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        run(&ns, "ip", &["addr", "add", "fd78::1/64", "dev", "q1", "nodad"])?;
        run(&ns, "ip", &["-6", "route", "add", "fd79::/64", "via", "fd78::2", "table", "100", "proto", "static"])?;
        let before = kernel_state(&ns).map_err(nlink::Error::invalid_message)?;

        let b = NetworkConfig::new().link("q1", |l| l.dummy().up()).address("q1", "10.78.0.1/24")?;
        let applied = b
            .apply_with_options(
                &conn,
                ApplyOptions::default()
                    .with_previous(a.clone())
                    .with_recreate_policy(RecreatePolicy::Allow),
            )
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        let stuck: Vec<String> = applied.irreversible().map(|s| s.to_string()).collect();
        assert!(stuck.is_empty(), "{stuck:?}");

        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        let after = kernel_state(&ns).map_err(nlink::Error::invalid_message)?;
        assert!(before == after, "the undo left:\n{}", state_diff(&before, &after));
        Ok(())
    })
    .await
}

/// A nexthop with an encap on a recreated link is not put back without it
/// (#783): no declaration has an encap, and the restore read the nexthop
/// back bare, so it said nothing and restored another nexthop.
#[tokio::test]
async fn a_nexthop_with_an_encap_is_not_restored_without_it() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "8021q", "mpls_router", "mpls_iptunnel");

    with_timeout(async {
        let ns = TestNamespace::new("undo-nh-encap")?;
        let conn = Connection::<Route>::new_in(ns.name())?;
        let cfg = |id: u16| {
            NetworkConfig::new()
                .link("u0", |l| l.dummy().up())
                .link("v0", move |l| l.vlan("u0", id).up())
                .address("v0", "10.80.1.1/24")
        };
        let applied = cfg(5)?.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        run(&ns, "ip", &["nexthop", "add", "id", "7", "encap", "mpls", "100", "via", "10.80.1.2", "dev", "v0"])?;

        let diff = cfg(6)?
            .diff_with_options(&conn, nlink::netlink::config::PlanOptions::default().recreate_policy(RecreatePolicy::Allow))
            .await?;
        let recreate = diff.links_to_recreate.iter().find(|r| r.name == "v0").expect("v0 is recreated");
        assert!(recreate.restore.is_none());
        assert!(
            recreate.unrestorable.iter().any(|w| w.contains("nexthop 7, with an encap")),
            "{:?}",
            recreate.unrestorable
        );
        Ok(())
    })
    .await
}

/// What no declaration can put back leaves the recreate without an
/// inverse, and says why (#745): an address with a lifetime, which a
/// daemon added.
#[tokio::test]
async fn what_cannot_be_put_back_stays_irreversible() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "8021q");

    with_timeout(async {
        let ns = TestNamespace::new("undo-stuck")?;
        let conn = Connection::<Route>::new_in(ns.name())?;
        let cfg = |id: u16| NetworkConfig::new().link("u0", |l| l.dummy().up()).link("v0", move |l| l.vlan("u0", id).up());
        let applied = cfg(5).apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        run(&ns, "ip", &["addr", "add", "10.80.0.1/24", "dev", "v0", "valid_lft", "3600", "preferred_lft", "3600"])?;

        let diff = cfg(6)
            .diff_with_options(&conn, nlink::netlink::config::PlanOptions::default().recreate_policy(RecreatePolicy::Allow))
            .await?;
        let recreate = diff.links_to_recreate.iter().find(|r| r.name == "v0").expect("v0 is recreated");
        assert!(recreate.restore.is_none());
        assert!(
            recreate.unrestorable.iter().any(|w| w.contains("10.80.0.1/24") && w.contains("lifetime")),
            "{:?}",
            recreate.unrestorable
        );
        let applied = diff.apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(applied.is_success(), "{applied:?}");
        let stuck: Vec<String> = applied.irreversible().map(|s| s.to_string()).collect();
        assert!(stuck.iter().any(|s| s.contains("v0")), "{stuck:?}");
        Ok(())
    })
    .await
}

/// Every kind a declaration has comes back from a removal as it was
/// (#745), each with a parameter off its default where it has one: the
/// read-back is checked against the kernel's own dump of each kind, not
/// just a synthesized one.
#[tokio::test]
async fn every_kind_comes_back_from_a_removal() -> Result<()> {
    use nlink::netlink::config::{BondMode, IpvlanIsolation, IpvlanMode, MacvlanMode};
    use nlink::netlink::link::{
        AdSelect, ErspanDirection, ErspanVersion, Ip6tnlMode, LacpRate, NetkitMode, NetkitPolicy, VlanProtocol,
        XmitHashPolicy,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};
    nlink::require_root!();
    nlink::require_modules!(
        "dummy", "veth", "bridge", "8021q", "vxlan", "macvlan", "macvtap", "ipvlan", "ip_gre", "ipip", "sit",
        "ip_vti", "ip6_tunnel", "ip6_gre", "ip6_vti", "xfrm_interface", "geneve", "macsec", "bonding", "vrf",
        "ifb", "netkit"
    );

    with_timeout(async {
        let ns = TestNamespace::new("undo-kinds")?;
        let conn = Connection::<Route>::new_in(ns.name())?;
        let v4 = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let v6 = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        // A device takes one kind of upper that receives for it: macvlans,
        // or an ipvlan, or a macsec.
        let lower = || {
            NetworkConfig::new()
                .link("lower", |l| l.dummy().up())
                .link("lower2", |l| l.dummy().up())
                .link("lower3", |l| l.dummy().up())
        };
        let a = Arc::new(
            lower()
                .link("d0", |l| l.dummy().mtu(1400).up())
                .link("ifb0", |l| l.ifb())
                .link("br0", |l| l.bridge().bridge_options(|b| b.stp(true).priority(8192)).up())
                // Removed after its bridge: the undo puts it back first.
                .link("bp0", |l| l.dummy().master("br0").up())
                .link("ve0", |l| l.veth("ve1").up())
                .link("vl0", |l| l.vlan("lower", 42).vlan_protocol(VlanProtocol::Dot1ad).up())
                .link("vx0", |l| {
                    l.vxlan(100)
                        .vxlan_remote(v4("10.0.0.2").into())
                        .vxlan_local(v4("10.0.0.1").into())
                        .vxlan_port(4789)
                        .vxlan_underlay_dev("lower")
                })
                .link("mv0", |l| l.macvlan("lower").macvlan_mode(MacvlanMode::Private))
                .link("mt0", |l| l.macvtap("lower").macvtap_mode(MacvlanMode::Vepa))
                .link("iv0", |l| {
                    l.ipvlan("lower2").ipvlan_mode(IpvlanMode::L3).ipvlan_isolation(IpvlanIsolation::Private)
                })
                .link("gr1", |l| {
                    l.gre()
                        .tunnel_local(v4("10.1.0.1"))
                        .tunnel_remote(v4("10.1.0.2"))
                        .tunnel_ttl(64)
                        .tunnel_key(7)
                        .tunnel_underlay_dev("lower")
                })
                .link("gt0", |l| l.gretap().tunnel_remote(v4("10.1.0.3")).tunnel_key(8))
                .link("ipip0", |l| l.ipip().tunnel_local(v4("10.1.0.1")).tunnel_remote(v4("10.1.0.6")).tunnel_ttl(10))
                .link("sit1", |l| l.sit().tunnel_remote(v4("10.1.0.4")))
                .link("vti1", |l| l.vti().tunnel_remote(v4("10.1.0.5")).tunnel_key(9))
                .link("t6", |l| {
                    l.ip6tnl()
                        .ip6tnl_local(v6("fd01::1"))
                        .ip6tnl_remote(v6("fd01::2"))
                        .ip6tnl_hoplimit(32)
                        .ip6tnl_encap_limit(2)
                        .ip6tnl_mode(Ip6tnlMode::Ip6ip6)
                })
                .link("g6", |l| l.ip6gre().ip6tnl_remote(v6("fd01::3")).tunnel_key(11))
                .link("gt6", |l| l.ip6gretap().ip6tnl_local(v6("fd01::4")).ip6tnl_remote(v6("fd01::7")))
                .link("vti6", |l| l.vti6().ip6tnl_remote(v6("fd01::5")).tunnel_key(12))
                .link("es0", |l| {
                    l.erspan(5)
                        .erspan_local(v4("10.2.0.1"))
                        .erspan_remote(v4("10.2.0.2"))
                        .erspan_ttl(20)
                        .erspan_version(ErspanVersion::V2 {
                            direction: ErspanDirection::Egress,
                            hwid: 3,
                        })
                })
                .link("es6", |l| {
                    l.ip6erspan(6)
                        .erspan_remote(v6("fd02::2"))
                        .erspan_version(ErspanVersion::V1 { index: 77 })
                })
                .link("xf0", |l| l.xfrm(9).tunnel_underlay_dev("lower"))
                .link("gn0", |l| {
                    l.geneve(9).geneve_remote(v4("10.3.0.2").into()).geneve_ttl(5).geneve_tos(3)
                })
                .link("ms0", |l| {
                    l.macsec("lower3").macsec_port(7).macsec_encrypt(true).macsec_replay_window(32)
                })
                .link("bo0", |l| {
                    l.bond()
                        .bond_mode(BondMode::Ieee802_3ad)
                        .miimon(100)
                        .xmit_hash_policy(XmitHashPolicy::Layer34)
                        .min_links(1)
                        .bond_ad_select(AdSelect::Bandwidth)
                        .bond_lacp_rate(LacpRate::Fast)
                        .bond_updelay(300)
                })
                .link("bo1", |l| l.bond().bond_mode(BondMode::ActiveBackup))
                .link("vrf0", |l| l.vrf(10).up())
                .link("nk0", |l| {
                    l.netkit("nk1").netkit_mode(NetkitMode::L2).netkit_primary_policy(NetkitPolicy::Blackhole)
                }),
        );
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let before = kernel_state(&ns).map_err(nlink::Error::invalid_message)?;

        let applied = lower()
            .apply_with_options(
                &conn,
                ApplyOptions::default()
                    .with_previous(a.clone())
                    .with_recreate_policy(RecreatePolicy::Allow),
            )
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        let stuck: Vec<String> = applied.irreversible().map(|s| s.to_string()).collect();
        assert!(stuck.is_empty(), "{stuck:?}");
        let left = ip_json(&ns, &["link", "show"]).map_err(nlink::Error::invalid_message)?;
        assert!(
            left.as_array().unwrap().iter().all(|l| l["ifname"] != "gr1" && l["ifname"] != "nk0"),
            "removed: {left}"
        );

        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        let after = kernel_state(&ns).map_err(nlink::Error::invalid_message)?;
        assert!(before == after, "the undo left:\n{}", state_diff(&before, &after));
        assert!(a.diff(&conn).await?.is_empty());
        Ok(())
    })
    .await
}
