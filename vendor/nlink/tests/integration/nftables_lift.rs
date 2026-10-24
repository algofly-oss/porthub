//! #708: a rule read back as `nft list` prints it.
//!
//! nft is the oracle. It installs a corpus of rules in each family's table,
//! and `RuleInfo::nft_syntax` must print every one as `nft list chain`
//! does. Then nlink installs a rule from each builder method, and
//! `Rule::nft_syntax` before installing, `RuleInfo::nft_syntax` after, and
//! nft's listing must all agree. Every disagreement is collected, so one run
//! shows them all.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use nlink::netlink::Nftables;
use nlink::netlink::nftables::config::{NftChange, NftablesConfig};
use nlink::netlink::nftables::types::{
    BaseChain, ChainName, CtDirection, CtState, CtStatus, Family, FibFlags, FilterHook, Generated,
    HeaderWrite, IcmpxCode, LimitUnit, NatStatement, PacketField, PktType, Priority, Rule,
    SocketMatch, TcpFlags,
};
use nlink::netlink::nftables::{
    DynsetExpr, DynsetOp, LogExpr, LogLevel, NumgenKind, OsfTtl, Register,
};
use nlink::netlink::types::route::RouteType;
use nlink::{Bytes, TcHandle};

use crate::common::{TestNamespace, nft};

/// The rule lines of `nft list chain <family> <table> <chain>`.
fn listed(
    ns: &TestNamespace,
    family: Family,
    table: &str,
    chain: &str,
) -> nlink::Result<Vec<String>> {
    let out = ns.exec("nft", &["list", "chain", family.name(), table, chain])?;
    Ok(out
        .lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with("table ")
                && !l.starts_with("chain ")
                && !l.starts_with("type ")
                && *l != "}"
        })
        .map(as_nft_1_1)
        .collect())
}

/// A line of nft 1.0 (the CI lane's, from Debian bookworm) as nft 1.1
/// prints it, which is how nlink prints it. 1.0 leaves out a packet limit's
/// default burst, names an ICMP code, and writes a masked flag match `tcp
/// flags syn / fin,syn,rst,ack` where 1.1 writes `tcp flags & (fin | syn |
/// rst | ack) == syn`.
fn as_nft_1_1(line: &str) -> String {
    let words: Vec<&str> = line.split(' ').collect();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let word = words[i];
        out.push(word.to_string());
        let packet_rate = word
            .split_once('/')
            .is_some_and(|(n, _)| n.parse::<u64>().is_ok());
        let after_rate = words[..i].ends_with(&["rate"]) || words[..i].ends_with(&["rate", "over"]);
        if after_rate && packet_rate && words.get(i + 1) != Some(&"burst") {
            out.push("burst 5 packets".into());
        }
        if words[..i].ends_with(&["icmp", "code"]) {
            let code = match word {
                "net-unreachable" => Some(0),
                "host-unreachable" => Some(1),
                "prot-unreachable" => Some(2),
                "port-unreachable" => Some(3),
                "frag-needed" => Some(4),
                "net-prohibited" => Some(9),
                "host-prohibited" => Some(10),
                "admin-prohibited" => Some(13),
                _ => None,
            };
            if let Some(code) = code {
                *out.last_mut().unwrap() = code.to_string();
            }
        }
        if word == "flags" && i >= 1 && words[i - 1] == "tcp" && words.get(i + 2) == Some(&"/") {
            let (Some(value), Some(mask)) = (words.get(i + 1), words.get(i + 3)) else {
                break;
            };
            let mask: Vec<&str> = mask.split(',').collect();
            let mask = match mask.as_slice() {
                [one] => one.to_string(),
                several => format!("({})", several.join(" | ")),
            };
            out.push(format!(
                "& {mask} == {}",
                value.split(',').collect::<Vec<_>>().join(" | ")
            ));
            i += 4;
            continue;
        }
        i += 1;
    }
    out.join(" ")
}

fn install(ns: &TestNamespace, name: &str, script: &str) -> nlink::Result<()> {
    let file = std::env::temp_dir().join(format!("nlink-lift-{name}-{}.nft", std::process::id()));
    std::fs::write(&file, script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed.map(drop)
}

/// Each chain's rules as nlink prints them, beside nft's listing; the lines
/// that differ.
async fn disagreements(
    ns: &TestNamespace,
    family: Family,
    table: &str,
    skip: &[&str],
) -> nlink::Result<Vec<String>> {
    let nft = ns.connection_for::<Nftables>()?;
    let rules = nft.list_rules(table, family).await?;
    let mut chains: Vec<&str> = rules.iter().map(|r| r.chain.as_str()).collect();
    chains.dedup();
    chains.retain(|c| !skip.contains(c));
    let mut wrong = Vec::new();
    for chain in chains {
        let ours: Vec<_> = rules.iter().filter(|r| r.chain == chain).collect();
        let theirs = listed(ns, family, table, chain)?;
        assert_eq!(
            ours.len(),
            theirs.len(),
            "{family} {table} {chain}: rule count"
        );
        for (rule, line) in ours.iter().zip(&theirs) {
            match rule.nft_syntax() {
                Some(text) if text == *line => {}
                Some(text) => {
                    wrong.push(format!("{family} {chain}:\n   nft: {line}\n  ours: {text}"))
                }
                None => wrong.push(format!(
                    "{family} {chain}:\n   nft: {line}\n  ours: None {:?}",
                    rule.expressions()
                )),
            }
        }
    }
    Ok(wrong)
}

const INET: &str = r#"
table inet t {
    set s4 { type ipv4_addr; flags dynamic,timeout; }
    set s6 { type ipv6_addr; }
    set sp { type inet_service; }
    set sc { type ipv4_addr . inet_service; }
    set sm { type mark; flags interval; }
    map vm { type inet_service : verdict; }
    map vmc { type ipv4_addr . inet_service : verdict; }
    map mm { type ipv4_addr : mark; }
    map cm { type ipv4_addr : counter; }
    counter c1 { }
    quota q1 { over 10 mbytes }
    limit l1 { rate 10/second }
    ct helper h1 { type "ftp" protocol tcp; }
    flowtable ft { hook ingress priority 0; devices = { lo }; }
    chain a2 { }
    chain a {
        ct state new
        ct state established,related accept
        ct state invalid drop
        ct state != established
        ct status dnat
        ct direction reply
        ct zone 3
        ct original zone 3
        ct mark 0x5
        ct mark != 0x5
        ct original ip saddr 1.2.3.4
        ct reply ip6 daddr ::1
        meta l4proto tcp ct reply proto-dst 80
        meta l4proto udp ct original proto-src 1000-2000
        ct label 3
        ct count over 10
        ct count 5
        ct packets > 10
        ct helper "ftp"
        meta pkttype broadcast
        meta pkttype != host
        meta l4proto tcp
        meta l4proto != udp
        meta l4proto ipv6-icmp
        meta nfproto ipv6
        meta mark 0x1
        meta mark != 0x3
        meta mark & 0xff00 == 0x100
        meta mark 0x10-0x20
        meta length > 1000
        meta cpu 1
        meta priority 1:10
        udp sport 53
        tcp sport != 1024
        udp dport != 53
        tcp dport 22 accept
        tcp dport 1000-2000
        tcp dport != 1000-2000
        tcp dport < 1024
        tcp flags syn
        tcp flags == syn
        tcp flags & (fin | syn | rst | ack) == syn
        tcp flags & (syn | ack) == syn | ack
        udp length > 100
        sctp dport 5000
        ip daddr 192.168.0.0/16
        ip saddr != 10.0.0.1
        ip saddr 10.16.0.0/12
        ip saddr != 10.0.0.0/24
        ip saddr 10.0.0.1-10.0.0.9
        ip dscp cs1
        ip ttl 64
        ip ttl != 1
        ip protocol tcp
        ip version 4
        ip length 100-200
        ip6 saddr 2001:db8::/32
        ip6 daddr != ::1
        ip6 dscp af21
        ip6 hoplimit 1
        ip6 nexthdr udp
        icmp type echo-request
        icmp code port-unreachable
        icmpv6 type nd-neighbor-solicit
        iifname "eth0"
        oifname "veth*"
        iifname != "lo"
        ip saddr @s4
        ip saddr != @s4
        ip6 daddr @s6
        tcp dport @sp
        ip saddr . tcp dport @sc
        meta mark @sm
        tcp dport vmap @vm
        ip saddr . tcp dport vmap @vmc
        meta mark set ip saddr map @mm
        counter name "c1"
        quota name "q1"
        limit name "l1"
        add @s4 { ip saddr }
        update @s4 { ip saddr timeout 30s }
        update @s4 { ip saddr timeout 1m30s counter }
        delete @s4 { ip saddr }
        quota 100 mbytes
        quota over 1000 bytes
        limit rate 10/minute burst 5 packets
        limit rate over 1 mbytes/second
        limit rate 1 kbytes/second burst 2 kbytes
        log
        log prefix "p: " group 2
        log level debug flags all
        log flags tcp sequence,options
        log group 3 snaplen 64 queue-threshold 10
        fib daddr type local
        fib daddr . iif type != local
        fib saddr . iif oif missing
        notrack
        flow add @ft
        meta priority set 1:10
        meta priority set none
        meta mark set ct mark
        ct mark set meta mark
        ct mark set 0x7
        ct mark set meta mark & 0x0000ffff
        ct zone set 4
        ct label set 5
        meta mark set meta mark & 0xffff00ff | 0x00000100
        meta nftrace set 1
        tcp option maxseg size set 1400
        tcp option maxseg size set rt mtu
        meta mark set numgen inc mod 2
        meta mark set numgen random mod 4 offset 1
        meta mark set jhash ip saddr mod 4
        meta mark set jhash ip saddr . tcp dport mod 2 seed 0x1
        meta mark set symhash mod 2 offset 100
        socket transparent 1
        socket wildcard 0
        socket mark 0x7
        osf ttl loose name "Linux"
        osf name "Linux"
        ip dscp set cs1
        ip ttl set 64
        ip saddr set 10.0.0.9
        ip6 dscp set af21
        ip6 hoplimit set 9
        ip6 daddr set 2001:db8::1
        tcp dport set 8080
        udp sport set 53
        queue to 3
        queue flags bypass to 1-3
        queue flags bypass,fanout to 2-5
        meta l4proto tcp reject with tcp reset
        reject
        reject with icmpx admin-prohibited
        reject with icmp host-unreachable
        reject with icmpv6 addr-unreachable
        ct helper set "h1"
        goto a2
        jump a2
        continue
        return
        tcp dport 22 counter accept comment "ssh"
    }
    chain in { type filter hook input priority 0;
        synproxy mss 1460 wscale 7 timestamp sack-perm
        synproxy
    }
    chain pre { type filter hook prerouting priority -150;
        meta l4proto tcp tproxy ip to 1.2.3.4:80
        meta l4proto tcp tproxy to :80
        meta l4proto udp tproxy ip6 to [2001:db8::1]:53
    }
    chain n { type nat hook postrouting priority 100;
        masquerade
        meta l4proto tcp masquerade to :1000-2000 random,persistent
        masquerade fully-random
        snat ip to 1.2.3.4
        meta l4proto tcp snat ip to 1.2.3.4:80
        snat ip to 10.0.0.1-10.0.0.5
        snat ip to 10.0.0.0/24
        snat ip prefix to 10.1.0.0/24
        meta l4proto udp snat ip6 to [2001:db8::1]:80
        snat ip6 to 2001:db8::1
    }
    chain p { type nat hook prerouting priority -100;
        redirect
        meta l4proto tcp dnat ip to 10.0.0.1-10.0.0.5:8000-8010
        tcp dport 80 redirect to :8080
    }
    chain unread {
        tcp dport { 22, 80 }
        dnat ip to ip saddr map { 10.0.0.1 : 10.0.0.2 }
        counter name ip saddr map @cm
        meta time < "2030-01-01 00:00:00"
    }
    chain numbers {
        iif "lo"
        tcp option maxseg size 1460
    }
}
"#;

const IP: &str = r#"
table ip t {
    chain a {
        tcp dport 22 accept
        ip saddr 10.0.0.0/8 drop
        ip protocol tcp tcp dport 22
        meta l4proto tcp reject with tcp reset
        reject with tcp reset
        reject
        reject with icmp host-unreachable
        reject with icmp port-unreachable
        icmp type echo-request
        dup to 10.0.0.1
        ct original saddr 10.0.0.1
        fib daddr type local
        rt ip nexthop 10.0.0.1
    }
    chain n { type nat hook postrouting priority 100;
        snat to 1.2.3.4
        meta l4proto tcp snat to 1.2.3.4:80
        masquerade
    }
}
table ip6 t {
    chain a {
        ip6 saddr ::1
        icmpv6 type echo-request
        reject
        reject with icmpv6 port-unreachable
        reject with icmpv6 admin-prohibited
        reject with tcp reset
        ct original saddr ::1
        rt ip6 nexthop ::1
    }
}
table bridge t {
    chain a {
        ether saddr 00:11:22:33:44:55
        ether type ip6
        ether type vlan
        ip saddr 10.0.0.1
        ip6 daddr ::1
        meta protocol ip
        tcp dport 22
        meta ibrname "br0"
    }
}
table netdev t {
    chain a {
        ip saddr 10.0.0.1
        ip6 daddr ::1
        meta protocol ip6
        udp dport 53
    }
}
"#;

#[tokio::test]
async fn nft_syntax_prints_what_nft_lists() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!(
        "nf_tables",
        "nft_ct",
        "nft_nat",
        "nft_masq",
        "nft_redir",
        "nft_log",
        "nft_limit",
        "nft_quota",
        "nft_connlimit",
        "nft_reject_inet",
        "nft_reject_ipv4",
        "nft_reject_ipv6",
        "nft_fib_inet",
        "nft_flow_offload",
        "nft_queue",
        "nft_numgen",
        "nft_hash",
        "nft_socket",
        "nft_osf",
        "nft_tproxy",
        "nft_synproxy",
        "nft_dup_ipv4",
        "nf_conntrack_ftp"
    );

    let ns = TestNamespace::new("nft-lift")?;
    install(&ns, "inet", INET)?;
    install(&ns, "ip", IP)?;
    let mut wrong = Vec::new();
    for family in [
        Family::Inet,
        Family::Ip,
        Family::Ip6,
        Family::Bridge,
        Family::Netdev,
    ] {
        wrong.extend(disagreements(&ns, family, "t", &["unread", "numbers"]).await?);
    }
    assert!(
        wrong.is_empty(),
        "{} rules print unlike nft:\n{}",
        wrong.len(),
        wrong.join("\n")
    );

    let nft = ns.connection_for::<Nftables>()?;
    let rules = nft.list_rules("t", Family::Inet).await?;
    let printed = |chain: &str| -> Vec<Option<String>> {
        rules
            .iter()
            .filter(|r| r.chain == chain)
            .map(|r| r.nft_syntax())
            .collect()
    };
    // What the rule does not hold: an anonymous set's elements, an object
    // map's type, a meta key nlink does not print.
    assert_eq!(printed("unread"), [None, None, None, None]);
    // What nft looks up on the host prints as a number; the TCP option match
    // implies its `meta l4proto tcp`, as nft has it.
    assert_eq!(
        printed("numbers"),
        [
            Some("iif 1".to_string()),
            Some("tcp option maxseg size 1460".to_string())
        ]
    );
    Ok(())
}

/// #708: every rule nft installs lifts to a `RuleSpec` that installs as
/// the same rule. nft writes the corpus; each rule is read back, lifted, the
/// table's rules are flushed, and nlink adds each lifted spec again; the
/// kernel must dump every rule as it did. A rule with an anonymous set is
/// left out: its set goes with it. Most rules lift to typed items; the rest
/// keep raw expressions, which lower as they are.
#[tokio::test]
async fn a_lifted_rule_installs_as_itself() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!(
        "nf_tables",
        "nft_ct",
        "nft_nat",
        "nft_masq",
        "nft_redir",
        "nft_log",
        "nft_limit",
        "nft_quota",
        "nft_connlimit",
        "nft_reject_inet",
        "nft_reject_ipv4",
        "nft_reject_ipv6",
        "nft_fib_inet",
        "nft_flow_offload",
        "nft_queue",
        "nft_numgen",
        "nft_hash",
        "nft_socket",
        "nft_osf",
        "nft_tproxy",
        "nft_synproxy",
        "nft_dup_ipv4",
        "nf_conntrack_ftp"
    );
    use nlink::netlink::nftables::{Expr, Item, RuleSpec};

    let ns = TestNamespace::new("nft-lift-spec")?;
    install(&ns, "inet", INET)?;
    install(&ns, "ip", IP)?;
    let nft = ns.connection_for::<Nftables>()?;
    let anonymous = |spec: &RuleSpec| {
        spec.items().iter().any(|i| {
            matches!(i, Item::Expr(Expr::Lookup(l)) if l.set.starts_with("__"))
                || matches!(i, Item::Match(m) if matches!(&m.value, nlink::netlink::nftables::Value::Set(s) if s.starts_with("__")))
        })
    };
    let (mut rules, mut typed) = (0, 0);
    let mut wrong = Vec::new();
    for family in [
        Family::Inet,
        Family::Ip,
        Family::Ip6,
        Family::Bridge,
        Family::Netdev,
    ] {
        let before: Vec<_> = nft
            .list_rules("t", family)
            .await?
            .into_iter()
            .map(|r| (r.chain.clone(), r.spec(), r))
            .filter(|(_, spec, _)| !anonymous(spec))
            .collect();
        ns.exec("nft", &["flush", "table", family.name(), "t"])?;
        for (chain, spec, info) in &before {
            rules += 1;
            if spec.items().iter().all(|i| !matches!(i, Item::Expr(_))) {
                typed += 1;
            } else if std::env::var_os("NLINK_SHOW_RAW").is_some() {
                let raw: Vec<_> = spec
                    .items()
                    .iter()
                    .filter(|i| matches!(i, Item::Expr(_)))
                    .collect();
                eprintln!("RAW {family} {chain}: {:?}\n    {raw:?}", info.nft_syntax());
            }
            let rule = Rule::from_spec("t", chain, spec.clone()).family(family);
            if let Err(e) = nft.add_rule(rule).await {
                wrong.push(format!(
                    "{family} {chain}: {e}
   rule: {:?}
   spec: {spec:?}",
                    info.nft_syntax()
                ));
            }
        }
        let after = nft.list_rules("t", family).await?;
        for chain in before
            .iter()
            .map(|(c, _, _)| c.as_str())
            .collect::<std::collections::BTreeSet<_>>()
        {
            let was: Vec<_> = before
                .iter()
                .filter(|(c, _, _)| c == chain)
                .map(|(_, _, r)| r)
                .collect();
            let now: Vec<_> = after.iter().filter(|r| r.chain == chain).collect();
            for (was, now) in was.iter().zip(&now) {
                if was.expression_bytes != now.expression_bytes {
                    wrong.push(format!(
                        "{family} {chain}: {:?}
    was {:?}
    now {:?}",
                        was.nft_syntax(),
                        was.expressions(),
                        now.expressions()
                    ));
                }
            }
        }
    }
    eprintln!("{typed} of {rules} rules lift to typed items");
    // 161 under nft 1.1.3, 156 under 1.0.6, which writes ranges otherwise.
    // The rest are fields nlink has no `Field` for (`ip ttl`, `meta
    // length`, `ether saddr`) and forms nft writes and nlink does not (a
    // prefix as a shorter load, `ip protocol` as an ip table's
    // dependency). NLINK_SHOW_RAW=1 lists them.
    assert!(
        typed >= 156,
        "only {typed} of {rules} rules lift to typed items"
    );
    assert!(
        wrong.is_empty(),
        "{} lifted rules do not install as they were:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    Ok(())
}

/// One rule from each builder method, per family.
fn nlink_rules() -> Vec<(Family, &'static str, Rule)> {
    let v4 = |s: &str| s.parse::<Ipv4Addr>().unwrap();
    let v6 = |s: &str| s.parse::<Ipv6Addr>().unwrap();
    let a2 = || ChainName::new("a2").unwrap();
    let r = || Rule::new("t", "a");
    let n = || Rule::new("t", "n");
    let p = || Rule::new("t", "p");
    let pre = || Rule::new("t", "pre");
    let mut rules = Vec::new();
    for family in [Family::Inet, Family::Ip] {
        let mut add =
            |chain: &'static str, rule: Rule| rules.push((family, chain, rule.family(family)));
        add("a", r().match_tcp_dport(22).accept());
        add("a", r().match_udp_dport(53).counter());
        add("a", r().match_tcp_sport(1024).drop());
        add("a", r().match_udp_sport(53));
        add("a", r().match_tcp_dport_not(22));
        add("a", r().match_udp_dport_not(53));
        add("a", r().match_tcp_sport_not(1));
        add("a", r().match_udp_sport_not(2));
        add("a", r().match_saddr_v4(v4("10.0.0.1"), 32));
        add("a", r().match_daddr_v4(v4("192.168.0.0"), 16));
        add("a", r().match_saddr_v4_not(v4("10.0.0.0"), 8));
        add("a", r().match_daddr_v4_not(v4("10.16.0.0"), 12));
        add("a", r().match_saddr(IpAddr::V4(v4("10.0.0.2")), 32));
        add("a", r().match_iif("eth0"));
        add("a", r().match_iif_not("lo"));
        add("a", r().match_iif_prefix("veth"));
        add("a", r().match_oif("eth1"));
        add("a", r().match_oif_not("lo"));
        add("a", r().match_oif_prefix("wg"));
        add(
            "a",
            r().match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
                .accept(),
        );
        add("a", r().match_ct_state(CtState::NEW));
        add("a", r().match_ct_status(CtStatus::DST_NAT));
        add("a", r().match_ct_direction(CtDirection::Reply));
        add("a", r().match_ct_zone(3));
        add(
            "a",
            r().match_ct_addr(CtDirection::Original, true, IpAddr::V4(v4("1.2.3.4"))),
        );
        add(
            "a",
            r().match_l4proto(6)
                .match_ct_port(CtDirection::Reply, false, 80),
        );
        add("a", r().match_ct_label(3));
        add("a", r().match_ct_count(5));
        add("a", r().match_ct_count_over(10));
        add("a", r().match_ct_mark(5));
        add("a", r().match_mark(1));
        add("a", r().match_mark_not(3));
        add("a", r().match_mark_masked(0x100, 0xff00));
        add("a", r().match_pkttype(PktType::Broadcast));
        add("a", r().match_pkttype_not(PktType::Host));
        add("a", r().match_l4proto(6));
        add("a", r().match_l4proto_not(17));
        add(
            "a",
            r().match_tcp_flags(
                TcpFlags::SYN,
                TcpFlags::SYN | TcpFlags::ACK | TcpFlags::RST | TcpFlags::FIN,
            ),
        );
        add("a", r().match_icmp_type(8));
        add(
            "a",
            r().match_range(PacketField::TcpDport, 1000u16, 2000u16),
        );
        add(
            "a",
            r().match_range_not(PacketField::UdpSport, 1u16, 1023u16),
        );
        add("a", r().match_range(PacketField::Mark, 0x10u32, 0x20u32));
        add(
            "a",
            r().match_range(
                PacketField::Ip4Saddr,
                IpAddr::V4(v4("10.0.0.1")),
                IpAddr::V4(v4("10.0.0.9")),
            ),
        );
        add("a", r().match_saddr_in_set("s4"));
        add("a", r().match_daddr_in_set("s4"));
        add("a", r().match_not_in_set(PacketField::Ip4Saddr, "s4"));
        add("a", r().match_in_set(PacketField::TcpDport, "sp"));
        add("a", r().match_in_interval_set(PacketField::Mark, "sm"));
        add("a", r().match_not_in_interval_set(PacketField::Mark, "sm"));
        add(
            "a",
            r().match_concat_in_set(&[PacketField::Ip4Saddr, PacketField::TcpDport], "sc"),
        );
        add(
            "a",
            r().match_concat_not_in_set(&[PacketField::Ip4Saddr, PacketField::TcpDport], "sc"),
        );
        add("a", r().vmap(PacketField::TcpDport, "vm"));
        add(
            "a",
            r().vmap_concat(&[PacketField::Ip4Saddr, PacketField::TcpDport], "vmc"),
        );
        add("a", r().set_mark_from_map(PacketField::Ip4Saddr, "mm"));
        add("a", r().counter_named("c1"));
        add("a", r().quota_named("q1"));
        add("a", r().limit_named("l1"));
        add("a", r().quota_until(100 * 1024 * 1024));
        add("a", r().quota_over(1000));
        add("a", r().limit(10, LimitUnit::Minute));
        add("a", r().limit_bytes(Bytes::kib(1), LimitUnit::Second));
        add("a", r().log(None));
        add("a", r().log(Some("p: ")));
        add(
            "a",
            r().expr(LogExpr::new().group(2).snaplen(64).level(LogLevel::Debug)),
        );
        add("a", r().match_fib_missing(FibFlags::SADDR | FibFlags::IIF));
        add("a", r().match_fib_type(FibFlags::DADDR, RouteType::Local));
        add("a", r().notrack());
        add("a", r().flow_offload("ft"));
        add("a", r().set_priority(TcHandle::new(1, 0x10)));
        add("a", r().save_mark_to_ct());
        add("a", r().restore_mark_from_ct());
        add("a", r().set_ct_mark(7));
        add("a", r().set_ct_zone(4));
        add("a", r().set_ct_label(5));
        add("a", r().set_mark(2));
        add("a", r().set_mark_masked(0x100, 0xff00));
        add("a", r().clamp_tcp_mss(1400));
        add("a", r().clamp_tcp_mss_to_pmtu());
        add(
            "a",
            r().generate(Generated::Numgen {
                kind: NumgenKind::Incremental,
                modulus: 2,
                offset: 0,
            })
            .set_meta_from(nlink::netlink::nftables::MetaKey::Mark),
        );
        add(
            "a",
            r().generate(Generated::Jhash {
                fields: vec![PacketField::Ip4Saddr, PacketField::TcpDport],
                modulus: 4,
                seed: Some(1),
                offset: 0,
            })
            .set_meta_from(nlink::netlink::nftables::MetaKey::Mark),
        );
        add(
            "a",
            r().generate(Generated::Symhash {
                modulus: 2,
                offset: 100,
            })
            .set_ct_from(nlink::netlink::nftables::CtKey::Mark),
        );
        add("a", r().match_socket(SocketMatch::Transparent(true)));
        add("a", r().match_socket(SocketMatch::Mark(7)));
        add("a", r().match_osf("Linux", OsfTtl::Loose, false));
        add("a", r().reject_tcp_reset());
        add("a", r().reject());
        add("a", r().reject_icmpx(IcmpxCode::AdminProhibited));
        add("a", r().reject_icmp(1));
        add("a", r().add_to_set(PacketField::Ip4Saddr, "s4", None));
        add(
            "a",
            r().update_in_set(PacketField::Ip4Saddr, "s4", Some(Duration::from_secs(30))),
        );
        add("a", r().delete_from_set(PacketField::Ip4Saddr, "s4"));
        add(
            "a",
            r().dynset(
                PacketField::Ip4Saddr,
                DynsetExpr::new(DynsetOp::Update, "s4", Register::R0).counter(),
            ),
        );
        add("a", r().set_header(HeaderWrite::IpDscp(8)));
        add("a", r().set_header(HeaderWrite::IpTtl(64)));
        add("a", r().set_header(HeaderWrite::IpSaddr(v4("10.0.0.9"))));
        add("a", r().set_header(HeaderWrite::TcpDport(8080)));
        add("a", r().set_header(HeaderWrite::UdpSport(53)));
        add("a", r().jump(a2()));
        add("a", r().goto(a2()));
        add(
            "a",
            r().match_tcp_dport(22).counter().accept().comment("ssh"),
        );
        add("n", n().snat(v4("1.2.3.4"), None));
        add("n", n().snat(v4("1.2.3.4"), Some(80)));
        add("n", n().masquerade());
        add(
            "n",
            n().nat(
                NatStatement::snat(v4("10.0.0.1"))
                    .to(v4("10.0.0.5"))
                    .ports(1000, 2000)
                    .random(),
            ),
        );
        add(
            "n",
            n().nat(NatStatement::masquerade().ports(1000, 2000).persistent()),
        );
        add("p", p().dnat(v4("10.0.0.1"), Some(8080)));
        add("p", p().redirect(Some(8080)));
        add("p", p().redirect(None));
        add(
            "pre",
            pre()
                .match_tcp_dport(80)
                .tproxy(family, Some(IpAddr::V4(v4("1.2.3.4"))), Some(80)),
        );
    }
    for family in [Family::Inet, Family::Ip6] {
        let mut add =
            |chain: &'static str, rule: Rule| rules.push((family, chain, rule.family(family)));
        add("a", r().match_saddr_v6(v6("2001:db8::"), 32));
        add("a", r().match_daddr_v6(v6("::1"), 128));
        add("a", r().match_saddr_v6_not(v6("fd00::"), 8));
        add("a", r().match_daddr_v6_not(v6("fd00::1"), 128));
        add("a", r().match_icmpv6_type(128));
        add(
            "a",
            r().match_ct_addr(CtDirection::Reply, false, IpAddr::V6(v6("::1"))),
        );
        add("a", r().match_in_set(PacketField::Ip6Daddr, "s6"));
        add("a", r().reject_icmpv6(3));
        add("a", r().set_header(HeaderWrite::Ip6Dscp(18)));
        add("a", r().set_header(HeaderWrite::Ip6HopLimit(9)));
        add(
            "a",
            r().set_header(HeaderWrite::Ip6Daddr(v6("2001:db8::1"))),
        );
        add("n", n().snat_v6(v6("2001:db8::1"), None));
        add("p", p().dnat_v6(v6("2001:db8::1"), Some(80)));
    }
    rules
}

fn scaffold(family: Family) -> String {
    let maps = match family {
        Family::Ip6 => "set s6 { type ipv6_addr; }",
        _ => {
            "set s4 { type ipv4_addr; flags dynamic,timeout; }
             set s6 { type ipv6_addr; }
             set sp { type inet_service; }
             set sc { type ipv4_addr . inet_service; }
             set sm { type mark; flags interval; }
             map vm { type inet_service : verdict; }
             map vmc { type ipv4_addr . inet_service : verdict; }
             map mm { type ipv4_addr : mark; }
             counter c1 { }
             quota q1 { over 10 mbytes }
             limit l1 { rate 10/second }
             flowtable ft { hook ingress priority 0; devices = { lo }; }"
        }
    };
    format!(
        "table {family} t {{
            {maps}
            chain a2 {{ }}
            chain a {{ }}
            chain n {{ type nat hook postrouting priority 100; }}
            chain p {{ type nat hook prerouting priority -100; }}
            chain pre {{ type filter hook prerouting priority -150; }}
        }}\n"
    )
}

#[tokio::test]
async fn nft_syntax_of_what_nlink_builds_is_what_nft_lists() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!(
        "nf_tables",
        "nft_ct",
        "nft_nat",
        "nft_masq",
        "nft_redir",
        "nft_log",
        "nft_limit",
        "nft_quota",
        "nft_connlimit",
        "nft_reject_inet",
        "nft_reject_ipv4",
        "nft_reject_ipv6",
        "nft_fib_inet",
        "nft_flow_offload",
        "nft_numgen",
        "nft_hash",
        "nft_socket",
        "nft_osf",
        "nft_tproxy"
    );

    let ns = TestNamespace::new("nft-lift-b")?;
    for family in [Family::Inet, Family::Ip, Family::Ip6] {
        install(&ns, family.name(), &scaffold(family))?;
    }
    let nft = ns.connection_for::<Nftables>()?;
    let rules = nlink_rules();
    let mut before = Vec::new();
    for (family, chain, rule) in &rules {
        before.push((*family, *chain, rule.nft_syntax()));
        nft.add_rule(rule.clone()).await?;
    }
    let mut wrong = Vec::new();
    for family in [Family::Inet, Family::Ip, Family::Ip6] {
        wrong.extend(disagreements(&ns, family, "t", &[]).await?);
        for chain in ["a", "n", "p", "pre"] {
            let theirs = listed(&ns, family, "t", chain)?;
            let ours = before
                .iter()
                .filter(|(f, c, _)| *f == family && *c == chain);
            for ((_, _, text), line) in ours.zip(&theirs) {
                if text.as_deref() != Some(line.as_str()) {
                    wrong.push(format!(
                        "{family} {chain} before installing:\n   nft: {line}\n  ours: {text:?}"
                    ));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} rules print unlike nft:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    Ok(())
}

/// `nft -s -a list chain`'s rules, by handle.
fn listed_stateless(
    ns: &TestNamespace,
    family: Family,
    table: &str,
    chain: &str,
) -> nlink::Result<Vec<(u64, String)>> {
    let out = ns.exec(
        "nft",
        &["-s", "-a", "list", "chain", family.name(), table, chain],
    )?;
    Ok(out
        .lines()
        .filter_map(|l| {
            let (rule, handle) = l.trim().rsplit_once(" # handle ")?;
            let handle = handle.parse().ok()?;
            let is_rule = !rule.starts_with("table ") && !rule.starts_with("chain ");
            is_rule.then(|| (handle, as_nft_1_1(rule)))
        })
        .collect())
}

/// A diff says what it deletes, replaces and moves as `nft -s list` prints
/// it, whatever the rule has counted: a rule nft added with counted packets
/// and a used quota, and rules nlink wrote.
#[tokio::test]
async fn the_diff_shows_what_the_kernel_has_as_nft_lists_it() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-lift-diff")?;
    let nft = ns.connection_for::<Nftables>()?;
    let input = |c: nlink::netlink::nftables::config::DeclaredChainBuilder| {
        c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
            .exclusive()
    };
    let was = NftablesConfig::new().table("f", Family::Inet, |t| {
        t.chain("input", input)
            .rule_keyed("input", "ssh", |r| r.match_tcp_dport(22).counter().accept())
            .rule_keyed("input", "dns", |r| r.match_udp_dport(53).counter().accept())
            .rule_keyed("input", "web", |r| {
                r.match_tcp_dport(80).quota_over(10 << 20).drop()
            })
            .rule_keyed("input", "ntp", |r| r.match_udp_dport(123).accept())
    });
    was.diff(&nft).await?.apply(&nft).await?;
    install(
        &ns,
        "diff",
        "add rule inet f input udp dport 5353 counter packets 5 bytes 300 \
         quota over 10 mbytes used 2 kbytes accept comment \"by hand\"\n",
    )?;

    // dns and the foreign rule go, web and ssh change places, and ntp,
    // in order either way, changes in place.
    let now = NftablesConfig::new().table("f", Family::Inet, |t| {
        t.chain("input", input)
            .rule_keyed("input", "web", |r| {
                r.match_tcp_dport(80).quota_over(10 << 20).drop()
            })
            .rule_keyed("input", "ssh", |r| r.match_tcp_dport(22).counter().accept())
            .rule_keyed("input", "ntp", |r| r.match_udp_dport(1123).accept())
    });
    let diff = now.diff(&nft).await?;
    let listed = listed_stateless(&ns, Family::Inet, "f", "input")?;
    let at = |handle: u64| {
        listed
            .iter()
            .find(|(h, _)| *h == handle)
            .map(|(_, rule)| rule.clone())
    };

    let mut shown: Vec<(u64, Option<String>)> = Vec::new();
    for change in nft::all(&diff) {
        if let NftChange::Rule(c) = change
            && let Some(from) = c.from()
        {
            shown.push((from.handle.unwrap().0, from.nft.clone()));
        }
    }
    assert_eq!(nft::count(&diff, "rule", "remove"), 2, "{diff}");
    assert_eq!(nft::replaced(&diff).len(), 1, "{diff}");
    assert_eq!(nft::moved(&diff).len(), 1, "{diff}");
    let text = diff.to_string();
    for (handle, current) in &shown {
        assert_eq!(*current, at(*handle), "handle {handle}: {diff}");
        let current = current.as_deref().unwrap_or_default();
        assert!(text.contains(current), "the diff shows `{current}`: {diff}");
    }
    assert!(
        text.contains(r#"udp dport 5353 counter quota over 10 mbytes accept comment "by hand""#),
        "{diff}"
    );
    assert!(
        text.contains("key=ntp): udp dport 123 accept -> udp dport 1123 accept"),
        "{diff}"
    );

    diff.apply(&nft).await?;
    let again = now.diff(&nft).await?;
    assert!(again.is_empty(), "{again}");
    Ok(())
}
