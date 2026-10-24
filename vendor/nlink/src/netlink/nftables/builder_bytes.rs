//! What every [`Rule`] builder method sends, recorded (#708).
//!
//! `builder_bytes.txt` holds a line for each case below in each family: a
//! hash of the expressions the rule sends, a hash of the echo the diff
//! compares, and the rule as `nft list` prints it, or the error adding it
//! fails with. It was recorded before the builder was rebuilt on
//! [`RuleSpec`](super::RuleSpec), so a builder method that sends something
//! else, or stops refusing something, fails here.
//! `NLINK_RECORD_BUILDER_BYTES=1` writes the file anew.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use super::expr::{WireForm, write_expressions_as};
use super::*;
use crate::netlink::builder::MessageBuilder;
use crate::netlink::types::route::RouteType;
use crate::{Bytes, TcHandle};

fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

/// Every builder method, most of them more than once.
fn cases() -> Vec<(&'static str, Rule)> {
    let r = || Rule::new("t", "c");
    let c2 = || ChainName::new("c2").unwrap();
    let mut cases: Vec<(&'static str, Rule)> = vec![
        ("empty", r()),
        ("tcp_dport", r().match_tcp_dport(22).accept()),
        ("udp_dport", r().match_udp_dport(53).counter()),
        ("tcp_sport", r().match_tcp_sport(1024).drop()),
        ("udp_sport", r().match_udp_sport(53)),
        ("tcp_dport_not", r().match_tcp_dport_not(22)),
        ("udp_dport_not", r().match_udp_dport_not(53)),
        ("tcp_sport_not", r().match_tcp_sport_not(1)),
        ("udp_sport_not", r().match_udp_sport_not(2)),
        ("saddr_v4_32", r().match_saddr_v4(v4("10.0.0.1"), 32)),
        ("saddr_v4_40", r().match_saddr_v4(v4("10.0.0.1"), 40)),
        ("daddr_v4_16", r().match_daddr_v4(v4("192.168.7.1"), 16)),
        ("saddr_v4_not_8", r().match_saddr_v4_not(v4("10.0.0.0"), 8)),
        (
            "daddr_v4_not_12",
            r().match_daddr_v4_not(v4("10.16.0.0"), 12),
        ),
        (
            "daddr_v4_not_32",
            r().match_daddr_v4_not(v4("10.16.0.3"), 32),
        ),
        ("saddr_v4_0", r().match_saddr_v4(v4("10.0.0.0"), 0)),
        ("saddr_v6_32", r().match_saddr_v6(v6("2001:db8::"), 32)),
        ("daddr_v6_128", r().match_daddr_v6(v6("::1"), 128)),
        ("saddr_v6_not_8", r().match_saddr_v6_not(v6("fd00::"), 8)),
        (
            "daddr_v6_not_128",
            r().match_daddr_v6_not(v6("fd00::1"), 128),
        ),
        (
            "saddr_any_v4",
            r().match_saddr(IpAddr::V4(v4("10.0.0.2")), 32),
        ),
        (
            "saddr_any_v6",
            r().match_saddr(IpAddr::V6(v6("fd00::2")), 64),
        ),
        (
            "saddr_not_any_v6",
            r().match_saddr_not(IpAddr::V6(v6("fd00::2")), 64),
        ),
        (
            "daddr_any_v4",
            r().match_daddr(IpAddr::V4(v4("10.1.0.0")), 16),
        ),
        (
            "daddr_not_any_v4",
            r().match_daddr_not(IpAddr::V4(v4("10.1.0.0")), 16),
        ),
        ("iif", r().match_iif("eth0")),
        ("iif_not", r().match_iif_not("lo")),
        ("iif_prefix", r().match_iif_prefix("veth")),
        ("oif", r().match_oif("eth1")),
        ("oif_not", r().match_oif_not("lo")),
        ("oif_prefix", r().match_oif_prefix("wg")),
        ("iif_15", r().match_iif("abcdefghijklmno")),
        ("iif_too_long", r().match_iif("abcdefghijklmnop")),
        (
            "oif_prefix_too_long",
            r().match_oif_prefix("abcdefghijklmnop"),
        ),
        (
            "ct_state",
            r().match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
                .accept(),
        ),
        ("ct_state_new", r().match_ct_state(CtState::NEW)),
        ("ct_status", r().match_ct_status(CtStatus::DST_NAT)),
        ("ct_direction", r().match_ct_direction(CtDirection::Reply)),
        ("ct_zone", r().match_ct_zone(3)),
        ("set_ct_zone", r().set_ct_zone(4)),
        (
            "ct_addr_v4",
            r().match_ct_addr(CtDirection::Original, true, IpAddr::V4(v4("1.2.3.4"))),
        ),
        (
            "ct_addr_v6",
            r().match_ct_addr(CtDirection::Reply, false, IpAddr::V6(v6("::1"))),
        ),
        (
            "ct_daddr_v4",
            r().match_ct_addr(CtDirection::Reply, false, IpAddr::V4(v4("1.2.3.5"))),
        ),
        (
            "ct_saddr_v6",
            r().match_ct_addr(CtDirection::Original, true, IpAddr::V6(v6("fd00::9"))),
        ),
        (
            "ct_port",
            r().match_l4proto(6)
                .match_ct_port(CtDirection::Reply, false, 80),
        ),
        (
            "ct_sport",
            r().match_ct_port(CtDirection::Original, true, 53),
        ),
        ("ct_label", r().match_ct_label(3)),
        ("ct_label_127", r().match_ct_label(127)),
        ("ct_label_128", r().match_ct_label(128)),
        ("set_ct_label", r().set_ct_label(5)),
        ("set_ct_label_200", r().set_ct_label(200)),
        ("ct_count", r().match_ct_count(5)),
        ("ct_count_over", r().match_ct_count_over(10)),
        ("ct_mark", r().match_ct_mark(5)),
        ("mark", r().match_mark(1)),
        ("mark_not", r().match_mark_not(3)),
        ("mark_masked", r().match_mark_masked(0x1ff, 0xff00)),
        ("pkttype", r().match_pkttype(PktType::Broadcast)),
        ("pkttype_not", r().match_pkttype_not(PktType::Host)),
        ("l4proto", r().match_l4proto(6)),
        ("l4proto_not", r().match_l4proto_not(17)),
        (
            "tcp_flags",
            r().match_tcp_flags(
                TcpFlags::SYN | TcpFlags::FIN,
                TcpFlags::SYN | TcpFlags::ACK | TcpFlags::RST,
            ),
        ),
        ("icmp_type", r().match_icmp_type(8)),
        ("icmpv6_type", r().match_icmpv6_type(128)),
        (
            "range_port",
            r().match_range(PacketField::TcpDport, 1000u16, 2000u16),
        ),
        (
            "range_not_port",
            r().match_range_not(PacketField::UdpSport, 1u16, 1023u16),
        ),
        (
            "range_mark",
            r().match_range(PacketField::Mark, 0x10u32, 0x20u32),
        ),
        ("range_iif", r().match_range(PacketField::Iif, 1u32, 4u32)),
        (
            "range_l4proto",
            r().match_range(PacketField::L4Proto, 6u8, 17u8),
        ),
        (
            "range_addr",
            r().match_range(
                PacketField::Ip4Saddr,
                IpAddr::V4(v4("10.0.0.1")),
                IpAddr::V4(v4("10.0.0.9")),
            ),
        ),
        (
            "range_addr6",
            r().match_range_not(
                PacketField::Ip6Daddr,
                IpAddr::V6(v6("fd00::1")),
                IpAddr::V6(v6("fd00::9")),
            ),
        ),
        (
            "range_point",
            r().match_range(PacketField::TcpSport, 7u16, 7u16),
        ),
        (
            "range_backwards",
            r().match_range(PacketField::TcpDport, 2000u16, 1000u16),
        ),
        (
            "range_wrong_kind",
            r().match_range(PacketField::TcpDport, IpAddr::V4(v4("10.0.0.1")), 9u16),
        ),
        (
            "range_mixed_family",
            r().match_range(
                PacketField::Ip4Saddr,
                IpAddr::V4(v4("10.0.0.1")),
                IpAddr::V6(v6("::9")),
            ),
        ),
        (
            "range_port_as_u32",
            r().match_range(PacketField::TcpDport, 1u32, 5u32),
        ),
        ("saddr_in_set", r().match_saddr_in_set("s4")),
        ("daddr_in_set", r().match_daddr_in_set("s4")),
        (
            "not_in_set",
            r().match_not_in_set(PacketField::Ip4Saddr, "s4"),
        ),
        ("in_set_port", r().match_in_set(PacketField::TcpDport, "sp")),
        ("in_set_v6", r().match_in_set(PacketField::Ip6Daddr, "s6")),
        ("in_set_mark", r().match_in_set(PacketField::Mark, "sm")),
        ("in_set_iif", r().match_in_set(PacketField::Iif, "si")),
        ("in_set_oif", r().match_in_set(PacketField::Oif, "si")),
        (
            "in_set_l4proto",
            r().match_in_set(PacketField::L4Proto, "sl"),
        ),
        (
            "in_interval_set_mark",
            r().match_in_interval_set(PacketField::Mark, "sm"),
        ),
        (
            "not_in_interval_set_mark",
            r().match_not_in_interval_set(PacketField::Mark, "sm"),
        ),
        (
            "in_interval_set_addr",
            r().match_in_interval_set(PacketField::Ip4Saddr, "sr"),
        ),
        (
            "not_in_interval_set_port",
            r().match_not_in_interval_set(PacketField::UdpDport, "sr"),
        ),
        (
            "concat_in_set",
            r().match_concat_in_set(&[PacketField::Ip4Saddr, PacketField::TcpDport], "sc"),
        ),
        (
            "concat_not_in_set",
            r().match_concat_not_in_set(&[PacketField::Ip4Saddr, PacketField::TcpDport], "sc"),
        ),
        (
            "concat_v6_mark",
            r().match_concat_in_set(
                &[
                    PacketField::Ip6Saddr,
                    PacketField::Mark,
                    PacketField::UdpDport,
                ],
                "sc6",
            ),
        ),
        (
            "concat_two_tcp",
            r().match_concat_in_set(&[PacketField::TcpSport, PacketField::TcpDport], "sc"),
        ),
        (
            "concat_too_long",
            r().match_concat_in_set(
                &[
                    PacketField::Ip6Saddr,
                    PacketField::Ip6Daddr,
                    PacketField::Ip6Saddr,
                    PacketField::Ip6Daddr,
                    PacketField::Mark,
                ],
                "sc",
            ),
        ),
        ("vmap", r().vmap(PacketField::TcpDport, "vm")),
        (
            "vmap_concat",
            r().vmap_concat(&[PacketField::Ip4Saddr, PacketField::TcpDport], "vmc"),
        ),
        ("vmap_v6", r().vmap(PacketField::Ip6Saddr, "vm6")),
        (
            "mark_from_map",
            r().set_mark_from_map(PacketField::Ip4Saddr, "mm"),
        ),
        (
            "priority_from_map",
            r().set_priority_from_map(PacketField::UdpDport, "pm"),
        ),
        ("objref_counter", r().objref(ObjectType::Counter, "c0")),
        ("objref_quota", r().objref(ObjectType::Quota, "q0")),
        ("counter_named", r().counter_named("c1")),
        ("quota_named", r().quota_named("q1")),
        ("limit_named", r().limit_named("l1")),
        ("set_secmark", r().set_secmark("sec")),
        ("set_ct_helper", r().set_ct_helper("ftp")),
        (
            "objref_from_map",
            r().objref_from_map(PacketField::Ip4Saddr, "om"),
        ),
        (
            "objref_from_map_v6",
            r().objref_from_map(PacketField::Ip6Daddr, "om6"),
        ),
        ("quota_until", r().quota_until(100 * 1024 * 1024)),
        ("quota_over", r().quota_over(1000)),
        ("limit", r().limit(10, LimitUnit::Minute)),
        (
            "limit_bytes",
            r().limit_bytes(Bytes::kib(1), LimitUnit::Second),
        ),
        ("log", r().log(None)),
        ("log_prefix", r().log(Some("p: "))),
        (
            "log_expr",
            r().expr(LogExpr::new().group(2).snaplen(64).level(LogLevel::Debug)),
        ),
        (
            "fib_missing",
            r().match_fib_missing(FibFlags::SADDR | FibFlags::IIF),
        ),
        (
            "fib_missing_daddr",
            r().match_fib_missing(FibFlags::DADDR | FibFlags::OIF | FibFlags::MARK),
        ),
        (
            "fib_type",
            r().match_fib_type(FibFlags::DADDR, RouteType::Local),
        ),
        (
            "fib_type_saddr",
            r().match_fib_type(FibFlags::SADDR | FibFlags::IIF, RouteType::Unicast),
        ),
        ("notrack", r().notrack()),
        ("flow_offload", r().flow_offload("ft")),
        ("set_priority", r().set_priority(TcHandle::new(1, 0x10))),
        ("save_mark_to_ct", r().save_mark_to_ct()),
        ("restore_mark_from_ct", r().restore_mark_from_ct()),
        ("set_ct_mark", r().set_ct_mark(7)),
        ("set_mark", r().set_mark(2)),
        ("set_mark_masked", r().set_mark_masked(0x1ff, 0xff00)),
        ("clamp_tcp_mss", r().clamp_tcp_mss(1400)),
        ("clamp_tcp_mss_to_pmtu", r().clamp_tcp_mss_to_pmtu()),
        (
            "numgen_mark",
            r().generate(Generated::Numgen {
                kind: NumgenKind::Incremental,
                modulus: 2,
                offset: 0,
            })
            .set_meta_from(MetaKey::Mark),
        ),
        (
            "numgen_random",
            r().generate(Generated::Numgen {
                kind: NumgenKind::Random,
                modulus: 10,
                offset: 3,
            })
            .set_ct_from(CtKey::Mark),
        ),
        (
            "jhash_mark",
            r().generate(Generated::Jhash {
                fields: vec![PacketField::Ip4Saddr, PacketField::TcpDport],
                modulus: 4,
                seed: Some(1),
                offset: 0,
            })
            .set_meta_from(MetaKey::Mark),
        ),
        (
            "jhash_v6",
            r().generate(Generated::Jhash {
                fields: vec![PacketField::Ip6Saddr],
                modulus: 3,
                seed: None,
                offset: 7,
            })
            .set_meta_from(MetaKey::Priority),
        ),
        (
            "symhash_ct",
            r().generate(Generated::Symhash {
                modulus: 2,
                offset: 100,
            })
            .set_ct_from(CtKey::Mark),
        ),
        (
            "socket_transparent",
            r().match_socket(SocketMatch::Transparent(true)),
        ),
        (
            "socket_wildcard",
            r().match_socket(SocketMatch::Wildcard(false)),
        ),
        ("socket_mark", r().match_socket(SocketMatch::Mark(7))),
        ("osf", r().match_osf("Linux", OsfTtl::Loose, false)),
        ("osf_version", r().match_osf("Linux", OsfTtl::Skip, true)),
        ("osf_exact", r().match_osf("Windows", OsfTtl::Exact, false)),
        (
            "osf_too_long",
            r().match_osf("abcdefghijklmnop", OsfTtl::Exact, false),
        ),
        ("reject", r().reject()),
        ("reject_tcp_reset", r().reject_tcp_reset()),
        (
            "reject_tcp_reset_after_tcp",
            r().match_tcp_dport(22).reject_tcp_reset(),
        ),
        (
            "reject_tcp_reset_after_udp",
            r().match_udp_dport(22).reject_tcp_reset(),
        ),
        ("reject_icmpx", r().reject_icmpx(IcmpxCode::AdminProhibited)),
        (
            "reject_icmpx_no_route",
            r().reject_icmpx(IcmpxCode::NoRoute),
        ),
        ("reject_icmp", r().reject_icmp(1)),
        ("reject_icmpv6", r().reject_icmpv6(3)),
        (
            "reject_with_icmp",
            r().reject_with(NFT_REJECT_ICMP_UNREACH, 3),
        ),
        ("reject_with_rst", r().reject_with(NFT_REJECT_TCP_RST, 0)),
        (
            "reject_with_icmpx_9",
            r().reject_with(NFT_REJECT_ICMPX_UNREACH, 9),
        ),
        (
            "add_to_set",
            r().add_to_set(PacketField::Ip4Saddr, "s4", None),
        ),
        (
            "update_in_set",
            r().update_in_set(PacketField::Ip4Saddr, "s4", Some(Duration::from_secs(30))),
        ),
        (
            "add_to_set_port",
            r().add_to_set(
                PacketField::TcpDport,
                "sp",
                Some(Duration::from_millis(1500)),
            ),
        ),
        (
            "delete_from_set",
            r().delete_from_set(PacketField::Ip4Saddr, "s4"),
        ),
        (
            "dynset_counter",
            r().dynset(
                PacketField::Ip4Saddr,
                DynsetExpr::new(DynsetOp::Update, "s4", Register::R0).counter(),
            ),
        ),
        (
            "dynset_limit",
            r().dynset(
                PacketField::Ip6Saddr,
                DynsetExpr::new(DynsetOp::Update, "s6", Register::R3)
                    .statement(LimitExpr::packets(10, LimitUnit::Second).over()),
            )
            .drop(),
        ),
        ("header_ip_dscp", r().set_header(HeaderWrite::IpDscp(8))),
        ("header_ip_dscp_63", r().set_header(HeaderWrite::IpDscp(63))),
        ("header_ip_dscp_64", r().set_header(HeaderWrite::IpDscp(64))),
        ("header_ip_ttl", r().set_header(HeaderWrite::IpTtl(64))),
        (
            "header_ip_saddr",
            r().set_header(HeaderWrite::IpSaddr(v4("10.0.0.9"))),
        ),
        (
            "header_ip_daddr",
            r().set_header(HeaderWrite::IpDaddr(v4("10.0.0.8"))),
        ),
        ("header_ip6_dscp", r().set_header(HeaderWrite::Ip6Dscp(18))),
        (
            "header_ip6_dscp_99",
            r().set_header(HeaderWrite::Ip6Dscp(99)),
        ),
        (
            "header_ip6_hoplimit",
            r().set_header(HeaderWrite::Ip6HopLimit(9)),
        ),
        (
            "header_ip6_saddr",
            r().set_header(HeaderWrite::Ip6Saddr(v6("2001:db8::2"))),
        ),
        (
            "header_ip6_daddr",
            r().set_header(HeaderWrite::Ip6Daddr(v6("2001:db8::1"))),
        ),
        ("header_tcp_sport", r().set_header(HeaderWrite::TcpSport(1))),
        (
            "header_tcp_dport",
            r().set_header(HeaderWrite::TcpDport(8080)),
        ),
        (
            "header_udp_sport",
            r().set_header(HeaderWrite::UdpSport(53)),
        ),
        (
            "header_udp_dport",
            r().set_header(HeaderWrite::UdpDport(54)),
        ),
        ("jump", r().jump(c2())),
        ("goto", r().goto(c2())),
        ("try_jump", r().try_jump("c3").unwrap()),
        ("try_goto", r().try_goto("c3").unwrap()),
        ("verdict_return", r().expr(Expr::Verdict(Verdict::Return))),
        (
            "comment",
            r().match_tcp_dport(22).counter().accept().comment("ssh"),
        ),
        ("comment_only", r().comment("nothing else")),
        ("snat", r().snat(v4("1.2.3.4"), None)),
        ("snat_port", r().snat(v4("1.2.3.4"), Some(80))),
        ("dnat_port", r().dnat(v4("10.0.0.1"), Some(8080))),
        ("dnat", r().dnat(v4("10.0.0.1"), None)),
        ("snat_v6", r().snat_v6(v6("2001:db8::1"), None)),
        ("snat_v6_port", r().snat_v6(v6("2001:db8::1"), Some(9))),
        ("dnat_v6_port", r().dnat_v6(v6("2001:db8::1"), Some(80))),
        ("dnat_v6", r().dnat_v6(v6("2001:db8::1"), None)),
        ("masquerade", r().masquerade()),
        (
            "nat_snat_range",
            r().nat(
                NatStatement::snat(v4("10.0.0.1"))
                    .to(v4("10.0.0.5"))
                    .ports(1000, 2000)
                    .random(),
            ),
        ),
        (
            "nat_masq_ports",
            r().nat(NatStatement::masquerade().ports(1000, 2000).persistent()),
        ),
        (
            "nat_dnat_v6_port",
            r().nat(NatStatement::dnat(v6("fd00::1")).port(80).fully_random()),
        ),
        ("nat_redirect", r().nat(NatStatement::redirect().port(53))),
        (
            "nat_snat_to_port",
            r().nat(NatStatement::snat_to_port(Family::Ip, 9)),
        ),
        (
            "nat_dnat_netmap",
            r().nat(
                NatStatement::dnat(v4("10.1.0.0"))
                    .to(v4("10.1.255.255"))
                    .netmap(),
            ),
        ),
        (
            "nat_mixed_family",
            r().nat(NatStatement::snat(v4("10.0.0.1")).to(v6("fd00::1"))),
        ),
        ("redirect_port", r().redirect(Some(8080))),
        ("redirect", r().redirect(None)),
        (
            "tproxy_ip",
            r().match_tcp_dport(80)
                .tproxy(Family::Ip, Some(IpAddr::V4(v4("1.2.3.4"))), Some(80)),
        ),
        ("tproxy_inet_port", r().tproxy(Family::Inet, None, Some(80))),
        (
            "tproxy_inet_v6",
            r().tproxy(Family::Inet, Some(IpAddr::V6(v6("::1"))), None),
        ),
        (
            "tproxy_ip6",
            r().tproxy(Family::Ip6, Some(IpAddr::V6(v6("::1"))), Some(1)),
        ),
        (
            "tproxy_wrong_family",
            r().tproxy(Family::Ip6, Some(IpAddr::V4(v4("1.2.3.4"))), None),
        ),
        ("tproxy_bridge", r().tproxy(Family::Bridge, None, Some(80))),
        (
            "dup_to_v4_dev",
            r().dup_to(IpAddr::V4(v4("10.0.0.2")), Some(2)),
        ),
        ("dup_to_v6", r().dup_to(IpAddr::V6(v6("fd00::2")), None)),
        ("dup_to_device", r().dup_to_device(3)),
        ("fwd_to", r().fwd_to(3)),
        ("fwd_ip_to_v4", r().fwd_ip_to(IpAddr::V4(v4("10.0.0.3")), 4)),
        ("fwd_ip_to_v6", r().fwd_ip_to(IpAddr::V6(v6("fd00::3")), 4)),
        (
            "queue",
            r().expr(QueueExpr::range(3, 4).flags(QueueFlags::FANOUT))
                .match_tcp_dport(1),
        ),
        ("expr_counter", r().match_tcp_dport(1).expr(Expr::Counter)),
        (
            "expressions_replace",
            r().match_tcp_dport(1)
                .expressions(vec![Expr::Counter, Expr::Verdict(Verdict::Accept)]),
        ),
        (
            "expressions_then_more",
            r().expressions(vec![Expr::Counter]).match_udp_dport(2),
        ),
        (
            "guards_repeat",
            r().match_tcp_dport(22)
                .match_tcp_sport(1)
                .clamp_tcp_mss(1400)
                .reject_tcp_reset(),
        ),
        (
            "guards_l4proto_then_port",
            r().match_l4proto(6).match_tcp_dport(22),
        ),
        (
            "guards_v4_and_v6",
            r().match_saddr_v4(v4("10.0.0.1"), 32)
                .match_daddr_v6(v6("::1"), 128)
                .match_icmp_type(8),
        ),
        (
            "guards_icmp_after_v4",
            r().match_daddr_v4(v4("10.0.0.1"), 24).match_icmp_type(0),
        ),
        (
            "guards_set_then_port",
            r().match_saddr_in_set("s4").match_udp_dport(53).accept(),
        ),
        (
            "two_errors",
            r().match_iif("abcdefghijklmnopq").set_ct_label(255),
        ),
        (
            "full",
            r().match_iif("eth0")
                .match_ct_state(CtState::NEW)
                .match_saddr_v4(v4("10.0.0.0"), 8)
                .match_tcp_dport(443)
                .limit(5, LimitUnit::Second)
                .counter()
                .log(Some("new: "))
                .set_mark_masked(1, 0xff)
                .accept()
                .comment("https"),
        ),
    ];
    // The few that differ by the table's family alone.
    cases.push((
        "tproxy_inet_v4",
        r().tproxy(Family::Inet, Some(IpAddr::V4(v4("1.2.3.4"))), None),
    ));
    cases
}

/// The families each case is lowered for: inet, the two that drop or
/// rewrite guards and rejects, and one of the two that write `meta
/// protocol` for `meta nfproto`.
const FAMILIES: [Family; 4] = [Family::Inet, Family::Ip, Family::Ip6, Family::Bridge];

/// FNV-1a, 64 bits: stable, unlike `DefaultHasher`.
fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// What `rule` sends in its family's table, or why it is refused.
fn lowered(rule: &Rule) -> std::result::Result<Vec<Expr>, String> {
    rule.lowered().map_err(|e| e.to_string())
}

fn encoded(exprs: &[Expr], form: WireForm) -> Vec<u8> {
    let mut b = MessageBuilder::new(0, 0);
    write_expressions_as(&mut b, exprs, form);
    b.as_bytes()[20..].to_vec()
}

fn record() -> String {
    let mut out = String::new();
    for (name, rule) in cases() {
        for family in FAMILIES {
            let rule = rule.clone().family(family);
            let line = match lowered(&rule) {
                Ok(exprs) => format!(
                    "{:016x} {:016x} {}",
                    fnv(&encoded(&exprs, WireForm::Request)),
                    fnv(&encoded(&exprs, WireForm::Echo)),
                    rule.nft_syntax().unwrap_or_else(|| "-".into()),
                ),
                Err(e) => format!("error: {e}"),
            };
            out.push_str(&format!("{name} {family}: {line}\n"));
        }
    }
    out
}

#[test]
#[cfg(target_endian = "little")]
fn every_builder_method_sends_what_it_sent() {
    const PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/netlink/nftables/builder_bytes.txt"
    );
    let now = record();
    if std::env::var_os("NLINK_RECORD_BUILDER_BYTES").is_some() {
        std::fs::write(PATH, &now).unwrap();
        return;
    }
    let then = std::fs::read_to_string(PATH).unwrap();
    let changed: Vec<String> = then
        .lines()
        .zip(now.lines())
        .filter(|(a, b)| a != b)
        .map(|(a, b)| format!("  was {a}\n  now {b}"))
        .collect();
    assert!(
        changed.is_empty() && then.lines().count() == now.lines().count(),
        "{} lines changed:\n{}",
        changed.len(),
        changed.join("\n")
    );
}

/// Every builder rule lifts back to typed items that lower to what it sent
/// (#708). A rule built without raw expressions lifts with none, and lifting
/// what a lift lowers to gives the same items.
#[test]
fn every_builder_rule_lifts_to_what_it_sent() {
    use super::spec::Item;
    let mut wrong = Vec::new();
    for (name, rule) in cases() {
        let raw_in = rule
            .spec()
            .items()
            .iter()
            .any(|i| matches!(i, Item::Expr(_)));
        for family in FAMILIES {
            let rule = rule.clone().family(family);
            let Ok(exprs) = rule.lowered() else { continue };
            let bytes = super::config::expression_bytes(&exprs);
            let decoded = super::expr::parse_expressions(&bytes);
            let items = super::spec_lift::lift(&decoded, Some(&bytes), family);
            let spec: RuleSpec = items.iter().cloned().collect();
            let again = spec
                .lower(family)
                .map(|e| super::config::expression_bytes(&e));
            let same = again.as_ref().is_ok_and(|again| {
                super::config::canonical_body(again, family)
                    == super::config::canonical_body(&bytes, family)
            });
            if !same {
                wrong.push(format!("{name} {family}: does not lower back: {items:?}"));
                continue;
            }
            if !raw_in && items.iter().any(|i| matches!(i, Item::Expr(_))) {
                wrong.push(format!("{name} {family}: raw items: {items:?}"));
            }
            let again = again.unwrap();
            let relifted = super::spec_lift::lift(
                &super::expr::parse_expressions(&again),
                Some(&again),
                family,
            );
            if relifted != items {
                wrong.push(format!(
                    "{name} {family}: lifts again to\n    {relifted:?}\n  not {items:?}"
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} lifts are wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// A rule cut short anywhere, or bytes that are no rule at all, lift
/// without a panic, to items that lower (#708).
#[test]
fn a_broken_rule_lifts_without_a_panic() {
    let lift = |bytes: &[u8], family| {
        let decoded = super::expr::parse_expressions(bytes);
        let items = super::spec_lift::lift(&decoded, Some(bytes), family);
        let _ = items.into_iter().collect::<RuleSpec>().lower(family);
    };
    for (_, rule) in cases() {
        for family in FAMILIES {
            let Ok(exprs) = rule.clone().family(family).lowered() else { continue };
            let bytes = super::config::expression_bytes(&exprs);
            for cut in (0..bytes.len()).step_by(4) {
                lift(&bytes[..cut], family);
            }
        }
    }
    // A rule too long to type is read back as it is, and a concatenation of
    // many ports does not try every choice of protocol.
    let long: Vec<Expr> = vec![Expr::Counter; 300];
    let bytes = super::config::expression_bytes(&long);
    let items = super::spec_lift::lift(
        &super::expr::parse_expressions(&bytes),
        Some(&bytes),
        Family::Inet,
    );
    assert_eq!(items.len(), 300);
    let ports = vec![PacketField::TcpDport; 16];
    let rule = Rule::new("t", "c").match_concat_in_set(&ports, "s");
    let bytes = super::config::expression_bytes(&rule.lowered().unwrap());
    // At most 64 choices of fields are tried, whatever the loads.
    let items = super::spec_lift::lift(&super::expr::parse_expressions(&bytes), Some(&bytes), Family::Inet);
    assert!(!items.is_empty());
    // xorshift64: the same garbage on every run.
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..4000 {
        let len = (next() % 160) as usize;
        let mut bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        // Mostly well-framed elements, so the decoders are reached.
        if len >= 8 && next() % 2 == 0 {
            let n = (len as u16).to_ne_bytes();
            bytes[..4].copy_from_slice(&[n[0], n[1], 1, 0x80]);
        }
        lift(&bytes, FAMILIES[(next() % 4) as usize]);
    }
}
