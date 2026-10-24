//! Sets of concatenated keys — ipset `hash:ip,port` and `hash:net,port` —
//! checked on traffic: a pair matches, its parts on their own do not.

use std::net::{Ipv4Addr, Ipv6Addr};

use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    BaseChain, Chain, Family, FilterHook, PacketField, Priority, Rule, Set, SetElement, SetKeyType,
};
use nlink::netlink::{Connection, Nftables};

use crate::common::traffic::{lo_up, send_udp};
use crate::common::{TestNamespace, nft, with_timeout};

/// `ip t` with an output chain and `set` holding `elements`.
async fn output_chain(conn: &Connection<Nftables>, set: &Set, elements: &[SetElement]) -> nlink::Result<()> {
    conn.add_table("t", Family::Ip).await?;
    conn.add_chain(
        Chain::new("t", "out")?
            .family(Family::Ip)
            .base(BaseChain::filter(FilterHook::Output, Priority::Filter)),
    )
    .await?;
    conn.add_set(set.clone()).await?;
    conn.add_set_elements(set, elements).await
}

async fn counters(conn: &Connection<Nftables>, family: Family) -> nlink::Result<Vec<u64>> {
    let rules = conn.list_rules("t", family).await?;
    Ok(rules
        .iter()
        .map(|r| r.counter().expect("rule has a counter").0)
        .collect())
}

fn ip_port() -> SetKeyType {
    SetKeyType::Concat(vec![SetKeyType::Ipv4Addr, SetKeyType::InetService])
}

const DADDR_DPORT: &[PacketField] = &[PacketField::Ip4Daddr, PacketField::UdpDport];

fn pair(a: u8, port: u16) -> SetElement {
    SetElement::concat([SetElement::ipv4(Ipv4Addr::new(127, 0, 0, a)), SetElement::port(port)])
}

/// `ip daddr . udp dport @s` matches the pairs in the set and not the
/// crossed ones, whose address and port are each in the set on their own;
/// `!= @s` counts exactly the others.
#[tokio::test]
async fn a_hash_set_of_address_and_port_matches_the_pair_not_its_parts() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-cc-hash")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let set = Set::new("t", "s").family(Family::Ip).key_type(ip_port());
        output_chain(&conn, &set, &[pair(1, 9), pair(2, 10)]).await?;
        for rule in [
            Rule::new("t", "out").match_concat_in_set(DADDR_DPORT, "s"),
            Rule::new("t", "out").match_concat_not_in_set(DADDR_DPORT, "s"),
        ] {
            conn.add_rule(rule.family(Family::Ip).counter()).await?;
        }
        send_udp(
            &ns,
            &["127.0.0.1:9", "127.0.0.1:10", "127.0.0.2:10", "127.0.0.2:9"],
            1,
        );
        assert_eq!(counters(&conn, Family::Ip).await?, [2, 2]);
        Ok(())
    })
    .await
}

/// An interval set of concatenated keys (the kernel's `pipapo`): each field
/// is a range of its own. `127.0.0.0/30 . 1000-2000` matches inside both
/// ranges only, and a single pair next to it is just that pair.
#[tokio::test]
async fn a_net_and_port_range_matches_inside_both_ranges_only() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-cc-pipapo")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let set = Set::new("t", "s").family(Family::Ip).key_type(ip_port()).interval();
        let ranged = SetElement::concat([
            SetElement::ipv4_prefix(Ipv4Addr::new(127, 0, 0, 0), 30)?,
            SetElement::port_range(1000, 2000),
        ]);
        output_chain(&conn, &set, &[ranged.clone(), pair(9, 53)]).await?;
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_concat_in_set(DADDR_DPORT, "s")
                .counter(),
        )
        .await?;
        let targets = [
            "127.0.0.2:1000",
            "127.0.0.3:2000",
            "127.0.0.2:999",
            "127.0.0.2:2001",
            "127.0.0.4:1500",
            "127.0.0.9:53",
            "127.0.0.9:54",
        ];
        send_udp(&ns, &targets, 1);
        assert_eq!(counters(&conn, Family::Ip).await?, [3]);

        // Read back as written: one ranged element, one single pair.
        let mut elements = conn.list_set_elements("t", "s", Family::Ip).await?;
        elements.sort_by(|a, b| a.key().cmp(b.key()));
        assert_eq!(elements, [ranged, pair(9, 53)]);
        Ok(())
    })
    .await
}

fn declared(elements: Vec<SetElement>) -> NftablesConfig {
    NftablesConfig::new().table("t", Family::Inet, move |t| {
        t.chain("out", |c| {
            c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
        })
        .set("v6", |s| {
            s.key_type(SetKeyType::Concat(vec![
                SetKeyType::Ipv6Addr,
                SetKeyType::InetService,
            ]))
            .element(SetElement::concat([
                SetElement::ipv6(Ipv6Addr::LOCALHOST),
                SetElement::port(9),
            ]))
        })
        .set("nets", move |s| {
            s.key_type(SetKeyType::Concat(vec![
                SetKeyType::Ipv4Addr,
                SetKeyType::InetService,
            ]))
            .interval()
            .elements(elements)
        })
        .rule_keyed("out", "v6", |r| {
            r.match_concat_in_set(&[PacketField::Ip6Daddr, PacketField::UdpDport], "v6")
                .counter()
        })
        .rule_keyed("out", "nets", |r| r.match_concat_in_set(DADDR_DPORT, "nets").counter())
    })
}

fn net_ports(c: u8, ports: (u16, u16)) -> SetElement {
    SetElement::concat([
        SetElement::ipv4_prefix(Ipv4Addr::new(10, 0, c, 0), 24).unwrap(),
        SetElement::port_range(ports.0, ports.1),
    ])
}

/// Declared concatenations converge. The IPv6 lookup loads its port into
/// word 4, which the kernel dumps as `NFT_REG_2`; a rule written with any
/// other name for that register would be replaced on every apply. The
/// interval set changes one element at a time, and traffic still matches
/// after the second apply.
#[tokio::test]
async fn declared_concatenations_converge_and_change_one_element_at_a_time() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-cc-decl")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let first = declared(vec![net_ports(0, (80, 90)), net_ports(1, (443, 443))]);
        first.diff(&conn).await?.apply(&conn).await?;
        let again = first.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");

        let second = declared(vec![net_ports(0, (80, 90)), net_ports(2, (53, 53))]);
        let diff = second.diff(&conn).await?;
        assert_eq!(nft::elements(&diff, "remove").len(), 1, "{diff}");
        assert_eq!(
            nft::elements(&diff, "remove")[0].elements.len(),
            1,
            "{diff}"
        );
        assert_eq!(nft::elements(&diff, "add")[0].elements.len(), 1, "{diff}");
        assert!(nft::replaced(&diff).is_empty(), "{diff}");
        diff.apply(&conn).await?;
        let again = second.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");

        send_udp(&ns, &["[::1]:9", "[::1]:9", "[::1]:10", "127.0.0.1:9"], 1);
        let rules = conn.list_rules("t", Family::Inet).await?;
        let v6 = rules.iter().find(|r| r.key.as_deref() == Some("v6")).unwrap();
        assert_eq!(v6.counter().unwrap().0, 2);
        Ok(())
    })
    .await
}
