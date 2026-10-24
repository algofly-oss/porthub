//! Interval sets — ranges and prefixes (ipset `hash:net`), and ranges of
//! host-order keys such as marks — checked on traffic: a range matches its
//! ends and nothing past them.

use std::net::Ipv4Addr;

use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    BaseChain, Chain, Family, FilterHook, PacketField, Priority, Rule, Set, SetElement, SetKeyType,
};
use nlink::netlink::{Connection, Nftables};

use crate::common::converge::assert_transition;
use crate::common::counters::rule_packets;
use crate::common::traffic::{lo_up, send_udp};
use crate::common::{TestNamespace, nft, with_timeout};

/// `ip t` with an output chain counting UDP whose `field` is in `set`.
async fn counting_chain(
    conn: &Connection<Nftables>,
    set: &Set,
    elements: &[SetElement],
    field: PacketField,
) -> nlink::Result<()> {
    conn.add_table("t", Family::Ip).await?;
    conn.add_chain(
        Chain::new("t", "out")?
            .family(Family::Ip)
            .base(BaseChain::filter(FilterHook::Output, Priority::Filter)),
    )
    .await?;
    conn.add_set(set.clone()).await?;
    conn.add_set_elements(set, elements).await?;
    conn.add_rule(
        Rule::new("t", "out")
            .family(Family::Ip)
            .match_l4proto(17)
            .match_in_set(field, set.name())
            .counter(),
    )
    .await
}

async fn counted(conn: &Connection<Nftables>) -> nlink::Result<u64> {
    let rules = conn.list_rules("t", Family::Ip).await?;
    Ok(rules[0].counter().expect("rule has a counter").0)
}

fn interval_set(name: &str, key_type: SetKeyType) -> Set {
    Set::new("t", name)
        .family(Family::Ip)
        .key_type(key_type)
        .interval()
}

/// `udp dport @r` with r = 1000-2000: 1000 and 2000 match, 999 and 2001
/// do not — the end element is `2000 + 1`, not 2000 and not missing.
#[tokio::test]
async fn a_port_range_matches_its_ends_and_nothing_past_them() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-iv-port")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let set = interval_set("r", SetKeyType::InetService);
        counting_chain(&conn, &set, &[SetElement::port_range(1000, 2000)], PacketField::UdpDport)
            .await?;
        send_udp(
            &ns,
            &["127.0.0.1:999", "127.0.0.1:1000", "127.0.0.1:2000", "127.0.0.1:2001"],
            1,
        );
        assert_eq!(counted(&conn).await?, 2);
        Ok(())
    })
    .await
}

/// A /30 matches its four addresses and not its neighbours.
#[tokio::test]
async fn a_prefix_matches_its_addresses_only() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-iv-prefix")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let set = interval_set("n", SetKeyType::Ipv4Addr);
        let net = SetElement::ipv4_prefix(Ipv4Addr::new(127, 0, 0, 4), 30)?;
        counting_chain(&conn, &set, &[net], PacketField::Ip4Daddr).await?;
        send_udp(
            &ns,
            &["127.0.0.3:9", "127.0.0.4:9", "127.0.0.7:9", "127.0.0.8:9"],
            1,
        );
        assert_eq!(counted(&conn).await?, 2, "only .4 and .7 are in the /30");
        Ok(())
    })
    .await
}

/// A single address in an interval set is that address. Written as a bare
/// interval start — as nlink would have before it modelled intervals — it
/// would have matched every address above it.
#[tokio::test]
async fn a_single_address_in_an_interval_set_is_just_that_address() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-iv-single")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let set = interval_set("n", SetKeyType::Ipv4Addr);
        let one = SetElement::ipv4(Ipv4Addr::new(127, 0, 0, 10));
        counting_chain(&conn, &set, &[one], PacketField::Ip4Daddr).await?;
        send_udp(&ns, &["127.0.0.10:9", "127.0.0.11:9", "127.0.0.200:9"], 1);
        assert_eq!(counted(&conn).await?, 1);
        Ok(())
    })
    .await
}

fn declared(ranges: Vec<SetElement>) -> NftablesConfig {
    NftablesConfig::new().table("t", Family::Ip, move |t| {
        t.set("nets", move |s| {
            s.key_type(SetKeyType::Ipv4Addr)
                .interval()
                .elements(ranges)
        })
    })
}

fn prefix(a: u8, b: u8, c: u8, len: u8) -> SetElement {
    SetElement::ipv4_prefix(Ipv4Addr::new(a, b, c, 0), len).unwrap()
}

/// Declared ranges converge; changing one range removes and adds only that
/// range; ranges that touch are merged into one.
#[tokio::test]
async fn declared_ranges_converge_and_change_one_at_a_time() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-iv-decl")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let single = SetElement::ipv4(Ipv4Addr::new(192, 0, 2, 7));
        let first = declared(vec![prefix(10, 0, 0, 24), prefix(10, 0, 2, 24), single.clone()]);
        first.diff(&conn).await?.apply(&conn).await?;
        let again = first.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        assert_eq!(conn.list_set_elements("t", "nets", Family::Ip).await?.len(), 3);

        let second = declared(vec![prefix(10, 0, 0, 24), prefix(10, 0, 3, 24), single]);
        let diff = second.diff(&conn).await?;
        assert_eq!(nft::elements(&diff, "remove").len(), 1, "{diff}");
        assert_eq!(
            nft::elements(&diff, "remove")[0].elements.len(),
            1,
            "{diff}"
        );
        assert_eq!(nft::elements(&diff, "add")[0].elements.len(), 1, "{diff}");
        diff.apply(&conn).await?;
        let again = second.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");

        // Two /25s that touch are one /24 to the kernel's lookups.
        let halves = declared(vec![
            SetElement::ipv4_prefix(Ipv4Addr::new(10, 9, 0, 0), 25)?,
            SetElement::ipv4_prefix(Ipv4Addr::new(10, 9, 0, 128), 25)?,
        ]);
        halves.diff(&conn).await?.apply(&conn).await?;
        let elements = conn.list_set_elements("t", "nets", Family::Ip).await?;
        assert_eq!(elements.len(), 1, "{elements:?}");
        assert_eq!(elements[0].key(), [10, 9, 0, 0]);
        assert_eq!(elements[0].key_end(), Some(&[10, 9, 0, 255][..]));
        let again = halves.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}

/// A range declared with its own timeout keeps it. The diff rebuilt
/// interval elements from bare ranges, so the timeout was never sent and
/// the range never timed out (#483).
#[tokio::test]
async fn a_declared_range_keeps_its_timeout() -> nlink::Result<()> {
    use std::time::Duration;
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-iv-timeout")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_timeout(async {
        let cfg = NftablesConfig::new().table("t", Family::Ip, |t| {
            t.set("r", |s| {
                s.key_type(SetKeyType::Ipv4Addr)
                    .interval()
                    .per_element_timeouts()
                    .element(
                        SetElement::ipv4_range(
                            Ipv4Addr::new(10, 0, 0, 1),
                            Ipv4Addr::new(10, 0, 0, 9),
                        )
                        .with_timeout(Duration::from_secs(600)),
                    )
            })
        });
        cfg.diff(&conn).await?.apply(&conn).await?;
        assert!(cfg.diff(&conn).await?.is_empty());
        let shown = ns.exec("nft", &["list", "set", "ip", "t", "r"])?;
        assert!(
            shown.contains("timeout 10m"),
            "the range has no timeout:\n{shown}"
        );
        Ok(())
    })
    .await
}

/// In ensure mode a declared range that overlaps one added at runtime goes
/// in as the part not already covered. The kernel refuses an overlapping
/// range, so every apply failed (#483).
#[tokio::test]
async fn ensure_mode_adds_around_a_runtime_range() -> nlink::Result<()> {
    use crate::common::converge::converges;
    use nlink::netlink::nftables::config::SetElementMode;
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-iv-ensure")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_timeout(async {
        let cfg = |declared: bool| {
            NftablesConfig::new().table("t", Family::Ip, move |t| {
                t.set("r", move |s| {
                    let s = s
                        .key_type(SetKeyType::Ipv4Addr)
                        .interval()
                        .element_mode(SetElementMode::Ensure);
                    if !declared {
                        return s;
                    }
                    s.element(SetElement::ipv4_range(
                        Ipv4Addr::new(10, 0, 0, 10),
                        Ipv4Addr::new(10, 0, 0, 40),
                    ))
                })
            })
        };
        cfg(false).diff(&conn).await?.apply(&conn).await?;
        ns.exec(
            "nft",
            &["add", "element", "ip", "t", "r", "{ 10.0.0.0-10.0.0.20 }"],
        )?;
        if let Err(why) = converges(&conn, &cfg(true), false).await {
            panic!("{why}");
        }
        for addr in ["10.0.0.0", "10.0.0.20", "10.0.0.21", "10.0.0.40"] {
            ns.exec(
                "nft",
                &["get", "element", "ip", "t", "r", &format!("{{ {addr} }}")],
            )?;
        }
        Ok(())
    })
    .await
}

// ============================================================================
// #703 — ranges of host-order keys: marks
// ============================================================================

/// #703: an interval set of marks as nft writes it — ranges and a single
/// mark, its keys in network order — and the lookups that convert the mark
/// first, in and not in: nlink installs the same, and `nft` lists the two
/// tables alike. nlink reads nft's elements back in host order.
#[tokio::test]
async fn mark_ranges_read_and_write_as_nft_does() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-iv-mark")?;
    let script = "table ip a {
 set m { type mark; flags interval; elements = { 1-10, 0x100, 0x1000-0x1fff } }
 chain out {
  type filter hook output priority 0;
  meta mark @m counter
  meta mark != @m counter
 }
}
";
    let file = std::env::temp_dir().join(format!("nlink-ivmark-{}.nft", std::process::id()));
    std::fs::write(&file, script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed?;

    let conn = ns.connection_for::<Nftables>()?;
    let elements = [
        SetElement::mark_range(1, 10),
        SetElement::mark(0x100),
        SetElement::mark_range(0x1000, 0x1fff),
    ];
    conn.add_table("b", Family::Ip).await?;
    let set = Set::new("b", "m")
        .family(Family::Ip)
        .key_type(SetKeyType::Mark)
        .interval();
    conn.add_set(set.clone()).await?;
    conn.add_set_elements(&set, &elements).await?;
    conn.add_chain(
        Chain::new("b", "out")?
            .family(Family::Ip)
            .base(BaseChain::filter(FilterHook::Output, Priority::Filter)),
    )
    .await?;
    let rule = || Rule::new("b", "out").family(Family::Ip);
    conn.add_rule(rule().match_in_interval_set(PacketField::Mark, "m").counter()).await?;
    conn.add_rule(rule().match_not_in_interval_set(PacketField::Mark, "m").counter()).await?;

    let listed = |table: &str| -> nlink::Result<String> {
        let out = ns.exec("nft", &["list", "table", "ip", table])?;
        Ok(out.replacen(&format!("table ip {table}"), "table ip T", 1))
    };
    assert_eq!(listed("b")?, listed("a")?, "nlink's table b, nft's table a");
    assert_eq!(ranges(&conn.list_set_elements("a", "m", Family::Ip).await?), ranges(&elements));
    Ok(())
}

/// Each element's key and range end.
fn ranges(elements: &[SetElement]) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    elements
        .iter()
        .map(|e| (e.key().to_vec(), e.key_end().map(<[u8]>::to_vec)))
        .collect()
}

/// `ip t`: every UDP datagram is marked `mark`, and counted when its mark
/// is in the interval set `marks`, which holds `ranges`.
fn marked(mark: u32, ranges: Vec<SetElement>) -> NftablesConfig {
    NftablesConfig::new().table("t", Family::Ip, move |t| {
        t.chain("out", |c| {
            c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
        })
        .set("marks", move |s| s.key_type(SetKeyType::Mark).interval().elements(ranges))
        .rule_keyed("out", "mark", move |r| r.match_l4proto(17).set_mark(mark))
        .rule_keyed("out", "in", |r| {
            r.match_l4proto(17)
                .match_in_interval_set(PacketField::Mark, "marks")
                .counter()
        })
    })
}

/// #703: declared mark ranges converge — touching ranges merged as the
/// numbers they are, read back in host order — and match the marks inside
/// them: a range that grows to take the mark in, then one that shrinks to
/// leave it out, each count as they should.
#[tokio::test]
async fn declared_mark_ranges_match_the_marks_inside_them() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-iv-markdecl")?;
    lo_up(&ns).await?;
    let steps = [
        // 255 and 256 touch: one range, 1..=511, which 300 is in.
        marked(300, vec![SetElement::mark_range(1, 255), SetElement::mark_range(256, 511)]),
        // 300 is past 299.
        marked(300, vec![SetElement::mark_range(1, 299)]),
        marked(300, vec![SetElement::mark_range(1, 299), SetElement::mark(300)]),
    ];
    let want = [
        (2, vec![SetElement::mark_range(1, 511)]),
        (0, vec![SetElement::mark_range(1, 299)]),
        (2, vec![SetElement::mark_range(1, 300)]),
    ];
    assert_transition(&ns, &steps, false, async |i, conn| {
        let before = rule_packets(conn, "t", Family::Ip, "out", 1)
            .await
            .map_err(|e| e.to_string())?;
        send_udp(&ns, &["127.0.0.1:9"], 2);
        let counted = rule_packets(conn, "t", Family::Ip, "out", 1)
            .await
            .map_err(|e| e.to_string())?
            - before;
        let (count, elements) = &want[i];
        if counted != *count {
            return Err(format!("step {}: {counted} counted, want {count}", i + 1));
        }
        let held = conn
            .list_set_elements("t", "marks", Family::Ip)
            .await
            .map_err(|e| e.to_string())?;
        if ranges(&held) != ranges(elements) {
            return Err(format!("step {}: the set holds {held:?}", i + 1));
        }
        Ok(())
    })
    .await
}

/// #703: a plain `match_in_set` looks a mark up in host order, which an
/// interval set of marks does not hold: the declaration is refused.
#[test]
fn a_plain_lookup_in_an_interval_set_of_marks_is_refused() {
    let cfg = NftablesConfig::new().table("t", Family::Ip, |t| {
        t.chain("out", |c| {
            c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
        })
        .set("marks", |s| s.key_type(SetKeyType::Mark).interval())
        .rule("out", |r| r.match_in_set(PacketField::Mark, "marks"))
    });
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("match_in_interval_set"), "{err}");
}
