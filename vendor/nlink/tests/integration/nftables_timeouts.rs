//! Set timeouts and `dynset` (`add|update|delete @set` from a rule) —
//! ipset `timeout` and `SET --add-set` — checked on traffic, declared
//! dynamic sets that keep what the packet path put in them, and dynset
//! per-element statements.

use std::net::Ipv4Addr;
use std::time::Duration;

use nlink::netlink::nftables::config::{Change, NftablesConfig};
use nlink::netlink::nftables::types::{
    BaseChain, Chain, Family, FilterHook, LimitUnit, PacketField, Priority, Register, Rule, Set,
    SetElement, SetKeyType,
};
use nlink::netlink::nftables::{
    DynsetExpr, DynsetOp, ElementStatement, LimitExpr, QuotaExpr, RuleExpr,
};
use nlink::netlink::{Connection, Nftables};

use crate::common::converge::assert_transition;
use crate::common::counters::rule_packets;
use crate::common::traffic::{lo_up, send_udp};
use crate::common::{TestNamespace, nft, with_timeout};

/// `ip t` with an output chain, `set`, and `rule` in the chain.
async fn chain_with(conn: &Connection<Nftables>, set: &Set, rule: Rule) -> nlink::Result<()> {
    conn.add_table("t", Family::Ip).await?;
    conn.add_chain(
        Chain::new("t", "out")?
            .family(Family::Ip)
            .base(BaseChain::filter(FilterHook::Output, Priority::Filter)),
    )
    .await?;
    conn.add_set(set.clone()).await?;
    conn.add_rule(rule.family(Family::Ip)).await
}

fn keys(elements: &[SetElement]) -> Vec<Vec<u8>> {
    let mut keys: Vec<Vec<u8>> = elements.iter().map(|e| e.key().to_vec()).collect();
    keys.sort();
    keys
}

fn ip(last: u8) -> Vec<u8> {
    vec![127, 0, 0, last]
}

/// `update @seen { ip daddr timeout 60s }` puts every destination the
/// chain sees in the set, with that timeout running.
#[tokio::test]
async fn update_in_set_records_each_destination_with_its_timeout() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-to-update")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let set = Set::new("t", "seen")
            .family(Family::Ip)
            .dynamic()
            .per_element_timeouts();
        let rule = Rule::new("t", "out").match_l4proto(17).update_in_set(
            PacketField::Ip4Daddr,
            "seen",
            Some(Duration::from_secs(60)),
        );
        chain_with(&conn, &set, rule).await?;
        send_udp(&ns, &["127.0.0.5:9", "127.0.0.6:9", "127.0.0.5:10"], 1);

        let seen = conn.list_set_elements("t", "seen", Family::Ip).await?;
        assert_eq!(keys(&seen), [ip(5), ip(6)]);
        for e in &seen {
            assert_eq!(e.timeout(), Some(Duration::from_secs(60)));
            let left = e.expiration().expect("a timed element reports its time left");
            assert!(left <= Duration::from_secs(60) && left > Duration::from_secs(50), "{left:?}");
        }
        Ok(())
    })
    .await
}

/// `delete @s { ip daddr }` removes the destination from the set.
#[tokio::test]
async fn delete_from_set_removes_the_destination() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-to-delete")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let set = Set::new("t", "s").family(Family::Ip).dynamic();
        let rule = Rule::new("t", "out")
            .match_l4proto(17)
            .delete_from_set(PacketField::Ip4Daddr, "s");
        chain_with(&conn, &set, rule).await?;
        let members = [5, 6].map(|n| SetElement::ipv4(Ipv4Addr::new(127, 0, 0, n)));
        conn.add_set_elements(&set, &members).await?;

        send_udp(&ns, &["127.0.0.5:9"], 1);
        let left = conn.list_set_elements("t", "s", Family::Ip).await?;
        assert_eq!(keys(&left), [ip(6)]);
        Ok(())
    })
    .await
}

/// Elements take the set's default timeout unless they carry their own,
/// and are gone — not listed — once it has run out.
#[tokio::test]
async fn elements_expire_after_the_set_default_or_their_own_timeout() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-to-expire")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        conn.add_table("t", Family::Ip).await?;
        let set = Set::new("t", "s")
            .family(Family::Ip)
            .timeout(Duration::from_secs(1))
            .gc_interval(Duration::from_secs(1));
        conn.add_set(set.clone()).await?;
        let info = conn.list_sets_in("t", Family::Ip).await?.remove(0);
        assert_eq!(info.timeout, Some(Duration::from_secs(1)));
        assert_eq!(info.gc_interval, Some(Duration::from_secs(1)));

        let short = SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 1));
        let long = SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 2)).with_timeout(Duration::from_secs(30));
        conn.add_set_elements(&set, &[short, long]).await?;
        let now = conn.list_set_elements("t", "s", Family::Ip).await?;
        assert_eq!(now.len(), 2);
        // Only a timeout that differs from the set's default is reported.
        let own: Vec<_> = now.iter().map(SetElement::timeout).collect();
        assert!(own.contains(&None) && own.contains(&Some(Duration::from_secs(30))), "{own:?}");

        tokio::time::sleep(Duration::from_millis(1500)).await;
        let later = conn.list_set_elements("t", "s", Family::Ip).await?;
        assert_eq!(keys(&later), [vec![10, 0, 0, 2]]);
        Ok(())
    })
    .await
}

fn declared(set_timeout: Duration, rule_timeout: Duration) -> NftablesConfig {
    NftablesConfig::new().table("t", Family::Ip, move |t| {
        t.chain("out", |c| {
            c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
        })
        .set("seen", move |s| {
            s.key_type(SetKeyType::Ipv4Addr)
                .dynamic()
                .timeout(set_timeout)
                .gc_interval(Duration::from_millis(1500))
        })
        .rule_keyed("out", "track", move |r| {
            r.match_l4proto(17)
                .update_in_set(PacketField::Ip4Daddr, "seen", Some(rule_timeout))
        })
        // No timeout of its own: the kernel echoes a zero one.
        .rule_keyed("out", "first", |r| {
            r.match_l4proto(6).add_to_set(PacketField::Ip4Saddr, "seen", None)
        })
    })
}

/// A declared dynamic set keeps what its rule put there (#395: a set
/// declared without elements had them wiped on every apply), and its
/// timeouts converge — including ones the kernel rounds to a jiffy.
#[tokio::test]
async fn a_declared_dynamic_set_keeps_what_the_packet_path_put_there() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-to-decl")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        // 1001 ms reads back as 1000 at HZ=250 or 1003 at HZ=300.
        let cfg = declared(Duration::from_secs(3600), Duration::from_millis(1001));
        cfg.diff(&conn).await?.apply(&conn).await?;
        let again = cfg.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");

        send_udp(&ns, &["127.0.0.5:9", "127.0.0.6:9"], 1);
        let again = cfg.diff(&conn).await?;
        assert!(again.is_empty(), "traffic must not make a diff: {again}");
        assert_eq!(again.apply(&conn).await?, 0);
        let seen = conn.list_set_elements("t", "seen", Family::Ip).await?;
        assert_eq!(keys(&seen), [ip(5), ip(6)]);

        // A changed default timeout is an in-place update: the set, its
        // elements and the rule's handle stay.
        let handle = conn.list_rules("t", Family::Ip).await?[0].handle;
        let longer = declared(Duration::from_secs(7200), Duration::from_millis(1001));
        let diff = longer.diff(&conn).await?;
        let sets: Vec<_> = diff.sets().collect();
        assert!(matches!(sets[..], [Change::Update { .. }]), "{diff}");
        diff.apply(&conn).await?;
        let info = conn.list_sets_in("t", Family::Ip).await?.remove(0);
        assert_eq!(info.timeout, Some(Duration::from_secs(7200)));
        assert_eq!(keys(&conn.list_set_elements("t", "seen", Family::Ip).await?).len(), 2);
        assert_eq!(conn.list_rules("t", Family::Ip).await?[0].handle, handle);
        let again = longer.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}

/// Resizing a set whose timeout and GC interval the declaration does not
/// state keeps them: the update overwrites both with what it carries, so it
/// carries the kernel's (#396).
#[tokio::test]
async fn a_resize_keeps_the_timers_it_does_not_declare() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-to-resize")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        conn.add_table("t", Family::Ip).await?;
        conn.add_set(
            Set::new("t", "s")
                .family(Family::Ip)
                .timeout(Duration::from_secs(30))
                .gc_interval(Duration::from_secs(5))
                .size(100),
        )
        .await?;

        let cfg = NftablesConfig::new().table("t", Family::Ip, |t| {
            t.set("s", |s| {
                s.key_type(SetKeyType::Ipv4Addr)
                    .per_element_timeouts()
                    .size(200)
            })
        });
        let diff = cfg.diff(&conn).await?;
        assert_eq!(nft::count(&diff, "set", "update"), 1, "{diff}");
        diff.apply(&conn).await?;

        let info = conn.list_sets_in("t", Family::Ip).await?.remove(0);
        assert_eq!(info.size, Some(200));
        assert_eq!(info.timeout, Some(Duration::from_secs(30)));
        assert_eq!(info.gc_interval, Some(Duration::from_secs(5)));
        let again = cfg.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}

/// In exact mode, an undeclared element that times out between the diff
/// and the apply does not fail the batch: the kernel would answer ENOENT
/// for its delete, so on a kernel that has it the removal is a destroy
/// (#483).
#[tokio::test]
async fn an_element_that_expires_before_the_apply_does_not_fail_it() -> nlink::Result<()> {
    use nlink::netlink::nftables::config::SetElementMode;
    require_root!();
    nlink::require_modules!("nf_tables");
    if !nlink::netlink::nftables::connection::kernel_has_destroy() {
        eprintln!("skipping: the kernel has no NFT_MSG_DESTROYSETELEM (6.3+)");
        return Ok(());
    }

    let ns = TestNamespace::new("nft-to-expire")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_timeout(async {
        let cfg = NftablesConfig::new().table("t", Family::Ip, |t| {
            t.set("s", |s| {
                s.key_type(SetKeyType::Ipv4Addr)
                    .per_element_timeouts()
                    .element_mode(SetElementMode::Exact)
                    .ipv4(Ipv4Addr::new(10, 0, 0, 1))
            })
        });
        cfg.diff(&conn).await?.apply(&conn).await?;
        ns.exec(
            "nft",
            &["add", "element", "ip", "t", "s", "{ 10.0.0.9 timeout 1s }"],
        )?;
        let diff = cfg.diff(&conn).await?;
        assert_eq!(nft::elements(&diff, "remove").len(), 1, "{diff}");
        tokio::time::sleep(Duration::from_millis(1500)).await;
        diff.apply(&conn).await?;
        assert!(cfg.diff(&conn).await?.is_empty());
        Ok(())
    })
    .await
}

// ============================================================================
// #703 — dynset per-element statements
// ============================================================================

/// `nft list table inet`, named `T` and without the time each element has
/// left, which runs on between two listings.
fn listed_table(ns: &TestNamespace, table: &str) -> nlink::Result<String> {
    let out = ns.exec("nft", &["list", "table", "inet", table])?;
    let mut words = out.split_whitespace();
    let mut kept = Vec::new();
    while let Some(word) = words.next() {
        if word == "expires" {
            words.next();
        } else {
            kept.push(word);
        }
    }
    Ok(kept.join(" ").replacen(&format!("table inet {table}"), "table inet T", 1))
}

/// #703: dynset statements as nft writes them — one, two, a limit, a
/// connlimit — decode typed, and nlink installs the same rules; `nft`
/// lists the two tables alike, before traffic and after, when each
/// element carries its own counter, quota and limit. An inet table, where
/// nft guards `ip daddr` with `meta nfproto` as nlink does in every family:
/// nft 1.0.6 cannot list a guarded dynset key in an ip table.
#[tokio::test]
async fn dynset_statements_read_and_write_as_nft_does() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_limit", "nft_quota", "nft_connlimit");

    let ns = TestNamespace::new("nft-dynstmt")?;
    lo_up(&ns).await?;
    let script = "table inet a {
 set s1 { type ipv4_addr; flags dynamic; }
 set s2 { type ipv4_addr; flags dynamic,timeout; }
 set s3 { type ipv4_addr; flags dynamic; }
 set s4 { type ipv4_addr; flags dynamic; }
 chain out {
  type filter hook output priority 0;
  add @s1 { ip daddr counter }
  update @s2 { ip daddr timeout 30s limit rate over 1/minute burst 2 packets } counter
  add @s3 { ip daddr counter quota over 1000 bytes }
  add @s4 { ip daddr ct count over 3 }
 }
}
";
    let file = std::env::temp_dir().join(format!("nlink-dynstmt-{}.nft", std::process::id()));
    std::fs::write(&file, script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed?;

    let conn = ns.connection_for::<Nftables>()?;
    conn.add_table("b", Family::Inet).await?;
    for (name, timeouts) in [("s1", false), ("s2", true), ("s3", false), ("s4", false)] {
        // nft gives a dynamic set a size of 65535.
        let set = Set::new("b", name).family(Family::Inet).dynamic().size(65535);
        conn.add_set(if timeouts { set.per_element_timeouts() } else { set }).await?;
    }
    conn.add_chain(
        Chain::new("b", "out")?
            .family(Family::Inet)
            .base(BaseChain::filter(FilterHook::Output, Priority::Filter)),
    )
    .await?;
    let dynset = |op, set| DynsetExpr::new(op, set, Register::R0);
    let limit = LimitExpr::packets(1, LimitUnit::Minute).burst(2).over();
    for rule in [
        Rule::new("b", "out").dynset(PacketField::Ip4Daddr, dynset(DynsetOp::Add, "s1").counter()),
        Rule::new("b", "out")
            .dynset(
                PacketField::Ip4Daddr,
                dynset(DynsetOp::Update, "s2").timeout(Duration::from_secs(30)).statement(limit),
            )
            .counter(),
        Rule::new("b", "out").dynset(
            PacketField::Ip4Daddr,
            dynset(DynsetOp::Add, "s3").counter().statement(QuotaExpr::new(1000).over()),
        ),
        Rule::new("b", "out").dynset(
            PacketField::Ip4Daddr,
            dynset(DynsetOp::Add, "s4").statement(ElementStatement::Connlimit { count: 3, over: true }),
        ),
    ] {
        conn.add_rule(rule.family(Family::Inet)).await?;
    }
    assert_eq!(listed_table(&ns, "b")?, listed_table(&ns, "a")?, "nlink's b, nft's a");

    // 6 datagrams and the 6 port unreachables they draw, all to 127.0.0.1.
    send_udp(&ns, &["127.0.0.1:9"], 6);
    let after = listed_table(&ns, "b")?;
    assert_eq!(after, listed_table(&ns, "a")?, "after traffic");
    assert!(after.contains("127.0.0.1 counter packets 12"), "{after}");

    let unknown = conn
        .list_rules("a", Family::Inet)
        .await?
        .iter()
        .flat_map(|r| r.expressions())
        .filter(|e| matches!(e, RuleExpr::Unknown { .. }))
        .count();
    assert_eq!(unknown, 0, "every dynset and its statements decode typed");
    Ok(())
}

/// `ip t`: UDP to an address over `burst` packets a minute is counted, per
/// address (`update @flood { ip daddr limit rate over 1/minute burst N }`),
/// and every address gets a counter and a quota of its own in `seen`.
fn flood(burst: u32) -> NftablesConfig {
    NftablesConfig::new().table("t", Family::Ip, move |t| {
        t.chain("out", |c| {
            c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
        })
        .set("flood", |s| s.key_type(SetKeyType::Ipv4Addr).dynamic())
        .set("seen", |s| s.key_type(SetKeyType::Ipv4Addr).dynamic())
        .rule_keyed("out", "flood", move |r| {
            let limit = LimitExpr::packets(1, LimitUnit::Minute).burst(burst).over();
            r.match_l4proto(17)
                .dynset(
                    PacketField::Ip4Daddr,
                    DynsetExpr::new(DynsetOp::Update, "flood", Register::R0).statement(limit),
                )
                .counter()
        })
        // Two statements: NFT_DYNSET_F_EXPR goes out and is never echoed.
        .rule_keyed("out", "seen", |r| {
            r.match_l4proto(17).dynset(
                PacketField::Ip4Daddr,
                DynsetExpr::new(DynsetOp::Add, "seen", Register::R0)
                    .counter()
                    .statement(QuotaExpr::new(1 << 20)),
            )
        })
    })
}

/// #703: declared dynset statements converge, limit each address on its
/// own, and a statement changed in place (burst 2 → 3) is applied: the next
/// addresses are let through one packet more.
#[tokio::test]
async fn declared_dynset_statements_converge_and_limit_per_address() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_limit", "nft_quota");

    let ns = TestNamespace::new("nft-dynstmt-decl")?;
    lo_up(&ns).await?;
    let steps = [flood(2), flood(3)];
    assert_transition(&ns, &steps, false, async |i, conn| {
        let over = async || {
            rule_packets(conn, "t", Family::Ip, "out", 0)
                .await
                .map_err(|e| e.to_string())
        };
        let before = over().await?;
        // Two addresses of their own per step, five datagrams each.
        let first = 10 + 2 * i;
        let targets = [format!("127.0.0.{first}:9"), format!("127.0.0.{}:9", first + 1)];
        send_udp(&ns, &targets, 5);
        let counted = over().await? - before;
        let burst = [2, 3][i] as u64;
        if counted != 2 * (5 - burst) {
            return Err(format!("step {}: {counted} over the limit, want {}", i + 1, 2 * (5 - burst)));
        }
        let seen = ns.exec("nft", &["list", "set", "ip", "t", "seen"]).map_err(|e| e.to_string())?;
        if !seen.contains(&format!("127.0.0.{first} counter packets 5 ")) {
            return Err(format!("step {}: no per-element counter: {seen}", i + 1));
        }
        Ok(())
    })
    .await
}
