//! Declarative rule identity and order.
//!
//! Rule order is policy — first match wins — so a declared chain has to end
//! up in declared order, and a rule nobody changed must be left alone: not
//! replaced (which resets its counters), not duplicated, not moved.

use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{BaseChain, Family, FilterHook, Priority, Rule};
use nlink::netlink::{Connection, Nftables};

use crate::common::traffic::{lo_up, send_udp};
use crate::common::{TestNamespace, nft, with_timeout};

/// A declared rule: its key and how to build its body.
type KeyedRule = (&'static str, fn(Rule) -> Rule);

/// A table `ip t` with an `output` filter chain `out`, holding `rules` in
/// order — each `(key, rule body)`.
fn cfg<F>(rules: Vec<(&'static str, F)>) -> NftablesConfig
where
    F: Fn(Rule) -> Rule + 'static,
{
    NftablesConfig::new().table("t", Family::Ip, move |mut t| {
        t = t.chain("out", |c| {
            c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
        });
        for (key, body) in rules {
            t = t.rule_keyed("out", key, body);
        }
        t
    })
}

/// Keys of the rules in `out`, in kernel order.
async fn keys(conn: &Connection<Nftables>) -> nlink::Result<Vec<String>> {
    Ok(conn
        .list_rules("t", Family::Ip)
        .await?
        .into_iter()
        .filter(|r| r.chain == "out")
        .map(|r| r.key.unwrap_or_default())
        .collect())
}

async fn handle_of(conn: &Connection<Nftables>, key: &str) -> nlink::Result<u64> {
    Ok(conn
        .list_rules("t", Family::Ip)
        .await?
        .into_iter()
        .find(|r| r.key.as_deref() == Some(key))
        .unwrap_or_else(|| panic!("rule {key} is installed"))
        .handle)
}

async fn packets_of(conn: &Connection<Nftables>, key: &str) -> nlink::Result<u64> {
    Ok(conn
        .list_rules("t", Family::Ip)
        .await?
        .into_iter()
        .find(|r| r.key.as_deref() == Some(key))
        .unwrap_or_else(|| panic!("rule {key} is installed"))
        .counter()
        .expect("rule has a counter")
        .0)
}

/// A rule declared between two installed rules lands between them — and
/// the traffic shows it: `count9` only counts if it sits before `drop9`.
#[tokio::test]
async fn a_rule_declared_between_installed_rules_lands_there() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-rule-mid")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let first = |r: Rule| r.match_udp_dport(1).counter();
        let count9 = |r: Rule| r.match_udp_dport(9).counter().accept();
        let drop9 = |r: Rule| r.match_udp_dport(9).drop();

        let before: Vec<KeyedRule> = vec![("first", first), ("drop9", drop9)];
        cfg(before).diff(&conn).await?.apply(&conn).await?;

        let after: Vec<KeyedRule> =
            vec![("first", first), ("count9", count9), ("drop9", drop9)];
        let after = cfg(after);
        after.diff(&conn).await?.apply(&conn).await?;

        assert_eq!(keys(&conn).await?, ["first", "count9", "drop9"]);
        send_udp(&ns, &["127.0.0.1:9"], 3);
        assert!(
            packets_of(&conn, "count9").await? >= 3,
            "count9 never saw the datagrams: it is not ahead of drop9",
        );
        let again = after.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}

/// `[a, b, c]` re-declared as `[c, a, b]` moves only `c`: `a` and `b` keep
/// their handles (and so their counters).
#[tokio::test]
async fn reordering_moves_only_the_rules_that_must_move() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-rule-reorder")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let a = |r: Rule| r.match_udp_dport(1).counter();
        let b = |r: Rule| r.match_udp_dport(2).counter();
        let c = |r: Rule| r.match_udp_dport(3).counter();
        let abc: Vec<KeyedRule> = vec![("a", a), ("b", b), ("c", c)];
        cfg(abc).diff(&conn).await?.apply(&conn).await?;
        let (ha, hb, hc) = (
            handle_of(&conn, "a").await?,
            handle_of(&conn, "b").await?,
            handle_of(&conn, "c").await?,
        );

        let cab: Vec<KeyedRule> = vec![("c", c), ("a", a), ("b", b)];
        let cab = cfg(cab);
        let diff = cab.diff(&conn).await?;
        assert_eq!(nft::moved(&diff).len(), 1, "only c moves: {diff}");
        diff.apply(&conn).await?;

        assert_eq!(keys(&conn).await?, ["c", "a", "b"]);
        assert_eq!(handle_of(&conn, "a").await?, ha);
        assert_eq!(handle_of(&conn, "b").await?, hb);
        assert_ne!(handle_of(&conn, "c").await?, hc);
        let again = cab.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}

/// The kernel echoes a counter's live values; a declared `.counter()` rule
/// that has seen traffic must still compare equal — and keep its count.
#[tokio::test]
async fn a_counter_that_has_counted_is_left_alone() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-rule-counter")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let counted: Vec<KeyedRule> =
            vec![("count9", |r| r.match_udp_dport(9).counter())];
        let config = cfg(counted);
        config.diff(&conn).await?.apply(&conn).await?;
        send_udp(&ns, &["127.0.0.1:9"], 4);
        assert!(packets_of(&conn, "count9").await? >= 4);

        let again = config.diff(&conn).await?;
        assert!(again.is_empty(), "live counter values are not drift: {again}");
        again.apply(&conn).await?;
        assert!(
            packets_of(&conn, "count9").await? >= 4,
            "re-applying reset the counter",
        );
        Ok(())
    })
    .await
}

/// A keyed rule with a human comment keeps its key as identity, and the
/// comment survives next to it.
#[tokio::test]
async fn a_keyed_rule_with_a_comment_keeps_its_identity() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-rule-comment")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let commented: Vec<KeyedRule> =
            vec![("k", |r| r.match_udp_dport(1).comment("allow the thing"))];
        let config = cfg(commented);
        config.diff(&conn).await?.apply(&conn).await?;

        let rule = conn.list_rules("t", Family::Ip).await?.remove(0);
        assert_eq!(rule.key.as_deref(), Some("k"));
        // The key has its own TLV (#527): the comment is the user's alone,
        // and `nft list` shows nothing of nlink's.
        assert_eq!(rule.comment_text.as_deref(), Some("allow the thing"));
        let listed = ns.exec("nft", &["list", "table", "ip", "t"])?;
        assert!(listed.contains("comment \"allow the thing\""), "{listed}");
        assert!(!listed.contains("nlink:"), "{listed}");
        let again = config.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");

        // A comment-only change is an in-place replace, not a new rule.
        let edited: Vec<KeyedRule> =
            vec![("k", |r| r.match_udp_dport(1).comment("allow the other thing"))];
        let diff = cfg(edited).diff(&conn).await?;
        assert_eq!(nft::replaced(&diff).len(), 1, "{diff}");
        assert_eq!(diff.change_count(), 1, "{diff}");
        Ok(())
    })
    .await
}

/// A key that cannot fit in the comment is an error, not a rule installed
/// without an identity.
#[tokio::test]
async fn an_overlong_key_is_an_error() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-rule-longkey")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let key = "k".repeat(122);
        let config = NftablesConfig::new().table("t", Family::Ip, move |t| {
            t.chain("out", |c| {
                c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
            })
            .rule_keyed("out", key.clone(), |r| r.match_udp_dport(1))
        });
        let err = config.diff(&conn).await.expect_err("a 122-byte key cannot be stored");
        assert!(err.to_string().contains("key"), "{err}");
        Ok(())
    })
    .await
}

/// Rules declared without a key converge too: a second apply neither adds
/// them again nor reports them.
#[tokio::test]
async fn unkeyed_rules_converge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-rule-unkeyed")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let config = NftablesConfig::new().table("t", Family::Ip, |t| {
            t.chain("out", |c| {
                c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
            })
            .rule("out", |r| r.match_udp_dport(1).counter())
            .rule("out", |r| r.match_udp_dport(2).counter())
            // Two identical unkeyed rules are two rules.
            .rule("out", |r| r.match_udp_dport(2).counter())
        });
        config.diff(&conn).await?.apply(&conn).await?;
        config.diff(&conn).await?.apply(&conn).await?;

        assert_eq!(conn.list_rules("t", Family::Ip).await?.len(), 3);
        let again = config.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}

/// Two kernel rules carrying the same key: the first is the match, the
/// other is deleted.
#[tokio::test]
async fn duplicate_keyed_rules_are_cleaned_up() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-rule-dup")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let one: Vec<KeyedRule> = vec![("k", |r| r.match_udp_dport(1))];
        let config = cfg(one);
        config.diff(&conn).await?.apply(&conn).await?;
        // A second rule carrying the same identity, as an older apply that
        // raced another would leave behind.
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_udp_dport(1)
                .comment("nlink:k"),
        )
        .await?;
        assert_eq!(keys(&conn).await?, ["k", "k"]);

        let diff = config.diff(&conn).await?;
        assert_eq!(nft::count(&diff, "rule", "remove"), 1, "{diff}");
        diff.apply(&conn).await?;
        assert_eq!(keys(&conn).await?, ["k"]);
        let again = config.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}

/// An `exclusive()` chain owns all of its rules: a foreign rule in it is
/// deleted.
#[tokio::test]
async fn an_exclusive_chain_removes_foreign_rules() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-rule-excl")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let config = NftablesConfig::new().table("t", Family::Ip, |t| {
            t.chain("out", |c| {
                c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
                    .exclusive()
            })
            .rule_keyed("out", "k", |r| r.match_udp_dport(1))
        });
        config.diff(&conn).await?.apply(&conn).await?;
        conn.add_rule(Rule::new("t", "out").family(Family::Ip).match_udp_dport(7))
            .await?;

        let diff = config.diff(&conn).await?;
        assert_eq!(
            nft::count(&diff, "rule", "remove"),
            1,
            "the foreign rule goes: {diff}"
        );
        diff.apply(&conn).await?;
        assert_eq!(keys(&conn).await?, ["k"]);
        Ok(())
    })
    .await
}


/// #527: a rule an older nlink wrote — its key inside the comment, as
/// `nlink:<key> <comment>` — keeps its identity and its comment, so the
/// diff neither re-adds nor replaces it.
#[tokio::test]
async fn a_rule_keyed_the_old_way_keeps_its_identity() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-rule-oldkey")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_timeout(async {
        let keyed: Vec<KeyedRule> =
            vec![("k", |r| r.match_udp_dport(1).comment("allow the thing"))];
        let config = cfg(keyed);
        // Create the table and chain, then swap the rule for the old form.
        config.diff(&conn).await?.apply(&conn).await?;
        let handle = conn.list_rules("t", Family::Ip).await?.remove(0).handle;
        conn.del_rule("t", "out", Family::Ip, handle).await?;
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_udp_dport(1)
                .comment("nlink:k allow the thing"),
        )
        .await?;
        assert_eq!(keys(&conn).await?, ["k"]);
        let diff = config.diff(&conn).await?;
        assert!(diff.is_empty(), "the old form is the same rule: {diff}");
        Ok(())
    })
    .await
}
