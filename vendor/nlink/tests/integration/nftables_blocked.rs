//! #708: what the diff cannot do is said, in one `blocked` list, and the
//! apply refuses it before it writes anything.
//!
//! The case this adds is a set, object or flowtable the diff recreates
//! while a rule nlink did not write uses it. The kernel refuses to delete
//! what a rule uses (`EBUSY`), and one refused message fails the whole
//! batch. That used to be a log line and then an `EBUSY` at commit; the diff
//! now refuses it with `NotSupported`, naming the set, and nothing changes.

use nlink::netlink::Nftables;
use nlink::netlink::nftables::config::{Blocked, NftDiffOptions, NftItem, NftablesConfig};
use nlink::netlink::nftables::types::{
    BaseChain, Family, FilterHook, PacketField, Priority, SetKeyType,
};

use crate::common::TestNamespace;

fn nft(ns: &TestNamespace, cmd: &str) -> nlink::Result<String> {
    let args: Vec<&str> = cmd.split_whitespace().collect();
    ns.exec("nft", &args)
}

/// Table `t` with a base chain `input`, a set `s` of `key`, and a rule
/// nlink writes that looks the set up.
fn with_set(key: SetKeyType, exclusive: bool) -> NftablesConfig {
    let field = match key {
        SetKeyType::Mark => PacketField::Mark,
        _ => PacketField::Ip4Saddr,
    };
    NftablesConfig::new().table("t", Family::Ip, move |t| {
        t.chain("input", |c| {
            let c = c.base(BaseChain::filter(FilterHook::Input, Priority::Filter));
            if exclusive { c.exclusive() } else { c }
        })
        .set("s", |s| s.key_type(key))
        .rule_keyed("input", "ours", move |r| {
            r.match_in_set(field, "s").counter()
        })
    })
}

#[tokio::test]
async fn a_set_a_foreign_rule_uses_is_not_recreated() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_tables");
    let ns = TestNamespace::new("nft-blocked-set")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_set(SetKeyType::Ipv4Addr, false)
        .diff(&conn)
        .await?
        .apply(&conn)
        .await?;
    nft(&ns, "add rule ip t input ip saddr @s drop")?;
    let before = nft(&ns, "list table ip t")?;

    // The key changes: the set is recreated, and our rule moves out of its
    // way, but the hand-added one cannot.
    let diff = with_set(SetKeyType::Mark, false).diff(&conn).await?;
    let [Blocked::Bound { item, rules }] = diff.blocked.as_slice() else {
        panic!("one bound set: {diff}");
    };
    assert_eq!(
        *item,
        NftItem::Set {
            table: "t".into(),
            family: Family::Ip,
            name: "s".into()
        }
    );
    assert_eq!(rules.len(), 1, "{diff}");
    assert_eq!(rules[0].key, None);
    assert_eq!(rules[0].nft.as_deref(), Some("ip saddr @s drop"));
    assert!(
        diff.to_string().contains("set Ip t/s (recreate refused"),
        "{diff}"
    );
    let err = diff
        .apply(&conn)
        .await
        .expect_err("the recreate is refused");
    assert!(err.is_not_supported(), "{err}");
    assert_eq!(
        err.object(),
        Some(&nlink::ErrorObject::NftSet {
            family: "ip".into(),
            table: "t".into(),
            name: "s".into(),
        }),
        "{err}"
    );
    assert_eq!(nft(&ns, "list table ip t")?, before, "nothing changed");
    Ok(())
}

/// In an exclusive chain the hand-added rule is the diff's to delete, so
/// nothing binds the set and it is recreated.
#[tokio::test]
async fn an_exclusive_chain_lets_its_set_be_recreated() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_tables");
    let ns = TestNamespace::new("nft-blocked-excl")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_set(SetKeyType::Ipv4Addr, true)
        .diff(&conn)
        .await?
        .apply(&conn)
        .await?;
    nft(&ns, "add rule ip t input ip saddr @s drop")?;
    let cfg = with_set(SetKeyType::Mark, true);
    let diff = cfg.diff(&conn).await?;
    assert!(diff.blocked.is_empty(), "{diff}");
    diff.apply(&conn).await?;
    assert!(cfg.diff(&conn).await?.is_empty());
    assert!(!nft(&ns, "list table ip t")?.contains("drop"));
    Ok(())
}

/// A hand-added rule in an undeclared chain the diff keeps, because another
/// hand-added rule jumps to it, binds the set too. The check used to look
/// only at declared chains.
#[tokio::test]
async fn a_foreign_rule_in_a_kept_chain_binds_its_set() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_tables");
    let ns = TestNamespace::new("nft-blocked-kept")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_set(SetKeyType::Ipv4Addr, false)
        .diff(&conn)
        .await?
        .apply(&conn)
        .await?;
    nft(&ns, "add chain ip t side")?;
    nft(&ns, "add rule ip t side ip saddr @s drop")?;
    nft(&ns, "add rule ip t input jump side")?;
    let diff = with_set(SetKeyType::Mark, false).diff(&conn).await?;
    let kinds: Vec<String> = diff
        .blocked
        .iter()
        .map(|b| match b {
            Blocked::InUse { item, .. } => format!("in use: {item}"),
            Blocked::Bound { item, rules } => format!("bound: {item} by {}", rules[0].chain),
            other => format!("{other:?}"),
        })
        .collect();
    assert_eq!(
        kinds,
        ["in use: chain Ip t/side", "bound: set Ip t/s by side"],
        "{diff}"
    );
    assert!(
        diff.apply(&conn)
            .await
            .expect_err("refused")
            .is_not_supported()
    );
    Ok(())
}

/// Recreating an owned table for a new comment would delete what others
/// put in it; the diff refuses, and the table stays as it is.
#[tokio::test]
async fn a_table_holding_foreign_rules_is_not_recreated() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_tables");
    let ns = TestNamespace::new("nft-blocked-table")?;
    let conn = ns.connection_for::<Nftables>()?;
    let commented = |comment: &str| {
        let comment = comment.to_string();
        NftablesConfig::new().table("t", Family::Ip, move |t| {
            t.comment(comment).chain("input", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
            })
        })
    };
    commented("a").diff(&conn).await?.apply(&conn).await?;
    nft(&ns, "add rule ip t input tcp dport 22 accept")?;
    let options = NftDiffOptions::default().recreate_on_comment_change(true);
    let diff = commented("b").diff_with_options(&conn, &options).await?;
    let [Blocked::TableRecreate { table, rules, .. }] = diff.blocked.as_slice() else {
        panic!("one refused table recreate: {diff}");
    };
    assert_eq!((table.as_str(), rules.len()), ("t", 1), "{diff}");
    assert_eq!(diff.change_count(), 1, "the refusal is all it says: {diff}");
    let err = diff.apply(&conn).await.expect_err("refused");
    assert!(err.is_not_supported(), "{err}");
    assert!(nft(&ns, "list table ip t")?.contains("tcp dport 22 accept"));
    Ok(())
}

/// An object nlink does not model is said, kept and not counted; the apply
/// goes on around it.
#[tokio::test]
async fn an_object_nlink_does_not_model_is_kept_and_said() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_synproxy");
    let ns = TestNamespace::new("nft-blocked-obj")?;
    let conn = ns.connection_for::<Nftables>()?;
    let cfg = with_set(SetKeyType::Ipv4Addr, false);
    cfg.diff(&conn).await?.apply(&conn).await?;
    nft(&ns, "add synproxy ip t syn { mss 1460 wscale 7 }")?;
    let diff = cfg.diff(&conn).await?;
    let [
        Blocked::UnmodelledObject {
            name, object_type, ..
        },
    ] = diff.blocked.as_slice()
    else {
        panic!("one unmodelled object: {diff}");
    };
    // NFT_OBJECT_SYNPROXY.
    assert_eq!((name.as_str(), *object_type), ("syn", 10), "{diff}");
    assert!(diff.is_empty(), "{diff}");
    assert!(
        diff.to_string()
            .contains("object Ip t/syn kept: nlink does not model its type (10)")
    );
    diff.apply(&conn).await?;
    assert!(nft(&ns, "list table ip t")?.contains("synproxy syn"));
    Ok(())
}
