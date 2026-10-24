//! Policy routing rule integration tests.

use nlink::{AddressFamily, Result};

use crate::common::TestNamespace;

/// The priorities of the IPv4 rules, as `ip rule` lists them.
fn priorities(ns: &TestNamespace) -> Result<Vec<u64>> {
    let out = ns.exec("ip", &["-4", "-j", "rule", "show"])?;
    let all: serde_json::Value = serde_json::from_str(&out).expect("ip -j");
    Ok(all.as_array().into_iter().flatten().filter_map(|r| r["priority"].as_u64()).collect())
}

/// `del_rule_by_priority` deletes the rule at the priority, whatever it
/// does (#667). It sent `lookup main` (action `FR_ACT_TO_TBL`, table 254),
/// and the kernel's `rule_find` matches a delete's action and table when
/// they are set: only a main-table lookup rule was found, and any other —
/// another table, a blackhole — was ENOENT.
#[tokio::test]
async fn del_rule_by_priority_deletes_any_rule_there() -> Result<()> {
    nlink::require_root!();

    let ns = TestNamespace::new("ruledel")?;
    let conn = ns.connection()?;
    ns.exec("ip", &["rule", "add", "pref", "100", "from", "10.0.0.0/8", "table", "100"])?;
    ns.exec("ip", &["rule", "add", "pref", "101", "prohibit"])?;
    ns.exec("ip", &["rule", "add", "pref", "102", "from", "10.1.0.0/16", "table", "main"])?;
    for p in [100, 101, 102] {
        conn.del_rule_by_priority(AddressFamily::v4(), p).await?;
    }
    assert_eq!(priorities(&ns)?, [0, 32766, 32767]);
    Ok(())
}

/// `flush_rules` removes every rule but the kernel's defaults (#667). It
/// deleted by priority and ignored the error, so it removed only the
/// main-table lookup rules and said nothing about the rest.
#[tokio::test]
async fn flush_rules_removes_every_rule_but_the_defaults() -> Result<()> {
    nlink::require_root!();

    let ns = TestNamespace::new("ruleflush")?;
    let conn = ns.connection()?;
    ns.exec("ip", &["rule", "add", "pref", "100", "fwmark", "0x1", "table", "200"])?;
    ns.exec("ip", &["rule", "add", "pref", "110", "blackhole"])?;
    ns.exec("ip", &["rule", "add", "pref", "120", "iif", "lo", "table", "main"])?;
    conn.flush_rules(AddressFamily::v4()).await?;
    assert_eq!(priorities(&ns)?, [0, 32766, 32767]);
    Ok(())
}

/// A rule that does not look a table up is added with none, as `ip rule`
/// adds it (#667): `RuleBuilder` sent table 254 for a blackhole too.
#[tokio::test]
async fn a_rule_that_drops_has_no_table() -> Result<()> {
    use nlink::netlink::rule::RuleBuilder;
    nlink::require_root!();

    let ns = TestNamespace::new("ruledrop")?;
    let conn = ns.connection()?;
    conn.add_rule(RuleBuilder::v4().priority(100).prohibit()).await?;
    conn.add_rule(RuleBuilder::v4().priority(110).from_prefix("10.0.0.0", 8).table(100)).await?;
    let out = ns.exec("ip", &["-4", "-d", "-j", "rule", "show"])?;
    let all: serde_json::Value = serde_json::from_str(&out).expect("ip -j");
    let at = |p: u64| all.as_array().into_iter().flatten().find(|r| r["priority"] == p).cloned();
    let prohibit = at(100).expect("rule 100");
    assert_eq!(prohibit["action"], "prohibit", "{prohibit}");
    assert!(prohibit.get("table").is_none(), "{prohibit}");
    assert_eq!(at(110).expect("rule 110")["table"], "100");
    Ok(())
}
