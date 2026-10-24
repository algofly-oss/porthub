//! Reading what traffic did: nftables rule counters and TC class stats.

use nlink::TcHandle;
use nlink::netlink::nftables::types::Family;
use nlink::netlink::{Connection, Nftables, Route};

/// Packets counted by the `nth` rule of `chain` in table `t` (dump
/// order, which is declaration order for a table nlink wrote).
pub async fn rule_packets(
    conn: &Connection<Nftables>,
    table: &str,
    family: Family,
    chain: &str,
    nth: usize,
) -> nlink::Result<u64> {
    let rules = conn.list_rules(table, family).await?;
    let rule = rules
        .iter()
        .filter(|r| r.chain == chain)
        .nth(nth)
        .unwrap_or_else(|| panic!("no rule #{nth} in chain {chain}"));
    Ok(rule.counter().expect("rule has a counter").0)
}

/// `(packets, bytes)` of the class `handle` on `ifindex`, or `None` when
/// there is no such class (or it reports no basic stats).
pub async fn class_stats(
    conn: &Connection<Route>,
    ifindex: u32,
    handle: TcHandle,
) -> nlink::Result<Option<(u64, u64)>> {
    let classes = conn.get_classes_by_index(ifindex).await?;
    Ok(classes
        .iter()
        .find(|c| c.handle() == handle)
        .and_then(|c| c.stats_basic().map(|s| (s.packets, s.bytes))))
}
