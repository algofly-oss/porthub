//! What an nftables diff changes, counted the way the tests ask (#708): by
//! kind and op, a recreate's cascade included.

use nlink::netlink::nftables::config::{Change, NftChange, NftElements, NftRule, NftablesDiff};

/// Every change, a recreate's cascade after it.
pub fn all(diff: &NftablesDiff) -> Vec<&NftChange> {
    diff.changes.iter().flat_map(NftChange::flatten).collect()
}

/// How many changes of `kind` do `op`: `count(&diff, "set", "recreate")`.
pub fn count(diff: &NftablesDiff, kind: &str, op: &str) -> usize {
    all(diff)
        .into_iter()
        .filter(|c| c.kind() == kind && c.op() == op)
        .count()
}

/// Each rule update, from where it is to what it becomes.
fn rule_updates(diff: &NftablesDiff) -> impl Iterator<Item = (&NftRule, &NftRule)> {
    all(diff).into_iter().filter_map(|c| match c {
        NftChange::Rule(Change::Update { from, to }) => Some((from, to)),
        _ => None,
    })
}

/// The rules replaced where they are.
pub fn replaced(diff: &NftablesDiff) -> Vec<&NftRule> {
    rule_updates(diff)
        .filter(|(_, to)| to.placement.is_none())
        .map(|(_, to)| to)
        .collect()
}

/// The rules taken out and added again somewhere: a reorder, or a
/// recreate's (then in its cascade).
pub fn moved(diff: &NftablesDiff) -> Vec<&NftRule> {
    rule_updates(diff)
        .filter(|(_, to)| to.placement.is_some())
        .map(|(_, to)| to)
        .collect()
}

/// The element batches `op` (`"add"` or `"remove"`) sends.
pub fn elements<'a>(diff: &'a NftablesDiff, op: &str) -> Vec<&'a NftElements> {
    all(diff)
        .into_iter()
        .filter(|c| c.op() == op)
        .filter_map(|c| match c {
            NftChange::Elements(Change::Add(e) | Change::Remove(e)) => Some(e),
            _ => None,
        })
        .collect()
}
