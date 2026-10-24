//! Rule identity, comparison and ordering for the declarative diff.
//!
//! Three things a declared chain needs to converge:
//!
//! - **Identity.** A rule's key lives in its comment, `nlink:<key>`. A rule
//!   declared without one gets a key derived from its content
//!   ([`effective_rules`]), so it is matched rather than re-added on every
//!   apply.
//! - **Comparison.** The kernel echoes live state — a counter's packets and
//!   bytes, a quota's consumption — so bodies are compared with that state
//!   zeroed on both sides ([`canonicalize_for_compare`]).
//! - **Order.** First match wins, so declared order is enforced, moving as
//!   few rules as possible ([`plan_chain`]).

use std::collections::{HashMap, HashSet};

use super::diff::{MoveReason, RulePlacement};
use super::types::DeclaredRule;
use crate::netlink::nftables::RuleInfo;
use crate::netlink::error::{Error, Result};

/// The declared rules with every key filled in: explicit keys as given,
/// and for a rule without one, `~` + the FNV-1a-64 of its chain, its
/// expression bytes and its comment — `.N` appended to the Nth identical
/// rule in the same chain.
///
/// The hash is hand-rolled: the key is stored in the kernel, so it has to
/// be the same on every build, which `std`'s `DefaultHasher` does not
/// promise.
pub(crate) fn effective_rules(rules: &[DeclaredRule]) -> Vec<DeclaredRule> {
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    rules
        .iter()
        .map(|rule| {
            if rule.handle_key.is_some() {
                return rule.clone();
            }
            let body = canonical_body(
                &super::diff::lower_to_expression_bytes(&rule.body),
                rule.body.family,
            );
            let base = derived_key(&rule.chain, &body, rule.body.comment_ref());
            let n = seen.entry((rule.chain.clone(), base.clone())).or_insert(0);
            let key = if *n == 0 {
                base
            } else {
                format!("{base}.{n}")
            };
            *n += 1;
            let mut rule = rule.clone();
            rule.handle_key = Some(key);
            rule
        })
        .collect()
}

/// A rule body as the diff compares it: the expression list normalized by
/// its schema, with the live state the kernel echoes (counter values, quota
/// consumption, a dynset timeout's jiffies) zeroed.
pub(crate) fn canonical_body(
    bytes: &[u8],
    family: crate::netlink::nftables::Family,
) -> Vec<u8> {
    let normalized = super::diff::normalize_expressions(bytes);
    canonicalize_for_compare(drop_redundant_guards(normalized, family))
}

/// The expression list without the protocol guards a rule says twice, or
/// that its family implies — what [`guards_for_family`] no longer writes.
/// A rule an older nlink installed with them is the rule declared without
/// them, and is not replaced on upgrade (#708).
///
/// [`guards_for_family`]: crate::netlink::nftables::expr::guards_for_family
fn drop_redundant_guards(bytes: Vec<u8>, family: crate::netlink::nftables::Family) -> Vec<u8> {
    use crate::netlink::nftables::expr::guard_implied;
    use crate::netlink::nftables::{
        MetaKey, NFTA_CMP_DATA, NFTA_CMP_OP, NFTA_CMP_SREG, NFTA_DATA_VALUE, NFTA_EXPR_DATA,
        NFTA_EXPR_NAME, NFTA_LIST_ELEM, NFTA_META_DREG, NFTA_META_KEY,
    };
    // One list element: its whole TLV span, its name and its data's
    // attributes.
    struct Elem<'a> {
        span: std::ops::Range<usize>,
        name: &'a [u8],
        attrs: Vec<(u16, &'a [u8])>,
    }
    let elems: Vec<Elem> = tlvs(&bytes, 0, bytes.len())
        .into_iter()
        .filter(|(ty, _, _)| *ty == NFTA_LIST_ELEM)
        .map(|(_, at, len)| {
            let mut name: &[u8] = &[];
            let mut attrs = Vec::new();
            for (ty, a, l) in tlvs(&bytes, at, len) {
                match ty {
                    NFTA_EXPR_NAME => name = bytes[a..a + l].strip_suffix(b"\0").unwrap_or(&bytes[a..a + l]),
                    NFTA_EXPR_DATA => {
                        attrs = tlvs(&bytes, a, l)
                            .into_iter()
                            .map(|(t, a, l)| (t, &bytes[a..a + l]))
                            .collect();
                    }
                    _ => {}
                }
            }
            Elem {
                span: at - 4..(at + len).next_multiple_of(4).min(bytes.len()),
                name,
                attrs,
            }
        })
        .collect();
    fn attr<'a>(e: &Elem<'a>, id: u16) -> Option<&'a [u8]> {
        e.attrs.iter().find(|(t, _)| *t == id).map(|(_, v)| *v)
    }
    let u32_of = |v: &[u8]| <[u8; 4]>::try_from(v).ok().map(u32::from_be_bytes);
    let guard = |load: &Elem, cmp: &Elem| -> Option<(MetaKey, u8)> {
        if load.name != b"meta" || cmp.name != b"cmp" {
            return None;
        }
        let key = match u32_of(attr(load, NFTA_META_KEY)?)? {
            k if k == MetaKey::NfProto as u32 => MetaKey::NfProto,
            k if k == MetaKey::L4Proto as u32 => MetaKey::L4Proto,
            _ => return None,
        };
        let same_reg = attr(load, NFTA_META_DREG)? == attr(cmp, NFTA_CMP_SREG)?;
        let eq = u32_of(attr(cmp, NFTA_CMP_OP)?)? == 0;
        let data = attr(cmp, NFTA_CMP_DATA)?;
        let value = tlvs(data, 0, data.len())
            .into_iter()
            .find(|(t, _, _)| *t == NFTA_DATA_VALUE)
            .map(|(_, a, l)| &data[a..a + l])?;
        (same_reg && eq && value.len() == 1).then_some((key, value[0]))
    };
    let mut seen: Vec<(MetaKey, u8)> = Vec::new();
    let mut drop = vec![false; elems.len()];
    let mut i = 0;
    while i + 1 < elems.len() {
        if let Some((key, value)) = guard(&elems[i], &elems[i + 1]) {
            if seen.contains(&(key, value)) || guard_implied(family, key, value) {
                drop[i] = true;
                drop[i + 1] = true;
            }
            seen.push((key, value));
            i += 2;
        } else {
            i += 1;
        }
    }
    if !drop.contains(&true) {
        return bytes;
    }
    let mut out = Vec::with_capacity(bytes.len());
    for (e, dropped) in elems.iter().zip(&drop) {
        if !dropped {
            out.extend_from_slice(&bytes[e.span.clone()]);
        }
    }
    out
}

/// The key of a rule declared without one: `~` + the FNV-1a-64 of its
/// chain, canonical body and comment.
fn derived_key(chain: &str, body: &[u8], comment: Option<&str>) -> String {
    let hash = fnv1a64(&[chain.as_bytes(), body, comment.unwrap_or("").as_bytes()]);
    format!("~{hash:016x}")
}

/// The kernel's rules, with each derived (`~`) key computed again from the
/// rule's own canonical body, as [`effective_rules`] computes the declared
/// ones, rather than read from its userdata (#721).
///
/// So a rule matches its declaration whatever the key stored with it says.
/// It was derived by the nlink that installed the rule, from a
/// normalization that may since have changed. Upgrading nlink then
/// replaces no rule. The `.N` ordinal follows kernel order, as the
/// declared one follows declared order.
pub(crate) fn rekey_derived(rules: Vec<RuleInfo>) -> Vec<RuleInfo> {
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    rules
        .into_iter()
        .map(|mut rule| {
            if !rule.key.as_deref().is_some_and(|k| k.starts_with('~')) {
                return rule;
            }
            let comment = rule
                .userdata_raw
                .as_deref()
                .and_then(crate::netlink::nftables::userdata::human_comment_of);
            let base = derived_key(
                &rule.chain,
                &canonical_body(&rule.expression_bytes, rule.family),
                comment.as_deref(),
            );
            let n = seen.entry((rule.chain.clone(), base.clone())).or_insert(0);
            rule.key = Some(if *n == 0 { base.clone() } else { format!("{base}.{n}") });
            *n += 1;
            rule
        })
        .collect()
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

impl super::types::NftablesConfig {
    /// Check the config before any kernel round-trip; [`diff`] calls this
    /// first. Everything here would otherwise fail half-way through an
    /// apply, or — worse — install something that does not mean what was
    /// declared:
    ///
    /// - a rule key must be 1–121 bytes of printable ASCII without spaces,
    ///   not start with `~`, and be unique in its chain;
    /// - a rule's key and comment together must fit the kernel's 127-byte
    ///   comment;
    /// - a declared rule cannot carry a [`position`](crate::netlink::nftables::Rule::position):
    ///   the diff places rules in declared order;
    /// - every declared set element must fit its set;
    /// - a rule's chain must be declared: an undeclared chain is deleted;
    /// - a base chain needs what its table's family has
    ///   ([`BaseChain::check_family`]): a hook the family has (`arp` has
    ///   input and output, `bridge` and `ip` no ingress), `nat` and `route`
    ///   chains only in ip, ip6 and inet tables, and a `nat` chain's
    ///   priority above -200;
    /// - what the deprecated chain setters describe must be a chain: no
    ///   policy without a hook, an ingress or egress hook with a device, a
    ///   `route` chain on output, a `nat` chain off forward and ingress. A
    ///   [`BaseChain`] cannot describe any of these (#708).
    ///
    /// The kernel refuses each of these chains, or — for a hook of another
    /// family — installs something else (#484).
    ///
    /// [`BaseChain`]: crate::netlink::nftables::BaseChain
    /// [`BaseChain::check_family`]: crate::netlink::nftables::BaseChain::check_family
    ///
    /// [`diff`]: Self::diff
    pub fn validate(&self) -> Result<()> {
        for (family, name) in self.absent_tables() {
            if self
                .tables()
                .iter()
                .any(|t| t.family() == *family && t.name() == name)
            {
                return Err(Error::invalid_message(format!(
                    "table {name}: declared and declared absent (#519)"
                )));
            }
        }
        for table in self.tables() {
            for chain in table.chains() {
                validate_chain(table.name(), table.family(), chain)?;
            }
            let mut seen: HashSet<(&str, &str)> = HashSet::new();
            for rule in table.rules() {
                let chain = rule.chain();
                if !table.chains().iter().any(|c| c.name() == chain) {
                    return Err(Error::invalid_message(format!(
                        "{}/{chain}: a rule in a chain the table does not declare, which the \
                         diff deletes; declare the chain",
                        table.name()
                    )));
                }
                rule.body.check()?;
                if rule.body.position.is_some() {
                    return Err(Error::invalid_message(format!(
                        "{}/{chain}: a declared rule cannot carry a position; the diff \
                         places rules in declared order",
                        table.name()
                    )));
                }
                if let Some(key) = rule.handle_key() {
                    validate_key(table.name(), chain, key)?;
                    if !seen.insert((chain, key)) {
                        return Err(Error::invalid_message(format!(
                            "{}/{chain}: rule key `{key}` is declared twice",
                            table.name()
                        )));
                    }
                }
            }
            for rule in effective_rules(table.rules()) {
                crate::netlink::nftables::userdata::encode_rule_userdata(
                    rule.handle_key(),
                    rule.body.comment_ref(),
                )
                .map_err(|e| {
                    Error::invalid_message(format!("{}/{}: {e}", table.name(), rule.chain()))
                })?;
            }
            for set in table.sets() {
                crate::netlink::nftables::connection::check_elements(
                    &set.to_set(table.name(), table.family()),
                    set.elements(),
                    crate::netlink::nftables::connection::ElementWrite::Add,
                )?;
            }
            check_interval_lookups(table)?;
        }
        Ok(())
    }
}

/// A lookup in an interval set of host-order keys needs the key in network
/// order, as the set stores it: a rule that looks a mark up as it is would
/// never match (#703).
fn check_interval_lookups(table: &super::types::DeclaredTable) -> Result<()> {
    use crate::netlink::nftables::types::{ByteorderOp, swaps_range_keys};
    use crate::netlink::nftables::Expr;
    for rule in table.rules() {
        let exprs = rule.exprs()?;
        for (i, expr) in exprs.iter().enumerate() {
            let Expr::Lookup(lookup) = expr else { continue };
            let Some(set) = table.sets().iter().find(|s| s.name() == lookup.set) else {
                continue;
            };
            let converted = i
                .checked_sub(1)
                .is_some_and(|p| matches!(exprs[p], Expr::Byteorder { op: ByteorderOp::Hton, .. }));
            if swaps_range_keys(set.key_type(), set.flags()) && !converted {
                return Err(Error::invalid_message(format!(
                    "{}/{}: set {} is an interval set of {:?} keys, which it keeps in \
                     network order; look it up with `match_in_interval_set`",
                    table.name(),
                    rule.chain(),
                    set.name(),
                    set.key_type()
                )));
            }
        }
    }
    Ok(())
}

/// The chain checks of [`validate`](super::types::NftablesConfig::validate):
/// what the deprecated setters describe that no chain is, and what the
/// table's family does not have ([`BaseChain::family_problem`]).
///
/// [`BaseChain::family_problem`]: crate::netlink::nftables::BaseChain
fn validate_chain(
    table: &str,
    family: crate::netlink::nftables::Family,
    chain: &super::types::DeclaredChain,
) -> Result<()> {
    let problem = chain
        .invalid
        .clone()
        .or_else(|| chain.base().and_then(|base| base.family_problem(family)));
    match problem {
        Some(why) => Err(Error::invalid_message(format!(
            "{table}/{}: {why}",
            chain.name()
        ))),
        None => Ok(()),
    }
}

/// FNV-1a, 64-bit, over `parts`, each followed by a `0xff` separator so
/// `["ab", "c"]` and `["a", "bc"]` differ.
fn fnv1a64(parts: &[&[u8]]) -> u64 {
    parts
        .iter()
        .fold(FNV_OFFSET, |hash, part| fnv_feed(fnv_feed(hash, part), &[0xff]))
}

/// Feed `bytes` into an FNV-1a-64 state.
fn fnv_feed(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Check an explicit rule key: 1–121 bytes (`nlink:<key>` and the NUL must
/// fit the kernel's 128), printable ASCII without spaces (a space separates
/// the key from a comment), and not starting with `~` (reserved for derived
/// keys).
pub(crate) fn validate_key(table: &str, chain: &str, key: &str) -> Result<()> {
    let bad = |why: &str| {
        Err(Error::invalid_message(format!(
            "{table}/{chain}: rule key `{key}` {why}"
        )))
    };
    if key.is_empty() {
        return bad("is empty");
    }
    if key.len() > 121 {
        return bad(&format!(
            "is {} bytes; at most 121 fit in a rule comment",
            key.len()
        ));
    }
    if !key.bytes().all(|b| b.is_ascii_graphic()) {
        return bad("must be printable ASCII without spaces");
    }
    if key.starts_with('~') {
        return bad("starts with `~`, which is reserved for derived keys");
    }
    Ok(())
}

/// Zero the live state the kernel echoes in a rule body, in place, so a
/// declared rule compares equal to its echo however much traffic it has
/// seen: a `counter`'s packets and bytes, a `quota`'s consumed bytes and
/// its depleted flag. Works on [`normalize_tlv`](super::diff::normalize_tlv)
/// output; anything that does not walk as TLVs is left as it is.
pub(crate) fn canonicalize_for_compare(mut bytes: Vec<u8>) -> Vec<u8> {
    use crate::netlink::nftables::{
        NFTA_COUNTER_BYTES, NFTA_COUNTER_PACKETS, NFTA_DYNSET_TIMEOUT, NFTA_EXPR_DATA,
        NFTA_EXPR_NAME, NFTA_LIST_ELEM, NFTA_QUOTA_CONSUMED, NFTA_QUOTA_FLAGS,
        NFT_QUOTA_F_DEPLETED,
    };
    for (ty, elem_at, elem_len) in tlvs(&bytes, 0, bytes.len()) {
        if ty != NFTA_LIST_ELEM {
            continue;
        }
        let mut name: Option<&[u8]> = None;
        let mut data: Option<(usize, usize)> = None;
        for (ty, at, len) in tlvs(&bytes, elem_at, elem_len) {
            match ty {
                NFTA_EXPR_NAME => name = Some(&bytes[at..at + len]),
                NFTA_EXPR_DATA => data = Some((at, len)),
                _ => {}
            }
        }
        let (Some(name), Some((data_at, data_len))) = (name, data) else {
            continue;
        };
        let name = name.strip_suffix(b"\0").unwrap_or(name).to_vec();
        for (ty, at, len) in tlvs(&bytes, data_at, data_len) {
            match (name.as_slice(), ty) {
                (b"counter", NFTA_COUNTER_BYTES | NFTA_COUNTER_PACKETS)
                | (b"quota", NFTA_QUOTA_CONSUMED) => bytes[at..at + len].fill(0),
                (b"quota", NFTA_QUOTA_FLAGS) if len == 4 => {
                    let flags = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
                    let flags = flags & !NFT_QUOTA_F_DEPLETED;
                    bytes[at..at + 4].copy_from_slice(&flags.to_be_bytes());
                }
                (b"dynset", NFTA_DYNSET_TIMEOUT) if len == 8 => {
                    let ms = u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap());
                    bytes[at..at + 8].copy_from_slice(&timeout_step(ms).to_be_bytes());
                }
                _ => {}
            }
        }
    }
    bytes
}

/// A timeout in milliseconds as the kernel can read it back, at any `HZ`:
/// rounded down to a multiple of 20 ms.
///
/// The kernel keeps timeouts in jiffies, converting with
/// `nsecs_to_jiffies64` (rounding down) and back with `jiffies64_to_msecs`
/// (rounding down again), so `1001 ms` reads back as `1000 ms` at `HZ=250`
/// and `1003 ms` at `HZ=300`. 20 ms is a whole number of jiffies at every
/// `HZ` Linux offers (100, 250, 300, 1000), so a value and its read-back
/// always fall in the same 20 ms step — and nlink cannot know the kernel's
/// `HZ`.
pub(crate) fn timeout_step(ms: u64) -> u64 {
    ms - ms % 20
}

/// Each expression of a rule body, as [`canonical_body`] compares it but
/// for the family's guards: normalized, with live state zeroed (#708). The
/// typed lift checks what an item lowers to against these.
pub(crate) fn canonical_elements(bytes: &[u8]) -> Vec<Vec<u8>> {
    let canonical = canonicalize_for_compare(super::diff::normalize_expressions(bytes));
    tlvs(&canonical, 0, canonical.len())
        .into_iter()
        .filter(|(ty, _, _)| *ty == crate::netlink::nftables::NFTA_LIST_ELEM)
        .map(|(_, at, len)| canonical[at..at + len].to_vec())
        .collect()
}

/// The attributes in `buf[at..at + len]`: `(type, payload offset, payload
/// length)`, flag bits masked off. Stops at the first malformed header.
fn tlvs(buf: &[u8], at: usize, len: usize) -> Vec<(u16, usize, usize)> {
    let end = at + len;
    let mut out = Vec::new();
    let mut pos = at;
    while pos + 4 <= end {
        let nla_len = u16::from_ne_bytes([buf[pos], buf[pos + 1]]) as usize;
        let ty = u16::from_ne_bytes([buf[pos + 2], buf[pos + 3]]) & !0xc000;
        if nla_len < 4 || pos + nla_len > end {
            break;
        }
        out.push((ty, pos + 4, nla_len - 4));
        pos += nla_len.next_multiple_of(4);
    }
    out
}

/// One kernel rule as the planner sees it.
#[derive(Debug, Clone)]
pub(crate) struct KernelSlot {
    pub(crate) handle: u64,
    /// nlink key, or `None` for a rule nlink did not write.
    pub(crate) key: Option<String>,
    /// Why it has to move whatever the order: bound to a set or object
    /// this diff recreates, so it is deleted ahead of it and put back
    /// afterwards.
    pub(crate) forced: Option<MoveReason>,
}

/// A declared rule to insert, in emission order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlannedInsert {
    /// Index into the chain's declared rules.
    pub(crate) declared: usize,
    pub(crate) placement: RulePlacement,
    /// Kernel handle being moved, or `None` for a new rule.
    pub(crate) from: Option<u64>,
    pub(crate) reason: MoveReason,
}

/// What one chain needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ChainPlan {
    /// Kernel handles to delete: nlink rules no longer declared, duplicate
    /// keys, and — in an exclusive chain — rules nlink did not write.
    pub(crate) deletes: Vec<u64>,
    /// New and moved rules, in the order they must be sent.
    pub(crate) inserts: Vec<PlannedInsert>,
    /// Rules that stay where they are but whose body or comment changed:
    /// `(handle, declared index)`.
    pub(crate) replaces: Vec<(u64, usize)>,
}

/// Plan one chain: bring the kernel's rules (`kernel`, in chain order) to
/// the declared ones (`declared_keys`, in declared order).
///
/// Rules nlink did not write are fixed points and never touched (unless the
/// chain is `exclusive`, when they are deleted). Of the declared rules
/// already installed, the longest run that is already in declared order
/// stays put; every other declared rule is inserted — or, if installed out
/// of order or `forced`, deleted and re-inserted — immediately before the
/// next staying rule, or after the last one, or at the end of the chain.
///
/// `changed(declared, kernel_pos)` says whether a staying rule's body or
/// comment differs; those are replaced in place. With `enforce_order` off,
/// every installed rule stays and only new rules are placed.
pub(crate) fn plan_chain(
    kernel: &[KernelSlot],
    declared_keys: &[&str],
    changed: impl Fn(usize, usize) -> bool,
    exclusive: bool,
    enforce_order: bool,
) -> ChainPlan {
    let mut plan = ChainPlan::default();
    let by_key: HashMap<&str, usize> = declared_keys
        .iter()
        .enumerate()
        .map(|(i, k)| (*k, i))
        .collect();

    // Match each declared rule to the first kernel rule with its key.
    let mut matched: Vec<Option<usize>> = vec![None; declared_keys.len()];
    for (pos, slot) in kernel.iter().enumerate() {
        match slot.key.as_deref() {
            Some(key) => match by_key.get(key) {
                Some(&i) if matched[i].is_none() => matched[i] = Some(pos),
                // Undeclared, or a second rule with a key already matched.
                _ => plan.deletes.push(slot.handle),
            },
            None if exclusive => plan.deletes.push(slot.handle),
            None => {}
        }
    }

    // The declared rules that may stay, in kernel order.
    let mut candidates: Vec<(usize, usize)> = matched
        .iter()
        .enumerate()
        .filter_map(|(i, pos)| pos.filter(|&p| kernel[p].forced.is_none()).map(|p| (p, i)))
        .collect();
    candidates.sort_unstable();
    let order: Vec<usize> = candidates.iter().map(|&(_, i)| i).collect();
    let staying: HashSet<usize> = if enforce_order {
        longest_increasing(&order)
    } else {
        order.iter().copied().collect()
    };
    let mut staying_sorted: Vec<usize> = staying.iter().copied().collect();
    staying_sorted.sort_unstable();
    let handle_of = |i: usize| RuleHandle(kernel[matched[i].unwrap()].handle);

    let mut before = Vec::new();
    let mut after = Vec::new();
    let mut append = Vec::new();
    for i in (0..declared_keys.len()).filter(|i| !staying.contains(i)) {
        let from = matched[i].map(|p| kernel[p].handle);
        let reason = matched[i]
            .and_then(|p| kernel[p].forced)
            .unwrap_or(MoveReason::Reorder);
        let next = staying_sorted.iter().find(|&&j| j > i);
        let prev = staying_sorted.iter().rev().find(|&&j| j < i);
        let insert = |placement| PlannedInsert {
            declared: i,
            placement,
            from,
            reason,
        };
        match (next, prev) {
            (Some(&j), _) => before.push(insert(RulePlacement::Before(handle_of(j)))),
            (None, Some(&j)) => after.push(insert(RulePlacement::After(handle_of(j)))),
            (None, None) => append.push(insert(RulePlacement::Append)),
        }
    }
    // Inserts before the same anchor go in declared order; inserts after
    // the same anchor go in reverse, each landing right after it.
    after.reverse();
    plan.inserts.extend(before);
    plan.inserts.extend(after);
    plan.inserts.extend(append);

    for &i in &staying_sorted {
        let pos = matched[i].unwrap();
        if changed(i, pos) {
            plan.replaces.push((kernel[pos].handle, i));
        }
    }
    plan
}

use super::diff::RuleHandle;

/// The positions (into `seq`) of one longest strictly increasing
/// subsequence, returned as the set of its values.
fn longest_increasing(seq: &[usize]) -> HashSet<usize> {
    // tails[k] = index into `seq` of the smallest tail of an increasing
    // run of length k + 1; prev links reconstruct the run.
    let mut tails: Vec<usize> = Vec::new();
    let mut prev: Vec<Option<usize>> = vec![None; seq.len()];
    for (i, &v) in seq.iter().enumerate() {
        let k = tails.partition_point(|&t| seq[t] < v);
        if k > 0 {
            prev[i] = Some(tails[k - 1]);
        }
        if k == tails.len() {
            tails.push(i);
        } else {
            tails[k] = i;
        }
    }
    let mut out = HashSet::new();
    let mut cur = tails.last().copied();
    while let Some(i) = cur {
        out.insert(seq[i]);
        cur = prev[i];
    }
    out
}

#[cfg(test)]
mod tests {

    /// A rule an older nlink installed with redundant guards is, to the
    /// diff, the rule written without them (#708); one with a guard its
    /// family needs is not.
    #[test]
    fn redundant_guards_do_not_count() {
        use crate::netlink::nftables::Family;
        use crate::netlink::nftables::expr::{Expr, write_expressions};
        use crate::netlink::nftables::types::{CmpOp, MetaKey, Register, Rule};
        let bytes = |exprs: &[Expr]| {
            let mut b = crate::netlink::builder::MessageBuilder::new(0, 0);
            write_expressions(&mut b, exprs);
            b.as_bytes()[20..].to_vec()
        };
        let guard = |key, value: u8| {
            [
                Expr::Meta { dreg: Register::R0, key },
                Expr::Cmp { sreg: Register::R0, op: CmpOp::Eq, data: vec![value] },
            ]
        };
        let lowered = Rule::new("t", "c").match_tcp_dport(22).match_tcp_sport(1);
        let lowered =
            crate::netlink::nftables::expr::exprs_for_family(&lowered.exprs(), Family::Ip)
                .into_owned();
        let mut old: Vec<Expr> = guard(MetaKey::NfProto, 2).to_vec();
        old.extend(
            Rule::new("t", "c")
                .match_tcp_dport(22)
                .match_tcp_sport(1)
                .exprs(),
        );
        assert_eq!(
            canonical_body(&bytes(&old), Family::Ip),
            canonical_body(&bytes(&lowered), Family::Ip),
            "an implied nfproto guard and a repeated l4proto one"
        );
        // In inet the nfproto guard is the rule's.
        assert_ne!(
            canonical_body(&bytes(&old), Family::Inet),
            canonical_body(&bytes(&lowered), Family::Inet)
        );
    }

    use super::*;

    /// Each chain the kernel would refuse, or read as another chain, and
    /// a rule in an undeclared chain, fail `validate()` (#484). With a
    /// `BaseChain` only the family can be wrong (#708); the matrix is the
    /// one `nftables_chain_kinds` checks against the kernel.
    #[test]
    fn validate_refuses_chains_the_kernel_would_not_take() {
        use crate::netlink::nftables::config::{DeclaredChainBuilder, NftablesConfig};
        use crate::netlink::nftables::{BaseChain, Family, FilterHook, NatHook, Priority};

        let check = |family: Family, base: BaseChain| {
            NftablesConfig::new()
                .table("t", family, move |t| t.chain("c", |c| c.base(base)))
                .validate()
                .map_err(|e| e.to_string())
        };
        let filter = |hook| BaseChain::filter(hook, Priority::Filter);
        let refused = [
            (
                Family::Arp,
                filter(FilterHook::Forward),
                "the arp family has no forward hook",
            ),
            (
                Family::Bridge,
                filter(FilterHook::ingress("d0")),
                "no ingress hook",
            ),
            // ip and ip6 have no ingress hook; only inet has (#708).
            (
                Family::Ip,
                filter(FilterHook::ingress("d0")),
                "no ingress hook",
            ),
            (
                Family::Ip6,
                filter(FilterHook::ingress("d0")),
                "no ingress hook",
            ),
            (
                Family::Inet,
                filter(FilterHook::egress("d0")),
                "no egress hook",
            ),
            (Family::Netdev, filter(FilterHook::Input), "no input hook"),
            (
                Family::Bridge,
                BaseChain::nat(NatHook::Prerouting, Priority::DstNat),
                "the bridge family has no nat chains",
            ),
            (
                Family::Arp,
                BaseChain::route(Priority::Filter),
                "no route chains",
            ),
            (
                Family::Ip,
                BaseChain::nat(NatHook::Prerouting, Priority::Raw),
                "above -200",
            ),
        ];
        for (family, base, want) in refused {
            let err = check(family, base).expect_err(want);
            assert!(err.contains(want), "{family:?}: {err}");
        }
        let accepted = [
            (Family::Arp, filter(FilterHook::Input)),
            (Family::Arp, filter(FilterHook::Output)),
            (Family::Bridge, filter(FilterHook::Forward)),
            (Family::Ip, BaseChain::route(Priority::Filter)),
            (
                Family::Ip6,
                BaseChain::nat(NatHook::Postrouting, Priority::SrcNat),
            ),
            (Family::Inet, filter(FilterHook::ingress(["d0", "d1"]))),
            (Family::Netdev, filter(FilterHook::ingress("d0"))),
            (Family::Netdev, filter(FilterHook::egress("d0"))),
        ];
        for (family, base) in accepted {
            assert_eq!(check(family, base), Ok(()), "{family:?}");
        }
        let regular: fn(DeclaredChainBuilder) -> DeclaredChainBuilder = |c| c;
        assert_eq!(
            NftablesConfig::new()
                .table("t", Family::Inet, |t| t.chain("c", regular))
                .validate()
                .map_err(|e| e.to_string()),
            Ok(())
        );
    }

    /// The deprecated setters can still describe what no chain is; the
    /// config holds the reason and `validate()` reports it (#708).
    #[test]
    #[allow(deprecated)]
    fn validate_refuses_what_the_deprecated_setters_describe() {
        use crate::netlink::nftables::config::{DeclaredChainBuilder, NftablesConfig};
        use crate::netlink::nftables::{ChainType, Family, Hook, Policy, Priority};

        let check = |family: Family, chain: fn(DeclaredChainBuilder) -> DeclaredChainBuilder| {
            NftablesConfig::new()
                .table("t", family, move |t| t.chain("c", chain))
                .validate()
                .map_err(|e| e.to_string())
        };
        type Chain = fn(DeclaredChainBuilder) -> DeclaredChainBuilder;
        let refused: [(Family, Chain, &str); 7] = [
            (Family::Inet, |c| c.policy(Policy::Drop), "a policy needs"),
            (
                Family::Netdev,
                |c| c.hook(Hook::NetdevIngress),
                "an ingress chain needs a device",
            ),
            (
                Family::Inet,
                |c| c.hook(Hook::InetIngress),
                "an ingress chain needs a device",
            ),
            (
                Family::Netdev,
                |c| c.hook(Hook::Egress),
                "an egress chain needs a device",
            ),
            (
                Family::Ip,
                |c| c.hook(Hook::Input).chain_type(ChainType::Route),
                "hooks output only",
            ),
            (
                Family::Ip,
                |c| c.hook(Hook::Forward).chain_type(ChainType::Nat),
                "a nat chain has no forward hook",
            ),
            (
                Family::Ip,
                |c| c.hook(Hook::Input).device("d0"),
                "takes no device",
            ),
        ];
        for (family, chain, want) in refused {
            let err = check(family, chain).expect_err(want);
            assert!(err.contains(want), "{family:?}: {err}");
        }
        // A hook alone is a filter chain at priority 0, as the kernel makes
        // it; the old spellings of ingress mean the family's own.
        let accepted: [(Family, Chain); 3] = [
            (Family::Ip, |c| {
                c.hook(Hook::Input).priority(Priority::Custom(5))
            }),
            (Family::Netdev, |c| c.hook(Hook::NetdevIngress).device("d0")),
            (Family::Inet, |c| c.device("d0").hook(Hook::InetIngress)),
        ];
        for (family, chain) in accepted {
            assert_eq!(check(family, chain), Ok(()), "{family:?}");
        }
    }

    /// A rule in an undeclared chain, and a match no interface could have,
    /// fail `validate()` (#484).
    #[test]
    fn validate_refuses_rules_the_kernel_would_not_take() {
        use crate::netlink::nftables::Family;
        use crate::netlink::nftables::config::NftablesConfig;

        let stray = NftablesConfig::new()
            .table("t", Family::Inet, |t| t.rule("c", |r| r.accept()))
            .validate()
            .expect_err("a rule in an undeclared chain")
            .to_string();
        assert!(stray.contains("does not declare"), "{stray}");
        let long = NftablesConfig::new()
            .table("t", Family::Inet, |t| {
                t.chain("c", |c| c)
                    .rule("c", |r| r.match_iif("sixteen-bytes-xx").accept())
            })
            .validate()
            .expect_err("a 16-byte interface name")
            .to_string();
        assert!(long.contains("longer than 15 bytes"), "{long}");
    }

    #[test]
    fn a_timeout_and_its_read_back_share_a_20ms_step_at_every_hz() {
        // The kernel's round trip: msecs -> jiffies (down) -> msecs (down).
        for hz in [100u64, 250, 300, 1000] {
            for ms in [1u64, 19, 20, 999, 1001, 1500, 3_600_000] {
                let jiffies = (ms * 1_000_000 / (1_000_000_000 / hz)).max(1);
                let read_back = jiffies * 1000 / hz;
                assert_eq!(timeout_step(ms), timeout_step(read_back), "HZ={hz} ms={ms}");
            }
        }
    }

    fn slots(keys: &[Option<&str>]) -> Vec<KernelSlot> {
        keys.iter()
            .enumerate()
            .map(|(i, k)| KernelSlot {
                handle: 100 + i as u64,
                key: k.map(str::to_string),
                forced: None,
            })
            .collect()
    }

    fn plan(kernel: &[KernelSlot], declared: &[&str]) -> ChainPlan {
        plan_chain(kernel, declared, |_, _| false, false, true)
    }

    #[test]
    fn an_up_to_date_chain_needs_nothing() {
        let k = slots(&[Some("a"), Some("b"), Some("c")]);
        assert_eq!(plan(&k, &["a", "b", "c"]), ChainPlan::default());
    }

    #[test]
    fn a_new_rule_goes_before_the_next_declared_one() {
        let k = slots(&[Some("a"), Some("z")]);
        let p = plan(&k, &["a", "m", "z"]);
        assert_eq!(
            p.inserts,
            [PlannedInsert {
                declared: 1,
                placement: RulePlacement::Before(RuleHandle(101)),
                from: None,
                reason: MoveReason::Reorder,
            }]
        );
        assert!(p.deletes.is_empty() && p.replaces.is_empty());
    }

    #[test]
    fn rules_after_the_last_installed_one_go_after_it_in_reverse() {
        let k = slots(&[Some("a")]);
        let p = plan(&k, &["a", "b", "c"]);
        // Each lands right after `a`, so c is sent before b.
        let order: Vec<_> = p.inserts.iter().map(|i| (i.declared, i.placement)).collect();
        assert_eq!(
            order,
            [
                (2, RulePlacement::After(RuleHandle(100))),
                (1, RulePlacement::After(RuleHandle(100))),
            ]
        );
    }

    #[test]
    fn an_empty_chain_is_filled_by_appending_in_order() {
        let p = plan(&[], &["a", "b"]);
        let order: Vec<_> = p.inserts.iter().map(|i| (i.declared, i.placement)).collect();
        assert_eq!(order, [(0, RulePlacement::Append), (1, RulePlacement::Append)]);
    }

    #[test]
    fn a_reorder_moves_only_what_is_out_of_order() {
        // [a, b, c] -> [c, a, b]: a and b stay, c moves before a.
        let k = slots(&[Some("a"), Some("b"), Some("c")]);
        let p = plan(&k, &["c", "a", "b"]);
        assert_eq!(
            p.inserts,
            [PlannedInsert {
                declared: 0,
                placement: RulePlacement::Before(RuleHandle(100)),
                from: Some(102),
                reason: MoveReason::Reorder,
            }]
        );
    }

    #[test]
    fn undeclared_and_duplicate_rules_are_deleted_and_foreign_ones_kept() {
        let k = slots(&[Some("a"), None, Some("gone"), Some("a")]);
        let p = plan(&k, &["a"]);
        assert_eq!(p.deletes, [102, 103]);
        assert!(p.inserts.is_empty());
    }

    #[test]
    fn an_exclusive_chain_deletes_foreign_rules() {
        let k = slots(&[None, Some("a")]);
        let p = plan_chain(&k, &["a"], |_, _| false, true, true);
        assert_eq!(p.deletes, [100]);
    }

    #[test]
    fn a_forced_rule_moves_back_to_its_place() {
        let mut k = slots(&[Some("a"), Some("b"), Some("c")]);
        k[1].forced = Some(MoveReason::BoundToRecreatedSet);
        let p = plan(&k, &["a", "b", "c"]);
        assert_eq!(
            p.inserts,
            [PlannedInsert {
                declared: 1,
                placement: RulePlacement::Before(RuleHandle(102)),
                from: Some(101),
                reason: MoveReason::BoundToRecreatedSet,
            }]
        );
    }

    #[test]
    fn changed_staying_rules_are_replaced_in_place() {
        let k = slots(&[Some("a"), Some("b")]);
        let p = plan_chain(&k, &["a", "b"], |i, _| i == 1, false, true);
        assert_eq!(p.replaces, [(101, 1)]);
        assert!(p.inserts.is_empty());
    }

    #[test]
    fn without_order_enforcement_installed_rules_stay() {
        let k = slots(&[Some("a"), Some("b"), Some("c")]);
        let p = plan_chain(&k, &["c", "a", "b"], |_, _| false, false, false);
        assert!(p.inserts.is_empty());
    }

    #[test]
    fn longest_increasing_keeps_the_longest_ordered_run() {
        assert_eq!(longest_increasing(&[0, 1, 2]), HashSet::from([0, 1, 2]));
        assert_eq!(longest_increasing(&[1, 2, 0]), HashSet::from([1, 2]));
        assert_eq!(longest_increasing(&[3, 0, 1, 2]), HashSet::from([0, 1, 2]));
        assert!(longest_increasing(&[]).is_empty());
    }

    #[test]
    fn fnv_is_the_standard_fnv1a_64() {
        // Reference vectors (the FNV authors' test suite). The derived keys
        // live in kernels, so the hash must never change between builds.
        assert_eq!(fnv_feed(FNV_OFFSET, b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv_feed(FNV_OFFSET, b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv_feed(FNV_OFFSET, b"foobar"), 0x8594_4171_f739_67e8);
        assert_eq!(
            fnv1a64(&[b"a"]),
            fnv_feed(fnv_feed(FNV_OFFSET, b"a"), &[0xff])
        );
        assert_ne!(fnv1a64(&[b"ab", b"c"]), fnv1a64(&[b"a", b"bc"]));
    }

    #[test]
    fn keys_are_validated() {
        assert!(validate_key("t", "c", "ssh").is_ok());
        assert!(validate_key("t", "c", &"k".repeat(121)).is_ok());
        assert!(validate_key("t", "c", &"k".repeat(122)).is_err());
        assert!(validate_key("t", "c", "").is_err());
        assert!(validate_key("t", "c", "has space").is_err());
        assert!(validate_key("t", "c", "~derived").is_err());
    }
}
