//! Internal scaffolding for TC-recipe `reconcile()` flows.
//!
//! Both [`PerPeerImpairer`] and [`PerHostLimiter`] build trees of the
//! shape:
//!
//! ```text
//! root HTB qdisc (1:)
//!   └── parent class 1:1
//!         ├── per-rule class 1:N → leaf qdisc (kind varies) [+ flower filter]
//!         └── default class      → leaf qdisc
//! ```
//!
//! [`LiveTree`] is the reconciliation-time snapshot of that shape, built
//! from three RTNETLINK dumps: qdiscs, classes, and filters at the root
//! parent. The diff logic itself lives in each helper (the recipes
//! disagree on rule shape and leaf kind), but the dump and the equality
//! primitives are shared here.
//!
//! [`PerPeerImpairer`]: super::impair::PerPeerImpairer
//! [`PerHostLimiter`]: super::ratelimit::PerHostLimiter

use std::collections::BTreeMap;

use super::{
    Connection,
    error::Result,
    messages::TcMessage,
    protocol::Route,
    tc::NetemConfig,
    tc_handle::TcHandle,
    tc_options::{HtbClassOptions, HtbOptions, QdiscOptions, parse_htb_class_options},
};

/// Minor of the recipe's default class, and of its leaf qdisc's major.
///
/// **Deliberately not derived from the rule count.** It used to be
/// `n + 2`, one past the last rule's class, which meant editing the
/// rule list moved the default class — and the HTB `default` naming it
/// had to move with it. `htb` has no `.change` operation at all:
///
/// ```text
/// # tc qdisc change dev d0 root handle 1: htb default 3
/// Error: Change operation not supported by specified qdisc.
/// ```
///
/// so `reconcile()` could not follow. Adding or removing a rule made it
/// fail outright with `EINVAL`, which is the one thing reconcile exists
/// to handle. Pinning the default out of the rules' range means the
/// `defcls` written at creation stays correct for the tree's whole life
/// (#269, #291).
///
/// Rule classes occupy `1:2 ..= 1:n+1`, so `0xFFFF` cannot collide
/// unless someone configures 65533 rules.
pub(crate) const DEFAULT_CLASS_MINOR: u16 = 0xFFFF;

/// Major of the default class's leaf qdisc: `8000:`.
///
/// Out of the rules' leaves (`10 + i`), like the class minor, and out of the
/// two ranges the kernel guards. It was `ffff:`, which is the ingress and
/// clsact qdisc's handle (`TC_H_INGRESS`'s major), so a recipe could not be
/// applied next to either — "Cannot move an existing qdisc to a different
/// parent" — including nlink's own `RateLimiter` ingress half (#485). And
/// `qdisc_alloc_handle` hands out `8001:`–`fffe:` to qdiscs added without a
/// handle; `8000:` is the one major below that range it never reaches.
///
/// `reconcile()` replaces a default leaf at any other handle — the
/// `ffff:` of a recipe applied before 0.31 — with one here.
pub(crate) const DEFAULT_LEAF_MAJOR: u16 = 0x8000;

/// Snapshot of one device's TC tree at the moment `reconcile()` ran.
///
/// Populated via [`dump_live_tree()`].
#[derive(Debug, Default)]
pub(crate) struct LiveTree {
    /// The qdisc whose parent is `TcHandle::ROOT` (if any).
    pub(crate) root_qdisc: Option<TcMessage>,
    /// Every class on the device, keyed by its handle.
    pub(crate) classes: BTreeMap<TcHandle, TcMessage>,
    /// Every non-root qdisc on the device, keyed by its parent (the
    /// class that owns it). Each rule's leaf qdisc lives here.
    pub(crate) leaf_qdiscs: BTreeMap<TcHandle, TcMessage>,
    /// Filters whose parent is the root qdisc handle (`1:`), keyed by
    /// `(priority, classid)`. Recipe filters land here.
    pub(crate) root_filters: Vec<TcMessage>,
}

impl LiveTree {
    /// Look up a class by its handle.
    pub(crate) fn class(&self, handle: TcHandle) -> Option<&TcMessage> {
        self.classes.get(&handle)
    }

    /// Look up the leaf qdisc whose parent is `class_handle`.
    pub(crate) fn leaf_for(&self, class_handle: TcHandle) -> Option<&TcMessage> {
        self.leaf_qdiscs.get(&class_handle)
    }

    /// The root qdisc, if one was *configured* rather than implied.
    ///
    /// Every interface always has a root qdisc: the kernel installs
    /// `noqueue`, `pfifo_fast`, `net.core.default_qdisc` or `mq`
    /// implicitly. Those carry **handle 0** — `qdisc_create` only calls
    /// `qdisc_alloc_handle()` for a qdisc someone asked for. Reading
    /// `root_qdisc` directly made the recipes' "nothing installed yet"
    /// arm unreachable, so `reconcile()` could never bootstrap and
    /// always demanded `with_fallback_to_apply(true)` (#287).
    pub(crate) fn configured_root_qdisc(&self) -> Option<&TcMessage> {
        self.root_qdisc.as_ref().filter(|q| q.handle_raw() != 0)
    }

    /// Look up a filter at the root parent by priority.
    pub(crate) fn filter_at_priority(
        &self,
        priority: crate::netlink::tc_handle::FilterPriority,
    ) -> Option<&TcMessage> {
        self.root_filters.iter().find(|f| f.priority() == priority)
    }
}

/// Dump the qdiscs, classes, and root-parent filters for `ifindex`.
///
/// The resulting tree is the input to each recipe's diff function. We
/// do not dump filters at every parent — recipe helpers only ever
/// install filters at the root HTB qdisc parent (`1:`).
pub(crate) async fn dump_live_tree(conn: &Connection<Route>, ifindex: u32) -> Result<LiveTree> {
    let mut tree = LiveTree::default();

    // Qdiscs: split into root + leaves keyed by parent.
    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    for q in qdiscs {
        if q.parent().is_root() {
            tree.root_qdisc = Some(q);
        } else {
            tree.leaf_qdiscs.insert(q.parent(), q);
        }
    }

    // Classes keyed by handle.
    let classes = conn.get_classes_by_index(ifindex).await?;
    for c in classes {
        tree.classes.insert(c.handle(), c);
    }

    // Filters at the root HTB parent (`1:`). Both helpers install at
    // this parent; if no root HTB exists this returns an empty list.
    let root_parent = TcHandle::major_only(1);
    tree.root_filters = conn
        .get_filters_by_parent_index(ifindex, root_parent)
        .await?;

    Ok(tree)
}

/// Get the parsed HTB qdisc options from a live root qdisc, if present.
pub(crate) fn root_htb_options(tree: &LiveTree) -> Option<HtbOptions> {
    let root = tree.root_qdisc.as_ref()?;
    if root.kind()? != "htb" {
        return None;
    }
    match root.options()? {
        QdiscOptions::Htb(opts) => Some(opts),
        _ => None,
    }
}

/// What keeps the live root qdisc `root` from being the HTB at
/// `root_handle` with default class `default_minor` a recipe builds, if
/// anything: another kind or handle, or another default class. HTB has no
/// change operation, so neither can be fixed in place — a change is always
/// `EINVAL` — and a recipe rebuilds the tree or says what is in the way
/// (#491).
pub(crate) fn root_conflict(
    root: &TcMessage,
    tree: &LiveTree,
    root_handle: TcHandle,
    default_minor: u16,
) -> Option<String> {
    if root.kind() != Some("htb") || root.handle() != root_handle {
        return Some(format!(
            "{:?} (handle {}), not HTB at {root_handle}",
            root.kind(),
            root.handle()
        ));
    }
    let default = root_htb_options(tree).map(|o| o.default_class);
    if default != Some(u32::from(default_minor)) {
        let have = default.map_or_else(|| "?".to_string(), |d| format!("{d:#x}"));
        return Some(format!(
            "HTB at {root_handle} with default class {have}, not {default_minor:#x}: another \
             recipe's tree, or one built before 0.26"
        ));
    }
    None
}

/// Whether the device's root is a tree a recipe built (#515): the HTB at
/// `1:` with default class `default_minor`, whose leaf qdiscs under it are
/// all `leaf_kind`. `PerHostLimiter` and `PerPeerImpairer` build the same
/// root — HTB `1:`, default `0xffff` — and tell their trees apart by the
/// leaves: fq_codel for the one, netem for the other. A recipe's
/// `remove`/`clear` deletes the root only when this holds; it used to delete
/// whatever root the device had.
pub(crate) fn recipe_owns_root(tree: &LiveTree, default_minor: u16, leaf_kind: &str) -> bool {
    let root = TcHandle::major_only(1);
    tree.configured_root_qdisc()
        .is_some_and(|q| root_conflict(q, tree, root, default_minor).is_none())
        && tree
            .leaf_qdiscs
            .values()
            .filter(|q| q.parent().major() == root.major() && q.handle_raw() != 0)
            .all(|q| q.kind() == Some(leaf_kind))
}

/// Get parsed HTB class options for a live class message.
pub(crate) fn htb_class_options(class: &TcMessage) -> Option<HtbClassOptions> {
    if class.kind()? != "htb" {
        return None;
    }
    let raw = class.raw_options()?;
    parse_htb_class_options(raw)
}

/// Compare a desired [`NetemConfig`] against a live netem leaf qdisc.
///
/// Returns `true` when every field that `NetemConfig::write_options`
/// would emit matches the kernel's parsed view of the live qdisc. This
/// is the gate that decides "leave this leaf alone" vs "rewrite it".
pub(crate) fn netem_matches(desired: &NetemConfig, live: &TcMessage) -> bool {
    if live.kind() != Some("netem") {
        return false;
    }
    let Some(QdiscOptions::Netem(live_opts)) = live.options() else {
        return false;
    };

    // Delay / jitter — `delay()` returns Some only when ns > 0.
    if desired.delay != live_opts.delay() {
        return false;
    }
    if desired.jitter != live_opts.jitter() {
        return false;
    }

    // Percentages — desired stores Percent (always present, ZERO meaning
    // "off"); live exposes Option<f64>. Compare via the kernel-side
    // probability so we ignore floating-point representation drift.
    let percent_matches = |desired: crate::util::Percent, live: Option<f64>| -> bool {
        let live_value = live.unwrap_or(0.0);
        let live_kernel = crate::util::Percent::new(live_value).as_kernel_probability();
        desired.as_kernel_probability() == live_kernel
    };

    if !percent_matches(desired.loss, live_opts.loss()) {
        return false;
    }
    if !percent_matches(desired.duplicate, live_opts.duplicate()) {
        return false;
    }
    if !percent_matches(desired.corrupt, live_opts.corrupt()) {
        return false;
    }
    if !percent_matches(desired.reorder, live_opts.reorder()) {
        return false;
    }
    // The correlations too — the declarative form has carried them since
    // #332, and a changed correlation is a changed qdisc (#346).
    if !percent_matches(desired.delay_correlation, live_opts.delay_correlation()) {
        return false;
    }
    if !percent_matches(desired.loss_correlation, live_opts.loss_correlation()) {
        return false;
    }
    if !percent_matches(desired.duplicate_correlation, live_opts.duplicate_correlation()) {
        return false;
    }
    if !percent_matches(desired.corrupt_correlation, live_opts.corrupt_correlation()) {
        return false;
    }
    if !percent_matches(desired.reorder_correlation, live_opts.reorder_correlation()) {
        return false;
    }

    // Reorder gap. NetemConfig::write_options forces gap=1 when
    // reorder is set with no explicit gap — match that quirk.
    let effective_gap = if !desired.reorder.is_zero() && desired.gap == 0 {
        1
    } else {
        desired.gap
    };
    if effective_gap != live_opts.gap {
        return false;
    }

    // Rate (bytes/sec). Desired's `rate` is Option<Rate>; live's is u64
    // (0 == unset). The overheads are echoed as sent.
    let desired_rate = desired.rate.map(|r| r.as_bytes_per_sec()).unwrap_or(0);
    if desired_rate != live_opts.rate
        || desired.rate_packet_overhead != live_opts.packet_overhead
        || desired.rate_cell_size != live_opts.cell_size
        || desired.rate_cell_overhead != live_opts.cell_overhead
    {
        return false;
    }

    // Queue limit. NetemConfig::new() defaults to 1000; live qopt.limit
    // is the same field and is always echoed.
    if desired.limit.as_u32() != live_opts.limit {
        return false;
    }

    // ECN and the slot are always sent, off when unset, so one set outside
    // nlink is a difference a replace closes (#493). A slot's "unlimited"
    // is 0 both ways — the kernel holds it as `INT_MAX` and `netem_dump`
    // turns that back into 0, so a limit of `INT_MAX` or more reads back as
    // 0 too. A slot drawn from a table (`slot distribution …`, which nlink
    // does not write) never matches.
    if desired.ecn != live_opts.ecn {
        return false;
    }
    let limit = |want: Option<u32>, live: i32| {
        let want = want
            .and_then(|n| i32::try_from(n).ok())
            .filter(|&n| n != i32::MAX);
        want.unwrap_or(0) == live
    };
    let nanos = |d: std::time::Duration| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX);
    match (&desired.slot, &live_opts.slot) {
        (None, None) => {}
        (Some(d), Some(l))
            if nanos(d.min_delay) == l.min_delay_ns
                && nanos(d.max_delay) == l.max_delay_ns
                && limit(d.max_packets.map(crate::util::Packets::as_u32), l.max_packets)
                && limit(d.max_bytes, l.max_bytes)
                && l.dist_delay_ns == 0
                && l.dist_jitter_ns == 0 => {}
        _ => return false,
    }
    // A seed is compared only when one is asked for: unasked, the kernel
    // picks one at random, and reports it.
    if desired.seed.is_some() && desired.seed != live_opts.seed() {
        return false;
    }
    // The delay distribution table is not compared: `netem_dump` never
    // reports it (see `NetemDistribution`).

    // Markov loss model (#368). The kernel echoes TCA_NETEM_LOSS only for
    // a model, so "none" on both sides is a match; otherwise compare in the
    // kernel's u32 units, since the read side carries u32 → f64 rounding.
    match (&desired.loss_model, live_opts.loss_model()) {
        (None, None) => {}
        (Some(d), Some(l)) if d.kernel_eq(l) => {}
        _ => return false,
    }

    true
}

/// Compare a desired target latency (used by `PerHostLimiter`'s
/// fq_codel leaves) against a live fq_codel qdisc.
///
/// `PerHostLimiter` only ever sets `target`; the rest of the
/// `FqCodelConfig` is left at the kernel default. We therefore accept
/// any kernel-chosen value for the unset fields and only enforce the
/// `target` field when the recipe sets one.
pub(crate) fn fq_codel_target_matches(desired_target_us: Option<u32>, live: &TcMessage) -> bool {
    if live.kind() != Some("fq_codel") {
        return false;
    }
    let Some(QdiscOptions::FqCodel(opts)) = live.options() else {
        return false;
    };
    // No target is the kernel's default, 5 ms: accepting any live one meant
    // a latency removed from the recipe was never reset (#490). Compared in
    // the kernel's own units.
    codel_round_trip_us(desired_target_us.unwrap_or(5_000)) == opts.target_us
}

/// Microseconds as they come back out of a `codel` time field.
///
/// The wire format is microseconds, but codel stores time in units of
/// 2^-10 seconds:
///
/// ```c
/// #define CODEL_SHIFT 10
/// static inline codel_time_t us_to_codel_time(u64 us)
/// { return (codel_time_t)((us * NSEC_PER_USEC) >> CODEL_SHIFT); }
/// static inline u32 codel_time_to_us(codel_time_t val)
/// { u64 valns = ((u64)val << CODEL_SHIFT); do_div(valns, NSEC_PER_USEC); return valns; }
/// ```
///
/// Both conversions truncate, so most values do not survive the round
/// trip: a 20 ms target is echoed back as 19999 µs. Comparing the
/// requested value against the echo therefore always disagreed, and
/// `reconcile()` rewrote every fq_codel leaf on every pass — an
/// idempotence break of the same shape as the psched-tick one
/// (#191-#194), and for the same reason: comparing a request against a
/// kernel-quantised readback.
pub(crate) fn codel_round_trip_us(us: u32) -> u32 {
    const CODEL_SHIFT: u32 = 10;
    const NSEC_PER_USEC: u64 = 1_000;
    let ticks = (us as u64 * NSEC_PER_USEC) >> CODEL_SHIFT;
    ((ticks << CODEL_SHIFT) / NSEC_PER_USEC) as u32
}

/// Split a netlink attribute blob into `(type, payload)` pairs.
///
/// Shares the walk guards of the crate's other chain walkers: an entry
/// shorter than its header, or one that would run past the end, stops
/// the walk instead of panicking.
fn split_attrs(mut input: &[u8]) -> BTreeMap<u16, &[u8]> {
    let mut out = BTreeMap::new();
    while input.len() >= 4 {
        let Ok(len_bytes) = input[..2].try_into() else {
            break;
        };
        let Ok(type_bytes) = input[2..4].try_into() else {
            break;
        };
        let len = u16::from_ne_bytes(len_bytes) as usize;
        let attr_type = u16::from_ne_bytes(type_bytes) & 0x3FFF;
        if len < 4 || input.len() < len {
            break;
        }
        out.insert(attr_type, &input[4..len]);
        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }
    out
}

/// The flower match *values* the recipe helpers can select on.
///
/// Used to decide whether a live filter matches on something the
/// desired one does not — i.e. whether a rule was *narrowed*.
///
/// Two deliberate exclusions. It is not "all `TCA_FLOWER_KEY_*`",
/// because the kernel echoes attributes nobody wrote
/// (`TCA_FLOWER_KEY_ETH_TYPE` derived from the filter's protocol,
/// `TCA_FLOWER_FLAGS`, `TCA_FLOWER_IN_HW_COUNT`) and treating those as
/// a mismatch would rewrite the filter on every reconcile pass. And it
/// carries no `_MASK` ids: `fl_set_key_val` fills an absent mask with
/// all-ones and dumps it back, so a port rule — where nlink sends the
/// value and no mask — would otherwise always look narrowed. A mask
/// never appears without its value here, so checking the values is
/// enough.
pub(crate) const RECIPE_FLOWER_VALUE_KEYS: &[u16] = {
    use super::types::tc::filter::flower::*;
    &[
        TCA_FLOWER_KEY_IP_PROTO,
        TCA_FLOWER_KEY_IPV4_SRC,
        TCA_FLOWER_KEY_IPV4_DST,
        TCA_FLOWER_KEY_IPV6_SRC,
        TCA_FLOWER_KEY_IPV6_DST,
        TCA_FLOWER_KEY_TCP_SRC,
        TCA_FLOWER_KEY_TCP_DST,
        TCA_FLOWER_KEY_UDP_SRC,
        TCA_FLOWER_KEY_UDP_DST,
        TCA_FLOWER_KEY_PORT_SRC_MIN,
        TCA_FLOWER_KEY_PORT_SRC_MAX,
        TCA_FLOWER_KEY_PORT_DST_MIN,
        TCA_FLOWER_KEY_PORT_DST_MAX,
    ]
};

/// Compare a desired flower filter against a live one, **match keys
/// included**.
///
/// The recipes previously accepted any live filter at the right
/// priority whose kind was `flower` and whose `TCA_FLOWER_CLASSID`
/// pointed at the right class. Since both the priority and the classid
/// are derived from the rule's *index*, editing a rule in place — a
/// different address, a different port, v4 to v6 — changed neither.
/// `reconcile()` reported "no changes" and left the old filter
/// classifying traffic by the old criteria, forever.
///
/// Returns `true` only when
///
/// * the live filter is a flower filter,
/// * its ethertype (`tcm_info`'s protocol) is the desired one,
/// * every attribute the desired filter emits — `TCA_FLOWER_CLASSID`
///   included — is present with a byte-identical payload, and
/// * the live filter selects on no *extra* recipe-vocabulary value.
pub(crate) fn flower_matches(
    desired: &super::filter::FlowerFilter,
    desired_protocol: super::eth_proto::EthProto,
    live: &TcMessage,
) -> bool {
    use super::filter::FilterConfig;

    if live.kind() != Some("flower") {
        return false;
    }
    if live.protocol() != desired_protocol {
        return false;
    }

    let Some(live_raw) = live.raw_options() else {
        return false;
    };
    let live_attrs = split_attrs(live_raw);

    // Serialize the desired filter through the same writer that would
    // install it, so this comparison cannot drift from what we send — under
    // the protocol it is installed with, which is where a flower filter
    // with no ethertype of its own takes one from (#433).
    let mut desired = desired.clone();
    desired.set_protocol(desired_protocol);
    let mut builder = crate::netlink::builder::MessageBuilder::new(0, 0);
    let start = builder.len();
    if desired.write_options(&mut builder).is_err() {
        return false;
    }
    let end = builder.len();
    let desired_blob = builder.as_bytes()[start..end].to_vec();
    let mut desired_attrs = split_attrs(&desired_blob);
    // Under a VLAN tag the kernel dumps the innermost ethertype (#827).
    let echo = super::filter::flower_dumped_eth_type(|id| desired_attrs.get(&id).and_then(|v| v.get(..2)?.try_into().ok()));
    let echoed;
    match echo {
        Some(Some(t)) => {
            echoed = t;
            desired_attrs.insert(super::types::tc::filter::flower::TCA_FLOWER_KEY_ETH_TYPE, &echoed[..]);
        }
        Some(None) => _ = desired_attrs.remove(&super::types::tc::filter::flower::TCA_FLOWER_KEY_ETH_TYPE),
        None => {}
    }

    // Every attribute we would write must be there, byte for byte.
    for (id, want) in &desired_attrs {
        match live_attrs.get(id) {
            Some(have) if have == want => {}
            _ => return false,
        }
    }
    // …and the live filter must not match on anything more than we
    // asked for.
    for id in RECIPE_FLOWER_VALUE_KEYS {
        if live_attrs.contains_key(id) && !desired_attrs.contains_key(id) {
            return false;
        }
    }

    true
}

/// The class a live flower filter sends its matches to
/// (`TCA_FLOWER_CLASSID`), if it is a flower filter that has one.
pub(crate) fn flower_classid(live: &TcMessage) -> Option<TcHandle> {
    use super::types::tc::filter::flower::TCA_FLOWER_CLASSID;

    if live.kind() != Some("flower") {
        return None;
    }
    let attrs = split_attrs(live.raw_options()?);
    let raw: [u8; 4] = attrs.get(&TCA_FLOWER_CLASSID)?.get(..4)?.try_into().ok()?;
    Some(TcHandle::from_raw(u32::from_ne_bytes(raw)))
}

/// Compare desired (rate, ceil) against a live HTB class.
///
/// Compares only the fields the recipes set today; deeper attributes
/// (burst, prio, quantum) are tracked by the kernel but are derived
/// inside [`HtbClassConfig::write_options`] from rate and the default
/// MTU when not explicitly set. Two classes that round-trip through
/// the recipe's defaults will match here even when the kernel has
/// filled in derived burst/cburst values.
/// [`htb_class_rates_match`], and the burst too: a recipe that sets one
/// compares it, and one that does not compares against the default it
/// writes, so a burst removed from the recipe is reset (#490).
pub(crate) fn htb_class_matches(class: &TcMessage, desired: &super::tc::HtbClassConfig) -> bool {
    let Some(opts) = htb_class_options(class) else {
        return false;
    };
    (opts.rate, opts.ceil) == desired.rates_bps() && opts.burst == desired.burst_as_dumped()
}

pub(crate) fn htb_class_rates_match(
    class: &TcMessage,
    desired_rate_bps: u64,
    desired_ceil_bps: u64,
) -> bool {
    let Some(opts) = htb_class_options(class) else {
        return false;
    };
    opts.rate == desired_rate_bps && opts.ceil == desired_ceil_bps
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::netlink::tc::QdiscConfig;
    use crate::util::{Percent, Rate};

    /// Build a `TcMessage` with `kind = "netem"` and an `options` blob
    /// produced by [`NetemConfig::write_options`]. This mirrors what
    /// the kernel echoes back on a qdisc dump.
    fn make_netem_msg(cfg: NetemConfig) -> TcMessage {
        let mut builder = crate::netlink::builder::MessageBuilder::new(0, 0);
        let start = builder.len();
        cfg.write_options(&mut builder).expect("write options");
        let end = builder.len();
        let blob = builder.as_bytes()[start..end].to_vec();

        TcMessage {
            kind: Some("netem".to_string()),
            options: Some(blob),
            ..TcMessage::default()
        }
    }

    #[test]
    fn codel_round_trip_matches_the_kernels_truncation() {
        // us_to_codel_time(20000) = (20000 * 1000) >> 10 = 19531,
        // codel_time_to_us(19531) = (19531 << 10) / 1000 = 19999.
        assert_eq!(codel_round_trip_us(20000), 19999);
        assert_eq!(codel_round_trip_us(0), 0);
        // Both conversions truncate, so the echo is never larger than
        // what was asked for — and, because it is not idempotent, this
        // must be applied to the *desired* value exactly once, never to
        // the value already read back.
        for us in [1u32, 999, 5_000, 20_000, 100_000, 1_000_000] {
            assert!(codel_round_trip_us(us) <= us, "round trip grew {us}");
        }
        assert_eq!(codel_round_trip_us(1_048_576), 1_048_576);
    }

    #[test]
    fn fq_codel_target_matches_accepts_the_kernels_echo() {
        // The leaf `reconcile()` reads back after asking for 20 ms.
        let live = TcMessage {
            kind: Some("fq_codel".to_string()),
            options: Some(fq_codel_options(19999)),
            ..TcMessage::default()
        };
        assert!(fq_codel_target_matches(Some(20_000), &live));
        // A genuinely different target still registers as drift.
        assert!(!fq_codel_target_matches(Some(50_000), &live));
        // No target asked for is the kernel's default, 5 ms, not "anything
        // goes": a dropped latency is reset (#490).
        assert!(!fq_codel_target_matches(None, &live));
        let default = TcMessage {
            kind: Some("fq_codel".to_string()),
            options: Some(fq_codel_options(4999)),
            ..TcMessage::default()
        };
        assert!(fq_codel_target_matches(None, &default));
    }

    /// A `TCA_FQ_CODEL_TARGET`-only options blob.
    fn fq_codel_options(target_us: u32) -> Vec<u8> {
        const TCA_FQ_CODEL_TARGET: u16 = 1;
        let mut out = Vec::new();
        out.extend_from_slice(&8u16.to_ne_bytes());
        out.extend_from_slice(&TCA_FQ_CODEL_TARGET.to_ne_bytes());
        out.extend_from_slice(&target_us.to_ne_bytes());
        out
    }

    // Markov loss models (#368): encoded by `write_options` as a nested
    // TCA_NETEM_LOSS, decoded by the read side, compared in kernel units.
    #[test]
    fn netem_matches_round_trips_loss_models() {
        use crate::netlink::tc::NetemLossModel;
        use crate::util::Percent;
        for model in [
            NetemLossModel::gilbert_elliot(Percent::new(1.0))
                .r(Percent::new(30.0))
                .loss_in_bad(Percent::new(50.0))
                .loss_in_good(Percent::new(0.1)),
            NetemLossModel::gilbert_intuitive(Percent::new(1.0))
                .p31(Percent::new(2.0))
                .p32(Percent::new(3.0))
                .p23(Percent::new(4.0))
                .p14(Percent::new(5.0)),
        ] {
            let desired = NetemConfig::new().loss_model(model).build();
            let live = make_netem_msg(desired.clone());
            let Some(QdiscOptions::Netem(opts)) = live.options() else {
                panic!("netem options did not parse");
            };
            let echoed = opts.loss_model().expect("TCA_NETEM_LOSS did not decode");
            assert!(echoed.kernel_eq(&model), "{model:?} came back as {echoed:?}");
            assert!(netem_matches(&desired, &live), "{model:?} does not match itself");
        }
    }

    #[test]
    fn netem_matches_rejects_a_changed_or_missing_loss_model() {
        use crate::netlink::tc::NetemLossModel;
        use crate::util::Percent;
        let ge = |r: f64| {
            NetemConfig::new()
                .loss_model(NetemLossModel::gilbert_elliot(Percent::new(1.0)).r(Percent::new(r)))
                .build()
        };
        assert!(!netem_matches(&ge(30.0), &make_netem_msg(ge(31.0))));
        // A model where there is none, and none where there is one.
        assert!(!netem_matches(&ge(30.0), &make_netem_msg(NetemConfig::new().build())));
        assert!(!netem_matches(&NetemConfig::new().build(), &make_netem_msg(ge(30.0))));
        // Same probability, different model.
        let gi = NetemConfig::new()
            .loss_model(NetemLossModel::gilbert_intuitive(Percent::new(1.0)))
            .build();
        assert!(!netem_matches(&gi, &make_netem_msg(ge(99.0))));
    }

    /// #493: `qopt.latency` is psched ticks; it was written as µs.
    #[test]
    fn netem_writes_qopt_latency_in_psched_ticks() {
        let cfg = NetemConfig::new()
            .delay(Duration::from_millis(100))
            .jitter(Duration::from_millis(10))
            .build();
        let opts = make_netem_msg(cfg).options.expect("options");
        let latency = u32::from_ne_bytes(opts[0..4].try_into().unwrap());
        let jitter = u32::from_ne_bytes(opts[20..24].try_into().unwrap());
        assert_eq!((latency, jitter), (1_562_500, 156_250));
    }

    /// #493: ECN and a slot set outside nlink survive a replace unless it
    /// sends them off, which `write_options` now does — so the comparison
    /// has to see them, or the replace is never made.
    #[test]
    fn netem_matches_sees_an_external_ecn_or_slot() {
        use crate::netlink::types::tc::qdisc::netem::{TCA_NETEM_ECN, TCA_NETEM_SLOT, TcNetemSlot};
        let desired = NetemConfig::new().delay(Duration::from_millis(50)).build();
        let with = |ty: u16, payload: &[u8]| {
            let mut live = make_netem_msg(desired.clone());
            let opts = live.options.as_mut().unwrap();
            opts.extend_from_slice(&(4 + payload.len() as u16).to_ne_bytes());
            opts.extend_from_slice(&ty.to_ne_bytes());
            opts.extend_from_slice(payload);
            live
        };
        assert!(netem_matches(&desired, &make_netem_msg(desired.clone())));
        assert!(!netem_matches(
            &desired,
            &with(TCA_NETEM_ECN, &1u32.to_ne_bytes())
        ));
        let slot = TcNetemSlot {
            min_delay: 1_000_000,
            max_delay: 2_000_000,
            ..Default::default()
        };
        assert!(!netem_matches(
            &desired,
            &with(TCA_NETEM_SLOT, slot.as_bytes())
        ));
    }

    /// #515: ECN, the slot, the seed and the rate overheads are written,
    /// so they are compared — a reconcile that ignored them would leave a
    /// changed one in place, and one that compared them wrongly would
    /// replace the qdisc forever.
    #[test]
    fn netem_matches_compares_ecn_slot_seed_and_overhead() {
        use crate::netlink::tc::NetemSlot;
        use crate::util::Rate;
        let base = || {
            NetemConfig::new()
                .delay(Duration::from_millis(10))
                .rate(Rate::mbit(1))
                .rate_overhead(20, 53, 5)
                .ecn(true)
                .seed(42)
                .slot(NetemSlot::new(Duration::from_millis(1), Duration::from_millis(2)).packets(crate::util::Packets::new(5)))
        };
        assert!(netem_matches(&base(), &make_netem_msg(base())));
        for (what, other) in [
            ("ecn", base().ecn(false)),
            ("seed", base().seed(43)),
            ("overhead", base().rate_overhead(20, 53, 6)),
            (
                "slot",
                base().slot(NetemSlot::new(
                    Duration::from_millis(1),
                    Duration::from_millis(3),
                )),
            ),
            (
                "slot packets",
                base().slot(NetemSlot::new(
                    Duration::from_millis(1),
                    Duration::from_millis(2),
                )),
            ),
        ] {
            assert!(
                !netem_matches(&base(), &make_netem_msg(other.clone())),
                "{what}"
            );
            assert!(
                !netem_matches(&other, &make_netem_msg(base())),
                "{what}, reversed"
            );
        }
        // No seed asked for accepts whatever the kernel picked.
        let mut unseeded = base();
        unseeded.seed = None;
        assert!(netem_matches(&unseeded, &make_netem_msg(base())));
        // A limit the kernel holds as INT_MAX — unlimited — dumps as 0.
        let slot = NetemSlot::new(Duration::from_millis(1), Duration::from_millis(2));
        let unlimited = make_netem_msg(NetemConfig::new().slot(slot));
        for n in [0, i32::MAX as u32, u32::MAX] {
            assert!(
                netem_matches(&NetemConfig::new().slot(slot.packets(crate::util::Packets::new(n))), &unlimited),
                "{n}"
            );
        }
        assert!(!netem_matches(
            &NetemConfig::new().slot(slot.packets(crate::util::Packets::new(5))),
            &unlimited
        ));
    }

    /// #633: a probability read back is `raw → f64 percent`; turning it
    /// into a raw value again truncated, and lost one unit for about 8 %
    /// of values — 1.2 % loss among them — so those never matched their
    /// own echo and were replaced on every reconcile. Every 0.01 % step.
    #[test]
    fn netem_matches_every_percentage_against_its_echo() {
        use crate::util::Percent;
        let mut never = Vec::new();
        for i in 0..=10_000u32 {
            let p = Percent::new(f64::from(i) / 100.0);
            let cfg = NetemConfig::new()
                .loss(p)
                .duplicate(p)
                .corrupt(p)
                .delay(Duration::from_millis(1))
                .reorder(p)
                .loss_correlation(p);
            if !netem_matches(&cfg, &make_netem_msg(cfg.clone())) {
                never.push(p.as_percent());
            }
        }
        assert!(
            never.is_empty(),
            "{} never converge, e.g. {:?}",
            never.len(),
            &never[..never.len().min(8)]
        );
    }

    #[test]
    fn netem_matches_round_trips_delay_only() {
        let desired = NetemConfig::new().delay(Duration::from_millis(50)).build();
        let live = make_netem_msg(desired.clone());
        assert!(netem_matches(&desired, &live));
    }

    #[test]
    fn netem_matches_rejects_different_delay() {
        let desired = NetemConfig::new().delay(Duration::from_millis(50)).build();
        let other = NetemConfig::new().delay(Duration::from_millis(60)).build();
        let live = make_netem_msg(other);
        assert!(!netem_matches(&desired, &live));
    }

    #[test]
    fn netem_matches_rejects_different_loss() {
        let desired = NetemConfig::new()
            .delay(Duration::from_millis(50))
            .loss(Percent::new(1.0))
            .build();
        let other = NetemConfig::new()
            .delay(Duration::from_millis(50))
            .loss(Percent::new(2.0))
            .build();
        let live = make_netem_msg(other);
        assert!(!netem_matches(&desired, &live));
    }

    #[test]
    fn netem_matches_round_trips_complex_config() {
        let cfg = NetemConfig::new()
            .delay(Duration::from_millis(40))
            .jitter(Duration::from_millis(5))
            .loss(Percent::new(0.5))
            .duplicate(Percent::new(0.1))
            .rate(Rate::mbit(100))
            .build();
        let live = make_netem_msg(cfg.clone());
        assert!(netem_matches(&cfg, &live));
    }

    #[test]
    fn netem_matches_handles_reorder_gap_default() {
        // When reorder is set without an explicit gap, the writer emits
        // gap=1; the comparison must use the same effective value.
        let cfg = NetemConfig::new()
            .delay(Duration::from_millis(20))
            .reorder(Percent::new(2.0))
            .build();
        let live = make_netem_msg(cfg.clone());
        assert!(netem_matches(&cfg, &live));
    }

    #[test]
    fn netem_matches_rejects_non_netem_kind() {
        let desired = NetemConfig::new().delay(Duration::from_millis(50)).build();
        let live = TcMessage::default();
        assert!(!netem_matches(&desired, &live));
    }

// ========================================================================
// #270 — flower match-key comparison
// ========================================================================

    /// Render a `FlowerFilter` the way the kernel would echo it back on a
    /// dump: kind `"flower"`, the writer's own option blob, and `tcm_info`
    /// carrying the ethertype in network order.
    fn live_flower(
        filter: &crate::netlink::filter::FlowerFilter,
        protocol: crate::EthProto,
    ) -> TcMessage {
        use crate::netlink::filter::FilterConfig;

    let mut builder = crate::netlink::builder::MessageBuilder::new(0, 0);
    let start = builder.len();
    filter.write_options(&mut builder).expect("write options");
    let end = builder.len();
    let blob = builder.as_bytes()[start..end].to_vec();

        let mut msg = TcMessage {
            kind: Some("flower".to_string()),
            options: Some(blob),
            ..TcMessage::default()
        };
        msg.header.tcm_info = protocol.as_u16().to_be() as u32;
        msg
    }

    const ETH_P_IP: crate::EthProto = crate::EthProto::IP;
    const ETH_P_IPV6: crate::EthProto = crate::EthProto::IPV6;

    fn dst_v4(addr: &str, prefix: u8, classid: TcHandle) -> crate::netlink::filter::FlowerFilter {
        crate::netlink::filter::FlowerFilter::new()
            .classid(classid)
            .priority(crate::FilterPriority::new(1))
            .dst_ipv4(addr.parse().unwrap(), prefix)
            .build()
    }

#[test]
fn flower_classid_reads_the_target_class() {
    let cid = TcHandle::new(1, 3);
    let live = live_flower(&dst_v4("10.0.0.1", 32, cid), ETH_P_IP);
    assert_eq!(flower_classid(&live), Some(cid));
    let not_flower = TcMessage {
        kind: Some("u32".to_string()),
        ..TcMessage::default()
    };
    assert_eq!(flower_classid(&not_flower), None);
}

#[test]
fn flower_matches_accepts_an_identical_filter() {
    let cid = TcHandle::new(1, 2);
    let f = dst_v4("10.0.0.1", 32, cid);
    assert!(flower_matches(&f, ETH_P_IP, &live_flower(&f, ETH_P_IP)));
}

#[test]
fn flower_matches_rejects_a_different_address() {
    // The bug: same rule index -> same priority and same classid, so
    // the old kind+classid check called this "unchanged".
    let cid = TcHandle::new(1, 2);
    let live = live_flower(&dst_v4("10.0.0.1", 32, cid), ETH_P_IP);
    assert!(!flower_matches(&dst_v4("10.0.0.2", 32, cid), ETH_P_IP, &live));
}

#[test]
fn flower_matches_rejects_a_different_prefix() {
    let cid = TcHandle::new(1, 2);
    let live = live_flower(&dst_v4("10.0.0.0", 24, cid), ETH_P_IP);
    assert!(!flower_matches(&dst_v4("10.0.0.0", 16, cid), ETH_P_IP, &live));
}

#[test]
fn flower_matches_rejects_src_where_dst_was_asked_for() {
    let cid = TcHandle::new(1, 2);
    let live = live_flower(
        &crate::netlink::filter::FlowerFilter::new()
            .classid(cid)
            .priority(crate::FilterPriority::new(1))
            .src_ipv4("10.0.0.1".parse().unwrap(), 32)
            .build(),
        ETH_P_IP,
    );
    assert!(!flower_matches(&dst_v4("10.0.0.1", 32, cid), ETH_P_IP, &live));
}

#[test]
fn flower_matches_rejects_a_v4_rule_turned_v6() {
    let cid = TcHandle::new(1, 2);
    let live = live_flower(&dst_v4("10.0.0.1", 32, cid), ETH_P_IP);
    let want = crate::netlink::filter::FlowerFilter::new()
        .classid(cid)
        .priority(crate::FilterPriority::new(1))
        .dst_ipv6("fd00::1".parse().unwrap(), 128)
        .build();
    assert!(!flower_matches(&want, ETH_P_IPV6, &live));
}

#[test]
fn flower_matches_rejects_a_different_classid() {
    let live = live_flower(&dst_v4("10.0.0.1", 32, TcHandle::new(1, 2)), ETH_P_IP);
    let want = dst_v4("10.0.0.1", 32, TcHandle::new(1, 3));
    assert!(!flower_matches(&want, ETH_P_IP, &live));
}

#[test]
fn flower_matches_rejects_a_live_filter_that_matches_on_more() {
    // Narrowing: the rule used to be "dst 10.0.0.1 tcp/443", it is now
    // just "dst 10.0.0.1". Every attribute the desired filter emits is
    // still present in the live one, so a desired-subset-of-live test
    // alone would wrongly pass.
    let cid = TcHandle::new(1, 2);
    let live = live_flower(
        &crate::netlink::filter::FlowerFilter::new()
            .classid(cid)
            .priority(crate::FilterPriority::new(1))
            .dst_ipv4("10.0.0.1".parse().unwrap(), 32)
            .ipv4()
            .ip_proto_tcp()
            .dst_port(443)
            .build(),
        ETH_P_IP,
    );
    assert!(!flower_matches(&dst_v4("10.0.0.1", 32, cid), ETH_P_IP, &live));
}

#[test]
fn flower_matches_rejects_a_different_port() {
    let cid = TcHandle::new(1, 2);
    let mk = |port: u16| {
        crate::netlink::filter::FlowerFilter::new()
            .classid(cid)
            .priority(crate::FilterPriority::new(1))
            .ipv4()
            .ip_proto_tcp()
            .dst_port(port)
            .build()
    };
    let live = live_flower(&mk(443), ETH_P_IP);
    assert!(flower_matches(&mk(443), ETH_P_IP, &live));
    assert!(!flower_matches(&mk(8443), ETH_P_IP, &live));
}

#[test]
fn flower_matches_rejects_tcp_where_udp_was_asked_for() {
    let cid = TcHandle::new(1, 2);
    let tcp = crate::netlink::filter::FlowerFilter::new()
        .classid(cid)
        .priority(crate::FilterPriority::new(1))
        .ipv4()
        .ip_proto_tcp()
        .dst_port(53)
        .build();
    let udp = crate::netlink::filter::FlowerFilter::new()
        .classid(cid)
        .priority(crate::FilterPriority::new(1))
        .ipv4()
        .ip_proto_udp()
        .dst_port(53)
        .build();
    assert!(!flower_matches(&udp, ETH_P_IP, &live_flower(&tcp, ETH_P_IP)));
}

/// The install path hands the filter its protocol before writing it, and a
/// flower filter with no ethertype of its own takes the protocol as one
/// (#433). The comparison has to do the same, or a filter that relies on it
/// never compares equal to what it installed and is replaced on every
/// reconcile.
#[test]
fn flower_matches_takes_the_ethertype_from_the_protocol_like_the_install_path() {
    let cid = TcHandle::new(1, 2);
    let want = crate::netlink::filter::FlowerFilter::new()
        .classid(cid)
        .priority(crate::FilterPriority::new(1))
        .ip_proto_udp()
        .dst_port(53)
        .build();
    let mut installed = want.clone();
    crate::netlink::filter::FilterConfig::set_protocol(&mut installed, ETH_P_IP);
    let live = live_flower(&installed, ETH_P_IP);
    assert!(flower_matches(&want, ETH_P_IP, &live));
}

#[test]
fn flower_matches_rejects_a_non_flower_filter() {
    let cid = TcHandle::new(1, 2);
    let mut live = live_flower(&dst_v4("10.0.0.1", 32, cid), ETH_P_IP);
    live.kind = Some("u32".to_string());
    assert!(!flower_matches(&dst_v4("10.0.0.1", 32, cid), ETH_P_IP, &live));
}

#[test]
fn split_attrs_stops_on_a_pathological_length() {
    // Rule 2 of the parser-robustness policy: a zero or sub-header
    // length must end the walk, not spin or index out of bounds.
    assert!(split_attrs(&[0, 0, 0, 0]).is_empty());
    assert!(split_attrs(&[2, 0, 1, 0]).is_empty());
    // A length past the end of the buffer is not readable.
    assert!(split_attrs(&[0xFF, 0xFF, 1, 0, 9, 9]).is_empty());
}
}
