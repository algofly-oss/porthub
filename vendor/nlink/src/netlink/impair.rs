//! Per-peer netem impairment helper.
//!
//! Mirrors the structure of [`super::ratelimit::PerHostLimiter`], but with a
//! netem leaf per destination instead of an `fq_codel` leaf under a rate cap.
//! Useful for emulating a shared L2 bridge with per-peer RTT and loss
//! characteristics (radio/satellite labs, geo-distributed WAN simulation).
//!
//! # Topology
//!
//! ```text
//! dev -> HTB root (1:) -> HTB class 1:1 (parent)
//!                          ├── HTB class 1:2 -> netem (peer 1)   <- flower(dst=peer1)
//!                          ├── HTB class 1:3 -> netem (peer 2)   <- flower(dst=peer2)
//!                          ├── HTB class 1:N+1 -> netem (peer N) <- flower(dst=peerN)
//!                          └── HTB class 1:N+2 -> netem (default, optional)
//! ```
//!
//! HTB is used (not PRIO) so that:
//! - Each per-peer class has its own pipe; one peer's bursty traffic does not
//!   starve another peer's traffic.
//! - The default class has explicit semantics via HTB's `default` attribute.
//! - The shape mirrors `PerHostLimiter`, easing maintenance.
//!
//! Per-peer rate caps are supported via [`PeerImpairment::rate_cap`]. When no
//! cap is set, each class gets `rate = ceil = assumed_link_rate` (default
//! [`DEFAULT_ASSUMED_LINK_RATE`], ~80 Gbps), which effectively disables
//! shaping while still satisfying HTB's positive-rate requirement.
//!
//! Filters use `cls_flower` (mainline since Linux 4.2). If the classifier is
//! unloaded, [`PerPeerImpairer::apply`] propagates the kernel `EOPNOTSUPP`
//! with a hint about `modprobe cls_flower`.
//!
//! # Direction
//!
//! Filters match on the packet about to leave `dev` (egress). Symmetric pair
//! impairment (impair the *path* between two peers) requires applying the
//! helper on both ends; the caller owns that fan-out.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # use nlink::Percent;
//! use nlink::netlink::{Connection, Route, namespace};
//! use nlink::netlink::impair::{PerPeerImpairer, PeerImpairment};
//! use nlink::netlink::tc::NetemConfig;
//! use std::time::Duration;
//!
//! let conn: Connection<Route> = Connection::new_in("lab-mgmt")?;
//!
//! PerPeerImpairer::new("vethA-br")
//!     .impair_dst_ip(
//!         "172.100.3.18".parse()?,
//!         NetemConfig::new()
//!             .delay(Duration::from_millis(15))
//!             .loss(Percent::new(1.0))
//!             .build(),
//!     )
//!     .impair_dst_ip(
//!         "172.100.3.19".parse()?,
//!         PeerImpairment::new(
//!             NetemConfig::new()
//!                 .delay(Duration::from_millis(40))
//!                 .loss(Percent::new(5.0))
//!                 .build(),
//!         )
//!         .rate_cap(nlink::Rate::mbit(100)),
//!     )
//!     .apply(&conn).await?;
//! # Ok(())
//! # }
//! ```

use std::net::IpAddr;

use super::{
    Connection,
    config::NetworkConfig,
    error::{Error, Result},
    filter::FlowerFilter,
    interface_ref::InterfaceRef,
    protocol::Route,
    tc::{HtbClassConfig, HtbQdiscConfig, NetemConfig},
    tc_handle::{FilterPriority, TcHandle},
    tc_recipe::{ReconcileOptions, ReconcileReport, StaleObject, UnmanagedObject},
    tc_recipe_internals::{
        DEFAULT_CLASS_MINOR, DEFAULT_LEAF_MAJOR, LiveTree, dump_live_tree, flower_classid,
        flower_matches, htb_class_rates_match, netem_matches, recipe_owns_root, root_conflict,
    },
};
use crate::netlink::eth_proto::EthProto;
use crate::util::Rate;


/// Default link-rate placeholder used to fill HTB rate/ceil when the caller
/// has not specified a per-rule cap.
///
/// 10 GB/s ≈ 80 Gbps. Large enough to be a no-op for any realistic interface,
/// small enough to leave headroom in HTB's internal arithmetic.
pub const DEFAULT_ASSUMED_LINK_RATE: Rate = Rate::bytes_per_sec(10_000_000_000);

// ============================================================================
// PeerMatch
// ============================================================================

/// What a per-peer rule matches on.
///
/// All variants are matched via `cls_flower`. Subnet variants accept a prefix
/// length up to 32 (IPv4) / 128 (IPv6); larger values are clamped.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PeerMatch {
    /// Match exactly one destination IP.
    DstIp(IpAddr),
    /// Match a destination subnet.
    DstSubnet(IpAddr, u8),
    /// Match a destination MAC.
    DstMac([u8; 6]),
    /// Match exactly one source IP.
    SrcIp(IpAddr),
    /// Match a source subnet.
    SrcSubnet(IpAddr, u8),
    /// Match a source MAC.
    SrcMac([u8; 6]),
}

// ============================================================================
// PeerImpairment
// ============================================================================

/// A netem configuration plus an optional HTB rate cap.
///
/// Implements `From<NetemConfig>` so callers can pass a bare `NetemConfig`
/// when no rate cap is needed.
#[derive(Debug, Clone)]
pub struct PeerImpairment {
    netem: NetemConfig,
    rate_cap: Option<Rate>,
}

impl PeerImpairment {
    /// Wrap a `NetemConfig` with no rate cap.
    pub fn new(netem: NetemConfig) -> Self {
        Self {
            netem,
            rate_cap: None,
        }
    }

    /// Set a rate cap on the per-peer pipe.
    pub fn rate_cap(mut self, rate: Rate) -> Self {
        self.rate_cap = Some(rate);
        self
    }

    /// Borrow the netem leaf configuration.
    pub fn netem(&self) -> &NetemConfig {
        &self.netem
    }

    /// Get the rate cap, if any.
    pub fn cap(&self) -> Option<Rate> {
        self.rate_cap
    }
}

impl From<NetemConfig> for PeerImpairment {
    fn from(netem: NetemConfig) -> Self {
        Self::new(netem)
    }
}

// ============================================================================
// PerPeerImpairer
// ============================================================================

#[derive(Debug, Clone)]
struct PeerRule {
    match_: PeerMatch,
    impairment: PeerImpairment,
}

/// Per-destination netem impairment on a single interface.
///
/// See the [module docs](self) for an overview and example.
///
/// # Apply contract
///
/// [`PerPeerImpairer::apply`] is destructive: it removes the device's root
/// qdisc before installing the new tree. Filters and classes installed by
/// the caller out-of-band will be wiped.
#[derive(Debug, Clone)]
pub struct PerPeerImpairer {
    target: InterfaceRef,
    rules: Vec<PeerRule>,
    default_impairment: Option<PeerImpairment>,
    assumed_link_rate: Rate,
}

#[nlink_macros::send_futures]
impl PerPeerImpairer {
    /// Create a helper targeting `dev` by name.
    pub fn new(dev: impl Into<String>) -> Self {
        Self::with_target(InterfaceRef::Name(dev.into()))
    }

    /// Create a helper targeting an interface by index.
    ///
    /// Prefer this when the caller has already resolved the interface (e.g.
    /// in a namespace-scoped reconciliation loop) — `apply()` will skip the
    /// implicit `get_link` lookup.
    pub fn new_by_index(ifindex: u32) -> Self {
        Self::with_target(InterfaceRef::Index(ifindex))
    }

    fn with_target(target: InterfaceRef) -> Self {
        Self {
            target,
            rules: Vec::new(),
            default_impairment: None,
            assumed_link_rate: DEFAULT_ASSUMED_LINK_RATE,
        }
    }

    /// Set impairment for traffic that does not match any rule.
    ///
    /// Without this, the default class is a pass-through (HTB class with
    /// no leaf qdisc — packets see the implicit `pfifo`).
    pub fn default_impairment(mut self, imp: impl Into<PeerImpairment>) -> Self {
        self.default_impairment = Some(imp.into());
        self
    }

    /// Override the link-rate placeholder used when a rule has no rate cap.
    ///
    /// The value is clamped to `>= 1` to satisfy HTB's positive-rate
    /// requirement.
    pub fn assumed_link_rate(mut self, rate: Rate) -> Self {
        self.assumed_link_rate = if rate.is_zero() {
            Rate::bytes_per_sec(1)
        } else {
            rate
        };
        self
    }

    // ---- destination matchers ----

    pub fn impair_dst_ip(self, ip: IpAddr, imp: impl Into<PeerImpairment>) -> Self {
        self.add_rule(PeerMatch::DstIp(ip), imp)
    }

    pub fn impair_dst_subnet(self, subnet: &str, imp: impl Into<PeerImpairment>) -> Result<Self> {
        let (addr, prefix) = parse_subnet(subnet)?;
        Ok(self.impair_dst_subnet_parsed(addr, prefix, imp))
    }

    pub fn impair_dst_subnet_parsed(
        self,
        addr: IpAddr,
        prefix: u8,
        imp: impl Into<PeerImpairment>,
    ) -> Self {
        self.add_rule(PeerMatch::DstSubnet(addr, prefix), imp)
    }

    pub fn impair_dst_mac(self, mac: [u8; 6], imp: impl Into<PeerImpairment>) -> Self {
        self.add_rule(PeerMatch::DstMac(mac), imp)
    }

    // ---- source matchers ----

    pub fn impair_src_ip(self, ip: IpAddr, imp: impl Into<PeerImpairment>) -> Self {
        self.add_rule(PeerMatch::SrcIp(ip), imp)
    }

    pub fn impair_src_subnet(self, subnet: &str, imp: impl Into<PeerImpairment>) -> Result<Self> {
        let (addr, prefix) = parse_subnet(subnet)?;
        Ok(self.impair_src_subnet_parsed(addr, prefix, imp))
    }

    pub fn impair_src_subnet_parsed(
        self,
        addr: IpAddr,
        prefix: u8,
        imp: impl Into<PeerImpairment>,
    ) -> Self {
        self.add_rule(PeerMatch::SrcSubnet(addr, prefix), imp)
    }

    pub fn impair_src_mac(self, mac: [u8; 6], imp: impl Into<PeerImpairment>) -> Self {
        self.add_rule(PeerMatch::SrcMac(mac), imp)
    }

    fn add_rule(mut self, match_: PeerMatch, imp: impl Into<PeerImpairment>) -> Self {
        self.rules.push(PeerRule {
            match_,
            impairment: imp.into(),
        });
        self
    }

    // ---- introspection ----

    pub fn target(&self) -> &InterfaceRef {
        &self.target
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Resolved interface index (only present when constructed by index).
    pub fn ifindex(&self) -> Option<u32> {
        self.target.as_index()
    }

    // ---- apply / clear ----

    /// This impairer as a declaration (#645): what [`apply`](Self::apply)
    /// installs on the device — the HTB root, `1:1`, a class, netem leaf
    /// and flower filter per rule, and the default class with its netem —
    /// added to `config`, with the same handles and priorities, so either
    /// way of installing it diffs empty against the other. A declaration
    /// names its device, so an impairer made with
    /// [`new_by_index`](Self::new_by_index) is refused.
    pub fn declare(&self, config: NetworkConfig) -> Result<NetworkConfig> {
        let InterfaceRef::Name(dev) = &self.target else {
            return Err(Error::invalid_message(
                "PerPeerImpairer: a declaration names its device; this one has an ifindex",
            ));
        };
        let link_rate = self.assumed_link_rate;
        let parent = TcHandle::new(1, 1);
        let total_rate = self.total_rate();
        Ok(config
            .qdisc(dev, |q| q.htb().default_class(u32::from(DEFAULT_CLASS_MINOR)))
            .tc(dev, |mut t| {
                t = t.class(
                    TcHandle::major_only(1),
                    parent,
                    HtbClassConfig::new(total_rate).ceil(total_rate).build(),
                );
                for (i, rule) in self.rules.iter().enumerate() {
                    let classid = TcHandle::new(1, (i + 2) as u16);
                    let rate = rule.impairment.rate_cap.unwrap_or(link_rate);
                    let priority = filter_priority(i);
                    t = t
                        .class(parent, classid, HtbClassConfig::new(rate).ceil(rate).build())
                        .leaf(
                            classid,
                            TcHandle::major_only((i + 10) as u16),
                            rule.impairment.netem.clone(),
                        )
                        .filter(
                            TcHandle::major_only(1),
                            priority,
                            protocol_for(&rule.match_),
                            build_flower(classid, priority, &rule.match_),
                        );
                }
                let default = TcHandle::new(1, DEFAULT_CLASS_MINOR);
                let rate = self
                    .default_impairment
                    .as_ref()
                    .and_then(|d| d.rate_cap)
                    .unwrap_or(link_rate);
                t = t.class(parent, default, HtbClassConfig::new(rate).ceil(rate).build());
                match &self.default_impairment {
                    Some(d) => t.leaf(default, TcHandle::major_only(DEFAULT_LEAF_MAJOR), d.netem.clone()),
                    None => t,
                }
            }))
    }

    /// [`declare`](Self::declare) into an empty config.
    pub fn to_config(&self) -> Result<NetworkConfig> {
        self.declare(NetworkConfig::new())
    }

    /// Apply the impairment, replacing any existing root qdisc on the device.
    #[tracing::instrument(level = "info", skip_all, fields(target = ?self.target, rules = self.rules.len()))]
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<()> {
        let ifindex = conn.resolve_interface(&self.target).await?;
        let link_rate = self.assumed_link_rate;
        let default_classid_minor = DEFAULT_CLASS_MINOR as u32;

        // Clean slate. A missing root qdisc is fine.
        let _ = conn.del_qdisc_by_index(ifindex, TcHandle::ROOT).await;

        // Root HTB at handle 1:.
        let root_handle = TcHandle::major_only(1);
        let htb_root = HtbQdiscConfig::new()
            .default_class(default_classid_minor)
            .build();
        conn.add_qdisc_by_index_full(ifindex, TcHandle::ROOT, Some(root_handle), htb_root)
            .await
            .map_err(|e| e.with_context("PerPeerImpairer: add HTB root"))?;

        // Parent class 1:1 with rate covering the sum of all children. With
        // each child borrowing from this parent up to their ceil, this lets
        // any child use its full configured rate without contention.
        let parent_classid = TcHandle::new(1, 1);
        let total_rate = self.total_rate();
        let root_cls = HtbClassConfig::new(total_rate).ceil(total_rate).build();
        conn.add_class_by_index(ifindex, TcHandle::major_only(1), parent_classid, root_cls)
            .await
            .map_err(|e| e.with_context("PerPeerImpairer: add HTB parent class 1:1"))?;

        // Per-rule classes + netem leaves + flower filters.
        for (i, rule) in self.rules.iter().enumerate() {
            let classid = TcHandle::new(1, (i + 2) as u16);
            let leaf_handle = TcHandle::major_only((i + 10) as u16);
            let class_rate = rule.impairment.rate_cap.unwrap_or(link_rate);

            let cls = HtbClassConfig::new(class_rate).ceil(class_rate).build();
            conn.add_class_by_index(ifindex, parent_classid, classid, cls)
                .await
                .map_err(|e| e.with_context(format!("PerPeerImpairer: add class {classid}")))?;

            conn.add_qdisc_by_index_full(
                ifindex,
                classid,
                Some(leaf_handle),
                rule.impairment.netem.clone(),
            )
            .await
            .map_err(|e| e.with_context(format!("PerPeerImpairer: add netem leaf at {classid}")))?;

            self.add_filter(conn, ifindex, i, &rule.match_, classid)
                .await?;
        }

        // Default class — receives whatever no filter matched.
        let default_classid = TcHandle::new(1, DEFAULT_CLASS_MINOR);
        let default_leaf_handle = TcHandle::major_only(DEFAULT_LEAF_MAJOR);
        let default_rate = self
            .default_impairment
            .as_ref()
            .and_then(|d| d.rate_cap)
            .unwrap_or(link_rate);
        let default_cls = HtbClassConfig::new(default_rate).ceil(default_rate).build();
        conn.add_class_by_index(ifindex, parent_classid, default_classid, default_cls)
            .await
            .map_err(|e| e.with_context("PerPeerImpairer: add default class"))?;

        if let Some(default) = &self.default_impairment {
            conn.add_qdisc_by_index_full(
                ifindex,
                default_classid,
                Some(default_leaf_handle),
                default.netem.clone(),
            )
            .await
            .map_err(|e| e.with_context("PerPeerImpairer: add default netem leaf"))?;
        }

        Ok(())
    }

    /// Remove the impairment: the device's root qdisc, if it is a tree a
    /// `PerPeerImpairer` built — the HTB `1:` with its default class and
    /// netem leaves (#515). Another root, a user's or a
    /// `PerHostLimiter`'s, is left alone; this deleted whatever root the
    /// device had.
    ///
    /// Idempotent: a missing root qdisc is treated as success.
    #[tracing::instrument(level = "info", skip_all, fields(target = ?self.target))]
    pub async fn clear(&self, conn: &Connection<Route>) -> Result<()> {
        let ifindex = conn.resolve_interface(&self.target).await?;
        let tree = dump_live_tree(conn, ifindex).await?;
        if !recipe_owns_root(&tree, DEFAULT_CLASS_MINOR, "netem") {
            return Ok(());
        }
        match conn.del_qdisc_by_index(ifindex, TcHandle::ROOT).await {
            Ok(()) => Ok(()),
            Err(e) if e.is_not_found() => Ok(()),
            Err(e) => Err(e),
        }
    }

    // ---- reconcile ----

    /// Non-destructively converge the live TC tree to match this
    /// impairer's desired state.
    ///
    /// Unlike [`apply()`], `reconcile()` dumps the existing tree, diffs
    /// it against what the helper would build, and emits the minimum
    /// set of `add_*` / `change_*` / `del_*` operations to converge.
    /// Calling `reconcile()` twice in a row with no other changes makes
    /// **zero** kernel calls on the second invocation
    /// ([`ReconcileReport::is_noop()`] returns `true`).
    ///
    /// Returns a structured [`ReconcileReport`] describing what changed.
    ///
    /// If the live root qdisc is the wrong kind (not HTB), reconcile
    /// returns an error by default. Pass [`ReconcileOptions::with_fallback_to_apply`]`(true)`
    /// to instead trigger a destructive rebuild via [`apply()`].
    ///
    /// [`apply()`]: Self::apply
    #[tracing::instrument(level = "info", skip_all, fields(target = ?self.target, rules = self.rules.len()))]
    pub async fn reconcile(&self, conn: &Connection<Route>) -> Result<ReconcileReport> {
        self.reconcile_with_options(conn, ReconcileOptions::new())
            .await
    }

    /// Compute what [`reconcile()`] would do without making kernel calls.
    ///
    /// The returned report's `dry_run` field is `true` and `changes_made`
    /// counts the operations that *would* have been issued.
    ///
    /// [`reconcile()`]: Self::reconcile
    #[tracing::instrument(level = "info", skip_all, fields(target = ?self.target, rules = self.rules.len()))]
    pub async fn reconcile_dry_run(&self, conn: &Connection<Route>) -> Result<ReconcileReport> {
        self.reconcile_with_options(conn, ReconcileOptions::new().with_dry_run(true))
            .await
    }

    /// [`reconcile()`] with explicit [`ReconcileOptions`].
    ///
    /// [`reconcile()`]: Self::reconcile
    #[tracing::instrument(level = "info", skip_all, fields(target = ?self.target, rules = self.rules.len(), dry_run = opts.dry_run, fallback = opts.fallback_to_apply))]
    pub async fn reconcile_with_options(
        &self,
        conn: &Connection<Route>,
        opts: ReconcileOptions,
    ) -> Result<ReconcileReport> {
        let ifindex = conn.resolve_interface(&self.target).await?;
        // Each attempt dumps the tree again (#532).
        let (mut report, attempts) = opts
            .retry(super::reconcile::transient, || {
                self.reconcile_inner(conn, ifindex, opts)
            })
            .await?;
        report.attempts = attempts;
        Ok(report)
    }

    async fn reconcile_inner(
        &self,
        conn: &Connection<Route>,
        ifindex: u32,
        opts: ReconcileOptions,
    ) -> Result<ReconcileReport> {
        let mut report = ReconcileReport {
            dry_run: opts.dry_run,
            ..ReconcileReport::default()
        };

        let tree = dump_live_tree(conn, ifindex).await?;

        let link_rate = self.assumed_link_rate;
        let total_rate = self.total_rate();
        let parent_classid = TcHandle::new(1, 1);
        let root_handle = TcHandle::major_only(1);
        let default_minor = DEFAULT_CLASS_MINOR;
        let default_classid = TcHandle::new(1, default_minor);
        let default_leaf_handle = TcHandle::major_only(DEFAULT_LEAF_MAJOR);
        let default_rate = self
            .default_impairment
            .as_ref()
            .and_then(|d| d.rate_cap)
            .unwrap_or(link_rate);

        // 1. Root HTB qdisc.
        match tree.configured_root_qdisc() {
            None => {
                // No root qdisc — full build path. Add it.
                if !opts.dry_run {
                    let cfg = HtbQdiscConfig::new()
                        .default_class(default_minor as u32)
                        .build();
                    conn.add_qdisc_by_index_full(ifindex, TcHandle::ROOT, Some(root_handle), cfg)
                        .await
                        .map_err(|e| e.with_context("PerPeerImpairer::reconcile: add HTB root"))?;
                }
                report.changes_made += 1;
                report.root_modified = true;
            }
            Some(q) => {
                // HTB has no change operation, so neither another root nor
                // another default class can be fixed in place. A change
                // was always EINVAL; the default differs on a pre-0.26
                // tree, or under an HTB `1:` another recipe built (#491).
                if let Some(conflict) = root_conflict(q, &tree, root_handle, default_minor) {
                    if opts.fallback_to_apply {
                        if opts.dry_run {
                            // In dry-run with fallback: just report it
                            // would be a full rebuild.
                            report.changes_made += 1;
                            report.root_modified = true;
                            // We can't usefully diff the rest of the
                            // tree under a foreign root.
                            return Ok(report);
                        }
                        // Destructive fallback.
                        return self.apply_as_reconcile(conn).await;
                    }
                    return Err(Error::invalid_message(format!(
                        "PerPeerImpairer::reconcile: root qdisc on ifindex {ifindex} is \
                         {conflict}; pass ReconcileOptions::with_fallback_to_apply(true) to \
                         rebuild"
                    )));
                }
            }
        }

        // 2. Parent class 1:1.
        let total_bps = total_rate.as_bytes_per_sec();
        match tree.class(parent_classid) {
            None => {
                if !opts.dry_run {
                    let cfg = HtbClassConfig::new(total_rate).ceil(total_rate).build();
                    conn.add_class_by_index(ifindex, root_handle, parent_classid, cfg)
                        .await
                        .map_err(|e| {
                            e.with_context("PerPeerImpairer::reconcile: add parent class 1:1")
                        })?;
                }
                report.changes_made += 1;
                report.root_modified = true;
            }
            Some(c) => {
                if !htb_class_rates_match(c, total_bps, total_bps) {
                    if !opts.dry_run {
                        let cfg = HtbClassConfig::new(total_rate).ceil(total_rate).build();
                        conn.change_class_by_index(ifindex, root_handle, parent_classid, cfg)
                            .await
                            .map_err(|e| {
                                e.with_context(
                                    "PerPeerImpairer::reconcile: update parent class 1:1",
                                )
                            })?;
                    }
                    report.changes_made += 1;
                    report.root_modified = true;
                }
            }
        }

        // 3. Per-rule classes + leaves + filters.
        for (i, rule) in self.rules.iter().enumerate() {
            let classid = TcHandle::new(1, (i + 2) as u16);
            let leaf_handle = TcHandle::major_only((i + 10) as u16);
            let class_rate = rule.impairment.rate_cap.unwrap_or(link_rate);
            let class_bps = class_rate.as_bytes_per_sec();
            let priority = filter_priority(i);
            let protocol = protocol_for(&rule.match_);

            let mut rule_added = false;
            let mut rule_modified = false;

            // 3a. Class.
            match tree.class(classid) {
                None => {
                    if !opts.dry_run {
                        let cfg = HtbClassConfig::new(class_rate).ceil(class_rate).build();
                        conn.add_class_by_index(ifindex, parent_classid, classid, cfg)
                            .await
                            .map_err(|e| {
                                e.with_context(format!(
                                    "PerPeerImpairer::reconcile: add class {classid}"
                                ))
                            })?;
                    }
                    report.changes_made += 1;
                    rule_added = true;
                }
                Some(c) => {
                    if !htb_class_rates_match(c, class_bps, class_bps) {
                        if !opts.dry_run {
                            let cfg = HtbClassConfig::new(class_rate).ceil(class_rate).build();
                            conn.change_class_by_index(ifindex, parent_classid, classid, cfg)
                                .await
                                .map_err(|e| {
                                    e.with_context(format!(
                                        "PerPeerImpairer::reconcile: update class {classid}"
                                    ))
                                })?;
                        }
                        report.changes_made += 1;
                        rule_modified = true;
                    }
                }
            }

            // 3b. Leaf netem qdisc (parent = classid).
            match tree.leaf_for(classid) {
                None => {
                    if !opts.dry_run {
                        conn.add_qdisc_by_index_full(
                            ifindex,
                            classid,
                            Some(leaf_handle),
                            rule.impairment.netem.clone(),
                        )
                        .await
                        .map_err(|e| {
                            e.with_context(format!(
                                "PerPeerImpairer::reconcile: add netem leaf at {classid}"
                            ))
                        })?;
                    }
                    report.changes_made += 1;
                    if !rule_added {
                        rule_modified = true;
                    }
                }
                Some(q) => {
                    if q.kind() != Some("netem") || !netem_matches(&rule.impairment.netem, q) {
                        // Replace, not change_qdisc, because the leaf may
                        // need a different handle if its kind changed.
                        if !opts.dry_run {
                            conn.replace_qdisc_by_index_full(
                                ifindex,
                                classid,
                                Some(leaf_handle),
                                rule.impairment.netem.clone(),
                            )
                            .await
                            .map_err(|e| {
                                e.with_context(format!(
                                    "PerPeerImpairer::reconcile: update netem leaf at {classid}"
                                ))
                            })?;
                        }
                        report.changes_made += 1;
                        if !rule_added {
                            rule_modified = true;
                        }
                    }
                }
            }

            // 3c. Flower filter at root parent (1:) priority 100+i.
            //
            // Compare the match keys, not just kind + classid: priority
            // and classid are both derived from the rule's index, so an
            // edited peer address reused them and reconcile called it
            // unchanged (#270).
            let desired_filter = build_flower(classid, priority, &rule.match_);
            let filter_ok = tree
                .filter_at_priority(priority)
                .map(|f| flower_matches(&desired_filter, protocol, f))
                .unwrap_or(false);
            if !filter_ok {
                if !opts.dry_run {
                    // Best-effort delete of any stale filter at this prio
                    // first; ignore not-found.
                    if let Some(stale) = tree.filter_at_priority(priority) {
                        let stale_proto = stale.protocol();
                        let _ = conn
                            .del_filter_by_index(ifindex, root_handle, stale_proto, priority)
                            .await;
                    }
                    let filter = desired_filter;
                    conn.add_filter_by_index_full(
                        ifindex,
                        root_handle,
                        None,
                        protocol,
                        priority,
                        filter,
                    )
                    .await
                    .map_err(|e| {
                        if e.is_not_supported() {
                            Error::not_supported(format!(
                                "cls_flower not loaded in target namespace; \
                                 try `modprobe cls_flower` (underlying: {e})"
                            ))
                        } else {
                            e.with_context(format!(
                                "PerPeerImpairer::reconcile: add filter for \
                                 {:?} -> {classid}",
                                rule.match_
                            ))
                        }
                    })?;
                }
                report.changes_made += 1;
                if !rule_added {
                    rule_modified = true;
                }
            }

            if rule_added {
                report.rules_added += 1;
            } else if rule_modified {
                report.rules_modified += 1;
            }
        }

        // 4. Default class.
        let default_bps = default_rate.as_bytes_per_sec();
        match tree.class(default_classid) {
            None => {
                if !opts.dry_run {
                    let cfg = HtbClassConfig::new(default_rate).ceil(default_rate).build();
                    conn.add_class_by_index(ifindex, parent_classid, default_classid, cfg)
                        .await
                        .map_err(|e| {
                            e.with_context("PerPeerImpairer::reconcile: add default class")
                        })?;
                }
                report.changes_made += 1;
                report.default_modified = true;
            }
            Some(c) => {
                if !htb_class_rates_match(c, default_bps, default_bps) {
                    if !opts.dry_run {
                        let cfg = HtbClassConfig::new(default_rate).ceil(default_rate).build();
                        conn.change_class_by_index(ifindex, parent_classid, default_classid, cfg)
                            .await
                            .map_err(|e| {
                                e.with_context("PerPeerImpairer::reconcile: update default class")
                            })?;
                    }
                    report.changes_made += 1;
                    report.default_modified = true;
                }
            }
        }

        // 4b. Default leaf netem (only if default_impairment is set).
        match (&self.default_impairment, tree.leaf_for(default_classid)) {
            (Some(default), None) => {
                if !opts.dry_run {
                    conn.add_qdisc_by_index_full(
                        ifindex,
                        default_classid,
                        Some(default_leaf_handle),
                        default.netem.clone(),
                    )
                    .await
                    .map_err(|e| {
                        e.with_context("PerPeerImpairer::reconcile: add default netem leaf")
                    })?;
                }
                report.changes_made += 1;
                report.default_modified = true;
            }
            // A leaf at the pre-0.31 `ffff:` (#485): delete it, then add one
            // at the new handle.
            (Some(default), Some(q)) if q.handle() != default_leaf_handle => {
                if !opts.dry_run {
                    conn.del_qdisc_by_index_full(ifindex, default_classid, Some(q.handle()))
                        .await
                        .map_err(|e| {
                            e.with_context("PerPeerImpairer::reconcile: remove legacy default leaf")
                        })?;
                    conn.add_qdisc_by_index_full(
                        ifindex,
                        default_classid,
                        Some(default_leaf_handle),
                        default.netem.clone(),
                    )
                    .await
                    .map_err(|e| {
                        e.with_context("PerPeerImpairer::reconcile: re-add default netem leaf")
                    })?;
                }
                report.changes_made += 1;
                report.default_modified = true;
            }
            (Some(default), Some(q)) => {
                if q.kind() != Some("netem") || !netem_matches(&default.netem, q) {
                    if !opts.dry_run {
                        conn.replace_qdisc_by_index_full(
                            ifindex,
                            default_classid,
                            Some(default_leaf_handle),
                            default.netem.clone(),
                        )
                        .await
                        .map_err(|e| {
                            e.with_context("PerPeerImpairer::reconcile: update default netem leaf")
                        })?;
                    }
                    report.changes_made += 1;
                    report.default_modified = true;
                }
            }
            (None, Some(q)) => {
                // Live tree has a leaf where we no longer want one.
                let stale_handle = q.handle();
                if !opts.dry_run {
                    let _ = conn
                        .del_qdisc_by_index_full(ifindex, default_classid, Some(stale_handle))
                        .await;
                }
                report.changes_made += 1;
                report.default_modified = true;
                report.stale_removed.push(StaleObject {
                    kind: "qdisc",
                    handle: stale_handle,
                    priority: None,
                });
            }
            (None, None) => {}
        }

        // 5. Stale removal — anything in our handle range that no
        // desired rule maps to. Walk the live tree.
        self.collect_stale_and_unmanaged(&tree, &mut report, conn, ifindex, opts)
            .await?;

        Ok(report)
    }

    /// Run the destructive [`apply()`] but return a [`ReconcileReport`]
    /// summarizing it (used for `fallback_to_apply` reconcile path).
    async fn apply_as_reconcile(&self, conn: &Connection<Route>) -> Result<ReconcileReport> {
        let n = self.rules.len();
        self.apply(conn).await?;
        Ok(ReconcileReport {
            // Count: 1 root + 1 parent + 3 per rule (class+leaf+filter)
            // + 1 default class + (1 if default leaf).
            changes_made: 2 + 3 * n + 1 + usize::from(self.default_impairment.is_some()),
            rules_added: n,
            root_modified: true,
            default_modified: true,
            ..ReconcileReport::default()
        })
    }

    /// Walk the live tree for objects in our managed handle range that
    /// aren't in the desired set (mark stale + remove) and objects
    /// outside (mark unmanaged, leave alone).
    async fn collect_stale_and_unmanaged(
        &self,
        tree: &LiveTree,
        report: &mut ReconcileReport,
        conn: &Connection<Route>,
        ifindex: u32,
        opts: ReconcileOptions,
    ) -> Result<()> {
        let n = self.rules.len();
        let parent_classid = TcHandle::new(1, 1);
        let root_handle = TcHandle::major_only(1);
        let default_classid = TcHandle::new(1, DEFAULT_CLASS_MINOR);
        // Rule classes only; the default sits at DEFAULT_CLASS_MINOR.
        let max_minor = (n + 1) as u16;

        // Filters first, then classes. `htb_delete` refuses a class
        // any filter still points at:
        //
        //   if (cl->children || qdisc_class_in_use(&cl->common)) {
        //           NL_SET_ERR_MSG(extack, "HTB class in use");
        //           return -EBUSY;
        //   }
        //
        // so removing a rule used to fail with EBUSY partway through
        // (#291) — the class went first and its filter was still bound.
        // Stale filters: a filter at a priority no rule installs any
        // more, that sends traffic into one of our classes (`1:M`, M >=
        // 2). Rule `i` sits at `100 + i`, so past 100 rules the
        // priorities leave the recipe band; telling ours apart by the band
        // left those filters behind when the rules shrank, still bound to
        // the classes this reconcile deletes — EBUSY (#491). A filter that
        // targets something else is not ours.
        let desired: std::collections::HashSet<FilterPriority> =
            (0..n).map(filter_priority).collect();
        let mut stale_filters: Vec<(FilterPriority, EthProto, TcHandle)> = Vec::new();
        for f in &tree.root_filters {
            let prio = f.priority();
            if desired.contains(&prio) {
                continue;
            }
            let ours = flower_classid(f).is_some_and(|c| c.major() == 1 && c.minor() >= 2);
            if !ours {
                report.unmanaged.push(UnmanagedObject {
                    kind: "filter",
                    handle: f.parent(),
                    priority: Some(prio),
                });
                continue;
            }
            if !stale_filters
                .iter()
                .any(|(p, proto, _)| *p == prio && *proto == f.protocol())
            {
                stale_filters.push((prio, f.protocol(), f.parent()));
            }
        }
        for (prio, proto, parent) in stale_filters {
            if !opts.dry_run {
                let _ = conn
                    .del_filter_by_index(ifindex, root_handle, proto, prio)
                    .await;
            }
            report.changes_made += 1;
            report.stale_removed.push(StaleObject {
                kind: "filter",
                handle: parent,
                priority: Some(prio),
            });
        }

        // Stale classes: `1:M` for M >= 2 outside [2..=max_minor], OR
        // M == max_minor when we don't want a default class. Also
        // delete leaf qdiscs first.
        // Collect stale classes (don't mutate during iteration).
        let mut stale_classes: Vec<TcHandle> = Vec::new();
        for handle in tree.classes.keys() {
            if handle.major() != 1 {
                continue; // outside our root major
            }
            let minor = handle.minor();
            if minor == 0 || minor == 1 {
                continue; // 1: and 1:1 are our root + parent
            }
            // In our managed range when minor in 2..=max_minor,
            // plus the fixed default class.
            if (minor >= 2 && minor <= max_minor) || minor == DEFAULT_CLASS_MINOR {
                continue; // wanted
            }
            // Otherwise, in major 1 but outside our minor range — stale.
            stale_classes.push(*handle);
        }
        for handle in &stale_classes {
            // Drop the leaf qdisc first if any (kernel removes leaves
            // with the class, but explicit del avoids surprises).
            if let Some(q) = tree.leaf_for(*handle) {
                let leaf_handle = q.handle();
                if !opts.dry_run {
                    let _ = conn
                        .del_qdisc_by_index_full(ifindex, *handle, Some(leaf_handle))
                        .await;
                }
            }
            if !opts.dry_run
                && let Err(e) = conn
                    .del_class_by_index(ifindex, parent_classid, *handle)
                    .await
                && !e.is_not_found()
            {
                return Err(e.with_context(format!(
                    "PerPeerImpairer::reconcile: remove stale class {handle}"
                )));
            }
            report.changes_made += 1;
            report.rules_removed += 1;
            report.stale_removed.push(StaleObject {
                kind: "class",
                handle: *handle,
                priority: None,
            });
        }

        // Default-class stale handling: if the desired default class is
        // not present in the live tree, that's covered above. If a
        // class at minor != max_minor is sitting where the default
        // should be, the stale-class loop above already removed it.
        let _ = default_classid;
        Ok(())
    }

    fn total_rate(&self) -> Rate {
        let link_rate = self.assumed_link_rate;
        let mut total = Rate::ZERO;
        for rule in &self.rules {
            total = total.saturating_add(rule.impairment.rate_cap.unwrap_or(link_rate));
        }
        total = total.saturating_add(
            self.default_impairment
                .as_ref()
                .and_then(|d| d.rate_cap)
                .unwrap_or(link_rate),
        );
        if total.is_zero() {
            Rate::bytes_per_sec(1)
        } else {
            total
        }
    }

    async fn add_filter(
        &self,
        conn: &Connection<Route>,
        ifindex: u32,
        index: usize,
        match_: &PeerMatch,
        classid: TcHandle,
    ) -> Result<()> {
        let priority = filter_priority(index);
        let protocol = protocol_for(match_);
        let filter = build_flower(classid, priority, match_);

        // Filter parent is the root HTB qdisc (1:).
        conn.add_filter_by_index_full(
            ifindex,
            TcHandle::major_only(1),
            None,
            protocol,
            priority,
            filter,
        )
        .await
        .map_err(|e| {
            if e.is_not_supported() {
                Error::not_supported(format!(
                    "cls_flower not loaded in target namespace; \
                     try `modprobe cls_flower` (underlying: {e})"
                ))
            } else {
                e.with_context(format!(
                    "PerPeerImpairer: add filter for {match_:?} -> {classid}"
                ))
            }
        })
    }
}

// ============================================================================
// helpers
// ============================================================================

fn protocol_for(m: &PeerMatch) -> EthProto {
    match m {
        PeerMatch::DstIp(IpAddr::V4(_))
        | PeerMatch::DstSubnet(IpAddr::V4(_), _)
        | PeerMatch::SrcIp(IpAddr::V4(_))
        | PeerMatch::SrcSubnet(IpAddr::V4(_), _) => EthProto::IP,
        PeerMatch::DstIp(IpAddr::V6(_))
        | PeerMatch::DstSubnet(IpAddr::V6(_), _)
        | PeerMatch::SrcIp(IpAddr::V6(_))
        | PeerMatch::SrcSubnet(IpAddr::V6(_), _) => EthProto::IPV6,
        PeerMatch::DstMac(_) | PeerMatch::SrcMac(_) => EthProto::ALL,
    }
}

// Sit above the conventional operator-installed range (1..50).
fn filter_priority(index: usize) -> FilterPriority {
    FilterPriority::new(100u16.saturating_add(u16::try_from(index).unwrap_or(u16::MAX - 100)))
}

fn build_flower(classid: TcHandle, priority: FilterPriority, match_: &PeerMatch) -> FlowerFilter {
    let mut f = FlowerFilter::new().classid(classid).priority(priority);
    match *match_ {
        PeerMatch::DstIp(IpAddr::V4(addr)) => f = f.dst_ipv4(addr, 32),
        PeerMatch::DstIp(IpAddr::V6(addr)) => f = f.dst_ipv6(addr, 128),
        PeerMatch::DstSubnet(IpAddr::V4(addr), prefix) => {
            f = f.dst_ipv4(addr, prefix.min(32));
        }
        PeerMatch::DstSubnet(IpAddr::V6(addr), prefix) => {
            f = f.dst_ipv6(addr, prefix.min(128));
        }
        PeerMatch::DstMac(mac) => f = f.dst_mac(mac),
        PeerMatch::SrcIp(IpAddr::V4(addr)) => f = f.src_ipv4(addr, 32),
        PeerMatch::SrcIp(IpAddr::V6(addr)) => f = f.src_ipv6(addr, 128),
        PeerMatch::SrcSubnet(IpAddr::V4(addr), prefix) => {
            f = f.src_ipv4(addr, prefix.min(32));
        }
        PeerMatch::SrcSubnet(IpAddr::V6(addr), prefix) => {
            f = f.src_ipv6(addr, prefix.min(128));
        }
        PeerMatch::SrcMac(mac) => f = f.src_mac(mac),
    }
    f.build()
}

fn parse_subnet(subnet: &str) -> Result<(IpAddr, u8)> {
    let (addr_part, prefix_part) = subnet
        .split_once('/')
        .ok_or_else(|| Error::invalid_message(format!("invalid subnet (missing '/'): {subnet}")))?;

    let addr: IpAddr = addr_part
        .parse()
        .map_err(|_| Error::invalid_message(format!("invalid IP address: {addr_part}")))?;

    let prefix: u8 = prefix_part
        .parse()
        .map_err(|_| Error::invalid_message(format!("invalid prefix length: {prefix_part}")))?;

    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(Error::invalid_message(format!(
            "prefix length {prefix} exceeds maximum {max}"
        )));
    }

    Ok((addr, prefix))
}

// ============================================================================
// tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    use super::*;

    fn netem_50ms() -> NetemConfig {
        NetemConfig::new().delay(Duration::from_millis(50)).build()
    }

    #[test]
    fn builder_records_target_name() {
        let imp = PerPeerImpairer::new("eth0");
        assert_eq!(imp.target().as_name(), Some("eth0"));
        assert_eq!(imp.ifindex(), None);
        assert_eq!(imp.rule_count(), 0);
    }

    #[test]
    fn builder_records_target_index() {
        let imp = PerPeerImpairer::new_by_index(7);
        assert_eq!(imp.ifindex(), Some(7));
        assert_eq!(imp.target().as_name(), None);
    }

    #[test]
    fn builder_collects_rules_in_order() {
        let imp = PerPeerImpairer::new("eth0")
            .impair_dst_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), netem_50ms())
            .impair_dst_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), netem_50ms())
            .impair_dst_mac([1, 2, 3, 4, 5, 6], netem_50ms());
        assert_eq!(imp.rule_count(), 3);
    }

    #[test]
    fn impair_dst_subnet_parses_prefix() {
        let imp = PerPeerImpairer::new("eth0")
            .impair_dst_subnet("10.0.0.0/8", netem_50ms())
            .expect("subnet parses");
        assert_eq!(imp.rule_count(), 1);
    }

    #[test]
    fn impair_dst_subnet_rejects_bad_input() {
        assert!(
            PerPeerImpairer::new("eth0")
                .impair_dst_subnet("10.0.0.0", netem_50ms())
                .is_err()
        );
        assert!(
            PerPeerImpairer::new("eth0")
                .impair_dst_subnet("10.0.0.0/33", netem_50ms())
                .is_err()
        );
        assert!(
            PerPeerImpairer::new("eth0")
                .impair_dst_subnet("not-an-ip/24", netem_50ms())
                .is_err()
        );
    }

    #[test]
    fn impair_src_subnet_handles_ipv6() {
        let imp = PerPeerImpairer::new("eth0")
            .impair_src_subnet("2001:db8::/32", netem_50ms())
            .expect("v6 subnet parses");
        assert_eq!(imp.rule_count(), 1);
    }

    #[test]
    fn ipv6_subnet_rejects_prefix_above_128() {
        assert!(
            PerPeerImpairer::new("eth0")
                .impair_dst_subnet("2001:db8::/129", netem_50ms())
                .is_err()
        );
    }

    #[test]
    fn default_impairment_optional() {
        let imp = PerPeerImpairer::new("eth0")
            .impair_dst_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), netem_50ms());
        assert!(imp.default_impairment.is_none());

        let imp = imp.default_impairment(netem_50ms());
        assert!(imp.default_impairment.is_some());
    }

    #[test]
    fn assumed_link_rate_clamps_to_one() {
        let imp = PerPeerImpairer::new("eth0").assumed_link_rate(Rate::ZERO);
        assert_eq!(imp.assumed_link_rate, Rate::bytes_per_sec(1));
    }

    #[test]
    fn peer_impairment_from_netem() {
        let imp: PeerImpairment = netem_50ms().into();
        assert!(imp.cap().is_none());
    }

    #[test]
    fn peer_impairment_rate_cap_sets_cap() {
        let imp = PeerImpairment::new(netem_50ms()).rate_cap(Rate::bytes_per_sec(12_500_000));
        assert_eq!(imp.cap(), Some(Rate::bytes_per_sec(12_500_000)));
    }

    #[test]
    fn peer_impairment_rate_cap_typed_units() {
        // Rate::mbit(100) == 12.5 MB/s
        let imp = PeerImpairment::new(netem_50ms()).rate_cap(Rate::mbit(100));
        assert_eq!(imp.cap(), Some(Rate::bytes_per_sec(12_500_000)));
    }

    #[test]
    fn total_rate_uses_link_rate_when_no_caps() {
        let imp = PerPeerImpairer::new("eth0")
            .assumed_link_rate(Rate::bytes_per_sec(1_000))
            .impair_dst_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), netem_50ms())
            .impair_dst_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), netem_50ms());
        // 2 rules + default => 3 * 1_000
        assert_eq!(imp.total_rate(), Rate::bytes_per_sec(3_000));
    }

    #[test]
    fn total_rate_sums_caps_and_defaults() {
        let imp = PerPeerImpairer::new("eth0")
            .assumed_link_rate(Rate::bytes_per_sec(5_000))
            .impair_dst_ip(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                PeerImpairment::new(netem_50ms()).rate_cap(Rate::bytes_per_sec(100)),
            )
            .impair_dst_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), netem_50ms())
            .default_impairment(
                PeerImpairment::new(netem_50ms()).rate_cap(Rate::bytes_per_sec(50)),
            );
        // 100 (capped) + 5_000 (default link rate) + 50 (default cap)
        assert_eq!(imp.total_rate(), Rate::bytes_per_sec(5_150));
    }

    #[test]
    fn total_rate_saturates_on_overflow() {
        let imp = PerPeerImpairer::new("eth0")
            .impair_dst_ip(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                PeerImpairment::new(netem_50ms()).rate_cap(Rate::MAX),
            )
            .impair_dst_ip(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                PeerImpairment::new(netem_50ms()).rate_cap(Rate::MAX),
            );
        assert_eq!(imp.total_rate(), Rate::MAX);
    }

    #[test]
    fn protocol_for_dst_ipv4() {
        assert_eq!(
            protocol_for(&PeerMatch::DstIp(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))),
            EthProto::IP
        );
    }

    #[test]
    fn protocol_for_dst_ipv6() {
        assert_eq!(
            protocol_for(&PeerMatch::DstIp(Ipv6Addr::LOCALHOST.into())),
            EthProto::IPV6
        );
    }

    #[test]
    fn protocol_for_src_subnet_ipv6() {
        assert_eq!(
            protocol_for(&PeerMatch::SrcSubnet(Ipv6Addr::UNSPECIFIED.into(), 64)),
            EthProto::IPV6
        );
    }

    #[test]
    fn protocol_for_mac_is_eth_p_all() {
        assert_eq!(protocol_for(&PeerMatch::DstMac([0; 6])), EthProto::ALL);
        assert_eq!(protocol_for(&PeerMatch::SrcMac([0; 6])), EthProto::ALL);
    }

    #[test]
    fn filter_priority_offset_by_100() {
        assert_eq!(filter_priority(0), 100);
        assert_eq!(filter_priority(5), 105);
    }

    #[test]
    fn filter_priority_does_not_panic_on_huge_index() {
        // Used as a defensive guarantee, not a real-world scenario.
        let _ = filter_priority(usize::MAX);
    }

    #[test]
    fn parse_subnet_v4_ok() {
        let (a, p) = parse_subnet("10.0.0.0/8").unwrap();
        assert_eq!(a, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(p, 8);
    }

    #[test]
    fn parse_subnet_v6_ok() {
        let (a, p) = parse_subnet("2001:db8::/32").unwrap();
        assert!(a.is_ipv6());
        assert_eq!(p, 32);
    }

    #[test]
    fn parse_subnet_rejects_missing_slash() {
        assert!(parse_subnet("10.0.0.0").is_err());
    }

    #[test]
    fn parse_subnet_rejects_bad_addr() {
        assert!(parse_subnet("garbage/24").is_err());
    }

    #[test]
    fn parse_subnet_rejects_prefix_too_large_v4() {
        assert!(parse_subnet("10.0.0.0/33").is_err());
    }

    #[test]
    fn parse_subnet_rejects_prefix_too_large_v6() {
        assert!(parse_subnet("2001:db8::/129").is_err());
    }

    #[test]
    fn build_flower_dst_ip_v4_classid() {
        let f = build_flower(
            TcHandle::new(1, 2),
            FilterPriority::new(100),
            &PeerMatch::DstIp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        );
        // Smoke test: builder runs without panicking and returns a flower
        // configuration. Detailed wire-format coverage lives in the
        // integration tests where the kernel echoes back the result.
        let _ = f;
    }

    #[test]
    fn clone_roundtrip_preserves_state() {
        let original = PerPeerImpairer::new("eth0")
            .assumed_link_rate(Rate::bytes_per_sec(2_500_000))
            .impair_dst_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), netem_50ms())
            .impair_dst_subnet("2001:db8::/32", netem_50ms())
            .expect("subnet parses")
            .impair_dst_mac([1, 2, 3, 4, 5, 6], netem_50ms())
            .default_impairment(
                PeerImpairment::new(netem_50ms()).rate_cap(Rate::bytes_per_sec(123_456)),
            );
        let clone = original.clone();
        assert_eq!(clone.rule_count(), original.rule_count());
        assert_eq!(clone.assumed_link_rate, original.assumed_link_rate);
        assert_eq!(
            clone.default_impairment.as_ref().and_then(|d| d.cap()),
            Some(Rate::bytes_per_sec(123_456))
        );
        assert_eq!(clone.target().as_name(), original.target().as_name());
        assert_eq!(clone.total_rate(), original.total_rate());
    }

    #[test]
    fn build_flower_dst_subnet_clamps_prefix() {
        // Prefix > 32 should be clamped silently rather than panic in the
        // ipv4 mask helper.
        let _ = build_flower(
            TcHandle::new(1, 2),
            FilterPriority::new(100),
            &PeerMatch::DstSubnet(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 99),
        );
    }
}
