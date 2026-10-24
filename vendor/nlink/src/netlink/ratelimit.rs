//! High-level rate limiting API.
//!
//! This module provides a simplified API for common rate limiting use cases,
//! abstracting away the complexity of TC (Traffic Control) configuration.
//!
//! # Overview
//!
//! The rate limiting API provides two main types:
//!
//! - [`RateLimiter`]: Simple interface-wide rate limiting for egress and ingress traffic
//! - [`PerHostLimiter`]: Per-IP or per-subnet rate limiting with customizable rules
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # use nlink::Rate;
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::ratelimit::RateLimiter;
//! use std::time::Duration;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Simple rate limiting
//! RateLimiter::new("eth0")
//!     .egress(Rate::mbit(100))
//!     .ingress(Rate::gbit(1))
//!     .burst_to(Rate::mbit(150))
//!     .latency(Duration::from_millis(20))
//!     .apply(&conn)
//!     .await?;
//!
//! // Remove limits
//! RateLimiter::new("eth0")
//!     .remove(&conn)
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Implementation Details
//!
//! Under the hood, the rate limiter uses:
//! - **Egress**: HTB qdisc with two classes + fq_codel leaf for AQM
//! - **Ingress**: IFB device + ingress hook (an `ingress` qdisc, or an
//!   existing `clsact`) + mirred egress redirect + HTB on the IFB
//!
//! ```text
//! Egress:
//!   eth0 -> HTB root (1:) -> class 1:1 (rate = ceil = the ceiling)
//!                         -> class 1:a (the rate, borrowing up to the ceiling) -> fq_codel
//!
//! Ingress:
//!   eth0 ingress -> matchall filter -> mirred egress redirect -> ifb_eth0 -> HTB -> fq_codel
//! ```

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::Duration,
};

use super::{
    Connection,
    config::NetworkConfig,
    error::{Error, Result},
    eth_proto::EthProto,
    link::IfbLink,
    messages::{LinkMessage, TcMessage},
    protocol::Route,
    tc::{FqCodelConfig, HtbClassConfig, HtbQdiscConfig, IngressConfig},
    tc_handle::{FilterPriority, TcHandle},
    tc_recipe::{ReconcileOptions, ReconcileReport, StaleObject, UnmanagedObject},
    tc_recipe_internals::{
        DEFAULT_CLASS_MINOR, DEFAULT_LEAF_MAJOR, LiveTree, dump_live_tree, flower_classid,
        flower_matches, fq_codel_target_matches, htb_class_matches, htb_class_rates_match,
        recipe_owns_root, root_conflict,
    },
};

/// Minor of the single leaf class `RateLimiter` creates under the HTB root.
///
/// The HTB qdisc's `default` and the class it names **must** come from this one
/// constant. They were previously written independently: the qdisc said
/// `default_class(0x10)` — 16 — while the class was created at
/// `TcHandle::new(1, 10)`, decimal 10. So `htb_classify` looked up a class that
/// did not exist, fell through to `HTB_DIRECT`, and transmitted every packet
/// unshaped.
///
/// `RateLimiter` installs no filters, so this default class is the *only* thing
/// standing between traffic and the wire (#258).
///
/// It is decimal 10: the class is `1:a` and the leaf `a:` in tc(8)'s hex
/// notation (#723).
const LEAF_CLASS_MINOR: u16 = 10;

// ============================================================================
// RateLimit
// ============================================================================

/// Rate limit configuration.
#[derive(Debug, Clone)]
pub struct RateLimit {
    /// Guaranteed rate.
    pub rate: crate::util::Rate,
    /// Maximum burst rate (ceiling).
    pub ceil: Option<crate::util::Rate>,
    /// Burst size.
    pub burst: Option<crate::util::Bytes>,
    /// Latency target for AQM (Active Queue Management).
    pub latency: Option<Duration>,
}

impl RateLimit {
    /// Create a new rate limit with the specified rate.
    pub fn new(rate: crate::util::Rate) -> Self {
        Self {
            rate,
            ceil: None,
            burst: None,
            latency: None,
        }
    }

    /// Set the ceiling rate (maximum burst rate).
    pub fn ceil(mut self, ceil: crate::util::Rate) -> Self {
        self.ceil = Some(ceil);
        self
    }

    /// Set the burst size.
    pub fn burst(mut self, burst: crate::util::Bytes) -> Self {
        self.burst = Some(burst);
        self
    }

    /// Set the latency target for AQM.
    pub fn latency(mut self, latency: Duration) -> Self {
        self.latency = Some(latency);
        self
    }
}

// ============================================================================
// RateLimiter
// ============================================================================

/// High-level rate limiter for an interface.
///
/// Provides a simple API for rate limiting both egress (upload) and ingress (download)
/// traffic on a network interface.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::Rate;
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::ratelimit::RateLimiter;
///
/// let conn = Connection::<Route>::new()?;
///
/// // Limit egress to 100 Mbps, ingress to 1 Gbps
/// RateLimiter::new("eth0")
///     .egress(Rate::mbit(100))
///     .ingress(Rate::gbit(1))
///     .apply(&conn)
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Target interface name.
    dev: String,
    /// Egress (upload) rate limit.
    egress: Option<RateLimit>,
    /// Ingress (download) rate limit.
    ingress: Option<RateLimit>,
}

#[nlink_macros::send_futures]
impl RateLimiter {
    /// Create a new rate limiter for the specified interface.
    pub fn new(dev: &str) -> Self {
        Self {
            dev: dev.to_string(),
            egress: None,
            ingress: None,
        }
    }

    /// Set the egress (upload) rate limit.
    pub fn egress(mut self, rate: crate::util::Rate) -> Self {
        self.egress = Some(RateLimit::new(rate));
        self
    }

    /// Set the ingress (download) rate limit.
    pub fn ingress(mut self, rate: crate::util::Rate) -> Self {
        self.ingress = Some(RateLimit::new(rate));
        self
    }

    /// Set the ceiling rate for bursting (applies to both egress and ingress).
    pub fn burst_to(mut self, ceil: crate::util::Rate) -> Self {
        if let Some(ref mut egress) = self.egress {
            egress.ceil = Some(ceil);
        }
        if let Some(ref mut ingress) = self.ingress {
            ingress.ceil = Some(ceil);
        }
        self
    }

    /// Set the burst buffer size (applies to both egress and ingress).
    pub fn burst_size(mut self, size: crate::util::Bytes) -> Self {
        if let Some(ref mut egress) = self.egress {
            egress.burst = Some(size);
        }
        if let Some(ref mut ingress) = self.ingress {
            ingress.burst = Some(size);
        }
        self
    }

    /// Set the latency target for AQM (applies to both egress and ingress).
    pub fn latency(mut self, latency: Duration) -> Self {
        if let Some(ref mut egress) = self.egress {
            egress.latency = Some(latency);
        }
        if let Some(ref mut ingress) = self.ingress {
            ingress.latency = Some(latency);
        }
        self
    }

    /// This limiter as a declaration (#645): what [`apply`](Self::apply)
    /// installs, added to `config`, so it is diffed and applied with the
    /// rest of the config instead of beside it. A limiter installed
    /// imperatively diffs empty against it, and one applied from it is
    /// already what [`reconcile`](Self::reconcile) converges to.
    ///
    /// Egress is an HTB root on the device with its classes and fq_codel
    /// leaf. Ingress is this limiter's IFB (named and tagged as `apply`
    /// does), the same tree on it, and the redirect on the device's hook:
    /// the clsact or ingress qdisc `config` declares there, or an ingress
    /// qdisc otherwise. What `config` already declares on the device's root
    /// or tree is merged with it, and a conflict fails its validation.
    ///
    /// ```
    /// use nlink::Rate;
    /// use nlink::netlink::{config::NetworkConfig, ratelimit::RateLimiter};
    ///
    /// let config = RateLimiter::new("eth0")
    ///     .egress(Rate::mbit(100))
    ///     .ingress(Rate::mbit(50))
    ///     .declare(NetworkConfig::new().link("eth0", |l| l.up()));
    /// config.validate()?;
    /// # Ok::<(), nlink::Error>(())
    /// ```
    pub fn declare(&self, mut config: NetworkConfig) -> NetworkConfig {
        if let Some(egress) = &self.egress {
            config = declare_limit(config, &self.dev, egress);
        }
        if let Some(ingress) = &self.ingress {
            let (ifb, tag) = (self.ifb_name(), self.ifb_tag());
            config = config.link(&ifb, |l| l.ifb().alias(&tag).up());
            config = declare_limit(config, &ifb, ingress);
            if !config.declares_ingress_hook(&self.dev) {
                config = config.qdisc(&self.dev, |q| q.ingress());
            }
            config = config.tc(&self.dev, |t| t.redirect_ingress_to(&ifb));
        }
        config
    }

    /// [`declare`](Self::declare) into an empty config.
    pub fn to_config(&self) -> NetworkConfig {
        self.declare(NetworkConfig::new())
    }

    /// Apply the rate limits: build this limiter's trees from scratch.
    ///
    /// Egress replaces the interface's root qdisc. Ingress hangs its
    /// redirect off the interface's `clsact` or `ingress` hook — adding an
    /// `ingress` qdisc if there is neither, never deleting one, so the
    /// programs on a clsact stay (#490) — and shapes on this limiter's IFB
    /// (see [`remove`](Self::remove) for what makes it this limiter's).
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev, egress = self.egress.is_some(), ingress = self.ingress.is_some()))]
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<()> {
        let ifindex = self.ifindex(conn).await?;
        if let Some(egress) = &self.egress {
            build_htb(conn, ifindex, egress)
                .await
                .map_err(|e| e.with_context(format!("RateLimiter::apply({}): egress", self.dev)))?;
        }
        if let Some(ingress) = &self.ingress {
            self.apply_ingress(conn, ifindex, ingress).await?;
        }
        Ok(())
    }

    /// Idempotently converge the interface to this limiter's desired
    /// state, mutating only what drifted (#169 — mirrors
    /// [`PerHostLimiter::reconcile`]).
    ///
    /// Unlike [`apply()`](Self::apply), which tears down the root
    /// qdisc and rebuilds (dropping in-flight queue state), reconcile
    /// dumps the live TC tree and issues only the kernel calls needed
    /// to close the gap. Calling `reconcile()` twice in a row with no
    /// other changes makes **zero** kernel calls on the second
    /// invocation.
    ///
    /// If a live root qdisc is the wrong kind (not the HTB shape this
    /// helper installs), reconcile errors by default; pass
    /// [`ReconcileOptions::with_fallback_to_apply`]`(true)` to trigger
    /// a destructive rebuild via [`apply()`](Self::apply) instead.
    ///
    /// A direction this limiter no longer declares is taken down, if what
    /// is there is this limiter's (see [`remove`](Self::remove)); it used
    /// to stay (#490). The burst and the AQM target are compared too: a
    /// burst or latency dropped from the declaration goes back to the
    /// default.
    ///
    /// The ingress redirect is checked for what it does: a matchall with a
    /// mirred **egress** redirect to this limiter's IFB. Anything else that
    /// redirects to the IFB — the u32 *ingress* redirect releases before
    /// 0.31 installed, which dropped every packet (#458) — is deleted and
    /// replaced.
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev))]
    pub async fn reconcile(&self, conn: &Connection<Route>) -> Result<ReconcileReport> {
        self.reconcile_with_options(conn, ReconcileOptions::new())
            .await
    }

    /// Compute what [`reconcile()`](Self::reconcile) would do without
    /// making kernel calls.
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev))]
    pub async fn reconcile_dry_run(&self, conn: &Connection<Route>) -> Result<ReconcileReport> {
        self.reconcile_with_options(conn, ReconcileOptions::new().with_dry_run(true))
            .await
    }

    /// [`reconcile()`](Self::reconcile) with explicit
    /// [`ReconcileOptions`].
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev, dry_run = opts.dry_run, fallback = opts.fallback_to_apply))]
    pub async fn reconcile_with_options(
        &self,
        conn: &Connection<Route>,
        opts: ReconcileOptions,
    ) -> Result<ReconcileReport> {
        let ifindex = self.ifindex(conn).await?;
        // Each attempt reads the trees again (#532).
        let (mut report, attempts) = opts
            .retry(super::reconcile::transient, || {
                self.reconcile_once(conn, ifindex, opts)
            })
            .await?;
        report.attempts = attempts;
        Ok(report)
    }

    async fn reconcile_once(
        &self,
        conn: &Connection<Route>,
        ifindex: u32,
        opts: ReconcileOptions,
    ) -> Result<ReconcileReport> {
        let mut report = ReconcileReport {
            dry_run: opts.dry_run,
            ..ReconcileReport::default()
        };

        // Egress half: HTB shape directly on the interface.
        match &self.egress {
            Some(egress) => {
                let rebuilt = self
                    .reconcile_htb_shape(conn, ifindex, egress, &opts, &mut report, "egress")
                    .await?;
                if rebuilt {
                    return Ok(report);
                }
            }
            None => {
                if owns_root(conn, ifindex).await? {
                    if !opts.dry_run {
                        gone_is_ok(conn.del_qdisc_by_index(ifindex, TcHandle::ROOT).await)?;
                    }
                    report.changes_made += 1;
                    report.root_modified = true;
                }
            }
        }

        let Some(ingress) = &self.ingress else {
            // The ingress half left the declaration: what of it is this
            // limiter's goes.
            if matches!(self.find_ifb(conn).await?, Ifb::Ours(_)) {
                if !opts.dry_run {
                    self.remove_ingress(conn).await?;
                }
                report.changes_made += 1;
                report.root_modified = true;
            }
            return Ok(report);
        };

        // Ingress half: this limiter's IFB, the hook, the redirect, and the
        // HTB shape on the IFB.
        let tag = self.ifb_tag();
        let ifb_ifindex = match self.owned_ifb(conn).await? {
            Some(l) => {
                if l.alias() != Some(tag.as_str()) {
                    if !opts.dry_run {
                        conn.set_link_alias_by_index(l.ifindex(), &tag).await?;
                    }
                    report.changes_made += 1;
                }
                if !l.is_up() {
                    if !opts.dry_run {
                        conn.set_link_up_by_index(l.ifindex()).await?;
                    }
                    report.changes_made += 1;
                }
                Some(l.ifindex())
            }
            None if opts.dry_run => {
                // Whole ingress branch pending: link + tag + up + shape
                // (root, 1:1, 1:a, leaf). The hook and filter are counted
                // below.
                report.changes_made += 7;
                report.root_modified = true;
                None
            }
            None => {
                let ifb = self.create_ifb(conn).await?;
                report.changes_made += 3;
                Some(ifb)
            }
        };

        // The hook on the main interface: a clsact's ingress if there is
        // one, else an ingress qdisc, added if missing.
        let hook = match live_ingress_hook(&conn.get_qdiscs_by_index(ifindex).await?) {
            Some(hook) => Some(hook),
            None => {
                if !opts.dry_run {
                    conn.add_qdisc_by_index_full(
                        ifindex,
                        TcHandle::INGRESS,
                        None,
                        IngressConfig::new(),
                    )
                    .await?;
                }
                report.changes_made += 1;
                (!opts.dry_run).then_some(TcHandle::INGRESS)
            }
        };

        // The redirect at the hook: the matchall *egress* redirect to this
        // IFB. Presence alone was checked, so an ingress-direction
        // redirect — which every release before 0.31 installed, and which
        // drops everything (#458) — read as converged.
        let redirect = match (ifb_ifindex, hook) {
            (Some(ifb), Some(hook)) => ifb_redirect_state(conn, ifindex, hook, ifb).await?,
            _ => IfbRedirect::Replace(Vec::new()),
        };
        if let IfbRedirect::Replace(wrong) = redirect {
            if let (false, Some(ifb), Some(hook)) = (opts.dry_run, ifb_ifindex, hook) {
                for (protocol, priority) in wrong {
                    conn.del_filter_by_index(ifindex, hook, protocol, priority)
                        .await?;
                }
                add_ifb_redirect(conn, ifindex, hook, ifb).await?;
            }
            report.changes_made += 1;
        }

        // HTB shape on the IFB side (skipped in dry-run when the IFB
        // doesn't exist yet — already counted above).
        if let Some(ifb_ifindex) = ifb_ifindex {
            let rebuilt = self
                .reconcile_htb_shape(conn, ifb_ifindex, ingress, &opts, &mut report, "ingress")
                .await?;
            if rebuilt {
                return Ok(report);
            }
        }

        Ok(report)
    }

    /// Converge one device's egress tree to the helper's canonical
    /// shape: HTB root `1:` (default `0xa`) → class `1:1` → class
    /// `1:a` → fq_codel leaf `a:`. Returns `true` when a wrong-kind
    /// root triggered the destructive `fallback_to_apply` rebuild (the
    /// caller must stop reconciling — the rebuild already converged
    /// everything).
    async fn reconcile_htb_shape(
        &self,
        conn: &Connection<Route>,
        ifindex: u32,
        limit: &RateLimit,
        opts: &ReconcileOptions,
        report: &mut ReconcileReport,
        ctx: &str,
    ) -> Result<bool> {
        let tree = dump_live_tree(conn, ifindex).await?;
        let root_handle = TcHandle::major_only(1);
        let class_1_1 = TcHandle::new(1, 1);
        let class_1_10 = TcHandle::new(1, LEAF_CLASS_MINOR);
        let leaf_handle = TcHandle::major_only(LEAF_CLASS_MINOR);
        let (outer, leaf_class) = limit_classes(limit);
        let target_us = limit.latency.map(|d| d.as_micros() as u32);

        // Root HTB.
        match tree.configured_root_qdisc() {
            None => {
                if !opts.dry_run {
                    let cfg = HtbQdiscConfig::new().default_class(LEAF_CLASS_MINOR as u32).build();
                    conn.add_qdisc_by_index_full(ifindex, TcHandle::ROOT, Some(root_handle), cfg)
                        .await
                        .map_err(|e| {
                            e.with_context(format!("RateLimiter::reconcile({ctx}): add HTB root"))
                        })?;
                }
                report.changes_made += 1;
                report.root_modified = true;
            }
            // Another root, or an HTB `1:` with another default class —
            // another recipe's tree, whose classes this one would mix into
            // (#491).
            Some(q) => {
                if let Some(conflict) = root_conflict(q, &tree, root_handle, LEAF_CLASS_MINOR) {
                    if opts.fallback_to_apply {
                        report.changes_made += 1;
                        report.root_modified = true;
                        if !opts.dry_run {
                            self.apply(conn).await?;
                        }
                        return Ok(true);
                    }
                    return Err(Error::invalid_message(format!(
                        "RateLimiter::reconcile({ctx}): root qdisc is {conflict}; pass \
                         ReconcileOptions::with_fallback_to_apply(true) to rebuild"
                    )));
                }
            }
        }

        // Classes 1:1 and 1:a.
        for (classid, parent, cfg) in [
            (class_1_1, root_handle, &outer),
            (class_1_10, class_1_1, &leaf_class),
        ] {
            match tree.class(classid) {
                None => {
                    if !opts.dry_run {
                        conn.add_class_by_index(ifindex, parent, classid, cfg.clone())
                            .await
                            .map_err(|e| {
                                e.with_context(format!(
                                    "RateLimiter::reconcile({ctx}): add class {classid}"
                                ))
                            })?;
                    }
                    report.changes_made += 1;
                }
                Some(c) if !htb_class_matches(c, cfg) => {
                    if !opts.dry_run {
                        conn.change_class_by_index(ifindex, parent, classid, cfg.clone())
                            .await
                            .map_err(|e| {
                                e.with_context(format!(
                                    "RateLimiter::reconcile({ctx}): update class {classid}"
                                ))
                            })?;
                    }
                    report.changes_made += 1;
                }
                Some(_) => {}
            }
        }

        // fq_codel leaf under 1:a.
        match tree.leaf_for(class_1_10) {
            None => {
                if !opts.dry_run {
                    conn.add_qdisc_by_index_full(
                        ifindex,
                        class_1_10,
                        Some(leaf_handle),
                        leaf_config(limit),
                    )
                    .await
                    .map_err(|e| {
                        e.with_context(format!("RateLimiter::reconcile({ctx}): add fq_codel leaf"))
                    })?;
                }
                report.changes_made += 1;
            }
            Some(q) if !fq_codel_target_matches(target_us, q) => {
                if !opts.dry_run {
                    conn.replace_qdisc_by_index_full(
                        ifindex,
                        class_1_10,
                        Some(leaf_handle),
                        leaf_config(limit),
                    )
                    .await
                    .map_err(|e| {
                        e.with_context(format!(
                            "RateLimiter::reconcile({ctx}): update fq_codel leaf"
                        ))
                    })?;
                }
                report.changes_made += 1;
            }
            Some(_) => {}
        }

        Ok(false)
    }

    /// Remove this limiter from the interface: [`remove_egress`] and
    /// [`remove_ingress`].
    ///
    /// Only what this limiter built goes: the root qdisc only when it is
    /// the HTB `1:` with this limiter's default class, the IFB only when it
    /// is an IFB carrying this limiter's tag as its alias (or, as every
    /// release before 0.31 left it, untagged), the redirect to it, and the
    /// `ingress` qdisc once nothing else is on it — never a `clsact`. It
    /// used to delete whatever root and ingress qdiscs were there,
    /// another recipe's or a clsact with its BPF programs, and to throw
    /// every error away (#490). Something already gone is not an error.
    ///
    /// [`remove_egress`]: Self::remove_egress
    /// [`remove_ingress`]: Self::remove_ingress
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev))]
    pub async fn remove(&self, conn: &Connection<Route>) -> Result<()> {
        self.remove_egress(conn).await?;
        self.remove_ingress(conn).await
    }

    /// Remove the egress half: the interface's root qdisc, if it is this
    /// limiter's. See [`remove`](Self::remove).
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev))]
    pub async fn remove_egress(&self, conn: &Connection<Route>) -> Result<()> {
        let Some(link) = conn.get_link_by_name(&self.dev).await? else {
            return Ok(());
        };
        if owns_root(conn, link.ifindex()).await? {
            gone_is_ok(
                conn.del_qdisc_by_index(link.ifindex(), TcHandle::ROOT)
                    .await,
            )?;
        }
        Ok(())
    }

    /// Remove the ingress half: the redirect to this limiter's IFB, the
    /// `ingress` qdisc if nothing else is on it, and the IFB. See
    /// [`remove`](Self::remove).
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev))]
    pub async fn remove_ingress(&self, conn: &Connection<Route>) -> Result<()> {
        // A device of the name that is not this limiter's is left alone.
        let ifb = match self.find_ifb(conn).await? {
            Ifb::Ours(link) => Some(*link),
            Ifb::Missing | Ifb::Foreign(_) => None,
        };
        if let Some(link) = conn.get_link_by_name(&self.dev).await? {
            let ifindex = link.ifindex();
            if let Some(hook) = live_ingress_hook(&conn.get_qdiscs_by_index(ifindex).await?) {
                if let Some(ifb) = &ifb {
                    for (protocol, priority) in
                        redirects_to(conn, ifindex, hook, ifb.ifindex()).await?
                    {
                        gone_is_ok(
                            conn.del_filter_by_index(ifindex, hook, protocol, priority)
                                .await,
                        )?;
                    }
                }
                let empty = conn
                    .get_filters_by_parent_index(ifindex, hook)
                    .await?
                    .is_empty();
                // `del_ingress`: the kernel itself refuses if a clsact
                // took the slot since the dump (#515).
                if hook == TcHandle::INGRESS && empty {
                    gone_is_ok(conn.del_ingress_by_index(ifindex).await)?;
                }
            }
        }
        if let Some(ifb) = ifb {
            gone_is_ok(conn.del_link_by_index(ifb.ifindex()).await)?;
        }
        Ok(())
    }

    async fn ifindex(&self, conn: &Connection<Route>) -> Result<u32> {
        Ok(conn
            .get_link_by_name(&self.dev)
            .await?
            .ok_or_else(|| Error::invalid_message(format!("interface not found: {}", self.dev)))?
            .ifindex())
    }

    /// The tag that marks this limiter's IFB: its alias.
    fn ifb_tag(&self) -> String {
        format!("nlink:ratelimit:{}", self.dev)
    }

    /// This limiter's IFB, if it exists.
    ///
    /// A device of that name that is not an IFB, or an IFB another limiter
    /// tagged — the name of a long interface is cut and hashed, so two can
    /// share one — is an error, not something to reuse or delete (#490).
    /// An untagged IFB of the name, which every release before 0.31 built,
    /// is taken as this limiter's.
    async fn owned_ifb(&self, conn: &Connection<Route>) -> Result<Option<LinkMessage>> {
        match self.find_ifb(conn).await? {
            Ifb::Missing => Ok(None),
            Ifb::Ours(link) => Ok(Some(*link)),
            Ifb::Foreign(why) => Err(Error::invalid_message(format!(
                "RateLimiter({}): {why}; it will not use or delete it",
                self.dev
            ))),
        }
    }

    /// What goes by this limiter's IFB name.
    async fn find_ifb(&self, conn: &Connection<Route>) -> Result<Ifb> {
        let name = self.ifb_name();
        let Some(link) = conn.get_link_by_name(&name).await? else {
            return Ok(Ifb::Missing);
        };
        if link.kind() != Some("ifb") {
            let kind = link.kind().unwrap_or("a device without a kind").to_string();
            return Ok(Ifb::Foreign(format!(
                "{name} exists and is {kind}, not an IFB"
            )));
        }
        Ok(match link.alias() {
            Some(tag) if tag != self.ifb_tag() => {
                Ifb::Foreign(format!("IFB {name} is tagged `{tag}`, not this limiter's"))
            }
            _ => Ifb::Ours(Box::new(link)),
        })
    }

    /// Create this limiter's IFB, tag it and bring it up; its ifindex.
    async fn create_ifb(&self, conn: &Connection<Route>) -> Result<u32> {
        let name = self.ifb_name();
        conn.add_link(IfbLink::new(&name)).await?;
        let ifindex = conn
            .get_link_by_name(&name)
            .await?
            .ok_or_else(|| {
                Error::invalid_message(format!("IFB device vanished after creation: {name}"))
            })?
            .ifindex();
        conn.set_link_alias_by_index(ifindex, &self.ifb_tag())
            .await?;
        conn.set_link_up_by_index(ifindex).await?;
        Ok(ifindex)
    }

    /// Get the IFB device name for this interface.
    /// Name of the IFB device that carries this interface's ingress
    /// shaping. Must fit `IFNAMSIZ` (16 bytes including the NUL).
    ///
    /// Two bugs lived in the old truncation (#281). `&self.dev[..11]`
    /// is a **byte** slice on a `String`, so a device name with a
    /// multi-byte character near the cut **panicked**. And any two
    /// devices sharing an 11-byte prefix mapped to the same IFB, so
    /// removing shaping on one tore down the other's — silently, since
    /// both `RateLimiter`s believe they own it.
    ///
    /// Long names now get a hash suffix instead of a bare prefix: the
    /// collision needs the full name to match, not the first eleven
    /// bytes, and the slice lands on a char boundary by construction. A
    /// 16-bit hash can still collide, which the IFB's tag catches (#490).
    fn ifb_name(&self) -> String {
        const IFNAMSIZ: usize = 15; // 16 including the NUL
        const PREFIX: &str = "ifb_";

        let budget = IFNAMSIZ - PREFIX.len();
        if self.dev.len() <= budget {
            return format!("{PREFIX}{}", self.dev);
        }

        // 4 hex digits of a name hash, so two devices sharing a prefix
        // get different IFBs.
        //
        // FNV-1a rather than `DefaultHasher`: this name has to survive
        // across process invocations — `remove()` must find what
        // `apply()` created — and std explicitly reserves the right to
        // change `DefaultHasher`'s algorithm between releases, which
        // would strand every IFB built by an older binary.
        let hash = {
            let mut h: u32 = 0x811c_9dc5;
            for b in self.dev.as_bytes() {
                h ^= *b as u32;
                h = h.wrapping_mul(0x0100_0193);
            }
            (h ^ (h >> 16)) as u16
        };
        let keep = budget - 5; // 4 hex digits + '_'
        // `floor_char_boundary` is unstable; walk back to one.
        let mut cut = keep.min(self.dev.len());
        while cut > 0 && !self.dev.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{PREFIX}{}_{hash:04x}", &self.dev[..cut])
    }

    /// Build the ingress half from scratch: this limiter's IFB (created or
    /// adopted, tagged and up), the redirect on the interface's hook, and
    /// the HTB tree on the IFB.
    async fn apply_ingress(
        &self,
        conn: &Connection<Route>,
        ifindex: u32,
        limit: &RateLimit,
    ) -> Result<()> {
        let ifb = match self.owned_ifb(conn).await? {
            Some(l) => {
                if l.alias() != Some(self.ifb_tag().as_str()) {
                    conn.set_link_alias_by_index(l.ifindex(), &self.ifb_tag())
                        .await?;
                }
                conn.set_link_up_by_index(l.ifindex()).await?;
                l.ifindex()
            }
            None => self.create_ifb(conn).await?,
        };

        // The hook: a clsact's ingress if the interface has one — never
        // replaced (#490) — else an ingress qdisc, added if missing. The
        // old code deleted whatever sat at `ffff:` first, and a clsact sits
        // there too.
        let hook = match live_ingress_hook(&conn.get_qdiscs_by_index(ifindex).await?) {
            Some(hook) => hook,
            None => {
                conn.add_qdisc_by_index_full(
                    ifindex,
                    TcHandle::INGRESS,
                    None,
                    IngressConfig::new(),
                )
                .await?;
                TcHandle::INGRESS
            }
        };
        for (protocol, priority) in redirects_to(conn, ifindex, hook, ifb).await? {
            conn.del_filter_by_index(ifindex, hook, protocol, priority)
                .await?;
        }
        add_ifb_redirect(conn, ifindex, hook, ifb).await?;
        build_htb(conn, ifb, limit)
            .await
            .map_err(|e| e.with_context(format!("RateLimiter::apply({}): ingress", self.dev)))
    }
}

/// What goes by a `RateLimiter`'s IFB name.
enum Ifb {
    Missing,
    /// An IFB with this limiter's tag, or none.
    Ours(Box<LinkMessage>),
    /// Something else; why it is not this limiter's.
    Foreign(String),
}

/// The classes a limit builds. `1:1` sits straight under the qdisc, so it
/// has no parent to borrow from and can never pass its own rate: with
/// `rate R, ceil C` there, the leaf's ceiling was out of reach and
/// [`RateLimiter::burst_to`] did nothing (measured: 1.1 Mbit/s through a
/// `1mbit`-to-`8mbit` limiter). `1:1` takes the ceiling as its rate; the
/// leaf `1:a` is guaranteed the rate and borrows up to the ceiling
/// (#490).
fn limit_classes(limit: &RateLimit) -> (HtbClassConfig, HtbClassConfig) {
    let ceil = limit.ceil.unwrap_or(limit.rate);
    let with_burst = |cfg: HtbClassConfig| match limit.burst {
        Some(burst) => cfg.burst(burst),
        None => cfg,
    };
    (
        with_burst(HtbClassConfig::new(ceil).ceil(ceil)).build(),
        with_burst(HtbClassConfig::new(limit.rate).ceil(ceil)).build(),
    )
}

/// An fq_codel leaf with `latency` as its target, or the kernel's default,
/// 5 ms, sent explicitly: a replace keeps every attribute it is not sent, so
/// a latency dropped from a recipe stayed (#490).
fn fq_codel_leaf(latency: Option<Duration>) -> FqCodelConfig {
    FqCodelConfig::new().target(latency.unwrap_or(Duration::from_millis(5)))
}

/// The fq_codel leaf a limit builds under `1:a`.
fn leaf_config(limit: &RateLimit) -> FqCodelConfig {
    fq_codel_leaf(limit.latency).build()
}

/// A limit's tree on `dev`, declared: what [`build_htb`] installs.
fn declare_limit(config: NetworkConfig, dev: &str, limit: &RateLimit) -> NetworkConfig {
    let (outer, leaf_class) = limit_classes(limit);
    config
        .qdisc(dev, |q| q.htb().default_class(LEAF_CLASS_MINOR as u32))
        .tc(dev, |t| {
            t.class(TcHandle::major_only(1), TcHandle::new(1, 1), outer)
                .class(TcHandle::new(1, 1), TcHandle::new(1, LEAF_CLASS_MINOR), leaf_class)
                .leaf(
                    TcHandle::new(1, LEAF_CLASS_MINOR),
                    TcHandle::major_only(LEAF_CLASS_MINOR),
                    leaf_config(limit),
                )
        })
}

/// Build a limit's tree on a device from scratch: HTB `1:` (default class
/// `0xa`), `1:1`, `1:a`, and the fq_codel leaf `a:`.
async fn build_htb(conn: &Connection<Route>, ifindex: u32, limit: &RateLimit) -> Result<()> {
    // Whatever is at the root goes; if it cannot, the add says why.
    let _ = conn.del_qdisc_by_index(ifindex, TcHandle::ROOT).await;
    let htb = HtbQdiscConfig::new()
        .default_class(LEAF_CLASS_MINOR as u32)
        .build();
    conn.add_qdisc_by_index_full(ifindex, TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;
    let (outer, leaf_class) = limit_classes(limit);
    conn.add_class_by_index(ifindex, TcHandle::major_only(1), TcHandle::new(1, 1), outer)
        .await?;
    conn.add_class_by_index(
        ifindex,
        TcHandle::new(1, 1),
        TcHandle::new(1, LEAF_CLASS_MINOR),
        leaf_class,
    )
    .await?;
    conn.add_qdisc_by_index_full(
        ifindex,
        TcHandle::new(1, LEAF_CLASS_MINOR),
        Some(TcHandle::major_only(LEAF_CLASS_MINOR)),
        leaf_config(limit),
    )
    .await
}

/// Whether `ifindex`'s root qdisc is a `RateLimiter`'s: an HTB `1:` with
/// its default class.
async fn owns_root(conn: &Connection<Route>, ifindex: u32) -> Result<bool> {
    let tree = dump_live_tree(conn, ifindex).await?;
    Ok(tree.configured_root_qdisc().is_some_and(|q| {
        root_conflict(q, &tree, TcHandle::major_only(1), LEAF_CLASS_MINOR).is_none()
    }))
}

/// The parent an ingress redirect hangs off on a device with these
/// qdiscs: a clsact's ingress hook, or the ingress qdisc. `None` when there
/// is neither.
fn live_ingress_hook(qdiscs: &[TcMessage]) -> Option<TcHandle> {
    if qdiscs.iter().any(|q| q.kind() == Some("clsact")) {
        Some(TcHandle::CLSACT_INGRESS)
    } else if qdiscs.iter().any(|q| q.kind() == Some("ingress")) {
        Some(TcHandle::INGRESS)
    } else {
        None
    }
}

/// An error that says what was to be deleted is already gone is not one.
fn gone_is_ok(result: Result<()>) -> Result<()> {
    match result {
        Err(e) if e.is_not_found() || e.is_no_device() => Ok(()),
        other => other,
    }
}

/// The `(protocol, priority)` of every filter at `hook` on `ifindex` that
/// redirects to `ifb_ifindex`, whatever its shape.
async fn redirects_to(
    conn: &Connection<Route>,
    ifindex: u32,
    hook: TcHandle,
    ifb_ifindex: u32,
) -> Result<Vec<(EthProto, FilterPriority)>> {
    let mut out: Vec<(EthProto, FilterPriority)> = Vec::new();
    for f in conn.get_filters_by_parent_index(ifindex, hook).await? {
        let to_ifb = mirred_targets(&f)
            .iter()
            .any(|(_, target)| *target == ifb_ifindex);
        if to_ifb && !out.contains(&(f.protocol(), f.priority())) {
            out.push((f.protocol(), f.priority()));
        }
    }
    Ok(out)
}

/// The priority of the IFB redirect on a device's ingress hook: the first
/// of the recipe band. It used to sit at 1, in the operator band.
const INGRESS_REDIRECT_PRIORITY: FilterPriority = FilterPriority::recipe(0);


/// Install the matchall egress redirect from `ifindex`'s ingress hook
/// (`hook`: the ingress qdisc's, or a clsact's ingress) to `ifb_ifindex`.
async fn add_ifb_redirect(
    conn: &Connection<Route>,
    ifindex: u32,
    hook: TcHandle,
    ifb_ifindex: u32,
) -> Result<()> {
    use super::action::{ActionList, MirredAction};
    use super::filter::MatchallFilter;

    let filter = MatchallFilter::new()
        .actions(ActionList::new().with(MirredAction::redirect_to_egress(ifb_ifindex)));
    conn.add_filter_by_index_full(
        ifindex,
        hook,
        None,
        EthProto::ALL,
        INGRESS_REDIRECT_PRIORITY,
        filter,
    )
    .await
}

/// What the device's ingress hook holds by way of an IFB redirect.
enum IfbRedirect {
    /// The matchall egress redirect to the IFB, at its priority.
    Correct,
    /// Missing, or wrong: these `(protocol, priority)` filters send to the
    /// IFB some other way (the u32 *ingress* redirect at priority 1 every
    /// release before 0.31 installed) and have to go first — the kernel
    /// refuses a different filter kind at the same priority and protocol.
    Replace(Vec<(EthProto, FilterPriority)>),
}

/// Read the ingress hook `hook` of `ifindex` for the redirect to
/// `ifb_ifindex`.
async fn ifb_redirect_state(
    conn: &Connection<Route>,
    ifindex: u32,
    hook: TcHandle,
    ifb_ifindex: u32,
) -> Result<IfbRedirect> {
    use super::types::tc::action::mirred::TCA_EGRESS_REDIR;

    let filters = conn.get_filters_by_parent_index(ifindex, hook).await?;
    let mut wrong = Vec::new();
    let mut correct = false;
    for f in &filters {
        let targets = mirred_targets(f);
        if !targets.iter().any(|(_, target)| *target == ifb_ifindex) {
            continue;
        }
        let right = f.kind() == Some("matchall")
            && f.priority() == INGRESS_REDIRECT_PRIORITY.as_u16()
            && targets == [(TCA_EGRESS_REDIR, ifb_ifindex)];
        if right {
            correct = true;
        } else if !wrong.contains(&(f.protocol(), f.priority())) {
            wrong.push((f.protocol(), f.priority()));
        }
    }
    Ok(if correct && wrong.is_empty() {
        IfbRedirect::Correct
    } else {
        IfbRedirect::Replace(wrong)
    })
}

/// The `(eaction, ifindex)` of every mirred action of a matchall or u32
/// filter.
fn mirred_targets(filter: &TcMessage) -> Vec<(i32, u32)> {
    use super::attr::AttrIter;
    use super::types::tc::action::{TCA_ACT_KIND, TCA_ACT_OPTIONS, mirred};
    use super::types::tc::filter::{matchall::TCA_MATCHALL_ACT, u32::TCA_U32_ACT};
    use zerocopy::FromBytes;

    let act_attr = match filter.kind() {
        Some("matchall") => TCA_MATCHALL_ACT,
        Some("u32") => TCA_U32_ACT,
        _ => return Vec::new(),
    };
    let Some(options) = filter.raw_options() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ty, acts) in AttrIter::new(options) {
        if ty & 0x7FFF != act_attr {
            continue;
        }
        for (_, act) in AttrIter::new(acts) {
            let is_mirred = AttrIter::new(act)
                .any(|(t, p)| t & 0x7FFF == TCA_ACT_KIND && p.starts_with(b"mirred"));
            if !is_mirred {
                continue;
            }
            let parms = AttrIter::new(act)
                .filter(|(t, _)| t & 0x7FFF == TCA_ACT_OPTIONS)
                .flat_map(|(_, opts)| AttrIter::new(opts))
                .find(|(t, _)| t & 0x7FFF == mirred::TCA_MIRRED_PARMS)
                .and_then(|(_, p)| mirred::TcMirred::read_from_prefix(p).ok())
                .map(|(m, _)| (m.eaction, m.ifindex));
            out.extend(parms);
        }
    }
    out
}

// ============================================================================
// PerHostLimiter
// ============================================================================

/// Per-IP or per-subnet rate limiting.
///
/// Allows setting different rate limits for different hosts or subnets.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::Rate;
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::ratelimit::PerHostLimiter;
///
/// let conn = Connection::<Route>::new()?;
///
/// PerHostLimiter::new("eth0", Rate::mbit(10))
///     .limit_ip("192.168.1.100".parse()?, Rate::mbit(100))
///     .limit_subnet("10.0.0.0/8", Rate::mbit(50))?
///     .limit_port(80, Rate::mbit(500))
///     .apply(&conn)
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct PerHostLimiter {
    /// Target interface name.
    dev: String,
    /// Default rate.
    default_rate: crate::util::Rate,
    /// Per-host rules.
    rules: Vec<HostRule>,
    /// Latency target for AQM.
    latency: Option<Duration>,
}

/// A rate limiting rule for a specific host or match condition.
#[derive(Debug, Clone)]
pub struct HostRule {
    /// Match condition.
    match_: HostMatch,
    /// Rate limit.
    rate: crate::util::Rate,
    /// Ceiling rate.
    ceil: Option<crate::util::Rate>,
}

/// Match condition for per-host limiting.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HostMatch {
    /// Match a specific IP address.
    Ip(IpAddr),
    /// Match a subnet (address and prefix length).
    Subnet(IpAddr, u8),
    /// Match a destination port (TCP and UDP, IPv4 and IPv6).
    Port(u16),
    /// Match a destination port range, inclusive (TCP and UDP, IPv4 and
    /// IPv6).
    PortRange(u16, u16),
    /// Match source IP address.
    SrcIp(IpAddr),
    /// Match source subnet.
    SrcSubnet(IpAddr, u8),
}

#[nlink_macros::send_futures]
impl PerHostLimiter {
    /// Create a new per-host rate limiter with a default rate for unmatched
    /// traffic.
    pub fn new(dev: &str, default_rate: crate::util::Rate) -> Self {
        Self {
            dev: dev.to_string(),
            default_rate,
            rules: Vec::new(),
            latency: None,
        }
    }

    /// Add a rate limit for a specific IP address.
    pub fn limit_ip(mut self, ip: IpAddr, rate: crate::util::Rate) -> Self {
        self.rules.push(HostRule {
            match_: HostMatch::Ip(ip),
            rate,
            ceil: None,
        });
        self
    }

    /// Add a rate limit for a specific IP address with ceiling.
    pub fn limit_ip_with_ceil(
        mut self,
        ip: IpAddr,
        rate: crate::util::Rate,
        ceil: crate::util::Rate,
    ) -> Self {
        self.rules.push(HostRule {
            match_: HostMatch::Ip(ip),
            rate,
            ceil: Some(ceil),
        });
        self
    }

    /// Add a rate limit for a subnet.
    pub fn limit_subnet(mut self, subnet: &str, rate: crate::util::Rate) -> Result<Self> {
        let (addr, prefix) = parse_subnet(subnet)?;
        self.rules.push(HostRule {
            match_: HostMatch::Subnet(addr, prefix),
            rate,
            ceil: None,
        });
        Ok(self)
    }

    /// Add a rate limit for a source IP address.
    pub fn limit_src_ip(mut self, ip: IpAddr, rate: crate::util::Rate) -> Self {
        self.rules.push(HostRule {
            match_: HostMatch::SrcIp(ip),
            rate,
            ceil: None,
        });
        self
    }

    /// Add a rate limit for a source subnet.
    pub fn limit_src_subnet(mut self, subnet: &str, rate: crate::util::Rate) -> Result<Self> {
        let (addr, prefix) = parse_subnet(subnet)?;
        self.rules.push(HostRule {
            match_: HostMatch::SrcSubnet(addr, prefix),
            rate,
            ceil: None,
        });
        Ok(self)
    }

    /// Add a rate limit for TCP and UDP traffic to a destination port,
    /// over IPv4 and IPv6.
    ///
    /// Classified by four flower filters, one per protocol and family, at
    /// the rule's four filter priorities: `100 + 4 * index` onwards, in the
    /// recipe band (#434).
    pub fn limit_port(mut self, port: u16, rate: crate::util::Rate) -> Self {
        self.rules.push(HostRule {
            match_: HostMatch::Port(port),
            rate,
            ceil: None,
        });
        self
    }

    /// Add a rate limit for TCP and UDP traffic, over IPv4 and IPv6, to a
    /// destination port in `start..=end`, the way
    /// [`limit_port`](Self::limit_port) does for one port.
    ///
    /// Classified by four flower port-range filters (kernel 5.2+), at the
    /// priorities `limit_port` takes. A one-port range (`start == end`) is
    /// that port; `start > end` makes `apply()` and `reconcile()` fail
    /// before changing anything.
    pub fn limit_port_range(mut self, start: u16, end: u16, rate: crate::util::Rate) -> Self {
        self.rules.push(HostRule {
            match_: HostMatch::PortRange(start, end),
            rate,
            ceil: None,
        });
        self
    }

    /// Set the latency target for AQM.
    pub fn latency(mut self, latency: Duration) -> Self {
        self.latency = Some(latency);
        self
    }

    /// Apply the per-host rate limits.
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev, rules = self.rules.len()))]
    /// This limiter as a declaration (#645): what [`apply`](Self::apply)
    /// installs on the device — the HTB root, `1:1`, a class, fq_codel leaf
    /// and filters per rule, and the default class — added to `config`,
    /// with the same handles and priorities, so either way of installing it
    /// diffs empty against the other. An error for the rules `apply`
    /// refuses.
    pub fn declare(&self, config: NetworkConfig) -> Result<NetworkConfig> {
        self.check_rules()?;
        let mut filters = Vec::new();
        for (i, rule) in self.rules.iter().enumerate() {
            filters.extend(rule_filters(i, rule, TcHandle::new(1, (i + 2) as u16))?);
        }
        let total_rate: crate::util::Rate =
            self.default_rate + self.rules.iter().map(|r| r.rate).sum::<crate::util::Rate>();
        let parent = TcHandle::new(1, 1);
        Ok(config
            .qdisc(&self.dev, |q| q.htb().default_class(u32::from(DEFAULT_CLASS_MINOR)))
            .tc(&self.dev, |mut t| {
                t = t.class(
                    TcHandle::major_only(1),
                    parent,
                    HtbClassConfig::new(total_rate).ceil(total_rate).build(),
                );
                for (i, rule) in self.rules.iter().enumerate() {
                    let classid = TcHandle::new(1, (i + 2) as u16);
                    t = t
                        .class(
                            parent,
                            classid,
                            HtbClassConfig::new(rule.rate).ceil(rule.ceil.unwrap_or(rule.rate)).build(),
                        )
                        .leaf(
                            classid,
                            TcHandle::major_only((i + 10) as u16),
                            fq_codel_leaf(self.latency).build(),
                        );
                }
                let default = TcHandle::new(1, DEFAULT_CLASS_MINOR);
                t = t
                    .class(
                        parent,
                        default,
                        HtbClassConfig::new(self.default_rate).ceil(self.default_rate).build(),
                    )
                    .leaf(
                        default,
                        TcHandle::major_only(DEFAULT_LEAF_MAJOR),
                        fq_codel_leaf(self.latency).build(),
                    );
                for (protocol, priority, filter) in filters {
                    t = t.filter(TcHandle::major_only(1), priority, protocol, filter);
                }
                t
            }))
    }

    /// [`declare`](Self::declare) into an empty config.
    pub fn to_config(&self) -> Result<NetworkConfig> {
        self.declare(NetworkConfig::new())
    }

    pub async fn apply(&self, conn: &Connection<Route>) -> Result<()> {
        // An unusable rule fails before the live tree is torn down.
        self.check_rules()?;

        // Remove existing root qdisc
        let _ = conn.del_qdisc(&self.dev, TcHandle::ROOT).await;

        // Add HTB qdisc at root with handle 1:
        //
        // Rule classes occupy minors 2..=n+1, so the default class is n+2.
        // This said `n + 1` — the *last rule's* class — so with any rules at
        // all, unmatched traffic was shaped at the last rule's rate instead of
        // `default_rate`; with none, it named the inner class 1:1 and
        // htb_classify fell through to HTB_DIRECT, bypassing the shaper
        // entirely. `reconcile_inner` always used n+2, so the two verbs
        // disagreed and apply-then-reconcile was never a no-op (#269).
        let default_minor = DEFAULT_CLASS_MINOR;
        let default_classid = default_minor as u32;
        let htb = HtbQdiscConfig::new().default_class(default_classid).build();
        conn.add_qdisc_full(
            &self.dev,
            TcHandle::ROOT,
            Some(TcHandle::major_only(1)),
            htb,
        )
        .await?;

        // Add root class (1:1) with sum of all rates as ceiling
        let parent_classid = TcHandle::new(1, 1);
        let major_only_1 = TcHandle::major_only(1);
        let total_rate: crate::util::Rate =
            self.default_rate + self.rules.iter().map(|r| r.rate).sum::<crate::util::Rate>();
        let root_config = HtbClassConfig::new(total_rate).ceil(total_rate).build();
        conn.add_class(&self.dev, major_only_1, parent_classid, root_config)
            .await?;

        // Add classes for each rule
        for (i, rule) in self.rules.iter().enumerate() {
            let classid = TcHandle::new(1, (i + 2) as u16);
            let leaf_handle = TcHandle::major_only((i + 10) as u16);
            let class_config = HtbClassConfig::new(rule.rate).ceil(rule.ceil.unwrap_or(rule.rate));
            conn.add_class(&self.dev, parent_classid, classid, class_config.build())
                .await?;

            // Add fq_codel leaf qdisc
            let fq_codel = fq_codel_leaf(self.latency);
            conn.add_qdisc_full(&self.dev, classid, Some(leaf_handle), fq_codel.build())
                .await?;

            // Add flower filter to classify traffic to this class
            self.add_filter_for_rule(conn, i, rule).await?;
        }

        // Add default class for unmatched traffic
        let default_classid = TcHandle::new(1, default_minor);
        let default_handle = TcHandle::major_only(DEFAULT_LEAF_MAJOR);
        let default_config = HtbClassConfig::new(self.default_rate)
            .ceil(self.default_rate)
            .build();
        conn.add_class(&self.dev, parent_classid, default_classid, default_config)
            .await?;

        // Add fq_codel leaf for default class
        let fq_codel = fq_codel_leaf(self.latency);
        conn.add_qdisc_full(
            &self.dev,
            default_classid,
            Some(default_handle),
            fq_codel.build(),
        )
        .await?;

        Ok(())
    }

    /// Remove the per-host rate limits: the device's root qdisc, if it is
    /// a tree a `PerHostLimiter` built — the HTB `1:` with its default
    /// class and fq_codel leaves (#515). Another root, a user's or a
    /// `PerPeerImpairer`'s, is left alone; this deleted whatever root the
    /// device had, and swallowed every error. An error other than "already
    /// gone" is returned now.
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev))]
    pub async fn remove(&self, conn: &Connection<Route>) -> Result<()> {
        let Some(link) = conn.get_link_by_name(&self.dev).await? else {
            return Ok(());
        };
        let tree = dump_live_tree(conn, link.ifindex()).await?;
        if recipe_owns_root(&tree, DEFAULT_CLASS_MINOR, "fq_codel") {
            gone_is_ok(
                conn.del_qdisc_by_index(link.ifindex(), TcHandle::ROOT)
                    .await,
            )?;
        }
        Ok(())
    }

    // ---- reconcile ----

    /// Non-destructively converge the live TC tree to match this
    /// limiter's desired state.
    ///
    /// Unlike [`apply()`], `reconcile()` dumps the existing tree, diffs
    /// it against what the helper would build, and emits the minimum
    /// set of `add_*` / `change_*` / `del_*` operations to converge.
    /// Calling `reconcile()` twice in a row with no other changes makes
    /// **zero** kernel calls on the second invocation.
    ///
    /// If the live root qdisc is the wrong kind (not HTB), reconcile
    /// returns an error by default. Pass [`ReconcileOptions::with_fallback_to_apply`]`(true)`
    /// to instead trigger a destructive rebuild via [`apply()`].
    ///
    /// [`apply()`]: Self::apply
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev, rules = self.rules.len()))]
    pub async fn reconcile(&self, conn: &Connection<Route>) -> Result<ReconcileReport> {
        self.reconcile_with_options(conn, ReconcileOptions::new())
            .await
    }

    /// Compute what [`reconcile()`] would do without making kernel calls.
    ///
    /// [`reconcile()`]: Self::reconcile
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev, rules = self.rules.len()))]
    pub async fn reconcile_dry_run(&self, conn: &Connection<Route>) -> Result<ReconcileReport> {
        self.reconcile_with_options(conn, ReconcileOptions::new().with_dry_run(true))
            .await
    }

    /// [`reconcile()`] with explicit [`ReconcileOptions`].
    ///
    /// [`reconcile()`]: Self::reconcile
    #[tracing::instrument(level = "info", skip_all, fields(dev = %self.dev, rules = self.rules.len(), dry_run = opts.dry_run, fallback = opts.fallback_to_apply))]
    pub async fn reconcile_with_options(
        &self,
        conn: &Connection<Route>,
        opts: ReconcileOptions,
    ) -> Result<ReconcileReport> {
        self.check_rules()?;
        // Resolve interface for typed-by-index calls.
        let link = conn
            .get_link_by_name(&self.dev)
            .await?
            .ok_or_else(|| Error::invalid_message(format!("interface not found: {}", self.dev)))?;
        let ifindex = link.ifindex();
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

        let parent_classid = TcHandle::new(1, 1);
        let root_handle = TcHandle::major_only(1);
        let default_minor = DEFAULT_CLASS_MINOR;
        let default_classid = TcHandle::new(1, default_minor);
        let default_leaf_handle = TcHandle::major_only(DEFAULT_LEAF_MAJOR);
        let total_rate: crate::util::Rate =
            self.default_rate + self.rules.iter().map(|r| r.rate).sum::<crate::util::Rate>();
        let target_us = self.latency.map(|d| d.as_micros() as u32);

        // 1. Root HTB qdisc.
        match tree.configured_root_qdisc() {
            None => {
                if !opts.dry_run {
                    let cfg = HtbQdiscConfig::new()
                        .default_class(default_minor as u32)
                        .build();
                    conn.add_qdisc_by_index_full(ifindex, TcHandle::ROOT, Some(root_handle), cfg)
                        .await
                        .map_err(|e| e.with_context("PerHostLimiter::reconcile: add HTB root"))?;
                }
                report.changes_made += 1;
                report.root_modified = true;
            }
            Some(q) => {
                // Another root, or another default class: HTB cannot
                // change either in place (#491).
                if let Some(conflict) = root_conflict(q, &tree, root_handle, default_minor) {
                    if opts.fallback_to_apply {
                        if opts.dry_run {
                            report.changes_made += 1;
                            report.root_modified = true;
                            return Ok(report);
                        }
                        return self.apply_as_reconcile(conn).await;
                    }
                    return Err(Error::invalid_message(format!(
                        "PerHostLimiter::reconcile: root qdisc on {} is {conflict}; pass \
                         ReconcileOptions::with_fallback_to_apply(true) to rebuild",
                        self.dev
                    )));
                }
            }
        }

        // 2. Parent class 1:1 with rate=ceil=total_rate.
        let total_bps = total_rate.as_bytes_per_sec();
        match tree.class(parent_classid) {
            None => {
                if !opts.dry_run {
                    let cfg = HtbClassConfig::new(total_rate).ceil(total_rate).build();
                    conn.add_class_by_index(ifindex, root_handle, parent_classid, cfg)
                        .await
                        .map_err(|e| {
                            e.with_context("PerHostLimiter::reconcile: add parent class 1:1")
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
                                e.with_context("PerHostLimiter::reconcile: update parent class 1:1")
                            })?;
                    }
                    report.changes_made += 1;
                    report.root_modified = true;
                }
            }
        }

        // 3. Per-rule classes + fq_codel leaves + filters.
        for (i, rule) in self.rules.iter().enumerate() {
            let classid = TcHandle::new(1, (i + 2) as u16);
            let leaf_handle = TcHandle::major_only((i + 10) as u16);
            let class_rate = rule.rate;
            let class_ceil = rule.ceil.unwrap_or(rule.rate);
            let class_rate_bps = class_rate.as_bytes_per_sec();
            let class_ceil_bps = class_ceil.as_bytes_per_sec();

            let mut rule_added = false;
            let mut rule_modified = false;

            // 3a. Class.
            match tree.class(classid) {
                None => {
                    if !opts.dry_run {
                        let cfg = HtbClassConfig::new(class_rate).ceil(class_ceil).build();
                        conn.add_class_by_index(ifindex, parent_classid, classid, cfg)
                            .await
                            .map_err(|e| {
                                e.with_context(format!(
                                    "PerHostLimiter::reconcile: add class {classid}"
                                ))
                            })?;
                    }
                    report.changes_made += 1;
                    rule_added = true;
                }
                Some(c) => {
                    if !htb_class_rates_match(c, class_rate_bps, class_ceil_bps) {
                        if !opts.dry_run {
                            let cfg = HtbClassConfig::new(class_rate).ceil(class_ceil).build();
                            conn.change_class_by_index(ifindex, parent_classid, classid, cfg)
                                .await
                                .map_err(|e| {
                                    e.with_context(format!(
                                        "PerHostLimiter::reconcile: update class {classid}"
                                    ))
                                })?;
                        }
                        report.changes_made += 1;
                        rule_modified = true;
                    }
                }
            }

            // 3b. fq_codel leaf.
            match tree.leaf_for(classid) {
                None => {
                    if !opts.dry_run {
                        let leaf = fq_codel_leaf(self.latency);
                        conn.add_qdisc_by_index_full(
                            ifindex,
                            classid,
                            Some(leaf_handle),
                            leaf.build(),
                        )
                        .await
                        .map_err(|e| {
                            e.with_context(format!(
                                "PerHostLimiter::reconcile: add fq_codel leaf at {classid}"
                            ))
                        })?;
                    }
                    report.changes_made += 1;
                    if !rule_added {
                        rule_modified = true;
                    }
                }
                Some(q) => {
                    if !fq_codel_target_matches(target_us, q) {
                        if !opts.dry_run {
                            let leaf = fq_codel_leaf(self.latency);
                            conn.replace_qdisc_by_index_full(
                                ifindex,
                                classid,
                                Some(leaf_handle),
                                leaf.build(),
                            )
                            .await
                            .map_err(|e| {
                                e.with_context(format!(
                                    "PerHostLimiter::reconcile: update fq_codel leaf at \
                                     {classid}"
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

            // 3c. Filter(s) at root parent: rule i's at 100 + 4i onwards
            // (`rule_filters`), one for an address match, four for a port.
            self.reconcile_filter_for_rule(
                conn,
                ifindex,
                &tree,
                i,
                rule,
                classid,
                opts,
                &mut rule_added,
                &mut rule_modified,
                &mut report,
            )
            .await?;

            if rule_added {
                report.rules_added += 1;
            } else if rule_modified {
                report.rules_modified += 1;
            }
        }

        // 4. Default class — always present in the desired tree.
        let default_bps = self.default_rate.as_bytes_per_sec();
        match tree.class(default_classid) {
            None => {
                if !opts.dry_run {
                    let cfg = HtbClassConfig::new(self.default_rate)
                        .ceil(self.default_rate)
                        .build();
                    conn.add_class_by_index(ifindex, parent_classid, default_classid, cfg)
                        .await
                        .map_err(|e| {
                            e.with_context("PerHostLimiter::reconcile: add default class")
                        })?;
                }
                report.changes_made += 1;
                report.default_modified = true;
            }
            Some(c) => {
                if !htb_class_rates_match(c, default_bps, default_bps) {
                    if !opts.dry_run {
                        let cfg = HtbClassConfig::new(self.default_rate)
                            .ceil(self.default_rate)
                            .build();
                        conn.change_class_by_index(ifindex, parent_classid, default_classid, cfg)
                            .await
                            .map_err(|e| {
                                e.with_context("PerHostLimiter::reconcile: update default class")
                            })?;
                    }
                    report.changes_made += 1;
                    report.default_modified = true;
                }
            }
        }

        // 4b. Default fq_codel leaf — always present.
        match tree.leaf_for(default_classid) {
            None => {
                if !opts.dry_run {
                    let leaf = fq_codel_leaf(self.latency);
                    conn.add_qdisc_by_index_full(
                        ifindex,
                        default_classid,
                        Some(default_leaf_handle),
                        leaf.build(),
                    )
                    .await
                    .map_err(|e| {
                        e.with_context("PerHostLimiter::reconcile: add default fq_codel leaf")
                    })?;
                }
                report.changes_made += 1;
                report.default_modified = true;
            }
            // A leaf at the pre-0.31 `ffff:` (#485): delete it, then add one
            // at the new handle.
            Some(q) if q.handle() != default_leaf_handle => {
                if !opts.dry_run {
                    conn.del_qdisc_by_index_full(ifindex, default_classid, Some(q.handle()))
                        .await
                        .map_err(|e| {
                            e.with_context("PerHostLimiter::reconcile: remove legacy default leaf")
                        })?;
                    let leaf = fq_codel_leaf(self.latency);
                    conn.add_qdisc_by_index_full(
                        ifindex,
                        default_classid,
                        Some(default_leaf_handle),
                        leaf.build(),
                    )
                    .await
                    .map_err(|e| {
                        e.with_context("PerHostLimiter::reconcile: re-add default fq_codel leaf")
                    })?;
                }
                report.changes_made += 1;
                report.default_modified = true;
            }
            Some(q) => {
                if !fq_codel_target_matches(target_us, q) {
                    if !opts.dry_run {
                        let leaf = fq_codel_leaf(self.latency);
                        conn.replace_qdisc_by_index_full(
                            ifindex,
                            default_classid,
                            Some(default_leaf_handle),
                            leaf.build(),
                        )
                        .await
                        .map_err(|e| {
                            e.with_context(
                                "PerHostLimiter::reconcile: update default fq_codel leaf",
                            )
                        })?;
                    }
                    report.changes_made += 1;
                    report.default_modified = true;
                }
            }
        }

        // 5. Stale removal.
        self.collect_stale_and_unmanaged(&tree, &mut report, conn, ifindex, opts)
            .await?;

        Ok(report)
    }

    #[allow(clippy::too_many_arguments)]
    async fn reconcile_filter_for_rule(
        &self,
        conn: &Connection<Route>,
        ifindex: u32,
        tree: &LiveTree,
        index: usize,
        rule: &HostRule,
        classid: TcHandle,
        opts: ReconcileOptions,
        rule_added: &mut bool,
        rule_modified: &mut bool,
        report: &mut ReconcileReport,
    ) -> Result<()> {
        let root_handle = TcHandle::major_only(1);

        // For each filter we want to install for this rule, check vs
        // the live tree at that priority. `apply()` installs the same
        // list.
        let want = rule_filters(index, rule, classid)?;

        for (proto, prio, filter) in want {
            let live = tree.filter_at_priority(prio);
            // Compare the match keys, not just kind + classid: both the
            // priority and the classid come from the rule's *index*, so
            // an edited rule reused them and reconcile saw no change
            // (#270).
            let ok = live
                .map(|f| flower_matches(&filter, proto, f))
                .unwrap_or(false);
            if !ok {
                if !opts.dry_run {
                    if let Some(stale) = live {
                        let _ = conn
                            .del_filter_by_index(ifindex, root_handle, stale.protocol(), prio)
                            .await;
                    }
                    conn.add_filter_by_index_full(ifindex, root_handle, None, proto, prio, filter)
                        .await
                        .map_err(|e| {
                            e.with_context(format!(
                                "PerHostLimiter::reconcile: add filter prio={prio} \
                             classid={classid}"
                            ))
                        })?;
                }
                report.changes_made += 1;
                if !*rule_added {
                    *rule_modified = true;
                }
            }
        }
        Ok(())
    }

    async fn apply_as_reconcile(&self, conn: &Connection<Route>) -> Result<ReconcileReport> {
        let n = self.rules.len();
        self.apply(conn).await?;
        Ok(ReconcileReport {
            // 1 root + 1 parent + 3 per rule (class+leaf+filter, +3 for
            // a port match's other filters) + 1 default class + 1 default
            // leaf. Estimate; undercounting port matches is ok.
            changes_made: 2 + 3 * n + 2,
            rules_added: n,
            root_modified: true,
            default_modified: true,
            ..ReconcileReport::default()
        })
    }

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
        // Stale classes in major 1: — computed first, because a filter
        // bound to one has to go before it, whatever band it sits in.
        let mut stale_classes: Vec<TcHandle> = Vec::new();
        for handle in tree.classes.keys() {
            if handle.major() != 1 {
                continue;
            }
            let minor = handle.minor();
            if minor == 0 || minor == 1 {
                continue;
            }
            if (minor >= 2 && minor <= max_minor) || minor == DEFAULT_CLASS_MINOR {
                continue;
            }
            stale_classes.push(*handle);
        }

        // The priorities the desired filters take: the list `apply()`
        // installs and step 3c just reconciled.
        let mut desired: HashSet<FilterPriority> = HashSet::new();
        for (i, rule) in self.rules.iter().enumerate() {
            let classid = TcHandle::new(1, (i + 2) as u16);
            desired.extend(
                rule_filters(i, rule, classid)?
                    .into_iter()
                    .map(|(_, p, _)| p),
            );
        }
        let is_rule_class = |c: TcHandle| c.major() == 1 && (2..=max_minor).contains(&c.minor());

        let mut stale_filters: Vec<(FilterPriority, EthProto, TcHandle)> = Vec::new();
        for f in &tree.root_filters {
            let prio = f.priority();
            // Step 3c reconciled every priority a rule wants, from this same
            // snapshot; whatever stood there has been compared, and replaced
            // if it differed. Deleting it again here would delete the
            // replacement.
            if desired.contains(&prio) {
                continue;
            }
            let target = flower_classid(f);
            // Anywhere else, a filter that sends traffic into one of this
            // limiter's classes is one of its own that no rule installs any
            // more:
            // - a removed rule's, bound to the class this reconcile removes
            //   (deleting the class first failed with EBUSY, "HTB class in
            //   use": #413, and #291 for PerPeerImpairer);
            // - a rule's that changed shape, such as a port rule turned into
            //   an address rule, still classifying the port's traffic into
            //   the class the address rule now owns (#425);
            // - one at a priority the layout before 0.30 used, `index + 1`
            //   and `index + 101/201/301`, which the first reconcile after
            //   upgrading moves into the recipe band (#434).
            if target.is_some_and(|c| stale_classes.contains(&c) || is_rule_class(c)) {
                if !stale_filters
                    .iter()
                    .any(|(p, proto, _)| *p == prio && *proto == f.protocol())
                {
                    stale_filters.push((prio, f.protocol(), f.parent()));
                }
                continue;
            }
            // Not ours: left alone, and reported.
            report.unmanaged.push(UnmanagedObject {
                kind: "filter",
                handle: f.parent(),
                priority: Some(prio),
            });
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
        for handle in &stale_classes {
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
                    "PerHostLimiter::reconcile: remove stale class {handle}"
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

        Ok(())
    }

    /// Fail on a rule no filter can express (an empty port range, a rule
    /// past the last priority), or on two filters that need the same
    /// priority, before anything is changed.
    ///
    /// [`rule_filters`] gives every rule its own four priorities, so the
    /// last check is a guard: the kernel would refuse a second filter at a
    /// priority if its ethertype differed and put it beside the first if
    /// not — where `reconcile()`, which reads one filter per priority, would
    /// replace one with the other on every pass. The layout before 0.30
    /// could do that past 100 rules.
    fn check_rules(&self) -> Result<()> {
        let mut taken: HashMap<FilterPriority, usize> = HashMap::new();
        for (i, rule) in self.rules.iter().enumerate() {
            for (_, prio, _) in rule_filters(i, rule, TcHandle::new(1, (i + 2) as u16))? {
                if let Some(other) = taken.insert(prio, i) {
                    return Err(Error::invalid_message(format!(
                        "PerHostLimiter: rules {other} and {i} both need filter priority \
                         {prio}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Add the flower filters for a specific rule — the ones `reconcile()`
    /// compares against.
    async fn add_filter_for_rule(
        &self,
        conn: &Connection<Route>,
        index: usize,
        rule: &HostRule,
    ) -> Result<()> {
        let classid = TcHandle::new(1, (index + 2) as u16);
        for (proto, prio, filter) in rule_filters(index, rule, classid)? {
            conn.add_filter_full(&self.dev, TcHandle::major_only(1), None, proto, prio, filter)
                .await?;
        }
        Ok(())
    }
}

/// Where a `PerHostLimiter`'s filters start: the recipe band, as
/// [`FilterPriority`] documents. Before 0.30 they started at 1, in the band
/// it reserves for operators (#434).
const FIRST_RULE_PRIORITY: u16 = FilterPriority::RECIPE_BAND_START;

/// The priorities each rule takes, from `FIRST_RULE_PRIORITY + 4 * index`:
/// IPv4 TCP (or an address rule's one filter), IPv4 UDP, IPv6 TCP, IPv6 UDP.
const PRIORITIES_PER_RULE: u16 = 4;

/// How many rules fit: the last one's fourth priority is `u16::MAX`.
const MAX_RULES: usize =
    ((u16::MAX - FIRST_RULE_PRIORITY + 1) / PRIORITIES_PER_RULE) as usize;

/// The flower filters that classify a `PerHostLimiter` rule's traffic
/// into its class, as `(tcm_info protocol, priority, filter)`.
///
/// One list for both verbs. `apply()` and `reconcile()` each built their
/// own, and they had drifted: for a port range `reconcile()` built none,
/// and `apply()` none for a range wider than 10 ports — and for a narrower
/// one a TCP filter per port, errors ignored, no UDP (#416).
///
/// Rule `index` owns the four priorities from `100 + 4 * index`, in the
/// recipe band (#434). An address rule uses the first. A port rule uses all
/// four, one per protocol and IP family: IPv4 TCP, IPv4 UDP, IPv6 TCP,
/// IPv6 UDP. They cannot share one: a priority holds a single `tcf_proto`
/// with one ethertype, and the kernel refuses another there ("Filter with
/// specified priority/protocol not found"); and `reconcile()` reads one
/// filter per priority. The IPv6 pair was missing until #425, so IPv6
/// traffic to a limited port went to the default class.
///
/// Consecutive priorities per rule mean every protocol meets the rules in
/// the order they were declared. Before 0.30 an address rule sat at
/// `index + 1` and a port rule's other filters at `index + 101/201/301`,
/// so for UDP and IPv6 traffic every address rule came first.
fn rule_filters(
    index: usize,
    rule: &HostRule,
    classid: TcHandle,
) -> Result<Vec<(EthProto, FilterPriority, super::filter::FlowerFilter)>> {
    use super::filter::FlowerFilter;

    // tcm_info etherproto values. The kernel walks the per-protocol
    // dispatch table before flower's own KEY_ETH_TYPE attribute is
    // consulted, so passing the wrong value here means the filter
    // never matches its intended packets.
    const ETH_P_IP: EthProto = EthProto::IP;
    const ETH_P_IPV6: EthProto = EthProto::IPV6;

    // `.ipv4()` / `.ipv6()` on the port filters is load-bearing, not
    // decoration: cls_flower discards `ip_proto` and the port keys unless
    // the request carries TCA_FLOWER_KEY_ETH_TYPE, and a port rule
    // without it installs as a match-all that claims every packet
    // on the interface (#288). The address setters imply it; the
    // L4 ones do not.

    if index >= MAX_RULES {
        return Err(Error::invalid_message(format!(
            "PerHostLimiter: rule {index} is past the last filter priority — a limiter holds \
             at most {MAX_RULES} rules (four priorities each, from {FIRST_RULE_PRIORITY})"
        )));
    }
    let priority = FilterPriority::new(FIRST_RULE_PRIORITY + PRIORITIES_PER_RULE * index as u16);
    let base = || FlowerFilter::new().classid(classid);
    let prefix_of = |ip: &IpAddr, subnet: Option<u8>| {
        subnet.unwrap_or(if ip.is_ipv4() { 32 } else { 128 })
    };
    // TCP and UDP, IPv4 and IPv6, each with `port` set on it, at the rule's
    // four priorities.
    let tcp_and_udp = |set_port: &dyn Fn(FlowerFilter) -> FlowerFilter| {
        let filter = |eth_p: EthProto, offset: u16, proto: fn(FlowerFilter) -> FlowerFilter| {
            let prio = FilterPriority::new(priority.as_u16() + offset);
            let family = if eth_p == ETH_P_IP {
                base().ipv4()
            } else {
                base().ipv6()
            };
            (eth_p, prio, set_port(proto(family.priority(prio))).build())
        };
        let [tcp4, udp4, tcp6, udp6] = [0, 1, 2, 3];
        vec![
            filter(ETH_P_IP, tcp4, FlowerFilter::ip_proto_tcp),
            filter(ETH_P_IP, udp4, FlowerFilter::ip_proto_udp),
            filter(ETH_P_IPV6, tcp6, FlowerFilter::ip_proto_tcp),
            filter(ETH_P_IPV6, udp6, FlowerFilter::ip_proto_udp),
        ]
    };

    Ok(match &rule.match_ {
        HostMatch::Ip(ip) | HostMatch::Subnet(ip, _) => {
            let subnet = match &rule.match_ {
                HostMatch::Subnet(_, p) => Some(*p),
                _ => None,
            };
            let prefix = prefix_of(ip, subnet);
            match ip {
                IpAddr::V4(addr) => vec![(
                    ETH_P_IP,
                    priority,
                    base().priority(priority).dst_ipv4(*addr, prefix).build(),
                )],
                IpAddr::V6(addr) => vec![(
                    ETH_P_IPV6,
                    priority,
                    base().priority(priority).dst_ipv6(*addr, prefix).build(),
                )],
            }
        }
        HostMatch::SrcIp(ip) | HostMatch::SrcSubnet(ip, _) => {
            let subnet = match &rule.match_ {
                HostMatch::SrcSubnet(_, p) => Some(*p),
                _ => None,
            };
            let prefix = prefix_of(ip, subnet);
            match ip {
                IpAddr::V4(addr) => vec![(
                    ETH_P_IP,
                    priority,
                    base().priority(priority).src_ipv4(*addr, prefix).build(),
                )],
                IpAddr::V6(addr) => vec![(
                    ETH_P_IPV6,
                    priority,
                    base().priority(priority).src_ipv6(*addr, prefix).build(),
                )],
            }
        }
        HostMatch::Port(port) => tcp_and_udp(&|f| f.dst_port(*port)),
        // The kernel takes a port range only with `min < max`
        // (`fl_set_key_port_range`), so a one-port range is the port.
        HostMatch::PortRange(start, end) if start == end => tcp_and_udp(&|f| f.dst_port(*start)),
        HostMatch::PortRange(start, end) if start < end => {
            tcp_and_udp(&|f| f.dst_port_range(*start, *end))
        }
        HostMatch::PortRange(start, end) => {
            return Err(Error::invalid_message(format!(
                "PerHostLimiter: port range {start}-{end} is empty (start is above end)"
            )));
        }
    })
}

/// Parse a subnet string like "10.0.0.0/8" into address and prefix length.
fn parse_subnet(subnet: &str) -> Result<(IpAddr, u8)> {
    let parts: Vec<&str> = subnet.split('/').collect();
    if parts.len() != 2 {
        return Err(Error::invalid_message(format!(
            "invalid subnet format: {}",
            subnet
        )));
    }

    let addr: IpAddr = parts[0]
        .parse()
        .map_err(|_| Error::invalid_message(format!("invalid IP address: {}", parts[0])))?;

    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| Error::invalid_message(format!("invalid prefix length: {}", parts[1])))?;

    // Validate prefix length
    let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return Err(Error::invalid_message(format!(
            "prefix length {} exceeds maximum {} for address type",
            prefix, max_prefix
        )));
    }

    Ok((addr, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;


    // ====================================================================
    // #258 / #269 — the HTB `default` must name a class that exists
    // ====================================================================
    //
    // Three separate default-class bugs shipped because nothing checked
    // that `defcls` and the created class agreed. When `htb_classify`
    // cannot resolve `defcls` it returns HTB_DIRECT and the packet
    // leaves the interface unshaped — no error, no log, just a rate
    // limit that silently does nothing.

    /// Read `default` out of an `HtbQdiscConfig`'s serialized options.
    fn htb_defcls(cfg: &HtbQdiscConfig) -> u32 {
        use crate::netlink::{tc::QdiscConfig, types::tc::qdisc::htb::TCA_HTB_INIT};

        let mut builder = crate::netlink::builder::MessageBuilder::new(0, 0);
        let start = builder.len();
        cfg.write_options(&mut builder).expect("write options");
        let blob = builder.as_bytes()[start..builder.len()].to_vec();

        // TCA_HTB_INIT payload is `struct tc_htb_glob`:
        //   version, rate2quantum, defcls, debug, direct_pkts
        // so `defcls` is the third u32.
        let mut input = &blob[..];
        while input.len() >= 4 {
            let len = u16::from_ne_bytes(input[..2].try_into().unwrap()) as usize;
            let ty = u16::from_ne_bytes(input[2..4].try_into().unwrap()) & 0x3FFF;
            assert!(len >= 4 && input.len() >= len, "malformed htb options");
            if ty == TCA_HTB_INIT {
                let p = &input[4..len];
                assert!(p.len() >= 12, "tc_htb_glob truncated");
                return u32::from_ne_bytes(p[8..12].try_into().unwrap());
            }
            let aligned = (len + 3) & !3;
            if input.len() <= aligned {
                break;
            }
            input = &input[aligned..];
        }
        panic!("no TCA_HTB_INIT in HtbQdiscConfig options");
    }

    #[test]
    fn ratelimiter_default_class_is_the_class_it_creates() {
        // `default_class(0x10)` (16) against a class at `1:10` (10) is
        // exactly the shape of #258. Both now read one constant.
        let cfg = HtbQdiscConfig::new()
            .default_class(LEAF_CLASS_MINOR as u32)
            .build();
        assert_eq!(htb_defcls(&cfg), LEAF_CLASS_MINOR as u32);
        assert_eq!(
            TcHandle::new(1, LEAF_CLASS_MINOR).minor(),
            htb_defcls(&cfg) as u16,
            "HTB default names a minor no class is created at"
        );
    }

    #[test]
    fn per_host_default_class_never_collides_with_a_rule_class() {
        // Rule i takes minor i+2, so n rules occupy 2..=n+1. The default
        // used to be n+2 in `reconcile` and n+1 in `apply` — the latter
        // being the *last rule's* class (#269). It is now a constant
        // outside the rules' range entirely, so no rule count can reach
        // it and no HTB `default` ever needs rewriting (#291).
        for n in 0..64usize {
            let rule_minors: Vec<u16> = (0..n).map(|i| (i + 2) as u16).collect();
            assert!(
                !rule_minors.contains(&DEFAULT_CLASS_MINOR),
                "n={n}: default class collides with a rule class"
            );
        }
        assert_ne!(DEFAULT_CLASS_MINOR, 0, "0 is the qdisc itself");
        assert_ne!(DEFAULT_CLASS_MINOR, 1, "1:1 is the parent class");
    }

    #[test]
    fn per_host_default_class_is_the_class_the_htb_default_names() {
        // `apply` and `reconcile` both read the same constant, so the
        // qdisc's `defcls` and the class that gets created cannot drift
        // apart the way they did in #258 and #269.
        let cfg = HtbQdiscConfig::new()
            .default_class(DEFAULT_CLASS_MINOR as u32)
            .build();
        assert_eq!(htb_defcls(&cfg), DEFAULT_CLASS_MINOR as u32);
        assert_eq!(
            TcHandle::new(1, DEFAULT_CLASS_MINOR).minor(),
            htb_defcls(&cfg) as u16
        );
    }

    // ====================================================================
    // #268 — ingress/clsact are parent-fixed
    // ====================================================================

    #[test]
    fn hook_qdiscs_declare_their_only_legal_parent() {
        use crate::netlink::tc::{ClsactConfig, FqCodelConfig, IngressConfig, QdiscConfig};

        // `ingress_init`/`clsact_init` answer EOPNOTSUPP for any parent
        // but TC_H_INGRESS, so `add_qdisc`'s TC_H_ROOT default could
        // never work for these two.
        assert_eq!(IngressConfig::new().fixed_parent(), Some(TcHandle::INGRESS));
        assert_eq!(ClsactConfig::new().fixed_parent(), Some(TcHandle::INGRESS));
        // Real schedulers keep the root default.
        assert_eq!(FqCodelConfig::new().build().fixed_parent(), None);
    }

    #[test]
    fn test_rate_limit_new() {
        use crate::util::Rate;
        let limit = RateLimit::new(Rate::bytes_per_sec(1_000_000));
        assert_eq!(limit.rate, Rate::bytes_per_sec(1_000_000));
        assert!(limit.ceil.is_none());
        assert!(limit.burst.is_none());
    }

    #[test]
    fn test_rate_limit_typed_units() {
        use crate::util::Rate;
        let limit = RateLimit::new(Rate::mbit(100));
        assert_eq!(limit.rate.as_bytes_per_sec(), 12_500_000);

        let limit = RateLimit::new(Rate::gbit(1));
        assert_eq!(limit.rate.as_bytes_per_sec(), 125_000_000);
    }

    #[test]
    fn test_rate_limiter_builder() {
        use crate::util::Rate;
        let limiter = RateLimiter::new("eth0")
            .egress(Rate::bytes_per_sec(1_000_000))
            .ingress(Rate::bytes_per_sec(2_000_000))
            .burst_to(Rate::bytes_per_sec(3_000_000));

        assert_eq!(limiter.dev, "eth0");
        assert!(limiter.egress.is_some());
        assert!(limiter.ingress.is_some());
        assert_eq!(
            limiter.egress.as_ref().unwrap().rate,
            Rate::bytes_per_sec(1_000_000)
        );
        assert_eq!(
            limiter.egress.as_ref().unwrap().ceil,
            Some(Rate::bytes_per_sec(3_000_000))
        );
        assert_eq!(
            limiter.ingress.as_ref().unwrap().rate,
            Rate::bytes_per_sec(2_000_000)
        );
        assert_eq!(
            limiter.ingress.as_ref().unwrap().ceil,
            Some(Rate::bytes_per_sec(3_000_000))
        );
    }

    #[test]
    fn test_ifb_name_generation() {
        let limiter = RateLimiter::new("eth0");
        assert_eq!(limiter.ifb_name(), "ifb_eth0");

        let limiter = RateLimiter::new("verylonginterfacename");
        assert!(limiter.ifb_name().len() <= 15);
    }

    #[test]
    fn ifb_names_do_not_collide_on_a_shared_prefix() {
        // The old truncation took the first 11 bytes, so any two
        // devices sharing that prefix mapped to the same IFB — and
        // removing shaping on one tore down the other's (#281).
        let a = RateLimiter::new("verylongname-aaaa").ifb_name();
        let b = RateLimiter::new("verylongname-bbbb").ifb_name();
        assert_ne!(a, b, "distinct devices must get distinct IFBs");
        assert!(a.len() <= 15 && b.len() <= 15, "{a} / {b}");
    }

    #[test]
    fn ifb_name_does_not_panic_on_a_multibyte_name() {
        // `&self.dev[..11]` is a *byte* slice on a `String`: a
        // multi-byte character straddling the cut panicked (#281).
        // Interface names are bytes to the kernel, so a name like this
        // is unusual but reachable — and a panic is never the answer.
        for dev in ["ααααααααααααααα", "eth-日本語-interface", "ααα"] {
            let name = RateLimiter::new(dev).ifb_name();
            assert!(name.len() <= 15, "{dev} -> {name} ({} bytes)", name.len());
        }
    }

    /// The attribute ids a rule filter writes.
    fn filter_keys(f: &super::super::filter::FlowerFilter) -> Vec<u16> {
        use super::super::filter::FilterConfig;
        let mut b = crate::netlink::builder::MessageBuilder::new(0, 0);
        let start = b.len();
        f.write_options(&mut b).expect("a usable filter");
        crate::netlink::attr::AttrIter::new(&b.as_bytes()[start..])
            .map(|(t, _)| t)
            .collect()
    }

    /// A port range gets TCP and UDP filters with range keys, at the
    /// priorities a single port gets (#416), for both families (#425).
    #[test]
    fn a_port_range_rule_gets_tcp_and_udp_range_filters() {
        use crate::netlink::types::tc::filter::flower::*;
        use crate::util::Rate;

        let limiter = PerHostLimiter::new("d0", Rate::mbit(10))
            .limit_port_range(8000, 8100, Rate::mbit(5))
            .limit_port_range(8200, 8200, Rate::mbit(5));
        let range = rule_filters(0, &limiter.rules[0], TcHandle::new(1, 2)).unwrap();
        let prios: Vec<(u16, u16)> = range
            .iter()
            .map(|(proto, prio, _)| (proto.as_u16(), prio.as_u16()))
            .collect();
        assert_eq!(
            prios,
            vec![(0x0800, 100), (0x0800, 101), (0x86DD, 102), (0x86DD, 103)]
        );
        for (_, _, f) in &range {
            let keys = filter_keys(f);
            assert!(keys.contains(&TCA_FLOWER_KEY_PORT_DST_MIN), "{keys:?}");
            assert!(keys.contains(&TCA_FLOWER_KEY_PORT_DST_MAX), "{keys:?}");
            assert!(keys.contains(&TCA_FLOWER_KEY_ETH_TYPE), "{keys:?}");
        }
        assert!(filter_keys(&range[0].2).contains(&TCA_FLOWER_KEY_IP_PROTO));

        // One port is the port: the kernel refuses min == max.
        let single = rule_filters(1, &limiter.rules[1], TcHandle::new(1, 3)).unwrap();
        assert!(filter_keys(&single[0].2).contains(&TCA_FLOWER_KEY_TCP_DST));
        assert!(filter_keys(&single[1].2).contains(&TCA_FLOWER_KEY_UDP_DST));
    }

    /// The `(type, payload)` pairs a rule filter writes.
    fn filter_attrs(f: &super::super::filter::FlowerFilter) -> Vec<(u16, Vec<u8>)> {
        use super::super::filter::FilterConfig;
        let mut b = crate::netlink::builder::MessageBuilder::new(0, 0);
        let start = b.len();
        f.write_options(&mut b).expect("a usable filter");
        crate::netlink::attr::AttrIter::new(&b.as_bytes()[start..])
            .map(|(t, p)| (t, p.to_vec()))
            .collect()
    }

    /// A port rule classifies both IP families: a TCP and a UDP filter for
    /// IPv4 and for IPv6, the ethertype in `tcm_info` and in the flower key
    /// agreeing (#425).
    #[test]
    fn port_rules_get_ipv4_and_ipv6_filters() {
        use crate::netlink::types::tc::filter::flower::*;
        use crate::util::Rate;

        let limiter = PerHostLimiter::new("d0", Rate::mbit(10))
            .limit_ip("10.0.0.1".parse().unwrap(), Rate::mbit(5))
            .limit_port(80, Rate::mbit(5))
            .limit_port_range(8000, 8100, Rate::mbit(5));
        for (i, port_key) in [
            (1, TCA_FLOWER_KEY_TCP_DST),
            (2, TCA_FLOWER_KEY_PORT_DST_MIN),
        ] {
            let filters =
                rule_filters(i, &limiter.rules[i], TcHandle::new(1, (i + 2) as u16)).unwrap();
            let mut shape = Vec::new();
            for (proto, prio, f) in &filters {
                let attrs = filter_attrs(f);
                let value = |id: u16| attrs.iter().find(|(t, _)| *t == id).map(|(_, p)| p.clone());
                assert_eq!(
                    value(TCA_FLOWER_KEY_ETH_TYPE),
                    Some(proto.as_u16().to_be_bytes().to_vec())
                );
                assert!(
                    attrs
                        .iter()
                        .any(|(t, _)| *t == port_key || *t == TCA_FLOWER_KEY_UDP_DST),
                    "rule {i} prio {prio}: no port key in {attrs:?}"
                );
                shape.push((
                    proto.as_u16(),
                    prio.as_u16(),
                    value(TCA_FLOWER_KEY_IP_PROTO).unwrap()[0],
                ));
            }
            let first = 100 + 4 * i as u16;
            assert_eq!(
                shape,
                [
                    (0x0800, first, 6),
                    (0x0800, first + 1, 17),
                    (0x86DD, first + 2, 6),
                    (0x86DD, first + 3, 17),
                ],
                "rule {i}"
            );
        }
    }

    /// `PerHostLimiter` installs in the recipe band, as `FilterPriority`
    /// documents and `PerPeerImpairer` does, never in the operator band
    /// `1..=49` (#434). Each rule takes the four priorities from
    /// `100 + 4 * index`, so every protocol meets the rules in the order they
    /// were declared. Before, an address rule's filter at `index + 1` always
    /// came before every port rule's UDP and IPv6 filters at
    /// `index + 101/201/301`, whatever the order.
    #[test]
    fn filters_sit_in_the_recipe_band_in_rule_order() {
        use crate::util::Rate;

        let limiter = PerHostLimiter::new("d0", Rate::mbit(10))
            .limit_port(53, Rate::mbit(5))
            .limit_ip("10.0.0.1".parse().unwrap(), Rate::mbit(5))
            .limit_port_range(8000, 8100, Rate::mbit(5))
            .limit_ip("fd00::1".parse().unwrap(), Rate::mbit(5));
        let mut last = 0;
        for (i, rule) in limiter.rules.iter().enumerate() {
            let prios: Vec<u16> = rule_filters(i, rule, TcHandle::new(1, (i + 2) as u16))
                .unwrap()
                .into_iter()
                .map(|(_, p, _)| p.as_u16())
                .collect();
            let base = 100 + 4 * i as u16;
            assert!(
                prios.iter().all(|p| (base..base + 4).contains(p)),
                "rule {i} at {prios:?}, want within {base}..{}",
                base + 4
            );
            assert!(prios[0] > last, "rule {i} at {prios:?} comes before rule {}", i.wrapping_sub(1));
            last = *prios.iter().max().unwrap();
        }
    }

    /// No two rules share a priority any more, so a port rule can have any
    /// number of rules after it: the old layout refused one with another rule
    /// 100, 200 or 300 places later. The limit is the last priority: rule
    /// `i` needs `100 + 4 * i + 3` to fit in a `u16`.
    #[test]
    fn a_limiter_holds_rules_up_to_the_last_priority() {
        use crate::util::Rate;

        let hosts = |mut limiter: PerHostLimiter, n: u32| {
            for k in 0..n {
                let ip = std::net::Ipv4Addr::from(0x0a00_0000 + k);
                limiter = limiter.limit_ip(ip.into(), Rate::mbit(1));
            }
            limiter
        };
        let port_first = || PerHostLimiter::new("d0", Rate::mbit(10)).limit_port(80, Rate::mbit(5));
        assert!(hosts(port_first(), 400).check_rules().is_ok());

        // 16359 rules: the last one's filters end at 65535.
        assert!(hosts(port_first(), 16358).check_rules().is_ok());
        let err = hosts(port_first(), 16359)
            .check_rules()
            .expect_err("rule 16359 would need priority 65536");
        assert!(err.to_string().contains("at most 16359 rules"), "{err}");
    }

    #[test]
    fn an_empty_port_range_is_refused_before_anything_changes() {
        use crate::util::Rate;
        let limiter =
            PerHostLimiter::new("d0", Rate::mbit(10)).limit_port_range(8100, 8000, Rate::mbit(5));
        let err = limiter.check_rules().expect_err("8100-8000 is empty");
        assert!(err.to_string().contains("8100-8000"), "{err}");
    }

    #[test]
    fn ifb_name_is_stable() {
        // Same device, same IFB — `remove()` has to find what `apply()`
        // created, possibly from a differently-compiled binary. The
        // literal is the point: it pins the hash so a change to it
        // shows up here rather than as an orphaned IFB in production.
        let a = RateLimiter::new("verylonginterfacename").ifb_name();
        assert_eq!(a, RateLimiter::new("verylonginterfacename").ifb_name());
        assert_eq!(a, "ifb_verylo_32f8");
    }

    #[test]
    fn test_parse_subnet() {
        let (addr, prefix) = parse_subnet("10.0.0.0/8").unwrap();
        assert_eq!(addr, "10.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(prefix, 8);

        let (addr, prefix) = parse_subnet("192.168.1.0/24").unwrap();
        assert_eq!(addr, "192.168.1.0".parse::<IpAddr>().unwrap());
        assert_eq!(prefix, 24);

        let (addr, prefix) = parse_subnet("2001:db8::/32").unwrap();
        assert!(addr.is_ipv6());
        assert_eq!(prefix, 32);

        // Invalid formats
        assert!(parse_subnet("10.0.0.0").is_err());
        assert!(parse_subnet("10.0.0.0/33").is_err());
    }

    #[test]
    fn test_per_host_limiter_builder() {
        use crate::util::Rate;
        let limiter = PerHostLimiter::new("eth0", Rate::mbit(10));
        assert_eq!(limiter.dev, "eth0");
        assert_eq!(limiter.default_rate, Rate::mbit(10));
        assert!(limiter.rules.is_empty());
    }

    #[test]
    fn test_per_host_limiter_with_rules() {
        use crate::util::Rate;
        let limiter = PerHostLimiter::new("eth0", Rate::mbit(10))
            .limit_ip("192.168.1.100".parse().unwrap(), Rate::mbit(100))
            .limit_subnet("10.0.0.0/8", Rate::mbit(50))
            .unwrap()
            .limit_port(80, Rate::mbit(500));

        assert_eq!(limiter.rules.len(), 3);
    }
}
