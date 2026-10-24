//! Unified declarative bundle covering RTNETLINK +
//! nftables + WireGuard in one type. Plan 200 §2.4.
//!
//! Lets consumers manage network + firewall + VPN from one
//! type without manually orchestrating per-protocol `apply`
//! calls in the right order.
//!
//! **Plan, then apply (#519).** [`Stack::plan_in`] diffs every set layer
//! once and returns a [`StackPlan`]: what each layer will change, which
//! prints as the dry run and serializes for a report. [`StackPlan::apply`]
//! applies *that* plan — no second diff of every layer, and no window in
//! which a validated diff is thrown away for a fresh one. Its order is the
//! natural dependency direction:
//!
//! 0. **WireGuard links** (`WireguardConfig::ensure_devices`): every
//!    declared `wgN` is created and brought up first, so the network layer
//!    can address the tunnel and route via a peer's tunnel address (#330).
//!    A layer planned while a link it names did not exist yet is planned
//!    again once it does.
//! 1. **RTNETLINK** (`NetworkConfig`): links, addresses, routes, qdiscs —
//!    everything else references interfaces.
//! 2. **nftables** (`NftablesConfig`): firewall rules can reference
//!    interfaces from step 1. The commit is refused (`ERESTART`) if the
//!    ruleset moved since the plan (#482).
//! 3. **WireGuard** (`WireguardConfig`): keys and peers on the links from
//!    step 0, routed through step 1, filtered by step 2.
//!
//! The plan takes [`PlanOptions`] (purge, `previous`, recreate policy,
//! ownership — the network layer's) and the apply [`ExecOptions`] (dry
//! run, continue on error, verify). [`Stack::apply_reconcile_in`] plans
//! and applies again when a concurrent change gets in the way.
//!
//! Each layer is optional; `Stack` skips layers that aren't set, so
//! callers can use Stack as their one-stop orchestrator without needing
//! every layer.
//!
//! `ovpn` is intentionally absent — the kernel ovpn family
//! is bleeding-edge (6.16+) and nlink ships only the link
//! half (Plan 190 §2.3b). The full GENL-side declarative
//! `OvpnConfig` will join the Stack once Plan 197 ships
//! (deferred to a future cycle for kernel-ABI stability —
//! the ovpn UAPI is still maturing).

use std::fmt;
use std::sync::Arc;

use crate::netlink::config::{
    ApplyOptions, ApplyResult as NetworkApplyResult, ConfigDiff, NetworkConfig, PlanOptions,
};
use crate::netlink::genl::wireguard::{
    WireguardApplyResult, WireguardConfig, WireguardConfigDiff,
};
use crate::netlink::namespace::{NetnsRef, NetnsTarget};
use crate::netlink::nftables::config::{NftablesConfig, NftablesDiff};
use crate::netlink::{Nftables, Route, Wireguard};
use crate::reconcile::{ExecOptions, ReconcileOptions};
use crate::{Connection, Error, Result};

use super::{apply, diff};

/// Unified declarative bundle spanning RTNETLINK +
/// nftables + WireGuard. Plan 200 §2.4.
///
/// `#[non_exhaustive]` since 0.32 (#519): build it with [`Stack::new`]
/// and the layer setters, so a layer can be added without a break.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
#[must_use = "Stack does nothing unless planned and applied"]
pub struct Stack {
    pub network: Option<NetworkConfig>,
    pub nftables: Option<NftablesConfig>,
    pub wireguard: Option<WireguardConfig>,
}

#[nlink_macros::send_futures]
impl Stack {
    /// Build an empty Stack.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the RTNETLINK layer.
    pub fn network(mut self, cfg: NetworkConfig) -> Self {
        self.network = Some(cfg);
        self
    }

    /// Set the nftables layer.
    pub fn nftables(mut self, cfg: NftablesConfig) -> Self {
        self.nftables = Some(cfg);
        self
    }

    /// Set the WireGuard layer.
    pub fn wireguard(mut self, cfg: WireguardConfig) -> Self {
        self.wireguard = Some(cfg);
        self
    }

    /// [`Self::plan_in`] for the host's namespace.
    pub async fn plan(&self, opts: PlanOptions) -> Result<StackPlan> {
        self.plan_in(NetnsRef::Default, opts).await
    }

    /// Diff every set layer in `ns` once (#519): what an apply of this
    /// stack would change there. Nothing is changed. A layer that fails
    /// to diff — a missing kernel module, an invalid config, a missing
    /// namespace — fails the plan, before anything is applied.
    ///
    /// ```no_run
    /// # async fn example() -> nlink::Result<()> {
    /// # let (net_cfg, fw_cfg) = (nlink::netlink::config::NetworkConfig::new(), nlink::netlink::nftables::config::NftablesConfig::new());
    /// use nlink::facade::Stack;
    /// use nlink::netlink::config::PlanOptions;
    /// use nlink::netlink::namespace::Netns;
    /// use nlink::ExecOptions;
    ///
    /// let stack = Stack::new().network(net_cfg).nftables(fw_cfg);
    /// // Opened once, so the plan and the apply see the same namespace.
    /// let lab = Netns::open("lab")?;
    /// let plan = stack.plan_in(&lab, PlanOptions::default().purge(true)).await?;
    /// print!("{plan}");                                  // the dry run
    /// let report = plan.apply(&lab, ExecOptions::new()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn plan_in<'a>(&self, ns: impl Into<NetnsTarget<'a>>, opts: PlanOptions) -> Result<StackPlan> {
        let ns: NetnsTarget<'a> = ns.into();
        let mut plan = StackPlan {
            stack: Arc::new(self.clone()),
            options: opts.clone(),
            ..StackPlan::default()
        };
        if let Some(cfg) = &self.wireguard {
            let wg = diff::wireguard_in(ns.clone(), cfg).await?;
            plan.wireguard_devices = wg.devices_to_add.clone();
            plan.wireguard = Some(wg);
        }
        if let Some(cfg) = &self.network {
            let mut network = diff::network_in_with(ns.clone(), cfg, opts).await?;
            // The apply creates the WireGuard links first, so a network
            // declaration on one is not missing (#475).
            if let Some(wg) = &self.wireguard {
                network
                    .links_missing
                    .retain(|name| !wg.devices().iter().any(|d| &d.ifname == name));
            }
            plan.network = Some(network);
        }
        if let Some(cfg) = &self.nftables {
            plan.nftables = Some(diff::nftables_in(ns, cfg).await?);
        }
        Ok(plan)
    }

    /// Plan and apply, retrying what a concurrent change can cause (#519):
    /// `EBUSY`, `EAGAIN`, an interrupted dump, and an nftables commit
    /// refused because the ruleset moved since the plan (`ERESTART`). Each
    /// attempt plans every layer again. `opts.dry_run` plans only.
    pub async fn apply_reconcile_in<'a>(
        &self,
        ns: impl Into<NetnsTarget<'a>>,
        opts: ReconcileOptions,
        apply: ApplyOptions,
    ) -> Result<StackReport> {
        let ns: NetnsTarget<'a> = ns.into();
        let mut exec = apply.exec;
        exec.dry_run |= opts.dry_run;
        let plan_options = &apply.plan;
        let ns = &ns;
        let (mut report, attempts) = opts
            .retry(
                |e| crate::netlink::reconcile::transient(e) || e.is_restart(),
                || async move {
                    let plan = self.plan_in(ns.clone(), plan_options.clone()).await?;
                    plan.apply_or_keep(ns.clone(), exec).await
                },
            )
            .await?;
        report.attempts = attempts;
        Ok(report)
    }

    /// Plan and apply every set layer in the host's namespace.
    pub async fn apply(&self) -> Result<StackReport> {
        self.apply_in(NetnsRef::Default).await
    }

    /// [`Self::apply`] with [`ApplyOptions`].
    pub async fn apply_with(&self, opts: ApplyOptions) -> Result<StackReport> {
        self.apply_in_with(NetnsRef::Default, opts).await
    }

    /// Plan and apply every set layer in a named namespace.
    #[deprecated(since = "0.32.0", note = "use `apply_in(ns, …)`, which takes a name (#532)")]
    pub async fn apply_in_namespace(&self, ns: &str) -> Result<StackReport> {
        self.apply_in(ns).await
    }

    /// Plan and apply every set layer inside any namespace specification —
    /// named, path-referenced, or a process's namespace by PID (container
    /// support, #169).
    pub async fn apply_in<'a>(&self, ns: impl Into<NetnsTarget<'a>>) -> Result<StackReport> {
        let ns: NetnsTarget<'a> = ns.into();
        self.apply_in_with(ns, ApplyOptions::default()).await
    }

    /// [`Self::plan_in`] with `opts.plan`, then [`StackPlan::apply`] with
    /// `opts.exec`: one diff of every layer, and the apply of exactly it.
    ///
    /// Until 0.32 this ran a pre-flight diff of every layer, threw it away,
    /// and let each layer diff again as it applied — a second full dump,
    /// and a window in which the kernel could change between the two
    /// (#519).
    ///
    /// **Dry run.** With `opts.exec.dry_run` nothing is touched — no
    /// WireGuard link, no firewall commit, no keys — and the report carries
    /// the plan in [`StackReport::planned`] (#501).
    pub async fn apply_in_with<'a>(
        &self,
        ns: impl Into<NetnsTarget<'a>>,
        opts: ApplyOptions,
    ) -> Result<StackReport> {
        let ns: NetnsTarget<'a> = ns.into();
        let plan = self.plan_in(ns.clone(), opts.plan).await?;
        plan.apply_or_keep(ns, opts.exec).await
    }

    /// Diff every set layer against the host's default namespace.
    #[deprecated(since = "0.32.0", note = "use `Stack::plan` (#519)")]
    pub async fn diff(&self) -> Result<StackPlan> {
        self.plan_in(NetnsRef::Default, PlanOptions::default())
            .await
    }

    /// [`Self::plan`] under its pre-0.32 name.
    #[deprecated(since = "0.32.0", note = "use `Stack::plan` (#519)")]
    pub async fn diff_with(&self, opts: PlanOptions) -> Result<StackPlan> {
        self.plan_in(NetnsRef::Default, opts).await
    }

    /// [`Self::plan_in`] for a named namespace, under its pre-0.32 name.
    #[deprecated(since = "0.32.0", note = "use `Stack::plan_in` (#519)")]
    pub async fn diff_in_namespace(&self, ns: &str) -> Result<StackPlan> {
        self.plan_in(ns, PlanOptions::default())
            .await
    }

    /// [`Self::plan_in`] under its pre-0.32 name.
    #[deprecated(since = "0.32.0", note = "use `Stack::plan_in` (#519)")]
    pub async fn diff_in<'a>(&self, ns: impl Into<NetnsTarget<'a>>) -> Result<StackPlan> {
        let ns: NetnsTarget<'a> = ns.into();
        self.plan_in(ns, PlanOptions::default()).await
    }

    /// [`Self::plan_in`] under its pre-0.32 name.
    #[deprecated(since = "0.32.0", note = "use `Stack::plan_in` (#519)")]
    pub async fn diff_in_with<'a>(&self, ns: impl Into<NetnsTarget<'a>>, opts: PlanOptions) -> Result<StackPlan> {
        let ns: NetnsTarget<'a> = ns.into();
        self.plan_in(ns, opts).await
    }
}

/// What applying a [`Stack`] will change, layer by layer (#519): from
/// [`Stack::plan_in`], applied with [`StackPlan::apply`]. `Display` is the
/// dry run; with the `serde` feature it serializes, keys never included.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Default)]
#[non_exhaustive]
#[must_use = "a plan does nothing until applied"]
pub struct StackPlan {
    /// WireGuard links the apply creates first.
    pub wireguard_devices: Vec<String>,
    /// The network layer's diff.
    pub network: Option<ConfigDiff>,
    /// The nftables layer's diff.
    pub nftables: Option<NftablesDiff>,
    /// The WireGuard layer's diff. Its `devices_to_add` are
    /// [`Self::wireguard_devices`].
    pub wireguard: Option<WireguardConfigDiff>,
    /// What was planned, for a layer planned again and for verify.
    #[cfg_attr(feature = "serde", serde(skip))]
    stack: Arc<Stack>,
    #[cfg_attr(feature = "serde", serde(skip))]
    options: PlanOptions,
}

/// The name [`StackPlan`] had before 0.32, when it was only a diff.
#[deprecated(since = "0.32.0", note = "renamed `StackPlan` (#519)")]
pub type StackDiff = StackPlan;

/// The name [`StackReport`] had before 0.32.
#[deprecated(since = "0.32.0", note = "renamed `StackReport` (#519)")]
pub type StackApplyReport = StackReport;

#[nlink_macros::send_futures]
impl StackPlan {
    /// `true` if no layer has anything to change.
    pub fn is_empty(&self) -> bool {
        self.network.as_ref().is_none_or(|d| d.is_empty())
            && self.nftables.as_ref().is_none_or(|d| d.is_empty())
            && self.wireguard.as_ref().is_none_or(|d| d.is_empty())
    }

    /// Total number of pending kernel mutations across every layer
    /// (#169) — sums the per-layer `change_count()`s. A WireGuard link to
    /// create counts once, in the WireGuard layer's.
    pub fn change_count(&self) -> usize {
        self.network.as_ref().map_or(0, |d| d.change_count())
            + self.nftables.as_ref().map_or(0, |d| d.change_count())
            + self.wireguard.as_ref().map_or(0, |d| d.change_count())
    }

    /// Apply this plan in `ns` (#519): WireGuard links, the network layer,
    /// the firewall commit, WireGuard keys and peers, in that order.
    ///
    /// - A layer planned while a WireGuard link it names did not exist yet
    ///   is planned again after step 0 creates it: a network declaration
    ///   on the tunnel, and the tunnel's keys and peers.
    /// - `exec.dry_run`: nothing is touched; the report's `dry_run` is set.
    /// - `exec.continue_on_error` applies inside the network layer; a layer
    ///   that fails stops the stack.
    /// - `exec.verify`: plan every layer again afterwards and fail with
    ///   [`ErrorDetail::StackNotConverged`](crate::ErrorDetail::StackNotConverged) if anything is left.
    /// - An nftables commit the ruleset moved under is refused with
    ///   `ERESTART` ([`Error::is_restart`]): plan again, or use
    ///   [`Stack::apply_reconcile_in`].
    pub async fn apply<'a>(&self, ns: impl Into<NetnsTarget<'a>>, exec: ExecOptions) -> Result<StackReport> {
        let ns: NetnsTarget<'a> = ns.into();
        let mut report = StackReport {
            attempts: 1,
            dry_run: exec.dry_run,
            ..StackReport::default()
        };
        if exec.dry_run {
            return Ok(report);
        }
        let stack = &self.stack;

        // Step 0: the links the network layer is about to address.
        let (mut network_again, mut wireguard_again) = (None, None);
        if let Some(cfg) = &stack.wireguard {
            report.wireguard_devices_created = apply::wireguard_devices_in(ns.clone(), cfg).await?;
            if !report.wireguard_devices_created.is_empty() {
                if let Some(net) = &stack.network {
                    network_again =
                        Some(diff::network_in_with(ns.clone(), net, self.options.clone()).await?);
                }
                wireguard_again = Some(diff::wireguard_in(ns.clone(), cfg).await?);
            }
        }

        // The stack verifies once, at the end, every layer.
        let layer_exec = exec.with_verify(false);
        if let Some(diff) = network_again.as_ref().or(self.network.as_ref()) {
            let conn: Connection<Route> = ns.connection()?;
            report.network = Some(diff.apply(&conn, layer_exec).await?);
        }
        if let Some(diff) = &self.nftables {
            let conn: Connection<Nftables> = ns.connection()?;
            report.nftables = Some(diff.apply(&conn).await?);
        }
        if let Some(diff) = wireguard_again.as_ref().or(self.wireguard.as_ref()) {
            let conn: Connection<Wireguard> = ns.connection_async().await?;
            report.wireguard = Some(diff.apply(&conn).await?);
        }

        if exec.verify {
            let remaining = stack.plan_in(ns, self.options.clone()).await?;
            if !remaining.is_empty() {
                return Err(Error::from(crate::netlink::ErrorDetail::StackNotConverged {
                    remaining: Box::new(remaining),
                }));
            }
        }
        Ok(report)
    }

    /// [`Self::apply`], keeping the plan in a dry run's report.
    async fn apply_or_keep<'a>(self, ns: impl Into<NetnsTarget<'a>>, exec: ExecOptions) -> Result<StackReport> {
        let ns: NetnsTarget<'a> = ns.into();
        let mut report = self.apply(ns, exec).await?;
        if exec.dry_run {
            report.planned = Some(self);
        }
        Ok(report)
    }
}

/// Every layer's diff with a heading, the layers with nothing to change
/// left out.
impl fmt::Display for StackPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("No changes needed");
        }
        let mut sections = Vec::new();
        if let Some(d) = self.network.as_ref().filter(|d| !d.is_empty()) {
            sections.push(format!("network:\n{d}"));
        }
        if let Some(d) = self.nftables.as_ref().filter(|d| !d.is_empty()) {
            sections.push(format!("nftables:\n{}", d.to_string().trim_end()));
        }
        if let Some(d) = self.wireguard.as_ref().filter(|d| !d.is_empty()) {
            sections.push(format!("wireguard:\n{d}"));
        }
        f.write_str(&sections.join("\n\n"))
    }
}

/// What applying a [`Stack`] did, layer by layer (#519).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Default)]
#[non_exhaustive]
#[must_use = "Inspect per-layer fields to learn what the stack apply changed"]
pub struct StackReport {
    /// WireGuard links created in step 0.
    pub wireguard_devices_created: Vec<String>,
    /// The network layer's result, including what it recreated
    /// ([`ApplyResult::recreated`](crate::netlink::config::ApplyResult::recreated)).
    pub network: Option<NetworkApplyResult>,
    /// The number of nftables changes committed. Called
    /// `nftables_change_count` before 0.32.
    pub nftables: Option<usize>,
    /// The WireGuard layer's result.
    pub wireguard: Option<WireguardApplyResult>,
    /// Plans made: more than 1 when [`Stack::apply_reconcile_in`] retried.
    pub attempts: usize,
    /// A dry run: nothing changed.
    pub dry_run: bool,
    /// A dry run's plan, when the stack planned it ([`Stack::apply_in_with`]);
    /// a [`StackPlan::apply`] caller has the plan already (#501).
    pub planned: Option<StackPlan>,
}

impl StackReport {
    /// `true` if nothing changed — for a dry run, if the plan is empty.
    pub fn is_noop(&self) -> bool {
        self.change_count() == 0
    }

    /// Total number of kernel mutations across every layer (#169) — for a
    /// dry run, the number the plan would make.
    pub fn change_count(&self) -> usize {
        self.planned.as_ref().map_or(0, |p| p.change_count())
            + self.network.as_ref().map_or(0, |r| r.changes_made)
            + self.nftables.unwrap_or(0)
            + self.wireguard.as_ref().map_or(0, |r| r.total_writes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_plan_and_report_are_empty() {
        let plan = StackPlan::default();
        assert!(plan.is_empty());
        assert_eq!(plan.to_string(), "No changes needed");
        assert!(StackReport::default().is_noop());
    }

    /// #169 — change_count sums the set layers.
    #[test]
    fn stack_change_counts_sum_layers() {
        let mut plan = StackPlan::default();
        assert_eq!(plan.change_count(), 0);
        let mut wg = WireguardConfigDiff::default();
        wg.devices_to_add.push("wg0".to_string());
        plan.wireguard = Some(wg);
        assert_eq!(plan.change_count(), 1);
        assert!(!plan.is_empty());
        assert!(plan.to_string().starts_with("wireguard:\n"), "{plan}");

        let mut report = StackReport::default();
        assert_eq!(report.change_count(), 0);
        report.nftables = Some(3);
        assert_eq!(report.change_count(), 3);
        assert!(!report.is_noop());
        report.planned = Some(plan);
        assert_eq!(report.change_count(), 4);
    }

    #[test]
    fn stack_builder_layers_optional() {
        let s = Stack::new();
        assert!(s.network.is_none());
        assert!(s.nftables.is_none());
        assert!(s.wireguard.is_none());

        let s = s.network(NetworkConfig::new());
        assert!(s.network.is_some());
    }
}
