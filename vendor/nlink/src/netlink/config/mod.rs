//! Declarative network configuration.
//!
//! This module provides a declarative API for specifying desired network state
//! and computing/applying the necessary changes to achieve it.
//!
//! # Overview
//!
//! Instead of imperatively calling `add_link`, `add_address`, etc., you describe
//! the desired state and let the library figure out what changes are needed:
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::config::NetworkConfig;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Define desired state
//! let config = NetworkConfig::new()
//!     .link("br0", |l| l.bridge().up())
//!     .link("veth0", |l| l.veth("veth1").master("br0").up())
//!     // The peer: created with veth0, and set up in the same apply.
//!     .link("veth1", |l| l.up())
//!     .address("br0", "192.168.100.1/24")?
//!     .route("10.0.0.0/8", |r| r.via("192.168.100.254"))?;
//!
//! // Preview changes
//! let diff = config.diff(&conn).await?;
//! println!("{diff}");
//!
//! // Apply changes
//! config.apply(&conn).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Benefits
//!
//! - **Idempotent**: Running the same config multiple times produces the same result
//! - **Diff-based**: Only makes necessary changes
//! - **Ordered**: Applies changes in the correct order (links before addresses, etc.)
//! - **Dry-run**: Preview changes before applying
//!
//! # Supported Resources
//!
//! - Links (interfaces): dummy, veth, bridge, vlan, vxlan, macvlan, bond,
//!   ifb, vrf, netkit, ovpn, and existing devices declared without a kind
//! - Addresses: IPv4 and IPv6
//! - Routes: IPv4 and IPv6, unicast (with a gateway, a device, or both),
//!   blackhole, unreachable and prohibit, in any table; not multipath
//! - Qdiscs: netem, htb, fq_codel, tbf, sfq, prio, ingress, clsact

mod apply;
mod diff;
mod kind;
mod plan;
mod preserve;
mod restore;
// #876 — a diff's JSON, checked against the schema it publishes.
#[cfg(all(test, feature = "schemars"))]
pub(crate) mod schema_check;
mod tc_tree;
#[cfg(feature = "serde")]
mod tc_tree_serde;
mod types;

// `ApplyError` is a field of `ApplyResult` and `LinkChanges` a field of
// `ConfigDiff`, so both were visible in public signatures and could not
// be *named* downstream — no `fn report(errs: &[ApplyError])` (#280).
// `ApplyResult` is `Serialize` under the `serde` feature, so `ApplyError`
// was in the JSON ABI while being unnameable in Rust.
pub use apply::{ApplyError, ApplyOptions, ApplyResult, ExecOptions};
#[allow(deprecated)]
pub use diff::DiffOptions;
pub use diff::{
    ConfigDiff, LinkChanges, NexthopConflict, PlanOptions, RouteConflict, Snapshot, VethPeerChange,
};
pub use kind::{
    Blocker, BlockerFilter, Certainty, LinkRecreate, LinkRemoval, LinkRename, OfflineDiff, OfflineRecreate, Owned,
    RecreatePolicy,
};
pub use plan::{JournalEntry, Plan, Step};
pub use preserve::{PreservedTc, TcObject, Underneath};
pub use restore::{LinkRestore, RestoredNexthop, RestoredRoute};
pub use tc_tree::{
    ClassSpec, DeclaredClass, DeclaredFilter, DeclaredLeaf, DeclaredTc, FilterKey, FilterSpec,
    TcBuilder, TcTreeDiff,
};
pub use types::*;

use super::{connection::Connection, error::Result, protocol::Route};

#[nlink_macros::send_futures]
impl NetworkConfig {
    /// Compute the difference between desired and current state.
    ///
    /// This fetches the current network state and compares it against
    /// the desired configuration, returning a diff of what needs to change.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # let config = nlink::netlink::config::NetworkConfig::new();
    /// let diff = config.diff(&conn).await?;
    /// if !diff.is_empty() {
    ///     println!("Changes needed:\n{}", diff.summary());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn diff(&self, conn: &Connection<Route>) -> Result<ConfigDiff> {
        diff::compute_diff(self, conn).await
    }

    /// Compute the diff with explicit [`PlanOptions`].
    ///
    /// With [`PlanOptions::purge`] on, the returned diff additionally
    /// carries [`ConfigDiff::addresses_to_remove`] /
    /// [`ConfigDiff::routes_to_remove`] for undeclared kernel resources
    /// (conservatively scoped — see [`PlanOptions::purge`]), and
    /// [`PlanOptions::purge_tables`] / [`PlanOptions::purge_address_devs`]
    /// widen that scope.
    /// The default ([`Self::diff`]) never populates the removal
    /// collections, so it can only ever *add* state.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::config::PlanOptions;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # let config = nlink::netlink::config::NetworkConfig::new();
    /// let diff = config.diff_with_options(&conn, PlanOptions::default().purge(true)).await?;
    /// // `diff.summary()` now shows `-` lines for resources that
    /// // would be removed; inspect before calling `diff.apply(&conn)`.
    /// # Ok(())
    /// # }
    /// ```
    pub async fn diff_with_options(
        &self,
        conn: &Connection<Route>,
        options: PlanOptions,
    ) -> Result<ConfigDiff> {
        diff::compute_diff_with_options(self, conn, &options).await
    }

    /// The links going from `previous` to this config recreates,
    /// predicted without a kernel (#513).
    ///
    /// It runs the comparison a live diff runs, against the link the
    /// kernel would hold for `previous`: its declaration encoded as the
    /// apply sends it and read back. So it cannot drift from what an apply
    /// does. A parameter `previous` left to a module parameter's default
    /// (the VXLAN port, a bond option) is a recreate
    /// [`IfKernelDefaultDiffers`](Certainty::IfKernelDefaultDiffers). What
    /// the live state would block cannot be known here; the live diff's
    /// [`links_to_recreate`](ConfigDiff::links_to_recreate) says that.
    ///
    /// ```
    /// use nlink::netlink::config::NetworkConfig;
    ///
    /// let before = NetworkConfig::new()
    ///     .link("d0", |l| l.dummy())
    ///     .link("v1", |l| l.vlan("d0", 10));
    /// let after = NetworkConfig::new()
    ///     .link("d0", |l| l.dummy())
    ///     .link("v1", |l| l.vlan("d0", 20));
    /// let offline = after.diff_against(&before);
    /// assert_eq!(offline.recreates[0].name, "v1");
    /// assert!(offline.recreates[0].reason.contains("vlan id 10 -> 20"));
    /// ```
    pub fn diff_against(&self, previous: &NetworkConfig) -> OfflineDiff {
        kind::diff_against(self, previous)
    }

    /// The diff against a [`Snapshot`] read earlier, with no kernel read
    /// (#518): what [`diff_with_options`](Self::diff_with_options) returns
    /// had the kernel still been in the snapshot's state.
    pub fn diff_snapshot(&self, snapshot: &Snapshot, options: PlanOptions) -> Result<ConfigDiff> {
        self.validate()?;
        diff::diff_snapshot(self, snapshot, &options)
    }

    /// Apply the configuration to achieve the desired state.
    ///
    /// This computes the diff and applies all necessary changes.
    /// Changes are applied in the correct order:
    /// 1. Create new links
    /// 2. Modify existing links
    /// 3. Add addresses
    /// 4. Add routes
    /// 5. Configure qdiscs
    /// 6. Remove old resources (if purge is enabled)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # let config = nlink::netlink::config::NetworkConfig::new();
    /// let result = config.apply(&conn).await?;
    /// println!("Made {} changes", result.changes_made);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<ApplyResult> {
        self.apply_with_options(conn, ApplyOptions::default()).await
    }

    /// Apply the configuration with custom options.
    ///
    /// # Options
    ///
    /// - `dry_run`: Compute diff but don't make any changes
    /// - `continue_on_error`: Keep going if some operations fail
    /// - `purge`: also remove undeclared addresses and routes, in the scope
    ///   [`PlanOptions::purge`] sets out. Links and qdiscs are never
    ///   removed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # let config = nlink::netlink::config::NetworkConfig::new();
    /// // Dry run first
    /// # use nlink::netlink::config::ApplyOptions;
    /// // `ApplyOptions` is `#[non_exhaustive]`, so it is built with the
    /// // `with_*` setters rather than a struct literal.
    /// let result = config
    ///     .apply_with_options(&conn, ApplyOptions::default().with_dry_run(true))
    ///     .await?;
    /// println!("Would make {} changes", result.changes_made);
    ///
    /// // Then apply for real
    /// config.apply(&conn).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn apply_with_options(
        &self,
        conn: &Connection<Route>,
        options: ApplyOptions,
    ) -> Result<ApplyResult> {
        apply::apply_config(self, conn, options).await
    }

    /// Apply, retrying what a concurrent change can cause: `EBUSY`,
    /// `EAGAIN`, and a dump the kernel interrupted (`NLM_F_DUMP_INTR`, past
    /// the dump's own re-dumps, #494). Each attempt diffs again, so one
    /// that failed halfway is finished by the next instead of tripping over
    /// what it already did (Plan 207e H4). Up to `opts.max_retries`
    /// retries, from `opts.backoff`, doubling.
    ///
    /// With `opts.dry_run`, nothing changes and the report counts what
    /// would. The same [`ReconcileOptions`](crate::reconcile::ReconcileOptions)
    /// as every other layer and recipe (#532).
    pub async fn apply_reconcile(
        &self,
        conn: &Connection<Route>,
        opts: crate::reconcile::ReconcileOptions,
    ) -> Result<crate::reconcile::ReconcileReport> {
        self.apply_reconcile_with_options(conn, opts, ApplyOptions::default())
            .await
    }

    /// [`Self::apply_reconcile`] with [`ApplyOptions`] for each attempt
    /// (#345): its plan (purge, `previous`, recreate policy, ownership)
    /// for every diff, and its execution (`continue_on_error`, `verify`)
    /// for every apply. Either's `dry_run` makes it a dry run.
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::config::{ApplyOptions, NetworkConfig};
    /// use nlink::reconcile::ReconcileOptions;
    ///
    /// let cfg = NetworkConfig::new() /* ... */;
    /// let report = cfg
    ///     .apply_reconcile_with_options(
    ///         &conn,
    ///         ReconcileOptions::default(),
    ///         ApplyOptions::default().with_purge(true),
    ///     )
    ///     .await?;
    /// println!("{} change(s) in {} attempt(s)", report.changes_made, report.attempts);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn apply_reconcile_with_options(
        &self,
        conn: &Connection<Route>,
        opts: crate::reconcile::ReconcileOptions,
        apply: ApplyOptions,
    ) -> Result<crate::reconcile::ReconcileReport> {
        let mut exec = apply.exec;
        exec.dry_run |= opts.dry_run;
        let plan = &apply.plan;
        let (changes_made, attempts) = opts
            .retry(crate::netlink::reconcile::transient, || async move {
                let diff = self.diff_with_options(conn, plan.clone()).await?;
                if diff.is_empty() {
                    return Ok(0);
                }
                Ok(apply::apply_diff(&diff, conn, exec).await?.changes_made)
            })
            .await?;
        Ok(crate::reconcile::ReconcileReport {
            attempts,
            changes_made,
            dry_run: exec.dry_run,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod apply_reconcile_tests {
    //! Plan 188 §2.4 — `NetworkConfig::apply_reconcile`.
    //!
    //! These tests verify the retry classification (the
    //! NftablesConfig precedent's logic mirrored for the
    //! RTNETLINK side). The integration-test side of the
    //! happy path lives in `tests/integration/cycle_0_19_backfill.rs`
    //! (`plan_188_apply_reconcile_first_attempt_succeeds`); the purge
    //! variant is `apply_reconcile_with_options_purges_and_plain_does_not`
    //! in `tests/integration/network_config_apply.rs`. Both root-gated.

    use crate::Error;
    use std::time::Duration;

    #[test]
    fn classify_io_ebusy_as_retryable() {
        // Plan 187 §2.5 fix: Error::errno() unwraps Io via
        // raw_os_error(). is_busy(Io(EBUSY)) must be true,
        // so apply_reconcile would retry instead of bubbling.
        let io_ebusy = Error::from(std::io::Error::from_raw_os_error(libc::EBUSY));
        assert!(io_ebusy.is_busy(), "Io(EBUSY) must trigger apply_reconcile retry");
        assert!(!io_ebusy.is_no_buffer_space(), "wrong predicate must NOT match");
    }

    #[test]
    fn classify_io_eagain_as_retryable() {
        let io_eagain = Error::from(std::io::Error::from_raw_os_error(libc::EAGAIN));
        assert!(io_eagain.is_try_again(), "Io(EAGAIN) must trigger apply_reconcile retry");
    }

    #[test]
    fn classify_kernel_einval_as_terminal() {
        // EINVAL is NOT retryable — must propagate.
        let einval = Error::from_errno_ext_ack(libc::EINVAL, None, None);
        assert!(!einval.is_busy());
        assert!(!einval.is_try_again());
        // apply_reconcile would short-circuit on the `Err(e) => return Err(e)`
        // arm.
    }

    #[test]
    fn reconcile_options_default_caps_at_3_retries() {
        use crate::reconcile::ReconcileOptions;
        let opts = ReconcileOptions::default();
        assert_eq!(opts.max_retries, 3);
        assert_eq!(opts.backoff, Duration::from_millis(100));
    }
}
