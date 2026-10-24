//! What applying declared state shares across the layers and the TC
//! recipes: how an apply runs ([`ExecOptions`], #519), and one set of
//! options and one report for a reconcile ([`ReconcileOptions`],
//! [`ReconcileReport`], #532).
//!
//! A reconcile is an apply that reads the kernel again and retries what a
//! concurrent change can cause. It is the same idea in every layer:
//! [`NetworkConfig::apply_reconcile`](super::config::NetworkConfig::apply_reconcile),
//! [`NftablesConfig::apply_reconcile`](super::nftables::config::NftablesConfig::apply_reconcile),
//! [`WireguardConfig::apply_reconcile`](super::genl::wireguard::WireguardConfig::apply_reconcile),
//! and the recipes' `reconcile_with_options`. Until 0.32 there were two
//! unrelated types of each name: the recipes' (`fallback_to_apply`,
//! `dry_run`) at the crate root, and the nftables one (`max_retries`,
//! `backoff`) that the network and WireGuard layers borrowed. These are
//! both, under every path either was reachable by.

use std::{future::Future, time::Duration};

use super::{
    error::{Error, Result},
    tc_handle::{FilterPriority, TcHandle},
};

/// How an apply executes, as opposed to what it plans (#519): whether it
/// changes anything, whether it stops at the first failure, and whether it
/// checks the kernel afterwards. What to remove and what to own is the
/// plan's ([`PlanOptions`](super::config::PlanOptions)); a precomputed diff
/// can only be executed, so
/// [`ConfigDiff::apply`](super::config::ConfigDiff::apply) takes these
/// alone.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", default))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecOptions {
    /// Change nothing: report what would be done.
    pub dry_run: bool,
    /// Record a failed step in the result's errors and go on, instead of
    /// stopping at it.
    pub continue_on_error: bool,
    /// Diff again after the apply, and fail with
    /// [`ErrorDetail::NotConverged`](crate::ErrorDetail::NotConverged) if anything is
    /// left (#518). Ignored on a dry run.
    pub verify: bool,
}

impl ExecOptions {
    /// Change everything, stop at the first failure, check nothing after.
    pub const fn new() -> Self {
        Self {
            dry_run: false,
            continue_on_error: false,
            verify: false,
        }
    }

    /// See [`Self::dry_run`].
    pub const fn with_dry_run(mut self, on: bool) -> Self {
        self.dry_run = on;
        self
    }

    /// See [`Self::continue_on_error`].
    pub const fn with_continue_on_error(mut self, on: bool) -> Self {
        self.continue_on_error = on;
        self
    }

    /// See [`Self::verify`].
    pub const fn with_verify(mut self, on: bool) -> Self {
        self.verify = on;
        self
    }
}

/// The options of a reconcile, for every layer and every TC recipe (#532).
///
/// ```
/// use nlink::reconcile::ReconcileOptions;
/// use std::time::Duration;
///
/// let opts = ReconcileOptions::new()
///     .with_max_retries(5)
///     .with_backoff(Duration::from_millis(50));
/// assert!(!opts.dry_run);
/// ```
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReconcileOptions {
    /// Retries after the first attempt, on an error a concurrent change
    /// can cause: a dump the kernel interrupted, and — except in nftables,
    /// where `EBUSY` means "in use" (#482) — `EBUSY` and `EAGAIN`. Each
    /// attempt reads the kernel again. Default 3.
    pub max_retries: usize,
    /// The wait before the first retry, doubling with each one (capped at
    /// `backoff × 2^10`). Default 100 ms.
    pub backoff: Duration,
    /// Change nothing: the report says what would be done, and its
    /// `dry_run` is set.
    pub dry_run: bool,
    /// A TC recipe's: rebuild the tree from scratch when the live one is
    /// too far off to fix in place (the root qdisc is another kind, say)
    /// instead of failing. The declarative layers ignore it.
    pub fallback_to_apply: bool,
}

impl Default for ReconcileOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl ReconcileOptions {
    /// Three retries from 100 ms; not a dry run; no fallback.
    pub const fn new() -> Self {
        Self {
            max_retries: 3,
            backoff: Duration::from_millis(100),
            dry_run: false,
            fallback_to_apply: false,
        }
    }

    /// See [`Self::max_retries`].
    pub const fn with_max_retries(mut self, retries: usize) -> Self {
        self.max_retries = retries;
        self
    }

    /// See [`Self::backoff`].
    pub const fn with_backoff(mut self, backoff: Duration) -> Self {
        self.backoff = backoff;
        self
    }

    /// See [`Self::dry_run`].
    pub const fn with_dry_run(mut self, on: bool) -> Self {
        self.dry_run = on;
        self
    }

    /// See [`Self::fallback_to_apply`].
    pub const fn with_fallback_to_apply(mut self, on: bool) -> Self {
        self.fallback_to_apply = on;
        self
    }

    /// The wait before retry `attempt` (0-based).
    pub(crate) fn backoff_for(&self, attempt: usize) -> Duration {
        self.backoff.saturating_mul(1u32 << attempt.min(10))
    }

    /// Run `f` until it succeeds, fails with an error `transient` does not
    /// accept, or the retries run out; the result and the attempts made.
    ///
    /// `f` is an `FnMut` returning a future, not an `AsyncFnMut`: with an
    /// async closure that borrows, rustc cannot prove the future `Send`
    /// for every lifetime, and no reconcile could be spawned (#879).
    pub(crate) async fn retry<T, Fut>(
        &self,
        transient: impl Fn(&Error) -> bool,
        mut f: impl FnMut() -> Fut,
    ) -> Result<(T, usize)>
    where
        Fut: Future<Output = Result<T>>,
    {
        let mut attempt = 0;
        loop {
            match f().await {
                Ok(value) => return Ok((value, attempt + 1)),
                Err(e) if transient(&e) && attempt < self.max_retries => {
                    tokio::time::sleep(self.backoff_for(attempt)).await;
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// What a concurrent change to rtnetlink state can make an apply fail with,
/// so that trying again can succeed.
pub(crate) fn transient(e: &Error) -> bool {
    e.is_busy() || e.is_try_again() || e.is_dump_interrupted()
}

/// What a reconcile did, in every layer and TC recipe (#532).
///
/// The counts by rule and the stale and unmanaged objects are a TC
/// recipe's; a declarative layer leaves them zero and empty.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
#[must_use = "Inspect `.is_noop()` or the counters to learn what the reconcile changed"]
pub struct ReconcileReport {
    /// Attempts made, the first included: 1 when it went through at once.
    pub attempts: usize,
    /// Kernel changes made — or, on a dry run, that would be.
    pub changes_made: usize,
    /// Whether this was a dry run, which changed nothing.
    pub dry_run: bool,
    /// A recipe's rules whose class, leaf and filter were added.
    pub rules_added: usize,
    /// A recipe's rules whose class or leaf was changed in place.
    pub rules_modified: usize,
    /// A recipe's rules removed because the declaration no longer has them.
    pub rules_removed: usize,
    /// Whether a recipe's default class (and its leaf) changed.
    pub default_modified: bool,
    /// Whether a recipe's root qdisc was added or changed.
    pub root_modified: bool,
    /// Objects in a recipe's handle range that no declared rule maps to,
    /// removed.
    pub stale_removed: Vec<StaleObject>,
    /// Objects outside a recipe's handle range: reported, never touched —
    /// someone else may have put them there.
    pub unmanaged: Vec<UnmanagedObject>,
}

impl ReconcileReport {
    /// Whether nothing changed: the kernel already held what was declared.
    pub fn is_noop(&self) -> bool {
        self.changes_made == 0
    }
}

/// An object a TC recipe recognized as its own (by handle) that the
/// declaration no longer references. The reconcile removes these.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StaleObject {
    /// Object kind: `"class"`, `"qdisc"`, or `"filter"`.
    pub kind: &'static str,
    /// The handle (qdisc/class) or filter parent.
    pub handle: TcHandle,
    /// Filter priority, if `kind == "filter"`.
    pub priority: Option<FilterPriority>,
}

/// An object outside a TC recipe's range. The reconcile does not touch
/// these but reports them, so callers can audit drift.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnmanagedObject {
    /// Object kind: `"class"`, `"qdisc"`, or `"filter"`.
    pub kind: &'static str,
    /// The handle (qdisc/class) or filter parent.
    pub handle: TcHandle,
    /// Filter priority, if `kind == "filter"`.
    pub priority: Option<FilterPriority>,
}

#[cfg(test)]
mod tests {
    use std::future::ready;

    use super::*;

    #[test]
    fn defaults() {
        let o = ReconcileOptions::default();
        assert_eq!(o, ReconcileOptions::new());
        assert_eq!((o.max_retries, o.backoff), (3, Duration::from_millis(100)));
        assert!(!o.dry_run && !o.fallback_to_apply);
        let r = ReconcileReport::default();
        assert!(r.is_noop());
        assert_eq!(r.attempts, 0);
        assert_eq!(ExecOptions::default(), ExecOptions::new());
    }

    #[test]
    fn the_backoff_doubles_and_stops_doubling() {
        let o = ReconcileOptions::new().with_backoff(Duration::from_millis(1));
        assert_eq!(o.backoff_for(0), Duration::from_millis(1));
        assert_eq!(o.backoff_for(3), Duration::from_millis(8));
        assert_eq!(o.backoff_for(40), Duration::from_millis(1024));
    }

    #[tokio::test]
    async fn retry_retries_what_is_transient_and_only_that() {
        let o = ReconcileOptions::new()
            .with_max_retries(2)
            .with_backoff(Duration::ZERO);
        let busy = || Error::from_errno_ext_ack(libc::EBUSY, None, None);

        // Busy twice, then through: three attempts.
        let mut calls = 0;
        let (v, attempts) = o
            .retry(transient, || {
                calls += 1;
                ready(if calls < 3 { Err(busy()) } else { Ok(7) })
            })
            .await
            .unwrap();
        assert_eq!((v, attempts), (7, 3));

        // Busy forever: the third failure is returned.
        let mut calls = 0;
        let e = o
            .retry(transient, || {
                calls += 1;
                ready(Err::<(), _>(busy()))
            })
            .await
            .unwrap_err();
        assert!(e.is_busy());
        assert_eq!(calls, 3);

        // Not transient: no retry.
        let mut calls = 0;
        let e = o
            .retry(transient, || {
                calls += 1;
                ready(Err::<(), _>(Error::from_errno_ext_ack(
                    libc::EINVAL,
                    None,
                    None,
                )))
            })
            .await
            .unwrap_err();
        assert!(e.is_invalid_argument());
        assert_eq!(calls, 1);
    }
}

/// Every reconcile entry point must be spawnable (#879). They all go
/// through [`ReconcileOptions::retry`], and when it took an
/// `AsyncFnMut`, rustc could not prove the returned future `Send` for
/// every lifetime of the borrows the closure captured: none of them could
/// run in `tokio::spawn` or behind a `dyn Future + Send`. Compile-only.
#[cfg(test)]
#[allow(dead_code)]
mod spawnable {
    use std::future::Future;

    use super::ReconcileOptions;
    use crate::facade::Stack;
    use crate::netlink::config::{ApplyOptions, NetworkConfig};
    use crate::netlink::genl::wireguard::WireguardConfig;
    use crate::netlink::impair::PerPeerImpairer;
    use crate::netlink::nftables::config::{NftablesConfig, NftablesDiff};
    use crate::netlink::ratelimit::{PerHostLimiter, RateLimiter};
    use crate::netlink::{Connection, Nftables, Route, Wireguard};

    /// The bounds `tokio::spawn` puts on its future.
    fn spawnable<F: Future + Send + 'static>(_: F) {}

    fn nftables_config(cfg: NftablesConfig, conn: Connection<Nftables>) {
        spawnable(async move { cfg.apply_reconcile(&conn, ReconcileOptions::new()).await });
    }

    fn nftables_diff(diff: NftablesDiff, conn: Connection<Nftables>) {
        spawnable(async move { diff.apply_reconcile(&conn, ReconcileOptions::new()).await });
    }

    fn network_config(cfg: NetworkConfig, conn: Connection<Route>) {
        spawnable(async move { cfg.apply_reconcile(&conn, ReconcileOptions::new()).await });
        spawnable(async move {
            NetworkConfig::new()
                .apply_reconcile_with_options(
                    &Connection::<Route>::new()?,
                    ReconcileOptions::new(),
                    ApplyOptions::default(),
                )
                .await
        });
    }

    fn wireguard_config(cfg: WireguardConfig, conn: Connection<Wireguard>) {
        spawnable(async move { cfg.apply_reconcile(&conn, ReconcileOptions::new()).await });
    }

    fn rate_limiter(limiter: RateLimiter, conn: Connection<Route>) {
        spawnable(async move { limiter.reconcile(&conn).await });
    }

    fn per_host_limiter(limiter: PerHostLimiter, conn: Connection<Route>) {
        spawnable(async move { limiter.reconcile(&conn).await });
    }

    fn per_peer_impairer(impairer: PerPeerImpairer, conn: Connection<Route>) {
        spawnable(async move { impairer.reconcile(&conn).await });
    }

    fn stack(stack: Stack) {
        spawnable(async move {
            stack
                .apply_reconcile_in("ns", ReconcileOptions::new(), Default::default())
                .await
        });
    }
}
