//! Shared types for TC recipe `reconcile()` operations.
//!
//! Each TC recipe helper (currently [`PerPeerImpairer`] and
//! [`PerHostLimiter`]) exposes both a destructive [`apply()`] verb and a
//! non-destructive [`reconcile()`] verb. `reconcile()` returns a
//! [`ReconcileReport`] describing the change set it computed (and, when
//! not in dry-run mode, executed).
//!
//! See `docs/recipes/per-peer-impairment.md` and the reconcile-loop
//! example in `CLAUDE.md` for usage.
//!
//! [`PerPeerImpairer`]: super::impair::PerPeerImpairer
//! [`PerHostLimiter`]: super::ratelimit::PerHostLimiter
//! [`apply()`]: super::impair::PerPeerImpairer::apply
//! [`reconcile()`]: super::impair::PerPeerImpairer::reconcile

// One type of each for every layer and recipe since 0.32 (#532).
pub use super::reconcile::{ReconcileOptions, ReconcileReport, StaleObject, UnmanagedObject};
