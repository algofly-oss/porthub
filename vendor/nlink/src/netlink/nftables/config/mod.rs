//! Declarative `NftablesConfig` — mirror of `NetworkConfig` for
//! the nftables subsystem.
//!
//! See [`NftablesConfig`] for the builder, [`NftablesDiff`] for
//! the result of `diff`, and `apply.rs` for the transactional
//! commit.
//!
//! # When to use
//!
//! - You manage a firewall declaratively (config file → kernel
//!   state) rather than imperatively (call `add_table` /
//!   `add_chain` / `add_rule` by hand).
//! - You need atomic apply (all-or-nothing) so the kernel never
//!   sees a partially-applied ruleset.
//! - You want a stable cycle: declare state → compute diff →
//!   apply → diff again is no-op.
//!
//! For one-off mutations, use the imperative
//! `Connection::<Nftables>::{add_table, add_chain, add_rule}`
//! methods directly.
//!
//! # Example
//!
//! ```no_run
//! use nlink::{Connection, Nftables, NftablesConfig};
//! use nlink::netlink::nftables::{BaseChain, Family, FilterHook, Policy, Priority};
//!
//! # async fn run() -> nlink::Result<()> {
//! let input = BaseChain::filter(FilterHook::Input, Priority::Filter).policy(Policy::Drop);
//! let cfg = NftablesConfig::new()
//!     .table("filter", Family::Inet, |t| t.chain("input", |c| c.base(input)));
//!
//! let conn = Connection::<Nftables>::new()?;
//! let diff = cfg.diff(&conn).await?;
//! println!("{diff}");
//! diff.apply(&conn).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Scope
//!
//! Covers tables, chains, rules, flowtables, sets (intervals,
//! concatenations, timeouts, maps and verdict maps) and named
//! stateful objects (counters, quotas, limits). A `DeclaredRule`
//! matches a kernel rule by its key — caller-supplied with
//! `rule_keyed`, else derived from its content — and declared order is
//! enforced per chain. Bodies are compared after attribute
//! normalization, with the live state the kernel echoes (counter
//! values, quota consumption) left out; sets and objects are compared
//! by configuration, never by what the packet path has done to them.
//! See `docs/recipes/nftables-declarative-config.md` and
//! `docs/recipes/nftables-sets-maps.md`.

mod apply;
mod change;
mod diff;
mod rules;
mod snapshot;
mod types;

pub(crate) use diff::expression_bytes;
pub(crate) use rules::{canonical_body, canonical_elements};
pub use change::{
    Blocked, Change, NftChain, NftChange, NftElements, NftFlowtable, NftItem, NftObject, NftRule,
    NftSet, NftTable,
};
pub use snapshot::RulesetSnapshot;

// The one reconcile vocabulary every layer shares (#532).
pub use crate::netlink::reconcile::{ReconcileOptions, ReconcileReport};
pub use diff::{NftDiffOptions, NftablesDiff, RuleHandle, RulePlacement};
pub(crate) use diff::{MoveReason, RuleMove, SetElementsChange};
// The Declared* types are what `NftablesConfig::tables()` hands back, so
// leaving them unexported made them unnameable — a caller could not
// destructure or construct one (#210, when one was a diff field's type).
// The *Builder types are the same story from the other direction: the
// declarative DSL hands one to every closure the caller writes
// (`cfg.table("t", Inet, |t| t.chain("c", |c| ...))`), so they are already
// de-facto public API — a caller just could not name them, which meant no
// helper function could take one as a parameter.
pub use types::{
    DeclaredChain, DeclaredChainBuilder, DeclaredFlowtable, DeclaredFlowtableBuilder,
    DeclaredObject, DeclaredRule, DeclaredSet, DeclaredSetBuilder, DeclaredTable,
    DeclaredTableBuilder, NftablesConfig, SetElementMode, TableMode,
};
