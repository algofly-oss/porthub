//! Compile the recipe markdown as doctests — #319.
//!
//! Nothing compiled `docs/recipes/`. 91 Rust blocks across 21 files, checked
//! only by `scripts/audit-recipe-drift.sh`, a grep gate whose own header
//! calls itself a stop-gap for "a synthetic compile-fixture per recipe
//! block". This is that fixture, and it needs no generator: rustdoc compiles
//! every fenced Rust block in a markdown file pulled in with `include_str!`,
//! so an empty module per recipe is the whole harness.
//!
//! `#[cfg(doctest)]` on the parent means these modules exist only when
//! rustdoc is collecting doctests — they cost nothing in a normal build.
//!
//! The `include_str!` paths reach above the package root, so the recipes are
//! not in the published tarball and this module only resolves in-tree. That
//! is fine for what it is: `#[cfg(doctest)]` means a normal build and
//! `cargo doc` (docs.rs included) never compile it, and the consumer of the
//! check is this repository's CI.
//!
//! A recipe whose code needs a feature is gated on it here, the same way
//! the crate's own doc examples are: rustdoc skips a `#[cfg]`-ed-out item's
//! documentation, and an ungated recipe would fail the default-feature
//! `cargo test --doc` for want of `nlink::lab`.
//!
//! A new recipe belongs here the day it is written. `cargo test --doc` is
//! then the only thing that has to agree the recipe is real.

#[doc = include_str!("../../../docs/recipes/bidirectional-rate-limit.md")]
mod bidirectional_rate_limit {}

#[doc = include_str!("../../../docs/recipes/bridge-vlan.md")]
mod bridge_vlan {}

#[doc = include_str!("../../../docs/recipes/cgroup-classification.md")]
mod cgroup_classification {}

#[doc = include_str!("../../../docs/recipes/connection-pool.md")]
mod connection_pool {}

#[cfg(feature = "lab")]
#[doc = include_str!("../../../docs/recipes/conntrack-programmatic.md")]
mod conntrack_programmatic {}

#[doc = include_str!("../../../docs/recipes/define-your-own-genl-family.md")]
mod define_your_own_genl_family {}

#[doc = include_str!("../../../docs/recipes/dpll-monitor.md")]
mod dpll_monitor {}

#[doc = include_str!("../../../docs/recipes/error-handling-patterns.md")]
mod error_handling_patterns {}

#[doc = include_str!("../../../docs/recipes/events-with-resync.md")]
mod events_with_resync {}

#[doc = include_str!("../../../docs/recipes/ipset-to-nftables.md")]
mod ipset_to_nftables {}

#[cfg(feature = "namespace_watcher")]
#[doc = include_str!("../../../docs/recipes/multi-namespace-events.md")]
mod multi_namespace_events {}

#[doc = include_str!("../../../docs/recipes/netdev-lifecycle.md")]
mod netdev_lifecycle {}

#[doc = include_str!("../../../docs/recipes/nft-mark-tc-classification.md")]
mod nft_mark_tc_classification {}

#[cfg(feature = "serde")]
#[doc = include_str!("../../../docs/recipes/nftables-declarative-config.md")]
mod nftables_declarative_config {}

#[cfg(feature = "lab")]
#[doc = include_str!("../../../docs/recipes/nftables-stateful-fw.md")]
mod nftables_stateful_fw {}

#[doc = include_str!("../../../docs/recipes/nftables-sets-maps.md")]
mod nftables_sets_maps {}

#[doc = include_str!("../../../docs/recipes/nftables-watch-with-resync.md")]
mod nftables_watch_with_resync {}

#[doc = include_str!("../../../docs/recipes/openvpn-dco.md")]
mod openvpn_dco {}

#[doc = include_str!("../../../docs/recipes/per-peer-impairment.md")]
mod per_peer_impairment {}

#[cfg(feature = "sockdiag")]
#[doc = include_str!("../../../docs/recipes/per-process-bandwidth.md")]
mod per_process_bandwidth {}

#[cfg(all(feature = "replay", feature = "lab"))]
#[doc = include_str!("../../../docs/recipes/replay-testing.md")]
mod replay_testing {}

#[doc = include_str!("../../../docs/recipes/tx-hw-shaping.md")]
mod tx_hw_shaping {}

#[cfg(feature = "lab")]
#[doc = include_str!("../../../docs/recipes/wireguard-mesh.md")]
mod wireguard_mesh {}

#[cfg(feature = "lab")]
#[doc = include_str!("../../../docs/recipes/xfrm-ipsec-tunnel.md")]
mod xfrm_ipsec_tunnel {}


// The living documents outside `docs/recipes/` (#449). Until these lines
// existed, 39 of their 40 Rust blocks no longer compiled. Some called
// methods that never existed, such as `FlowerFilter::action` (#450) and a
// subnet scanner nlink does not have. Each is gated on every feature its
// blocks use.

#[cfg(all(feature = "sockdiag", feature = "namespace_watcher", feature = "schemars"))]
#[doc = include_str!("../../../docs/library.md")]
mod library_md {}

// `tracing_subscriber` is a dependency only through `lab`.
#[cfg(feature = "lab")]
#[doc = include_str!("../../../docs/observability.md")]
mod observability_md {}

#[cfg(feature = "schemars")]
#[doc = include_str!("../../../README.md")]
mod readme_md {}
