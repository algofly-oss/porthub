//! One-line diff wrappers. Plan 200 §2.2.
//!
//! Pair with [`super::apply`] — render the diff, decide
//! whether to apply, then commit.
//!
//! Each config type has two shapes: plain, for the default namespace,
//! and `_in(ns)`, for any other. `ns` is anything
//! [`Into<NetnsTarget>`](crate::netlink::namespace::NetnsTarget): an
//! `ip netns` name, an open `Netns`, a `NetnsRef`, a path, a
//! namespace fd (#169, #532). The `_in_namespace(&str)` forms are
//! deprecated.

use crate::netlink::config::{ConfigDiff, PlanOptions, NetworkConfig};
use crate::netlink::genl::wireguard::{WireguardConfig, WireguardConfigDiff};
use crate::netlink::namespace::{NetnsRef, NetnsTarget};
use crate::netlink::nftables::config::{NftablesConfig, NftablesDiff};
use crate::netlink::{Nftables, Route, Wireguard};
use crate::{Connection, Result};

// =============================================================================
// NetworkConfig — RTNETLINK
// =============================================================================

/// Diff a network config against the host's default
/// namespace.
#[nlink_macros::send_futures]
pub async fn network(cfg: &NetworkConfig) -> Result<ConfigDiff> {
    network_in(NetnsRef::Default, cfg).await
}

/// Diff a network config against a named namespace.
#[deprecated(since = "0.32.0", note = "use `network_in(ns, …)`, which takes a name (#532)")]
#[nlink_macros::send_futures]
pub async fn network_in_namespace(ns: &str, cfg: &NetworkConfig) -> Result<ConfigDiff> {
    network_in(ns, cfg).await
}

/// Diff a network config against any namespace specification
/// (named, path, or PID — container support, #169).
#[nlink_macros::send_futures]
pub async fn network_in<'a>(ns: impl Into<NetnsTarget<'a>>, cfg: &NetworkConfig) -> Result<ConfigDiff> {
    let ns: NetnsTarget<'a> = ns.into();
    network_in_with(ns, cfg, PlanOptions::default()).await
}

/// [`network_in`] with [`PlanOptions`] — `purge(true)` includes the
/// removals a purging apply would perform (#330).
#[nlink_macros::send_futures]
pub async fn network_in_with<'a>(
    ns: impl Into<NetnsTarget<'a>>,
    cfg: &NetworkConfig,
    opts: PlanOptions,
) -> Result<ConfigDiff> {
    let ns: NetnsTarget<'a> = ns.into();
    let conn: Connection<Route> = ns.connection()?;
    cfg.diff_with_options(&conn, opts).await
}

// =============================================================================
// NftablesConfig
// =============================================================================

/// Diff an nftables config against the host's default
/// namespace.
#[nlink_macros::send_futures]
pub async fn nftables(cfg: &NftablesConfig) -> Result<NftablesDiff> {
    nftables_in(NetnsRef::Default, cfg).await
}

/// Diff an nftables config against a named namespace.
#[deprecated(since = "0.32.0", note = "use `nftables_in(ns, …)`, which takes a name (#532)")]
#[nlink_macros::send_futures]
pub async fn nftables_in_namespace(ns: &str, cfg: &NftablesConfig) -> Result<NftablesDiff> {
    nftables_in(ns, cfg).await
}

/// Diff an nftables config against any namespace specification
/// (named, path, or PID — container support, #169).
#[nlink_macros::send_futures]
pub async fn nftables_in<'a>(ns: impl Into<NetnsTarget<'a>>, cfg: &NftablesConfig) -> Result<NftablesDiff> {
    let ns: NetnsTarget<'a> = ns.into();
    let conn: Connection<Nftables> = ns.connection()?;
    cfg.diff(&conn).await
}

// =============================================================================
// WireguardConfig
// =============================================================================

/// Diff a WireGuard config against the host's default
/// namespace.
#[nlink_macros::send_futures]
pub async fn wireguard(cfg: &WireguardConfig) -> Result<WireguardConfigDiff> {
    wireguard_in(NetnsRef::Default, cfg).await
}

/// Diff a WireGuard config against a named namespace.
#[deprecated(since = "0.32.0", note = "use `wireguard_in(ns, …)`, which takes a name (#532)")]
#[nlink_macros::send_futures]
pub async fn wireguard_in_namespace(
    ns: &str,
    cfg: &WireguardConfig,
) -> Result<WireguardConfigDiff> {
    wireguard_in(ns, cfg).await
}

/// Diff a WireGuard config against any namespace specification
/// (named, path, or PID — container support, #169).
#[nlink_macros::send_futures]
pub async fn wireguard_in<'a>(
    ns: impl Into<NetnsTarget<'a>>,
    cfg: &WireguardConfig,
) -> Result<WireguardConfigDiff> {
    let ns: NetnsTarget<'a> = ns.into();
    let conn: Connection<Wireguard> = ns.connection_async().await?;
    cfg.diff(&conn).await
}
