//! One-line apply wrappers. Plan 200 §2.1.
//!
//! Each function opens a fresh `Connection<P>` and calls
//! `cfg.apply(&conn).await`. Use these for the common case;
//! reach for the typed `Connection<P>::new()?.apply(&cfg)`
//! form when you need a pre-existing connection (e.g. one
//! shared across many apply calls).
//!
//! Each config type has two shapes: plain, for the default namespace,
//! and `_in(ns)`, for any other. `ns` is anything
//! [`Into<NetnsTarget>`](crate::netlink::namespace::NetnsTarget): an
//! `ip netns` name, an open `Netns`, a `NetnsRef`, a path, a
//! namespace fd (#169, #532). The `_in_namespace(&str)` forms are
//! deprecated.

use crate::netlink::config::{ApplyOptions, ApplyResult, NetworkConfig};
use crate::netlink::genl::wireguard::WireguardConfig;
use crate::netlink::namespace::{NetnsRef, NetnsTarget};
use crate::netlink::nftables::config::NftablesConfig;
use crate::netlink::{Nftables, Route, Wireguard};
use crate::{Connection, Result};

// =============================================================================
// NetworkConfig — RTNETLINK
// =============================================================================

/// Apply a network config to the host's default namespace.
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::config::NetworkConfig;
/// let cfg = NetworkConfig::new().link("eth0", |b| b.dummy());
/// nlink::facade::apply::network(&cfg).await?;
/// # Ok(())
/// # }
/// ```
#[nlink_macros::send_futures]
pub async fn network(cfg: &NetworkConfig) -> Result<ApplyResult> {
    network_in(NetnsRef::Default, cfg).await
}

/// Apply a network config inside a named namespace.
#[deprecated(since = "0.32.0", note = "use `network_in(ns, …)`, which takes a name (#532)")]
#[nlink_macros::send_futures]
pub async fn network_in_namespace(ns: &str, cfg: &NetworkConfig) -> Result<ApplyResult> {
    network_in(ns, cfg).await
}

/// Apply a network config inside any namespace specification
/// (named, path, or PID — container support, #169).
#[nlink_macros::send_futures]
pub async fn network_in<'a>(ns: impl Into<NetnsTarget<'a>>, cfg: &NetworkConfig) -> Result<ApplyResult> {
    let ns: NetnsTarget<'a> = ns.into();
    network_in_with(ns, cfg, ApplyOptions::default()).await
}

/// [`network_in`] with [`ApplyOptions`] — purge, dry-run,
/// continue-on-error (#330).
#[nlink_macros::send_futures]
pub async fn network_in_with<'a>(
    ns: impl Into<NetnsTarget<'a>>,
    cfg: &NetworkConfig,
    opts: ApplyOptions,
) -> Result<ApplyResult> {
    let ns: NetnsTarget<'a> = ns.into();
    let conn: Connection<Route> = ns.connection()?;
    cfg.apply_with_options(&conn, opts).await
}

// =============================================================================
// NftablesConfig
// =============================================================================

/// Apply an nftables config to the host's default namespace.
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::netlink::nftables::Family;
/// use nlink::netlink::nftables::config::NftablesConfig;
/// let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| t);
/// nlink::facade::apply::nftables(&cfg).await?;
/// # Ok(())
/// # }
/// ```
#[nlink_macros::send_futures]
pub async fn nftables(cfg: &NftablesConfig) -> Result<usize> {
    nftables_in(NetnsRef::Default, cfg).await
}

/// Apply an nftables config inside a named namespace.
#[deprecated(since = "0.32.0", note = "use `nftables_in(ns, …)`, which takes a name (#532)")]
#[nlink_macros::send_futures]
pub async fn nftables_in_namespace(ns: &str, cfg: &NftablesConfig) -> Result<usize> {
    nftables_in(ns, cfg).await
}

/// Apply an nftables config inside any namespace specification
/// (named, path, or PID — container support, #169).
#[nlink_macros::send_futures]
pub async fn nftables_in<'a>(ns: impl Into<NetnsTarget<'a>>, cfg: &NftablesConfig) -> Result<usize> {
    let ns: NetnsTarget<'a> = ns.into();
    let conn: Connection<Nftables> = ns.connection()?;
    // Re-diffs if another writer changes the ruleset under it (#482).
    let opts = crate::reconcile::ReconcileOptions::default();
    Ok(cfg.apply_reconcile(&conn, opts).await?.changes_made)
}

// =============================================================================
// WireguardConfig
// =============================================================================

/// Apply a WireGuard config to the host's default namespace.
///
/// Opens the WG GENL connection via the async resolver
/// (family-ID resolution requires a roundtrip to the kernel
/// genetlink controller). Missing declared devices are created
/// first via [`WireguardConfig::ensure_devices`] with a Route
/// connection in the same namespace (#169).
#[nlink_macros::send_futures]
pub async fn wireguard(
    cfg: &WireguardConfig,
) -> Result<crate::netlink::genl::wireguard::WireguardApplyResult> {
    wireguard_in(NetnsRef::Default, cfg).await
}

/// Apply a WireGuard config inside a named namespace.
#[deprecated(since = "0.32.0", note = "use `wireguard_in(ns, …)`, which takes a name (#532)")]
#[nlink_macros::send_futures]
pub async fn wireguard_in_namespace(
    ns: &str,
    cfg: &WireguardConfig,
) -> Result<crate::netlink::genl::wireguard::WireguardApplyResult> {
    wireguard_in(ns, cfg).await
}

/// Apply a WireGuard config inside any namespace specification
/// (named, path, or PID — container support, #169).
///
/// Bootstraps missing devices: declared WG links that don't exist
/// are created through a Route connection in the same namespace
/// before the GENL apply, so a bare `WireguardConfig` works
/// end-to-end without a separate `NetworkConfig` layer.
#[nlink_macros::send_futures]
pub async fn wireguard_in<'a>(
    ns: impl Into<NetnsTarget<'a>>,
    cfg: &WireguardConfig,
) -> Result<crate::netlink::genl::wireguard::WireguardApplyResult> {
    let ns: NetnsTarget<'a> = ns.into();
    wireguard_devices_in(ns.clone(), cfg).await?;
    wireguard_keys_in(ns, cfg).await
}

/// The GENL half of [`wireguard_in`]: keys, listen ports and peers on
/// links that already exist. [`Stack`](super::Stack) creates the links
/// first and calls this, rather than bootstrapping them twice (#501).
pub(crate) async fn wireguard_keys_in<'a>(
    ns: impl Into<NetnsTarget<'a>>,
    cfg: &WireguardConfig,
) -> Result<crate::netlink::genl::wireguard::WireguardApplyResult> {
    let ns: NetnsTarget<'a> = ns.into();
    let conn: Connection<Wireguard> = ns.connection_async().await?;
    cfg.apply(&conn).await
}

/// Only the link half of [`wireguard_in`]: create every declared
/// WireGuard link that is missing and bring every declared link up,
/// through a Route connection in the namespace. Returns the names
/// created. This is what a `NetworkConfig` that addresses the tunnel
/// needs to run *before* it — [`Stack`](super::Stack) does so (#330).
#[nlink_macros::send_futures]
pub async fn wireguard_devices_in<'a>(ns: impl Into<NetnsTarget<'a>>, cfg: &WireguardConfig) -> Result<Vec<String>> {
    let ns: NetnsTarget<'a> = ns.into();
    let route: Connection<Route> = ns.connection()?;
    cfg.ensure_devices(&route).await
}
