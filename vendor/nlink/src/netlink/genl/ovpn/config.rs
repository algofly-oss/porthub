//! Declarative OVPN configuration — Plan 197 §2.2.
//!
//! Mirrors [`WireguardConfig`][crate::netlink::genl::wireguard::config::WireguardConfig]
//! and [`NftablesConfig`][crate::netlink::nftables::config::NftablesConfig]:
//! describe the desired ovpn interface state (peers + keys), then
//! `.diff()` / `.apply()` against the running kernel.
//!
//! # Identity model
//!
//! - **Peer identity** = `peer_id: u32` (userspace-assigned; max
//!   0xFFFFFF). A peer present in the kernel but not in the config
//!   is removed. A peer in the config but not in the kernel is
//!   added.
//! - **Key identity** = `(peer_id, slot)` (primary or secondary).
//!   Diffs install / delete keys per (peer, slot).
//!
//! # Diff inputs — read-only counters are excluded
//!
//! Per Plan 178 (the canonical NftablesDiff body-bytes false-positive
//! lesson) and Plan 196 (WireguardConfig): the `vpn-{rx,tx}-{bytes,
//! packets}` and `link-{rx,tx}-{bytes,packets}` counters on
//! `OvpnPeer` are read-only and grow monotonically — they MUST NOT
//! trigger drift detection. The `normalize_for_diff` step drops
//! them.
//!
//! # Key bytes vs key swap
//!
//! Installed key bytes are write-only — `key_get` never returns
//! them. The diff therefore can't tell whether a configured
//! `OvpnKeyConfig` matches the bytes the kernel currently holds.
//! Policy mirrors Wireguard's private-key write semantics: keys
//! present in the config are re-installed on every apply, but only
//! against slots that don't already hold a key with the same
//! `(cipher_alg, key_id)` metadata. This is idempotent at the
//! OpenVPN protocol layer.

use std::collections::BTreeMap;
use std::fmt;

use crate::netlink::genl::ovpn::messages::{OvpnKeyconf, OvpnKeydir, OvpnPeer};
use crate::netlink::genl::ovpn::types::{OvpnCipherAlg, OvpnKeySlot};
use crate::netlink::Connection;
use crate::{Error, Result};

use super::Ovpn;

// ============================================================
// Declarative types
// ============================================================

/// Desired OVPN configuration — one or more ovpn interfaces,
/// each with its peers + cipher keys.
#[derive(Debug, Clone, Default)]
#[must_use = "OvpnConfig does nothing unless .diff() or .apply() is called"]
pub struct OvpnConfig {
    interfaces: Vec<OvpnInterfaceConfig>,
}

#[nlink_macros::send_futures]
impl OvpnConfig {
    /// Start an empty config.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare an ovpn interface. The interface is identified by
    /// its kernel ifindex; the link itself must already exist
    /// (created via [`OvpnLink`][crate::netlink::link::OvpnLink]).
    pub fn interface<F>(mut self, ifindex: u32, build: F) -> Self
    where
        F: FnOnce(OvpnInterfaceConfigBuilder) -> OvpnInterfaceConfigBuilder,
    {
        let cfg = build(OvpnInterfaceConfigBuilder::new(ifindex)).build();
        self.interfaces.push(cfg);
        self
    }

    /// Borrow the declared interfaces.
    pub fn interfaces(&self) -> &[OvpnInterfaceConfig] {
        &self.interfaces
    }

    /// Compute the diff between this declaration and the kernel
    /// state.
    ///
    /// Reads the current peer set for every declared interface
    /// via `peer_dump`, then computes adds / updates / removes
    /// per peer + the installed-key metadata via `key_get` on
    /// each `(peer, slot)` pair the config declares.
    pub async fn diff(&self, conn: &Connection<Ovpn>) -> Result<OvpnDiff> {
        let mut diff = OvpnDiff::default();

        for iface in &self.interfaces {
            // 1. Read live peer state.
            let live_peers = conn.peer_dump(iface.ifindex).await?;
            let live_by_id: BTreeMap<u32, OvpnPeer> = live_peers
                .into_iter()
                .filter_map(|p| p.id.map(|id| (id, p)))
                .collect();

            // 2. Diff peers.
            for (&peer_id, declared) in &iface.peers {
                match live_by_id.get(&peer_id) {
                    None => {
                        diff.peers_to_add
                            .push((iface.ifindex, peer_id, declared.clone()));
                    }
                    Some(live) => {
                        if !peer_matches(declared, live) {
                            diff.peers_to_update.push((
                                iface.ifindex,
                                peer_id,
                                declared.clone(),
                            ));
                        }
                    }
                }
            }
            for &live_id in live_by_id.keys() {
                if !iface.peers.contains_key(&live_id) {
                    diff.peers_to_remove.push((iface.ifindex, live_id));
                }
            }

            // 3. Diff keys per (peer, slot).
            //
            //    Live key metadata: `key_get` returns Ok with the
            //    keyconf, Err(is_not_found) when no key is installed
            //    at that slot. We probe every (peer, slot) the
            //    config declares.
            for (&peer_id, declared_peer) in &iface.peers {
                for (&slot, declared_key) in &declared_peer.keys {
                    let live = conn.key_get(iface.ifindex, peer_id, slot).await;
                    match live {
                        Err(e) if e.is_not_found() => {
                            diff.keys_to_install.push((
                                iface.ifindex,
                                peer_id,
                                slot,
                                declared_key.clone(),
                            ));
                        }
                        Err(other) => return Err(other),
                        Ok(live_meta) => {
                            if !key_metadata_matches(declared_key, &live_meta) {
                                // Metadata mismatch → re-install
                                // (delete + install in apply).
                                diff.keys_to_delete
                                    .push((iface.ifindex, peer_id, slot));
                                diff.keys_to_install.push((
                                    iface.ifindex,
                                    peer_id,
                                    slot,
                                    declared_key.clone(),
                                ));
                            }
                            // Metadata-match case: nothing to do.
                            // Key bytes are write-only; we trust
                            // the metadata as the identity.
                        }
                    }
                }
            }
        }

        Ok(diff)
    }

    /// Compute the diff and apply it in one call. Equivalent to
    /// `self.diff(conn).await?.apply(conn).await`.
    pub async fn apply(&self, conn: &Connection<Ovpn>) -> Result<()> {
        self.diff(conn).await?.apply(conn).await
    }

    /// Reconcile policy: compute the diff, apply, then re-diff
    /// and bail loudly if anything still differs. Used when
    /// concurrent mutators may race with this apply.
    ///
    /// Returns `Error::is_busy()` (mapped from a non-empty
    /// post-apply diff) on convergence failure.
    pub async fn apply_reconcile(&self, conn: &Connection<Ovpn>) -> Result<()> {
        self.apply(conn).await?;
        let post = self.diff(conn).await?;
        if post.is_empty() {
            return Ok(());
        }
        Err(Error::invalid_message(format!(
            "ovpn apply_reconcile: kernel state diverged from config after apply \
             ({post})"
        )))
    }
}

/// One ovpn interface inside an [`OvpnConfig`].
#[derive(Debug, Clone)]
pub struct OvpnInterfaceConfig {
    /// Kernel ifindex of the ovpn interface.
    pub ifindex: u32,
    /// Declared peers, keyed by peer_id.
    pub peers: BTreeMap<u32, OvpnPeerConfig>,
}

/// Builder for [`OvpnInterfaceConfig`].
#[derive(Debug)]
#[must_use = "builders do nothing unless used"]
pub struct OvpnInterfaceConfigBuilder {
    ifindex: u32,
    peers: BTreeMap<u32, OvpnPeerConfig>,
}

impl OvpnInterfaceConfigBuilder {
    pub fn new(ifindex: u32) -> Self {
        Self {
            ifindex,
            peers: BTreeMap::new(),
        }
    }

    /// Declare a peer on this interface.
    pub fn peer<F>(mut self, peer_id: u32, build: F) -> Self
    where
        F: FnOnce(OvpnPeerConfigBuilder) -> OvpnPeerConfigBuilder,
    {
        let cfg = build(OvpnPeerConfigBuilder::new(peer_id)).build();
        self.peers.insert(peer_id, cfg);
        self
    }

    pub fn build(self) -> OvpnInterfaceConfig {
        OvpnInterfaceConfig {
            ifindex: self.ifindex,
            peers: self.peers,
        }
    }
}

/// Per-peer desired state.
#[derive(Debug, Clone, Default)]
pub struct OvpnPeerConfig {
    /// Userspace-assigned peer ID.
    pub peer_id: u32,
    /// Remote endpoint (UDP/TCP).
    pub remote: Option<std::net::SocketAddr>,
    /// Optional local source endpoint.
    pub local: Option<std::net::SocketAddr>,
    /// VPN-internal IPv4 the peer is assigned.
    pub vpn_ipv4: Option<std::net::Ipv4Addr>,
    /// VPN-internal IPv6 the peer is assigned.
    pub vpn_ipv6: Option<std::net::Ipv6Addr>,
    /// Keepalive interval (seconds).
    pub keepalive_interval: Option<u32>,
    /// Keepalive timeout (seconds).
    pub keepalive_timeout: Option<u32>,
    /// Optional per-peer socket fd. Same-netns only; cross-netns
    /// fd passing is deferred to a follow-up
    /// (`Connection::attach_socket`).
    pub socket_fd: Option<u32>,
    /// Cipher keys, keyed by slot.
    pub keys: BTreeMap<OvpnKeySlot, OvpnKeyConfig>,
}

/// Builder for [`OvpnPeerConfig`].
#[derive(Debug)]
#[must_use = "builders do nothing unless used"]
pub struct OvpnPeerConfigBuilder {
    cfg: OvpnPeerConfig,
}

impl OvpnPeerConfigBuilder {
    pub fn new(peer_id: u32) -> Self {
        Self {
            cfg: OvpnPeerConfig {
                peer_id,
                ..OvpnPeerConfig::default()
            },
        }
    }

    pub fn remote(mut self, addr: std::net::SocketAddr) -> Self {
        self.cfg.remote = Some(addr);
        self
    }

    pub fn local(mut self, addr: std::net::SocketAddr) -> Self {
        self.cfg.local = Some(addr);
        self
    }

    pub fn vpn_ipv4(mut self, addr: std::net::Ipv4Addr) -> Self {
        self.cfg.vpn_ipv4 = Some(addr);
        self
    }

    pub fn vpn_ipv6(mut self, addr: std::net::Ipv6Addr) -> Self {
        self.cfg.vpn_ipv6 = Some(addr);
        self
    }

    pub fn keepalive(mut self, interval_secs: u32, timeout_secs: u32) -> Self {
        self.cfg.keepalive_interval = Some(interval_secs);
        self.cfg.keepalive_timeout = Some(timeout_secs);
        self
    }

    pub fn socket_fd(mut self, fd: u32) -> Self {
        self.cfg.socket_fd = Some(fd);
        self
    }

    pub fn key(mut self, slot: OvpnKeySlot, key: OvpnKeyConfig) -> Self {
        self.cfg.keys.insert(slot, key);
        self
    }

    pub fn build(self) -> OvpnPeerConfig {
        self.cfg
    }
}

/// One cipher-key configuration, slotted into Primary or Secondary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OvpnKeyConfig {
    /// 3-bit OpenVPN per-packet key ID (0..=7).
    pub key_id: u32,
    /// AEAD algorithm.
    pub cipher_alg: OvpnCipherAlg,
    /// Cipher key + nonce tail for encrypting outgoing traffic.
    pub encrypt: OvpnKeydir,
    /// Cipher key + nonce tail for decrypting incoming traffic.
    pub decrypt: OvpnKeydir,
}

impl OvpnKeyConfig {
    /// Build a key config from raw material.
    pub fn new(
        key_id: u32,
        cipher_alg: OvpnCipherAlg,
        encrypt: OvpnKeydir,
        decrypt: OvpnKeydir,
    ) -> Self {
        Self {
            key_id,
            cipher_alg,
            encrypt,
            decrypt,
        }
    }
}

// ============================================================
// Diff
// ============================================================

/// Result of `OvpnConfig::diff` — set of additive + destructive
/// operations to apply.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct OvpnDiff {
    /// `(ifindex, peer_id, peer)` triples for peers the kernel
    /// hasn't yet seen.
    pub peers_to_add: Vec<(u32, u32, OvpnPeerConfig)>,
    /// `(ifindex, peer_id, peer)` triples for peers whose declared
    /// state differs from the kernel.
    pub peers_to_update: Vec<(u32, u32, OvpnPeerConfig)>,
    /// `(ifindex, peer_id)` pairs for peers present in the kernel
    /// but absent from the config.
    pub peers_to_remove: Vec<(u32, u32)>,
    /// `(ifindex, peer_id, slot, key)` quadruples for keys to
    /// install (or re-install after a metadata-change delete).
    pub keys_to_install: Vec<(u32, u32, OvpnKeySlot, OvpnKeyConfig)>,
    /// `(ifindex, peer_id, slot)` triples for keys whose metadata
    /// differs from declared — deleted before re-install.
    pub keys_to_delete: Vec<(u32, u32, OvpnKeySlot)>,
}

#[nlink_macros::send_futures]
impl OvpnDiff {
    /// `true` when no ops would be performed.
    pub fn is_empty(&self) -> bool {
        self.peers_to_add.is_empty()
            && self.peers_to_update.is_empty()
            && self.peers_to_remove.is_empty()
            && self.keys_to_install.is_empty()
            && self.keys_to_delete.is_empty()
    }

    /// Brief one-line summary, useful for logging.
    pub fn summary(&self) -> String {
        format!(
            "+{}p ~{}p -{}p +{}k -{}k",
            self.peers_to_add.len(),
            self.peers_to_update.len(),
            self.peers_to_remove.len(),
            self.keys_to_install.len(),
            self.keys_to_delete.len(),
        )
    }

    /// Apply the diff in a sensible order:
    ///
    /// 1. Delete stale peers (frees up resources).
    /// 2. Delete stale keys.
    /// 3. Add new peers.
    /// 4. Update existing peers.
    /// 5. Install / re-install keys.
    pub async fn apply(&self, conn: &Connection<Ovpn>) -> Result<()> {
        for (ifindex, peer_id) in &self.peers_to_remove {
            conn.peer_del(*ifindex, *peer_id).await?;
        }

        for (ifindex, peer_id, slot) in &self.keys_to_delete {
            conn.key_del(*ifindex, *peer_id, *slot).await?;
        }

        for (ifindex, peer_id, peer) in &self.peers_to_add {
            conn.peer_new(*ifindex, build_kernel_peer(*peer_id, peer))
                .await?;
        }

        for (ifindex, peer_id, peer) in &self.peers_to_update {
            conn.peer_set(*ifindex, build_kernel_peer(*peer_id, peer))
                .await?;
        }

        for (ifindex, peer_id, slot, key) in &self.keys_to_install {
            let keyconf = OvpnKeyconf::new(
                *peer_id,
                *slot,
                key.key_id,
                key.cipher_alg,
                key.encrypt.clone(),
                key.decrypt.clone(),
            );
            conn.key_new(*ifindex, keyconf).await?;
        }

        Ok(())
    }
}

impl fmt::Display for OvpnDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("(no changes)");
        }
        let mut first = true;
        let mut write_section = |label: &str, count: usize| -> fmt::Result {
            if count == 0 {
                return Ok(());
            }
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            write!(f, "{count} {label}")
        };
        write_section("peers to add", self.peers_to_add.len())?;
        write_section("peers to update", self.peers_to_update.len())?;
        write_section("peers to remove", self.peers_to_remove.len())?;
        write_section("keys to install", self.keys_to_install.len())?;
        write_section("keys to delete", self.keys_to_delete.len())?;
        Ok(())
    }
}

// ============================================================
// Diff comparators
// ============================================================

/// Convert an [`OvpnPeerConfig`] into the [`OvpnPeer`] message
/// the kernel expects.
fn build_kernel_peer(peer_id: u32, cfg: &OvpnPeerConfig) -> OvpnPeer {
    let mut peer = OvpnPeer::identity(peer_id);
    if let Some(remote) = cfg.remote {
        match remote {
            std::net::SocketAddr::V4(v4) => peer.set_remote_v4(v4),
            std::net::SocketAddr::V6(v6) => peer.set_remote_v6(v6),
        }
    }
    if let Some(local) = cfg.local {
        // The kernel separates local-ipv4/ipv6/port for UDP. We
        // populate whichever family matches the declared address.
        match local {
            std::net::SocketAddr::V4(v4) => {
                peer.local_ipv4 = Some(OvpnPeer::encode_ipv4(*v4.ip()));
                peer.local_port = Some(OvpnPeer::encode_port(v4.port()));
            }
            std::net::SocketAddr::V6(v6) => {
                peer.local_ipv6 = Some(OvpnPeer::encode_ipv6(*v6.ip()));
                peer.local_port = Some(OvpnPeer::encode_port(v6.port()));
            }
        }
    }
    if let Some(v4) = cfg.vpn_ipv4 {
        peer.vpn_ipv4 = Some(OvpnPeer::encode_ipv4(v4));
    }
    if let Some(v6) = cfg.vpn_ipv6 {
        peer.vpn_ipv6 = Some(OvpnPeer::encode_ipv6(v6));
    }
    if let Some(interval) = cfg.keepalive_interval {
        peer.keepalive_interval = Some(interval);
    }
    if let Some(timeout) = cfg.keepalive_timeout {
        peer.keepalive_timeout = Some(timeout);
    }
    if let Some(fd) = cfg.socket_fd {
        peer.socket = Some(fd);
    }
    peer
}

/// Compare the declared `OvpnPeerConfig` against what the kernel
/// reports for the peer. Read-only counter fields are excluded
/// from comparison (Plan 178 invariant).
fn peer_matches(declared: &OvpnPeerConfig, live: &OvpnPeer) -> bool {
    // Remote endpoint
    if let Some(remote) = declared.remote
        && live.remote_socket() != Some(remote)
    {
        return false;
    }
    // VPN-internal IPv4
    if let Some(v4) = declared.vpn_ipv4
        && live.vpn_ipv4.as_deref().and_then(OvpnPeer::decode_ipv4) != Some(v4)
    {
        return false;
    }
    // VPN-internal IPv6
    if let Some(v6) = declared.vpn_ipv6
        && live.vpn_ipv6.as_deref().and_then(OvpnPeer::decode_ipv6) != Some(v6)
    {
        return false;
    }
    // Local source endpoint. Stored by the builder, encoded on
    // create, read back on dump — and compared by nothing, so changing
    // it was a silent no-op that `apply_reconcile` then reported as
    // successful convergence (#281).
    if let Some(local) = declared.local
        && live.local_socket() != Some(local)
    {
        return false;
    }
    // Keepalives
    if let Some(interval) = declared.keepalive_interval
        && live.keepalive_interval != Some(interval)
    {
        return false;
    }
    if let Some(timeout) = declared.keepalive_timeout
        && live.keepalive_timeout != Some(timeout)
    {
        return false;
    }
    // socket_fd: not user-comparable (kernel stores its own
    // index; ignored for drift purposes — re-applying socket_fd
    // would just re-attach the same fd).
    //
    // Counters (vpn_*, link_*): intentionally NOT compared
    // (Plan 178 invariant).
    true
}

/// Compare declared key metadata against what `key_get` returns.
/// Key bytes are write-only; identity = (cipher_alg, key_id).
fn key_metadata_matches(declared: &OvpnKeyConfig, live: &OvpnKeyconf) -> bool {
    if live.cipher_alg != Some(declared.cipher_alg) {
        return false;
    }
    if live.key_id != Some(declared.key_id) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_key(key_id: u32) -> OvpnKeyConfig {
        OvpnKeyConfig::new(
            key_id,
            OvpnCipherAlg::AesGcm,
            OvpnKeydir::new([1u8; 32], [2u8; 8]),
            OvpnKeydir::new([3u8; 32], [4u8; 8]),
        )
    }

    #[test]
    fn empty_diff_summary_is_descriptive() {
        let diff = OvpnDiff::default();
        assert!(diff.is_empty());
        assert_eq!(diff.summary(), "+0p ~0p -0p +0k -0k");
        assert_eq!(format!("{diff}"), "(no changes)");
    }

    #[test]
    fn diff_display_lists_nonzero_sections() {
        let mut diff = OvpnDiff::default();
        diff.peers_to_add
            .push((7, 1, OvpnPeerConfig::default()));
        diff.keys_to_install.push((
            7,
            1,
            OvpnKeySlot::Primary,
            dummy_key(0),
        ));
        let s = format!("{diff}");
        assert!(s.contains("1 peers to add"), "{s}");
        assert!(s.contains("1 keys to install"), "{s}");
        assert!(!s.contains("peers to remove"), "{s}");
    }

    #[test]
    fn config_builder_records_peer() {
        let cfg = OvpnConfig::new()
            .interface(5, |b| {
                b.peer(42, |p| {
                    p.remote("10.0.0.1:1194".parse().unwrap())
                        .keepalive(20, 60)
                        .vpn_ipv4("172.16.0.1".parse().unwrap())
                        .key(OvpnKeySlot::Primary, dummy_key(1))
                })
            })
            .interface(5, |b| {
                // Test that a second interface call appends (this
                // doesn't dedupe — duplicate ifindex would be a
                // caller bug).
                b.peer(99, |p| p.keepalive(30, 90))
            });
        assert_eq!(cfg.interfaces().len(), 2);
        assert_eq!(cfg.interfaces()[0].ifindex, 5);
        assert_eq!(cfg.interfaces()[0].peers.len(), 1);
        let p = &cfg.interfaces()[0].peers[&42];
        assert_eq!(p.peer_id, 42);
        assert_eq!(p.keepalive_interval, Some(20));
        assert_eq!(p.keys.len(), 1);
        assert_eq!(
            p.keys.get(&OvpnKeySlot::Primary).unwrap().cipher_alg,
            OvpnCipherAlg::AesGcm
        );
    }

    #[test]
    fn peer_matches_ignores_counters() {
        let declared = OvpnPeerConfig {
            peer_id: 1,
            remote: Some("10.0.0.1:1194".parse().unwrap()),
            keepalive_interval: Some(20),
            keepalive_timeout: Some(60),
            ..OvpnPeerConfig::default()
        };
        // Live peer with the same config-relevant fields and
        // wildly different counters.
        let mut live = OvpnPeer::identity(1);
        live.set_remote_v4("10.0.0.1:1194".parse().unwrap());
        live.keepalive_interval = Some(20);
        live.keepalive_timeout = Some(60);
        live.vpn_rx_bytes = Some(1_000_000_000);
        live.link_tx_packets = Some(50_000);
        assert!(peer_matches(&declared, &live));
    }

    #[test]
    fn peer_matches_detects_endpoint_drift() {
        let declared = OvpnPeerConfig {
            peer_id: 1,
            remote: Some("10.0.0.1:1194".parse().unwrap()),
            ..OvpnPeerConfig::default()
        };
        let mut live = OvpnPeer::identity(1);
        live.set_remote_v4("10.0.0.2:1194".parse().unwrap());
        assert!(!peer_matches(&declared, &live));
    }

    #[test]
    fn peer_matches_detects_keepalive_drift() {
        let declared = OvpnPeerConfig {
            peer_id: 1,
            keepalive_interval: Some(20),
            ..OvpnPeerConfig::default()
        };
        let mut live = OvpnPeer::identity(1);
        live.keepalive_interval = Some(30);
        assert!(!peer_matches(&declared, &live));
    }

    #[test]
    fn key_metadata_matches_on_alg_and_id() {
        let declared = dummy_key(1);
        let live = OvpnKeyconf {
            peer_id: Some(7),
            slot: Some(OvpnKeySlot::Primary),
            key_id: Some(1),
            cipher_alg: Some(OvpnCipherAlg::AesGcm),
            ..OvpnKeyconf::default()
        };
        assert!(key_metadata_matches(&declared, &live));
    }

    #[test]
    fn key_metadata_mismatch_on_alg() {
        let declared = dummy_key(1);
        let live = OvpnKeyconf {
            peer_id: Some(7),
            slot: Some(OvpnKeySlot::Primary),
            key_id: Some(1),
            cipher_alg: Some(OvpnCipherAlg::Chacha20Poly1305),
            ..OvpnKeyconf::default()
        };
        assert!(!key_metadata_matches(&declared, &live));
    }

    #[test]
    fn key_metadata_mismatch_on_key_id() {
        let declared = dummy_key(1);
        let live = OvpnKeyconf {
            peer_id: Some(7),
            slot: Some(OvpnKeySlot::Primary),
            key_id: Some(2),
            cipher_alg: Some(OvpnCipherAlg::AesGcm),
            ..OvpnKeyconf::default()
        };
        assert!(!key_metadata_matches(&declared, &live));
    }

    #[test]
    fn build_kernel_peer_serializes_endpoint_correctly() {
        let cfg = OvpnPeerConfig {
            peer_id: 7,
            remote: Some("10.0.0.1:1194".parse().unwrap()),
            vpn_ipv4: Some("172.16.0.7".parse().unwrap()),
            keepalive_interval: Some(20),
            keepalive_timeout: Some(60),
            ..OvpnPeerConfig::default()
        };
        let peer = build_kernel_peer(7, &cfg);
        assert_eq!(peer.id, Some(7));
        assert_eq!(
            peer.remote_socket(),
            Some("10.0.0.1:1194".parse().unwrap())
        );
        assert_eq!(
            peer.vpn_ipv4.as_deref().and_then(OvpnPeer::decode_ipv4),
            Some("172.16.0.7".parse().unwrap())
        );
        assert_eq!(peer.keepalive_interval, Some(20));
        assert_eq!(peer.keepalive_timeout, Some(60));
    }
}
