//! Typed request + reply structs for the OVPN GENL family.
//!
//! Mostly `#[derive(GenlMessage)]` + `#[derive(NetlinkAttrs)]`
//! from `nlink-macros`. Per-field commentary:
//!
//! - **IPv4 / port** are stored as `Option<Vec<u8>>` (4 or 2
//!   bytes, respectively, big-endian per the YAML spec). The
//!   nlink-macros derive doesn't currently model per-field
//!   big-endian primitives; binary attributes round-trip the
//!   exact bytes both directions, which is what the kernel
//!   expects. Convenience helpers on the typed wrappers convert
//!   to/from `Ipv4Addr` / `SocketAddrV4`.
//! - **IPv6** is `Option<Vec<u8>>` (16 bytes). Same rationale.
//! - **Counters** (vpn-rx-bytes, link-tx-packets, …) are typed as
//!   `u64`. The YAML spec has them as `uint`, which the kernel writes
//!   with `nla_put_uint`: 4 bytes while the value fits in 32 bits, 8
//!   after. `parse_u64_attr` reads both (#763; it took only the 8-byte
//!   form, so a peer's small counters failed to decode).

use super::types::{
    OvpnAttr, OvpnCipherAlg, OvpnCmd, OvpnDelPeerReason, OvpnKeySlot, OvpnKeyconfAttr,
    OvpnKeydirAttr, OvpnPeerAttr,
};
use crate::macros::{GenlMessage, NetlinkAttrs};

// ============================================================
// Nested: OvpnKeydir
// ============================================================

/// Per-direction key material — one block for encrypt, one for
/// decrypt. Wire shape: nested attribute group inside
/// `OVPN_A_KEYCONF_ENCRYPT_DIR` / `OVPN_A_KEYCONF_DECRYPT_DIR`.
///
/// `cipher_key` length must be appropriate for the chosen cipher
/// (AES-128-GCM = 16 bytes, AES-256-GCM = 32, ChaCha20-Poly1305 = 32).
/// `nonce_tail` is always exactly 8 bytes (the AEAD IV is the
/// 4-byte packet ID concatenated with this 8-byte tail).
///
/// **Security note**: this struct holds raw cipher key material.
/// Callers are responsible for zeroing the bytes when no longer
/// needed — nlink does not enforce zero-on-drop.
#[derive(NetlinkAttrs, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OvpnKeydir {
    /// Cipher key bytes. See doc on the struct for the per-cipher
    /// length expectations.
    #[genl_attr(OvpnKeydirAttr::CipherKey)]
    pub cipher_key: Option<Vec<u8>>,
    /// 8-byte nonce tail.
    #[genl_attr(OvpnKeydirAttr::NonceTail)]
    pub nonce_tail: Option<Vec<u8>>,
}

impl std::fmt::Debug for OvpnKeydir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("OvpnKeydir")
            .field(
                "cipher_key",
                &self
                    .cipher_key
                    .as_ref()
                    .map(|k| crate::util::SecretBytes(k.as_ref())),
            )
            .field("nonce_tail", &self.nonce_tail)
            .finish()
    }
}

impl OvpnKeydir {
    /// Build a keydir from raw cipher key + nonce tail. The kernel
    /// rejects mismatched lengths against the chosen cipher.
    pub fn new(cipher_key: impl Into<Vec<u8>>, nonce_tail: impl Into<Vec<u8>>) -> Self {
        Self {
            cipher_key: Some(cipher_key.into()),
            nonce_tail: Some(nonce_tail.into()),
        }
    }
}

// ============================================================
// Nested: OvpnKeyconf (the keyconf block)
// ============================================================

/// Cipher-key configuration block. Wire shape: nested attribute
/// group inside `OVPN_A_KEYCONF`.
#[derive(NetlinkAttrs, Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OvpnKeyconf {
    /// Peer this key belongs to.
    #[genl_attr(OvpnKeyconfAttr::PeerId)]
    pub peer_id: Option<u32>,
    /// Slot — primary or secondary.
    #[genl_attr(OvpnKeyconfAttr::Slot, repr = "u32")]
    pub slot: Option<OvpnKeySlot>,
    /// 3-bit key ID embedded in the OpenVPN per-packet header.
    #[genl_attr(OvpnKeyconfAttr::KeyId)]
    pub key_id: Option<u32>,
    /// AEAD cipher algorithm.
    #[genl_attr(OvpnKeyconfAttr::CipherAlg, repr = "u32")]
    pub cipher_alg: Option<OvpnCipherAlg>,
    /// Key material for outgoing traffic.
    #[genl_attr(OvpnKeyconfAttr::EncryptDir, nested)]
    pub encrypt_dir: Option<OvpnKeydir>,
    /// Key material for incoming traffic.
    #[genl_attr(OvpnKeyconfAttr::DecryptDir, nested)]
    pub decrypt_dir: Option<OvpnKeydir>,
}

impl OvpnKeyconf {
    /// Construct a fully-specified keyconf — what `KEY_NEW` needs.
    pub fn new(
        peer_id: u32,
        slot: OvpnKeySlot,
        key_id: u32,
        cipher_alg: OvpnCipherAlg,
        encrypt_dir: OvpnKeydir,
        decrypt_dir: OvpnKeydir,
    ) -> Self {
        Self {
            peer_id: Some(peer_id),
            slot: Some(slot),
            key_id: Some(key_id),
            cipher_alg: Some(cipher_alg),
            encrypt_dir: Some(encrypt_dir),
            decrypt_dir: Some(decrypt_dir),
        }
    }

    /// Identity-only keyconf — used as the body of `KEY_GET` /
    /// `KEY_DEL` requests.
    pub fn identity(peer_id: u32, slot: OvpnKeySlot) -> Self {
        Self {
            peer_id: Some(peer_id),
            slot: Some(slot),
            ..Self::default()
        }
    }

    /// Identity-only keyconf for `KEY_SWAP` (only peer_id is
    /// required; the kernel swaps both slots atomically).
    pub fn swap_identity(peer_id: u32) -> Self {
        Self {
            peer_id: Some(peer_id),
            ..Self::default()
        }
    }
}

// ============================================================
// Nested: OvpnPeer (the peer block)
// ============================================================

/// Per-peer state block. Wire shape: nested attribute group
/// inside `OVPN_A_PEER`.
///
/// The byte-order-sensitive fields (`remote_ipv4`, `remote_port`,
/// `vpn_ipv4`, `local_ipv4`, `local_port`) are stored as raw
/// `Vec<u8>` payloads in network (big-endian) order. Use the
/// typed helpers on this struct ([`Self::remote_socket`],
/// [`Self::set_remote_v4`], [`Self::set_remote_v6`]) to convert
/// to/from `std::net` types.
#[derive(NetlinkAttrs, Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OvpnPeer {
    /// Userspace-assigned 3-byte peer ID (max 0xFFFFFF).
    #[genl_attr(OvpnPeerAttr::Id)]
    pub id: Option<u32>,
    /// Remote IPv4 address — 4 bytes, big-endian.
    #[genl_attr(OvpnPeerAttr::RemoteIpv4)]
    pub remote_ipv4: Option<Vec<u8>>,
    /// Remote IPv6 address — 16 bytes.
    #[genl_attr(OvpnPeerAttr::RemoteIpv6)]
    pub remote_ipv6: Option<Vec<u8>>,
    /// IPv6 scope ID (interface index) for link-local remotes.
    #[genl_attr(OvpnPeerAttr::RemoteIpv6ScopeId)]
    pub remote_ipv6_scope_id: Option<u32>,
    /// Remote UDP/TCP port — 2 bytes, big-endian.
    #[genl_attr(OvpnPeerAttr::RemotePort)]
    pub remote_port: Option<Vec<u8>>,
    /// Per-peer transport socket fd (`OVPN_A_PEER_SOCKET`). On
    /// `peer-new`/`peer-set` this is a file descriptor in the calling
    /// process, resolved by the kernel via `sockfd_lookup`; on a
    /// `peer-get` reply the kernel echoes back its own reference index.
    #[genl_attr(OvpnPeerAttr::Socket)]
    pub socket: Option<u32>,
    /// The netnsid of the socket's netns. `-1` (`!0u32`) means
    /// "same netns as the caller of `peer-new`".
    #[genl_attr(OvpnPeerAttr::SocketNetnsid)]
    pub socket_netnsid: Option<i32>,
    /// Tunnel-internal IPv4 address — 4 bytes, big-endian.
    #[genl_attr(OvpnPeerAttr::VpnIpv4)]
    pub vpn_ipv4: Option<Vec<u8>>,
    /// Tunnel-internal IPv6 address — 16 bytes.
    #[genl_attr(OvpnPeerAttr::VpnIpv6)]
    pub vpn_ipv6: Option<Vec<u8>>,
    /// Local IPv4 to send from (UDP, optional).
    #[genl_attr(OvpnPeerAttr::LocalIpv4)]
    pub local_ipv4: Option<Vec<u8>>,
    /// Local IPv6 to send from (UDP, optional).
    #[genl_attr(OvpnPeerAttr::LocalIpv6)]
    pub local_ipv6: Option<Vec<u8>>,
    /// Local port to send from — 2 bytes, big-endian.
    #[genl_attr(OvpnPeerAttr::LocalPort)]
    pub local_port: Option<Vec<u8>>,
    /// Seconds between outbound keep-alives.
    #[genl_attr(OvpnPeerAttr::KeepaliveInterval)]
    pub keepalive_interval: Option<u32>,
    /// Seconds of inbound silence before the peer is assumed dead.
    #[genl_attr(OvpnPeerAttr::KeepaliveTimeout)]
    pub keepalive_timeout: Option<u32>,
    /// Reason a peer was deleted — only set on the
    /// `peer-del-ntf` notification.
    #[genl_attr(OvpnPeerAttr::DelReason, repr = "u32")]
    pub del_reason: Option<OvpnDelPeerReason>,
    /// Read-only counter: VPN-layer RX bytes.
    #[genl_attr(OvpnPeerAttr::VpnRxBytes)]
    pub vpn_rx_bytes: Option<u64>,
    /// Read-only counter: VPN-layer TX bytes.
    #[genl_attr(OvpnPeerAttr::VpnTxBytes)]
    pub vpn_tx_bytes: Option<u64>,
    /// Read-only counter: VPN-layer RX packets.
    #[genl_attr(OvpnPeerAttr::VpnRxPackets)]
    pub vpn_rx_packets: Option<u64>,
    /// Read-only counter: VPN-layer TX packets.
    #[genl_attr(OvpnPeerAttr::VpnTxPackets)]
    pub vpn_tx_packets: Option<u64>,
    /// Read-only counter: transport-layer RX bytes.
    #[genl_attr(OvpnPeerAttr::LinkRxBytes)]
    pub link_rx_bytes: Option<u64>,
    /// Read-only counter: transport-layer TX bytes.
    #[genl_attr(OvpnPeerAttr::LinkTxBytes)]
    pub link_tx_bytes: Option<u64>,
    /// Read-only counter: transport-layer RX packets.
    #[genl_attr(OvpnPeerAttr::LinkRxPackets)]
    pub link_rx_packets: Option<u64>,
    /// Read-only counter: transport-layer TX packets.
    #[genl_attr(OvpnPeerAttr::LinkTxPackets)]
    pub link_tx_packets: Option<u64>,
    /// Peer-supplied TX ID (multipeer-to-multipeer mode).
    #[genl_attr(OvpnPeerAttr::TxId)]
    pub tx_id: Option<u32>,
}

impl OvpnPeer {
    /// Construct a peer identified only by `id` — used as the
    /// body of `peer-del` (peer ID is the only required field).
    pub fn identity(id: u32) -> Self {
        Self {
            id: Some(id),
            ..Self::default()
        }
    }
}

// ============================================================
// Top-level messages
// ============================================================

/// `peer-new` request — install a new peer on the ovpn interface.
///
/// The peer's UDP/TCP socket is passed as an SCM_RIGHTS auxiliary
/// control message alongside this netlink request; the
/// `peer.socket` field stays unset until the kernel echoes back
/// its socket index in the reply.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = OvpnCmd::PeerNew)]
pub struct OvpnPeerNewRequest {
    /// Target ovpn interface ifindex.
    #[genl_attr(OvpnAttr::Ifindex)]
    pub ifindex: u32,
    /// Peer state block.
    #[genl_attr(OvpnAttr::Peer, nested)]
    pub peer: Option<OvpnPeer>,
}

impl OvpnPeerNewRequest {
    /// Build a peer-new request.
    pub fn new(ifindex: u32, peer: OvpnPeer) -> Self {
        Self {
            ifindex,
            peer: Some(peer),
        }
    }
}

/// `peer-set` request — modify an existing peer.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = OvpnCmd::PeerSet)]
pub struct OvpnPeerSetRequest {
    /// Target ovpn interface ifindex.
    #[genl_attr(OvpnAttr::Ifindex)]
    pub ifindex: u32,
    /// Peer state block — only the `id` and the to-be-modified
    /// attributes need be set.
    #[genl_attr(OvpnAttr::Peer, nested)]
    pub peer: Option<OvpnPeer>,
}

impl OvpnPeerSetRequest {
    /// Build a peer-set request.
    pub fn new(ifindex: u32, peer: OvpnPeer) -> Self {
        Self {
            ifindex,
            peer: Some(peer),
        }
    }
}

/// `peer-get` request — single-peer query (do form) or full
/// dump (dump form, peer omitted).
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = OvpnCmd::PeerGet)]
pub struct OvpnPeerGetRequest {
    /// Target ovpn interface ifindex. Required.
    #[genl_attr(OvpnAttr::Ifindex)]
    pub ifindex: u32,
    /// Identity of the peer to query. `None` = dump every peer
    /// on the interface.
    #[genl_attr(OvpnAttr::Peer, nested)]
    pub peer: Option<OvpnPeer>,
}

impl OvpnPeerGetRequest {
    /// Single-peer get.
    pub fn by_id(ifindex: u32, peer_id: u32) -> Self {
        Self {
            ifindex,
            peer: Some(OvpnPeer::identity(peer_id)),
        }
    }

    /// Dump every peer on the interface.
    pub fn dump(ifindex: u32) -> Self {
        Self {
            ifindex,
            peer: None,
        }
    }
}

/// `peer-get` reply — a peer's full state. Also the per-frame
/// body emitted during a dump and on `peer-del-ntf` /
/// `peer-float-ntf`.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = OvpnCmd::PeerGet)]
#[non_exhaustive]
pub struct OvpnPeerReply {
    /// Interface ifindex echoing the request.
    #[genl_attr(OvpnAttr::Ifindex)]
    pub ifindex: u32,
    /// Peer state.
    #[genl_attr(OvpnAttr::Peer, nested)]
    pub peer: Option<OvpnPeer>,
}

/// `peer-del` request — remove a peer.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = OvpnCmd::PeerDel)]
pub struct OvpnPeerDelRequest {
    /// Target ovpn interface ifindex.
    #[genl_attr(OvpnAttr::Ifindex)]
    pub ifindex: u32,
    /// Identity of the peer to remove (peer_id only).
    #[genl_attr(OvpnAttr::Peer, nested)]
    pub peer: Option<OvpnPeer>,
}

impl OvpnPeerDelRequest {
    pub fn new(ifindex: u32, peer_id: u32) -> Self {
        Self {
            ifindex,
            peer: Some(OvpnPeer::identity(peer_id)),
        }
    }
}

/// `key-new` request — install a cipher key for a specific
/// (peer, slot).
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = OvpnCmd::KeyNew)]
pub struct OvpnKeyNewRequest {
    /// Target ovpn interface ifindex.
    #[genl_attr(OvpnAttr::Ifindex)]
    pub ifindex: u32,
    /// Full keyconf block.
    #[genl_attr(OvpnAttr::Keyconf, nested)]
    pub keyconf: Option<OvpnKeyconf>,
}

impl OvpnKeyNewRequest {
    pub fn new(ifindex: u32, keyconf: OvpnKeyconf) -> Self {
        Self {
            ifindex,
            keyconf: Some(keyconf),
        }
    }
}

/// `key-get` request — read back non-sensitive key metadata
/// (cipher alg, key id, slot). The key bytes themselves are
/// never returned to userspace.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = OvpnCmd::KeyGet)]
pub struct OvpnKeyGetRequest {
    /// Target ovpn interface ifindex.
    #[genl_attr(OvpnAttr::Ifindex)]
    pub ifindex: u32,
    /// Identity of the key (peer_id + slot).
    #[genl_attr(OvpnAttr::Keyconf, nested)]
    pub keyconf: Option<OvpnKeyconf>,
}

impl OvpnKeyGetRequest {
    pub fn new(ifindex: u32, peer_id: u32, slot: OvpnKeySlot) -> Self {
        Self {
            ifindex,
            keyconf: Some(OvpnKeyconf::identity(peer_id, slot)),
        }
    }
}

/// `key-get` reply — non-sensitive metadata about an installed
/// key. Also the per-frame body emitted on `key-swap-ntf`.
///
/// The reply never contains `encrypt_dir` / `decrypt_dir` —
/// installed key bytes are write-only.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = OvpnCmd::KeyGet)]
#[non_exhaustive]
pub struct OvpnKeyReply {
    /// Interface ifindex echoing the request.
    #[genl_attr(OvpnAttr::Ifindex)]
    pub ifindex: u32,
    /// Keyconf state.
    #[genl_attr(OvpnAttr::Keyconf, nested)]
    pub keyconf: Option<OvpnKeyconf>,
}

/// `key-swap` request — atomically promote secondary → primary
/// (and demote primary → secondary). Sent at OpenVPN's rekey
/// cutover point.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = OvpnCmd::KeySwap)]
pub struct OvpnKeySwapRequest {
    /// Target ovpn interface ifindex.
    #[genl_attr(OvpnAttr::Ifindex)]
    pub ifindex: u32,
    /// Peer identity (only `peer_id` is read).
    #[genl_attr(OvpnAttr::Keyconf, nested)]
    pub keyconf: Option<OvpnKeyconf>,
}

impl OvpnKeySwapRequest {
    pub fn new(ifindex: u32, peer_id: u32) -> Self {
        Self {
            ifindex,
            keyconf: Some(OvpnKeyconf::swap_identity(peer_id)),
        }
    }
}

/// `key-del` request — remove a cipher key from one (peer, slot).
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = OvpnCmd::KeyDel)]
pub struct OvpnKeyDelRequest {
    /// Target ovpn interface ifindex.
    #[genl_attr(OvpnAttr::Ifindex)]
    pub ifindex: u32,
    /// Key identity (peer_id + slot).
    #[genl_attr(OvpnAttr::Keyconf, nested)]
    pub keyconf: Option<OvpnKeyconf>,
}

impl OvpnKeyDelRequest {
    pub fn new(ifindex: u32, peer_id: u32, slot: OvpnKeySlot) -> Self {
        Self {
            ifindex,
            keyconf: Some(OvpnKeyconf::identity(peer_id, slot)),
        }
    }
}

// ============================================================
// IPv4 / port / IPv6 helpers — convert Vec<u8> ↔ std::net types
// ============================================================

/// Convenience helpers for the byte-order-sensitive peer fields.
///
/// Implemented as inherent methods on [`OvpnPeer`].
impl OvpnPeer {
    /// Encode an `Ipv4Addr` as 4 BE bytes for storage in any
    /// of the IPv4-valued peer fields.
    pub fn encode_ipv4(addr: std::net::Ipv4Addr) -> Vec<u8> {
        addr.octets().to_vec()
    }

    /// Decode 4 BE bytes back to an `Ipv4Addr`. Returns `None`
    /// when the slice has the wrong length.
    pub fn decode_ipv4(bytes: &[u8]) -> Option<std::net::Ipv4Addr> {
        if bytes.len() != 4 {
            return None;
        }
        Some(std::net::Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))
    }

    /// Encode an `Ipv6Addr` as its 16-byte big-endian octets.
    pub fn encode_ipv6(addr: std::net::Ipv6Addr) -> Vec<u8> {
        addr.octets().to_vec()
    }

    /// Decode 16 BE bytes back to an `Ipv6Addr`.
    pub fn decode_ipv6(bytes: &[u8]) -> Option<std::net::Ipv6Addr> {
        if bytes.len() != 16 {
            return None;
        }
        let mut octets = [0u8; 16];
        octets.copy_from_slice(bytes);
        Some(std::net::Ipv6Addr::from(octets))
    }

    /// Encode a u16 port as 2 BE bytes.
    pub fn encode_port(port: u16) -> Vec<u8> {
        port.to_be_bytes().to_vec()
    }

    /// Decode 2 BE bytes as a u16 port.
    pub fn decode_port(bytes: &[u8]) -> Option<u16> {
        if bytes.len() != 2 {
            return None;
        }
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Set both `remote_ipv4` and `remote_port` from a
    /// `SocketAddrV4`. The previous IPv6 remote (if any) is left
    /// untouched.
    pub fn set_remote_v4(&mut self, addr: std::net::SocketAddrV4) {
        self.remote_ipv4 = Some(Self::encode_ipv4(*addr.ip()));
        self.remote_port = Some(Self::encode_port(addr.port()));
    }

    /// Set both `remote_ipv6` and `remote_port` from a
    /// `SocketAddrV6`. Also writes `remote_ipv6_scope_id` from
    /// the address.
    pub fn set_remote_v6(&mut self, addr: std::net::SocketAddrV6) {
        self.remote_ipv6 = Some(Self::encode_ipv6(*addr.ip()));
        self.remote_port = Some(Self::encode_port(addr.port()));
        if addr.scope_id() != 0 {
            self.remote_ipv6_scope_id = Some(addr.scope_id());
        }
    }

    /// Best-effort decode of the remote endpoint into a
    /// `SocketAddr`. Returns `None` if neither v4 nor v6 fields
    /// are populated or if the port is missing/malformed.
    pub fn remote_socket(&self) -> Option<std::net::SocketAddr> {
        let port = self.remote_port.as_deref().and_then(Self::decode_port)?;
        if let Some(v4) = self.remote_ipv4.as_deref().and_then(Self::decode_ipv4) {
            return Some(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                v4, port,
            )));
        }
        if let Some(v6) = self.remote_ipv6.as_deref().and_then(Self::decode_ipv6) {
            let scope = self.remote_ipv6_scope_id.unwrap_or(0);
            return Some(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                v6, port, 0, scope,
            )));
        }
        None
    }

    /// The peer's **local** source endpoint, decoded from
    /// `local_ipv4`/`local_ipv6` + `local_port`.
    ///
    /// Mirrors [`remote_socket`](Self::remote_socket). It did not
    /// exist, which is why `peer_matches` could not compare `local`
    /// even though the config stores it, `apply` encodes it on create,
    /// and the dump reads it back — so changing it was a silent no-op
    /// and `apply_reconcile` reported successful convergence (#281).
    pub fn local_socket(&self) -> Option<std::net::SocketAddr> {
        let port = self.local_port.as_deref().and_then(Self::decode_port)?;
        if let Some(v4) = self.local_ipv4.as_deref().and_then(Self::decode_ipv4) {
            return Some(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                v4, port,
            )));
        }
        if let Some(v6) = self.local_ipv6.as_deref().and_then(Self::decode_ipv6) {
            return Some(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                v6, port, 0, 0,
            )));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        macros::{__rt, NetlinkAttrs},
        netlink::MessageBuilder,
    };

    fn body(write: impl FnOnce(&mut MessageBuilder)) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        write(&mut b);
        b.as_bytes()[start..].to_vec()
    }

    #[test]
    fn keydir_round_trips() {
        let original = OvpnKeydir::new([0x11; 32], [0x22; 8]);
        let body = body(|b| original.write_attrs(b).unwrap());
        let parsed = OvpnKeydir::read_attrs(&body).expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn keyconf_round_trips_full() {
        let original = OvpnKeyconf::new(
            42,
            OvpnKeySlot::Primary,
            3,
            OvpnCipherAlg::AesGcm,
            OvpnKeydir::new(vec![1; 32], vec![2; 8]),
            OvpnKeydir::new(vec![3; 32], vec![4; 8]),
        );
        let body = body(|b| original.write_attrs(b).unwrap());
        let parsed = OvpnKeyconf::read_attrs(&body).expect("parse");
        assert_eq!(parsed.peer_id, Some(42));
        assert_eq!(parsed.slot, Some(OvpnKeySlot::Primary));
        assert_eq!(parsed.key_id, Some(3));
        assert_eq!(parsed.cipher_alg, Some(OvpnCipherAlg::AesGcm));
        assert_eq!(parsed.encrypt_dir, original.encrypt_dir);
        assert_eq!(parsed.decrypt_dir, original.decrypt_dir);
    }

    #[test]
    fn keyconf_identity_only_emits_peer_and_slot() {
        let original = OvpnKeyconf::identity(7, OvpnKeySlot::Secondary);
        let body = body(|b| original.write_attrs(b).unwrap());
        let attrs: Vec<u16> = __rt::attr_iter(&body).map(|(t, _)| t).collect();
        assert_eq!(
            attrs,
            vec![OvpnKeyconfAttr::PeerId as u16, OvpnKeyconfAttr::Slot as u16,]
        );
    }

    #[test]
    fn peer_identity_emits_only_id() {
        let peer = OvpnPeer::identity(99);
        let body = body(|b| peer.write_attrs(b).unwrap());
        let attrs: Vec<u16> = __rt::attr_iter(&body).map(|(t, _)| t).collect();
        assert_eq!(attrs, vec![OvpnPeerAttr::Id as u16]);
    }

    #[test]
    fn ipv4_encode_decode_round_trips() {
        let addr = std::net::Ipv4Addr::new(10, 0, 0, 99);
        let bytes = OvpnPeer::encode_ipv4(addr);
        assert_eq!(bytes, vec![10, 0, 0, 99]);
        assert_eq!(OvpnPeer::decode_ipv4(&bytes), Some(addr));
        assert_eq!(OvpnPeer::decode_ipv4(&[1, 2, 3]), None);
    }

    #[test]
    fn ipv6_encode_decode_round_trips() {
        let addr: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
        let bytes = OvpnPeer::encode_ipv6(addr);
        assert_eq!(bytes.len(), 16);
        assert_eq!(OvpnPeer::decode_ipv6(&bytes), Some(addr));
        assert_eq!(OvpnPeer::decode_ipv6(&[0; 4]), None);
    }

    #[test]
    fn port_encode_decode_is_big_endian() {
        let bytes = OvpnPeer::encode_port(1194);
        // 1194 = 0x04AA → BE bytes [0x04, 0xAA]
        assert_eq!(bytes, vec![0x04, 0xAA]);
        assert_eq!(OvpnPeer::decode_port(&bytes), Some(1194));
        assert_eq!(OvpnPeer::decode_port(&[1, 2, 3]), None);
    }

    #[test]
    fn set_remote_v4_populates_both_fields() {
        let mut peer = OvpnPeer::identity(1);
        peer.set_remote_v4("10.0.0.1:1194".parse().unwrap());
        let sock = peer.remote_socket().expect("decode");
        assert_eq!(sock, "10.0.0.1:1194".parse().unwrap());
    }

    #[test]
    fn set_remote_v6_populates_address_and_port() {
        let mut peer = OvpnPeer::identity(2);
        peer.set_remote_v6("[2001:db8::1]:1194".parse().unwrap());
        let sock = peer.remote_socket().expect("decode");
        assert_eq!(sock, "[2001:db8::1]:1194".parse().unwrap());
    }

    #[test]
    fn peer_new_request_emits_ifindex_and_nested_peer() {
        let req = OvpnPeerNewRequest::new(7, OvpnPeer::identity(42));
        let body = body(|b| req.to_bytes(b).unwrap());
        let attrs: Vec<u16> = __rt::attr_iter(&body).map(|(t, _)| t).collect();
        assert_eq!(attrs, vec![OvpnAttr::Ifindex as u16, OvpnAttr::Peer as u16]);
    }

    #[test]
    fn peer_get_dump_omits_peer_nest() {
        let req = OvpnPeerGetRequest::dump(7);
        let body = body(|b| req.to_bytes(b).unwrap());
        let attrs: Vec<u16> = __rt::attr_iter(&body).map(|(t, _)| t).collect();
        assert_eq!(attrs, vec![OvpnAttr::Ifindex as u16]);
    }

    #[test]
    fn peer_get_by_id_emits_peer_nest() {
        let req = OvpnPeerGetRequest::by_id(3, 99);
        let body = body(|b| req.to_bytes(b).unwrap());
        let attrs: Vec<u16> = __rt::attr_iter(&body).map(|(t, _)| t).collect();
        assert_eq!(attrs, vec![OvpnAttr::Ifindex as u16, OvpnAttr::Peer as u16]);
    }

    #[test]
    fn peer_socket_and_netnsid_round_trip() {
        // `Connection::<Ovpn>::attach_socket` / `attach_socket_in_netns`
        // set exactly these two fields on an identity peer and send a
        // `peer-set`. Verify they survive the wire round-trip so the
        // kernel actually receives `OVPN_A_PEER_SOCKET` (+ `_NETNSID`).
        let mut peer = OvpnPeer::identity(21);
        peer.socket = Some(42);
        peer.socket_netnsid = Some(3);
        let original = OvpnPeerReply {
            ifindex: 9,
            peer: Some(peer),
        };
        let body = body(|b| original.to_bytes(b).unwrap());
        let parsed = OvpnPeerReply::from_bytes(&body).expect("parse");
        let p = parsed.peer.expect("peer present");
        assert_eq!(p.id, Some(21));
        assert_eq!(p.socket, Some(42));
        assert_eq!(p.socket_netnsid, Some(3));
    }

    #[test]
    fn peer_reply_round_trips_counters() {
        let mut peer = OvpnPeer::identity(5);
        peer.vpn_rx_bytes = Some(1_000_000);
        peer.link_tx_packets = Some(50);
        peer.set_remote_v4("192.168.1.50:1194".parse().unwrap());
        let original = OvpnPeerReply {
            ifindex: 7,
            peer: Some(peer.clone()),
        };
        let body = body(|b| original.to_bytes(b).unwrap());
        let parsed = OvpnPeerReply::from_bytes(&body).expect("parse");
        assert_eq!(parsed.ifindex, 7);
        let parsed_peer = parsed.peer.expect("peer present");
        assert_eq!(parsed_peer.id, Some(5));
        assert_eq!(parsed_peer.vpn_rx_bytes, Some(1_000_000));
        assert_eq!(parsed_peer.link_tx_packets, Some(50));
        assert_eq!(
            parsed_peer.remote_socket(),
            Some("192.168.1.50:1194".parse().unwrap())
        );
    }

    #[test]
    fn key_swap_request_only_emits_peer_id_inside_keyconf() {
        let req = OvpnKeySwapRequest::new(11, 42);
        let outer_body = body(|b| req.to_bytes(b).unwrap());
        // Outer: ifindex + keyconf
        let outer: Vec<u16> = __rt::attr_iter(&outer_body).map(|(t, _)| t).collect();
        assert_eq!(
            outer,
            vec![OvpnAttr::Ifindex as u16, OvpnAttr::Keyconf as u16]
        );
        // Pull the nested keyconf bytes and check the inner attrs.
        for (ty, payload) in __rt::attr_iter(&outer_body) {
            if ty == OvpnAttr::Keyconf as u16 {
                let inner: Vec<u16> = __rt::attr_iter(payload).map(|(t, _)| t).collect();
                assert_eq!(inner, vec![OvpnKeyconfAttr::PeerId as u16]);
            }
        }
    }

    #[test]
    fn key_del_request_emits_peer_id_and_slot() {
        let req = OvpnKeyDelRequest::new(11, 42, OvpnKeySlot::Secondary);
        let outer_body = body(|b| req.to_bytes(b).unwrap());
        for (ty, payload) in __rt::attr_iter(&outer_body) {
            if ty == OvpnAttr::Keyconf as u16 {
                let inner: Vec<u16> = __rt::attr_iter(payload).map(|(t, _)| t).collect();
                assert_eq!(
                    inner,
                    vec![OvpnKeyconfAttr::PeerId as u16, OvpnKeyconfAttr::Slot as u16]
                );
            }
        }
    }
}
