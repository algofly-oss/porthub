//! OVPN command + attribute + value enums.
//!
//! Direct translation of the kernel UAPI for OpenVPN data-channel
//! offload (kernel 6.16+), per
//! `Documentation/netlink/specs/ovpn.yaml`.
//!
//! Wire shape:
//! - 8 GENL commands (peer / key add/get/set/del/swap) and 3
//!   multicast notifications (`peer-del-ntf`, `key-swap-ntf`,
//!   `peer-float-ntf`) on the `peers` mcast group.
//! - Top-level message attributes ([`OvpnAttr`]) carry the ifindex
//!   plus one of the nested-group attributes ([`OvpnAttr::Peer`] or
//!   [`OvpnAttr::Keyconf`]).
//! - The nested peer block uses [`OvpnPeerAttr`].
//! - The nested keyconf block uses [`OvpnKeyconfAttr`], and itself
//!   contains two nested keydir blocks ([`OvpnKeydirAttr`]) for the
//!   encrypt + decrypt directions.

use crate::macros::{GenlAttribute, GenlCommand, GenlEnum};

/// Constant pulled from the YAML spec — every per-key
/// `nonce_tail` is exactly 8 bytes (AES-GCM IV construction).
pub const OVPN_NONCE_TAIL_SIZE: usize = 8;

/// Maximum cipher-key length the kernel accepts on `OVPN_A_KEYDIR_CIPHER_KEY`.
/// AES-256-GCM uses 32; ChaCha20-Poly1305 uses 32; smaller for
/// AES-128-GCM. 256 is the kernel's upper bound from `max-len: 256`.
pub const OVPN_MAX_CIPHER_KEY_LEN: usize = 256;

/// Maximum peer ID — the kernel checks `max: 0xFFFFFF`. Peer IDs
/// are userspace-assigned; matches OpenVPN 2.7's wire-format
/// 3-byte peer ID field.
pub const OVPN_MAX_PEER_ID: u32 = 0x00FF_FFFF;

/// Maximum key ID — the kernel checks `max: 7` (3-bit field in the
/// OpenVPN wire header).
pub const OVPN_MAX_KEY_ID: u32 = 7;

// ============================================================
// Commands
// ============================================================

/// OVPN GENL command codes.
///
/// Wire: `u8`. The YAML spec doesn't pin numeric values explicitly
/// (the list ordering is the implicit numbering, starting at 1
/// after the unspec slot).
#[derive(GenlCommand, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_command(repr = "u8")]
#[non_exhaustive]
pub enum OvpnCmd {
    /// Add a remote peer to an ovpn interface.
    PeerNew = 1,
    /// Modify an existing remote peer.
    PeerSet = 2,
    /// Retrieve a single peer's state (do) or every peer on
    /// the interface (dump).
    PeerGet = 3,
    /// Delete an existing remote peer.
    PeerDel = 4,
    /// Multicast notification: a peer was deleted.
    PeerDelNtf = 5,
    /// Install a cipher key for a specific peer + slot.
    KeyNew = 6,
    /// Retrieve non-sensitive metadata about an installed key.
    KeyGet = 7,
    /// Atomically swap the primary and secondary slot for a peer.
    KeySwap = 8,
    /// Multicast notification: a key's IV space is exhausted
    /// (renegotiation hint).
    KeySwapNtf = 9,
    /// Delete a cipher key from a peer slot.
    KeyDel = 10,
    /// Multicast notification: a peer's remote endpoint changed
    /// (NAT rebind / mobility).
    PeerFloatNtf = 11,
}

// ============================================================
// Top-level message attributes
// ============================================================

/// Top-level attributes carried inside an OVPN GENL message.
///
/// Wire: `u16`. From the `ovpn` attribute-set in the YAML spec.
#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
#[non_exhaustive]
pub enum OvpnAttr {
    /// `OVPN_A_IFINDEX` — kernel ifindex of the ovpn interface
    /// to operate on. Required on every request.
    Ifindex = 1,
    /// `OVPN_A_PEER` — nested attribute group describing a peer
    /// (see [`OvpnPeerAttr`]).
    Peer = 2,
    /// `OVPN_A_KEYCONF` — nested attribute group describing a
    /// cipher-key configuration (see [`OvpnKeyconfAttr`]).
    Keyconf = 3,
}

// ============================================================
// Nested peer attributes
// ============================================================

/// Per-peer attribute kinds. Nested inside `OVPN_A_PEER`.
///
/// Wire: `u16`.
#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
#[non_exhaustive]
pub enum OvpnPeerAttr {
    /// `OVPN_A_PEER_ID` — userspace-assigned u32 (max 0xFFFFFF).
    Id = 1,
    /// `OVPN_A_PEER_REMOTE_IPV4` — big-endian u32 (network order).
    RemoteIpv4 = 2,
    /// `OVPN_A_PEER_REMOTE_IPV6` — 16-byte binary.
    RemoteIpv6 = 3,
    /// `OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID` — u32 scope ID
    /// (`sin6_scope_id`).
    RemoteIpv6ScopeId = 4,
    /// `OVPN_A_PEER_REMOTE_PORT` — big-endian u16 (network order).
    RemotePort = 5,
    /// `OVPN_A_PEER_SOCKET` — the UDP/TCP socket fd the kernel
    /// should use for this peer. Passed alongside SCM_RIGHTS in
    /// the auxiliary control message.
    Socket = 6,
    /// `OVPN_A_PEER_SOCKET_NETNSID` — netnsid of the socket's
    /// netns (s32; signed because -1 = "same as caller").
    SocketNetnsid = 7,
    /// `OVPN_A_PEER_VPN_IPV4` — IPv4 inside the tunnel (BE u32).
    VpnIpv4 = 8,
    /// `OVPN_A_PEER_VPN_IPV6` — 16-byte tunnel IPv6.
    VpnIpv6 = 9,
    /// `OVPN_A_PEER_LOCAL_IPV4` — BE u32, UDP only.
    LocalIpv4 = 10,
    /// `OVPN_A_PEER_LOCAL_IPV6` — 16-byte, UDP only.
    LocalIpv6 = 11,
    /// `OVPN_A_PEER_LOCAL_PORT` — BE u16, UDP only.
    LocalPort = 12,
    /// `OVPN_A_PEER_KEEPALIVE_INTERVAL` — seconds between
    /// keep-alives we send.
    KeepaliveInterval = 13,
    /// `OVPN_A_PEER_KEEPALIVE_TIMEOUT` — seconds of silence
    /// before the peer is assumed dead.
    KeepaliveTimeout = 14,
    /// `OVPN_A_PEER_DEL_REASON` — only on notifications, carries
    /// [`OvpnDelPeerReason`].
    DelReason = 15,
    /// `OVPN_A_PEER_VPN_RX_BYTES` — read-only counter.
    VpnRxBytes = 16,
    /// `OVPN_A_PEER_VPN_TX_BYTES` — read-only counter.
    VpnTxBytes = 17,
    /// `OVPN_A_PEER_VPN_RX_PACKETS` — read-only counter.
    VpnRxPackets = 18,
    /// `OVPN_A_PEER_VPN_TX_PACKETS` — read-only counter.
    VpnTxPackets = 19,
    /// `OVPN_A_PEER_LINK_RX_BYTES` — read-only counter.
    LinkRxBytes = 20,
    /// `OVPN_A_PEER_LINK_TX_BYTES` — read-only counter.
    LinkTxBytes = 21,
    /// `OVPN_A_PEER_LINK_RX_PACKETS` — read-only counter.
    LinkRxPackets = 22,
    /// `OVPN_A_PEER_LINK_TX_PACKETS` — read-only counter.
    LinkTxPackets = 23,
    /// `OVPN_A_PEER_TX_ID` — peer-supplied 3-byte ID to use on
    /// outgoing packets (multipeer-to-multipeer).
    TxId = 24,
}

// ============================================================
// Nested keyconf attributes
// ============================================================

/// Per-cipher-key attribute kinds. Nested inside `OVPN_A_KEYCONF`.
///
/// Wire: `u16`.
#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
#[non_exhaustive]
pub enum OvpnKeyconfAttr {
    /// `OVPN_A_KEYCONF_PEER_ID` — which peer this key belongs to.
    PeerId = 1,
    /// `OVPN_A_KEYCONF_SLOT` — primary or secondary; see
    /// [`OvpnKeySlot`].
    Slot = 2,
    /// `OVPN_A_KEYCONF_KEY_ID` — 3-bit key ID embedded in the
    /// per-packet OpenVPN header.
    KeyId = 3,
    /// `OVPN_A_KEYCONF_CIPHER_ALG` — cipher algorithm
    /// ([`OvpnCipherAlg`]).
    CipherAlg = 4,
    /// `OVPN_A_KEYCONF_ENCRYPT_DIR` — nested keydir block for
    /// encrypting outgoing traffic.
    EncryptDir = 5,
    /// `OVPN_A_KEYCONF_DECRYPT_DIR` — nested keydir block for
    /// decrypting incoming traffic.
    DecryptDir = 6,
}

// ============================================================
// Nested keydir attributes
// ============================================================

/// Inner per-direction key material attributes. Nested inside
/// either `OVPN_A_KEYCONF_ENCRYPT_DIR` or `OVPN_A_KEYCONF_DECRYPT_DIR`.
///
/// Wire: `u16`.
#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
#[non_exhaustive]
pub enum OvpnKeydirAttr {
    /// `OVPN_A_KEYDIR_CIPHER_KEY` — raw cipher key bytes
    /// (≤ [`OVPN_MAX_CIPHER_KEY_LEN`] = 256).
    CipherKey = 1,
    /// `OVPN_A_KEYDIR_NONCE_TAIL` — 8-byte nonce tail (mixed
    /// with the per-packet ID to form the AEAD IV).
    NonceTail = 2,
}

// ============================================================
// Value enums
// ============================================================

/// AEAD cipher algorithm.
///
/// Wire: `u32`. The `None` variant corresponds to the YAML spec's
/// `none` entry — used by callers who want to install a peer
/// without an active cipher (rare; mostly a placeholder slot for
/// the kernel state machine).
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum OvpnCipherAlg {
    /// `OVPN_CIPHER_ALG_NONE` — no cipher; data-channel is plain.
    None = 0,
    /// `OVPN_CIPHER_ALG_AES_GCM`.
    AesGcm = 1,
    /// `OVPN_CIPHER_ALG_CHACHA20_POLY1305`.
    Chacha20Poly1305 = 2,
}

/// Cipher-key slot — OpenVPN keeps one primary + one secondary
/// installed at any time so rekeying can race the cutover.
///
/// Wire: `u32`.
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum OvpnKeySlot {
    /// `OVPN_KEY_SLOT_PRIMARY` — currently-active key for both
    /// encrypt + decrypt.
    Primary = 0,
    /// `OVPN_KEY_SLOT_SECONDARY` — staged key; `key_swap` makes
    /// it primary.
    Secondary = 1,
}

/// Reason a peer was deleted, carried on the `peer-del-ntf`
/// multicast notification.
///
/// Wire: `u32`.
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum OvpnDelPeerReason {
    /// `OVPN_DEL_PEER_REASON_TEARDOWN` — interface going down.
    Teardown = 0,
    /// `OVPN_DEL_PEER_REASON_USERSPACE` — explicit user request
    /// (`peer-del` from userspace).
    Userspace = 1,
    /// `OVPN_DEL_PEER_REASON_EXPIRED` — keepalive timeout
    /// elapsed.
    Expired = 2,
    /// `OVPN_DEL_PEER_REASON_TRANSPORT_ERROR` — UDP/TCP error.
    TransportError = 3,
    /// `OVPN_DEL_PEER_REASON_TRANSPORT_DISCONNECT` — TCP socket
    /// disconnect (client mode).
    TransportDisconnect = 4,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_codec_round_trips_every_variant() {
        for (variant, expected) in [
            (OvpnCmd::PeerNew, 1u8),
            (OvpnCmd::PeerSet, 2),
            (OvpnCmd::PeerGet, 3),
            (OvpnCmd::PeerDel, 4),
            (OvpnCmd::PeerDelNtf, 5),
            (OvpnCmd::KeyNew, 6),
            (OvpnCmd::KeyGet, 7),
            (OvpnCmd::KeySwap, 8),
            (OvpnCmd::KeySwapNtf, 9),
            (OvpnCmd::KeyDel, 10),
            (OvpnCmd::PeerFloatNtf, 11),
        ] {
            let raw: u8 = variant.into();
            assert_eq!(raw, expected, "OvpnCmd → u8 mismatch");
            let back: OvpnCmd = OvpnCmd::try_from(raw).expect("roundtrip");
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn command_codec_rejects_unknown_value() {
        let err = OvpnCmd::try_from(99u8).unwrap_err();
        assert!(format!("{err}").contains("99"));
    }

    #[test]
    fn top_level_attr_codec_round_trips() {
        for (v, expected) in [
            (OvpnAttr::Ifindex, 1u16),
            (OvpnAttr::Peer, 2),
            (OvpnAttr::Keyconf, 3),
        ] {
            assert_eq!(u16::from(v), expected);
            assert_eq!(OvpnAttr::try_from(expected).unwrap(), v);
        }
    }

    #[test]
    fn peer_attr_codec_round_trips_low_mid_high() {
        for (v, expected) in [
            (OvpnPeerAttr::Id, 1u16),
            (OvpnPeerAttr::KeepaliveInterval, 13),
            (OvpnPeerAttr::TxId, 24),
        ] {
            assert_eq!(u16::from(v), expected);
            assert_eq!(OvpnPeerAttr::try_from(expected).unwrap(), v);
        }
    }

    #[test]
    fn keyconf_attr_codec_round_trips() {
        for (v, expected) in [
            (OvpnKeyconfAttr::PeerId, 1u16),
            (OvpnKeyconfAttr::CipherAlg, 4),
            (OvpnKeyconfAttr::DecryptDir, 6),
        ] {
            assert_eq!(u16::from(v), expected);
            assert_eq!(OvpnKeyconfAttr::try_from(expected).unwrap(), v);
        }
    }

    #[test]
    fn keydir_attr_codec_round_trips() {
        for (v, expected) in [
            (OvpnKeydirAttr::CipherKey, 1u16),
            (OvpnKeydirAttr::NonceTail, 2),
        ] {
            assert_eq!(u16::from(v), expected);
            assert_eq!(OvpnKeydirAttr::try_from(expected).unwrap(), v);
        }
    }

    #[test]
    fn value_enums_round_trip() {
        macro_rules! check {
            ($enum:ty, $variant:expr, $expected:expr) => {{
                let v: $enum = $variant;
                let raw: u32 = v.into();
                assert_eq!(raw, $expected);
                assert_eq!(<$enum>::try_from(raw).unwrap(), v);
            }};
        }
        check!(OvpnCipherAlg, OvpnCipherAlg::None, 0);
        check!(OvpnCipherAlg, OvpnCipherAlg::AesGcm, 1);
        check!(OvpnCipherAlg, OvpnCipherAlg::Chacha20Poly1305, 2);
        check!(OvpnKeySlot, OvpnKeySlot::Primary, 0);
        check!(OvpnKeySlot, OvpnKeySlot::Secondary, 1);
        check!(OvpnDelPeerReason, OvpnDelPeerReason::Teardown, 0);
        check!(OvpnDelPeerReason, OvpnDelPeerReason::TransportDisconnect, 4);
    }

    #[test]
    fn constants_match_kernel_caps() {
        // From the YAML spec — guards against accidental drift.
        assert_eq!(OVPN_NONCE_TAIL_SIZE, 8);
        assert_eq!(OVPN_MAX_CIPHER_KEY_LEN, 256);
        assert_eq!(OVPN_MAX_PEER_ID, 0xFF_FFFF);
        assert_eq!(OVPN_MAX_KEY_ID, 7);
    }
}
