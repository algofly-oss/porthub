//! MACsec (IEEE 802.1AE) kernel constants.
//!
//! This module provides constants for MACsec Generic Netlink operations.
//!
//! Transcribed from `include/uapi/linux/if_macsec.h` and checked against it on
//! every build: `scripts/audit-uapi-constants.modmap` maps each module here to
//! its kernel prefix, so a wrong value — or an attribute the kernel has never
//! defined — fails CI rather than shipping. The pre-0.26 version of this file
//! contained both (#260).

/// MACsec GENL commands (`MACSEC_CMD_*`).
///
/// There are no `GET_RXSC` / `GET_TXSA` / `GET_RXSA` commands; the kernel
/// exposes a single `GET_TXSC` dump that carries the whole device tree.
pub mod macsec_cmd {
    /// Dump TX SC information (the only read command; carries RX SCs and SAs).
    pub const GET_TXSC: u8 = 0;
    /// Add an RX SC.
    pub const ADD_RXSC: u8 = 1;
    /// Delete an RX SC.
    pub const DEL_RXSC: u8 = 2;
    /// Update an RX SC.
    pub const UPD_RXSC: u8 = 3;
    /// Add a TX SA.
    pub const ADD_TXSA: u8 = 4;
    /// Delete a TX SA.
    pub const DEL_TXSA: u8 = 5;
    /// Update a TX SA.
    pub const UPD_TXSA: u8 = 6;
    /// Add an RX SA.
    pub const ADD_RXSA: u8 = 7;
    /// Delete an RX SA.
    pub const DEL_RXSA: u8 = 8;
    /// Update an RX SA.
    pub const UPD_RXSA: u8 = 9;
    /// Update the offload setting.
    pub const UPD_OFFLOAD: u8 = 10;
}

/// Top-level MACsec attributes (`MACSEC_ATTR_*`).
pub mod macsec_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Interface index (u32).
    pub const IFINDEX: u16 = 1;
    /// RX SC configuration (nested `macsec_rxsc_attr`).
    pub const RXSC_CONFIG: u16 = 2;
    /// SA configuration (nested `macsec_sa_attr`).
    pub const SA_CONFIG: u16 = 3;
    /// SecY configuration, dump only (nested `macsec_secy_attr`).
    pub const SECY: u16 = 4;
    /// TX SA list, dump only (nested `macsec_sa_attr` per SA).
    pub const TXSA_LIST: u16 = 5;
    /// RX SC list, dump only (nested `macsec_rxsc_attr` per SC).
    pub const RXSC_LIST: u16 = 6;
    /// TX SC statistics, dump only (nested `macsec_txsc_stats_attr`).
    pub const TXSC_STATS: u16 = 7;
    /// SecY statistics, dump only (nested `macsec_secy_stats_attr`).
    pub const SECY_STATS: u16 = 8;
    /// Offload configuration (nested `macsec_offload_attr`).
    pub const OFFLOAD: u16 = 9;
}

/// RX SC configuration attributes (`MACSEC_RXSC_ATTR_*`).
pub mod macsec_rxsc_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Secure Channel Identifier (u64).
    pub const SCI: u16 = 1;
    /// Whether the RX SC is active (u8).
    pub const ACTIVE: u16 = 2;
    /// SA list, dump only (nested).
    pub const SA_LIST: u16 = 3;
    /// Statistics, dump only (nested).
    pub const STATS: u16 = 4;
    /// Netlink alignment padding.
    pub const PAD: u16 = 5;
}

/// SA configuration attributes (`MACSEC_SA_ATTR_*`).
pub mod macsec_sa_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Association Number, 0..=3 (u8).
    pub const AN: u16 = 1;
    /// Whether the SA is active (u8).
    pub const ACTIVE: u16 = 2;
    /// Packet number (u32, or u64 with XPN).
    pub const PN: u16 = 3;
    /// The key itself (binary; config only, never dumped).
    pub const KEY: u16 = 4;
    /// Key identifier (binary, up to `MACSEC_KEYID_LEN`).
    pub const KEYID: u16 = 5;
    /// Statistics, dump only (nested).
    pub const STATS: u16 = 6;
    /// Netlink alignment padding.
    pub const PAD: u16 = 7;
    /// Short Secure Channel Identifier, XPN only (u32).
    pub const SSCI: u16 = 8;
    /// Salt, XPN only (binary, `MACSEC_SALT_LEN`).
    pub const SALT: u16 = 9;
}

/// SecY configuration attributes (`MACSEC_SECY_ATTR_*`).
pub mod macsec_secy_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Secure Channel Identifier (u64).
    pub const SCI: u16 = 1;
    /// Encoding SA (u8).
    pub const ENCODING_SA: u16 = 2;
    /// Replay window size (u32).
    pub const WINDOW: u16 = 3;
    /// Cipher suite id (u64) — see [`super::macsec_cipher`].
    pub const CIPHER_SUITE: u16 = 4;
    /// ICV length (u8).
    pub const ICV_LEN: u16 = 5;
    /// Protect frames (u8).
    pub const PROTECT: u16 = 6;
    /// Replay protection enabled (u8).
    pub const REPLAY: u16 = 7;
    /// Operational state (u8).
    pub const OPER: u16 = 8;
    /// Validation mode (u8) — see [`super::macsec_validate`].
    pub const VALIDATE: u16 = 9;
    /// Encrypt frames (u8).
    pub const ENCRYPT: u16 = 10;
    /// Include SCI in the SecTAG (u8).
    pub const INC_SCI: u16 = 11;
    /// End station bit (u8).
    pub const ES: u16 = 12;
    /// Single copy broadcast (u8).
    pub const SCB: u16 = 13;
    /// Netlink alignment padding.
    pub const PAD: u16 = 14;
}

/// SecY statistics (`MACSEC_SECY_STATS_ATTR_*`).
pub mod macsec_secy_stats_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Transmitted untagged packets.
    pub const OUT_PKTS_UNTAGGED: u16 = 1;
    /// Received untagged packets.
    pub const IN_PKTS_UNTAGGED: u16 = 2;
    /// Transmitted packets that were too long.
    pub const OUT_PKTS_TOO_LONG: u16 = 3;
    /// Received packets with no SecTAG.
    pub const IN_PKTS_NO_TAG: u16 = 4;
    /// Received packets with a bad SecTAG.
    pub const IN_PKTS_BAD_TAG: u16 = 5;
    /// Received packets for an unknown SCI.
    pub const IN_PKTS_UNKNOWN_SCI: u16 = 6;
    /// Received packets with no SCI.
    pub const IN_PKTS_NO_SCI: u16 = 7;
    /// Received packets dropped by overrun.
    pub const IN_PKTS_OVERRUN: u16 = 8;
    /// Netlink alignment padding.
    pub const PAD: u16 = 9;
}

/// TX SC statistics (`MACSEC_TXSC_STATS_ATTR_*`).
pub mod macsec_txsc_stats_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Protected packets transmitted.
    pub const OUT_PKTS_PROTECTED: u16 = 1;
    /// Encrypted packets transmitted.
    pub const OUT_PKTS_ENCRYPTED: u16 = 2;
    /// Protected octets transmitted.
    pub const OUT_OCTETS_PROTECTED: u16 = 3;
    /// Encrypted octets transmitted.
    pub const OUT_OCTETS_ENCRYPTED: u16 = 4;
    /// Netlink alignment padding.
    pub const PAD: u16 = 5;
}

/// RX SC statistics (`MACSEC_RXSC_STATS_ATTR_*`).
pub mod macsec_rxsc_stats_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Validated octets received.
    pub const IN_OCTETS_VALIDATED: u16 = 1;
    /// Decrypted octets received.
    pub const IN_OCTETS_DECRYPTED: u16 = 2;
    /// Unchecked packets received.
    pub const IN_PKTS_UNCHECKED: u16 = 3;
    /// Delayed packets received.
    pub const IN_PKTS_DELAYED: u16 = 4;
    /// Valid packets received.
    pub const IN_PKTS_OK: u16 = 5;
    /// Invalid packets received.
    pub const IN_PKTS_INVALID: u16 = 6;
    /// Late packets received.
    pub const IN_PKTS_LATE: u16 = 7;
    /// Packets received that failed validation.
    pub const IN_PKTS_NOT_VALID: u16 = 8;
    /// Packets received for an SA that is not in use.
    pub const IN_PKTS_NOT_USING_SA: u16 = 9;
    /// Packets received on an unused SA.
    pub const IN_PKTS_UNUSED_SA: u16 = 10;
    /// Netlink alignment padding.
    pub const PAD: u16 = 11;
}

/// Per-SA statistics (`MACSEC_SA_STATS_ATTR_*`).
///
/// Note the ordering: the `IN_*` counters come first and the two `OUT_*`
/// counters are 6 and 7. A transcription that put `OUT_PKTS_PROTECTED` at 1
/// reported the RX "valid packets" counter as a TX counter (#260).
pub mod macsec_sa_stats_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Valid packets received.
    pub const IN_PKTS_OK: u16 = 1;
    /// Invalid packets received.
    pub const IN_PKTS_INVALID: u16 = 2;
    /// Packets received that failed validation.
    pub const IN_PKTS_NOT_VALID: u16 = 3;
    /// Packets received for an SA that is not in use.
    pub const IN_PKTS_NOT_USING_SA: u16 = 4;
    /// Packets received on an unused SA.
    pub const IN_PKTS_UNUSED_SA: u16 = 5;
    /// Protected packets transmitted.
    pub const OUT_PKTS_PROTECTED: u16 = 6;
    /// Encrypted packets transmitted.
    pub const OUT_PKTS_ENCRYPTED: u16 = 7;
}

/// Offload attributes (`MACSEC_OFFLOAD_ATTR_*`).
pub mod macsec_offload_attr {
    /// Unspecified.
    pub const UNSPEC: u16 = 0;
    /// Offload type (u8) — see [`super::macsec_offload`].
    pub const TYPE: u16 = 1;
    /// Netlink alignment padding.
    pub const PAD: u16 = 2;
}

/// Offload types (`MACSEC_OFFLOAD_*`).
pub mod macsec_offload {
    /// No offload; MACsec is done in software.
    pub const OFF: u8 = 0;
    /// Offloaded to the PHY.
    pub const PHY: u8 = 1;
    /// Offloaded to the MAC.
    pub const MAC: u8 = 2;
}

/// Validation modes (`MACSEC_VALIDATE_*`).
pub mod macsec_validate {
    /// Disabled.
    pub const DISABLED: u8 = 0;
    /// Check (accept invalid frames).
    pub const CHECK: u8 = 1;
    /// Strict (drop invalid frames).
    pub const STRICT: u8 = 2;
}

/// MACsec cipher suite IDs (`MACSEC_CIPHER_ID_*`).
///
/// These are the values the kernel expects in `MACSEC_SECY_ATTR_CIPHER_SUITE`.
/// Before 0.26 every name here held the *previous* suite's id, so asking for
/// `GCM_AES_256` configured GCM-AES-128 — a silent halving of key strength with
/// nothing in the returned state to reveal it, because the reverse mapping was
/// wrong in the same direction (#260).
pub mod macsec_cipher {
    /// GCM-AES-128.
    pub const GCM_AES_128: u64 = 0x0080_C200_0100_0001;
    /// GCM-AES-256.
    pub const GCM_AES_256: u64 = 0x0080_C200_0100_0002;
    /// GCM-AES-XPN-128 (extended packet numbering).
    pub const GCM_AES_XPN_128: u64 = 0x0080_C200_0100_0003;
    /// GCM-AES-XPN-256 (extended packet numbering).
    pub const GCM_AES_XPN_256: u64 = 0x0080_C200_0100_0004;
}

/// The legacy default cipher id (`MACSEC_DEFAULT_CIPHER_ID`).
///
/// The kernel accepts two ids for GCM-AES-128: this one and
/// [`macsec_cipher::GCM_AES_128`], which the header calls
/// `MACSEC_DEFAULT_CIPHER_ALT`. They are equivalent on the wire. This value
/// used to be exposed *as* `GCM_AES_128`, which is why the rest of the table
/// was shifted by one.
pub const MACSEC_DEFAULT_CIPHER_ID: u64 = 0x0080_0200_0100_0001;

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned against `if_macsec.h`, not against what nlink used to send.
    ///
    /// The previous version of this test asserted `GCM_AES_256 ==
    /// 0x0080_C200_0100_0001`, which is the kernel's GCM-AES-**128** — so the
    /// suite stayed green while the library silently downgraded the cipher.
    /// The audit gate now checks these on every build; this test is the fast
    /// local echo of it.
    #[test]
    fn cipher_ids_match_the_kernel_header() {
        assert_eq!(macsec_cipher::GCM_AES_128, 0x0080_C200_0100_0001);
        assert_eq!(macsec_cipher::GCM_AES_256, 0x0080_C200_0100_0002);
        assert_eq!(macsec_cipher::GCM_AES_XPN_128, 0x0080_C200_0100_0003);
        assert_eq!(macsec_cipher::GCM_AES_XPN_256, 0x0080_C200_0100_0004);
        assert_eq!(MACSEC_DEFAULT_CIPHER_ID, 0x0080_0200_0100_0001);

        // Each suite must be distinct — the bug was two names sharing meaning.
        let all = [
            macsec_cipher::GCM_AES_128,
            macsec_cipher::GCM_AES_256,
            macsec_cipher::GCM_AES_XPN_128,
            macsec_cipher::GCM_AES_XPN_256,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "two cipher suites share an id");
            }
        }
    }

    #[test]
    fn test_validate_values() {
        assert_eq!(macsec_validate::DISABLED, 0);
        assert_eq!(macsec_validate::CHECK, 1);
        assert_eq!(macsec_validate::STRICT, 2);
    }
}
