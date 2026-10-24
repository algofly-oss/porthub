//! MACsec type definitions.

use crate::netlink::types::macsec::{macsec_cipher, macsec_offload, macsec_validate};

/// MACsec cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum MacsecCipherSuite {
    /// GCM-AES-128 (default, 16-byte key).
    #[default]
    GcmAes128,
    /// GCM-AES-256 (32-byte key).
    GcmAes256,
    /// GCM-AES-XPN-128 (extended packet numbering, 16-byte key).
    GcmAesXpn128,
    /// GCM-AES-XPN-256 (extended packet numbering, 32-byte key).
    GcmAesXpn256,
}

impl MacsecCipherSuite {
    /// Convert to kernel cipher ID.
    pub fn to_u64(self) -> u64 {
        match self {
            Self::GcmAes128 => macsec_cipher::GCM_AES_128,
            Self::GcmAes256 => macsec_cipher::GCM_AES_256,
            Self::GcmAesXpn128 => macsec_cipher::GCM_AES_XPN_128,
            Self::GcmAesXpn256 => macsec_cipher::GCM_AES_XPN_256,
        }
    }

    /// Parse from kernel cipher ID.
    pub fn from_u64(val: u64) -> Option<Self> {
        match val {
            macsec_cipher::GCM_AES_128 => Some(Self::GcmAes128),
            macsec_cipher::GCM_AES_256 => Some(Self::GcmAes256),
            macsec_cipher::GCM_AES_XPN_128 => Some(Self::GcmAesXpn128),
            macsec_cipher::GCM_AES_XPN_256 => Some(Self::GcmAesXpn256),
            _ => None,
        }
    }

    /// Get the required key length for this cipher.
    pub fn key_len(&self) -> usize {
        match self {
            Self::GcmAes128 | Self::GcmAesXpn128 => 16,
            Self::GcmAes256 | Self::GcmAesXpn256 => 32,
        }
    }

    /// Check if this cipher uses extended packet numbering.
    pub fn is_xpn(&self) -> bool {
        matches!(self, Self::GcmAesXpn128 | Self::GcmAesXpn256)
    }
}

/// MACsec validation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum MacsecValidate {
    /// Validation disabled.
    Disabled,
    /// Check mode (accept invalid frames with warning).
    #[default]
    Check,
    /// Strict mode (drop invalid frames).
    Strict,
}

impl MacsecValidate {
    /// Convert to kernel value.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Disabled => macsec_validate::DISABLED,
            Self::Check => macsec_validate::CHECK,
            Self::Strict => macsec_validate::STRICT,
        }
    }

    /// Parse from kernel value.
    pub fn from_u8(val: u8) -> Self {
        match val {
            macsec_validate::DISABLED => Self::Disabled,
            macsec_validate::CHECK => Self::Check,
            macsec_validate::STRICT => Self::Strict,
            _ => Self::Disabled,
        }
    }
}

/// MACsec offload type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum MacsecOffload {
    /// No offload (software).
    #[default]
    Off,
    /// PHY offload.
    Phy,
    /// MAC offload.
    Mac,
}

impl MacsecOffload {
    /// Convert to kernel value.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Off => macsec_offload::OFF,
            Self::Phy => macsec_offload::PHY,
            Self::Mac => macsec_offload::MAC,
        }
    }

    /// Parse from kernel value.
    pub fn from_u8(val: u8) -> Self {
        match val {
            macsec_offload::PHY => Self::Phy,
            macsec_offload::MAC => Self::Mac,
            _ => Self::Off,
        }
    }
}

/// MACsec device information.
#[derive(Debug, Clone, Default)]
pub struct MacsecDevice {
    /// Interface index.
    pub ifindex: u32,
    /// Secure Channel Identifier (SCI).
    pub sci: u64,
    /// Cipher suite.
    pub cipher: MacsecCipherSuite,
    /// ICV (Integrity Check Value) length in bytes.
    pub icv_len: u8,
    /// Encoding SA (active TX SA number).
    pub encoding_sa: u8,
    /// Encryption enabled.
    pub encrypt: bool,
    /// Frame protection enabled.
    pub protect: bool,
    /// Replay protection enabled.
    pub replay_protect: bool,
    /// Replay window size.
    pub replay_window: u32,
    /// Validation mode.
    pub validate: MacsecValidate,
    /// Include SCI in frames.
    pub include_sci: bool,
    /// End station mode.
    pub end_station: bool,
    /// Single Copy Broadcast mode.
    pub scb: bool,
    /// Offload mode.
    pub offload: MacsecOffload,
    /// TX SC information.
    pub tx_sc: Option<MacsecTxSc>,
    /// RX SC list.
    pub rx_scs: Vec<MacsecRxSc>,
}

impl MacsecDevice {
    /// Create a new empty device.
    pub fn new() -> Self {
        Self::default()
    }
}

/// TX Secure Channel information.
#[derive(Debug, Clone, Default)]
pub struct MacsecTxSc {
    /// Secure Channel Identifier.
    pub sci: u64,
    /// TX SAs (Security Associations).
    pub sas: Vec<MacsecTxSa>,
    /// Protected packets count.
    pub stats_protected_pkts: u64,
    /// Encrypted packets count.
    pub stats_encrypted_pkts: u64,
    /// Protected octets count.
    pub stats_protected_octets: u64,
    /// Encrypted octets count.
    pub stats_encrypted_octets: u64,
}

/// TX Security Association.
#[derive(Debug, Clone, Default)]
pub struct MacsecTxSa {
    /// Association Number (0-3).
    pub an: u8,
    /// Active flag.
    pub active: bool,
    /// Packet number (next PN to use).
    pub pn: u64,
    /// Key ID (128 bits).
    pub key_id: Option<[u8; 16]>,
}

/// RX Secure Channel information.
#[derive(Debug, Clone, Default)]
pub struct MacsecRxSc {
    /// Secure Channel Identifier.
    pub sci: u64,
    /// Active flag.
    pub active: bool,
    /// RX SAs (Security Associations).
    pub sas: Vec<MacsecRxSa>,
    /// OK packets count.
    pub stats_ok_pkts: u64,
    /// Invalid packets count.
    pub stats_invalid_pkts: u64,
    /// Not valid packets count.
    pub stats_not_valid_pkts: u64,
    /// Validated octets count.
    pub stats_validated_octets: u64,
    /// Decrypted octets count.
    pub stats_decrypted_octets: u64,
}

/// RX Security Association.
#[derive(Debug, Clone, Default)]
pub struct MacsecRxSa {
    /// Association Number (0-3).
    pub an: u8,
    /// Active flag.
    pub active: bool,
    /// Packet number (next expected PN).
    pub pn: u64,
    /// Key ID (128 bits).
    pub key_id: Option<[u8; 16]>,
}

/// Builder for MACsec Security Association configuration.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::genl::macsec::MacsecSaBuilder;
///
/// // Create a TX SA with a 128-bit key
/// let key = [0u8; 16];
/// let sa = MacsecSaBuilder::new(0, &key)
///     .packet_number(1)
///     .active(true);
/// ```
#[derive(Clone)]
#[must_use = "builders do nothing unless used"]
pub struct MacsecSaBuilder {
    /// Association Number (0-3).
    an: u8,
    /// Key data.
    key: Vec<u8>,
    /// Initial packet number.
    pn: Option<u64>,
    /// Active flag.
    active: bool,
    /// Key ID.
    key_id: Option<[u8; 16]>,
}

impl std::fmt::Debug for MacsecSaBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("MacsecSaBuilder")
            .field("an", &self.an)
            .field("key", &crate::util::SecretBytes(&self.key))
            .field("pn", &self.pn)
            .field("active", &self.active)
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl MacsecSaBuilder {
    /// Create a new SA builder.
    ///
    /// # Arguments
    ///
    /// * `an` - Association Number (0-3)
    /// * `key` - Encryption key (16 bytes for AES-128, 32 bytes for AES-256)
    ///
    /// # Panics
    ///
    /// Panics if `an` is greater than 3.
    pub fn new(an: u8, key: &[u8]) -> Self {
        assert!(an <= 3, "Association Number must be 0-3");
        Self {
            an,
            key: key.to_vec(),
            pn: None,
            active: false,
            key_id: None,
        }
    }

    /// Set the initial packet number.
    ///
    /// For TX SAs, this is the next PN to use.
    /// For RX SAs, this is the next expected PN.
    pub fn packet_number(mut self, pn: u64) -> Self {
        self.pn = Some(pn);
        self
    }

    /// Set the active flag.
    ///
    /// For TX SAs, only one SA can be active at a time (the encoding SA).
    /// For RX SAs, multiple SAs can be active for key rollover.
    pub fn active(mut self, active: bool) -> Self {
        self.active = active;
        self
    }

    /// Set the key identifier.
    ///
    /// The key ID is a 128-bit identifier used for key management.
    pub fn key_id(mut self, id: [u8; 16]) -> Self {
        self.key_id = Some(id);
        self
    }

    /// Get the association number.
    pub fn get_an(&self) -> u8 {
        self.an
    }

    /// Get the key.
    pub fn get_key(&self) -> &[u8] {
        &self.key
    }

    /// Get the packet number if set.
    pub fn get_pn(&self) -> Option<u64> {
        self.pn
    }

    /// Get the active flag.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get the key ID if set.
    pub fn get_key_id(&self) -> Option<&[u8; 16]> {
        self.key_id.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_suite() {
        assert_eq!(MacsecCipherSuite::GcmAes128.key_len(), 16);
        assert_eq!(MacsecCipherSuite::GcmAes256.key_len(), 32);
        assert!(!MacsecCipherSuite::GcmAes128.is_xpn());
        assert!(MacsecCipherSuite::GcmAesXpn128.is_xpn());

        assert_eq!(
            MacsecCipherSuite::from_u64(macsec_cipher::GCM_AES_128),
            Some(MacsecCipherSuite::GcmAes128)
        );
        assert_eq!(
            MacsecCipherSuite::from_u64(macsec_cipher::GCM_AES_256),
            Some(MacsecCipherSuite::GcmAes256)
        );
    }

    #[test]
    fn test_validate_mode() {
        assert_eq!(MacsecValidate::Disabled.to_u8(), 0);
        assert_eq!(MacsecValidate::Check.to_u8(), 1);
        assert_eq!(MacsecValidate::Strict.to_u8(), 2);
        assert_eq!(MacsecValidate::from_u8(2), MacsecValidate::Strict);
    }

    #[test]
    fn test_offload_type() {
        assert_eq!(MacsecOffload::Off.to_u8(), 0);
        assert_eq!(MacsecOffload::Phy.to_u8(), 1);
        assert_eq!(MacsecOffload::Mac.to_u8(), 2);
        assert_eq!(MacsecOffload::from_u8(1), MacsecOffload::Phy);
    }

    #[test]
    fn test_sa_builder() {
        let key = [0u8; 16];
        let sa = MacsecSaBuilder::new(0, &key)
            .packet_number(100)
            .active(true);

        assert_eq!(sa.get_an(), 0);
        assert_eq!(sa.get_key().len(), 16);
        assert_eq!(sa.get_pn(), Some(100));
        assert!(sa.is_active());
    }

    #[test]
    #[should_panic(expected = "Association Number must be 0-3")]
    fn test_sa_builder_invalid_an() {
        let key = [0u8; 16];
        let _ = MacsecSaBuilder::new(4, &key);
    }
}
