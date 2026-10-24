//! Shared utilities for nlink.

pub mod addr;
pub mod address_family;
pub mod bytes;
pub mod device;
pub mod ifname;
pub mod names;
pub mod packets;
pub mod parse;
pub mod percent;
pub mod rate;
#[cfg(feature = "serde")]
pub mod serde_units;
pub mod uevent_trigger;

pub use addr::{format_addr, format_prefix, parse_addr, parse_prefix};
pub use address_family::AddressFamily;
pub use bytes::{Bytes, BytesParseError};
pub use packets::{Packets, PacketsParseError};
pub use device::{get_ifindex, get_ifindex_opt, get_ifname, get_ifname_or_index};
pub use parse::{get_rate, get_size, get_time, get_u8, get_u16, get_u32, get_u64};
pub use percent::{Percent, PercentParseError};
pub use rate::{Rate, RateParseError};

/// Key material, for a hand-written `Debug`: shows how many bytes there
/// are, never what they are (#499). A derived `Debug` printed every
/// private and preshared key, so any `?config` in a `tracing` field, any
/// `dbg!`, any panic message that included one, leaked it.
pub(crate) struct SecretBytes<'a>(pub(crate) &'a [u8]);

impl std::fmt::Debug for SecretBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{} bytes redacted>", self.0.len())
    }
}

#[cfg(test)]
mod secret_tests {
    use crate::netlink::{
        genl::{
            macsec::MacsecSaBuilder,
            ovpn::messages::OvpnKeydir,
            wireguard::{WgDevice, WgDeviceBuilder, WgPeer, WgPeerBuilder, WireguardConfig},
        },
        xfrm::{XfrmAlgoAead, XfrmAlgoAuth, XfrmAlgoEncr, XfrmAlgorithm},
    };

    /// A key byte no other field here uses, and how it would print.
    const SECRET: u8 = 0xA7;
    const PRINTED: &str = "167";

    fn assert_redacted(what: &str, debug: String) {
        assert!(!debug.contains(PRINTED), "{what} prints key bytes: {debug}");
        assert!(debug.contains("bytes redacted"), "{what}: {debug}");
    }

    /// #499 / #567: a derived `Debug` printed private, preshared, cipher, SA
    /// and MACsec keys byte by byte.
    #[test]
    fn key_material_never_prints() {
        let key = [SECRET; 32];
        let device = WgDevice {
            private_key: Some(key),
            peers: vec![WgPeer {
                preshared_key: Some(key),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_redacted("WgDevice", format!("{device:?}"));
        let builder = WgDeviceBuilder::new()
            .private_key(key)
            .peer(WgPeerBuilder::new([1; 32]).preshared_key(key));
        assert_redacted("WgDeviceBuilder", format!("{builder:?}"));
        let config = WireguardConfig::new().device("wg0", |d| {
            d.private_key(key)
                .peer([1; 32], |p| p.preshared_key(key))
        });
        assert_redacted("WireguardConfig", format!("{config:?}"));
        assert_redacted("OvpnKeydir", format!("{:?}", OvpnKeydir::new(key, [2; 8])));
        let auth = XfrmAlgoAuth {
            name: "hmac(sha256)".into(),
            key: key.to_vec(),
        };
        let encr = XfrmAlgoEncr {
            name: "cbc(aes)".into(),
            key: key.to_vec(),
        };
        let aead = XfrmAlgoAead {
            name: "rfc4106(gcm(aes))".into(),
            key: key.to_vec(),
            icv_truncbits: 128,
        };
        assert_redacted("XfrmAlgo*", format!("{auth:?} {encr:?} {aead:?}"));
        let dumped = XfrmAlgorithm {
            name: "cbc(aes)".into(),
            key_len: 256,
            key: key.to_vec(),
        };
        assert_redacted("XfrmAlgorithm", format!("{dumped:?}"));
        assert_redacted("MacsecSaBuilder", format!("{:?}", MacsecSaBuilder::new(0, &key)));
    }
}
