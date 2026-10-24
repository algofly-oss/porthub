//! OpenVPN data-channel offload (DCO) Generic Netlink family.
//!
//! The kernel's `ovpn` GENL family (stabilized in **Linux 6.16**)
//! lets userspace push OpenVPN 2.7 data-channel processing into
//! the kernel. The TLS handshake stays in userspace; the
//! pre-derived AEAD keys + per-peer socket descriptors are handed
//! to the kernel via this family, and packets are encrypted /
//! decrypted in-kernel from then on. This eliminates the
//! per-packet user/kernel boundary crossings that bottlenecked
//! pre-2.7 OpenVPN.
//!
//! # Status — Plan 197
//!
//! | Phase | Ships |
//! |---|---|
//! | Family marker + module scaffold | ✓ |
//! | Command + attribute + value enums | ✓ |
//! | Imperative `Connection<Ovpn>` methods | ✓ |
//! | Multicast `peers` group + `OvpnEvent` | ✓ |
//! | Declarative `OvpnConfig` + diff + apply | ✓ |
//! | `attach_socket` SCM_RIGHTS cross-netns | deferred |
//!
//! The interface itself is created via RTNL — see
//! [`OvpnLink`][crate::netlink::link::OvpnLink] (Plan 190 §2.3b).
//! The GENL family operates on an already-existing ovpn interface
//! by `ifindex`.
//!
//! # Construction
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, genl::ovpn::Ovpn};
//!
//! let conn = Connection::<Ovpn>::new_async().await?;
//! // Family ID resolved against the kernel "ovpn" registration;
//! // FamilyNotFound on kernels without CONFIG_OVPN.
//! # Ok(())
//! # }
//! ```
//!
//! Resolution failure is the common case on stock distro kernels
//! that don't load the `ovpn` module. Handle via
//! [`Error::is_not_found`](crate::Error::is_not_found):
//!
//! ```no_run
//! # async fn example() -> nlink::Result<()> {
//! # use nlink::Connection;
//! # use nlink::netlink::genl::ovpn::Ovpn;
//! match Connection::<Ovpn>::new_async().await {
//!     Ok(conn) => { /* use it */ }
//!     Err(e) if e.is_not_found() => {
//!         tracing::warn!("OVPN DCO not available on this kernel; skipping");
//!     }
//!     Err(e) => return Err(e),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Cipher constraints
//!
//! The kernel accepts AES-GCM (128 or 256-bit) and
//! ChaCha20-Poly1305 only — the TLS handshake in OpenVPN 2.7
//! must negotiate one of these. Legacy CBC + non-AEAD modes are
//! intentionally not supported in DCO mode.

use crate::macros::genl_family;

pub mod config;
pub mod connection;
pub mod events;
pub mod messages;
pub mod types;

pub use config::{
    OvpnConfig, OvpnDiff, OvpnInterfaceConfig, OvpnInterfaceConfigBuilder, OvpnKeyConfig,
    OvpnPeerConfig, OvpnPeerConfigBuilder,
};
pub use events::OvpnEvent;
pub use messages::{
    OvpnKeyDelRequest, OvpnKeyGetRequest, OvpnKeyNewRequest, OvpnKeyReply, OvpnKeySwapRequest,
    OvpnKeyconf, OvpnKeydir, OvpnPeer, OvpnPeerDelRequest, OvpnPeerGetRequest, OvpnPeerNewRequest,
    OvpnPeerReply, OvpnPeerSetRequest,
};
pub use types::{
    OvpnAttr, OvpnCipherAlg, OvpnCmd, OvpnDelPeerReason, OvpnKeyconfAttr, OvpnKeySlot,
    OvpnKeydirAttr, OvpnPeerAttr, OVPN_MAX_CIPHER_KEY_LEN, OVPN_MAX_KEY_ID, OVPN_MAX_PEER_ID,
    OVPN_NONCE_TAIL_SIZE,
};

/// OVPN Generic Netlink family marker.
///
/// Constructed via [`Connection::<Ovpn>::new_async()`][Connection]
/// — the family ID is resolved against the kernel at connection
/// time. Returns
/// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) on
/// kernels without OVPN support (kernel < 6.16 or `ovpn` module
/// not loaded).
///
/// [Connection]: crate::netlink::Connection
#[genl_family(name = "ovpn", version = 1)]
pub struct Ovpn;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{
        construction::AsyncConstructible, AsyncProtocolInit, Protocol, ProtocolState,
    };

    #[test]
    fn family_marker_carries_expected_name_and_version() {
        assert_eq!(Ovpn::NAME, "ovpn");
        assert_eq!(Ovpn::VERSION, 1);
    }

    #[test]
    fn default_marker_has_zero_family_id_before_resolution() {
        let d = Ovpn::default();
        assert_eq!(d.family_id(), 0);
    }

    #[test]
    fn protocol_state_routes_to_generic() {
        const _: () = {
            assert!(matches!(Ovpn::PROTOCOL, Protocol::Generic));
        };
    }

    fn assert_async_constructible<P: AsyncConstructible>() {}
    fn assert_async_protocol_init<P: AsyncProtocolInit>() {}

    #[test]
    fn ovpn_satisfies_async_construction_bounds() {
        assert_async_constructible::<Ovpn>();
        assert_async_protocol_init::<Ovpn>();
    }
}
