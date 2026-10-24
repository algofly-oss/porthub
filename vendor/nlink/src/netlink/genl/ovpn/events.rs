//! OVPN multicast `peers` group — typed event stream.
//!
//! The kernel emits three notifications on the `peers` multicast
//! group:
//!
//! - `peer-del-ntf` — fired when a peer is removed (operator
//!   action, keep-alive timeout, transport error, or interface
//!   teardown). Carries the peer body + a `del_reason` enum.
//! - `key-swap-ntf` — fired when the kernel's per-key IV space
//!   is approaching exhaustion; userspace should renegotiate.
//! - `peer-float-ntf` — fired when a peer's source address /
//!   port changes mid-session (NAT rebind / mobility).
//!
//! Subscribe via [`Connection::<Ovpn>::subscribe_peers`][sm].
//! Consume via [`Connection::events`][ev].
//!
//! [sm]: crate::netlink::Connection::subscribe_group
//! [ev]: crate::netlink::Connection::events

use crate::macros::GenlMessage;
use crate::netlink::genl::GENL_HDRLEN;

use super::messages::{OvpnKeyReply, OvpnPeerReply};
use super::types::OvpnCmd;
use super::Ovpn;

/// A multicast notification from the OVPN `peers` group.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum OvpnEvent {
    /// `OVPN_CMD_PEER_DEL_NTF` — a peer was deleted. The
    /// `del_reason` field on the inner peer indicates why.
    PeerDeleted(OvpnPeerReply),
    /// `OVPN_CMD_KEY_SWAP_NTF` — a key's IV space is exhausted
    /// (renegotiation hint). The body carries the same shape as
    /// a `key-get` reply.
    KeySwap(OvpnKeyReply),
    /// `OVPN_CMD_PEER_FLOAT_NTF` — a peer's remote endpoint
    /// changed mid-session. The body carries the updated peer
    /// state (`remote_ipv4` / `remote_ipv6` + `remote_port` will
    /// reflect the new endpoint).
    PeerFloat(OvpnPeerReply),
}

/// Parse a single GENL message payload (post-nlmsghdr) into an
/// [`OvpnEvent`], using the GENL header's `cmd` byte to dispatch.
///
/// Returns `None` for unrecognised commands (forward-compat with
/// kernel additions) or malformed payloads.
pub(crate) fn parse_ovpn_event(payload: &[u8]) -> Option<OvpnEvent> {
    if payload.len() < GENL_HDRLEN {
        return None;
    }
    let cmd = payload[0];
    let attrs = &payload[GENL_HDRLEN..];

    if cmd == OvpnCmd::PeerDelNtf as u8 {
        let reply = OvpnPeerReply::from_bytes(attrs).ok()?;
        return Some(OvpnEvent::PeerDeleted(reply));
    }
    if cmd == OvpnCmd::KeySwapNtf as u8 {
        let reply = OvpnKeyReply::from_bytes(attrs).ok()?;
        return Some(OvpnEvent::KeySwap(reply));
    }
    if cmd == OvpnCmd::PeerFloatNtf as u8 {
        let reply = OvpnPeerReply::from_bytes(attrs).ok()?;
        return Some(OvpnEvent::PeerFloat(reply));
    }
    None
}

impl crate::netlink::Connection<Ovpn> {
    /// Subscribe to the OVPN `peers` multicast group.
    ///
    /// Convenience wrapper around `self.subscribe_group("peers")`.
    /// After this returns, [`self.events()`](crate::netlink::Connection::events)
    /// yields a stream of [`OvpnEvent`] values.
    ///
    /// Returns [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound)
    /// (with `"ovpn::peers"` in the name) when the kernel doesn't
    /// register the group — typically a too-old kernel (< 6.16).
    pub fn subscribe_peers(&self) -> crate::Result<()> {
        self.subscribe_group("peers")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macros::__rt;
    use crate::netlink::genl::GenlMsgHdr;
    use crate::netlink::genl::ovpn::types::{
        OvpnAttr, OvpnDelPeerReason, OvpnKeyconfAttr, OvpnKeySlot, OvpnPeerAttr,
    };
    use crate::netlink::MessageBuilder;

    /// Build a synthetic notification payload: GENL header + outer
    /// attrs (which include a nested OVPN_A_PEER or OVPN_A_KEYCONF
    /// block).
    fn synth_payload(cmd: OvpnCmd, attrs_fn: impl FnOnce(&mut MessageBuilder)) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        b.append(&GenlMsgHdr::new(cmd as u8, 1));
        attrs_fn(&mut b);
        let full = b.finish();
        // Strip the 16-byte nlmsghdr the builder prepended.
        full[16..].to_vec()
    }

    fn build_nested_peer_attr(id: u32, with_del_reason: bool) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        __rt::emit_u32_attr(&mut b, OvpnPeerAttr::Id as u16, id);
        if with_del_reason {
            __rt::emit_u32_attr(
                &mut b,
                OvpnPeerAttr::DelReason as u16,
                OvpnDelPeerReason::Expired as u32,
            );
        }
        b.as_bytes()[start..].to_vec()
    }

    fn build_nested_keyconf_attr(peer_id: u32, slot: OvpnKeySlot) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        __rt::emit_u32_attr(&mut b, OvpnKeyconfAttr::PeerId as u16, peer_id);
        __rt::emit_u32_attr(&mut b, OvpnKeyconfAttr::Slot as u16, slot as u32);
        b.as_bytes()[start..].to_vec()
    }

    #[test]
    fn parses_peer_del_with_expired_reason() {
        let peer_bytes = build_nested_peer_attr(42, true);
        let payload = synth_payload(OvpnCmd::PeerDelNtf, |b| {
            __rt::emit_u32_attr(b, OvpnAttr::Ifindex as u16, 7);
            __rt::emit_bytes_attr(b, OvpnAttr::Peer as u16, &peer_bytes);
        });
        let evt = parse_ovpn_event(&payload).expect("parsed");
        match evt {
            OvpnEvent::PeerDeleted(reply) => {
                assert_eq!(reply.ifindex, 7);
                let peer = reply.peer.expect("peer present");
                assert_eq!(peer.id, Some(42));
                assert_eq!(peer.del_reason, Some(OvpnDelPeerReason::Expired));
            }
            other => panic!("expected PeerDeleted, got {other:?}"),
        }
    }

    #[test]
    fn parses_peer_float_notification() {
        let peer_bytes = build_nested_peer_attr(99, false);
        let payload = synth_payload(OvpnCmd::PeerFloatNtf, |b| {
            __rt::emit_u32_attr(b, OvpnAttr::Ifindex as u16, 9);
            __rt::emit_bytes_attr(b, OvpnAttr::Peer as u16, &peer_bytes);
        });
        let evt = parse_ovpn_event(&payload).expect("parsed");
        match evt {
            OvpnEvent::PeerFloat(reply) => {
                assert_eq!(reply.ifindex, 9);
                assert_eq!(reply.peer.expect("peer present").id, Some(99));
            }
            other => panic!("expected PeerFloat, got {other:?}"),
        }
    }

    #[test]
    fn parses_key_swap_notification() {
        let keyconf_bytes = build_nested_keyconf_attr(7, OvpnKeySlot::Primary);
        let payload = synth_payload(OvpnCmd::KeySwapNtf, |b| {
            __rt::emit_u32_attr(b, OvpnAttr::Ifindex as u16, 4);
            __rt::emit_bytes_attr(b, OvpnAttr::Keyconf as u16, &keyconf_bytes);
        });
        let evt = parse_ovpn_event(&payload).expect("parsed");
        match evt {
            OvpnEvent::KeySwap(reply) => {
                assert_eq!(reply.ifindex, 4);
                let kc = reply.keyconf.expect("keyconf present");
                assert_eq!(kc.peer_id, Some(7));
                assert_eq!(kc.slot, Some(OvpnKeySlot::Primary));
            }
            other => panic!("expected KeySwap, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_notification_commands() {
        // PeerGet isn't a notification.
        let payload = synth_payload(OvpnCmd::PeerGet, |b| {
            __rt::emit_u32_attr(b, OvpnAttr::Ifindex as u16, 0);
        });
        assert!(parse_ovpn_event(&payload).is_none());
    }

    #[test]
    fn rejects_truncated_payload() {
        assert!(parse_ovpn_event(&[]).is_none());
        assert!(parse_ovpn_event(&[1]).is_none()); // < GENL_HDRLEN
    }
}
