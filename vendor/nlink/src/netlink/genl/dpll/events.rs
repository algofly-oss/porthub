//! DPLL multicast monitor — typed event stream.
//!
//! The kernel emits `DPLL_CMD_DEVICE_CREATE_NTF` /
//! `_DEVICE_DELETE_NTF` / `_DEVICE_CHANGE_NTF` (and the matching
//! pin notifications) on the `"monitor"` multicast group whenever
//! a device or pin is created, removed, or changes state. The
//! group ID is registered by the kernel at driver-load time and
//! resolved at [`Connection::<Dpll>::new_async()`][nasync] via
//! the macro stack's `CTRL_ATTR_MCAST_GROUPS` parsing (Plan 156
//! Phase 5).
//!
//! Subscribe via [`subscribe_group`][sg] (the generic helper) or
//! [`subscribe_monitor`][sm] (the family-specific convenience).
//! Consume via the existing [`EventSource`][es]-driven
//! [`events()`][cev] / [`into_events()`][cinto].
//!
//! [nasync]: crate::netlink::Connection
//! [sg]: crate::netlink::Connection::subscribe_group
//! [sm]: crate::netlink::Connection::subscribe_monitor
//! [es]: crate::netlink::EventSource
//! [cev]: crate::netlink::Connection::events
//! [cinto]: crate::netlink::Connection::into_events
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, genl::dpll::{Dpll, DpllEvent}};
//! use tokio_stream::StreamExt;
//!
//! let conn = Connection::<Dpll>::new_async().await?;
//! conn.subscribe_monitor()?;
//! let mut events = conn.events().await;
//! while let Some(evt) = events.next().await {
//!     match evt? {
//!         DpllEvent::DeviceChanged(dev) => {
//!             println!("device {} → {:?}", dev.id, dev.lock_status);
//!         }
//!         DpllEvent::PinChanged(pin) => {
//!             println!("pin {} → {:?}", pin.id, pin.state);
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use crate::macros::GenlMessage;
use crate::netlink::genl::GENL_HDRLEN;

use super::messages::{DpllDeviceReply, DpllPinReply};
use super::types::DpllCmd;
use super::Dpll;

/// A DPLL multicast-monitor event.
///
/// The kernel ships create / delete / change notifications for
/// both devices and pins on the `"monitor"` group. Delete
/// notifications carry only the ID of the destroyed object (the
/// rest of the reply is undefined-but-zeroed by the kernel).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DpllEvent {
    /// `DPLL_CMD_DEVICE_CREATE_NTF` — a new DPLL device was
    /// registered (driver probed, hardware appeared).
    DeviceCreated(DpllDeviceReply),
    /// `DPLL_CMD_DEVICE_DELETE_NTF` — a DPLL device was
    /// unregistered. Only `id` is meaningful.
    DeviceDeleted { id: u32 },
    /// `DPLL_CMD_DEVICE_CHANGE_NTF` — a DPLL device's state
    /// changed (mode, lock status, etc.).
    DeviceChanged(DpllDeviceReply),
    /// `DPLL_CMD_PIN_CREATE_NTF` — a new pin was registered.
    PinCreated(DpllPinReply),
    /// `DPLL_CMD_PIN_DELETE_NTF` — a pin was unregistered.
    /// Only `id` is meaningful.
    PinDeleted { id: u32 },
    /// `DPLL_CMD_PIN_CHANGE_NTF` — a pin's state changed
    /// (priority, frequency, lock state, etc.).
    PinChanged(DpllPinReply),
}

/// Parse a single GENL message payload (post-nlmsghdr) into a
/// [`DpllEvent`], using the GENL header's `cmd` byte to dispatch.
///
/// Returns `None` for unrecognised commands (forward-compat with
/// kernel additions) or malformed payloads (the macros'
/// `from_bytes` returns defaults on missing attrs; a truncated
/// GENL header is the only hard failure here).
pub(crate) fn parse_dpll_event(payload: &[u8]) -> Option<DpllEvent> {
    if payload.len() < GENL_HDRLEN {
        return None;
    }
    let cmd = payload[0];
    let attrs = &payload[GENL_HDRLEN..];

    // Try every DPLL_CMD_*_NTF the kernel ships. `from_bytes`
    // defaults missing fields, so `delete` notifications (which
    // carry only the ID) still parse cleanly.
    if cmd == DpllCmd::DeviceCreateNtf as u8 {
        let reply = DpllDeviceReply::from_bytes(attrs).ok()?;
        return Some(DpllEvent::DeviceCreated(reply));
    }
    if cmd == DpllCmd::DeviceChangeNtf as u8 {
        let reply = DpllDeviceReply::from_bytes(attrs).ok()?;
        return Some(DpllEvent::DeviceChanged(reply));
    }
    if cmd == DpllCmd::DeviceDeleteNtf as u8 {
        let reply = DpllDeviceReply::from_bytes(attrs).ok()?;
        return Some(DpllEvent::DeviceDeleted { id: reply.id });
    }
    if cmd == DpllCmd::PinCreateNtf as u8 {
        let reply = DpllPinReply::from_bytes(attrs).ok()?;
        return Some(DpllEvent::PinCreated(reply));
    }
    if cmd == DpllCmd::PinChangeNtf as u8 {
        let reply = DpllPinReply::from_bytes(attrs).ok()?;
        return Some(DpllEvent::PinChanged(reply));
    }
    if cmd == DpllCmd::PinDeleteNtf as u8 {
        let reply = DpllPinReply::from_bytes(attrs).ok()?;
        return Some(DpllEvent::PinDeleted { id: reply.id });
    }
    None
}

impl crate::netlink::Connection<Dpll> {
    /// Subscribe to the DPLL `"monitor"` multicast group.
    ///
    /// Convenience wrapper around `self.subscribe_group("monitor")`.
    /// After this returns, [`self.events()`](crate::netlink::Connection::events)
    /// yields a stream of [`DpllEvent`] values.
    ///
    /// Returns
    /// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound)
    /// (with the `"dpll::monitor"` name) when the kernel doesn't
    /// register the group — typically a kernel-too-old / DPLL-
    /// driver-not-loaded mismatch.
    pub fn subscribe_monitor(&self) -> crate::Result<()> {
        self.subscribe_group("monitor")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macros::__rt;
    use crate::netlink::MessageBuilder;
    use crate::netlink::genl::GenlMsgHdr;

    use crate::netlink::genl::dpll::types::{
        DpllAttr, DpllLockStatus, DpllMode, DpllPinAttr, DpllPinState,
    };

    /// Build a synthetic notification payload: GENL header + attrs.
    fn synth_payload(cmd: DpllCmd, attrs_fn: impl FnOnce(&mut MessageBuilder)) -> Vec<u8> {
        // We can't easily synthesize the post-nlmsghdr-only bytes
        // via MessageBuilder (it always writes the netlink header).
        // Build them manually: 4 bytes GENL header + attrs body.
        let mut b = MessageBuilder::new(0, 0);
        b.append(&GenlMsgHdr::new(cmd as u8, 1));
        attrs_fn(&mut b);
        let full = b.finish();
        // Strip the 16-byte nlmsghdr that MessageBuilder prepended.
        full[16..].to_vec()
    }

    /// A notification about a device of a type newer than `DpllType`
    /// is delivered, with `kind: None`. Before #727 it was dropped.
    #[test]
    fn a_device_of_a_newer_type_is_still_announced() {
        let payload = synth_payload(DpllCmd::DeviceCreateNtf, |b| {
            __rt::emit_u32_attr(b, DpllAttr::Id as u16, 9);
            __rt::emit_u32_attr(b, DpllAttr::Type as u16, 3); // DPLL_TYPE_GENERIC, v7.x
            __rt::emit_u32_attr(b, DpllAttr::LockStatus as u16, DpllLockStatus::Locked as u32);
        });
        match parse_dpll_event(&payload).expect("the event must not be dropped") {
            DpllEvent::DeviceCreated(dev) => {
                assert_eq!(dev.id, 9);
                assert_eq!(dev.kind, None);
                assert_eq!(dev.lock_status, Some(DpllLockStatus::Locked));
            }
            other => panic!("expected DeviceCreated, got {other:?}"),
        }
    }

    #[test]
    fn parses_device_change_with_full_state() {
        let payload = synth_payload(DpllCmd::DeviceChangeNtf, |b| {
            __rt::emit_u32_attr(b, DpllAttr::Id as u16, 7);
            __rt::emit_str_attr(b, DpllAttr::ModuleName as u16, "ice");
            __rt::emit_u32_attr(b, DpllAttr::LockStatus as u16, DpllLockStatus::Locked as u32);
            __rt::emit_u32_attr(b, DpllAttr::Mode as u16, DpllMode::Automatic as u32);
        });

        let evt = parse_dpll_event(&payload).expect("parsed");
        match evt {
            DpllEvent::DeviceChanged(dev) => {
                assert_eq!(dev.id, 7);
                assert_eq!(dev.module_name, "ice");
                assert_eq!(dev.lock_status, Some(DpllLockStatus::Locked));
                assert_eq!(dev.mode, Some(DpllMode::Automatic));
            }
            other => panic!("expected DeviceChanged; got {other:?}"),
        }
    }

    #[test]
    fn parses_device_delete_extracting_id() {
        let payload = synth_payload(DpllCmd::DeviceDeleteNtf, |b| {
            __rt::emit_u32_attr(b, DpllAttr::Id as u16, 42);
        });
        let evt = parse_dpll_event(&payload).expect("parsed");
        match evt {
            DpllEvent::DeviceDeleted { id } => assert_eq!(id, 42),
            other => panic!("expected DeviceDeleted; got {other:?}"),
        }
    }

    #[test]
    fn parses_pin_change() {
        let payload = synth_payload(DpllCmd::PinChangeNtf, |b| {
            __rt::emit_u32_attr(b, DpllPinAttr::Id as u16, 9);
            __rt::emit_u32_attr(
                b,
                DpllPinAttr::State as u16,
                DpllPinState::Connected as u32,
            );
            __rt::emit_u32_attr(b, DpllPinAttr::Prio as u16, 5);
        });
        let evt = parse_dpll_event(&payload).expect("parsed");
        match evt {
            DpllEvent::PinChanged(pin) => {
                assert_eq!(pin.id, 9);
                assert_eq!(pin.state, Some(DpllPinState::Connected));
                assert_eq!(pin.prio, Some(5));
            }
            other => panic!("expected PinChanged; got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_notification_commands() {
        // DeviceGet isn't a notification; events.rs only handles
        // *_NTF variants.
        let payload = synth_payload(DpllCmd::DeviceGet, |b| {
            __rt::emit_u32_attr(b, DpllAttr::Id as u16, 0);
        });
        assert!(parse_dpll_event(&payload).is_none());
    }

    #[test]
    fn rejects_truncated_payload() {
        assert!(parse_dpll_event(&[]).is_none());
        assert!(parse_dpll_event(&[1]).is_none()); // <GENL_HDRLEN
    }
}
