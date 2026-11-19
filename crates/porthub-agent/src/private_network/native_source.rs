//! Native source identity and shutdown proof. No route or address is authorized
//! by a persisted completion bit; publication always requires a fresh probe.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Pin {
    Unknown,
    Intent {
        name: String,
    },
    Interface {
        name: String,
        index: u32,
    },
    Windows {
        name: String,
        index: u32,
        guid: String,
        luid: u64,
    },
}
impl Pin {
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Unknown => "ph-unbound",
            Self::Intent { name } | Self::Interface { name, .. } | Self::Windows { name, .. } => {
                name
            }
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            !self.name().is_empty()
                && self.name().len() <= 128
                && !self
                    .name()
                    .bytes()
                    .any(|b| b == 0 || b == b'/' || b == b'\\'),
            "invalid retired native interface name"
        );
        match self {
            Self::Interface { index, .. } => ensure!(*index > 0, "invalid retired interface index"),
            Self::Windows {
                index, guid, luid, ..
            } => ensure!(
                *index > 0
                    && *luid != 0
                    && guid.len() == 32
                    && guid
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                "invalid retired Windows identity"
            ),
            _ => {}
        }
        Ok(())
    }
}
/// Stored after the native handle fields, so lease release follows handle
/// destruction. Interior ownership supports a normal legacy-to-sparse handover
/// even when readiness already retains Weak references to the same Tun.
#[derive(Default)]
pub(crate) struct OwnerLease(std::sync::Mutex<Option<crate::profile::Lease>>);
impl OwnerLease {
    pub(crate) fn bind(&self, lease: crate::profile::Lease) -> Result<()> {
        let mut held = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("native owner lease state poisoned"))?;
        ensure!(held.is_none(), "native owner lease already bound");
        *held = Some(lease);
        Ok(())
    }
    pub(crate) fn held(&self) -> Result<bool> {
        Ok(self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("native owner lease state poisoned"))?
            .is_some())
    }
}
/// Small private native boundary, also exercised with injected failing OS calls.
/// An implementation must return COMPLETE observations, never turn read errors
/// into an empty address list or use a cached identity as fresh evidence.
pub(crate) trait ShutdownIo {
    fn identity(&self) -> Result<Pin>;
    fn addresses(&self) -> Result<Vec<IpAddr>>;
    fn remove(&self, own: Ipv4Addr) -> Result<()>;
    fn end_session(&self) -> Result<()>;
}
pub(crate) fn stop_checked(io: &impl ShutdownIo, expected: &Pin, own: Ipv4Addr) -> Result<()> {
    expected.validate()?;
    let same = || -> Result<()> {
        ensure!(
            io.identity()? == *expected,
            "owned native identity changed during source shutdown"
        );
        Ok(())
    };
    for _ in 0..3 {
        same()?;
        let addresses = io.addresses()?;
        same()?;
        if !addresses.contains(&IpAddr::V4(own)) {
            break;
        }
        io.remove(own)?;
    }
    same()?;
    io.end_session()?;
    same()?;
    let absent = !io.addresses()?.contains(&IpAddr::V4(own));
    same()?;
    ensure!(absent, "owned native source address remains after shutdown");
    Ok(())
}
/// Always destroy our handle, including when native shutdown fails. Memory
/// release alone is deliberately NOT the subsequent OS/publication proof.
pub(crate) fn release_owner<T>(
    owner: std::sync::Arc<T>,
    stop: impl FnOnce(&T) -> Result<()>,
) -> Result<()> {
    let stopped = stop(&owner);
    let weak = std::sync::Arc::downgrade(&owner);
    drop(owner);
    let released = weak.upgrade().is_none();
    stopped?;
    ensure!(released, "native owner still pinned; closure not proven");
    Ok(())
}
#[cfg(any(unix, test))]
fn interface_absence(
    name_index: Option<u32>,
    original: u32,
    original_index_present: bool,
) -> Result<()> {
    ensure!(name_index.is_none()&&!original_index_present,"native interface/index remains or was renamed/reused; absence not proven (original index {original})");
    Ok(())
}
#[cfg(target_os = "macos")]
#[path = "retired_utun.rs"]
mod retired_utun;
#[cfg(unix)]
pub(crate) fn verify_absent(pin: &Pin, own: Ipv4Addr) -> Result<Pin> {
    use std::ffi::CString;
    pin.validate()?;
    ensure!(
        !matches!(pin, Pin::Windows { .. }),
        "Windows source proof cannot authorize a Unix interface"
    );
    if matches!(pin, Pin::Unknown) {
        ensure!(
            !getifaddrs::getifaddrs()?.any(|row| row.address.ip_addr() == Some(IpAddr::V4(own))),
            "legacy native source still present; exact owned recovery required"
        );
        return Ok(pin.clone());
    }
    let name = CString::new(pin.name())?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        let error = std::io::Error::last_os_error();
        ensure!(
            matches!(error.raw_os_error(), Some(libc::ENXIO) | Some(libc::ENODEV)),
            "native absence inventory failed: {error}"
        );
        if let Pin::Interface {
            index: original, ..
        } = pin
        {
            let mut buffer = [0 as libc::c_char; libc::IF_NAMESIZE];
            let present =
                !unsafe { libc::if_indextoname(*original, buffer.as_mut_ptr()) }.is_null();
            if !present {
                let error = std::io::Error::last_os_error();
                ensure!(
                    matches!(error.raw_os_error(), Some(libc::ENXIO) | Some(libc::ENODEV)),
                    "native index absence inventory failed: {error}"
                );
            }
            #[cfg(target_os = "macos")]
            if present {
                // Darwin can recycle the ifindex for a different utun. Require
                // an exclusive reservation of the original kernel control unit.
                retired_utun::prove_unused(&name, own)?;
                return Ok(pin.clone());
            }
            interface_absence(None, *original, present)?;
        }
        // Intent has no observed OS identity. A constructor may have died before
        // its actual (macOS-assigned) name was checkpointed: require source-wide
        // absence, without deleting any unknown/foreign interface.
        if matches!(pin, Pin::Intent { .. }) {
            ensure!(
                !getifaddrs::getifaddrs()?
                    .any(|row| row.address.ip_addr() == Some(IpAddr::V4(own))),
                "unbound native source still present; exact owned recovery required"
            );
        }
        return Ok(pin.clone());
    }
    match pin {
        Pin::Interface {
            index: expected, ..
        } => ensure!(
            index == *expected,
            "native interface name/index was replaced; preserved"
        ),
        _ => {
            anyhow::bail!("unbound or foreign native interface remains; source shutdown not proven")
        }
    }
    // A still-live original utun/TUN must not be adopted, deleted or declared
    // absent. Its exclusive owner/FD must close before normal retry proceeds.
    anyhow::bail!("owned native interface remains; waiting for exact owner closure")
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    struct Io {
        pin: RefCell<Pin>,
        addresses: RefCell<Vec<IpAddr>>,
        removed: RefCell<Vec<Ipv4Addr>>,
        reads: Cell<usize>,
        fail: Option<&'static str>,
        change_final: bool,
    }
    impl ShutdownIo for Io {
        fn identity(&self) -> Result<Pin> {
            if self.change_final && self.reads.get() > 1 {
                return Ok(Pin::Windows {
                    name: "owned".into(),
                    index: 2,
                    guid: "f".repeat(32),
                    luid: 3,
                });
            }
            Ok(self.pin.borrow().clone())
        }
        fn addresses(&self) -> Result<Vec<IpAddr>> {
            self.reads.set(self.reads.get() + 1);
            ensure!(self.fail != Some("read"), "injected native read");
            Ok(self.addresses.borrow().clone())
        }
        fn remove(&self, own: Ipv4Addr) -> Result<()> {
            ensure!(self.fail != Some("remove"), "injected native remove");
            self.removed.borrow_mut().push(own);
            self.addresses
                .borrow_mut()
                .retain(|ip| *ip != IpAddr::V4(own));
            Ok(())
        }
        fn end_session(&self) -> Result<()> {
            ensure!(self.fail != Some("session"), "injected native session end");
            Ok(())
        }
    }
    fn io() -> Io {
        Io {
            pin: RefCell::new(Pin::Windows {
                name: "owned".into(),
                index: 2,
                guid: "a".repeat(32),
                luid: 3,
            }),
            addresses: RefCell::new(vec![
                "10.2.0.2".parse().unwrap(),
                "192.168.1.9".parse().unwrap(),
            ]),
            removed: Default::default(),
            reads: Cell::new(0),
            fail: None,
            change_final: false,
        }
    }
    #[test]
    fn source_stop_removes_only_owned_address_and_preserves_foreign() {
        let io = io();
        stop_checked(&io, &io.pin.borrow(), "10.2.0.2".parse().unwrap()).unwrap();
        assert_eq!(
            *io.removed.borrow(),
            vec!["10.2.0.2".parse::<Ipv4Addr>().unwrap()]
        );
        assert_eq!(
            *io.addresses.borrow(),
            vec!["192.168.1.9".parse::<IpAddr>().unwrap()]
        );
    }
    #[test]
    fn wrong_guid_luid_or_index_never_mutates() {
        for n in 0..3 {
            let io = io();
            let mut pin = io.pin.borrow().clone();
            if let Pin::Windows {
                guid, luid, index, ..
            } = &mut pin
            {
                match n {
                    0 => *guid = "b".repeat(32),
                    1 => *luid = 8,
                    _ => *index = 9,
                }
            }
            assert!(stop_checked(&io, &pin, "10.2.0.2".parse().unwrap()).is_err());
            assert!(io.removed.borrow().is_empty());
        }
    }
    #[test]
    fn native_errors_and_post_read_identity_change_never_acknowledge() {
        for failure in ["read", "remove", "session"] {
            let mut io = io();
            io.fail = Some(failure);
            assert!(stop_checked(&io, &io.pin.borrow(), "10.2.0.2".parse().unwrap()).is_err());
        }
        let mut io = io();
        io.change_final = true;
        assert!(stop_checked(&io, &io.pin.borrow(), "10.2.0.2".parse().unwrap()).is_err());
    }
    #[test]
    fn actual_owner_release_runs_drop_even_when_native_stop_fails() {
        struct Owner(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Owner {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let owner = std::sync::Arc::new(Owner(dropped.clone()));
        assert!(
            release_owner(owner, |_| anyhow::bail!("injected native shutdown failure")).is_err()
        );
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        let owner = std::sync::Arc::new(Owner(dropped));
        let retained = owner.clone();
        assert!(release_owner(owner, |_| Ok(())).is_err());
        drop(retained);
    }
    #[test]
    fn renamed_or_reused_interface_index_is_not_native_absence() {
        assert!(interface_absence(None, 22, true).is_err());
        assert!(interface_absence(Some(22), 22, true).is_err());
        assert!(interface_absence(Some(23), 22, false).is_err());
        assert!(interface_absence(None, 22, false).is_ok());
    }
    #[cfg(unix)]
    #[test]
    fn foreign_platform_pin_is_rejected_before_native_absence_query() {
        let pin = Pin::Windows {
            name: "owned".into(),
            index: 2,
            guid: "a".repeat(32),
            luid: 3,
        };
        assert!(verify_absent(&pin, "10.2.0.2".parse().unwrap()).is_err());
    }
}
