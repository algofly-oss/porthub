//! Private synthetic-class fixture identity guard. Never selects a camera by label.
//! SetupAPI only maps an existing symbolic interface to its present devnode; it
//! does not open/activate a capture endpoint or alter PnP state.
use anyhow::{ensure, Context, Result};
use std::collections::BTreeSet;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Node {
    pub id: String,
    pub service: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Proof {
    pub symbolic: String,
    pub nodes: Vec<Node>,
}
pub(super) fn valid_serial(serial: &str) -> bool {
    serial
        .strip_prefix("PortHubPrivateUvc")
        .is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}
fn exact_ancestor(id: &str, serial: &str) -> bool {
    let parts = id.split('\\').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0].eq_ignore_ascii_case("USB")
        && parts[1].eq_ignore_ascii_case("VID_1209&PID_0001")
        && parts[2].eq_ignore_ascii_case(serial)
}
impl Proof {
    pub fn selected(&self, serial: &str) -> bool {
        valid_serial(serial)
            && !self.symbolic.is_empty()
            && self.symbolic.len() <= 1024
            && self.nodes.len() <= 16
            && self
                .nodes
                .iter()
                .any(|node| exact_ancestor(&node.id, serial))
            && self
                .nodes
                .iter()
                .any(|node| node.service.eq_ignore_ascii_case("usbvideo"))
    }
    pub fn verify(&self, current: &Self, serial: &str) -> Result<()> {
        ensure!(
            self.selected(serial) && self == current,
            "Owned synthetic camera ancestry changed"
        );
        Ok(())
    }
}
#[cfg(windows)]
pub(super) fn inspect(symbolic: &str) -> Result<Option<Proof>> {
    use windows_sys::Win32::{Devices::DeviceAndDriverInstallation::*, Foundation::GetLastError};
    ensure!(
        !symbolic.is_empty() && symbolic.len() <= 1024 && !symbolic.chars().any(char::is_control),
        "Invalid symbolic camera interface"
    );
    struct List(HDEVINFO);
    impl Drop for List {
        fn drop(&mut self) {
            unsafe {
                SetupDiDestroyDeviceInfoList(self.0);
            }
        }
    }
    let list = List(unsafe { SetupDiCreateDeviceInfoList(std::ptr::null(), std::ptr::null_mut()) });
    ensure!(list.0 != -1, "Camera metadata list unavailable");
    let wide = symbolic.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut interface: SP_DEVICE_INTERFACE_DATA = unsafe { std::mem::zeroed() };
    interface.cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
    if unsafe { SetupDiOpenDeviceInterfaceW(list.0, wide.as_ptr(), 0, &mut interface) } == 0 {
        let error = unsafe { GetLastError() };
        if [2, 433, 1167, 1168].contains(&error) {
            return Ok(None);
        }
        anyhow::bail!("Camera interface metadata unavailable ({error})");
    }
    let mut required = 0;
    let mut device: SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
    device.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;
    unsafe {
        SetupDiGetDeviceInterfaceDetailW(
            list.0,
            &interface,
            std::ptr::null_mut(),
            0,
            &mut required,
            std::ptr::null_mut(),
        );
    }
    ensure!(
        (8..=8192).contains(&required),
        "Camera interface detail exceeds bound"
    );
    let mut storage = vec![0u64; (required as usize + 7) / 8];
    unsafe {
        *(storage.as_mut_ptr() as *mut u32) = if cfg!(target_pointer_width = "64") {
            8
        } else {
            6
        };
    }
    ensure!(
        unsafe {
            SetupDiGetDeviceInterfaceDetailW(
                list.0,
                &interface,
                storage.as_mut_ptr().cast(),
                required,
                &mut required,
                &mut device,
            )
        } != 0,
        "Camera interface devnode unavailable"
    );
    let mut current = device.DevInst;
    let mut seen = BTreeSet::new();
    let mut nodes = Vec::new();
    for depth in 0..16 {
        ensure!(seen.insert(current), "Camera devnode ancestry cycle");
        let (mut flags, mut problem) = (0, 0);
        if unsafe { CM_Get_DevNode_Status(&mut flags, &mut problem, current, 0) } != CR_SUCCESS {
            return Ok(None);
        }
        if depth == 0 && (flags & DN_STARTED == 0 || problem != 0) {
            return Ok(None);
        }
        let mut id = [0u16; 512];
        if unsafe { CM_Get_Device_IDW(current, id.as_mut_ptr(), id.len() as u32, 0) } != CR_SUCCESS
        {
            return Ok(None);
        }
        let length = id
            .iter()
            .position(|v| *v == 0)
            .context("Unterminated camera devnode ID")?;
        let id = String::from_utf16(&id[..length])?;
        ensure!(
            !id.is_empty() && !id.chars().any(char::is_control),
            "Invalid camera ancestry ID"
        );
        let mut service = [0u16; 256];
        let (mut kind, mut length) = (0, (service.len() * 2) as u32);
        let result = unsafe {
            CM_Get_DevNode_Registry_PropertyW(
                current,
                CM_DRP_SERVICE,
                &mut kind,
                service.as_mut_ptr().cast(),
                &mut length,
                0,
            )
        };
        let service = if result == CR_SUCCESS {
            ensure!(
                kind == 1 && length >= 2 && length <= 512 && length % 2 == 0,
                "Invalid camera driver metadata"
            );
            let end = service
                .iter()
                .position(|v| *v == 0)
                .context("Unterminated camera driver service")?;
            String::from_utf16(&service[..end])?.to_ascii_lowercase()
        } else {
            String::new()
        };
        nodes.push(Node {
            id: id.to_ascii_uppercase(),
            service,
        });
        let mut parent = 0;
        if unsafe { CM_Get_Parent(&mut parent, current, 0) } != CR_SUCCESS {
            return Ok(Some(Proof {
                symbolic: symbolic.to_ascii_lowercase(),
                nodes,
            }));
        }
        current = parent;
    }
    anyhow::bail!("Camera ancestry exceeds16 nodes")
}
#[cfg(test)]
mod tests {
    use super::*;
    fn serial() -> String {
        format!("PortHubPrivateUvc{}", "1".repeat(32))
    }
    fn proof() -> Proof {
        Proof {
            symbolic: "synthetic-interface".into(),
            nodes: vec![
                Node {
                    id: "USB\\VID_1209&PID_0001&MI_00\\private-child".into(),
                    service: "usbvideo".into(),
                },
                Node {
                    id: format!("USB\\VID_1209&PID_0001\\{}", serial()),
                    service: "usbccgp".into(),
                },
            ],
        }
    }
    #[test]
    fn only_exact_private_serial_vid_pid_and_native_class_can_select() {
        let p = proof();
        assert!(p.selected(&serial()));
        for bad in [
            "PortHubPrivateUvc",
            "PhysicalCameraSerial",
            "PortHubPrivateUvc111",
        ] {
            assert!(!p.selected(bad));
        }
        for id in [
            "USB\\VID_1209&PID_00010\\bad",
            "USB\\VID_ffff&PID_0001\\bad",
        ] {
            let mut p = proof();
            p.nodes[1].id = id.into();
            assert!(!p.selected(&serial()));
        }
        let mut p = proof();
        p.nodes[0].service = "foreign-driver".into();
        assert!(!p.selected(&serial()));
    }
    #[test]
    fn replaced_or_reparented_interface_never_reuses_prior_capture_identity() {
        let p = proof();
        p.verify(&p, &serial()).unwrap();
        for field in 0..3 {
            let mut changed = p.clone();
            match field {
                0 => changed.symbolic.push('x'),
                1 => changed.nodes[0].id.push('x'),
                _ => changed.nodes[0].service = "other".into(),
            };
            assert!(p.verify(&changed, &serial()).is_err());
        }
    }
}
