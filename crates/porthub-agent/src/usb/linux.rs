//! Linux USB/IP kernel handoff. Only selected devices are detached; no usbipd is started.
use anyhow::{ensure, Context, Result};
use porthub_components::usb::{valid_busid, Device};
use std::{
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};
fn value(path: &Path, name: &str) -> String {
    std::fs::read_to_string(path.join(name))
        .unwrap_or_default()
        .trim()
        .chars()
        .take(256)
        .collect()
}
fn speed(v: &str) -> Option<u32> {
    match v {
        "1.5" => Some(1),
        "12" => Some(2),
        "480" => Some(3),
        "5000" => Some(5),
        "10000" | "20000" => Some(6),
        _ => None,
    }
}
pub(super) fn inventory() -> Vec<Device> {
    inventory_at(Path::new("/sys"))
}
fn inventory_at(sys: &Path) -> Vec<Device> {
    let Ok(entries) = std::fs::read_dir(sys.join("bus/usb/devices")) else {
        return vec![];
    };
    let mut devices = Vec::new();
    for entry in entries.flatten() {
        let busid = entry.file_name().to_string_lossy().to_string();
        if !valid_busid(&busid) {
            continue;
        }
        let path = entry.path();
        let Ok(real) = std::fs::canonicalize(&path) else {
            continue;
        };
        if real
            .components()
            .any(|c| c.as_os_str().to_string_lossy().starts_with("vhci_hcd"))
        {
            continue;
        }
        let Some(speed) = speed(&value(&path, "speed")) else {
            continue;
        };
        let (Ok(busnum), Ok(devnum)) = (
            value(&path, "busnum").parse(),
            value(&path, "devnum").parse(),
        ) else {
            continue;
        };
        let mut blocked = None;
        if value(&path, "bDeviceClass") == "09" {
            continue; // Enumerate attached devices individually; USB/IP cannot export hubs.
        }
        // Never detach an active network interface or any mounted block device.
        if let Ok(net) = std::fs::read_dir(sys.join("class/net")) {
            for n in net.flatten() {
                if std::fs::canonicalize(n.path().join("device"))
                    .is_ok_and(|p| p.starts_with(&real))
                    && value(&n.path(), "operstate") == "up"
                {
                    blocked = Some("Active network interface".into());
                }
            }
        }
        let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        if let Ok(disks) = std::fs::read_dir(sys.join("class/block")) {
            for disk in disks.flatten() {
                if std::fs::canonicalize(disk.path()).is_ok_and(|p| p.starts_with(&real)) {
                    let dev = value(&disk.path(), "dev");
                    if mounts
                        .lines()
                        .any(|l| l.split_whitespace().nth(2) == Some(dev.as_str()))
                    {
                        blocked = Some("Mounted storage device".into());
                    }
                }
            }
        }
        let manufacturer = value(&path, "manufacturer");
        let product_name = value(&path, "product");
        let device = Device {
            busid,
            vendor: value(&path, "idVendor"),
            product: value(&path, "idProduct"),
            serial: value(&path, "serial"),
            name: format!("{manufacturer} {product_name}")
                .trim()
                .chars()
                .take(256)
                .collect(),
            busnum,
            devnum,
            speed,
            blocked,
        };
        if device.valid() {
            devices.push(device)
        }
        if devices.len() >= 128 {
            break;
        }
    }
    devices.sort_by(|a, b| a.busid.cmp(&b.busid));
    devices
}
pub(super) async fn module(source: bool) -> Result<()> {
    let name = if source { "usbip_host" } else { "vhci_hcd" };
    let loaded = if source {
        Path::new("/sys/bus/usb/drivers/usbip-host").exists()
    } else {
        Path::new("/sys/devices/platform/vhci_hcd.0/attach").exists()
    };
    if loaded {
        return Ok(());
    }
    let executable = ["/usr/sbin/modprobe", "/sbin/modprobe"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .context("Install Linux USB/IP kernel modules (modprobe is missing)")?;
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new(executable)
            .args(["-q", name])
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    ensure!(
        output.status.success(),
        "Cannot load {name}; install matching Linux kernel USB/IP modules and use the system agent"
    );
    Ok(())
}
fn write(path: impl AsRef<Path>, value: impl AsRef<[u8]>) -> Result<()> {
    std::fs::write(path.as_ref(), value)
        .with_context(|| format!("USB kernel operation failed: {}", path.as_ref().display()))
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Claim {
    device: Device,
}
fn journal(profile: &Path, busid: &str) -> PathBuf {
    crate::profile::sibling(profile, &format!(".usb-{busid}.json"))
}
pub(super) fn recover(profile: &Path) {
    let Some(parent) = profile.parent() else {
        return;
    };
    let Some(stem) = profile.file_name().and_then(|s| s.to_str()) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    // sibling() uses the profile stem, rather than trusting arbitrary device paths from disk.
    let marker = crate::profile::sibling(profile, ".usb-");
    let prefix = marker.file_name().unwrap().to_string_lossy().to_string();
    let _ = stem;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(&prefix) || !name.ends_with(".json") {
            continue;
        }
        if let Ok(bytes) = crate::profile::read_private(&path) {
            if let Ok(claim) = serde_json::from_slice::<Claim>(&bytes) {
                if claim.device.valid() && journal(profile, &claim.device.busid) == path {
                    restore(&claim.device);
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }
}
fn restore(device: &Device) {
    let Some(current) = inventory()
        .into_iter()
        .find(|d| d.busid == device.busid && d.same_device(device))
    else {
        return;
    };
    let path = Path::new("/sys/bus/usb/devices").join(&current.busid);
    if std::fs::read_link(path.join("driver"))
        .ok()
        .and_then(|p| p.file_name().map(|s| s.to_owned()))
        .is_some_and(|p| p == "usbip-host")
    {
        let _ = write(path.join("usbip_sockfd"), b"-1");
        let _ = write(
            "/sys/bus/usb/drivers/usbip-host/unbind",
            current.busid.as_bytes(),
        );
    }
    let _ = write(
        "/sys/bus/usb/drivers/usbip-host/match_busid",
        format!("del {}", current.busid),
    );
    let _ = write("/sys/bus/usb/drivers_probe", current.busid.as_bytes());
    // Preparation may fail after detaching an interface but before exporting.
    if let Ok(entries) = std::fs::read_dir(&path) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(&format!("{}:", current.busid))
                && !entry.path().join("driver").exists()
            {
                let _ = write(
                    "/sys/bus/usb/drivers_probe",
                    entry.file_name().as_encoded_bytes(),
                );
            }
        }
    }
}
pub(super) struct Handoff {
    pub kernel: std::net::TcpStream,
    device: Option<Device>,
    journal: Option<PathBuf>,
    port: Option<u32>,
}
impl Drop for Handoff {
    fn drop(&mut self) {
        let _ = self.kernel.shutdown(std::net::Shutdown::Both);
        if let Some(port) = self.port {
            let _ = write("/sys/devices/platform/vhci_hcd.0/detach", port.to_string());
        }
        if let Some(device) = &self.device {
            restore(device);
        }
        if let Some(path) = &self.journal {
            let _ = std::fs::remove_file(path);
        }
    }
}
// A UAS controller can retain stream state after its driver is detached. Reset
// the selected, unmounted device before exporting its bulk-only alternate mode.
fn prepare_storage(path: &Path, device: &Device) -> Result<()> {
    let descriptors = std::fs::read(path.join("descriptors"))?;
    let mut bulk_interfaces = Vec::new();
    let mut offset = 0;
    while offset + 2 <= descriptors.len() {
        let len = descriptors[offset] as usize;
        if len < 2 || offset + len > descriptors.len() {
            break;
        }
        let d = &descriptors[offset..offset + len];
        if len >= 9 && d[1] == 4 && d[3] == 0 && d[5] == 8 && d[7] == 0x50 {
            bulk_interfaces.push(d[2] as u32);
        }
        offset += len;
    }
    let interfaces: Vec<_> = std::fs::read_dir(path)?
        .flatten()
        .map(|entry| entry.path())
        .filter(|p| value(p, "bInterfaceClass") == "08" && value(p, "bInterfaceProtocol") == "62")
        .filter_map(|p| {
            u32::from_str_radix(&value(&p, "bInterfaceNumber"), 16)
                .ok()
                .map(|n| (p, n))
        })
        .filter(|(_, n)| bulk_interfaces.contains(n))
        .collect();
    if interfaces.is_empty() {
        return Ok(());
    }
    let unbind = || -> Result<()> {
        for (interface, _) in &interfaces {
            if interface.join("driver").exists() {
                write(
                    interface.join("driver/unbind"),
                    interface.file_name().unwrap().as_encoded_bytes(),
                )?;
            }
        }
        Ok(())
    };
    let usb = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!(
            "/dev/bus/usb/{:03}/{:03}",
            device.busnum, device.devnum
        ))?;
    unbind()?;
    // USBDEVFS_RESET, CLAIMINTERFACE, SETINTERFACE and RELEASEINTERFACE.
    if unsafe { libc::ioctl(usb.as_raw_fd(), 0x5514, 0) } < 0 {
        return Err(std::io::Error::last_os_error()).context("Reset USB storage before export");
    }
    unbind()?;
    for (_, number) in &interfaces {
        if unsafe { libc::ioctl(usb.as_raw_fd(), 0x8004550fu32 as _, number) } < 0 {
            return Err(std::io::Error::last_os_error()).context("Claim USB storage interface");
        }
        let alternate = [*number, 0u32];
        let result =
            unsafe { libc::ioctl(usb.as_raw_fd(), 0x80085504u32 as _, alternate.as_ptr()) };
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::ioctl(usb.as_raw_fd(), 0x80045510u32 as _, number);
        }
        if result < 0 {
            return Err(error).context("Select USB bulk storage interface");
        }
    }
    Ok(())
}

pub(super) fn handoff(
    profile: &Path,
    device: &Device,
    source: bool,
) -> Result<(Handoff, tokio::net::TcpStream)> {
    ensure!(device.valid(), "Invalid USB device");
    // The kernel requires a TCP socket, so bridge over a private loopback pair.
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let kernel = std::net::TcpStream::connect(listener.local_addr()?)?;
    let (proxy, remote) = listener.accept()?;
    ensure!(
        remote == kernel.local_addr()?,
        "USB loopback socket ownership mismatch"
    );
    kernel.set_nodelay(true)?;
    proxy.set_nodelay(true)?;
    proxy.set_nonblocking(true)?;
    let proxy = tokio::net::TcpStream::from_std(proxy)?;
    let mut guard = Handoff {
        kernel,
        device: None,
        journal: None,
        port: None,
    };
    if source {
        let current = inventory()
            .into_iter()
            .find(|d| d.same_device(device))
            .context("The selected USB device is unplugged or has changed identity")?;
        ensure!(
            current.blocked.is_none(),
            "{}",
            current.blocked.as_deref().unwrap_or("Device unavailable")
        );
        ensure!(
            current.busnum == device.busnum
                && current.devnum == device.devnum
                && current.speed == device.speed,
            "USB device was re-enumerated; waiting for updated inventory"
        );
        let path = Path::new("/sys/bus/usb/devices").join(&device.busid);
        ensure!(
            !path.join("usbip_sockfd").exists(),
            "USB device is already owned by another exporter"
        );
        let journal = journal(profile, &device.busid);
        crate::profile::write_private(
            &journal,
            &serde_json::to_vec(&Claim {
                device: current.clone(),
            })?,
            true,
        )?;
        guard.device = Some(current);
        guard.journal = Some(journal);
        prepare_storage(&path, device)?;
        write(
            "/sys/bus/usb/drivers/usbip-host/match_busid",
            format!("add {}", device.busid),
        )?;
        if path.join("driver").exists() {
            write(path.join("driver/unbind"), device.busid.as_bytes())?;
        }
        write(
            "/sys/bus/usb/drivers/usbip-host/bind",
            device.busid.as_bytes(),
        )?;
        write(
            path.join("usbip_sockfd"),
            guard.kernel.as_raw_fd().to_string(),
        )?;
    } else {
        let status = std::fs::read_to_string("/sys/devices/platform/vhci_hcd.0/status")?;
        let port = free_port(&status, device.speed).context("No free USB/IP virtual port")?;
        let devid = ((device.busnum as u32) << 16) | device.devnum as u32;
        let attach = |speed| {
            write(
                "/sys/devices/platform/vhci_hcd.0/attach",
                format!("{port} {} {devid} {speed}", guard.kernel.as_raw_fd()),
            )
        };
        attach_compatible(device.speed, attach)?;
        guard.port = Some(port);
    }
    Ok((guard, proxy))
}
fn attach_compatible(speed: u32, attach: impl Fn(u32) -> Result<()>) -> Result<()> {
    if let Err(error) = attach(speed) {
        // Older vhci kernels reject SuperSpeedPlus but support SuperSpeed.
        if speed == 6
            && error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.raw_os_error() == Some(libc::EINVAL))
        {
            attach(5)?;
        } else {
            return Err(error);
        }
    }
    Ok(())
}
fn free_port(status: &str, speed: u32) -> Option<u32> {
    status
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 3
                || fields[0] != if speed >= 5 { "ss" } else { "hs" }
                || fields[2] != "004"
            {
                return None;
            }
            fields[1].parse().ok()
        })
        .next()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn speed_fallback_only_retries_unsupported_superspeed_plus() {
        use std::cell::RefCell;
        for (speed, errno, expected) in [
            (6, libc::EINVAL, vec![6, 5]),
            (5, libc::EINVAL, vec![5]),
            (6, libc::EBUSY, vec![6]),
            (6, libc::EACCES, vec![6]),
        ] {
            let attempts = RefCell::new(Vec::new());
            let result = attach_compatible(speed, |value| {
                attempts.borrow_mut().push(value);
                if attempts.borrow().len() == 1 {
                    Err(std::io::Error::from_raw_os_error(errno).into())
                } else {
                    Ok(())
                }
            });
            assert_eq!(*attempts.borrow(), expected);
            assert_eq!(result.is_ok(), expected.len() == 2);
        }
    }
    #[test]
    fn virtual_port_matches_speed_and_is_free() {
        let status="hub port sta spd dev sockfd local_busid\nhs 0000 006 003 00010002 1 1-2\nhs 0001 004 000 00000000 0 0-0\nss 0008 004 000 00000000 0 0-0\n";
        assert_eq!(free_port(status, 3), Some(1));
        assert_eq!(free_port(status, 5), Some(8));
        assert_eq!(speed("5000"), Some(5));
    }
}
