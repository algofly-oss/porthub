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
fn inventory_at(sys: &Path) -> Vec<Device> { inventory_scan(sys,false,None,None) }
fn inventory_scan(sys: &Path, imported: bool, selected: Option<&str>, mounts: Option<&str>) -> Vec<Device> {
    let Ok(entries) = std::fs::read_dir(sys.join("bus/usb/devices")) else {
        return vec![];
    };
    let mut devices = Vec::new();
    for entry in entries.flatten() {
        let busid = entry.file_name().to_string_lossy().to_string();
        if !valid_busid(&busid) || selected.is_some_and(|selected|selected!=busid) {
            continue;
        }
        let path = entry.path();
        let Ok(real) = std::fs::canonicalize(&path) else {
            continue;
        };
        if !imported && real
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
        let fallback_mounts;
        let mounts = if let Some(mounts)=mounts {mounts} else {fallback_mounts=std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();&fallback_mounts};
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
        let mut manufacturer = value(&path, "manufacturer");
        let mut product_name = value(&path, "product");
        if product_name.is_empty() {
            let dev = value(&path, "dev");
            if let Some((major, minor)) = dev.split_once(':').and_then(|(a, b)| {
                Some((a.parse::<u32>().ok()?, b.parse::<u32>().ok()?))
            }) {
                if let Ok(record) = std::fs::read_to_string(format!("/run/udev/data/c{major}:{minor}")) {
                    for line in record.lines() {
                        if let Some(model) = line.strip_prefix("E:ID_MODEL_FROM_DATABASE=") {
                            product_name = model.to_owned();
                        }
                        if manufacturer.is_empty() {
                            if let Some(vendor) = line.strip_prefix("E:ID_VENDOR_FROM_DATABASE=") {
                                manufacturer = vendor.to_owned();
                            }
                        }
                    }
                }
            }
        }
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
fn physical_at_port(sys: &Path, busid: &str, expected: &Device, mounts: &str) -> Option<Device> {
    inventory_scan(sys, false, Some(busid), Some(mounts))
        .into_iter()
        .find(|d| d.same_device(expected))
}
fn available(device: Device) -> Result<Device> {
    ensure!(
        device.blocked.is_none(),
        "{}",
        device
            .blocked
            .as_deref()
            .unwrap_or("USB device unavailable")
    );
    Ok(device)
}
pub(super) fn resolve_physical(expected: &Device) -> Result<Device> {
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    resolve_physical_at(Path::new("/sys"), expected, &mounts)
}
fn resolve_physical_at(sys: &Path, expected: &Device, mounts: &str) -> Result<Device> {
    ensure!(
        expected.valid() && !expected.busid.starts_with("0-"),
        "Invalid physical USB identity"
    );
    std::fs::read_dir(sys.join("class/net"))?;
    std::fs::read_dir(sys.join("class/block"))?;
    if let Some(device) = physical_at_port(sys, &expected.busid, expected, mounts) {
        return available(device);
    }
    ensure!(
        !expected.serial.is_empty(),
        "USB device unplugged or changed"
    );
    let mut selected = None;
    for (count, entry) in std::fs::read_dir(sys.join("bus/usb/devices"))?.enumerate() {
        ensure!(
            count < 4096,
            "USB identity search exceeds bounded inventory"
        );
        let entry = entry?;
        let busid = entry.file_name().to_string_lossy().into_owned();
        if !valid_busid(&busid) {
            continue;
        }
        let path = std::fs::canonicalize(entry.path())?;
        if path
            .components()
            .any(|p| p.as_os_str().to_string_lossy().starts_with("vhci_hcd"))
        {
            continue;
        }
        // Do not read unrelated manufacturers/names to find one fingerprint.
        let attribute = |name: &str| -> Result<String> {
            let text = std::fs::read_to_string(path.join(name))?;
            let text = text.trim();
            ensure!(text.len() <= 256, "USB identity attribute exceeds bounds");
            Ok(text.to_owned())
        };
        if attribute("idVendor")? != expected.vendor || attribute("idProduct")? != expected.product
        {
            continue;
        }
        if attribute("serial")? != expected.serial {
            continue;
        }
        ensure!(selected.is_none(), "Ambiguous serialized USB device");
        selected = Some(busid);
    }
    let busid = selected.context("USB device unplugged or changed")?;
    available(
        physical_at_port(sys, &busid, expected, mounts)
            .context("USB device changed during selection")?,
    )
}
fn exact_physical(expected: &Device) -> Result<Device> {
    let sys = Path::new("/sys");
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    std::fs::read_dir(sys.join("class/net"))?;
    std::fs::read_dir(sys.join("class/block"))?;
    available(
        physical_at_port(sys, &expected.busid, expected, &mounts)
            .context("Selected USB port changed identity")?,
    )
}

fn selected_physical_device(device: &Device) -> Option<Device> {
    inventory_scan(Path::new("/sys"), false, Some(&device.busid), None)
        .into_iter()
        .find(|current| current.same_device(device))
}
fn restore(device: &Device) {
    let Some(current) = selected_physical_device(device)
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
fn imported_busid(status:&str,port:u32,device:&Device)->Result<String> {
    let remote=((device.busnum as u32)<<16)|device.devnum as u32;
    let rows:Vec<_>=status.lines().filter_map(|line|{let fields:Vec<_>=line.split_whitespace().collect();(fields.len()>=7&&fields[1].parse::<u32>().ok()==Some(port)).then_some(fields)}).collect();
    ensure!(rows.len()==1,"Imported USB port identity is unavailable");let row=&rows[0];
    ensure!(row[2]=="006"&&u32::from_str_radix(row[4],16).ok()==Some(remote)&&valid_busid(row[6])&&row[6]!="0-0","Imported USB device is not ready or changed identity");
    Ok(row[6].into())
}
fn relay_interface_policy(path:&Path,busid:&str)->Result<()> {
    let mut classes=Vec::new();
    for item in std::fs::read_dir(path)? {
        let item=item?;
        if item.file_name().to_string_lossy().starts_with(&format!("{busid}:")) {
            let class=std::fs::read_to_string(item.path().join("bInterfaceClass"))?;
            classes.push(u8::from_str_radix(class.trim(),16)?);
        }
    }
    ensure!(!classes.is_empty(),"Imported USB interfaces are not ready");
    // Checking mounts alone leaves a race before the parent drops its VHCI
    // consumer. Storage needs held exclusive block-device leases before an
    // onward handoff can safely be offered. Keep that unsupported for now.
    ensure!(!classes.contains(&8),"Imported storage cannot be forwarded onward until exclusive volume protection is supported");
    ensure!(classes.iter().all(|class|matches!(class,1|3)),"Onward forwarding currently supports imported audio and HID devices only");
    Ok(())
}
pub(super) fn relay_import(port:u32,expected:&Device)->Result<Device> {
    let status=std::fs::read_to_string("/sys/devices/platform/vhci_hcd.0/status")?;
    let busid=imported_busid(&status,port,expected)?;
    let path=std::fs::canonicalize(Path::new("/sys/bus/usb/devices").join(&busid))?;
    ensure!(path.components().any(|c|c.as_os_str().to_string_lossy().starts_with("vhci_hcd")),"Selected device is not the owned USB import");
    relay_interface_policy(&path,&busid)?;
    // Unknown topology/mount state is never permission to detach storage.
    let mounts=std::fs::read_to_string("/proc/self/mountinfo")?;
    std::fs::read_dir("/sys/class/block")?;std::fs::read_dir("/sys/class/net")?;
    let actual=inventory_scan(Path::new("/sys"),true,Some(&busid),Some(&mounts)).into_iter().next().context("Imported USB device is unavailable")?;
    ensure!(actual.vendor==expected.vendor&&actual.product==expected.product&&actual.serial==expected.serial,"Imported USB fingerprint changed");
    ensure!(actual.blocked.is_none(),"{}",actual.blocked.as_deref().unwrap_or("Imported USB cannot be forwarded"));
    let latest=std::fs::read_to_string("/sys/devices/platform/vhci_hcd.0/status")?;
    ensure!(imported_busid(&latest,port,expected)?==busid,"USB import changed during ownership verification");
    Ok(actual)
}
pub(super) struct Handoff {
    pub kernel: std::net::TcpStream,
    device: Option<Device>,
    journal: Option<PathBuf>,
    port: Option<u32>,
}
impl Handoff { pub(super) fn virtual_port(&self)->Option<u32>{self.port} }
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
fn prepare_storage(
    path: &Path,
    device: &Device,
    claim: &super::native_probe::ClaimPermit,
) -> Result<()> {
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
                claim.check()?;
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
    claim.check()?;
    unbind()?;
    // USBDEVFS_RESET, CLAIMINTERFACE, SETINTERFACE and RELEASEINTERFACE.
    claim.check()?;
    if unsafe { libc::ioctl(usb.as_raw_fd(), 0x5514, 0) } < 0 {
        return Err(std::io::Error::last_os_error()).context("Reset USB storage before export");
    }
    unbind()?;
    for (_, number) in &interfaces {
        claim.check()?;
        if unsafe { libc::ioctl(usb.as_raw_fd(), 0x8004550fu32 as _, number) } < 0 {
            return Err(std::io::Error::last_os_error()).context("Claim USB storage interface");
        }
        let alternate = [*number, 0u32];
        let result = claim.check().and_then(|()| {
            if unsafe { libc::ioctl(usb.as_raw_fd(), 0x80085504u32 as _, alternate.as_ptr()) } < 0 {
                Err(std::io::Error::last_os_error()).context("Select USB bulk storage interface")
            } else {
                Ok(())
            }
        });
        unsafe {
            libc::ioctl(usb.as_raw_fd(), 0x80045510u32 as _, number);
        }
        result?;
    }
    Ok(())
}

pub(super) fn handoff(
    profile: &Path,
    device: &Device,
    source: bool,
) -> Result<(Handoff, tokio::net::TcpStream)> {
    ensure!(!source, "Physical USB source requires live claim authority");
    handoff_checked(profile, device, false, None)
}
pub(super) fn handoff_source(
    profile: &Path,
    device: &Device,
    claim: &super::native_probe::ClaimPermit,
) -> Result<(Handoff, tokio::net::TcpStream)> {
    handoff_checked(profile, device, true, Some(claim))
}
fn handoff_checked(
    profile: &Path,
    device: &Device,
    source: bool,
    claim: Option<&super::native_probe::ClaimPermit>,
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
        let claim = claim.context("Live USB source claim missing")?;
        claim.after_preflight(
            || exact_physical(device),
            |current| {
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
                prepare_storage(&path, device, claim)?;
                claim.check()?;
                write(
                    "/sys/bus/usb/drivers/usbip-host/match_busid",
                    format!("add {}", device.busid),
                )?;
                if path.join("driver").exists() {
                    claim.check()?;
                    write(path.join("driver/unbind"), device.busid.as_bytes())?;
                }
                claim.check()?;
                write(
                    "/sys/bus/usb/drivers/usbip-host/bind",
                    device.busid.as_bytes(),
                )?;
                claim.check()?;
                write(
                    path.join("usbip_sockfd"),
                    guard.kernel.as_raw_fd().to_string(),
                )?;
                Ok(())
            },
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
    fn onward_policy_requires_proven_audio_or_hid_and_never_storage() -> Result<()> {
        let dir=tempfile::tempdir()?;let path=dir.path();
        assert!(relay_interface_policy(path,"5-1").is_err());
        std::fs::create_dir(path.join("5-1:1.0"))?;
        let class=path.join("5-1:1.0/bInterfaceClass");
        for (value,supported) in [("01",true),("03",true),("08",false),("ff",false),("02",false)] {
            std::fs::write(&class,value)?;assert_eq!(relay_interface_policy(path,"5-1").is_ok(),supported);
        }
        std::fs::write(&class,"01")?;std::fs::create_dir(path.join("5-1:1.1"))?;
        std::fs::write(path.join("5-1:1.1/bInterfaceClass"),"08")?;
        assert!(relay_interface_policy(path,"5-1").unwrap_err().to_string().contains("exclusive volume"));
        Ok(())
    }
    #[test]
    fn relay_port_identity_requires_unique_ready_exact_kernel_device() {
        let device=Device{busid:"2-7".into(),vendor:"1377".into(),product:"1100".into(),serial:"fixture".into(),name:"Mic".into(),busnum:2,devnum:7,speed:3,blocked:None};
        let row="hs 0001 006 003 00020007 1 5-1\n";
        assert_eq!(imported_busid(row,1,&device).unwrap(),"5-1");
        for invalid in [row.replace("006","005"),row.replace("00020007","00020008"),row.replace("5-1","0-0"),format!("{row}{row}"),row.replace("0001","0002")] {
            assert!(imported_busid(&invalid,1,&device).is_err(),"Unsafe status accepted: {invalid}");
        }
    }
    #[test]
    fn selected_physical_bus_preserves_mounted_disk_guard() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let sys = dir.path();
        let devices = sys.join("bus/usb/devices");
        for (busid, devnum) in [("1-1", "1"), ("1-2", "2")] {
            let path = devices.join(busid);
            std::fs::create_dir_all(&path)?;
            for (name, value) in [("speed", "480"), ("busnum", "1"), ("devnum", devnum),
                ("idVendor", "0781"), ("idProduct", "5583"), ("serial", "duplicate")] {
                std::fs::write(path.join(name), value)?;
            }
        }
        let block = devices.join("1-2/block/sdz");
        std::fs::create_dir_all(&block)?;
        std::fs::write(block.join("dev"), "8:96")?;
        std::fs::create_dir_all(sys.join("class/block"))?;
        std::os::unix::fs::symlink(block, sys.join("class/block/sdz"))?;
        let selected = inventory_scan(sys, false, Some("1-2"),
            Some("42 1 8:96 / /mnt/test rw - ext4 /dev/sdz rw"));
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].busid, "1-2");
        assert_eq!(selected[0].blocked.as_deref(), Some("Mounted storage device"));
        Ok(())
    }

    #[test]
    fn targeted_virtual_inventory_retains_storage_and_network_safety_guards() -> Result<()> {
        use std::os::unix::fs::symlink;
        let dir=tempfile::tempdir()?;let sys=dir.path();
        let real=sys.join("devices/platform/vhci_hcd.0/usb5/5-1");
        for path in [sys.join("bus/usb/devices"),sys.join("class/block"),sys.join("class/net"),real.join("block/sdz")] {std::fs::create_dir_all(path)?;}
        for (name,value) in [("speed","480"),("busnum","5"),("devnum","1"),("bDeviceClass","00"),("idVendor","1377"),("idProduct","1100"),("serial","fixture"),("product","Mic")] {std::fs::write(real.join(name),value)?;}
        std::fs::write(real.join("block/sdz/dev"),"8:96")?;
        symlink(&real,sys.join("bus/usb/devices/5-1"))?;
        symlink(real.join("block/sdz"),sys.join("class/block/sdz"))?;
        assert!(inventory_at(sys).is_empty(),"Ordinary inventory must still hide VHCI imports");
        let blocked=inventory_scan(sys,true,Some("5-1"),Some("42 1 8:96 / /mnt/test rw - ext4 /dev/sdz rw"));
        assert_eq!(blocked[0].blocked.as_deref(),Some("Mounted storage device"));
        assert!(inventory_scan(sys,true,Some("5-2"),Some("")).is_empty());
        assert!(inventory_scan(sys,true,Some("5-1"),Some(""))[0].blocked.is_none());
        let net=sys.join("class/net/test0");std::fs::create_dir_all(&net)?;std::fs::create_dir_all(real.join("5-1:1.0"))?;
        symlink(real.join("5-1:1.0"),net.join("device"))?;std::fs::write(net.join("operstate"),"up")?;
        assert_eq!(inventory_scan(sys,true,Some("5-1"),Some(""))[0].blocked.as_deref(),Some("Active network interface"));
        Ok(())
    }
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

#[cfg(test)]
mod physical_lookup_tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::{ffi::OsStrExt, fs::symlink};
    fn device(sys: &Path, bus: &str, serial: &str) -> Result<Device> {
        let p = sys.join("bus/usb/devices").join(bus);
        std::fs::create_dir_all(&p)?;
        std::fs::create_dir_all(sys.join("class/net"))?;
        std::fs::create_dir_all(sys.join("class/block"))?;
        let devnum = bus.split('-').nth(1).unwrap();
        for (name, value) in [
            ("speed", "480"),
            ("busnum", "1"),
            ("devnum", devnum),
            ("bDeviceClass", "00"),
            ("idVendor", "1377"),
            ("idProduct", "1100"),
            ("serial", serial),
            ("manufacturer", "Fixture"),
            ("product", "Mic"),
        ] {
            std::fs::write(p.join(name), value)?;
        }
        Ok(Device {
            busid: bus.into(),
            vendor: "1377".into(),
            product: "1100".into(),
            serial: serial.into(),
            name: "Fixture Mic".into(),
            busnum: 1,
            devnum: devnum.parse()?,
            speed: 3,
            blocked: None,
        })
    }
    #[test]
    fn exact_port_and_unique_replug_do_not_open_unrelated_manufacturer() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let sys = temp.path();
        let expected = device(sys, "1-2", "selected")?;
        device(sys, "1-3", "unrelated")?;
        let manufacturer = sys.join("bus/usb/devices/1-3/manufacturer");
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        ensure!(fd >= 0);
        let watcher = unsafe { std::fs::File::from_raw_fd(fd) };
        let name = std::ffi::CString::new(manufacturer.as_os_str().as_bytes())?;
        ensure!(
            unsafe { libc::inotify_add_watch(watcher.as_raw_fd(), name.as_ptr(), libc::IN_OPEN) }
                >= 0
        );
        assert_eq!(resolve_physical_at(sys, &expected, "")?.busid, "1-2");
        let mut replug = expected.clone();
        replug.busid = "1-9".into();
        assert_eq!(resolve_physical_at(sys, &replug, "")?.busid, "1-2");
        let mut events = [0u8; 128];
        assert_eq!(
            unsafe {
                libc::read(
                    watcher.as_raw_fd(),
                    events.as_mut_ptr().cast(),
                    events.len(),
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::WouldBlock
        );
        Ok(())
    }
    #[test]
    fn duplicate_serial_prefers_exact_port_but_replug_must_be_unique() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let sys = temp.path();
        let expected = device(sys, "1-2", "same")?;
        device(sys, "1-3", "same")?;
        assert_eq!(resolve_physical_at(sys, &expected, "")?.busid, "1-2");
        let mut moved = expected.clone();
        moved.busid = "1-9".into();
        assert!(resolve_physical_at(sys, &moved, "")
            .unwrap_err()
            .to_string()
            .contains("Ambiguous"));
        Ok(())
    }
    #[test]
    fn selected_lookup_preserves_mounted_and_active_network_denials() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let sys = temp.path();
        let expected = device(sys, "1-2", "selected")?;
        let physical = sys.join("bus/usb/devices/1-2");
        let block = physical.join("block/sdz");
        std::fs::create_dir_all(&block)?;
        std::fs::write(block.join("dev"), "8:96")?;
        symlink(&block, sys.join("class/block/sdz"))?;
        assert!(resolve_physical_at(
            sys,
            &expected,
            "42 1 8:96 / /mnt/test rw - ext4 /dev/sdz rw"
        )
        .unwrap_err()
        .to_string()
        .contains("Mounted"));
        std::fs::remove_file(sys.join("class/block/sdz"))?;
        let net = sys.join("class/net/fixture");
        std::fs::create_dir_all(&net)?;
        symlink(&physical, net.join("device"))?;
        std::fs::write(net.join("operstate"), "up")?;
        assert!(resolve_physical_at(sys, &expected, "")
            .unwrap_err()
            .to_string()
            .contains("Active network"));
        Ok(())
    }
}
