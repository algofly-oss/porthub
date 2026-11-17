#[path = "asmedia.rs"]
mod asmedia;
use super::*;
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
};
// Inventory caches only a kernel sysfs-generation witness, never raw handles.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Binding {
    sysfs: PathBuf,
    sysfs_key: (u64, u64),
    rdev: u64,
    command_sysfs: PathBuf,
    command_key: (u64, u64),
    command_rdev: u64,
}
fn native_open(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "Native drive object unavailable".into())
}
fn key(path: &Path) -> Result<(u64, u64), String> {
    let m = std::fs::metadata(path).map_err(|_| "Native drive identity unavailable")?;
    Ok((m.dev(), m.ino()))
}
fn dev_number(path: &Path) -> Result<u64, String> {
    let v = value(path, "dev");
    let (major, minor) = v.split_once(':').ok_or("Native drive number unavailable")?;
    Ok(libc::makedev(
        major.parse().map_err(|_| "Invalid native drive major")?,
        minor.parse().map_err(|_| "Invalid native drive minor")?,
    ))
}
fn current_identity(device: &Device, sysfs: &Path) -> Result<Device, String> {
    let name = device
        .path
        .file_name()
        .ok_or("Native drive name missing")?
        .to_string_lossy();
    let base = sysfs.join("device");
    let mut model = value(&base, "model");
    let mut serial = value(&base, "serial");
    if device.protocol == "nvme" {
        let ctrl = Path::new("/sys/class/nvme").join(
            name.rsplit_once('n')
                .map(|(v, _)| v)
                .ok_or("Invalid NVMe namespace")?,
        );
        model = value(&ctrl, "model");
        serial = value(&ctrl, "serial");
    }
    if serial.is_empty() {
        serial = value(sysfs, "wwid");
    }
    let capacity = value(sysfs, "size")
        .parse::<u64>()
        .ok()
        .and_then(|v| v.checked_mul(512))
        .ok_or("Native drive capacity unavailable")?;
    let mut current = Device::new(
        device.path.clone(),
        &model,
        &serial,
        if device.protocol == "nvme_usb" {
            "ata"
        } else {
            &device.protocol
        },
        capacity,
    );
    current.protocol = device.protocol.clone();
    Ok(current)
}
fn held_node_matches(file: &File, path: &Path) -> Result<bool, String> {
    let held = file
        .metadata()
        .map_err(|_| "Held native object unavailable")?;
    let current = std::fs::symlink_metadata(path).map_err(|_| "Native node removed")?;
    Ok(!current.file_type().is_symlink()
        && (held.dev(), held.ino(), held.rdev()) == (current.dev(), current.ino(), current.rdev()))
}
impl Binding {
    #[cfg(test)]
    pub(super) fn test_generation(value: u64) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            sysfs: "/test/sysfs/drive".into(),
            sysfs_key: (1, value),
            rdev: 1,
            command_sysfs: "/test/sysfs/drive".into(),
            command_key: (1, value),
            command_rdev: 1,
        })
    }
    fn capture(device: &Device, sysfs: &Path) -> Result<Self, String> {
        let sysfs = std::fs::canonicalize(sysfs).map_err(|_| "Native sysfs object unavailable")?;
        let sysfs_key = key(&sysfs)?;
        let rdev = dev_number(&sysfs)?;
        let command_sysfs = if device.protocol == "nvme" {
            Path::new("/sys/class/nvme").join(
                controller(device)
                    .file_name()
                    .ok_or("NVMe controller missing")?,
            )
        } else {
            sysfs.clone()
        };
        let command_key = key(&command_sysfs)?;
        let command_rdev = dev_number(&command_sysfs)?;
        let binding = Self {
            sysfs,
            sysfs_key,
            rdev,
            command_sysfs,
            command_key,
            command_rdev,
        };
        binding.validate(device)?;
        Ok(binding)
    }
    fn validate(&self, expected: &Device) -> Result<(), String> {
        let current = std::fs::canonicalize(
            Path::new("/sys/class/block")
                .join(expected.path.file_name().ok_or("Drive name missing")?),
        )
        .map_err(|_| "Drive removed")?;
        if current != self.sysfs
            || key(&current)? != self.sysfs_key
            || dev_number(&current)? != self.rdev
            || !expected.same_identity(&current_identity(expected, &current)?)
        {
            return Err("Native drive identity changed".into());
        }
        if key(&self.command_sysfs)? != self.command_key
            || dev_number(&self.command_sysfs)? != self.command_rdev
        {
            return Err("Native controller generation changed".into());
        }
        if value(&current.join("device/power"), "runtime_status") == "suspended"
            || current.ancestors().any(|p| {
                std::fs::read_link(p.join("driver"))
                    .ok()
                    .is_some_and(|d| d.file_name().is_some_and(|n| n == "usbip-host"))
            })
        {
            return Err("Native drive sleeping or forwarded".into());
        }
        Ok(())
    }
}
struct Session<'a> {
    device: &'a Device,
    binding: &'a Binding,
    disk: File,
    command: File,
}
impl<'a> Session<'a> {
    fn open(device: &'a Device) -> Result<Self, String> {
        let binding = device
            .native
            .as_deref()
            .ok_or("Native inventory generation unavailable")?;
        binding.validate(device)?;
        let disk = native_open(&device.path)?;
        let command = if device.protocol == "nvme" {
            native_open(&controller(device))?
        } else {
            disk.try_clone().map_err(|_| "Cannot retain native disk")?
        };
        let session = Self {
            device,
            binding,
            disk,
            command,
        };
        session.validate()?;
        Ok(session)
    }
    fn validate(&self) -> Result<(), String> {
        self.binding.validate(self.device)?;
        if !held_node_matches(&self.disk, &self.device.path)?
            || !held_node_matches(&self.command, &controller_path(self.device))?
        {
            return Err("Native pathname no longer names held object".into());
        }
        let disk = self.disk.metadata().map_err(|_| "Native disk removed")?;
        let command = self
            .command
            .metadata()
            .map_err(|_| "Native controller removed")?;
        if !disk.file_type().is_block_device()
            || disk.rdev() != self.binding.rdev
            || command.rdev() != self.binding.command_rdev
        {
            return Err("Opened native drive object changed".into());
        }
        Ok(())
    }
}
fn value(path: &Path, name: &str) -> String {
    std::fs::read_to_string(path.join(name))
        .unwrap_or_default()
        .trim()
        .to_owned()
}
// Hyper-V/WSL VMBus disks expose virtual block storage, not a physical drive's
// native SMART controller. Classify by the kernel bus/driver, never model text.
fn virtual_disk_bus(path: &Path) -> bool {
    let Ok(path) = std::fs::canonicalize(path) else {
        return true;
    };
    path.ancestors().any(|p| {
        [("subsystem", "vmbus"), ("driver", "hv_storvsc")]
            .iter()
            .any(|(link, name)| {
                std::fs::read_link(p.join(link))
                    .ok()
                    .is_some_and(|target| target.file_name().is_some_and(|n| n == *name))
            })
    })
}
pub(super) fn inventory() -> Result<Inventory, String> {
    inventory_at(Path::new("/sys/class/block"))
}
fn inventory_at(root: &Path) -> Result<Inventory, String> {
    let entries = std::fs::read_dir(root).map_err(|_| "Physical inventory unavailable")?;
    let mut devices = Vec::new();
    let mut uncertain = HashSet::new();
    for entry in entries {
        let entry = entry.map_err(|_| "Incomplete physical inventory")?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if path.join("partition").exists()
            || !(name.starts_with("sd")
                || name.starts_with("hd")
                || name.starts_with("nvme")
                || name.starts_with("mmcblk"))
            || !path.join("device").exists()
            || virtual_disk_bus(&path)
        {
            continue;
        }
        let capacity = value(&path, "size")
            .parse::<u64>()
            .unwrap_or_default()
            .saturating_mul(512);
        if capacity == 0 {
            uncertain.insert(Path::new("/dev").join(&name));
            continue;
        }
        let base = path.join("device");
        let nvme = name.starts_with("nvme");
        let mut model = value(&base, "model");
        let mut serial = value(&base, "serial");
        if nvme {
            let controller = name.rsplit_once('n').map(|(v, _)| v).unwrap_or(&name);
            let ctrl = Path::new("/sys/class/nvme").join(controller);
            model = value(&ctrl, "model");
            serial = value(&ctrl, "serial");
        }
        if serial.is_empty() {
            serial = value(&path, "wwid");
        }
        let mut device = Device::new(
            Path::new("/dev").join(&name),
            &model,
            &serial,
            if nvme { "nvme" } else { "ata" },
            capacity,
        );
        // Keep legacy physical identity stable; only the reported protocol changes.
        if !nvme && asmedia::supported(&device.path) {
            device.protocol = "nvme_usb".into();
        }
        let stat = value(&path, "stat")
            .split_whitespace()
            .filter_map(|n| n.parse::<u64>().ok())
            .collect::<Vec<_>>();
        device.busy_counter = stat
            .get(2)
            .zip(stat.get(6))
            .map(|(r, w)| r.saturating_add(*w).saturating_mul(512));
        device.asleep = value(&base.join("power"), "runtime_status") == "suspended";
        device.in_use = std::fs::canonicalize(&path).ok().is_some_and(|p| {
            p.ancestors().any(|parent| {
                std::fs::read_link(parent.join("driver"))
                    .ok()
                    .and_then(|p| p.file_name().map(|s| s == "usbip-host"))
                    .unwrap_or(false)
            })
        });
        // Sleeping drives remain reportable without opening/waking their controller.
        if !device.asleep && !device.in_use {
            device.native = Binding::capture(&device, &path)
                .ok()
                .map(std::sync::Arc::new);
        }
        devices.push(device);
    }
    devices.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Inventory { devices, uncertain })
}
#[repr(C)]
#[derive(Default)]
struct Nvme {
    opcode: u8,
    flags: u8,
    reserved: u16,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    metadata: u64,
    addr: u64,
    metadata_len: u32,
    data_len: u32,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
    timeout_ms: u32,
    result: u32,
}
fn controller_path(device: &Device) -> PathBuf {
    if device.protocol == "nvme" {
        controller(device)
    } else {
        device.path.clone()
    }
}
fn controller(device: &Device) -> PathBuf {
    let name = device
        .path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    Path::new("/dev").join(name.rsplit_once('n').map(|(v, _)| v).unwrap_or(&name))
}
fn nvme_command(
    session: &Session<'_>,
    opcode: u8,
    cdw10: u32,
    data: &mut [u8],
    allowed: Option<&dyn Fn() -> bool>,
) -> Result<(), String> {
    session.validate()?;
    let file = &session.command;
    let mut cmd = Nvme {
        opcode,
        nsid: if opcode == 6 { 0 } else { u32::MAX },
        addr: data.as_mut_ptr() as u64,
        data_len: data.len() as u32,
        cdw10,
        timeout_ms: 2000,
        ..Default::default()
    };
    let code =
        0xc0000000u64 | ((std::mem::size_of::<Nvme>() as u64) << 16) | (b'N' as u64) << 8 | 0x41;
    if allowed.is_some_and(|check| !check()) {
        return Err("Short self-tests disabled locally".into());
    }
    if unsafe { libc::ioctl(file.as_raw_fd(), code as _, &mut cmd) } != 0 {
        return Err("NVMe SMART command unavailable".into());
    }
    Ok(())
}
#[repr(C)]
struct Sg {
    interface_id: i32,
    direction: i32,
    cmd_len: u8,
    sense_len: u8,
    iovec_count: u16,
    data_len: u32,
    data: *mut libc::c_void,
    cmd: *mut u8,
    sense: *mut u8,
    timeout: u32,
    flags: u32,
    pack_id: i32,
    user: *mut libc::c_void,
    status: u8,
    masked_status: u8,
    msg_status: u8,
    written_sense: u8,
    host_status: u16,
    driver_status: u16,
    resid: i32,
    duration: u32,
    info: u32,
}
fn ata_command(
    session: &Session<'_>,
    command: u8,
    feature: u8,
    lba: u8,
    data: &mut [u8],
    allowed: Option<&dyn Fn() -> bool>,
) -> Result<Vec<u8>, String> {
    // The file is read-only, including SMART EXECUTE OFFLINE: the sole non-read
    // operation permitted here is the device's non-destructive short self-test.
    session.validate()?;
    let file = &session.command;
    let mut cdb = [0u8; 16];
    cdb[0] = 0x85;
    cdb[1] = if data.is_empty() { 3 << 1 } else { 4 << 1 };
    cdb[2] = if data.is_empty() { 0x20 } else { 0x2e };
    cdb[4] = feature;
    cdb[6] = u8::from(!data.is_empty());
    cdb[8] = lba;
    if command == 0xb0 {
        cdb[10] = 0x4f;
        cdb[12] = 0xc2;
    }
    cdb[14] = command;
    let mut sense = [0u8; 64];
    let mut io = Sg {
        interface_id: b'S' as i32,
        direction: if data.is_empty() { -1 } else { -3 },
        cmd_len: 16,
        sense_len: 64,
        iovec_count: 0,
        data_len: data.len() as u32,
        data: data.as_mut_ptr().cast(),
        cmd: cdb.as_mut_ptr(),
        sense: sense.as_mut_ptr(),
        timeout: 2000,
        flags: 0,
        pack_id: 0,
        user: std::ptr::null_mut(),
        status: 0,
        masked_status: 0,
        msg_status: 0,
        written_sense: 0,
        host_status: 0,
        driver_status: 0,
        resid: 0,
        duration: 0,
        info: 0,
    };
    if allowed.is_some_and(|check| !check()) {
        return Err("Short self-tests disabled locally".into());
    }
    if unsafe { libc::ioctl(file.as_raw_fd(), 0x2285, &mut io) } < 0
        || io.host_status != 0
        || io.resid > 0
    {
        return Err("ATA SMART transport unavailable".into());
    }
    let mut offset = 8;
    let mut registers = None;
    if matches!(sense[0] & 0x7f, 0x72 | 0x73) {
        while offset + 2 <= io.written_sense as usize {
            let len = sense[offset + 1] as usize + 2;
            if len < 2 || offset + len > sense.len() {
                break;
            }
            if sense[offset] == 9 && len >= 14 {
                registers = Some(sense[offset..offset + 14].to_vec());
                break;
            }
            offset += len;
        }
    }
    if let Some(reg) = &registers {
        if reg[13] & 1 != 0 {
            return Err("ATA device rejected SMART command".into());
        }
    } else if io.status != 0 || io.driver_status != 0 {
        return Err("ATA SMART pass-through unsupported".into());
    }
    Ok(registers.unwrap_or_default())
}
pub(super) fn probe(device: &Device) -> Result<Reading, String> {
    let session = Session::open(device)?;
    if device.protocol == "nvme_usb" {
        return asmedia::probe(&session);
    }
    if device.protocol == "nvme" {
        let mut bytes = [0; 512];
        nvme_command(&session, 2, (127 << 16) | 2, &mut bytes, None)?;
        let mut out = super::nvme(&bytes)?;
        let mut identify = [0; 4096];
        if nvme_command(&session, 6, 1, &mut identify, None).is_ok() {
            out.short_test_supported =
                u16::from_le_bytes([identify[256], identify[257]]) & 0x10 != 0;
        }
        if out.short_test_supported {
            let mut log = [0; 512];
            if nvme_command(&session, 2, (127 << 16) | 6, &mut log, None).is_ok() {
                out.self_test = if log[0] & 0xf != 0 {
                    "running"
                } else if log[4] >> 4 == 0 || log[4] & 0xf == 15 {
                    "not_run"
                } else {
                    match log[4] & 0xf {
                        0 => "passed",
                        1..=4 | 8 | 9 => "aborted",
                        5..=7 => "failed",
                        _ => "not_run",
                    }
                }
                .into();
            }
        }
        return Ok(out);
    }
    // CHECK POWER MODE does not wake a standby HDD. A bridge that cannot report
    // power state still permits the normal read-only SMART query.
    if let Ok(registers) = ata_command(&session, 0xe5, 0, 0, &mut [], None) {
        if registers.get(5) == Some(&0) {
            return Err("Drive is in standby".into());
        }
    }
    let mut bytes = [0; 512];
    ata_command(&session, 0xb0, 0xd0, 0, &mut bytes, None)?;
    let mut thresholds = [0; 512];
    let thresholds = ata_command(&session, 0xb0, 0xd1, 0, &mut thresholds, None)
        .ok()
        .map(|_| thresholds);
    let mut log = [0; 512];
    let log = ata_command(&session, 0xb0, 0xd5, 6, &mut log, None)
        .ok()
        .map(|_| log);
    super::ata(
        &bytes,
        thresholds.as_ref().map(|v| v.as_slice()),
        log.as_ref().map(|v| v.as_slice()),
    )
}
pub(super) fn short_test(
    device: &Device,
    reading: &Reading,
    allowed: &dyn Fn() -> bool,
) -> Result<(), String> {
    if device.protocol == "nvme_usb" {
        return Err("USB NVMe short self-tests are not supported".into());
    }
    if !reading.short_test_supported {
        return Err("Short self-test unsupported".into());
    }
    let session = Session::open(device)?;
    if device.protocol == "nvme" {
        nvme_command(&session, 0x14, 1, &mut [], Some(allowed))
    } else {
        ata_command(&session, 0xb0, 0xd4, 1, &mut [], Some(allowed)).map(|_| ())
    }
}

#[cfg(test)]
mod virtual_bus_tests {
    use super::*;
    #[test]
    fn excludes_kernel_vmbus_ancestry_without_model_heuristics() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!(
            "porthub-vmbus-fixture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        struct Clean(PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _clean = Clean(root.clone());
        let block = root.join("controller/host0/target0/block/sda");
        std::fs::create_dir_all(&block).unwrap();
        assert!(!virtual_disk_bus(&block));
        symlink("/sys/bus/vmbus", root.join("controller/subsystem")).unwrap();
        assert!(virtual_disk_bus(&block));
        std::fs::remove_file(root.join("controller/subsystem")).unwrap();
        symlink(
            "/sys/bus/vmbus/drivers/hv_storvsc",
            root.join("controller/driver"),
        )
        .unwrap();
        assert!(virtual_disk_bus(&block));
        std::fs::remove_file(root.join("controller/driver")).unwrap();
        symlink("/sys/bus/usb", root.join("controller/subsystem")).unwrap();
        assert!(!virtual_disk_bus(&block));
        assert!(virtual_disk_bus(&root.join("missing")));
    }
}

#[cfg(test)]
mod held_native_object_tests {
    use super::*;
    #[test]
    fn held_descriptor_does_not_follow_reused_name_or_symlink() {
        let root =
            std::env::temp_dir().join(format!("porthub-smart-node-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let node = root.join("node");
        std::fs::write(&node, b"same bytes").unwrap();
        let held = File::open(&node).unwrap();
        assert!(held_node_matches(&held, &node).unwrap());
        std::fs::rename(&node, root.join("removed")).unwrap();
        std::fs::write(&node, b"same bytes").unwrap();
        assert!(!held_node_matches(&held, &node).unwrap());
        std::fs::remove_file(&node).unwrap();
        std::os::unix::fs::symlink(root.join("removed"), &node).unwrap();
        assert!(!held_node_matches(&held, &node).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod inventory_failure_tests {
    use super::*;
    #[test]
    fn inaccessible_inventory_is_not_confirmed_empty() {
        let root = tempfile::tempdir().unwrap();
        assert!(inventory_at(&root.path().join("missing")).is_err());
        assert!(inventory_at(root.path()).unwrap().devices.is_empty());
        std::fs::create_dir_all(root.path().join("sda/device")).unwrap();
        let partial = inventory_at(root.path()).unwrap();
        assert!(partial.devices.is_empty());
        assert!(partial.uncertain.contains(Path::new("/dev/sda")));
    }
}
