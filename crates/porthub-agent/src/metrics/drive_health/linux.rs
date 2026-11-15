#[path = "asmedia.rs"]
mod asmedia;
use super::*;
use std::{
    fs::{File, OpenOptions},
    os::fd::AsRawFd,
};
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
pub(super) fn inventory() -> Vec<Device> {
    let Ok(entries) = std::fs::read_dir("/sys/class/block") else {
        return Vec::new();
    };
    let mut devices = Vec::new();
    for entry in entries.flatten() {
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
        devices.push(device);
    }
    devices.sort_by(|a, b| a.path.cmp(&b.path));
    devices
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
fn controller(device: &Device) -> PathBuf {
    let name = device
        .path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    Path::new("/dev").join(name.rsplit_once('n').map(|(v, _)| v).unwrap_or(&name))
}
fn nvme_command(device: &Device, opcode: u8, cdw10: u32, data: &mut [u8]) -> Result<(), String> {
    let file = File::open(controller(device)).map_err(|_| "NVMe device unavailable".to_owned())?;
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
    device: &Device,
    command: u8,
    feature: u8,
    lba: u8,
    data: &mut [u8],
) -> Result<Vec<u8>, String> {
    // The file is read-only, including SMART EXECUTE OFFLINE: the sole non-read
    // operation permitted here is the device's non-destructive short self-test.
    let file = OpenOptions::new()
        .read(true)
        .open(&device.path)
        .map_err(|_| "ATA device unavailable".to_owned())?;
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
    if device.protocol == "nvme_usb" {
        return asmedia::probe(device);
    }
    if device.protocol == "nvme" {
        let mut bytes = [0; 512];
        nvme_command(device, 2, (127 << 16) | 2, &mut bytes)?;
        let mut out = super::nvme(&bytes)?;
        let mut identify = [0; 4096];
        if nvme_command(device, 6, 1, &mut identify).is_ok() {
            out.short_test_supported =
                u16::from_le_bytes([identify[256], identify[257]]) & 0x10 != 0;
        }
        if out.short_test_supported {
            let mut log = [0; 512];
            if nvme_command(device, 2, (127 << 16) | 6, &mut log).is_ok() {
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
    if let Ok(registers) = ata_command(device, 0xe5, 0, 0, &mut []) {
        if registers.get(5) == Some(&0) {
            return Err("Drive is in standby".into());
        }
    }
    let mut bytes = [0; 512];
    ata_command(device, 0xb0, 0xd0, 0, &mut bytes)?;
    let mut thresholds = [0; 512];
    let thresholds = ata_command(device, 0xb0, 0xd1, 0, &mut thresholds)
        .ok()
        .map(|_| thresholds);
    let mut log = [0; 512];
    let log = ata_command(device, 0xb0, 0xd5, 6, &mut log)
        .ok()
        .map(|_| log);
    super::ata(
        &bytes,
        thresholds.as_ref().map(|v| v.as_slice()),
        log.as_ref().map(|v| v.as_slice()),
    )
}
pub(super) fn short_test(device: &Device, reading: &Reading) -> Result<(), String> {
    if device.protocol == "nvme_usb" {
        return Err("USB NVMe short self-tests are not supported".into());
    }
    if !reading.short_test_supported {
        return Err("Short self-test unsupported".into());
    }
    if device.protocol == "nvme" {
        nvme_command(device, 0x14, 1, &mut [])
    } else {
        ata_command(device, 0xb0, 0xd4, 1, &mut []).map(|_| ())
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
