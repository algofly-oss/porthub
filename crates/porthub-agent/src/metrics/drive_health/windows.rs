//! Windows SMART reads use the native storage IOCTLs. No WMI, subprocesses,
//! external drivers or unbounded inventory loops are required.
use super::*;
use std::{
    fs::{File, OpenOptions},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
};
use windows_sys::Win32::System::IO::DeviceIoControl;
const QUERY: u32 = 0x002d1400;
fn open(path: &Path, write: bool) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .write(write)
        .share_mode(3)
        .open(path)
        .map_err(|_| "Native storage access is unavailable".into())
}
fn io(file: &File, code: u32, input: &[u8], output: &mut [u8]) -> Result<usize, String> {
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle().cast(),
            code,
            input.as_ptr().cast(),
            input.len() as u32,
            output.as_mut_ptr().cast(),
            output.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err("Native SMART request is unsupported or unavailable".into());
    }
    Ok(returned as usize)
}
fn le(data: &[u8], offset: usize) -> u32 {
    data.get(offset..offset + 4)
        .and_then(|v| v.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or_default()
}
fn string(data: &[u8], offset: usize) -> String {
    let start = le(data, offset) as usize;
    if start < 36 || start >= data.len() {
        return String::new();
    }
    text(
        &String::from_utf8_lossy(data[start..].split(|b| *b == 0).next().unwrap_or_default()),
        120,
    )
}
pub(super) fn inventory() -> Vec<Device> {
    let mut devices = Vec::new();
    for index in 0..128 {
        let path = PathBuf::from(format!("\\\\.\\PhysicalDrive{index}"));
        let Ok(file) = open(&path, false) else {
            continue;
        };
        let mut descriptor = [0u8; 1024];
        let Ok(n) = io(&file, QUERY, &[0; 12], &mut descriptor) else {
            continue;
        };
        if n < 36 {
            continue;
        }
        let descriptor = &descriptor[..n.min(1024)];
        let bus = le(descriptor, 28);
        if matches!(bus, 14 | 15) {
            continue;
        } // virtual/file-backed disks
        let vendor = string(descriptor, 12);
        let model = string(descriptor, 16);
        let serial = string(descriptor, 24);
        let mut length = [0u8; 8];
        let capacity = if io(&file, 0x0007405c, &[], &mut length).is_ok() {
            u64::from_le_bytes(length)
        } else {
            0
        };
        if capacity == 0 {
            continue;
        }
        let protocol = if bus == 17 { "nvme" } else { "ata" };
        let mut device = Device::new(
            path,
            &format!("{vendor} {model}").trim(),
            &serial,
            protocol,
            capacity,
        );
        let mut performance = [0u8; 88];
        if io(&file, 0x00070020, &[], &mut performance).is_ok() {
            device.busy_counter =
                Some(counter(&performance[..8]).saturating_add(counter(&performance[8..16])));
        }
        // GetDevicePowerState is observational; unlike a VERIFY command it does not
        // spin up a sleeping USB/SATA disk just to poll health.
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetDevicePowerState(
                device: windows_sys::Win32::Foundation::HANDLE,
                on: *mut i32,
            ) -> i32;
        }
        let mut on = 1;
        unsafe {
            if GetDevicePowerState(file.as_raw_handle().cast(), &mut on) != 0 {
                device.asleep = on == 0;
            }
        }
        devices.push(device);
        if devices.len() == MAX_DRIVES {
            break;
        }
    }
    devices
}
fn nvme_log(device: &Device, page: u32) -> Result<[u8; 512], String> {
    let file = open(&device.path, false)?;
    let mut request = vec![0u8; 8 + 40 + 512];
    // STORAGE_PROPERTY_QUERY + STORAGE_PROTOCOL_SPECIFIC_DATA. ProtocolDataOffset
    // is relative to the latter, including in the returned descriptor.
    for (at, value) in [(0, 49u32), (8, 3), (12, 2), (16, page), (24, 40), (28, 512)] {
        request[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    let mut output = vec![0u8; request.len()];
    let n = io(&file, QUERY, &request, &mut output)?;
    let offset = 8usize
        .checked_add(le(&output, 24) as usize)
        .ok_or("Invalid native SMART response")?;
    if le(&output, 28) < 512 || offset + 512 > n {
        return Err("Incomplete native SMART health log".into());
    }
    let mut data = [0; 512];
    data.copy_from_slice(&output[offset..offset + 512]);
    Ok(data)
}
fn ata_data(device: &Device, feature: u8, sector: u8) -> Result<[u8; 512], String> {
    let file = open(&device.path, true)?;
    let mut request = [0u8; 32];
    request[..4].copy_from_slice(&512u32.to_le_bytes());
    request[4] = feature;
    request[5] = 1;
    request[6] = sector;
    request[7] = 0x4f;
    request[8] = 0xc2;
    request[9] = 0xa0;
    request[10] = 0xb0;
    let mut output = [0u8; 16 + 512];
    let n = io(&file, 0x0007c088, &request, &mut output)?;
    if n < 528 || output[4] != 0 {
        return Err("ATA SMART data is unavailable".into());
    }
    let mut data = [0; 512];
    data.copy_from_slice(&output[16..]);
    Ok(data)
}
pub(super) fn probe(device: &Device) -> Result<Reading, String> {
    if device.protocol == "nvme" {
        let data = nvme_log(device, 2)?;
        let mut out = super::nvme(&data)?;
        out.short_test_supported = false;
        out.self_test = "unsupported".into();
        return Ok(out);
    }
    let values = ata_data(device, 0xd0, 0)?;
    let thresholds = ata_data(device, 0xd1, 0).ok();
    let log = ata_data(device, 0xd5, 6).ok();
    super::ata(
        &values,
        thresholds.as_ref().map(|b| b.as_slice()),
        log.as_ref().map(|b| b.as_slice()),
    )
}
pub(super) fn short_test(device: &Device, reading: &Reading) -> Result<(), String> {
    if device.protocol == "nvme" || !reading.short_test_supported {
        return Err("Native short self-test unavailable".into());
    }
    let file = open(&device.path, true)?;
    let mut request = [0u8; 32];
    request[4] = 0xd4;
    request[6] = 1;
    request[7] = 0x4f;
    request[8] = 0xc2;
    request[9] = 0xa0;
    request[10] = 0xb0;
    let mut output = [0u8; 16];
    io(&file, 0x0007c084, &request, &mut output)?;
    if output[4] != 0 {
        return Err("Drive rejected the short self-test".into());
    }
    Ok(())
}
