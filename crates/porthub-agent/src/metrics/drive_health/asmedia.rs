//! Read-only ASMedia NVMe-over-USB health queries. The protocol facts are
//! documented by smartmontools' scsinvme and USB bridge database; this is an
//! independent, deliberately non-general Rust encoder, not its implementation.
//! https://www.smartmontools.org/static/doxygen/scsinvme_8cpp_source.html
//! No arbitrary opcodes, output transfers, self-tests, or firmware operations.
use super::{Device, Sg};
use std::{
    fs::File,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt},
    },
    path::{Path, PathBuf},
};
const ERROR: &str = "Native USB NVMe SMART access is unsupported or unavailable";
#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    block: PathBuf,
    usb: PathBuf,
    vendor: u16,
    product: u16,
    serial: String,
}
fn known(vendor: u16, product: u16) -> bool {
    matches!(
        (vendor, product),
        (0x04e8, 0x4001)
            | (0x04e8, 0x61fd)
            | (0x174c, 0x2362)
            | (0x174c, 0x2364)
            | (0x174c, 0x2463)
    )
}
fn field(path: &Path, key: &str) -> Result<String, String> {
    let bytes = std::fs::read(path.join(key)).map_err(|_| ERROR.to_string())?;
    if bytes.len() > 512 {
        return Err(ERROR.into());
    }
    let value = std::str::from_utf8(&bytes).map_err(|_| ERROR)?.trim();
    if value.chars().any(char::is_control) {
        return Err(ERROR.into());
    }
    Ok(value.into())
}
fn identity(block: &Path) -> Result<Identity, String> {
    let block = std::fs::canonicalize(block).map_err(|_| ERROR)?;
    let usb = block
        .ancestors()
        .find(|p| p.join("idVendor").is_file() && p.join("idProduct").is_file())
        .ok_or(ERROR)?;
    let vendor = u16::from_str_radix(&field(usb, "idVendor")?, 16).map_err(|_| ERROR)?;
    let product = u16::from_str_radix(&field(usb, "idProduct")?, 16).map_err(|_| ERROR)?;
    if !known(vendor, product) {
        return Err(ERROR.into());
    }
    let serial = field(usb, "serial")?;
    if serial.is_empty() || serial.len() > 256 {
        return Err(ERROR.into());
    }
    Ok(Identity {
        usb: usb.to_path_buf(),
        block,
        vendor,
        product,
        serial,
    })
}
pub(super) fn supported(path: &Path) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    identity(&Path::new("/sys/class/block").join(name)).is_ok()
}
#[derive(Clone, Copy, Debug)]
enum Query {
    IdentifyController,
    Health,
}
impl Query {
    fn bytes(self) -> usize {
        match self {
            Self::IdentifyController => 4096,
            Self::Health => 512,
        }
    }
    fn cdb(self) -> [u8; 16] {
        let mut command = [0; 16];
        command[0] = 0xe6;
        // ASMedia: byte1 NVMe admin opcode; byte3 CNS/LID; bytes6..7
        // big-endian NUMD (zero-based dword count) for Get Log Page only.
        match self {
            Self::IdentifyController => {
                command[1] = 6;
                command[3] = 1;
            }
            Self::Health => {
                command[1] = 2;
                command[3] = 2;
                command[6..8].copy_from_slice(&127u16.to_be_bytes());
            }
        }
        command
    }
}
fn bind(file: &File, device: &Device) -> Result<Identity, String> {
    let meta = file.metadata().map_err(|_| ERROR)?;
    if !meta.file_type().is_block_device() {
        return Err(ERROR.into());
    }
    let major = libc::major(meta.rdev());
    let minor = libc::minor(meta.rdev());
    let current = identity(&Path::new("/sys/dev/block").join(format!("{major}:{minor}")))?;
    let expected =
        identity(&Path::new("/sys/class/block").join(device.path.file_name().ok_or(ERROR)?))?;
    if current != expected {
        return Err(ERROR.into());
    }
    // Preserve the existing physical ID despite correcting its reported
    // protocol. Revalidate inventory identity rather than trusting a reused sdX.
    let model = field(&current.block.join("device"), "model")?;
    let serial = field(&current.block.join("device"), "serial")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| field(&current.block, "wwid").ok())
        .unwrap_or_default();
    let capacity = field(&current.block, "size")?
        .parse::<u64>()
        .ok()
        .and_then(|v| v.checked_mul(512))
        .ok_or(ERROR)?;
    let fresh = Device::new(device.path.clone(), &model, &serial, "ata", capacity);
    if fresh.id != device.id || fresh.capacity != device.capacity {
        return Err(ERROR.into());
    }
    // Never query a locally exported device whose kernel driver is owned by
    // another USB session, or wake an interface already runtime-suspended.
    if current.block.ancestors().any(|p| {
        std::fs::read_link(p.join("driver"))
            .ok()
            .is_some_and(|d| d.file_name().is_some_and(|n| n == "usbip-host"))
    }) || field(&current.block.join("device/power"), "runtime_status")
        .ok()
        .as_deref()
        == Some("suspended")
    {
        return Err(ERROR.into());
    }
    Ok(current)
}
fn transfer(file: &File, query: Query) -> Result<Vec<u8>, String> {
    let mut command = query.cdb();
    let mut data = vec![0; query.bytes()];
    let mut sense = [0u8; 64];
    let mut request = Sg {
        interface_id: b'S' as i32,
        direction: -3,
        cmd_len: 16,
        sense_len: 64,
        iovec_count: 0,
        data_len: data.len() as u32,
        data: data.as_mut_ptr().cast(),
        cmd: command.as_mut_ptr(),
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
    let ok = unsafe { libc::ioctl(file.as_raw_fd(), 0x2285, &mut request) };
    if ok != 0
        || !completion(
            request.status,
            request.host_status,
            request.driver_status,
            request.resid,
            request.info,
        )
    {
        return Err(ERROR.into());
    }
    Ok(data)
}
fn completion(status: u8, host: u16, driver: u16, resid: i32, info: u32) -> bool {
    status == 0 && host == 0 && driver == 0 && resid == 0 && info & 1 == 0
}
fn valid_identify(data: &[u8]) -> bool {
    if data.len() != 4096 {
        return false;
    }
    let vendor = u16::from_le_bytes([data[0], data[1]]);
    let text =
        |v: &[u8]| v.iter().all(|c| matches!(c, 0x20..=0x7e)) && v.iter().any(|b| *b != b' ');
    vendor != 0 && vendor != u16::MAX && text(&data[4..24]) && text(&data[24..64])
}
pub(super) fn probe(session: &super::Session<'_>) -> Result<super::super::Reading, String> {
    let device = session.device;
    session.validate()?;
    if device.in_use || device.asleep {
        return Err(ERROR.into());
    }
    let file = &session.disk;
    let original = bind(&file, device)?;
    session.validate()?;
    let identify = transfer(&file, Query::IdentifyController)?;
    if !valid_identify(&identify) || bind(&file, device)? != original {
        return Err(ERROR.into());
    }
    session.validate()?;
    let health = transfer(&file, Query::Health)?;
    if bind(&file, device)? != original {
        return Err(ERROR.into());
    }
    session.validate()?;
    let mut reading = super::super::nvme(&health)?;
    reading.short_test_supported = false;
    reading.self_test = "unsupported".into();
    Ok(reading)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_known_bridge_ids() {
        assert!(known(0x04e8, 0x4001));
        assert!(known(0x174c, 0x2362));
        for id in [(0x174c, 0x1153), (0x04e8, 0x61f5), (0x152d, 0x578), (0, 0)] {
            assert!(!known(id.0, id.1));
        }
    }
    #[test]
    fn wire_allows_only_two_read_queries() {
        assert_eq!(Query::IdentifyController.bytes(), 4096);
        assert_eq!(
            Query::IdentifyController.cdb(),
            [0xe6, 6, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(Query::Health.bytes(), 512);
        assert_eq!(
            Query::Health.cdb(),
            [0xe6, 2, 0, 2, 0, 0, 0, 127, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
    #[test]
    fn rejects_partial_transport_or_error_status() {
        assert!(completion(0, 0, 0, 0, 0));
        for (status, host, driver, resid, info) in [
            (2, 0, 0, 0, 0),
            (0, 1, 0, 0, 0),
            (0, 0, 1, 0, 0),
            (0, 0, 0, 1, 0),
            (0, 0, 0, -1, 0),
            (0, 0, 0, 0, 1),
        ] {
            assert!(!completion(status, host, driver, resid, info));
        }
    }
    #[test]
    fn requires_positive_nvme_identify() {
        let mut d = vec![0; 4096];
        assert!(!valid_identify(&d));
        d[0..2].copy_from_slice(&0x144du16.to_le_bytes());
        d[4..24].fill(b' ');
        d[4..10].copy_from_slice(b"SERIAL");
        d[24..64].fill(b' ');
        d[24..29].copy_from_slice(b"MODEL");
        assert!(valid_identify(&d));
        d[4] = 0;
        assert!(!valid_identify(&d));
        assert!(!valid_identify(&d[..512]));
    }
}
