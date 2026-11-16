//! Read-only native inventory. QUERYCAP never allocates buffers or starts capture.
use porthub_components::media::{Device, Kind};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
fn bounded_file(path: &Path) -> Option<String> {
    let value = fs::read_to_string(path).ok()?;
    (value.len() <= 65536).then(|| {
        value
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(256)
            .collect()
    })
}
fn identity(path: &Path, suffix: &str) -> String {
    // USB serial when available survives bus renumbering; otherwise native topology.
    let physical = fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
    let mut stable = physical.to_string_lossy().into_owned();
    for ancestor in physical.ancestors().take(12) {
        if let Some(serial) = bounded_file(&ancestor.join("serial")).filter(|s| !s.is_empty()) {
            let vendor = bounded_file(&ancestor.join("idVendor")).unwrap_or_default();
            let product = bounded_file(&ancestor.join("idProduct")).unwrap_or_default();
            stable = format!("usb:{vendor}:{product}:{serial}");
            break;
        }
    }
    format!("{:x}", Sha256::digest(format!("{stable}:{suffix}")))
}
fn microphone_rows(root: &Path, pcm: &str) -> Vec<Device> {
    let mut rows = BTreeMap::new();
    for line in pcm.lines().take(256) {
        let Some((address, description)) = line.split_once(':') else {
            continue;
        };
        let Some((card, device)) = address.trim().split_once('-') else {
            continue;
        };
        let (Ok(card), Ok(device)) = (card.parse::<u32>(), device.parse::<u32>()) else {
            continue;
        };
        if card > 4095 || device > 4095 {
            continue;
        }
        let captures = description
            .split(':')
            .filter_map(|part| part.trim().strip_prefix("capture "))
            .filter_map(|s| s.trim().parse::<u32>().ok())
            .any(|n| n > 0);
        if !captures {
            continue;
        }
        let card_path = root.join(format!("class/sound/card{card}"));
        let native_card = bounded_file(&card_path.join("id")).filter(|s| !s.is_empty());
        let Some(native_card) = native_card else {
            continue;
        };
        let name = description
            .split(':')
            .next()
            .unwrap_or("Microphone")
            .trim()
            .chars()
            .take(256)
            .collect();
        let id = format!(
            "microphone:{}",
            identity(&card_path.join("device"), &format!("pcm:{device}"))
        );
        rows.insert(
            id.clone(),
            Device {
                id,
                name,
                kind: Kind::Microphone,
                backend: "alsa-inventory".into(),
                native_id: format!("hw:CARD={native_card},DEV={device}"),
                capture_available: false,
                capture_state: porthub_components::media::CaptureState::Unsupported,
                unavailable_reason: Some(
                    "Native media capture adapter is not installed or verified".into(),
                ),
            },
        );
    }
    rows.into_values().collect()
}
#[repr(C)]
#[derive(Default)]
struct Capability {
    driver: [u8; 16],
    card: [u8; 32],
    bus_info: [u8; 32],
    version: u32,
    capabilities: u32,
    device_caps: u32,
    reserved: [u32; 3],
}
fn camera_capture(path: &Path) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd;
    let file = fs::OpenOptions::new().read(true).open(path)?;
    let mut cap = Capability::default();
    // _IOR('V',0,struct v4l2_capability), UAPI layout asserted below.
    if unsafe { libc::ioctl(file.as_raw_fd(), 0x80685600u32 as _, &mut cap) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let flags = if cap.capabilities & 0x80000000 != 0 {
        cap.device_caps
    } else {
        cap.capabilities
    };
    Ok(flags & (1 | 0x1000) != 0)
}
pub(super) fn devices() -> anyhow::Result<Vec<Device>> {
    let mut rows = match fs::read_to_string("/proc/asound/pcm") {
        Ok(pcm) if pcm.len() <= 65536 => microphone_rows(Path::new("/sys"), &pcm),
        Ok(_) => anyhow::bail!("Audio inventory exceeds bound"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => anyhow::bail!("Native audio inventory unavailable"),
    };
    let cameras = match fs::read_dir("/sys/class/video4linux") {
        Ok(rows) => rows,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(rows),
        Err(_) => anyhow::bail!("Native camera inventory unavailable"),
    };
    for camera in cameras.take(128) {
        let camera = camera?;
        let filename = camera.file_name();
        let Some(filename) = filename.to_str() else {
            continue;
        };
        if !filename
            .strip_prefix("video")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|v| v.is_ascii_digit()))
        {
            continue;
        }
        let device = PathBuf::from("/dev").join(filename);
        let (include, reason) = match camera_capture(&device) {
            Ok(true) => (
                true,
                "Native media capture adapter is not installed or verified",
            ),
            Ok(false) => (false, ""),
            Err(_) => (true, "Camera capability query denied or unavailable"),
        };
        if !include {
            continue;
        }
        rows.push(Device {
            id: format!(
                "camera:{}",
                identity(
                    &camera.path().join("device"),
                    &format!(
                        "v4l2:{}",
                        bounded_file(&camera.path().join("index"))
                            .unwrap_or_else(|| filename.into())
                    )
                )
            ),
            name: bounded_file(&camera.path().join("name")).unwrap_or_else(|| filename.into()),
            kind: Kind::Camera,
            backend: "v4l2-inventory".into(),
            native_id: device.to_string_lossy().into_owned(),
            capture_available: false,
            capture_state: porthub_components::media::CaptureState::Unsupported,
            unavailable_reason: Some(reason.into()),
        });
    }
    Ok(rows)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audio_inventory_excludes_playback_only_and_deduplicates_native_identity() {
        let dir = tempfile::tempdir().unwrap();
        for card in [0, 1] {
            let p = dir.path().join(format!("class/sound/card{card}"));
            fs::create_dir_all(p.join("device")).unwrap();
            fs::write(p.join("id"), format!("Card{card}")).unwrap();
        }
        let pcm="00-00: Same label : playback 1\n00-01: Same label : capture 1\n01-01: Same label : capture 2\n01-01: Same label : capture 2\nbad: capture 1\n";
        let rows = microphone_rows(dir.path(), pcm);
        assert_eq!(rows.len(), 2);
        assert_ne!(rows[0].id, rows[1].id);
        assert!(rows.iter().all(|v| !v.capture_available));
        assert_eq!(std::mem::size_of::<Capability>(), 104);
    }
}
