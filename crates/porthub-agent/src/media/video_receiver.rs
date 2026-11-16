//! Receiver-local UVC endpoint. The shared caller owns its unique USB slot,
//! authenticated carrier and independent plan/policy lifetime.
use super::{
    stream::Status,
    usb_video::{Camera, Identity},
    usbip_video::{self, CaptureDemand},
    video_stream,
};
use anyhow::{ensure, Context, Result};
use porthub_components::{media::Kind, media_forward::Plan, usb::Device};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Notify,
};
use tokio_util::sync::CancellationToken;
fn device(plan: &Plan, slot: u16) -> (Device, Vec<u8>) {
    let d = Device {
        busid: format!("65535-{slot}"),
        vendor: format!("{:04x}", plan.identity.vendor),
        product: format!("{:04x}", plan.identity.product),
        serial: plan.id.clone(),
        name: plan.name.clone(),
        busnum: 65535,
        devnum: slot,
        speed: 3,
        blocked: None,
    };
    let mut wire = vec![0; 312];
    wire[..7].copy_from_slice(b"porthub");
    wire[256..256 + d.busid.len()].copy_from_slice(d.busid.as_bytes());
    for (offset, value) in [(288, 65535u32), (292, slot as u32), (296, 3)] {
        wire[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    wire[300..302].copy_from_slice(&plan.identity.vendor.to_be_bytes());
    wire[302..304].copy_from_slice(&plan.identity.product.to_be_bytes());
    wire[304..306].copy_from_slice(&0x100u16.to_be_bytes());
    wire[306..309].copy_from_slice(&[0xef, 2, 1]);
    wire[309..312].copy_from_slice(&[1, 1, 2]);
    (d, wire)
}
#[cfg(any(target_os = "linux", windows))]
pub async fn run_local<S: AsyncRead + AsyncWrite + Unpin>(
    profile: &Path,
    plan: &Plan,
    slot: u16,
    carrier: S,
    cancel: CancellationToken,
    status: Status,
) -> Result<()> {
    ensure!(
        plan.kind() == Some(Kind::Camera) && slot != 0,
        "Invalid typed camera receiver plan"
    );
    ensure!(
        plan.format().context("Camera plan has no fixed format")? == Camera::format(),
        "Camera plan format differs from UVC receiver"
    );
    ensure!(
        available(),
        "{}",
        unavailable_reason().unwrap_or("Camera receiver is unavailable")
    );
    #[cfg(all(test,windows))]
    super::windows_video_destination_fixture::authorize_attachment(profile,plan,slot)?;
    let (device, wire) = device(plan, slot);
    let (mut attached, kernel) =
        crate::usb::media_transport::attach_video(profile, &device, &wire).await?;
    #[cfg(all(test,windows))]
    super::windows_video_destination_fixture::attached(profile,plan,slot)?;
    let mut camera = Camera::new(
        Identity {
            vendor: plan.identity.vendor,
            product: plan.identity.product,
        },
        plan.id.clone(),
    )?;
    camera.set_name(&plan.name)?;
    let engine = Arc::new(Mutex::new(camera));
    let notify = Arc::new(Notify::new());
    let (active, changes) = tokio::sync::watch::channel(CaptureDemand::default());
    let usb = usbip_video::serve(
        kernel,
        engine.clone(),
        0xffff0000 | slot as u32,
        notify.clone(),
        active,
        cancel.child_token(),
    );
    let frames = video_stream::receive(
        carrier,
        profile,
        engine,
        notify,
        changes,
        cancel.child_token(),
        status.clone(),
    );
    status("ready");
    tokio::select! {biased;_=cancel.cancelled()=>Ok(()),r=usb=>r,r=frames=>r,r=attached.failed()=>r}
}

/// Positive metadata preflight. Discovery never loads modules or opens a camera.
/// Windows reuses the existing signed UDE controller metadata/open preflight.
/// This neither attaches a USB device nor opens an audio/video source.
pub fn available() -> bool {
    #[cfg(all(test,windows))]
    if super::windows_video_destination_fixture::available_for_fixture(){return true;}
    #[cfg(target_os = "linux")]
    {
        use std::{
            sync::OnceLock,
            time::{Duration, Instant},
        };
        if Path::new("/sys/module/vhci_hcd").exists() && Path::new("/sys/module/uvcvideo").exists()
        {
            return true;
        }
        static CACHE: OnceLock<Mutex<Option<(Instant, bool)>>> = OnceLock::new();
        let mut cache = CACHE
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some((at, value)) = &*cache {
            if at.elapsed() < Duration::from_secs(30) {
                return *value;
            }
        }
        let value = driver_available(Path::new("/"), "vhci_hcd")
            && driver_available(Path::new("/"), "uvcvideo");
        *cache = Some((Instant::now(), value));
        value
    }
    #[cfg(windows)]
    {
        crate::usb::media_transport::receiver_available()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        false
    }
}
pub fn unavailable_reason() -> Option<&'static str> {
    if available() {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        Some("Matching Linux USB/IP and UVC camera kernel drivers are unavailable")
    }
    #[cfg(windows)]
    {
        Some("The signed Windows USB receive controller is unavailable")
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Some("Native camera receiving is unsupported on this platform")
    }
}
#[cfg(target_os = "linux")]
fn bounded(path: &Path, limit: usize) -> Option<String> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() > limit {
        return None;
    }
    String::from_utf8(bytes).ok()
}
#[cfg(target_os = "linux")]
fn driver_available(root: &Path, name: &str) -> bool {
    if root.join("sys/module").join(name).is_dir() {
        return true;
    }
    let Some(kernel) = bounded(&root.join("proc/sys/kernel/osrelease"), 128) else {
        return false;
    };
    let kernel = kernel.trim();
    if kernel.is_empty()
        || !kernel
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return false;
    }
    let base = root.join("lib/modules").join(kernel);
    for (file, builtin) in [("modules.dep", false), ("modules.builtin", true)] {
        let Some(text) = bounded(&base.join(file), 8 * 1024 * 1024) else {
            continue;
        };
        for line in text.lines() {
            let path = line.split_once(':').map(|(p, _)| p).unwrap_or(line);
            let p = Path::new(path);
            if p.is_absolute()
                || !p
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_)))
            {
                continue;
            }
            let Some(file) = p.file_name().and_then(|v| v.to_str()) else {
                continue;
            };
            let target = name.replace('_', "-");
            let stem = file.split_once(".ko");
            let matches = stem.is_some_and(|(stem, suffix)| {
                stem.replace('_', "-") == target && matches!(suffix, "" | ".xz" | ".zst" | ".gz")
            });
            if matches && (builtin || base.join(p).is_file()) {
                if !builtin {
                    let dependencies = line
                        .split_once(':')
                        .map(|(_, v)| v)
                        .unwrap_or("")
                        .split_whitespace()
                        .collect::<Vec<_>>();
                    if dependencies.len() > 128 {
                        return false;
                    }
                    if !dependencies.into_iter().all(|dependency| {
                        let p = Path::new(dependency);
                        !p.is_absolute()
                            && p.components()
                                .all(|c| matches!(c, std::path::Component::Normal(_)))
                            && base.join(p).is_file()
                    }) {
                        return false;
                    }
                }
                return true;
            }
        }
    }
    false
}
#[cfg(all(test, target_os = "linux"))]
mod capability_tests {
    use super::*;
    #[test]
    fn preflight_accepts_installed_or_builtin_drivers_without_requiring_load() -> Result<()> {
        let root = tempfile::tempdir()?;
        let r = root.path();
        std::fs::create_dir_all(r.join("proc/sys/kernel"))?;
        std::fs::write(r.join("proc/sys/kernel/osrelease"), "test-kernel\n")?;
        let modules = r.join("lib/modules/test-kernel");
        std::fs::create_dir_all(modules.join("kernel/media"))?;
        std::fs::write(
            modules.join("modules.dep"),
            "kernel/media/uvcvideo.ko.zst: kernel/media/videodev.ko.zst\n",
        )?;
        assert!(!driver_available(r, "uvcvideo"));
        std::fs::write(modules.join("kernel/media/uvcvideo.ko.zst"), b"fixture")?;
        assert!(
            !driver_available(r, "uvcvideo"),
            "Missing loadable dependency must not be advertised ready"
        );
        std::fs::write(modules.join("kernel/media/videodev.ko.zst"), b"fixture")?;
        assert!(driver_available(r, "uvcvideo"));
        std::fs::write(modules.join("modules.builtin"), "kernel/usb/vhci-hcd.ko\n")?;
        assert!(driver_available(r, "vhci_hcd"));
        std::fs::write(modules.join("modules.dep"), "../../uvcvideo.ko.zst:\n")?;
        assert!(!driver_available(r, "uvcvideo"));
        std::fs::write(r.join("proc/sys/kernel/osrelease"), "../../etc")?;
        assert!(!driver_available(r, "vhci_hcd"));
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod windows_capability_tests {
    #[test]
    fn requires_the_existing_signed_usb_receiver_preflight() {
        // No attach/capture: the same metadata-only controller check is used by
        // ordinary USB and microphone receiving. CI has no UDE controller.
        if super::super::windows_video_destination_fixture::available_for_fixture() {
            return;
        }
        let ready = crate::usb::media_transport::receiver_available();
        assert_eq!(super::available(), ready);
        if ready {
            assert_eq!(super::unavailable_reason(), None);
        } else {
            assert_eq!(super::unavailable_reason(), Some("The signed Windows USB receive controller is unavailable"));
        }
    }
}
