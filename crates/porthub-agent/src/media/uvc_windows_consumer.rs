//! Private, ignored consumer: exact generated USB camera only, never a default.
use super::{native_video, uvc_windows_identity as identity};
use anyhow::{ensure, Context, Result};
use porthub_components::media::{Kind, VideoEncoding, VideoFormat};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
const JPEG: &[u8] = include_bytes!("../../tests/data/private_uvc_colorbars_640x480.jpg");
fn result_path(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    ensure!(
        path.is_absolute()
            && path
                .file_name()
                .is_some_and(|name| name == "consumer-result.json")
            && !path.exists(),
        "Fresh private consumer report required"
    );
    let parent = path.parent().context("Consumer report parent missing")?;
    let metadata = std::fs::symlink_metadata(parent)?;
    ensure!(
        parent
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("PortHubPrivateUvcProof-"))
            && metadata.is_dir()
            && metadata.file_attributes() & 0x400 == 0,
        "Consumer report directory is not a fresh owned fixture"
    );
    Ok(())
}
fn report(path: &Path, value: &serde_json::Value) -> Result<()> {
    result_path(path)?;
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= 8192, "Consumer report exceeds8KiB");
    let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|error| error.error)?;
    Ok(())
}
fn exact(serial: &str) -> Result<Option<(String, identity::Proof)>> {
    let mut found = None;
    for device in native_video::inventory()? {
        ensure!(
            device.kind == Kind::Camera,
            "Unexpected native camera inventory kind"
        );
        let Some(proof) = identity::inspect(&device.native_id)? else {
            continue;
        };
        if proof.selected(serial) {
            ensure!(
                found.is_none(),
                "Multiple synthetic camera interfaces match exact identity"
            );
            found = Some((device.native_id, proof));
        }
    }
    Ok(found)
}
#[test]
#[ignore = "Requires root-reviewed ordinary limited interactive synthetic UVC consumer window"]
fn native_windows_uvcvideo_colorbars_consumer() -> Result<()> {
    ensure!(
        std::env::var("PORTHUB_PRIVATE_UVC_CONSUMER").as_deref() == Ok("1"),
        "Explicit private synthetic camera consumer authorization required"
    );
    let serial = std::env::var("PORTHUB_PRIVATE_UVC_SERIAL")?;
    ensure!(
        identity::valid_serial(&serial),
        "Exact private camera serial required"
    );
    let result = PathBuf::from(std::env::var("PORTHUB_PRIVATE_UVC_RESULT")?);
    result_path(&result)?;
    let outcome = (|| {
        // Metadata-only bounded readiness polling. Never retry a failed ActivateObject.
        let waiting = Instant::now();
        let (symbolic, proof) = loop {
            if let Some(found) = exact(&serial)? {
                break found;
            }
            ensure!(
                waiting.elapsed() < Duration::from_secs(20),
                "Exact synthetic camera metadata did not become ready"
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        let current =
            identity::inspect(&symbolic)?.context("Synthetic camera detached before capture")?;
        proof.verify(&current, &serial)?;
        let cancel = AtomicBool::new(false);
        let started = Instant::now();
        let ready = std::cell::Cell::new(false);
        let mut frames = 0u64;
        let mut bytes = 0u64;
        let mut first_ms = None;
        native_video::capture_native_mjpeg(
            &symbolic,
            VideoFormat {
                width: 640,
                height: 480,
                fps_num: 15,
                fps_den: 1,
                encoding: VideoEncoding::Mjpeg,
            },
            &cancel,
            |format| {
                ensure!(
                    format.width == 640
                        && format.height == 480
                        && format.encoding == VideoEncoding::Mjpeg,
                    "Native camera changed format"
                );
                ready.set(true);
                Ok(())
            },
            |jpeg| {
                ensure!(ready.get(), "Frame delivered before exact-mode readiness");
                ensure!(
                    jpeg == JPEG,
                    "Camera frame differs from generated fixture colorbars"
                );
                if first_ms.is_none() {
                    first_ms = Some(started.elapsed().as_millis() as u64)
                }
                frames += 1;
                bytes += jpeg.len() as u64;
                if frames == 45 {
                    cancel.store(true, Ordering::Release)
                }
                ensure!(
                    frames <= 45 && started.elapsed() < Duration::from_secs(6),
                    "Consumer frame/clock bound exceeded"
                );
                Ok(())
            },
        )?;
        let elapsed = started.elapsed();
        ensure!(
            frames == 45
                && (Duration::from_millis(2500)..=Duration::from_secs(5)).contains(&elapsed),
            "45 generated frames did not follow nominal15fps clock"
        );
        Ok::<_, anyhow::Error>(
            serde_json::json!({"ok":true,"serial":serial,"identity_verified":true,"native_class":"usbvideo","frames":frames,"bytes":bytes,"elapsed_ms":elapsed.as_millis(),"first_frame_ms":first_ms,"width":640,"height":480,"nominal_fps":15,"exact_generated_jpeg":true,"physical_camera":false,"default_camera_selected":false,"saved_video":false}),
        )
    })();
    let summary = match &outcome {
        Ok(value) => value.clone(),
        Err(error) => {
            serde_json::json!({"ok":false,"serial":serial,"identity_verified":false,"error":error.to_string().chars().take(256).collect::<String>(),"physical_camera":false,"default_camera_selected":false,"saved_video":false})
        }
    };
    // Persist bounded summary on failure too, so producer can detach promptly.
    report(&result, &summary)?;
    outcome.map(|_| ())
}

/// Read-only baseline for outer wrappers before attach and after detach. No
/// Windows-wide default-camera selector exists here and no source is activated.
#[test]
#[ignore = "Requires explicitly authorized existing interactive metadata context"]
fn native_windows_uvcvideo_metadata_only() -> Result<()> {
    ensure!(
        std::env::var("PORTHUB_PRIVATE_UVC_METADATA").as_deref() == Ok("1"),
        "Explicit metadata authorization required"
    );
    let mut rows = Vec::new();
    for device in native_video::inventory()? {
        ensure!(
            device.kind == Kind::Camera && !device.capture_available,
            "Unexpected native camera inventory capability"
        );
        rows.push((device.id, device.name));
    }
    rows.sort();
    use sha2::Digest;
    let hash = format!("{:x}", sha2::Sha256::digest(serde_json::to_vec(&rows)?));
    println!(
        "PRIVATE_WINDOWS_UVC_METADATA {}",
        serde_json::json!({"camera_count":rows.len(),"inventory_fingerprint":hash,"source_activated":false,"default_camera_selected":false,"saved_video":false})
    );
    Ok(())
}
