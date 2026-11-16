//! On-demand native user-session adapter. Enumeration never connects a capture stream.
#[cfg(target_os = "linux")]
mod audio;
#[cfg(any(windows, test))]
mod capture_output;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod linux_video;
#[cfg(any(target_os = "linux", windows))]
mod video_output;
#[cfg(target_os = "linux")]
mod video_session;
#[cfg(windows)]
mod windows_audio;
#[cfg(windows)]
mod windows_session;
#[cfg(windows)]
mod windows_video;
#[cfg(windows)]
mod windows_video_session;
fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        #[cfg(target_os = "linux")]
        (Some("inventory"), None) => println!("{}", serde_json::to_string(&linux::inventory()?)?),
        #[cfg(windows)]
        (Some("inventory"), None) => {
            println!("{}", serde_json::to_string(&windows_audio::inventory()?)?)
        }
        #[cfg(any(target_os = "linux", windows))]
        (Some("inventory-local"), None) => {
            use porthub_components::media::{LocalInventory, LocalSource};
            let mut inventory = LocalInventory::default();
            #[cfg(target_os = "linux")]
            let microphones = linux::inventory();
            #[cfg(windows)]
            let microphones = windows_audio::inventory();
            match microphones {
                Ok(rows) => inventory
                    .sources
                    .extend(rows.into_iter().map(|device| LocalSource {
                        device,
                        camera_identity: None,
                    })),
                Err(_) => {
                    inventory.microphone_unavailable_reason =
                        Some("Microphone inventory is unavailable in this user session".into())
                }
            }
            #[cfg(target_os = "linux")]
            match linux_video::inventory() {
                Ok(rows) => {
                    for camera in rows {
                        inventory.sources.push(LocalSource {
                            device: camera.device,
                            camera_identity: Some(serde_json::to_value(camera.expected)?),
                        });
                    }
                }
                Err(_) => {
                    inventory.camera_unavailable_reason =
                        Some("Complete camera inventory is unavailable in this user session".into())
                }
            }
            #[cfg(windows)]
            match windows_video::inventory() {
                Ok(rows) => {
                    for device in rows {
                        let expected = windows_video_session::ExpectedCamera::from_device(&device)?;
                        inventory.sources.push(LocalSource {
                            device,
                            camera_identity: Some(serde_json::to_value(expected)?),
                        });
                    }
                }
                Err(_) => {
                    inventory.camera_unavailable_reason =
                        Some("Complete camera inventory is unavailable in this user session".into());
                }
            }
            // Keep independent optional kinds usable when the other inventory
            // is incomplete or exceeds its bounded local identity envelope.
            for kind in [
                porthub_components::media::Kind::Microphone,
                porthub_components::media::Kind::Camera,
            ] {
                let rows = inventory
                    .sources
                    .iter()
                    .filter(|s| s.device.kind == kind)
                    .collect::<Vec<_>>();
                if rows.len() > 64
                    || !rows.iter().all(|s| s.valid())
                    || serde_json::to_vec(&rows)?.len() > 120 * 1024
                {
                    inventory.sources.retain(|s| s.device.kind != kind);
                    let reason =
                        Some("Native source inventory exceeds safe identity bounds".into());
                    if kind == porthub_components::media::Kind::Camera {
                        inventory.camera_unavailable_reason = reason;
                    } else {
                        inventory.microphone_unavailable_reason = reason;
                    }
                }
            }
            if !inventory.valid() || serde_json::to_vec(&inventory)?.len() > 128 * 1024 {
                inventory
                    .sources
                    .retain(|s| s.device.kind != porthub_components::media::Kind::Camera);
                inventory.camera_unavailable_reason =
                    Some("Combined source inventory exceeds safe identity bounds".into());
            }
            let bytes = serde_json::to_vec(&inventory)?;
            println!("{}", String::from_utf8(bytes)?);
        }
        #[cfg(target_os = "linux")]
        (Some("serve"), None) => audio::serve()?,
        #[cfg(windows)]
        (Some("serve"), None) => windows_session::serve()?,
        _ => {
            anyhow::bail!("Use inventory; media capture requires an authenticated explicit session")
        }
    }
    Ok(())
}
