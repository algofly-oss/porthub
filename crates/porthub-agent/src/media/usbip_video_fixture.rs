//! Ignored, explicitly gated native Linux receiver proof. Only synthetic pixels.
use super::super::usb_video::{FPS, HEIGHT, Identity, WIDTH};
use super::*;
use porthub_components::{
    media::{VideoEncoding, VideoFormat, VideoFrame},
    usb::Device,
};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
};
const JPEG: &[u8] = include_bytes!("../../tests/data/private_uvc_colorbars_640x480.jpg");

fn optional_text(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
fn optional_canonical(path: &Path) -> Result<Option<PathBuf>> {
    match std::fs::canonicalize(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
fn verify_usb(usb: &Path, serial: &str) -> Result<bool> {
    let Some(actual) = optional_text(&usb.join("serial"))? else {
        return Ok(false);
    };
    if actual.trim() != serial {
        return Ok(false);
    }
    let Some(vendor) = optional_text(&usb.join("idVendor"))? else {
        return Ok(false);
    };
    let Some(product) = optional_text(&usb.join("idProduct"))? else {
        return Ok(false);
    };
    ensure!(
        vendor.trim() == "1209" && product.trim() == "0001",
        "Fresh synthetic USB identity changed"
    );
    Ok(true)
}
fn video_nodes_at(
    class: &Path,
    dev: &Path,
    serial: &str,
    capture_only: bool,
) -> Result<Vec<(PathBuf, PathBuf)>> {
    let entries = match std::fs::read_dir(class) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(error) => return Err(error.into()),
    };
    let mut found = vec![];
    for entry in entries {
        let entry = match entry {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let path = entry.path();
        if capture_only
            && optional_text(&path.join("index"))?.is_none_or(|index| index.trim() != "0")
        {
            continue;
        }
        // Sysfs entries may disappear between read_dir and canonicalize on detach.
        let Some(device) = optional_canonical(&path.join("device"))? else {
            continue;
        };
        let mut owned = None;
        for ancestor in device.ancestors() {
            if verify_usb(ancestor, serial)? {
                owned = Some(ancestor.to_path_buf());
                break;
            }
        }
        let Some(usb) = owned else { continue };
        let Some(driver) = optional_canonical(&device.join("driver"))? else {
            continue;
        };
        ensure!(
            driver.file_name().is_some_and(|name| name == "uvcvideo"),
            "Owned synthetic camera lacks native uvcvideo driver"
        );
        found.push((dev.join(entry.file_name()), usb));
    }
    Ok(found)
}
fn exact_video_node(serial: &str) -> Result<Option<(PathBuf, PathBuf)>> {
    let mut found = video_nodes_at(
        Path::new("/sys/class/video4linux"),
        Path::new("/dev"),
        serial,
        true,
    )?;
    ensure!(found.len() <= 1, "Ambiguous private video capture nodes");
    Ok(found.pop())
}
fn exact_usb_ancestor(serial: &str) -> Result<Option<PathBuf>> {
    let mut found = vec![];
    for entry in std::fs::read_dir("/sys/bus/usb/devices")? {
        let entry = match entry {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let Some(path) = optional_canonical(&entry.path())? else {
            continue;
        };
        if verify_usb(&path, serial)? {
            found.push(path);
        }
    }
    found.sort();
    found.dedup();
    ensure!(found.len() <= 1, "Ambiguous own synthetic USB ancestors");
    Ok(found.pop())
}
fn pin_fresh_capture_node(node: &Path, usb: &Path, serial: &str) -> Result<std::fs::File> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
    ensure!(
        exact_video_node(serial)?.as_ref() == Some(&(node.to_path_buf(), usb.to_path_buf())),
        "Synthetic camera identity changed before open"
    );
    let before = std::fs::symlink_metadata(node)?;
    ensure!(
        before.file_type().is_char_device(),
        "Owned camera path is not a direct character device"
    );
    let sys_node = Path::new("/sys/class/video4linux").join(
        node.file_name()
            .ok_or_else(|| anyhow::anyhow!("Missing owned video node name"))?,
    );
    let registered = std::fs::read_to_string(sys_node.join("dev"))?;
    let (major, minor) = registered
        .trim()
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("Invalid registered video device number"))?;
    ensure!(
        major.parse::<u32>()? == libc::major(before.rdev())
            && minor.parse::<u32>()? == libc::minor(before.rdev()),
        "Owned capture path does not match registered sysfs character device"
    );
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(node)?;
    let opened = file.metadata()?;
    ensure!(
        opened.file_type().is_char_device()
            && (opened.dev(), opened.ino(), opened.rdev())
                == (before.dev(), before.ino(), before.rdev()),
        "Synthetic capture node changed during open"
    );
    ensure!(
        exact_video_node(serial)?.as_ref() == Some(&(node.to_path_buf(), usb.to_path_buf())),
        "Synthetic camera detached during open"
    );
    Ok(file)
}
async fn bounded_stderr(mut reader: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut kept = vec![];
    let mut total = 0usize;
    let mut buffer = [0; 1024];
    loop {
        let size = reader.read(&mut buffer).await?;
        if size == 0 {
            return Ok(kept);
        };
        total += size;
        ensure!(total <= 65536, "Synthetic ffmpeg stderr exceeded64KiB");
        let retain = size.min(8192 - kept.len());
        kept.extend_from_slice(&buffer[..retain]);
    }
}
async fn capture_to_null(file: std::fs::File) -> Result<Duration> {
    let start = tokio::time::Instant::now();
    let mut child = tokio::process::Command::new("ffmpeg")
        .kill_on_drop(true)
        .args([
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "v4l2",
            "-input_format",
            "mjpeg",
            "-video_size",
            "640x480",
            "-framerate",
            "15",
            "-i",
            "/proc/self/fd/0",
            "-frames:v",
            "45",
            "-f",
            "null",
            "-",
        ])
        .stdin(Stdio::from(file))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("Missing owned capture stderr"))?;
    let result = tokio::time::timeout(Duration::from_secs(12), async {
        let (status, diagnostics) = tokio::try_join!(
            async { Ok::<_, anyhow::Error>(child.wait().await?) },
            bounded_stderr(stderr)
        )?;
        ensure!(
            status.success(),
            "Exact synthetic camera capture failed: {}",
            String::from_utf8_lossy(&diagnostics)
        );
        Ok::<_, anyhow::Error>(())
    })
    .await;
    if !matches!(result, Ok(Ok(()))) {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result??;
    let elapsed = start.elapsed();
    ensure!(
        (Duration::from_millis(2500)..=Duration::from_secs(5)).contains(&elapsed),
        "45 synthetic frames did not follow the15fps wall clock: {elapsed:?}"
    );
    Ok(elapsed)
}
/// Private1209:0001 is an in-house fixture identity, not a production allocation.
/// https://pid.codes/1209/0001/ No physical camera is opened by this fixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Requires root-reviewed explicit Linux VHCI synthetic-camera test window"]
async fn native_linux_uvcvideo_colorbars_to_null() -> Result<()> {
    ensure!(
        std::env::var("PORTHUB_PRIVATE_UVC_CLASS_TEST").as_deref() == Ok("1"),
        "Explicit private UVC authorization required"
    );
    ensure!(
        std::fs::read_to_string("/proc/self/status")?
            .lines()
            .any(|l| l.starts_with("Uid:") && l.split_whitespace().nth(2) == Some("0")),
        "Native fixture requires root"
    );
    let profile = PathBuf::from(std::env::var("PORTHUB_PRIVATE_UVC_PROFILE")?);
    ensure!(
        profile.is_absolute() && profile.is_file(),
        "Explicit existing registration path required"
    );
    let serial = format!(
        "PortHubPrivateUvc{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    let devnum = (std::process::id() as u16).max(1);
    let device = Device {
        busid: format!("65535-{devnum}"),
        vendor: "1209".into(),
        product: "0001".into(),
        serial: serial.clone(),
        name: "PortHub private synthetic colorbars".into(),
        busnum: 65535,
        devnum,
        speed: 3,
        blocked: None,
    };
    let mut wire = vec![0; 312];
    wire[..7].copy_from_slice(b"porthub");
    wire[256..256 + device.busid.len()].copy_from_slice(device.busid.as_bytes());
    for (offset, value) in [(288, 65535u32), (292, devnum as u32), (296, 3)] {
        wire[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    wire[300..302].copy_from_slice(&0x1209u16.to_be_bytes());
    wire[302..304].copy_from_slice(&1u16.to_be_bytes());
    wire[304..306].copy_from_slice(&0x100u16.to_be_bytes());
    wire[306..309].copy_from_slice(&[0xef, 2, 1]);
    wire[309] = 1;
    wire[310] = 1;
    wire[311] = 2;
    let camera = Arc::new(Mutex::new(Camera::new(
        Identity {
            vendor: 0x1209,
            product: 1,
        },
        serial.clone(),
    )?));
    let changed = Arc::new(Notify::new());
    let cancel = CancellationToken::new();
    let (streaming, mut demand) = watch::channel(CaptureDemand::default());
    let mut receiver = None;
    let mut executor = None;
    let mut producer = None;
    let mut saved_usb = None;
    let mut saved_nodes = Vec::<PathBuf>::new();
    let result=async {
    let (attached, stream) = crate::usb::attach_virtual(&profile, &device, &wire).await?;
    receiver=Some(attached);
    executor=Some( AbortOnDropHandle::new(tokio::spawn(serve(
        stream,
        camera.clone(),
        0xffff0000 | devnum as u32,
        changed.clone(),
        streaming,
        cancel.clone(),
    ))));
    producer=Some( AbortOnDropHandle::new(tokio::spawn({
        let camera = camera.clone();
        let cancel = cancel.clone();
        async move {
            let mut generation = 0;
            let mut sequence = 0;
            let mut epoch = String::new();
            let mut tick = tokio::time::interval(Duration::from_micros(66667));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {_=cancel.cancelled()=>return Ok::<(),anyhow::Error>(()),r=demand.changed()=>{r?;},_=tick.tick()=>{}}
                let state = *demand.borrow_and_update();
                if !state.active {
                    continue;
                }
                if generation != state.generation {
                    generation = state.generation;
                    sequence = 0;
                    epoch = format!("{generation:032x}");
                    camera.lock().map_err(|_|anyhow::anyhow!("Synthetic camera engine poisoned"))?.begin_epoch(&epoch)?;
                }
                sequence += 1;
                let frame = VideoFrame {
                    sequence,
                    source_monotonic_micros: sequence * 66667,
                    format: VideoFormat {
                        encoding: VideoEncoding::Mjpeg,
                        width: WIDTH,
                        height: HEIGHT,
                        fps_num: FPS,
                        fps_den: 1,
                    },
                    jpeg: JPEG.to_vec(),
                };
                camera.lock().map_err(|_|anyhow::anyhow!("Synthetic camera engine poisoned"))?.push(&epoch, frame)?;
                changed.notify_one();
            }
        }
    })));
        let(node,usb)=tokio::time::timeout(Duration::from_secs(10),async{loop{
            if let Some(usb)=exact_usb_ancestor(&serial)?{saved_usb=Some(usb);}
            let nodes=video_nodes_at(Path::new("/sys/class/video4linux"),Path::new("/dev"),&serial,false)?;
            for(node,_)in nodes{if !saved_nodes.contains(&node){saved_nodes.push(node);}}
            if let Some(value)=exact_video_node(&serial)?{return Ok::<_,anyhow::Error>(value)}
            tokio::time::sleep(Duration::from_millis(50)).await;
        }}).await??;
        saved_usb=Some(usb.clone());
        let file=pin_fresh_capture_node(&node,&usb,&serial)?;
        let elapsed=capture_to_null(file).await?;
        let completed=camera.lock().map_err(|_|anyhow::anyhow!("Synthetic camera engine poisoned"))?.counters.completed_frames;ensure!(completed>=45,"Insufficient synthetic video frames");
        println!("PRIVATE_UVC_CLASS_PROOF serial={serial} node={} frames={completed} elapsed_ms={} width=640 height=480 nominal_fps=15 physical_camera=false",node.display(),elapsed.as_millis());Ok::<_,anyhow::Error>(())
    }.await;
    cancel.cancel();
    if let Some(producer) = producer {
        let _ = tokio::time::timeout(Duration::from_secs(2), producer).await;
    }
    if let Some(executor) = executor {
        let _ = tokio::time::timeout(Duration::from_secs(2), executor).await;
    }
    drop(receiver);
    // Verify both USB ancestry and every owned V4L2 node, even on early failure.
    let cleanup = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let current_usb = exact_usb_ancestor(&serial)?;
            if saved_usb.is_none() {
                saved_usb = current_usb.clone();
            }
            let current_nodes = video_nodes_at(
                Path::new("/sys/class/video4linux"),
                Path::new("/dev"),
                &serial,
                false,
            )?;
            for (node, _) in &current_nodes {
                if !saved_nodes.contains(node) {
                    saved_nodes.push(node.clone());
                }
            }
            let usb_absent =
                saved_usb.as_ref().is_none_or(|path| !path.exists()) && current_usb.is_none();
            let nodes_absent =
                current_nodes.is_empty() && saved_nodes.iter().all(|path| !path.exists());
            if usb_absent && nodes_absent {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    cleanup??;
    println!(
        "PRIVATE_UVC_CLEANUP serial={serial} owned_usb_ancestor_absent=true owned_video_nodes_absent=true"
    );
    result
}

#[test]
fn sysfs_discovery_tolerates_detach_and_rechecks_full_identity() -> Result<()> {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir()?;
    let class = root.path().join("class");
    let dev = root.path().join("dev");
    let usb = root.path().join("devices/usb1/1-1");
    let interface = usb.join("1-1:1.0");
    let driver = root.path().join("drivers/uvcvideo");
    std::fs::create_dir_all(&interface)?;
    std::fs::create_dir_all(&driver)?;
    std::fs::write(usb.join("serial"), "OwnedSynthetic\n")?;
    std::fs::write(usb.join("idVendor"), "1209\n")?;
    std::fs::write(usb.join("idProduct"), "0001\n")?;
    symlink(&driver, interface.join("driver"))?;
    for index in 0..2 {
        let path = class.join(format!("video{index}"));
        std::fs::create_dir_all(&path)?;
        std::fs::write(path.join("index"), index.to_string())?;
        symlink(&interface, path.join("device"))?;
    }
    let removed = class.join("video99");
    std::fs::create_dir_all(&removed)?;
    std::fs::write(removed.join("index"), "0")?;
    symlink(root.path().join("already-detached"), removed.join("device"))?;
    assert_eq!(
        video_nodes_at(&class, &dev, "OwnedSynthetic", true)?.len(),
        1
    );
    assert_eq!(
        video_nodes_at(&class, &dev, "OwnedSynthetic", false)?.len(),
        2
    );
    std::fs::write(usb.join("idVendor"), "ffff")?;
    assert!(video_nodes_at(&class, &dev, "OwnedSynthetic", true).is_err());
    std::fs::write(usb.join("idVendor"), "1209")?;
    std::fs::write(usb.join("serial"), "SomeOtherCamera")?;
    assert!(video_nodes_at(&class, &dev, "OwnedSynthetic", true)?.is_empty());
    std::fs::write(usb.join("serial"), "OwnedSynthetic")?;
    std::fs::remove_file(interface.join("driver"))?;
    let wrong = root.path().join("drivers/foreign-driver");
    std::fs::create_dir_all(&wrong)?;
    symlink(wrong, interface.join("driver"))?;
    assert!(video_nodes_at(&class, &dev, "OwnedSynthetic", true).is_err());
    Ok(())
}
#[tokio::test]
async fn ffmpeg_diagnostic_capture_is_memory_bounded() -> Result<()> {
    let bytes = vec![b'x'; 65536];
    assert_eq!(bounded_stderr(bytes.as_slice()).await?.len(), 8192);
    let excessive = vec![b'x'; 65537];
    assert!(bounded_stderr(excessive.as_slice()).await.is_err());
    Ok(())
}
