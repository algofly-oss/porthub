//! On-demand exact-device camera capture. No inventory/default-device lookup and
//! no background source are created by loading this module. Capture requires an
//! explicit inherited-pipe request bound to a retained inventory proof.
use anyhow::{ensure, Result};
use porthub_components::media::{VideoEncoding, VideoFormat, MAX_VIDEO_FRAME};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
#[path = "video_jpeg.rs"]
mod jpeg;
#[cfg(target_pointer_width = "64")]
#[path = "linux_video_native.rs"]
mod native;
const POLL: Duration = Duration::from_millis(50);
const FRAME_DEADLINE: Duration = Duration::from_secs(5);
fn exact(format: VideoFormat) -> bool {
    format.encoding == VideoEncoding::Mjpeg
        && format.width == 640
        && format.height == 480
        && format.fps_den > 0
        && format.fps_num as u64 == 15 * format.fps_den as u64
}
/// Positive capability/mode rejection, distinct from disconnects or unknown I/O.
#[derive(Debug)]
pub struct CameraUnsupported(pub &'static str);
impl std::fmt::Display for CameraUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for CameraUnsupported {}
fn supported(condition: bool, reason: &'static str) -> Result<()> {
    if !condition {
        return Err(CameraUnsupported(reason).into());
    }
    Ok(())
}
/// Inventory-time selection proof. The facade stores this alongside the opaque
/// source ID; it must never reconstruct it from a path at capture time.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedDevice {
    native_path: String,
    rdev: u64,
    node_inode: u64,
    sys_path: String,
    sys_inode: u64,
    ancestors: Vec<(String, String)>,
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct VideoSource {
    pub device: porthub_components::media::Device,
    pub expected: ExpectedDevice,
}
/// Metadata-only inventory. Never opens a camera or chooses a default source.
#[cfg(target_pointer_width = "64")]
pub fn inventory() -> Result<Vec<VideoSource>> {
    native::inventory()
}
impl ExpectedDevice {
    pub fn source_id(&self) -> String {
        use porthub_components::media::{stable_source_id, Kind};
        let root = self
            .sys_path
            .split("/video4linux/")
            .next()
            .unwrap_or(&self.sys_path);
        let leaf = self
            .ancestors
            .iter()
            .find(|(key, _)| key.ends_with("/idVendor"))
            .map(|(key, _)| key.trim_end_matches("/idVendor"));
        let value = |suffix: &str| {
            self.ancestors
                .iter()
                .find(|(key, _)| leaf.is_some_and(|p| key == &format!("{p}/{suffix}")))
                .map(|(_, v)| v.trim())
                .unwrap_or("")
        };
        let hardware = if !value("serial").is_empty() {
            format!(
                "usb:{}:{}:{}",
                value("idVendor"),
                value("idProduct"),
                value("serial")
            )
        } else {
            format!("bus:{root}:{}:{}", value("idVendor"), value("idProduct"))
        };
        let interface = self
            .ancestors
            .iter()
            .find(|(key, _)| key.ends_with("/bInterfaceNumber"))
            .map(|(_, v)| v.trim())
            .unwrap_or("native");
        let index = self
            .ancestors
            .iter()
            .find(|(key, _)| key.ends_with("/index"))
            .map(|(_, v)| v.trim())
            .unwrap_or("unknown");
        stable_source_id(
            Kind::Camera,
            &hardware,
            &format!("interface:{interface}:index:{index}"),
        )
    }
    fn verify_held(&self, rdev: u64, inode: u64) -> Result<()> {
        ensure!(
            rdev == self.rdev && inode == self.node_inode,
            "Held camera does not match selected inventory node"
        );
        Ok(())
    }
    fn verify(&self, current: &Self) -> Result<()> {
        ensure!(self == current, "Selected inventory camera was replaced");
        Ok(())
    }
    /// Metadata-only inventory: no native camera handle or capture ioctl.
    #[cfg(target_pointer_width = "64")]
    pub fn inspect(native_path: &str) -> Result<Self> {
        native::selection(native_path)
    }
}
/// The outer authenticated desktop facade resolves its selected source ID to
/// this retained inventory proof. It owns PHV1 framing/epoch and a bounded latest
/// frame queue. Callbacks must never retain a borrowed native buffer or block.
pub fn capture(
    expected: &ExpectedDevice,
    format: VideoFormat,
    cancel: &AtomicBool,
    ready: impl FnOnce(VideoFormat) -> Result<()>,
    emit: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    ensure!(
        exact(format),
        "Camera requires exact 640x480 at 15 fps baseline MJPEG"
    );
    if cancel.load(Ordering::Acquire) {
        return Ok(());
    }
    #[cfg(target_pointer_width = "64")]
    {
        let mut backend = native::Camera::open(expected, format, cancel)?;
        let start = Instant::now();
        let outcome = run(&mut backend, format, cancel, ready, emit, || {
            start.elapsed()
        });
        complete(outcome, backend.finish())
    }
    #[cfg(not(target_pointer_width = "64"))]
    {
        let _ = (expected, ready, emit);
        anyhow::bail!("Native camera ABI is not validated for this architecture");
    }
}
fn complete(outcome: Result<()>, cleanup: Result<()>) -> Result<()> {
    match (outcome, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => {
            Err(cleanup.context(format!("Camera capture also failed: {error:#}")))
        }
    }
}
trait Backend {
    fn next(&mut self, wait: Duration) -> Result<Option<Vec<u8>>>;
}
struct Image(Vec<u8>);
impl Drop for Image {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
fn baseline(jpeg: &[u8]) -> bool {
    jpeg::baseline(jpeg)
}

fn run<B: Backend>(
    backend: &mut B,
    format: VideoFormat,
    cancel: &AtomicBool,
    ready: impl FnOnce(VideoFormat) -> Result<()>,
    mut emit: impl FnMut(&[u8]) -> Result<()>,
    mut now: impl FnMut() -> Duration,
) -> Result<()> {
    ensure!(exact(format), "Unsupported camera mode");
    let mut ready = Some(ready);
    let mut deadline = now() + FRAME_DEADLINE;
    loop {
        if cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        ensure!(
            now() < deadline,
            "Camera did not deliver an exact valid frame before timeout"
        );
        let Some(bytes) = backend.next(POLL)? else {
            continue;
        };
        let image = Image(bytes);
        if cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        ensure!(
            image.0.len() <= MAX_VIDEO_FRAME,
            "Camera returned an oversized JPEG buffer"
        );
        // Drivers may produce an incomplete startup frame. Never publish it or
        // signal readiness; wait for a valid exact frame within the same deadline.
        if !baseline(&image.0) {
            continue;
        }
        if let Some(ready) = ready.take() {
            ready(format)?;
        }
        if cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        emit(&image.0)?;
        deadline = now() + FRAME_DEADLINE;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, collections::VecDeque};
    fn mode() -> VideoFormat {
        VideoFormat {
            encoding: VideoEncoding::Mjpeg,
            width: 640,
            height: 480,
            fps_num: 15,
            fps_den: 1,
        }
    }
    fn jpeg() -> Vec<u8> {
        vec![
            255, 216, 255, 192, 0, 17, 8, 1, 224, 2, 128, 3, 1, 17, 0, 2, 17, 0, 3, 17, 0, 255,
            218, 0, 12, 3, 1, 0, 2, 0, 3, 0, 0, 63, 0, 42, 255, 217,
        ]
    }
    #[test]
    fn camera_source_id_tracks_physical_serial_and_endpoint_not_video_number() {
        let selected = ExpectedDevice {
            native_path: "/dev/video4".into(),
            rdev: 123,
            node_inode: 456,
            sys_path: "/sys/devices/usb1/1-2/1-2:1.0/video4linux/video4".into(),
            sys_inode: 789,
            ancestors: vec![
                ("/sys/devices/usb1/1-2/idVendor".into(), "abcd".into()),
                ("/sys/devices/usb1/1-2/idProduct".into(), "0001".into()),
                ("/sys/devices/usb1/1-2/serial".into(), "chosen".into()),
                (
                    "/sys/devices/usb1/1-2/1-2:1.0/bInterfaceNumber".into(),
                    "00".into(),
                ),
                (
                    "/sys/devices/usb1/1-2/1-2:1.0/video4linux/video4/index".into(),
                    "0".into(),
                ),
            ],
        };
        let mut moved = selected.clone();
        moved.native_path = "/dev/video9".into();
        moved.rdev += 1;
        moved.node_inode += 1;
        moved.sys_inode += 1;
        moved.sys_path = moved
            .sys_path
            .replace("usb1/1-2/1-2", "usb2/2-4/2-4")
            .replace("video4", "video9");
        for (key, _) in &mut moved.ancestors {
            *key = key
                .replace("usb1/1-2/1-2", "usb2/2-4/2-4")
                .replace("usb1/1-2/", "usb2/2-4/")
                .replace("video4/", "video9/");
        }
        assert_eq!(selected.source_id(), moved.source_id());
        assert!(selected.verify(&moved).is_err());
        moved
            .ancestors
            .iter_mut()
            .find(|(key, _)| key.ends_with("/serial"))
            .unwrap()
            .1 = "other".into();
        assert_ne!(selected.source_id(), moved.source_id());
        let mut other_interface = selected.clone();
        other_interface
            .ancestors
            .iter_mut()
            .find(|(key, _)| key.ends_with("/bInterfaceNumber"))
            .unwrap()
            .1 = "01".into();
        assert_ne!(selected.source_id(), other_interface.source_id());
        let mut serialless = selected.clone();
        serialless
            .ancestors
            .retain(|(key, _)| !key.ends_with("/serial"));
        let mut replacement = serialless.clone();
        replacement
            .ancestors
            .iter_mut()
            .find(|(key, _)| key.ends_with("/idProduct"))
            .unwrap()
            .1 = "0002".into();
        assert_ne!(serialless.source_id(), replacement.source_id());
    }
    #[test]
    fn capture_never_reports_success_when_cleanup_failed() {
        assert!(complete(Ok(()), Ok(())).is_ok());
        assert!(complete(Ok(()), Err(anyhow::anyhow!("restore failed")))
            .unwrap_err()
            .to_string()
            .contains("restore failed"));
        let error = complete(
            Err(anyhow::anyhow!("capture failed")),
            Err(anyhow::anyhow!("restore failed")),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("capture failed") && message.contains("restore failed"));
        let error = complete(
            Err(CameraUnsupported("unsupported").into()),
            Err(anyhow::anyhow!("restore failed")),
        )
        .unwrap_err();
        assert!(
            !error.chain().any(|e| e.is::<CameraUnsupported>()),
            "Cleanup failure must not be cached as unsupported"
        );
    }
    #[test]
    fn inventory_proof_rejects_hotplug_reuse_and_serial_changes() {
        let selected = ExpectedDevice {
            native_path: "/dev/video4".into(),
            rdev: 123,
            node_inode: 456,
            sys_path: "/sys/devices/usb1/1-2/video4linux/video4".into(),
            sys_inode: 789,
            ancestors: vec![("/sys/devices/usb1/1-2/serial".into(), "chosen".into())],
        };
        assert!(selected.verify(&selected).is_ok());
        assert!(selected
            .verify_held(selected.rdev, selected.node_inode)
            .is_ok());
        // ABA: pathname snapshots can both match A while the held FD is B.
        assert!(selected.verify(&selected.clone()).is_ok());
        assert!(selected
            .verify_held(selected.rdev, selected.node_inode + 1)
            .is_err());
        assert!(selected
            .verify_held(selected.rdev + 1, selected.node_inode)
            .is_err());
        let mut changes = vec![];
        let mut replaced = selected.clone();
        replaced.node_inode += 1;
        changes.push(replaced);
        let mut replaced = selected.clone();
        replaced.sys_inode += 1;
        changes.push(replaced);
        let mut replaced = selected.clone();
        replaced.rdev += 1;
        changes.push(replaced);
        let mut replaced = selected.clone();
        replaced.ancestors[0].1 = "other".into();
        changes.push(replaced);
        let mut replaced = selected.clone();
        replaced.sys_path.push_str("-other");
        changes.push(replaced);
        let mut replaced = selected.clone();
        replaced.native_path = "/dev/video5".into();
        changes.push(replaced);
        for replaced in changes {
            assert!(selected.verify(&replaced).is_err());
        }
    }
    #[test]
    fn baseline_requires_complete_scan_and_exact_final_eoi() {
        assert!(baseline(include_bytes!(
            "../../porthub-agent/tests/data/private_uvc_colorbars_640x480.jpg"
        )));
        let good = jpeg();
        assert!(baseline(&good));
        let mut no_scan = good[..21].to_vec();
        no_scan.extend([255, 217]);
        assert!(!baseline(&no_scan));
        let mut no_entropy = good.clone();
        no_entropy.remove(no_entropy.len() - 3);
        assert!(!baseline(&no_entropy));
        let mut missing_eoi = good.clone();
        missing_eoi.truncate(missing_eoi.len() - 2);
        assert!(!baseline(&missing_eoi));
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(!baseline(&trailing));
        let mut bad_scan = good.clone();
        bad_scan[27] = 99;
        assert!(!baseline(&bad_scan));
        let mut progressive = good.clone();
        progressive[3] = 0xc2;
        assert!(!baseline(&progressive));
        let mut stuffed = good[..good.len() - 2].to_vec();
        stuffed.extend([255, 0, 255, 208, 43, 255, 217]);
        assert!(baseline(&stuffed));
        let mut premature = good[..good.len() - 2].to_vec();
        premature.extend([255, 218, 0, 2, 255, 217]);
        assert!(!baseline(&premature));
    }
    struct Fake<'a> {
        frames: VecDeque<Vec<u8>>,
        time: &'a Cell<Duration>,
        calls: usize,
    }
    impl Backend for Fake<'_> {
        fn next(&mut self, wait: Duration) -> Result<Option<Vec<u8>>> {
            assert!(wait <= POLL);
            self.calls += 1;
            self.time.set(self.time.get() + wait);
            Ok(self.frames.pop_front())
        }
    }
    #[test]
    fn ready_requires_valid_exact_frame_then_emit() {
        let clock = Cell::new(Duration::ZERO);
        let cancel = AtomicBool::new(false);
        let events = std::cell::RefCell::new(vec![]);
        let mut b = Fake {
            frames: VecDeque::from([jpeg()]),
            time: &clock,
            calls: 0,
        };
        run(
            &mut b,
            mode(),
            &cancel,
            |_| {
                events.borrow_mut().push("ready");
                Ok(())
            },
            |bytes| {
                assert_eq!(bytes, jpeg());
                events.borrow_mut().push("frame");
                cancel.store(true, Ordering::Release);
                Ok(())
            },
            || clock.get(),
        )
        .unwrap();
        assert_eq!(*events.borrow(), ["ready", "frame"]);
        assert_eq!(b.calls, 1);
    }
    #[test]
    fn malformed_or_progressive_frame_never_ready() {
        for mut j in [vec![], jpeg(), jpeg()] {
            if j.len() > 4 {
                j[3] = 0xc2;
            }
            let clock = Cell::new(Duration::ZERO);
            let mut b = Fake {
                frames: VecDeque::from([j]),
                time: &clock,
                calls: 0,
            };
            assert!(run(
                &mut b,
                mode(),
                &AtomicBool::new(false),
                |_| panic!("premature readiness"),
                |_| panic!("bad frame emitted"),
                || clock.get()
            )
            .is_err());
        }
    }
    #[test]
    fn wrong_rate_and_pre_cancel_do_not_poll() {
        let clock = Cell::new(Duration::ZERO);
        let mut b = Fake {
            frames: VecDeque::new(),
            time: &clock,
            calls: 0,
        };
        let mut f = mode();
        f.fps_num = 30;
        assert!(run(
            &mut b,
            f,
            &AtomicBool::new(false),
            |_| Ok(()),
            |_| Ok(()),
            || clock.get()
        )
        .is_err());
        run(
            &mut b,
            mode(),
            &AtomicBool::new(true),
            |_| panic!(),
            |_| panic!(),
            || clock.get(),
        )
        .unwrap();
        assert_eq!(b.calls, 0);
    }
    #[test]
    fn startup_timeout_and_slow_parent_fail_bounded() {
        let clock = Cell::new(Duration::ZERO);
        let mut b = Fake {
            frames: VecDeque::new(),
            time: &clock,
            calls: 0,
        };
        assert!(run(
            &mut b,
            mode(),
            &AtomicBool::new(false),
            |_| panic!(),
            |_| panic!(),
            || clock.get()
        )
        .is_err());
        assert_eq!(b.calls, 100);
        let mut b = Fake {
            frames: VecDeque::from([jpeg()]),
            time: &clock,
            calls: 0,
        };
        assert!(run(
            &mut b,
            mode(),
            &AtomicBool::new(false),
            |_| Ok(()),
            |_| anyhow::bail!("bounded queue closed"),
            || clock.get()
        )
        .is_err());
        assert_eq!(b.calls, 1);
    }
    #[test]
    fn cancelled_capture_never_opens_even_nonexistent_source() {
        capture(
            &ExpectedDevice {
                native_path: "/dev/video999999999".into(),
                rdev: 0,
                node_inode: 0,
                sys_path: String::new(),
                sys_inode: 0,
                ancestors: vec![],
            },
            mode(),
            &AtomicBool::new(true),
            |_| panic!("cancelled capture readiness"),
            |_| panic!("cancelled capture emitted"),
        )
        .unwrap();
    }
    #[test]
    fn oversized_or_wrong_geometry_is_not_ready() {
        let mut large = jpeg();
        large.resize(MAX_VIDEO_FRAME + 1, 0);
        let mut small = jpeg();
        small[9..11].copy_from_slice(&320u16.to_be_bytes());
        for image in [large, small] {
            let clock = Cell::new(Duration::ZERO);
            let mut b = Fake {
                frames: VecDeque::from([image]),
                time: &clock,
                calls: 0,
            };
            assert!(run(
                &mut b,
                mode(),
                &AtomicBool::new(false),
                |_| panic!("invalid camera ready"),
                |_| panic!("invalid camera output"),
                || clock.get()
            )
            .is_err());
        }
    }
    #[test]
    fn invalid_startup_frame_does_not_prevent_next_valid_frame() {
        let clock = Cell::new(Duration::ZERO);
        let cancel = AtomicBool::new(false);
        let mut b = Fake {
            frames: VecDeque::from([vec![], jpeg()]),
            time: &clock,
            calls: 0,
        };
        let ready = Cell::new(false);
        run(
            &mut b,
            mode(),
            &cancel,
            |_| {
                ready.set(true);
                Ok(())
            },
            |_| {
                assert!(ready.get());
                cancel.store(true, Ordering::Release);
                Ok(())
            },
            || clock.get(),
        )
        .unwrap();
        assert_eq!(b.calls, 2);
    }
}
