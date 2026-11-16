//! Minimal 64-bit Linux V4L2 single-plane capture ABI, from the public UAPI.
//! https://docs.kernel.org/userspace-api/media/v4l/dev-capture.html
//! https://docs.kernel.org/userspace-api/media/v4l/vidioc-reqbufs.html
use super::*;
use anyhow::Context;
use std::{
    ffi::{c_int, c_long, c_short, c_ulong, c_void},
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
    ptr::NonNull,
};
const CAPTURE: u32 = 1;
const MMAP: u32 = 1;
const MJPG: u32 = u32::from_le_bytes(*b"MJPG");
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Capability {
    driver: [u8; 16],
    card: [u8; 32],
    bus: [u8; 32],
    version: u32,
    caps: u32,
    device_caps: u32,
    reserved: [u32; 3],
}
#[repr(C)]
#[derive(Clone, Copy)]
union FormatData {
    raw: [u8; 200],
    alignment: u64,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Format {
    kind: u32,
    data: FormatData,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Parameters {
    kind: u32,
    data: [u32; 50],
}
#[repr(C)]
#[derive(Default)]
struct Buffers {
    count: u32,
    kind: u32,
    memory: u32,
    capabilities: u32,
    flags: u8,
    reserved: [u8; 3],
}
#[repr(C)]
union Location {
    offset: u32,
    address: c_ulong,
}
#[repr(C)]
struct Buffer {
    index: u32,
    kind: u32,
    used: u32,
    flags: u32,
    field: u32,
    time: [c_long; 2],
    timecode: [u8; 16],
    sequence: u32,
    memory: u32,
    location: Location,
    length: u32,
    reserved2: u32,
    request_fd: i32,
}
impl Buffer {
    fn new(index: u32) -> Self {
        Self {
            index,
            kind: CAPTURE,
            used: 0,
            flags: 0,
            field: 0,
            time: [0; 2],
            timecode: [0; 16],
            sequence: 0,
            memory: MMAP,
            location: Location { address: 0 },
            length: 0,
            reserved2: 0,
            request_fd: 0,
        }
    }
}
#[repr(C)]
struct PollFd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}
unsafe extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, arg: *mut c_void) -> c_int;
    fn poll(fds: *mut PollFd, count: c_ulong, timeout: c_int) -> c_int;
    fn mmap(
        address: *mut c_void,
        length: usize,
        protection: c_int,
        flags: c_int,
        fd: c_int,
        offset: c_long,
    ) -> *mut c_void;
    fn munmap(address: *mut c_void, length: usize) -> c_int;
}
const fn code<T>(direction: u32, number: u32) -> c_ulong {
    ((direction << 30) | ((std::mem::size_of::<T>() as u32) << 16) | ((b'V' as u32) << 8) | number)
        as c_ulong
}
fn request<T>(file: &File, direction: u32, number: u32, data: &mut T) -> Result<()> {
    loop {
        let rc = unsafe {
            ioctl(
                file.as_raw_fd(),
                code::<T>(direction, number),
                (data as *mut T).cast(),
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(e).context("Native camera request failed");
    }
}
fn mode_request<T>(file: &File, direction: u32, number: u32, data: &mut T) -> Result<()> {
    match request(file, direction, number, data) {
        Err(error)
            if error.chain().any(|e| {
                e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.raw_os_error() == Some(22))
            }) =>
        {
            Err(
                CameraUnsupported("Selected camera does not support the requested MJPEG mode")
                    .into(),
            )
        }
        result => result,
    }
}
fn identity(file: &File) -> Result<Capability> {
    let mut c = Capability::default();
    request(file, 2, 0, &mut c)?;
    let caps = if c.caps & 0x80000000 != 0 {
        c.device_caps
    } else {
        c.caps
    };
    supported(
        caps & 0x04000001 == 0x04000001 && caps & 0x0000c000 == 0,
        "Selected camera does not support single-plane capture",
    )?;
    for field in [&c.driver[..], &c.card[..], &c.bus[..]] {
        let n = field.iter().position(|b| *b == 0).unwrap_or(field.len());
        ensure!(
            n > 0
                && field[..n].iter().any(|b| !b.is_ascii_whitespace())
                && field[..n]
                    .iter()
                    .all(|b| b.is_ascii_graphic() || *b == b' '),
            "Camera identity is unavailable"
        );
    }
    Ok(c)
}
pub(super) fn inventory() -> Result<Vec<VideoSource>> {
    use porthub_components::media::{CaptureState, Device, Kind};
    let entries = match std::fs::read_dir("/sys/class/video4linux") {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    let mut sources = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut count = 0;
    for entry in entries {
        let entry = entry?;
        count += 1;
        ensure!(count <= 128, "Camera inventory exceeds bound");
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name
            .strip_prefix("video")
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        let expected = match ExpectedDevice::inspect(&format!("/dev/{name}")) {
            Ok(v) => v,
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue
            }
            Err(e) => return Err(e),
        };
        // Forwarded/synthetic receivers are not physical camera sources. Do not
        // silently create a media feedback loop; relay needs explicit lineage.
        if Path::new(&expected.sys_path).components().any(|c| {
            let c = c.as_os_str().to_string_lossy();
            c == "virtual" || c.starts_with("vhci_hcd")
        }) {
            continue;
        }
        // Metadata nodes generally have index1; exact native mode is revalidated
        // only after explicit capture, never by starting a discovery stream.
        if expected
            .ancestors
            .iter()
            .find(|(k, _)| k.ends_with("/index"))
            .is_none_or(|(_, v)| v.trim() != "0")
        {
            continue;
        }
        let label = std::fs::read_to_string(entry.path().join("name"))?;
        let label = label.trim();
        ensure!(
            !label.is_empty() && label.len() <= 256 && !label.chars().any(char::is_control),
            "Camera label is invalid"
        );
        ensure!(
            serde_json::to_vec(&expected)?.len() <= 6144,
            "Camera selection proof exceeds bound"
        );
        let id = expected.source_id();
        ensure!(
            seen.insert(id.clone()),
            "Camera physical identity is ambiguous"
        );
        sources.push(VideoSource {
            device: Device {
                id,
                name: label.into(),
                kind: Kind::Camera,
                backend: "v4l2".into(),
                native_id: expected.native_path.clone(),
                capture_available: false,
                capture_state: CaptureState::PermissionUnknown,
                unavailable_reason: None,
            },
            expected,
        });
    }
    Ok(sources)
}
fn pix(data: &[u8; 200], n: usize) -> u32 {
    u32::from_ne_bytes(data[n..n + 4].try_into().unwrap())
}
fn exact_pixels(data: &[u8; 200]) -> bool {
    pix(data, 0) == 640
        && pix(data, 4) == 480
        && pix(data, 8) == MJPG
        && pix(data, 12) == 1
        && (1..=MAX_VIDEO_FRAME as u32).contains(&pix(data, 20))
}
struct Mapping {
    address: NonNull<u8>,
    length: usize,
}
impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe {
            munmap(self.address.as_ptr().cast(), self.length);
        }
    }
}
pub(super) struct Camera {
    file: File,
    maps: Vec<Mapping>,
    allocated: bool,
    streaming: bool,
    restore: Option<(Format, Parameters)>,
    configuration_changed: bool,
}
pub(super) fn selection(path: &str) -> Result<ExpectedDevice> {
    let path = Path::new(path);
    ensure!(
        path.is_absolute()
            && path.parent() == Some(Path::new("/dev"))
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_prefix("video"))
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())),
        "Explicit canonical video device required"
    );
    let before = std::fs::symlink_metadata(path)?;
    ensure!(
        before.file_type().is_char_device(),
        "Selected path is not a direct camera device"
    );
    let sys = Path::new("/sys/class/video4linux").join(path.file_name().unwrap());
    let sys = std::fs::canonicalize(sys)?;
    ensure!(
        sys.starts_with("/sys/devices"),
        "Camera is outside the kernel device tree"
    );
    let dev = before.rdev();
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000);
    let minor = (dev & 0xff) | ((dev >> 12) & 0xffffff00);
    ensure!(
        std::fs::read_to_string(sys.join("dev"))?.trim() == format!("{major}:{minor}"),
        "Camera node differs from sysfs"
    );
    let mut ancestors = vec![];
    let index = std::fs::read_to_string(sys.join("index"))?;
    ensure!(
        index.trim().parse::<u32>().is_ok_and(|v| v < 32),
        "Camera index exceeds bound"
    );
    ancestors.push((format!("{}/index", sys.display()), index));
    for ancestor in sys
        .ancestors()
        .take_while(|p| p.starts_with("/sys/devices"))
    {
        for key in ["serial", "idVendor", "idProduct", "bInterfaceNumber"] {
            match std::fs::read_to_string(ancestor.join(key)) {
                Ok(value) => {
                    ensure!(value.len() <= 512, "Camera identity field exceeds bound");
                    ancestors.push((format!("{}/{}", ancestor.display(), key), value));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).context("Camera ancestry is unavailable"),
            }
        }
    }
    Ok(ExpectedDevice {
        native_path: path.to_str().context("Invalid camera path")?.into(),
        rdev: dev,
        node_inode: before.ino(),
        sys_path: sys.to_str().context("Invalid sysfs path")?.into(),
        sys_inode: std::fs::metadata(&sys)?.ino(),
        ancestors,
    })
}
impl Camera {
    pub(super) fn open(
        expected: &ExpectedDevice,
        format: VideoFormat,
        cancel: &AtomicBool,
    ) -> Result<Self> {
        ensure!(exact(format), "Unsupported native camera format");
        expected.verify(&selection(&expected.native_path)?)?;
        let path = Path::new(&expected.native_path);
        let before = std::fs::symlink_metadata(path)?;
        // V4L2 requires an I/O-capable handle to configure its capture queue. Only
        // capture ioctls are used; mapping flags follow V4L2, and write() is absent.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(0x20000 | 0x800)
            .open(path)
            .context("Selected camera is unavailable")?;
        let held = file.metadata()?;
        ensure!(
            held.file_type().is_char_device()
                && held.rdev() == before.rdev()
                && held.ino() == before.ino(),
            "Selected camera changed during open"
        );
        expected.verify_held(held.rdev(), held.ino())?;
        let dev = held.rdev();
        let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000);
        let minor = (dev & 0xff) | ((dev >> 12) & 0xffffff00);
        let sys = Path::new("/sys/class/video4linux").join(path.file_name().unwrap());
        ensure!(
            std::fs::read_to_string(sys.join("dev"))?.trim() == format!("{major}:{minor}"),
            "Camera descriptor does not match selected sysfs node"
        );
        let held_identity = identity(&file)?;
        expected.verify(&selection(&expected.native_path)?)?;
        ensure!(!cancel.load(Ordering::Acquire), "Camera request cancelled");
        ensure!(
            identity(&file)? == held_identity,
            "Camera identity changed before configuration"
        );
        let mut old_format = Format {
            kind: CAPTURE,
            data: FormatData { raw: [0; 200] },
        };
        request(&file, 3, 4, &mut old_format)?;
        let mut old_parameters = Parameters {
            kind: CAPTURE,
            data: [0; 50],
        };
        request(&file, 3, 21, &mut old_parameters)?;
        supported(
            old_parameters.data[0] & 0x1000 != 0
                && old_parameters.data[2] > 0
                && old_parameters.data[3] > 0,
            "Selected camera cannot expose a verifiable frame rate",
        )?;
        let mut camera = Self {
            file,
            maps: vec![],
            allocated: false,
            streaming: false,
            restore: Some((old_format, old_parameters)),
            configuration_changed: false,
        };
        let configured = (|| -> Result<()> {
            let mut f = Format {
                kind: CAPTURE,
                data: FormatData { raw: [0; 200] },
            };
            let p = unsafe { &mut f.data.raw };
            for (n, v) in [
                (0, 640u32),
                (4, 480),
                (8, MJPG),
                (12, 1),
                (20, MAX_VIDEO_FRAME as u32),
            ] {
                p[n..n + 4].copy_from_slice(&v.to_ne_bytes());
            }
            mode_request(&camera.file, 3, 64, &mut f)?;
            supported(
                exact_pixels(unsafe { &f.data.raw }),
                "Selected camera cannot supply exact 640x480 MJPEG",
            )?;
            camera.configuration_changed = true;
            mode_request(&camera.file, 3, 5, &mut f)?;
            supported(
                exact_pixels(unsafe { &f.data.raw }),
                "Selected camera changed the required MJPEG mode",
            )?;
            let mut parameters = old_parameters;
            parameters.data[2] = 1;
            parameters.data[3] = 15;
            mode_request(&camera.file, 3, 22, &mut parameters)?;
            supported(
                parameters.data[2] > 0
                    && parameters.data[3] as u64 == 15 * parameters.data[2] as u64,
                "Selected camera cannot supply nominal 15fps",
            )?;
            let mut buffers = Buffers {
                count: 4,
                kind: CAPTURE,
                memory: MMAP,
                ..Default::default()
            };
            request(&camera.file, 3, 8, &mut buffers)?;
            camera.allocated = true;
            ensure!(
                (1..=4).contains(&buffers.count),
                "Camera buffer count exceeds limit"
            );
            for index in 0..buffers.count {
                ensure!(!cancel.load(Ordering::Acquire), "Camera request cancelled");
                let mut buffer = Buffer::new(index);
                request(&camera.file, 3, 9, &mut buffer)?;
                ensure!(
                    (1..=MAX_VIDEO_FRAME as u32).contains(&buffer.length)
                        && buffer.memory == MMAP
                        && buffer.kind == CAPTURE,
                    "Camera buffer exceeds bound"
                );
                let address = unsafe {
                    mmap(
                        std::ptr::null_mut(),
                        buffer.length as usize,
                        3, // V4L2 requires PROT_READ|PROT_WRITE even for capture.
                        1, // MAP_SHARED; application only creates read-only slices.
                        camera.file.as_raw_fd(),
                        buffer.location.offset as c_long,
                    )
                };
                ensure!(
                    address as usize != usize::MAX,
                    "Camera memory mapping failed"
                );
                let Some(address) = NonNull::new(address.cast::<u8>()) else {
                    unsafe {
                        munmap(address, buffer.length as usize);
                    }
                    anyhow::bail!("Invalid camera mapping");
                };
                camera.maps.push(Mapping {
                    address,
                    length: buffer.length as usize,
                });
                request(&camera.file, 3, 15, &mut buffer)?;
            }
            ensure!(!cancel.load(Ordering::Acquire), "Camera request cancelled");
            let mut kind = CAPTURE;
            request(&camera.file, 1, 18, &mut kind)?;
            camera.streaming = true;
            Ok(())
        })();
        if let Err(error) = configured {
            return complete(Err(error), camera.finish()).map(|_| camera);
        }
        Ok(camera)
    }
}
// DQBUF ERROR is recoverable per the kernel API, but never excuses bad
// type/index/bounds. A skipped frame is requeued by next() before returning.
fn frame_length(buffer: &Buffer, lengths: &[usize]) -> Result<Option<usize>> {
    ensure!(
        buffer.kind == CAPTURE && buffer.memory == MMAP,
        "Invalid camera buffer type"
    );
    let length = *lengths
        .get(buffer.index as usize)
        .ok_or_else(|| anyhow::anyhow!("Invalid camera buffer index"))?;
    ensure!(
        buffer.used as usize <= length && buffer.used as usize <= MAX_VIDEO_FRAME,
        "Camera frame exceeds mapped buffer"
    );
    if buffer.flags & 0x40 != 0 || buffer.used == 0 {
        return Ok(None);
    }
    Ok(Some(buffer.used as usize))
}
impl Backend for Camera {
    fn next(&mut self, wait: Duration) -> Result<Option<Vec<u8>>> {
        let mut fd = PollFd {
            fd: self.file.as_raw_fd(),
            events: 1,
            revents: 0,
        };
        let result = unsafe { poll(&mut fd, 1, wait.min(POLL).as_millis() as c_int) };
        if result < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                return Ok(None);
            }
            return Err(e).context("Camera readiness failed");
        }
        if result == 0 {
            return Ok(None);
        }
        ensure!(
            fd.revents & 0x38 == 0,
            "Camera disconnected or capture failed"
        );
        let mut buffer = Buffer::new(0);
        if let Err(e) = request(&self.file, 3, 17, &mut buffer) {
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock)
            {
                return Ok(None);
            }
            return Err(e);
        }
        // Copy while owned, then requeue BEFORE validating JPEG/emitting/readiness.
        // Thus a slow/closed parent never holds one of the native device buffers.
        let frame = (|| {
            let lengths: Vec<usize> = self.maps.iter().map(|m| m.length).collect();
            let Some(length) = frame_length(&buffer, &lengths)? else {
                return Ok(None);
            };
            let map = &self.maps[buffer.index as usize];
            Ok::<_, anyhow::Error>(Some(
                unsafe { std::slice::from_raw_parts(map.address.as_ptr(), length) }.to_vec(),
            ))
        })();
        // Never send an invalid driver-supplied index back as a queue operation.
        if (buffer.index as usize) < self.maps.len() {
            let mut returned = Buffer::new(buffer.index);
            request(&self.file, 3, 15, &mut returned)?;
        }
        frame
    }
}
impl Camera {
    /// Explicit cleanup reports failures on normal capture exit. Drop retries
    /// best effort on constructor failure/disconnection/unwind.
    pub(super) fn finish(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        if self.streaming {
            let mut kind = CAPTURE;
            match request(&self.file, 1, 19, &mut kind) {
                Ok(()) => self.streaming = false,
                Err(_) => errors.push("stream stop failed"),
            }
        }
        self.maps.clear();
        if self.allocated {
            let mut buffers = Buffers {
                count: 0,
                kind: CAPTURE,
                memory: MMAP,
                ..Default::default()
            };
            match request(&self.file, 3, 8, &mut buffers) {
                Ok(()) => {
                    self.allocated = false;
                    self.streaming = false;
                }
                Err(_) => errors.push("capture buffers could not be freed"),
            }
        }
        if self.configuration_changed {
            if let Some((original_format, original_parameters)) = self.restore {
                let mut format = original_format;
                let mut parameters = original_parameters;
                let set_format = request(&self.file, 3, 5, &mut format);
                let set_rate = request(&self.file, 3, 22, &mut parameters);
                if set_format.is_err() {
                    errors.push("original camera format restoration failed");
                }
                if set_rate.is_err() {
                    errors.push("original camera rate restoration failed");
                }
                let mut actual_format = Format {
                    kind: CAPTURE,
                    data: FormatData { raw: [0; 200] },
                };
                let mut actual_parameters = Parameters {
                    kind: CAPTURE,
                    data: [0; 50],
                };
                let verified = request(&self.file,3,4,&mut actual_format).is_ok()
                    &&request(&self.file,3,21,&mut actual_parameters).is_ok()
                    &&actual_format.kind==original_format.kind
                    // Compare defined single-plane pixel format fields only,
                    // excluding driver-reserved union padding.
                    &&unsafe {actual_format.data.raw[..48]==original_format.data.raw[..48]}
                    &&actual_parameters.data[1..4]==original_parameters.data[1..4];
                if !verified {
                    errors.push("original camera format/rate read-back differs");
                }
                if set_format.is_ok() && set_rate.is_ok() && verified {
                    self.configuration_changed = false;
                }
            } else {
                errors.push("original camera configuration is unavailable");
            }
        }
        ensure!(
            errors.is_empty(),
            "Camera cleanup failed: {}",
            errors.join("; ")
        );
        Ok(())
    }
}
impl Drop for Camera {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recoverable_driver_frames_are_skipped_but_invalid_metadata_is_fatal() {
        let mut b = Buffer::new(0);
        b.used = 10;
        assert_eq!(frame_length(&b, &[64]).unwrap(), Some(10));
        b.flags = 0x40;
        assert_eq!(frame_length(&b, &[64]).unwrap(), None);
        b.flags = 0;
        b.used = 0;
        assert_eq!(frame_length(&b, &[64]).unwrap(), None);
        b.flags = 0x40;
        b.used = 65;
        assert!(frame_length(&b, &[64]).is_err());
        b.used = 0;
        b.index = 1;
        assert!(frame_length(&b, &[64]).is_err());
        b.index = 0;
        b.kind = 2;
        assert!(frame_length(&b, &[64]).is_err());
        b.kind = CAPTURE;
        b.memory = 2;
        assert!(frame_length(&b, &[64]).is_err());
    }
    #[test]
    fn kernel_64bit_abi_and_ioctl_numbers() {
        assert_eq!(std::mem::size_of::<Capability>(), 104);
        assert_eq!(std::mem::size_of::<Format>(), 208);
        assert_eq!(std::mem::size_of::<Parameters>(), 204);
        assert_eq!(std::mem::size_of::<Buffers>(), 20);
        assert_eq!(std::mem::size_of::<Buffer>(), 88);
        assert_eq!(std::mem::offset_of!(Buffer, time), 24);
        assert_eq!(std::mem::offset_of!(Buffer, location), 64);
        assert_eq!(code::<Capability>(2, 0), 0x80685600);
        assert_eq!(code::<Buffer>(3, 17), 0xc0585611);
    }
    #[test]
    fn mode_negotiation_never_silently_accepts_resize_or_raw_pixels() {
        let mut p = [0; 200];
        for (n, v) in [(0, 640u32), (4, 480), (8, MJPG), (12, 1), (20, 65536)] {
            p[n..n + 4].copy_from_slice(&v.to_ne_bytes());
        }
        assert!(exact_pixels(&p));
        p[0..4].copy_from_slice(&320u32.to_ne_bytes());
        assert!(!exact_pixels(&p));
    }
}
