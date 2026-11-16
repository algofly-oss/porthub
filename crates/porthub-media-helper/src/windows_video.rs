//! Explicit native-MJPEG camera source; inventory does not activate a camera.
//! https://learn.microsoft.com/windows/win32/medfound/audio-video-capture-in-media-foundation
//! https://learn.microsoft.com/windows/win32/api/mfreadwrite/nf-mfreadwrite-imfsourcereaderex-setnativemediatype
use anyhow::{ensure, Context, Result};
use porthub_components::media::{
    stable_source_id, CaptureState, Device, Kind, VideoEncoding, VideoFormat,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
        Arc,
    },
    time::{Duration, Instant},
};
use windows::{
    core::{implement, Interface, Ref, GUID, HRESULT, PWSTR},
    Win32::{
        Media::MediaFoundation::*,
        System::{
            Com::{CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_MULTITHREADED},
            RemoteDesktop::ProcessIdToSessionId,
            Threading::GetCurrentProcessId,
        },
    },
};
#[path = "video_pixels.rs"]
mod pixels;
#[path = "windows_video_wic.rs"]
mod wic;
#[derive(Clone, Copy, Debug)]
enum Native {
    Mjpeg,
    Raw {
        layout: pixels::Layout,
        stride: usize,
        matrix: pixels::Matrix,
        range: pixels::Range,
    },
}
fn nominal_15(num: u32, den: u32) -> bool {
    if num == 0 || den == 0 {
        return false;
    }
    let interval = 10_000_000u64 * den as u64 / num as u64;
    interval.abs_diff(666_666) <= 1
}
#[derive(Debug)]
pub struct CameraUnsupported;
impl std::fmt::Display for CameraUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Selected camera has no supported 640x480 nominal15fps MJPEG mode")
    }
}
impl std::error::Error for CameraUnsupported {}
#[path = "video_events.rs"]
mod events;
const MAX_FRAME: usize = 2 * 1024 * 1024;
struct Runtime;
impl Runtime {
    fn user() -> Result<Self> {
        let mut session = 0;
        unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) }?;
        ensure!(
            session != 0,
            "Camera access requires the interactive Windows user session"
        );
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok() }?;
        if let Err(error) = unsafe { MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET) } {
            unsafe { CoUninitialize() };
            return Err(error.into());
        }
        Ok(Self)
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = unsafe { MFShutdown() };
        unsafe { CoUninitialize() }
    }
}
fn attributes() -> Result<IMFAttributes> {
    let mut attributes = None;
    unsafe { MFCreateAttributes(&mut attributes, 4) }?;
    attributes.context("Media attributes unavailable")
}
struct Activations {
    pointer: *mut Option<IMFActivate>,
    count: u32,
}
impl Drop for Activations {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            unsafe {
                for entry in std::slice::from_raw_parts_mut(self.pointer, self.count as usize) {
                    drop(entry.take());
                }
                CoTaskMemFree(Some(self.pointer.cast()));
            }
        }
    }
}
fn sources() -> Result<Vec<IMFActivate>> {
    let attributes = attributes()?;
    unsafe {
        attributes.SetGUID(
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
        )
    }?;
    let mut array = Activations {
        pointer: std::ptr::null_mut(),
        count: 0,
    };
    unsafe { MFEnumDeviceSources(&attributes, &mut array.pointer, &mut array.count) }?;
    ensure!(
        array.count <= 256 && (array.count == 0 || !array.pointer.is_null()),
        "Camera inventory exceeds limit"
    );
    if array.count == 0 {
        return Ok(vec![]);
    }
    unsafe { std::slice::from_raw_parts(array.pointer, array.count as usize) }
        .iter()
        .map(|v| v.clone().context("Invalid camera activation entry"))
        .collect()
}
fn text(attributes: &IMFAttributes, key: &GUID) -> Result<String> {
    let mut pointer = PWSTR::null();
    let mut length = 0;
    unsafe { attributes.GetAllocatedString(key, &mut pointer, &mut length) }?;
    let result = if pointer.0.is_null() || length > 1024 {
        Err(anyhow::anyhow!("Camera identity metadata exceeds limit"))
    } else {
        String::from_utf16(unsafe { std::slice::from_raw_parts(pointer.0, length as usize) })
            .context("Invalid camera identity metadata")
    };
    unsafe { CoTaskMemFree(Some(pointer.0.cast())) };
    result
}
fn symbolic(source: &IMFActivate) -> Result<String> {
    let id = text(
        source,
        &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
    )?;
    ensure!(
        !id.is_empty() && id.len() <= 512 && !id.chars().any(char::is_control),
        "Invalid camera symbolic identity"
    );
    Ok(id)
}
pub fn inventory() -> Result<Vec<Device>> {
    let _runtime = Runtime::user()?;
    let mut seen = std::collections::BTreeSet::new();
    let mut rows = Vec::new();
    for source in sources()? {
        let native = symbolic(&source)?;
        let canonical = native.to_ascii_lowercase();
        let id = stable_source_id(Kind::Camera, "windows-mf", &canonical);
        ensure!(
            seen.insert(id.clone()),
            "Native camera identity is ambiguous"
        );
        let name = text(&source, &MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME)
            .unwrap_or_else(|_| "Camera".into());
        ensure!(
            name.len() <= 256 && !name.is_empty() && !name.chars().any(char::is_control),
            "Invalid native camera label"
        );
        rows.push(Device {
            id,
            name,
            kind: Kind::Camera,
            backend: "windows-mf".into(),
            native_id: native,
            capture_available: false,
            capture_state: CaptureState::PermissionUnknown,
            unavailable_reason: None,
        });
    }
    Ok(rows)
}

struct Source(IMFMediaSource, bool);
impl Source {
    fn finish(&mut self) -> Result<()> {
        match unsafe { self.0.Shutdown() } {
            Ok(()) => {}
            Err(error) if error.code() == MF_E_SHUTDOWN => {}
            Err(error) => return Err(error.into()),
        }
        self.1 = true;
        Ok(())
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        if !self.1 {
            let _ = self.finish();
        }
    }
}
struct Image(Vec<u8>, bool);
impl Drop for Image {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
struct Reader(IMFSourceReader);
impl std::ops::Deref for Reader {
    type Target = IMFSourceReader;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for Reader {
    fn drop(&mut self) {
        let _ = unsafe { self.0.Flush(MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32) };
    }
}
struct Locked<'a>(&'a IMFMediaBuffer);
impl Drop for Locked<'_> {
    fn drop(&mut self) {
        let _ = unsafe { self.0.Unlock() };
    }
}
fn sample_bytes(sample: &IMFSample) -> Result<Image> {
    // Check total sample length before asking MF to allocate a contiguous copy.
    let length = unsafe { sample.GetTotalLength() }? as usize;
    ensure!(
        length > 0 && length <= MAX_FRAME,
        "Native camera frame exceeds2MiB limit"
    );
    let buffer = unsafe { sample.ConvertToContiguousBuffer() }?;
    if let Ok(two_d) = buffer.cast::<IMF2DBuffer>() {
        let length = unsafe { two_d.GetContiguousLength() }? as usize;
        ensure!(
            length > 0 && length <= MAX_FRAME,
            "Native 2D camera frame exceeds bound"
        );
        let mut bytes = vec![0u8; length];
        if let Err(error) = unsafe { two_d.ContiguousCopyTo(&mut bytes) } {
            bytes.fill(0);
            return Err(error.into());
        }
        return Ok(Image(bytes, true));
    }
    let mut pointer = std::ptr::null_mut();
    let mut length = 0;
    let mut capacity = 0;
    unsafe { buffer.Lock(&mut pointer, Some(&mut capacity), Some(&mut length)) }?;
    let _locked = Locked(&buffer);
    ensure!(
        !pointer.is_null() && length > 0 && length <= capacity && length as usize <= MAX_FRAME,
        "Invalid camera sample buffer"
    );
    Ok(Image(
        unsafe { std::slice::from_raw_parts(pointer, length as usize) }.to_vec(),
        false,
    ))
}
#[implement(IMFSourceReaderCallback)]
struct Callback {
    sender: SyncSender<Result<Option<Image>>>,
    failed: Arc<AtomicBool>,
}
#[allow(non_snake_case)]
impl IMFSourceReaderCallback_Impl for Callback_Impl {
    fn OnReadSample(
        &self,
        status: HRESULT,
        _stream: u32,
        flags: u32,
        _timestamp: i64,
        sample: Ref<IMFSample>,
    ) -> windows::core::Result<()> {
        let rejected = (MF_SOURCE_READERF_ERROR.0
            | MF_SOURCE_READERF_ENDOFSTREAM.0
            | MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED.0
            | MF_SOURCE_READERF_NATIVEMEDIATYPECHANGED.0) as u32;
        let event = if status.is_err() {
            Err(status.ok().unwrap_err().into())
        } else if flags & rejected != 0 {
            Err(anyhow::anyhow!(
                "Native camera ended or changed its negotiated mode"
            ))
        } else {
            sample.as_ref().map(sample_bytes).transpose()
        };
        if self.sender.try_send(event).is_err() {
            self.failed.store(true, Ordering::Release);
        }
        Ok(())
    }
    fn OnFlush(&self, _stream: u32) -> windows::core::Result<()> {
        Ok(())
    }
    fn OnEvent(&self, _stream: u32, event: Ref<IMFMediaEvent>) -> windows::core::Result<()> {
        if let Some(event) = event.as_ref() {
            if let Ok(status) = unsafe { event.GetStatus() } {
                if status.is_err()
                    && self
                        .sender
                        .try_send(Err(status.ok().unwrap_err().into()))
                        .is_err()
                {
                    self.failed.store(true, Ordering::Release);
                }
            }
        }
        Ok(())
    }
}
fn valid_requested(format: &VideoFormat) -> bool {
    format.encoding == VideoEncoding::Mjpeg
        && format.width == 640
        && format.height == 480
        && format.fps_den > 0
        && format.fps_num as u64 == 15 * format.fps_den as u64
}

fn attribute<T>(value: windows::core::Result<T>) -> Result<Option<T>> {
    match value {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.code() == MF_E_ATTRIBUTENOTFOUND => Ok(None),
        Err(e) => Err(e.into()),
    }
}
fn matches(native: &IMFMediaType, requested: &VideoFormat) -> Result<Option<Native>> {
    if attribute(unsafe { native.GetGUID(&MF_MT_MAJOR_TYPE) })? != Some(MFMediaType_Video) {
        return Ok(None);
    }
    let Some(size) = attribute(unsafe { native.GetUINT64(&MF_MT_FRAME_SIZE) })? else {
        return Ok(None);
    };
    let Some(rate) = attribute(unsafe { native.GetUINT64(&MF_MT_FRAME_RATE) })? else {
        return Ok(None);
    };
    if (size >> 32) as u32 != requested.width
        || size as u32 != requested.height
        || !nominal_15((rate >> 32) as u32, rate as u32)
    {
        return Ok(None);
    }
    let subtype = unsafe { native.GetGUID(&MF_MT_SUBTYPE) }?;
    if subtype == MFVideoFormat_MJPG {
        return Ok(Some(Native::Mjpeg));
    }
    let layout = if subtype == MFVideoFormat_NV12 {
        pixels::Layout::Nv12
    } else if subtype == MFVideoFormat_YUY2 {
        pixels::Layout::Yuy2
    } else {
        return Ok(None);
    };
    // YUV is top-down per the native format contract. Do not guess padded
    // layout when its declared stride is missing or negative.
    let Some(stride) =
        attribute(unsafe { native.GetUINT32(&MF_MT_DEFAULT_STRIDE) })?.map(|v| v as i32)
    else {
        return Ok(None);
    };
    if stride <= 0 || stride > 8192 {
        return Ok(None);
    }
    let matrix = match attribute(unsafe { native.GetUINT32(&MF_MT_YUV_MATRIX) })? {
        Some(v) if v == MFVideoTransferMatrix_BT709.0 as u32 => pixels::Matrix::Bt709,
        Some(v) if v == MFVideoTransferMatrix_BT601.0 as u32 => pixels::Matrix::Bt601,
        None | Some(0) => pixels::Matrix::Bt601, // Explicit fixed SD-profile conversion default, not hardware-attested metadata.
        _ => return Ok(None),
    };
    let range = match attribute(unsafe { native.GetUINT32(&MF_MT_VIDEO_NOMINAL_RANGE) })? {
        Some(v) if v == MFNominalRange_0_255.0 as u32 => pixels::Range::Full,
        Some(v) if v == MFNominalRange_16_235.0 as u32 => pixels::Range::Limited,
        None | Some(0) => pixels::Range::Limited,
        _ => return Ok(None),
    };
    let stride = stride as usize;
    let minimum = match layout {
        pixels::Layout::Nv12 => 640,
        pixels::Layout::Yuy2 => 1280,
    };
    let required = match layout {
        pixels::Layout::Nv12 => stride * 720,
        pixels::Layout::Yuy2 => stride * 480,
    };
    if stride < minimum || required > MAX_FRAME {
        return Ok(None);
    }
    Ok(Some(Native::Raw {
        layout,
        stride,
        matrix,
        range,
    }))
}
#[path = "video_jpeg.rs"]
mod jpeg;
fn validate_jpeg(frame: &[u8], format: &VideoFormat) -> Result<()> {
    ensure!(
        valid_requested(format) && jpeg::baseline(frame),
        "Native camera did not deliver complete baseline MJPEG"
    );
    Ok(())
}
/// Exact selected camera and nominal mode. Prefer native MJPEG; supported
/// NV12/YUY2 uses bounded Rust CPU conversion and the built-in Microsoft JPEG
/// encoder. No GPU manager, resize, device fallback or discovery activation.
/// Callbacks must remain bounded; the facade owns cancellable output queues.
pub fn capture(
    symbolic_link: &str,
    requested: VideoFormat,
    cancel: &AtomicBool,
    ready: impl FnOnce(VideoFormat) -> Result<()>,
    frame: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    capture_impl(symbolic_link, requested, cancel, true, ready, frame)
}
/// Private class proof must reject native raw media before any CPU encoder.
#[cfg(test)]
pub fn capture_native_mjpeg(
    symbolic_link: &str,
    requested: VideoFormat,
    cancel: &AtomicBool,
    ready: impl FnOnce(VideoFormat) -> Result<()>,
    frame: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    capture_impl(symbolic_link, requested, cancel, false, ready, frame)
}
fn capture_impl(
    symbolic_link: &str,
    requested: VideoFormat,
    cancel: &AtomicBool,
    allow_raw: bool,
    ready: impl FnOnce(VideoFormat) -> Result<()>,
    mut frame: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    ensure!(
        !symbolic_link.is_empty()
            && symbolic_link.len() <= 512
            && !symbolic_link.chars().any(char::is_control),
        "Explicit bounded camera identity required"
    );
    ensure!(
        valid_requested(&requested),
        "Requested camera mode exceeds native capture bounds"
    );
    if cancel.load(Ordering::Acquire) {
        return Ok(());
    }
    let _runtime = Runtime::user()?;
    let mut selected = None;
    for source in sources()? {
        if symbolic(&source)?.eq_ignore_ascii_case(symbolic_link) {
            ensure!(selected.is_none(), "Selected camera identity is ambiguous");
            selected = Some(source);
        }
    }
    let selected = selected.context("Selected camera is absent")?;
    let mut source = Source(
        unsafe { selected.ActivateObject::<IMFMediaSource>() }
            .context("Selected camera access denied or unavailable")?,
        false,
    );
    let attributes = attributes()?;
    unsafe { attributes.SetUINT32(&MF_READWRITE_DISABLE_CONVERTERS, 1) }?;
    unsafe { attributes.SetUINT32(&MF_READWRITE_ENABLE_HARDWARE_TRANSFORMS, 0) }?;
    unsafe { attributes.SetUINT32(&MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING, 0) }?;
    let (sender, receiver) = mpsc::sync_channel(2);
    let failed = Arc::new(AtomicBool::new(false));
    let callback: IMFSourceReaderCallback = Callback {
        sender,
        failed: failed.clone(),
    }
    .into();
    unsafe { attributes.SetUnknown(&MF_SOURCE_READER_ASYNC_CALLBACK, &callback) }?;
    let reader = Reader(unsafe { MFCreateSourceReaderFromMediaSource(&source.0, &attributes) }?);
    let stream = MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32;
    unsafe { reader.SetStreamSelection(MF_SOURCE_READER_ALL_STREAMS.0 as u32, false) }?;
    unsafe { reader.SetStreamSelection(stream, true) }?;
    let mut chosen = None;
    let mut complete = false;
    for index in 0..256 {
        match unsafe { reader.GetNativeMediaType(stream, index) } {
            Ok(native) => {
                if let Some(mode) = matches(&native, &requested)? {
                    if !allow_raw && !matches!(mode, Native::Mjpeg) {
                        continue;
                    }
                    if matches!(mode, Native::Mjpeg) {
                        chosen = Some((native, mode));
                        break;
                    }
                    if chosen.is_none() {
                        chosen = Some((native, mode));
                    }
                }
            }
            Err(error) if error.code() == MF_E_NO_MORE_TYPES => {
                complete = true;
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    if !complete
        && !chosen
            .as_ref()
            .is_some_and(|(_, mode)| matches!(mode, Native::Mjpeg))
    {
        match unsafe { reader.GetNativeMediaType(stream, 256) } {
            Err(error) if error.code() == MF_E_NO_MORE_TYPES => {}
            Err(error) => return Err(error.into()),
            Ok(_) => anyhow::bail!("Native camera type list exceeds bound"),
        }
    }
    let (chosen, _) = chosen.ok_or(CameraUnsupported)?;
    let extended: IMFSourceReaderEx = reader.cast()?;
    unsafe { extended.SetNativeMediaType(stream, &chosen) }?;
    unsafe { reader.SetCurrentMediaType(stream, None, &chosen) }?;
    let mode = matches(&unsafe { reader.GetCurrentMediaType(stream) }?, &requested)?
        .context("Camera output differs from selected native mode")?;
    ensure!(
        allow_raw || matches!(mode, Native::Mjpeg),
        "Selected camera did not expose native MJPEG to the ordinary consumer"
    );
    let encoder = if matches!(mode, Native::Raw { .. }) {
        Some(wic::Encoder::new()?)
    } else {
        None
    };
    struct NativeEvents<'a> {
        reader: &'a IMFSourceReader,
        receiver: &'a mpsc::Receiver<Result<Option<Image>>>,
        failed: &'a AtomicBool,
        stream: u32,
    }
    impl events::Events<Image> for NativeEvents<'_> {
        fn request(&mut self) -> Result<()> {
            unsafe {
                self.reader
                    .ReadSample(self.stream, 0, None, None, None, None)
            }?;
            Ok(())
        }
        fn poll(&mut self, wait: Duration) -> Result<events::Poll<Image>> {
            ensure!(
                !self.failed.load(Ordering::Acquire),
                "Native camera callback queue overflowed"
            );
            match self.receiver.recv_timeout(wait) {
                Ok(value) => Ok(events::Poll::Event(value?)),
                Err(mpsc::RecvTimeoutError::Timeout) => Ok(events::Poll::Timeout),
                Err(_) => anyhow::bail!("Native camera callback closed"),
            }
        }
    }
    let mut events = NativeEvents {
        reader: &reader,
        receiver: &receiver,
        failed: &failed,
        stream,
    };
    let mut ready = Some(ready);
    let origin = Instant::now();
    events::run(
        &mut events,
        cancel,
        |mut bytes| {
            if let Native::Raw {
                layout,
                stride,
                matrix,
                range,
            } = mode
            {
                let stride = if bytes.1 {
                    match layout {
                        pixels::Layout::Nv12 => 640,
                        pixels::Layout::Yuy2 => 1280,
                    }
                } else {
                    stride
                };
                if bytes.1 {
                    let required = match layout {
                        pixels::Layout::Nv12 => 640 * 480 * 3 / 2,
                        pixels::Layout::Yuy2 => 640 * 480 * 2,
                    };
                    ensure!(
                        bytes.0.len() == required,
                        "Native 2D YUV contiguous layout differs"
                    );
                }
                let mut bgr = pixels::bgr(&bytes.0, 640, 480, stride, layout, matrix, range)?;
                let encoded = encoder.as_ref().unwrap().encode(&bgr);
                bgr.fill(0);
                bytes = Image(encoded?, false);
            }
            Ok(if validate_jpeg(&bytes.0, &requested).is_ok() {
                Some(bytes)
            } else {
                None
            })
        },
        |bytes| {
            if let Some(ready) = ready.take() {
                ready(requested)?;
            }
            frame(&bytes.0)
        },
        || origin.elapsed(),
    )?;
    unsafe { reader.Flush(stream) }?;
    source.finish()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn mode() -> VideoFormat {
        VideoFormat {
            width: 640,
            height: 480,
            fps_num: 15,
            fps_den: 1,
            encoding: VideoEncoding::Mjpeg,
        }
    }
    #[test]
    fn bounded_jpeg_header_must_match_selected_mode() {
        let frame = [
            0xff, 0xd8, 0xff, 0xc0, 0, 11, 8, 1, 0xe0, 2, 0x80, 1, 1, 0x11, 0, 0xff, 0xd9,
        ];
        assert!(
            validate_jpeg(&frame, &mode()).is_err(),
            "Header-only data must not signal camera readiness"
        );
        let mut wrong = frame;
        wrong[10] = 0x81;
        assert!(validate_jpeg(&wrong, &mode()).is_err());
        let mut broken = frame;
        broken[5] = 0xff;
        assert!(validate_jpeg(&broken, &mode()).is_err());
    }
    #[test]
    fn requested_modes_are_bounded_without_rate_fallback() {
        let mut mode = mode();
        assert!(valid_requested(&mode));
        mode.fps_num = 61;
        assert!(!valid_requested(&mode));
        mode.fps_num = 30;
        mode.fps_den = 0;
        assert!(!valid_requested(&mode));
    }
}

#[cfg(test)]
mod native_contract_tests {
    use super::*;
    #[test]
    fn nominal_frame_interval_accepts_uvc_tick_rounding_but_not_rate_fallback() {
        assert!(nominal_15(15, 1));
        assert!(nominal_15(10_000_000, 666_666));
        assert!(nominal_15(10_000_000, 666_667));
        assert!(!nominal_15(30, 1));
        assert!(!nominal_15(0, 1));
        assert!(!nominal_15(15, 0));
    }
    #[test]
    fn mjpeg_requires_complete_baseline_before_ready() {
        let mode = VideoFormat {
            encoding: VideoEncoding::Mjpeg,
            width: 640,
            height: 480,
            fps_num: 15,
            fps_den: 1,
        };
        let bytes =
            include_bytes!("../../porthub-agent/tests/data/private_uvc_colorbars_640x480.jpg");
        assert!(validate_jpeg(bytes, &mode).is_ok());
        let mut broken = bytes.to_vec();
        broken.truncate(broken.len() - 2);
        assert!(validate_jpeg(&broken, &mode).is_err());
    }
}
