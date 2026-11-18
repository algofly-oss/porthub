//! Explicit user-session WASAPI capture. Inventory never activates an audio stream.
//! https://learn.microsoft.com/windows/win32/coreaudio/capturing-a-stream
//! https://learn.microsoft.com/windows/win32/coreaudio/endpoint-id-strings
use anyhow::{ensure, Context, Result};
use porthub_components::media::{stable_source_id, Device, Kind, MAX_PCM_FRAME, PCM_RATE};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Devices::FunctionDiscovery::PKEY_Device_FriendlyName,
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
        Media::Audio::{
            eCapture, eConsole, eRender, EDataFlow, IAudioCaptureClient, IAudioClient,
            IAudioRenderClient, IMMDevice, IMMDeviceEnumerator, MMDeviceEnumerator,
            AUDCLNT_BUFFERFLAGS_SILENT, AUDCLNT_SHAREMODE_SHARED,
            AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM, AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
            AUDCLNT_STREAMFLAGS_LOOPBACK, AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY,
            DEVICE_STATE_ACTIVE, WAVEFORMATEX,
        },
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize,
                StructuredStorage::{PropVariantClear, PropVariantToStringAlloc},
                CLSCTX_ALL, COINIT_APARTMENTTHREADED, STGM_READ,
            },
            RemoteDesktop::ProcessIdToSessionId,
            Threading::{CreateEventW, GetCurrentProcessId, WaitForSingleObject},
        },
    },
};
struct Apartment;
impl Apartment {
    fn user() -> Result<Self> {
        let mut session = 0;
        unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) }?;
        ensure!(
            session != 0,
            "Microphone access requires the interactive Windows user session"
        );
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok() }?;
        Ok(Self)
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() }
    }
}
fn enumerator() -> Result<IMMDeviceEnumerator> {
    Ok(unsafe { CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL) }?)
}
/// Both GetId and PropVariantToStringAlloc allocate with COM's task allocator.
unsafe fn allocated_string(value: PWSTR) -> Result<String> {
    ensure!(!value.0.is_null(), "Missing Windows endpoint metadata");
    let result = value
        .to_string()
        .context("Invalid Windows endpoint metadata");
    CoTaskMemFree(Some(value.0.cast()));
    result
}
fn native_id(device: &IMMDevice) -> Result<String> {
    let id = unsafe { allocated_string(device.GetId()?)? };
    ensure!(
        !id.is_empty() && id.len() <= 512 && !id.chars().any(char::is_control),
        "Invalid Windows endpoint identity"
    );
    Ok(id)
}
fn label(device: &IMMDevice) -> Result<String> {
    unsafe {
        let store = device.OpenPropertyStore(STGM_READ)?;
        let mut property = store.GetValue(&PKEY_Device_FriendlyName)?;
        let text = PropVariantToStringAlloc(&property);
        let _ = PropVariantClear(&mut property);
        let text = allocated_string(text?)?;
        let clean: String = text.chars().filter(|c| !c.is_control()).take(256).collect();
        ensure!(!clean.is_empty(), "Empty microphone label");
        Ok(clean)
    }
}
fn devices(enumerator: &IMMDeviceEnumerator) -> Result<Vec<(IMMDevice, String)>> {
    devices_flow(enumerator, eCapture)
}
fn devices_flow(
    enumerator: &IMMDeviceEnumerator,
    flow: EDataFlow,
) -> Result<Vec<(IMMDevice, String)>> {
    let endpoints = unsafe { enumerator.EnumAudioEndpoints(flow, DEVICE_STATE_ACTIVE) }?;
    let count = unsafe { endpoints.GetCount() }?;
    ensure!(count <= 256, "Audio endpoint inventory exceeds limit");
    let mut result = Vec::with_capacity(count as usize);
    for index in 0..count {
        let endpoint = unsafe { endpoints.Item(index) }?;
        let id = native_id(&endpoint)?;
        result.push((endpoint, id));
    }
    Ok(result)
}
pub fn inventory() -> Result<Vec<Device>> {
    let _apartment = Apartment::user()?;
    let enumerator = enumerator()?;
    devices(&enumerator)?.into_iter().map(|(endpoint,id)|Ok(Device{
        id:stable_source_id(Kind::Microphone,"windows-wasapi",&id),
        name:label(&endpoint).unwrap_or_else(|_|"Microphone".into()),
        kind:Kind::Microphone,backend:"windows-wasapi".into(),native_id:id,
        capture_available:false,capture_state:porthub_components::media::CaptureState::PermissionUnknown,
        unavailable_reason:Some("Source enumerated; explicit capture session and permissions have not been verified".into()),
    })).collect()
}
/// Enumerating playback endpoints never activates loopback or rendering.
pub fn playback_inventory() -> Result<Vec<Device>> {
    let _apartment = Apartment::user()?;
    let enumerator = enumerator()?;
    devices_flow(&enumerator, eRender)?
        .into_iter()
        .map(|(endpoint, id)| {
            Ok(Device {
                id: stable_source_id(Kind::Speaker, "windows-wasapi", &id),
                name: label(&endpoint).unwrap_or_else(|_| "Speaker".into()),
                kind: Kind::Speaker,
                backend: "windows-wasapi".into(),
                native_id: id,
                capture_available: false,
                capture_state: porthub_components::media::CaptureState::PermissionUnknown,
                unavailable_reason: Some(
                    "Speaker enumerated; explicit playback route has not been verified".into(),
                ),
            })
        })
        .collect()
}
struct Event(HANDLE);
impl Drop for Event {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}
struct Running<'a>(&'a IAudioClient);
impl Drop for Running<'_> {
    fn drop(&mut self) {
        let _ = unsafe { self.0.Stop() };
    }
}
struct Packet<'a> {
    client: &'a IAudioCaptureClient,
    frames: u32,
}
impl Drop for Packet<'_> {
    fn drop(&mut self) {
        let _ = unsafe { self.client.ReleaseBuffer(self.frames) };
    }
}
fn format() -> WAVEFORMATEX {
    WAVEFORMATEX {
        wFormatTag: 3,
        nChannels: 1,
        nSamplesPerSec: PCM_RATE,
        nAvgBytesPerSec: PCM_RATE * 4,
        nBlockAlign: 4,
        wBitsPerSample: 32,
        cbSize: 0,
    }
}
fn emit_samples(bytes: &[u8], emit: &mut impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
    ensure!(
        bytes.len() % 4 == 0
            && bytes
                .chunks_exact(4)
                .all(|p| f32::from_le_bytes(p.try_into().unwrap()).is_finite()),
        "Invalid native microphone PCM"
    );
    for frame in bytes.chunks(MAX_PCM_FRAME) {
        emit(frame)?;
    }
    Ok(())
}
/// `endpoint_id` must come from a fresh inventory selection; labels and defaults
/// never select a device. Callbacks run on this COM thread and must be bounded:
/// the caller owns a cancellable, at most100ms queue to its inherited PCM pipe.
pub fn capture(
    endpoint_id: &str,
    cancel: &AtomicBool,
    ready: impl FnOnce() -> Result<()>,
    mut emit: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    ensure!(
        !endpoint_id.is_empty()
            && endpoint_id.len() <= 512
            && !endpoint_id.chars().any(char::is_control),
        "Invalid selected microphone identity"
    );
    let _apartment = Apartment::user()?;
    if cancel.load(Ordering::Acquire) {
        return Ok(());
    }
    let enumerator = enumerator()?;
    // Match active capture endpoints rather than accepting a render endpoint ID.
    let (endpoint, _) = devices(&enumerator)?
        .into_iter()
        .find(|(_, id)| id == endpoint_id)
        .context("Selected microphone is absent or inactive")?;
    let event = Event(unsafe { CreateEventW(None, false, false, PCWSTR::null()) }?);
    let client: IAudioClient = unsafe { endpoint.Activate(CLSCTX_ALL, None) }
        .context("Selected microphone activation denied or unavailable")?;
    let requested = format();
    // OS conversion is explicit; failed format/privacy initialization never
    // retries against another endpoint or the system default microphone.
    unsafe {
        client.Initialize(
            AUDCLNT_SHAREMODE_SHARED,
            AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM
                | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY
                | AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
            1_000_000,
            0,
            &requested,
            None,
        )
    }
    .context("Selected microphone cannot provide48kHz mono F32 or access is denied")?;
    let capacity = unsafe { client.GetBufferSize() }?;
    ensure!(
        capacity > 0 && capacity <= PCM_RATE / 2,
        "Native microphone buffer exceeds500ms limit"
    );
    unsafe { client.SetEventHandle(event.0) }?;
    let capture: IAudioCaptureClient = unsafe { client.GetService() }?;
    if cancel.load(Ordering::Acquire) {
        return Ok(());
    }
    unsafe { client.Start() }.context("Selected microphone capture could not start")?;
    let _running = Running(&client);
    ready()?;
    let mut last_packet = Instant::now();
    while !cancel.load(Ordering::Acquire) {
        let wait = unsafe { WaitForSingleObject(event.0, 50) };
        ensure!(
            wait == WAIT_OBJECT_0 || wait == WAIT_TIMEOUT,
            "Native microphone wait failed"
        );
        ensure!(
            last_packet.elapsed() < Duration::from_secs(5),
            "Selected microphone stopped producing packets"
        );
        if wait == WAIT_TIMEOUT {
            continue;
        }
        while !cancel.load(Ordering::Acquire) && unsafe { capture.GetNextPacketSize() }? > 0 {
            let mut pointer = std::ptr::null_mut();
            let mut frames = 0;
            let mut flags = 0;
            unsafe { capture.GetBuffer(&mut pointer, &mut frames, &mut flags, None, None) }?;
            let packet = Packet {
                client: &capture,
                frames,
            };
            ensure!(
                frames > 0 && frames <= capacity,
                "Invalid native microphone packet size"
            );
            let size = frames as usize * 4;
            if flags & AUDCLNT_BUFFERFLAGS_SILENT.0 as u32 != 0 {
                // Bounded zero chunks; do not dereference the undefined silent pointer.
                let zeros = [0u8; MAX_PCM_FRAME];
                let mut remaining = size;
                while remaining > 0 {
                    let n = remaining.min(MAX_PCM_FRAME);
                    emit(&zeros[..n])?;
                    remaining -= n;
                }
            } else {
                ensure!(!pointer.is_null(), "Native microphone packet has no data");
                let samples = unsafe { std::slice::from_raw_parts(pointer, size) };
                emit_samples(samples, &mut emit)?;
            }
            drop(packet);
            last_packet = Instant::now();
        }
    }
    Ok(())
}
/// Shared-mode loopback is pinned to the explicitly selected render endpoint.
/// Silence is valid. Never substitute the default or another render endpoint.
pub fn capture_playback(
    selected: &str,
    cancel: &AtomicBool,
    ready: impl FnOnce(&str) -> Result<()>,
    mut emit: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let _apartment = Apartment::user()?;
    let enumerator = enumerator()?;
    let (endpoint, _) = devices_flow(&enumerator, eRender)?
        .into_iter()
        .find(|(_, id)| id == selected)
        .context("Selected playback output is absent or inactive")?;
    let client: IAudioClient = unsafe { endpoint.Activate(CLSCTX_ALL, None) }?;
    let event = Event(unsafe { CreateEventW(None, false, false, PCWSTR::null()) }?);
    let requested = format();
    unsafe {
        client.Initialize(
            AUDCLNT_SHAREMODE_SHARED,
            AUDCLNT_STREAMFLAGS_LOOPBACK
                | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM
                | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY
                | AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
            1_000_000,
            0,
            &requested,
            None,
        )
    }
    .context("System playback loopback initialization failed")?;
    let capacity = unsafe { client.GetBufferSize() }?;
    ensure!(
        capacity > 0 && capacity <= PCM_RATE / 2,
        "System playback buffer exceeds500ms bound"
    );
    unsafe { client.SetEventHandle(event.0) }?;
    let capture: IAudioCaptureClient = unsafe { client.GetService() }?;
    if cancel.load(Ordering::Acquire) {
        return Ok(());
    }
    unsafe { client.Start() }?;
    let _running = Running(&client);
    ready(selected)?;
    while !cancel.load(Ordering::Acquire) {
        let wait = unsafe { WaitForSingleObject(event.0, 50) };
        ensure!(
            wait == WAIT_OBJECT_0 || wait == WAIT_TIMEOUT,
            "System playback wait failed"
        );
        while !cancel.load(Ordering::Acquire) && unsafe { capture.GetNextPacketSize() }? > 0 {
            let mut pointer = std::ptr::null_mut();
            let mut frames = 0;
            let mut flags = 0;
            unsafe { capture.GetBuffer(&mut pointer, &mut frames, &mut flags, None, None) }?;
            let packet = Packet {
                client: &capture,
                frames,
            };
            ensure!(
                frames > 0 && frames <= capacity,
                "Invalid system playback packet"
            );
            let size = frames as usize * 4;
            if flags & AUDCLNT_BUFFERFLAGS_SILENT.0 as u32 != 0 {
                let zeros = [0u8; MAX_PCM_FRAME];
                let mut left = size;
                while left > 0 {
                    let n = left.min(MAX_PCM_FRAME);
                    emit(&zeros[..n])?;
                    left -= n;
                }
            } else {
                ensure!(!pointer.is_null(), "System playback packet missing data");
                emit_samples(
                    unsafe { std::slice::from_raw_parts(pointer, size) },
                    &mut emit,
                )?;
            }
            drop(packet);
        }
    }
    Ok(())
}
/// Render to the user-session default output selected when this route starts.
pub fn render_playback(
    cancel: &AtomicBool,
    ready: impl FnOnce(&str) -> Result<()>,
    mut fill: impl FnMut(&mut [u8]) -> Result<()>,
) -> Result<()> {
    let _apartment = Apartment::user()?;
    let enumerator = enumerator()?;
    let endpoint = unsafe { enumerator.GetDefaultAudioEndpoint(eRender, eConsole) }
        .context("Default speaker unavailable")?;
    let selected = native_id(&endpoint)?;
    let client: IAudioClient = unsafe { endpoint.Activate(CLSCTX_ALL, None) }?;
    let requested = format();
    let event = Event(unsafe { CreateEventW(None, false, false, PCWSTR::null()) }?);
    unsafe {
        client.Initialize(
            AUDCLNT_SHAREMODE_SHARED,
            AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM
                | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY
                | AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
            1_000_000,
            0,
            &requested,
            None,
        )
    }
    .context("Selected speaker cannot render48kHz monoF32")?;
    let capacity = unsafe { client.GetBufferSize() }?;
    ensure!(
        capacity > 0 && capacity <= PCM_RATE / 2,
        "Speaker buffer exceeds500ms bound"
    );
    unsafe { client.SetEventHandle(event.0) }?;
    let output: IAudioRenderClient = unsafe { client.GetService() }?;
    if cancel.load(Ordering::Acquire) {
        return Ok(());
    }
    unsafe { client.Start() }?;
    let _running = Running(&client);
    ready(&selected)?;
    let mut checked = Instant::now();
    while !cancel.load(Ordering::Acquire) {
        if checked.elapsed() >= Duration::from_secs(1) {
            let current = unsafe { enumerator.GetDefaultAudioEndpoint(eRender, eConsole) }?;
            ensure!(
                native_id(&current)? == selected,
                "Default speaker changed; restart route"
            );
            checked = Instant::now();
        }
        let wait = unsafe { WaitForSingleObject(event.0, 50) };
        ensure!(
            wait == WAIT_OBJECT_0 || wait == WAIT_TIMEOUT,
            "Speaker playback wait failed"
        );
        let padding = unsafe { client.GetCurrentPadding() }?;
        ensure!(padding <= capacity, "Invalid speaker padding");
        let frames = capacity - padding;
        if frames == 0 {
            continue;
        }
        let pointer = unsafe { output.GetBuffer(frames) }?;
        ensure!(!pointer.is_null(), "Speaker render buffer missing");
        let samples = unsafe { std::slice::from_raw_parts_mut(pointer, frames as usize * 4) };
        let result = fill(samples);
        let release = unsafe {
            output.ReleaseBuffer(
                frames,
                if result.is_err() {
                    AUDCLNT_BUFFERFLAGS_SILENT.0 as u32
                } else {
                    0
                },
            )
        };
        result?;
        release?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pcm_callbacks_are_bounded_and_nonfinite_is_rejected() {
        let data = vec![0u8; MAX_PCM_FRAME * 2 + 4];
        let mut sizes = vec![];
        emit_samples(&data, &mut |p| {
            sizes.push(p.len());
            Ok(())
        })
        .unwrap();
        assert_eq!(sizes, vec![MAX_PCM_FRAME, MAX_PCM_FRAME, 4]);
        assert!(emit_samples(&f32::NAN.to_le_bytes(), &mut |_| panic!(
            "Invalid sample reached callback"
        ))
        .is_err());
    }
    #[test]
    fn endpoint_identity_is_separate_from_the_display_label() {
        assert_ne!(
            stable_source_id(Kind::Microphone, "windows-wasapi", "endpoint-a"),
            stable_source_id(Kind::Microphone, "windows-wasapi", "endpoint-b")
        );
        let f = format();
        let (rate, channels, bits) = (f.nSamplesPerSec, f.nChannels, f.wBitsPerSample);
        assert_eq!(rate, 48_000);
        assert_eq!(channels, 1);
        assert_eq!(bits, 32);
    }
}
