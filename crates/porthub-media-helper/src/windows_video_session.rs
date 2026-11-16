//! Explicit inherited-pipe PHV1 camera session. No discovery/default activation.
use crate::{video_output::VideoOutput, windows_video};
use anyhow::{ensure, Context, Result};
use porthub_components::media::{VideoFormat, VideoFrame};
use std::{
    io::{Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};

/// Local-only proof retained from metadata inventory, never a network source selector.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedCamera {
    source_id: String,
    symbolic_link: String,
}
impl ExpectedCamera {
    pub fn from_device(device: &porthub_components::media::Device) -> Result<Self> {
        ensure!(
            device.kind == porthub_components::media::Kind::Camera
                && device.backend == "windows-mf",
            "Wrong native camera backend"
        );
        let result = Self {
            source_id: device.id.clone(),
            symbolic_link: device.native_id.clone(),
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.symbolic_link.is_empty()
                && self.symbolic_link.len() <= 512
                && !self.symbolic_link.chars().any(char::is_control),
            "Invalid native camera identity"
        );
        ensure!(
            self.source_id
                == porthub_components::media::stable_source_id(
                    porthub_components::media::Kind::Camera,
                    "windows-mf",
                    &self.symbolic_link.to_ascii_lowercase()
                ),
            "Native camera proof/source mismatch"
        );
        Ok(())
    }
    pub fn source_id(&self) -> &str {
        &self.source_id
    }
}

/// The caller parses a bounded authenticated SessionRequest, retains the exact
/// inventory proof, and supplies the still-owned inherited control reader.
pub fn serve<R: Read + Send + 'static>(
    session: &str,
    source_id: &str,
    expected: ExpectedCamera,
    format: VideoFormat,
    mut input: R,
) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE},
    };
    validate(session, source_id, &expected)?;
    ensure!(
        unsafe { GetFileType(HANDLE(std::io::stdin().as_raw_handle())) } == FILE_TYPE_PIPE,
        "Camera session requires an inherited control pipe"
    );
    let cancel = Arc::new(AtomicBool::new(false));
    let stop = cancel.clone();
    std::thread::spawn(move || {
        let mut byte = [0u8; 1];
        let _ = input.read(&mut byte);
        stop.store(true, Ordering::Release);
    });
    let output = VideoOutput::new(cancel.clone());
    let origin = Instant::now();
    let mut sequence = 0u64;
    let ready_declared = std::cell::Cell::new(false);
    let result = windows_video::capture(
        &expected.symbolic_link,
        format,
        &cancel,
        |negotiated| {
            ready_declared.set(true);
            output.ready(&serde_json::json!({"session":session,"state":"capturing","backend":"windows-mf","source_id":source_id,"format":negotiated}))
        },
        |jpeg| {
            let mut frame = VideoFrame {
                sequence,
                source_monotonic_micros: origin
                    .elapsed()
                    .as_micros()
                    .try_into()
                    .context("Camera timestamp overflow")?,
                format,
                jpeg: jpeg.to_vec(),
            };
            sequence = sequence
                .checked_add(1)
                .context("Camera sequence exhausted")?;
            let encoded = frame.encode();
            frame.jpeg.fill(0);
            output.frame(encoded.context("Native camera frame failed PHV1 validation")?)
        },
    );
    match result {
        Err(error) if !ready_declared.get() && unsupported(&error) => startup_state(
            std::io::stdout(),
            session,
            "unsupported",
            "Selected camera does not support the required MJPEG mode",
        ),
        Err(error) if !ready_declared.get() && permission_denied(&error) => {
            denied(std::io::stdout(), session)
        }
        result => result,
    }
}
fn permission_denied(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<windows::core::Error>()
            .is_some_and(|e| e.code().0 as u32 == 0x80070005)
    })
}
fn unsupported(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|e| e.is::<windows_video::CameraUnsupported>())
}
fn denied<W: Write + Send + 'static>(writer: W, session: &str) -> Result<()> {
    startup_state(
        writer,
        session,
        "denied",
        "Camera permission denied by the operating system",
    )
}
fn startup_state<W: Write + Send + 'static>(
    mut writer: W,
    session: &str,
    state: &'static str,
    reason: &'static str,
) -> Result<()> {
    let mut bytes =
        serde_json::to_vec(&serde_json::json!({"session":session,"state":state,"reason":reason}))?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= 4096, "Camera denial exceeds bound");
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = writer.write_all(&bytes).and_then(|_| writer.flush());
        let _ = send.send(result);
    });
    receive
        .recv_timeout(std::time::Duration::from_millis(500))
        .context("Camera permission status delivery timed out")??;
    Ok(())
}
fn validate(session: &str, source_id: &str, expected: &ExpectedCamera) -> Result<()> {
    expected.validate()?;
    ensure!(
        session.len() == 32 && session.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid camera session nonce"
    );
    ensure!(
        source_id == expected.source_id(),
        "Camera inventory proof belongs to another selected source"
    );
    ensure!(
        serde_json::to_vec(expected)?.len() <= 6144,
        "Camera inventory proof exceeds bound"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn camera_proof_cannot_select_another_endpoint_or_source() {
        let symbolic_link = "\\\\?\\usb#private-camera".to_owned();
        let id = porthub_components::media::stable_source_id(
            porthub_components::media::Kind::Camera,
            "windows-mf",
            &symbolic_link.to_ascii_lowercase(),
        );
        let mut expected = ExpectedCamera {
            source_id: id.clone(),
            symbolic_link,
        };
        assert!(validate(&"a".repeat(32), &id, &expected).is_ok());
        assert!(validate("invalid", &id, &expected).is_err());
        assert!(validate(&"a".repeat(32), "media:another", &expected).is_err());
        expected.symbolic_link.push('2');
        assert!(validate(&"a".repeat(32), &id, &expected).is_err());
    }
    #[test]
    fn only_native_access_denied_is_permission_denial() {
        let denied_error =
            windows::core::Error::from_hresult(windows::core::HRESULT(0x80070005u32 as i32));
        assert!(permission_denied(&anyhow::Error::new(denied_error)));
        assert!(!permission_denied(&anyhow::anyhow!("Access denied")));
        let unavailable =
            windows::core::Error::from_hresult(windows::core::HRESULT(0x80004005u32 as i32));
        assert!(!permission_denied(&anyhow::Error::new(unavailable)));
        assert!(unsupported(&windows_video::CameraUnsupported.into()));
        assert!(!unsupported(&anyhow::anyhow!("unsupported camera")));
    }
}
