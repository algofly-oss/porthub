//! Inherited-pipe facade; WASAPI is initialized only for an explicit selected source.
use anyhow::{ensure, Context, Result};
use porthub_components::media::{Operation, SessionRequest, MAX_PCM_FRAME, PCM_CHANNELS, PCM_RATE};
use std::os::windows::io::AsRawHandle;
use std::{
    io::{BufRead, Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use windows::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE},
};
pub fn serve() -> Result<()> {
    let stdin = std::io::stdin();
    ensure!(
        unsafe { GetFileType(HANDLE(stdin.as_raw_handle())) } == FILE_TYPE_PIPE,
        "Media capture requires an inherited control pipe"
    );
    let mut reader = std::io::BufReader::new(stdin);
    let mut header = Vec::new();
    Read::by_ref(&mut reader)
        .take(8193)
        .read_until(b'\n', &mut header)?;
    ensure!(
        header.len() <= 8192 && header.last() == Some(&b'\n'),
        "Invalid media session request"
    );
    let request: SessionRequest =
        serde_json::from_slice(&header).context("Invalid media session request")?;
    ensure!(request.valid(), "Invalid media session request");
    if request.operation == Operation::CaptureCamera {
        let expected = serde_json::from_value(
            request.camera_identity.clone().context("Retained camera identity required")?,
        ).context("Invalid retained camera identity")?;
        return crate::windows_video_session::serve(
            &request.session,
            request.source_id.as_deref().context("Explicit camera identity required")?,
            expected,
            request.video_format.context("Explicit camera format required")?,
            reader,
        );
    }
    microphone_operation(request.operation)?;
    let sources = match crate::windows_audio::inventory() {
        Ok(sources) => sources,
        Err(error) if permission_denied(&error) => {
            return denied(std::io::stdout(), &request.session)
        }
        Err(error) => return Err(error),
    };
    let source_id = request
        .source_id
        .as_deref()
        .context("Explicit microphone identity required")?;
    let source = sources
        .iter()
        .find(|d| d.id == source_id || d.native_id == source_id)
        .context("Selected microphone is not present in the user session")?;
    ensure!(
        source.kind == porthub_components::media::Kind::Microphone,
        "Selected endpoint is not a microphone"
    );
    let endpoint = source.native_id.clone();
    let cancel = Arc::new(AtomicBool::new(false));
    let input_cancel = cancel.clone();
    std::thread::spawn(move || {
        let mut byte = [0];
        let _ = reader.read(&mut byte);
        input_cancel.store(true, Ordering::Release);
    });
    ensure!(
        !cancel.load(Ordering::Acquire),
        "Media request cancelled before capture"
    );
    let selected = endpoint.clone();
    let output = crate::capture_output::Output::audio(cancel.clone());
    let ready_sent = AtomicBool::new(false);
    let result = crate::windows_audio::capture(
        &endpoint,
        &cancel,
        || {
            output.ready(&serde_json::json!({"session":request.session,"state":"capturing","backend":"wasapi","endpoint_id":selected,"rate":PCM_RATE,"channels":PCM_CHANNELS,"format":"f32le"}))?;
            ready_sent.store(true, Ordering::Release);
            Ok(())
        },
        |pcm| {
            ensure!(
                !pcm.is_empty() && pcm.len() <= MAX_PCM_FRAME && pcm.len() % 4 == 0,
                "Native audio frame exceeds bound"
            );
            ensure!(
                pcm.chunks_exact(4)
                    .all(|v| f32::from_le_bytes(v.try_into().unwrap()).is_finite()),
                "Native audio supplied invalid samples"
            );
            output.frame(pcm)
        },
    );
    if let Err(error) = result {
        // Never insert JSON into an already-started PCM stream. A later OS
        // revocation still terminates capture, and the parent sees its closure.
        if !ready_sent.load(Ordering::Acquire) && permission_denied(&error) {
            drop(output); // Its unused callback queue cannot race this status.
            return denied(std::io::stdout(), &request.session);
        }
        return Err(error);
    }
    Ok(())
}
// Exact opcode allowlist: future camera operations cannot fall back to audio.
fn microphone_operation(operation: Operation) -> Result<()> {
    ensure!(
        operation == Operation::CaptureMicrophone,
        "Windows media helper currently supports microphone capture only"
    );
    Ok(())
}
fn permission_denied(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<windows::core::Error>()
            .is_some_and(|error| error.code().0 == 0x80070005u32 as i32)
    })
}
/// Only startup failure uses this path: WASAPI has already released its native
/// handles/packets. A blocked parent cannot keep the process alive indefinitely.
fn denied<W: Write + Send + 'static>(mut writer: W, session: &str) -> Result<()> {
    let mut bytes = serde_json::to_vec(
        &serde_json::json!({"session":session,"state":"denied","reason":"Microphone permission denied by the operating system"}),
    )?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= 4096, "Media denial exceeds bound");
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = writer.write_all(&bytes).and_then(|_| writer.flush());
        let _ = send.send(result);
    });
    receive
        .recv_timeout(std::time::Duration::from_millis(500))
        .context("Media permission status delivery timed out")??;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_native_access_denied_is_classified_as_permission_denial() {
        let denied = anyhow::Error::new(windows::core::Error::from_hresult(
            windows::core::HRESULT(0x80070005u32 as i32),
        ))
        .context("Explicit native capture failed");
        assert!(permission_denied(&denied));
        let unavailable = anyhow::Error::new(windows::core::Error::from_hresult(
            windows::core::HRESULT(0x88890004u32 as i32),
        ));
        assert!(!permission_denied(&unavailable));
        assert!(!permission_denied(&anyhow::anyhow!(
            "permission is not verified"
        )));
    }
    #[test]
    fn stalled_status_parent_has_a_bounded_deadline() {
        struct Blocked(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
        impl Write for Blocked {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let mut open = self.0 .0.lock().unwrap();
                while !*open {
                    open = self.0 .1.wait(open).unwrap();
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let start = std::time::Instant::now();
        let result = denied(Blocked(gate.clone()), &"a".repeat(32));
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert!(result.is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }
    #[test]
    fn bounded_denial_is_one_status_with_no_endpoint_details() -> Result<()> {
        struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for Sink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
        denied(Sink(bytes.clone()), &"a".repeat(32))?;
        let bytes = bytes.lock().unwrap();
        assert!(bytes.len() < 4096 && bytes.ends_with(b"\n"));
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(value["state"], "denied");
        assert!(value.get("endpoint_id").is_none());
        Ok(())
    }
    #[test]
    fn unsupported_operations_never_fall_back_to_microphone() {
        microphone_operation(Operation::CaptureMicrophone).unwrap();
        assert!(microphone_operation(Operation::PublishMicrophone)
            .unwrap_err()
            .to_string()
            .contains("microphone capture only"));
    }
}
