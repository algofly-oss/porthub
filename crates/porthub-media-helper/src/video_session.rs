//! Explicit inherited-pipe PHV1 camera session. No discovery/default activation.
use crate::{
    linux_video::{self, ExpectedDevice},
    video_output::VideoOutput,
};
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
/// The caller parses a bounded authenticated SessionRequest, retains the exact
/// inventory proof, and supplies the still-owned inherited control reader.
pub fn serve<R: Read + Send + 'static>(
    session: &str,
    source_id: &str,
    expected: ExpectedDevice,
    format: VideoFormat,
    mut input: R,
) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    validate(session, source_id, &expected)?;
    ensure!(
        std::fs::metadata("/proc/self/fd/0")?.file_type().is_fifo(),
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
    let result = linux_video::capture(
        &expected,
        format,
        &cancel,
        |negotiated| {
            ready_declared.set(true);
            output.ready(&serde_json::json!({"session":session,"state":"capturing","backend":"v4l2","source_id":source_id,"format":negotiated}))
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
            .downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
    })
}
fn unsupported(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|e| e.is::<linux_video::CameraUnsupported>())
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
fn validate(session: &str, source_id: &str, expected: &ExpectedDevice) -> Result<()> {
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
    fn denial_delivery_is_bounded_when_parent_pipe_stalls() {
        struct Block(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
        impl Write for Block {
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
        let start = Instant::now();
        let result = denied(Block(gate.clone()), &"a".repeat(32));
        assert!(result.is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
    }
    #[test]
    fn unsupported_requires_positive_typed_capability_evidence() {
        assert!(unsupported(
            &linux_video::CameraUnsupported("capability unsupported").into()
        ));
        assert!(!unsupported(&anyhow::anyhow!("unsupported camera")));
        assert!(!unsupported(
            &std::io::Error::from(std::io::ErrorKind::NotFound).into()
        ));
    }
    #[test]
    fn only_native_permission_denial_is_reported_as_denied() {
        assert!(permission_denied(
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied).into()
        ));
        assert!(!permission_denied(
            &std::io::Error::from(std::io::ErrorKind::NotFound).into()
        ));
        assert!(!permission_denied(&anyhow::anyhow!("permission denied")));
    }
    #[test]
    fn malformed_identity_fails_before_any_camera_or_pipe_access() {
        let expected:ExpectedDevice=serde_json::from_value(serde_json::json!({"native_path":"/dev/video999999999","rdev":0,"node_inode":0,"sys_path":"/sys/devices/fixture/video4linux/video999999999","sys_inode":0,"ancestors":[]})).unwrap();
        assert!(validate("invalid", &expected.source_id(), &expected).is_err());
        assert!(validate(&"a".repeat(32), &"media:wrong", &expected).is_err());
        assert!(validate(&"a".repeat(32), &expected.source_id(), &expected).is_ok());
        let mut oversized = serde_json::to_value(&expected).unwrap();
        oversized["sys_path"] = serde_json::Value::String("x".repeat(8192));
        let oversized: ExpectedDevice = serde_json::from_value(oversized).unwrap();
        assert!(validate(&"a".repeat(32), &oversized.source_id(), &oversized).is_err());
    }
}
