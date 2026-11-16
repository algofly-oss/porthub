//! One replaceable encoded camera frame; native buffers never wait for stdout.
use anyhow::{ensure, Result};
use porthub_components::media::MAX_VIDEO_NETWORK_FRAME;
use std::{
    io::Write,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
};
struct Bytes(Vec<u8>);
impl Drop for Bytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
#[derive(Default)]
struct State {
    declared: bool,
    ready: Option<Bytes>,
    latest: Option<Bytes>,
}
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    cancel: Arc<AtomicBool>,
}
pub struct VideoOutput {
    shared: Arc<Shared>,
}
impl VideoOutput {
    pub fn new(cancel: Arc<AtomicBool>) -> Self {
        Self::writer(std::io::stdout(), cancel)
    }
    fn writer<W: Write + Send + 'static>(mut writer: W, cancel: Arc<AtomicBool>) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            cancel,
        });
        let output = shared.clone();
        std::thread::spawn(move || loop {
            let (bytes, framed) = {
                let mut state = output.state.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    if output.cancel.load(Ordering::Acquire) {
                        return;
                    }
                    if let Some(ready) = state.ready.take() {
                        break (ready, false);
                    }
                    if let Some(frame) = state.latest.take() {
                        break (frame, true);
                    }
                    state = output
                        .changed
                        .wait(state)
                        .unwrap_or_else(|e| e.into_inner());
                }
            };
            let result = (|| {
                if framed {
                    writer.write_all(&(bytes.0.len() as u32).to_le_bytes())?;
                }
                writer.write_all(&bytes.0)?;
                writer.flush()
            })();
            if result.is_err() {
                output.cancel.store(true, Ordering::Release);
                output.changed.notify_all();
                return;
            }
        });
        Self { shared }
    }
    pub fn ready(&self, value: &serde_json::Value) -> Result<()> {
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        ensure!(bytes.len() <= 4096, "Camera readiness exceeds bound");
        let mut state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(
            !state.declared && !self.shared.cancel.load(Ordering::Acquire),
            "Camera readiness already declared or cancelled"
        );
        state.declared = true;
        state.ready = Some(Bytes(bytes));
        self.shared.changed.notify_one();
        Ok(())
    }
    pub fn frame(&self, mut bytes: Vec<u8>) -> Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_VIDEO_NETWORK_FRAME {
            bytes.fill(0);
            anyhow::bail!("Camera output frame exceeds bound");
        }
        let mut state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.shared.cancel.load(Ordering::Acquire) {
            bytes.fill(0);
            return Ok(());
        }
        if !state.declared {
            bytes.fill(0);
            anyhow::bail!("Camera frame precedes readiness");
        }
        state.latest = Some(Bytes(bytes));
        self.shared.changed.notify_one();
        Ok(())
    }
}
impl Drop for VideoOutput {
    fn drop(&mut self) {
        self.shared.cancel.store(true, Ordering::Release);
        {
            let mut state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
            state.latest = None;
            state.ready = None;
        }
        self.shared.changed.notify_all();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Block {
        entered: std::sync::mpsc::Sender<()>,
        gate: Arc<(Mutex<bool>, Condvar)>,
        bytes: Arc<Mutex<Vec<u8>>>,
    }
    impl Write for Block {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let _ = self.entered.send(());
            let (mut open, changed) = (self.gate.0.lock().unwrap(), &self.gate.1);
            while !*open {
                open = changed.wait(open).unwrap();
            }
            self.bytes.lock().unwrap().extend(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn slow_writer_keeps_only_latest_frame_without_blocking_capture() {
        let (cancel, gate, bytes) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new((Mutex::new(false), Condvar::new())),
            Arc::new(Mutex::new(vec![])),
        );
        let (tx, rx) = std::sync::mpsc::channel();
        let output = VideoOutput::writer(
            Block {
                entered: tx,
                gate: gate.clone(),
                bytes: bytes.clone(),
            },
            cancel.clone(),
        );
        output
            .ready(&serde_json::json!({"state":"capturing"}))
            .unwrap();
        rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap();
        for n in 1..=100 {
            output.frame(vec![n; 16]).unwrap();
        }
        {
            let state = output.shared.state.lock().unwrap();
            assert_eq!(state.latest.as_ref().unwrap().0, vec![100; 16]);
        }
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            let captured = bytes.lock().unwrap().clone();
            if captured.ends_with(&[100; 16]) {
                assert!(captured.starts_with(b"{\"state\":\"capturing\"}\n"));
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        drop(output);
        assert!(cancel.load(Ordering::Acquire));
    }
    #[test]
    fn frames_require_ready_and_bounds() {
        let output = VideoOutput::writer(Vec::new(), Arc::new(AtomicBool::new(false)));
        assert!(output.frame(vec![1]).is_err());
        assert!(output.frame(vec![0; MAX_VIDEO_NETWORK_FRAME + 1]).is_err());
        output.ready(&serde_json::json!({"ready":true})).unwrap();
        assert!(output.ready(&serde_json::json!({"ready":true})).is_err());
    }
}
