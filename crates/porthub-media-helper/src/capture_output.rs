//! Native capture callbacks never wait for a slow parent pipe.
use anyhow::{ensure, Result};
use std::{
    collections::VecDeque,
    io::Write,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
};
struct Entry {
    bytes: Vec<u8>,
    framed: bool,
}
#[derive(Default)]
struct State {
    entries: VecDeque<Entry>,
    bytes: usize,
    ready: bool,
}
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    cancel: Arc<AtomicBool>,
}
pub struct Output {
    shared: Arc<Shared>,
    max_frame: usize,
    max_queued: usize,
}
impl Output {
    pub fn audio(cancel: Arc<AtomicBool>) -> Self {
        Self::new(
            std::io::stdout(),
            cancel,
            porthub_components::media::MAX_PCM_FRAME,
            19_200,
        )
    }
    fn new<W: Write + Send + 'static>(
        mut writer: W,
        cancel: Arc<AtomicBool>,
        max_frame: usize,
        max_queued: usize,
    ) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            cancel,
        });
        let output = shared.clone();
        std::thread::spawn(move || loop {
            let entry = {
                let mut state = output.state.lock().unwrap_or_else(|e| e.into_inner());
                while state.entries.is_empty() && !output.cancel.load(Ordering::Acquire) {
                    state = output
                        .changed
                        .wait(state)
                        .unwrap_or_else(|e| e.into_inner());
                }
                if output.cancel.load(Ordering::Acquire) {
                    break;
                }
                let entry = state.entries.pop_front().unwrap();
                if entry.framed {
                    state.bytes -= entry.bytes.len();
                }
                entry
            };
            let result = if entry.framed {
                writer
                    .write_all(&(entry.bytes.len() as u32).to_le_bytes())
                    .and_then(|_| writer.write_all(&entry.bytes))
            } else {
                writer.write_all(&entry.bytes)
            };
            if result.and_then(|_| writer.flush()).is_err() {
                output.cancel.store(true, Ordering::Release);
                output.changed.notify_all();
                break;
            }
        });
        Self {
            shared,
            max_frame,
            max_queued,
        }
    }
    pub fn ready(&self, value: &serde_json::Value) -> Result<()> {
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        ensure!(bytes.len() <= 4096, "Media readiness exceeds bound");
        let mut state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(
            !state.ready && !self.shared.cancel.load(Ordering::Acquire),
            "Media readiness already sent or cancelled"
        );
        state.ready = true;
        state.entries.push_back(Entry {
            bytes,
            framed: false,
        });
        self.shared.changed.notify_one();
        Ok(())
    }
    pub fn frame(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= self.max_frame,
            "Media callback frame exceeds bound"
        );
        if self.shared.cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(state.ready, "Native media produced data before readiness");
        while state.bytes + bytes.len() > self.max_queued {
            let Some(index) = state.entries.iter().position(|e| e.framed) else {
                break;
            };
            let mut old = state.entries.remove(index).unwrap();
            state.bytes -= old.bytes.len();
            old.bytes.fill(0);
        }
        state.entries.push_back(Entry {
            bytes: bytes.to_vec(),
            framed: true,
        });
        state.bytes += bytes.len();
        self.shared.changed.notify_one();
        Ok(())
    }
}
impl Drop for Output {
    fn drop(&mut self) {
        self.shared.cancel.store(true, Ordering::Release);
        let mut state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
        for entry in &mut state.entries {
            entry.bytes.fill(0);
        }
        state.entries.clear();
        state.bytes = 0;
        self.shared.changed.notify_all();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Blocked {
        gate: Arc<(Mutex<bool>, Condvar)>,
        entered: std::sync::mpsc::Sender<()>,
    }
    impl Write for Blocked {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let _ = self.entered.send(());
            let (guard, signal) = (&self.gate.0, &self.gate.1);
            let mut state = guard.lock().unwrap();
            while !*state {
                state = signal.wait(state).unwrap();
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn slow_pipe_cannot_block_native_callbacks_or_eof_cancellation() -> Result<()> {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let output = Output::new(
            Blocked {
                gate: gate.clone(),
                entered: tx,
            },
            cancel.clone(),
            3840,
            19200,
        );
        output.ready(&serde_json::json!({"state":"capturing"}))?;
        rx.recv_timeout(std::time::Duration::from_secs(1))?;
        for _ in 0..100 {
            output.frame(&vec![0; 3840])?;
        }
        let shared = output.shared.clone();
        assert!(shared.state.lock().unwrap().bytes <= 19200);
        drop(output);
        assert!(cancel.load(Ordering::Acquire));
        assert_eq!(shared.state.lock().unwrap().bytes, 0);
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        Ok(())
    }
}
