//! One PTY per tmux attachment, all connected to the same workspace. Disconnect
//! kills only that attachment process; it never kills tmux's shared server.
use crate::{multiplexer::Workspace, protocol::*};
use anyhow::{ensure, Result};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::{
    collections::VecDeque,
    io::{Read, Write},
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const INPUT_CAPACITY: usize = 64 * 1024;
const INPUT_BATCH: usize = 16 * 1024;
#[derive(Default)]
struct InputBuffer(Mutex<VecDeque<u8>>);
impl InputBuffer {
    fn enqueue(&self, bytes: &[u8]) -> Result<()> {
        let mut pending = self.0.lock().expect("PTY input buffer");
        ensure!(
            pending.len() + bytes.len() <= INPUT_CAPACITY,
            "terminal input is backpressured"
        );
        pending.extend(bytes);
        Ok(())
    }
    fn next(&self) -> Vec<u8> {
        let mut pending = self.0.lock().expect("PTY input buffer");
        let length = pending.len().min(INPUT_BATCH);
        pending.drain(..length).collect()
    }
    fn clear(&self) {
        self.0.lock().expect("PTY input buffer").clear();
    }
}

fn write_measured(
    writer: &mut impl Write,
    mut bytes: &[u8],
    traffic: &crate::traffic::Counters,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        match writer.write(bytes) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(count) => {
                traffic.input(count);
                bytes = &bytes[count..];
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub struct Client {
    master: Box<dyn MasterPty + Send>,
    child: Option<Box<dyn Child + Send + Sync>>,
    input: Arc<InputBuffer>,
    input_wake: mpsc::Sender<()>,
    cancel: CancellationToken,
    read_only: bool,
    traffic: crate::traffic::Counters,
}

impl Client {
    pub fn attach(
        workspace: &Workspace,
        client: u64,
        read_only: bool,
        cols: u16,
        rows: u16,
        term: &str,
        output: mpsc::Sender<HostOutput>,
    ) -> Result<Self> {
        Self::attach_measured(workspace,client,read_only,cols,rows,term,output,Default::default())
    }
    pub(crate) fn attach_measured(workspace:&Workspace,client:u64,read_only:bool,cols:u16,rows:u16,
        term:&str,output:mpsc::Sender<HostOutput>,traffic:crate::traffic::Counters) -> Result<Self> {
        dimensions(cols, rows)?;
        ensure!(
            !term.is_empty()
                && term.len() <= 64
                && term
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b)),
            "invalid terminal type"
        );
        let pty = native_pty_system().openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        let command = workspace.attach(read_only);
        let mut builder = CommandBuilder::new(command.get_program());
        builder.args(command.get_args());
        for (key, value) in command.get_envs() {
            if let Some(value) = value {
                builder.env(key, value);
            } else {
                builder.env_remove(key);
            }
        }
        builder.env("TERM", term);
        let child = pty.slave.spawn_command(builder)?;
        drop(pty.slave);
        let mut reader = pty.master.try_clone_reader()?;
        let mut writer = owned_writer(pty.master.as_ref())?;
        let cancel = CancellationToken::new();
        let reading = cancel.clone();
        let handle = tokio::runtime::Handle::current();
        let read_traffic=traffic.clone();
        tokio::task::spawn_blocking(move || {
            let mut bytes = [0; 8192];
            while !reading.is_cancelled() {
                let size = match reader.read(&mut bytes) {
                    Ok(0) | Err(_) => break,
                    Ok(size) => size,
                };
                read_traffic.output(size);
                let event = HostOutput::Output {
                    client,
                    data: encode_data(&bytes[..size]),
                };
                let sent = handle.block_on(async {
                    tokio::select!{_ = reading.cancelled()=>false,result = output.send(event)=>result.is_ok()}
                });
                if !sent {
                    return;
                }
            }
            let _ = output.try_send(HostOutput::Closed { client });
        });
        // Bound bytes rather than keystroke messages. A fast typing/paste burst
        // may contain hundreds of tiny frames before this writer is scheduled.
        let input = Arc::new(InputBuffer::default());
        let pending = input.clone();
        let (input_wake, mut receive) = mpsc::channel::<()>(1);
        let writing = cancel.clone();
        let write_traffic=traffic.clone();
        tokio::task::spawn_blocking(move || {
            while receive.blocking_recv().is_some() {
                if writing.is_cancelled() {
                    pending.clear();
                    break;
                }
                loop {
                    if writing.is_cancelled() {
                        pending.clear();
                        return;
                    }
                    let bytes = pending.next();
                    if bytes.is_empty() {
                        break;
                    }
                    if write_measured(&mut writer,&bytes,&write_traffic).is_err() {
                        pending.clear();
                        return;
                    }
                }
            }
        });
        Ok(Self {
            master: pty.master,
            child: Some(child),
            input,
            input_wake,
            cancel,
            read_only,
            traffic,
        })
    }

    pub fn traffic(&self) -> crate::traffic::Snapshot {
        self.traffic.snapshot()
    }
    #[cfg(feature = "direct")]
    pub(crate) fn traffic_counter(&self) -> crate::traffic::Counters {
        self.traffic.clone()
    }
    pub fn input(&self, data: &str) -> Result<()> {
        self.input_sink().write(&decode_data(data)?)
    }
    pub fn input_sink(&self) -> InputSink {
        InputSink {
            input: self.input.clone(),
            wake: self.input_wake.clone(),
            cancel: self.cancel.clone(),
            read_only: self.read_only,
        }
    }

    /// Redraw this attachment without injecting a key or changing shell state.
    pub fn redraw_command(&self, workspace: &Workspace) -> Result<std::process::Command> {
        let tty = self
            .master
            .tty_name()
            .ok_or_else(|| anyhow::anyhow!("terminal TTY unavailable"))?;
        ensure!(tty.is_absolute(), "invalid terminal TTY");
        let mut command = workspace.command();
        command.args(["refresh-client", "-t"]).arg(tty);
        Ok(command)
    }
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        dimensions(cols, rows)?;
        self.master.resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        Ok(())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.input.clear();
        // A transport may still hold an InputSink clone. Wake the writer so
        // cancellation does not depend on every sender clone being dropped.
        let _ = self.input_wake.try_send(());
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            // Reap the detached tmux client, not the long-lived shared server.
            // A dedicated reaper avoids blocking the async transport loop.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
}

#[cfg(test)]
mod input_tests {
    #[test]
    fn traffic_counts_only_bytes_accepted_by_a_partial_pty_write() {
        struct Partial(usize);
        impl std::io::Write for Partial {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Err(std::io::ErrorKind::BrokenPipe.into());
                }
                let count = self.0.min(bytes.len());
                self.0 -= count;
                Ok(count)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let traffic = crate::traffic::Counters::default();
        assert!(super::write_measured(&mut Partial(3), b"abcdefg", &traffic).is_err());
        assert_eq!(traffic.snapshot().input_bytes, 3);
        assert_eq!(traffic.snapshot().output_bytes, 0);
    }
    use super::*;
    #[test]
    fn tiny_keystrokes_are_coalesced_in_order_and_overflow_does_not_partially_enqueue() -> Result<()>
    {
        let input = InputBuffer::default();
        for byte in 0..4000 {
            input.enqueue(&[(byte % 251) as u8])?;
        }
        assert_eq!(
            input.next(),
            (0..4000).map(|byte| (byte % 251) as u8).collect::<Vec<_>>()
        );
        assert!(input.next().is_empty());
        input.enqueue(&vec![b'a'; INPUT_CAPACITY])?;
        assert!(input.enqueue(b"overflow").is_err());
        let mut received = Vec::new();
        loop {
            let batch = input.next();
            if batch.is_empty() {
                break;
            }
            assert!(batch.len() <= INPUT_BATCH);
            received.extend(batch);
        }
        assert_eq!(received, vec![b'a'; INPUT_CAPACITY]);
        input.enqueue(b"after drain")?;
        input.clear();
        assert!(input.next().is_empty());
        Ok(())
    }
}

/// Cloneable bounded writer; cancellation and the original attachment role are
/// retained even when a transport actor outlives its network connection.
#[derive(Clone)]
pub struct InputSink {
    input: Arc<InputBuffer>,
    wake: mpsc::Sender<()>,
    cancel: CancellationToken,
    read_only: bool,
}
impl InputSink {
    pub fn write(&self, bytes: &[u8]) -> Result<()> {
        ensure!(!self.read_only, "terminal participant is read-only");
        ensure!(!self.cancel.is_cancelled(), "terminal input is closed");
        ensure!(bytes.len() <= MAX_DATA, "terminal input exceeds limit");
        self.input.enqueue(bytes)?;
        match self.wake.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(())) => anyhow::bail!("terminal input is closed"),
        }
    }
}

// portable-pty's writer injects newline+EOF on Drop. That can race a tmux
// attachment's SIGHUP and terminate the shared shell. A plain owned descriptor
// closes without ever typing into the terminal.
fn owned_writer(master: &dyn MasterPty) -> Result<std::fs::File> {
    use std::os::fd::FromRawFd;
    let descriptor = master
        .as_raw_fd()
        .ok_or_else(|| anyhow::anyhow!("terminal PTY descriptor unavailable"))?;
    // SAFETY: duplicate a live descriptor and transfer this new descriptor
    // exactly once into File. CLOEXEC prevents leaking it to child jobs.
    let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 3) };
    ensure!(
        duplicate >= 0,
        "could not duplicate terminal PTY writer: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { std::fs::File::from_raw_fd(duplicate) })
}

#[cfg(test)]
mod writer_lifecycle_tests {
    use super::*;
    struct ChildGuard(Box<dyn Child + Send + Sync>);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {let _ = self.0.kill();}
            let _ = self.0.wait();
        }
    }
    #[test]
    fn dropping_an_input_writer_does_not_type_eof_or_end_the_shell() -> Result<()> {
        let pty = native_pty_system().openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        let mut command = CommandBuilder::new("/bin/sh");
        command.arg("-i");
        command.env("ENV", "");
        command.env("BASH_ENV", "");
        command.env("PS1", "writer-test$ ");
        let mut child = ChildGuard(pty.slave.spawn_command(command)?);
        drop(pty.slave);
        let mut reader = pty.master.try_clone_reader()?;
        let (send, receive) = std::sync::mpsc::channel();
        let reading = std::thread::spawn(move || {
            let mut bytes = [0; 4096];
            while let Ok(count) = reader.read(&mut bytes) {
                if count == 0 {
                    break;
                }
                if send.send(bytes[..count].to_vec()).is_err() {
                    break;
                }
            }
        });
        let wait = |marker: &str| -> Result<()> {
            let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
            let mut bytes = Vec::new();
            while !String::from_utf8_lossy(&bytes).contains(marker) {
                let remaining = until
                    .checked_duration_since(std::time::Instant::now())
                    .ok_or_else(|| anyhow::anyhow!("PTY writer fixture timed out"))?;
                bytes.extend(receive.recv_timeout(remaining)?);
            }
            Ok(())
        };
        let mut first = owned_writer(pty.master.as_ref())?;
        first.write_all(b"PERSISTED=alive; printf 'WRITER%s\\n' 'READY'\n")?;
        wait("WRITERREADY")?;
        drop(first);
        // Leave the child running while the writer is dropped. The old writer
        // actively injected EOF here; a terminal disconnect must not do so.
        std::thread::sleep(std::time::Duration::from_millis(50));
        ensure!(
            child.0.try_wait()?.is_none(),
            "dropping a writer terminated the shell"
        );
        let mut second = owned_writer(pty.master.as_ref())?;
        second.write_all(b"printf 'STILL:%s\\n' \"$PERSISTED\"\n")?;
        wait("STILL:alive")?;
        drop(second);
        drop(child);
        drop(pty.master);
        reading.join().unwrap();
        Ok(())
    }
}
