//! Native guest byte I/O. Opening the controlling TTY separately avoids changing
//! O_NONBLOCK on the caller's inherited stdin/stdout open-file descriptions.
use anyhow::{ensure, Context, Result};
use std::{
    fs::{File, OpenOptions},
    io::{self, IsTerminal, Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::io::unix::AsyncFd;

pub struct Terminal {
    file: AsyncFd<File>,
    original: libc::termios,
    displayed: AtomicBool,
}
impl Terminal {
    pub fn open() -> Result<Self> {
        ensure!(
            io::stdin().is_terminal() && io::stdout().is_terminal(),
            "native terminal joining requires an interactive terminal"
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
            .open("/dev/tty")
            .context("open controlling terminal")?;
        Self::from_file(file)
    }
    fn from_file(file: File) -> Result<Self> {
        let original = attributes(&file)?;
        // Register before entering raw mode so a registration error leaves the
        // caller's terminal unchanged. `file` is a private open description.
        // SAFETY: the owned File keeps this descriptor open and stable until
        // AsyncFd drops it; no raw descriptor is transferred or closed elsewhere.
        let file = unsafe { AsyncFd::register(file)? };
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(file.get_ref().as_raw_fd(), libc::TCSANOW, &raw) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self {
            file,
            original,
            displayed: AtomicBool::new(false),
        })
    }
    pub fn size(&self) -> Result<(u16, u16)> {
        let mut size = std::mem::MaybeUninit::<libc::winsize>::zeroed();
        if unsafe {
            libc::ioctl(
                self.file.get_ref().as_raw_fd(),
                libc::TIOCGWINSZ,
                size.as_mut_ptr(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let size = unsafe { size.assume_init() };
        Ok((size.ws_col.clamp(20, 500), size.ws_row.clamp(5, 200)))
    }
    /// Cancellation never leaves a background stdin reader or consumes a byte
    /// that wasn't returned. Escape/mouse/paste bytes pass through unchanged.
    pub async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        read(&self.file, bytes).await
    }
    /// The delivery cursor advances only after this completes. Writes may be
    /// partial; readiness backpressure does not allocate another output queue.
    pub async fn write_all(&self, mut bytes: &[u8]) -> io::Result<()> {
        if !bytes.is_empty() {
            self.displayed.store(true, Ordering::Relaxed);
        }
        while !bytes.is_empty() {
            let mut ready = self.file.writable().await?;
            match ready.try_io(|file| {
                let mut file = file.get_ref();
                file.write(bytes)
            }) {
                Ok(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(Ok(count)) => bytes = &bytes[count..],
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => {}
            }
        }
        Ok(())
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        if self.displayed.load(Ordering::Relaxed) {
            // Best effort on the nonblocking descriptor: never hang teardown
            // because a terminal stopped consuming output. In particular, an
            // abrupt gateway loss must not leave mouse capture or hidden cursor.
            let mut file = self.file.get_ref();
            let _=file.write_all(b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?25h\x1b[0m\x1b[?1049l");
        }
        // No flush: queued remote bytes and a user's just-typed local bytes must
        // not be discarded during detach or normal error unwinding.
        unsafe {
            libc::tcsetattr(
                self.file.get_ref().as_raw_fd(),
                libc::TCSANOW,
                &self.original,
            )
        };
    }
}
fn attributes(file: &File) -> io::Result<libc::termios> {
    let mut value = std::mem::MaybeUninit::uninit();
    if unsafe { libc::tcgetattr(file.as_raw_fd(), value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { value.assume_init() })
}
async fn read(file: &AsyncFd<File>, bytes: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut ready = file.readable().await?;
        match ready.try_io(|file| {
            let mut file = file.get_ref();
            file.read(bytes)
        }) {
            Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
            Ok(result) => return result,
            Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::fd::FromRawFd, time::Duration};
    fn pty() -> Result<(File, File)> {
        let (mut master, mut slave) = (-1, -1);
        let size = libc::winsize {
            ws_col: 100,
            ws_row: 30,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        ensure!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    &size,
                )
            } == 0,
            "test PTY creation failed"
        );
        let (master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        for file in [&master, &slave] {
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            ensure!(
                flags >= 0
                    && unsafe {
                        libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                    } == 0,
                "test PTY nonblocking setup failed"
            );
        }
        Ok((master, slave))
    }
    #[tokio::test]
    async fn raw_keys_resize_output_and_detach_restore_the_original_terminal() -> Result<()> {
        let (mut master, slave) = pty()?;
        let observer = slave.try_clone()?;
        let original = attributes(&observer)?;
        let terminal = Terminal::from_file(slave)?;
        let raw = attributes(&observer)?;
        assert_eq!(raw.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG), 0);
        assert_eq!(terminal.size()?, (100, 30));
        let keys = b"\x03\x04\x1b[18~\x1b[<64;10;5M\x1b[200~paste\r\n\x1b[201~\0\xff";
        let mut bytes = vec![0; keys.len()];
        assert!(
            tokio::time::timeout(Duration::from_millis(10), terminal.read(&mut bytes))
                .await
                .is_err()
        );
        master.write_all(keys)?;
        let mut offset = 0;
        while offset < bytes.len() {
            let count =
                tokio::time::timeout(Duration::from_secs(2), terminal.read(&mut bytes[offset..]))
                    .await??;
            assert!(count > 0);
            offset += count;
        }
        assert_eq!(
            bytes, keys,
            "control keys, F7, mouse and paste bytes must remain exact"
        );
        let output = b"\x1b[?1000h\x1b]52;c;dGVzdA==\x07\r\n\0\xff";
        terminal.write_all(output).await?;
        // SAFETY: this owned File retains a stable descriptor for the registration.
        let master = unsafe { AsyncFd::register(master)? };
        let mut received = vec![0; output.len()];
        let mut offset = 0;
        while offset < received.len() {
            let count = tokio::time::timeout(
                Duration::from_secs(2),
                read(&master, &mut received[offset..]),
            )
            .await??;
            assert!(count > 0);
            offset += count;
        }
        assert_eq!(
            received, output,
            "output acceptance must not rewrite terminal or clipboard sequences"
        );
        let size = libc::winsize {
            ws_col: 121,
            ws_row: 42,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        assert_eq!(
            unsafe { libc::ioctl(master.get_ref().as_raw_fd(), libc::TIOCSWINSZ, &size) },
            0
        );
        assert_eq!(terminal.size()?, (121, 42));
        drop(terminal);
        let mut cleanup = [0; 256];
        let count =
            tokio::time::timeout(Duration::from_secs(2), read(&master, &mut cleanup)).await??;
        assert!(cleanup[..count]
            .windows(8)
            .any(|bytes| bytes == b"\x1b[?1000l"));
        assert!(cleanup[..count]
            .windows(6)
            .any(|bytes| bytes == b"\x1b[?25h"));
        let restored = attributes(&observer)?;
        assert_eq!(restored.c_iflag, original.c_iflag);
        assert_eq!(restored.c_oflag, original.c_oflag);
        assert_eq!(restored.c_cflag, original.c_cflag);
        assert_eq!(restored.c_lflag, original.c_lflag);
        assert_eq!(restored.c_cc, original.c_cc);
        Ok(())
    }
    #[tokio::test]
    async fn cancelling_an_attachment_restores_raw_mode_without_a_reader_thread() -> Result<()> {
        let (_master, slave) = pty()?;
        let observer = slave.try_clone()?;
        let original = attributes(&observer)?;
        let terminal = Terminal::from_file(slave)?;
        let attachment = async move {
            let _terminal = terminal;
            std::future::pending::<()>().await;
        };
        assert!(tokio::time::timeout(Duration::from_millis(10), attachment)
            .await
            .is_err());
        let restored = attributes(&observer)?;
        assert_eq!(restored.c_iflag, original.c_iflag);
        assert_eq!(restored.c_oflag, original.c_oflag);
        assert_eq!(restored.c_lflag, original.c_lflag);
        assert_eq!(restored.c_cc, original.c_cc);
        Ok(())
    }
    #[tokio::test]
    async fn native_relay_carries_raw_input_and_read_only_history_without_shell_input() -> Result<()>
    {
        use crate::terminal_guest::{relay, Guest};
        use futures_util::{SinkExt, StreamExt};
        use porthub_terminal::protocol::*;
        use tokio_tungstenite::{
            tungstenite::{protocol::Role, Message},
            WebSocketStream,
        };
        for read_only in [false, true] {
            let (master, slave) = pty()?;
            let terminal = Terminal::from_file(slave)?;
            // SAFETY: the owned File retains this descriptor until AsyncFd drops it.
            let master = unsafe { AsyncFd::register(master)? };
            let (client, server) = tokio::io::duplex(131072);
            let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
            let mut server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
            let welcome = ViewerEvent::Welcome {
                direct_transport: false,
                history_snapshots: true,
                name: "fixture".into(),
                read_only,
                expires_at: 0,
                participants: 1,
            };
            let remote_welcome = welcome.clone();
            let (seen, screen_seen) = tokio::sync::oneshot::channel();
            let remote = async move {
                let hello = server.next().await.context("missing hello")??.into_text()?;
                let hello: serde_json::Value = serde_json::from_str(&hello)?;
                assert_eq!(hello["token"], "a".repeat(64));
                server
                    .send(Message::Text(
                        serde_json::to_string(&remote_welcome)?.into(),
                    ))
                    .await?;
                let resize = server
                    .next()
                    .await
                    .context("missing initial resize")??
                    .into_text()?;
                assert!(matches!(
                    serde_json::from_str::<ViewerInput>(&resize)?,
                    ViewerInput::Resize {
                        cols: 100,
                        rows: 30
                    }
                ));
                server
                    .send(Message::Text(
                        serde_json::to_string(&ViewerEvent::Output {
                            data: encode_data(b"READY\r\n"),
                        })?
                        .into(),
                    ))
                    .await?;
                let input = server
                    .next()
                    .await
                    .context("missing guest input")??
                    .into_text()?;
                let response = match serde_json::from_str::<ViewerInput>(&input)? {
                    ViewerInput::Input { data } if !read_only => {
                        assert_eq!(
                            decode_data(&data)?,
                            b"\x03\x04\x1b[18~\x1b[200~paste\x1b[201~"
                        );
                        ViewerEvent::Output {
                            data: encode_data(b"WRITER_ACCEPTED\r\n"),
                        }
                    }
                    ViewerInput::History {
                        request,
                        freeze: true,
                        snapshot: None,
                        ..
                    } if read_only => ViewerEvent::History {
                        page: serde_json::from_value(serde_json::json!({
                            "request":request,"snapshot":"b".repeat(32),"pane":"%1",
                            "data":encode_data(b"READER_HISTORY\n"),"done":true,"total":1,
                            "before":0,"lines":1,"truncated":false}))?,
                    },
                    _ => anyhow::bail!("read-only shell input or unexpected guest request"),
                };
                server
                    .send(Message::Text(serde_json::to_string(&response)?.into()))
                    .await?;
                screen_seen.await?;
                server
                    .send(Message::Text(
                        serde_json::to_string(&ViewerEvent::Closed {
                            reason: "fixture complete".into(),
                            retryable: false,
                        })?
                        .into(),
                    ))
                    .await?;
                Ok::<_, anyhow::Error>(())
            };
            let viewer = async {
                let (mut guest, welcome) =
                    Guest::authenticate(client, &"a".repeat(64), None, 100, 30).await?;
                let end = relay::run(&mut guest, &terminal, &welcome).await?;
                assert_eq!(end.reason, "fixture complete");
                assert!(!end.retryable);
                Ok::<_, anyhow::Error>(())
            };
            let local = async {
                let mut screen = Vec::new();
                let mut buffer = [0; 8192];
                while !screen.windows(5).any(|bytes| bytes == b"READY") {
                    let count = read(&master, &mut buffer).await?;
                    assert!(count > 0);
                    screen.extend_from_slice(&buffer[..count]);
                }
                let keys = if read_only {
                    b"never execute this\r\x1b[18~".as_slice()
                } else {
                    b"\x03\x04\x1b[18~\x1b[200~paste\x1b[201~".as_slice()
                };
                let mut writer = master.get_ref();
                writer.write_all(keys)?;
                let marker = if read_only {
                    b"READER_HISTORY".as_slice()
                } else {
                    b"WRITER_ACCEPTED".as_slice()
                };
                while !screen.windows(marker.len()).any(|bytes| bytes == marker) {
                    let count = read(&master, &mut buffer).await?;
                    assert!(count > 0);
                    screen.extend_from_slice(&buffer[..count]);
                }
                seen.send(())
                    .map_err(|_| anyhow::anyhow!("fixture screen observer ended"))?;
                Ok::<_, anyhow::Error>(())
            };
            tokio::time::timeout(Duration::from_secs(3), async {
                tokio::try_join!(remote, viewer, local)
            })
            .await??;
        }
        Ok(())
    }
}
