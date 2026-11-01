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
    /// Offline input belongs to no active attachment. Do not execute it after a
    /// successful reconnect; ordinary detach never uses this explicit flush.
    pub(super) fn discard_offline_input(&self) -> io::Result<()> {
        if unsafe { libc::tcflush(self.file.get_ref().as_raw_fd(), libc::TCIFLUSH) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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
        let mut size = libc::winsize {
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
                    std::ptr::null_mut(),
                    &mut size,
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
    async fn native_setup_discards_waiting_keys_and_ctrl_c_cancels_locally()->Result<()> {
        let (mut master,slave)=pty()?;
        let terminal=Terminal::from_file(slave)?;
        master.write_all(b"not an online command\r")?;
        let ready=crate::terminal_guest::client::preparing(&terminal,async {tokio::time::sleep(Duration::from_millis(30)).await;7_u8}).await?;
        assert_eq!(ready,Some(7));
        let mut bytes=[0;128];
        assert!(tokio::time::timeout(Duration::from_millis(20),terminal.read(&mut bytes)).await.is_err(),"waiting keys must not cross into the connected shell");
        master.write_all(&[3])?;
        let cancelled=tokio::time::timeout(Duration::from_secs(1),crate::terminal_guest::client::preparing(&terminal,std::future::pending::<u8>())).await??;
        assert_eq!(cancelled,None);
        Ok(())
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
    #[tokio::test]
    async fn native_client_resumes_without_replaying_old_commands_or_offline_keystrokes(
    ) -> Result<()> {
        use crate::terminal_guest::{client, Failure, Guest, Recovery};
        use futures_util::{SinkExt, StreamExt};
        use porthub_terminal::protocol::*;
        use tokio_tungstenite::{
            tungstenite::{protocol::Role, Message},
            WebSocketStream,
        };
        struct Connect {
            sockets: std::collections::VecDeque<WebSocketStream<tokio::io::DuplexStream>>,
            attempts: usize,
            gate: Option<tokio::sync::oneshot::Receiver<()>>,
        }
        #[async_trait::async_trait]
        impl client::Connector for Connect {
            type Stream = tokio::io::DuplexStream;
            async fn connect(
                &mut self,
                recovery: &mut Option<Recovery>,
                cols: u16,
                rows: u16,
            ) -> Result<(Guest<Self::Stream>, ViewerEvent)> {
                self.attempts += 1;
                if self.attempts > 1 {
                    assert!(
                        recovery.is_some(),
                        "never fall back to the invitation on resume"
                    );
                }
                if self.attempts == 2 {
                    return Err(Failure::Disconnected("isolated transient failure").into());
                }
                if self.attempts == 3 {
                    self.gate.take().unwrap().await?;
                }
                Guest::authenticate_resumable(
                    self.sockets.pop_front().unwrap(),
                    &"a".repeat(64),
                    recovery,
                    cols,
                    rows,
                )
                .await
            }
        }
        async fn send(
            socket: &mut WebSocketStream<tokio::io::DuplexStream>,
            event: ViewerEvent,
        ) -> Result<()> {
            socket
                .send(Message::Text(serde_json::to_string(&event)?.into()))
                .await?;
            Ok(())
        }
        async fn observe(
            master: &AsyncFd<File>,
            screen: &mut Vec<u8>,
            marker: &[u8],
        ) -> Result<()> {
            let mut bytes = [0; 8192];
            while !screen.windows(marker.len()).any(|bytes| bytes == marker) {
                let count = read(master, &mut bytes).await?;
                assert!(count > 0);
                screen.extend_from_slice(&bytes[..count]);
            }
            Ok(())
        }
        let (master, slave) = pty()?;
        let terminal = Terminal::from_file(slave)?;
        // SAFETY: the owned File retains a stable descriptor for this registration.
        let master = unsafe { AsyncFd::register(master)? };
        let mut sockets = std::collections::VecDeque::new();
        let mut servers = Vec::new();
        for _ in 0..2 {
            let (a, b) = tokio::io::duplex(131072);
            sockets.push_back(WebSocketStream::from_raw_socket(a, Role::Client, None).await);
            servers.push(WebSocketStream::from_raw_socket(b, Role::Server, None).await);
        }
        let (gate, wait) = tokio::sync::oneshot::channel();
        let mut connector = Connect {
            sockets,
            attempts: 0,
            gate: Some(wait),
        };
        let remote = async move {
            for (index, mut server) in servers.into_iter().enumerate() {
                let hello = server.next().await.context("missing hello")??.into_text()?;
                let hello: serde_json::Value = serde_json::from_str(&hello)?;
                if index == 0 {
                    assert_eq!(hello["token"], "a".repeat(64));
                } else {
                    assert_eq!(hello["resume_token"], "b".repeat(64));
                    assert!(hello.get("token").is_none());
                }
                send(
                    &mut server,
                    ViewerEvent::Recovery {
                        session: "a".repeat(32),
                        token: if index == 0 {
                            "b".repeat(64)
                        } else {
                            "c".repeat(64)
                        },
                        participant: 1,
                        reconnect_timeout: 10,
                    },
                )
                .await?;
                send(
                    &mut server,
                    ViewerEvent::Welcome {
                        direct_transport: false,
                        history_snapshots: true,
                        name: "recover".into(),
                        read_only: false,
                        expires_at: 0,
                        participants: 1,
                    },
                )
                .await?;
                let resize = server
                    .next()
                    .await
                    .context("missing resize")??
                    .into_text()?;
                assert!(matches!(
                    serde_json::from_str::<ViewerInput>(&resize)?,
                    ViewerInput::Resize { .. }
                ));
                send(
                    &mut server,
                    ViewerEvent::Output {
                        data: encode_data(if index == 0 {
                            b"FIRST_READY"
                        } else {
                            b"SECOND_READY"
                        }),
                    },
                )
                .await?;
                let input = server.next().await.context("missing input")??.into_text()?;
                let ViewerInput::Input { data } = serde_json::from_str::<ViewerInput>(&input)?
                else {
                    anyhow::bail!("unexpected guest message")
                };
                assert_eq!(
                    decode_data(&data)?,
                    if index == 0 {
                        b"once\r".as_slice()
                    } else {
                        b"after\r".as_slice()
                    },
                    "old or offline command crossed the attachment boundary"
                );
                if index == 0 {
                    server.close(None).await?;
                } else {
                    send(
                        &mut server,
                        ViewerEvent::Closed {
                            reason: "complete".into(),
                            retryable: false,
                        },
                    )
                    .await?;
                }
            }
            Ok::<_, anyhow::Error>(())
        };
        let local = async {
            let mut screen = Vec::new();
            observe(&master, &mut screen, b"FIRST_READY").await?;
            let mut writer = master.get_ref();
            writer.write_all(b"once\r")?;
            observe(&master, &mut screen, b"PortHub reconnecting").await?;
            writer.write_all(b"offline_must_not_execute\r")?;
            gate.send(())
                .map_err(|_| anyhow::anyhow!("reconnect gate dropped"))?;
            observe(&master, &mut screen, b"SECOND_READY").await?;
            writer.write_all(b"after\r")?;
            Ok::<_, anyhow::Error>(())
        };
        let viewer = async {
            let end = client::run(&mut connector, &terminal).await?;
            assert_eq!(end.reason, "complete");
            assert!(!end.retryable);
            Ok::<_, anyhow::Error>(())
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::try_join!(remote, local, viewer)
        })
        .await??;
        assert_eq!(
            connector.attempts, 3,
            "transient retry should preserve its credential and deadline"
        );
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn native_recovery_stops_at_its_deadline_or_immediately_on_rejection() -> Result<()> {
        use crate::terminal_guest::{client, Failure, Guest, Recovery};
        use futures_util::SinkExt;
        use porthub_terminal::protocol::*;
        use tokio_tungstenite::{
            tungstenite::{protocol::Role, Message},
            WebSocketStream,
        };
        struct Connect {
            socket: Option<WebSocketStream<tokio::io::DuplexStream>>,
            attempts: usize,
            rejected: bool,
            deadline: Option<tokio::time::Instant>,
        }
        #[async_trait::async_trait]
        impl client::Connector for Connect {
            type Stream = tokio::io::DuplexStream;
            async fn connect(
                &mut self,
                recovery: &mut Option<Recovery>,
                cols: u16,
                rows: u16,
            ) -> Result<(Guest<Self::Stream>, ViewerEvent)> {
                self.attempts += 1;
                if let Some(socket) = self.socket.take() {
                    return Guest::authenticate_resumable(
                        socket,
                        &"a".repeat(64),
                        recovery,
                        cols,
                        rows,
                    )
                    .await;
                }
                let credential = recovery.as_ref().context("lost recovery credential")?;
                assert_eq!(credential.capability, "b".repeat(64));
                match self.deadline {
                    None => self.deadline = credential.deadline,
                    Some(deadline) => assert_eq!(credential.deadline, Some(deadline)),
                }
                Err(if self.rejected {
                    Failure::Rejected
                } else {
                    Failure::Disconnected("isolated unavailable gateway")
                }
                .into())
            }
        }
        for rejected in [false, true] {
            let (_master, slave) = pty()?;
            let terminal = Terminal::from_file(slave)?;
            let (a, b) = tokio::io::duplex(131072);
            let client = WebSocketStream::from_raw_socket(a, Role::Client, None).await;
            let mut server = WebSocketStream::from_raw_socket(b, Role::Server, None).await;
            for event in [
                ViewerEvent::Recovery {
                    session: "a".repeat(32),
                    token: "b".repeat(64),
                    participant: 1,
                    reconnect_timeout: 10,
                },
                ViewerEvent::Welcome {
                    direct_transport: false,
                    history_snapshots: true,
                    name: "bounded".into(),
                    read_only: false,
                    expires_at: 0,
                    participants: 1,
                },
            ] {
                server
                    .send(Message::Text(serde_json::to_string(&event)?.into()))
                    .await?;
            }
            server.close(None).await?;
            let mut connector = Connect {
                socket: Some(client),
                attempts: 0,
                rejected,
                deadline: None,
            };
            let result = client::run(&mut connector, &terminal).await;
            assert!(result.is_err());
            if rejected {
                assert_eq!(connector.attempts, 2);
            } else {
                assert!(connector.attempts > 2 && connector.attempts < 20);
                assert!(tokio::time::Instant::now() >= connector.deadline.unwrap());
                assert!(
                    tokio::time::Instant::now() - connector.deadline.unwrap()
                        < Duration::from_millis(10)
                );
            }
        }
        Ok(())
    }
    #[tokio::test]
    async fn native_direct_tty_switches_to_relay_without_repeating_shell_input() -> Result<()> {
        native_direct_tty_flow(false).await
    }
    #[tokio::test]
    async fn native_direct_tty_revokes_private_permission_without_reconnecting_the_guest(
    ) -> Result<()> {
        native_direct_tty_flow(true).await
    }
    async fn native_direct_tty_flow(revoke: bool) -> Result<()> {
        use crate::terminal_guest::{relay, Guest};
        use futures_util::{SinkExt, StreamExt};
        use porthub_terminal::{
            delivery::{Frame, Message as Packet, Receiver},
            direct::{Event, Peer},
            protocol::*,
        };
        use tokio_tungstenite::{
            tungstenite::{protocol::Role, Message},
            WebSocketStream,
        };
        async fn signal(
            socket: &mut WebSocketStream<tokio::io::DuplexStream>,
            event: ViewerEvent,
        ) -> Result<()> {
            socket
                .send(Message::Text(serde_json::to_string(&event)?.into()))
                .await?;
            Ok(())
        }
        let (master, slave) = pty()?;
        let terminal = Terminal::from_file(slave)?;
        // SAFETY: the owned File retains a stable descriptor for this registration.
        let master = unsafe { AsyncFd::register(master)? };
        let (a, b) = tokio::io::duplex(131072);
        let client = WebSocketStream::from_raw_socket(a, Role::Client, None).await;
        let mut server = WebSocketStream::from_raw_socket(b, Role::Server, None).await;
        let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let (permission, mut policy_writer, mut policy_observer) = if revoke {
            let (permission, writer) = crate::terminal_policy::test_permission().await?;
            let observer = permission.receiver.clone();
            (Some(permission), Some(writer), Some(observer))
        } else {
            (None, None, None)
        };
        let (seen, screen_seen) = tokio::sync::oneshot::channel();
        let remote = Box::pin(async move {
            server.next().await.context("missing hello")??;
            signal(
                &mut server,
                ViewerEvent::Welcome {
                    name: "direct".into(),
                    read_only: false,
                    expires_at: 0,
                    participants: 1,
                    direct_transport: true,
                    history_snapshots: true,
                },
            )
            .await?;
            let resize = server
                .next()
                .await
                .context("missing resize")??
                .into_text()?;
            assert!(matches!(
                serde_json::from_str::<ViewerInput>(&resize)?,
                ViewerInput::Resize { .. }
            ));
            let offer = server
                .next()
                .await
                .context("missing direct offer")??
                .into_text()?;
            let ViewerInput::DirectOffer {
                request,
                description,
            } = serde_json::from_str::<ViewerInput>(&offer)?
            else {
                anyhow::bail!("direct offer required")
            };
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            let local = socket.local_addr()?;
            let (peer, description) =
                Peer::answer(std::time::Instant::now(), &description.0, &[local])?;
            let mut peer = Box::new(peer);
            signal(
                &mut server,
                ViewerEvent::DirectAnswer {
                    answer: DirectAnswer {
                        request,
                        description: DirectDescription(description),
                        input_epoch: "a".repeat(32),
                        output_epoch: "b".repeat(32),
                    },
                },
            )
            .await?;
            let mut receiver = Receiver::new(&"a".repeat(32))?;
            let mut applied = Vec::new();
            let mut initial = false;
            let mut direct_inputs = 0;
            let mut relay_inputs = 0;
            let mut output_acked = false;
            let mut bytes = vec![0; 65536];
            loop {
                while let Some(event) = peer.event()? {
                    if matches!(event, Event::Ready) && !initial {
                        initial = true;
                        peer.send(
                            std::time::Instant::now(),
                            &Packet::Data(Frame::new(&"b".repeat(32), 1, b"DIRECT_READY")?)
                                .encode()?,
                        )?;
                    }
                }
                while let Some((remote, bytes)) = peer.datagram() {
                    socket.send_to(&bytes, remote).await?;
                }
                let deadline = peer
                    .deadline()
                    .unwrap_or(std::time::Instant::now() + Duration::from_secs(60));
                let message = tokio::select! {
                    event=server.next()=>{
                        let text=event.context("gateway disconnected")??.into_text()?;
                        let ViewerInput::Delivery {packet}=serde_json::from_str::<ViewerInput>(&text)? else {anyhow::bail!("unsequenced input after negotiation")};
                        Some((packet.decode()?,true))
                    },
                    packet=socket.recv_from(&mut bytes)=>{
                        let (count,remote)=packet?;
                        let _=peer.receive(std::time::Instant::now(),local,remote,&bytes[..count]);None
                    },
                    _=tokio::time::sleep_until(deadline.into())=>{peer.timeout(std::time::Instant::now())?;None},
                };
                let mut messages = Vec::new();
                if let Some(message) = message {
                    messages.push(message);
                }
                while let Some(bytes) = peer.read()? {
                    messages.push((Packet::parse(&bytes)?, false));
                }
                for (message, via_relay) in messages {
                    match message {
                        Packet::Data(frame) => {
                            if via_relay {
                                relay_inputs += 1;
                            } else {
                                direct_inputs += 1;
                            }
                            receiver.stage(frame)?;
                            while let Some(frame) = receiver.next() {
                                let sequence = frame.sequence();
                                applied.extend_from_slice(frame.payload());
                                receiver.commit(sequence)?;
                            }
                            if !via_relay && policy_writer.is_some() {
                                // Revoke after the command reached the host.
                                // Observe the shared permission change before
                                // sending the relay confirmation below.
                                drop(policy_writer.take());
                                policy_observer.as_mut().unwrap().changed().await?;
                            }
                            if via_relay {
                                signal(
                                    &mut server,
                                    ViewerEvent::Delivery {
                                        packet: DeliveryPacket::encode(&Packet::Ack {
                                            epoch: "a".repeat(32),
                                            sequence: receiver.acknowledged(),
                                        })?,
                                    },
                                )
                                .await?;
                                signal(
                                    &mut server,
                                    ViewerEvent::Delivery {
                                        packet: DeliveryPacket::encode(&Packet::Data(Frame::new(
                                            &"b".repeat(32),
                                            2,
                                            b"RELAY_CONFIRMED",
                                        )?))?,
                                    },
                                )
                                .await?;
                            }
                            // Deliberately withhold the direct input ACK to
                            // exercise the native runner's real fallback timer.
                        }
                        Packet::Ack { epoch, sequence } => {
                            assert_eq!(epoch, "b".repeat(32));
                            if sequence == 2 {
                                assert!(via_relay);
                                output_acked = true;
                            }
                        }
                    }
                }
                if output_acked {
                    assert!(direct_inputs >= 1 && relay_inputs >= 1);
                    assert_eq!(applied, b"first\r", "fallback typed the command twice");
                    screen_seen.await?;
                    signal(
                        &mut server,
                        ViewerEvent::Closed {
                            reason: "complete".into(),
                            retryable: false,
                        },
                    )
                    .await?;
                    return Ok::<_, anyhow::Error>(());
                }
            }
        });
        let viewer = async {
            let (mut guest, welcome) =
                Guest::authenticate(client, &"a".repeat(64), None, 100, 30).await?;
            let end = Box::pin(relay::run_with_policy(
                &mut guest,
                &terminal,
                &welcome,
                Some(client_udp),
                permission,
            ))
            .await?;
            assert_eq!(end.reason, "complete");
            Ok::<_, anyhow::Error>(())
        };
        let local = async {
            let mut screen = Vec::new();
            let mut bytes = [0; 8192];
            while !screen.windows(12).any(|bytes| bytes == b"DIRECT_READY") {
                let count = read(&master, &mut bytes).await?;
                assert!(count > 0);
                screen.extend_from_slice(&bytes[..count]);
            }
            let mut writer = master.get_ref();
            writer.write_all(b"first\r")?;
            while !screen.windows(15).any(|bytes| bytes == b"RELAY_CONFIRMED") {
                let count = read(&master, &mut bytes).await?;
                assert!(count > 0);
                screen.extend_from_slice(&bytes[..count]);
            }
            seen.send(())
                .map_err(|_| anyhow::anyhow!("screen observer dropped"))?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(remote, viewer, local)
        })
        .await??;
        Ok(())
    }
}
