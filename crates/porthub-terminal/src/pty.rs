//! One PTY per tmux attachment, all connected to the same workspace. Disconnect
//! kills only that attachment process; it never kills tmux's shared server.
use crate::{multiplexer::Workspace, protocol::*};
use anyhow::{ensure, Result};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub struct Client {
    master: Box<dyn MasterPty + Send>,
    child: Option<Box<dyn Child + Send + Sync>>,
    input: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    read_only: bool,
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
        let mut writer = pty.master.take_writer()?;
        let cancel = CancellationToken::new();
        let reading = cancel.clone();
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let mut bytes = [0; 8192];
            while !reading.is_cancelled() {
                let size = match reader.read(&mut bytes) {
                    Ok(0) | Err(_) => break,
                    Ok(size) => size,
                };
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
        let (input, mut receive) = mpsc::channel::<Vec<u8>>(16);
        tokio::task::spawn_blocking(move || {
            while let Some(bytes) = receive.blocking_recv() {
                if writer.write_all(&bytes).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            master: pty.master,
            child: Some(child),
            input,
            cancel,
            read_only,
        })
    }

    pub fn input(&self, data: &str) -> Result<()> {
        ensure!(!self.read_only, "terminal participant is read-only");
        let bytes = decode_data(data)?;
        self.input
            .try_send(bytes)
            .map_err(|_| anyhow::anyhow!("terminal input is backpressured or closed"))
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
