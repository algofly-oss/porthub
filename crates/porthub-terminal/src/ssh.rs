//! Standard SSH viewers for an already-authorized terminal invitation. The SSH
//! gateway never spawns a local shell and accepts no forwarding or exec jobs.
use crate::{
    hub::{Attachment, Hub, Shared},
    protocol::*,
};
use anyhow::{ensure, Result};
use russh::{
    server::{self, Msg, Session},
    Channel, ChannelId, Pty,
};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

pub fn host_key(path: &Path) -> Result<russh::keys::PrivateKey> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "unsafe terminal SSH host key"
        );
        #[cfg(unix)]
        ensure!(
            metadata.mode() & 0o077 == 0,
            "terminal SSH host key must be private"
        );
        return Ok(russh::keys::load_secret_key(path, None)?);
    }
    let key = russh::keys::PrivateKey::random(&mut rand10::rng(), russh::keys::Algorithm::Ed25519)?;
    let value = key.to_openssh(russh::keys::ssh_key::LineEnding::LF)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    use std::io::Write;
    let mut file = options.open(path)?;
    file.write_all(value.as_bytes())?;
    file.sync_all()?;
    Ok(key)
}
pub fn config(key: russh::keys::PrivateKey) -> Arc<server::Config> {
    Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_millis(500),
        auth_rejection_time_initial: Some(Duration::from_millis(500)),
        max_auth_attempts: 2,
        inactivity_timeout: Some(Duration::from_secs(300)),
        keepalive_interval: Some(Duration::from_secs(20)),
        keepalive_max: 3,
        window_size: 128 * 1024,
        maximum_packet_size: 32768,
        channel_buffer_size: 32,
        event_buffer_size: 64,
        nodelay: true,
        ..Default::default()
    })
}
pub async fn serve<S>(
    stream: S,
    config: Arc<server::Config>,
    hub: Hub,
    cancel: CancellationToken,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (authenticated, auth) = tokio::sync::oneshot::channel();
    let handler = Viewer {
        hub,
        capability: None,
        channel: None,
        size: (80, 24),
        term: "xterm-256color".into(),
        peer: None,
        worker: None,
        authenticated: Some(authenticated),
    };
    // Own the physical connection outside russh's spawned task. Cancellation
    // closes both halves even when authentication/output is stalled.
    let (transport, mut relay) = tokio::io::duplex(65536);
    let mut stream = stream;
    let work = cancel.child_token();
    let stop = work.clone();
    let _bridge = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        tokio::select! {_=stop.cancelled()=>{},_=tokio::io::copy_bidirectional(&mut stream,&mut relay)=>{}}
    }));
    let mut running = tokio::time::timeout(
        Duration::from_secs(10),
        server::run_stream(config, transport, handler),
    )
    .await??;
    tokio::select! {
        result=&mut running=>{result?;return Ok(());},
        result=tokio::time::timeout(Duration::from_secs(10),auth)=>{if !matches!(result,Ok(Ok(()))) {work.cancel();anyhow::bail!("terminal SSH authentication timed out");}},
        _=cancel.cancelled()=>{work.cancel();return Ok(());}
    }
    tokio::select! {result=&mut running=>{result?;},_=cancel.cancelled()=>{work.cancel();}}
    Ok(())
}
struct Viewer {
    hub: Hub,
    capability: Option<String>,
    channel: Option<ChannelId>,
    size: (u16, u16),
    term: String,
    peer: Option<(u64, Arc<Shared>)>,
    worker: Option<tokio::task::JoinHandle<()>>,
    authenticated: Option<tokio::sync::oneshot::Sender<()>>,
}
impl Drop for Viewer {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}
async fn output(mut viewer: Attachment, channel: ChannelId, handle: server::Handle) {
    loop {
        let event = tokio::select! {_=viewer.session.stop.cancelled()=>break,event=viewer.events.recv()=>event};
        match event {
            Some(ViewerEvent::Output { data }) => {
                let Ok(bytes) = decode_data(&data) else {
                    break;
                };
                if !matches!(
                    tokio::time::timeout(Duration::from_secs(10), handle.data(channel, bytes))
                        .await,
                    Ok(Ok(()))
                ) {
                    break;
                }
            }
            Some(ViewerEvent::Closed { .. }) | None => break,
            _ => {}
        }
    }
    let _ = handle.eof(channel).await;
    let _ = handle.close(channel).await;
}
impl server::Handler for Viewer {
    type Error = anyhow::Error;
    async fn auth_none(&mut self, user: &str) -> Result<server::Auth> {
        if self
            .hub
            .resolve(user)
            .is_ok_and(|(session, _)| session.options.access != Access::Web)
        {
            self.capability = Some(user.into());
            if let Some(done) = self.authenticated.take() {
                let _ = done.send(());
            }
            Ok(server::Auth::Accept)
        } else {
            Ok(server::Auth::Reject {
                proceed_with_methods: Some(russh::MethodSet::empty()),
                partial_success: false,
            })
        }
    }
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<()> {
        if self.capability.is_some() && self.channel.is_none() {
            self.channel = Some(channel.id());
            reply.accept().await;
        } else {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
        }
        Ok(())
    }
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _px: u32,
        _py: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<()> {
        let size = (
            u16::try_from(if cols == 0 { 80 } else { cols }).unwrap_or(0),
            u16::try_from(if rows == 0 { 24 } else { rows }).unwrap_or(0),
        );
        if dimensions(size.0, size.1).is_ok()
            && term.len() <= 64
            && term
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b))
        {
            self.size = size;
            self.term = term.to_owned();
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }
    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<()> {
        if self.peer.is_some() {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let Some(capability) = &self.capability else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        match self
            .hub
            .attach(capability, self.size.0, self.size.1, &self.term)
        {
            Ok(viewer) => {
                self.peer = Some((viewer.id, viewer.session.clone()));
                session.channel_success(channel)?;
                self.worker = Some(tokio::spawn(output(viewer, channel, session.handle())));
            }
            Err(_) => {
                session.channel_failure(channel)?;
            }
        }
        Ok(())
    }
    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<()> {
        if let Some((id, shared)) = &self.peer {
            for bytes in data.chunks(MAX_DATA) {
                let _ = shared.input(
                    *id,
                    ViewerInput::Input {
                        data: encode_data(bytes),
                    },
                );
            }
        }
        Ok(())
    }
    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        cols: u32,
        rows: u32,
        _px: u32,
        _py: u32,
        _session: &mut Session,
    ) -> Result<()> {
        if let Some((id, shared)) = &self.peer {
            let _ = shared.input(
                *id,
                ViewerInput::Resize {
                    cols: u16::try_from(cols).unwrap_or(0),
                    rows: u16::try_from(rows).unwrap_or(0),
                },
            );
        }
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<()> {
        session.channel_failure(channel)?;
        Ok(())
    }
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<()> {
        session.channel_failure(channel)?;
        Ok(())
    }
    async fn channel_close(&mut self, _channel: ChannelId, _session: &mut Session) -> Result<()> {
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
        self.peer = None;
        Ok(())
    }
}
