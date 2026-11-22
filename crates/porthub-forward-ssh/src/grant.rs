//! An SSH credential represents one saved set of TCP mappings. Client-supplied
//! destinations are only lookup keys; they are never dialled by the gateway.
use anyhow::{ensure, Result};
use russh::server::{self, ChannelOpenHandle, Msg, Session};
use russh::Channel;
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    sync::{mpsc, oneshot, Semaphore},
};
use tokio_util::sync::CancellationToken;

pub struct Dial {
    // The broker binds this opaque key to a registered machine and service.
    pub service: String,
    pub stream: oneshot::Sender<DuplexStream>,
}

pub struct Grant {
    local: HashMap<(String, u16), String>,
    remote: HashSet<u16>,
    sessions: AtomicUsize,
    channels: Arc<Semaphore>,
    jobs: mpsc::Sender<Dial>,
    open: Mutex<HashMap<u16, server::Handle>>,
    pub cancel: CancellationToken,
}

impl Grant {
    pub fn new(
        local: HashMap<(String, u16), String>,
        remote: HashSet<u16>,
        jobs: mpsc::Sender<Dial>,
    ) -> Result<Arc<Self>> {
        ensure!(
            (1..=32).contains(&(local.len() + remote.len()))
                && !remote.contains(&0)
                && local
                    .keys()
                    .all(|(host, port)| !host.is_empty() && *port != 0),
            "Invalid forwarding mappings"
        );
        Ok(Arc::new(Self {
            local,
            remote,
            jobs,
            sessions: AtomicUsize::new(0),
            channels: Arc::new(Semaphore::new(32)),
            open: Mutex::new(HashMap::new()),
            cancel: CancellationToken::new(),
        }))
    }

    pub fn has_session(&self) -> bool {
        !self.cancel.is_cancelled() && self.sessions.load(Ordering::Relaxed) > 0
    }

    pub fn is_listening(&self, port: u16) -> bool {
        !self.cancel.is_cancelled() && self.open.lock().unwrap().contains_key(&port)
    }

    /// Caller supplies an already-authorized private or explicitly public stream.
    pub async fn forward<S>(&self, port: u16, socket: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.bridge(port, None, socket).await
    }

    /// The SSH client provides a reverse dynamic listener. Only the destination
    /// port comes from the caller; the address always names the exporter itself.
    pub async fn forward_host<S>(
        &self,
        gateway_port: u16,
        destination_port: u16,
        socket: S,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        ensure!(destination_port != 0, "Invalid destination port");
        self.bridge(gateway_port, Some(destination_port), socket)
            .await
    }

    async fn bridge<S>(&self, port: u16, destination: Option<u16>, mut socket: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let _permit = self.channels.clone().try_acquire_owned()?;
        let handle = self
            .open
            .lock()
            .unwrap()
            .get(&port)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Exporter offline"))?;
        let request =
            handle.channel_open_forwarded_tcpip("127.0.0.1", u32::from(port), "127.0.0.1", 0);
        let channel = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => return Ok(()),
            result = tokio::time::timeout(Duration::from_secs(8), request) => result??,
        };
        let mut ssh = channel.into_stream();
        if let Some(destination) = destination {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => return Ok(()),
                result = tokio::time::timeout(Duration::from_secs(8), connect_loopback(&mut ssh, destination)) => result??,
            }
        }
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => {},
            result = tokio::io::copy_bidirectional(&mut ssh, &mut socket) => { result?; }
        }
        Ok(())
    }
}

// RFC 1928 no-auth CONNECT with a numeric IPv4 loopback address. OpenSSH's
// reverse dynamic forward returns an IPv4 bind address.
async fn connect_loopback(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    port: u16,
) -> Result<()> {
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0; 2];
    stream.read_exact(&mut method).await?;
    ensure!(method == [5, 0], "SSH client declined SOCKS negotiation");
    let [hi, lo] = port.to_be_bytes();
    stream
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, hi, lo])
        .await?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await?;
    ensure!(
        reply[..3] == [5, 0, 0],
        "SSH client could not reach the local service"
    );
    let len = match reply[3] {
        1 => 4,
        4 => 16,
        3 => usize::from(stream.read_u8().await?),
        _ => anyhow::bail!("Invalid SOCKS bind address"),
    };
    let mut address = [0; 257];
    stream.read_exact(&mut address[..len + 2]).await?;
    Ok(())
}

pub struct ForwardSession {
    grant: Arc<Grant>,
    registered: HashSet<u16>,
    work: tokio::task::JoinSet<()>,
}
impl ForwardSession {
    pub fn new(grant: Arc<Grant>) -> Self {
        grant.sessions.fetch_add(1, Ordering::Relaxed);
        Self {
            grant,
            registered: Default::default(),
            work: Default::default(),
        }
    }
    pub async fn direct(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        number: u32,
        reply: ChannelOpenHandle,
    ) {
        while self.work.try_join_next().is_some() {}
        let Some(service) = u16::try_from(number)
            .ok()
            .and_then(|p| self.grant.local.get(&(host.to_owned(), p)))
            .cloned()
        else {
            return;
        };
        let Ok(permit) = self.grant.channels.clone().try_acquire_owned() else {
            return;
        };
        if self.grant.cancel.is_cancelled() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        if self
            .grant
            .jobs
            .try_send(Dial {
                service,
                stream: tx,
            })
            .is_err()
        {
            return;
        }
        let stop = self.grant.cancel.clone();
        self.work.spawn(async move {
            let _permit = permit;
            let mut stream = tokio::select! {
                biased;
                _ = stop.cancelled() => return,
                result = tokio::time::timeout(Duration::from_secs(8), rx) => {
                    let Ok(Ok(stream)) = result else { return; };
                    stream
                }
            };
            reply.accept().await;
            let mut wire = channel.into_stream();
            tokio::select! {
                biased;
                _ = stop.cancelled() => {},
                _ = tokio::io::copy_bidirectional(&mut wire, &mut stream) => {},
            }
        });
    }
    pub fn listen(&mut self, address: &str, number: u32, session: &Session) -> bool {
        let Ok(port) = u16::try_from(number) else {
            return false;
        };
        if address != "127.0.0.1"
            || !self.grant.remote.contains(&port)
            || self.grant.cancel.is_cancelled()
        {
            return false;
        }
        let mut active = self.grant.open.lock().unwrap();
        if active.contains_key(&port) {
            return false;
        }
        active.insert(port, session.handle());
        self.registered.insert(port);
        true
    }
    pub fn unlisten(&mut self, address: &str, number: u32) -> bool {
        let Ok(port) = u16::try_from(number) else {
            return false;
        };
        if address != "127.0.0.1" || !self.registered.remove(&port) {
            return false;
        }
        self.grant.open.lock().unwrap().remove(&port);
        true
    }
}
impl Drop for ForwardSession {
    fn drop(&mut self) {
        self.grant.sessions.fetch_sub(1, Ordering::Relaxed);
        let mut active = self.grant.open.lock().unwrap();
        for port in self.registered.drain() {
            active.remove(&port);
        }
    }
}

#[cfg(test)]
mod presence_tests {
    use super::*;

    #[test]
    fn presence_tracks_sessions_even_when_another_owner_retains_the_grant() {
        let (jobs, _) = mpsc::channel(1);
        let grant = Grant::new(HashMap::new(), HashSet::from([24000]), jobs).unwrap();
        assert!(!grant.has_session());
        let first = ForwardSession::new(grant.clone());
        let second = ForwardSession::new(grant.clone());
        assert!(grant.has_session());
        drop(first);
        assert!(grant.has_session());
        drop(second);
        assert!(!grant.has_session());
    }
}
