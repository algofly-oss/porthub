//! LAN discovery through ICE host candidates. The portal stays on its public URL;
//! DTLS authenticates the peer against signaling on the existing gateway.
use anyhow::{ensure, Result};
use porthub_components::keyboard::CHANNEL;
use porthub_terminal::direct::{Event, Peer};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinSet};
pub struct Direct {
    peer: Peer,
    sockets: Vec<Arc<UdpSocket>>,
    incoming: mpsc::Receiver<(SocketAddr, SocketAddr, Vec<u8>)>,
    readers: JoinSet<()>,
    ready: bool,
}
impl Drop for Direct {
    fn drop(&mut self) {
        self.readers.abort_all();
        let _ = self.peer.close();
    }
}
impl Direct {
    pub async fn answer(offer: &str) -> Result<(Self, String)> {
        let mut ips = Vec::new();
        for interface in getifaddrs::getifaddrs()? {
            let Some(IpAddr::V4(ip)) = interface.address.ip_addr() else {
                continue;
            };
            // No network scanning, external discovery server, or public candidate.
            if (ip.is_private() || ip.is_loopback()) && !ips.contains(&ip) {
                ips.push(ip);
            }
            if ips.len() == 8 {
                break;
            }
        }
        let mut sockets = Vec::new();
        let mut candidates = Vec::new();
        for ip in ips {
            if let Ok(socket) = UdpSocket::bind((ip, 0)).await {
                candidates.push(socket.local_addr()?);
                sockets.push(Arc::new(socket));
            }
        }
        ensure!(!sockets.is_empty(), "No local network candidates");
        let (peer, answer) = Peer::answer_named(Instant::now(), offer, &candidates, &[], CHANNEL)?;
        let (tx, incoming) = mpsc::channel(64);
        let mut readers = JoinSet::new();
        for socket in &sockets {
            let socket = socket.clone();
            let tx = tx.clone();
            readers.spawn(async move {
                let mut bytes = vec![0; 65536];
                while let Ok((n, remote)) = socket.recv_from(&mut bytes).await {
                    let Ok(local) = socket.local_addr() else {
                        break;
                    };
                    if tx.send((local, remote, bytes[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            });
        }
        Ok((
            Self {
                peer,
                sockets,
                incoming,
                readers,
                ready: false,
            },
            answer,
        ))
    }
    async fn flush(&mut self) -> Result<()> {
        while let Some((local, remote, bytes)) = self.peer.datagram_from() {
            if let Some(socket) = self
                .sockets
                .iter()
                .find(|s| s.local_addr().ok() == Some(local))
            {
                socket.send_to(&bytes, remote).await?;
            }
        }
        Ok(())
    }
    pub async fn next(&mut self) -> Result<Vec<u8>> {
        loop {
            while let Some(event) = self.peer.event()? {
                match event {
                    Event::Ready => self.ready = true,
                    Event::Closed => anyhow::bail!("Local connection closed"),
                }
            }
            if let Some(bytes) = self.peer.read()? {
                return Ok(bytes);
            }
            self.flush().await?;
            let deadline = self
                .peer
                .deadline()
                .unwrap_or_else(|| Instant::now() + std::time::Duration::from_secs(30));
            tokio::select! {
                packet=self.incoming.recv()=>{let(local,remote,bytes)=packet.ok_or_else(||anyhow::anyhow!("Local connection stopped"))?;self.peer.receive(Instant::now(),local,remote,&bytes)?;}
                _=tokio::time::sleep_until(deadline.into())=>self.peer.timeout(Instant::now())?
            }
        }
    }
    pub async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        // Relay input can arrive while ICE/DTLS is negotiating. Its ACK uses
        // the relay until the data channel opens; do not tear down discovery.
        if !self.ready {
            return Ok(());
        }
        self.peer.send(Instant::now(), bytes)?;
        self.flush().await
    }
}
