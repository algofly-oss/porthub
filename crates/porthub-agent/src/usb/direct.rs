//! The same authenticated ICE/DTLS engine used by keyboard and terminal modules.
use anyhow::{ensure, Context, Result};
use porthub_terminal::direct::{Event, Peer};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
    task::JoinSet,
};
const CHANNEL: &str = "porthub-usb/1";
pub(super) struct Candidates {
    sockets: Vec<Arc<UdpSocket>>,
    addresses: Vec<SocketAddr>,
}
impl Candidates {
    pub async fn gather(control: Option<&crate::control::Control>) -> Result<Self> {
        let mut ips = Vec::new();
        for interface in getifaddrs::getifaddrs()? {
            if !interface.flags.contains(getifaddrs::InterfaceFlags::UP)
                || ["docker", "br-", "veth", "virbr", "cni", "flannel"]
                    .iter()
                    .any(|prefix| interface.name.starts_with(prefix))
            {
                continue;
            }

            if let Some(IpAddr::V4(ip)) = interface.address.ip_addr() {
                if control
                    .is_some_and(|c| !c.direct_interface_allowed(&interface.name, IpAddr::V4(ip)))
                {
                    continue;
                }

                if (ip.is_private()
                    || ip.is_loopback()
                    || ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
                    && !ips.contains(&ip)
                {
                    ips.push(ip)
                }
            }
            if ips.len() >= 16 {
                break;
            }
        }
        let mut sockets = Vec::new();
        let mut addresses = Vec::new();
        for ip in ips {
            if let Ok(socket) = UdpSocket::bind((ip, 0)).await {
                addresses.push(socket.local_addr()?);
                sockets.push(Arc::new(socket));
            }
        }
        ensure!(!sockets.is_empty(), "No direct USB candidates");
        Ok(Self { sockets, addresses })
    }
    pub fn offer(&self) -> Result<(Peer, String)> {
        Peer::offer_named(Instant::now(), &self.addresses, &[], CHANNEL)
    }
    pub fn answer(&self, offer: &str) -> Result<(Peer, String)> {
        Peer::answer_named(Instant::now(), offer, &self.addresses, &[], CHANNEL)
    }
    pub fn run(self, mut peer: Peer) -> Direct {
        let (send, mut outgoing) = mpsc::channel::<Vec<u8>>(8);
        let (tx, incoming) = mpsc::channel::<Vec<u8>>(8);
        let (ready, connected) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut readers = JoinSet::new();
            let (packets, mut received) = mpsc::channel(128);
            for socket in &self.sockets {
                let socket = socket.clone();
                let packets = packets.clone();
                readers.spawn(async move {
                    let mut bytes = vec![0; 65536];
                    loop {
                        let (n, remote) = match socket.recv_from(&mut bytes).await {
                            Ok(packet) => packet,
                            Err(_) => {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                                continue;
                            }
                        };
                        if packets
                            .send((socket.local_addr()?, remote, bytes[..n].to_vec()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok::<_, std::io::Error>(())
                });
            }
            drop(packets);
            let mut ready = Some(ready);
            let mut pending: Option<Vec<u8>> = None;
            let mut tick = tokio::time::interval(Duration::from_millis(5));
            let result=async{loop{
    while let Some(event)=peer.event()?{match event{Event::Ready=>{if let Some(ready)=ready.take(){let _=ready.send(());}},Event::Closed=>anyhow::bail!("Direct USB connection closed")}}
    while let Some(bytes)=peer.read()?{tx.send(bytes).await.context("USB consumer stopped")?;}
    if let Some(bytes)=pending.as_ref(){if ready.is_none()&&peer.can_send(bytes.len())?{peer.send(Instant::now(),bytes)?;pending=None;}}
    while let Some((local,remote,bytes))=peer.datagram_from(){if let Some(socket)=self.sockets.iter().find(|s|s.local_addr().ok()==Some(local)){if local.ip().is_loopback()!=remote.ip().is_loopback(){continue;}
      if let Err(error)=socket.send_to(&bytes,remote).await{tracing::trace!(%local,%remote,%error,"USB ICE candidate unavailable");}}}
    tokio::select!{
     bytes=outgoing.recv(),if pending.is_none()=>{pending=Some(bytes.context("USB sender stopped")?);},
     packet=received.recv()=>{let(local,remote,bytes)=packet.context("Direct sockets stopped")?;peer.receive(Instant::now(),local,remote,&bytes)?;},
     _=tick.tick()=>{if peer.deadline().is_some_and(|d|d<=Instant::now()){peer.timeout(Instant::now())?;}}
    }
   }#[allow(unreachable_code)]Ok::<_,anyhow::Error>(())}.await;
            readers.abort_all();
            let _ = peer.close();
            result
        });
        Direct {
            send,
            incoming,
            connected: Some(connected),
            task,
        }
    }
}
pub(super) struct Direct {
    pub send: mpsc::Sender<Vec<u8>>,
    pub incoming: mpsc::Receiver<Vec<u8>>,
    pub connected: Option<oneshot::Receiver<()>>,
    task: tokio::task::JoinHandle<Result<()>>,
}
impl Direct {
    pub async fn stopped(&mut self) -> Result<()> {
        (&mut self.task).await?
    }
}
impl Drop for Direct {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn authenticated_direct_usb_stream_is_ordered_and_backpressured() -> Result<()> {
        let a = Candidates::gather(None).await?;
        let b = Candidates::gather(None).await?;
        let (mut ap, offer) = a.offer()?;
        let (bp, answer) = b.answer(&offer)?;
        ap.accept_answer(Instant::now(), &answer)?;
        let mut a = a.run(ap);
        let mut b = b.run(bp);
        tokio::time::timeout(Duration::from_secs(8), async {
            a.connected.take().unwrap().await?;
            b.connected.take().unwrap().await?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        let tx = a.send.clone();
        let chunks = 128;
        let started = Instant::now();
        let sending = tokio::spawn(async move {
            for i in 0..chunks {
                tx.send(vec![(i % 251) as u8; 16384]).await?;
            }
            Ok::<_, anyhow::Error>(())
        });
        tokio::time::timeout(Duration::from_secs(15), async {
            for i in 0..chunks {
                let bytes = b.incoming.recv().await.context("Direct transport closed")?;
                ensure!(
                    bytes == vec![(i % 251) as u8; 16384],
                    "USB stream bytes changed order"
                );
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        sending.await??;
        b.send.send(b"reverse".to_vec()).await?;
        ensure!(
            tokio::time::timeout(Duration::from_secs(3), a.incoming.recv()).await?
                == Some(b"reverse".to_vec())
        );
        eprintln!(
            "Native direct USB transport: {} MiB in {:.3}s",
            chunks * 16384 / 1048576,
            started.elapsed().as_secs_f64()
        );
        Ok(())
    }
}
