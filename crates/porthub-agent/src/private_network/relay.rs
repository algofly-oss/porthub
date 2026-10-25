//! Gateway fallback uses the existing API TLS connection and a bounded queue.
//! Direct peer packets never enter this owner. No probing occurs per flow.
use super::controller::Event;
use crate::private_profile::Profile;
use anyhow::{ensure, Result};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
use tokio_util::sync::CancellationToken;
#[derive(Clone)]
pub struct Sender {
    output: mpsc::Sender<Bytes>,
    ready: Arc<AtomicBool>,
}
impl Sender {
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
    pub fn send(&self, peer: &str, packet: &[u8]) -> Result<()> {
        ensure!(
            self.ready.load(Ordering::Acquire),
            "private relay is not ready"
        );
        ensure!(
            !peer.is_empty() && peer.len() <= 60 && (20..=1380).contains(&packet.len()),
            "invalid private relay packet"
        );
        let mut bytes = Vec::with_capacity(1 + peer.len() + packet.len());
        bytes.push(peer.len() as u8);
        bytes.extend_from_slice(peer.as_bytes());
        bytes.extend_from_slice(packet);
        self.output
            .try_send(bytes.into())
            .map_err(|_| anyhow::anyhow!("private relay queue unavailable"))
    }
}
pub fn channel() -> (Sender, mpsc::Receiver<Bytes>) {
    let (output, input) = mpsc::channel(128);
    (
        Sender {
            output,
            ready: Default::default(),
        },
        input,
    )
}
pub async fn run(
    profile: Profile,
    instance: String,
    sender: Sender,
    mut packets: mpsc::Receiver<Bytes>,
    events: mpsc::Sender<Event>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut bases = vec![profile.server.clone()];
    bases.extend(profile.fallback_servers.clone());
    let mut base_index = 0;
    let mut retry = Duration::from_secs(1);
    loop {
        let base = &bases[base_index];
        base_index = (base_index + 1) % bases.len();
        let mut url = url::Url::parse(base)?;
        let scheme = if url.scheme() == "https" {
            "wss"
        } else {
            ensure!(
                profile.allow_insecure_http_for_tests,
                "private relay requires TLS"
            );
            "ws"
        };
        url.set_scheme(scheme)
            .map_err(|_| anyhow::anyhow!("invalid private relay authority"))?;
        url.set_path("/api/access/private/relay");
        let mut request = url.as_str().into_client_request()?;
        let headers = request.headers_mut();
        headers.insert("x-porthub-peer", profile.peer_id.parse()?);
        headers.insert("x-porthub-instance", instance.parse()?);
        headers.insert(
            "authorization",
            format!("Bearer {}", profile.token).parse()?,
        );
        let connection = tokio::select! {_=cancel.cancelled()=>return Ok(()),result=tokio::time::timeout(Duration::from_secs(4),tokio_tungstenite::connect_async_with_config(request,Some(tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default().read_buffer_size(8192).write_buffer_size(8192).max_write_buffer_size(32768).max_message_size(Some(1500)).max_frame_size(Some(1500))),true))=>result};
        if let Ok(Ok((mut socket, _))) = connection {
            sender.ready.store(true, Ordering::Release);
            retry = Duration::from_secs(1);
            let mut heartbeat = tokio::time::interval(Duration::from_secs(25));
            heartbeat.tick().await;
            loop {
                let outgoing = tokio::select! {
                    _=cancel.cancelled()=>{sender.ready.store(false,Ordering::Release);return Ok(())},
                    packet=packets.recv()=>{let Some(packet)=packet else{return Ok(())};Some(Message::Binary(packet))},
                    _=heartbeat.tick()=>Some(Message::Ping(Bytes::new())),
                    frame=socket.next()=>match frame {
                        Some(Ok(Message::Binary(frame)))=>{
                            if let Some((&length,rest))=frame.split_first() {
                                let length=usize::from(length);
                                if length>0 && length<=60 && rest.len()>=length+20 && rest.len()<=length+1380 {
                                    if let Ok(peer)=std::str::from_utf8(&rest[..length]) {let _=events.try_send(Event::Packet{peer:peer.into(),bytes:frame.slice(1+length..),direct:false,received_at:Instant::now()});}
                                }
                            }None
                        },
                        Some(Ok(Message::Ping(bytes)))=>Some(Message::Pong(bytes)),
                        Some(Ok(Message::Pong(_)))=>None,
                        _=>break,
                    }
                };
                if let Some(outgoing) = outgoing {
                    let sent = tokio::select! {_=cancel.cancelled()=>{sender.ready.store(false,Ordering::Release);return Ok(())},result=tokio::time::timeout(Duration::from_secs(5),socket.send(outgoing))=>result};
                    if !matches!(sent, Ok(Ok(()))) {
                        break;
                    }
                }
            }
            sender.ready.store(false, Ordering::Release);
            while packets.try_recv().is_ok() {}
        }
        tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(retry)=>{}}
        retry = (retry * 2).min(Duration::from_secs(15));
    }
}
