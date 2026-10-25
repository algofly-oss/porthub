//! Gateway fallback prefers the operator's direct API origin, then the secure
//! API origin. Peer payloads remain protected by their authenticated DTLS session.
use super::controller::Event;
use crate::private_profile::Profile;
use anyhow::{ensure, Result};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use porthub_mesh::RELAY_BATCH_MAGIC;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
use tokio_util::sync::CancellationToken;
#[derive(Clone)]
pub struct Sender {
    output: mpsc::Sender<Bytes>,
    ready: Arc<AtomicBool>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub direct_url: Option<String>,
    pub relay_token: Option<String>,
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
fn dispatch_record(frame: Bytes, events: &mpsc::Sender<Event>) {
    if let Some((&length, rest)) = frame.split_first() {
        let length = usize::from(length);
        if length > 0 && length <= 60 && rest.len() >= length + 20 && rest.len() <= length + 1380 {
            if let Ok(peer) = std::str::from_utf8(&rest[..length]) {
                let _ = events.try_send(Event::Packet {
                    peer: peer.into(),
                    bytes: frame.slice(1 + length..),
                    direct: false,
                    received_at: Instant::now(),
                });
            }
        }
    }
}
fn dispatch_frame(frame: Bytes, events: &mpsc::Sender<Event>) {
    if let Some(mut offset) = frame
        .strip_prefix(RELAY_BATCH_MAGIC)
        .map(|_| RELAY_BATCH_MAGIC.len())
    {
        let mut count = 0;
        while offset < frame.len() {
            if count == 32 || frame.len() - offset < 2 {
                return;
            }
            let length = usize::from(u16::from_be_bytes([frame[offset], frame[offset + 1]]));
            offset += 2;
            if length == 0 || length > 1441 || length > frame.len() - offset {
                return;
            }
            dispatch_record(frame.slice(offset..offset + length), events);
            offset += length;
            count += 1;
        }
    } else {
        dispatch_record(frame, events);
    }
}
pub async fn run(
    profile: Profile,
    instance: String,
    sender: Sender,
    mut packets: mpsc::Receiver<Bytes>,
    mut config: watch::Receiver<Option<Config>>,
    events: mpsc::Sender<Event>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut retry = Duration::from_secs(1);
    loop {
        while config.borrow_and_update().is_none() {
            tokio::select! {_=cancel.cancelled()=>return Ok(()),changed=config.changed()=>if changed.is_err(){return Ok(())}}
        }
        let direct = config.borrow_and_update().clone().and_then(|candidate| {
            let (Some(direct_url), Some(relay_token)) =
                (candidate.direct_url, candidate.relay_token)
            else {
                return None;
            };
            let Ok(url) = url::Url::parse(&direct_url) else {
                return None;
            };
            let usable = url.scheme() == "http"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/"
                && (32..=128).contains(&relay_token.len());
            usable.then_some(Config {
                direct_url: Some(direct_url),
                relay_token: Some(relay_token),
            })
        });
        // Prefer the operator-configured direct origin; use the secure API
        // route only when the direct connection fails.
        let mut candidates = Vec::with_capacity(profile.fallback_servers.len() + 2);
        if let Some(candidate) = direct {
            candidates.push((
                candidate.direct_url.unwrap(),
                candidate.relay_token.unwrap(),
            ));
        }
        candidates.push((profile.server.clone(), profile.token.clone()));
        candidates.extend(
            profile
                .fallback_servers
                .iter()
                .cloned()
                .map(|base| (base, profile.token.clone())),
        );
        let mut connected = None;
        for (base, token) in candidates {
            let mut url = url::Url::parse(&base)?;
            let scheme = if url.scheme() == "https" {
                "wss"
            } else if url.scheme() == "http" {
                "ws"
            } else {
                continue;
            };
            url.set_scheme(scheme)
                .map_err(|_| anyhow::anyhow!("invalid private relay authority"))?;
            url.set_path("/api/access/private/relay");
            let mut request = url.as_str().into_client_request()?;
            let headers = request.headers_mut();
            headers.insert("x-porthub-peer", profile.peer_id.parse()?);
            headers.insert("x-porthub-instance", instance.parse()?);
            headers.insert("authorization", format!("Bearer {token}").parse()?);
            headers.insert("x-porthub-relay-batch", "1".parse()?);
            let result = tokio::select! {
                _=cancel.cancelled()=>return Ok(()),
                result=tokio::time::timeout(
                    Duration::from_secs(2),
                    tokio_tungstenite::connect_async_with_config(
                        request,
                        Some(
                            tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                                .read_buffer_size(8192)
                                .write_buffer_size(8192)
                                .max_write_buffer_size(65536)
                                .max_message_size(Some(65536))
                                .max_frame_size(Some(65536)),
                        ),
                        true,
                    ),
                )=>result,
            };
            if let Ok(Ok((socket, response))) = result {
                let batch = response
                    .headers()
                    .get("x-porthub-relay-batch")
                    .is_some_and(|value| value == "1");
                connected = Some((socket, batch));
                break;
            }
        }
        if let Some((mut socket, batch)) = connected {
            sender.ready.store(true, Ordering::Release);
            retry = Duration::from_secs(1);
            let mut heartbeat = tokio::time::interval(Duration::from_secs(25));
            heartbeat.tick().await;
            loop {
                let outgoing = tokio::select! {
                    changed=config.changed()=>{if changed.is_err(){return Ok(())}break;},
                    _=cancel.cancelled()=>{sender.ready.store(false,Ordering::Release);return Ok(())},
                    packet=packets.recv()=>{
                        let Some(packet)=packet else{return Ok(())};
                        if batch {
                            let mut records=vec![packet];
                            while records.len()<32 {match packets.try_recv(){Ok(packet)=>records.push(packet),Err(_)=>break}}
                            let mut output=Vec::with_capacity(4+records.iter().map(|p|2+p.len()).sum::<usize>());
                            output.extend_from_slice(RELAY_BATCH_MAGIC);
                            for record in records {output.extend_from_slice(&(record.len() as u16).to_be_bytes());output.extend_from_slice(&record);}
                            Some(Message::Binary(output.into()))
                        } else {Some(Message::Binary(packet))}
                    },
                    _=heartbeat.tick()=>Some(Message::Ping(Bytes::new())),
                    frame=socket.next()=>match frame {
                        Some(Ok(Message::Binary(frame)))=>{dispatch_frame(frame,&events);None},
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Bytes {
        let mut value = vec![1];
        value.extend_from_slice(b"p");
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        value.extend_from_slice(&packet);
        value.into()
    }

    #[tokio::test]
    async fn dispatch_accepts_legacy_packets_and_batches() {
        let (events, mut received) = mpsc::channel(8);
        let packet = record();
        dispatch_frame(packet.clone(), &events);
        let mut batch = RELAY_BATCH_MAGIC.to_vec();
        for _ in 0..2 {
            batch.extend_from_slice(&(packet.len() as u16).to_be_bytes());
            batch.extend_from_slice(&packet);
        }
        dispatch_frame(batch.into(), &events);
        for _ in 0..3 {
            let Some(Event::Packet {
                peer,
                bytes,
                direct,
                ..
            }) = received.recv().await
            else {
                panic!("private relay packet expected");
            };
            assert_eq!(peer, "p");
            assert_eq!(bytes.len(), 20);
            assert!(!direct);
        }
    }
}
