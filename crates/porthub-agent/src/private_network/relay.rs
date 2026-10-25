//! Gateway fallback prefers the operator's direct API origin, then the secure
//! API origin. This packet fallback authenticates at the gateway; peer-session
//! DTLS is a separate path. Stream payload encryption belongs to the stream layer.
use super::controller::Event;
use crate::private_profile::Profile;
use anyhow::{ensure, Result};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
#[cfg(test)]
use porthub_mesh::RELAY_BATCH_MAGIC;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
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
    dropped_packets: Arc<AtomicU64>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub direct_url: Option<String>,
    pub relay_token: Option<String>,
}
impl Sender {
    #[cfg(feature = "private-stream")]
    pub async fn send_stream(&self, peer: &str, packet: &[u8]) -> Result<()> {
        ensure!(self.is_ready(), "private relay is not ready");
        ensure!(
            !peer.is_empty() && peer.len() <= 60 && (20..=1380).contains(&packet.len()),
            "invalid private relay packet"
        );
        let mut bytes = Vec::with_capacity(1 + peer.len() + packet.len());
        bytes.push(peer.len() as u8);
        bytes.extend_from_slice(peer.as_bytes());
        bytes.extend_from_slice(packet);
        self.output
            .send(bytes.into())
            .await
            .map_err(|_| anyhow::anyhow!("private relay stopped"))
    }
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
        if self.output.try_send(bytes.into()).is_err() {
            self.dropped_packets.fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("private relay queue unavailable");
        }
        Ok(())
    }
    fn take_dropped_packets(&self) -> u64 {
        self.dropped_packets.swap(0, Ordering::Relaxed)
    }
}
pub fn channel() -> (Sender, mpsc::Receiver<Bytes>) {
    // Buffer at most about 2.8 MiB of packets per agent to absorb short relay
    // stalls while keeping memory use bounded.
    let (output, input) = mpsc::channel(2048);
    (
        Sender {
            output,
            ready: Default::default(),
            dropped_packets: Default::default(),
        },
        input,
    )
}
async fn dispatch_record(frame: Bytes, events: &mpsc::Sender<Event>) {
    if let Some((&length, rest)) = frame.split_first() {
        let length = usize::from(length);
        if length > 0 && length <= 60 && rest.len() >= length + 20 && rest.len() <= length + 1380 {
            if let Ok(peer) = std::str::from_utf8(&rest[..length]) {
                let _ = events
                    .send(Event::Packet {
                        peer: peer.into(),
                        bytes: frame.slice(1 + length..),
                        direct: false,
                        received_at: Instant::now(),
                    })
                    .await;
            }
        }
    }
}
async fn dispatch_frame(frame: Bytes, events: &mpsc::Sender<Event>) {
    if let Ok(records) = porthub_mesh::batch::decode(frame) {
        for record in records {
            dispatch_record(record, events).await;
        }
    }
}

async fn outgoing_frame(
    first: Bytes,
    batch: bool,
    prefixes: bool,
    packets: &mut mpsc::Receiver<Bytes>,
) -> Result<Message> {
    if !batch {
        return Ok(Message::Binary(first));
    }
    let mut records = vec![first];
    while records.len() < 32 {
        match packets.try_recv() {
            Ok(packet) => records.push(packet),
            Err(_) => break,
        }
    }
    Ok(Message::Binary(
        porthub_mesh::batch::encode(&records, prefixes)?.into(),
    ))
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
            headers.insert("x-porthub-relay-prefix", "1".parse()?);
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
                match socket.get_ref() {
                    tokio_tungstenite::MaybeTlsStream::Plain(stream) => {
                        porthub_mesh::configure_tcp(stream)
                    }
                    tokio_tungstenite::MaybeTlsStream::Rustls(stream) => {
                        porthub_mesh::configure_tcp(stream.get_ref().0)
                    }
                    _ => {}
                }
                let batch = response
                    .headers()
                    .get("x-porthub-relay-batch")
                    .is_some_and(|value| value == "1");
                let prefixes = batch
                    && response
                        .headers()
                        .get("x-porthub-relay-prefix")
                        .is_some_and(|value| value == "1");
                connected = Some((socket, batch, prefixes));
                break;
            }
        }
        if let Some((socket, batch, prefixes)) = connected {
            tracing::debug!(batch, prefixes, "private relay framing negotiated");
            // Receiving must continue while TCP writes are backpressured:
            // QUIC acknowledgements on this same carrier release send credit.
            let (mut socket, mut incoming) = socket.split();
            let reading = cancel.child_token();
            let read_cancel = reading.clone();
            let read_events = events.clone();
            let (pongs, mut pong_rx) = mpsc::channel(8);
            let reader = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _=read_cancel.cancelled()=>break,
                        frame=incoming.next()=>match frame {
                            Some(Ok(Message::Binary(frame)))=>tokio::select! {_=read_cancel.cancelled()=>break,_=dispatch_frame(frame,&read_events)=>{}},
                            Some(Ok(Message::Ping(bytes)))=>if pongs.try_send(bytes).is_err(){break;},
                            Some(Ok(Message::Pong(_)))=>{},
                            _=>break,
                        }
                    }
                }
                read_cancel.cancel();
            }));
            sender.ready.store(true, Ordering::Release);
            retry = Duration::from_secs(1);
            let mut heartbeat = tokio::time::interval(Duration::from_secs(25));
            heartbeat.tick().await;
            let mut stop = false;
            loop {
                let outgoing = tokio::select! {
                    changed=config.changed()=>{if changed.is_err(){stop=true;}break;},
                    _=cancel.cancelled()=>{stop=true;break;},
                    _=reading.cancelled()=>break,
                    packet=packets.recv()=>{
                        let Some(packet)=packet else{stop=true;break;};
                        Some(outgoing_frame(packet,batch,prefixes,&mut packets).await?)
                    },
                    _=heartbeat.tick()=>{
                        let dropped=sender.take_dropped_packets();
                        if dropped>0 {tracing::warn!(dropped_packets=dropped,"private relay sender queue overflowed");}
                        Some(Message::Ping(Bytes::new()))
                    },
                    Some(bytes)=pong_rx.recv()=>Some(Message::Pong(bytes)),
                };
                if let Some(outgoing) = outgoing {
                    let sent = tokio::select! {_=cancel.cancelled()=>{stop=true;break;},_=reading.cancelled()=>break,result=tokio::time::timeout(Duration::from_secs(5),socket.send(outgoing))=>result};
                    if !matches!(sent, Ok(Ok(()))) {
                        break;
                    }
                }
            }
            reading.cancel();
            reader.abort();
            let _ = reader.await;
            sender.ready.store(false, Ordering::Release);
            while packets.try_recv().is_ok() {}
            if stop {
                return Ok(());
            }
        }
        tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(retry)=>{}}
        retry = (retry * 2).min(Duration::from_secs(15));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn queued_stream_records_batch_without_delaying_control_records() {
        use futures_util::FutureExt;
        let (sender, mut packets) = mpsc::channel(8);
        assert!(outgoing_frame(record(), true, false, &mut packets)
            .now_or_never()
            .is_some());
        let ip = porthub_mesh::control_packet::encode(
            porthub_mesh::control_packet::STREAM,
            "10.200.0.1".parse().unwrap(),
            "10.200.0.2".parse().unwrap(),
            &[7; 1200],
        )
        .unwrap();
        let mut framed = vec![1, b'p'];
        framed.extend_from_slice(&ip);
        let framed = Bytes::from(framed);
        sender.send(framed.clone()).await.unwrap();
        sender.send(framed.clone()).await.unwrap();
        let Message::Binary(output) = outgoing_frame(framed, true, false, &mut packets)
            .await
            .unwrap()
        else {
            panic!("binary relay batch expected");
        };
        let (events, mut received) = mpsc::channel(8);
        dispatch_frame(output, &events).await;
        for _ in 0..3 {
            assert!(matches!(received.try_recv(),Ok(Event::Packet {bytes,..}) if bytes==ip));
        }
        assert!(received.try_recv().is_err());
    }

    #[cfg(feature = "private-stream")]
    #[tokio::test]
    async fn inbound_packets_continue_while_outbound_tcp_is_backpressured() -> Result<()> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.set_recv_buffer_size(4096)?;
        socket.bind("127.0.0.1:0".parse()?)?;
        let listener = socket.listen(16)?;
        let base = format!("http://{}", listener.local_addr()?);
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let gateway = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut wire = tokio_tungstenite::accept_async(stream).await?;
            // Do not read the client's data. Its bounded writer and TCP send
            // buffer fill, while the reverse direction remains usable.
            tokio::time::sleep(Duration::from_secs(1)).await;
            wire.send(Message::Binary(record())).await?;
            stop.cancelled().await;
            Ok::<_, anyhow::Error>(())
        });
        let profile = Profile {
            server: base.clone(),
            peer_id: format!("{}:{}", "1".repeat(24), "2".repeat(24)),
            token: "test-token".repeat(4),
            workspace: "1".repeat(24),
            account_email: None,
            fallback_servers: Vec::new(),
            allow_insecure_http_for_tests: true,
        };
        let (sender, input) = channel();
        let (_updates, config) = watch::channel(Some(Config {
            direct_url: Some(base),
            relay_token: Some("t".repeat(32)),
        }));
        let (events, mut received) = mpsc::channel(8);
        let owner = tokio::spawn(run(
            profile,
            "test-instance".into(),
            sender.clone(),
            input,
            config,
            events,
            cancel.clone(),
        ));
        let result = async {
            tokio::time::timeout(Duration::from_secs(2), async {
                while !sender.is_ready() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await?;
            let sending = sender.clone();
            let fill = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                for _ in 0..20000 {
                    sending.send_stream("p", &[0; 1380]).await?;
                }
                Ok::<_, anyhow::Error>(())
            }));
            let event = tokio::time::timeout(Duration::from_secs(2), received.recv()).await?;
            ensure!(
                matches!(event,Some(Event::Packet {ref peer,..}) if peer=="p"),
                "reverse packet was not delivered"
            );
            ensure!(
                !fill.is_finished(),
                "test failed to maintain outbound pressure"
            );
            fill.abort();
            let _ = fill.await;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), owner).await???;
        tokio::time::timeout(Duration::from_secs(2), gateway).await???;
        ensure!(!sender.is_ready(), "cancelled relay remained ready");
        result
    }

    #[cfg(feature = "private-stream")]
    #[tokio::test]
    async fn reliable_stream_waits_for_capacity_instead_of_dropping_a_burst() {
        let (sender, mut received) = channel();
        sender.ready.store(true, Ordering::Release);
        let packet = record().slice(2..);
        for _ in 0..2048 {
            sender.send("p", &packet).unwrap();
        }
        let mut pending = Box::pin(sender.send_stream("p", &packet));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut pending)
                .await
                .is_err()
        );
        received.recv().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), pending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sender.take_dropped_packets(), 0);
        for _ in 0..2048 {
            assert_eq!(received.recv().await.unwrap(), record());
        }
    }

    #[tokio::test]
    async fn inbound_relay_preserves_packets_when_the_control_queue_is_full() {
        let (events, mut received) = mpsc::channel(1);
        let packet = record();
        dispatch_frame(packet.clone(), &events).await;
        let mut pending = Box::pin(dispatch_frame(packet.clone(), &events));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut pending)
                .await
                .is_err()
        );
        assert!(
            matches!(received.recv().await, Some(Event::Packet { bytes, .. }) if bytes == packet.slice(2..))
        );
        tokio::time::timeout(Duration::from_secs(1), pending)
            .await
            .unwrap();
        assert!(
            matches!(received.recv().await, Some(Event::Packet { bytes, .. }) if bytes == packet.slice(2..))
        );
        assert!(received.try_recv().is_err());
    }

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
        dispatch_frame(packet.clone(), &events).await;
        let mut batch = RELAY_BATCH_MAGIC.to_vec();
        for _ in 0..2 {
            batch.extend_from_slice(&(packet.len() as u16).to_be_bytes());
            batch.extend_from_slice(&packet);
        }
        dispatch_frame(batch.into(), &events).await;
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
