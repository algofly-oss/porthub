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
    hash::{Hash, Hasher},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
use tokio_util::sync::CancellationToken;
const RELAY_LANES: usize = 4;
const RELAY_QUEUE_PACKETS: usize = 2048;
#[derive(Clone)]
pub struct Sender {
    output: Arc<[mpsc::Sender<Bytes>; RELAY_LANES]>,
    ready: Arc<[AtomicBool; RELAY_LANES]>,
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
        let bytes = Bytes::from(bytes);
        let lane = self.packet_lane(peer, packet)?;
        self.output[lane]
            .send(bytes)
            .await
            .map_err(|_| anyhow::anyhow!("private relay stopped"))
    }
    fn packet_lane(&self, peer: &str, packet: &[u8]) -> Result<usize> {
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        peer.hash(&mut hash);
        // All short-header packets on one QUIC connection use the same
        // destination CID. Keep them on one carrier to avoid artificial loss
        // from TCP lanes delivering those packets in different orders.
        if packet.len() >= 29 && packet[9] == porthub_mesh::control_packet::STREAM {
            let payload = &packet[20..];
            if payload[0] & 0x80 == 0 {
                payload[1..9].hash(&mut hash);
            } else if payload.len() >= 6 {
                let length = usize::from(payload[5]);
                if let Some(cid) = payload.get(6..6 + length) {
                    cid.hash(&mut hash);
                }
            }
        } else if packet.len() >= 40 && packet[9] == porthub_mesh::control_packet::EXIT {
            // Hash the inner flow so parallel exit connections can use separate
            // carriers without reordering packets within a connection.
            let inner = &packet[20..];
            inner[9].hash(&mut hash);
            inner[12..20].hash(&mut hash);
            let header = usize::from(inner[0] & 15) * 4;
            if matches!(inner[9], 6 | 17) && header >= 20 {
                if let Some(ports) = inner.get(header..header + 4) { ports.hash(&mut hash); }
            }
        } else if packet.len() >= 20 {
            packet[9].hash(&mut hash);
            packet[12..20].hash(&mut hash);
            if matches!(packet[9], 6 | 17) && packet.len() >= 24 {
                packet[20..24].hash(&mut hash);
            }
        }
        let start = hash.finish() as usize % RELAY_LANES;
        for offset in 0..RELAY_LANES {
            let lane = (start + offset) % RELAY_LANES;
            if self.ready[lane].load(Ordering::Acquire) {
                return Ok(lane);
            }
        }
        anyhow::bail!("private relay is not ready")
    }

    pub fn is_ready(&self) -> bool {
        self.ready.iter().any(|lane| lane.load(Ordering::Acquire))
    }
    fn set_ready(&self, lane: usize, ready: bool) {
        if let Some(state) = self.ready.get(lane) {
            state.store(ready, Ordering::Release);
        }
    }
    pub fn send(&self, peer: &str, packet: &[u8]) -> Result<()> {
        ensure!(self.is_ready(), "private relay is not ready");
        ensure!(
            !peer.is_empty() && peer.len() <= 60 && (20..=1380).contains(&packet.len()),
            "invalid private relay packet"
        );
        let mut bytes = Vec::with_capacity(1 + peer.len() + packet.len());
        bytes.push(peer.len() as u8);
        bytes.extend_from_slice(peer.as_bytes());
        bytes.extend_from_slice(packet);
        let bytes = Bytes::from(bytes);
        let lane = self.packet_lane(peer, packet)?;
        if self.output[lane].try_send(bytes).is_ok() {
            return Ok(());
        }
        self.dropped_packets.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("private relay queue unavailable")
    }

    fn take_dropped_packets(&self) -> u64 {
        self.dropped_packets.swap(0, Ordering::Relaxed)
    }
}
pub fn channel() -> (Sender, [mpsc::Receiver<Bytes>; RELAY_LANES]) {
    // Keep the combined relay queue budget unchanged while spreading traffic
    // over independent TCP congestion windows.
    let mut outputs = Vec::with_capacity(RELAY_LANES);
    let mut inputs = Vec::with_capacity(RELAY_LANES);
    for _ in 0..RELAY_LANES {
        let (output, input) = mpsc::channel(RELAY_QUEUE_PACKETS / RELAY_LANES);
        outputs.push(output);
        inputs.push(input);
    }
    let output: [mpsc::Sender<Bytes>; RELAY_LANES] = outputs
        .try_into()
        .unwrap_or_else(|_| unreachable!("relay lane count is fixed"));
    let input: [mpsc::Receiver<Bytes>; RELAY_LANES] = inputs
        .try_into()
        .unwrap_or_else(|_| unreachable!("relay lane count is fixed"));
    (
        Sender {
            output: Arc::new(output),
            ready: Arc::new(std::array::from_fn(|_| AtomicBool::new(false))),
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
    packets: [mpsc::Receiver<Bytes>; RELAY_LANES],
    config: watch::Receiver<Option<Config>>,
    events: mpsc::Sender<Event>,
    cancel: CancellationToken,
) -> Result<()> {
    let (_source, interfaces) = watch::channel(Vec::new());
    run_bound(profile, instance, sender, packets, config, interfaces, events, cancel).await
}

pub async fn run_bound(
    profile: Profile,
    instance: String,
    sender: Sender,
    mut packets: [mpsc::Receiver<Bytes>; RELAY_LANES],
    mut config: watch::Receiver<Option<Config>>,
    interfaces: watch::Receiver<Vec<std::net::SocketAddr>>,
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
            let usable = matches!(url.scheme(), "http" | "https")
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
        let local: Vec<_> = interfaces.borrow().iter().map(|address| address.ip()).collect();
        let mut primary = None;
        for (base, token) in candidates {
            if let Some(connection) = connect_lane(
                &base,
                &token,
                &profile.peer_id,
                &instance,
                0,
                RELAY_LANES as u8,
                &local,
                &cancel,
            )
            .await?
            {
                let lane_count = connection.lane_count;
                primary = Some((base, token, connection, lane_count));
                break;
            }
        }
        if let Some((base, token, first, lane_count)) = primary {
            let mut connections = vec![first];
            for lane in 1..usize::from(lane_count) {
                let Some(connection) = connect_lane(
                    &base,
                    &token,
                    &profile.peer_id,
                    &instance,
                    lane as u8,
                    lane_count,
                    &local,
                    &cancel,
                )
                .await?
                else {
                    break;
                };
                connections.push(connection);
            }
            tracing::debug!(lanes = connections.len(), "private relay lanes connected");
            retry = Duration::from_secs(1);
            let stop = serve_lanes(
                connections,
                &mut packets,
                &sender,
                &mut config,
                &events,
                &cancel,
            )
            .await?;
            for lane in 0..RELAY_LANES {
                sender.set_ready(lane, false);
            }
            if stop {
                return Ok(());
            }
        }
        tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(retry)=>{}}
        retry = (retry * 2).min(Duration::from_secs(15));
    }
}

type RelaySocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type RelaySink = futures_util::stream::SplitSink<RelaySocket, Message>;

struct ConnectedLane {
    lane: usize,
    socket: RelaySocket,
    batch: bool,
    prefixes: bool,
    lane_count: u8,
}

async fn connect_lane(
    base: &str,
    token: &str,
    peer: &str,
    instance: &str,
    lane: u8,
    requested_lanes: u8,
    local: &[std::net::IpAddr],
    cancel: &CancellationToken,
) -> Result<Option<ConnectedLane>> {
    let Ok(mut url) = url::Url::parse(base) else { return Ok(None); };
    let scheme = if url.scheme() == "https" {
        "wss"
    } else if url.scheme() == "http" {
        "ws"
    } else {
        return Ok(None);
    };
    url.set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("invalid private relay authority"))?;
    url.set_path("/api/access/private/relay");
    let mut request = url.as_str().into_client_request()?;
    let headers = request.headers_mut();
    headers.insert("x-porthub-peer", peer.parse()?);
    headers.insert("x-porthub-instance", instance.parse()?);
    headers.insert("authorization", format!("Bearer {token}").parse()?);
    headers.insert("x-porthub-relay-batch", "1".parse()?);
    headers.insert("x-porthub-relay-prefix", "1".parse()?);
    headers.insert("x-porthub-relay-lane", lane.to_string().parse()?);
    headers.insert(
        "x-porthub-relay-lanes",
        requested_lanes.to_string().parse()?,
    );
    let result = tokio::select! {
        _=cancel.cancelled()=>return Ok(None),
        result=tokio::time::timeout(
            Duration::from_secs(2),
            async {
                let stream = porthub_mesh::underlay::connect(&url, local).await?;
                porthub_mesh::configure_tcp(&stream);
                Ok::<_,anyhow::Error>(tokio_tungstenite::client_async_tls_with_config(
                request,
                stream,
                Some(
                    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                        .read_buffer_size(8192)
                        .write_buffer_size(8192)
                        .max_write_buffer_size(65536)
                        .max_message_size(Some(65536))
                        .max_frame_size(Some(65536)),
                ),
                None,
            ).await?)
            },
        )=>result,
    };
    let Ok(Ok((socket, response))) = result else {
        return Ok(None);
    };
    match socket.get_ref() {
        tokio_tungstenite::MaybeTlsStream::Plain(stream) => porthub_mesh::configure_tcp(stream),
        tokio_tungstenite::MaybeTlsStream::Rustls(stream) => {
            porthub_mesh::configure_tcp(stream.get_ref().0)
        }
        _ => {}
    }
    let lane_count = response
        .headers()
        .get("x-porthub-relay-lanes")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u8>().ok())
        .filter(|value| (1..=RELAY_LANES as u8).contains(value))
        .unwrap_or(1);
    if lane >= lane_count || lane_count < requested_lanes && lane > 0 {
        return Ok(None);
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
    Ok(Some(ConnectedLane {
        lane: usize::from(lane),
        socket,
        batch,
        prefixes,
        lane_count,
    }))
}

async fn serve_lanes(
    connections: Vec<ConnectedLane>,
    packets: &mut [mpsc::Receiver<Bytes>; RELAY_LANES],
    sender: &Sender,
    config: &mut watch::Receiver<Option<Config>>,
    events: &mpsc::Sender<Event>,
    cancel: &CancellationToken,
) -> Result<bool> {
    let reading = cancel.child_token();
    let mut readers = tokio::task::JoinSet::new();
    let mut writers = futures_util::stream::FuturesUnordered::new();
    for (connection, input) in connections.into_iter().zip(packets.iter_mut()) {
        let lane = connection.lane;
        let (writer, mut incoming) = connection.socket.split();
        let (pongs, pong_rx) = mpsc::channel::<Bytes>(4);
        sender.set_ready(lane, true);
        let read_events = events.clone();
        let read_cancel = reading.clone();
        readers.spawn(async move {
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
        });
        // Each socket has its own writer. A full TCP send buffer on one lane
        // must not prevent the other lanes from making progress.
        writers.push(write_lane(
            writer,
            input,
            pong_rx,
            connection.batch,
            connection.prefixes,
        ));
    }
    let mut heartbeat = tokio::time::interval(Duration::from_secs(25));
    heartbeat.tick().await;
    let stop = loop {
        tokio::select! {
            changed=config.changed()=>break changed.is_err(),
            _=cancel.cancelled()=>break true,
            _=readers.join_next()=>break false,
            _=writers.next()=>break false,
            _=heartbeat.tick()=>{
                let dropped = sender.take_dropped_packets();
                if dropped > 0 {
                    tracing::warn!(dropped_packets=dropped, "private relay sender queue overflowed");
                }
            },
        }
    };
    drop(writers);
    reading.cancel();
    readers.abort_all();
    while readers.join_next().await.is_some() {}
    for (lane, input) in packets.iter_mut().enumerate() {
        sender.set_ready(lane, false);
        while input.try_recv().is_ok() {}
    }
    Ok(stop)
}

async fn write_lane(
    mut socket: RelaySink,
    packets: &mut mpsc::Receiver<Bytes>,
    mut pongs: mpsc::Receiver<Bytes>,
    batch: bool,
    prefixes: bool,
) -> Result<()> {
    let mut heartbeat = tokio::time::interval(Duration::from_secs(25));
    heartbeat.tick().await;
    loop {
        let message = tokio::select! {
            packet=packets.recv()=>{
                let Some(packet)=packet else {return Ok(());};
                outgoing_frame(packet,batch,prefixes,packets).await?
            },
            pong=pongs.recv()=>{
                let Some(pong)=pong else {return Ok(());};
                Message::Pong(pong)
            },
            _=heartbeat.tick()=>Message::Ping(Bytes::new()),
        };
        tokio::time::timeout(Duration::from_secs(5), socket.send(message)).await??;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_flows_keep_carrier_affinity_and_distribute_parallel_connections() {
        let (sender, _inputs) = channel();
        for lane in 0..RELAY_LANES { sender.set_ready(lane, true); }
        let mut packet = vec![0u8; 100];
        packet[9] = porthub_mesh::control_packet::EXIT;
        packet[20] = 0x45; packet[29] = 6;
        packet[32..36].copy_from_slice(&[10,203,0,1]);
        packet[36..40].copy_from_slice(&[8,8,8,8]);
        packet[42..44].copy_from_slice(&443u16.to_be_bytes());
        let mut lanes = std::collections::HashSet::new();
        for port in 40000..40100u16 {
            packet[40..42].copy_from_slice(&port.to_be_bytes());
            let lane = sender.packet_lane("exit", &packet).unwrap();
            lanes.insert(lane);
            for value in [0, 1, 255] {
                packet[44..].fill(value);
                assert_eq!(sender.packet_lane("exit", &packet).unwrap(), lane);
            }
        }
        assert!(lanes.len() > 1);
    }

    #[test]
    fn stream_packets_keep_carrier_affinity_when_payload_changes() {
        let (sender, _inputs) = channel();
        for lane in 0..RELAY_LANES {
            sender.set_ready(lane, true);
        }
        let mut packet = vec![0u8; 100];
        packet[9] = porthub_mesh::control_packet::STREAM;
        packet[20] = 0x40;
        packet[21..29].copy_from_slice(b"test-cid");
        let lane = sender.packet_lane("peer", &packet).unwrap();
        for value in 0..=255u8 {
            packet[29..].fill(value);
            assert_eq!(sender.packet_lane("peer", &packet).unwrap(), lane);
        }
        sender.set_ready(lane, false);
        assert_ne!(sender.packet_lane("peer", &packet).unwrap(), lane);
    }

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
        // A rejected direct origin must not prevent the configured API fallback.
        let rejecting = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let rejected_base = format!("http://{}", rejecting.local_addr()?);
        let rejection = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut stream, _) = rejecting.accept().await?;
            let mut request = vec![0u8; 4096];
            let _ = stream.read(&mut request).await?;
            stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            Ok::<_, anyhow::Error>(())
        });

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
            direct_url: Some(rejected_base),
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
            tokio::time::timeout(Duration::from_secs(3), rejection).await???;
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

    #[tokio::test]
    async fn a_blocked_lane_does_not_block_other_relay_lanes() -> Result<()> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.set_recv_buffer_size(4096)?;
        socket.bind("127.0.0.1:0".parse()?)?;
        let listener = socket.listen(16)?;
        let base = format!("http://{}", listener.local_addr()?);
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let (observed, mut observations) = mpsc::channel(4);
        let gateway = tokio::spawn(async move {
            let mut handlers = tokio::task::JoinSet::new();
            for lane in 0..RELAY_LANES {
                let (stream, _) = listener.accept().await?;
                let wire = tokio_tungstenite::accept_hdr_async(stream, move |request: &tokio_tungstenite::tungstenite::handshake::server::Request, mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    assert_eq!(request.headers()["x-porthub-relay-lane"],lane.to_string());
                    response.headers_mut().insert("x-porthub-relay-lanes","4".parse().unwrap());
                    Ok(response)
                }).await?;
                let stop = stop.clone();
                let observed = observed.clone();
                handlers.spawn(async move {
                    let mut wire = wire;
                    if lane == 0 {
                        stop.cancelled().await;
                    } else {
                        tokio::select! {
                            _=stop.cancelled()=>{},
                            frame=wire.next()=>{
                                if matches!(frame,Some(Ok(Message::Binary(_)))) {
                                    observed.send(lane).await.unwrap();
                                }
                                stop.cancelled().await;
                            }
                        }
                    }
                });
            }
            while handlers.join_next().await.is_some() {}
            Ok::<_, anyhow::Error>(())
        });
        let mut connections = Vec::new();
        for lane in 0..RELAY_LANES {
            let connection = connect_lane(
                &base,
                "test-token",
                "peer",
                "instance",
                lane as u8,
                4,
                &[],
                &cancel,
            )
            .await?;
            connections.push(connection.ok_or_else(|| anyhow::anyhow!("lane connection failed"))?);
        }
        let (sender, mut inputs) = channel();
        let (_updates, mut config) = watch::channel(None);
        let (events, _received) = mpsc::channel(8);
        let owner_sender = sender.clone();
        let owner_cancel = cancel.clone();
        let owner = tokio::spawn(async move {
            serve_lanes(
                connections,
                &mut inputs,
                &owner_sender,
                &mut config,
                &events,
                &owner_cancel,
            )
            .await
        });
        let output = sender.output[0].clone();
        let fill = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            let mut packet = vec![1, b'p'];
            packet.extend_from_slice(&[0; 1380]);
            let packet = Bytes::from(packet);
            for _ in 0..20000 {
                output.send(packet.clone()).await?;
            }
            Ok::<_, anyhow::Error>(())
        }));
        let result = async {
            tokio::time::timeout(Duration::from_secs(2), async {
                while sender.output[0].capacity() > 0 || !sender.is_ready() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await?;
            // Give the writer time to consume its first queue and block in TCP.
            tokio::time::sleep(Duration::from_millis(100)).await;
            ensure!(!fill.is_finished(), "lane zero was not backpressured");
            sender.output[1].send(record()).await?;
            ensure!(
                tokio::time::timeout(Duration::from_secs(1), observations.recv()).await? == Some(1),
                "unblocked lane stalled"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        cancel.cancel();
        fill.abort();
        let _ = fill.await;
        tokio::time::timeout(Duration::from_secs(2), owner).await???;
        tokio::time::timeout(Duration::from_secs(2), gateway).await???;
        ensure!(!sender.is_ready(), "cancelled relay remained ready");
        result
    }

    #[cfg(feature = "private-stream")]
    #[tokio::test]
    async fn reliable_stream_waits_for_capacity_instead_of_dropping_a_burst() {
        let (sender, mut received) = channel();
        for lane in 0..RELAY_LANES {
            sender.set_ready(lane, true);
        }
        let packet = record().slice(2..);
        for output in sender.output.iter() {
            for _ in 0..RELAY_QUEUE_PACKETS / RELAY_LANES {
                output.try_send(record()).unwrap();
            }
        }
        let mut pending = Box::pin(sender.send_stream("p", &packet));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut pending)
                .await
                .is_err()
        );
        let lane = sender.packet_lane("p", &packet).unwrap();
        received[lane].recv().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), pending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sender.take_dropped_packets(), 0);
        for input in &mut received {
            for _ in 0..RELAY_QUEUE_PACKETS / RELAY_LANES {
                assert_eq!(input.recv().await.unwrap(), record());
            }
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
