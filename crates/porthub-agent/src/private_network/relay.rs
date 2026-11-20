//! Gateway fallback prefers the operator's direct API origin, then the secure
//! API origin. This packet fallback authenticates at the gateway; peer-session
//! DTLS is a separate path. Stream payload encryption belongs to the stream layer.
use super::{controller::Event,authority_event::CarrierScope};
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
/// Bounded queued record carries immutable admission witnesses, never a lookup
/// into a newer policy when the socket eventually becomes writable.
#[derive(Clone)]
pub struct Queued {
    bytes:Bytes,
    guards:Vec<super::authority_event::Authority<()>>,
    permits:Vec<porthub_mesh::udp::SendPermit>,
}
impl From<Bytes> for Queued {fn from(bytes:Bytes)->Self{Self{bytes,guards:Vec::new(),permits:Vec::new()}}}
impl std::ops::Deref for Queued {type Target=Bytes;fn deref(&self)->&Bytes{&self.bytes}}
impl Queued {
    fn check(&self)->Result<()> {for guard in &self.guards {guard.check()?;}ensure!(self.permits.iter().all(|permit|permit.valid()),"private relay originating permit retired");Ok(())}
    async fn during<T>(&self,operation:impl std::future::Future<Output=Result<T>>)->Result<T> {
        if self.guards.is_empty()&&self.permits.is_empty(){return operation.await;}
        tokio::pin!(operation);let mut tick=tokio::time::interval(Duration::from_millis(50));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let guarded=std::future::poll_fn(|cx|{if let Err(error)=self.check(){return std::task::Poll::Ready(Err(error));}operation.as_mut().poll(cx)});
            tokio::select!{result=guarded=>return result,_=tick.tick()=>self.check()?}
        }
    }
}

#[derive(Clone)]
pub struct Sender {
    output: Arc<[mpsc::Sender<Queued>; RELAY_LANES]>,
    authority:Arc<std::sync::Mutex<Option<(super::authority_event::Authority<()>,super::sparse::Handle)>>>,
    ready: Arc<[AtomicBool; RELAY_LANES]>,
    dropped_packets: Arc<AtomicU64>,
}
#[derive(Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PinnedRelay {
    pub(crate) url: String,
    pub(crate) spki_sha256: String,
}
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Config {
    #[cfg(feature="private-sparse")]
    pub clock: Option<super::gateway_time::ClockSample>,
    pub pinned: Option<PinnedRelay>,
    pub direct_url: Option<String>,
    pub relay_token: Option<String>,
}
impl Sender {
    pub(crate) fn update_authority(&self,base:super::authority_event::Authority<()>,pairs:super::sparse::Handle) {
        *self.authority.lock().unwrap_or_else(|p|p.into_inner())=Some((base,pairs));
    }
    fn admitted(&self,peer:&str,bytes:Bytes,scope:CarrierScope)->Result<Queued> {
        let configured=self.authority.lock().unwrap_or_else(|p|p.into_inner()).clone();
        let mut guards=Vec::new();
        if let Some((base,pairs))=configured {
            ensure!(!pairs.revoked(),"private relay source retired");
            base.check()?;if base.remaining()?.is_some(){guards.push(base);}
            if pairs.enabled(){guards.push(scope.peer_authority(&pairs,peer).ok_or_else(||anyhow::anyhow!("relay pair authority expired"))?);}
        }
        Ok(Queued{bytes,guards,permits:Vec::new()})
    }
    #[cfg(feature = "private-stream")]
    pub async fn send_stream(&self, peer: &str, packet: &[u8]) -> Result<()> {self.send_stream_guarded(peer,packet,None).await}
    #[cfg(feature="private-stream")]
    pub async fn send_stream_guarded(&self,peer:&str,packet:&[u8],permit:Option<porthub_mesh::udp::SendPermit>)->Result<()> {
        ensure!(packet.get(9)!=Some(&porthub_mesh::control_packet::EXIT),"EXIT requires routing authority");
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
            .send({let mut record=self.admitted(peer,bytes,CarrierScope::Private)?;if let Some(permit)=permit{ensure!(permit.valid(),"private relay originating permit retired");record.permits.push(permit);}record})
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
    pub fn send(&self, peer: &str, packet: &[u8]) -> Result<()> {self.send_guarded(peer,packet,None)}
    pub(crate) fn send_exit(&self,peer:&str,packet:&[u8])->Result<()> {
        self.send_scoped(peer,packet,None,CarrierScope::Exit)
    }
    pub(crate) fn send_exit_guarded(&self,peer:&str,packet:&[u8],permit:Option<porthub_mesh::udp::SendPermit>)->Result<()> {
        self.send_scoped(peer,packet,permit,CarrierScope::Exit)
    }
    pub(crate) fn send_probe(&self,peer:&str,packet:&[u8])->Result<()> {
        self.send_scoped(peer,packet,None,CarrierScope::Probe)
    }
    pub(crate) fn send_guarded(&self,peer:&str,packet:&[u8],permit:Option<porthub_mesh::udp::SendPermit>)->Result<()> {
        self.send_scoped(peer,packet,permit,CarrierScope::Private)
    }
    fn send_scoped(&self,peer:&str,packet:&[u8],permit:Option<porthub_mesh::udp::SendPermit>,scope:CarrierScope)->Result<()> {
        ensure!((scope==CarrierScope::Exit)==(packet.get(9)==Some(&porthub_mesh::control_packet::EXIT)),"carrier permission does not match envelope");
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
        if scope==CarrierScope::Probe {
            let envelope=porthub_mesh::control_packet::decode(porthub_mesh::control_packet::PROBE,bytes.slice(1+peer.len()..)).ok_or_else(||anyhow::anyhow!("invalid probe envelope"))?;
            ensure!(super::probe::valid_frame(&envelope.payload,false),"invalid relayed measurement frame");
        }
        if scope==CarrierScope::Exit {ensure!(porthub_mesh::control_packet::decode(porthub_mesh::control_packet::EXIT,bytes.slice(1+peer.len()..)).is_some(),"invalid EXIT envelope");}
        let lane = self.packet_lane(peer, packet)?;
        if self.output[lane].try_send({let mut record=self.admitted(peer,bytes,scope)?;if let Some(permit)=permit{ensure!(permit.valid(),"private relay originating permit retired");record.permits.push(permit);}record}).is_ok() {
            return Ok(());
        }
        self.dropped_packets.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("private relay queue unavailable")
    }

    fn take_dropped_packets(&self) -> u64 {
        self.dropped_packets.swap(0, Ordering::Relaxed)
    }
}
pub fn channel() -> (Sender, [mpsc::Receiver<Queued>; RELAY_LANES]) {
    // Keep the combined relay queue budget unchanged while spreading traffic
    // over independent TCP congestion windows.
    let mut outputs = Vec::with_capacity(RELAY_LANES);
    let mut inputs = Vec::with_capacity(RELAY_LANES);
    for _ in 0..RELAY_LANES {
        let (output, input) = mpsc::channel(RELAY_QUEUE_PACKETS / RELAY_LANES);
        outputs.push(output);
        inputs.push(input);
    }
    let output: [mpsc::Sender<Queued>; RELAY_LANES] = outputs
        .try_into()
        .unwrap_or_else(|_| unreachable!("relay lane count is fixed"));
    let input: [mpsc::Receiver<Queued>; RELAY_LANES] = inputs
        .try_into()
        .unwrap_or_else(|_| unreachable!("relay lane count is fixed"));
    (
        Sender {
            output: Arc::new(output),
            authority:Default::default(),
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
                        origin: None, // relay data has no direct-reader generation witness
                        received_boot: super::controller::exit_ingress_boot(&frame[1+length..]),
                        peer: peer.into(),
                        bytes: frame.slice(1 + length..),
                        direct: false,
                        carrier_direct:false,
                        received_at: Instant::now(),
                    })
                    .await;
            }
        }
    }
}
async fn dispatch_downstream(frame:Bytes, origins:bool, events:&mpsc::Sender<Event>) {
    if frame.starts_with(porthub_mesh::relay_origin::MAGIC) {
        if !origins {return;}
        let Ok(records)=porthub_mesh::relay_origin::decode(frame) else{return;};
        if records.iter().any(|(origin,bytes)|bytes.get(12..16)!=Some(origin.ip.octets().as_slice())){return;}
        #[cfg(all(target_os="linux",feature="netns-tests"))] {
            static OBSERVATIONS:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
            if OBSERVATIONS.fetch_add(1,Ordering::Relaxed)<8{eprintln!("native_relay_origin decoded_records={}",records.len());}
        }
        let received_at=Instant::now();
        let frame_boot=records.iter().find_map(|(_,bytes)|super::controller::exit_ingress_boot(bytes));
        let mut identities=std::collections::HashMap::new();
        for(origin,bytes)in records {
            let identity=identities.entry(origin.stamp.clone()).or_insert_with(||Arc::new(porthub_network::policy::PeerInfo{
                id:origin.peer.clone(),ip:origin.ip,fingerprint:origin.fingerprint.clone(),instance:origin.instance.clone(),relay_origin:Some(origin.stamp.clone()),
                online:false,stream_transport:String::new(),lan_networks:Vec::new(),hostname:String::new(),aliases:Vec::new(),
            })).clone();
            let received_boot=if bytes.get(9)==Some(&porthub_mesh::control_packet::EXIT){frame_boot}else{None};
            if events.send(Event::Packet{peer:origin.peer.clone(),bytes,origin:Some(identity),received_boot,direct:false,carrier_direct:false,received_at}).await.is_err(){return;}
        }
    }else{dispatch_frame(frame,events).await;}
}
async fn dispatch_frame(frame: Bytes, events: &mpsc::Sender<Event>) {
    if let Ok(records) = porthub_mesh::batch::decode(frame) {
        for record in records {
            dispatch_record(record, events).await;
        }
    }
}

#[cfg(test)]
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
    packets: [mpsc::Receiver<Queued>; RELAY_LANES],
    config: watch::Receiver<Option<Config>>,
    events: mpsc::Sender<Event>,
    cancel: CancellationToken,
) -> Result<()> {
    let (_source, interfaces) = watch::channel(Vec::new());
    run_bound(profile, instance, sender, packets, config, interfaces, events, cancel).await
}

async fn candidate_paths<F, Fut>(
    settings: &crate::outbound::Settings,
    allow_local_test: bool,
    destinations: &[std::net::SocketAddr],
    selection: &mut crate::outbound::Selection,
    discover: F,
) -> Result<Vec<Option<crate::outbound::Candidate>>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<crate::outbound::Candidate>>>,
{
    // System mode deliberately delegates route/source selection to the kernel.
    // Explicit local test profiles also need no interface inventory. Never let
    // a failed or blocking inventory gate a connection that will not use it.
    let local_test = allow_local_test
        && !destinations.is_empty()
        && destinations.iter().all(|address| address.ip().is_loopback());
    if settings.system || local_test {
        return Ok(vec![None]);
    }
    let paths = tokio::time::timeout(Duration::from_secs(2), discover()).await??;
    Ok(selection.order(&paths, Instant::now()).into_iter().map(Some).collect())
}

fn valid_relay_url(value: &str, tls_only: bool) -> bool {
    let Ok(url) = url::Url::parse(value) else { return false; };
    (url.scheme() == "https" || !tls_only && url.scheme() == "http")
        && url.host_str().is_some() && url.username().is_empty() && url.password().is_none()
        && url.query().is_none() && url.fragment().is_none() && url.path() == "/"
}

pub async fn run_bound(
    profile: Profile,
    instance: String,
    sender: Sender,
    mut packets: [mpsc::Receiver<Queued>; RELAY_LANES],
    mut config: watch::Receiver<Option<Config>>,
    interfaces: watch::Receiver<Vec<std::net::SocketAddr>>,
    events: mpsc::Sender<Event>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut retry = Duration::from_secs(1);
    let settings = crate::outbound::Settings::from_env()?;
    let mut selection = crate::outbound::Selection::default();
    loop {
        while config.borrow_and_update().is_none() {
            tokio::select! {_=cancel.cancelled()=>return Ok(()),changed=config.changed()=>if changed.is_err(){return Ok(())}}
        }
        #[cfg(feature="private-sparse")]
        let clock=config.borrow().as_ref().and_then(|config|config.clock);
        #[cfg(not(feature="private-sparse"))]
        let clock=None;
        let mut candidates = Vec::with_capacity(profile.fallback_servers.len() + 3);
        if let Some(configuration) = config.borrow_and_update().clone() {
            if let Some(token) = configuration.relay_token.filter(|t| (32..=128).contains(&t.len())) {
                if let Some(pinned) = configuration.pinned {
                    if valid_relay_url(&pinned.url, true) && pinned.spki_sha256.len() == 64
                        && pinned.spki_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                        candidates.push((pinned.url, token.clone(), Some(pinned.spki_sha256)));
                    }
                }
                if let Some(url) = configuration.direct_url.filter(|u| valid_relay_url(u, false)) {
                    candidates.push((url, token, None));
                }
            }
        }
        candidates.push((profile.server.clone(), profile.token.clone(), None));
        candidates.extend(
            profile
                .fallback_servers
                .iter()
                .cloned()
                .map(|base| (base, profile.token.clone(), None)),
        );
        let mut local: Vec<_> = interfaces.borrow().iter().map(|address| address.ip()).collect();
        let mut primary = None;
        for (base, token, pin) in candidates {
            let url = url::Url::parse(&base)?;
            let host = url.host_str().ok_or_else(|| anyhow::anyhow!("relay hostname missing"))?;
            let destinations: Vec<_> = match tokio::time::timeout(Duration::from_secs(2),tokio::net::lookup_host((host.trim_matches(['[',']']),url.port_or_known_default().unwrap_or(443)))).await {
                Ok(Ok(addresses)) => addresses.take(16).collect(),
                _ => continue,
            };
            let paths = match candidate_paths(&settings, profile.allow_insecure_http_for_tests,
                &destinations, &mut selection, || crate::outbound::discover(&settings, &destinations)).await {
                Ok(paths) => paths,
                Err(_) => continue,
            };
            for path in paths {
                local = path.as_ref().map(|p|vec![p.source]).unwrap_or_default();
                if let Some(connection) = connect_lane(&base,pin.as_deref(),clock,&token,&profile.peer_id,&instance,0,RELAY_LANES as u8,&local,&cancel).await? {
                    if let Some(path) = path { selection.success(path); }
                    let lane_count = connection.lane_count;
                    primary = Some((base.clone(),token.clone(),pin.clone(),connection,lane_count));
                    break;
                }
                if let Some(path) = &path { selection.failure(path,Instant::now()); }
            }
            if primary.is_some() { break; }
        }
        if let Some((base, token, pin, first, lane_count)) = primary {
            let mut connections = vec![first];
            for lane in 1..usize::from(lane_count) {
                let Some(connection) = connect_lane(
                    &base,
                    pin.as_deref(),
                    clock,
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
    origins: bool,
    lane: usize,
    socket: RelaySocket,
    batch: bool,
    prefixes: bool,
    lane_count: u8,
}

async fn connect_lane(
    base: &str,
    pin: Option<&str>,
    #[cfg(feature="private-sparse")] clock: Option<super::gateway_time::ClockSample>,
    #[cfg(not(feature="private-sparse"))] _clock: Option<()>,
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
    #[cfg(feature="private-sparse")]
    if scheme=="wss" && clock.is_none() && std::time::SystemTime::now()<std::time::UNIX_EPOCH { return Ok(None); }
    let connector = match pin {
        Some(pin) if scheme == "wss" => {
            let Ok(tls) = porthub_identity::pinned_client_config(pin) else { return Ok(None); };
            #[cfg(feature="private-sparse")]
            let tls=if let Some(clock)=clock {let mut config=tls;config.time_provider=Arc::new(clock);config}else{tls};
            Some(tokio_tungstenite::Connector::Rustls(Arc::new(tls)))
        }
        #[cfg(feature="private-sparse")]
        None if scheme=="wss" && clock.is_some() => {
            let roots=rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let tls=rustls::ClientConfig::builder_with_details(Arc::new(rustls::crypto::ring::default_provider()),Arc::new(clock.expect("matched authenticated clock")))
                .with_safe_default_protocol_versions()?.with_root_certificates(roots).with_no_client_auth();
            Some(tokio_tungstenite::Connector::Rustls(Arc::new(tls)))
        }
        Some(_) => return Ok(None),
        None => None,
    };
    url.set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("invalid private relay authority"))?;
    url.set_path("/api/access/private/relay");
    let mut request = url.as_str().into_client_request()?;
    let headers = request.headers_mut();
    headers.insert("x-porthub-peer", peer.parse()?);
    headers.insert("x-porthub-instance", instance.parse()?);
    headers.insert("authorization", format!("Bearer {token}").parse()?);
    headers.insert("x-porthub-relay-origin", "1".parse()?);
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
                connector,
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
    let origins=response.headers().get("x-porthub-relay-origin").is_some_and(|v|v=="1");
    if pin.is_some() && !origins { return Ok(None); }
    #[cfg(all(target_os="linux",feature="netns-tests"))] {
        static OBSERVATIONS:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
        if OBSERVATIONS.fetch_add(1,Ordering::Relaxed)<8{eprintln!("native_relay_origin negotiated={origins}");}
    }
    Ok(Some(ConnectedLane {
        origins,
        lane: usize::from(lane),
        socket,
        batch,
        prefixes,
        lane_count,
    }))
}

#[derive(Clone,Copy)]
struct HeartbeatTiming { ping:Duration, response:Duration, check:Duration }
const HEARTBEAT:HeartbeatTiming=HeartbeatTiming{ping:Duration::from_secs(25),response:Duration::from_secs(15),check:Duration::from_secs(1)};
struct LaneProbe { nonce:[u8;16], state:std::sync::Mutex<(u64,Option<(Bytes,tokio::time::Instant)>)> }
impl LaneProbe {
    fn new()->Result<Self>{let mut nonce=[0;16];getrandom::fill(&mut nonce).map_err(|_|anyhow::anyhow!("relay heartbeat nonce unavailable"))?;Ok(Self{nonce,state:std::sync::Mutex::new((0,None))})}
    fn challenge(&self,now:tokio::time::Instant,response:Duration)->Result<Option<Bytes>>{
        let mut state=self.state.lock().unwrap_or_else(|p|p.into_inner());
        if let Some((_,deadline))=&state.1 {ensure!(now<*deadline,"relay heartbeat response expired");return Ok(None);}
        state.0=state.0.checked_add(1).ok_or_else(||anyhow::anyhow!("relay heartbeat sequence exhausted"))?;
        let mut bytes=self.nonce.to_vec();bytes.extend_from_slice(&state.0.to_be_bytes());let bytes=Bytes::from(bytes);
        state.1=Some((bytes.clone(),now+response));Ok(Some(bytes))
    }
    fn pong(&self,bytes:&Bytes,now:tokio::time::Instant){let mut state=self.state.lock().unwrap_or_else(|p|p.into_inner());if state.1.as_ref().is_some_and(|(expected,deadline)|expected==bytes&&now<*deadline){state.1=None;}}
    fn expired(&self,now:tokio::time::Instant)->bool{self.state.lock().unwrap_or_else(|p|p.into_inner()).1.as_ref().is_some_and(|(_,deadline)|now>=*deadline)}
}

async fn serve_lanes(
    connections: Vec<ConnectedLane>,
    packets: &mut [mpsc::Receiver<Queued>; RELAY_LANES],
    sender: &Sender,
    config: &mut watch::Receiver<Option<Config>>,
    events: &mpsc::Sender<Event>,
    cancel: &CancellationToken,
) -> Result<bool> {
    serve_lanes_with_heartbeat(connections,packets,sender,config,events,cancel,HEARTBEAT).await
}
async fn serve_lanes_with_heartbeat(
    connections:Vec<ConnectedLane>,packets:&mut[mpsc::Receiver<Queued>;RELAY_LANES],sender:&Sender,
    config:&mut watch::Receiver<Option<Config>>,events:&mpsc::Sender<Event>,cancel:&CancellationToken,timing:HeartbeatTiming,
)->Result<bool>{
    let reading = cancel.child_token();
    let mut readers = tokio::task::JoinSet::new();
    let mut writers = futures_util::stream::FuturesUnordered::new();
    let probes=connections.iter().map(|_|LaneProbe::new().map(Arc::new)).collect::<Result<Vec<_>>>()?;
    for ((connection, input),probe) in connections.into_iter().zip(packets.iter_mut()).zip(probes) {
        let lane = connection.lane;
        let (writer, mut incoming) = connection.socket.split();
        let (pongs, pong_rx) = mpsc::channel::<Bytes>(4);
        let reader_probe=probe.clone();
        sender.set_ready(lane, true);
        let reader_sender=sender.clone();
        let read_events = events.clone();
        let read_cancel = reading.clone();
        let origins=connection.origins;
        readers.spawn(async move {
            let mut check=tokio::time::interval(timing.check);
            check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _=read_cancel.cancelled()=>break,
                    _=check.tick()=>if reader_probe.expired(tokio::time::Instant::now()) {tracing::warn!(lane,"private relay lane missed matched heartbeat response");break;},
                    frame=incoming.next()=>match frame {
                        Some(Ok(Message::Binary(frame)))=>tokio::select! {_=read_cancel.cancelled()=>break,_=dispatch_downstream(frame,origins,&read_events)=>{}},
                        Some(Ok(Message::Ping(bytes)))=>if pongs.try_send(bytes).is_err(){break;},
                        Some(Ok(Message::Pong(bytes)))=>reader_probe.pong(&bytes,tokio::time::Instant::now()),
                        _=>break,
                    }
                }
            }
            reader_sender.set_ready(lane,false);
        });
        // Each socket has its own writer. A full TCP send buffer on one lane
        // must not prevent the other lanes from making progress.
        writers.push(write_lane_probed(
            writer,input,pong_rx,connection.batch,connection.prefixes,Some(probe),timing,
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

#[cfg(test)]
async fn write_lane(
    socket: RelaySink,
    packets: &mut mpsc::Receiver<Queued>,
    pongs: mpsc::Receiver<Bytes>,
    batch: bool,
    prefixes: bool,
) -> Result<()> {
    write_lane_probed(socket,packets,pongs,batch,prefixes,None,HEARTBEAT).await
}
async fn write_lane_probed(
    mut socket:RelaySink,packets:&mut mpsc::Receiver<Queued>,mut pongs:mpsc::Receiver<Bytes>,batch:bool,prefixes:bool,
    probe:Option<Arc<LaneProbe>>,timing:HeartbeatTiming,
)->Result<()>{
    let mut heartbeat = tokio::time::interval(timing.ping);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    heartbeat.tick().await;
    loop {
        let (message,authority) = tokio::select! {
            packet=packets.recv()=>{
                let Some(packet)=packet else {return Ok(());};
                if packet.check().is_err(){continue;}
                let mut records=vec![packet.bytes.clone()];let mut guards=packet.guards;let mut permits=packet.permits;
                if batch {for _ in 1..32 {match packets.try_recv(){Ok(next)=>{if next.check().is_ok(){records.push(next.bytes);guards.extend(next.guards);permits.extend(next.permits);}},Err(_)=>break}}}
                let message=if batch {Message::Binary(porthub_mesh::batch::encode(&records,prefixes)?.into())}else{Message::Binary(records.pop().unwrap())};
                (message,Queued{bytes:Bytes::new(),guards,permits})
            },
            pong=pongs.recv()=>{
                let Some(pong)=pong else {return Ok(());};
                (Message::Pong(pong),Bytes::new().into())
            },
            _=heartbeat.tick()=>{
                let bytes=match &probe {Some(probe)=>{let Some(bytes)=probe.challenge(tokio::time::Instant::now(),timing.response)? else{continue;};bytes},None=>Bytes::new()};
                (Message::Ping(bytes),Bytes::new().into())
            },
        };
        authority.during(async {tokio::time::timeout(Duration::from_secs(5),socket.send(message)).await??;Ok(())}).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_current_on_time_pong_retires_pending_probe() -> Result<()> {
        let probe=LaneProbe::new()?;let now=tokio::time::Instant::now();
        let first=probe.challenge(now,Duration::from_secs(15))?.unwrap();
        probe.pong(&Bytes::from_static(b"foreign"),now);
        assert!(probe.challenge(now+Duration::from_secs(5),Duration::from_secs(15))?.is_none());
        assert!(probe.expired(now+Duration::from_secs(15)));
        probe.pong(&first,now+Duration::from_secs(15));assert!(probe.expired(now+Duration::from_secs(15)));
        let live=LaneProbe::new()?;let first=live.challenge(now,Duration::from_secs(15))?.unwrap();
        live.pong(&first,now+Duration::from_secs(1));let second=live.challenge(now+Duration::from_secs(2),Duration::from_secs(15))?.unwrap();
        assert_ne!(first,second);live.pong(&first,now+Duration::from_secs(3));assert!(live.expired(now+Duration::from_secs(17)));Ok(())
    }

    #[tokio::test]
    async fn private_lane_checks_published_key_before_sending_bearer() -> Result<()> {
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
        let identity = rcgen::generate_simple_self_signed(vec!["edge.invalid".into()])?;
        let cert = identity.cert.der().clone();
        let pin = porthub_identity::origin::Metadata::from_certificate(&cert, 443)?.spki_sha256;
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der());
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?.with_no_client_auth()
            .with_single_cert(vec![cert], key.into())?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            // A different key fails during TLS, before a request is possible.
            let (wrong, _) = listener.accept().await?;
            ensure!(acceptor.accept(wrong).await.is_err());
            let (correct, _) = listener.accept().await?;
            let tls = acceptor.accept(correct).await?;
            let _ws = tokio_tungstenite::accept_hdr_async(tls, |request: &Request, mut response: Response| {
                assert_eq!(request.uri().path(), "/api/access/private/relay");
                assert_eq!(request.headers()["authorization"], "Bearer fixture");
                response.headers_mut().insert("x-porthub-relay-origin", "1".parse().unwrap());
                Ok(response)
            }).await?;
            Ok::<_, anyhow::Error>(())
        });
        let stop = CancellationToken::new();
        let url = format!("https://{address}");
        assert!(connect_lane(&format!("http://{address}"), Some(&pin), None, "fixture", "peer", "instance", 0, 1, &[], &stop).await?.is_none());
        assert!(connect_lane(&url, Some(&"00".repeat(32)), None, "fixture", "peer", "instance", 0, 1, &[], &stop).await?.is_none());
        assert!(connect_lane(&url, Some(&pin), None, "fixture", "peer", "instance", 0, 1, &[], &stop).await?.is_some());
        tokio::time::timeout(Duration::from_secs(4), server).await???;
        Ok(())
    }

    async fn real_lane_heartbeat(responsive:bool)->Result<()> {
        use tokio::io::AsyncReadExt;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base=format!("http://{}",listener.local_addr()?);
        let stop=CancellationToken::new();let _guard=stop.clone().drop_guard();
        let peer_stop=stop.clone();let drained=Arc::new(std::sync::atomic::AtomicUsize::new(0));let count=drained.clone();
        let peer=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            let(stream,_)=listener.accept().await?;
            let mut wire=tokio_tungstenite::accept_async(stream).await?;
            if responsive {
                loop {tokio::select!{_=peer_stop.cancelled()=>break,frame=wire.next()=>match frame {
                    Some(Ok(Message::Ping(bytes)))=>{count.fetch_add(1,Ordering::Relaxed);wire.send(Message::Pong(bytes)).await?;},
                    Some(Ok(_))=>{},_=>break,
                }}}
            }else{
                // Preserve a live TCP receiver that ACKs/drains every write,
                // while the application never produces a WebSocket Pong.
                let mut raw=wire.into_inner();let mut bytes=[0;4096];
                loop {tokio::select!{_=peer_stop.cancelled()=>break,n=raw.read(&mut bytes)=>{let n=n?;if n==0{break;}count.fetch_add(n,Ordering::Relaxed);}}}
            }
            Ok::<_,anyhow::Error>(())
        }));
        let connection=connect_lane(&base,None,None,"test-token","peer","instance",0,1,&[],&stop).await?.ok_or_else(||anyhow::anyhow!("test relay unavailable"))?;
        let(sender,mut inputs)=channel();let(_update,mut config)=watch::channel(None);let(events,_incoming)=mpsc::channel(8);
        let owner_sender=sender.clone();let owner_stop=stop.clone();
        let owner=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move{
            serve_lanes_with_heartbeat(vec![connection],&mut inputs,&owner_sender,&mut config,&events,&owner_stop,
                HeartbeatTiming{ping:Duration::from_millis(30),response:Duration::from_millis(100),check:Duration::from_millis(10)}).await
        }));
        tokio::time::timeout(Duration::from_secs(1),async{while !sender.is_ready(){tokio::task::yield_now().await;}}).await?;
        if responsive {
            tokio::time::sleep(Duration::from_millis(350)).await;
            ensure!(sender.is_ready()&&!owner.is_finished(),"responsive idle lane retired");
            ensure!(drained.load(Ordering::Relaxed)>=3,"healthy lane did not answer repeated probes");
            stop.cancel();let _=tokio::time::timeout(Duration::from_secs(1),owner).await???;
        }else{
            ensure!(!tokio::time::timeout(Duration::from_secs(1),owner).await???,"half-open lane did not request reconnect");
            ensure!(!sender.is_ready(),"blackholed lane remained ready");
            ensure!(drained.load(Ordering::Relaxed)>0,"test never ACKed/drained a successful client write");stop.cancel();
        }
        tokio::time::timeout(Duration::from_secs(1),peer).await???;Ok(())
    }
    #[tokio::test]
    async fn real_tcp_accepting_writes_without_pong_retires_ready_lane()->Result<()>{real_lane_heartbeat(false).await}
    #[tokio::test]
    async fn real_idle_lane_matching_pongs_preserve_readiness()->Result<()>{real_lane_heartbeat(true).await}

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

    #[cfg(feature="private-sparse")]
    #[tokio::test]
    async fn real_websocket_writer_drops_expired_queued_record_despite_fresh_sender_renewal()->Result<()> {
        use super::super::{authority_clock::{SuspendClock,RequestWindow},authority_event::Authority};
        struct Clock(std::sync::atomic::AtomicU64);
        impl SuspendClock for Clock {fn elapsed_since_boot(&self)->Result<Duration>{Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))}}
        let clock=Arc::new(Clock(std::sync::atomic::AtomicU64::new(0)));
        let make=||Authority::new((),Some(RequestWindow::start(clock.clone()).unwrap()),chrono::Utc::now()+chrono::Duration::seconds(30));
        let (sender,mut lanes)=channel();sender.set_ready(0,true);let (pairs,_)=super::super::sparse::channel();
        sender.update_authority(make(),pairs.clone());sender.send("p",&record()[2..])?;
        clock.0.store(15000,Ordering::SeqCst);
        sender.update_authority(make(),pairs);
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url=format!("ws://{}/",listener.local_addr()?);
        let (client,server)=tokio::join!(tokio_tungstenite::connect_async(url),async {let (socket,_)=listener.accept().await?;Ok::<_,anyhow::Error>(tokio_tungstenite::accept_async(socket).await?)});
        let (sink,_)=client?.0.split();let mut server=server?;
        let (_pong_send,pongs)=mpsc::channel(1);let (_unused,replacement)=mpsc::channel(1);
        let mut input=std::mem::replace(&mut lanes[0],replacement);
        let task=tokio::spawn(async move {write_lane(sink,&mut input,pongs,false,false).await});
        assert!(tokio::time::timeout(Duration::from_millis(50),server.next()).await.is_err());
        sender.send("p",&record()[2..])?;
        let frame=tokio::time::timeout(Duration::from_secs(1),server.next()).await?.unwrap()?;
        assert_eq!(frame,Message::Binary(record()));
        assert!(tokio::time::timeout(Duration::from_millis(50),server.next()).await.is_err());
        task.abort();let _=task.await;Ok(())
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
            stream
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
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
            #[cfg(feature="private-sparse")] clock:None,
            pinned: None,
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
            use anyhow::Context;
            tokio::time::timeout(Duration::from_secs(3), rejection)
                .await
                .context("direct-origin rejection timed out")?
                .context("direct-origin rejection task failed")?
                .context("direct-origin rejection failed")?;
            tokio::time::timeout(Duration::from_secs(2), async {
                while !sender.is_ready() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .context("fallback relay did not become ready")?;
            let sending = sender.clone();
            let fill = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                for _ in 0..20000 {
                    sending.send_stream("p", &[0; 1380]).await?;
                }
                Ok::<_, anyhow::Error>(())
            }));
            let event = tokio::time::timeout(Duration::from_secs(2), received.recv())
                .await
                .context("reverse packet timed out under outbound pressure")?;
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
        // Always observe both cleanup tasks; cancellation/handshake errors must
        // not hide the original readiness or reverse-packet failure.
        let owner_cleanup = async {
            use anyhow::Context;
            tokio::time::timeout(Duration::from_secs(2), owner)
                .await
                .context("owner cleanup timed out")?
                .context("owner cleanup task failed")??;
            Ok::<_, anyhow::Error>(())
        };
        let gateway_cleanup = async {
            use anyhow::Context;
            tokio::time::timeout(Duration::from_secs(2), gateway)
                .await
                .context("gateway cleanup timed out")?
                .context("gateway cleanup task failed")??;
            Ok::<_, anyhow::Error>(())
        };
        let (owner_result, gateway_result) = tokio::join!(owner_cleanup, gateway_cleanup);
        let mut cleanup_errors = Vec::new();
        for (name, outcome) in [("owner", owner_result), ("gateway", gateway_result)] {
            if let Err(error) = outcome {
                cleanup_errors.push(format!("{name}: {error:#}"));
            }
        }
        if sender.is_ready() {
            cleanup_errors.push("cancelled relay remained ready".into());
        }
        if let Err(error) = result {
            anyhow::bail!(
                "primary scenario failure: {error:#}; cleanup errors: {cleanup_errors:?}"
            );
        }
        ensure!(
            cleanup_errors.is_empty(),
            "relay cleanup failed: {cleanup_errors:?}"
        );
        Ok(())
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
                None,
                None,
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
                output.send(packet.clone().into()).await?;
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
            sender.output[1].send(record().into()).await?;
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
                output.try_send(record().into()).unwrap();
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
                assert_eq!(input.recv().await.unwrap().bytes, record());
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

#[cfg(test)]
mod candidate_path_tests {
    use super::*;
    fn destination(value: &str) -> Vec<std::net::SocketAddr> { vec![value.parse().unwrap()] }
    #[tokio::test]
    async fn system_and_explicit_loopback_never_call_failed_inventory() -> Result<()> {
        for (system, local, addresses) in [
            (true, false, destination("192.0.2.1:443")),
            (false, true, destination("127.0.0.1:443")),
            (false, true, destination("[::1]:443")),
        ] {
            let settings = crate::outbound::Settings { system, ..Default::default() };
            let called = std::cell::Cell::new(false);
            let paths = candidate_paths(&settings, local, &addresses, &mut Default::default(), || {
                called.set(true);
                std::future::ready(Err(anyhow::anyhow!("injected interface inventory failure")))
            }).await?;
            assert!(!called.get());
            assert_eq!(paths, vec![None]);
        }
        Ok(())
    }
    #[tokio::test]
    async fn unbound_path_does_not_poll_blocked_inventory() -> Result<()> {
        let settings = crate::outbound::Settings { system: true, ..Default::default() };
        let paths = tokio::time::timeout(Duration::from_millis(100), candidate_paths(
            &settings, false, &destination("192.0.2.1:443"), &mut Default::default(),
            || std::future::pending(),
        )).await??;
        assert_eq!(paths, vec![None]);
        Ok(())
    }
    #[tokio::test]
    async fn bound_and_nonlocal_profiles_preserve_inventory_errors_without_unbound_fallback() {
        for (local, addresses) in [
            (false, destination("127.0.0.1:443")),
            (true, destination("192.0.2.1:443")),
            (true, vec!["127.0.0.1:443".parse().unwrap(), "192.0.2.1:443".parse().unwrap()]),
            (true, Vec::new()),
        ] {
            let result = candidate_paths(&Default::default(), local, &addresses, &mut Default::default(),
                || std::future::ready(Err(anyhow::anyhow!("injected inventory failure")))).await;
            assert!(result.is_err());
        }
    }
    #[tokio::test]
    async fn explicit_bound_candidate_retains_source_interface_destination_and_selection() -> Result<()> {
        let addresses = destination("192.0.2.1:443");
        let candidate = crate::outbound::Candidate { source:"10.1.2.3".parse()?,interface:"vpn0".into(),destination:addresses[0],gateway:Some("10.1.2.1".parse()?),metric:Some(17) };
        let settings = crate::outbound::Settings { interface:Some("vpn0".into()),source:Some(candidate.source),system:false };
        let paths = candidate_paths(&settings, false, &addresses, &mut Default::default(),
            || std::future::ready(Ok(vec![candidate.clone()]))).await?;
        assert_eq!(paths,vec![Some(candidate)]);
        Ok(())
    }
}

#[cfg(all(test,feature="private-sparse"))]
mod exit_authority_tests {
    use super::*;
    use super::super::{authority_event::{Authority,Owner,send_permit,send_exit_permit},authority_clock::{RequestWindow,SuspendClock},sparse};
    struct Clock(AtomicU64);
    impl SuspendClock for Clock {fn elapsed_since_boot(&self)->Result<Duration>{Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))}}
    struct Fixture {
        clock:Arc<Clock>,owner:Owner,handle:sparse::Handle,base:porthub_network::policy::Snapshot,
    }
    impl Fixture {
        fn authority(&self,expiry:chrono::DateTime<chrono::Utc>)->Authority<()> {
            Authority::new((),Some(RequestWindow::start(self.clock.clone()).unwrap()),expiry).retired_with(self.owner.domain())
        }
        fn publish(&self,sender:&Sender)->Authority<()> {
            let base=self.authority(self.base.expires_at);self.handle.update_base_authority(&self.base,base.clone());sender.update_authority(base.clone(),self.handle.clone());base
        }
        fn new(sender:&Sender)->Self {
            let base=serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(30),"sparse":{"protocol":1,"epoch":"a".repeat(64),"exit_epoch":"e".repeat(64)},"peers":[{"id":"a","ip":"10.203.0.2","fingerprint":"local","instance":"local-instance","hostname":"a.phub"}],"grants":[]})).unwrap();
            let (handle,_)=sparse::channel();let f=Self{clock:Arc::new(Clock(AtomicU64::new(0))),owner:Owner::new(),handle,base};f.publish(sender);
            let pair=serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","epoch":"a".repeat(64),"revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(15),"local":{"id":"a","ip":"10.203.0.2","fingerprint":"local","instance":"local-instance","hostname":"a.phub"},"peer":{"id":"b","ip":"10.203.1.2","fingerprint":"remote","instance":"remote-instance","hostname":"b.phub"},"grants":[{"source":"a","destination":"b","protocol":"any","ports":[]}],"exit":{"epoch":"e".repeat(64),"route_id":"route","client":"a","router":"b","traffic_mode":"internet_only"}})).unwrap();
            let pair:porthub_network::policy::PairLease=pair;
            f.handle.installed_authority(&porthub_network::policy::Lookup{kind:"peer".into(),value:"b".into()},pair.clone(),f.authority(pair.expires_at));f
        }
    }
    fn packet(protocol:u8)->Bytes {porthub_mesh::control_packet::encode(protocol,"10.203.0.2".parse().unwrap(),"10.203.1.2".parse().unwrap(),&[0;28]).unwrap()}
    fn queued(inputs:&mut[mpsc::Receiver<Queued>;RELAY_LANES])->Queued {inputs.iter_mut().find_map(|input|input.try_recv().ok()).expect("admitted record missing")}
    #[test]
    fn exit_carrier_keeps_original_expiry_when_private_policy_changes() {
        let (sender,mut inputs)=channel();sender.set_ready(0,true);let mut f=Fixture::new(&sender);let base=f.authority(f.base.expires_at);
        let private=send_permit(Some(&base),&f.handle,"b").unwrap().unwrap();let exit=send_exit_permit(Some(&base),&f.handle,"b").unwrap().unwrap();
        sender.send_exit("b",&packet(porthub_mesh::control_packet::EXIT)).unwrap();let old=queued(&mut inputs);assert!(old.check().is_ok());
        f.clock.0.store(10000,Ordering::SeqCst);f.base.sparse.as_mut().unwrap().epoch="b".repeat(64);let fresh=f.publish(&sender);
        assert!(!private.valid());assert!(exit.valid());assert!(old.check().is_ok());
        assert!(send_permit(Some(&fresh),&f.handle,"b").is_err());assert!(send_exit_permit(Some(&fresh),&f.handle,"b").unwrap().unwrap().valid());
        sender.send_exit("b",&packet(porthub_mesh::control_packet::EXIT)).unwrap();let new=queued(&mut inputs);
        assert!(sender.send("b",&packet(porthub_mesh::control_packet::PROBE)).is_err());
        f.clock.0.store(15000,Ordering::SeqCst);assert!(f.handle.authority_valid());assert!(!exit.valid());assert!(old.check().is_err()&&new.check().is_err());
        assert!(send_exit_permit(Some(&fresh),&f.handle,"b").is_err());
    }
    #[tokio::test]
    async fn exit_carrier_rejects_revoked_exit_before_polling_delivery_and_preserves_private() {
        let (sender,mut inputs)=channel();sender.set_ready(0,true);let mut f=Fixture::new(&sender);let base=f.authority(f.base.expires_at);
        let private=send_permit(Some(&base),&f.handle,"b").unwrap().unwrap();let exit=send_exit_permit(Some(&base),&f.handle,"b").unwrap().unwrap();
        let wire=packet(porthub_mesh::control_packet::EXIT);
        assert!(sender.send("b",&wire).is_err());assert!(sender.send_stream_guarded("b",&wire,None).await.is_err());
        assert!(sender.send_exit("b",&packet(porthub_mesh::control_packet::PROBE)).is_err());
        sender.send_exit("b",&wire).unwrap();let old=queued(&mut inputs);
        f.base.sparse.as_mut().unwrap().exit_epoch=Some("f".repeat(64));let fresh=f.publish(&sender);
        assert!(private.valid());assert!(!exit.valid());assert!(send_exit_permit(Some(&fresh),&f.handle,"b").is_err());assert!(sender.send_exit("b",&wire).is_err());
        let touched=AtomicBool::new(false);assert!(old.during(async{touched.store(true,Ordering::SeqCst);Ok(())}).await.is_err());assert!(!touched.load(Ordering::SeqCst));
        sender.send("b",&packet(porthub_mesh::control_packet::PROBE)).unwrap();let private_record=queued(&mut inputs);assert!(private_record.check().is_ok());
        f.owner.revoke();assert!(!private.valid());assert!(private_record.check().is_err());
    }
    #[tokio::test]
    async fn guarded_exit_carrier_keeps_origin_bound_until_actual_delivery() {
        let(sender,mut inputs)=channel();sender.set_ready(0,true);let f=Fixture::new(&sender);
        let clock=Arc::new(Clock(AtomicU64::new(0)));let age=RequestWindow::start(clock.clone()).unwrap();let check_age=age.clone();
        let original=porthub_mesh::udp::SendPermit::bounded(move||check_age.remaining_within(Duration::from_secs(5)).is_ok(),move||age.remaining_within(Duration::from_secs(5)).ok());
        assert!(sender.send_exit_guarded("b",&packet(porthub_mesh::control_packet::PROBE),Some(original.clone())).is_err());
        sender.send_exit_guarded("b",&packet(porthub_mesh::control_packet::EXIT),Some(original)).unwrap();
        let record=queued(&mut inputs);assert!(record.check().is_ok());clock.0.store(6000,Ordering::SeqCst);
        assert!(f.handle.exit_pair_authority("b").is_some(),"current exit remains live");
        let touched=AtomicBool::new(false);
        assert!(record.during(async{touched.store(true,Ordering::SeqCst);Ok(())}).await.is_err());
        assert!(!touched.load(Ordering::SeqCst),"expired originating datagram reached the queued write");
    }
    #[test]
    fn sparse_exit_carrier_cannot_omit_base_or_fall_back_to_legacy() {
        let (sender,_)=channel();let f=Fixture::new(&sender);
        assert!(send_exit_permit(None,&f.handle,"b").is_err());assert!(send_exit_permit(Some(&f.authority(f.base.expires_at)),&f.handle,"unknown").is_err());
        let (legacy,_)=sparse::channel();assert!(send_exit_permit(None,&legacy,"b").unwrap().is_none());
        f.handle.revoke_all();assert!(send_exit_permit(Some(&f.authority(f.base.expires_at)),&f.handle,"b").is_err());
        sender.set_ready(0,true);assert!(sender.send_exit("b",&packet(porthub_mesh::control_packet::EXIT)).is_err());
    }
    fn measurement(direct:bool)->Bytes {
        super::super::probe::Quality::default().start("b",direct,1,Instant::now()).remove(0)
    }
    fn probe_wire(payload:&[u8])->Bytes {
        porthub_mesh::control_packet::encode(porthub_mesh::control_packet::PROBE,"10.203.0.2".parse().unwrap(),"10.203.1.2".parse().unwrap(),payload).unwrap()
    }
    #[test]
    fn probe_scope_survives_private_change_using_original_exit_expiry_only() {
        use super::super::authority_event::send_probe_permit;
        let (sender,mut inputs)=channel();sender.set_ready(0,true);let mut f=Fixture::new(&sender);let base=f.authority(f.base.expires_at);
        let before=send_probe_permit(Some(&base),&f.handle,"b").unwrap().unwrap();
        sender.send_probe("b",&probe_wire(&measurement(false))).unwrap();let old=queued(&mut inputs);
        f.clock.0.store(10000,Ordering::SeqCst);f.base.sparse.as_mut().unwrap().epoch="b".repeat(64);let fresh=f.publish(&sender);
        assert!(!before.valid());assert!(old.check().is_err(),"queued original private receipt was promoted to exit permission");
        assert!(send_permit(Some(&fresh),&f.handle,"b").is_err());
        let probe=send_probe_permit(Some(&fresh),&f.handle,"b").unwrap().unwrap();assert!(probe.valid());
        sender.send_probe("b",&probe_wire(&measurement(false))).unwrap();let retained=queued(&mut inputs);assert!(retained.check().is_ok());
        f.clock.0.store(15000,Ordering::SeqCst);assert!(f.handle.authority_valid());assert!(!probe.valid());assert!(retained.check().is_err());
        assert!(send_probe_permit(Some(&fresh),&f.handle,"b").is_err());
    }
    #[test]
    fn probe_scope_uses_private_permission_after_exit_revocation_but_never_payloads() {
        use super::super::authority_event::send_probe_permit;
        let (sender,mut inputs)=channel();sender.set_ready(0,true);let mut f=Fixture::new(&sender);
        f.base.sparse.as_mut().unwrap().exit_epoch=Some("f".repeat(64));let fresh=f.publish(&sender);
        assert!(send_exit_permit(Some(&fresh),&f.handle,"b").is_err());
        assert!(send_probe_permit(Some(&fresh),&f.handle,"b").unwrap().unwrap().valid());
        sender.send_probe("b",&probe_wire(&measurement(false))).unwrap();let retained=queued(&mut inputs);
        for wrong in [packet(porthub_mesh::control_packet::EXIT),packet(porthub_mesh::control_packet::STREAM),probe_wire(b"application payload"),probe_wire(&measurement(true))] {
            assert!(sender.send_probe("b",&wrong).is_err(),"measurement permission admitted non-probe or wrong-carrier bytes");
        }
        let mut corrupt=measurement(false).to_vec();corrupt[11]=0;assert!(sender.send_probe("b",&probe_wire(&corrupt)).is_err());
        f.handle.revoke_all();assert!(retained.check().is_err());assert!(send_probe_permit(Some(&fresh),&f.handle,"b").is_err());
        assert!(sender.send_probe("b",&probe_wire(&measurement(false))).is_err());
    }

}

#[cfg(test)]
mod relay_origin_tests {
    use super::*;
    #[tokio::test]
    async fn only_negotiated_server_origin_is_retained_and_shared(){
        let origin=Arc::new(porthub_mesh::relay_origin::Origin{peer:"remote".into(),ip:"10.203.0.1".parse().unwrap(),fingerprint:"fp".into(),instance:"instance".into(),stamp:"a".repeat(32)});
        let mut packet=vec![0;20];packet[0]=0x45;packet[3]=20;packet[12..16].copy_from_slice(&origin.ip.octets());
        let frame=porthub_mesh::relay_origin::encode(&[(origin.clone(),Bytes::from(packet.clone())),(origin.clone(),Bytes::from(packet))]).unwrap();
        let(tx,mut rx)=mpsc::channel(4);dispatch_downstream(frame.clone(),false,&tx).await;assert!(rx.try_recv().is_err());
        dispatch_downstream(frame,true,&tx).await;
        let Event::Packet{origin:Some(first),..}=rx.recv().await.unwrap()else{panic!("missing origin")};
        let Event::Packet{origin:Some(second),..}=rx.recv().await.unwrap()else{panic!("missing origin")};
        assert!(Arc::ptr_eq(&first,&second));assert_eq!(first.relay_origin.as_deref(),Some(origin.stamp.as_str()));
        let mut legacy=vec![6];legacy.extend_from_slice(b"remote");legacy.extend_from_slice(&[0;20]);dispatch_downstream(legacy.into(),true,&tx).await;
        assert!(matches!(rx.recv().await.unwrap(),Event::Packet{origin:None,..}));
    }
}
