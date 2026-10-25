//! Private gateway fallback on the existing authenticated API port. Leases are
//! published only after private sync's final credential and membership check.
use crate::{
    domain::workspaces::token_digest,
    error::{ApiError, ApiResult},
    App,
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use porthub_mesh::RELAY_BATCH_MAGIC;
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
#[derive(Clone)]
struct Lease {
    credential_hash: String,
    hash: String,
    relay_token: String,
    instance: String,
    ip: Ipv4Addr,
    allowed: HashSet<String>,
    expires: Instant,
}
struct Connection {
    instance: String,
    generation: u64,
    output: mpsc::Sender<Vec<u8>>,
}
#[derive(Default)]
struct Inner {
    leases: HashMap<String, Lease>,
    connections: HashMap<String, Connection>,
    generation: u64,
    dropped_packets: AtomicU64,
}
#[derive(Default)]
pub struct Hub(Mutex<Inner>);
impl Hub {
    pub fn publish(
        &self,
        id: &str,
        hash: &str,
        instance: &str,
        ip: Ipv4Addr,
        allowed: HashSet<String>,
    ) -> String {
        let mut hub = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        hub.leases.retain(|_, lease| lease.expires > now);
        if hub.leases.len() >= 16384 && !hub.leases.contains_key(id) {
            return String::new();
        }
        let relay_token = hub
            .leases
            .get(id)
            .filter(|lease| {
                lease.expires > now && lease.credential_hash == hash && lease.instance == instance
            })
            .map(|lease| lease.relay_token.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());
        hub.leases.insert(
            id.into(),
            Lease {
                credential_hash: hash.into(),
                hash: token_digest(&relay_token),
                relay_token: relay_token.clone(),
                instance: instance.into(),
                ip,
                allowed,
                expires: now + Duration::from_secs(15),
            },
        );
        relay_token
    }
    pub(crate) fn peer_alive(&self, id: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .leases
            .get(id)
            .is_some_and(|lease| lease.expires > Instant::now())
    }
    pub(crate) fn pair_allowed(&self, source: &str, target: &str) -> bool {
        let hub = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        hub.leases
            .get(source)
            .is_some_and(|lease| lease.expires > now && lease.allowed.contains(target))
            && hub
                .leases
                .get(target)
                .is_some_and(|lease| lease.expires > now && lease.allowed.contains(source))
    }
    fn authorized(&self, id: &str, hash: &str, instance: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .leases
            .get(id)
            .is_some_and(|lease| {
                lease.expires > Instant::now()
                    && (lease.hash == hash || lease.credential_hash == hash)
                    && lease.instance == instance
            })
    }
    fn route(&self, source: &str, hash: &str, instance: &str, frame: &[u8]) {
        let mut records = Vec::with_capacity(32);
        if let Some(mut offset) = frame
            .strip_prefix(RELAY_BATCH_MAGIC)
            .map(|_| RELAY_BATCH_MAGIC.len())
        {
            while offset < frame.len() {
                if records.len() == 32 || frame.len() - offset < 2 {
                    return;
                }
                let length = usize::from(u16::from_be_bytes([frame[offset], frame[offset + 1]]));
                offset += 2;
                if length == 0 || length > 1441 || length > frame.len() - offset {
                    return;
                }
                records.push(&frame[offset..offset + length]);
                offset += length;
            }
            if records.is_empty() {
                return;
            }
        } else {
            records.push(frame);
        }
        let hub = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        for record in records {
            Self::route_record(&hub, source, hash, instance, record, now);
        }
    }
    fn route_record(
        hub: &Inner,
        source: &str,
        hash: &str,
        instance: &str,
        frame: &[u8],
        now: Instant,
    ) {
        let Some((&length, rest)) = frame.split_first() else {
            return;
        };
        let length = usize::from(length);
        if length == 0 || length > 60 || rest.len() < length + 20 || rest.len() > length + 1380 {
            return;
        }
        let Ok(target) = std::str::from_utf8(&rest[..length]) else {
            return;
        };
        let packet = &rest[length..];
        if packet[0] >> 4 != 4
            || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
        {
            return;
        }
        let Some(a) = hub.leases.get(source).filter(|a| {
            a.expires > now
                && (a.hash == hash || a.credential_hash == hash)
                && a.instance == instance
                && a.allowed.contains(target)
        }) else {
            return;
        };
        let Some(b) = hub
            .leases
            .get(target)
            .filter(|b| b.expires > now && b.allowed.contains(source))
        else {
            return;
        };
        if packet[12..16] != a.ip.octets() || packet[16..20] != b.ip.octets() {
            return;
        }
        let Some(connection) = hub
            .connections
            .get(target)
            .filter(|connection| connection.instance == b.instance)
        else {
            return;
        };
        let mut forwarded = Vec::with_capacity(1 + source.len() + packet.len());
        forwarded.push(source.len() as u8);
        forwarded.extend_from_slice(source.as_bytes());
        forwarded.extend_from_slice(packet);
        // Inner IP congestion control supplies reliability. An idle or slow
        // recipient cannot allocate unbounded gateway memory or block others.
        if connection.output.try_send(forwarded).is_err() {
            hub.dropped_packets.fetch_add(1, Ordering::Relaxed);
        }
    }
}
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/access/private/relay", get(upgrade))
        .route(
            "/api/access/private/relay/speedtest",
            get(crate::legacy_turn::speedtest).post(crate::legacy_turn::speedtest),
        )
}
fn header(headers: &HeaderMap, key: &str) -> ApiResult<String> {
    headers
        .get(key)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .map(String::from)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::FORBIDDEN,
                "Private relay authentication required",
            )
        })
}
async fn upgrade(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    if !headers.contains_key("x-porthub-peer") {
        if !app.config.private_transport.enabled() {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "Private relay unavailable",
            ));
        }
        return Ok(ws
            .read_buffer_size(8192)
            .write_buffer_size(8192)
            .max_write_buffer_size(131072)
            .max_message_size(65536)
            .max_frame_size(65536)
            .on_upgrade(move |socket| crate::legacy_turn::serve(app, socket)));
    }
    let id = header(&headers, "x-porthub-peer")?;
    let instance = header(&headers, "x-porthub-instance")?;
    let auth = header(&headers, "authorization")?;
    let token = auth.strip_prefix("Bearer ").ok_or_else(|| {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "Private relay authentication required",
        )
    })?;
    let hash = token_digest(token);
    if !app.private_relay.authorized(&id, &hash, &instance) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Private relay lease unavailable",
        ));
    }
    let batch = headers
        .get("x-porthub-relay-batch")
        .is_some_and(|value| value == "1");
    let mut response = ws
        .read_buffer_size(8192)
        .write_buffer_size(8192)
        .max_write_buffer_size(65536)
        .max_message_size(65536)
        .max_frame_size(65536)
        .on_upgrade(move |socket| serve(app, socket, id, hash, instance, batch));
    if batch {
        response
            .headers_mut()
            .insert("x-porthub-relay-batch", HeaderValue::from_static("1"));
    }
    Ok(response)
}
async fn serve(
    app: Arc<App>,
    mut socket: WebSocket,
    id: String,
    hash: String,
    instance: String,
    batch: bool,
) {
    let (generation, mut packets) = {
        let mut hub = app
            .private_relay
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if hub.connections.len() >= 4096 && !hub.connections.contains_key(&id) {
            return;
        }
        let active = hub
            .connections
            .len()
            .saturating_sub(usize::from(hub.connections.contains_key(&id)))
            + 1;
        let capacity = relay_queue_capacity(active);
        let (output, packets) = mpsc::channel(capacity);
        hub.generation = hub.generation.wrapping_add(1);
        let generation = hub.generation;
        hub.connections.insert(
            id.clone(),
            Connection {
                instance: instance.clone(),
                generation,
                output,
            },
        );
        (generation, packets)
    };
    let mut lease_check = tokio::time::interval(Duration::from_secs(5));
    let mut drop_report = tokio::time::interval(Duration::from_secs(10));
    drop_report.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _=lease_check.tick()=>{if !app.private_relay.authorized(&id,&hash,&instance){break;}},
            _=drop_report.tick()=>{
                let dropped=app.private_relay.0.lock().unwrap_or_else(|p|p.into_inner()).dropped_packets.swap(0,Ordering::Relaxed);
                if dropped>0 {tracing::warn!(dropped_packets=dropped,"private relay gateway queue overflowed");}
            },
            frame=socket.recv()=>match frame {Some(Ok(Message::Binary(bytes)))=>app.private_relay.route(&id,&hash,&instance,&bytes),Some(Ok(Message::Ping(bytes)))=>{if !matches!(tokio::time::timeout(Duration::from_secs(3),socket.send(Message::Pong(bytes))).await,Ok(Ok(()))){break;}},Some(Ok(Message::Pong(_)))=>{},_=>break},
            packet=packets.recv()=>{
                let Some(packet)=packet else{break;};
                if !app.private_relay.authorized(&id,&hash,&instance){break;}
                let mut output=packet;
                if batch {
                    let mut records=vec![output];
                    while records.len()<32 {
                        match packets.try_recv(){Ok(packet)=>records.push(packet),Err(_)=>break}
                    }
                    output=Vec::with_capacity(4+records.iter().map(|p|2+p.len()).sum::<usize>());
                    output.extend_from_slice(RELAY_BATCH_MAGIC);
                    for record in records {
                        output.extend_from_slice(&(record.len() as u16).to_be_bytes());
                        output.extend_from_slice(&record);
                    }
                }
                if !matches!(tokio::time::timeout(Duration::from_secs(3),socket.send(Message::Binary(output.into()))).await,Ok(Ok(()))){break;}
            }
        }
    }
    let mut hub = app
        .private_relay
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if hub
        .connections
        .get(&id)
        .is_some_and(|connection| connection.generation == generation)
    {
        hub.connections.remove(&id);
    }
}

const MIN_RELAY_QUEUE_PACKETS: usize = 128;
const MAX_RELAY_QUEUE_PACKETS: usize = 2048;
// Keep the worst-case queued packet budget at or below the old 4096 x 128 cap.
const MAX_RELAY_QUEUE_BUDGET: usize = 4096 * MIN_RELAY_QUEUE_PACKETS;
fn relay_queue_capacity(active_connections: usize) -> usize {
    (MAX_RELAY_QUEUE_BUDGET / active_connections.max(1))
        .clamp(MIN_RELAY_QUEUE_PACKETS, MAX_RELAY_QUEUE_PACKETS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_queue_capacity_grows_for_few_peers_without_increasing_global_bound() {
        assert_eq!(relay_queue_capacity(1), MAX_RELAY_QUEUE_PACKETS);
        assert_eq!(relay_queue_capacity(256), MAX_RELAY_QUEUE_PACKETS);
        assert_eq!(relay_queue_capacity(512), 1024);
        assert_eq!(relay_queue_capacity(4096), MIN_RELAY_QUEUE_PACKETS);
    }

    #[test]
    fn relay_credentials_are_ephemeral_and_stable_for_a_live_instance() {
        let hub = Hub::default();
        let allowed = HashSet::new();
        let token = hub.publish(
            "peer",
            "stored-machine-credential-hash",
            "instance-a",
            Ipv4Addr::LOCALHOST,
            allowed.clone(),
        );
        assert_eq!(token.len(), 32);
        assert!(hub.authorized("peer", &token_digest(&token), "instance-a"));
        assert!(hub.authorized("peer", "stored-machine-credential-hash", "instance-a"));
        assert_eq!(
            token,
            hub.publish(
                "peer",
                "stored-machine-credential-hash",
                "instance-a",
                Ipv4Addr::LOCALHOST,
                allowed.clone(),
            )
        );
        let replacement = hub.publish(
            "peer",
            "stored-machine-credential-hash",
            "instance-b",
            Ipv4Addr::LOCALHOST,
            allowed,
        );
        assert_ne!(token, replacement);
        assert!(!hub.authorized("peer", &token_digest(&token), "instance-a"));
        assert!(hub.authorized("peer", &token_digest(&replacement), "instance-b"));
    }

    #[test]
    fn batched_and_legacy_frames_route_the_same_way() {
        let hub = Hub::default();
        let a_ip = Ipv4Addr::new(10, 0, 0, 1);
        let b_ip = Ipv4Addr::new(10, 0, 0, 2);
        let a = hub.publish(
            "peer-a",
            "credential-a",
            "instance-a",
            a_ip,
            HashSet::from(["peer-b".to_owned()]),
        );
        hub.publish(
            "peer-b",
            "credential-b",
            "instance-b",
            b_ip,
            HashSet::from(["peer-a".to_owned()]),
        );
        let (output, mut received) = mpsc::channel(8);
        hub.0.lock().unwrap().connections.insert(
            "peer-b".into(),
            Connection {
                instance: "instance-b".into(),
                generation: 1,
                output,
            },
        );
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        packet[8] = 64;
        packet[12..16].copy_from_slice(&a_ip.octets());
        packet[16..20].copy_from_slice(&b_ip.octets());
        let mut record = vec![6];
        record.extend_from_slice(b"peer-b");
        record.extend_from_slice(&packet);
        let mut batch = RELAY_BATCH_MAGIC.to_vec();
        for _ in 0..2 {
            batch.extend_from_slice(&(record.len() as u16).to_be_bytes());
            batch.extend_from_slice(&record);
        }
        hub.route("peer-a", &token_digest(&a), "instance-a", &batch);
        hub.route("peer-a", &token_digest(&a), "instance-a", &record);
        for _ in 0..3 {
            let forwarded = received.try_recv().expect("forwarded packet");
            assert_eq!(forwarded[0], 6);
            assert_eq!(&forwarded[1..7], b"peer-a");
            assert_eq!(&forwarded[7..], &packet);
        }
    }
}
