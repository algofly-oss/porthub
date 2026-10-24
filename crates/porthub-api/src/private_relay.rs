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
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
#[derive(Clone)]
struct Lease {
    hash: String,
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
    ) {
        let mut hub = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        hub.leases.retain(|_, lease| lease.expires > now);
        if hub.leases.len() >= 16384 && !hub.leases.contains_key(id) {
            return;
        }
        hub.leases.insert(
            id.into(),
            Lease {
                hash: hash.into(),
                instance: instance.into(),
                ip,
                allowed,
                expires: now + Duration::from_secs(15),
            },
        );
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
                lease.expires > Instant::now() && lease.hash == hash && lease.instance == instance
            })
    }
    fn route(&self, source: &str, hash: &str, instance: &str, frame: &[u8]) {
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
        let hub = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let Some(a) = hub.leases.get(source).filter(|a| {
            a.expires > now
                && a.hash == hash
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
        let _ = connection.output.try_send(forwarded);
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
    Ok(ws
        .read_buffer_size(8192)
        .write_buffer_size(8192)
        .max_write_buffer_size(32768)
        .max_message_size(1500)
        .max_frame_size(1500)
        .on_upgrade(move |socket| serve(app, socket, id, hash, instance)))
}
async fn serve(app: Arc<App>, mut socket: WebSocket, id: String, hash: String, instance: String) {
    let (output, mut packets) = mpsc::channel(128);
    let generation = {
        let mut hub = app
            .private_relay
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if hub.connections.len() >= 4096 && !hub.connections.contains_key(&id) {
            return;
        }
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
        generation
    };
    let mut lease_check = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _=lease_check.tick()=>{if !app.private_relay.authorized(&id,&hash,&instance){break;}},
            frame=socket.recv()=>match frame {Some(Ok(Message::Binary(bytes)))=>app.private_relay.route(&id,&hash,&instance,&bytes),Some(Ok(Message::Ping(bytes)))=>{if !matches!(tokio::time::timeout(Duration::from_secs(3),socket.send(Message::Pong(bytes))).await,Ok(Ok(()))){break;}},Some(Ok(Message::Pong(_)))=>{},_=>break},
            packet=packets.recv()=>{let Some(packet)=packet else{break;};if !app.private_relay.authorized(&id,&hash,&instance) || !matches!(tokio::time::timeout(Duration::from_secs(3),socket.send(Message::Binary(packet.into()))).await,Ok(Ok(()))){break;}}
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
