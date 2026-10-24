//! Standard TURN over the existing WebSocket endpoint for enrolled legacy
//! peers. All allocations are virtual memory channels; no UDP sockets or
//! arbitrary loopback/Internet destinations are reachable through this relay.
use crate::App;
use anyhow::{ensure, Result};
use async_trait::async_trait;
use axum::extract::ws::{Message, WebSocket};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
    time::Duration,
};
use tokio::sync::{mpsc, Mutex as AsyncMutex, Semaphore};
use tokio_util::sync::CancellationToken;
use turn_util::{Conn, Error as IoError, Result as IoResult};
type TurnResult<T> = std::result::Result<T, turn::Error>;
struct Entry {
    generation: u64,
    connection: Weak<Memory>,
}
struct Allocations {
    next: u16,
    generation: u64,
    entries: HashMap<u16, Entry>,
}
pub struct Network {
    allocations: Mutex<Allocations>,
    pub connections: Arc<Semaphore>,
    noise: std::sync::OnceLock<axum::body::Bytes>,
}
impl Default for Network {
    fn default() -> Self {
        Self {
            allocations: Mutex::new(Allocations {
                next: 20000,
                generation: 0,
                entries: HashMap::new(),
            }),
            connections: Arc::new(Semaphore::new(512)),
            noise: Default::default(),
        }
    }
}
#[derive(Default)]
struct Authentication {
    peer: Mutex<Option<String>>,
    proved: AtomicBool,
}
struct RestAuth {
    app: Arc<App>,
    state: Arc<Authentication>,
}
impl turn::auth::AuthHandler for RestAuth {
    fn auth_handle(&self, username: &str, realm: &str, _source: SocketAddr) -> TurnResult<Vec<u8>> {
        let invalid = || turn::Error::Other("private relay authentication required".into());
        if realm != "porthub" {
            return Err(invalid());
        }
        let password = self
            .app
            .config
            .private_transport
            .turn_password(username)
            .ok_or_else(invalid)?;
        let (_, peer) = username.split_once(':').ok_or_else(invalid)?;
        if !self.app.private_relay.peer_alive(peer) {
            return Err(invalid());
        }
        let mut current = self.state.peer.lock().unwrap_or_else(|p| p.into_inner());
        if current.as_ref().is_some_and(|current| current != peer) {
            return Err(invalid());
        }
        *current = Some(peer.into());
        Ok(turn::auth::generate_auth_key(username, realm, &password))
    }
}
struct Allocator {
    app: Arc<App>,
    authentication: Arc<Authentication>,
}
#[async_trait]
impl turn::relay::RelayAddressGenerator for Allocator {
    fn validate(&self) -> TurnResult<()> {
        Ok(())
    }
    async fn allocate_conn(
        &self,
        use_ipv4: bool,
        requested: u16,
    ) -> TurnResult<(Arc<dyn Conn + Send + Sync>, SocketAddr)> {
        if !use_ipv4 {
            return Err(turn::Error::Other(
                "only private IPv4 relay allocations are supported".into(),
            ));
        }
        let peer = self
            .authentication
            .peer
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .ok_or_else(|| turn::Error::Other("private relay identity missing".into()))?;
        if !self.app.private_relay.peer_alive(&peer) {
            return Err(turn::Error::Other("private relay lease expired".into()));
        }
        let connection = {
            let mut allocations = self
                .app
                .legacy_turn
                .allocations
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let mut port = requested;
            let available = |allocations: &Allocations, port: u16| {
                (20000..65000).contains(&port)
                    && allocations
                        .entries
                        .get(&port)
                        .is_none_or(|entry| entry.connection.strong_count() == 0)
            };
            if !available(&allocations, port) {
                let mut found = false;
                for _ in 20000..65000 {
                    port = allocations.next;
                    allocations.next = if port >= 64999 { 20000 } else { port + 1 };
                    if available(&allocations, port) {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(turn::Error::Other("private relay capacity reached".into()));
                }
            }
            allocations.generation = allocations.generation.wrapping_add(1);
            let generation = allocations.generation;
            let (sender, receiver) = mpsc::channel(8192);
            let connection = Arc::new(Memory {
                app: self.app.clone(),
                peer,
                port,
                generation,
                sender,
                receiver: AsyncMutex::new(receiver),
                cancel: CancellationToken::new(),
            });
            allocations.entries.insert(
                port,
                Entry {
                    generation,
                    connection: Arc::downgrade(&connection),
                },
            );
            connection
        };
        // allocate_conn is reached only after TURN MESSAGE-INTEGRITY succeeds.
        self.authentication.proved.store(true, Ordering::Release);
        let address = connection.local_addr()?;
        Ok((connection, address))
    }
}
struct Packet {
    bytes: Vec<u8>,
    source: SocketAddr,
}
struct Memory {
    app: Arc<App>,
    peer: String,
    port: u16,
    generation: u64,
    sender: mpsc::Sender<Packet>,
    receiver: AsyncMutex<mpsc::Receiver<Packet>>,
    cancel: CancellationToken,
}
impl Memory {
    fn release(&self) {
        self.cancel.cancel();
        let mut allocations = self
            .app
            .legacy_turn
            .allocations
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if allocations
            .entries
            .get(&self.port)
            .is_some_and(|entry| entry.generation == self.generation)
        {
            allocations.entries.remove(&self.port);
        }
    }
}
impl Drop for Memory {
    fn drop(&mut self) {
        self.release();
    }
}
#[async_trait]
impl Conn for Memory {
    async fn connect(&self, _: SocketAddr) -> IoResult<()> {
        Err(IoError::ErrNoRemAddr)
    }
    async fn recv(&self, buffer: &mut [u8]) -> IoResult<usize> {
        Ok(self.recv_from(buffer).await?.0)
    }
    async fn recv_from(&self, buffer: &mut [u8]) -> IoResult<(usize, SocketAddr)> {
        let mut input = self.receiver.lock().await;
        let packet = tokio::select! {_=self.cancel.cancelled()=>return Err(IoError::ErrUseClosedNetworkConn),packet=input.recv()=>packet.ok_or(IoError::ErrUseClosedNetworkConn)?};
        if packet.bytes.len() > buffer.len() {
            return Err(IoError::ErrPacketTooBig);
        }
        buffer[..packet.bytes.len()].copy_from_slice(&packet.bytes);
        Ok((packet.bytes.len(), packet.source))
    }
    async fn send(&self, _: &[u8]) -> IoResult<usize> {
        Err(IoError::ErrNoRemAddr)
    }
    async fn send_to(&self, buffer: &[u8], target: SocketAddr) -> IoResult<usize> {
        if self.cancel.is_cancelled() {
            return Err(IoError::ErrUseClosedNetworkConn);
        }
        if target.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Ok(buffer.len());
        }
        let target = {
            self.app
                .legacy_turn
                .allocations
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entries
                .get(&target.port())
                .and_then(|entry| entry.connection.upgrade())
        };
        if let Some(target) = target {
            if self
                .app
                .private_relay
                .pair_allowed(&self.peer, &target.peer)
            {
                let packet = Packet {
                    bytes: buffer.into(),
                    source: self.local_addr()?,
                };
                let _ = tokio::time::timeout(Duration::from_millis(50), target.sender.send(packet))
                    .await;
            }
        }
        Ok(buffer.len())
    }
    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, self.port)))
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }
    async fn close(&self) -> IoResult<()> {
        self.release();
        Ok(())
    }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}
struct Transport {
    input: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    output: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
}
#[async_trait]
impl Conn for Transport {
    async fn connect(&self, _: SocketAddr) -> IoResult<()> {
        Ok(())
    }
    async fn recv(&self, buffer: &mut [u8]) -> IoResult<usize> {
        Ok(self.recv_from(buffer).await?.0)
    }
    async fn recv_from(&self, buffer: &mut [u8]) -> IoResult<(usize, SocketAddr)> {
        let mut input = self.input.lock().await;
        let packet = tokio::select! {_=self.cancel.cancelled()=>return Err(IoError::ErrUseClosedNetworkConn),packet=input.recv()=>packet.ok_or(IoError::ErrUseClosedNetworkConn)?};
        if packet.len() > buffer.len() {
            return Err(IoError::ErrPacketTooBig);
        }
        buffer[..packet.len()].copy_from_slice(&packet);
        Ok((packet.len(), SocketAddr::from((Ipv4Addr::LOCALHOST, 1))))
    }
    async fn send(&self, buffer: &[u8]) -> IoResult<usize> {
        self.send_to(buffer, SocketAddr::from((Ipv4Addr::LOCALHOST, 1)))
            .await
    }
    async fn send_to(&self, buffer: &[u8], _: SocketAddr) -> IoResult<usize> {
        tokio::select! {_=self.cancel.cancelled()=>return Err(IoError::ErrUseClosedNetworkConn),result=self.output.send(buffer.into())=>result.map_err(|_|IoError::ErrUseClosedNetworkConn)?};
        Ok(buffer.len())
    }
    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)))
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 1)))
    }
    async fn close(&self) -> IoResult<()> {
        self.cancel.cancel();
        Ok(())
    }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}
#[derive(Default)]
pub struct Framing {
    bytes: Vec<u8>,
}
impl Framing {
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            self.bytes.len() + bytes.len() <= 65536,
            "TURN stream frame exceeds limit"
        );
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    pub fn packet(&mut self) -> Result<Option<Vec<u8>>> {
        if self.bytes.len() < 4 {
            return Ok(None);
        }
        let length = usize::from(u16::from_be_bytes([self.bytes[2], self.bytes[3]]));
        let size = match self.bytes[0] & 0xc0 {
            0 => {
                ensure!(length % 4 == 0, "invalid STUN length");
                20 + length
            }
            0x40 => (4 + length + 3) & !3,
            _ => anyhow::bail!("invalid TURN stream frame"),
        };
        ensure!(size <= 65536, "TURN packet exceeds limit");
        if self.bytes.len() < size {
            return Ok(None);
        }
        Ok(Some(self.bytes.drain(..size).collect()))
    }
}
pub async fn serve(app: Arc<App>, mut socket: WebSocket) {
    let Ok(_permit) = app.legacy_turn.connections.clone().try_acquire_owned() else {
        return;
    };
    let authentication = Arc::new(Authentication::default());
    let cancel = CancellationToken::new();
    let (input, input_rx) = mpsc::channel(128);
    let (output, mut output_rx) = mpsc::channel(128);
    let transport = Arc::new(Transport {
        input: AsyncMutex::new(input_rx),
        output,
        cancel: cancel.clone(),
    });
    let config = turn::server::config::ServerConfig {
        conn_configs: vec![turn::server::config::ConnConfig {
            conn: transport,
            relay_addr_generator: Box::new(Allocator {
                app: app.clone(),
                authentication: authentication.clone(),
            }),
        }],
        realm: "porthub".into(),
        auth_handler: Arc::new(RestAuth {
            app: app.clone(),
            state: authentication.clone(),
        }),
        channel_bind_timeout: Duration::from_secs(600),
        alloc_close_notify: None,
    };
    let Ok(server) = turn::server::Server::new(config).await else {
        return;
    };
    let started = std::time::Instant::now();
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    let mut framing = Framing::default();
    let outcome:Result<()>=async {loop {tokio::select! {
        _=interval.tick()=>{
            let peer=authentication.peer.lock().unwrap_or_else(|p|p.into_inner()).clone();
            if authentication.proved.load(Ordering::Acquire) {if !peer.is_some_and(|peer|app.private_relay.peer_alive(&peer)){break;}}
            else if started.elapsed()>Duration::from_secs(10){break;}
        },
        packet=output_rx.recv()=>{let Some(packet)=packet else{break;};tokio::time::timeout(Duration::from_secs(5),socket.send(Message::Binary(packet.into()))).await??;},
        frame=socket.recv()=>match frame {
            Some(Ok(Message::Binary(bytes)))=>{framing.push(&bytes)?;while let Some(packet)=framing.packet()? {tokio::time::timeout(Duration::from_secs(5),input.send(packet)).await??;}},
            Some(Ok(Message::Ping(bytes)))=>{tokio::time::timeout(Duration::from_secs(5),socket.send(Message::Pong(bytes))).await??;},
            Some(Ok(Message::Pong(_)))=>{},_=>break,
        }
    }}Ok(())}.await;
    let _ = outcome;
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(3), server.close()).await;
}

/// Legacy clients measure relay routes using their short-lived TURN identity.
/// This does not expose an unauthenticated download/upload endpoint.
pub async fn speedtest(
    axum::extract::State(app): axum::extract::State<Arc<App>>,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
    request: axum::extract::Request,
) -> crate::error::ApiResult<axum::response::Response> {
    use axum::{
        body::Body,
        http::{header, Method, StatusCode},
        response::IntoResponse,
    };
    use futures_util::StreamExt;
    let denied =
        || crate::error::ApiError::new(StatusCode::FORBIDDEN, "Private relay credential required");
    let username = request
        .headers()
        .get("x-relay-user")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 128)
        .ok_or_else(denied)?;
    let credential = request
        .headers()
        .get("x-relay-credential")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 128)
        .ok_or_else(denied)?;
    if !app
        .config
        .private_transport
        .verify_turn_credential(username, credential)
    {
        return Err(denied());
    }
    let (_, peer) = username.split_once(':').ok_or_else(denied)?;
    if !app.private_relay.peer_alive(peer) {
        return Err(denied());
    }
    let permit = app
        .legacy_turn
        .connections
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            crate::error::ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "Private relay busy")
        })?;
    const MAX: usize = 32 * 1024 * 1024;
    if request.method() == Method::GET {
        let count = query
            .get("bytes")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0)
            .min(MAX);
        let noise = app
            .legacy_turn
            .noise
            .get_or_init(|| {
                use rand::RngCore;
                let mut bytes = vec![0; 1024 * 1024];
                rand::thread_rng().fill_bytes(&mut bytes);
                bytes.into()
            })
            .clone();
        let stream = futures_util::stream::unfold(
            (noise, count, permit),
            |(noise, remaining, permit)| async move {
                if remaining == 0 {
                    return None;
                }
                let size = remaining.min(noise.len());
                let bytes = noise.slice(..size);
                Some((
                    Ok::<_, std::io::Error>(bytes),
                    (noise, remaining - size, permit),
                ))
            },
        );
        return Ok((
            [
                (header::CACHE_CONTROL, "private, no-store, no-transform"),
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CONTENT_LENGTH, &count.to_string()),
            ],
            Body::from_stream(stream),
        )
            .into_response());
    }
    if request.method() == Method::POST {
        let mut input = request.into_body().into_data_stream();
        let mut count = 0;
        while let Some(chunk) = input.next().await {
            let chunk = chunk
                .map_err(|_| crate::error::ApiError::bad_request("Invalid speed-test body"))?;
            count = (count + chunk.len()).min(MAX);
            if count == MAX {
                break;
            }
        }
        return Ok((
            [(header::CACHE_CONTROL, "private, no-store")],
            count.to_string(),
        )
            .into_response());
    }
    Err(crate::error::ApiError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "Method not allowed",
    ))
}
