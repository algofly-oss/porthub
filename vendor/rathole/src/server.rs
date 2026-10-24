use crate::config::{Config, ServerConfig, ServerServiceConfig, ServiceType, TransportType};
use crate::config_watcher::{ConfigChange, ServerServiceChange};
use crate::constants::{listen_backoff, UDP_BUFFER_SIZE};
use crate::helper::retry_notify_with_deadline;
use crate::multi_map::MultiMap;
use crate::protocol::Hello::{ControlChannelHello, DataChannelHello};
use crate::protocol::{
    self, read_auth, read_hello, Ack, ControlChannelCmd, DataChannelCmd, Hello, UdpTraffic,
    HASH_WIDTH_IN_BYTES,
};
use crate::transport::{SocketOpts, TcpTransport, Transport};
use anyhow::{anyhow, bail, Context, Result};
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;

use rand::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tokio::time;
use tracing::{debug, error, info, info_span, instrument, warn, Instrument, Span};

#[cfg(feature = "noise")]
use crate::transport::NoiseTransport;
#[cfg(feature = "tls")]
use crate::transport::TlsTransport;
#[cfg(feature = "websocket")]
use crate::transport::WebsocketTransport;

type ServiceDigest = protocol::Digest; // SHA256 of a service name
type Nonce = protocol::Digest; // Also called `session_key`

const TCP_POOL_SIZE: usize = 8; // The number of cached connections for TCP servies
const UDP_POOL_SIZE: usize = 2; // The number of cached connections for UDP services
const CHAN_SIZE: usize = 2048; // The capacity of various chans
const HANDSHAKE_TIMEOUT: u64 = 5; // Timeout for transport handshake

/// PortHub's in-process server. The owning HTTP server supplies byte streams;
/// Rathole retains authentication, connection pooling and TCP/UDP forwarding.
pub struct EmbeddedServer {
    inner: Server<crate::transport::embedded::EmbeddedTransport>,
}

impl EmbeddedServer {
    pub async fn new(config: Config) -> Result<Self> {
        let config = config.server.context("missing server configuration")?;
        Ok(Self {
            inner: Server::from(config).await?,
        })
    }

    /// Call under the owner's read lock, then spawn the returned future. The
    /// read lock must not be held for the lifetime of a tunnel.
    pub fn accept(
        &self,
        stream: Box<dyn crate::transport::embedded::TunnelIo>,
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'static {
        let services = self.inner.services.clone();
        let channels = self.inner.control_channels.clone();
        let config = self.inner.config.clone();
        async move {
            handle_connection::<crate::transport::embedded::EmbeddedTransport>(
                stream, services, channels, config,
            )
            .await
        }
    }

    /// Revoke removed/changed services without disturbing unchanged sessions.
    pub async fn reload(&mut self, config: Config) -> Result<()> {
        let next = config.server.context("missing server configuration")?;
        if self.inner.config.heartbeat_interval != next.heartbeat_interval {
            bail!("changing heartbeat_interval requires restarting the edge")
        }
        self.inner.finish_closing().await?;
        let previous = self.inner.services.read().await.clone();
        let wanted = generate_service_hashmap(&next);
        for (digest, service) in &previous {
            if !wanted.contains_key(digest) {
                self.inner
                    .handle_hot_reload(ConfigChange::ServerChange(ServerServiceChange::Delete(
                        service.name.clone(),
                    )))
                    .await?;
            }
        }
        for (digest, service) in wanted {
            if previous.get(&digest) != Some(&service) {
                self.inner
                    .handle_hot_reload(ConfigChange::ServerChange(ServerServiceChange::Add(
                        service,
                    )))
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn shutdown(&mut self) {
        let digests = {
            let mut services = self.inner.services.write().await;
            let digests: Vec<_> = services.keys().copied().collect();
            services.clear();
            digests
        };
        {
            let mut channels = self.inner.control_channels.write().await;
            for digest in digests {
                if let Some(handle) = channels.remove1(&digest) {
                    self.inner.closing.push(handle);
                }
            }
        }
        if let Err(error) = self.inner.finish_closing().await {
            error!(%error, "embedded service shutdown failed");
        }
    }
}

// The entrypoint of running a server
pub async fn run_server(
    config: Config,
    shutdown_rx: broadcast::Receiver<bool>,
    update_rx: mpsc::Receiver<ConfigChange>,
) -> Result<()> {
    let config = match config.server {
            Some(config) => config,
            None => {
                return Err(anyhow!("Try to run as a server, but the configuration is missing. Please add the `[server]` block"))
            }
        };

    match config.transport.transport_type {
        TransportType::Tcp => {
            let mut server = Server::<TcpTransport>::from(config).await?;
            server.run(shutdown_rx, update_rx).await?;
        }
        TransportType::Tls => {
            #[cfg(feature = "tls")]
            {
                let mut server = Server::<TlsTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(feature = "tls"))]
            crate::helper::feature_not_compile("tls")
        }
        TransportType::Noise => {
            #[cfg(feature = "noise")]
            {
                let mut server = Server::<NoiseTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(feature = "noise"))]
            crate::helper::feature_not_compile("noise")
        }
        TransportType::Websocket => {
            #[cfg(feature = "websocket")]
            {
                let mut server = Server::<WebsocketTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(feature = "websocket"))]
            crate::helper::feature_not_compile("websocket")
        }
    }

    Ok(())
}

// A hash map of ControlChannelHandles, indexed by ServiceDigest or Nonce
// See also MultiMap
type ControlChannelMap<T> = MultiMap<ServiceDigest, Nonce, ControlChannelHandle<T>>;

// Server holds all states of running a server
struct Server<T: Transport> {
    // `[server]` config
    config: Arc<ServerConfig>,

    // `[server.services]` config, indexed by ServiceDigest
    services: Arc<RwLock<HashMap<ServiceDigest, ServerServiceConfig>>>,
    // Collection of contorl channels
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    // Wrapper around the transport layer
    transport: Arc<T>,
    // Retain ownership across cancellation of a reload/IPC request. A retry
    // must still await sockets belonging to an earlier interrupted revocation.
    closing: Vec<ControlChannelHandle<T>>,
}

// Generate a hash map of services which is indexed by ServiceDigest
fn generate_service_hashmap(
    server_config: &ServerConfig,
) -> HashMap<ServiceDigest, ServerServiceConfig> {
    let mut ret = HashMap::new();
    for u in &server_config.services {
        ret.insert(protocol::digest(u.0.as_bytes()), (*u.1).clone());
    }
    ret
}

impl<T: 'static + Transport> Server<T> {
    // Create a server from `[server]`
    pub async fn from(config: ServerConfig) -> Result<Server<T>> {
        let config = Arc::new(config);
        let services = Arc::new(RwLock::new(generate_service_hashmap(&config)));
        let control_channels = Arc::new(RwLock::new(ControlChannelMap::new()));
        let transport = Arc::new(T::new(&config.transport)?);
        Ok(Server {
            config,
            services,
            control_channels,
            transport,
            closing: Vec::new(),
        })
    }

    // The entry point of Server
    pub async fn run(
        &mut self,
        mut shutdown_rx: broadcast::Receiver<bool>,
        mut update_rx: mpsc::Receiver<ConfigChange>,
    ) -> Result<()> {
        // Listen at `server.bind_addr`
        let l = self
            .transport
            .bind(&self.config.bind_addr)
            .await
            .with_context(|| "Failed to listen at `server.bind_addr`")?;
        info!("Listening at {}", self.config.bind_addr);

        // Retry at least every 100ms
        let mut backoff = ExponentialBackoff {
            max_interval: Duration::from_millis(100),
            max_elapsed_time: None,
            ..Default::default()
        };

        // Wait for connections and shutdown signals
        loop {
            tokio::select! {
                // Wait for incoming control and data channels
                ret = self.transport.accept(&l) => {
                    match ret {
                        Err(err) => {
                            // Detects whether it's an IO error
                            if let Some(err) = err.downcast_ref::<io::Error>() {
                                // If it is an IO error, then it's possibly an
                                // EMFILE. So sleep for a while and retry
                                // TODO: Only sleep for EMFILE, ENFILE, ENOMEM, ENOBUFS
                                if let Some(d) = backoff.next_backoff() {
                                    error!("Failed to accept: {:#}. Retry in {:?}...", err, d);
                                    time::sleep(d).await;
                                } else {
                                    // This branch will never be executed according to the current retry policy
                                    error!("Too many retries. Aborting...");
                                    break;
                                }
                            }
                            // If it's not an IO error, then it comes from
                            // the transport layer, so just ignore it
                        }
                        Ok((conn, addr)) => {
                            backoff.reset();

                            // Do transport handshake with a timeout
                            match time::timeout(Duration::from_secs(HANDSHAKE_TIMEOUT), self.transport.handshake(conn)).await {
                                Ok(conn) => {
                                    match conn.with_context(|| "Failed to do transport handshake") {
                                        Ok(conn) => {
                                            let services = self.services.clone();
                                            let control_channels = self.control_channels.clone();
                                            let server_config = self.config.clone();
                                            tokio::spawn(async move {
                                                if let Err(err) = handle_connection(conn, services, control_channels, server_config).await {
                                                    error!("{:#}", err);
                                                }
                                            }.instrument(info_span!("connection", %addr)));
                                        }, Err(e) => {
                                            error!("{:#}", e);
                                        }
                                    }
                                },
                                Err(e) => {
                                    error!("Transport handshake timeout: {}", e);
                                }
                            }
                        }
                    }
                },
                // Wait for the shutdown signal
                _ = shutdown_rx.recv() => {
                    info!("Shuting down gracefully...");
                    break;
                },
                e = update_rx.recv() => {
                    if let Some(e) = e {
                        self.handle_hot_reload(e).await?;
                    }
                }
            }
        }

        info!("Shutdown");

        Ok(())
    }

    async fn handle_hot_reload(&mut self, e: ConfigChange) -> Result<()> {
        self.finish_closing().await?;
        let hash = match e {
            ConfigChange::ServerChange(server_change) => match server_change {
                ServerServiceChange::Add(cfg) => {
                    let hash = protocol::digest(cfg.name.as_bytes());
                    self.services.write().await.insert(hash, cfg);
                    hash
                }
                ServerServiceChange::Delete(s) => {
                    let hash = protocol::digest(s.as_bytes());
                    let _ = self.services.write().await.remove(&hash);
                    hash
                }
            },
            ignored => {
                warn!("Ignored {:?} since running as a server", ignored);
                return Ok(());
            }
        };
        let previous = self.control_channels.write().await.remove1(&hash);
        if let Some(handle) = previous {
            self.closing.push(handle);
        }
        self.finish_closing().await
    }

    async fn finish_closing(&mut self) -> Result<()> {
        let mut failure = None;
        while let Some(handle) = self.closing.last_mut() {
            let result = handle.close().await;
            self.closing.pop();
            if let Err(error) = result {
                failure = Some(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

// Handle connections to `server.bind_addr`
async fn handle_connection<T: 'static + Transport>(
    mut conn: T::Stream,
    services: Arc<RwLock<HashMap<ServiceDigest, ServerServiceConfig>>>,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    server_config: Arc<ServerConfig>,
) -> Result<()> {
    // Read hello
    let hello = read_hello(&mut conn).await?;
    match hello {
        ControlChannelHello(_, service_digest) => {
            do_control_channel_handshake(
                conn,
                services,
                control_channels,
                service_digest,
                server_config,
            )
            .await?;
        }
        DataChannelHello(_, nonce) => {
            do_data_channel_handshake(conn, control_channels, nonce).await?;
        }
    }
    Ok(())
}

async fn do_control_channel_handshake<T: 'static + Transport>(
    mut conn: T::Stream,
    services: Arc<RwLock<HashMap<ServiceDigest, ServerServiceConfig>>>,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    service_digest: ServiceDigest,
    server_config: Arc<ServerConfig>,
) -> Result<()> {
    info!("Try to handshake a control channel");

    T::hint(&conn, SocketOpts::for_control_channel());

    // Generate a nonce
    let mut nonce = vec![0u8; HASH_WIDTH_IN_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Send hello
    let hello_send = Hello::ControlChannelHello(
        protocol::CURRENT_PROTO_VERSION,
        nonce.clone().try_into().unwrap(),
    );
    conn.write_all(&bincode::serialize(&hello_send).unwrap())
        .await?;
    conn.flush().await?;

    // Lookup the service
    let service_config = match services.read().await.get(&service_digest) {
        Some(v) => v,
        None => {
            conn.write_all(&bincode::serialize(&Ack::ServiceNotExist).unwrap())
                .await?;
            conn.flush().await?;
            bail!("No such a service {}", hex::encode(service_digest));
        }
    }
    .to_owned();

    let service_name = &service_config.name;

    // Calculate the checksum
    let mut concat = Vec::from(service_config.token.as_ref().unwrap().as_bytes());
    concat.append(&mut nonce);

    // Read auth
    let protocol::Auth(d) = read_auth(&mut conn).await?;

    // Validate
    let session_key = protocol::digest(&concat);
    if session_key != d {
        conn.write_all(&bincode::serialize(&Ack::AuthFailed).unwrap())
            .await?;
        conn.flush().await?;
        debug!(
            "Expect {}, but got {}",
            hex::encode(session_key),
            hex::encode(d)
        );
        bail!("Service {} failed the authentication", service_name);
    } else {
        // A removal/token rotation may have raced this handshake. Hold the
        // service read guard until the authenticated handle is registered.
        let current_services = services.read().await;
        if current_services.get(&service_digest) != Some(&service_config) {
            bail!("Service changed during authentication");
        }
        let mut h = control_channels.write().await;

        // Replace an existing control channel, retaining established TCP copies.
        // Because a control channel doesn't report back when it's dead,
        // the handle in the map could be stall, dropping the old handle enables
        // the client to reconnect.
        if let Some(previous) = h.get1_mut(&service_digest) {
            warn!(
                "Replacing previous control channel for service {}",
                service_name
            );
            previous.retire().await;
        }

        // Send ack
        conn.write_all(&bincode::serialize(&Ack::Ok).unwrap())
            .await?;
        conn.flush().await?;

        // A failed acknowledgement must leave the old draining generations
        // owned by the service map for the next reconnect or revocation.
        let previous = h.remove1(&service_digest);

        info!(service = %service_config.name, "Control channel established");
        let mut handle =
            ControlChannelHandle::new(conn, service_config, server_config.heartbeat_interval);
        if let Some(mut previous) = previous {
            // Keep every generation under the current service's revocation
            // owner. A reconnect may drain TCP copies, but deletion or token
            // rotation must still close those copies before returning.
            handle.retired.append(&mut previous.retired);
            handle.retired.push(previous);
            handle
                .retired
                .retain(|generation| !generation.tasks.iter().all(|task| task.is_finished()));
        }

        // Insert the new handle
        let _ = h.insert(service_digest, session_key, handle);
    }

    Ok(())
}

async fn do_data_channel_handshake<T: 'static + Transport>(
    conn: T::Stream,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    nonce: Nonce,
) -> Result<()> {
    debug!("Try to handshake a data channel");

    // Validate
    let control_channels_guard = control_channels.read().await;
    match control_channels_guard.get2(&nonce) {
        Some(handle) => {
            T::hint(&conn, SocketOpts::from_server_cfg(&handle.service));

            // Send the data channel to the corresponding control channel
            handle
                .data_ch_tx
                .send(conn)
                .await
                .map_err(|_| anyhow!("Data channel for a stale control channel"))?;
        }
        None => {
            warn!("Data channel has incorrect nonce");
        }
    }
    Ok(())
}

pub struct ControlChannelHandle<T: Transport> {
    // Shutdown the control channel by dropping it
    _shutdown_tx: broadcast::Sender<bool>,
    data_ch_tx: mpsc::Sender<T::Stream>,
    service: ServerServiceConfig,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    listener_closed: Option<oneshot::Receiver<()>>,
    retired: Vec<ControlChannelHandle<T>>,
}

impl<T> ControlChannelHandle<T>
where
    T: 'static + Transport,
{
    /// Completion means listeners, queued visitors and active copies have all
    /// released their sockets, rather than merely receiving a stop signal.
    async fn close(&mut self) -> Result<()> {
        let _ = self._shutdown_tx.send(true);
        for previous in &self.retired {
            let _ = previous._shutdown_tx.send(true);
        }
        let mut retired = std::mem::take(&mut self.retired);
        let mut failure = None;
        if let Err(error) = self.join_tasks().await {
            failure = Some(error);
        }
        for previous in &mut retired {
            if let Err(error) = previous.join_tasks().await {
                failure = Some(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    async fn join_tasks(&mut self) -> Result<()> {
        let mut failure = None;
        while !self.tasks.is_empty() {
            let result = (&mut self.tasks[0]).await;
            self.tasks.remove(0);
            if let Err(error) = result {
                failure = Some(error);
            }
        }
        match failure {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }

    /// Release the old listener before a replacement binds it. TCP copies
    /// already paired with visitors stay alive under this handle's ownership.
    async fn retire(&mut self) {
        let _ = self._shutdown_tx.send(false);
        if let Some(closed) = &mut self.listener_closed {
            let _ = closed.await;
            self.listener_closed = None;
        }
    }

    // Create a control channel handle, where the control channel handling task
    // and the connection pool task are created.
    #[instrument(name = "handle", skip_all, fields(service = %service.name))]
    fn new(
        conn: T::Stream,
        service: ServerServiceConfig,
        heartbeat_interval: u64,
    ) -> ControlChannelHandle<T> {
        // Create a shutdown channel
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<bool>(1);
        let (listener_closed, listener_closed_rx) = oneshot::channel();

        // Store data channels
        let (data_ch_tx, data_ch_rx) = mpsc::channel(CHAN_SIZE * 2);

        // Store data channel creation requests
        let (data_ch_req_tx, data_ch_req_rx) = mpsc::unbounded_channel();

        // Cache some data channels for later use
        let pool_size = match service.service_type {
            ServiceType::Tcp => TCP_POOL_SIZE,
            ServiceType::Udp => UDP_POOL_SIZE,
        };

        for _i in 0..pool_size {
            if let Err(e) = data_ch_req_tx.send(true) {
                error!("Failed to request data channel {}", e);
            };
        }

        let shutdown_rx_clone = shutdown_tx.subscribe();
        let bind_addr = service.bind_addr.clone();
        let pool = match service.service_type {
            ServiceType::Tcp => tokio::spawn(
                async move {
                    if let Err(e) = run_tcp_connection_pool::<T>(
                        bind_addr,
                        data_ch_rx,
                        data_ch_req_tx,
                        shutdown_rx_clone,
                        listener_closed,
                    )
                    .await
                    .with_context(|| "Failed to run TCP connection pool")
                    {
                        error!("{:#}", e);
                    }
                }
                .instrument(Span::current()),
            ),
            ServiceType::Udp => tokio::spawn(
                async move {
                    let mut stopping = shutdown_rx_clone;
                    let pool = run_udp_connection_pool::<T>(
                        bind_addr,
                        data_ch_rx,
                        data_ch_req_tx,
                        stopping.resubscribe(),
                    );
                    let result = tokio::select! {
                        result=pool=>result,
                        _=stopping.recv()=>Ok(()),
                    };
                    let _ = listener_closed.send(());
                    if let Err(e) = result.with_context(|| "Failed to run UDP connection pool") {
                        error!("{:#}", e);
                    }
                }
                .instrument(Span::current()),
            ),
        };

        // Create the control channel
        let ch = ControlChannel::<T> {
            conn,
            shutdown_rx,
            data_ch_req_rx,
            heartbeat_interval,
        };

        // Run the control channel
        let mut stopping = shutdown_tx.subscribe();
        let control = tokio::spawn(
            async move {
                let result = tokio::select! {
                    result=ch.run()=>result,
                    _=stopping.recv()=>Ok(()),
                };
                if let Err(err) = result {
                    error!("{:#}", err);
                }
            }
            .instrument(Span::current()),
        );

        ControlChannelHandle {
            _shutdown_tx: shutdown_tx,
            data_ch_tx,
            service,
            tasks: vec![pool, control],
            listener_closed: Some(listener_closed_rx),
            retired: Vec::new(),
        }
    }
}

// Control channel, using T as the transport layer. P is TcpStream or UdpTraffic
struct ControlChannel<T: Transport> {
    conn: T::Stream,                               // The connection of control channel
    shutdown_rx: broadcast::Receiver<bool>,        // Receives the shutdown signal
    data_ch_req_rx: mpsc::UnboundedReceiver<bool>, // Receives visitor connections
    heartbeat_interval: u64,                       // Application-layer heartbeat interval in secs
}

impl<T: Transport> ControlChannel<T> {
    async fn write_and_flush(&mut self, data: &[u8]) -> Result<()> {
        self.conn
            .write_all(data)
            .await
            .with_context(|| "Failed to write control cmds")?;
        self.conn
            .flush()
            .await
            .with_context(|| "Failed to flush control cmds")?;
        Ok(())
    }
    // Run a control channel
    #[instrument(skip_all)]
    async fn run(mut self) -> Result<()> {
        let create_ch_cmd = bincode::serialize(&ControlChannelCmd::CreateDataChannel).unwrap();
        let heartbeat = bincode::serialize(&ControlChannelCmd::HeartBeat).unwrap();

        // Wait for data channel requests and the shutdown signal
        loop {
            tokio::select! {
                val = self.data_ch_req_rx.recv() => {
                    match val {
                        Some(_) => {
                            if let Err(e) = self.write_and_flush(&create_ch_cmd).await {
                                error!("{:#}", e);
                                break;
                            }
                        }
                        None => {
                            break;
                        }
                    }
                },
                _ = time::sleep(Duration::from_secs(self.heartbeat_interval)), if self.heartbeat_interval != 0 => {
                            if let Err(e) = self.write_and_flush(&heartbeat).await {
                                error!("{:#}", e);
                                break;
                            }
                }
                // Wait for the shutdown signal
                _ = self.shutdown_rx.recv() => {
                    break;
                }
            }
        }

        info!("Control channel shutdown");

        Ok(())
    }
}

fn tcp_listen_and_send(
    addr: String,
    data_ch_req_tx: mpsc::UnboundedSender<bool>,
    mut shutdown_rx: broadcast::Receiver<bool>,
) -> (mpsc::Receiver<TcpStream>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(CHAN_SIZE);

    let task = tokio::spawn(async move {
        let l = retry_notify_with_deadline(listen_backoff(),  || async {
            Ok(TcpListener::bind(&addr).await?)
        }, |e, duration| {
            error!("{:#}. Retry in {:?}", e, duration);
        }, &mut shutdown_rx).await
        .with_context(|| "Failed to listen for the service");

        let l: TcpListener = match l {
            Ok(v) => v,
            Err(e) => {
                error!("{:#}", e);
                return;
            }
        };

        info!("Listening at {}", &addr);

        // Retry at least every 1s
        let mut backoff = ExponentialBackoff {
            max_interval: Duration::from_secs(1),
            max_elapsed_time: None,
            ..Default::default()
        };

        // Wait for visitors and the shutdown signal
        loop {
            tokio::select! {
                val = l.accept() => {
                    match val {
                        Err(e) => {
                            // `l` is a TCP listener so this must be a IO error
                            // Possibly a EMFILE. So sleep for a while
                            error!("{}. Sleep for a while", e);
                            if let Some(d) = backoff.next_backoff() {
                                time::sleep(d).await;
                            } else {
                                // This branch will never be reached for current backoff policy
                                error!("Too many retries. Aborting...");
                                break;
                            }
                        }
                        Ok((incoming, addr)) => {
                            // For every visitor, request to create a data channel
                            if data_ch_req_tx.send(true).with_context(|| "Failed to send data chan create request").is_err() {
                                // An error indicates the control channel is broken
                                // So break the loop
                                break;
                            }

                            backoff.reset();

                            debug!("New visitor from {}", addr);

                            // Send the visitor to the connection pool
                            let _ = tx.send(incoming).await;
                        }
                    }
                },
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }

        info!("TCPListener shutdown");
    }.instrument(Span::current()));

    (rx, task)
}

#[instrument(skip_all)]
async fn run_tcp_connection_pool<T: Transport>(
    bind_addr: String,
    mut data_ch_rx: mpsc::Receiver<T::Stream>,
    data_ch_req_tx: mpsc::UnboundedSender<bool>,
    mut shutdown_rx: broadcast::Receiver<bool>,
    listener_closed: oneshot::Sender<()>,
) -> Result<()> {
    let (mut visitor_rx, listener) =
        tcp_listen_and_send(bind_addr, data_ch_req_tx.clone(), shutdown_rx.resubscribe());
    let cmd = bincode::serialize(&DataChannelCmd::StartForwardTcp).unwrap();
    let mut copies = tokio::task::JoinSet::new();
    let forwarding = async {
        'pool: loop {
            let visitor = tokio::select! {
                visitor=visitor_rx.recv()=>visitor,
                result=copies.join_next(), if !copies.is_empty()=> {
                    if let Some(Err(error)) = result { warn!(%error,"TCP copy task failed"); }
                    continue;
                }
            };
            let Some(mut visitor) = visitor else {
                break;
            };
            loop {
                if let Some(mut ch) = data_ch_rx.recv().await {
                    if ch.write_all(&cmd).await.is_ok() {
                        copies.spawn(async move {
                            let _ = copy_bidirectional(&mut ch, &mut visitor).await;
                        });
                        break;
                    } else {
                        // Current data channel is broken. Request for a new one
                        if data_ch_req_tx.send(true).is_err() {
                            break 'pool;
                        }
                    }
                } else {
                    break 'pool;
                }
            }
        }
    };
    let drain = tokio::select! { _=forwarding=>false, signal=shutdown_rx.recv()=>matches!(signal, Ok(false)) };
    // The listener can be blocked handing off a queued visitor; abort and join
    // it explicitly, then drain every active forwarding task before returning.
    listener.abort();
    let listener_result = listener.await;
    // Drop queued visitors and idle old-session channels before acknowledging
    // release. Only copies that already started forwarding may survive.
    drop(visitor_rx);
    drop(data_ch_rx);
    let _ = listener_closed.send(());
    if drain {
        loop {
            tokio::select! {
                result=copies.join_next()=>if result.is_none(){break;},
                _=shutdown_rx.recv()=>break,
            }
        }
    }
    copies.shutdown().await;
    if let Err(error) = listener_result {
        if !error.is_cancelled() {
            return Err(error.into());
        }
    }

    info!("Shutdown");
    Ok(())
}

#[instrument(skip_all)]
async fn run_udp_connection_pool<T: Transport>(
    bind_addr: String,
    mut data_ch_rx: mpsc::Receiver<T::Stream>,
    _data_ch_req_tx: mpsc::UnboundedSender<bool>,
    mut shutdown_rx: broadcast::Receiver<bool>,
) -> Result<()> {
    // TODO: Load balance

    let l = retry_notify_with_deadline(
        listen_backoff(),
        || async { Ok(UdpSocket::bind(&bind_addr).await?) },
        |e, duration| {
            warn!("{:#}. Retry in {:?}", e, duration);
        },
        &mut shutdown_rx,
    )
    .await
    .with_context(|| "Failed to listen for the service")?;

    info!("Listening at {}", &bind_addr);

    let cmd = bincode::serialize(&DataChannelCmd::StartForwardUdp).unwrap();

    // Receive one data channel
    let mut conn = data_ch_rx
        .recv()
        .await
        .ok_or_else(|| anyhow!("No available data channels"))?;
    conn.write_all(&cmd).await?;
    conn.flush().await?;

    let mut buf = [0u8; UDP_BUFFER_SIZE];
    loop {
        tokio::select! {
            // Forward inbound traffic to the client
            val = l.recv_from(&mut buf) => {
                let (n, from) = val?;
                UdpTraffic::write_slice(&mut conn, from, &buf[..n]).await?;
            },

            // Forward outbound traffic from the client to the visitor
            hdr_len = conn.read_u8() => {
                let t = UdpTraffic::read(&mut conn, hdr_len?).await?;
                l.send_to(&t.data, t.from).await?;
            }

            _ = shutdown_rx.recv() => {
                break;
            }
        }
    }

    debug!("UDP pool dropped");

    Ok(())
}
