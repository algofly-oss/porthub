//! Standard TURN carried on the shared gateway WebSocket, with no helper
//! process or additional listener. The returned socket carries ICE and DTLS;
//! the gateway never receives decrypted private IP packets through this API.
use anyhow::{ensure, Result};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{mpsc, Mutex as AsyncMutex},
    task::JoinHandle,
};
use tokio_tungstenite::tungstenite::{protocol::WebSocketConfig, Message};
use tokio_util::sync::CancellationToken;
use turn_util::{Conn, Error as IoError, Result as IoResult};

const SERVER: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1);
pub type Socket = Arc<dyn Conn + Send + Sync>;

struct Transport {
    input: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    output: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
}
#[async_trait]
impl Conn for Transport {
    async fn connect(&self, address: SocketAddr) -> IoResult<()> {
        if address != SERVER {
            return Err(IoError::ErrUseClosedNetworkConn);
        }
        Ok(())
    }
    async fn recv(&self, buffer: &mut [u8]) -> IoResult<usize> {
        Ok(self.recv_from(buffer).await?.0)
    }
    async fn recv_from(&self, buffer: &mut [u8]) -> IoResult<(usize, SocketAddr)> {
        let mut input = self.input.lock().await;
        let packet = tokio::select! {
            _ = self.cancel.cancelled() => return Err(IoError::ErrUseClosedNetworkConn),
            packet = input.recv() => packet.ok_or(IoError::ErrUseClosedNetworkConn)?,
        };
        if packet.len() > buffer.len() {
            return Err(IoError::ErrPacketTooBig);
        }
        buffer[..packet.len()].copy_from_slice(&packet);
        Ok((packet.len(), SERVER))
    }
    async fn send(&self, buffer: &[u8]) -> IoResult<usize> {
        self.send_to(buffer, SERVER).await
    }
    async fn send_to(&self, buffer: &[u8], target: SocketAddr) -> IoResult<usize> {
        if target != SERVER || buffer.len() > 65536 {
            return Err(IoError::ErrPacketTooBig);
        }
        tokio::select! {
            _ = self.cancel.cancelled() => return Err(IoError::ErrUseClosedNetworkConn),
            result = self.output.send(buffer.into()) => result.map_err(|_| IoError::ErrUseClosedNetworkConn)?,
        }
        Ok(buffer.len())
    }
    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(SocketAddr::from(([127, 0, 0, 1], 443)))
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(SERVER)
    }
    async fn close(&self) -> IoResult<()> {
        self.cancel.cancel();
        Ok(())
    }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

struct Lifetime {
    cancel: CancellationToken,
    cleanup: Mutex<Option<JoinHandle<()>>>,
}
// A discovery task may be cancelled at any await during authentication. Keep
// ownership until the completed allocation takes over, so cancellation cannot
// detach a WebSocket reader or TURN retransmission timers.
struct Setup {
    cancel: CancellationToken,
    wire: Option<JoinHandle<()>>,
    client: Option<Arc<turn::client::Client>>,
}
impl Drop for Setup {
    fn drop(&mut self) {
        if self.wire.is_none() {
            return;
        }
        self.cancel.cancel();
        if let Some(wire) = self.wire.take() {
            wire.abort();
        }
        if let Some(client) = self.client.take() {
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(2), client.close()).await;
            });
        }
    }
}
impl Drop for Lifetime {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
/// Clones share one allocation. Dropping the last owner closes the WebSocket
/// and stops TURN renewal tasks. `close` also waits for bounded cleanup.
#[derive(Clone)]
pub struct Allocation {
    socket: Socket,
    lifetime: Arc<Lifetime>,
}
impl Allocation {
    pub async fn connect(
        url: &str,
        username: &str,
        password: &str,
        allow_plaintext_origin: bool,
    ) -> Result<Self> {
        Self::connect_bound(url, username, password, allow_plaintext_origin, &[]).await
    }
    pub async fn connect_bound(
        url: &str, username: &str, password: &str, allow_plaintext_origin: bool, local: &[std::net::IpAddr],
    ) -> Result<Self> {
        let url = url::Url::parse(url).map_err(|_| anyhow::anyhow!("invalid private relay URL"))?;
        ensure!(
            url.scheme() == "wss" || (url.scheme() == "ws" && allow_plaintext_origin),
            "private TURN relay requires TLS"
        );
        ensure!(
            url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "invalid private relay authority"
        );
        ensure!(
            !username.is_empty()
                && username.len() <= 128
                && !password.is_empty()
                && password.len() <= 256,
            "invalid private relay credential"
        );
        let config = WebSocketConfig::default()
            .read_buffer_size(8192)
            .write_buffer_size(8192)
            .max_message_size(Some(65536))
            .max_frame_size(Some(65536));
        let (mut websocket, _) = tokio::time::timeout(
            Duration::from_secs(5),
            async {
                let stream = crate::underlay::connect(&url, local).await?;
                crate::configure_tcp(&stream);
                Ok::<_,anyhow::Error>(tokio_tungstenite::client_async_tls_with_config(url.as_str(), stream, Some(config), None).await?)
            },
        )
        .await
        .map_err(|_| anyhow::anyhow!("private relay connection timed out"))?
        .map_err(|_| anyhow::anyhow!("private relay connection failed"))?;
        match websocket.get_ref() {
            tokio_tungstenite::MaybeTlsStream::Plain(stream) => crate::configure_tcp(stream),
            tokio_tungstenite::MaybeTlsStream::Rustls(stream) => {
                crate::configure_tcp(stream.get_ref().0)
            }
            _ => {}
        }
        let cancel = CancellationToken::new();
        let wire_cancel = cancel.clone();
        let (input, input_rx) = mpsc::channel(128);
        let (output, mut output_rx) = mpsc::channel(128);
        let transport = Arc::new(Transport {
            input: AsyncMutex::new(input_rx),
            output,
            cancel: cancel.clone(),
        });
        let wire = tokio::spawn(async move {
            let result: Result<()> = async {
                let mut bytes = Vec::new();
                loop { tokio::select! {
                    _ = wire_cancel.cancelled() => break,
                    packet = output_rx.recv() => {
                        let Some(packet) = packet else { break; };
                        tokio::time::timeout(Duration::from_secs(5), websocket.send(Message::Binary(packet.into()))).await??;
                    },
                    message = websocket.next() => match message {
                        Some(Ok(Message::Binary(packet))) => {
                            ensure!(bytes.len() + packet.len() <= 65536, "private TURN frame exceeds limit");
                            bytes.extend_from_slice(&packet);
                            while bytes.len() >= 4 {
                                let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
                                let size = match bytes[0] & 0xc0 {
                                    0 => { ensure!(length % 4 == 0, "invalid TURN STUN length"); 20 + length },
                                    0x40 => (4 + length + 3) & !3,
                                    _ => anyhow::bail!("invalid TURN frame"),
                                };
                                ensure!(size <= 65536, "private TURN frame exceeds limit");
                                if bytes.len() < size { break; }
                                let packet = bytes.drain(..size).collect();
                                tokio::select! { _ = wire_cancel.cancelled() => return Ok(()), result = input.send(packet) => { if result.is_err() { return Ok(()); } } }
                            }
                        },
                        Some(Ok(Message::Ping(packet))) => { tokio::time::timeout(Duration::from_secs(5), websocket.send(Message::Pong(packet))).await??; },
                        Some(Ok(Message::Pong(_))) => {},
                        _ => break,
                    }
                }}
                Ok(())
            }.await;
            // Errors intentionally contain no URL or credential in normal logs.
            let _ = result;
            wire_cancel.cancel();
        });
        let mut setup = Setup {
            cancel: cancel.clone(),
            wire: Some(wire),
            client: None,
        };
        let client = turn::client::Client::new(turn::client::ClientConfig {
            stun_serv_addr: String::new(),
            turn_serv_addr: SERVER.to_string(),
            username: username.into(),
            password: password.into(),
            realm: "porthub".into(),
            software: String::new(),
            rto_in_ms: 200,
            conn: transport,
            vnet: None,
        })
        .await;
        let result: Result<_> = async {
            let client =
                Arc::new(client.map_err(|_| anyhow::anyhow!("private TURN setup failed"))?);
            setup.client = Some(client.clone());
            let allocation: Result<Socket> = async {
                client
                    .listen()
                    .await
                    .map_err(|_| anyhow::anyhow!("private TURN listener failed"))?;
                let socket = tokio::time::timeout(Duration::from_secs(5), client.allocate())
                    .await
                    .map_err(|_| anyhow::anyhow!("private TURN allocation timed out"))?
                    .map_err(|_| anyhow::anyhow!("private TURN allocation failed"))?;
                Ok(Arc::new(socket) as Socket)
            }
            .await;
            match allocation {
                Ok(socket) => Ok((client, socket)),
                Err(error) => {
                    let _ = client.close().await;
                    Err(error)
                }
            }
        }
        .await;
        let (client, socket) = result?;
        let wire = setup.wire.take().expect("TURN setup owns its reader");
        setup.client = None;
        let cleanup_socket = socket.clone();
        let cleanup_cancel = cancel.clone();
        let cleanup = tokio::spawn(async move {
            cleanup_cancel.cancelled().await;
            let _ = tokio::time::timeout(Duration::from_secs(2), cleanup_socket.close()).await;
            let _ = tokio::time::timeout(Duration::from_secs(2), client.close()).await;
            wire.abort();
            let _ = wire.await;
        });
        Ok(Self {
            socket,
            lifetime: Arc::new(Lifetime {
                cancel,
                cleanup: Mutex::new(Some(cleanup)),
            }),
        })
    }
    pub fn socket(&self) -> Socket {
        self.socket.clone()
    }
    pub async fn close(&self) {
        self.lifetime.cancel.cancel();
        let task = self
            .lifetime
            .cleanup
            .lock()
            .expect("relay cleanup mutex poisoned")
            .take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}
