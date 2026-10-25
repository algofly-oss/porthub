//! Reliable private streams over the existing peer/gateway datagram paths.
//! QUIC owns encryption, replay protection, ordering and retransmission. No OS
//! socket is opened: path changes retain one virtual endpoint and connection.
use crate::{
    protocol::{fingerprint, pin},
    Identity,
};
use anyhow::{ensure, Result};
use bytes::Bytes;
use quinn::{AsyncUdpSocket, UdpPoller};
pub use quinn::{Connection, RecvStream, SendStream};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    DigitallySignedStruct, DistinguishedName, Error, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

const PORT: u16 = 1;
pub const MAX_DATAGRAM: usize = crate::MAX_PACKET - 20;
const QUEUE: usize = 256;
const MAX_PEERS: usize = 4096;
const MAX_CONNECTIONS: usize = 512;
const ALPN: &[u8] = b"porthub-private-stream/1";

#[derive(Clone, PartialEq, Eq)]
pub struct Peer {
    pub id: String,
    pub ip: Ipv4Addr,
    pub fingerprint: String,
    pub instance: String,
}
type Peers = Arc<RwLock<HashMap<Ipv4Addr, Peer>>>;
pub struct Datagram {
    pub address: Ipv4Addr,
    pub payload: Bytes,
}
#[derive(Clone)]
pub struct Ingress {
    input: mpsc::Sender<Datagram>,
    peers: Peers,
}
impl Ingress {
    fn validate(&self, source: Ipv4Addr, payload: &Bytes) -> Result<()> {
        ensure!(
            !payload.is_empty() && payload.len() <= MAX_DATAGRAM,
            "invalid private stream datagram"
        );
        ensure!(
            self.peers
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .contains_key(&source),
            "private stream peer is not admitted"
        );
        Ok(())
    }
    pub fn send(&self, source: Ipv4Addr, payload: Bytes) -> Result<()> {
        self.validate(source, &payload)?;
        self.input
            .try_send(Datagram {
                address: source,
                payload,
            })
            .map_err(|_| anyhow::anyhow!("private stream receive queue unavailable"))
    }
    /// Preserve reliable-carrier backpressure instead of creating local loss.
    /// Recheck admission after waiting because policy can change while queued.
    pub async fn send_reliable(&self, source: Ipv4Addr, payload: Bytes) -> Result<()> {
        self.validate(source, &payload)?;
        let permit = self
            .input
            .reserve()
            .await
            .map_err(|_| anyhow::anyhow!("private stream receive queue unavailable"))?;
        self.validate(source, &payload)?;
        permit.send(Datagram {
            address: source,
            payload,
        });
        Ok(())
    }
}
pub struct PacketIo {
    input: mpsc::Sender<Datagram>,
    output: mpsc::Receiver<Datagram>,
    peers: Peers,
}
impl PacketIo {
    pub fn ingress(&self) -> Ingress {
        Ingress {
            input: self.input.clone(),
            peers: self.peers.clone(),
        }
    }
    pub async fn outgoing(&mut self) -> Option<Datagram> {
        self.output.recv().await
    }
    /// The caller must derive `source` from the authenticated peer identity,
    /// never from an untrusted packet's claimed IP address.
    pub fn incoming(&self, source: Ipv4Addr, payload: Bytes) -> Result<()> {
        self.ingress().send(source, payload)
    }
}
struct PacketSocket {
    local: Ipv4Addr,
    input: Mutex<mpsc::Receiver<Datagram>>,
    output: mpsc::Sender<Datagram>,
}
impl fmt::Debug for PacketSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateStreamSocket")
            .finish_non_exhaustive()
    }
}
struct Writable(Mutex<PollSender<Datagram>>);
impl fmt::Debug for Writable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateStreamWritable")
    }
}
impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut sender = self.0.lock().unwrap_or_else(|p| p.into_inner());
        match sender.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                sender.abort_send();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}
impl AsyncUdpSocket for PacketSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable(Mutex::new(PollSender::new(self.output.clone()))))
    }
    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        let IpAddr::V4(destination) = transmit.destination.ip() else {
            return Ok(());
        };
        // Admission happens at connect and ingress. Permit encrypted QUIC close
        // packets to drain after the peer is removed from the admission map.
        if transmit.destination.port() != PORT
            || transmit.contents.len() > MAX_DATAGRAM
            || !destination.is_private()
            || destination == self.local
        {
            return Ok(());
        }
        self.output
            .try_send(Datagram {
                address: destination,
                payload: Bytes::copy_from_slice(transmit.contents),
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => io::ErrorKind::WouldBlock.into(),
                mpsc::error::TrySendError::Closed(_) => io::ErrorKind::BrokenPipe.into(),
            })
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut input = self.input.lock().unwrap_or_else(|p| p.into_inner());
        match input.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                if bufs.is_empty() || meta.is_empty() || packet.payload.len() > bufs[0].len() {
                    return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                }
                bufs[0][..packet.payload.len()].copy_from_slice(&packet.payload);
                meta[0] = quinn::udp::RecvMeta {
                    addr: SocketAddr::from((packet.address, PORT)),
                    len: packet.payload.len(),
                    stride: packet.payload.len(),
                    ecn: None,
                    dst_ip: Some(self.local.into()),
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from((self.local, PORT)))
    }
    fn may_fragment(&self) -> bool {
        false
    }
}

struct Verifier {
    expected: Option<[u8; 32]>,
    peers: Peers,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}
impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateStreamPeerVerifier")
            .finish_non_exhaustive()
    }
}
impl Verifier {
    fn verify(&self, certificate: &CertificateDer<'_>) -> std::result::Result<(), Error> {
        let actual: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
        let admitted = if let Some(expected) = self.expected {
            actual == expected
        } else {
            self.peers
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .values()
                .any(|peer| pin(&peer.fingerprint).ok() == Some(actual))
        };
        if admitted {
            Ok(())
        } else {
            Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
    fn signature12(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }
    fn signature13(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }
}
impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        self.verify(certificate)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        self.signature12(message, certificate, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        self.signature13(message, certificate, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
impl ClientCertVerifier for Verifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        certificate: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> std::result::Result<ClientCertVerified, Error> {
        self.verify(certificate)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        self.signature12(message, certificate, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        self.signature13(message, certificate, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
fn transport() -> Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config
        .max_concurrent_uni_streams(0u8.into())
        .max_concurrent_bidi_streams(512u32.into())
        // Independent reliable carriers can deliver whole bursts out of order.
        // Allow their bounded queues to drain before declaring datagrams lost;
        // PTO still probes a stalled path and real loss remains recoverable.
        .packet_threshold(16384)
        .time_threshold(4.0)
        .initial_mtu(MAX_DATAGRAM as u16)
        .min_mtu(MAX_DATAGRAM as u16)
        .mtu_discovery_config(None)
        .max_idle_timeout(None)
        .stream_receive_window((16u32 * 1024 * 1024).into())
        .receive_window((32u32 * 1024 * 1024).into())
        .send_window(32 * 1024 * 1024)
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Arc::new(config)
}
pub struct Endpoint {
    inner: quinn::Endpoint,
    local: Ipv4Addr,
    identity: Identity,
    peers: Peers,
    connections: Mutex<HashMap<Ipv4Addr, quinn::Connection>>,
}
impl Endpoint {
    pub fn new(identity: Identity, local: Ipv4Addr) -> Result<(Self, PacketIo)> {
        ensure!(local.is_private(), "invalid private stream endpoint");
        let peers: Peers = Default::default();
        let provider = rustls::crypto::ring::default_provider();
        let verifier = Arc::new(Verifier {
            expected: None,
            peers: peers.clone(),
            algorithms: provider.signature_verification_algorithms,
        });
        let (certificates, key) = identity.tls_material()?;
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, key)?;
        tls.alpn_protocols = vec![ALPN.into()];
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
        ));
        server.transport = transport();
        let (input, incoming) = mpsc::channel(QUEUE);
        let (outgoing, output) = mpsc::channel(QUEUE);
        let socket = Arc::new(PacketSocket {
            local,
            input: Mutex::new(incoming),
            output: outgoing,
        });
        let mut config = quinn::EndpointConfig::default();
        config.max_udp_payload_size(MAX_DATAGRAM as u16)?;
        let inner = quinn::Endpoint::new_with_abstract_socket(
            config,
            Some(server),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        Ok((
            Self {
                inner,
                local,
                identity,
                peers: peers.clone(),
                connections: Default::default(),
            },
            PacketIo {
                input,
                output,
                peers,
            },
        ))
    }
    /// Pins originate only from an authenticated private-policy snapshot.
    /// Port grants are checked separately when a TCP stream is opened.
    pub fn update_peers(&self, peers: Vec<Peer>) -> Result<()> {
        ensure!(peers.len() <= MAX_PEERS, "too many private stream peers");
        let mut next = HashMap::new();
        let mut ids = HashSet::new();
        let mut fingerprints = HashSet::new();
        for mut peer in peers {
            ensure!(
                peer.ip.is_private()
                    && peer.ip != self.local
                    && !peer.id.is_empty()
                    && peer.id.len() <= 60
                    && !peer.instance.is_empty()
                    && peer.instance.len() <= 64,
                "invalid private stream peer"
            );
            let hash = pin(&peer.fingerprint)?;
            peer.fingerprint = peer.fingerprint.to_ascii_uppercase();
            ensure!(
                peer.fingerprint != self.identity.fingerprint()
                    && ids.insert(peer.id.clone())
                    && fingerprints.insert(hash),
                "ambiguous private stream identity"
            );
            ensure!(
                next.insert(peer.ip, peer).is_none(),
                "ambiguous private stream peer address"
            );
        }
        let mut trusted = self.peers.write().unwrap_or_else(|p| p.into_inner());
        self.connections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|ip, connection| {
                let keep = connection.close_reason().is_none() && trusted.get(ip) == next.get(ip);
                if !keep {
                    connection.close(1u8.into(), b"private peer authorization changed");
                }
                keep
            });
        *trusted = next;
        Ok(())
    }
    fn register(
        &self,
        connection: quinn::Connection,
        expected: Option<&Peer>,
    ) -> Result<(Peer, quinn::Connection)> {
        let IpAddr::V4(ip) = connection.remote_address().ip() else {
            anyhow::bail!("invalid private stream address")
        };
        let trusted = self.peers.read().unwrap_or_else(|p| p.into_inner());
        let peer = trusted
            .get(&ip)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("private stream peer revoked"))?;
        ensure!(
            expected.is_none_or(|expected| *expected == peer),
            "private stream peer changed during handshake"
        );
        let certificates = connection
            .peer_identity()
            .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
            .ok_or_else(|| anyhow::anyhow!("private stream certificate unavailable"))?;
        ensure!(
            certificates
                .first()
                .is_some_and(|certificate| fingerprint(certificate.as_ref()) == peer.fingerprint),
            "private stream peer identity mismatch"
        );
        let mut connections = self.connections.lock().unwrap_or_else(|p| p.into_inner());
        connections.retain(|_, connection| connection.close_reason().is_none());
        ensure!(
            connections.len() < MAX_CONNECTIONS || connections.contains_key(&ip),
            "private stream connection limit reached"
        );
        if connections.contains_key(&ip) {
            connection.close(2u8.into(), b"private stream connection already prepared");
            anyhow::bail!("private stream connection already prepared");
        }
        connections.insert(ip, connection.clone());
        Ok((peer, connection))
    }
    pub fn prepared(&self, expected: &Peer) -> Option<quinn::Connection> {
        let trusted = self.peers.read().unwrap_or_else(|p| p.into_inner());
        if trusted.get(&expected.ip) != Some(expected) {
            return None;
        }
        self.connections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&expected.ip)
            .filter(|connection| connection.close_reason().is_none())
            .cloned()
    }
    pub async fn connect(&self, expected: &Peer) -> Result<quinn::Connection> {
        let ip = expected.ip;
        ensure!(
            self.peers
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .get(&ip)
                == Some(expected),
            "private stream peer not admitted"
        );
        if let Some(connection) = self.prepared(expected) {
            return Ok(connection);
        }
        let provider = rustls::crypto::ring::default_provider();
        let verifier = Arc::new(Verifier {
            expected: Some(pin(&expected.fingerprint)?),
            peers: self.peers.clone(),
            algorithms: provider.signature_verification_algorithms,
        });
        let (certificates, key) = self.identity.tls_material()?;
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(certificates, key)?;
        tls.alpn_protocols = vec![ALPN.into()];
        let mut config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
        ));
        config.transport_config(transport());
        let connection = tokio::time::timeout(
            Duration::from_secs(10),
            self.inner.connect_with(
                config,
                SocketAddr::from((ip, PORT)),
                "private.porthub.invalid",
            )?,
        )
        .await??;
        let (_, connection) = self.register(connection, Some(expected))?;
        Ok(connection)
    }
    pub async fn accept(&self) -> Result<(Peer, quinn::Connection)> {
        let incoming = self
            .inner
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("private stream endpoint stopped"))?;
        let connection = tokio::time::timeout(Duration::from_secs(10), incoming).await??;
        self.register(connection, None)
    }
    pub fn close(&self) {
        self.inner
            .close(0u8.into(), b"private stream owner stopped");
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod ingress_tests {
    use super::*;

    #[tokio::test]
    async fn reliable_ingress_waits_for_capacity_and_rechecks_revocation() -> Result<()> {
        let source = Ipv4Addr::new(10, 234, 253, 1);
        let (input, mut output) = mpsc::channel(1);
        let peers = Arc::new(RwLock::new(HashMap::from([(
            source,
            Peer {
                id: "peer".into(),
                ip: source,
                fingerprint: String::new(),
                instance: "instance".into(),
            },
        )])));
        let ingress = Ingress {
            input,
            peers: peers.clone(),
        };
        ingress.send(source, Bytes::from_static(b"first"))?;
        let mut waiting = Box::pin(ingress.send_reliable(source, Bytes::from_static(b"second")));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut waiting)
                .await
                .is_err()
        );
        assert_eq!(output.recv().await.unwrap().payload, b"first"[..]);
        tokio::time::timeout(Duration::from_secs(1), waiting).await??;
        assert_eq!(output.recv().await.unwrap().payload, b"second"[..]);

        ingress.send(source, Bytes::from_static(b"queued"))?;
        let mut waiting = Box::pin(ingress.send_reliable(source, Bytes::from_static(b"revoked")));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut waiting)
                .await
                .is_err()
        );
        peers.write().unwrap().clear();
        assert_eq!(output.recv().await.unwrap().payload, b"queued"[..]);
        assert!(tokio::time::timeout(Duration::from_secs(1), waiting)
            .await?
            .is_err());
        assert!(output.try_recv().is_err());
        Ok(())
    }
}
