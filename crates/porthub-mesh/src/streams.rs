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
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
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
const MAX_CONNECTIONS_PER_PEER: usize = 8;
const ALPN: &[u8] = b"porthub-private-stream/1";
const ORIGIN_ALPN: &[u8] = b"porthub-private-stream/2-origin";
const PARALLEL_ALPN: &[u8] = b"porthub-private-stream/1-lanes8";

#[derive(Clone, PartialEq, Eq)]
pub struct Peer {
    pub id: String,
    pub ip: Ipv4Addr,
    pub fingerprint: String,
    pub instance: String,
}
type Peers = Arc<RwLock<HashMap<Ipv4Addr, Peer>>>;
type Admissions = Arc<RwLock<Option<HashMap<Ipv4Addr,crate::udp::SendPermit>>>>;
pub struct Datagram {
    pub permit:Option<crate::udp::SendPermit>,
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
                permit:None,
                address: source,
                payload,
            })
            .map_err(|_| anyhow::anyhow!("private stream receive queue unavailable"))
    }
    /// Preserve reliable-carrier backpressure instead of creating local loss.
    /// Recheck admission after waiting because policy can change while queued.
    pub async fn send_reliable(&self, source: Ipv4Addr, payload: Bytes) -> Result<()> {self.send_reliable_guarded(source,payload,None).await}
    pub async fn send_reliable_guarded(&self,source:Ipv4Addr,payload:Bytes,admission:Option<crate::udp::SendPermit>)->Result<()> {
        ensure!(admission.as_ref().is_none_or(|permit|permit.valid()),"private stream admission retired");
        self.validate(source, &payload)?;
        let permit = self
            .input
            .reserve()
            .await
            .map_err(|_| anyhow::anyhow!("private stream receive queue unavailable"))?;
        self.validate(source, &payload)?;
        ensure!(admission.as_ref().is_none_or(|permit|permit.valid()),"private stream admission retired");
        permit.send(Datagram {
            permit:admission,
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
        let mut dropped=0;loop {let packet=self.output.recv().await?;if packet.permit.as_ref().is_none_or(|permit|permit.valid()){return Some(packet);}dropped+=1;if dropped%32==0{tokio::task::yield_now().await;}}
    }
    /// The caller must derive `source` from the authenticated peer identity,
    /// never from an untrusted packet's claimed IP address.
    pub fn incoming(&self, source: Ipv4Addr, payload: Bytes) -> Result<()> {
        self.ingress().send(source, payload)
    }
}
struct PacketSocket {
    #[cfg(test)] blocked_sends:Arc<AtomicUsize>,
    #[cfg(test)] denied_sends:Arc<AtomicUsize>,
    generation:Option<crate::udp::SendFactory>,
    admissions:Admissions,
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
struct Writable {sender:Mutex<PollSender<Datagram>>,#[cfg(test)] blocked:Arc<AtomicUsize>}
impl fmt::Debug for Writable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateStreamWritable")
    }
}
impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut sender = self.sender.lock().unwrap_or_else(|p| p.into_inner());
        match sender.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                sender.abort_send();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => {#[cfg(test)] self.blocked.fetch_add(1,Ordering::SeqCst);Poll::Pending},
        }
    }
}
impl AsyncUdpSocket for PacketSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable{sender:Mutex::new(PollSender::new(self.output.clone())),#[cfg(test)] blocked:self.blocked_sends.clone()})
    }
    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        let generation=match &self.generation {Some(factory)=>match factory.snapshot(){Some(permit) if permit.valid()=>Some(permit),_=>{#[cfg(test)] self.denied_sends.fetch_add(1,Ordering::SeqCst);return Ok(());}},None=>None};
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
        let permit=match &*self.admissions.read().unwrap_or_else(|p|p.into_inner()) {
            Some(admissions)=>match admissions.get(&destination){Some(permit) if permit.valid()=>Some(permit.clone()),_=>return Ok(())},None=>None
        };
        let permit=match (generation,permit){(Some(a),Some(b))=>Some(crate::udp::SendPermit::new(move||a.valid()&&b.valid())),(a,b)=>a.or(b)};
        self.output
            .try_send(Datagram {
                permit,
                address: destination,
                payload: Bytes::copy_from_slice(transmit.contents),
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {#[cfg(test)] self.blocked_sends.fetch_add(1,Ordering::SeqCst);io::ErrorKind::WouldBlock.into()},
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
                let current=self.admissions.read().unwrap_or_else(|p|p.into_inner());
                let generation=self.generation.as_ref().is_none_or(|factory|factory.snapshot().is_some_and(|permit|permit.valid()));
                let accepted=generation&&match &*current {Some(admissions)=>admissions.get(&packet.address).is_some_and(|permit|permit.valid())&&packet.permit.as_ref().is_some_and(|permit|permit.valid()),None=>packet.permit.as_ref().is_none_or(|permit|permit.valid())};
                if !accepted {cx.waker().wake_by_ref();return Poll::Pending;}
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
fn transport(idle_timeout: Option<Duration>,credited:bool,bounded_source:bool) -> Result<Arc<quinn::TransportConfig>> {
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
        .send_window(32 * 1024 * 1024);
    if credited {
        config.max_concurrent_bidi_streams(0u8.into()).stream_receive_window(8288u32.into()).receive_window(8288u32.into()).send_window(96);
    } else if bounded_source {
        config.max_concurrent_bidi_streams(0u8.into()).stream_receive_window(96u32.into()).receive_window(96u32.into()).send_window(8288);
    }
    if let Some(timeout) = idle_timeout {
        config.max_idle_timeout(Some(timeout.try_into()?));
    }
    config.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
    Ok(Arc::new(config))
}
/// Proof that this connection was created by an endpoint whose immutable
/// socket-generation factory is the supplied one, not a later admission map.
#[derive(Clone)]
pub struct FencedConnection {connection:Connection,generation:crate::udp::SendFactory,peer:Peer,local:Ipv4Addr}
impl FencedConnection {
    pub fn local_ip(&self)->Ipv4Addr{self.local}
    pub fn peer(&self)->&Peer{&self.peer}
    pub fn connection(&self)->&Connection{&self.connection}
    pub fn belongs_to(&self,generation:&crate::udp::SendFactory)->bool{self.generation.same_generation(generation)}
}

/// Sealed outgoing guarded profile: no raw Connection/window mutation escape.
#[derive(Clone)]
pub struct BoundedSourceConnection {connection:Connection,generation:crate::udp::SendFactory,peer:Peer,local:Ipv4Addr}
impl BoundedSourceConnection {
    pub fn peer(&self)->&Peer{&self.peer}
    pub fn local_ip(&self)->Ipv4Addr{self.local}
    pub fn belongs_to(&self,generation:&crate::udp::SendFactory)->bool{self.generation.same_generation(generation)}
    pub fn stats(&self)->quinn::ConnectionStats{self.connection.stats()}
    pub fn close(&self){self.connection.close(1u8.into(),b"guarded source stopped");}
    pub async fn closed(&self){self.connection.closed().await;}
    pub async fn open_chunk(&self,original:&crate::udp::SendPermit)->Result<(SendStream,RecvStream)>{
        ensure!(original.remaining().is_some(),"guarded source origin bound unknown");
        Ok(original.during(self.connection.open_bi()).await??)
    }
}

/// A credited receiver has no public raw Quinn Connection escape hatch. Only
/// this owned, non-Clone wrapper can advertise its one incoming stream.
pub struct CreditedReceiverConnection {connection:Connection,generation:crate::udp::SendFactory,peer:Peer,local:Ipv4Addr}
#[derive(Clone)]
pub struct ReceiverCloser(Connection);
impl ReceiverCloser {pub fn close(&self){self.0.close(1u8.into(),b"RX generation retired");} pub async fn closed(&self){self.0.closed().await;}}
struct AcceptCreditAttempt {closer:ReceiverCloser,armed:bool}
impl Drop for AcceptCreditAttempt{fn drop(&mut self){if self.armed{self.closer.close();}}}
impl Drop for CreditedReceiverConnection{fn drop(&mut self){self.connection.close(1u8.into(),b"RX owner stopped");}}
impl CreditedReceiverConnection {
    pub fn peer(&self)->&Peer{&self.peer}
    pub fn local_ip(&self)->Ipv4Addr{self.local}
    pub fn belongs_to(&self,generation:&crate::udp::SendFactory)->bool{self.generation.same_generation(generation)}
    pub fn closer(&self)->ReceiverCloser{ReceiverCloser(self.connection.clone())}
    pub fn stats(&self)->quinn::ConnectionStats{self.connection.stats()}
    pub async fn accept_one(&mut self,original:&crate::udp::SendPermit)->Result<(SendStream,RecvStream)>{
        ensure!(original.valid(),"RX original credit retired before advertisement");
        let mut attempt=AcceptCreditAttempt{closer:self.closer(),armed:true};
        self.connection.set_max_concurrent_bi_streams(1u8.into());
        let accepted=original.during(self.connection.accept_bi()).await?;
        // Disable automatic replacement BEFORE either half can be freed.
        self.connection.set_max_concurrent_bi_streams(0u8.into());
        let accepted=accepted?;attempt.armed=false;Ok(accepted)
    }
}

pub struct Endpoint {
    #[cfg(test)] blocked_sends:Arc<AtomicUsize>,
    #[cfg(test)] denied_sends:Arc<AtomicUsize>,
    generation:Option<crate::udp::SendFactory>,
    admissions:Admissions,
    admission_bindings:Mutex<HashMap<Ipv4Addr,Arc<std::sync::atomic::AtomicBool>>>,
    inner: quinn::Endpoint,
    local: Ipv4Addr,
    identity: Identity,
    peers: Peers,
    connections: Mutex<HashMap<Ipv4Addr, Vec<quinn::Connection>>>,
    next_connection: AtomicUsize,
    peer_budget: AtomicUsize,
    protocols: Vec<Vec<u8>>,
    credited:bool,
    bounded_source:bool,
}
impl Endpoint {
    pub fn new(identity: Identity, local: Ipv4Addr) -> Result<(Self, PacketIo)> {
        Self::with_protocols(identity, local, vec![PARALLEL_ALPN.into(), ALPN.into()])
    }
    pub fn new_fenced(identity:Identity,local:Ipv4Addr,generation:crate::udp::SendFactory)->Result<(Self,PacketIo)> {
        Self::with_protocols_fenced(identity,local,vec![PARALLEL_ALPN.into(),ALPN.into()],Some(generation))
    }
    /// Experimental receiver profile: advertise no incoming application stream
    /// until its immutable origin credit is installed. Legacy profile unchanged.
    pub fn new_fenced_credited(identity:Identity,local:Ipv4Addr,generation:crate::udp::SendFactory)->Result<(Self,PacketIo)>{
        Self::with_protocols_profile(identity,local,vec![ORIGIN_ALPN.into()],Some(generation),QUEUE,true,false)
    }
    pub fn new_fenced_source(identity:Identity,local:Ipv4Addr,generation:crate::udp::SendFactory)->Result<(Self,PacketIo)>{
        Self::with_protocols_profile(identity,local,vec![ORIGIN_ALPN.into()],Some(generation),QUEUE,false,true)
    }
    fn with_protocols(identity:Identity,local:Ipv4Addr,protocols:Vec<Vec<u8>>)->Result<(Self,PacketIo)> {Self::with_protocols_fenced(identity,local,protocols,None)}
    fn with_protocols_fenced(identity:Identity,local:Ipv4Addr,protocols:Vec<Vec<u8>>,generation:Option<crate::udp::SendFactory>)->Result<(Self,PacketIo)>{Self::with_protocols_fenced_capacity(identity,local,protocols,generation,QUEUE)}
    fn with_protocols_fenced_capacity(
        identity: Identity,
        local: Ipv4Addr,
        protocols: Vec<Vec<u8>>,
        generation:Option<crate::udp::SendFactory>,
        capacity:usize,
    ) -> Result<(Self, PacketIo)> {
        Self::with_protocols_profile(identity,local,protocols,generation,capacity,false,false)
    }
    fn with_protocols_profile(identity:Identity,local:Ipv4Addr,protocols:Vec<Vec<u8>>,generation:Option<crate::udp::SendFactory>,capacity:usize,credited:bool,bounded_source:bool)->Result<(Self,PacketIo)>{
        ensure!((1..=QUEUE).contains(&capacity),"invalid bounded stream queue capacity");
        ensure!(local.is_private(), "invalid private stream endpoint");
        let peers: Peers = Default::default();
        let admissions:Admissions=Default::default();
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
        tls.alpn_protocols = protocols.clone();
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
        ));
        server.transport = transport(None,credited,bounded_source)?;
        let (input, incoming) = mpsc::channel(QUEUE);
        let (outgoing, output) = mpsc::channel(capacity);
        #[cfg(test)] let blocked_sends=Arc::new(AtomicUsize::new(0));
        #[cfg(test)] let denied_sends=Arc::new(AtomicUsize::new(0));
        let socket = Arc::new(PacketSocket {
            #[cfg(test)] blocked_sends:blocked_sends.clone(),
            #[cfg(test)] denied_sends:denied_sends.clone(),            generation:generation.clone(),            admissions:admissions.clone(),            local,
            input: Mutex::new(incoming),
            output: outgoing,
        });
        let mut config = quinn::EndpointConfig::default();
        config.max_udp_payload_size(MAX_DATAGRAM as u16)?;
        let inner = quinn::Endpoint::new_with_abstract_socket(
            config,
            if bounded_source{None}else{Some(server)},
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        Ok((
            Self {
                #[cfg(test)] blocked_sends,
                #[cfg(test)] denied_sends,
                generation,
                admissions,
                admission_bindings:Default::default(),
                inner,
                local,
                identity,
                peers: peers.clone(),
                connections: Default::default(),
                next_connection: AtomicUsize::new(0),
                peer_budget: AtomicUsize::new(if credited||bounded_source{64}else{MAX_CONNECTIONS}),
                protocols,
                credited,
                bounded_source,
            },
            PacketIo {
                input,
                output,
                peers,
            },
        ))
    }
    /// A sparse identity cache is not a request to eagerly allocate sockets for every entry.
    /// This lowers admission only; it never increases the existing endpoint bounds.
    pub fn set_peer_connection_budget(&self,limit:usize)->Result<()> {
        let maximum=if self.credited||self.bounded_source{64}else{MAX_CONNECTIONS};
        ensure!((1..=maximum).contains(&limit),"invalid private stream peer budget");
        self.peer_budget.store(limit,Ordering::Relaxed);Ok(())
    }
    pub fn capacity_for(&self,peer:&Peer)->bool {
        let connections=self.connections.lock().unwrap_or_else(|p|p.into_inner());
        let active=|connections:&Vec<quinn::Connection>|connections.iter().any(|c|c.close_reason().is_none());
        connections.get(&peer.ip).is_some_and(active)
            || connections.values().filter(|c|active(c)).count()<self.peer_budget.load(Ordering::Relaxed)
    }
    /// Pins originate only from an authenticated private-policy snapshot.
    /// Port grants are checked separately when a TCP stream is opened.
    /// None preserves legacy behavior. Some is an explicit fail-closed sparse
    /// admission table; original permits are copied into each emitted datagram.
    pub fn update_send_admissions(&self,admissions:Option<HashMap<Ipv4Addr,crate::udp::SendPermit>>)->Result<()> {
        let peers=self.peers.read().unwrap_or_else(|p|p.into_inner());
        let bindings=self.admission_bindings.lock().unwrap_or_else(|p|p.into_inner());
        let admissions=if let Some(next)=admissions {
            ensure!(next.len()<=MAX_PEERS,"private stream admissions exceed bound");
            ensure!(next.keys().all(|ip|peers.contains_key(ip)&&bindings.contains_key(ip)),"stream admission does not match current peer");
            Some(next.into_iter().map(|(ip,permit)|{let binding=bindings[&ip].clone();(ip,crate::udp::SendPermit::new(move||binding.load(Ordering::SeqCst)&&permit.valid()))}).collect())
        }else{None};
        *self.admissions.write().unwrap_or_else(|p|p.into_inner())=admissions;Ok(())
    }
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
        // Retire old queued/native permits BEFORE closing old connections: close
        // wakes the QUIC driver and must not emit stale buffered application data.
        let mut bindings=self.admission_bindings.lock().unwrap_or_else(|p|p.into_inner());
        bindings.retain(|ip,active|{let keep=trusted.get(ip)==next.get(ip);if !keep{active.store(false,Ordering::SeqCst);}keep});
        for ip in next.keys(){bindings.entry(*ip).or_insert_with(||Arc::new(std::sync::atomic::AtomicBool::new(true)));}
        drop(bindings);
        self.connections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|ip, peer_connections| {
                let allowed = trusted.get(ip) == next.get(ip);
                peer_connections.retain(|connection| {
                    let keep = connection.close_reason().is_none() && allowed;
                    if !keep && !allowed {
                        connection.close(1u8.into(), b"private peer authorization changed");
                    }
                    keep
                });
                !peer_connections.is_empty()
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
        connections.retain(|_, peer_connections| {
            peer_connections.retain(|connection| connection.close_reason().is_none());
            !peer_connections.is_empty()
        });
        if !connections.contains_key(&ip) && connections.len()>=self.peer_budget.load(Ordering::Relaxed) {
            connection.close(2u8.into(),b"private stream peer budget reached");anyhow::bail!("private stream peer budget reached");
        }
        let connection_count: usize = connections.values().map(Vec::len).sum();
        ensure!(
            connection_count < MAX_CONNECTIONS * MAX_CONNECTIONS_PER_PEER,
            "private stream connection limit reached"
        );
        let peer_connections = connections.entry(ip).or_default();
        if peer_connections.len() >= MAX_CONNECTIONS_PER_PEER {
            connection.close(2u8.into(), b"private stream connection already prepared");
            anyhow::bail!("private stream connection limit reached");
        }
        peer_connections.push(connection.clone());
        Ok((peer, connection))
    }
    pub fn prepared(&self, expected: &Peer) -> Option<quinn::Connection> {
        if self.credited||self.bounded_source{return None;}
        self.prepared_inner(expected)
    }
    fn prepared_inner(&self,expected:&Peer)->Option<quinn::Connection>{
        let trusted = self.peers.read().unwrap_or_else(|p| p.into_inner());
        if trusted.get(&expected.ip) != Some(expected) {
            return None;
        }
        let mut connections = self.connections.lock().unwrap_or_else(|p| p.into_inner());
        let peer_connections = connections.get_mut(&expected.ip)?;
        peer_connections.retain(|connection| connection.close_reason().is_none());
        if peer_connections.is_empty() {
            connections.remove(&expected.ip);
            return None;
        }
        let lane = self.next_connection.fetch_add(1, Ordering::Relaxed) % peer_connections.len();
        peer_connections.get(lane).cloned()
    }
    pub fn connection_count(&self, expected: &Peer) -> usize {
        let trusted = self.peers.read().unwrap_or_else(|p| p.into_inner());
        if trusted.get(&expected.ip) != Some(expected) {
            return 0;
        }
        let mut connections = self.connections.lock().unwrap_or_else(|p| p.into_inner());
        let Some(peer_connections) = connections.get_mut(&expected.ip) else {
            return 0;
        };
        peer_connections.retain(|connection| connection.close_reason().is_none());
        let count = peer_connections.len();
        if count == 0 {
            connections.remove(&expected.ip);
        }
        count
    }
    pub fn connection_stats(&self, expected: &Peer) -> Vec<quinn::ConnectionStats> {
        let trusted = self.peers.read().unwrap_or_else(|p| p.into_inner());
        if trusted.get(&expected.ip) != Some(expected) {
            return Vec::new();
        }
        let mut connections = self.connections.lock().unwrap_or_else(|p| p.into_inner());
        let Some(peer_connections) = connections.get_mut(&expected.ip) else {
            return Vec::new();
        };
        peer_connections.retain(|connection| connection.close_reason().is_none());
        let stats = peer_connections.iter().map(Connection::stats).collect();
        if peer_connections.is_empty() {
            connections.remove(&expected.ip);
        }
        stats
    }
    pub async fn connect_source(&self,peer:&Peer)->Result<BoundedSourceConnection>{
        ensure!(self.bounded_source,"endpoint has no bounded source profile");
        let generation=self.generation.clone().ok_or_else(||anyhow::anyhow!("source generation absent"))?;
        let connection=self.connect_inner(peer).await?;Ok(BoundedSourceConnection{connection,generation,peer:peer.clone(),local:self.local})
    }
    pub async fn connect_fenced(&self,peer:&Peer)->Result<FencedConnection> {
        let generation=self.generation.clone().ok_or_else(||anyhow::anyhow!("connection has no immutable socket-generation fence"))?;
        let connection=self.connect(peer).await?;Ok(FencedConnection{connection,generation,peer:peer.clone(),local:self.local})
    }
    pub async fn connect(&self, expected: &Peer) -> Result<quinn::Connection> {
        ensure!(!self.credited&&!self.bounded_source,"guarded profile requires owned connection wrapper");
        self.connect_inner(expected).await
    }
    async fn connect_inner(&self,expected:&Peer)->Result<quinn::Connection>{
        let ip = expected.ip;
        ensure!(self.capacity_for(expected),"private stream peer budget reached");
        ensure!(
            self.peers
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .get(&ip)
                == Some(expected),
            "private stream peer not admitted"
        );
        if let Some(connection) = self.prepared_inner(expected) {
            return Ok(connection);
        }
        self.connect_new(expected, None).await
    }
    /// Parallel lanes are negotiated in the authenticated TLS handshake. Older
    /// peers retain one connection without repeated rejected extra handshakes.
    pub fn supports_parallel(&self, expected: &Peer) -> bool {
        let trusted = self.peers.read().unwrap_or_else(|p| p.into_inner());
        if trusted.get(&expected.ip) != Some(expected) {
            return false;
        }
        let connections = self.connections.lock().unwrap_or_else(|p| p.into_inner());
        connections.get(&expected.ip).is_some_and(|connections| {
            connections
                .iter()
                .find(|connection| connection.close_reason().is_none())
                .and_then(|connection| connection.handshake_data())
                .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .is_some_and(|data| data.protocol.as_deref() == Some(PARALLEL_ALPN))
        })
    }
    /// Keep negotiated lanes prepared without keepalive traffic. Opening an
    /// application flow after an idle period must not wait for new handshakes.
    pub async fn connect_additional(&self, expected: &Peer) -> Result<quinn::Connection> {
        ensure!(!self.credited&&!self.bounded_source,"guarded profile requires owned connection wrapper");
        ensure!(
            self.supports_parallel(expected),
            "private peer supports one stream connection"
        );
        ensure!(
            self.connection_count(expected) < MAX_CONNECTIONS_PER_PEER,
            "private stream lane limit reached"
        );
        self.connect_new(expected, None).await
    }
    async fn connect_new(
        &self,
        expected: &Peer,
        idle_timeout: Option<Duration>,
    ) -> Result<quinn::Connection> {
        let ip = expected.ip;
        ensure!(
            self.peers
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .get(&ip)
                == Some(expected),
            "private stream peer not admitted"
        );
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
        tls.alpn_protocols = self.protocols.clone();
        let mut config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
        ));
        config.transport_config(transport(idle_timeout,self.credited,self.bounded_source)?);
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
    pub async fn accept_fenced(&self)->Result<FencedConnection>{
        ensure!(!self.credited&&!self.bounded_source,"guarded profile requires owned connection wrapper");
        let generation=self.generation.clone().ok_or_else(||anyhow::anyhow!("receiver has no immutable socket fence"))?;
        let (peer,connection)=self.accept().await?;Ok(FencedConnection{connection,generation,peer,local:self.local})
    }
    pub async fn accept_credited(&self)->Result<CreditedReceiverConnection>{
        ensure!(self.credited,"endpoint has no credited receiver profile");
        let generation=self.generation.clone().ok_or_else(||anyhow::anyhow!("receiver generation absent"))?;
        let (peer,connection)=self.accept_inner().await?;Ok(CreditedReceiverConnection{connection,generation,peer,local:self.local})
    }
    pub async fn accept(&self) -> Result<(Peer, quinn::Connection)> {
        ensure!(!self.credited&&!self.bounded_source,"guarded profile requires owned connection wrapper");
        self.accept_inner().await
    }
    async fn accept_inner(&self)->Result<(Peer,quinn::Connection)>{
        let incoming = self
            .inner
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("private stream endpoint stopped"))?;
        let connection = tokio::time::timeout(Duration::from_secs(10), incoming).await??;
        self.register(connection, None)
    }
    pub fn close(&self) {
        for active in self.admission_bindings.lock().unwrap_or_else(|p|p.into_inner()).values(){active.store(false,Ordering::SeqCst);}
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
    async fn origin_profile_rejects_legacy_alpn_before_any_application_open()->Result<()>{
        let a=Identity::new()?;let b=Identity::new()?;let aip="10.234.245.1".parse()?;let bip="10.234.245.2".parse()?;
        let ap=Peer{id:"a".into(),ip:aip,fingerprint:a.fingerprint().into(),instance:"a".into()};let bp=Peer{id:"b".into(),ip:bip,fingerprint:b.fingerprint().into(),instance:"b".into()};
        let factory=crate::udp::SendFactory::new(||Some(crate::udp::SendPermit::control(||true)));
        let(source,mut ai)=Endpoint::new_fenced_source(a,aip,factory)?;let(target,mut bi)=Endpoint::new(b,bip)?;
        source.update_peers(vec![bp.clone()])?;target.update_peers(vec![ap])?;
        let ia=ai.ingress();let ib=bi.ingress();let stop=tokio_util::sync::CancellationToken::new();let cancel=stop.clone();
        let pump=tokio::spawn(async move{loop{tokio::select!{_=cancel.cancelled()=>break,p=ai.outgoing()=>match p{Some(p)=>{let _=ib.send_reliable_guarded(aip,p.payload,p.permit).await;},None=>break},p=bi.outgoing()=>match p{Some(p)=>{let _=ia.send_reliable_guarded(bip,p.payload,p.permit).await;},None=>break}}}});
        let result=tokio::time::timeout(Duration::from_secs(2),async{tokio::join!(source.connect_source(&bp),target.accept())}).await;
        source.close();target.close();stop.cancel();pump.await?;
        ensure!(matches!(result,Ok((Err(_),Err(_)))),"origin profile negotiated legacy/raw stream protocol");Ok(())
    }
    #[tokio::test]
    async fn bounded_source_has_no_unsolicited_streams_and_exact_96_byte_receipt_window()->Result<()>{
        let a=Identity::new()?;let b=Identity::new()?;let a_ip="10.234.246.1".parse()?;let b_ip="10.234.246.2".parse()?;
        let a_peer=Peer{id:"source".into(),ip:a_ip,fingerprint:a.fingerprint().into(),instance:"one".into()};let b_peer=Peer{id:"receiver".into(),ip:b_ip,fingerprint:b.fingerprint().into(),instance:"two".into()};
        let factory=crate::udp::SendFactory::new(||Some(crate::udp::SendPermit::control(||true)));
        let(source,mut a_io)=Endpoint::new_fenced_source(a,a_ip,factory.clone())?;let(destination,mut b_io)=Endpoint::with_protocols(b,b_ip,vec![ORIGIN_ALPN.into()])?;source.update_peers(vec![b_peer.clone()])?;destination.update_peers(vec![a_peer.clone()])?;
        assert!(source.set_peer_connection_budget(65).is_err());assert!(destination.set_peer_connection_budget(512).is_ok());
        let a_in=a_io.ingress();let b_in=b_io.ingress();let stop=tokio_util::sync::CancellationToken::new();let cancel=stop.clone();let pump=tokio::spawn(async move{loop{tokio::select!{
            _=cancel.cancelled()=>break,
            p=a_io.outgoing()=>match p{Some(p)=>{let _=b_in.send_reliable_guarded(a_ip,p.payload,p.permit).await;},None=>break},
            p=b_io.outgoing()=>match p{Some(p)=>{let _=a_in.send_reliable_guarded(b_ip,p.payload,p.permit).await;},None=>break}
        }}});
        let mut writer=None;
        let result=async{
            let(client,server)=tokio::time::timeout(Duration::from_secs(3),async{tokio::join!(source.connect_source(&b_peer),destination.accept())}).await?;let client=client?;let(_,server)=server?;
            ensure!(client.peer()==&b_peer&&client.belongs_to(&factory),"bounded source identity/factory not sealed");ensure!(source.prepared(&b_peer).is_none()&&source.connect(&b_peer).await.is_err()&&source.connect_fenced(&b_peer).await.is_err(),"raw source connection escaped");
            ensure!(matches!(tokio::time::timeout(Duration::from_millis(30),source.accept()).await,Ok(Err(_))),"source accepted raw incoming connection");
            ensure!(tokio::time::timeout(Duration::from_millis(30),server.open_bi()).await.is_err(),"unsolicited remote stream allowed");
            let origin=crate::udp::SendPermit::bounded(||true,||Some(Duration::from_secs(10)));let(mut request,mut receipt)=client.open_chunk(&origin).await?;request.write_all(b"request").await?;request.finish()?;
            let(mut reply,mut input)=server.accept_bi().await?;ensure!(input.read_to_end(7).await?==b"request","bounded source request changed");writer=Some(tokio::spawn(async move{reply.write_all(&vec![7;4096]).await?;reply.finish()?;ensure!(reply.stopped().await?.is_none(),"adversarial reply reset");Ok::<_,anyhow::Error>(())}));
            tokio::time::timeout(Duration::from_secs(1),async{while client.stats().frame_rx.stream==0{tokio::task::yield_now().await;}}).await?;
            ensure!(tokio::time::timeout(Duration::from_millis(30),writer.as_mut().unwrap()).await.is_err(),"oversized reply escaped receive credit before application read");
            let first=receipt.read_chunk(4096,true).await?.ok_or_else(||anyhow::anyhow!("receipt unexpectedly ended"))?;ensure!(first.bytes.len()==96,"receipt prebuffer exceeded exact96-byte window");
            client.close();Ok::<_,anyhow::Error>(())
        }.await;
        source.close();destination.close();stop.cancel();pump.await?;if let Some(writer)=writer{let _=tokio::time::timeout(Duration::from_secs(1),writer).await?;}result
    }
    #[tokio::test]
    async fn actual_quinn_prepared_transmit_cannot_borrow_republished_admission_on_retired_socket()->Result<()> {
        let a=Identity::new()?;let b=Identity::new()?;let a_ip="10.234.251.1".parse()?;let b_ip="10.234.251.2".parse()?;
        let alive=Arc::new(std::sync::atomic::AtomicBool::new(true));let original=alive.clone();
        let factory=crate::udp::SendFactory::new(move||{
            if !original.load(Ordering::SeqCst){return None;}
            let original=original.clone();Some(crate::udp::SendPermit::new(move||original.load(Ordering::SeqCst)))
        });
        let b_peer=Peer{id:"b".into(),ip:b_ip,fingerprint:b.fingerprint().into(),instance:"b".into()};
        let a_peer=Peer{id:"a".into(),ip:a_ip,fingerprint:a.fingerprint().into(),instance:"a".into()};
        // Capacity 1 forces poll_writable Pending. Pinned Quinn 0.11.12
        // State::drive_transmit prepares t BEFORE poll_writable and stores it
        // in buffered_transmit on Pending; no try_send(WouldBlock) is required.
        // Production still uses unchanged QUEUE=256.
        let(source,mut a_io)=Endpoint::with_protocols_fenced_capacity(a,a_ip,vec![ALPN.into()],Some(factory.clone()),1)?;
        let(destination,mut b_io)=Endpoint::new(b,b_ip)?;source.update_peers(vec![b_peer.clone()])?;destination.update_peers(vec![a_peer])?;
        let a_in=a_io.ingress();let b_in=b_io.ingress();let stop=tokio_util::sync::CancellationToken::new();let cancel=stop.clone();
        let(pause,mut paused)=tokio::sync::watch::channel(false);let(report,mut reported)=tokio::sync::watch::channel(false);
        let pump=tokio::spawn(async move{let mut halted=false;loop{tokio::select!{biased;
            _=cancel.cancelled()=>break,
            result=paused.changed()=>{if result.is_err(){break;}halted=*paused.borrow_and_update();report.send_replace(halted);},
            packet=a_io.outgoing(),if !halted=>match packet{Some(packet)=>{let _=b_in.send_reliable_guarded(a_ip,packet.payload,packet.permit).await;},None=>break},
            packet=b_io.outgoing()=>match packet{Some(packet)=>{let _=a_in.send_reliable_guarded(b_ip,packet.payload,packet.permit).await;},None=>break}
        }}});
        let(client,server)=tokio::time::timeout(Duration::from_secs(3),async{tokio::join!(source.connect_fenced(&b_peer),destination.accept())}).await?;
        let client=client?;let(_,server)=server?;
        ensure!(client.belongs_to(&factory),"fenced connection lost immutable factory");
        ensure!(!client.belongs_to(&crate::udp::SendFactory::new(||Some(crate::udp::SendPermit::new(||true)))),"fresh generation aliased old connection");
        pause.send(true)?;while !*reported.borrow_and_update(){reported.changed().await?;}
        source.blocked_sends.store(0,Ordering::SeqCst);let baseline=client.connection().stats().frame_tx.stream;
        let(mut send,_receive)=client.connection().open_bi().await?;send.write_all(&vec![3;8192]).await?;send.finish()?;
        tokio::time::timeout(Duration::from_secs(1),async{while source.blocked_sends.load(Ordering::SeqCst)==0||client.connection().stats().frame_tx.stream<=baseline{tokio::task::yield_now().await;}}).await?;
        alive.store(false,Ordering::SeqCst);
        // A current mutable peer admission must not re-authorize Quinn's OLD
        // already-prepared bytes: the socket's factory cannot be replaced.
        source.update_send_admissions(Some(HashMap::from([(b_ip,crate::udp::SendPermit::new(||true))])))?;
        pause.send(false)?;while *reported.borrow_and_update(){reported.changed().await?;}
        tokio::time::timeout(Duration::from_secs(1),async{while source.denied_sends.load(Ordering::SeqCst)==0{tokio::task::yield_now().await;}}).await?;
        ensure!(tokio::time::timeout(Duration::from_millis(50),server.accept_bi()).await.is_err(),"retired prepared application transmit reached peer");
        let _=send.reset(1u8.into());source.close();destination.close();stop.cancel();pump.await?;Ok(())
    }
    #[tokio::test]
    async fn endpoint_identity_replacement_retires_already_queued_permits()->Result<()> {
        let a=Identity::new()?;let b=Identity::new()?;let (endpoint,_)=Endpoint::new(a,"10.234.253.1".parse()?)?;
        let mut peer=Peer{id:"b".into(),ip:"10.234.253.2".parse()?,fingerprint:b.fingerprint().into(),instance:"old".into()};
        endpoint.update_peers(vec![peer.clone()])?;
        endpoint.update_send_admissions(Some(HashMap::from([(peer.ip,crate::udp::SendPermit::new(||true))])))?;
        let old=endpoint.admissions.read().unwrap().as_ref().unwrap()[&peer.ip].clone();assert!(old.valid());
        peer.instance="new".into();endpoint.update_peers(vec![peer.clone()])?;assert!(!old.valid());
        endpoint.update_send_admissions(Some(HashMap::from([(peer.ip,crate::udp::SendPermit::new(||true))])))?;
        assert!(endpoint.admissions.read().unwrap().as_ref().unwrap()[&peer.ip].valid());assert!(!old.valid());
        endpoint.close();assert!(!endpoint.admissions.read().unwrap().as_ref().unwrap()[&peer.ip].valid());Ok(())
    }
    #[tokio::test]
    async fn actual_packet_socket_and_packetio_keep_original_admission_on_both_queues()->Result<()> {
        let local=Ipv4Addr::new(10,234,253,1);let remote=Ipv4Addr::new(10,234,253,2);
        let active=Arc::new(std::sync::atomic::AtomicBool::new(true));let old_active=active.clone();
        let old=crate::udp::SendPermit::new(move||old_active.load(Ordering::SeqCst));
        let fresh=crate::udp::SendPermit::new(||true);
        let admissions:Admissions=Arc::new(RwLock::new(Some(HashMap::from([(remote,old.clone())]))));
        let (send,input)=mpsc::channel(2);let (output,receive)=mpsc::channel(2);
        let socket=PacketSocket{blocked_sends:Default::default(),denied_sends:Default::default(),generation:None,local,input:Mutex::new(input),output,admissions:admissions.clone()};
        let mut io=PacketIo{input:send.clone(),output:receive,peers:Default::default()};
        socket.try_send(&quinn::udp::Transmit{destination:(remote,PORT).into(),ecn:None,contents:b"old",segment_size:None,src_ip:None})?;
        send.send(Datagram{address:remote,payload:Bytes::from_static(b"old"),permit:Some(old)}).await?;
        active.store(false,Ordering::SeqCst);*admissions.write().unwrap()=Some(HashMap::from([(remote,fresh.clone())]));
        socket.try_send(&quinn::udp::Transmit{destination:(remote,PORT).into(),ecn:None,contents:b"new",segment_size:None,src_ip:None})?;
        let received=tokio::time::timeout(Duration::from_secs(1),io.outgoing()).await?.unwrap();assert_eq!(received.payload,Bytes::from_static(b"new"));
        let mut bytes=[0;16];let mut bufs=[IoSliceMut::new(&mut bytes)];let mut metadata=[quinn::udp::RecvMeta::default()];
        let mut context=Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(socket.poll_recv(&mut context,&mut bufs,&mut metadata).is_pending(),"retired ingress must not reach Quinn");
        send.send(Datagram{address:remote,payload:Bytes::from_static(b"new"),permit:Some(fresh)}).await?;
        assert!(matches!(socket.poll_recv(&mut context,&mut bufs,&mut metadata),Poll::Ready(Ok(1))));assert_eq!(&bufs[0][..metadata[0].len],b"new");
        Ok(())
    }
    #[tokio::test]
    async fn parallel_lanes_negotiate_and_legacy_peers_keep_one_connection() -> Result<()> {
        for parallel in [false, true] {
            let a_ip = Ipv4Addr::new(10, 234, 252, 1);
            let b_ip = Ipv4Addr::new(10, 234, 252, 2);
            let a_identity = Identity::new()?;
            let b_identity = Identity::new()?;
            let a_peer = Peer {
                id: "a".into(),
                ip: a_ip,
                fingerprint: a_identity.fingerprint().into(),
                instance: "a-instance".into(),
            };
            let b_peer = Peer {
                id: "b".into(),
                ip: b_ip,
                fingerprint: b_identity.fingerprint().into(),
                instance: "b-instance".into(),
            };
            let (a, mut a_io) = Endpoint::new(a_identity, a_ip)?;
            let protocols = if parallel {
                vec![PARALLEL_ALPN.into(), ALPN.into()]
            } else {
                vec![ALPN.into()]
            };
            let (b, mut b_io) = Endpoint::with_protocols(b_identity, b_ip, protocols)?;
            a.update_peers(vec![b_peer.clone()])?;
            b.update_peers(vec![a_peer.clone()])?;
            let a_in = a_io.ingress();
            let b_in = b_io.ingress();
            let wire = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        packet=a_io.outgoing()=>match packet {Some(packet)=>{let _=b_in.send_reliable(a_ip,packet.payload).await;},None=>break},
                        packet=b_io.outgoing()=>match packet {Some(packet)=>{let _=a_in.send_reliable(b_ip,packet.payload).await;},None=>break},
                    }
                }
            }));
            tokio::time::timeout(Duration::from_secs(5), async {
                let (source, (_, target)) = tokio::try_join!(a.connect(&b_peer), b.accept())?;
                assert_eq!(a.supports_parallel(&b_peer), parallel);
                assert_eq!(b.supports_parallel(&a_peer), parallel);
                if parallel {
                    tokio::try_join!(a.connect_additional(&b_peer), b.accept())?;
                    assert_eq!(a.connection_count(&b_peer), 2);
                } else {
                    assert!(a.connect_additional(&b_peer).await.is_err());
                    assert_eq!(a.connection_count(&b_peer), 1);
                }
                let send = async {
                    let (mut send, _) = source.open_bi().await?;
                    send.write_all(b"still connected").await?;
                    send.finish()?;
                    Ok::<_, anyhow::Error>(())
                };
                let receive = async {
                    let (_, mut receive) = target.accept_bi().await?;
                    assert_eq!(receive.read_to_end(64).await?, b"still connected");
                    Ok::<_, anyhow::Error>(())
                };
                tokio::try_join!(send, receive)?;
                Ok::<_, anyhow::Error>(())
            })
            .await??;
            wire.abort();
            let _ = wire.await;
        }
        Ok(())
    }

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
