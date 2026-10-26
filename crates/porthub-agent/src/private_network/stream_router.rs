//! Private TCP stream ownership. Policy and prepared peer connections are read
//! from memory; discovery and handshakes run outside the TUN packet loop.
use super::{
    controller::Event,
    policy::{PeerInfo, Snapshot},
    tcp_stream::{self, Flow},
};
use anyhow::{ensure, Result};
use bytes::Bytes;
use porthub_mesh::{
    streams::{self, Endpoint, Peer},
    Identity,
};
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

const MAX_FLOWS: usize = 512;
const MAX_STREAM_LANES: usize = 8;
const HEADER: &[u8; 4] = b"PHT1";
#[derive(Default)]
struct Ports(Vec<(u16, u16)>);
impl Ports {
    fn contains(&self, port: u16) -> bool {
        self.0
            .iter()
            .any(|&(start, end)| start <= port && port <= end)
    }
    fn merge(&mut self) {
        self.0.sort_unstable();
        let mut merged: Vec<(u16, u16)> = Vec::new();
        for (start, end) in self.0.drain(..) {
            if let Some(previous) = merged
                .last_mut()
                .filter(|previous| start <= previous.1.saturating_add(1))
            {
                previous.1 = previous.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        self.0 = merged;
    }
}
struct Policy {
    own: String,
    ip: Ipv4Addr,
    deadline: Instant,
    peers: HashMap<String, Peer>,
    incoming: HashMap<String, Ports>,
    outgoing: HashMap<String, Ports>,
}
impl Policy {
    fn empty(own: String, ip: Ipv4Addr) -> Self {
        Self {
            own,
            ip,
            deadline: Instant::now(),
            peers: HashMap::new(),
            incoming: HashMap::new(),
            outgoing: HashMap::new(),
        }
    }
    fn compile(snapshot: &Snapshot, own: &str, ip: Ipv4Addr) -> Result<Self> {
        ensure!(
            snapshot.self_ == own
                && snapshot
                    .peers
                    .iter()
                    .any(|peer| peer.id == own && peer.ip == ip),
            "private stream identity changed"
        );
        let mut policy = Self::empty(own.into(), ip);
        policy.deadline = Instant::now()
            + snapshot
                .expires_at
                .signed_duration_since(chrono::Utc::now())
                .to_std()?;
        for grant in &snapshot.grants {
            if grant.protocol != "tcp" && grant.protocol != "any" {
                continue;
            }
            let entry = if grant.source == own {
                policy
                    .outgoing
                    .entry(grant.destination.clone())
                    .or_default()
            } else if grant.destination == own {
                policy.incoming.entry(grant.source.clone()).or_default()
            } else {
                continue;
            };
            if grant.ports.is_empty() {
                entry.0.push((1, u16::MAX));
            } else {
                entry
                    .0
                    .extend(grant.ports.iter().map(|port| (port.start, port.end)));
            }
        }
        for ports in policy
            .incoming
            .values_mut()
            .chain(policy.outgoing.values_mut())
        {
            ports.merge();
        }
        for peer in &snapshot.peers {
            if peer.id != own
                && peer.stream_transport == "quic1"
                && !peer.fingerprint.is_empty()
                && !peer.instance.is_empty()
                && (policy.incoming.contains_key(&peer.id)
                    || policy.outgoing.contains_key(&peer.id))
            {
                policy.peers.insert(peer.id.clone(), mesh_peer(peer));
            }
        }
        Ok(policy)
    }
    fn allows(&self, peer: &Peer, flow: Flow, outbound: bool) -> bool {
        if self.peers.get(&peer.id) != Some(peer) {
            return false;
        }
        let (ports, source, destination) = if outbound {
            (&self.outgoing, self.ip, peer.ip)
        } else {
            (&self.incoming, peer.ip, self.ip)
        };
        *flow.source.ip() == source
            && *flow.destination.ip() == destination
            && flow.source.port() != 0
            && ports
                .get(&peer.id)
                .is_some_and(|ports| ports.contains(flow.destination.port()))
    }
}
fn mesh_peer(peer: &PeerInfo) -> Peer {
    Peer {
        id: peer.id.clone(),
        ip: peer.ip,
        fingerprint: peer.fingerprint.to_ascii_uppercase(),
        instance: peer.instance.clone(),
    }
}
struct Owned {
    flow: Flow,
    peer: Peer,
    outbound: bool,
    cancel: CancellationToken,
    finished: bool,
}
struct State {
    policy: Policy,
    flows: HashMap<Flow, Owned>,
}
enum Command {
    Source {
        kernel: Flow,
        syn: Bytes,
        connection: streams::Connection,
    },
    Ready {
        peer: Peer,
        connection: streams::Connection,
    },
    Incoming {
        peer: Peer,
        send: streams::SendStream,
        receive: streams::RecvStream,
        permit: OwnedSemaphorePermit,
    },
}
enum Finished {
    Owner(Result<()>),
    Dial(Peer, Result<streams::Connection>),
    Reader(usize),
    Flow(Option<Flow>),
}
#[derive(Clone)]
pub struct Router {
    state: Arc<Mutex<State>>,
    endpoint: Arc<Endpoint>,
    tcp: tcp_stream::Handle,
    ingress: streams::Ingress,
    receive_drops: Arc<AtomicU64>,
    commands: mpsc::Sender<Command>,
    changed: watch::Sender<u64>,
    events: mpsc::Sender<Event>,
    cancel: CancellationToken,
}
pub struct Background {
    carrier: Option<mpsc::Sender<streams::Datagram>>,
    router: Router,
    commands: mpsc::Receiver<Command>,
    changed: watch::Receiver<u64>,
    tcp_runner: tcp_stream::Runner,
    tcp_packets: mpsc::Receiver<Bytes>,
    packets: streams::PacketIo,
}
pub fn new(
    own: String,
    ip: Ipv4Addr,
    identity: Identity,
    events: mpsc::Sender<Event>,
    cancel: CancellationToken,
) -> Result<(Router, Background)> {
    let (endpoint, packets) = Endpoint::new(identity, ip)?;
    let ingress = packets.ingress();
    let (tcp, tcp_packets, tcp_runner) = tcp_stream::stack()?;
    let (commands, input) = mpsc::channel(128);
    let (changed, updates) = watch::channel(0);
    let router = Router {
        state: Arc::new(Mutex::new(State {
            policy: Policy::empty(own, ip),
            flows: HashMap::new(),
        })),
        endpoint: Arc::new(endpoint),
        tcp,
        ingress,
        receive_drops: Default::default(),
        commands,
        changed,
        events,
        cancel,
    };
    Ok((
        router.clone(),
        Background {
            carrier: None,
            router,
            commands: input,
            changed: updates,
            tcp_runner,
            tcp_packets,
            packets,
        },
    ))
}
impl Router {
    pub fn log_transport_stats(&self) {
        if !tracing::enabled!(tracing::Level::DEBUG) {
            return;
        }
        let receive_drops = self.receive_drops.load(Ordering::Relaxed);
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        for peer in state.policy.peers.values() {
            for (lane, stats) in self.endpoint.connection_stats(peer).into_iter().enumerate() {
                tracing::debug!(
                    peer_id = %peer.id,
                    lane,
                    lane_count = self.endpoint.connection_count(peer),
                    receive_drops,
                    tx_bytes = stats.udp_tx.bytes,
                    rx_bytes = stats.udp_rx.bytes,
                    rtt_us = stats.path.rtt.as_micros() as u64,
                    min_rtt_us = stats.path.min_rtt.as_micros() as u64,
                    cwnd = stats.path.cwnd,
                    sent_packets = stats.path.sent_packets,
                    lost_packets = stats.path.lost_packets,
                    lost_bytes = stats.path.lost_bytes,
                    stream_blocked = stats.frame_tx.stream_data_blocked,
                    connection_blocked = stats.frame_tx.data_blocked,
                    stream_credit_updates = stats.frame_rx.max_stream_data,
                    "private stream transport statistics"
                );
            }
        }
    }
    pub fn prepared(&self, peer_id: &str) -> bool {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.policy.deadline > Instant::now()
            && state
                .policy
                .peers
                .get(peer_id)
                .is_some_and(|peer| self.endpoint.prepared(peer).is_some())
    }
    pub fn update(&self, snapshot: &Snapshot) -> Result<()> {
        let (own, ip) = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            (state.policy.own.clone(), state.policy.ip)
        };
        let policy = Policy::compile(snapshot, &own, ip)?;
        self.endpoint
            .update_peers(policy.peers.values().cloned().collect())?;
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        for entry in state.flows.values() {
            if !policy.allows(&entry.peer, entry.flow, entry.outbound) {
                entry.cancel.cancel();
            }
        }
        state
            .flows
            .retain(|_, entry| !entry.finished || self.tcp.owns(entry.flow));
        state.policy = policy;
        self.changed.send_replace(snapshot.revision);
        Ok(())
    }
    pub fn valid_lease(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .policy
            .deadline
            > Instant::now()
    }
    pub async fn receive(&self, source: Ipv4Addr, payload: Bytes) {
        let deadline = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .policy
            .deadline;
        let now = Instant::now();
        if deadline <= now {
            return;
        }
        // The endpoint and transmit carrier have independent owners. A bounded
        // wait preserves receive pressure without trapping control-plane work.
        let deadline = deadline.min(now + Duration::from_millis(200));
        if !matches!(
            tokio::time::timeout_at(deadline.into(), self.ingress.send_reliable(source, payload))
                .await,
            Ok(Ok(()))
        ) {
            self.receive_drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    /// Returns immediately. A new flow uses a stream only after its peer's
    /// connection has already been prepared in the background.
    pub fn kernel_packet(&self, peer_id: &str, packet: Bytes, prefer_stream: bool) -> bool {
        let Some(kernel) = Flow::from_packet(&packet) else {
            return false;
        };
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = state.flows.get(&kernel) {
            if entry.peer.id == peer_id {
                if state.policy.deadline > Instant::now() && !entry.cancel.is_cancelled() {
                    let _ = self.tcp.packet(packet);
                }
                return true;
            }
            return false;
        }
        if !prefer_stream
            || state.policy.deadline <= Instant::now()
            || state.flows.len() >= MAX_FLOWS
            || self.commands.is_closed()
        {
            return false;
        }
        let Some(peer) = state.policy.peers.get(peer_id).cloned() else {
            return false;
        };
        if !state.policy.allows(&peer, kernel, true) || tcp_stream::reject_syn(&packet).is_err() {
            return false;
        }
        let Some(connection) = self.endpoint.prepared(&peer) else {
            tracing::debug!("private TCP stream not prepared; retaining packet path");
            return false;
        };
        tracing::debug!(
            port = kernel.destination.port(),
            connection_id = connection.stable_id(),
            "private TCP stream admitted locally"
        );
        state.flows.insert(
            kernel,
            Owned {
                flow: kernel,
                peer,
                outbound: true,
                cancel: self.cancel.child_token(),
                finished: false,
            },
        );
        if self
            .commands
            .try_send(Command::Source {
                kernel,
                syn: packet,
                connection,
            })
            .is_err()
        {
            state.flows.remove(&kernel);
            return false;
        }
        true
    }
    async fn event(&self, event: Event) {
        tokio::select! {_=self.cancel.cancelled()=>{},_=self.events.send(event)=>{}}
    }
    fn admit_target(&self, peer: &Peer, flow: Flow) -> Result<(Flow, CancellationToken)> {
        let kernel = flow.reverse();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            state.policy.deadline > Instant::now() && state.policy.allows(peer, flow, false),
            "private TCP stream is not authorized"
        );
        ensure!(
            state.flows.len() < MAX_FLOWS && !state.flows.contains_key(&kernel),
            "private TCP stream tuple unavailable"
        );
        let cancel = self.cancel.child_token();
        state.flows.insert(
            kernel,
            Owned {
                flow,
                peer: peer.clone(),
                outbound: false,
                cancel: cancel.clone(),
                finished: false,
            },
        );
        Ok((kernel, cancel))
    }
    async fn source(&self, kernel: Flow, syn: Bytes, connection: streams::Connection) -> Finished {
        let entry = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state
                .flows
                .get(&kernel)
                .map(|entry| (entry.peer.clone(), entry.cancel.clone()))
        };
        let Some((peer, cancel)) = entry else {
            return Finished::Flow(None);
        };
        let result = tokio::select! {
            _=cancel.cancelled()=>Err(anyhow::anyhow!("private TCP stream cancelled")),
            result=async {
                let opening=async {tokio::time::timeout(Duration::from_secs(12),async {
                    let (mut send,receive)=connection.open_bi().await?;
                    let mut header=[0;8];header[..4].copy_from_slice(HEADER);header[4..6].copy_from_slice(&kernel.source.port().to_be_bytes());header[6..8].copy_from_slice(&kernel.destination.port().to_be_bytes());
                    send.write_all(&header).await?;
                    Ok::<_,anyhow::Error>((send,receive))
                }).await?};
                // Prepare the local TCP leg concurrently. Header and payload
                // share one stream, so opening does not add a network round trip.
                let ((send,receive),(_,mut local))=tokio::try_join!(opening,self.tcp.accept_syn(syn.clone()))?;
                let mut remote=tokio::io::join(receive,send);
                tokio::io::copy_bidirectional(&mut local,&mut remote).await?;
                Ok::<_,anyhow::Error>(())
            }=>result,
        };
        if let Err(error) = &result {
            tracing::debug!(%error, reason=?connection.close_reason(), "private TCP source stream failed");
            let _ = self.tcp.close(kernel).await;
            if !self.tcp.owns(kernel) {
                if let Ok(bytes) = tcp_stream::reject_syn(&syn) {
                    self.event(Event::StreamLocal {
                        peer: peer.id,
                        bytes,
                    })
                    .await;
                }
            }
        }
        Finished::Flow(Some(kernel))
    }
    async fn target(
        &self,
        peer: Peer,
        mut send: streams::SendStream,
        mut receive: streams::RecvStream,
        permit: OwnedSemaphorePermit,
    ) -> Finished {
        let mut admitted = None;
        let result = async {
            let mut header = [0; 8];
            tokio::time::timeout(Duration::from_secs(3), receive.read_exact(&mut header)).await??;
            ensure!(&header[..4] == HEADER, "invalid private TCP stream header");
            let ip = self
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .policy
                .ip;
            let flow = Flow {
                source: std::net::SocketAddrV4::new(
                    peer.ip,
                    u16::from_be_bytes([header[4], header[5]]),
                ),
                destination: std::net::SocketAddrV4::new(
                    ip,
                    u16::from_be_bytes([header[6], header[7]]),
                ),
            };
            let (kernel, cancel) = self.admit_target(&peer, flow)?;
            admitted = Some((kernel, flow));
            drop(permit);
            tokio::select! {
                _=cancel.cancelled()=>Err(anyhow::anyhow!("private TCP stream cancelled")),
                result=async {
                    let mut local=self.tcp.connect(flow).await?;
                    let mut remote=tokio::io::join(&mut receive,&mut send);
                    tokio::io::copy_bidirectional(&mut local,&mut remote).await?;
                    Ok::<_,anyhow::Error>(())
                }=>result,
            }
        }
        .await;
        if let Err(error) = &result {
            tracing::debug!(%error,"private TCP target stream failed");
            if let Some((_, flow)) = admitted {
                let _ = self.tcp.close(flow).await;
            }
            let _ = send.reset(1u8.into());
            let _ = receive.stop(1u8.into());
        }
        Finished::Flow(admitted.map(|(kernel, _)| kernel))
    }
}
impl Background {
    pub fn with_carrier(mut self, carrier: mpsc::Sender<streams::Datagram>) -> Self {
        self.carrier = Some(carrier);
        self
    }
    pub async fn run(self) -> Result<()> {
        let Self {
            carrier,
            router,
            mut commands,
            mut changed,
            tcp_runner,
            mut tcp_packets,
            mut packets,
        } = self;
        let mut tasks = JoinSet::new();
        let stop = router.cancel.clone();
        tasks.spawn(async move { Finished::Owner(tcp_runner.run(stop).await) });
        let local = router.clone();
        tasks.spawn(async move {let result=async {loop {tokio::select! {
            _=local.cancel.cancelled()=>return Ok(()),
            packet=tcp_packets.recv()=>{
                let Some(packet)=packet else{ensure!(local.cancel.is_cancelled(),"private TCP packet owner stopped");return Ok(());};
                let peer=Flow::from_packet(&packet).and_then(|flow|local.state.lock().unwrap_or_else(|p|p.into_inner()).flows.get(&flow.reverse()).map(|entry|entry.peer.id.clone()));
                if let Some(peer)=peer {local.event(Event::StreamLocal {peer,bytes:packet}).await;}
            }
        }}}.await;Finished::Owner(result)});
        let transport = router.clone();
        tasks.spawn(async move {let result=async {loop {tokio::select! {
            _=transport.cancel.cancelled()=>return Ok(()),
            packet=packets.outgoing()=>{
                let Some(packet)=packet else{ensure!(transport.cancel.is_cancelled(),"private stream packet owner stopped");return Ok(());};
                if let Some(carrier)=&carrier {
                    tokio::select! {_=transport.cancel.cancelled()=>return Ok(()),result=carrier.send(packet)=>{ensure!(result.is_ok(),"private stream carrier stopped");}}
                } else {transport.event(Event::StreamDatagram {destination:packet.address,payload:packet.payload}).await;}
            }
        }}}.await;Finished::Owner(result)});
        let accepting = router.clone();
        tasks.spawn(async move {loop {
            let result=tokio::select! {_=accepting.cancel.cancelled()=>return Finished::Owner(Ok(())),result=accepting.endpoint.accept()=>result};
            if let Ok((peer,connection))=result {
                if accepting.commands.send(Command::Ready {peer,connection}).await.is_err(){return Finished::Owner(Ok(()));}
            } else {tokio::select! {_=accepting.cancel.cancelled()=>return Finished::Owner(Ok(())),_=tokio::time::sleep(Duration::from_millis(100))=>{}}}
        }});
        let header_slots = Arc::new(Semaphore::new(32));
        let mut preparing = HashSet::new();
        let mut backoff: HashMap<String, (Instant, Duration)> = HashMap::new();
        let mut readers = HashMap::new();
        let result:Result<()>=async {loop {
            let pending={let state=router.state.lock().unwrap_or_else(|p|p.into_inner());
                state.policy.peers.values().filter(|peer|{
                    let lanes=if router.endpoint.supports_parallel(peer){MAX_STREAM_LANES}else{1};
                    let connections=router.endpoint.connection_count(peer);
                    state.policy.deadline>Instant::now()
                        && (connections>0 || state.policy.own<peer.id)
                        && connections<lanes
                        && !preparing.contains(&peer.id)
                        && backoff.get(&peer.id).is_none_or(|(due,_)|*due<=Instant::now())
                })
                    .take(8usize.saturating_sub(preparing.len())).cloned().collect::<Vec<_>>()};
            for peer in pending {preparing.insert(peer.id.clone());let endpoint=router.endpoint.clone();let additional=endpoint.connection_count(&peer)>0;tasks.spawn(async move {let result=if additional{endpoint.connect_additional(&peer).await}else{endpoint.connect(&peer).await};Finished::Dial(peer,result)});}
            tokio::select! {
                _=router.cancel.cancelled()=>break,
                updated=changed.changed()=>{
                    if updated.is_err(){break;}
                    let state=router.state.lock().unwrap_or_else(|p|p.into_inner());backoff.retain(|id,_|state.policy.peers.contains_key(id));
                },
                command=commands.recv()=>match command {
                    Some(Command::Source {kernel,syn,connection})=>{let flow=router.clone();tasks.spawn(async move {flow.source(kernel,syn,connection).await});},
                    Some(Command::Incoming {peer,send,receive,permit})=>{let flow=router.clone();tasks.spawn(async move {flow.target(peer,send,receive,permit).await});},
                    Some(Command::Ready {peer,connection})=>spawn_reader(&mut tasks,&mut readers,&router,&header_slots,peer,connection),
                    None=>break,
                },
                finished=tasks.join_next()=>match finished {
                    Some(Ok(Finished::Owner(result)))=>{result?;ensure!(router.cancel.is_cancelled(),"private stream owner stopped");break;},
                    Some(Ok(Finished::Dial(peer,result)))=>{
                        preparing.remove(&peer.id);
                        match result {Ok(connection)=>{backoff.remove(&peer.id);spawn_reader(&mut tasks,&mut readers,&router,&header_slots,peer,connection);},
                            Err(_)=>{let delay=backoff.get(&peer.id).map_or(Duration::from_secs(1),|(_,delay)|(*delay*2).min(Duration::from_secs(30)));backoff.insert(peer.id,(Instant::now()+delay,delay));}}
                    },
                    Some(Ok(Finished::Flow(Some(kernel))))=>if let Some(entry)=router.state.lock().unwrap_or_else(|p|p.into_inner()).flows.get_mut(&kernel){entry.finished=true;},
                    Some(Ok(Finished::Flow(None)))=>{},
                    Some(Ok(Finished::Reader(id)))=>{readers.remove(&id);},
                    Some(Err(_))|None=>anyhow::bail!("private stream task failed"),
                },
            }
        }Ok(())}.await;
        router.cancel.cancel();
        router.endpoint.close();
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        result
    }
}
fn spawn_reader(
    tasks: &mut JoinSet<Finished>,
    readers: &mut HashMap<usize, streams::Connection>,
    router: &Router,
    slots: &Arc<Semaphore>,
    peer: Peer,
    connection: streams::Connection,
) {
    let id = connection.stable_id();
    if readers.contains_key(&id) {
        return;
    }
    readers.insert(id, connection.clone());
    let router = router.clone();
    let slots = slots.clone();
    tasks.spawn(async move {loop {
        let result=tokio::select! {_=router.cancel.cancelled()=>return Finished::Reader(id),result=connection.accept_bi()=>result};
        let Ok((mut send,mut receive))=result else{return Finished::Reader(id);};
        let Ok(permit)=slots.clone().try_acquire_owned() else {let _=send.reset(3u8.into());let _=receive.stop(3u8.into());continue;};
        let command=Command::Incoming {peer:peer.clone(),send,receive,permit};
        tokio::select! {_=router.cancel.cancelled()=>return Finished::Reader(id),result=router.commands.send(command)=>if result.is_err(){return Finished::Reader(id);}}
    }});
}
