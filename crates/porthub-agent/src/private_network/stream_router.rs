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
struct Ports(Vec<(u16, u16)>,Option<porthub_network::policy::pair_acl::CompiledPortMask>);
impl Ports {
    fn contains(&self, port: u16) -> bool {
        if let Some(mask)=&self.1{return mask.contains(port);}
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
    pair_deadlines: HashMap<String,Instant>,
    base_authority:Option<super::authority_event::Authority<()>>,
    pair_authorities:HashMap<String,super::authority_event::Authority<()>>,
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
            pair_deadlines: HashMap::new(),
            base_authority:None,
            pair_authorities:HashMap::new(),
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
                .to_std().map_err(|_| anyhow::anyhow!("private policy lease expired; check host clock synchronization and gateway connectivity"))?;
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
        if let Some(acl)=&snapshot.pair_acl{
            ensure!(snapshot.sparse.is_none()&&snapshot.peers.len()==2&&snapshot.grants.is_empty()&&snapshot.exit_routes.is_empty(),"compact stream ACL is not an exact pair");
            let other=snapshot.peers.iter().find(|p|p.id!=own).ok_or_else(||anyhow::anyhow!("compact stream ACL omits remote identity"))?;
            let compiled=acl.compile()?;let outgoing=compiled.tcp(false);let incoming=compiled.tcp(true);
            if outgoing.any(){policy.outgoing.insert(other.id.clone(),Ports(Vec::new(),Some(outgoing)));}
            if incoming.any(){policy.incoming.insert(other.id.clone(),Ports(Vec::new(),Some(incoming)));}
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
    fn compile_pairs(snapshot:&Snapshot,own:&str,ip:Ipv4Addr,pairs:&[(Snapshot,Instant)])->Result<Self>{
        let mut policy=Self::compile(snapshot,own,ip)?;
        if snapshot.sparse.is_some(){for (pair,deadline) in pairs{
            if *deadline<=Instant::now(){continue;}
            ensure!(pair.workspace==snapshot.workspace&&pair.self_==snapshot.self_&&pair.sparse.is_none()&&pair.peers.len()==2&&pair.exit_routes.is_empty(),"private stream pair authority changed");
            ensure!(*deadline<=Instant::now()+Duration::from_secs(60),"private stream pair lease exceeds bound");
            let pair_policy=Self::compile(pair,own,ip)?;
            for id in pair_policy.peers.keys(){policy.pair_deadlines.insert(id.clone(),*deadline);}
            policy.peers.extend(pair_policy.peers);policy.incoming.extend(pair_policy.incoming);policy.outgoing.extend(pair_policy.outgoing);
        }}Ok(policy)
    }
    fn permit(&self,id:&str)->Result<Option<porthub_mesh::udp::SendPermit>> {
        let Some(base)=&self.base_authority else{return Ok(None);};base.check()?;
        let pair=self.pair_authorities.get(id).ok_or_else(||anyhow::anyhow!("private stream pair retired"))?.clone();pair.check()?;let base=base.clone();
        let bounded_base=base.clone();let bounded_pair=pair.clone();
        Ok(Some(porthub_mesh::udp::SendPermit::bounded(move||base.check().is_ok()&&pair.check().is_ok(),move||Some(bounded_base.remaining().ok()??.min(bounded_pair.remaining().ok()??)))))
    }
    fn allows(&self, peer: &Peer, flow: Flow, outbound: bool) -> bool {
        if self.base_authority.as_ref().is_some_and(|base|base.check().is_err()||self.pair_authorities.get(&peer.id).is_none_or(|pair|pair.check().is_err())){return false;}
        if self.deadline<=Instant::now() || self.pair_deadlines.get(&peer.id).is_some_and(|d|*d<=Instant::now()) || self.peers.get(&peer.id) != Some(peer) {
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
    pub fn active_peers(&self)->Vec<String>{
        let state=self.state.lock().unwrap_or_else(|p|p.into_inner());
        state.flows.values().filter(|flow|!flow.cancel.is_cancelled()&&(!flow.finished||self.tcp.owns(flow.flow))&&state.policy.allows(&flow.peer,flow.flow,flow.outbound))
            .map(|flow|flow.peer.id.clone()).collect::<HashSet<_>>().into_iter().collect()
    }
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
            && state.policy.pair_deadlines.get(peer_id).is_none_or(|d|*d>Instant::now())
            && state
                .policy
                .peers
                .get(peer_id)
                .is_some_and(|peer| self.endpoint.prepared(peer).is_some())
    }
    pub fn update(&self, snapshot: &Snapshot) -> Result<()> { self.update_pairs(snapshot,&[]) }
    pub fn update_pairs(&self,snapshot:&Snapshot,pairs:&[(Snapshot,Instant)])->Result<()> {self.update_pairs_authorized(snapshot,pairs,None,None)}
    pub(crate) fn update_pairs_authorized(&self,snapshot:&Snapshot,pairs:&[(Snapshot,Instant)],base:Option<super::authority_event::Authority<()>>,handle:Option<super::sparse::Handle>)->Result<()> {
        ensure!(pairs.len()<=porthub_network::policy::MAX_PAIR_LEASES,"private stream pair cache exceeds bounds");
        let (own, ip) = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            (state.policy.own.clone(), state.policy.ip)
        };
        let mut policy=Policy::compile_pairs(snapshot,&own,ip,pairs)?;
        // PHT1 is an unframed long-lived byte stream. Quinn writes enqueue;
        // they do not prove acknowledgement/original retransmission authority.
        // Decline ONLY sparse optimization until bounded ACK chunks and runner
        // origins exist. Raw guarded packet/relay routing remains available.
        // This intermediate boundary is NOT sparse optimized-stream readiness.
        if snapshot.sparse.is_some(){policy.peers.clear();policy.incoming.clear();policy.outgoing.clear();policy.pair_deadlines.clear();}

        if let Some(base)=base.filter(|_|snapshot.sparse.is_some()) {
            base.check()?;
            if base.remaining()?.is_some(){
                policy.base_authority=Some(base);
                let handle=handle.ok_or_else(||anyhow::anyhow!("private stream authority owner missing"))?;
                for id in policy.peers.keys(){if let Some(authority)=handle.pair_authority(id){policy.pair_authorities.insert(id.clone(),authority);}}
            }
        }
        self.endpoint.set_peer_connection_budget(if snapshot.sparse.is_some(){64}else{512})?;
        self.endpoint
            .update_peers(policy.peers.values().cloned().collect())?;
        let admissions=if policy.base_authority.is_some(){Some(policy.peers.values().filter_map(|peer|policy.permit(&peer.id).ok().flatten().map(|permit|(peer.ip,permit))).collect())}else{None};
        self.endpoint.update_send_admissions(admissions)?;
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
    fn delivery_scope(&self)->porthub_mesh::udp::SendPermit{let cancel=self.cancel.clone();porthub_mesh::udp::SendPermit::control(move||!cancel.is_cancelled())}
    pub(crate) fn retire(&self){self.cancel.cancel();self.endpoint.close();}
    pub fn valid_lease(&self) -> bool {
        let state=self.state.lock().unwrap_or_else(|p|p.into_inner());
        !self.cancel.is_cancelled()&&state.policy.deadline>Instant::now()&&state.policy.base_authority.as_ref().is_none_or(|authority|authority.check().is_ok())
    }
    pub async fn receive(&self, source: Ipv4Addr, payload: Bytes) {
        if self.cancel.is_cancelled(){return;}
        let (deadline,admission) = {
            let state=self.state.lock().unwrap_or_else(|p|p.into_inner());
            let Some(peer)=state.policy.peers.values().find(|p|p.ip==source) else{return;};
            (state.policy.pair_deadlines.get(&peer.id).copied().unwrap_or(state.policy.deadline).min(state.policy.deadline),match state.policy.permit(&peer.id){Ok(permit)=>permit,Err(_)=>return})
        };
        let now = Instant::now();
        if deadline <= now {
            return;
        }
        // The endpoint and transmit carrier have independent owners. A bounded
        // wait preserves receive pressure without trapping control-plane work.
        let deadline = deadline.min(now + Duration::from_millis(200));
        if !matches!(
            tokio::time::timeout_at(deadline.into(), async {if let Some(admission)=admission {admission.during(self.ingress.send_reliable_guarded(source,payload,Some(admission.clone()))).await?}else{self.ingress.send_reliable(source,payload).await}})
                .await,
            Ok(Ok(()))
        ) {
            self.receive_drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    /// Returns immediately. A new flow uses a stream only after its peer's
    /// connection has already been prepared in the background.
    pub fn kernel_packet(&self, peer_id: &str, packet: Bytes, prefer_stream: bool) -> bool {
        if self.cancel.is_cancelled(){return false;}
        let Some(kernel) = Flow::from_packet(&packet) else {
            return false;
        };
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = state.flows.get(&kernel) {
            if entry.peer.id == peer_id {
                if state.policy.allows(&entry.peer,entry.flow,entry.outbound) && !entry.cancel.is_cancelled() {
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
    /// Independent deadline guard: established QUIC copying cannot outlive a pair lease
    /// while an unrelated base refresh or blocked data writer keeps the stream alive.
    async fn authority_guard(&self,peer:&Peer,flow:Flow,outbound:bool){
        let mut changed=self.changed.subscribe();
        loop{
            let (deadline,guarded)={let state=self.state.lock().unwrap_or_else(|p|p.into_inner());
                if !state.policy.allows(peer,flow,outbound){return;}
                (state.policy.pair_deadlines.get(&peer.id).copied().unwrap_or(state.policy.deadline).min(state.policy.deadline),state.policy.base_authority.is_some())};
            tokio::select!{_=self.cancel.cancelled()=>return, result=changed.changed()=>{if result.is_err(){return;}},_=tokio::time::sleep_until(deadline.into())=>{},_=async {if guarded {tokio::time::sleep(Duration::from_millis(50)).await}else{std::future::pending::<()>().await}}=>{}}
        }
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
            _=self.authority_guard(&peer,kernel,true)=>Err(anyhow::anyhow!("private TCP source authority expired")),
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
                        scope:self.delivery_scope(),
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
                _=self.authority_guard(&peer,flow,false)=>Err(anyhow::anyhow!("private TCP target authority expired")),
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
                if let Some(peer)=peer {local.event(Event::StreamLocal {peer,bytes:packet,scope:local.delivery_scope()}).await;}
            }
        }}}.await;Finished::Owner(result)});
        let transport = router.clone();
        tasks.spawn(async move {let result=async {loop {tokio::select! {
            _=transport.cancel.cancelled()=>return Ok(()),
            packet=packets.outgoing()=>{
                let Some(mut packet)=packet else{ensure!(transport.cancel.is_cancelled(),"private stream packet owner stopped");return Ok(());};
                let scope=transport.delivery_scope();packet.permit=Some(match packet.permit.take(){Some(origin)=>porthub_mesh::udp::SendPermit::combine(vec![origin,scope]),None=>scope});
                if let Some(carrier)=&carrier {
                    tokio::select! {_=transport.cancel.cancelled()=>return Ok(()),result=carrier.send(packet)=>{ensure!(result.is_ok(),"private stream carrier stopped");}}
                } else {transport.event(Event::StreamDatagram {destination:packet.address,payload:packet.payload,permit:packet.permit}).await;}
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
                        && state.policy.pair_deadlines.get(&peer.id).is_none_or(|d|*d>Instant::now())
                        && router.endpoint.capacity_for(peer)
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
        router.retire();
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

#[cfg(test)]mod sparse_lease_tests{
 use super::*;
 fn snapshots(a:&Identity,b:&Identity)->(Snapshot,Snapshot){
  let base:Snapshot=serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(30),"sparse":{"protocol":1,"epoch":"a".repeat(64)},"peers":[{"id":"a","ip":"10.203.0.2","fingerprint":a.fingerprint(),"instance":"instance-a","hostname":"a.phub","stream_transport":"quic1"}],"grants":[]})).unwrap();
  let mut pair=base.clone();pair.sparse=None;pair.expires_at=chrono::Utc::now()+chrono::Duration::seconds(15);
  pair.peers.push(serde_json::from_value(serde_json::json!({"id":"b","ip":"10.203.1.2","fingerprint":b.fingerprint(),"instance":"instance-b","hostname":"b.phub","stream_transport":"quic1"})).unwrap());
  pair.grants=serde_json::from_value(serde_json::json!([{"source":"a","destination":"b","protocol":"tcp","ports":[{"start":443,"end":443}]}])).unwrap();(base,pair)
 }
 fn flow()->Flow{Flow{source:"10.203.0.2:4000".parse().unwrap(),destination:"10.203.1.2:443".parse().unwrap()}}
 #[cfg(feature="private-sparse")]
 #[tokio::test]async fn guarded_sparse_policy_does_not_publish_pht1_even_with_valid_authority(){
  struct Clock(std::sync::atomic::AtomicU64);
  impl super::super::authority_clock::SuspendClock for Clock{fn elapsed_since_boot(&self)->Result<Duration>{Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))}}
  let clock=Arc::new(Clock(std::sync::atomic::AtomicU64::new(0)));
  let witness=||super::super::authority_clock::RequestWindow::start(clock.clone()).unwrap();
  let a=Identity::new().unwrap();let b=Identity::new().unwrap();let(base,pair)=snapshots(&a,&b);let peer=mesh_peer(&pair.peers[1]);
  let lease=porthub_network::policy::PairLease{workspace:pair.workspace.clone(),self_:pair.self_.clone(),epoch:base.sparse.as_ref().unwrap().epoch.clone(),expires_at:pair.expires_at,revision:pair.revision,local:pair.peers[0].clone(),peer:pair.peers[1].clone(),grants:pair.grants.clone(),acl:pair.pair_acl.clone()};
  let(handle,_)=super::super::sparse::channel();let query=porthub_network::policy::Lookup{kind:"peer".into(),value:"b".into()};
  handle.update_base_authority(&base,super::super::authority_event::Authority::new((),Some(witness()),base.expires_at));
  handle.installed_authority(&query,lease,super::super::authority_event::Authority::new((),Some(witness()),pair.expires_at));
  clock.0.store(10000,Ordering::SeqCst);
  let base_authority=super::super::authority_event::Authority::new((),Some(witness()),base.expires_at);
  handle.update_base_authority(&base,base_authority.clone());
  let(router,_)=new("a".into(),"10.203.0.2".parse().unwrap(),a,tokio::sync::mpsc::channel(8).0,CancellationToken::new()).unwrap();
  router.update_pairs_authorized(&base,&[(pair,Instant::now()+Duration::from_secs(10))],Some(base_authority),Some(handle.clone())).unwrap();
  assert!(!router.state.lock().unwrap().policy.allows(&peer,flow(),true),"sparse PHT1 must be declined even with valid independent authority");
  assert!(router.valid_lease());assert!(router.state.lock().unwrap().policy.peers.is_empty());assert!(!router.prepared("b"));
 }
 #[cfg(feature="private-sparse")]
 #[tokio::test]async fn real_kernel_syn_with_valid_sparse_acl_retains_guarded_packet_fallback(){
  let a=Identity::new().unwrap();let b=Identity::new().unwrap();let(base,pair)=snapshots(&a,&b);
  let lease=porthub_network::policy::PairLease{workspace:pair.workspace.clone(),self_:pair.self_.clone(),epoch:base.sparse.as_ref().unwrap().epoch.clone(),expires_at:pair.expires_at,revision:pair.revision,local:pair.peers[0].clone(),peer:pair.peers[1].clone(),grants:pair.grants.clone(),acl:pair.pair_acl.clone()};
  let mut policy=porthub_network::policy::Engine::default();policy.apply(base.clone()).unwrap();policy.install_pair(lease).unwrap();
  let(router,_)=new("a".into(),"10.203.0.2".parse().unwrap(),a,tokio::sync::mpsc::channel(8).0,CancellationToken::new()).unwrap();
  router.update_pairs(&base,&[(pair,Instant::now()+Duration::from_secs(10))]).unwrap();
  let (kernel,mut packets,runner)=tcp_stream::stack().unwrap();let cancel=CancellationToken::new();let stop=cancel.clone();
  let task=tokio::spawn(async move{runner.run(stop).await});let waiting=tokio::spawn(async move{kernel.connect(flow()).await});
  let syn=tokio::time::timeout(Duration::from_secs(1),packets.recv()).await.unwrap().unwrap();
  assert!(policy.check(&syn,"b",false),"sparse raw packet ACL remains authorized");
  assert!(!router.kernel_packet("b",syn,true),"unsupported optimization must return raw path, not swallow SYN");
  assert!(router.state.lock().unwrap().flows.is_empty());assert!(router.endpoint.prepared(&mesh_peer(&policy.pair_peer("b").unwrap())).is_none());
  cancel.cancel();task.await.unwrap().unwrap();assert!(waiting.await.unwrap().is_err());
 }


 #[tokio::test]async fn queued_real_legacy_quinn_output_cannot_inherit_replacement_router_generation()->Result<()>{
  let a=Identity::new()?;let b=Identity::new()?;let(_,pair)=snapshots(&a,&b);let cancel=CancellationToken::new();
  let(events,mut input)=tokio::sync::mpsc::channel(16);
  let(router,background)=new("a".into(),"10.203.0.2".parse()?,a.clone(),events,cancel.clone())?;router.update(&pair)?;
  let(tx,mut rx)=tokio::sync::mpsc::channel(16);let task=tokio::spawn(background.with_carrier(tx).run());
  let packet=tokio::time::timeout(Duration::from_secs(2),rx.recv()).await?.ok_or_else(||anyhow::anyhow!("legacy output missing"))?;
  let queued_scope=packet.permit.clone();let live_before=queued_scope.as_ref().is_some_and(|scope|scope.valid());
  // Finish actual pinned TLS, then obtain the source proxy's real native
  // SYNACK while intentionally keeping it queued outside the kernel.
  let(peer,mut io)=Endpoint::new(b,"10.203.1.2".parse()?)?;peer.update_peers(vec![mesh_peer(&pair.peers[0])])?;let peer=Arc::new(peer);let ingress=io.ingress();
  ingress.send_reliable_guarded("10.203.0.2".parse()?,packet.payload,packet.permit).await?;
  let pump_stop=CancellationToken::new();let stopping=pump_stop.clone();let own=router.clone();let pump=tokio::spawn(async move{loop{tokio::select!{
   _=stopping.cancelled()=>break,
   p=rx.recv()=>match p{Some(p)=>{if p.permit.as_ref().is_none_or(|p|p.valid()){ingress.send_reliable_guarded("10.203.0.2".parse()?,p.payload,p.permit).await?;}},None=>break},
   p=io.outgoing()=>match p{Some(p)=>own.receive("10.203.1.2".parse()?,p.payload).await,None=>break}
  }}Ok::<_,anyhow::Error>(())});
  let accepting=peer.clone();let remote=tokio::time::timeout(Duration::from_secs(2),accepting.accept()).await??.1;
  tokio::time::timeout(Duration::from_secs(1),async{while !router.prepared("b"){tokio::task::yield_now().await;}}).await?;
  let(kernel,mut packets,runner)=tcp_stream::stack()?;let kernel_stop=CancellationToken::new();let running=tokio::spawn(runner.run(kernel_stop.clone()));let connecting=tokio::spawn(async move{kernel.connect(flow()).await});
  let syn=tokio::time::timeout(Duration::from_secs(1),packets.recv()).await?.unwrap();let mut policy=porthub_network::policy::Engine::default();policy.apply(pair.clone())?;ensure!(policy.check(&syn,"b",false),"legacy fixture SYN not authorized");ensure!(router.kernel_packet("b",syn,true),"legacy fixture stream was not prepared");
  let(_reply,mut request)=tokio::time::timeout(Duration::from_secs(1),remote.accept_bi()).await??;let mut header=[0;8];request.read_exact(&mut header).await?;ensure!(&header[..4]==b"PHT1","legacy wire changed");
  let event=tokio::time::timeout(Duration::from_secs(1),input.recv()).await?.ok_or_else(||anyhow::anyhow!("native legacy output missing"))?;
  let Event::StreamLocal{peer:owner,bytes,scope}=event else{anyhow::bail!("unexpected legacy native event")};
  ensure!(owner=="b"&&scope.valid()&&policy.check(&bytes,"b",true),"queued native SYNACK did not belong to authorized legacy flow");
  cancel.cancel();tokio::time::timeout(Duration::from_secs(1),task).await???;
  pump_stop.cancel();peer.close();tokio::time::timeout(Duration::from_secs(1),pump).await???;kernel_stop.cancel();tokio::time::timeout(Duration::from_secs(1),running).await???;ensure!(connecting.await?.is_err(),"undelivered native SYNACK reached kernel");
  ensure!(live_before,"real legacy queued output omitted its immutable router generation");
  ensure!(queued_scope.as_ref().is_some_and(|scope|!scope.valid())&&!scope.valid(),"retired router output can inherit a replacement's policy");
  let(replacement,_)=new("a".into(),"10.203.0.2".parse()?,a,tokio::sync::mpsc::channel(8).0,CancellationToken::new())?;replacement.update(&pair)?;
  ensure!(replacement.valid_lease()&&replacement.delivery_scope().valid()&&queued_scope.as_ref().is_some_and(|scope|!scope.valid())&&!scope.valid(),"fresh legacy fallback revived old queued byte/transport output");Ok(())
 }
 #[test]fn compact_port_masks_keep_quic_permission_exact_without_range_expansion(){
  let a=Identity::new().unwrap();let b=Identity::new().unwrap();let(base,mut pair)=snapshots(&a,&b);
  let grant=porthub_network::policy::Grant{source:"a".into(),destination:"b".into(),protocol:"tcp".into(),ports:(1..=u16::MAX).step_by(2).map(|port|porthub_network::policy::Port{start:port,end:port}).collect()};
  pair.pair_acl=Some(porthub_network::policy::pair_acl::PairAcl::from_grants("a","b",&[grant]).unwrap());pair.grants.clear();
  let policy=Policy::compile_pairs(&base,"a","10.203.0.2".parse().unwrap(),&[(pair.clone(),Instant::now()+Duration::from_secs(10))]).unwrap();let peer=mesh_peer(&pair.peers[1]);
  assert!(policy.outgoing["b"].0.is_empty(),"compact policy must not expand into 32K range records");
  for port in 0..=u16::MAX{let mut test=flow();test.destination.set_port(port);assert_eq!(policy.allows(&peer,test,true),port%2==1);}
  assert!(!policy.incoming.contains_key("b"));
  let mut spoof=peer.clone();spoof.instance="different-instance".into();assert!(!policy.allows(&spoof,flow(),true));
 }
 #[tokio::test]async fn established_stream_guard_expires_pair_without_any_status_tick_or_base_expiry(){
  let a=Identity::new().unwrap();let b=Identity::new().unwrap();let(base,pair)=snapshots(&a,&b);let peer=mesh_peer(&pair.peers[1]);
  let(router,_background)=new("a".into(),"10.203.0.2".parse().unwrap(),a,tokio::sync::mpsc::channel(8).0,CancellationToken::new()).unwrap();
  router.update(&pair).unwrap();router.state.lock().unwrap().policy.pair_deadlines.insert("b".into(),Instant::now()+Duration::from_millis(40));
  assert!(router.state.lock().unwrap().policy.allows(&peer,flow(),true));
  tokio::time::timeout(Duration::from_secs(1),router.authority_guard(&peer,flow(),true)).await.expect("pair guard must not wait for 30s base or status tick");
  assert!(router.valid_lease());assert!(!router.state.lock().unwrap().policy.allows(&peer,flow(),true));
 }
 #[tokio::test]async fn renewal_updates_guard_but_authoritative_pair_removal_wakes_it_immediately(){
  let a=Identity::new().unwrap();let b=Identity::new().unwrap();let(base,pair)=snapshots(&a,&b);let peer=mesh_peer(&pair.peers[1]);
  let(router,_background)=new("a".into(),"10.203.0.2".parse().unwrap(),a,tokio::sync::mpsc::channel(8).0,CancellationToken::new()).unwrap();
  router.update(&pair).unwrap();router.state.lock().unwrap().policy.pair_deadlines.insert("b".into(),Instant::now()+Duration::from_secs(1));
  let own=router.clone();let wait=tokio::spawn(async move{own.authority_guard(&peer,flow(),true).await});tokio::task::yield_now().await;
  router.update(&pair).unwrap();router.state.lock().unwrap().policy.pair_deadlines.insert("b".into(),Instant::now()+Duration::from_secs(2));tokio::task::yield_now().await;assert!(!wait.is_finished());
  router.update_pairs(&base,&[]).unwrap();tokio::time::timeout(Duration::from_millis(500),wait).await.unwrap().unwrap();assert!(router.valid_lease());
 }
}
