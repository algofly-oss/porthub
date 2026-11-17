//! Experimental autonomous source/cold-receiver flow actors. Not advertised.
use super::*;
use super::{
    carrier::{Frame, Key, Role},
    dispatch::{Dispatcher, EndpointSlot, Outcome},
    duplex,
    flow_authority::{LocalAuthority, PendingSyn, Side},
    flow_open::{self, NativeIngress, NativeOwner},
    receiver, source,
};
use crate::private_network::controller::Event;
use porthub_mesh::Identity;
use porthub_network::tcp_stream::{self, tagged};
use std::net::Ipv4Addr;
use tokio::sync::watch;
const FLOWS: usize = 256;
const PER_PEER: usize = 4;
// Same bound as the existing raw transport flow-pinning table. Exhaustion
// declines new optimizations; it never truncates identities or raw packets.
const DECISIONS: usize = 65536;
#[derive(Clone, Copy)]
enum Decision {
    Raw,
    Stream(Option<u32>),
}
fn syn_sequence(bytes: &[u8]) -> Option<u32> {
    tagged::validate_syn(bytes).ok()?;
    let offset = usize::from(bytes.first()? & 15) * 4;
    Some(u32::from_be_bytes(
        bytes.get(offset + 4..offset + 8)?.try_into().ok()?,
    ))
}
pub(crate) type Lookup = Arc<dyn Fn(&str) -> Option<Arc<LocalAuthority>> + Send + Sync>;
pub(crate) type Request = Arc<dyn Fn(&str) + Send + Sync>;
type Id = (String, [u8; 16]);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Opening,
    Running,
    Complete,
    Failed,
    Retired,
}
struct Record {
    peer: String,
    nonce: [u8; 16],
    cancel: CancellationToken,
    kernel: Mutex<Option<tcp_stream::Flow>>,
    ingress: watch::Sender<Option<NativeIngress>>,
    output: mpsc::Sender<tagged::Packet>,
    phase: watch::Sender<Phase>,
    output_task: Mutex<Option<JoinHandle<()>>>,
}
struct State {
    records: HashMap<Id, Arc<Record>>,
    kernel: HashMap<tcp_stream::Flow, Id>,
    decisions: HashMap<tcp_stream::Flow, Decision>,
    decisions_full: bool,
}
enum Command {
    Source {
        record: Arc<Record>,
        syn: PendingSyn,
    },
    Target {
        record: Arc<Record>,
        key: Key,
        receiver: Arc<EndpointSlot>,
    },
}
struct Inner {
    requested: bool,
    identity: Identity,
    current: Lookup,
    request: Request,
    dispatch: Dispatcher,
    native: tagged::Handle,
    budget: Budget,
    events: mpsc::Sender<Event>,
    cancel: CancellationToken,
    state: Mutex<State>,
    commands: mpsc::Sender<Command>,
}
#[derive(Clone)]
pub(crate) struct Runtime(Arc<Inner>);
pub(crate) struct Background {
    runtime: Runtime,
    commands: mpsc::Receiver<Command>,
    runner: tagged::Runner,
    packets: mpsc::Receiver<tagged::Packet>,
}
impl Runtime {
    pub(crate) fn new(
        identity: Identity,
        current: Lookup,
        request: Request,
        events: mpsc::Sender<Event>,
        cancel: CancellationToken,
    ) -> Result<(Self, Background)> {
        Self::new_protocol(identity, current, request, events, cancel, false)
    }
    pub(crate) fn new_requested(
        identity: Identity,
        current: Lookup,
        request: Request,
        events: mpsc::Sender<Event>,
        cancel: CancellationToken,
    ) -> Result<(Self, Background)> {
        Self::new_protocol(identity, current, request, events, cancel, true)
    }
    fn new_protocol(
        identity: Identity,
        current: Lookup,
        request: Request,
        events: mpsc::Sender<Event>,
        cancel: CancellationToken,
        requested: bool,
    ) -> Result<(Self, Background)> {
        let (native, packets, runner) = tagged::stack()?;
        let (commands, input) = mpsc::channel(64);
        let runtime = Self(Arc::new(Inner {
            requested,
            identity,
            current,
            request,
            dispatch: Dispatcher::default(),
            native,
            budget: Budget::default(),
            events,
            cancel,
            state: Mutex::new(State {
                records: HashMap::new(),
                kernel: HashMap::new(),
                decisions: HashMap::new(),
                decisions_full: false,
            }),
            commands,
        }));
        Ok((
            runtime.clone(),
            Background {
                runtime,
                commands: input,
                runner,
                packets,
            },
        ))
    }
    fn current(&self, peer: &str) -> source::Current {
        let lookup = self.0.current.clone();
        let peer = peer.to_owned();
        Arc::new(move || lookup(&peer))
    }
    fn reserve(
        &self,
        peer: &str,
        nonce: [u8; 16],
        kernel: Option<tcp_stream::Flow>,
    ) -> Result<(Arc<Record>, mpsc::Receiver<tagged::Packet>)> {
        let mut state = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
        let id = (peer.to_owned(), nonce);
        ensure!(
            !state.records.contains_key(&id) && state.records.len() < FLOWS,
            "native flow budget busy"
        );
        ensure!(
            state
                .records
                .values()
                .filter(|record| record.peer == peer)
                .count()
                < PER_PEER,
            "native peer flow budget busy"
        );
        let peers = state
            .records
            .values()
            .map(|record| record.peer.as_str())
            .collect::<std::collections::HashSet<_>>();
        ensure!(
            peers.contains(peer) || peers.len() < 64,
            "native active peer budget busy"
        );
        if let Some(kernel) = kernel {
            ensure!(
                !state.decisions_full
                    && state.decisions.len() < DECISIONS
                    && !state.decisions.contains_key(&kernel),
                "native flow first transport decision unavailable"
            );
            ensure!(
                !state.kernel.contains_key(&kernel),
                "native kernel tuple already owned"
            );
            state.decisions.insert(kernel, Decision::Stream(None));
            state.kernel.insert(kernel, id.clone());
        }
        let (ingress, _) = watch::channel(None);
        let (phase, _) = watch::channel(Phase::Opening);
        let (output, packets) = mpsc::channel(16);
        let record = Arc::new(Record {
            peer: peer.into(),
            nonce,
            cancel: self.0.cancel.child_token(),
            kernel: Mutex::new(kernel),
            ingress,
            output,
            phase,
            output_task: Mutex::new(None),
        });
        state.records.insert(id, record.clone());
        Ok((record, packets))
    }
    fn remove(&self, record: &Arc<Record>) {
        record.cancel.cancel();
        let mut state = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
        let id = (record.peer.clone(), record.nonce);
        if state
            .records
            .get(&id)
            .is_some_and(|old| Arc::ptr_eq(old, record))
        {
            state.records.remove(&id);
            if let Some(kernel) = *record.kernel.lock().unwrap_or_else(|p| p.into_inner()) {
                if state.kernel.get(&kernel) == Some(&id) {
                    state.kernel.remove(&kernel);
                }
            }
        }
    }
    fn bind_kernel(&self, record: &Arc<Record>, kernel: tcp_stream::Flow) -> Result<()> {
        let mut state = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
        let id = (record.peer.clone(), record.nonce);
        ensure!(
            state
                .records
                .get(&id)
                .is_some_and(|old| Arc::ptr_eq(old, record))
                && !state.kernel.contains_key(&kernel),
            "native target tuple unavailable"
        );
        ensure!(
            !matches!(state.decisions.get(&kernel), Some(Decision::Raw)) && !state.decisions_full,
            "target tuple already committed to raw transport"
        );
        if !state.decisions.contains_key(&kernel) && state.decisions.len() >= DECISIONS {
            state.decisions_full = true;
            anyhow::bail!("target flow decision budget busy");
        }
        state.decisions.insert(kernel, Decision::Stream(None));
        state.kernel.insert(kernel, id);
        *record.kernel.lock().unwrap_or_else(|p| p.into_inner()) = Some(kernel);
        Ok(())
    }
    /// Caller must commit this choice before forwarding a SYN to a raw path.
    /// Existing raw-flow/restart freshness is a native integration prerequisite.
    pub(crate) fn kernel_packet(&self, peer: &str, bytes: Bytes, prefer_stream: bool) -> bool {
        let Some(flow) = tcp_stream::Flow::from_packet(&bytes) else {
            return false;
        };
        let record = {
            let state = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
            state
                .kernel
                .get(&flow)
                .and_then(|id| state.records.get(id))
                .cloned()
        };
        if let Some(record) = record {
            if record.peer != peer {
                return false;
            }
            if let Some(ingress) = record.ingress.borrow().as_ref() {
                if let Err(error) = ingress.input(bytes) {
                    if error.downcast_ref::<tagged::AdmissionError>()
                        != Some(&tagged::AdmissionError::Busy)
                    {
                        record.cancel.cancel();
                    }
                }
            }
            return true;
        }
        {
            let mut state = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
            match state.decisions.get(&flow).copied() {
                Some(Decision::Raw) => return false,
                Some(Decision::Stream(isn)) => {
                    // A genuinely new local SYN may reuse an old four-tuple,
                    // but that reincarnation stays raw. Old stream packets
                    // cannot fall through into a newly current raw authority.
                    if syn_sequence(&bytes).is_some_and(|seq| Some(seq) != isn) {
                        state.decisions.insert(flow, Decision::Raw);
                        return false;
                    }
                    return true;
                }
                None => {}
            }
            if state.decisions_full || state.decisions.len() >= DECISIONS {
                if !state.decisions_full {
                    tracing::warn!(
                        "native stream decision budget busy; new flows retain raw transport"
                    );
                }
                state.decisions_full = true;
                return false;
            }
            if !prefer_stream || self.0.cancel.is_cancelled() {
                state.decisions.insert(flow, Decision::Raw);
                return false;
            }
        }
        let Some(local) = (self.0.current)(peer) else {
            (self.0.request)(peer);
            self.commit_raw(flow);
            return false;
        };
        let sequence = syn_sequence(&bytes);
        let Ok(syn) = local.admit_syn(bytes) else {
            self.commit_raw(flow);
            return false;
        };
        let nonce = syn.parameters().0;
        let Ok((record, output)) = self.reserve(peer, nonce, Some(flow)) else {
            self.commit_raw(flow);
            return false;
        };
        if self
            .0
            .commands
            .try_send(Command::Source {
                record: record.clone(),
                syn,
            })
            .is_err()
        {
            self.remove(&record);
            self.commit_raw(flow);
            return false;
        }
        self.0
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .decisions
            .insert(flow, Decision::Stream(sequence));
        self.spawn_output(record, output);
        true
    }
    fn commit_raw(&self, flow: tcp_stream::Flow) {
        let mut state = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.decisions.contains_key(&flow) || state.decisions.len() < DECISIONS {
            state.decisions.insert(flow, Decision::Raw);
        } else {
            state.decisions_full = true;
        }
    }
    /// Called only after authenticated raw-packet ACL validation. An existing
    /// stream owner cannot be bypassed by injecting the same tuple as raw IP.
    pub(crate) fn raw_ingress(&self, bytes: &[u8]) -> bool {
        let Some(flow) = tcp_stream::Flow::from_packet(bytes).map(|flow| flow.reverse()) else {
            return true;
        };
        let mut state = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.kernel.contains_key(&flow) {
            return false;
        }
        if matches!(state.decisions.get(&flow), Some(Decision::Stream(_)))
            && syn_sequence(bytes).is_none()
        {
            return false;
        }
        if state.decisions.contains_key(&flow) || state.decisions.len() < DECISIONS {
            state.decisions.insert(flow, Decision::Raw);
        } else {
            state.decisions_full = true;
        }
        true
    }
    pub(crate) fn receive(&self, peer: &str, address: Ipv4Addr, bytes: Bytes) -> Result<Outcome> {
        self.receive_offered(peer, address, bytes, true)
    }
    pub(crate) fn receive_offered(
        &self,
        peer: &str,
        address: Ipv4Addr,
        bytes: Bytes,
        allow_new: bool,
    ) -> Result<Outcome> {
        let frame = Frame::decode(bytes.clone())?;
        let result = self.0.dispatch.receive(peer, address, bytes.clone())?;
        if result != Outcome::Missing {
            return Ok(result);
        }
        if !allow_new {
            return Ok(Outcome::Missing);
        }
        let key = frame.key();
        if key.direction() != 0 || key.role() != Role::Receiver {
            return Ok(Outcome::Missing);
        }
        let Some(local) = (self.0.current)(peer) else {
            (self.0.request)(peer);
            return Ok(Outcome::Busy);
        };
        ensure!(
            local.channel_identity().peer().id == peer
                && local.channel_identity().peer().ip == address,
            "native carrier authenticated peer mismatch"
        );
        let (record, output) = match self.reserve(peer, key.nonce(), None) {
            Ok(record) => record,
            Err(_) => return Ok(Outcome::Busy),
        };
        let receiver = match EndpointSlot::new_protocol(
            &self.0.dispatch,
            key,
            self.current(peer),
            self.0.identity.clone(),
            record.cancel.clone(),
            self.0.requested,
        ) {
            Ok(slot) => Arc::new(slot),
            Err(error) => {
                self.remove(&record);
                return Err(error);
            }
        };
        if self
            .0
            .commands
            .try_send(Command::Target {
                record: record.clone(),
                key,
                receiver,
            })
            .is_err()
        {
            self.remove(&record);
            return Ok(Outcome::Busy);
        }
        self.spawn_output(record, output);
        self.0.dispatch.receive(peer, address, bytes)
    }
    fn spawn_output(&self, record: Arc<Record>, mut packets: mpsc::Receiver<tagged::Packet>) {
        let events = self.0.events.clone();
        let owned = record.clone();
        let task = tokio::spawn(async move {
            let _owner_guard = record.cancel.clone().drop_guard();
            let mut ready = record.ingress.subscribe();
            loop {
                let packet = tokio::select! {_=record.cancel.cancelled()=>break,p=packets.recv()=>match p{Some(p)=>p,None=>break}};
                let result=packet.deliver(|_|async{loop{if let Some(ingress)=ready.borrow().clone(){return Ok::<_,anyhow::Error>(ingress);}tokio::select!{_=record.cancel.cancelled()=>anyhow::bail!("native output owner retired"),r=ready.changed()=>{r.map_err(|_|anyhow::anyhow!("native ingress owner stopped"))?;}}}}).await;
                if let Ok(ingress) = result {
                    if ingress.publish(packet, &events).await.is_err() {
                        record.cancel.cancel();
                        break;
                    }
                } else {
                    record.cancel.cancel();
                    break;
                }
            }
        });
        *owned.output_task.lock().unwrap_or_else(|p| p.into_inner()) = Some(task);
    }
    async fn reap_output(record: &Record) {
        record.cancel.cancel();
        let task = record
            .output_task
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }
    pub(crate) fn observe(&self, peer: &str, nonce: [u8; 16]) -> Option<watch::Receiver<Phase>> {
        self.0
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .records
            .get(&(peer.into(), nonce))
            .map(|record| record.phase.subscribe())
    }
    pub(crate) fn counts(&self) -> (usize, usize) {
        (
            self.0
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .records
                .len(),
            self.0.dispatch.len(),
        )
    }
}
impl Background {
    pub(crate) async fn run(mut self) -> Result<()> {
        let mut flows = tokio::task::JoinSet::new();
        let mut native = tokio::task::JoinSet::new();
        let stop = self.runtime.0.cancel.clone();
        let _owner_guard = stop.clone().drop_guard();
        native.spawn(self.runner.run(stop.clone()));
        let result=async{loop{tokio::select!{
   _=stop.cancelled()=>break,
   command=self.commands.recv()=>{let Some(command)=command else{break};let runtime=self.runtime.clone();flows.spawn(async move{let(record,result)=match command{Command::Source{record,syn}=>{let result=run_source(&runtime,&record,syn).await;(record,result)},Command::Target{record,key,receiver}=>{let result=run_target(&runtime,&record,key,receiver).await;(record,result)}};record.phase.send_replace(if result.is_ok(){Phase::Retired}else{Phase::Failed});runtime.remove(&record);Runtime::reap_output(&record).await;result});},
   packet=self.packets.recv()=>{let Some(packet)=packet else{if stop.is_cancelled(){break;}anyhow::bail!("native output stack stopped")};let Some(flow)=tcp_stream::Flow::from_packet(packet.bytes())else{continue};let record={let state=self.runtime.0.state.lock().unwrap_or_else(|p|p.into_inner());state.kernel.get(&flow.reverse()).and_then(|id|state.records.get(id)).cloned()};if let Some(record)=record{let _=record.output.try_send(packet);}},
   finished=flows.join_next(),if !flows.is_empty()=>{if let Some(Err(error))=finished{return Err(error.into());}},
   finished=native.join_next()=>match finished{Some(Ok(Ok(()))) if stop.is_cancelled()=>break,Some(Ok(Err(error)))=>return Err(error),_=>anyhow::bail!("native runner stopped")},
  }}Ok::<_,anyhow::Error>(())}.await;
        stop.cancel();
        for record in self
            .runtime
            .0
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .records
            .values()
        {
            record.cancel.cancel();
        }
        flows.abort_all();
        native.abort_all();
        while flows.join_next().await.is_some() {}
        while native.join_next().await.is_some() {}
        let records = self
            .runtime
            .0
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .records
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for record in records {
            self.runtime.remove(&record);
            Runtime::reap_output(&record).await;
        }
        result
    }
}
async fn pump_inner(
    slot: Arc<EndpointSlot>,
    mut packets: porthub_mesh::streams::PacketIo,
    events: mpsc::Sender<Event>,
    cancel: CancellationToken,
) -> Result<()> {
    loop {
        let datagram = tokio::select! {_=cancel.cancelled()=>return Ok(()),p=packets.outgoing()=>match p{Some(p)=>p,None=>return Ok(())}};
        let outgoing = match slot.outgoing(datagram) {
            Ok(outgoing) => outgoing,
            Err(_) if !slot.active() => return Ok(()),
            Err(error) => return Err(error),
        };
        let Some((destination, payload, permit)) = outgoing else {
            continue;
        };
        permit
            .during(events.send(Event::StreamDatagram {
                destination,
                payload,
                permit: Some(permit.clone()),
            }))
            .await?
            .map_err(|_| anyhow::anyhow!("native carrier event owner stopped"))?;
    }
}
async fn pump(
    slot: Arc<EndpointSlot>,
    packets: porthub_mesh::streams::PacketIo,
    events: mpsc::Sender<Event>,
    cancel: CancellationToken,
) -> Result<()> {
    let result = pump_inner(slot, packets, events, cancel.clone()).await;
    cancel.cancel();
    result
}
async fn attach(
    runtime: &Runtime,
    record: &Record,
    key: Key,
    tasks: &mut tokio::task::JoinSet<Result<()>>,
) -> Result<Arc<EndpointSlot>> {
    let mut slot = EndpointSlot::new_protocol(
        &runtime.0.dispatch,
        key,
        runtime.current(&record.peer),
        runtime.0.identity.clone(),
        record.cancel.clone(),
        runtime.0.requested,
    )?;
    let packets = slot.take_packets()?;
    let slot = Arc::new(slot);
    tasks.spawn(pump(
        slot.clone(),
        packets,
        runtime.0.events.clone(),
        record.cancel.clone(),
    ));
    Ok(slot)
}
async fn run_source(runtime: &Runtime, record: &Arc<Record>, syn: PendingSyn) -> Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    let result = async {
        let source = attach(
            runtime,
            record,
            Key::new(record.nonce, 0, Role::Source)?,
            &mut tasks,
        )
        .await?;
        let receiver = attach(
            runtime,
            record,
            Key::new(record.nonce, 1, Role::Receiver)?,
            &mut tasks,
        )
        .await?;
        let current = runtime.current(&record.peer);
        let local =
            current().ok_or_else(|| anyhow::anyhow!("source flow authority unavailable"))?;
        let peer = local.channel_identity().peer().clone();
        let client = source.endpoint().connect_source(&peer).await?;
        let opened = flow_open::initiate_native(&client, &source.gate(), &local, &syn).await?;
        let opening = opened.prepare_source(&runtime.0.native, syn).await?;
        record
            .ingress
            .send_replace(Some(opening.ingress(current.clone())?));
        let native = opening.established().await?;
        record
            .ingress
            .send_replace(Some(native.ingress(current.clone())?));
        let mut accepted = receiver.endpoint().accept_credited().await?;
        let local = current().ok_or_else(|| anyhow::anyhow!("response authority unavailable"))?;
        flow_open::accept_response(
            &mut accepted,
            &receiver.gate(),
            &local,
            &opened,
            opened.receiver_key(),
        )
        .await?;
        run_duplex(
            runtime,
            record,
            native,
            opened.context(),
            Side::Initiator,
            client,
            accepted,
            source.gate(),
            receiver.gate(),
            &mut tasks,
        )
        .await
    };
    let result = tokio::select! {_=record.cancel.cancelled()=>Err(anyhow::anyhow!("source flow owner retired")),result=result=>result};
    record.cancel.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}
async fn run_target(
    runtime: &Runtime,
    record: &Arc<Record>,
    key: Key,
    receiver: Arc<EndpointSlot>,
) -> Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    let result = async {
        // The initial slot was published before its first Initial was enqueued.
        // Transfer its sole PacketIo owner into this flow actor.
        let receiver = Arc::try_unwrap(receiver)
            .map_err(|_| anyhow::anyhow!("target packet owner already shared"))?;
        let mut receiver = receiver;
        let packets = receiver.take_packets()?;
        let receiver = Arc::new(receiver);
        tasks.spawn(pump(
            receiver.clone(),
            packets,
            runtime.0.events.clone(),
            record.cancel.clone(),
        ));
        let mut accepted = receiver.endpoint().accept_credited().await?;
        let current = runtime.current(&record.peer);
        let local = current().ok_or_else(|| anyhow::anyhow!("target authority unavailable"))?;
        let opened =
            flow_open::accept_request(&mut accepted, &receiver.gate(), &local, key).await?;
        runtime.bind_kernel(
            record,
            opened
                .context()
                .source_native_tuple(Side::Acceptor)
                .reverse(),
        )?;
        let opening = opened.prepare_destination(&runtime.0.native).await?;
        record
            .ingress
            .send_replace(Some(opening.ingress(current.clone())?));
        let native = opening.established().await?;
        record
            .ingress
            .send_replace(Some(native.ingress(current.clone())?));
        let source = attach(runtime, record, opened.source_key(), &mut tasks).await?;
        let peer = local.channel_identity().peer().clone();
        let client = source.endpoint().connect_source(&peer).await?;
        let local = current().ok_or_else(|| anyhow::anyhow!("response authority unavailable"))?;
        flow_open::initiate_response(&client, &source.gate(), &local, &opened).await?;
        run_duplex(
            runtime,
            record,
            native,
            opened.context(),
            Side::Acceptor,
            client,
            accepted,
            source.gate(),
            receiver.gate(),
            &mut tasks,
        )
        .await
    };
    let result = tokio::select! {_=record.cancel.cancelled()=>Err(anyhow::anyhow!("target flow owner retired")),result=result=>result};
    record.cancel.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}
#[allow(clippy::too_many_arguments)]
async fn run_duplex(
    runtime: &Runtime,
    record: &Record,
    native: NativeOwner,
    context: super::flow_authority::Context,
    side: Side,
    client: porthub_mesh::streams::BoundedSourceConnection,
    accepted: porthub_mesh::streams::CreditedReceiverConnection,
    source_gate: Gate,
    receiver_gate: Gate,
    tasks: &mut tokio::task::JoinSet<Result<()>>,
) -> Result<()> {
    let current = runtime.current(&record.peer);
    let c = current.clone();
    let view = context.clone();
    let access: receiver::Current =
        Arc::new(move || c().and_then(|local| view.receiver_access(&local, side).ok()));
    let source = source::Source::from_native(
        native.clone(),
        client,
        source_gate,
        runtime.0.budget.clone(),
        current.clone(),
    )?;
    let receiver = receiver::Receiver::from_native(
        native.clone(),
        accepted,
        receiver_gate,
        runtime.0.budget.clone(),
        access.clone(),
    )?;
    let mut duplex = duplex::Duplex::new(source, receiver, access)?;
    let renew = native.clone();
    let stop = record.cancel.clone();
    tasks.spawn(async move { let result = async { let mut tick=tokio::time::interval(std::time::Duration::from_secs(5));loop { tokio::select! { _=stop.cancelled()=>return Ok(()), _=tick.tick()=>{renew.renew_control(current.clone()).await?;} } } }.await; stop.cancel(); result });
    record.phase.send_replace(Phase::Running);
    duplex.run().await?;
    record.phase.send_replace(Phase::Complete);
    duplex.drain_to_original_deadline().await
}

#[cfg(test)]
#[path = "flow_runtime_tests.rs"]
mod tests;
