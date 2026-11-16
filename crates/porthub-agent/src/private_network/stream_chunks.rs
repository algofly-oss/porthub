//! Experimental finite-stream origin actor. Not a production stream protocol:
//! native-runner ACK validation and receiver integration remain unwired.
use anyhow::{ensure, Result};
use bytes::Bytes;
use porthub_mesh::{
    streams::{Connection, FencedConnection, Peer},
    udp::{SendFactory, SendPermit},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
const CHUNK: usize = 8192;
const HEADER: usize = 96;
const MAX_BYTES: usize = 8 * 1024 * 1024;
#[derive(Default)]
struct Usage {
    bytes: usize,
    chunks: usize,
    connections: usize,
}
#[derive(Default)]
struct BudgetState {
    total: Usage,
    peers: HashMap<String, Usage>,
    flows: HashMap<(String, [u8; 16]), Usage>,
}
#[derive(Clone, Default)]
pub(crate) struct Budget(Arc<Mutex<BudgetState>>);
struct Credit {
    budget: Budget,
    peer: String,
    flow: [u8; 16],
    bytes: Option<usize>,
}
impl Budget {
    fn charge(&self, peer: &str, flow: [u8; 16], bytes: Option<usize>) -> Result<Credit> {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let key = (peer.to_owned(), flow);
        let p = state.peers.get(peer);
        let f = state.flows.get(&key);
        ensure!(
            p.is_some() || state.peers.len() < 64,
            "chunk peer budget unavailable"
        );
        ensure!(
            f.is_some() || state.flows.len() < 512,
            "chunk flow budget unavailable"
        );
        if let Some(n) = bytes {
            ensure!((1..=CHUNK).contains(&n), "invalid chunk size");
            ensure!(
                state.total.chunks < 1024 && state.total.bytes + n <= MAX_BYTES,
                "global chunk budget unavailable"
            );
            ensure!(
                p.is_some_and(|p| p.chunks < 256 && p.bytes + n <= 2 * 1024 * 1024),
                "peer chunk budget unavailable"
            );
            ensure!(
                f.is_some_and(|f| f.chunks < 128 && f.bytes + n <= 1024 * 1024),
                "flow chunk budget unavailable"
            );
        } else {
            ensure!(
                state.total.connections < 512
                    && p.is_none_or(|p| p.connections < 8)
                    && f.is_none_or(|f| f.connections == 0),
                "chunk connection budget unavailable"
            );
        }
        fn add(u: &mut Usage, n: Option<usize>) {
            if let Some(n) = n {
                u.bytes += n;
                u.chunks += 1
            } else {
                u.connections += 1
            }
        }
        add(&mut state.total, bytes);
        add(state.peers.entry(peer.into()).or_default(), bytes);
        add(state.flows.entry(key).or_default(), bytes);
        Ok(Credit {
            budget: self.clone(),
            peer: peer.into(),
            flow,
            bytes,
        })
    }
}
impl Drop for Credit {
    fn drop(&mut self) {
        let mut s = self.budget.0.lock().unwrap_or_else(|p| p.into_inner());
        fn subtract(u: &mut Usage, n: Option<usize>) {
            if let Some(n) = n {
                u.bytes -= n;
                u.chunks -= 1
            } else {
                u.connections -= 1
            }
        }
        subtract(&mut s.total, self.bytes);
        if let Some(p) = s.peers.get_mut(&self.peer) {
            subtract(p, self.bytes)
        }
        if let Some(f) = s.flows.get_mut(&(self.peer.clone(), self.flow)) {
            subtract(f, self.bytes)
        }
        s.peers.retain(|_, u| u.connections > 0 || u.chunks > 0);
        s.flows.retain(|_, u| u.connections > 0 || u.chunks > 0);
    }
}
struct GateState {
    alive: AtomicBool,
    pending: Mutex<BTreeMap<[u8; HEADER], SendPermit>>,
    cancel: CancellationToken,
    parent: SendPermit,
}
impl GateState {
    fn retire(&self) {
        self.alive.store(false, Ordering::SeqCst);
        self.cancel.cancel();
    }
}
#[derive(Clone)]
pub(crate) struct Gate {
    state: Arc<GateState>,
    factory: SendFactory,
}
impl Gate {
    pub(crate) fn new(owner_scope: SendPermit) -> Self {
        let state = Arc::new(GateState {
            alive: AtomicBool::new(true),
            pending: Default::default(),
            cancel: CancellationToken::new(),
            parent: owner_scope,
        });
        let source = state.clone();
        let factory = SendFactory::new(move || {
            let pending = source.pending.lock().unwrap_or_else(|p| p.into_inner());
            if !source.alive.load(Ordering::SeqCst)
                || !source.parent.valid()
                || pending.values().any(|p| !p.valid())
            {
                source.retire();
                return None;
            }
            let permits = pending.values().cloned().collect::<Vec<_>>();
            let source = source.clone();
            Some(SendPermit::new(move || {
                let valid = source.alive.load(Ordering::SeqCst)
                    && source.parent.valid()
                    && permits.iter().all(|p| p.valid());
                if !valid {
                    source.retire();
                }
                valid
            }))
        });
        Self { state, factory }
    }
    pub(crate) fn factory(&self) -> SendFactory {
        self.factory.clone()
    }
    fn retire(&self) {
        self.state.retire();
    }
}
#[derive(Clone)]
pub(crate) struct Flow {
    pub nonce: [u8; 16],
    pub direction: u8,
    pub local_port: u16,
    pub remote_port: u16,
    pub epoch: [u8; 32],
}
impl Flow {
    fn header(
        &self,
        sequence: u64,
        offset: u64,
        length: usize,
        generation: [u8; 16],
    ) -> Result<[u8; HEADER]> {
        ensure!(
            self.nonce != [0; 16]
                && self.direction < 2
                && self.local_port != 0
                && self.remote_port != 0
                && self.epoch != [0; 32],
            "invalid chunk flow binding"
        );
        let mut h = [0; HEADER];
        h[..4].copy_from_slice(b"PHC1");
        h[4..20].copy_from_slice(&self.nonce);
        h[20] = self.direction;
        h[21..29].copy_from_slice(&sequence.to_be_bytes());
        h[29..37].copy_from_slice(&offset.to_be_bytes());
        h[37..41].copy_from_slice(&(length as u32).to_be_bytes());
        h[41..43].copy_from_slice(&self.local_port.to_be_bytes());
        h[43..45].copy_from_slice(&self.remote_port.to_be_bytes());
        h[45..77].copy_from_slice(&self.epoch);
        let mut hash = Sha256::new();
        hash.update(generation);
        hash.update(&h[..77]);
        h[77..93].copy_from_slice(&hash.finalize()[..16]);
        Ok(h)
    }
}
struct Command {
    payload: Bytes,
    permit: SendPermit,
    _credit: Credit,
    reply: oneshot::Sender<Result<[u8; HEADER]>>,
}
#[derive(Clone)]
pub(crate) struct Sender {
    commands: mpsc::Sender<Command>,
    gate: Gate,
    budget: Budget,
    peer: String,
    flow: [u8; 16],
}
pub(crate) struct Owner {
    gate: Gate,
    task: Option<JoinHandle<()>>,
}
impl Owner {
    pub(crate) async fn shutdown(mut self) -> Result<()> {
        self.gate.retire();
        if let Some(task) = self.task.take() {
            task.await
                .map_err(|_| anyhow::anyhow!("chunk cleanup owner failed"))?;
        }
        Ok(())
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.gate.retire();
    }
}
struct Abandon {
    gate: Gate,
    armed: bool,
}
impl Drop for Abandon {
    fn drop(&mut self) {
        if self.armed {
            self.gate.retire();
        }
    }
}
impl Sender {
    pub(crate) async fn send(&self, payload: Bytes, permit: SendPermit) -> Result<[u8; HEADER]> {
        ensure!(
            self.gate.state.alive.load(Ordering::SeqCst) && permit.valid(),
            "chunk admission retired"
        );
        let credit = self
            .budget
            .charge(&self.peer, self.flow, Some(payload.len()))?;
        let (reply, waiting) = oneshot::channel();
        let command = Command {
            payload,
            permit: permit.clone(),
            _credit: credit,
            reply,
        };
        permit
            .during(self.commands.send(command))
            .await?
            .map_err(|_| anyhow::anyhow!("chunk owner stopped"))?;
        let mut abandon = Abandon {
            gate: self.gate.clone(),
            armed: true,
        };
        let result = waiting
            .await
            .map_err(|_| anyhow::anyhow!("chunk owner stopped"))?;
        abandon.armed = false;
        result
    }
}
fn validate_connection(peer: &Peer, connection: &Connection) -> Result<()> {
    ensure!(
        connection.remote_address().ip() == std::net::IpAddr::V4(peer.ip),
        "chunk connection assignment mismatch"
    );
    let certificates = connection
        .peer_identity()
        .and_then(|p| {
            p.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .ok_or_else(|| anyhow::anyhow!("chunk certificate missing"))?;
    let actual = certificates.first().map(|c| {
        Sha256::digest(c.as_ref())
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    });
    let expected = peer.fingerprint.replace(':', "").to_ascii_uppercase();
    ensure!(
        actual.as_deref() == Some(&expected),
        "chunk peer fingerprint mismatch"
    );
    Ok(())
}
/// This actor currently prototypes one flow per owned generation, one finite
/// chunk at a time. It is NOT the production multiplexing/native-ACK protocol.
pub(crate) fn start(
    peer: Peer,
    connection: FencedConnection,
    gate: Gate,
    budget: Budget,
    flow: Flow,
) -> Result<(Sender, Owner)> {
    ensure!(
        connection.peer() == &peer,
        "chunk connection peer identity/instance mismatch"
    );
    ensure!(
        connection.belongs_to(&gate.factory),
        "chunk connection belongs to another socket generation"
    );
    validate_connection(&peer, connection.connection())?;
    flow.header(0, 0, 1, [1; 16])?;
    let connection_credit = budget.charge(&peer.id, flow.nonce, None)?;
    let (commands, mut input) = mpsc::channel::<Command>(32);
    let sender = Sender {
        commands,
        gate: gate.clone(),
        budget,
        peer: peer.id.clone(),
        flow: flow.nonce,
    };
    let running = gate.clone();
    let connection = connection.connection().clone();
    let mut generation = [0; 16];
    getrandom::fill(&mut generation).map_err(|_| anyhow::anyhow!("chunk nonce unavailable"))?;
    let task = tokio::spawn(async move {
        let _connection_credit = connection_credit;
        let mut sequence = 0u64;
        let mut offset = 0u64;
        loop {
            let mut command = tokio::select! {biased;_=running.state.cancel.cancelled()=>break,value=input.recv()=>match value{Some(value)=>value,None=>break}};
            if command.reply.is_closed() || !command.permit.valid() {
                let _ = command
                    .reply
                    .send(Err(anyhow::anyhow!("chunk was not started")));
                continue;
            }
            let header = match flow.header(sequence, offset, command.payload.len(), generation) {
                Ok(h) => h,
                Err(_) => {
                    running.retire();
                    break;
                }
            };
            let Some(next_sequence) = sequence.checked_add(1) else {
                running.retire();
                break;
            };
            let Some(next_offset) = offset.checked_add(command.payload.len() as u64) else {
                running.retire();
                break;
            };
            running
                .state
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(header, command.permit.clone());
            let result = tokio::select! {biased;_=running.state.cancel.cancelled()=>Err(anyhow::anyhow!("chunk generation retired")),_=command.reply.closed()=>Err(anyhow::anyhow!("chunk consumer abandoned")),result=transfer(&connection,&header,&command.payload,&command.permit)=>result};
            if result.is_err()
                || !command.permit.valid()
                || !running.state.alive.load(Ordering::SeqCst)
            {
                running.retire();
                connection.close(1u8.into(), b"chunk origin retired");
                connection.closed().await;
                let _ = command
                    .reply
                    .send(Err(anyhow::anyhow!("chunk acknowledgement failed")));
                break;
            }
            // Both finite stream ACK and exact application receipt completed under the
            // ORIGINAL permit. Never remove an expired unacknowledged fence first.
            running
                .state
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&header);
            sequence = next_sequence;
            offset = next_offset;
            let _ = command.reply.send(Ok(header));
        }
        running.retire();
        input.close();
        connection.close(1u8.into(), b"chunk owner stopped");
        connection.closed().await;
        running
            .state
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        while input.try_recv().is_ok() {}
    });
    Ok((
        sender,
        Owner {
            gate,
            task: Some(task),
        },
    ))
}
async fn transfer(
    connection: &Connection,
    header: &[u8; HEADER],
    payload: &Bytes,
    permit: &SendPermit,
) -> Result<()> {
    let (mut send, mut receive) = permit.during(connection.open_bi()).await??;
    let result = permit
        .during(async {
            send.write_all(header).await?;
            send.write_all(payload).await?;
            send.finish()?;
            let transport = async {
                ensure!(send.stopped().await?.is_none(), "chunk reset by peer");
                Ok::<_, anyhow::Error>(())
            };
            let application = async {
                let mut receipt = [0; HEADER];
                receive.read_exact(&mut receipt).await?;
                ensure!(&receipt == header, "foreign chunk acknowledgement");
                let mut extra = [0];
                ensure!(
                    receive.read(&mut extra).await?.is_none(),
                    "chunk acknowledgement has trailing data"
                );
                Ok::<_, anyhow::Error>(())
            };
            tokio::try_join!(transport, application)?;
            Ok::<_, anyhow::Error>(())
        })
        .await;
    match result {
        Ok(Ok(())) => Ok(()),
        _ => {
            let _ = send.reset(1u8.into());
            let _ = receive.stop(1u8.into());
            anyhow::bail!("finite chunk did not acknowledge original admission")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use porthub_mesh::{streams::Endpoint, Identity};
    struct Fixture {
        owner: Owner,
        sender: Sender,
        budget: Budget,
        gate: Gate,
        server: JoinHandle<Result<()>>,
        pump: JoinHandle<()>,
        stop: CancellationToken,
        source: Arc<Endpoint>,
        destination: Arc<Endpoint>,
    }
    async fn fixture(mode: u8) -> Result<Fixture> {
        let a = Identity::new()?;
        let b = Identity::new()?;
        let a_ip = "10.234.252.1".parse()?;
        let b_ip = "10.234.252.2".parse()?;
        let a_peer = Peer {
            id: "a".into(),
            ip: a_ip,
            fingerprint: a.fingerprint().into(),
            instance: "a-instance".into(),
        };
        let b_peer = Peer {
            id: "b".into(),
            ip: b_ip,
            fingerprint: b.fingerprint().into(),
            instance: "b-instance".into(),
        };
        let gate = Gate::new(SendPermit::new(|| true));
        let (source, mut a_io) = Endpoint::new_fenced(a, a_ip, gate.factory())?;
        let (destination, mut b_io) = Endpoint::new(b, b_ip)?;
        source.update_peers(vec![b_peer.clone()])?;
        destination.update_peers(vec![a_peer])?;
        let a_in = a_io.ingress();
        let b_in = b_io.ingress();
        let stop = CancellationToken::new();
        let cancel = stop.clone();
        let pump = tokio::spawn(async move {
            loop {
                tokio::select! {
                 _=cancel.cancelled()=>break,
                 packet=a_io.outgoing()=>match packet{Some(packet)=>{let _=b_in.send_reliable_guarded(a_ip,packet.payload,packet.permit).await;},None=>break},
                 packet=b_io.outgoing()=>match packet{Some(packet)=>{let _=a_in.send_reliable_guarded(b_ip,packet.payload,packet.permit).await;},None=>break}
                }
            }
        });
        let source = Arc::new(source);
        let destination = Arc::new(destination);
        let (client, accepted) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            tokio::join!(source.connect_fenced(&b_peer), destination.accept())
        })
        .await?;
        let client = client?;
        let (_, remote) = accepted?;
        let server_stop = stop.clone();
        let server = tokio::spawn(async move {
            let (mut reply, mut receive) = remote.accept_bi().await?;
            if mode == 2 {
                receive.stop(7u8.into())?;
                reply.reset(7u8.into())?;
                tokio::select! {_=remote.closed()=>{},_=server_stop.cancelled()=>{}}
                return Ok(());
            }
            let mut header = [0; HEADER];
            receive.read_exact(&mut header).await?;
            let length = u32::from_be_bytes(header[37..41].try_into().unwrap()) as usize;
            ensure!(length <= CHUNK, "oversized fixture chunk");
            let mut payload = vec![0; length];
            receive.read_exact(&mut payload).await?;
            ensure!(
                payload.iter().all(|byte| *byte == 3),
                "fixture data changed"
            );
            let mut extra = [0];
            ensure!(
                receive.read(&mut extra).await?.is_none(),
                "sender did not finish finite chunk"
            );
            if mode == 1 {
                tokio::select! {_=remote.closed()=>{},_=server_stop.cancelled()=>{}}
                return Ok(());
            }
            if mode == 3 {
                header[4] ^= 1;
            }
            reply.write_all(&header).await?;
            reply.finish()?;
            // This fixture is an application receipt, NOT a native TCP ACK witness.
            tokio::select! {_=remote.closed()=>{},_=server_stop.cancelled()=>{}}
            Ok(())
        });
        let budget = Budget::default();
        let flow = Flow {
            nonce: [1; 16],
            direction: 0,
            local_port: 4000,
            remote_port: 443,
            epoch: [1; 32],
        };
        let (sender, owner) = start(b_peer, client, gate.clone(), budget.clone(), flow)?;
        Ok(Fixture {
            owner,
            sender,
            budget,
            gate,
            server,
            pump,
            stop,
            source,
            destination,
        })
    }
    async fn cleanup(f: Fixture) -> Result<()> {
        f.owner.shutdown().await?;
        f.stop.cancel();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), f.server).await??;
        f.source.close();
        f.destination.close();
        f.stop.cancel();
        f.pump.await?;
        let state = f.budget.0.lock().unwrap();
        ensure!(
            state.total.bytes == 0
                && state.total.chunks == 0
                && state.total.connections == 0
                && state.peers.is_empty()
                && state.flows.is_empty(),
            "chunk credits leaked"
        );
        result
    }
    #[tokio::test]
    async fn actual_finished_quinn_stream_and_exact_receipt_release_original_credit() -> Result<()>
    {
        let f = fixture(0).await?;
        let receipt = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            f.sender
                .send(Bytes::from(vec![3; CHUNK]), SendPermit::new(|| true)),
        )
        .await??;
        ensure!(&receipt[..4] == b"PHC1", "bad receipt");
        ensure!(
            f.gate.state.pending.lock().unwrap().is_empty(),
            "acked chunk retained"
        );
        ensure!(
            f.budget.0.lock().unwrap().total.bytes == 0,
            "acked payload retained credit"
        );
        cleanup(f).await
    }
    #[tokio::test]
    async fn actual_quinn_transport_ack_alone_cannot_release_chunk_or_extend_expired_origin(
    ) -> Result<()> {
        let f = fixture(1).await?;
        let live = Arc::new(AtomicBool::new(true));
        let check = live.clone();
        let sender = f.sender.clone();
        let waiting = tokio::spawn(async move {
            sender
                .send(
                    Bytes::from(vec![3; CHUNK]),
                    SendPermit::new(move || check.load(Ordering::SeqCst)),
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while f.gate.state.pending.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        ensure!(
            !waiting.is_finished(),
            "transport ACK falsely completed application receipt"
        );
        ensure!(
            f.budget.0.lock().unwrap().total.bytes == CHUNK,
            "unacknowledged credit released"
        );
        live.store(false, Ordering::SeqCst);
        ensure!(
            tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
                .await??
                .is_err(),
            "expired origin completed"
        );
        ensure!(
            !f.gate.state.alive.load(Ordering::SeqCst),
            "old generation remained active"
        );
        cleanup(f).await
    }
    #[tokio::test]
    async fn actual_quinn_peer_reset_cannot_acknowledge_chunk() -> Result<()> {
        let f = fixture(2).await?;
        ensure!(
            f.sender
                .send(Bytes::from(vec![3; 128]), SendPermit::new(|| true))
                .await
                .is_err(),
            "reset falsely acknowledged"
        );
        cleanup(f).await
    }
    #[tokio::test]
    async fn actual_quinn_foreign_flow_receipt_cannot_release_as_success() -> Result<()> {
        let f = fixture(3).await?;
        ensure!(
            f.sender
                .send(Bytes::from(vec![3; 128]), SendPermit::new(|| true))
                .await
                .is_err(),
            "foreign receipt accepted"
        );
        cleanup(f).await
    }
    #[tokio::test]
    async fn actual_pending_quinn_chunk_cannot_borrow_fresh_queued_admission() -> Result<()> {
        let f = fixture(1).await?;
        let valid = Arc::new(AtomicBool::new(true));
        let original = valid.clone();
        let first = f.sender.clone();
        let old = tokio::spawn(async move {
            first
                .send(
                    Bytes::from(vec![3; CHUNK]),
                    SendPermit::new(move || original.load(Ordering::SeqCst)),
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while f.gate.state.pending.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let second = f.sender.clone();
        let fresh = tokio::spawn(async move {
            second
                .send(Bytes::from(vec![3; CHUNK]), SendPermit::new(|| true))
                .await
        });
        tokio::task::yield_now().await;
        valid.store(false, Ordering::SeqCst);
        ensure!(
            tokio::time::timeout(std::time::Duration::from_secs(1), old)
                .await??
                .is_err(),
            "old chunk used fresh queued admission"
        );
        ensure!(
            tokio::time::timeout(std::time::Duration::from_secs(1), fresh)
                .await??
                .is_err(),
            "retired generation admitted a queued replacement"
        );
        cleanup(f).await
    }
    #[tokio::test]
    async fn abandoning_actual_unacknowledged_quinn_chunk_retires_generation() -> Result<()> {
        let f = fixture(1).await?;
        let sender = f.sender.clone();
        let pending = tokio::spawn(async move {
            sender
                .send(Bytes::from(vec![3; CHUNK]), SendPermit::new(|| true))
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while f.gate.state.pending.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        pending.abort();
        let _ = pending.await;
        ensure!(
            !f.gate.state.alive.load(Ordering::SeqCst),
            "abandoned original origin was forgotten without fencing"
        );
        cleanup(f).await
    }
    #[test]
    fn original_credit_budget_bounds_connections_peers_flows_and_bytes() {
        let budget = Budget::default();
        let mut owners = Vec::new();
        for peer in 0..64 {
            for flow in 0..8 {
                let mut nonce = [0; 16];
                nonce[0] = flow + 1;
                owners.push(budget.charge(&format!("p{peer}"), nonce, None).unwrap());
            }
        }
        assert!(budget.charge("overflow", [1; 16], None).is_err());
        assert!(budget.charge("p0", [9; 16], None).is_err());
        let mut chunks = Vec::new();
        for peer in 0..4 {
            for flow in 1..=2 {
                let mut nonce = [0; 16];
                nonce[0] = flow;
                for _ in 0..128 {
                    chunks.push(
                        budget
                            .charge(&format!("p{peer}"), nonce, Some(CHUNK))
                            .unwrap(),
                    );
                }
            }
        }
        assert_eq!(budget.0.lock().unwrap().total.bytes, MAX_BYTES);
        assert!(budget.charge("p4", [1; 16], Some(1)).is_err());
        drop(chunks);
        assert_eq!(budget.0.lock().unwrap().total.bytes, 0);
        drop(owners);
        assert!(budget.0.lock().unwrap().peers.is_empty());
    }
}
