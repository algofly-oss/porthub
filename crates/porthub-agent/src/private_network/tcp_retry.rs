//! A newly read local TUN segment can arrive between fresh pair admission and
//! the peer completing its handshake. A repeated OS retransmission may be tens
//! of seconds away. Nothing in this buffer survives a worker or its original
//! bounded authorities. Readiness requests contain no segment data.
use bytes::Bytes;
use porthub_mesh::udp::SendPermit;
use porthub_network::policy::{Engine, Packet, RetryProof, TcpContinuity};
use std::time::{Duration, Instant};
use uuid::Uuid;

const LIMIT: usize = 32;
const WINDOW: Duration = Duration::from_secs(2);
struct Entry {
    proof: RetryProof,
    peer: String,
    generation: Uuid,
    due: Instant,
    permit: SendPermit,
    bytes: Option<Bytes>,
}
#[derive(Default)]
pub(super) struct LocalRetries(Vec<Entry>);

impl LocalRetries {
    pub fn active(&self) -> bool {
        !self.0.is_empty()
    }

    pub fn observe(
        &mut self,
        policy: &Engine,
        pending: &TcpContinuity,
        peer: &str,
        packet: Packet,
        bytes: &[u8],
        generation: Uuid,
        permit: impl FnOnce() -> Option<SendPermit>,
    ) {
        if self.0.len() >= LIMIT
            || bytes.len() > porthub_mesh::MAX_PACKET
            || !packet.has_tcp_data(bytes)
        {
            return;
        }
        let Some(proof) = policy.retry_proof(pending, peer, packet) else {
            return;
        };
        if self.0.iter().any(|e| e.peer == peer && e.proof == proof) {
            return;
        }
        let Some(permit) = permit().filter(|p| p.valid()) else {
            return;
        };
        self.0.push(Entry {
            proof,
            peer: peer.into(),
            generation,
            due: Instant::now() + WINDOW,
            permit,
            bytes: Some(Bytes::copy_from_slice(bytes)),
        });
    }
    pub fn requests(
        &mut self,
        policy: &Engine,
        generation: Option<Uuid>,
    ) -> Vec<(String, Vec<u8>)> {
        let now = Instant::now();
        self.0
            .retain(|e| Some(e.generation) == generation && e.due > now && e.permit.valid());
        self.0
            .iter()
            .filter(|e| e.bytes.is_some() && policy.retry_owner(&e.peer, e.proof).is_some())
            .map(|e| (e.peer.clone(), e.proof.request(*e.generation.as_bytes())))
            .collect()
    }
    pub fn ready(
        &mut self,
        policy: &Engine,
        peer: &str,
        generation: Uuid,
        wire: &[u8],
        current: impl FnOnce() -> Option<SendPermit>,
    ) -> Option<(Bytes, SendPermit)> {
        let e = self.0.iter_mut().find(|e| {
            e.peer == peer
                && e.generation == generation
                && e.bytes.is_some()
                && e.proof.matches_reply(*generation.as_bytes(), wire)
        })?;
        let owner = policy.retry_owner(peer, e.proof)?;
        let due = e.due;
        let bound = SendPermit::bounded(
            move || owner.upgrade().is_some_and(|r| r.alive()),
            move || due.checked_duration_since(Instant::now()),
        );
        let permit = SendPermit::combine(vec![e.permit.clone(), current()?, bound]);
        if !permit.valid() {
            return None;
        }
        Some((e.bytes.take()?, permit))
    }
}
