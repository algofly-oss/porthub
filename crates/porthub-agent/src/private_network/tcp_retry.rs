//! A newly read local TUN segment can arrive between fresh pair admission and
//! the peer completing its handshake. A repeated OS retransmission may be tens
//! of seconds away. Nothing in this buffer survives a worker or its original
//! bounded authorities. Readiness requests contain no segment data.
use bytes::Bytes;
use porthub_mesh::udp::SendPermit;
use porthub_network::policy::{Engine, LocalOpening, Packet, RetryProof, TcpContinuity};
use std::time::{Duration, Instant};
use uuid::Uuid;

const LIMIT: usize = 32;
// Base recovery and the first fresh pair can be separate control exchanges.
// Field captures measured 4.8s from a local retry to a valid pair.
const QUARANTINE: Duration = Duration::from_secs(8);
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
        let mut groups: Vec<(&str, Vec<RetryProof>)> = Vec::new();
        for e in &self.0 {
            if e.bytes.is_none() || policy.retry_owner(&e.peer, e.proof).is_none() {
                continue;
            }
            if let Some((_, proofs)) = groups
                .iter_mut()
                .find(|(peer, proofs)| *peer == e.peer && proofs[0].same_challenge(&e.proof))
            {
                proofs.push(e.proof);
            } else {
                groups.push((&e.peer, vec![e.proof]));
            }
        }
        let Some(generation) = generation else {
            return Vec::new();
        };
        groups
            .into_iter()
            .map(|(peer, proofs)| {
                (
                    peer.into(),
                    proofs[0].request_batch(*generation.as_bytes(), proofs.iter()),
                )
            })
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
        let (e, owner) = self
            .0
            .iter_mut()
            .filter(|e| {
                e.peer == peer
                    && e.generation == generation
                    && e.bytes.is_some()
                    && e.proof.matches_reply(*generation.as_bytes(), wire)
            })
            .find_map(|e| {
                if e.due <= Instant::now() || !e.permit.valid() {
                    return None;
                }
                let owner = policy.retry_owner(peer, e.proof)?;
                Some((e, owner))
            })?;
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

struct Unconfirmed {
    peer: String,
    opening: LocalOpening,
    generation: Uuid,
    expires: Instant,
    bytes: Bytes,
}
/// Newly read packets only. This worker-local holding area has no transport,
/// carrier permit, native write capability, or ability to emit application bytes.
#[derive(Default)]
pub(super) struct Quarantine(Vec<Unconfirmed>);
impl Quarantine {
    pub fn active(&self) -> bool {
        !self.0.is_empty()
    }
    pub fn expire(&mut self, generation: Option<Uuid>) {
        self.0
            .retain(|e| e.expires > Instant::now() && Some(e.generation) == generation);
    }
    pub fn observe(
        &mut self,
        pending: &TcpContinuity,
        generation: Uuid,
        packet: Packet,
        bytes: &[u8],
        local: &LocalRetries,
    ) {
        self.expire(Some(generation));
        if self.0.len() + local.0.len() >= LIMIT
            || bytes.len() > porthub_mesh::MAX_PACKET
            || !packet.has_tcp_data(bytes)
        {
            return;
        }
        let Some((peer, opening)) = pending.local_opening(packet) else {
            return;
        };
        if self
            .0
            .iter()
            .any(|e| e.opening == opening && e.peer == peer)
        {
            return;
        }
        self.0.push(Unconfirmed {
            peer: peer.into(),
            opening,
            generation,
            expires: Instant::now() + QUARANTINE,
            bytes: Bytes::copy_from_slice(bytes),
        });
    }
    pub fn admit(
        &mut self,
        local: &mut LocalRetries,
        policy: &Engine,
        pending: &TcpContinuity,
        peer: &str,
        generation: Uuid,
        permit: impl Fn() -> Option<SendPermit>,
    ) {
        self.expire(Some(generation));
        self.0.retain(|e| {
            if e.peer != peer {
                return true;
            }
            let Some(packet) = Packet::parse(&e.bytes) else {
                return false;
            };
            let Some(proof) = policy.retry_proof(pending, peer, packet) else {
                return false;
            };
            if !proof.matches_opening(e.opening) {
                return false;
            }
            local.observe(policy, pending, peer, packet, &e.bytes, generation, &permit);
            false
        });
    }
}
