//! Bounded, process-local evidence of ordinary raw TCP handshakes. No packets,
//! transport handles, permits or old authorizations are retained.
use super::*;

const MAX_PEERS: usize = 32;
const MAX_FLOWS: usize = 256;
const BATCH: usize = 32;
const WAIT: Duration = Duration::from_secs(35);
const CONFIRM: Duration = Duration::from_secs(6);
const HEADER: usize = 37;
type Opening = [u8; 16];

fn encode(packet: Packet) -> Opening {
    let k = packet.key;
    let mut out = [0; 16];
    out[..4].copy_from_slice(&k.src.octets());
    out[4..8].copy_from_slice(&k.dst.octets());
    out[8..10].copy_from_slice(&k.sport.to_be_bytes());
    out[10..12].copy_from_slice(&k.dport.to_be_bytes());
    out[12..].copy_from_slice(&packet.tcp_sequence.to_be_bytes());
    out
}
fn key(opening: Opening) -> Key {
    Key {
        src: Ipv4Addr::from(<[u8; 4]>::try_from(&opening[..4]).unwrap()),
        dst: Ipv4Addr::from(<[u8; 4]>::try_from(&opening[4..8]).unwrap()),
        sport: u16::from_be_bytes(opening[8..10].try_into().unwrap()),
        dport: u16::from_be_bytes(opening[10..12].try_into().unwrap()),
        protocol: 6,
        icmp: 0,
    }
}
fn reverse(k: Key) -> Key {
    Key {
        src: k.dst,
        dst: k.src,
        sport: k.dport,
        dport: k.sport,
        ..k
    }
}
fn matches_query(peer: &PeerInfo, query: &Lookup) -> bool {
    match query.kind.as_str() {
        "peer" => peer.id == query.value,
        "ip" => query.value.parse::<Ipv4Addr>().ok() == Some(peer.ip),
        "name" => std::iter::once(&peer.hostname)
            .chain(peer.aliases.iter())
            .any(|name| {
                name.trim_end_matches('.')
                    .eq_ignore_ascii_case(query.value.trim_end_matches('.'))
            }),
        _ => true,
    }
}
fn established(flow: &Flow, now: Instant) -> bool {
    flow.opening.key.protocol == 6
        && flow.phase == 2
        && flow.fin_directions == 0
        && flow.close_until.is_none()
        && flow.expires > now
        && flow.raw_path & 7 == 3
}

struct Candidate {
    opening: Packet,
    until: Instant,
}
struct Pair {
    local: PeerInfo,
    peer: PeerInfo,
    epoch: String,
    workspace: String,
    flows: Vec<Candidate>,
    until: Instant,
    challenge: Option<([u8; 16], Instant)>,
}
#[derive(Default)]
pub struct TcpContinuity {
    pending: HashMap<String, Pair>,
}

impl TcpContinuity {
    pub fn peers(&self) -> impl Iterator<Item = &str> {
        self.pending.keys().map(String::as_str)
    }
    pub fn contains(&self, peer: &str) -> bool {
        self.pending.contains_key(peer)
    }
    pub fn discard(&mut self, peer: &str) {
        self.pending.remove(peer);
    }
    pub fn discard_query(&mut self, query: &Lookup) {
        self.pending.retain(|_, p| !matches_query(&p.peer, query));
    }
    #[cfg(test)]
    pub(super) fn timeout_confirmation(&mut self, peer: &str) {
        if let Some(p) = self.pending.get_mut(peer) {
            if let Some((_, end)) = &mut p.challenge {
                *end = Instant::now();
            }
        }
    }
    pub fn expire(&mut self) {
        let now = Instant::now();
        self.pending.retain(|_, p| {
            p.until > now && p.challenge.is_none_or(|(_, due)| due > now) && !p.flows.is_empty()
        });
    }
    fn count(&self) -> usize {
        self.pending.values().map(|p| p.flows.len()).sum()
    }
    fn insert(&mut self, id: String, mut pair: Pair) {
        if self.contains(&id) || self.pending.len() >= MAX_PEERS {
            return;
        }
        pair.flows.truncate(MAX_FLOWS.saturating_sub(self.count()));
        if !pair.flows.is_empty() {
            self.pending.insert(id, pair);
        }
    }
    pub fn merge(&mut self, mut other: Self) {
        self.expire();
        other.expire();
        for (id, p) in other.pending {
            self.insert(id, p);
        }
    }
    pub(super) fn capture(&mut self, id: &str, pair: &Engine) {
        if self.contains(id) || self.pending.len() >= MAX_PEERS {
            return;
        }
        let remaining = MAX_FLOWS.saturating_sub(self.count());
        if remaining == 0 {
            return;
        }
        let now = Instant::now();
        let Some(snapshot) = &pair.snapshot else {
            return;
        };
        let Some(epoch) = &pair.pair_private_epoch else {
            return;
        };
        let Some(local) = snapshot.peers.iter().find(|p| p.id == snapshot.self_) else {
            return;
        };
        let Some(peer) = snapshot.peers.iter().find(|p| p.id == id) else {
            return;
        };
        let flows: Vec<_> = pair
            .flows
            .values()
            .filter(|f| established(f, now))
            .take(remaining)
            .map(|f| Candidate {
                opening: f.opening,
                until: f.expires,
            })
            .collect();
        self.insert(
            id.to_owned(),
            Pair {
                local: local.clone(),
                peer: peer.clone(),
                epoch: epoch.clone(),
                workspace: snapshot.workspace.clone(),
                until: now + WAIT,
                flows,
                challenge: None,
            },
        );
    }
    /// New SYN, FIN or RST permanently retires the old four-tuple candidate.
    pub fn observe_lifecycle(&mut self, packet: Packet) {
        if self.pending.is_empty() || (!packet.fin && !packet.rst && !(packet.syn && !packet.ack)) {
            return;
        }
        let k = packet.key;
        self.pending.retain(|_, p| {
            p.flows
                .retain(|f| f.opening.key != k && f.opening.key != reverse(k));
            !p.flows.is_empty()
        });
    }
    pub fn awaiting(&mut self, peer: &str, packet: Packet) -> bool {
        self.expire();
        self.pending.get(peer).is_some_and(|p| {
            p.challenge.is_some()
                && p.flows
                    .iter()
                    .any(|f| f.opening.key == packet.key || f.opening.key == reverse(packet.key))
        })
    }
    pub fn requests(&mut self, generation: [u8; 16]) -> Vec<(String, Vec<u8>)> {
        self.expire();
        let mut frames = Vec::new();
        for (id, p) in &self.pending {
            let Some((challenge, _)) = p.challenge else {
                continue;
            };
            for batch in p.flows.chunks(BATCH) {
                frames.push((
                    id.clone(),
                    frame(
                        1,
                        generation,
                        challenge,
                        batch.iter().map(|f| encode(f.opening)),
                    ),
                ));
            }
        }
        frames
    }
}
fn frame(
    kind: u8,
    generation: [u8; 16],
    nonce: [u8; 16],
    flows: impl Iterator<Item = Opening>,
) -> Vec<u8> {
    let mut b = b"PHC1".to_vec();
    b.push(kind);
    b.extend_from_slice(&generation);
    b.extend_from_slice(&nonce);
    for flow in flows.take(BATCH) {
        b.extend_from_slice(&flow);
    }
    b
}
impl Engine {
    pub fn observe_raw_tcp(&mut self, peer: &str, packet: Packet, inbound: bool, raw: bool) {
        if self.expired_tcp.is_none() || packet.key.protocol != 6 || (raw && packet.syn) {
            return;
        }
        let Some(pair) = self.pairs.get_mut(peer) else {
            return;
        };
        let k = packet.key;
        let k = if pair.flows.contains_key(&k) {
            k
        } else {
            reverse(k)
        };
        if let Some(f) = pair.flows.get_mut(&k) {
            f.raw_path |= if !raw {
                4
            } else if inbound {
                1
            } else {
                2
            };
        }
    }
    pub fn discard_tcp_query(&mut self, query: &Lookup) {
        if let Some(waiting) = &mut self.expired_tcp {
            waiting.discard_query(query);
        }
        for (id, pair) in &mut self.pairs {
            if pair.snapshot.as_ref().is_some_and(|s| {
                s.peers
                    .iter()
                    .find(|p| p.id == *id)
                    .is_some_and(|p| matches_query(p, query))
            }) {
                for flow in pair.flows.values_mut() {
                    flow.raw_path |= 4;
                }
            }
        }
    }
    pub fn enable_tcp_continuity(&mut self, enabled: bool) {
        if enabled {
            self.expired_tcp.get_or_insert_with(Default::default);
        } else {
            self.expired_tcp = None;
        }
    }
    pub fn take_expired_tcp(&mut self) -> TcpContinuity {
        self.expired_tcp
            .as_deref_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    }
    pub fn retire_expired_pair(&mut self, id: &str) {
        if let Some(p) = self.pairs.remove(id) {
            if let Some(waiting) = &mut self.expired_tcp {
                waiting.expire();
                waiting.capture(id, &p);
            }
        }
    }
    pub fn invalidate_tcp_continuity(&mut self) {
        self.expired_tcp = None;
        for p in self.pairs.values_mut() {
            for f in p.flows.values_mut() {
                f.raw_path |= 4;
            }
        }
    }
    pub fn pause_established_tcp(&self) -> TcpContinuity {
        let mut p = TcpContinuity::default();
        for (id, engine) in &self.pairs {
            p.capture(id, engine);
        }
        p
    }
    /// Validate the newly installed pair, including the original opening direction.
    /// The relay stamp belongs to the old carrier. Every control frame separately
    /// authenticates its new carrier; the process certificate and instance stay exact.
    pub fn prepare_tcp(&self, pending: &mut TcpContinuity, lease: &PairLease) -> bool {
        pending.expire();
        let Some(old) = pending.pending.get_mut(&lease.peer.id) else {
            return false;
        };
        let current = self
            .pairs
            .get(&lease.peer.id)
            .filter(|p| p.valid_lease() && p.pair_private_epoch.as_ref() == Some(&old.epoch));
        let same = |a: &PeerInfo, b: &PeerInfo| {
            a.id == b.id
                && a.ip == b.ip
                && a.instance == b.instance
                && a.fingerprint == b.fingerprint
        };
        if !self.valid_lease()
            || old.workspace != lease.workspace
            || old.epoch != lease.epoch
            || !same(&old.local, &lease.local)
            || !same(&old.peer, &lease.peer)
            || current.is_none()
        {
            pending.discard(&lease.peer.id);
            return false;
        }
        let p = current.unwrap();
        let now = Instant::now();
        old.flows.retain(|e| e.until > now && p.allowed(e.opening));
        if old.flows.is_empty() {
            pending.discard(&lease.peer.id);
            return false;
        }
        if old.challenge.is_none() {
            let mut nonce = [0; 16];
            if getrandom::fill(&mut nonce).is_err() {
                pending.discard(&lease.peer.id);
                return false;
            }
            old.challenge = Some((nonce, now + CONFIRM));
        }
        true
    }
    /// The caller supplies a validated, fresh ordinary pair and authenticates
    /// the control envelope. Neither a query nor an unrecognized reply admits data.
    pub fn tcp_confirmation(
        &mut self,
        pending: &mut TcpContinuity,
        id: &str,
        generation: [u8; 16],
        wire: &[u8],
    ) -> Option<Vec<u8>> {
        pending.expire();
        if wire.len() <= HEADER
            || wire.len() > HEADER + 16 * BATCH
            || !(wire.len() - HEADER).is_multiple_of(16)
            || &wire[..4] != b"PHC1"
            || wire[5..21] != generation
            || !self.valid_lease()
        {
            return None;
        }
        let p = self
            .pairs
            .get_mut(id)
            .filter(|p| p.valid_lease() && p.pair_private_epoch.is_some())?;
        let input = wire[HEADER..]
            .chunks_exact(16)
            .map(|b| <[u8; 16]>::try_from(b).unwrap());
        let nonce = wire[21..37].try_into().ok()?;
        let now = Instant::now();
        match wire[4] {
            1 => {
                let mut approved = Vec::new();
                for flow in input {
                    let live = p.flows.get(&key(flow)).is_some_and(|f| {
                        (established(f, now)
                            || f.raw_path & 8 != 0
                                && f.raw_path & 4 == 0
                                && f.fin_directions == 0
                                && f.expires > now)
                            && encode(f.opening) == flow
                            && p.allowed(f.opening)
                    });
                    let waiting = pending.pending.get(id).is_some_and(|prior| {
                        prior.challenge.is_some()
                            && prior.flows.iter().any(|f| {
                                encode(f.opening) == flow && f.until > now && p.allowed(f.opening)
                            })
                    });
                    if live || waiting {
                        approved.push(flow);
                    }
                }
                (!approved.is_empty()).then(|| frame(2, generation, nonce, approved.into_iter()))
            }
            2 => {
                let old = pending.pending.get_mut(id)?;
                if old
                    .challenge
                    .is_none_or(|(challenge, _)| challenge != nonce)
                {
                    return None;
                }
                for flow in input {
                    let Some(i) = old.flows.iter().position(|f| encode(f.opening) == flow) else {
                        continue;
                    };
                    let e = old.flows.swap_remove(i);
                    let k = e.opening.key;
                    if e.until <= now
                        || p.flows.contains_key(&k)
                        || p.flows.contains_key(&reverse(k))
                        || !p.allowed(e.opening)
                    {
                        continue;
                    }
                    let Ok(permit) = p.flow_budget.0.clone().try_acquire_owned() else {
                        break;
                    };
                    p.has_resumed_tcp = true;
                    p.flows.insert(
                        k,
                        Flow {
                            remote: String::new(),
                            opening: e.opening,
                            expires: e.until,
                            phase: 2,
                            raw_path: 8,
                            resumed_at: Some(now),
                            fin_directions: 0,
                            close_until: None,
                            _permit: Some(permit),
                        },
                    );
                }
                if old.flows.is_empty() {
                    pending.discard(id);
                }
                None
            }
            _ => None,
        }
    }
    #[cfg(test)]
    pub(super) fn restore_established_tcp(
        &mut self,
        pending: &mut TcpContinuity,
        lease: &PairLease,
    ) -> usize {
        if !self.prepare_tcp(pending, lease) {
            return 0;
        }
        let old = self.pairs[&lease.peer.id].flows.len();
        for (id, mut request) in pending.requests([0; 16]) {
            request[4] = 2;
            self.tcp_confirmation(pending, &id, [0; 16], &request);
        }
        self.pairs[&lease.peer.id].flows.len() - old
    }
}
