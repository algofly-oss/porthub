//! Lease-bound IPv4 ACLs and reply tracking. A packet's addresses must match
//! its authenticated remote peer; no LAN/default-gateway forwarding is allowed.
pub mod pair_acl;
pub mod exit_pick;
pub use exit_pick::{ExitPickRequest,ExitPickResponse,ExitPickStatus,ExitChoice};
mod sparse;
mod tcp_continuity;
pub use tcp_continuity::{RetryProof, TcpContinuity, TcpResume};
pub use sparse::{ExitIntent,ExitRole,ExitPair, Lookup, PairLease, PairResponse, SparseInfo, MAX_PAIR_LEASES, MAX_PRIVATE_SUFFIXES, MAX_PRIVATE_SUFFIX_BYTES};
use anyhow::{ensure, Result};
/// Existing full-snapshot ceiling, including the mandatory local identity.
pub const MAX_SNAPSHOT_PEERS: usize = 4096;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    time::{Duration, Instant},
};
#[derive(Clone, Deserialize, Serialize)]
pub struct PeerInfo {
    pub id: String,
    pub ip: Ipv4Addr,
    pub fingerprint: String,
    pub instance: String,
    /// Server-authored relay incarnation; absent for legacy/direct identities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_origin: Option<String>,
    #[serde(default)]
    pub online: bool,
    #[serde(default)]
    pub stream_transport: String,
    #[serde(default)]
    pub lan_networks: Vec<porthub_mesh::lan_routes::Network>,
    pub hostname: String,
    #[serde(default)]
    pub aliases: Vec<String>,
}
impl PeerInfo {
    /// Compare an authenticated packet source with the currently authorized peer.
    /// A direct reader authenticates the process certificate. A stamped gateway
    /// record additionally identifies the relay registration that supplied it.
    pub fn matches_packet_origin(&self, origin: &Self) -> bool {
        self.id == origin.id
            && self.ip == origin.ip
            && self.instance == origin.instance
            && self.fingerprint == origin.fingerprint
            && origin.relay_origin.as_ref().is_none_or(|stamp| self.relay_origin.as_ref() == Some(stamp))
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Port {
    pub start: u16,
    pub end: u16,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct Grant {
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub ports: Vec<Port>,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct ExitRoute {
    pub id: String,
    pub name: String,
    pub routing_peers: Vec<String>,
    #[serde(default)]
    pub tor_enabled: bool,
    #[serde(default = "default_tor_groups")]
    pub tor_circuit_groups: usize,
    pub clients: Vec<String>,
    #[serde(default)]
    pub selection: porthub_mesh::exit_policy::Selection,
    #[serde(default)]
    pub traffic_mode: porthub_mesh::exit_policy::TrafficMode,
    #[serde(default)]
    pub allow_direct_fallback: bool,
    #[serde(default = "yes")]
    pub masquerade: bool,
    #[serde(default = "yes")]
    pub block_lan_access: bool,
}
fn default_tor_groups() -> usize { 4 }
fn yes() -> bool {
    true
}

#[cfg(test)]
mod tor_route_tests {
    use super::*;
    fn snapshot() -> Snapshot {
        serde_json::from_value(serde_json::json!({
            "workspace":"workspace","self":"client","revision":1,
            "expires_at":Utc::now()+chrono::Duration::seconds(30),
            "peers":[{"id":"client","ip":"10.203.0.2","fingerprint":"local","instance":"instance","hostname":"client"}],
            "grants":[],"exit_routes":[{"id":"route","name":"Tor","routing_peers":[],"clients":["client"],"tor_enabled":true}]
        })).unwrap()
    }
    #[test]
    fn explicit_local_tor_is_valid_without_remote_exit_permissions() {
        let mut engine=Engine::default();
        assert!(engine.apply(snapshot()).is_ok());
        assert!(engine.valid_lease());
        let mut invalid=snapshot();invalid.exit_routes[0].tor_enabled=false;
        assert!(engine.apply(invalid).is_err());
        assert!(!engine.valid_lease());
    }
    #[test]
    fn expired_policy_fails_closed_with_an_actionable_clock_diagnostic() {
        let mut engine=Engine::default();engine.apply(snapshot()).unwrap();
        let mut expired=snapshot();expired.expires_at=Utc::now()-chrono::Duration::seconds(20);
        let error=engine.apply(expired).unwrap_err().to_string();
        assert!(error.contains("check host clock synchronization"));assert!(!engine.valid_lease());
    }
    #[test]
    fn retired_address_rules_do_not_replace_answers_or_discard_valid_blocks() {
        let mut raw=serde_json::to_value(snapshot()).unwrap();
        raw["dns_rules"]=serde_json::json!([
            {"domain":"blocked.test","action":{"type":"block"}},
            {"domain":"mapped.test","action":{"type":"override","addresses":["192.0.2.1"]}}
        ]);
        let policy:Snapshot=serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(policy.dns_rules.len(),1);assert_eq!(policy.dns_rules[0].domain,"blocked.test");
        raw["dns_rules"][0]["action"]=serde_json::json!({"type":"unknown"});
        assert!(serde_json::from_value::<Snapshot>(raw).is_err());
    }
    #[test]
    fn tor_groups_and_client_identity_are_enforced() {
        let mut invalid=snapshot();invalid.exit_routes[0].tor_circuit_groups=17;
        assert!(Engine::default().apply(invalid).is_err());
        let mut invalid=snapshot();invalid.exit_routes[0].clients=vec!["unregistered".into()];
        assert!(Engine::default().apply(invalid).is_err());
    }
}
#[derive(Clone, Deserialize, Serialize)]
pub struct Snapshot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sparse: Option<SparseInfo>,
    pub workspace: String,
    #[serde(rename = "self")]
    pub self_: String,
    pub revision: u64,
    pub expires_at: DateTime<Utc>,
    pub peers: Vec<PeerInfo>,
    #[serde(default)]
    pub dns_suffixes: Vec<String>,
    pub grants: Vec<Grant>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub pair_acl: Option<pair_acl::PairAcl>,
    #[serde(default)]
    pub exit_routes: Vec<ExitRoute>,
    #[serde(default, deserialize_with="blocking_dns_rules")]
    pub dns_rules: Vec<porthub_mesh::dns_policy::Rule>,
}
// A rolling upgrade may still receive an old gateway's address rules. Ignore
// only that retired action, retaining blocks and rejecting malformed blocks.
fn blocking_dns_rules<'de,D:serde::Deserializer<'de>>(deserializer:D)->std::result::Result<Vec<porthub_mesh::dns_policy::Rule>,D::Error> {
    let rules=Vec::<serde_json::Value>::deserialize(deserializer)?;
    rules.into_iter().filter(|rule|rule["action"]["type"]!="override")
        .map(|rule|serde_json::from_value(rule).map_err(serde::de::Error::custom)).collect()
}
// The control protocol calls the identity field "self".
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    sport: u16,
    dport: u16,
    icmp: u16,
}
#[derive(Clone, Copy)]
pub struct Packet {
    key: Key,
    syn: bool,
    ack: bool,
    rst: bool,
    fin: bool,
    icmp_type: u8,
    tcp_sequence: u32,
}
impl Packet {
    pub fn source(&self) -> Ipv4Addr {
        self.key.src
    }
    pub fn destination(&self) -> Ipv4Addr {
        self.key.dst
    }
    pub fn opening_sequence(&self) -> Option<u32> {
        (self.key.protocol == 6 && self.syn && !self.ack && !self.fin && !self.rst).then_some(self.tcp_sequence)
    }
    pub fn has_tcp_data(&self, bytes:&[u8])->bool {
        if self.key.protocol!=6 || self.syn || self.rst || self.fin || !self.ack {return false;}
        let ip=usize::from(bytes.first().copied().unwrap_or_default()&15)*4;
        bytes.get(ip+12).is_some_and(|header|ip+usize::from(header>>4)*4<bytes.len())
    }
    pub fn is_finish(&self) -> bool { self.key.protocol == 6 && self.fin }
    pub fn is_reset(&self) -> bool {
        self.key.protocol == 6 && self.rst
    }
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 || bytes[0] >> 4 != 4 {
            return None;
        }
        let h = usize::from(bytes[0] & 15) * 4;
        let n = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if h < 20
            || h > bytes.len()
            || n != bytes.len()
            || u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0
        {
            return None;
        }
        let mut sum = bytes[..h]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u32::from(u16::from_be_bytes([p[0], p[1]])))
            .sum::<u32>();
        while sum >> 16 != 0 {
            sum = (sum & 65535) + (sum >> 16);
        }
        if sum != 65535 {
            return None;
        }
        let mut packet = Self {
            key: Key {
                src: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
                dst: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
                protocol: bytes[9],
                sport: 0,
                dport: 0,
                icmp: 0,
            },
            syn: false,
            ack: false,
            rst: false,
            fin: false,
            icmp_type: 0,
            tcp_sequence: 0,
        };
        match bytes[9] {
            6 => {
                if n - h < 20 {
                    return None;
                }
                let header = usize::from(bytes[h + 12] >> 4) * 4;
                if header < 20 || header > n - h {
                    return None;
                }
                packet.tcp_sequence = u32::from_be_bytes(bytes[h + 4..h + 8].try_into().ok()?);
                packet.syn = bytes[h + 13] & 2 != 0;
                packet.ack = bytes[h + 13] & 16 != 0;
                packet.rst = bytes[h + 13] & 4 != 0;
                packet.fin = bytes[h + 13] & 1 != 0;
            }
            17 => {
                if n - h < 8
                    || usize::from(u16::from_be_bytes([bytes[h + 4], bytes[h + 5]])) != n - h
                {
                    return None;
                }
            }
            1 => {
                if n - h < 8 || ![0, 8].contains(&bytes[h]) {
                    return None;
                }
                packet.icmp_type = bytes[h];
                packet.key.icmp = u16::from_be_bytes([bytes[h + 4], bytes[h + 5]]);
            }
            _ => return None,
        }
        if bytes[9] != 1 {
            packet.key.sport = u16::from_be_bytes([bytes[h], bytes[h + 1]]);
            packet.key.dport = u16::from_be_bytes([bytes[h + 2], bytes[h + 3]]);
            if packet.key.sport == 0 || packet.key.dport == 0 {
                return None;
            }
        }
        Some(packet)
    }
}
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct FlowId(Key);
impl FlowId {
    /// Opaque direction-independent picker correlation, not authorization.
    pub fn selection_tag(&self)->String {
        use sha2::{Digest,Sha256};
        let key=self.0;let mut hash=Sha256::new();hash.update(key.src.octets());hash.update(key.dst.octets());hash.update([key.protocol]);
        hash.update(key.sport.to_be_bytes());hash.update(key.dport.to_be_bytes());hash.update(key.icmp.to_be_bytes());format!("{:x}",hash.finalize())
    }
}
impl Packet {
    pub fn flow_id(&self) -> FlowId {
        let key = self.key;
        let reverse = Key {
            src: key.dst,
            dst: key.src,
            sport: key.dport,
            dport: key.sport,
            ..key
        };
        FlowId(key.min(reverse))
    }
    pub fn flow_ttl(&self) -> Duration {
        if self.key.protocol == 6 && self.ack && !self.syn { TCP_ESTABLISHED_TTL } else { ttl(self.key.protocol) }
    }
}
struct Flow {
    remote: String,
    expires: Instant,
    opening: Packet,
    phase: u8,
    raw_path: u8,
    resumed: Option<std::sync::Arc<TcpResume>>,
    fin_directions: u8,
    close_until: Option<Instant>,
    _permit:Option<tokio::sync::OwnedSemaphorePermit>,
}
#[derive(Clone)]
struct FlowBudget(std::sync::Arc<tokio::sync::Semaphore>);
impl Default for FlowBudget {fn default()->Self{Self(std::sync::Arc::new(tokio::sync::Semaphore::new(65536)))}}
#[derive(Default)]
pub struct Engine {
    snapshot: Option<Snapshot>,
    ips: HashMap<String, Ipv4Addr>,
    flows: HashMap<Key, Flow>,
    exit_flows: HashMap<Key, Flow>,
    deadline: Option<Instant>,
    pairs: HashMap<String, Box<Engine>>,
    compiled_pair: Option<pair_acl::CompiledPairAcl>,
    flow_budget:FlowBudget,
    exit_flow_budget:FlowBudget,
    expired_tcp: Option<Box<TcpContinuity>>,
    has_resumed_tcp: bool,
    pair_private_epoch:Option<String>,
    pair_exit_epoch:Option<String>,
}
impl Engine {
    pub fn revoke(&mut self) {
        self.deadline = None;
        self.compiled_pair=None;
        self.pairs.clear();
        self.flows.clear();
        self.exit_flows.clear();
    }
    pub fn apply(&mut self, mut snapshot: Snapshot) -> Result<()> {
        let result = (|| {
            self.validate_sparse_base(&snapshot)?;
            let retain_pairs = self.same_sparse_authority(&snapshot);
            let compiled_pair=if let Some(acl)=&snapshot.pair_acl{
                ensure!(snapshot.sparse.is_none()&&snapshot.peers.len()==2&&snapshot.grants.is_empty(),"compact ACL is not a complete exact pair");
                Some(acl.compile()?)
            }else{None};
            let remaining = snapshot
                .expires_at
                .signed_duration_since(crate::local_wall_time())
                .to_std().map_err(|_| anyhow::anyhow!("private policy lease expired; check host clock synchronization and gateway connectivity"))?;
            ensure!(
                !remaining.is_zero()
                    && remaining <= Duration::from_secs(60)
                    && snapshot.revision > 0,
                "invalid private policy lease"
            );
            if let Some(old) = &self.snapshot {
                ensure!(
                    snapshot.workspace == old.workspace
                        && snapshot.self_ == old.self_
                        && snapshot.revision >= old.revision,
                    "private identity or policy revision changed"
                );
            }
            ensure!(
                snapshot.peers.len() <= MAX_SNAPSHOT_PEERS && snapshot.grants.len() <= 65536,
                "private policy exceeds size limit"
            );
            let mut ips = HashMap::new();
            let mut addresses = HashSet::new();
            for peer in &snapshot.peers {
                ensure!(
                    peer.ip.is_private()
                        && !peer.id.is_empty()
                        && addresses.insert(peer.ip)
                        && ips.insert(peer.id.clone(), peer.ip).is_none(),
                    "invalid private peer address binding"
                );
            }
            ensure!(
                ips.contains_key(&snapshot.self_),
                "private policy omits local identity"
            );
            // Validate independently of the API: dynamic group membership can
            // change between editing a route and publishing a policy lease.
            ensure!(snapshot.exit_routes.len() <= 256, "too many exit routes");
            let mut route_ids = HashSet::new();
            let mut exit_clients = HashSet::new();
            let mut routing_peers = HashSet::new();
            for route in &snapshot.exit_routes {
                ensure!(
                    !route.id.is_empty() && route_ids.insert(&route.id)
                        && (!route.routing_peers.is_empty() || route.tor_enabled) && !route.clients.is_empty()
                        && (route.traffic_mode.internet() || (!route.routing_peers.is_empty() && !route.tor_enabled))
                        && (1..=16).contains(&route.tor_circuit_groups)
                        && route.routing_peers.len() <= MAX_SNAPSHOT_PEERS && route.clients.len() <= MAX_SNAPSHOT_PEERS,
                    "invalid exit route"
                );
                let mut unique_peers = HashSet::new();
                for peer in &route.routing_peers {
                    ensure!(ips.contains_key(peer) && unique_peers.insert(peer), "invalid exit peer");
                    routing_peers.insert(peer);
                }
                for client in &route.clients {
                    ensure!(ips.contains_key(client) && exit_clients.insert(client), "ambiguous exit assignment");
                }
            }
            ensure!(routing_peers.is_disjoint(&exit_clients), "recursive exit routing is not supported");
            for grant in &snapshot.grants {
                ensure!(
                    ips.contains_key(&grant.source)
                        && ips.contains_key(&grant.destination)
                        && ["tcp", "udp", "icmp", "any"].contains(&grant.protocol.as_str()),
                    "invalid private grant"
                );
                ensure!(
                    grant.ports.is_empty() || ["tcp", "udp"].contains(&grant.protocol.as_str()),
                    "invalid private port restrictions"
                );
                ensure!(
                    grant.ports.iter().all(|p| p.start > 0 && p.end >= p.start),
                    "invalid private port range"
                );
            }
            if let Some(old) = &self.snapshot {
                let current: HashMap<_, _> = snapshot
                    .peers
                    .iter()
                    .map(|peer| (peer.id.as_str(), peer))
                    .collect();
                let mut changed = HashSet::new();
                for peer in &old.peers {
                    let next = current.get(peer.id.as_str());
                    if next.is_none_or(|next| {
                        next.ip != peer.ip
                            || next.instance != peer.instance
                            || next.fingerprint != peer.fingerprint
                    }) {
                        changed.insert(peer.ip);
                        if let Some(next) = next {
                            changed.insert(next.ip);
                        }
                    }
                }
                self.exit_flows.retain(|key, flow| {
                    !changed.contains(&key.src) && !changed.contains(&key.dst)
                        && self.ips.get(&flow.remote).is_none_or(|ip| !changed.contains(ip))
                });
                self.flows
                    .retain(|key, _| !changed.contains(&key.src) && !changed.contains(&key.dst));
            }
            snapshot.peers.shrink_to_fit();
            self.ips = ips;
            self.compiled_pair=compiled_pair;
            self.reconcile_pair_generations(&snapshot,retain_pairs);
            self.snapshot = Some(snapshot);
            self.deadline = Some(Instant::now() + remaining);
            let old = std::mem::take(&mut self.flows);
            let now = Instant::now();
            self.flows = old
                .into_iter()
                .filter(|(_, f)| f.expires > now && self.allowed(f.opening))
                .collect();
            let old_exits = std::mem::take(&mut self.exit_flows);
            self.exit_flows = old_exits.into_iter().filter(|(_, flow)| {
                flow.expires > now && self.exit_permitted(flow.opening, &flow.remote).is_some()
            }).collect();
            Ok(())
        })();
        if result.is_err() {
            self.revoke();
        }
        result
    }
    pub fn lease_deadline(&self) -> Option<Instant> { self.deadline }
    pub fn valid_lease(&self) -> bool {
        self.deadline.is_some_and(|deadline| deadline > Instant::now())
    }
    fn allowed(&self, packet: Packet) -> bool {
        let Some(snapshot) = &self.snapshot else {
            return false;
        };
        let protocol = match packet.key.protocol {
            6 => "tcp",
            17 => "udp",
            1 => "icmp",
            _ => return false,
        };
        if let Some(compiled)=&self.compiled_pair {
            let local=self.ips[&snapshot.self_];
            let Some(remote)=snapshot.peers.iter().find(|p|p.id!=snapshot.self_).map(|p|p.ip) else{return false;};
            let reverse=if packet.key.src==local&&packet.key.dst==remote{false}else if packet.key.src==remote&&packet.key.dst==local{true}else{return false;};
            return compiled.allows(reverse,packet.key.protocol,packet.key.dport);
        }
        snapshot.grants.iter().any(|g| {
            self.ips[&g.source] == packet.key.src
                && self.ips[&g.destination] == packet.key.dst
                && (g.protocol == "any" || g.protocol == protocol)
                && (g.ports.is_empty()
                    || g.ports
                        .iter()
                        .any(|p| p.start <= packet.key.dport && packet.key.dport <= p.end))
        })
    }
    /// A local event that arrived before this exact connection was revalidated
    /// cannot become deliverable by sitting in a queue until the new grant.
    pub fn check_received(&mut self,bytes:&[u8],peer:&str,arrival:Instant)->bool {
        if self.expired_tcp.is_some() {
            if let Some((p,packet))=self.pairs.get(peer).filter(|p|p.has_resumed_tcp).and_then(|p|Some((p,Packet::parse(bytes)?))) {
                let k=packet.key;
                let reverse=Key{src:k.dst,dst:k.src,sport:k.dport,dport:k.sport,..k};
                if [k,reverse].iter().any(|k|p.flows.get(k).and_then(|f|f.resumed.as_ref()).is_some_and(|r|arrival<r.at)){return false;}
            }
        }
        self.check(bytes,peer,true)
    }
    pub fn check(&mut self, bytes: &[u8], remote: &str, inbound: bool) -> bool {
        if self.snapshot.as_ref().is_some_and(|s| s.sparse.is_some()) {
            if !self.valid_lease() { self.pairs.clear(); return false; }
            if let Some(pair) = self.pairs.get_mut(remote) { return pair.check(bytes, remote, inbound); }
        }
        let Some(packet) = Packet::parse(bytes) else {
            return false;
        };
        let now = Instant::now();
        if self.deadline.is_none_or(|d| d <= now) {
            self.flows.clear();
            return false;
        }
        let Some(snapshot) = &self.snapshot else {
            return false;
        };
        let (source, destination) = if inbound {
            (remote, snapshot.self_.as_str())
        } else {
            (snapshot.self_.as_str(), remote)
        };
        if self.ips.get(source) != Some(&packet.key.src)
            || self.ips.get(destination) != Some(&packet.key.dst)
        {
            return false;
        }
        let may_open = self.allowed(packet);
        track_packet_budget(&mut self.flows, packet, "", may_open, now,Some(&self.flow_budget))
    }

    /// Tell the local TCP stack to reopen a connection whose handshake state
    /// disappeared. Only the TUN's outbound read path may request this reply.
    #[cfg(feature = "private-stream")]
    pub fn closed_local_tcp_reply(&self, bytes: &[u8], peer: &str) -> Option<bytes::Bytes> {
        let packet = Packet::parse(bytes)?;
        if packet.key.protocol != 6 || !packet.ack || packet.syn || packet.rst || !self.valid_lease() {
            return None;
        }
        let engine = if self.snapshot.as_ref()?.sparse.is_some() {
            self.pairs.get(peer)?.as_ref()
        } else {
            self
        };
        let snapshot = engine.snapshot.as_ref()?;
        let key = packet.key;
        if !engine.valid_lease()
            || peer == snapshot.self_
            || engine.ips.get(&snapshot.self_) != Some(&key.src)
            || engine.ips.get(peer) != Some(&key.dst)
            || !engine.allowed(packet)
        {
            return None;
        }
        let reverse = Key { src: key.dst, dst: key.src, sport: key.dport, dport: key.sport, ..key };
        if engine.flows.contains_key(&key) || engine.flows.contains_key(&reverse) {
            return None;
        }
        crate::tcp_stream::reject_local_ack(bytes).ok()
    }

    // A separate state table prevents exit grants from widening private ACLs.
    // The authenticated transport identity is bound to every tracked flow.
    pub fn check_exit(&mut self, bytes: &[u8], remote: &str, inbound: bool) -> bool {
        if !self.valid_lease() { self.exit_flows.clear(); return false; }
        let Some(packet)=Packet::parse(bytes) else{return false};
        // Sparse exit permissions are exact, independently expiring pair leases.
        // Local Tor remains governed by its explicit base policy path.
        if self.snapshot.as_ref().is_some_and(|snapshot|snapshot.sparse.is_some()
            && !snapshot.peers.iter().any(|peer|peer.id==remote)) {
            self.prune_pairs();
            let Some(pair)=self.pairs.get_mut(remote) else{return false};
            let Some((request,_))=pair.exit_permitted(packet,remote) else{return false};
            let target=if request{packet.destination()}else{packet.source()};
            // A bounded pair cannot enumerate every overlay identity. The complete
            // capture prefixes replace that legacy inventory check, never ACLs.
            if self.snapshot.as_ref().and_then(|s|s.sparse.as_ref()).is_some_and(|s|
                s.capture_pools.iter().any(|pool|pool.contains(target))) {return false;}
            return pair.check_exit_local(packet,remote,inbound);
        }
        self.check_exit_local(packet,remote,inbound)
    }
    fn check_exit_local(&mut self,packet:Packet,remote:&str,inbound:bool)->bool {
        let now=Instant::now();
        if self.deadline.is_none_or(|deadline|deadline<=now){self.exit_flows.clear();return false;}
        // No placeholder/process-unbound identity can start or retain an exit flow.
        if !self.snapshot.as_ref().is_some_and(|snapshot|snapshot.peers.iter().any(|peer|
            peer.id==remote&&!peer.fingerprint.is_empty()&&!peer.instance.is_empty())) {return false;}
        let Some((request,local_is_client))=self.exit_permitted(packet,remote) else{return false};
        if request!=(inbound!=local_is_client){return false;}
        track_packet_budget(&mut self.exit_flows,packet,remote,request,now,Some(&self.exit_flow_budget))
    }

    fn exit_permitted(&self, packet: Packet, remote: &str) -> Option<(bool, bool)> {
        let snapshot = self.snapshot.as_ref()?;
        for route in &snapshot.exit_routes {
            let local_is_client = route.clients.contains(&snapshot.self_)
                && route.routing_peers.iter().any(|id| id == remote);
            let local_is_exit = route.routing_peers.contains(&snapshot.self_)
                && route.clients.iter().any(|id| id == remote);
            if !local_is_client && !local_is_exit { continue; }
            let client = if local_is_client { &snapshot.self_ } else { remote };
            let client_ip = self.ips.get(client)?;
            let request = packet.source() == *client_ip;
            let target = if request { packet.destination() } else {
                if packet.destination() != *client_ip { return None; }
                packet.source()
            };
            // Never make overlay peers, loopback or host metadata reachable by
            // granting internet access. LAN access is separately opt-in.
            if self.ips.values().any(|ip| *ip == target)
                || !route.traffic_mode.permits(target)
                || !exit_target(target, false) {
                return None;
            }
            return Some((request, local_is_client));
        }
        None
    }
}

fn exit_target(ip: Ipv4Addr, block_lan: bool) -> bool {
    let [a, b, _, _] = ip.octets();
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_link_local()
        && !ip.is_multicast() && !ip.is_broadcast() && a != 0 && a < 240
        && !(a == 100 && (64..=127).contains(&b))
        && !(block_lan && ip.is_private())
}

fn track_packet(flows: &mut HashMap<Key, Flow>, packet: Packet, remote: &str, may_open: bool, now: Instant) -> bool {
    track_packet_budget(flows,packet,remote,may_open,now,None)
}
fn track_packet_budget(flows: &mut HashMap<Key, Flow>, packet: Packet, remote: &str, may_open: bool, now: Instant,budget:Option<&FlowBudget>) -> bool {
        let key = packet.key;
        let reverse = Key {
            src: key.dst,
            dst: key.src,
            sport: key.dport,
            dport: key.sport,
            ..key
        };
        for candidate in [key, reverse] {
            if flows.get(&candidate).is_some_and(|f| f.expires <= now) {
                flows.remove(&candidate);
            }
            if may_open && candidate == key && packet.opening_sequence().is_some()
                && flows.get(&candidate).is_some_and(|flow| flow.opening.opening_sequence() != packet.opening_sequence() || flow.close_until.is_some()) {
                flows.remove(&candidate);
            }
            if let Some(flow) = flows.get_mut(&candidate) {
                if flow.remote != remote { return false; }
                let reply = candidate != key;
                if key.protocol == 1
                    && ((reply && packet.icmp_type != 0) || (!reply && packet.icmp_type != 8))
                {
                    return false;
                }
                if key.protocol == 6 {
                    if packet.fin || packet.rst {if let Some(r)=&flow.resumed {r.retire();}}
                    if packet.rst {
                        flows.remove(&candidate);
                        return true;
                    }
                    if reply && packet.syn && !packet.ack {
                        break;
                    }
                    if flow.phase == 0 {
                        if reply {
                            if !packet.syn || !packet.ack {
                                return false;
                            }
                            flow.phase = 1;
                        } else if !packet.syn || packet.ack {
                            return false;
                        }
                    } else if flow.phase == 1 {
                        if !reply && packet.ack && !packet.syn {
                            flow.phase = 2;
                        } else if !(reply && packet.syn && packet.ack) {
                            return false;
                        }
                    }
                }
                if key.protocol == 6 && packet.fin {
                    flow.fin_directions |= if reply { 2 } else { 1 };
                    if flow.fin_directions == 3 { flow.close_until.get_or_insert(now + Duration::from_secs(120)); }
                }
                flow.expires = now + if key.protocol == 6 && flow.phase == 2 { TCP_ESTABLISHED_TTL } else { ttl(key.protocol) };
                if let Some(until) = flow.close_until { flow.expires = flow.expires.min(until); }
                return true;
            }
        }
        if !may_open
            || (key.protocol == 6 && (!packet.syn || packet.ack || packet.rst || packet.fin))
            || (key.protocol == 1 && packet.icmp_type != 8)
        {
            return false;
        }
        if flows.len() >= 65536 {
            flows.retain(|_, f| f.expires > now);
            if flows.len() >= 65536 {
                return false;
            }
        }
        let permit=if let Some(budget)=budget{match budget.0.clone().try_acquire_owned(){Ok(permit)=>Some(permit),Err(_)=>return false}}else{None};
        flows.insert(
            key,
            Flow {
                _permit:permit,
                remote: remote.to_owned(),
                expires: now + ttl(key.protocol),
                opening: packet,
                phase: 0,
                raw_path: 0,
                resumed: None,
                fin_directions: 0,
                close_until: None,
            },
        );
        true
}

// Match the usual Linux conntrack established TCP idle lifetime. Policy
// leases and identity revocation still apply independently of this timeout.
const TCP_ESTABLISHED_TTL: Duration = Duration::from_secs(5 * 24 * 60 * 60);

fn ttl(protocol: u8) -> Duration {
    Duration::from_secs(if protocol == 6 { 300 } else { 30 })
}

#[cfg(test)]
mod lifetime_tests {
    use super::*;

    #[test]
    fn closed_tcp_expires_without_shortening_half_closed_streams() {
        let start = Instant::now();
        let syn = Packet {
            key: Key { src: Ipv4Addr::new(10, 203, 0, 1), dst: Ipv4Addr::new(203, 0, 113, 1), protocol: 6, sport: 4000, dport: 443, icmp: 0 },
            syn: true, ack: false, rst: false, fin: false, icmp_type: 0, tcp_sequence: 1,
        };
        let reply = Packet { key: Key { src: syn.key.dst, dst: syn.key.src, sport: syn.key.dport, dport: syn.key.sport, ..syn.key }, ack: true, ..syn };
        let ack = Packet { syn: false, ack: true, ..syn };
        let mut flows = HashMap::new();
        assert!(track_packet(&mut flows, syn, "exit", true, start));
        assert!(track_packet(&mut flows, reply, "exit", false, start));
        assert!(track_packet(&mut flows, ack, "exit", true, start));
        assert!(track_packet(&mut flows, Packet { fin: true, ..ack }, "exit", true, start));
        let later = start + Duration::from_secs(3600);
        assert!(track_packet(&mut flows, Packet { syn: false, ..reply }, "exit", false, later));
        assert!(flows[&syn.key].close_until.is_none());
        assert!(track_packet(&mut flows, Packet { syn: false, fin: true, ..reply }, "exit", false, later));
        assert!(track_packet(&mut flows, ack, "exit", true, later + Duration::from_secs(60)));
        assert_eq!(flows[&syn.key].expires, later + Duration::from_secs(120));
        assert!(!track_packet(&mut flows, ack, "exit", true, later + Duration::from_secs(121)));
        assert!(flows.is_empty());
    }

    #[test]
    fn reused_tuple_requires_authorized_opening_before_changing_exit() {
        let now = Instant::now();
        let syn = Packet {
            key: Key { src: Ipv4Addr::new(10, 203, 0, 1), dst: Ipv4Addr::new(203, 0, 113, 1), protocol: 6, sport: 4000, dport: 443, icmp: 0 },
            syn: true, ack: false, rst: false, fin: false, icmp_type: 0, tcp_sequence: 1,
        };
        let mut flows = HashMap::new();
        assert!(track_packet(&mut flows, syn, "exit-a", true, now));
        assert!(!track_packet(&mut flows, syn, "exit-b", true, now));
        let fresh = Packet { tcp_sequence: 2, ..syn };
        assert!(!track_packet(&mut flows, fresh, "exit-b", false, now));
        assert_eq!(flows[&syn.key].remote, "exit-a");
        assert!(track_packet(&mut flows, fresh, "exit-b", true, now));
        assert_eq!(flows[&syn.key].remote, "exit-b");
        assert_eq!(flows[&syn.key].phase, 0);
    }

    #[test]
    fn quiet_established_tcp_survives_but_unfinished_handshakes_expire() {
        let start = Instant::now();
        let syn = Packet {
            key: Key { src: Ipv4Addr::new(10, 203, 0, 1), dst: Ipv4Addr::new(203, 0, 113, 1), protocol: 6, sport: 4000, dport: 443, icmp: 0 },
            syn: true, ack: false, rst: false, fin: false, icmp_type: 0, tcp_sequence: 1,
        };
        let reply = Packet { key: Key { src: syn.key.dst, dst: syn.key.src, sport: syn.key.dport, dport: syn.key.sport, ..syn.key }, ack: true, ..syn };
        let ack = Packet { syn: false, ack: true, ..syn };
        let mut flows = HashMap::new();
        assert!(track_packet(&mut flows, syn, "exit", true, start));
        assert!(track_packet(&mut flows, reply, "exit", false, start));
        assert!(track_packet(&mut flows, ack, "exit", true, start));
        let later = start + Duration::from_secs(3600);
        assert!(track_packet(&mut flows, ack, "exit", true, later));
        assert!(!track_packet(&mut flows, ack, "another-exit", true, later));
        assert_eq!(ack.flow_ttl(), TCP_ESTABLISHED_TTL);
        let mut incomplete = HashMap::new();
        assert!(track_packet(&mut incomplete, syn, "exit", true, start));
        assert!(!track_packet(&mut incomplete, reply, "exit", false, later));
        assert!(!track_packet(&mut flows, ack, "exit", true, later + TCP_ESTABLISHED_TTL));
    }
}

#[cfg(test)]
mod legacy_capacity_contract_tests {
    use super::*;
    #[test]
    fn full_4096_peer_snapshot_remains_valid_and_4097_is_not_truncated() {
        let peers:Vec<_>=(0..MAX_SNAPSHOT_PEERS).map(|i|serde_json::json!({
            "id":format!("p{i}"),"ip":Ipv4Addr::from(0x0a4d0001+i as u32),
            "fingerprint":format!("fingerprint-{i}"),"instance":format!("instance-{i}"),"hostname":format!("p{i}.phub")
        })).collect();
        let mut snapshot:Snapshot=serde_json::from_value(serde_json::json!({"workspace":"w","self":"p0","revision":1,"expires_at":Utc::now()+chrono::Duration::seconds(30),"peers":peers,"grants":[]})).unwrap();
        let mut engine=Engine::default();engine.apply(snapshot.clone()).unwrap();assert!(engine.valid_lease());
        let mut extra=snapshot.peers[0].clone();extra.id="overflow".into();extra.ip="10.78.0.1".parse().unwrap();snapshot.peers.push(extra);snapshot.revision=2;
        assert!(engine.apply(snapshot).is_err());assert!(!engine.valid_lease());
    }
}
