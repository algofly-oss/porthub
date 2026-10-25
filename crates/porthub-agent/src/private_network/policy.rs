//! Lease-bound IPv4 ACLs and reply tracking. A packet's addresses must match
//! its authenticated remote peer; no LAN/default-gateway forwarding is allowed.
use anyhow::{ensure, Result};
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
    #[serde(default)]
    pub stream_transport: String,
    pub hostname: String,
    #[serde(default)]
    pub aliases: Vec<String>,
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
pub struct Snapshot {
    pub workspace: String,
    #[serde(rename = "self")]
    pub self_: String,
    pub revision: u64,
    pub expires_at: DateTime<Utc>,
    pub peers: Vec<PeerInfo>,
    #[serde(default)]
    pub dns_suffixes: Vec<String>,
    pub grants: Vec<Grant>,
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
}
impl Packet {
    pub fn source(&self) -> Ipv4Addr {
        self.key.src
    }
    pub fn destination(&self) -> Ipv4Addr {
        self.key.dst
    }
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
        ttl(self.key.protocol)
    }
}
struct Flow {
    expires: Instant,
    opening: Packet,
    phase: u8,
}
#[derive(Default)]
pub struct Engine {
    snapshot: Option<Snapshot>,
    ips: HashMap<String, Ipv4Addr>,
    flows: HashMap<Key, Flow>,
    deadline: Option<Instant>,
}
impl Engine {
    pub fn revoke(&mut self) {
        self.deadline = None;
        self.flows.clear();
    }
    pub fn apply(&mut self, mut snapshot: Snapshot) -> Result<()> {
        let result = (|| {
            let remaining = snapshot
                .expires_at
                .signed_duration_since(Utc::now())
                .to_std()?;
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
                snapshot.peers.len() <= 4096 && snapshot.grants.len() <= 65536,
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
                self.flows
                    .retain(|key, _| !changed.contains(&key.src) && !changed.contains(&key.dst));
            }
            snapshot.peers.shrink_to_fit();
            self.ips = ips;
            self.snapshot = Some(snapshot);
            self.deadline = Some(Instant::now() + remaining);
            let old = std::mem::take(&mut self.flows);
            let now = Instant::now();
            self.flows = old
                .into_iter()
                .filter(|(_, f)| f.expires > now && self.allowed(f.opening))
                .collect();
            Ok(())
        })();
        if result.is_err() {
            self.revoke();
        }
        result
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
    pub fn check(&mut self, bytes: &[u8], remote: &str, inbound: bool) -> bool {
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
        let key = packet.key;
        let reverse = Key {
            src: key.dst,
            dst: key.src,
            sport: key.dport,
            dport: key.sport,
            ..key
        };
        for candidate in [key, reverse] {
            if self.flows.get(&candidate).is_some_and(|f| f.expires <= now) {
                self.flows.remove(&candidate);
            }
            if let Some(flow) = self.flows.get_mut(&candidate) {
                let reply = candidate != key;
                if key.protocol == 1
                    && ((reply && packet.icmp_type != 0) || (!reply && packet.icmp_type != 8))
                {
                    return false;
                }
                if key.protocol == 6 {
                    if packet.rst {
                        self.flows.remove(&candidate);
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
                flow.expires = now + ttl(key.protocol);
                return true;
            }
        }
        if !self.allowed(packet)
            || (key.protocol == 6 && (!packet.syn || packet.ack || packet.rst || packet.fin))
            || (key.protocol == 1 && packet.icmp_type != 8)
        {
            return false;
        }
        if self.flows.len() >= 65536 {
            self.flows.retain(|_, f| f.expires > now);
            if self.flows.len() >= 65536 {
                return false;
            }
        }
        self.flows.insert(
            key,
            Flow {
                expires: now + ttl(key.protocol),
                opening: packet,
                phase: 0,
            },
        );
        true
    }
}
fn ttl(protocol: u8) -> Duration {
    Duration::from_secs(if protocol == 6 { 300 } else { 30 })
}
