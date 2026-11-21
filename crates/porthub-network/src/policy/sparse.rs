//! Negotiated pair ACLs: independent short leases, never a partially truncated snapshot.
use super::*;

pub const MAX_PAIR_LEASES: usize = 256;
pub const MAX_PRIVATE_SUFFIXES: usize = 256;
pub const MAX_PRIVATE_SUFFIX_BYTES: usize = 32768;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
pub struct Lookup {
    pub kind: String,
    pub value: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairResponse {
    pub query: Lookup,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<PairLease>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SparseInfo {
    pub protocol: u32,
    /// Stable authorization generation, distinct from the per-sync revision counter.
    pub epoch: String,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub exit_epoch: Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub selection_epoch:Option<String>,
    #[serde(default,skip_serializing_if="Vec::is_empty")]
    pub exit_intents:Vec<ExitIntent>,
    #[serde(default)]
    pub capture_pools: Vec<porthub_mesh::lan_routes::Network>,
}

/// Owned plumbing/discovery intent only. Remote packets still require ExitPair.
#[derive(Clone,Copy,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="snake_case")]
pub enum ExitRole {Client,Router}
#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ExitIntent {
    pub id:String,pub name:String,pub role:ExitRole,
    pub selection:porthub_mesh::exit_policy::Selection,
    pub traffic_mode:porthub_mesh::exit_policy::TrafficMode,
    pub allow_direct_fallback:bool,pub tor_enabled:bool,pub tor_circuit_groups:usize,
    #[serde(default,skip_serializing_if="Vec::is_empty")]
    pub lan_networks:Vec<porthub_mesh::lan_routes::Network>,
    #[serde(default="yes")] pub masquerade:bool,
    #[serde(default="yes")] pub block_lan_access:bool,
}
/// Separately negotiated exact exit authority. It never grants ordinary private
/// ports, chooses an exit, or enables local Tor/direct fallback by itself.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExitPair {
    pub epoch: String,
    pub route_id: String,
    pub client: String,
    pub router: String,
    pub traffic_mode: porthub_mesh::exit_policy::TrafficMode,
}
impl ExitPair {
    fn route(&self,local:&str,remote:&str)->Result<ExitRoute> {
        ensure!(!self.route_id.is_empty()&&self.route_id.len()<=60
            && ((self.client==local&&self.router==remote)||(self.client==remote&&self.router==local))
            && local!=remote,"exit pair authority includes another identity");
        Ok(ExitRoute { id:self.route_id.clone(),name:self.route_id.clone(),routing_peers:vec![self.router.clone()],clients:vec![self.client.clone()],
            tor_enabled:false,tor_circuit_groups:4,selection:Default::default(),traffic_mode:self.traffic_mode,
            allow_direct_fallback:false,masquerade:true,block_lan_access:self.traffic_mode==porthub_mesh::exit_policy::TrafficMode::InternetOnly })
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairLease {
    pub workspace: String,
    #[serde(rename = "self")]
    pub self_: String,
    pub epoch: String,
    pub expires_at: DateTime<Utc>,
    /// Monotonic remote identity publication revision, rejecting reordered old process bindings.
    pub revision: u64,
    pub local: PeerInfo,
    pub peer: PeerInfo,
    pub grants: Vec<Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<ExitPair>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl: Option<super::pair_acl::PairAcl>,
}

fn same_identity(a: &PeerInfo, b: &PeerInfo) -> bool {
    a.id == b.id && a.ip == b.ip && a.fingerprint == b.fingerprint && a.instance == b.instance
}

impl Engine {
    pub(super) fn validate_sparse_base(&self, snapshot: &Snapshot) -> Result<()> {
        if let Some(sparse) = &snapshot.sparse {
            ensure!(
                sparse.protocol == 1
                    && sparse.epoch.len() == 64
                    && sparse
                        .epoch
                        .bytes()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "unsupported sparse private authority"
            );
            ensure!(sparse.exit_intents.len()<=256&&(sparse.exit_intents.is_empty()||(sparse.exit_epoch.is_some()&&sparse.selection_epoch.is_some())),"exit intent negotiation/bounds invalid");
            let mut intent_ids=std::collections::HashSet::new();let mut clients=0;let mut routers=0;
            for intent in &sparse.exit_intents {
                ensure!(!intent.id.is_empty()&&intent.id.len()<=60&&intent.name.len()<=256&&intent_ids.insert(&intent.id)
                    &&intent.lan_networks.len()<=32
                    &&(1..=16).contains(&intent.tor_circuit_groups)
                    &&(!intent.tor_enabled||(intent.role==ExitRole::Client&&intent.traffic_mode.internet())),"invalid exit intent");
                match intent.role{ExitRole::Client=>clients+=1,ExitRole::Router=>routers+=1}
            }
            ensure!(clients<=1&&(clients==0||routers==0),"ambiguous or recursive exit intent");
            ensure!(sparse.selection_epoch.as_ref().is_none_or(|epoch|epoch.len()==64&&epoch.bytes().all(|c|c.is_ascii_hexdigit()&&!c.is_ascii_uppercase())),"invalid exit selection generation");
            ensure!(sparse.exit_epoch.as_ref().is_none_or(|epoch|epoch.len()==64
                && epoch.bytes().all(|c|c.is_ascii_hexdigit()&&!c.is_ascii_uppercase())),"invalid exit pair generation");
            ensure!(
                snapshot.dns_suffixes.len() <= MAX_PRIVATE_SUFFIXES
                    && snapshot.dns_suffixes.iter().map(String::len).sum::<usize>()
                        <= MAX_PRIVATE_SUFFIX_BYTES
                    && snapshot.dns_suffixes.iter().all(|s| !s.is_empty()
                        && s.len() <= 253
                        && s.split('.').all(|label| !label.is_empty()
                            && label.len() <= 63
                            && !label.starts_with('-')
                            && !label.ends_with('-')
                            && label
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-'))),
                "sparse private namespace metadata exceeds bounds or is invalid"
            );
            ensure!(
                sparse.capture_pools.len() <= crate::capture_routes::MAX_CAPTURE_PREFIXES,
                "sparse capture prefixes exceed bounds"
            );
        }
        Ok(())
    }

    pub(super) fn same_sparse_authority(&self, next: &Snapshot) -> bool {
        let Some(old) = &self.snapshot else {
            return false;
        };
        old.sparse
            .as_ref()
            .zip(next.sparse.as_ref())
            .is_some_and(|(a, b)| a.protocol == b.protocol && a.epoch == b.epoch)
            && old.workspace == next.workspace
            && old.self_ == next.self_
            && old
                .peers
                .iter()
                .find(|p| p.id == old.self_)
                .zip(next.peers.iter().find(|p| p.id == next.self_))
                .is_some_and(|(a, b)| same_identity(a, b))
    }

    /// Install only after validating a complete response. A bad response cannot revoke unrelated leases.
    /// Refreshing the base authority never extends this peer's expiry or reverse-flow lifetime.
    /// Preserve independently authorized traffic without renewing any deadline.
    /// This mutates only cached permission projections, never a received lease.
    pub(super) fn reconcile_pair_generations(&mut self,next:&Snapshot,retain_private:bool) {
        let identity=self.snapshot.as_ref().is_some_and(|old|old.sparse.is_some()&&next.sparse.is_some()
            && old.workspace==next.workspace&&old.self_==next.self_
            && old.peers.iter().find(|p|p.id==old.self_).zip(next.peers.iter().find(|p|p.id==next.self_)).is_some_and(|(a,b)|same_identity(a,b)));
        if !identity {self.pairs.clear();return;}
        let sparse=next.sparse.as_ref().expect("checked sparse identity");
        self.pairs.retain(|_,pair|{
            let private=retain_private&&pair.pair_private_epoch.as_deref()==Some(sparse.epoch.as_str());
            let exit=sparse.exit_epoch.as_deref().is_some_and(|generation|pair.pair_exit_epoch.as_deref()==Some(generation));
            if !private {
                pair.flows.clear();pair.compiled_pair=None;pair.pair_private_epoch=None;
                if let Some(snapshot)=&mut pair.snapshot {snapshot.grants.clear();snapshot.pair_acl=None;}
            }
            if !exit {
                pair.exit_flows.clear();pair.pair_exit_epoch=None;
                if let Some(snapshot)=&mut pair.snapshot {snapshot.exit_routes.clear();}
            }
            private||exit
        });
    }
    pub fn install_pair(&mut self, lease: PairLease) -> Result<()> {
        ensure!(self.valid_lease(), "sparse base authority expired");
        self.prune_pairs();
        let base = self
            .snapshot
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing private authority"))?;
        let sparse = base
            .sparse
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("sparse private authority not negotiated"))?;
        ensure!(
            lease.workspace == base.workspace
                && lease.self_ == base.self_
                && lease.epoch == sparse.epoch,
            "pair lease authority changed"
        );
        let local = base
            .peers
            .iter()
            .find(|p| p.id == base.self_)
            .ok_or_else(|| anyhow::anyhow!("missing local identity"))?;
        ensure!(
            same_identity(&lease.local, local),
            "pair lease local identity changed"
        );
        ensure!(
            [&lease.local, &lease.peer]
                .into_iter()
                .all(|p| !p.id.is_empty()
                    && p.id.len() <= 60
                    && p.hostname.len() <= 254
                    && !p.fingerprint.is_empty()
                    && p.fingerprint.len() <= 95
                    && !p.instance.is_empty()
                    && p.instance.len() <= 64
                    && p.aliases.len() <= 64
                    && p.aliases.iter().all(|a| a.len() <= 254)
                    && p.lan_networks.len() <= 32),
            "pair identity metadata exceeds bounds"
        );
        ensure!(
            lease.peer.id != base.self_
                && !lease.peer.fingerprint.is_empty()
                && !lease.peer.instance.is_empty(),
            "pair lease has no authenticated remote identity"
        );
        ensure!(
            !base
                .peers
                .iter()
                .any(|p| p.ip == lease.peer.ip && p.id != lease.peer.id),
            "pair address collides with base identity"
        );
        ensure!(
            self.pairs.contains_key(&lease.peer.id) || self.pairs.len() < MAX_PAIR_LEASES,
            "private pair cache is full"
        );
        ensure!(
            !self.pairs.iter().any(
                |(id, p)| id != &lease.peer.id && p.ips.values().any(|ip| *ip == lease.peer.ip)
            ),
            "pair address collides with cached identity"
        );
        if let Some(exit)=&lease.exit {
            ensure!(sparse.exit_epoch.as_deref()==Some(exit.epoch.as_str()),"exit pair generation changed");
        }
        if lease.exit.as_ref().is_some_and(|exit|exit.traffic_mode.lan()) {
            ensure!(!sparse.capture_pools.is_empty()
                && [&lease.local,&lease.peer].iter().all(|peer|sparse.capture_pools.iter().any(|pool|pool.contains(peer.ip))),
                "LAN exit pair lacks complete overlay capture metadata");
        }
        let exit_routes=lease.exit.as_ref().map(|exit|exit.route(&lease.self_,&lease.peer.id)).transpose()?.into_iter().collect();
        if let Some(acl) = &lease.acl {
            ensure!(
                lease.grants.is_empty(),
                "compact and legacy pair ACL cannot be mixed"
            );
            acl.compile()?;
        } else {
            ensure!(
                lease.grants.len() <= 128
                    && (!lease.grants.is_empty() || lease.exit.is_some())
                    && lease.grants.iter().all(|g| g.ports.len() <= 64),
                "pair grant count exceeds bounds or is denied"
            );
            ensure!(
                lease.grants.iter().all(|g| (g.source == lease.self_
                    && g.destination == lease.peer.id)
                    || (g.destination == lease.self_ && g.source == lease.peer.id)),
                "pair grants include another identity"
            );
        }
        ensure!(lease.revision > 0, "pair revision missing");
        if let Some(existing) = self
            .pairs
            .get(&lease.peer.id)
            .and_then(|p| p.snapshot.as_ref())
        {
            ensure!(
                lease.revision >= existing.revision,
                "pair identity revision regressed"
            );
            if lease.revision == existing.revision {
                ensure!(
                    existing
                        .peers
                        .iter()
                        .find(|p| p.id == lease.peer.id)
                        .is_some_and(|old| same_identity(old, &lease.peer)),
                    "pair identity changed without a new revision"
                );
            }
        }
        let private_epoch=lease.epoch.clone();let exit_epoch=lease.exit.as_ref().map(|exit|exit.epoch.clone());
        let id = lease.peer.id.clone();
        let snapshot = Snapshot {
            sparse: None,
            workspace: lease.workspace,
            self_: lease.self_,
            revision: lease.revision,
            expires_at: lease.expires_at,
            peers: vec![lease.local, lease.peer],
            grants: lease.grants,
            pair_acl: lease.acl,
            dns_suffixes: vec![],
            exit_routes,
            dns_rules: vec![],
        };
        let mut engine = Box::<Engine>::default();
        engine.flow_budget = self.flow_budget.clone();
        engine.exit_flow_budget = self.exit_flow_budget.clone();
        engine.pair_private_epoch=Some(private_epoch.clone());engine.pair_exit_epoch=exit_epoch.clone();
        engine.apply(snapshot.clone())?;
        // The existing engine revalidates opening ACLs and retires flows on identity changes.
        // An unchanged lease renewal must preserve established TCP reverse-flow tracking.
        if let Some(existing) = self.pairs.get_mut(&id) {
            existing.apply(snapshot)?;
            existing.pair_private_epoch=Some(private_epoch);existing.pair_exit_epoch=exit_epoch;
        } else {
            self.pairs.insert(id, engine);
        }
        Ok(())
    }

    /// Called by the bounded runtime tick, not each packet. Established private
    /// flows retain on-demand renewal eligibility while independently expiring ACLs
    /// are still reauthorized by the gateway; no deadline is extended locally.
    pub fn active_pair_flows(&mut self) -> Vec<String> {
        self.prune_pairs();
        let now = Instant::now();
        let mut active = Vec::new();
        for (id, pair) in &mut self.pairs {
            pair.flows.retain(|_, flow| flow.expires > now);
            pair.exit_flows.retain(|_, flow| flow.expires > now);
            if !pair.flows.is_empty() || !pair.exit_flows.is_empty() {
                active.push(id.clone());
            }
        }
        active
    }

    pub fn revoke_pair(&mut self, id: &str) {
        self.pairs.remove(id);
    }
    pub fn prune_pairs(&mut self) {
        if let Some(pending)=&mut self.expired_tcp {pending.expire();}
        self.pairs.retain(|id,pair| {
            if pair.valid_lease(){return true;}
            if let Some(pending)=&mut self.expired_tcp {pending.capture(id,pair);}
            false
        });
    }
    pub fn pair_count(&self) -> usize {
        self.pairs.len()
    }
    pub fn pair_snapshots(&self) -> Vec<(Snapshot, Instant)> {
        if !self.valid_lease() {
            return Vec::new();
        }
        self.pairs
            .values()
            .filter(|p| p.valid_lease())
            .filter_map(|p| Some((p.snapshot.clone()?, p.deadline?)))
            .collect()
    }
    /// Private-stream view of already validated pair leases. Exit authority
    /// remains in the engine for the exit packet path and is never translated
    /// into private ports. Preserve the original identity, ACL and deadline.
    pub fn private_stream_pair_snapshots(&self) -> Vec<(Snapshot, Instant)> {
        if !self.valid_lease() { return Vec::new(); }
        let Some(epoch) = self.snapshot.as_ref().and_then(|s| s.sparse.as_ref()).map(|s| s.epoch.as_str()) else {
            return Vec::new();
        };
        self.pairs.values()
            .filter(|p| p.valid_lease() && p.pair_private_epoch.as_deref() == Some(epoch))
            .filter_map(|p| {
                let mut snapshot = p.snapshot.clone()?;
                snapshot.exit_routes.clear();
                Some((snapshot, p.deadline?))
            })
            .collect()
    }
    pub fn pair_peer(&self, id: &str) -> Option<&PeerInfo> {
        if !self.valid_lease() {
            return None;
        }
        self.pairs
            .get(id)
            .filter(|p| p.valid_lease())?
            .snapshot
            .as_ref()?
            .peers
            .iter()
            .find(|p| p.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer(id: &str, ip: &str) -> PeerInfo {
        serde_json::from_value(serde_json::json!({"id":id,"ip":ip,"fingerprint":format!("fingerprint-{id}"),"instance":format!("instance-{id}"),"hostname":format!("{id}.phub")})).unwrap()
    }
    fn base(epoch: &str) -> Snapshot {
        serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","revision":1,"expires_at":Utc::now()+chrono::Duration::seconds(30),"peers":[peer("a","10.203.0.2")],"grants":[],"sparse":{"protocol":1,"epoch":epoch}})).unwrap()
    }
    fn pair(epoch: &str) -> PairLease {
        PairLease {
            workspace: "w".into(),
            self_: "a".into(),
            epoch: epoch.into(),
            expires_at: Utc::now() + chrono::Duration::seconds(5),
            revision: 1,
            acl: None,
            exit: None,
            local: peer("a", "10.203.0.2"),
            peer: peer("b", "10.203.1.2"),
            grants: vec![Grant {
                source: "a".into(),
                destination: "b".into(),
                protocol: "any".into(),
                ports: vec![],
            }],
        }
    }
    fn tcp_segment(inbound: bool, flags: u8, local_port: u16) -> [u8; 40] {
        let mut buf = [0; 40];
        buf[0] = 0x45;
        buf[3] = 40;
        buf[8] = 64;
        buf[9] = 6;
        let local = [10, 203, 0, 2];
        let remote = [10, 203, 1, 2];
        let (src, dst, sport, dport) = if inbound {
            (remote, local, 8888u16, local_port)
        } else { (local, remote, local_port, 8888) };
        buf[12..16].copy_from_slice(&src);
        buf[16..20].copy_from_slice(&dst);
        buf[20..22].copy_from_slice(&sport.to_be_bytes());
        buf[22..24].copy_from_slice(&dport.to_be_bytes());
        buf[32] = 0x50;
        buf[33] = flags;
        let sum: u32 = buf[..20].chunks_exact(2).map(|v|u16::from_be_bytes([v[0],v[1]]) as u32).sum();
        let sum = (sum & 65535) + (sum >> 16);
        buf[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        buf
    }

    fn establish(e: &mut Engine, port: u16, raw: bool) {
        e.enable_tcp_continuity(true);
        for (inbound,flags) in [(false,2),(true,18),(false,16),(true,16)] {
            let bytes = tcp_segment(inbound,flags,port);
            assert!(e.check(&bytes,"b",inbound));
            e.observe_raw_tcp("b",Packet::parse(&bytes).unwrap(),inbound,raw);
        }
    }

    #[test]
    fn ordinary_continuation_requires_both_new_authorities_and_original_open_permission() {
        let epoch = "a".repeat(64);
        let mut engine = Engine::default();
        engine.apply(base(&epoch)).unwrap();
        let lease = pair(&epoch);
        engine.install_pair(lease.clone()).unwrap();
        establish(&mut engine,41000,true);
        establish(&mut engine,41001,false);
        establish(&mut engine,41002,true);
        assert!(engine.check(&tcp_segment(true,17,41002),"b",true));
        let budget=engine.flow_budget.0.clone();
        let mut waiting=engine.pause_established_tcp();
        let mut no_pair=engine.pause_established_tcp();
        let mut changed=engine.pause_established_tcp();
        let mut tightened=engine.pause_established_tcp();
        engine.revoke();
        let permits=budget.available_permits();
        let ack=tcp_segment(false,16,41000);
        assert!(!engine.check(&ack,"b",false));
        engine.apply(base(&epoch)).unwrap();
        assert_eq!(engine.restore_established_tcp(&mut no_pair,&lease),0);
        engine.install_pair(lease.clone()).unwrap();
        assert!(engine.restore_established_tcp(&mut waiting,&lease)==1);
        assert_eq!(budget.available_permits()+1,permits);
        assert!(engine.check(&ack,"b",false));
        assert!(!engine.check(&tcp_segment(false,16,41001),"b",false));
        assert!(!engine.check(&tcp_segment(false,16,41002),"b",false));
        assert_eq!(engine.restore_established_tcp(&mut waiting,&lease),0);
        engine.revoke_pair("b");
        let mut id=lease.clone();
        id.peer.instance="new-process".into();
        engine.install_pair(id.clone()).unwrap();
        assert_eq!(engine.restore_established_tcp(&mut changed,&id),0);
        engine.revoke_pair("b");
        let mut acl=lease.clone();
        acl.grants[0].protocol="tcp".into();
        acl.grants[0].ports=vec![Port{start:22,end:22}];
        engine.install_pair(acl.clone()).unwrap();
        assert_eq!(engine.restore_established_tcp(&mut tightened,&acl),0);
    }

    #[test]
    fn bilateral_confirmation_only_restores_the_same_opening_after_a_valid_peer_response() {
        let epoch="a".repeat(64);let lease=pair(&epoch);
        let mut source=Engine::default();source.apply(base(&epoch)).unwrap();
        source.install_pair(lease.clone()).unwrap();establish(&mut source,41000,true);
        let mut target=Engine::default();target.apply(base(&epoch)).unwrap();
        target.install_pair(lease.clone()).unwrap();establish(&mut target,41000,true);
        let mut frozen=source.pause_established_tcp();let mut target_frozen=TcpContinuity::default();
        source.revoke();source.apply(base(&epoch)).unwrap();source.install_pair(lease.clone()).unwrap();
        source.enable_tcp_continuity(true);
        assert!(source.prepare_tcp(&mut frozen,&lease));
        let gen=[7;16];let original=frozen.requests(gen)[0].1.clone();let ack=tcp_segment(false,16,41000);
        assert!(!source.check(&ack,"b",false));
        assert!(target.tcp_confirmation(&mut target_frozen,"b",[0;16],&original).is_none());
        let mut reply=target.tcp_confirmation(&mut target_frozen,"b",gen,&original).unwrap();
        reply[28]^=1;source.tcp_confirmation(&mut frozen,"b",gen,&reply);
        assert!(!source.check(&ack,"b",false));
        reply[28]^=1;let before=Instant::now();source.tcp_confirmation(&mut frozen,"b",gen,&reply);
        assert!(source.check(&ack,"b",false));
        assert!(!source.check_received(&tcp_segment(true,16,41000),"b",before));
        assert!(source.check_received(&tcp_segment(true,16,41000),"b",Instant::now()));
        assert!(!frozen.contains("b"));
    }

    #[test]
    fn retry_requires_both_owners_and_rejects_timeout_denial_and_tuple_reuse() {
        let epoch="a".repeat(64);let lease=pair(&epoch);let generation=[7;16];
        let mut engine=Engine::default();engine.apply(base(&epoch)).unwrap();engine.install_pair(lease.clone()).unwrap();
        for port in 41010..41014{establish(&mut engine,port,true);}
        let mut before=engine.pause_established_tcp();
        let mut remote=Engine::default();remote.apply(base(&epoch)).unwrap();remote.install_pair(lease.clone()).unwrap();
        for port in 41010..41014{establish(&mut remote,port,true);}
        let mut remote_saved=remote.pause_established_tcp();let mut expired=engine.pause_established_tcp();
        engine.revoke();engine.apply(base(&epoch)).unwrap();engine.install_pair(lease.clone()).unwrap();
        let packet=|port|Packet::parse(&tcp_segment(false,16,port)).unwrap();
        assert!(engine.retry_proof(&before,"b",packet(41010)).is_none());
        assert!(engine.prepare_tcp(&mut before,&lease));assert!(engine.prepare_tcp(&mut expired,&lease));
        expired.timeout_confirmation("b");assert!(engine.retry_proof(&expired,"b",packet(41010)).is_none());
        let proofs:Vec<_>=(41010..41014).map(|port|engine.retry_proof(&before,"b",packet(port)).unwrap()).collect();
        assert!(engine.retry_owner("b",proofs[0]).is_none());
        let grant=remote.tcp_confirmation(&mut TcpContinuity::default(),"b",generation,&before.requests(generation)[0].1).unwrap();
        remote.revoke();remote.apply(base(&epoch)).unwrap();remote.install_pair(lease.clone()).unwrap();
        assert!(remote.prepare_tcp(&mut remote_saved,&lease));
        // The normal handshake may proceed simultaneously. An unconfirmed peer
        // cannot attest to being ready to receive a saved local transmission.
        assert!(remote.tcp_confirmation(&mut remote_saved,"b",generation,&proofs[0].request(generation)).is_none());
        engine.tcp_confirmation(&mut before,"b",generation,&grant);
        let ready=engine.tcp_confirmation(&mut before,"b",generation,&proofs[0].request(generation)).unwrap();
        let batch=proofs[0].request_batch(generation,proofs.iter().take(3));
        let batched=engine.tcp_confirmation(&mut before,"b",generation,&batch).unwrap();
        assert!(proofs[..3].iter().all(|p|p.matches_reply(generation,&batched)));
        assert!(!proofs[3].matches_reply(generation,&batched));
        assert!(!proofs[0].matches_reply(generation,&batched[..batched.len()-1]));
        assert!(proofs[0].matches_reply(generation,&ready));assert!(!proofs[0].matches_reply([1;16],&ready));
        assert!(!proofs[1].matches_reply(generation,&ready));
        let guards:Vec<_>=proofs.iter().map(|p|engine.retry_owner("b",*p).unwrap()).collect();
        let mut replaced=tcp_segment(false,2,41010);replaced[24..28].copy_from_slice(&818u32.to_be_bytes());
        assert!(engine.check(&replaced,"b",false));assert!(guards[0].upgrade().is_none());
        assert!(engine.check(&tcp_segment(false,17,41011),"b",false));
        assert!(guards[1].upgrade().is_none_or(|r|!r.alive()));
        engine.discard_tcp_query(&Lookup{kind:"peer".into(),value:"b".into()});
        assert!(engine.retry_owner("b",proofs[2]).is_none());assert!(guards[2].upgrade().is_none_or(|r|!r.alive()));
        engine.revoke();assert!(guards[3].upgrade().is_none());
    }

    #[test]
    fn unconfirmed_local_segment_must_match_original_senders_sequence_window() {
        let epoch="a".repeat(64);let lease=pair(&epoch);
        let mut e=Engine::default();e.apply(base(&epoch)).unwrap();e.install_pair(lease).unwrap();
        establish(&mut e,41000,true);
        let mut sent=Packet::parse(&tcp_segment(false,16,41000)).unwrap();
        sent.tcp_sequence=5000;sent.tcp_data_len=640;e.observe_raw_tcp("b",sent,false,true);
        let mut peer=Packet::parse(&tcp_segment(true,16,41000)).unwrap();
        peer.tcp_acknowledgement=5050;e.observe_raw_tcp("b",peer,true,true);
        let mut frozen=e.pause_established_tcp();
        sent.tcp_sequence=5050;sent.tcp_data_len=463;assert!(frozen.local_opening(sent).is_some());
        sent.tcp_sequence=5640;assert!(frozen.local_opening(sent).is_some());
        sent.tcp_sequence=5530;assert!(frozen.local_opening(sent).is_none());
        sent.tcp_sequence=5050u32.wrapping_sub(1);assert!(frozen.local_opening(sent).is_none());
        sent.tcp_sequence=5050u32.wrapping_add(1<<31);assert!(frozen.local_opening(sent).is_none());
        assert!(frozen.local_opening(peer).is_none());
        frozen.observe_lifecycle(Packet::parse(&tcp_segment(false,2,41000)).unwrap());
        sent.tcp_sequence=5050;assert!(frozen.local_opening(sent).is_none());
    }

    #[test]
    fn expired_pair_confirms_for_a_bounded_window_and_a_denial_survives_regrant(){
        let epoch="a".repeat(64);let lease=pair(&epoch);let mut e=Engine::default();
        e.apply(base(&epoch)).unwrap();e.install_pair(lease.clone()).unwrap();establish(&mut e,41010,true);
        e.pairs.get_mut("b").unwrap().deadline=Some(Instant::now());
        e.prune_pairs();let mut pending=e.take_expired_tcp();assert!(pending.contains("b"));
        let query=Lookup{kind:"peer".into(),value:"b".into()};
        e.install_pair(lease.clone()).unwrap();assert!(e.prepare_tcp(&mut pending,&lease));
        let packet=Packet::parse(&tcp_segment(false,16,41010)).unwrap();
        assert!(pending.awaiting("b",packet));
        pending.timeout_confirmation("b");assert!(!pending.awaiting("b",packet));
        assert!(!e.check(&tcp_segment(false,16,41010),"b",false));
        establish(&mut e,41011,true);e.discard_tcp_query(&query);
        e.retire_expired_pair("b");let mut retired=e.take_expired_tcp();
        e.install_pair(lease.clone()).unwrap();assert!(!e.prepare_tcp(&mut retired,&lease));
    }

    #[test]
    fn ordinary_continuation_is_bounded_and_requires_complete_unchanged_raw_flows() {
        let epoch="a".repeat(64);
        let mut e=Engine::default();
        e.apply(base(&epoch)).unwrap();
        let lease=pair(&epoch);
        e.install_pair(lease.clone()).unwrap();
        assert!(e.check(&tcp_segment(false,2,40990),"b",false));
        assert!(!e.pause_established_tcp().contains("b"));
        establish(&mut e,40991,true);
        e.invalidate_tcp_continuity();
        assert!(!e.pause_established_tcp().contains("b"));
        for port in 41000..41300 {establish(&mut e,port,true);}
        let mut pending=e.pause_established_tcp();
        e.revoke();
        e.apply(base(&epoch)).unwrap();
        e.install_pair(lease.clone()).unwrap();
        assert_eq!(e.restore_established_tcp(&mut pending,&lease),256);
    }

    #[test]
    fn private_packet_origin_tracks_the_authorized_process_and_relay_registration() {
        let epoch = "a".repeat(64);
        let mut engine = Engine::default();
        engine.apply(base(&epoch)).unwrap();
        let mut first = pair(&epoch);
        first.peer.relay_origin = Some("1".repeat(32));
        let old = first.peer.clone();
        engine.install_pair(first.clone()).unwrap();

        let mut next = first;
        next.revision += 1;
        next.peer.instance = "replacement".into();
        next.peer.fingerprint = "replacement-cert".into();
        next.peer.relay_origin = Some("2".repeat(32));
        let incoming = next.peer.clone();
        let current = engine.pair_peer("b").unwrap();
        assert!(current.matches_packet_origin(&old));
        assert!(!current.matches_packet_origin(&incoming));
        engine.install_pair(next).unwrap();
        let current = engine.pair_peer("b").unwrap();
        assert!(current.matches_packet_origin(&incoming));
        assert!(!current.matches_packet_origin(&old));

        let mut direct = incoming.clone();
        direct.relay_origin = None;
        assert!(current.matches_packet_origin(&direct));
        for altered in [
            PeerInfo { id: "other".into(), ..direct.clone() },
            PeerInfo { ip: "10.203.1.3".parse().unwrap(), ..direct.clone() },
            PeerInfo { fingerprint: old.fingerprint, ..direct.clone() },
            PeerInfo { instance: old.instance, ..direct.clone() },
            PeerInfo { relay_origin: old.relay_origin, ..direct },
        ] {
            assert!(!current.matches_packet_origin(&altered));
        }
    }
    #[test]
    fn exit_intent_capture_is_exact_bounded_and_preserves_native_defaults(){
        let epoch="a".repeat(64);let mut snapshot=base(&epoch);
        let value=serde_json::json!({"id":"route","name":"LAN","role":"client","selection":"sticky","traffic_mode":"lan_only","allow_direct_fallback":false,"tor_enabled":false,"tor_circuit_groups":4,"lan_networks":["10.1.0.0/24","10.2.0.0/24"]});
        let intent:ExitIntent=serde_json::from_value(value).unwrap();assert!(intent.masquerade&&intent.block_lan_access);
        assert!(!intent.lan_networks.iter().any(|n|n.contains("10.3.0.1".parse().unwrap())));
        snapshot.sparse.as_mut().unwrap().selection_epoch=Some(epoch.clone());snapshot.sparse.as_mut().unwrap().exit_epoch=Some(epoch);snapshot.sparse.as_mut().unwrap().exit_intents.push(intent);
        Engine::default().apply(snapshot.clone()).unwrap();
        snapshot.sparse.as_mut().unwrap().exit_intents[0].lan_networks=(0..33).map(|n|format!("10.{n}.0.0/16").parse().unwrap()).collect();
        assert!(Engine::default().apply(snapshot).is_err());
    }

    #[test]
    fn namespace_metadata_is_bounded_and_malformed_replacement_fails_closed() {
        let epoch = "a".repeat(64);
        let mut valid = base(&epoch);
        valid.dns_suffixes = vec!["phub".into(), "custom.internal".into()];
        let mut e = Engine::default();
        e.apply(valid.clone()).unwrap();
        e.install_pair(pair(&epoch)).unwrap();
        let mut bad = valid.clone();
        bad.dns_suffixes.push(".invalid".into());
        assert!(e.apply(bad).is_err());
        assert!(!e.valid_lease());
        assert_eq!(e.pair_count(), 0);
        let mut too_many = valid.clone();
        too_many.dns_suffixes = vec!["custom.internal".into(); MAX_PRIVATE_SUFFIXES + 1];
        assert!(e.apply(too_many).is_err());
        let long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let mut too_big = valid;
        too_big.dns_suffixes = vec![long; 130];
        assert!(e.apply(too_big).is_err());
    }

    #[test]
    fn base_refresh_does_not_refresh_pair_and_generation_change_retires_identity() {
        let epoch = "a".repeat(64);
        let mut e = Engine::default();
        e.apply(base(&epoch)).unwrap();
        e.install_pair(pair(&epoch)).unwrap();
        let deadline = e.pairs["b"].deadline;
        let mut refresh = base(&epoch);
        refresh.revision = 2;
        e.apply(refresh).unwrap();
        assert_eq!(e.pairs["b"].deadline, deadline);
        assert!(e.pair_peer("b").is_some());
        let mut growth = base(&epoch);
        growth.revision = 3;
        growth
            .sparse
            .as_mut()
            .unwrap()
            .capture_pools
            .push("10.203.0.0/16".parse().unwrap());
        e.apply(growth).unwrap();
        assert_eq!(
            e.pairs["b"].deadline, deadline,
            "adding capture capacity must not reset configured flows"
        );
        let mut next = base(&"b".repeat(64));
        next.revision = 4;
        e.apply(next).unwrap();
        assert_eq!(e.pair_count(), 0);
        assert!(e.install_pair(pair(&epoch)).is_err());
    }
    #[test]
    fn expired_pair_does_not_revoke_base_or_an_unrelated_pair() {
        let epoch = "a".repeat(64);
        let mut e = Engine::default();
        e.apply(base(&epoch)).unwrap();
        e.install_pair(pair(&epoch)).unwrap();
        e.pairs.get_mut("b").unwrap().deadline = Some(Instant::now() - Duration::from_secs(1));
        e.prune_pairs();
        assert!(e.valid_lease());
        assert!(e.pair_peer("b").is_none());
        assert_eq!(e.pair_count(), 0);
    }
    #[test]
    fn invalid_peer_or_foreign_grant_cannot_replace_a_valid_lease() {
        let epoch = "a".repeat(64);
        let mut e = Engine::default();
        e.apply(base(&epoch)).unwrap();
        e.install_pair(pair(&epoch)).unwrap();
        let mut wrong = pair(&epoch);
        wrong.local.instance = "stale".into();
        assert!(e.install_pair(wrong).is_err());
        let mut wrong = pair(&epoch);
        wrong.grants[0].destination = "c".into();
        assert!(e.install_pair(wrong).is_err());
        assert!(e.pair_peer("b").is_some());
        e.revoke();
        assert!(e.pair_peer("b").is_none());
    }
    fn exit_base(epoch:&str)->Snapshot {
        let mut snapshot=base(epoch);snapshot.sparse.as_mut().unwrap().capture_pools=vec!["10.203.0.0/16".parse().unwrap()];snapshot.sparse.as_mut().unwrap().exit_epoch=Some("e".repeat(64));snapshot
    }
    fn exit_pair(epoch:&str,local_client:bool)->PairLease {
        let mut lease=pair(epoch);lease.grants.clear();
        lease.exit=Some(ExitPair{epoch:"e".repeat(64),route_id:"exit-route".into(),client:if local_client{"a"}else{"b"}.into(),router:if local_client{"b"}else{"a"}.into(),traffic_mode:porthub_mesh::exit_policy::TrafficMode::InternetOnly});lease
    }
    #[test]
    fn private_stream_projection_never_inherits_exit_authority_or_renews_lease() {
        let epoch = "a".repeat(64);
        for with_private in [false, true] {
            let mut engine = Engine::default();
            engine.apply(exit_base(&epoch)).unwrap();
            let mut lease = exit_pair(&epoch, true);
            if with_private { lease.grants = pair(&epoch).grants; }
            let original_grants = serde_json::to_value(&lease.grants).unwrap();
            engine.install_pair(lease).unwrap();
            let full = engine.pair_snapshots();
            assert!(!full[0].0.exit_routes.is_empty());
            let projected = engine.private_stream_pair_snapshots();
            assert_eq!(projected.len(), 1);
            assert!(projected[0].0.exit_routes.is_empty());
            assert_eq!(projected[0].1, full[0].1);
            assert_eq!(projected[0].0.workspace, full[0].0.workspace);
            assert_eq!(projected[0].0.self_, full[0].0.self_);
            assert_eq!(serde_json::to_value(&projected[0].0.peers).unwrap(), serde_json::to_value(&full[0].0.peers).unwrap());
            assert_eq!(serde_json::to_value(&projected[0].0.grants).unwrap(), original_grants);
            assert!(!engine.pair_snapshots()[0].0.exit_routes.is_empty(), "projection mutated live exit policy");
            let mut private = Engine::default();
            private.apply(projected[0].0.clone()).unwrap();
            assert_eq!(private.check(&udp("10.203.0.2", "10.203.1.2", 15000, 53), "b", false), with_private);
            assert!(!private.check_exit(&udp("10.203.0.2", "8.8.8.8", 15001, 53), "b", false));
            engine.apply(exit_base(&"b".repeat(64))).unwrap();
            assert!(engine.private_stream_pair_snapshots().is_empty(), "retired private epoch leaked into projection");
            assert_eq!(engine.pair_snapshots()[0].1, full[0].1, "exit retention renewed original clock");
            engine.revoke_pair("b");
            assert!(engine.private_stream_pair_snapshots().is_empty());
        }
    }
    #[test]
    fn exact_exit_pairs_authorize_both_roles_without_private_port_permissions() {
        let epoch="a".repeat(64);
        let old=serde_json::to_value(pair(&epoch)).unwrap();assert!(old.get("exit").is_none());
        let decoded:PairLease=serde_json::from_value(old).unwrap();assert!(decoded.exit.is_none());
        for local_client in [true,false] {
            let mut e=Engine::default();e.apply(exit_base(&epoch)).unwrap();e.install_pair(exit_pair(&epoch,local_client)).unwrap();
            let client=if local_client{"10.203.0.2"}else{"10.203.1.2"};
            let request=udp(client,"8.8.8.8",15000,53);let reply=udp("8.8.8.8",client,53,15000);
            assert!(!e.check_exit(&reply,"b",local_client),"unsolicited exit reply admitted");
            assert!(e.check_exit(&request,"b",!local_client));assert!(e.check_exit(&reply,"b",local_client));
            assert!(!e.check_exit(&request,"c",!local_client));
            assert!(!e.check_exit(&udp("10.203.9.9","8.8.8.8",15000,53),"b",!local_client));
            assert!(!e.check_exit(&udp(client,"192.168.1.1",15000,53),"b",!local_client));
            assert!(!e.check(&udp("10.203.0.2","10.203.1.2",15000,53),"b",false),"exit authority widened private ports");
            assert_eq!(e.active_pair_flows(),vec!["b"]);
            e.revoke_pair("b");assert!(!e.check_exit(&reply,"b",local_client));
        }
    }
    #[test]
    fn exit_pair_identity_expiry_and_mode_replacement_are_independent_of_base_liveness() {
        let epoch="a".repeat(64);let mut e=Engine::default();e.apply(exit_base(&epoch)).unwrap();
        let mut invalid=exit_pair(&epoch,true);invalid.exit.as_mut().unwrap().router="c".into();assert!(e.install_pair(invalid).is_err());
        let request=udp("10.203.0.2","8.8.8.8",15000,53);let reply=udp("8.8.8.8","10.203.0.2",53,15000);
        e.install_pair(exit_pair(&epoch,true)).unwrap();assert!(e.check_exit(&request,"b",false));
        let mut changed=exit_pair(&epoch,true);changed.exit.as_mut().unwrap().traffic_mode=porthub_mesh::exit_policy::TrafficMode::LanOnly;
        let mut unknown=Engine::default();unknown.apply(base(&epoch)).unwrap();assert!(unknown.install_pair(changed.clone()).is_err());
        e.install_pair(changed).unwrap();assert!(!e.check_exit(&reply,"b",true));
        assert!(!e.check_exit(&udp("10.203.0.2","10.203.9.9",15000,53),"b",false),"LAN exit bypassed an uncached overlay identity");
        assert!(e.check_exit(&udp("10.203.0.2","192.168.1.1",15000,53),"b",false));
        e.pairs.get_mut("b").unwrap().deadline=Some(Instant::now()-Duration::from_secs(1));
        assert!(!e.check_exit(&request,"b",false));assert!(e.valid_lease());assert!(e.active_pair_flows().is_empty());
        e.install_pair(exit_pair(&epoch,true)).unwrap();assert!(e.check_exit(&request,"b",false));
        let mut changed=exit_base(&"b".repeat(64));changed.sparse.as_mut().unwrap().exit_epoch=Some("f".repeat(64));
        e.apply(changed).unwrap();assert!(!e.check_exit(&reply,"b",true));
    }
    #[test]
    fn exit_pairs_share_the_existing_total_exit_flow_bound() {
        let epoch="a".repeat(64);let mut e=Engine::default();e.apply(exit_base(&epoch)).unwrap();
        e.exit_flow_budget=FlowBudget(std::sync::Arc::new(tokio::sync::Semaphore::new(1)));
        e.install_pair(exit_pair(&epoch,true)).unwrap();
        let mut c=exit_pair(&epoch,true);c.peer=peer("c","10.203.1.3");c.exit.as_mut().unwrap().router="c".into();e.install_pair(c).unwrap();
        assert!(e.check_exit(&udp("10.203.0.2","8.8.8.8",15000,53),"b",false));
        assert!(!e.check_exit(&udp("10.203.0.2","1.1.1.1",15001,53),"c",false));
        e.revoke_pair("b");assert!(e.check_exit(&udp("10.203.0.2","1.1.1.1",15001,53),"c",false));
    }
    #[test]
    fn independent_generations_preserve_only_authorized_flows_without_local_deadline_renewal() {
        let epoch="a".repeat(64);let mut e=Engine::default();e.apply(exit_base(&epoch)).unwrap();
        let mut composite=pair(&epoch);composite.exit=exit_pair(&epoch,true).exit;e.install_pair(composite).unwrap();
        let private=udp("10.203.0.2","10.203.1.2",15001,53);let private_reply=udp("10.203.1.2","10.203.0.2",53,15001);
        let exit=udp("10.203.0.2","8.8.8.8",15000,53);let exit_reply=udp("8.8.8.8","10.203.0.2",53,15000);
        assert!(e.check(&private,"b",false));assert!(e.check_exit(&exit,"b",false));
        let before=e.pairs["b"].deadline;
        e.apply(exit_base(&"b".repeat(64))).unwrap();
        assert_eq!(e.pairs["b"].deadline,before,"local ordinary epoch update extended exit lease");
        assert!(!e.check(&private_reply,"b",true));assert!(e.check_exit(&exit_reply,"b",true));
        let mut fresh=pair(&"b".repeat(64));fresh.exit=exit_pair(&"b".repeat(64),true).exit;e.install_pair(fresh).unwrap();
        assert!(e.check(&private,"b",false));assert!(e.check_exit(&exit_reply,"b",true),"unchanged genuine lease renewal lost established exit flow");
        let before=e.pairs["b"].deadline;
        let mut changed=exit_base(&"b".repeat(64));changed.sparse.as_mut().unwrap().exit_epoch=Some("f".repeat(64));e.apply(changed).unwrap();
        assert_eq!(e.pairs["b"].deadline,before,"local exit epoch update extended private lease");
        assert!(e.check(&private_reply,"b",true));assert!(!e.check_exit(&exit_reply,"b",true));
        assert!(e.install_pair(exit_pair(&"b".repeat(64),true)).is_err(),"old exit epoch was reauthorized");
        assert!(e.check(&private_reply,"b",true),"stale exit reply destroyed unrelated private authority");
    }
    #[test]
    fn selection_generation_change_preserves_existing_exit_tracking_and_original_lease() {
        let epoch="a".repeat(64);let mut base=exit_base(&epoch);base.sparse.as_mut().unwrap().selection_epoch=Some("c".repeat(64));
        let mut engine=Engine::default();engine.apply(base.clone()).unwrap();engine.install_pair(exit_pair(&epoch,true)).unwrap();
        let request=udp("10.203.0.2","8.8.8.8",15000,53);let reply=udp("8.8.8.8","10.203.0.2",53,15000);
        assert!(engine.check_exit(&request,"b",false));let deadline=engine.pairs["b"].deadline;
        base.sparse.as_mut().unwrap().selection_epoch=Some("d".repeat(64));engine.apply(base.clone()).unwrap();
        assert_eq!(engine.pairs["b"].deadline,deadline);assert!(engine.check_exit(&reply,"b",true),"scheduling change discarded established exit tracking");
        base.sparse.as_mut().unwrap().exit_epoch=Some("f".repeat(64));engine.apply(base).unwrap();
        assert!(!engine.check_exit(&reply,"b",true),"actual permission withdrawal retained exit tracking");
    }
    #[test]
    fn source_identity_change_cannot_retain_either_generation() {
        let epoch="a".repeat(64);let mut e=Engine::default();e.apply(exit_base(&epoch)).unwrap();
        e.install_pair(exit_pair(&epoch,true)).unwrap();
        let mut changed=exit_base(&epoch);changed.peers[0].instance="new-owned-process".into();e.apply(changed).unwrap();
        assert_eq!(e.pair_count(),0,"old exit source survived process identity change");
        let mut bad=exit_base(&epoch);bad.sparse.as_mut().unwrap().exit_epoch=Some("invalid".into());assert!(e.apply(bad).is_err());
    }
    fn udp(source: &str, destination: &str, sport: u16, dport: u16) -> Vec<u8> {
        let mut b = vec![0u8; 28];
        b[0] = 0x45;
        b[2..4].copy_from_slice(&28u16.to_be_bytes());
        b[8] = 64;
        b[9] = 17;
        b[12..16].copy_from_slice(&source.parse::<Ipv4Addr>().unwrap().octets());
        b[16..20].copy_from_slice(&destination.parse::<Ipv4Addr>().unwrap().octets());
        b[20..22].copy_from_slice(&sport.to_be_bytes());
        b[22..24].copy_from_slice(&dport.to_be_bytes());
        b[24..26].copy_from_slice(&8u16.to_be_bytes());
        let mut sum = b[..20]
            .chunks_exact(2)
            .map(|v| u32::from(u16::from_be_bytes([v[0], v[1]])))
            .sum::<u32>();
        while sum >> 16 != 0 {
            sum = (sum & 65535) + (sum >> 16)
        }
        b[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        b
    }
    #[test]
    fn all_pair_engines_share_one_client_flow_budget_and_release_on_revoke_expiry_drop() {
        let epoch = "a".repeat(64);
        let mut e = Engine::default();
        assert_eq!(e.flow_budget.0.available_permits(), 65536);
        e.flow_budget = FlowBudget(std::sync::Arc::new(tokio::sync::Semaphore::new(2)));
        let budget = e.flow_budget.0.clone();
        e.apply(base(&epoch)).unwrap();
        e.install_pair(pair(&epoch)).unwrap();
        let mut other = pair(&epoch);
        other.peer.id = "c".into();
        other.peer.ip = "10.203.1.3".parse().unwrap();
        other.grants[0].destination = "c".into();
        e.install_pair(other.clone()).unwrap();
        assert!(e.check(&udp("10.203.0.2", "10.203.1.2", 4000, 443), "b", false));
        assert!(e.check(&udp("10.203.0.2", "10.203.1.3", 4000, 443), "c", false));
        assert_eq!(budget.available_permits(), 0);
        assert!(
            !e.check(&udp("10.203.0.2", "10.203.1.3", 4001, 443), "c", false),
            "another pair must not allocate another 65536-flow budget"
        );
        assert!(
            e.check(&udp("10.203.1.2", "10.203.0.2", 443, 4000), "b", true),
            "backpressure must not reject established replies"
        );
        e.revoke_pair("b");
        assert_eq!(budget.available_permits(), 1);
        assert!(e.check(&udp("10.203.0.2", "10.203.1.3", 4001, 443), "c", false));
        for flow in e.pairs.get_mut("c").unwrap().flows.values_mut() {
            flow.expires = Instant::now() - Duration::from_secs(1);
        }
        assert!(e.active_pair_flows().is_empty());
        assert_eq!(budget.available_permits(), 2);
        assert!(e.check(&udp("10.203.0.2", "10.203.1.3", 4002, 443), "c", false));
        assert_eq!(e.active_pair_flows(), vec!["c".to_owned()]);
        drop(e);
        assert_eq!(budget.available_permits(), 2);
    }

    #[cfg(feature = "private-stream")]
    #[test]
    fn closed_local_tcp_feedback_requires_an_authorized_untracked_socket() {
        use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket, TcpSeqNumber};

        let local = Ipv4Addr::new(10, 203, 0, 2);
        let remote = Ipv4Addr::new(10, 203, 1, 2);
        let segment = |syn: bool, destination_port| {
            let mut bytes = [0u8; 40];
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
            ip.set_version(4);
            ip.set_header_len(20);
            ip.set_total_len(40);
            ip.set_hop_limit(64);
            ip.set_next_header(IpProtocol::Tcp);
            ip.set_src_addr(local);
            ip.set_dst_addr(remote);
            ip.fill_checksum();
            let mut tcp = TcpPacket::new_unchecked(&mut bytes[20..]);
            tcp.set_header_len(20);
            tcp.set_src_port(40000);
            tcp.set_dst_port(destination_port);
            tcp.set_syn(syn);
            tcp.set_ack(!syn);
            tcp.set_seq_number(TcpSeqNumber(42));
            tcp.set_ack_number(TcpSeqNumber(824));
            tcp.fill_checksum(&IpAddress::Ipv4(local), &IpAddress::Ipv4(remote));
            bytes
        };

        let epoch = "a".repeat(64);
        let mut e = Engine::default();
        e.apply(base(&epoch)).unwrap();
        let ack = segment(false, 8888);
        assert!(e.closed_local_tcp_reply(&ack, "b").is_none());
        let mut lease = pair(&epoch);
        lease.grants[0].protocol = "tcp".into();
        lease.grants[0].ports = vec![Port { start: 8888, end: 8888 }];
        e.install_pair(lease).unwrap();
        assert!(!e.check(&ack, "b", false));
        let reply = e.closed_local_tcp_reply(&ack, "b").unwrap();
        let ip = Ipv4Packet::new_checked(&reply[..]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!((ip.src_addr(), ip.dst_addr()), (remote, local));
        assert!(tcp.rst() && !tcp.ack() && tcp.seq_number() == TcpSeqNumber(824));
        assert!(ip.verify_checksum() && tcp.verify_checksum(&IpAddress::Ipv4(remote), &IpAddress::Ipv4(local)));
        assert!(!e.check(&ack, "b", false));
        assert!(e.closed_local_tcp_reply(&ack, "other").is_none());
        assert!(e.closed_local_tcp_reply(&segment(false, 22), "b").is_none());
        assert!(e.closed_local_tcp_reply(&reply, "b").is_none());
        let mut corrupt = ack;
        corrupt[36] ^= 1;
        assert!(e.closed_local_tcp_reply(&corrupt, "b").is_none());
        let syn = segment(true, 8888);
        assert!(e.closed_local_tcp_reply(&syn, "b").is_none());
        assert!(e.check(&syn, "b", false));
        assert!(e.closed_local_tcp_reply(&ack, "b").is_none());
        e.revoke();
        assert!(e.closed_local_tcp_reply(&ack, "b").is_none());
    }
    #[test]
    fn compact_complex_pair_checks_real_packets_and_retires_old_flow_on_permission_change() {
        let epoch = "a".repeat(64);
        let mut e = Engine::default();
        e.apply(base(&epoch)).unwrap();
        let mut p = pair(&epoch);
        let grants = (1..500)
            .step_by(2)
            .map(|port| Grant {
                source: "a".into(),
                destination: "b".into(),
                protocol: "udp".into(),
                ports: vec![Port {
                    start: port,
                    end: port,
                }],
            })
            .collect::<Vec<_>>();
        p.acl = Some(super::super::pair_acl::PairAcl::from_grants("a", "b", &grants).unwrap());
        p.grants.clear();
        e.install_pair(p.clone()).unwrap();
        let out = udp("10.203.0.2", "10.203.1.2", 4000, 443);
        let reply = udp("10.203.1.2", "10.203.0.2", 443, 4000);
        assert!(e.check(&out, "b", false));
        assert!(e.check(&reply, "b", true));
        assert!(!e.check(&udp("10.203.0.2", "10.203.1.2", 4000, 444), "b", false));
        assert!(!e.check(&reply, "foreign", true));
        assert!(!e.check(&udp("10.203.1.2", "10.203.0.2", 443, 6000), "b", true));
        let mut mixed = p.clone();
        mixed.grants = grants.clone();
        assert!(e.install_pair(mixed).is_err());
        assert!(
            e.check(&reply, "b", true),
            "invalid replacement cannot discard current exact authority"
        );
        p.acl = Some(
            super::super::pair_acl::PairAcl::from_grants(
                "a",
                "b",
                &[Grant {
                    source: "a".into(),
                    destination: "b".into(),
                    protocol: "udp".into(),
                    ports: vec![Port {
                        start: 445,
                        end: 445,
                    }],
                }],
            )
            .unwrap(),
        );
        e.install_pair(p).unwrap();
        assert!(
            !e.check(&reply, "b", true),
            "old opening permission must be revalidated"
        );
        assert!(e.check(&udp("10.203.0.2", "10.203.1.2", 4000, 445), "b", false));
    }

    #[test]
    fn real_packets_keep_reverse_flow_on_renewal_but_expiry_and_identity_rotation_revoke() {
        let epoch = "a".repeat(64);
        let mut e = Engine::default();
        e.apply(base(&epoch)).unwrap();
        e.install_pair(pair(&epoch)).unwrap();
        let out = udp("10.203.0.2", "10.203.1.2", 4000, 443);
        let reply = udp("10.203.1.2", "10.203.0.2", 443, 4000);
        assert!(e.check(&out, "b", false));
        assert!(!e.check(&reply, "foreign", true));
        assert!(e.check(&reply, "b", true));
        e.install_pair(pair(&epoch)).unwrap();
        assert!(
            e.check(&reply, "b", true),
            "lease renewal preserves reverse flow"
        );
        let mut rotated = pair(&epoch);
        rotated.peer.fingerprint = "new-certificate".into();
        rotated.revision = 2;
        e.install_pair(rotated).unwrap();
        assert!(
            !e.check(&reply, "b", true),
            "old reverse flow cannot survive certificate rotation"
        );
        assert!(
            e.install_pair(pair(&epoch)).is_err(),
            "late old certificate response cannot replace a newer binding"
        );
        assert!(e.check(&out, "b", false));
        e.pairs.get_mut("b").unwrap().deadline = Some(Instant::now() - Duration::from_secs(1));
        assert!(!e.check(&reply, "b", true));
        assert!(e.valid_lease());
    }
    #[test]
    fn pair_cache_has_hard_resource_bound_and_expired_entries_release_capacity() {
        let epoch = "a".repeat(64);
        let mut e = Engine::default();
        e.apply(base(&epoch)).unwrap();
        for i in 0..MAX_PAIR_LEASES {
            let mut p = pair(&epoch);
            p.peer.id = format!("p{i}");
            p.peer.ip = Ipv4Addr::from(u32::from(Ipv4Addr::new(10, 204, 0, 1)) + i as u32);
            p.grants[0].destination = p.peer.id.clone();
            e.install_pair(p).unwrap();
        }
        assert_eq!(e.pair_count(), MAX_PAIR_LEASES);
        assert!(e.install_pair(pair(&epoch)).is_err());
        e.pairs.get_mut("p0").unwrap().deadline = Some(Instant::now() - Duration::from_secs(1));
        e.install_pair(pair(&epoch)).unwrap();
        assert_eq!(e.pair_count(), MAX_PAIR_LEASES);
    }
}
