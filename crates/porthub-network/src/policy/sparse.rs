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
    #[serde(default)]
    pub capture_pools: Vec<porthub_mesh::lan_routes::Network>,
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
        if let Some(acl) = &lease.acl {
            ensure!(
                lease.grants.is_empty(),
                "compact and legacy pair ACL cannot be mixed"
            );
            acl.compile()?;
        } else {
            ensure!(
                lease.grants.len() <= 128
                    && !lease.grants.is_empty()
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
            exit_routes: vec![],
            dns_rules: vec![],
        };
        let mut engine = Box::<Engine>::default();
        engine.flow_budget = self.flow_budget.clone();
        engine.apply(snapshot.clone())?;
        // The existing engine revalidates opening ACLs and retires flows on identity changes.
        // An unchanged lease renewal must preserve established TCP reverse-flow tracking.
        if let Some(existing) = self.pairs.get_mut(&id) {
            existing.apply(snapshot)?;
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
            if !pair.flows.is_empty() {
                active.push(id.clone());
            }
        }
        active
    }

    pub fn revoke_pair(&mut self, id: &str) {
        self.pairs.remove(id);
    }
    pub fn prune_pairs(&mut self) {
        self.pairs.retain(|_, p| p.valid_lease());
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
