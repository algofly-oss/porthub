//! Bounded sparse identity control/cache. Packet misses only enqueue intent; they never await HTTP.
use porthub_network::policy::{Lookup, PairLease, PeerInfo, Snapshot, MAX_PAIR_LEASES};
use std::{
    collections::{BTreeMap, HashSet},
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;
const MAX_INTENTS: usize = 256;
#[derive(Clone)]
pub struct Handle {
    state: Arc<Mutex<State>>,
    changed: Arc<Notify>,
    revoked: Arc<AtomicBool>,
    demand: Arc<Notify>,
}
pub struct Control {
    handle: Handle,
    sequence: u64,
}
struct Cached {
    lease: PairLease,
    deadline: Instant,
    last_used: Instant,
}
struct Intent {
    used: Instant,
    sent: Option<Instant>,
    retry_after: Instant,
}
#[derive(Default)]
struct State {
    epoch: Option<String>,
    deadline: Option<Instant>,
    cache: BTreeMap<String, Cached>,
    wanted: BTreeMap<Lookup, Intent>,
}
pub fn channel() -> (Handle, Control) {
    let handle = Handle {
        state: Default::default(),
        changed: Default::default(),
        revoked: Default::default(),
        demand: Default::default(),
    };
    (
        handle.clone(),
        Control {
            handle,
            sequence: 0,
        },
    )
}
impl Handle {
    pub fn revoke_all(&self) {
        self.revoked.store(true, Ordering::SeqCst);
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        s.deadline = None;
        s.cache.clear();
        s.wanted.clear();
        drop(s);
        self.changed.notify_waiters();
        self.demand.notify_waiters();
    }
    pub fn revoked(&self) -> bool {
        self.revoked.load(Ordering::SeqCst)
    }
    pub fn update_base(&self, snapshot: &Snapshot) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let epoch = snapshot.sparse.as_ref().map(|s| s.epoch.clone());
        if s.epoch != epoch {
            s.cache.clear();
        }
        s.epoch = epoch;
        s.deadline = snapshot
            .expires_at
            .signed_duration_since(chrono::Utc::now())
            .to_std()
            .ok()
            .map(|left| Instant::now() + left);
        if s.epoch.is_none() {
            s.cache.clear();
            s.wanted.clear();
        }
        drop(s);
        self.changed.notify_waiters();
    }
    fn peer(&self, select: impl Fn(&PeerInfo) -> bool) -> Option<PeerInfo> {
        let mut s = self.state.try_lock().ok()?;
        let now = Instant::now();
        if s.epoch.is_none() || s.deadline.is_none_or(|d| d <= now) {
            return None;
        }
        let hit = s
            .cache
            .values_mut()
            .find(|c| c.deadline > now && select(&c.lease.peer))?;
        hit.last_used = now;
        Some(hit.lease.peer.clone())
    }
    pub fn dns_ttl(&self, ip: Ipv4Addr) -> Option<u32> {
        let s = self.state.try_lock().ok()?;
        let now = Instant::now();
        let base = s.deadline?;
        let peer = s
            .cache
            .values()
            .find(|c| c.lease.peer.ip == ip && c.deadline > now)?;
        let remaining = peer
            .deadline
            .min(base)
            .checked_duration_since(now)?
            .as_secs();
        (remaining > 0).then_some(remaining.min(5) as u32)
    }
    pub fn by_ip(&self, ip: Ipv4Addr) -> Option<PeerInfo> {
        self.peer(|p| p.ip == ip)
    }
    pub fn by_id(&self, id: &str) -> Option<PeerInfo> {
        self.peer(|p| p.id == id)
    }
    pub fn enabled(&self) -> bool {
        let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        s.epoch.is_some()
    }
    pub fn leases(&self) -> Vec<PairLease> {
        let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        s.cache
            .values()
            .filter(|c| c.deadline > now)
            .map(|c| c.lease.clone())
            .collect()
    }
    pub fn peers(&self) -> Vec<PeerInfo> {
        let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        if s.epoch.is_none() || s.deadline.is_none_or(|d| d <= now) {
            return Vec::new();
        }
        s.cache
            .values()
            .filter(|p| p.deadline > now)
            .map(|p| p.lease.peer.clone())
            .collect()
    }
    pub fn request_ip(&self, ip: Ipv4Addr) -> bool {
        ip.is_private()
            && self.request(Lookup {
                kind: "ip".into(),
                value: ip.to_string(),
            })
    }
    pub fn request_peer(&self, id: &str) -> bool {
        !id.is_empty()
            && id.len() <= 60
            && self.request(Lookup {
                kind: "peer".into(),
                value: id.into(),
            })
    }
    pub fn request(&self, query: Lookup) -> bool {
        let Ok(mut s) = self.state.try_lock() else {
            return false;
        };
        let now = Instant::now();
        if s.epoch.is_none() || s.deadline.is_none_or(|d| d <= now) {
            return false;
        }
        if !s.wanted.contains_key(&query) && s.wanted.len() >= MAX_INTENTS {
            return false;
        }
        s.wanted
            .entry(query)
            .and_modify(|i| i.used = now)
            .or_insert(Intent {
                used: now,
                sent: None,
                retry_after: now,
            });
        drop(s);
        self.demand.notify_one();
        true
    }
    /// Called only by the packet owner AFTER Engine and native /32 route installation succeed.
    pub fn installed(&self, query: &Lookup, lease: PairLease) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        if s.epoch.as_deref() != Some(&lease.epoch) || s.deadline.is_none_or(|d| d <= now) {
            return;
        }
        let Ok(left) = lease
            .expires_at
            .signed_duration_since(chrono::Utc::now())
            .to_std()
        else {
            return;
        };
        s.cache.retain(|_, c| c.deadline > now);
        if !s.cache.contains_key(&lease.peer.id) && s.cache.len() >= MAX_PAIR_LEASES {
            return;
        }
        let used = s
            .cache
            .get(&lease.peer.id)
            .map(|c| c.last_used)
            .unwrap_or(now);
        s.cache.insert(
            lease.peer.id.clone(),
            Cached {
                lease,
                deadline: now + left,
                last_used: used,
            },
        );
        s.wanted.remove(query);
        drop(s);
        self.changed.notify_waiters();
    }
    pub fn cached_query(&self, query: &Lookup) -> Option<PeerInfo> {
        let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        s.cache
            .values()
            .find(|c| {
                c.deadline > now
                    && match query.kind.as_str() {
                        "peer" => c.lease.peer.id == query.value,
                        "ip" => c.lease.peer.ip.to_string() == query.value,
                        "name" => {
                            let name = query.value.trim_end_matches('.');
                            c.lease.peer.hostname.eq_ignore_ascii_case(name)
                                || c.lease
                                    .peer
                                    .aliases
                                    .iter()
                                    .any(|a| a.eq_ignore_ascii_case(name))
                        }
                        _ => false,
                    }
            })
            .map(|c| c.lease.peer.clone())
    }
    pub fn retire(&self, id: &str) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .cache
            .remove(id);
        self.changed.notify_waiters();
    }
    pub fn unavailable(&self, query: &Lookup) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(i) = s.wanted.get_mut(query) {
            i.retry_after = Instant::now() + Duration::from_secs(2);
        }
        drop(s);
        self.changed.notify_waiters();
    }
    pub async fn resolve_name(&self, name: &str) -> Option<PeerInfo> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let query = Lookup {
            kind: "name".into(),
            value: name.clone(),
        };
        let wait = async {
            loop {
                let notified = self.changed.notified();
                if let Some(peer) = self.peer(|p| {
                    p.hostname.eq_ignore_ascii_case(&name)
                        || p.aliases.iter().any(|a| a.eq_ignore_ascii_case(&name))
                }) {
                    return Some(peer);
                }
                if !self.request(query.clone()) {
                    return None;
                }
                notified.await;
            }
        };
        tokio::time::timeout(Duration::from_secs(3), wait)
            .await
            .ok()
            .flatten()
    }
}
/// This helper is shared by the native packet owner and no-device lifecycle regressions.
/// Only an authenticated authoritative denial retires a pair; overload/temporary failures do not.
pub fn apply_denial(
    handle: &Handle,
    policy: &mut porthub_network::policy::Engine,
    response: &porthub_network::policy::PairResponse,
) -> Option<PeerInfo> {
    if response.status != "unavailable" {
        return None;
    }
    let peer = handle.cached_query(&response.query)?;
    policy.revoke_pair(&peer.id);
    handle.retire(&peer.id);
    Some(peer)
}
impl Control {
    pub async fn demand(&self) {
        self.handle.demand.notified().await;
    }
    pub fn urgent(&self) -> bool {
        let s = self.handle.state.lock().unwrap_or_else(|p| p.into_inner());
        !s.wanted.is_empty() || s.cache.values().any(|c| c.deadline > Instant::now())
    }
    pub fn handle(&self) -> Handle {
        self.handle.clone()
    }
    pub fn batch(&mut self) -> anyhow::Result<serde_json::Value> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("sparse sequence exhausted"))?;
        let mut s = self.handle.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        s.cache.retain(|_, c| c.deadline > now);
        s.wanted
            .retain(|_, i| now.saturating_duration_since(i.used) < Duration::from_secs(30));
        let mut renew: Vec<_> = s
            .cache
            .values()
            .filter(|c| {
                now.saturating_duration_since(c.last_used) < Duration::from_secs(30)
                    && c.deadline <= now + Duration::from_secs(10)
            })
            .map(|c| {
                (
                    c.deadline,
                    Lookup {
                        kind: "peer".into(),
                        value: c.lease.peer.id.clone(),
                    },
                )
            })
            .collect();
        renew.sort_by_key(|p| p.0);
        let mut misses: Vec<_> = s
            .wanted
            .iter()
            .filter(|(_, i)| {
                i.retry_after <= now
                    && i.sent
                        .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(1))
            })
            .map(|(q, i)| (i.sent, q.clone()))
            .collect();
        misses.sort_by_key(|p| p.0);
        let mut wanted = Vec::new();
        let mut seen = HashSet::new();
        // Give due renewals most slots, while reserving bounded progress for cold new destinations.
        for (_, q) in renew
            .into_iter()
            .take(if misses.is_empty() { 16 } else { 12 })
        {
            if seen.insert(q.clone()) {
                wanted.push(q);
            }
        }
        for (_, q) in misses {
            if wanted.len() >= 16 {
                break;
            }
            if seen.insert(q.clone()) {
                if let Some(i) = s.wanted.get_mut(&q) {
                    i.sent = Some(now);
                }
                wanted.push(q);
            }
        }
        Ok(serde_json::json!({"protocol":1,"sequence":self.sequence,"wanted":wanted}))
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn base(epoch: &str) -> Snapshot {
        serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(30),"sparse":{"protocol":1,"epoch":epoch},"peers":[{"id":"a","ip":"10.203.0.2","fingerprint":"local","instance":"local-instance","hostname":"a.phub"}],"grants":[]})).unwrap()
    }
    fn lease(epoch: &str) -> PairLease {
        serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","epoch":epoch,"revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(15),"local":{"id":"a","ip":"10.203.0.2","fingerprint":"local","instance":"local-instance","hostname":"a.phub"},"peer":{"id":"b","ip":"10.203.1.2","fingerprint":"remote","instance":"remote-instance","hostname":"b.phub","aliases":["alias.phub"]},"grants":[{"source":"a","destination":"b","protocol":"any","ports":[]}]})).unwrap()
    }
    #[test]
    fn miss_intents_deduplicate_and_stop_at_a_hard_bound() {
        let (h, mut c) = channel();
        h.update_base(&base(&"a".repeat(64)));
        for i in 0..256 {
            assert!(h.request_peer(&format!("peer-{i}")));
        }
        assert!(!h.request_peer("overflow"));
        assert!(h.request_peer("peer-0"));
        assert_eq!(c.batch().unwrap()["wanted"].as_array().unwrap().len(), 16);
        assert_eq!(h.state.lock().unwrap().wanted.len(), 256);
    }
    #[test]
    fn base_refresh_cannot_extend_pair_and_old_epoch_completion_is_discarded() {
        let epoch = "a".repeat(64);
        let (h, _) = channel();
        h.update_base(&base(&epoch));
        let q = Lookup {
            kind: "name".into(),
            value: "b.phub".into(),
        };
        h.installed(&q, lease(&epoch));
        let deadline = h.state.lock().unwrap().cache["b"].deadline;
        h.update_base(&base(&epoch));
        assert_eq!(h.state.lock().unwrap().cache["b"].deadline, deadline);
        h.update_base(&base(&"b".repeat(64)));
        h.installed(&q, lease(&epoch));
        assert!(h.by_id("b").is_none());
    }
    #[test]
    fn expired_pair_has_no_dns_answer_or_route_identity_even_if_base_is_valid() {
        let epoch = "a".repeat(64);
        let (h, _) = channel();
        h.update_base(&base(&epoch));
        h.installed(
            &Lookup {
                kind: "peer".into(),
                value: "b".into(),
            },
            lease(&epoch),
        );
        assert_eq!(h.by_ip("10.203.1.2".parse().unwrap()).unwrap().id, "b");
        h.state.lock().unwrap().cache.get_mut("b").unwrap().deadline =
            Instant::now() - Duration::from_secs(1);
        assert!(h.by_id("b").is_none());
        assert!(h.dns_ttl("10.203.1.2".parse().unwrap()).is_none());
    }
    #[tokio::test]
    async fn names_wait_for_packet_owner_installation_and_accept_no_early_answer() {
        let epoch = "a".repeat(64);
        let (h, mut c) = channel();
        h.update_base(&base(&epoch));
        let resolve = h.clone();
        let task = tokio::spawn(async move { resolve.resolve_name("alias.phub.").await });
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        let batch = c.batch().unwrap();
        assert_eq!(batch["wanted"][0]["kind"], "name");
        h.installed(
            &Lookup {
                kind: "name".into(),
                value: "alias.phub".into(),
            },
            lease(&epoch),
        );
        assert_eq!(task.await.unwrap().unwrap().id, "b");
    }
    #[test]
    fn authoritative_denial_retires_only_matching_pair_but_busy_and_invalid_do_not() {
        let epoch = "a".repeat(64);
        let (h, _) = channel();
        let base = base(&epoch);
        h.update_base(&base);
        let pair = lease(&epoch);
        let mut engine = porthub_network::policy::Engine::default();
        engine.apply(base).unwrap();
        engine.install_pair(pair.clone()).unwrap();
        let query = Lookup {
            kind: "peer".into(),
            value: "b".into(),
        };
        h.installed(&query, pair);
        for status in ["busy", "invalid"] {
            let response = porthub_network::policy::PairResponse {
                query: query.clone(),
                status: status.into(),
                lease: None,
            };
            assert!(apply_denial(&h, &mut engine, &response).is_none());
            assert!(engine.pair_peer("b").is_some());
        }
        let response = porthub_network::policy::PairResponse {
            query: query.clone(),
            status: "unavailable".into(),
            lease: None,
        };
        assert_eq!(apply_denial(&h, &mut engine, &response).unwrap().id, "b");
        assert!(engine.pair_peer("b").is_none());
        assert!(engine.valid_lease());
    }
    #[tokio::test]
    async fn whole_source_revocation_clears_cache_and_wakes_waiting_name_without_extending_ttl() {
        let epoch = "a".repeat(64);
        let (h, _) = channel();
        h.update_base(&base(&epoch));
        h.installed(
            &Lookup {
                kind: "peer".into(),
                value: "b".into(),
            },
            lease(&epoch),
        );
        let handle = h.clone();
        let waiting = tokio::spawn(async move { handle.resolve_name("unknown.phub").await });
        tokio::task::yield_now().await;
        h.revoke_all();
        assert!(h.revoked());
        assert!(h.peers().is_empty());
        assert!(!h.request_peer("b"));
        assert!(tokio::time::timeout(Duration::from_millis(100), waiting)
            .await
            .unwrap()
            .unwrap()
            .is_none());
    }
}
