//! Bounded exit assignments. Peer health or selection changes never move an
//! established flow to a different NAT source address.
use porthub_mesh::exit_policy::Selection;
use sha2::{Digest, Sha256};
use std::{
    collections::{hash_map::RandomState, HashMap},
    hash::{BuildHasher, Hash},
    time::{Duration, Instant},
};

// Namespace fixtures wait for the actual packet-path selection state rather
// than guessing how long the background control sync will take.
#[cfg(feature = "netns-tests")]
pub fn test_selection_updates() -> tokio::sync::watch::Receiver<Option<(Selection, usize)>> {
    test_selection_sender().subscribe()
}
#[cfg(feature = "netns-tests")]
fn test_selection_sender() -> &'static tokio::sync::watch::Sender<Option<(Selection, usize)>> {
    static STATE: std::sync::OnceLock<tokio::sync::watch::Sender<Option<(Selection, usize)>>> = std::sync::OnceLock::new();
    STATE.get_or_init(|| tokio::sync::watch::channel(None).0)
}

struct Assignment {
    peer: String,
    deadline: Instant,
    syn_sequence: Option<u32>,
    fin_directions: u8,
    close_until: Option<Instant>,
}
impl Assignment {
    fn refresh(&mut self, now: Instant, ttl: Duration) {
        self.deadline = self.deadline.max(now + ttl);
        if let Some(limit) = self.close_until { self.deadline = self.deadline.min(limit); }
    }
}

pub struct FlowTable<K> {
    client: String,
    peers: Vec<String>,
    mode: Selection,
    flows: HashMap<K, Assignment>,
    cursor: u64,
    random: RandomState,
    next_reap: Instant,
    capacity: usize,
}

impl<K: Eq + Hash> FlowTable<K> {
    pub fn new(client: String) -> Self {
        Self {
            client,
            peers: Vec::new(),
            mode: Selection::Sticky,
            flows: HashMap::new(),
            cursor: 0,
            random: RandomState::new(),
            next_reap: Instant::now(),
            capacity: 65_536,
        }
    }

    /// Called by the control/health task, never by a connectivity probe on the
    /// packet path. Sorting makes round robin independent of report ordering.
    pub fn configure(&mut self, peers: impl IntoIterator<Item = String>, mode: Selection) {
        self.peers = peers.into_iter().collect();
        self.peers.sort();
        self.peers.dedup();
        self.mode = mode;
        #[cfg(feature = "netns-tests")]
        test_selection_sender().send_replace(Some((mode, self.peers.len())));
    }

    /// Refresh only an authenticated reply from the assigned exit. Never
    /// create an assignment from unsolicited incoming packets.
    pub fn observe(&mut self, flow: &K, peer: &str, now: Instant, ttl: Duration) {
        if let Some(entry) = self.flows.get_mut(flow) {
            if entry.peer == peer && entry.deadline > now { entry.refresh(now, ttl); }
        }
    }

    /// Call only after policy validation. A single FIN is a half-close and
    /// must not expire a stream that continues transferring in the other direction.
    pub fn observe_close(&mut self, flow: &K, peer: &str, outgoing: bool, fin: bool, reset: bool, now: Instant) {
        if !fin && !reset { return; }
        if let Some(entry) = self.flows.get_mut(flow) {
            if entry.peer != peer || entry.deadline <= now { return; }
            if fin { entry.fin_directions |= if outgoing { 1 } else { 2 }; }
            if reset || entry.fin_directions == 3 {
                let until = *entry.close_until.get_or_insert(now + Duration::from_secs(120));
                entry.deadline = entry.deadline.min(until);
            }
        }
    }

    pub fn select(&mut self, flow: K, now: Instant, ttl: Duration) -> Option<&str> {
        self.select_with_syn(flow, now, ttl, None)
    }

    pub fn select_with_syn(&mut self, flow: K, now: Instant, ttl: Duration, syn_sequence: Option<u32>) -> Option<&str> {
        if now >= self.next_reap {
            self.flows.retain(|_, entry| entry.deadline > now);
            self.next_reap = now + Duration::from_secs(30);
        }
        // A new SYN sequence is a new TCP connection even when its four-tuple
        // is reused. Retransmissions of the original SYN retain the same exit.
        if syn_sequence.is_some() && self.flows.get(&flow).is_some_and(|entry| entry.syn_sequence != syn_sequence || entry.close_until.is_some()) {
            self.flows.remove(&flow);
        }
        if self.flows.get(&flow).is_some_and(|entry| entry.deadline > now) {
            let entry = self.flows.get_mut(&flow).expect("existing flow");
            entry.refresh(now, ttl);
            let peer = &entry.peer;
            // Keep the assignment through temporary unavailability. A new
            // exit would silently invalidate TCP's externally visible tuple.
            return self
                .peers
                .binary_search(peer)
                .is_ok()
                .then_some(peer.as_str());
        }
        self.flows.remove(&flow);
        if self.peers.is_empty() || self.flows.len() >= self.capacity {
            return None;
        }
        let index = match self.mode {
            Selection::Sticky => self
                .peers
                .iter()
                .enumerate()
                .max_by_key(|(_, peer)| {
                    let mut hash = Sha256::new();
                    hash.update((self.client.len() as u64).to_be_bytes());
                    hash.update(self.client.as_bytes());
                    hash.update(peer.as_bytes());
                    hash.finalize()
                })
                .map(|(index, _)| index)?,
            Selection::RoundRobin => (self.cursor % self.peers.len() as u64) as usize,
            Selection::Random => {
                (self.random.hash_one((&flow, self.cursor)) % self.peers.len() as u64) as usize
            }
        };
        self.cursor = self.cursor.wrapping_add(1);
        let peer = self.peers[index].clone();
        Some(
            self.flows
                .entry(flow)
                .or_insert(Assignment { peer, deadline: now + ttl, syn_sequence, fin_directions: 0, close_until: None })
                .peer
                .as_str(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peers() -> Vec<String> {
        vec!["luna".into(), "condor".into()]
    }

    #[test]
    fn new_connections_alternate_but_existing_connections_keep_their_exit() {
        let mut table = FlowTable::new("miro".into());
        table.configure(peers(), Selection::RoundRobin);
        let now = Instant::now();
        let ttl = Duration::from_secs(300);
        assert_eq!(table.select(1, now, ttl), Some("condor"));
        assert_eq!(table.select(2, now, ttl), Some("luna"));
        assert_eq!(table.select(1, now, ttl), Some("condor"));
        assert_eq!(table.select(3, now, ttl), Some("condor"));
        table.configure(vec!["luna".into()], Selection::Random);
        assert_eq!(table.select(1, now, ttl), None);
        assert_eq!(table.select(4, now, ttl), Some("luna"));
        table.configure(peers(), Selection::Sticky);
        assert_eq!(table.select(1, now, ttl), Some("condor"));
        assert_eq!(table.select(2, now, ttl), Some("luna"));
    }

    #[test]
    fn sticky_is_stable_across_flows_restarts_and_peer_order() {
        let now = Instant::now();
        let ttl = Duration::from_secs(300);
        let mut a = FlowTable::new("miro".into());
        a.configure(peers(), Selection::Sticky);
        let expected = a.select(1, now, ttl).unwrap().to_owned();
        for flow in 2..100 {
            assert_eq!(a.select(flow, now, ttl), Some(expected.as_str()));
        }
        let mut b = FlowTable::new("miro".into());
        b.configure(peers().into_iter().rev(), Selection::Sticky);
        assert_eq!(b.select(100, now, ttl), Some(expected.as_str()));
    }

    #[test]
    fn random_selection_is_pinned_and_uses_only_configured_peers() {
        let mut table = FlowTable::new("miro".into());
        table.configure(peers(), Selection::Random);
        let now = Instant::now();
        let ttl = Duration::from_secs(300);
        for flow in 0..1024 {
            let assigned = table.select(flow, now, ttl).unwrap().to_owned();
            assert!(assigned == "luna" || assigned == "condor");
            assert_eq!(table.select(flow, now, ttl), Some(assigned.as_str()));
        }
    }

    #[test]
    fn no_healthy_exit_does_not_reassign_existing_connections() {
        let mut table = FlowTable::new("miro".into());
        table.configure(peers(), Selection::RoundRobin);
        let now = Instant::now();
        let ttl = Duration::from_secs(300);
        let assigned = table.select(1, now, ttl).unwrap().to_owned();
        table.configure(Vec::new(), Selection::RoundRobin);
        assert_eq!(table.select(1, now, ttl), None);
        assert_eq!(table.select(2, now, ttl), None);
        table.configure(peers(), Selection::RoundRobin);
        assert_eq!(table.select(1, now, ttl), Some(assigned.as_str()));
        assert_eq!(table.select(2, now, ttl), Some("luna"));
    }

    #[test]
    fn authenticated_replies_refresh_pins_without_creating_or_moving_them() {
        let mut table = FlowTable::new("miro".into());
        table.configure(peers(), Selection::RoundRobin);
        let now = Instant::now();
        let ttl = Duration::from_secs(30);
        assert_eq!(table.select(1, now, ttl), Some("condor"));
        table.observe(&1, "luna", now + Duration::from_secs(20), ttl);
        assert_eq!(table.flows[&1].deadline, now + ttl);
        table.observe(&2, "condor", now, ttl);
        assert!(!table.flows.contains_key(&2));
        table.observe(&1, "condor", now + Duration::from_secs(20), ttl);
        assert_eq!(table.select(1, now + Duration::from_secs(40), ttl), Some("condor"));
        let long = Duration::from_secs(5 * 86400);
        table.observe(&1, "condor", now + Duration::from_secs(40), long);
        // A retransmitted handshake must not shorten an established pin.
        assert_eq!(table.select(1, now + Duration::from_secs(41), ttl), Some("condor"));
        assert_eq!(table.select(1, now + Duration::from_secs(3600), long), Some("condor"));
    }

    #[test]
    fn reused_tcp_tuple_rotates_only_for_a_new_connection() {
        let mut table = FlowTable::new("miro".into());
        table.configure(peers(), Selection::RoundRobin);
        let now = Instant::now();
        let ttl = Duration::from_secs(300);
        assert_eq!(table.select_with_syn(1, now, ttl, Some(100)), Some("condor"));
        assert_eq!(table.select_with_syn(1, now, ttl, Some(100)), Some("condor"));
        assert_eq!(table.select_with_syn(1, now, ttl, Some(200)), Some("luna"));
        table.observe_close(&1, "luna", true, false, true, now);
        assert_eq!(table.select_with_syn(1, now, ttl, Some(200)), Some("condor"));
    }

    #[test]
    fn half_closed_stream_stays_pinned_but_closed_stream_releases_capacity() {
        let mut table = FlowTable::new("miro".into());
        table.capacity = 1;
        table.configure(peers(), Selection::RoundRobin);
        let now = Instant::now();
        let ttl = Duration::from_secs(5 * 86400);
        assert_eq!(table.select_with_syn(1, now, ttl, Some(100)), Some("condor"));
        table.observe_close(&1, "condor", true, true, false, now);
        let later = now + Duration::from_secs(3600);
        table.observe(&1, "condor", later, ttl);
        assert_eq!(table.select(1, later, ttl), Some("condor"));
        table.observe_close(&1, "luna", false, true, false, later);
        assert!(table.flows[&1].close_until.is_none());
        table.observe_close(&1, "condor", false, true, false, later);
        table.observe(&1, "condor", later + Duration::from_secs(60), ttl);
        assert_eq!(table.flows[&1].deadline, later + Duration::from_secs(120));
        assert_eq!(table.select(2, later + Duration::from_secs(121), ttl), Some("luna"));
        assert_eq!(table.flows.len(), 1);
    }

    #[test]
    fn capacity_is_bounded_and_expired_flows_are_reclaimed() {
        let mut table = FlowTable::new("miro".into());
        table.capacity = 2;
        table.configure(peers(), Selection::RoundRobin);
        let now = Instant::now();
        let ttl = Duration::from_secs(1);
        assert!(table.select(1, now, ttl).is_some());
        assert!(table.select(2, now, ttl).is_some());
        assert!(table.select(3, now, ttl).is_none());
        assert!(table
            .select(3, now + Duration::from_secs(31), ttl)
            .is_some());
        assert_eq!(table.flows.len(), 1);
    }
}

/// Debounce transport churn without probing on the packet path. Policy expiry
/// or withdrawing permission closes bypass immediately.
#[derive(Default)]
pub struct Fallback {
    bypass: bool,
    candidate: Option<(bool, Instant)>,
}
impl Fallback {
    pub fn update(&mut self, allowed: bool, available: usize, valid: bool, now: Instant) -> bool {
        if !allowed || !valid {
            self.bypass = false;
            self.candidate = None;
            return false;
        }
        let wanted = available == 0;
        if wanted == self.bypass { self.candidate = None; }
        else {
            let (candidate, since) = self.candidate.get_or_insert((wanted, now));
            if *candidate != wanted { *candidate = wanted; *since = now; }
            if now.saturating_duration_since(*since) >= Duration::from_secs(5) {
                self.bypass = wanted;
                self.candidate = None;
            }
        }
        self.bypass
    }
}

#[cfg(test)]
mod fallback_tests {
    use super::*;
    #[test]
    fn bypass_requires_permission_stable_outage_and_a_valid_policy() {
        let mut state = Fallback::default();
        let now = Instant::now();
        assert!(!state.update(false, 0, true, now));
        assert!(!state.update(true, 0, true, now));
        assert!(!state.update(true, 1, true, now + Duration::from_secs(4)));
        assert!(!state.update(true, 0, true, now + Duration::from_secs(5)));
        assert!(state.update(true, 0, true, now + Duration::from_secs(10)));
        assert!(state.update(true, 1, true, now + Duration::from_secs(11)));
        assert!(!state.update(true, 1, true, now + Duration::from_secs(16)));
        assert!(!state.update(true, 0, true, now + Duration::from_secs(17)));
        assert!(state.update(true, 0, true, now + Duration::from_secs(22)));
        assert!(!state.update(true, 0, false, now + Duration::from_secs(23)));
        assert!(!state.update(true, 0, true, now + Duration::from_secs(24)));
        assert!(state.update(true, 0, true, now + Duration::from_secs(29)));
        assert!(!state.update(false, 0, true, now + Duration::from_secs(30)));
    }
}
