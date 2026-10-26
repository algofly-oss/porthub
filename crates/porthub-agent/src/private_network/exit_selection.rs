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

pub struct FlowTable<K> {
    client: String,
    peers: Vec<String>,
    mode: Selection,
    flows: HashMap<K, (String, Instant)>,
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
        if let Some((assigned, deadline)) = self.flows.get_mut(flow) {
            if assigned == peer && *deadline > now {
                *deadline = (*deadline).max(now + ttl);
            }
        }
    }

    pub fn select(&mut self, flow: K, now: Instant, ttl: Duration) -> Option<&str> {
        if now >= self.next_reap {
            self.flows.retain(|_, (_, deadline)| *deadline > now);
            self.next_reap = now + Duration::from_secs(30);
        }
        if self
            .flows
            .get(&flow)
            .is_some_and(|(_, deadline)| *deadline > now)
        {
            let (peer, deadline) = self.flows.get_mut(&flow).expect("existing flow");
            *deadline = (*deadline).max(now + ttl);
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
                .or_insert((peer, now + ttl))
                .0
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
        assert_eq!(table.flows[&1].1, now + ttl);
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
