//! Workspace and per-peer wakeups. Notifications carry no policy, names or grants.
use mongodb::bson::oid::ObjectId;
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Default)]
pub struct Changes {
    workspaces: Mutex<HashMap<ObjectId, (watch::Sender<Uuid>, Instant)>>,
    peers: Mutex<HashMap<String, (watch::Sender<Uuid>, Instant)>>,
    waiting: Mutex<HashSet<String>>,
}

impl Changes {
    pub fn changed(&self, owner: ObjectId) {
        if let Some((signal, _)) = self.workspaces.lock().unwrap().get(&owner) {
            signal.send_replace(Uuid::new_v4());
        }
    }

    pub fn subscribe(&self, owner: ObjectId) -> Option<watch::Receiver<Uuid>> {
        subscribe_to(&self.workspaces, owner, 4096)
    }

    /// Called only after the gateway accepted a newly incident private pair.
    /// Receivers already renewing the same pair generate no additional work.
    pub fn peer_ready(&self, target: &str) {
        if let Some((signal, _)) = self.peers.lock().unwrap().get(target) {
            signal.send_replace(Uuid::new_v4());
        }
    }

    pub fn subscribe_peer(&self, peer: &str) -> Option<watch::Receiver<Uuid>> {
        subscribe_to(&self.peers, peer.to_owned(), 16384)
    }

    pub fn admit<'a>(&'a self, peer: &'a str) -> Option<Waiter<'a>> {
        let mut waiting = self.waiting.lock().unwrap();
        if waiting.len() >= 16384 || !waiting.insert(peer.to_owned()) {
            return None;
        }
        Some(Waiter(self, peer))
    }
}

fn subscribe_to<K: Eq + std::hash::Hash>(
    signals: &Mutex<HashMap<K, (watch::Sender<Uuid>, Instant)>>,
    key: K,
    limit: usize,
) -> Option<watch::Receiver<Uuid>> {
    let mut entries = signals.lock().unwrap();
    if entries.len() >= limit && !entries.contains_key(&key) {
        entries.retain(|_, (tx, used)| {
            tx.receiver_count() > 0 || used.elapsed() < Duration::from_secs(120)
        });
        if entries.len() >= limit {
            return None;
        }
    }
    let (tx, used) = entries
        .entry(key)
        .or_insert_with(|| (watch::channel(Uuid::new_v4()).0, Instant::now()));
    *used = Instant::now();
    Some(tx.subscribe())
}

pub struct Waiter<'a>(&'a Changes, &'a str);
impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        self.0.waiting.lock().unwrap().remove(self.1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_pair_wakes_only_the_target_and_survives_a_gap_between_requests() {
        let changes = Changes::default();
        let owner = changes.subscribe(ObjectId::new()).unwrap();
        let other = changes.subscribe_peer("b").unwrap();
        let before = *changes.subscribe_peer("a").unwrap().borrow();
        changes.peer_ready("a");
        assert_ne!(*changes.subscribe_peer("a").unwrap().borrow(), before);
        assert!(!other.has_changed().unwrap());
        assert!(!owner.has_changed().unwrap());
    }

    #[tokio::test]
    async fn concurrent_edits_coalesce_and_only_wake_the_right_workspace() {
        let changes = Changes::default();
        let owner = ObjectId::new();
        let mut first = changes.subscribe(owner).unwrap();
        let before = *first.borrow_and_update();
        let other = changes.subscribe(ObjectId::new()).unwrap();
        changes.changed(owner);
        changes.changed(owner);
        first.changed().await.unwrap();
        assert_ne!(*first.borrow(), before);
        assert_eq!(*first.borrow(), *changes.subscribe(owner).unwrap().borrow());
        assert!(!other.has_changed().unwrap());
        let waiter = changes.admit("peer").unwrap();
        assert!(changes.admit("peer").is_none());
        drop(waiter);
        assert!(changes.admit("peer").is_some());
    }
}
