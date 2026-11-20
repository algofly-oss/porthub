//! Workspace-scoped wakeups. Notifications carry no policy, names or grants.
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
    waiting: Mutex<HashSet<String>>,
}

impl Changes {
    pub fn changed(&self, owner: ObjectId) {
        if let Some((signal, _)) = self.workspaces.lock().unwrap().get(&owner) {
            signal.send_replace(Uuid::new_v4());
        }
    }

    pub fn subscribe(&self, owner: ObjectId) -> Option<watch::Receiver<Uuid>> {
        let mut entries = self.workspaces.lock().unwrap();
        if entries.len() >= 4096 && !entries.contains_key(&owner) {
            entries.retain(|_, (tx, used)| {
                tx.receiver_count() > 0 || used.elapsed() < Duration::from_secs(120)
            });
            if entries.len() >= 4096 {
                return None;
            }
        }
        let (tx, used) = entries
            .entry(owner)
            .or_insert_with(|| (watch::channel(Uuid::new_v4()).0, Instant::now()));
        *used = Instant::now();
        Some(tx.subscribe())
    }

    pub fn admit<'a>(&'a self, peer: &'a str) -> Option<Waiter<'a>> {
        let mut waiting = self.waiting.lock().unwrap();
        if waiting.len() >= 16384 || !waiting.insert(peer.to_owned()) {
            return None;
        }
        Some(Waiter(self, peer))
    }
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
