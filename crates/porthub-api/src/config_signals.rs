//! Request-owned per-machine wakeups. There are no polling tasks, and inactive
//! machines retain no strong references or timers in the notification registry.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::Notify;

#[derive(Default)]
pub struct ConfigSignals {
    entries: Mutex<HashMap<String, Weak<Notify>>>,
}
impl ConfigSignals {
    pub fn subscribe(&self, machine: &str) -> Arc<Notify> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(entry) = entries.get(machine).and_then(Weak::upgrade) {
            return entry;
        }
        if entries.len() >= 64 {
            entries.retain(|_, entry| entry.strong_count() > 0);
        }
        let entry = Arc::new(Notify::new());
        entries.insert(machine.into(), Arc::downgrade(&entry));
        entry
    }
    pub fn changed(&self, machine: &str) {
        let entry = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(machine)
            .and_then(Weak::upgrade);
        if let Some(entry) = entry {
            entry.notify_waiters();
        }
    }
}
