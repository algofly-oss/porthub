//! Per-attachment snapshot ownership. Slow captures cannot resurrect a detached
//! guest or replace a newer refresh, and quota pressure never evicts live pages.
use super::Snapshot;
use crate::protocol::{history_request, random_token, token, MAX_VIEWERS};
use anyhow::{ensure, Result};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub struct CaptureReservation {
    cache: String,
    client: u64,
    epoch: u64,
}
struct Retained {
    snapshot: Snapshot,
    accessed: Instant,
}
#[derive(Default)]
struct Entry {
    pending: Option<u64>,
    retained: Option<Retained>,
}

pub struct SnapshotCache {
    identity: String,
    entries: BTreeMap<u64, Entry>,
    epoch: u64,
    used: usize,
    limit: usize,
    idle: Duration,
}
impl Default for SnapshotCache {
    fn default() -> Self {
        Self::new(128 * 1024 * 1024, Duration::from_secs(600)).expect("valid snapshot limits")
    }
}
impl SnapshotCache {
    pub fn new(limit: usize, idle: Duration) -> Result<Self> {
        ensure!(
            limit > 0 && !idle.is_zero(),
            "invalid history snapshot limits"
        );
        Ok(Self {
            identity: random_token(16),
            entries: BTreeMap::new(),
            epoch: 0,
            used: 0,
            limit,
            idle,
        })
    }
    pub fn storage_bytes(&self) -> usize {
        self.used
    }
    pub fn attach(&mut self, client: u64) -> Result<()> {
        ensure!(
            self.entries.len() < MAX_VIEWERS && !self.entries.contains_key(&client),
            "invalid snapshot attachment"
        );
        self.entries.insert(client, Entry::default());
        Ok(())
    }
    pub fn detach(&mut self, client: u64) {
        if let Some(entry) = self.entries.remove(&client) {
            if let Some(retained) = entry.retained {
                self.used -= retained.snapshot.storage_bytes();
            }
        }
    }
    pub fn reap(&mut self, now: Instant) {
        for entry in self.entries.values_mut() {
            if entry
                .retained
                .as_ref()
                .is_some_and(|value| now.saturating_duration_since(value.accessed) >= self.idle)
            {
                self.used -= entry
                    .retained
                    .take()
                    .expect("retained snapshot")
                    .snapshot
                    .storage_bytes();
            }
        }
    }
    /// Called before spawning a bounded capture outside the cache lock. The
    /// previous snapshot remains available if capture or quota admission fails.
    pub fn begin(&mut self, client: u64) -> Result<CaptureReservation> {
        let entry = self
            .entries
            .get_mut(&client)
            .ok_or_else(|| anyhow::anyhow!("history guest detached"))?;
        self.epoch = self
            .epoch
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("snapshot generation exhausted"))?;
        entry.pending = Some(self.epoch);
        Ok(CaptureReservation {
            cache: self.identity.clone(),
            client,
            epoch: self.epoch,
        })
    }
    pub fn install(
        &mut self,
        reservation: CaptureReservation,
        snapshot: Snapshot,
        now: Instant,
    ) -> Result<()> {
        ensure!(
            reservation.cache == self.identity,
            "history capture belongs to another attachment generation"
        );
        self.reap(now);
        let entry = self
            .entries
            .get_mut(&reservation.client)
            .ok_or_else(|| anyhow::anyhow!("history guest detached"))?;
        ensure!(
            entry.pending == Some(reservation.epoch),
            "history capture superseded"
        );
        let previous = entry
            .retained
            .as_ref()
            .map_or(0, |value| value.snapshot.storage_bytes());
        let next = self.used - previous;
        let next = next
            .checked_add(snapshot.storage_bytes())
            .ok_or_else(|| anyhow::anyhow!("snapshot quota exceeded"))?;
        ensure!(
            next <= self.limit,
            "history snapshot storage is busy; try again after another viewer releases history"
        );
        entry.retained = Some(Retained {
            snapshot,
            accessed: now,
        });
        entry.pending = None;
        self.used = next;
        Ok(())
    }
    pub fn get(
        &mut self,
        client: u64,
        identity: &str,
        pane: &str,
        now: Instant,
    ) -> Result<Snapshot> {
        ensure!(token(identity, 32), "invalid history snapshot identity");
        history_request(pane, 0, 1)?;
        self.reap(now);
        let retained = self
            .entries
            .get_mut(&client)
            .and_then(|entry| entry.retained.as_mut())
            .ok_or_else(|| anyhow::anyhow!("history snapshot expired; refresh history"))?;
        ensure!(
            retained.snapshot.id() == identity
                && (pane.is_empty() || pane == retained.snapshot.pane()),
            "history snapshot unavailable; refresh history"
        );
        retained.accessed = now;
        Ok(retained.snapshot.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot(text: &str) -> Snapshot {
        Snapshot::new("%0".into(), text.as_bytes().into()).unwrap()
    }

    #[test]
    fn ownership_and_generation_fence_detach_and_out_of_order_refreshes() -> Result<()> {
        let now = Instant::now();
        let mut cache = SnapshotCache::default();
        cache.attach(1)?;
        cache.attach(2)?;
        let stale = cache.begin(1)?;
        cache.detach(1);
        cache.attach(1)?;
        let current = cache.begin(1)?;
        assert!(cache.install(stale, snapshot("old\n"), now).is_err());
        let retained = snapshot("new\n");
        let id = retained.id().to_owned();
        cache.install(current, retained, now)?;
        assert!(cache.get(2, &id, "%0", now).is_err());
        assert!(cache.get(1, &id, "%1", now).is_err());
        let earlier = cache.begin(1)?;
        let later = cache.begin(1)?;
        let replacement = snapshot("latest\n");
        let latest = replacement.id().to_owned();
        cache.install(later, replacement, now)?;
        assert!(cache.install(earlier, snapshot("stale\n"), now).is_err());
        assert_eq!(
            cache.get(1, &latest, "", now)?.page(0, 1)?.bytes,
            b"latest\n"
        );
        assert!(cache.get(1, &id, "", now).is_err());
        Ok(())
    }

    #[test]
    fn reservations_cannot_cross_cache_generations() -> Result<()> {
        let mut previous = SnapshotCache::default();
        let mut current = SnapshotCache::default();
        previous.attach(1)?;
        current.attach(1)?;
        let old = previous.begin(1)?;
        let own = current.begin(1)?;
        assert!(current
            .install(old, snapshot("old\n"), Instant::now())
            .is_err());
        current.install(own, snapshot("current\n"), Instant::now())?;
        Ok(())
    }

    #[test]
    fn quota_failure_preserves_readers_until_detach_frees_storage() -> Result<()> {
        let now = Instant::now();
        let a = snapshot("alpha\n");
        let b = snapshot("beta\n");
        let mut cache = SnapshotCache::new(
            a.storage_bytes() + b.storage_bytes() - 1,
            Duration::from_secs(60),
        )?;
        cache.attach(1)?;
        cache.attach(2)?;
        let id = a.id().to_owned();
        let reservation = cache.begin(1)?;
        cache.install(reservation, a, now)?;
        let reservation = cache.begin(2)?;
        assert!(cache.install(reservation, b.clone(), now).is_err());
        assert_eq!(cache.get(1, &id, "", now)?.page(0, 1)?.bytes, b"alpha\n");
        cache.detach(1);
        assert_eq!(cache.storage_bytes(), 0);
        let reservation = cache.begin(2)?;
        cache.install(reservation, b.clone(), now)?;
        assert_eq!(cache.storage_bytes(), b.storage_bytes());
        Ok(())
    }

    #[test]
    fn active_paging_renews_idle_expiry_and_expired_ids_never_silently_refresh() -> Result<()> {
        let now = Instant::now();
        let mut cache = SnapshotCache::new(1024, Duration::from_secs(3))?;
        cache.attach(1)?;
        let data = snapshot("retained\n");
        let id = data.id().to_owned();
        let reservation = cache.begin(1)?;
        cache.install(reservation, data, now)?;
        cache.get(1, &id, "", now + Duration::from_secs(2))?;
        cache.get(1, &id, "", now + Duration::from_secs(4))?;
        cache.reap(now + Duration::from_secs(8));
        assert_eq!(cache.storage_bytes(), 0);
        assert!(cache.get(1, &id, "", now + Duration::from_secs(8)).is_err());
        assert!(cache.begin(2).is_err());
        assert!(SnapshotCache::new(0, Duration::from_secs(1)).is_err());
        Ok(())
    }
}
