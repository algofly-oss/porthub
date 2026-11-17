//! Thirty-second batched telemetry. Packet paths only touch bounded atomics.
//! A protected bounded pending journal survives worker/host restarts. Overflow is
//! explicit; it never blocks private transport or fabricates historical bytes.
use anyhow::{ensure, Result};
use porthub_mesh::traffic_report::{Report, Row, MAX_COUNTER, MAX_PENDING, MAX_ROWS};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};
#[derive(Default)]
pub struct Counters([AtomicU64; 4]);
impl Counters {
    pub fn add(&self, sent: bool, direct: bool, bytes: usize) {
        let i = match (direct, sent) {
            (true, true) => 0,
            (true, false) => 1,
            (false, true) => 2,
            (false, false) => 3,
        };
        let _ = self.0[i].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            Some(n.saturating_add(bytes as u64).min(MAX_COUNTER))
        });
    }
    fn take(&self) -> [u64; 4] {
        std::array::from_fn(|i| self.0[i].swap(0, Ordering::Relaxed))
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    instance: String,
    next: u64,
    dropped_rows: u64,
    pending: VecDeque<Row>,
}
struct State {
    journal: Journal,
    last: Instant,
    last_wall: i64,
    last_report: Option<Instant>,
    enabled: bool,
    dirty: bool,
    durable_sequence: u64,
}
pub struct Tracker {
    path: PathBuf,
    peers: RwLock<HashMap<String, (Arc<Counters>, bool)>>,
    state: Mutex<State>,
}
impl Tracker {
    pub fn new(profile: &Path) -> Arc<Self> {
        let path = crate::profile::sibling(profile, ".private-traffic.json");
        let loaded = Self::load(&path);
        let (journal, enabled) = match loaded {
            Ok(Some(j)) => (j, true),
            Ok(None) => (
                Journal {
                    instance: uuid::Uuid::new_v4().simple().to_string(),
                    next: 1,
                    dropped_rows: 0,
                    pending: VecDeque::new(),
                },
                true,
            ),
            Err(_) => (
                Journal {
                    instance: String::new(),
                    next: 1,
                    dropped_rows: 0,
                    pending: VecDeque::new(),
                },
                false,
            ),
        };
        let durable_sequence = journal.next - 1;
        Arc::new(Self {
            path,
            peers: RwLock::new(HashMap::new()),
            state: Mutex::new(State {
                journal,
                last: Instant::now(),
                last_wall: chrono::Utc::now().timestamp_millis(),
                last_report: None,
                enabled,
                dirty: false,
                durable_sequence,
            }),
        })
    }
    fn load(path: &Path) -> Result<Option<Journal>> {
        if !path.try_exists()? {
            return Ok(None);
        }
        let bytes = crate::profile::read_private(path)?;
        ensure!(
            bytes.len() <= 4 * 1024 * 1024,
            "private traffic journal too large"
        );
        let j: Journal = serde_json::from_slice(&bytes)?;
        ensure!(
            j.dropped_rows <= MAX_COUNTER
                && j.pending.len() <= MAX_PENDING
                && j.next > 0
                && j.next <= MAX_COUNTER
                && j.pending.iter().all(Row::valid)
                && j.pending
                    .iter()
                    .zip(j.pending.iter().skip(1))
                    .all(|(a, b)| a.sequence < b.sequence)
                && j.pending.back().is_none_or(|r| r.sequence < j.next)
                && j.instance.len() == 32
                && j.instance.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid private traffic journal"
        );
        Ok(Some(j))
    }
    pub fn reconcile(&self, ids: impl Iterator<Item = String>) -> HashMap<String, Arc<Counters>> {
        let mut peers = self.peers.write().unwrap_or_else(|e| e.into_inner());
        for value in peers.values_mut() {
            value.1 = false;
        }
        let mut current = HashMap::new();
        let mut untracked = 0_u64;
        for id in ids.take(4096) {
            if porthub_mesh::traffic_report::peer_id(&id) {
                if let Some((counter, active)) = peers.get_mut(&id) {
                    *active = true;
                    current.insert(id, counter.clone());
                } else if peers.len() < 8192 {
                    let counter = Arc::new(Counters::default());
                    peers.insert(id.clone(), (counter.clone(), true));
                    current.insert(id, counter);
                } else {
                    untracked += 1;
                }
            }
        }
        drop(peers);
        if untracked > 0 {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.journal.dropped_rows = state
                .journal
                .dropped_rows
                .saturating_add(untracked)
                .min(MAX_COUNTER);
            state.dirty = true;
        }
        current
    }
    pub fn counter(&self, peer: &str) -> Option<Arc<Counters>> {
        self.peers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(peer)
            .map(|v| v.0.clone())
    }
    pub async fn run(self: Arc<Self>, cancel: tokio_util::sync::CancellationToken) {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        tick.tick().await;
        loop {
            let final_sample = tokio::select! {_=cancel.cancelled()=>true,_=tick.tick()=>false};
            let tracker = self.clone();
            if tokio::task::spawn_blocking(move || tracker.sample())
                .await
                .is_err()
            {
                break;
            }
            if final_sample {
                break;
            }
        }
    }
    pub(super) fn sample(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !state.enabled {
            return;
        }
        let elapsed = state.last.elapsed().as_secs();
        let duration = elapsed.clamp(1, 120) as u32;
        let observed_at = chrono::Utc::now().timestamp_millis();
        let start = state.last_wall;
        state.last_wall = observed_at;
        let invalid_interval =
            elapsed > 120 || observed_at < start || observed_at - start > 180_000;
        state.last = Instant::now();
        let now = start.div_euclid(60_000) * 60_000;
        let mut peers = self.peers.write().unwrap_or_else(|e| e.into_inner());
        for (peer, (counter, _)) in peers.iter() {
            let v = counter.take();
            if v == [0; 4] {
                continue;
            }
            if invalid_interval {
                state.journal.dropped_rows = state
                    .journal
                    .dropped_rows
                    .saturating_add(1)
                    .min(MAX_COUNTER);
                state.dirty = true;
                continue;
            }
            if state.journal.next >= MAX_COUNTER {
                state.enabled = false;
                return;
            }
            if state.journal.pending.len() == MAX_PENDING {
                state.journal.pending.pop_front();
                state.journal.dropped_rows = state
                    .journal
                    .dropped_rows
                    .saturating_add(1)
                    .min(MAX_COUNTER);
            }
            let sequence = state.journal.next;
            state.journal.next += 1;
            state.journal.pending.push_back(Row {
                sequence,
                peer_id: peer.clone(),
                at: now,
                duration_seconds: duration,
                observed_at,
                direct_sent: v[0],
                direct_received: v[1],
                relay_sent: v[2],
                relay_received: v[3],
            });
            state.dirty = true;
        }
        peers.retain(|_, (_, active)| *active);
        drop(peers);
        if !state.dirty {
            return;
        }
        let (bytes, sequence) = match Self::encoded(&mut state.journal) {
            Ok(bytes) => (bytes, state.journal.next - 1),
            Err(_) => {
                state.enabled = false;
                return;
            }
        };
        state.dirty = false;
        drop(state);
        // No peer/state lock is held across disk IO. Sync uses try_lock and
        // only exposes observations whose successful durable write completed.
        let result = crate::profile::write_private(&self.path, &bytes, true);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if result.is_err() {
            state.enabled = false;
        } else {
            state.durable_sequence = state.durable_sequence.max(sequence);
        }
    }
    fn encoded(journal: &mut Journal) -> Result<Vec<u8>> {
        loop {
            let bytes = serde_json::to_vec(journal)?;
            if bytes.len() <= 4 * 1024 * 1024 {
                return Ok(bytes);
            }
            ensure!(
                !journal.pending.is_empty(),
                "private traffic metadata exceeds byte budget"
            );
            // Evict a bounded chunk and explicitly account for it. Both reader
            // and writer use the SAME 4MiB hard limit.
            let count = journal.pending.len().min(64);
            journal.pending.drain(..count);
            journal.dropped_rows = journal
                .dropped_rows
                .saturating_add(count as u64)
                .min(MAX_COUNTER);
        }
    }
    /// Called from existing sync, never from the packet hot path. First persist
    /// immutable observations, then return a bounded retryable upload batch.
    pub fn report(&self) -> Option<Report> {
        let Ok(mut state) = self.state.try_lock() else {
            return None;
        };
        if !state.enabled
            || state
                .last_report
                .is_some_and(|at| at.elapsed() < Duration::from_secs(30))
        {
            return None;
        }
        state.last_report = Some(Instant::now());
        Some(Report {
            instance: state.journal.instance.clone(),
            rows: state
                .journal
                .pending
                .iter()
                .take_while(|row| row.sequence <= state.durable_sequence)
                .take(MAX_ROWS)
                .cloned()
                .collect(),
            dropped_rows: state.journal.dropped_rows,
        })
    }
    pub fn acknowledge(&self, sequence: u64, discarded: u64) {
        let Ok(mut state) = self.state.try_lock() else {
            return;
        };
        if !state.enabled || sequence == 0 || sequence >= state.journal.next {
            return;
        }
        if state
            .journal
            .pending
            .front()
            .is_none_or(|r| r.sequence > sequence)
        {
            return;
        }
        let before = state.journal.pending.len();
        while state
            .journal
            .pending
            .front()
            .is_some_and(|r| r.sequence <= sequence)
        {
            state.journal.pending.pop_front();
        }
        let removed = before - state.journal.pending.len();
        state.journal.dropped_rows = state
            .journal
            .dropped_rows
            .saturating_add(discarded.min(removed as u64))
            .min(MAX_COUNTER);
        state.dirty = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer(n: char) -> String {
        format!("{}:{}", "a".repeat(24), n.to_string().repeat(24))
    }
    fn fresh() -> (tempfile::TempDir, Arc<Tracker>) {
        let dir = tempfile::Builder::new()
            .prefix("porthub-traffic-")
            .permissions({
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::Permissions::from_mode(0o700)
                }
                #[cfg(not(unix))]
                {
                    std::fs::metadata(std::env::temp_dir())
                        .unwrap()
                        .permissions()
                }
            })
            .tempdir()
            .unwrap();
        let tracker = Tracker::new(&dir.path().join("profile.json"));
        (dir, tracker)
    }
    #[test]
    fn journal_retry_restart_ack_and_idle_writes_are_bounded() {
        let (dir, tracker) = fresh();
        let p = peer('b');
        let counters = tracker.reconcile([p.clone()].into_iter());
        counters[&p].add(true, true, 4096);
        tracker.sample();
        let bytes = crate::profile::read_private(&tracker.path).unwrap();
        let first = tracker.report().unwrap();
        assert_eq!(first.rows.len(), 1);
        assert_eq!(first.rows[0].direct_sent, 4096);
        assert!(first.valid());
        assert!(
            tracker.report().is_none(),
            "sync polling must not repeat an unchanged batch faster than30s"
        );
        tracker.sample();
        assert_eq!(
            crate::profile::read_private(&tracker.path).unwrap(),
            bytes,
            "idle sampler must not rewrite journal"
        );
        let restarted = Tracker::new(&dir.path().join("profile.json"));
        let retry = restarted.report().unwrap();
        assert_eq!(first.instance, retry.instance);
        assert_eq!(first.rows, retry.rows);
        restarted.acknowledge(retry.rows[0].sequence, 0);
        restarted.sample();
        let again = Tracker::new(&dir.path().join("profile.json"));
        assert!(again.report().unwrap().rows.is_empty());
    }
    #[test]
    fn retired_peer_is_drained_and_churn_does_not_fill_live_slots() {
        let (_dir, tracker) = fresh();
        let p = peer('b');
        let c = tracker.reconcile([p.clone()].into_iter());
        c[&p].add(false, false, 128);
        tracker.reconcile(std::iter::empty());
        tracker.sample();
        assert!(tracker.counter(&p).is_none());
        assert_eq!(tracker.report().unwrap().rows[0].relay_received, 128);
    }
    #[test]
    fn exact_byte_budget_evicts_with_visible_loss_and_remains_restart_readable() {
        let (_dir, tracker) = fresh();
        let p = peer('b');
        let mut state = tracker.state.lock().unwrap();
        for sequence in 1..=MAX_PENDING as u64 {
            state.journal.pending.push_back(Row {
                sequence,
                peer_id: p.clone(),
                at: 60_000,
                observed_at: 90_000,
                duration_seconds: 30,
                direct_sent: MAX_COUNTER,
                direct_received: MAX_COUNTER,
                relay_sent: MAX_COUNTER,
                relay_received: MAX_COUNTER,
            });
        }
        state.journal.next = MAX_PENDING as u64 + 1;
        let before = state.journal.pending.len();
        let bytes = Tracker::encoded(&mut state.journal).unwrap();
        assert!(bytes.len() <= 4 * 1024 * 1024);
        assert!(state.journal.pending.len() <= before);
        assert_eq!(
            state.journal.dropped_rows,
            (before - state.journal.pending.len()) as u64
        );
        crate::profile::write_private(&tracker.path, &bytes, true).unwrap();
        drop(state);
        assert!(Tracker::load(&tracker.path).unwrap().is_some());
    }
    #[test]
    fn malformed_journal_is_not_reset_and_clock_gap_is_explicit_loss() {
        let (_dir, tracker) = fresh();
        crate::profile::write_private(&tracker.path, b"malformed", true).unwrap();
        assert!(Tracker::new(&tracker.path.with_file_name("profile.json"))
            .report()
            .is_none());
        let too_large = vec![b' '; 4 * 1024 * 1024 + 1];
        crate::profile::write_private(&tracker.path, &too_large, true).unwrap();
        assert!(Tracker::load(&tracker.path).is_err());
        assert_eq!(
            std::fs::metadata(&tracker.path).unwrap().len(),
            too_large.len() as u64,
            "oversized journal must not be silently reset"
        );
        let (_dir, tracker) = fresh();
        let p = peer('b');
        let c = tracker.reconcile([p.clone()].into_iter());
        c[&p].add(true, true, 99);
        tracker.state.lock().unwrap().last_wall = chrono::Utc::now().timestamp_millis() + 120_000;
        tracker.sample();
        let report = tracker.report().unwrap();
        assert!(report.rows.is_empty());
        assert_eq!(report.dropped_rows, 1);
    }
    #[test]
    fn packet_counter_does_not_wait_for_journal_state_or_peer_locks() {
        let (_dir, tracker) = fresh();
        let p = peer('b');
        let c = tracker.reconcile([p.clone()].into_iter());
        let _journal = tracker.state.lock().unwrap();
        let _peers = tracker.peers.write().unwrap();
        c[&p].add(true, true, 64);
        assert_eq!(c[&p].take()[0], 64);
    }
}
