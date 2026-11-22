//! Native filesystem/volume calls can block indefinitely in a driver. They must
//! not run on a Tokio executor thread used by control heartbeats.
use porthub_components::metrics::{Disk, Memory};
use std::time::Instant;

pub(super) type Snapshot = (Vec<Disk>, Memory);

const MAX_AGE: std::time::Duration = std::time::Duration::from_secs(30);
struct Pending<T> {
    receive: tokio::sync::oneshot::Receiver<T>,
    started: Instant,
    discard: bool,
}
pub(super) struct Sampler<T> {
    pending: Option<Pending<T>>,
    cached: Option<(Instant, T)>,
}
impl<T> Default for Sampler<T> {
    fn default() -> Self {
        Self {
            pending: None,
            cached: None,
        }
    }
}
impl<T: Clone + Send + 'static> Sampler<T> {
    pub(super) fn invalidate(&mut self) {
        self.cached = None;
        if let Some(pending) = &mut self.pending {
            pending.discard = true;
        }
    }
    fn poll_completed(&mut self, now: Instant) {
        use tokio::sync::oneshot::error::TryRecvError;
        let completed =
            self.pending
                .as_mut()
                .and_then(|pending| match pending.receive.try_recv() {
                    Ok(value) => Some(Some(value)),
                    Err(TryRecvError::Empty) => None,
                    Err(TryRecvError::Closed) => Some(None),
                });
        if let Some(value) = completed {
            let pending = self.pending.take().expect("completed pending probe");
            if !pending.discard && now.saturating_duration_since(pending.started) <= MAX_AGE {
                if let Some(value) = value {
                    self.cached = Some((pending.started, value));
                }
            }
        }
        if self
            .cached
            .as_ref()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) > MAX_AGE)
        {
            self.cached = None;
        }
    }
    fn sample_with(
        &mut self,
        enabled: bool,
        now: Instant,
        probe: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        if !enabled {
            self.invalidate();
            return None;
        }
        self.poll_completed(now);
        if self.pending.is_none() {
            let (send, receive) = tokio::sync::oneshot::channel();
            // A stuck kernel call retains this one slot. Do not spawn another
            // scan on a timeout, and do not make runtime shutdown join it.
            match std::thread::Builder::new()
                .name("porthub-disk-metrics".into())
                .spawn(move || {
                    let _ = send.send(probe());
                }) {
                Ok(_) => {
                    self.pending = Some(Pending {
                        receive,
                        started: now,
                        discard: false,
                    })
                }
                Err(_) => tracing::warn!("Cannot start native disk metrics probe"),
            }
        }
        self.cached.as_ref().map(|(_, value)| value.clone())
    }
}
impl Sampler<Snapshot> {
    pub(super) fn sample(&mut self) -> Snapshot {
        self.sample_with(true, Instant::now(), collect)
            .unwrap_or_else(|| (Vec::new(), Memory { used: 0, total: 0 }))
    }
}

fn collect() -> Snapshot {
    let mut disks = sysinfo::Disks::new();
    disks.refresh(true);
    let mut seen = std::collections::HashSet::new();
    let mut drives = Vec::new();
    let mut disk = Memory { used: 0, total: 0 };
    for d in disks.list() {
        if matches!(d.file_system().to_str(), Some("overlay" | "aufs"))
            || d.total_space() == 0
            || d.total_space() > i64::MAX as u64
            || drives.len() >= 128
        {
            continue;
        }
        #[cfg(windows)]
        let Some(identity) = super::disk_identity::collect(d) else {
            continue;
        };
        #[cfg(windows)]
        let (key, id, name) = (identity.key, identity.id, identity.name);
        #[cfg(not(windows))]
        let (key, id, name) = {
            let name = d.name().to_string_lossy();
            (
                d.name().to_os_string(),
                super::integrated_gpu::label(&name, 256),
                super::integrated_gpu::label(&name, 120),
            )
        };
        if id.is_empty() || !seen.insert(key) {
            continue;
        }
        drives.push(Disk {
            id,
            name,
            used: d.total_space().saturating_sub(d.available_space()),
            total: d.total_space(),
        });
        disk.total = disk.total.saturating_add(d.total_space());
        disk.used = disk
            .used
            .saturating_add(d.total_space().saturating_sub(d.available_space()));
    }
    (drives, disk)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(flavor = "current_thread")]
    async fn blocked_native_scan_does_not_suspend_heartbeat_or_cancellation() {
        let (release, held) = std::sync::mpsc::channel();
        let (heartbeat, observed) = std::sync::mpsc::channel();
        let (canceled, observed_cancel) = std::sync::mpsc::channel();
        let (entered, began) = std::sync::mpsc::channel();
        let observer = std::thread::spawn(move || {
            began
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap();
            let alive = observed
                .recv_timeout(std::time::Duration::from_secs(1))
                .is_ok();
            // Keep the native probe blocked until cancellation also runs on
            // the same executor. The old inline path times out before either.
            let cancellation = alive
                && observed_cancel
                    .recv_timeout(std::time::Duration::from_secs(1))
                    .is_ok();
            release.send(()).unwrap();
            (alive, cancellation)
        });
        let cancel = tokio_util::sync::CancellationToken::new();
        let worker_cancel = cancel.clone();
        let (probe_entered, probe_started) = tokio::sync::oneshot::channel();
        let heartbeat_ready = std::sync::Arc::new(tokio::sync::Notify::new());
        let ready = heartbeat_ready.clone();
        let heartbeat_task = tokio::spawn(async move {
            probe_started.await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            let _ = heartbeat.send(());
            ready.notify_one();
            worker_cancel.cancelled().await;
            let _ = canceled.send(());
        });
        let mut sampler = Sampler::default();
        let _ = sampler.sample_with(true, Instant::now(), move || {
            entered.send(()).unwrap();
            let _ = probe_entered.send(());
            held.recv_timeout(std::time::Duration::from_secs(3))
                .unwrap();
            7u8
        });
        // This must remain runnable even while the native probe is blocked.
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            heartbeat_ready.notified(),
        )
        .await
        .unwrap();
        cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_millis(100), heartbeat_task)
            .await
            .unwrap()
            .unwrap();
        let (heartbeat_progressed, cancellation_progressed) = observer.join().unwrap();
        assert!(
            heartbeat_progressed,
            "native disk probe blocked the control heartbeat executor"
        );
        assert!(
            cancellation_progressed,
            "native disk probe blocked cancellation on the control executor"
        );
    }
    async fn finish<T: Clone + Send + 'static>(sampler: &mut Sampler<T>, now: Instant) {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while sampler.pending.is_some() {
                sampler.poll_completed(now);
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn hung_scan_is_single_flight_and_disabled_result_is_discarded() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let (entered, began) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let mut sampler = Sampler::default();
        let now = Instant::now();
        assert!(sampler
            .sample_with(true, now, move || {
                count.fetch_add(1, Ordering::SeqCst);
                let _ = entered.send(());
                held.recv().unwrap();
                7u8
            })
            .is_none());
        began.await.unwrap();
        for _ in 0..100 {
            assert!(sampler
                .sample_with(true, now, || panic!("overlapping native probe"))
                .is_none());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(sampler
            .sample_with(false, now, || panic!("disabled native probe"))
            .is_none());
        release.send(()).unwrap();
        finish(&mut sampler, now).await;
        assert!(sampler.cached.is_none());
        assert!(sampler.sample_with(true, now, || 9).is_none());
        finish(&mut sampler, now).await;
        assert_eq!(sampler.sample_with(true, now, || 10), Some(9));
    }
    #[tokio::test]
    async fn late_scan_and_expired_cache_are_not_published_as_fresh() {
        let mut sampler = Sampler::default();
        let now = Instant::now();
        assert!(sampler.sample_with(true, now, || 7u8).is_none());
        finish(
            &mut sampler,
            now + MAX_AGE + std::time::Duration::from_millis(1),
        )
        .await;
        assert!(sampler.cached.is_none());
        let fresh = now + MAX_AGE + std::time::Duration::from_secs(1);
        assert!(sampler.sample_with(true, fresh, || 9).is_none());
        finish(&mut sampler, fresh).await;
        assert_eq!(sampler.sample_with(true, fresh, || 10), Some(9));
        sampler.poll_completed(fresh + MAX_AGE + std::time::Duration::from_millis(1));
        assert!(sampler.cached.is_none());
    }
}
