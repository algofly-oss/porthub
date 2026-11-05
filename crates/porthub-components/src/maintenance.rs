//! Optional work never blocks startup or participates in core OTA status.
use crate::{catalog::Component, store::Manager};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Default)]
pub struct Status {
    pub running: bool,
    pub last_success_unix: Option<u64>,
    pub unavailable: Vec<Component>,
    pub catalog_unavailable: bool,
}
#[derive(Clone, Debug)]
pub struct Options {
    /// False still updates components that have already been installed.
    pub prefetch: bool,
    pub refresh: Duration,
    pub max_backoff: Duration,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            prefetch: true,
            refresh: Duration::from_secs(6 * 3600),
            max_backoff: Duration::from_secs(300),
        }
    }
}
pub struct Guard {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
    status: watch::Receiver<Status>,
}
impl Guard {
    /// Spawns immediately. No network or disk operations are awaited here.
    pub fn start(manager: Manager, options: Options, parent: &CancellationToken) -> Self {
        let cancel = parent.child_token();
        let worker_cancel = cancel.clone();
        let (status, receiver) = watch::channel(Status::default());
        let task = tokio::spawn(async move {
            let mut failure_delay = Duration::from_secs(2);
            let refresh = options
                .refresh
                .clamp(Duration::from_secs(60), Duration::from_secs(24 * 3600));
            let cap = options
                .max_backoff
                .clamp(Duration::from_secs(2), Duration::from_secs(3600));
            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as u64
                ^ std::process::id() as u64;
            let mut cycles = 0u64;
            loop {
                if worker_cancel.is_cancelled() {
                    break;
                }
                status.send_modify(|s| {
                    s.running = true;
                    s.unavailable.clear();
                    s.catalog_unavailable = false;
                });
                let result = manager.refresh_state(&worker_cancel).await;
                let delay = match result {
                    Ok(refreshed) => {
                        let catalog = refreshed.catalog;
                        status.send_modify(|s| s.catalog_unavailable = !refreshed.fresh);
                        for component in Component::OPTIONAL {
                            if worker_cancel.is_cancelled() {
                                break;
                            }
                            if manager.selected(&catalog, component).is_err() {
                                continue;
                            }
                            if !options.prefetch
                                && manager
                                    .installed(component)
                                    .await
                                    .map_or(true, |installed| installed.is_empty())
                            {
                                continue;
                            }
                            if manager
                                .ensure(&catalog, component, &worker_cancel)
                                .await
                                .is_err()
                            {
                                status.send_modify(|s| s.unavailable.push(component));
                            }
                        }
                        let success = refreshed.fresh && status.borrow().unavailable.is_empty();
                        if success {
                            status.send_modify(|s| {
                                s.last_success_unix = Some(
                                    SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                )
                            });
                            failure_delay = Duration::from_secs(2);
                            refresh
                        } else {
                            let delay = failure_delay;
                            failure_delay = (failure_delay * 2).min(cap);
                            delay
                        }
                    }
                    Err(_) => {
                        status.send_modify(|s| s.catalog_unavailable = true);
                        let delay = failure_delay;
                        failure_delay = (failure_delay * 2).min(cap);
                        delay
                    }
                };
                status.send_modify(|s| s.running = false);
                // Stable bounded per-process jitter spreads retries and refreshes.
                cycles = cycles.wrapping_add(1);
                let jitter = Duration::from_millis(
                    seed.wrapping_add(cycles.wrapping_mul(7919))
                        % (delay.as_millis() as u64 / 10 + 1),
                );
                tokio::select! { biased; _ = worker_cancel.cancelled() => break, _ = tokio::time::sleep(delay + jitter) => {} }
            }
            status.send_modify(|s| s.running = false);
        });
        Self {
            cancel,
            task,
            status: receiver,
        }
    }
    pub fn status(&self) -> watch::Receiver<Status> {
        self.status.clone()
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
