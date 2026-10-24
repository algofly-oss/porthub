//! One scheduled reachability worker per public registration. Nothing in this
//! module runs on a visitor connection or in the forwarding copy loop.
use porthub_tunnel::client_plan::{Candidate, ClientPlan, RouteKind};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, watch};

#[derive(Clone)]
pub(crate) struct Snapshot {
    pub revision: u64,
    pub plan: Arc<ClientPlan>,
    pub current: Candidate,
}
pub(crate) struct Update {
    pub revision: u64,
    pub candidate: Candidate,
}
pub(crate) struct Monitor {
    settings: watch::Sender<Option<Snapshot>>,
    events: mpsc::Receiver<Update>,
    task: tokio::task::JoinHandle<()>,
    revision: Option<u64>,
}
impl Monitor {
    pub fn new(interval: Duration, timeout: Duration) -> Self {
        let (settings, receiver) = watch::channel(None);
        let (sender, events) = mpsc::channel(1);
        let task = tokio::spawn(run(receiver, sender, interval, timeout));
        Self {
            settings,
            events,
            task,
            revision: None,
        }
    }
    pub fn set(&mut self, revision: u64, snapshot: Option<Snapshot>) {
        if self.revision != Some(revision) {
            self.settings.send_replace(snapshot);
            self.revision = Some(revision);
        }
    }
    pub async fn next(&mut self) -> Option<Update> {
        self.events.recv().await
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn run(
    mut settings: watch::Receiver<Option<Snapshot>>,
    events: mpsc::Sender<Update>,
    interval: Duration,
    timeout: Duration,
) {
    let interval = interval.max(Duration::from_millis(100));
    let mut failures = 0;
    let mut ticks = 0;
    loop {
        let snapshot = settings.borrow_and_update().clone();
        let Some(snapshot) = snapshot else {
            if settings.changed().await.is_err() {
                break;
            }
            failures = 0;
            ticks = 0;
            continue;
        };
        let check = async {
            tokio::time::sleep(interval).await;
            let healthy = snapshot.current.probe(timeout).await.is_ok();
            failures = if healthy { 0 } else { (failures + 1).min(2) };
            ticks = (ticks + 1) % 10;
            // Do not churn healthy domain routes looking for a slightly faster
            // handshake. Revisit the operator's direct origin every ten ticks.
            let recovering_origin =
                healthy && ticks == 0 && snapshot.current.kind != RouteKind::Origin;
            if failures < 2 && !recovering_origin {
                return;
            }
            let mut candidates = snapshot.plan.as_ref().clone();
            candidates.candidates.retain(|candidate| {
                candidate.endpoint != snapshot.current.endpoint
                    && (!recovering_origin || candidate.kind == RouteKind::Origin)
            });
            if candidates.candidates.is_empty() {
                return;
            }
            if let Some(candidate) = candidates.available(timeout).await {
                let _ = events.try_send(Update {
                    revision: snapshot.revision,
                    candidate,
                });
            }
        };
        tokio::select! {
            result=settings.changed()=>{
                if result.is_err() { break; }
                failures=0;
                ticks=0;
            },
            _=check=>{},
        }
    }
}
