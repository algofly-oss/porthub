//! Bound native inspections without putting driver waits on the async executor.
use anyhow::{Context, Result};
use std::sync::{Arc, OnceLock};
use tokio::sync::{oneshot, Semaphore};

pub(super) fn broker_slot() -> &'static Arc<Semaphore> {
    static SLOT: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOT.get_or_init(|| Arc::new(Semaphore::new(1)))
}
pub(super) fn selection_slot() -> &'static Arc<Semaphore> {
    static SLOT: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOT.get_or_init(|| Arc::new(Semaphore::new(1)))
}
async fn run_on<T: Send + 'static>(
    slot: &Arc<Semaphore>,
    operation: impl FnOnce() -> T + Send + 'static,
) -> Result<T> {
    let permit = slot
        .clone()
        .try_acquire_owned()
        .context("Native USB inspection is still busy")?;
    let (send, receive) = oneshot::channel();
    std::thread::Builder::new()
        .name("porthub-usb-query".into())
        .spawn(move || {
            // Cancellation/timeout drops only the receiver. The worker retains its
            // slot until the native call AND any unaccepted owned result are dropped.
            let _permit = permit;
            let _ = send.send(operation());
        })?;
    tokio::time::timeout(std::time::Duration::from_secs(2), receive)
        .await
        .context("Native USB inspection timed out")?
        .context("Native USB inspection stopped")
}
pub(super) async fn broker<T: Send + 'static>(
    operation: impl FnOnce() -> T + Send + 'static,
) -> Result<T> {
    run_on(broker_slot(), operation).await
}
pub(super) async fn selected<T: Send + 'static>(
    operation: impl FnOnce() -> T + Send + 'static,
) -> Result<T> {
    run_on(selection_slot(), operation).await
}

/// Original caller liveness, retained across blocking native preflight.
pub(super) struct ClaimPermit {
    alive: Arc<std::sync::atomic::AtomicBool>,
    deadline: std::time::Instant,
}
impl ClaimPermit {
    pub(super) fn check(&self) -> Result<()> {
        anyhow::ensure!(
            self.alive.load(std::sync::atomic::Ordering::Acquire)
                && std::time::Instant::now() < self.deadline,
            "Native USB claim canceled or expired"
        );
        Ok(())
    }
    pub(super) fn after_preflight<P, T>(
        &self,
        inspect: impl FnOnce() -> Result<P>,
        claim: impl FnOnce(P) -> Result<T>,
    ) -> Result<T> {
        let prepared = inspect()?;
        self.check()?;
        claim(prepared)
    }
}
struct CancelClaim(Arc<std::sync::atomic::AtomicBool>);
impl Drop for CancelClaim {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}
async fn claim_on<T: Send + 'static>(
    slot: &Arc<Semaphore>,
    operation: impl FnOnce(ClaimPermit) -> T + Send + 'static,
) -> Result<T> {
    let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let _cancel = CancelClaim(alive.clone());
    let claim = ClaimPermit {
        alive,
        deadline: std::time::Instant::now() + std::time::Duration::from_secs(2),
    };
    run_on(slot, move || operation(claim)).await
}
pub(super) async fn selected_claim<T: Send + 'static>(
    operation: impl FnOnce(ClaimPermit) -> T + Send + 'static,
) -> Result<T> {
    claim_on(selection_slot(), operation).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    #[derive(Debug)]
    struct OwnedResult(Arc<AtomicBool>);
    impl Drop for OwnedResult {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn canceled_query_holds_slot_until_late_owned_result_is_cleaned() {
        let slot = Arc::new(Semaphore::new(1));
        let (entered, ready) = oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = dropped.clone();
        let gate = slot.clone();
        let task = tokio::spawn(async move {
            run_on(&gate, move || {
                let _ = entered.send(());
                blocked.recv().unwrap();
                OwnedResult(flag)
            })
            .await
        });
        ready.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(run_on(&slot, || ()).await.is_err());
        assert!(!dropped.load(Ordering::SeqCst));
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while slot.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(dropped.load(Ordering::SeqCst));
        assert!(run_on(&slot, || 42).await.unwrap() == 42);
    }
}

#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn blocked_preflight_never_claims_after_cancellation_or_timeout() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for timeout in [false, true] {
        let slot = Arc::new(Semaphore::new(1));
        let (entered, ready) = oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let claims = Arc::new(AtomicUsize::new(0));
        let mutations = claims.clone();
        let gate = slot.clone();
        let task = tokio::spawn(async move {
            claim_on(&gate, move |claim| {
                claim.after_preflight(
                    || {
                        let _ = entered.send(());
                        blocked.recv().unwrap();
                        Ok(())
                    },
                    |_| {
                        mutations.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                )
            })
            .await
        });
        ready.await.unwrap();
        if timeout {
            assert!(task.await.unwrap().is_err());
        } else {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        assert_eq!(slot.available_permits(), 0);
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while slot.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            claims.load(Ordering::SeqCst),
            0,
            "Late preflight must not enter ownership mutation"
        );
    }
}
