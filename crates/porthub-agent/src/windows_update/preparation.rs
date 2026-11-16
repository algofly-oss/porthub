//! Actual preparation/backoff wait used by the Windows controller. Only a
//! relevant policy transition or a new request may interrupt an existing wait.
use crate::update::Request;
use std::future::Future;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
pub(super) enum Awaited<T> {
    Finished(T),
    Changed,
    Stopped,
}
pub(super) async fn guarded<F, P, G>(
    operation: F,
    stop: &CancellationToken,
    attempt: &CancellationToken,
    requests: &mut watch::Receiver<Option<Request>>,
    policy: &mut watch::Receiver<P>,
    enabled: G,
    known: &mut bool,
) -> Awaited<F::Output>
where
    F: Future,
    G: Fn(&P) -> bool,
{
    let next = enabled(&policy.borrow());
    if next != *known {
        *known = next;
        attempt.cancel();
        return Awaited::Changed;
    }
    tokio::pin!(operation);
    loop {
        tokio::select! {biased;
            _=stop.cancelled()=>{attempt.cancel();return Awaited::Stopped;},
            changed=requests.changed()=>{attempt.cancel();return if changed.is_err(){Awaited::Stopped}else{Awaited::Changed};},
            changed=policy.changed()=>{
                if changed.is_err(){attempt.cancel();return Awaited::Stopped;}
                let next=enabled(&policy.borrow_and_update());
                if next!=*known{*known=next;attempt.cancel();return Awaited::Changed;}
            },
            result=&mut operation=>return Awaited::Finished(result),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::{Feature, Policy};
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Duration,
    };
    fn on() -> Policy {
        Policy::default()
    }
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    #[tokio::test]
    async fn revoked_during_preparation_cancels_and_reaps_future() {
        let (_requests, mut rx) = watch::channel(None);
        let (tx, mut policy) = watch::channel(on());
        let stop = CancellationToken::new();
        let attempt = CancellationToken::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let d = dropped.clone();
        let mut known = true;
        let action = async {
            let _guard = DropFlag(d);
            std::future::pending::<()>().await
        };
        let future = guarded(
            action,
            &stop,
            &attempt,
            &mut rx,
            &mut policy,
            |p| p.enabled(Feature::AutoUpdate),
            &mut known,
        );
        tokio::pin!(future);
        tokio::select! {biased;_=&mut future=>panic!("preparation unexpectedly ended"),_=tokio::task::yield_now()=>{}}
        let mut off = on();
        off.disabled.insert(Feature::AutoUpdate, true);
        tx.send(off).unwrap();
        assert!(matches!(future.await, Awaited::Changed));
        assert!(attempt.is_cancelled());
        assert!(dropped.load(Ordering::SeqCst));
    }
    #[tokio::test(start_paused = true)]
    async fn unrelated_features_never_bypass_original_backoff_deadline() {
        let (_requests, mut rx) = watch::channel(None);
        let (tx, mut policy) = watch::channel(on());
        let stop = CancellationToken::new();
        let attempt = CancellationToken::new();
        let mut known = true;
        let future = guarded(
            tokio::time::sleep(Duration::from_secs(30)),
            &stop,
            &attempt,
            &mut rx,
            &mut policy,
            |p| p.enabled(Feature::AutoUpdate),
            &mut known,
        );
        tokio::pin!(future);
        for n in 0..4 {
            let mut p = on();
            p.disabled.insert(Feature::Keyboard, n % 2 == 0);
            tx.send(p).unwrap();
            tokio::select! {biased;_=&mut future=>panic!("unrelated policy bypassed backoff"),_=tokio::task::yield_now()=>{}}
        }
        tokio::time::advance(Duration::from_secs(29)).await;
        tokio::select! {biased;_=&mut future=>panic!("backoff ended early"),_=tokio::task::yield_now()=>{}}
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(future.await, Awaited::Finished(())));
        assert!(!attempt.is_cancelled());
    }
    #[tokio::test]
    async fn superseding_request_and_shutdown_cancel_pending_work() {
        for shutdown in [false, true] {
            let (tx, mut rx) = watch::channel(None);
            let (_policy_tx, mut policy) = watch::channel(on());
            let stop = CancellationToken::new();
            let attempt = CancellationToken::new();
            let mut known = true;
            if shutdown {
                stop.cancel();
            } else {
                tx.send(Some(Request {
                    id: "next".into(),
                    target_version: "1.11.36".into(),
                }))
                .unwrap();
            }
            let result = guarded(
                std::future::pending::<()>(),
                &stop,
                &attempt,
                &mut rx,
                &mut policy,
                |p| p.enabled(Feature::AutoUpdate),
                &mut known,
            )
            .await;
            assert!(if shutdown {
                matches!(result, Awaited::Stopped)
            } else {
                matches!(result, Awaited::Changed)
            });
            assert!(attempt.is_cancelled());
        }
    }
}
