//! Serialized optional prerequisite preparation. An in-progress OS installer is
//! allowed to settle; policy checks inside preparation prevent subsequent work.
use crate::features::{Feature, Policy};
use std::{future::Future, time::Duration};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Requested {
    pub host: bool,
    pub receive: bool,
    pub direct: bool,
    source_microphone: bool,
    source_camera: bool,
}
impl Requested {
    pub fn from_policy(policy: &Policy) -> Self {
        let raw = policy.enabled(Feature::Usb);
        let mic = policy.enabled(Feature::MicrophoneShare);
        let camera = policy.enabled(Feature::CameraShare);
        let receive = raw || policy.enabled(Feature::MediaReceive);
        Self {
            host: raw,
            receive,
            direct: policy.enabled(Feature::DirectConnections) && (raw || receive || mic || camera),
            source_microphone: mic,
            source_camera: camera,
        }
    }
    pub fn any(self) -> bool {
        self.host || self.receive || self.direct
    }
}
fn state(policy: &Policy) -> Requested {
    Requested::from_policy(policy)
}
/// Signature checks can await OS revocation services. Recheck the current role
/// after verification, immediately before launching the privileged installer.
pub(super) async fn after_verification<V, C, A, F>(
    verification: V,
    permitted: C,
    launch: A,
) -> anyhow::Result<bool>
where
    V: Future<Output = anyhow::Result<()>>,
    C: FnOnce() -> anyhow::Result<bool>,
    A: FnOnce() -> F,
    F: Future<Output = anyhow::Result<()>>,
{
    verification.await?;
    if !permitted()? {
        return Ok(false);
    }
    launch().await?;
    Ok(true)
}
pub(super) async fn run<F, Fut>(
    mut policy: watch::Receiver<Policy>,
    cancel: CancellationToken,
    mut attempt: F,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let mut current = state(&policy.borrow());
    let mut ready = false;
    let mut delay = Duration::from_secs(30);
    loop {
        if !current.any() || ready {
            tokio::select! {
                _ = cancel.cancelled() => return,
                changed = policy.changed() => {
                    if changed.is_err() { return; }
                    let next = state(&policy.borrow_and_update());
                    if next != current { ready = false; delay = Duration::from_secs(30); }
                    current = next;
                }
            }
            continue;
        }
        let operation = attempt();
        tokio::pin!(operation);
        let mut changed_during_attempt = false;
        let success = loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                changed = policy.changed() => {
                    if changed.is_err() { return; }
                    let next = state(&policy.borrow_and_update());
                    changed_during_attempt |= next != current;
                    current = next;
                    // Do not start a second installer while the first settles.
                }
                success = &mut operation => break success,
            }
        };
        ready = success && !changed_during_attempt && current.any();
        if ready || !current.any() {
            continue;
        }
        let deadline = tokio::time::sleep(delay);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = &mut deadline => { delay = (delay * 2).min(Duration::from_secs(900)); break; }
                changed = policy.changed() => {
                    if changed.is_err() { return; }
                    let next = state(&policy.borrow_and_update());
                    if next != current {
                        current = next;
                        delay = Duration::from_secs(30);
                        break;
                    }
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    fn policy(enabled: bool) -> Policy {
        let mut p = Policy::default();
        p.disabled.insert(Feature::Usb, !enabled);
        for f in [
            Feature::MediaReceive,
            Feature::MicrophoneShare,
            Feature::CameraShare,
        ] {
            p.disabled.insert(f, true);
        }
        p
    }
    async fn settle() {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }
    #[tokio::test(start_paused = true)]
    async fn disabled_enable_retry_backoff_success_and_cancel() {
        let (tx, rx) = watch::channel(policy(false));
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let task = tokio::spawn(run(rx, stop, move || {
            let n = c.fetch_add(1, Ordering::SeqCst);
            async move { n > 0 }
        }));
        settle().await;
        assert_eq!(count.load(Ordering::SeqCst), 0);
        tx.send(policy(true)).unwrap();
        settle().await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(29)).await;
        settle().await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(count.load(Ordering::SeqCst), 2);
        tokio::time::advance(Duration::from_secs(3600)).await;
        settle().await;
        assert_eq!(count.load(Ordering::SeqCst), 2);
        cancel.cancel();
        task.await.unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn disable_midflight_serializes_reenable_and_shutdown_cancels() {
        let (tx, rx) = watch::channel(policy(true));
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let g = gate.clone();
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let task = tokio::spawn(run(rx, stop, move || {
            c.fetch_add(1, Ordering::SeqCst);
            let g = g.clone();
            async move {
                g.acquire().await.unwrap().forget();
                true
            }
        }));
        settle().await;
        tx.send(policy(false)).unwrap();
        settle().await;
        tokio::time::advance(Duration::from_secs(120)).await;
        settle().await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        gate.add_permits(1);
        settle().await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        tx.send(policy(true)).unwrap();
        settle().await;
        assert_eq!(count.load(Ordering::SeqCst), 2);
        cancel.cancel();
        task.await.unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn unrelated_updates_preserve_deadline_and_exponential_delay_caps() {
        let (tx, rx) = watch::channel(policy(true));
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run(rx, cancel.clone(), move || {
            c.fetch_add(1, Ordering::SeqCst);
            async { false }
        }));
        settle().await;
        for (index, seconds) in [30, 60, 120, 240, 480, 900, 900].into_iter().enumerate() {
            assert_eq!(count.load(Ordering::SeqCst), index + 1);
            for n in 0..3 {
                let mut p = policy(true);
                p.disabled.insert(Feature::Keyboard, n % 2 == 0);
                tx.send(p).unwrap();
                settle().await;
                assert_eq!(count.load(Ordering::SeqCst), index + 1);
            }
            tokio::time::advance(Duration::from_secs(seconds - 1)).await;
            settle().await;
            assert_eq!(count.load(Ordering::SeqCst), index + 1);
            tokio::time::advance(Duration::from_secs(1)).await;
            settle().await;
            assert_eq!(count.load(Ordering::SeqCst), index + 2);
        }
        cancel.cancel();
        task.await.unwrap();
    }
    #[test]
    fn independent_media_policies_request_only_required_prerequisites() {
        let off = policy(false);
        assert!(!Requested::from_policy(&off).any());
        for source in [Feature::MicrophoneShare, Feature::CameraShare] {
            let mut p = off.clone();
            p.disabled.insert(source, false);
            let r = Requested::from_policy(&p);
            assert!(!r.host && !r.receive && r.direct);
            p.disabled.insert(Feature::DirectConnections, true);
            assert!(!Requested::from_policy(&p).any());
        }
        let mut p = off.clone();
        p.disabled.insert(Feature::MediaReceive, false);
        let r = Requested::from_policy(&p);
        assert!(!r.host && r.receive && r.direct);
        p.disabled.insert(Feature::Usb, false);
        let r = Requested::from_policy(&p);
        assert!(r.host && r.receive && r.direct);
    }
    #[tokio::test(start_paused = true)]
    async fn media_receive_enable_without_raw_usb_starts_preparation() {
        let (tx, rx) = watch::channel(policy(false));
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run(rx, cancel.clone(), move || {
            c.fetch_add(1, Ordering::SeqCst);
            async { true }
        }));
        settle().await;
        assert_eq!(count.load(Ordering::SeqCst), 0);
        let mut p = policy(false);
        p.disabled.insert(Feature::MediaReceive, false);
        tx.send(p).unwrap();
        settle().await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        cancel.cancel();
        task.await.unwrap();
    }
    #[tokio::test]
    async fn signature_wait_rechecks_permission_before_launch_and_rejects_bad_signature() {
        use std::sync::atomic::AtomicBool;
        let permitted = Arc::new(AtomicBool::new(true));
        let launches = Arc::new(AtomicUsize::new(0));
        let (verified, wait) = tokio::sync::oneshot::channel();
        let p = permitted.clone();
        let count = launches.clone();
        let task = tokio::spawn(after_verification(
            async move {
                wait.await.unwrap();
                Ok(())
            },
            move || Ok(p.load(Ordering::SeqCst)),
            move || async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        ));
        settle().await;
        permitted.store(false, Ordering::SeqCst);
        verified.send(()).unwrap();
        assert!(!task.await.unwrap().unwrap());
        assert_eq!(launches.load(Ordering::SeqCst), 0);
        let count = launches.clone();
        let result = after_verification(
            async { anyhow::bail!("invalid signature") },
            || Ok(true),
            move || async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(launches.load(Ordering::SeqCst), 0);
        let count = launches.clone();
        assert!(after_verification(
            async { Ok(()) },
            || Ok(true),
            move || async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        )
        .await
        .unwrap());
        assert_eq!(launches.load(Ordering::SeqCst), 1);
    }
}
