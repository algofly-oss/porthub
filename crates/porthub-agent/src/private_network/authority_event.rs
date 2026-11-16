//! Nonserialized control authority. Cloning/caching retains the request start;
//! this envelope does not yet replace every data-plane lease clock.
use anyhow::Result;

#[cfg(feature = "private-sparse")]
pub(crate) type Witness = super::authority_clock::RequestWindow;
#[cfg(not(feature = "private-sparse"))]
pub(crate) type Witness = ();

#[derive(Clone)]
pub struct Authority<T> {
    pub(crate) value: T,
    #[cfg(feature = "private-sparse")]
    witness: Option<Witness>,
    #[cfg(feature = "private-sparse")]
    expiry: std::time::SystemTime,
}
impl<T> Authority<T> {
    pub(crate) fn new(
        value: T,
        witness: Option<Witness>,
        expiry: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        #[cfg(not(feature = "private-sparse"))]
        let _ = (witness, expiry);
        Self {
            value,
            #[cfg(feature = "private-sparse")]
            witness,
            #[cfg(feature = "private-sparse")]
            expiry: expiry.into(),
        }
    }
    pub(crate) fn check(&self) -> Result<()> {
        #[cfg(feature = "private-sparse")]
        if let Some(witness) = &self.witness {
            witness.check(self.expiry)?;
        }
        Ok(())
    }
    pub(crate) fn accepted(&self) -> Result<&T> {
        self.check()?;
        Ok(&self.value)
    }
    pub(crate) fn accept(self) -> Result<T> {
        self.check()?;
        Ok(self.value)
    }
}

pub(crate) fn request_start() -> Result<Option<Witness>> {
    #[cfg(feature = "private-sparse")]
    {
        return super::authority_clock::RequestWindow::start(std::sync::Arc::new(
            super::authority_clock::NativeClock,
        ))
        .map(Some);
    }
    #[cfg(not(feature = "private-sparse"))]
    Ok(None)
}

#[cfg(all(test, feature = "private-sparse"))]
mod tests {
    use super::*;
    use std::{
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
        time::Duration,
    };
    struct Clock(AtomicU64);
    impl super::super::authority_clock::SuspendClock for Clock {
        fn elapsed_since_boot(&self) -> Result<Duration> {
            Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))
        }
    }
    #[tokio::test]
    async fn actual_runtime_event_queue_rejects_delayed_snapshot_and_pair_without_installing() {
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let witness = super::super::authority_clock::RequestWindow::start(clock.clone()).unwrap();
        let expiry = chrono::Utc::now() + chrono::Duration::seconds(30);
        let snapshot: super::super::policy::Snapshot = serde_json::from_value(serde_json::json!({
            "workspace":"w","self":"a","revision":1,"expires_at":expiry,"peers":[{"id":"a","ip":"10.203.0.2","fingerprint":"fingerprint-a","instance":"instance-a","hostname":"a.phub"}],"grants":[]
        }))
        .unwrap();
        let pair: porthub_network::policy::PairResponse = serde_json::from_value(
            serde_json::json!({"query":{"kind":"peer","value":"a"},"status":"denied"}),
        )
        .unwrap();
        let (send, mut recv) = tokio::sync::mpsc::channel(2);
        let mut positive = super::super::policy::Engine::default();
        positive.apply(snapshot.clone()).unwrap();
        assert!(positive.valid_lease());
        let mut policy = super::super::policy::Engine::default();
        let envelope = Authority::new(snapshot, Some(witness.clone()), expiry);
        let cached = envelope.clone();
        send.send(super::super::controller::Event::Snapshot(envelope))
            .await
            .unwrap();
        send.send(super::super::controller::Event::Pair(Authority::new(
            pair,
            Some(witness),
            expiry,
        )))
        .await
        .unwrap();
        clock.0.store(15000, Ordering::SeqCst);
        let mut installs = 0;
        match recv.recv().await.unwrap() {
            super::super::controller::Event::Snapshot(value) => {
                if let Ok(snapshot) = value.accepted() {
                    policy.apply(snapshot.clone()).unwrap();
                    installs += 1
                }
            }
            _ => panic!(),
        }
        match recv.recv().await.unwrap() {
            super::super::controller::Event::Pair(value) => {
                if value.accept().is_ok() {
                    installs += 1
                }
            }
            _ => panic!(),
        }
        assert_eq!(installs, 0);
        assert!(!policy.valid_lease());
        assert!(
            cached.accept().is_err(),
            "local cached re-emission must retain expired witness"
        );
    }
    #[tokio::test]
    async fn installation_await_cannot_publish_expired_authority() {
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let witness = super::super::authority_clock::RequestWindow::start(clock.clone()).unwrap();
        let authority = Authority::new(
            (),
            Some(witness),
            chrono::Utc::now() + chrono::Duration::seconds(30),
        );
        authority.accepted().unwrap();
        let (finish, wait) = tokio::sync::oneshot::channel();
        let install = tokio::spawn(async move {
            wait.await.unwrap();
            // Same post-native-await gate used before runtime publication.
            authority.check()?;
            Ok::<_, anyhow::Error>("published")
        });
        clock.0.store(15000, Ordering::SeqCst);
        finish.send(()).unwrap();
        assert!(install.await.unwrap().is_err());
    }
}
