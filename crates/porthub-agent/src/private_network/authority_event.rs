//! Nonserialized control authority. Cloning/caching retains the request start;
//! this envelope does not yet replace every data-plane lease clock.
use anyhow::Result;

#[cfg(feature = "private-sparse")]
pub(crate) type Witness = super::authority_clock::RequestWindow;
#[cfg(not(feature = "private-sparse"))]
pub(crate) type Witness = ();

/// Unique runtime owner is created only after the protected profile Lease. All
/// domain clones are observation-only; dropping the owner cannot be reversed.
#[derive(Clone)]
pub(crate) struct Domain {
    active: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
pub(crate) struct Owner {
    domain: Domain,
}
impl Owner {
    pub(crate) fn new() -> Self {
        Self {
            domain: Domain {
                active: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            },
        }
    }
    pub(crate) fn domain(&self) -> Domain {
        self.domain.clone()
    }
    pub(crate) fn revoke(&self) {
        self.domain
            .active
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.revoke();
    }
}
impl Domain {
    pub(crate) fn valid(&self) -> bool {
        self.active.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[derive(Clone)]
pub struct Authority<T> {
    pub(crate) value: T,
    retirement: Option<Domain>,
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
            retirement: None,
            #[cfg(feature = "private-sparse")]
            witness,
            #[cfg(feature = "private-sparse")]
            expiry: expiry.into(),
        }
    }
    pub(crate) fn retired_with(mut self, domain: Domain) -> Self {
        self.retirement = Some(domain);
        self
    }
    pub(crate) fn check(&self) -> Result<()> {
        anyhow::ensure!(
            self.retirement.as_ref().is_none_or(|domain| domain.valid()),
            "private authority retired"
        );
        #[cfg(feature = "private-sparse")]
        if let Some(witness) = &self.witness {
            witness.check(self.expiry)?;
        }
        Ok(())
    }
    /// Revalidate BEFORE every poll of a pending operation, including the first
    /// poll after resume/backpressure. The bounded timer also cancels a stalled
    /// operation that otherwise never wakes. It never refreshes the witness.
    pub(crate) async fn during<R>(
        &self,
        operation: impl std::future::Future<Output = Result<R>>,
    ) -> Result<R> {
        if self.remaining()?.is_none() {
            return operation.await;
        }
        tokio::pin!(operation);
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(50));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let guarded = std::future::poll_fn(|cx| {
                if let Err(error) = self.check() {
                    return std::task::Poll::Ready(Err(error));
                }
                operation.as_mut().poll(cx)
            });
            tokio::select! {result=guarded=>return result,_=tick.tick()=>self.check()?}
        }
    }
    pub(crate) fn remaining(&self) -> Result<Option<std::time::Duration>> {
        anyhow::ensure!(
            self.retirement.as_ref().is_none_or(|domain| domain.valid()),
            "private authority retired"
        );
        #[cfg(feature = "private-sparse")]
        if let Some(witness) = &self.witness {
            return witness.remaining(self.expiry).map(Some);
        }
        Ok(None)
    }
    pub(crate) fn retained(&self) -> Authority<()> {
        Authority {
            value: (),
            retirement: self.retirement.clone(),
            #[cfg(feature = "private-sparse")]
            witness: self.witness.clone(),
            #[cfg(feature = "private-sparse")]
            expiry: self.expiry,
        }
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

pub(crate) fn send_permit(base:Option<&Authority<()>>,pairs:&super::sparse::Handle,peer:&str)->Result<Option<porthub_mesh::udp::SendPermit>> {
    let Some(base)=base else{return Ok(None);};
    base.check()?;if base.remaining()?.is_none(){return Ok(None);}
    let base=base.clone();let pair=if pairs.enabled(){Some(pairs.pair_authority(peer).ok_or_else(||anyhow::anyhow!("private peer authority expired"))?)}else{None};
    let bounded_base=base.clone();let bounded_pair=pair.clone();
    Ok(Some(porthub_mesh::udp::SendPermit::bounded(move||base.check().is_ok()&&pair.as_ref().is_none_or(|p|p.check().is_ok()),move||{
        let left=bounded_base.remaining().ok()??;match &bounded_pair{Some(pair)=>Some(left.min(pair.remaining().ok()??)),None=>Some(left)}
    })))
}

pub(crate) fn request_start(domain: Option<&Domain>) -> Result<Option<Witness>> {
    #[cfg(not(feature = "private-sparse"))]
    let _ = domain;
    #[cfg(feature = "private-sparse")]
    {
        return super::authority_clock::RequestWindow::start_in(
            std::sync::Arc::new(super::authority_clock::NativeClock),
            domain.cloned(),
        )
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
    #[tokio::test]
    async fn real_backpressured_writer_cannot_resume_delivery_after_suspend_expiry() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let witness = super::super::authority_clock::RequestWindow::start(clock.clone()).unwrap();
        let authority = Authority::new(
            (),
            Some(witness),
            chrono::Utc::now() + chrono::Duration::seconds(30),
        );
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let (started, wait) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            authority
                .during(async {
                    writer.write_all(&[1]).await?;
                    started.send(()).unwrap();
                    writer.write_all(&[2]).await?;
                    Ok(())
                })
                .await
        });
        wait.await.unwrap();
        assert!(!task.is_finished());
        clock.0.store(15000, Ordering::SeqCst);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        assert!(task.await.unwrap().is_err());
        assert_eq!(bytes, vec![1]);
    }
    #[tokio::test]
    async fn profile_owner_drop_revokes_queued_witness_and_real_pending_writer() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let owner = Owner::new();
        let old_domain = owner.domain();
        let witness = super::super::authority_clock::RequestWindow::start_in(
            clock.clone(),
            Some(old_domain.clone()),
        )
        .unwrap();
        let authority = Authority::new(
            (),
            Some(witness),
            chrono::Utc::now() + chrono::Duration::seconds(30),
        );
        let cached = authority.clone();
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let (started, wait) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            authority
                .during(async {
                    writer.write_all(&[1]).await?;
                    started.send(()).unwrap();
                    writer.write_all(&[2]).await?;
                    Ok(())
                })
                .await
        });
        wait.await.unwrap();
        drop(owner);
        assert!(!old_domain.valid());
        assert!(cached.check().is_err());
        let replacement = Owner::new();
        assert!(replacement.domain().valid());
        assert!(cached.check().is_err());
        assert!(
            super::super::authority_clock::RequestWindow::start_in(clock, Some(old_domain))
                .is_err()
        );
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, vec![1]);
        assert!(task.await.unwrap().is_err());
    }
}
