//! Native-owner-qualified negotiation, independent of ACL authorization.
//! Release approval stays closed until the native lifecycle gates are proven.
use super::{super::authority_event::Authority, super::device::Tun, Snapshot};
use anyhow::{ensure, Result};
use std::{
    net::Ipv4Addr,
    sync::{Arc, Weak},
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
const NATIVE_LIFECYCLE_APPROVED: bool = false;
#[derive(Clone, PartialEq, Eq)]
struct Scope {
    workspace: String,
    own: String,
    ip: Ipv4Addr,
    fingerprint: String,
    epoch: String,
}
impl Scope {
    fn from_snapshot(base: &Snapshot) -> Option<Self> {
        let sparse = base.sparse.as_ref()?;
        if sparse.protocol != 1
            || sparse.epoch.len() != 64
            || !sparse
                .epoch
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return None;
        }
        let own = base.peers.iter().find(|p| p.id == base.self_)?;
        Some(Self {
            workspace: base.workspace.clone(),
            own: base.self_.clone(),
            ip: own.ip,
            fingerprint: own.fingerprint.clone(),
            epoch: sparse.epoch.clone(),
        })
    }
}
#[derive(Clone)]
enum NativeOwner {
    Tun(Weak<Tun>),
    #[cfg(test)]
    Fixture(Weak<()>),
}
impl NativeOwner {
    fn live(&self) -> bool {
        match self {
            Self::Tun(owner) => owner.upgrade().is_some(),
            #[cfg(test)]
            Self::Fixture(owner) => owner.upgrade().is_some(),
        }
    }
}
/// Nonserialized and non-authorizing. A weak native owner never keeps an
/// obsolete adapter alive, while its immutable authority cannot be renewed by
/// a newer reply or the capability watch channel.
#[derive(Clone)]
pub(crate) struct NativeReady {
    scope: Scope,
    authority: Authority<()>,
    native: NativeOwner,
    owner: CancellationToken,
}
impl NativeReady {
    pub(crate) fn prepared(
        base: &Snapshot,
        authority: Authority<()>,
        tun: &Arc<Tun>,
        owner: CancellationToken,
    ) -> Result<Self> {
        authority.check()?;
        ensure!(
            authority.remaining()?.is_some(),
            "native offer authority bound absent"
        );
        let scope = Scope::from_snapshot(base)
            .ok_or_else(|| anyhow::anyhow!("native offer sparse scope invalid"))?;
        Ok(Self {
            scope,
            authority,
            native: NativeOwner::Tun(Arc::downgrade(tun)),
            owner,
        })
    }
    fn valid(&self) -> bool {
        !self.owner.is_cancelled()
            && self.native.live()
            && self.authority.check().is_ok()
            && self.authority.remaining().ok().flatten().is_some()
    }
}
pub(super) struct Offer {
    legacy: bool,
    expected: Option<Scope>,
    server_origin: bool,
}
impl Offer {
    pub(super) fn new(sparse: bool) -> Self {
        Self {
            legacy: !sparse,
            expected: None,
            server_origin: false,
        }
    }
    pub(super) fn observe(&mut self, sparse: bool) {
        self.legacy = !sparse;
        self.expected = None;
        self.server_origin = false;
    }
    pub(super) fn observe_snapshot(&mut self, base: &Snapshot) {
        self.legacy = base.sparse.is_none();
        self.expected = Scope::from_snapshot(base);
        self.server_origin = false;
    }
    pub(super) fn observe_reply(&mut self, base: &Snapshot, protocols: &[String]) {
        self.observe_snapshot(base);
        self.server_origin = protocols.len() <= 8
            && protocols.iter().map(String::len).sum::<usize>() <= 256
            && protocols.iter().any(|protocol| protocol == "quic3-credit");
    }
    pub(super) fn transport(&self) -> &'static str {
        self.validated(None, false)
    }
    pub(super) fn offered(
        &self,
        updates: Option<&watch::Receiver<Option<NativeReady>>>,
    ) -> &'static str {
        let ready = updates
            .filter(|updates| updates.has_changed().is_ok())
            .and_then(|updates| updates.borrow().clone());
        self.validated(ready.as_ref(), NATIVE_LIFECYCLE_APPROVED)
    }
    fn validated(&self, ready: Option<&NativeReady>, approved: bool) -> &'static str {
        if !cfg!(feature = "private-stream") {
            return "";
        }
        if self.legacy {
            return "quic1";
        }
        if !cfg!(feature = "private-sparse") || !approved || !self.server_origin {
            return "";
        }
        if ready.is_some_and(|ready| ready.valid() && self.expected.as_ref() == Some(&ready.scope))
        {
            "quic3-credit"
        } else {
            ""
        }
    }
}
#[cfg(all(test, feature = "private-sparse"))]
mod tests {
    use super::*;
    use crate::private_network::authority_clock::{RequestWindow, SuspendClock};
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };
    struct Clock(AtomicU64);
    impl SuspendClock for Clock {
        fn elapsed_since_boot(&self) -> Result<Duration> {
            Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))
        }
    }
    fn base() -> Snapshot {
        serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(30),"sparse":{"protocol":1,"epoch":"a".repeat(64)},"peers":[{"id":"a","ip":"10.234.0.1","fingerprint":"fp-a","instance":"a-instance","hostname":"a.phub"}],"grants":[]})).unwrap()
    }
    fn ready(base: &Snapshot, clock: Arc<Clock>, owner: &Arc<()>) -> NativeReady {
        NativeReady {
            scope: Scope::from_snapshot(base).unwrap(),
            authority: Authority::new(
                (),
                Some(RequestWindow::start(clock).unwrap()),
                base.expires_at,
            ),
            native: NativeOwner::Fixture(Arc::downgrade(owner)),
            owner: CancellationToken::new(),
        }
    }
    #[test]
    fn exact_native_scope_gate_and_actual_owner_lifetime_are_required_before_offer() {
        let base = base();
        let owner = Arc::new(());
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let ready = ready(&base, clock, &owner);
        let mut offer = Offer::new(true);
        offer.observe_reply(&base, &["quic3-credit".into()]);
        assert_eq!(offer.validated(Some(&ready), false), "");
        assert_eq!(
            offer.validated(Some(&ready), true),
            if cfg!(all(feature = "private-sparse", feature = "private-stream")) {
                "quic3-credit"
            } else {
                ""
            }
        );
        let mut foreign = base.clone();
        foreign.workspace = "foreign".into();
        offer.observe_reply(&foreign, &["quic3-credit".into()]);
        assert_eq!(offer.validated(Some(&ready), true), "");
        for change in 0..3 {
            let mut next = base.clone();
            match change {
                0 => next.sparse.as_mut().unwrap().epoch = "b".repeat(64),
                1 => next.peers[0].ip = "10.235.0.1".parse().unwrap(),
                _ => next.peers[0].fingerprint = "replacement".into(),
            };
            offer.observe_reply(&next, &["quic3-credit".into()]);
            assert_eq!(offer.validated(Some(&ready), true), "");
        }
        offer.observe_reply(&base, &["quic3-credit".into()]);
        drop(owner);
        assert_eq!(offer.validated(Some(&ready), true), "");
    }
    #[test]
    fn newer_reply_or_watch_cache_cannot_refresh_original_native_witness_and_closed_owner_withdraws(
    ) {
        let base = base();
        let owner = Arc::new(());
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let ready = ready(&base, clock.clone(), &owner);
        let mut offer = Offer::new(true);
        offer.observe_reply(&base, &["quic3-credit".into()]);
        clock.0.store(15000, Ordering::SeqCst);
        let mut renewed = base.clone();
        renewed.revision += 1;
        renewed.expires_at = chrono::Utc::now() + chrono::Duration::seconds(30);
        offer.observe_reply(&renewed, &["quic3-credit".into()]);
        assert_eq!(offer.validated(Some(&ready), true), "");
        let (sender, updates) = watch::channel(Some(ready));
        assert_eq!(offer.offered(Some(&updates)), "");
        drop(sender);
        assert_eq!(offer.offered(Some(&updates)), "");
        offer.observe(false);
        assert_eq!(
            offer.offered(Some(&updates)),
            if cfg!(feature = "private-stream") {
                "quic1"
            } else {
                ""
            }
        );
    }
    #[test]
    fn old_or_unknown_gateway_capability_never_causes_an_unsupported_origin_request() {
        let base = base();
        let owner = Arc::new(());
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let ready = ready(&base, clock, &owner);
        let mut offer = Offer::new(true);
        offer.observe_snapshot(&base);
        assert_eq!(offer.validated(Some(&ready), true), "");
        offer.observe_reply(&base, &["future".into()]);
        assert_eq!(offer.validated(Some(&ready), true), "");
        let oversized = vec!["quic3-credit".into(); 9];
        offer.observe_reply(&base, &oversized);
        assert_eq!(offer.validated(Some(&ready), true), "");
        offer.observe(false);
        assert_eq!(
            offer.transport(),
            if cfg!(feature = "private-stream") {
                "quic1"
            } else {
                ""
            }
        );
    }
}

#[cfg(all(test, not(feature = "private-sparse")))]
mod legacy_tests {
    use super::*;

    #[test]
    fn sparse_offers_stay_disabled_without_the_feature() {
        let mut offer = Offer::new(true);
        assert_eq!(offer.validated(None, true), "");
        offer.observe(false);
        assert_eq!(
            offer.validated(None, true),
            if cfg!(feature = "private-stream") {
                "quic1"
            } else {
                ""
            }
        );
    }
}
