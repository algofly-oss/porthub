//! Provider-only bounded holding area. Retention is NOT packet authorization.
//! An authenticated reader's immutable identity must match a later exact pair.
use super::super::{
    authority_clock::{NativeClock, RequestWindow, SuspendClock},
    authority_event::{Authority, Domain, Owner},
    exit_forwarding::{Plan, Readiness},
};
use anyhow::{ensure, Result};
use bytes::Bytes;
use porthub_network::policy::{ExitIntent, ExitRole, FlowId, Packet, PeerInfo, Snapshot};
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};
const AGE: Duration = Duration::from_secs(5);
const PACKETS: usize = 64;
const BYTES: usize = 64 * 1024;
const FLOWS: usize = 32;
const PER_FLOW: usize = 4;
const FLOW_BYTES: usize = 4096;
fn ingress_remaining(
    clock: &dyn SuspendClock,
    received_at: Instant,
    received_boot: Duration,
) -> Option<Duration> {
    let boot = clock
        .elapsed_since_boot()
        .ok()?
        .checked_sub(received_boot)?;
    let awake = Instant::now().checked_duration_since(received_at)?;
    AGE.checked_sub(boot)
        .filter(|left| !left.is_zero())
        .and_then(|left| Some(left.min(AGE.checked_sub(awake)?)))
        .filter(|left| !left.is_zero())
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Scope {
    workspace: String,
    own: String,
    ip: std::net::Ipv4Addr,
    fingerprint: String,
    instance: String,
    exit_epoch: String,
    intents: Vec<ExitIntent>,
}
impl Scope {
    pub(super) fn from(base: &Snapshot) -> Option<Self> {
        let sparse = base.sparse.as_ref()?;
        let own = base.peers.iter().find(|peer| peer.id == base.self_)?;
        let intents: Vec<_> = sparse
            .exit_intents
            .iter()
            .filter(|intent| intent.role == ExitRole::Router)
            .cloned()
            .collect();
        if intents.is_empty() {
            return None;
        }
        Some(Self {
            workspace: base.workspace.clone(),
            own: base.self_.clone(),
            ip: own.ip,
            fingerprint: own.fingerprint.clone(),
            instance: own.instance.clone(),
            exit_epoch: sparse.exit_epoch.clone()?,
            intents,
        })
    }
}
pub(super) fn same_identity(a: &PeerInfo, b: &PeerInfo) -> bool {
    a.id == b.id && a.ip == b.ip && a.fingerprint == b.fingerprint && a.instance == b.instance
}
pub(super) fn same_peer(a: &PeerInfo, b: &PeerInfo) -> bool {
    same_identity(a, b)
        && a.relay_origin
            .as_ref()
            .is_none_or(|stamp| b.relay_origin.as_ref() == Some(stamp))
}
pub(super) struct Entry {
    pub(super) bytes: Bytes,
    pub(super) origin: Arc<PeerInfo>,
    pub(super) base: Authority<()>,
    pub(super) refresh_requested: bool,
    flow: FlowId,
    age: RequestWindow,
    ingress_clock: Arc<dyn SuspendClock>,
    received_at: Instant,
    received_boot: Duration,
    domain: Domain,
    // None is an UNAUTHORIZED pending packet. Binding occurs once after exact
    // current identity/ExitPair/policy validation, without restarting age/base.
    bound: Option<(Plan, porthub_mesh::udp::SendPermit)>,
}
impl Entry {
    fn ingress_remaining(&self) -> Option<Duration> {
        ingress_remaining(
            self.ingress_clock.as_ref(),
            self.received_at,
            self.received_boot,
        )
    }
    pub(super) fn valid(&self) -> bool {
        self.domain.valid()
            && self.base.check().is_ok()
            && self.age.remaining_within(AGE).is_ok()
            && self.ingress_remaining().is_some()
            && self
                .bound
                .as_ref()
                .is_none_or(|(_, original)| original.valid())
    }
    pub(super) fn bind(
        &mut self,
        plan: &Plan,
        current: &PeerInfo,
        original_exit: porthub_mesh::udp::SendPermit,
    ) -> bool {
        if !self.valid() || !same_peer(&self.origin, current) {
            return false;
        }
        if let Some((original, _)) = &self.bound {
            return original == plan;
        }
        if !original_exit.valid() {
            return false;
        }
        self.bound = Some((plan.clone(), original_exit));
        true
    }
    fn origin_guard(
        &self,
        plan: &Plan,
        peer: &PeerInfo,
        current: porthub_mesh::udp::SendPermit,
    ) -> Result<porthub_mesh::udp::SendPermit> {
        ensure!(
            self.valid() && same_peer(&self.origin, peer),
            "pending EXIT origin expired or identity replaced"
        );
        let (bound, original) = self
            .bound
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("pending EXIT has no exact pair binding"))?;
        ensure!(bound == plan, "pending EXIT native generation changed");
        let domain = self.domain.clone();
        let d = domain.clone();
        let age = self.age.clone();
        let a = age.clone();
        let clock = self.ingress_clock.clone();
        let c = clock.clone();
        let received_at = self.received_at;
        let received_boot = self.received_boot;
        let base = self.base.clone();
        let b = base.clone();
        let retention = porthub_mesh::udp::SendPermit::bounded(
            move || {
                d.valid()
                    && base.check().is_ok()
                    && a.remaining_within(AGE).is_ok()
                    && ingress_remaining(c.as_ref(), received_at, received_boot).is_some()
            },
            move || {
                if !domain.valid() {
                    return None;
                }
                Some(
                    b.remaining()
                        .ok()??
                        .min(age.remaining_within(AGE).ok()?)
                        .min(ingress_remaining(
                            clock.as_ref(),
                            received_at,
                            received_boot,
                        )?),
                )
            },
        );
        Ok(porthub_mesh::udp::SendPermit::combine(vec![
            retention,
            original.clone(),
            current,
        ]))
    }
    pub(super) fn guard(
        &self,
        plan: &Plan,
        peer: &PeerInfo,
        current: porthub_mesh::udp::SendPermit,
        ready: &Readiness,
    ) -> Result<porthub_mesh::udp::SendPermit> {
        let permit = self.origin_guard(plan, peer, current)?;
        let ready = ready.clone();
        let plan = plan.clone();
        Ok(permit.constrain(move || ready.ready(&plan)))
    }
}
#[derive(Default)]
pub(super) struct Queue {
    scope: Option<Scope>,
    owner: Option<Owner>,
    items: VecDeque<Entry>,
    bytes: usize,
    clock: Option<Arc<dyn SuspendClock>>,
}
impl Queue {
    pub(super) fn observe(&mut self, scope: Option<Scope>) {
        if self.scope != scope {
            self.owner.take();
            self.items.clear();
            self.bytes = 0;
            self.owner = scope.as_ref().map(|_| Owner::new());
            self.scope = scope;
        }
    }
    pub(super) fn len(&self) -> usize {
        self.items.len()
    }
    pub(super) fn push_at(
        &mut self,
        bytes: Bytes,
        origin: Arc<PeerInfo>,
        base: &Authority<()>,
        received_at: Instant,
        received_boot: Option<Duration>,
    ) -> bool {
        let Some(received_boot) = received_boot else {
            return false;
        };
        let clock = self.clock.clone().unwrap_or_else(|| Arc::new(NativeClock));
        if ingress_remaining(clock.as_ref(), received_at, received_boot).is_none() {
            return false;
        }
        self.items.retain(Entry::valid);
        self.bytes = self.items.iter().map(|entry| entry.bytes.len()).sum();
        let Some(owner) = self.owner.as_ref() else {
            return false;
        };
        if bytes.len() > porthub_mesh::MAX_PACKET - 20
            || origin.id.is_empty()
            || origin.id.len() > 60
            || origin.fingerprint.is_empty()
            || origin.instance.is_empty()
        {
            return false;
        }
        let Some(packet) = Packet::parse(&bytes) else {
            return false;
        };
        if packet.source() != origin.ip
            || base
                .remaining()
                .ok()
                .flatten()
                .is_none_or(|left| left.is_zero())
        {
            return false;
        }
        let flow = packet.flow_id();
        let same: Vec<_> = self
            .items
            .iter()
            .filter(|entry| entry.flow == flow)
            .collect();
        if self.items.len() >= PACKETS
            || self.bytes + bytes.len() > BYTES
            || same.len() >= PER_FLOW
            || same.iter().map(|entry| entry.bytes.len()).sum::<usize>() + bytes.len() > FLOW_BYTES
        {
            return false;
        }
        if same.is_empty() {
            let mut flows = Vec::new();
            for entry in &self.items {
                if !flows.contains(&entry.flow) {
                    flows.push(entry.flow);
                }
            }
            if flows.len() >= FLOWS {
                return false;
            }
        }
        let Ok(age) =
            RequestWindow::start(self.clock.clone().unwrap_or_else(|| Arc::new(NativeClock)))
        else {
            return false;
        };
        self.bytes += bytes.len();
        self.items.push_back(Entry {
            bytes,
            origin,
            base: base.clone(),
            refresh_requested: false,
            flow,
            age,
            ingress_clock: clock,
            received_at,
            received_boot,
            domain: owner.domain(),
            bound: None,
        });
        true
    }
    #[cfg(test)]
    fn push(&mut self, bytes: Bytes, origin: Arc<PeerInfo>, base: &Authority<()>) -> bool {
        let boot = self
            .clock
            .as_ref()
            .and_then(|clock| clock.elapsed_since_boot().ok());
        self.push_at(bytes, origin, base, Instant::now(), boot)
    }
    pub(super) fn discard_last(&mut self) {
        if let Some(entry) = self.items.pop_back() {
            self.bytes -= entry.bytes.len();
        }
    }
    pub(super) fn bind_last(
        &mut self,
        plan: &Plan,
        peer: &PeerInfo,
        permit: porthub_mesh::udp::SendPermit,
    ) -> bool {
        self.items
            .back_mut()
            .is_some_and(|entry| entry.bind(plan, peer, permit))
    }
    pub(super) fn pop(&mut self) -> Option<Entry> {
        while let Some(entry) = self.items.pop_front() {
            self.bytes -= entry.bytes.len();
            if entry.valid() {
                return Some(entry);
            }
        }
        None
    }
    pub(super) fn pending(&mut self, entry: Entry) {
        self.bytes += entry.bytes.len();
        self.items.push_back(entry);
    }
}
/// No native-readiness wait occurs here: only an actual TUN write after ACK.
/// Recheck the retained/current guards before EVERY poll, including resume.
pub(super) async fn during<T>(
    permit: porthub_mesh::udp::SendPermit,
    operation: impl std::future::Future<Output = Result<T>>,
) -> Result<Option<T>> {
    super::super::authority_event::during_permit(permit, operation).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Clock(AtomicU64);
    impl SuspendClock for Clock {
        fn elapsed_since_boot(&self) -> Result<Duration> {
            Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))
        }
    }
    fn base(clock: Arc<Clock>) -> Authority<()> {
        Authority::new(
            (),
            Some(RequestWindow::start(clock).unwrap()),
            chrono::Utc::now() + chrono::Duration::seconds(15),
        )
    }
    fn scope() -> Scope {
        Scope{workspace:"w".into(),own:"router".into(),ip:"10.203.0.3".parse().unwrap(),fingerprint:"r".into(),instance:"ri".into(),exit_epoch:"e".repeat(64),intents:vec![serde_json::from_value(serde_json::json!({"id":"exit","name":"Exit","role":"router","selection":"round_robin","traffic_mode":"all","allow_direct_fallback":false,"tor_enabled":false,"tor_circuit_groups":4})).unwrap()]}
    }
    fn peer() -> Arc<PeerInfo> {
        Arc::new(serde_json::from_value(serde_json::json!({"id":"client","ip":"10.203.0.2","fingerprint":"c","instance":"ci","hostname":"c.phub"})).unwrap())
    }
    fn packet(port: u16, size: usize) -> Bytes {
        let mut p = vec![0u8; size];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(size as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 203, 0, 2]);
        p[16..20].copy_from_slice(&[203, 0, 113, 1]);
        p[20..22].copy_from_slice(&port.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p[24..26].copy_from_slice(&((size - 20) as u16).to_be_bytes());
        let mut sum: u32 = p[..20]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_be_bytes(*b) as u32)
            .sum();
        while sum >> 16 != 0 {
            sum = (sum & 65535) + (sum >> 16);
        }
        p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        p.into()
    }
    fn permit() -> porthub_mesh::udp::SendPermit {
        porthub_mesh::udp::SendPermit::bounded(|| true, || Some(Duration::from_secs(15)))
    }
    fn queue() -> (Queue, Authority<()>, Arc<Clock>) {
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let a = base(clock.clone());
        let mut q = Queue::default();
        q.clock = Some(clock.clone());
        q.observe(Some(scope()));
        (q, a, clock)
    }
    #[test]
    fn unauthorised_pending_bytes_need_exact_identity_pair_and_native_generation_binding() {
        let (mut q, a, _) = queue();
        let peer = peer();
        assert!(q.push(packet(1, 32), peer.clone(), &a));
        let mut entry = q.pop().unwrap();
        let (ready, _) = super::super::super::exit_forwarding::readiness_channel();
        let first = ready.request([peer.ip].into()).unwrap();
        assert!(
            entry.origin_guard(&first, &peer, permit()).is_err(),
            "retention alone granted no packet authority"
        );
        let mut foreign = (*peer).clone();
        foreign.instance = "replacement".into();
        assert!(!entry.bind(&first, &foreign, permit()));
        assert!(entry.bind(&first, &peer, permit()));
        assert!(entry.origin_guard(&first, &peer, permit()).unwrap().valid());
        let next = ready.request(Default::default()).unwrap();
        assert!(!entry.bind(&next, &peer, permit()));
        assert!(entry.origin_guard(&next, &peer, permit()).is_err());
    }
    #[tokio::test]
    async fn suspend_or_scope_revoke_prevents_actual_pending_write_poll() {
        let (mut q, a, clock) = queue();
        let p = peer();
        assert!(q.push(packet(1, 32), p.clone(), &a));
        let mut entry = q.pop().unwrap();
        let (r, _) = super::super::super::exit_forwarding::readiness_channel();
        let plan = r.request([p.ip].into()).unwrap();
        assert!(entry.bind(&plan, &p, permit()));
        let guard = entry.origin_guard(&plan, &p, permit()).unwrap();
        clock.0.store(6000, Ordering::SeqCst);
        assert!(a.check().is_ok());
        let polled = std::sync::atomic::AtomicBool::new(false);
        assert!(during(guard, async {
            polled.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap()
        .is_none());
        assert!(!polled.load(Ordering::SeqCst));
        clock.0.store(0, Ordering::SeqCst);
        let mut changed = scope();
        changed.exit_epoch = "other".into();
        q.observe(Some(changed));
        assert!(!entry.valid());
    }
    #[tokio::test]
    async fn actual_write_future_is_not_polled_without_exact_native_applied_ack() {
        let (mut q, a, _) = queue();
        let p = peer();
        assert!(q.push(packet(1, 32), p.clone(), &a));
        let mut entry = q.pop().unwrap();
        let (ready, _) = super::super::super::exit_forwarding::readiness_channel();
        let plan = ready.request([p.ip].into()).unwrap();
        assert!(entry.bind(&plan, &p, permit()));
        let guard = entry.guard(&plan, &p, permit(), &ready).unwrap();
        let touched = std::sync::atomic::AtomicBool::new(false);
        assert!(during(guard, async {
            touched.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap()
        .is_none());
        assert!(!touched.load(Ordering::SeqCst));
    }
    #[test]
    fn bounds_and_original_age_survive_pending_rotation_without_reallocation_of_payload() {
        let (mut q, a, clock) = queue();
        let p = peer();
        let bytes = packet(1, 32);
        assert!(q.push(bytes.clone(), p.clone(), &a));
        let entry = q.pop().unwrap();
        assert_eq!(entry.bytes.as_ptr(), bytes.as_ptr());
        q.pending(entry);
        clock.0.store(5000, Ordering::SeqCst);
        assert!(q.pop().is_none());
        clock.0.store(0, Ordering::SeqCst);
        for _ in 0..4 {
            assert!(q.push(packet(1, 32), p.clone(), &a));
        }
        assert!(!q.push(packet(1, 32), p.clone(), &a));
        q.observe(None);
        q.observe(Some(scope()));
        for port in 1..=32 {
            assert!(q.push(packet(port, 32), p.clone(), &a));
        }
        assert!(!q.push(packet(33, 32), p.clone(), &a));
        q.observe(None);
        q.observe(Some(scope()));
        for port in 1..=16 {
            for _ in 0..4 {
                assert!(q.push(packet(port, 32), p.clone(), &a));
            }
        }
        assert!(!q.push(packet(17, 32), p.clone(), &a));
        q.observe(None);
        q.observe(Some(scope()));
        let mut accepted = 0;
        for port in 1..=32 {
            for _ in 0..3 {
                if q.push(packet(port, 1300), p.clone(), &a) {
                    accepted += 1;
                }
            }
        }
        assert!(accepted < 64 && q.bytes <= BYTES);
    }
    #[tokio::test]
    async fn readiness_withdrawal_while_write_pending_is_retryable_without_new_age() {
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        struct Pending(Arc<AtomicUsize>);
        impl std::future::Future for Pending {
            type Output = Result<()>;
            fn poll(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Self::Output> {
                self.0.fetch_add(1, Ordering::SeqCst);
                std::task::Poll::Pending
            }
        }
        let (mut q, a, clock) = queue();
        let p = peer();
        assert!(q.push(packet(1, 32), p.clone(), &a));
        let mut entry = q.pop().unwrap();
        let (r, _) = super::super::super::exit_forwarding::readiness_channel();
        let plan = r.request([p.ip].into()).unwrap();
        assert!(entry.bind(&plan, &p, permit()));
        let ready = Arc::new(AtomicBool::new(true));
        let check = ready.clone();
        let guard = entry
            .origin_guard(&plan, &p, permit())
            .unwrap()
            .constrain(move || check.load(Ordering::SeqCst));
        let polls = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(during(guard, Pending(polls.clone())));
        tokio::time::timeout(Duration::from_millis(200), async {
            while polls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let before = polls.load(Ordering::SeqCst);
        ready.store(false, Ordering::SeqCst);
        assert!(tokio::time::timeout(Duration::from_millis(200), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .is_none());
        assert_eq!(polls.load(Ordering::SeqCst), before);
        ready.store(true, Ordering::SeqCst); // ACK may recover before caller requeues
        assert!(entry.valid());
        q.pending(entry);
        clock.0.store(4000, Ordering::SeqCst);
        let entry = q.pop().unwrap();
        assert_eq!(entry.received_boot, Duration::ZERO);
        q.pending(entry);
        clock.0.store(6000, Ordering::SeqCst);
        assert!(q.pop().is_none());
    }
    #[tokio::test]
    async fn genuine_write_error_is_not_classified_as_retryable_ack_withdrawal() {
        let error = during(permit(), async {
            Err::<(), _>(std::io::Error::from(std::io::ErrorKind::BrokenPipe).into())
        })
        .await
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::BrokenPipe
        );
    }
    #[test]
    fn new_relay_stamp_waits_for_matching_pair_without_restamping_original_bytes() {
        let (mut q, a, clock) = queue();
        let mut fresh = (*peer()).clone();
        fresh.relay_origin = Some("2".repeat(32));
        let incoming = Arc::new(fresh.clone());
        let mut stale = fresh.clone();
        stale.relay_origin = Some("1".repeat(32));
        let bytes = packet(1, 32);
        assert!(q.push(bytes.clone(), incoming.clone(), &a));
        let mut entry = q.pop().unwrap();
        let (r, _) = super::super::super::exit_forwarding::readiness_channel();
        let plan = r.request([fresh.ip].into()).unwrap();
        assert!(same_identity(&incoming, &stale));
        assert!(!same_peer(&incoming, &stale));
        assert!(!entry.bind(&plan, &stale, permit()));
        entry.refresh_requested = true;
        q.pending(entry);
        clock.0.store(1000, Ordering::SeqCst);
        let mut entry = q.pop().unwrap();
        assert!(entry.refresh_requested);
        assert_eq!(entry.origin.relay_origin, Some("2".repeat(32)));
        assert_eq!(entry.received_boot, Duration::ZERO);
        assert_eq!(&entry.bytes[..], &bytes);
        assert!(entry.bind(&plan, &fresh, permit()));
        for field in 0..3 {
            let mut foreign = fresh.clone();
            match field {
                0 => foreign.ip = "10.203.9.9".parse().unwrap(),
                1 => foreign.fingerprint = "other".into(),
                _ => foreign.instance = "other".into(),
            };
            assert!(!entry.bind(&plan, &foreign, permit()));
            assert!(entry.origin_guard(&plan, &foreign, permit()).is_err());
        }
    }
    #[test]
    fn queued_before_dispatch_suspend_or_missing_boot_stamp_cannot_gain_fresh_age() {
        let (mut q, _, clock) = queue();
        let p = peer();
        clock.0.store(10000, Ordering::SeqCst);
        let fresh = base(clock.clone());
        assert!(fresh.check().is_ok());
        assert!(
            !q.push_at(
                packet(1, 32),
                p.clone(),
                &fresh,
                Instant::now(),
                Some(Duration::ZERO)
            ),
            "pre-dispatch suspend must count despite fresh base"
        );
        assert!(
            !q.push_at(packet(1, 32), p.clone(), &fresh, Instant::now(), None),
            "missing source clock is not a fresh origin"
        );
        assert!(
            !q.push_at(
                packet(1, 32),
                p,
                &fresh,
                Instant::now() - Duration::from_secs(6),
                Some(Duration::from_secs(10))
            ),
            "awake channel backlog must count too"
        );
    }
    #[test]
    fn pending_original_pair_expiry_is_not_replaced_by_fresh_current_pair() {
        let (mut q, a, _) = queue();
        let p = peer();
        assert!(q.push(packet(1, 32), p.clone(), &a));
        let mut entry = q.pop().unwrap();
        let (r, _) = super::super::super::exit_forwarding::readiness_channel();
        let plan = r.request([p.ip].into()).unwrap();
        let live = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let check = live.clone();
        let old = porthub_mesh::udp::SendPermit::bounded(
            move || check.load(Ordering::SeqCst),
            || Some(Duration::from_secs(10)),
        );
        assert!(entry.bind(&plan, &p, old));
        live.store(false, Ordering::SeqCst);
        assert!(entry.origin_guard(&plan, &p, permit()).is_err());
    }
}
