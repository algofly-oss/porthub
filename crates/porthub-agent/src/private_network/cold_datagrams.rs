//! Small runtime-owned buffer for non-retransmitting cold exit datagrams.
//! Payload never enters the shared picker or survives original authority/scope.
use super::super::authority_event::{Authority, Domain, Owner};
use bytes::Bytes;
use porthub_network::policy::{ExitIntent, FlowId, Packet, Snapshot};
use std::{
    collections::VecDeque,
    net::Ipv4Addr,
    time::{Duration, Instant},
};
const PACKETS: usize = 64;
const BYTES: usize = 64 * 1024;
const FLOWS: usize = 32;
const PER_FLOW_PACKETS: usize = 4;
const PER_FLOW_BYTES: usize = 4096;
const LIFETIME: Duration = Duration::from_secs(5);
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Scope {
    workspace: String,
    own: String,
    ip: Ipv4Addr,
    fingerprint: String,
    instance: String,
    exit_epoch: String,
    selection_epoch: String,
    intent: ExitIntent,
}
impl Scope {
    pub(super) fn from(base: &Snapshot, intent: &ExitIntent) -> Option<Self> {
        let sparse = base.sparse.as_ref()?;
        let own = base.peers.iter().find(|peer| peer.id == base.self_)?;
        Some(Self {
            workspace: base.workspace.clone(),
            own: base.self_.clone(),
            ip: own.ip,
            fingerprint: own.fingerprint.clone(),
            instance: own.instance.clone(),
            exit_epoch: sparse.exit_epoch.clone()?,
            selection_epoch: sparse.selection_epoch.clone()?,
            intent: intent.clone(),
        })
    }
}
pub(super) struct Datagram {
    pub(super) bytes: Bytes,
    pub(super) flow: FlowId,
    pub(super) tag: String,
    pub(super) authority: Authority<()>,
    domain: Domain,
    deadline: Instant,
    #[cfg(feature = "private-sparse")]
    age: super::super::authority_clock::RequestWindow,
}
impl Datagram {
    fn age_remaining(&self) -> Option<Duration> {
        #[cfg(feature = "private-sparse")]
        {
            return Some(
                self.age
                    .remaining_within(LIFETIME)
                    .ok()?
                    .min(self.deadline.checked_duration_since(Instant::now())?),
            );
        }
        #[cfg(not(feature = "private-sparse"))]
        {
            self.deadline.checked_duration_since(Instant::now())
        }
    }
    pub(super) fn valid(&self, now: Instant) -> bool {
        now < self.deadline
            && self.domain.valid()
            && self.authority.check().is_ok()
            && self.age_remaining().is_some()
    }
    /// The originating clock and scope remain vetoes in the FINAL carrier queue.
    pub(super) fn permit(
        &self,
        current: porthub_mesh::udp::SendPermit,
    ) -> porthub_mesh::udp::SendPermit {
        let a = self.authority.clone();
        let b = a.clone();
        let domain = self.domain.clone();
        let deadline = self.deadline;
        let check_domain = domain.clone();
        #[cfg(feature = "private-sparse")]
        let age = self.age.clone();
        #[cfg(feature = "private-sparse")]
        let check_age = age.clone();
        let original = porthub_mesh::udp::SendPermit::bounded(
            move || {
                #[cfg(feature = "private-sparse")]
                if check_age.remaining_within(LIFETIME).is_err() {
                    return false;
                }
                check_domain.valid() && Instant::now() < deadline && a.check().is_ok()
            },
            move || {
                if !domain.valid() {
                    return None;
                }
                #[cfg(feature = "private-sparse")]
                let left = age.remaining_within(LIFETIME).ok()?;
                #[cfg(not(feature = "private-sparse"))]
                let left = LIFETIME;
                Some(
                    left.min(
                        b.remaining()
                            .ok()??
                            .min(deadline.checked_duration_since(Instant::now())?),
                    ),
                )
            },
        );
        porthub_mesh::udp::SendPermit::combine(vec![original, current])
    }
}
#[derive(Default)]
pub(super) struct Queue {
    scope: Option<Scope>,
    owner: Option<Owner>,
    items: VecDeque<Datagram>,
    bytes: usize,
    #[cfg(feature = "private-sparse")]
    clock: Option<std::sync::Arc<dyn super::super::authority_clock::SuspendClock>>,
}
impl Queue {
    pub(super) fn observe(&mut self, scope: Option<Scope>) {
        if self.scope != scope {
            self.owner.take(); // retires permits already queued to a carrier too
            self.items.clear();
            self.bytes = 0;
            self.owner = scope.as_ref().map(|_| Owner::new());
            self.scope = scope;
        }
    }
    pub(super) fn len(&self) -> usize {
        self.items.len()
    }
    pub(super) fn push(&mut self, bytes: &[u8], authority: &Authority<()>, now: Instant) -> bool {
        let Some(owner) = self.owner.as_ref() else {
            return false;
        };
        if !matches!(bytes.get(9), Some(1 | 17)) || bytes.len() > porthub_mesh::MAX_PACKET - 20 {
            return false;
        }
        let Some(packet) = Packet::parse(bytes) else {
            return false;
        };
        if authority
            .remaining()
            .ok()
            .flatten()
            .is_none_or(|left| left.is_zero())
        {
            return false;
        }
        if self
            .scope
            .as_ref()
            .is_none_or(|scope| scope.ip != packet.source())
        {
            return false;
        }
        let flow = packet.flow_id();
        let same: Vec<_> = self.items.iter().filter(|item| item.flow == flow).collect();
        if self.items.len() >= PACKETS
            || self.bytes + bytes.len() > BYTES
            || same.len() >= PER_FLOW_PACKETS
            || same.iter().map(|item| item.bytes.len()).sum::<usize>() + bytes.len()
                > PER_FLOW_BYTES
        {
            return false;
        }
        if same.is_empty() {
            let mut distinct = Vec::new();
            for item in &self.items {
                if !distinct.contains(&item.flow) {
                    distinct.push(item.flow);
                }
            }
            if distinct.len() >= FLOWS {
                return false;
            }
        }
        let tag = super::super::exit_picker::flow_tag(&flow.selection_tag(), None);
        #[cfg(feature = "private-sparse")]
        let age = match super::super::authority_clock::RequestWindow::start(
            self.clock
                .clone()
                .unwrap_or_else(|| std::sync::Arc::new(super::super::authority_clock::NativeClock)),
        ) {
            Ok(age) => age,
            Err(_) => return false,
        };
        self.items.push_back(Datagram {
            bytes: Bytes::copy_from_slice(bytes),
            flow,
            tag,
            authority: authority.clone(),
            domain: owner.domain(),
            deadline: now + LIFETIME,
            #[cfg(feature = "private-sparse")]
            age,
        });
        self.bytes += bytes.len();
        true
    }
    pub(super) fn pop(&mut self, now: Instant) -> Option<Datagram> {
        while let Some(item) = self.items.pop_front() {
            self.bytes -= item.bytes.len();
            if item.valid(now) {
                return Some(item);
            }
        }
        None
    }
    pub(super) fn pending(&mut self, item: Datagram) {
        self.bytes += item.bytes.len();
        self.items.push_back(item);
    }
}

#[cfg(all(test, feature = "private-sparse"))]
mod tests {
    use super::*;
    use crate::private_network::authority_clock::{RequestWindow, SuspendClock};
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };
    struct Clock(AtomicU64);
    impl SuspendClock for Clock {
        fn elapsed_since_boot(&self) -> anyhow::Result<Duration> {
            Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))
        }
    }
    fn authority() -> (Authority<()>, Arc<Clock>) {
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        (
            Authority::new(
                (),
                Some(RequestWindow::start(clock.clone()).unwrap()),
                chrono::Utc::now() + chrono::Duration::seconds(15),
            ),
            clock,
        )
    }
    fn scope() -> Scope {
        Scope{workspace:"w".into(),own:"a".into(),ip:"10.203.0.2".parse().unwrap(),fingerprint:"a".into(),instance:"i".into(),exit_epoch:"e".repeat(64),selection_epoch:"s".repeat(64),intent:serde_json::from_value(serde_json::json!({"id":"exit","name":"Exit","role":"client","selection":"round_robin","traffic_mode":"all","allow_direct_fallback":false,"tor_enabled":false,"tor_circuit_groups":4})).unwrap()}
    }
    fn packet(protocol: u8, port: u16, size: usize) -> Vec<u8> {
        let mut p = vec![0u8; size];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(size as u16).to_be_bytes());
        p[8] = 64;
        p[9] = protocol;
        p[12..16].copy_from_slice(&[10, 203, 0, 2]);
        p[16..20].copy_from_slice(&[203, 0, 113, 1]);
        if protocol == 17 {
            p[20..22].copy_from_slice(&port.to_be_bytes());
            p[22..24].copy_from_slice(&443u16.to_be_bytes());
            p[24..26].copy_from_slice(&((size - 20) as u16).to_be_bytes());
        }
        if protocol == 1 {
            p[20] = 8;
            p[24..26].copy_from_slice(&port.to_be_bytes());
        }
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
        p
    }
    #[test]
    fn cold_udp_and_icmp_keep_exact_bytes_once_and_tcp_is_not_buffered() {
        let (a, _) = authority();
        let now = Instant::now();
        let mut q = Queue::default();
        q.observe(Some(scope()));
        for protocol in [17, 1] {
            let bytes = packet(protocol, 100, 32);
            assert!(q.push(&bytes, &a, now));
            let p = q.pop(now).unwrap();
            assert_eq!(&p.bytes[..], &bytes);
            assert!(p.valid(now));
            assert!(q.pop(now).is_none());
        }
        assert!(!q.push(&packet(6, 100, 40), &a, now));
    }
    #[test]
    fn cold_datagram_bounds_are_global_and_per_flow() {
        let (a, _) = authority();
        let now = Instant::now();
        let mut q = Queue::default();
        q.observe(Some(scope()));
        for _ in 0..4 {
            assert!(q.push(&packet(17, 100, 32), &a, now));
        }
        assert!(!q.push(&packet(17, 100, 32), &a, now));
        q.observe(None);
        q.observe(Some(scope()));
        for port in 1..=32 {
            assert!(q.push(&packet(17, port, 32), &a, now));
        }
        assert!(!q.push(&packet(17, 33, 32), &a, now));
        q.observe(None);
        q.observe(Some(scope()));
        for port in 1..=16 {
            for _ in 0..4 {
                assert!(q.push(&packet(17, port, 32), &a, now));
            }
        }
        assert_eq!(q.len(), 64);
        assert!(!q.push(&packet(17, 17, 32), &a, now));
        q.observe(None);
        q.observe(Some(scope()));
        for _ in 0..3 {
            assert!(q.push(&packet(17, 100, 1300), &a, now));
        }
        assert!(!q.push(&packet(17, 100, 1300), &a, now));
        q.observe(None);
        q.observe(Some(scope()));
        let mut accepted = 0;
        for port in 1..=32 {
            for _ in 0..3 {
                if q.push(&packet(17, port, 1300), &a, now) {
                    accepted += 1;
                }
            }
        }
        assert!(accepted < 64);
        assert!(q.bytes <= BYTES);
    }
    #[test]
    fn pending_does_not_renew_deadline_and_scope_change_retires_final_carrier_permit() {
        let (a, _) = authority();
        let now = Instant::now();
        let mut q = Queue::default();
        q.observe(Some(scope()));
        assert!(q.push(&packet(17, 100, 32), &a, now));
        let item = q.pop(now).unwrap();
        let permit = item.permit(porthub_mesh::udp::SendPermit::bounded(
            || true,
            || Some(Duration::from_secs(30)),
        ));
        assert!(permit.valid());
        q.pending(item);
        assert!(q.pop(now + LIFETIME).is_none()); // pending never re-stamps enqueue time
        let mut changed = scope();
        changed.selection_epoch = "new".into();
        q.observe(Some(changed));
        assert!(!permit.valid());
    }
    #[test]
    fn original_expiry_and_owner_retirement_veto_bytes_already_queued_to_carrier() {
        let (a, clock) = authority();
        let now = Instant::now();
        let mut q = Queue::default();
        q.observe(Some(scope()));
        assert!(q.push(&packet(1, 100, 32), &a, now));
        let item = q.pop(now).unwrap();
        let permit = item.permit(porthub_mesh::udp::SendPermit::bounded(
            || true,
            || Some(Duration::from_secs(30)),
        ));
        assert!(permit.valid());
        clock.0.store(16000, Ordering::SeqCst);
        assert!(!permit.valid());
        assert!(!item.valid(now));
        let (a, _) = authority();
        assert!(q.push(&packet(17, 101, 32), &a, now));
        let item = q.pop(now).unwrap();
        let permit = item.permit(porthub_mesh::udp::SendPermit::bounded(
            || true,
            || Some(Duration::from_secs(30)),
        ));
        drop(q);
        assert!(!permit.valid());
    }
    #[test]
    fn cold_datagram_survives_pair_before_availability_without_renewing_enqueue_age() {
        let (a, _) = authority();
        let now = Instant::now();
        let mut q = Queue::default();
        q.observe(Some(scope()));
        let bytes = packet(17, 100, 32);
        assert!(q.push(&bytes, &a, now));
        let item = q.pop(now).unwrap();
        let deadline = item.deadline;
        let mut table = porthub_network::exit_selection::FlowTable::new("a".into());
        assert!(table
            .select_for_peer(item.flow, now, Duration::from_secs(30), None, Some("b"))
            .is_none());
        q.pending(item);
        table.configure(["b".into()], Default::default());
        let item = q.pop(now + Duration::from_secs(1)).unwrap();
        assert_eq!(item.deadline, deadline);
        assert_eq!(&item.bytes[..], &bytes);
        assert_eq!(
            table.select_for_peer(item.flow, now, Duration::from_secs(30), None, Some("b")),
            Some("b")
        );
        assert!(q.pop(now).is_none(), "one original datagram delivered once");
    }
    #[test]
    fn suspend_age_expires_final_permit_even_while_original_base_is_live() {
        let (a, original_clock) = authority();
        let age_clock = Arc::new(Clock(AtomicU64::new(0)));
        let now = Instant::now();
        let mut q = Queue::default();
        q.clock = Some(age_clock.clone());
        q.observe(Some(scope()));
        assert!(q.push(&packet(17, 100, 32), &a, now));
        let item = q.pop(now).unwrap();
        let permit = item.permit(porthub_mesh::udp::SendPermit::bounded(
            || true,
            || Some(Duration::from_secs(30)),
        ));
        assert!(permit.valid());
        age_clock.0.store(10000, Ordering::SeqCst);
        assert_eq!(original_clock.0.load(Ordering::SeqCst), 0);
        assert!(a.check().is_ok());
        assert!(!item.valid(now));
        assert!(
            !permit.valid(),
            "suspended cold payload retained beyond its own five-second lifetime"
        );
    }
    #[test]
    fn foreign_source_and_changed_route_or_identity_cannot_replay() {
        let (a, _) = authority();
        let now = Instant::now();
        let mut q = Queue::default();
        let mut foreign = scope();
        foreign.ip = "10.203.0.9".parse().unwrap();
        q.observe(Some(foreign));
        assert!(!q.push(&packet(17, 100, 32), &a, now));
        for field in 0..4 {
            q.observe(Some(scope()));
            assert!(q.push(&packet(17, 100, 32), &a, now));
            let mut changed = scope();
            match field {
                0 => changed.exit_epoch = "x".into(),
                1 => changed.intent.id = "other".into(),
                2 => changed.fingerprint = "other".into(),
                _ => changed.instance = "other".into(),
            };
            q.observe(Some(changed));
            assert!(q.pop(now).is_none());
        }
    }
}
