//! Bounded, payload-free cold-flow selection shared by packet and control owners.
//! A choice is routing metadata. The packet owner still checks its installed
//! exact ExitPair and native carrier before committing a NAT assignment.
use super::authority_event::Authority;
use anyhow::{ensure, Result};
use porthub_network::policy::{
    ExitChoice, ExitPickRequest, ExitPickResponse, ExitPickStatus, ExitRole, Snapshot,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
const CAPACITY: usize = 256;
const IDLE: Duration = Duration::from_secs(120);
const RETRY: Duration = Duration::from_secs(3);
#[derive(Clone, Default)]
pub(crate) struct Handle(Arc<Mutex<State>>, Arc<tokio::sync::Notify>);
#[derive(Default)]
struct State {
    scope: Option<(String, String, Ipv4Addr, String, String, String, String)>,
    routes: BTreeSet<String>,
    ordinal: u64,
    carriers: Option<(Instant, bool, bool)>,
    entries: BTreeMap<(String, String, bool), Entry>,
    active: Option<(String, String, bool)>,
}
struct Entry {
    request: ExitPickRequest,
    used: Instant,
    retry: Instant,
    started: bool,
    choice: Option<(ExitChoice, Authority<()>)>,
}
impl Handle {
    fn due(state: &State, now: Instant) -> bool {
        if state.scope.is_none() { return false; }
        if let Some(key) = &state.active {
            if let Some(entry) = state.entries.get(key) {
                return entry.choice.is_none() && entry.retry <= now;
            }
        }
        state.entries.values().any(|entry| entry.choice.is_none() && entry.retry <= now)
    }
    fn notify_due(&self, state: &State) {
        if Self::due(state, Instant::now()) { self.1.notify_one(); }
    }
    /// Checking state before parking plus Notify's stored permit closes the
    /// request/registration race. Repeated packet polls never create demand.
    pub(crate) fn has_due(&self) -> bool {
        Self::due(&self.0.lock().unwrap(), Instant::now())
    }
    pub(crate) async fn demand(&self) {
        loop {
            if self.has_due() { return; }
            self.1.notified().await;
        }
    }

    pub(crate) fn observe(&self, base: &Snapshot) {
        let mut state = self.0.lock().unwrap();
        let scope = base
            .sparse
            .as_ref()
            .zip(base.peers.iter().find(|p| p.id == base.self_))
            .filter(|(s, _)| s.exit_epoch.is_some() && s.selection_epoch.is_some())
            .map(|(s, p)| {
                (
                    base.workspace.clone(),
                    base.self_.clone(),
                    p.ip,
                    p.fingerprint.clone(),
                    p.instance.clone(),
                    s.exit_epoch.clone().unwrap(),
                    s.selection_epoch.clone().unwrap(),
                )
            });
        if scope != state.scope {
            state.entries.clear();
            state.active = None;
            state.ordinal = 0;
            state.carriers = None;
            state.scope = scope;
        }
        state.routes = base
            .sparse
            .as_ref()
            .map(|s| {
                s.exit_intents
                    .iter()
                    .filter(|i| i.role == ExitRole::Client)
                    .map(|i| i.id.clone())
                    .collect()
            })
            .unwrap_or_default();
        let routes = state.routes.clone();
        state
            .entries
            .retain(|(route, _, _), _| routes.contains(route));
    }
    pub(crate) fn revoke(&self) {
        let mut state = self.0.lock().unwrap();
        state.scope = None;
        state.active = None;
        state.routes.clear();
        state.entries.clear();
        state.carriers = None;
    }
    pub(crate) fn update_carriers(&self, gateway: bool, local_tor: bool) {
        self.0.lock().unwrap().carriers = Some((Instant::now(), gateway, local_tor));
    }
    pub(crate) fn carriers(&self) -> (bool, bool) {
        self.0
            .lock()
            .unwrap()
            .carriers
            .filter(|(at, _, _)| at.elapsed() < Duration::from_secs(3))
            .map(|(_, gateway, tor)| (gateway, tor))
            .unwrap_or((false, false))
    }
    /// Observe a completed choice without creating work, refreshing usage, or
    /// notifying control. Used only to preserve the existing fresh Tor SYN path.
    pub(crate) fn cached_choice(&self,route:&str,flow:&str,destination:Ipv4Addr,warmup:bool)->Option<ExitChoice>{
        let state=self.0.lock().unwrap();if state.scope.is_none()||!state.routes.contains(route){return None;}
        let entry=state.entries.get(&(route.to_owned(),flow.to_owned(),warmup))?;
        if entry.request.destination!=destination||entry.used.elapsed()>=IDLE{return None;}
        let(choice,authority)=entry.choice.as_ref()?;
        (authority.check().is_ok()&&authority.remaining().ok().flatten().is_some()).then(||choice.clone())
    }
    pub(crate) fn request(
        &self,
        route: &str,
        flow: &str,
        destination: Ipv4Addr,
        warmup: bool,
    ) -> Option<ExitChoice> {
        let mut state = self.0.lock().unwrap();
        let now = Instant::now();
        if state.scope.is_none() || !state.routes.contains(route) {
            return None;
        }
        state
            .entries
            .retain(|_, entry| now.duration_since(entry.used) < IDLE);
        let key = (route.to_owned(), flow.to_owned(), warmup);
        if let Some(entry) = state.entries.get_mut(&key) {
            if entry.request.destination != destination {
                return None;
            }
            entry.used = now;
            if let Some((choice, authority)) = &entry.choice {
                if authority.check().is_ok() && authority.remaining().ok().flatten().is_some() {
                    return Some(choice.clone());
                }
                entry.choice = None;
                entry.started = false;
                entry.request.cursor = None;
                entry.retry = now;
                self.notify_due(&state);
            }
            return None;
        }
        if state.entries.len() >= CAPACITY {
            return None;
        }
        let request = ExitPickRequest {
            route_id: route.into(),
            selection_epoch: state.scope.as_ref()?.6.clone(),
            flow_id: flow.into(),
            ordinal: state.ordinal,
            destination,
            local_tor_ready: false,
            available_peers: None,
            cursor: None,
            warmup,
            discover: false,
            unavailable_peers: Vec::new(),
        };
        if request.validate().is_err() {
            return None;
        }
        // Warmup discovers transport metadata and must not consume RR positions.
        if !warmup {
            state.ordinal = state.ordinal.wrapping_add(1);
        }
        state.entries.insert(
            key,
            Entry {
                request,
                used: now,
                retry: now,
                started: false,
                choice: None,
            },
        );
        self.notify_due(&state);
        None
    }
    /// One control RPC per sync. Carrier availability is fixed throughout a
    /// cursor fold; changing it halfway would invalidate the server selection.
    #[cfg(test)]
    pub(crate) fn next(
        &self,
        local_tor_ready: bool,
        available_peers: Option<Vec<String>>,
    ) -> Option<ExitPickRequest> {
        self.next_with_failures(local_tor_ready, available_peers, Vec::new())
    }
    pub(crate) fn next_with_failures(
        &self,
        local_tor_ready: bool,
        available_peers: Option<Vec<String>>,
        unavailable_peers: Vec<String>,
    ) -> Option<ExitPickRequest> {
        let mut state = self.0.lock().unwrap();
        let now = Instant::now();
        if state.scope.is_none() {
            return None;
        }
        state
            .entries
            .retain(|_, entry| now.duration_since(entry.used) < IDLE);
        // The server deliberately keeps one cursor slot per source. Never
        // interleave another cold flow while this fold owns that slot.
        if state
            .active
            .as_ref()
            .is_some_and(|key| !state.entries.contains_key(key))
        {
            state.active = None;
        }
        let key = if let Some(key) = &state.active {
            key.clone()
        } else {
            let key = state
                .entries
                .iter()
                .filter(|(_, entry)| entry.choice.is_none() && entry.retry <= now)
                .min_by_key(|(_, entry)| entry.retry)
                .map(|(key, _)| key.clone())?;
            state.active = Some(key.clone());
            key
        };
        let entry = state.entries.get_mut(&key)?;
        if entry.retry > now {
            return None;
        }
        if !entry.started {
            entry.request.local_tor_ready = local_tor_ready;
            entry.request.discover = !entry.request.warmup && available_peers.is_some();
            entry.request.available_peers = available_peers;
            entry.request.unavailable_peers = unavailable_peers;
            entry.started = true;
        }
        if entry.request.validate().is_err() {
            entry.started = false;
            entry.retry = now + RETRY;
            return None;
        }
        entry.retry = now + RETRY;
        Some(entry.request.clone())
    }
    pub(crate) fn accept(
        &self,
        sent: &ExitPickRequest,
        response: ExitPickResponse,
        authority: Authority<()>,
    ) -> Result<()> {
        authority.check()?;
        ensure!(
            authority.remaining()?.is_some(),
            "exit choice has no bounded request witness"
        );
        let mut state = self.0.lock().unwrap();
        let epoch = &state
            .scope
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("exit picker scope retired"))?
            .5;
        response.validate_for(sent, epoch)?;
        let key = (sent.route_id.clone(), sent.flow_id.clone(), sent.warmup);
        let entry = state
            .entries
            .get_mut(&key)
            .ok_or_else(|| anyhow::anyhow!("exit picker flow retired"))?;
        ensure!(
            serde_json::to_vec(&entry.request)? == serde_json::to_vec(sent)?,
            "exit picker request changed before response"
        );
        let now = Instant::now();
        match response.status {
            ExitPickStatus::Pending => {
                entry.request.cursor = response.cursor;
                entry.retry = now;
            }
            ExitPickStatus::Ready => {
                entry.choice = Some((response.choice.expect("validated ready choice"), authority));
            }
            ExitPickStatus::Unavailable | ExitPickStatus::UpgradeRequired => {
                entry.request.cursor = None;
                entry.started = false;
                entry.retry = now + RETRY;
            }
        }
        if response.status != ExitPickStatus::Pending {
            state.active = None;
        }
        self.notify_due(&state);
        Ok(())
    }
    /// A definitive cursor rejection discards only this fold; unrelated
    /// queued flows and any installed NAT assignments remain untouched.
    pub(crate) fn rejected(&self, sent: &ExitPickRequest) {
        let mut state = self.0.lock().unwrap();
        let key = (sent.route_id.clone(), sent.flow_id.clone(), sent.warmup);
        if let Some(entry) = state.entries.get_mut(&key) {
            if serde_json::to_vec(&entry.request).ok() != serde_json::to_vec(sent).ok() {
                return;
            }
            entry.request.cursor = None;
            entry.started = false;
            entry.retry = Instant::now() + RETRY;
            if state.active.as_ref() == Some(&key) {
                state.active = None;
            }
        }
    }
    pub(crate) fn committed(&self, route: &str, flow: &str) {
        let mut state = self.0.lock().unwrap();
        let key = (route.into(), flow.into(), false);
        state.entries.remove(&key);
        if state.active.as_ref() == Some(&key) {
            state.active = None;
        }
        self.notify_due(&state);
    }
}

/// Only observed transport failures are excluded. Absence of a carrier is
/// discovery work, not evidence that a registered router is unreachable.
#[derive(Default)]
pub(crate) struct Failures(BTreeMap<String, Instant>);
impl Failures {
    pub(crate) fn observe(&mut self, id: &str, ready: bool, failed: bool) {
        self.0
            .retain(|_, at| at.elapsed() < Duration::from_secs(30));
        if ready {
            self.0.remove(id);
        } else if failed && (self.0.len() < CAPACITY || self.0.contains_key(id)) {
            self.0.insert(id.into(), Instant::now());
        }
    }
    pub(crate) fn peers(&mut self) -> Vec<String> {
        self.0
            .retain(|_, at| at.elapsed() < Duration::from_secs(30));
        self.0.keys().cloned().collect()
    }
}

/// A reused TCP tuple with a new SYN sequence is a new cold-flow request.
pub(crate) fn flow_tag(flow: &str, syn: Option<u32>) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(flow.as_bytes());
    hash.update([u8::from(syn.is_some())]);
    hash.update(syn.unwrap_or_default().to_be_bytes());
    format!("{:x}", hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_network::authority_clock::{RequestWindow, SuspendClock};
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Clock(AtomicU64);
    impl SuspendClock for Clock {
        fn elapsed_since_boot(&self) -> Result<Duration> {
            Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))
        }
    }
    fn base() -> Snapshot {
        serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(30),
            "sparse":{"protocol":1,"epoch":"a".repeat(64),"exit_epoch":"e".repeat(64),"selection_epoch":"c".repeat(64),"exit_intents":[{"id":"route","name":"Exit","role":"client","selection":"sticky","traffic_mode":"internet_only","allow_direct_fallback":false,"tor_enabled":true,"tor_circuit_groups":4}]},
            "peers":[{"id":"a","ip":"10.234.0.1","fingerprint":"fp-a","instance":"a-instance","hostname":"a.phub"}],"grants":[]})).unwrap()
    }
    fn authority(clock: Arc<Clock>) -> Authority<()> {
        Authority::new(
            (),
            Some(RequestWindow::start(clock).unwrap()),
            chrono::Utc::now() + chrono::Duration::seconds(30),
        )
    }
    fn reply(request: &ExitPickRequest, status: ExitPickStatus) -> ExitPickResponse {
        ExitPickResponse {
            route_id: request.route_id.clone(),
            selection_epoch: request.selection_epoch.clone(),
            flow_id: request.flow_id.clone(),
            ordinal: request.ordinal,
            warmup: request.warmup,
            discover: request.discover,
            epoch: "e".repeat(64),
            status,
            choice: (status == ExitPickStatus::Ready).then_some(ExitChoice::LocalTor),
            lease: None,
            cursor: (status == ExitPickStatus::Pending).then(|| "cursor-1".into()),
        }
    }
    #[tokio::test]
    async fn cached_tor_view_never_creates_work_or_refreshes_original_choice(){
        let handle=Handle::default();handle.observe(&base());let dst="1.1.1.1".parse().unwrap();let flow="c".repeat(64);
        assert!(handle.cached_choice("route",&flow,dst,false).is_none());assert!(handle.next(true,None).is_none());
        assert!(tokio::time::timeout(Duration::from_millis(10),handle.demand()).await.is_err());
        handle.request("route",&flow,dst,false);handle.demand().await;let sent=handle.next(true,None).unwrap();let clock=Arc::new(Clock(AtomicU64::new(0)));
        handle.accept(&sent,reply(&sent,ExitPickStatus::Ready),authority(clock.clone())).unwrap();let key=("route".to_owned(),flow.clone(),false);
        let used=handle.0.lock().unwrap().entries[&key].used;
        assert!(matches!(handle.cached_choice("route",&flow,dst,false),Some(ExitChoice::LocalTor)));assert_eq!(handle.0.lock().unwrap().entries[&key].used,used);
        clock.0.store(15000,Ordering::SeqCst);assert!(handle.cached_choice("route",&flow,dst,false).is_none());
        assert!(tokio::time::timeout(Duration::from_millis(10),handle.demand()).await.is_err(),"read-only peek must not start a new control grant");
    }
    #[tokio::test]
    async fn demand_covers_before_and_after_wait_registration_without_packet_poll_wakes() {
        let handle = Handle::default();
        handle.observe(&base());
        let dst = "1.1.1.1".parse().unwrap();
        let first = "a".repeat(64);
        handle.request("route", &first, dst, false);
        tokio::time::timeout(Duration::from_millis(100),handle.demand()).await.unwrap();
        let sent = handle.next(true,None).unwrap();
        for _ in 0..1000 { handle.request("route", &first, dst, false); }
        assert!(tokio::time::timeout(Duration::from_millis(10),handle.demand()).await.is_err());
        handle.accept(&sent,reply(&sent,ExitPickStatus::Pending),authority(Arc::new(Clock(AtomicU64::new(0))))).unwrap();
        tokio::time::timeout(Duration::from_millis(100),handle.demand()).await.unwrap();
        let sent = handle.next(true,None).unwrap();
        handle.accept(&sent,reply(&sent,ExitPickStatus::Ready),authority(Arc::new(Clock(AtomicU64::new(0))))).unwrap();
        let parked=handle.clone();
        let waiter=tokio::spawn(async move{parked.demand().await});
        tokio::task::yield_now().await;
        handle.request("route", &"b".repeat(64), dst, false);
        tokio::time::timeout(Duration::from_millis(100),waiter).await.unwrap().unwrap();
        handle.revoke();
        assert!(tokio::time::timeout(Duration::from_millis(10),handle.demand()).await.is_err());
    }
    #[test]
    fn tcp_tuple_reuse_has_distinct_correlation_and_stale_carriers_are_not_ready() {
        let flow = "a".repeat(64);
        assert_eq!(flow_tag(&flow, Some(1)), flow_tag(&flow, Some(1)));
        assert_ne!(flow_tag(&flow, Some(1)), flow_tag(&flow, Some(2)));
        assert_ne!(flow_tag(&flow, None), flow_tag(&flow, Some(0)));
        let handle = Handle::default();
        handle.0.lock().unwrap().carriers =
            Some((Instant::now() - Duration::from_secs(4), true, true));
        assert_eq!(handle.carriers(), (false, false));
    }
    #[test]
    fn one_server_cursor_is_not_overwritten_by_another_flow_and_commits_free_capacity() {
        let handle = Handle::default();
        handle.observe(&base());
        let dst = "1.1.1.1".parse().unwrap();
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        handle.request("route", &first, dst, false);
        let request = handle.next(true, None).unwrap();
        handle.request("route", &second, dst, false);
        assert!(
            handle.next(true, None).is_none(),
            "pending HTTP retry must retain the single source slot"
        );
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        handle
            .accept(
                &request,
                reply(&request, ExitPickStatus::Pending),
                authority(clock.clone()),
            )
            .unwrap();
        let continuation = handle.next(true, None).unwrap();
        assert_eq!(continuation.flow_id, first);
        handle.rejected(&continuation);
        let other = handle.next(true, None).unwrap();
        assert_eq!(other.flow_id, second);
        handle
            .accept(
                &other,
                reply(&other, ExitPickStatus::Ready),
                authority(clock),
            )
            .unwrap();
        assert_eq!(
            handle.request("route", &second, dst, false),
            Some(ExitChoice::LocalTor)
        );
        handle.committed("route", &second);
        let state = handle.0.lock().unwrap();
        assert_eq!(state.entries.len(), 1);
        assert!(state.active.is_none());
        assert!(state
            .entries
            .values()
            .next()
            .unwrap()
            .request
            .cursor
            .is_none());
    }
    #[test]
    fn direct_only_flow_discovers_beyond_ready_cache_and_excludes_only_observed_failures() {
        let handle = Handle::default();
        handle.observe(&base());
        let dst = "1.1.1.1".parse().unwrap();
        let mut failures = Failures::default();
        failures.observe("unknown", false, false);
        assert!(failures.peers().is_empty());
        failures.observe("broken", false, true);
        handle.request("route", &"a".repeat(64), dst, false);
        let request = handle
            .next_with_failures(false, Some(Vec::new()), failures.peers())
            .unwrap();
        assert!(request.discover);
        assert_eq!(request.available_peers, Some(Vec::new()));
        assert_eq!(request.unavailable_peers, ["broken"]);
        assert_eq!(request.ordinal, 0);
        request.validate().unwrap();
        failures.observe("broken", true, false);
        assert!(failures.peers().is_empty());
        for i in 0..CAPACITY + 10 {
            failures.observe(&format!("peer-{i}"), false, true);
        }
        assert_eq!(failures.peers().len(), CAPACITY);
        for at in failures.0.values_mut() {
            *at = Instant::now() - Duration::from_secs(31);
        }
        assert!(failures.peers().is_empty());
    }
    #[test]
    fn scheduling_generation_retires_pending_choices_independently_of_permission_epoch() {
        let handle = Handle::default();
        let mut snapshot = base();
        handle.observe(&snapshot);
        let dst = "1.1.1.1".parse().unwrap();
        let flow = "a".repeat(64);
        handle.request("route", &flow, dst, false);
        let old = handle.next(true, None).unwrap();
        snapshot.sparse.as_mut().unwrap().selection_epoch = Some("d".repeat(64));
        handle.observe(&snapshot);
        handle.request("route", &flow, dst, false);
        let fresh = handle.next(true, None).unwrap();
        assert_eq!(fresh.selection_epoch, "d".repeat(64));
        assert_eq!(
            snapshot.sparse.as_ref().unwrap().exit_epoch.as_deref(),
            Some("e".repeat(64).as_str())
        );
        assert!(handle
            .accept(
                &old,
                reply(&old, ExitPickStatus::Ready),
                authority(Arc::new(Clock(AtomicU64::new(0))))
            )
            .is_err());
    }
    #[test]
    fn selection_is_bounded_and_warmup_does_not_consume_flow_ordinals() {
        let handle = Handle::default();
        handle.observe(&base());
        let dst = "1.1.1.1".parse().unwrap();
        handle.request("route", &"f".repeat(64), dst, true);
        assert_eq!(handle.next(true, None).unwrap().ordinal, 0);
        for i in 0..CAPACITY + 10 {
            handle.request("route", &format!("{i:064x}"), dst, false);
        }
        let state = handle.0.lock().unwrap();
        assert_eq!(state.entries.len(), CAPACITY);
        assert_eq!(state.ordinal, 255);
        assert_eq!(
            state.entries[&("route".into(), format!("{:064x}", 0), false)]
                .request
                .ordinal,
            0
        );
    }
    #[test]
    fn cursor_continuation_freezes_input_and_rejects_outdated_response() {
        let handle = Handle::default();
        handle.observe(&base());
        handle.request("route", &"b".repeat(64), "1.1.1.1".parse().unwrap(), false);
        let first = handle.next(true, None).unwrap();
        assert!(handle.next(false, Some(vec![])).is_none());
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        handle
            .accept(
                &first,
                reply(&first, ExitPickStatus::Pending),
                authority(clock.clone()),
            )
            .unwrap();
        let next = handle.next(false, Some(vec![])).unwrap();
        assert_eq!(next.cursor.as_deref(), Some("cursor-1"));
        assert!(next.local_tor_ready);
        assert!(next.available_peers.is_none());
        assert!(handle
            .accept(
                &first,
                reply(&first, ExitPickStatus::Ready),
                authority(clock.clone())
            )
            .is_err());
        handle
            .accept(
                &next,
                reply(&next, ExitPickStatus::Ready),
                authority(clock.clone()),
            )
            .unwrap();
        assert_eq!(
            handle.request("route", &first.flow_id, first.destination, false),
            Some(ExitChoice::LocalTor)
        );
        clock.0.store(15000, Ordering::SeqCst);
        assert!(handle
            .request("route", &first.flow_id, first.destination, false)
            .is_none());
        let retried = handle.next(false, Some(vec![])).unwrap();
        assert_eq!(retried.ordinal, first.ordinal);
        assert!(retried.cursor.is_none());
        assert!(!retried.local_tor_ready);
    }
    #[test]
    fn scope_change_revoke_and_missing_native_observation_clear_choices() {
        let handle = Handle::default();
        let mut snapshot = base();
        handle.observe(&snapshot);
        let dst = "1.1.1.1".parse().unwrap();
        let flow = "b".repeat(64);
        assert_eq!(handle.carriers(), (false, false));
        handle.update_carriers(true, true);
        assert_eq!(handle.carriers(), (true, true));
        handle.request("route", &flow, dst, false);
        let request = handle.next(true, None).unwrap();
        snapshot.sparse.as_mut().unwrap().exit_epoch = Some("f".repeat(64));
        handle.observe(&snapshot);
        assert_eq!(handle.carriers(), (false, false));
        assert!(handle
            .accept(
                &request,
                reply(&request, ExitPickStatus::Ready),
                authority(Arc::new(Clock(AtomicU64::new(0))))
            )
            .is_err());
        assert!(handle.next(true, None).is_none());
        handle.revoke();
        assert!(handle.request("route", &flow, dst, false).is_none());
        assert!(handle.next(true, None).is_none());
    }
}
