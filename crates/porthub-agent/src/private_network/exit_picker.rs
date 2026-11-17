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
pub(crate) struct Handle(Arc<Mutex<State>>);
#[derive(Default)]
struct State {
    scope: Option<(String, String, Ipv4Addr, String, String, String)>,
    routes: BTreeSet<String>,
    ordinal: u64,
    carriers: Option<(Instant, bool, bool)>,
    entries: BTreeMap<(String, String, bool), Entry>,
}
struct Entry {
    request: ExitPickRequest,
    used: Instant,
    retry: Instant,
    started: bool,
    choice: Option<(ExitChoice, Authority<()>)>,
}
impl Handle {
    pub(crate) fn observe(&self, base: &Snapshot) {
        let mut state = self.0.lock().unwrap();
        let scope = base
            .sparse
            .as_ref()
            .zip(base.peers.iter().find(|p| p.id == base.self_))
            .filter(|(s, _)| s.exit_epoch.is_some())
            .map(|(s, p)| {
                (
                    base.workspace.clone(),
                    base.self_.clone(),
                    p.ip,
                    p.fingerprint.clone(),
                    p.instance.clone(),
                    s.exit_epoch.clone().unwrap(),
                )
            });
        if scope != state.scope {
            state.entries.clear();
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
            }
            return None;
        }
        if state.entries.len() >= CAPACITY {
            return None;
        }
        let request = ExitPickRequest {
            route_id: route.into(),
            flow_id: flow.into(),
            ordinal: state.ordinal,
            destination,
            local_tor_ready: false,
            available_peers: None,
            cursor: None,
            warmup,
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
        None
    }
    /// One control RPC per sync. Carrier availability is fixed throughout a
    /// cursor fold; changing it halfway would invalidate the server selection.
    pub(crate) fn next(
        &self,
        local_tor_ready: bool,
        available_peers: Option<Vec<String>>,
    ) -> Option<ExitPickRequest> {
        let mut state = self.0.lock().unwrap();
        let now = Instant::now();
        if state.scope.is_none() {
            return None;
        }
        state
            .entries
            .retain(|_, entry| now.duration_since(entry.used) < IDLE);
        let entry = state
            .entries
            .values_mut()
            .filter(|entry| entry.choice.is_none() && entry.retry <= now)
            .min_by_key(|entry| entry.retry)?;
        if !entry.started {
            entry.request.local_tor_ready = local_tor_ready;
            entry.request.available_peers = available_peers;
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
        Ok(())
    }
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
            "sparse":{"protocol":1,"epoch":"a".repeat(64),"exit_epoch":"e".repeat(64),"exit_intents":[{"id":"route","name":"Exit","role":"client","selection":"sticky","traffic_mode":"internet_only","allow_direct_fallback":false,"tor_enabled":true,"tor_circuit_groups":4}]},
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
            flow_id: request.flow_id.clone(),
            ordinal: request.ordinal,
            warmup: request.warmup,
            epoch: "e".repeat(64),
            status,
            choice: (status == ExitPickStatus::Ready).then_some(ExitChoice::LocalTor),
            lease: None,
            cursor: (status == ExitPickStatus::Pending).then(|| "cursor-1".into()),
        }
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
