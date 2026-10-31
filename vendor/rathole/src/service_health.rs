//! Read-only health snapshots and a wakeup for the existing control actor.
//! A check cannot own, abort, or time-limit an established forwarding copy.
use std::sync::{Arc, Mutex};
use tokio::{
    sync::Notify,
    time::{Duration, Instant},
};
#[derive(Clone, Debug, serde::Serialize)]
pub struct ServiceHealth {
    pub state: &'static str,
    pub data_health_acknowledged: bool,
    pub checks: u64,
    pub control_recoveries: u64,
}
struct State {
    connected: bool,
    ever_connected: bool,
    last_command: Instant,
    timeout: Duration,
    data_health: bool,
    checks: u64,
    recoveries: u64,
}
struct Shared {
    state: Mutex<State>,
    wake: Notify,
    traffic: Arc<crate::telemetry::Counters>,
}
#[derive(Clone)]
pub struct ServiceHealthHandle(Arc<Shared>);
impl ServiceHealthHandle {
    pub(crate) fn new(timeout: u64) -> Self {
        Self(Arc::new(Shared {
            state: Mutex::new(State {
                connected: false,
                ever_connected: false,
                last_command: Instant::now(),
                timeout: Duration::from_secs(timeout),
                data_health: false,
                checks: 0,
                recoveries: 0,
            }),
            wake: Notify::new(),
            traffic: Arc::new(crate::telemetry::Counters::default()),
        }))
    }
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn traffic(&self)->crate::Traffic { self.0.traffic.snapshot() }
    pub fn same_instance(&self,other:&Self)->bool {Arc::ptr_eq(&self.0,&other.0)}
    /// Only fold retired counters after all actors and I/O writers release them.
    pub fn traffic_finished(&self)->bool {Arc::strong_count(&self.0)==1 && Arc::strong_count(&self.0.traffic)==1}
    pub(crate) fn counters(&self)->Arc<crate::telemetry::Counters>{self.0.traffic.clone()}
    /// Observability must never nudge, probe or reconnect a healthy service.
    pub fn observe(&self)->ServiceHealth {
        let state=self.state();let healthy=state.connected && (state.timeout.is_zero() || state.last_command.elapsed()<state.timeout);
        ServiceHealth{state:if healthy{"healthy"}else{"recovering"},data_health_acknowledged:state.data_health,checks:state.checks,control_recoveries:state.recoveries}
    }
    /// Uses authenticated control activity; never opens an application socket.
    pub fn check(&self) -> ServiceHealth {
        let mut state = self.state();
        state.checks = state.checks.saturating_add(1);
        let healthy = state.connected
            && (state.timeout.is_zero() || state.last_command.elapsed() < state.timeout);
        let result = ServiceHealth {
            state: if healthy { "healthy" } else { "recovering" },
            data_health_acknowledged: state.data_health,
            checks: state.checks,
            control_recoveries: state.recoveries,
        };
        drop(state);
        self.0.wake.notify_one();
        result
    }
    pub(crate) fn connected(&self, data_health: bool) {
        let mut s = self.state();
        if s.ever_connected && !s.connected {
            s.recoveries = s.recoveries.saturating_add(1);
        }
        s.connected = true;
        s.ever_connected = true;
        s.last_command = Instant::now();
        s.data_health = data_health;
    }
    pub(crate) fn command(&self) {
        self.state().last_command = Instant::now();
    }
    pub(crate) fn disconnected(&self) {
        self.state().connected = false;
    }
    pub(crate) fn stale(&self) -> bool {
        let s = self.state();
        s.connected && !s.timeout.is_zero() && s.last_command.elapsed() >= s.timeout
    }
    pub(crate) async fn notified(&self) {
        self.0.wake.notified().await;
    }
}
pub(crate) struct Guard(pub ServiceHealthHandle);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.disconnected();
    }
}
