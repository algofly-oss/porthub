//! Bounded, classified lifecycle events; never log identities or raw failures.
use super::relay;
use crate::control::{Failure, Reply};
use std::{
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Event {
    ReportUnavailable,
    ReportDenied,
    ReportRejected,
    ReportInvalid,
    PlansInvalid,
    PolicyChanged,
    PlanWithdrawn,
    PlanChanged,
    TaskFinished,
    WorkerStopped,
    ImportRegistrationFailed,
    PlannedRestart,
    DataClosed,
    LocalRestart,
    PeerRestart,
    SessionCancelled,
    SessionClosed,
    Reconnecting,
    ControlClosed,
    ControlProtocol,
    Io(std::io::ErrorKind),
    SessionOther,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Role {
    Controller,
    Carrier,
    Source,
    Destination,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Phase {
    Control,
    Setup,
    Direct,
    Gateway,
}
impl Phase {
    pub(super) fn from_state(state: Option<&str>) -> Self {
        match state {
            Some("active-direct") => Self::Direct,
            Some("active-relay") => Self::Gateway,
            _ => Self::Setup,
        }
    }
}

pub(super) fn report_response(result: Result<Reply, Failure>) -> Result<serde_json::Value, Event> {
    match result {
        Ok(reply) => reply.json().map_err(|_| Event::ReportInvalid),
        Err(Failure::Unavailable) => Err(Event::ReportUnavailable),
        Err(Failure::Rejected(401 | 403 | 410)) => Err(Event::ReportDenied),
        Err(Failure::Rejected(_)) => Err(Event::ReportRejected),
        Err(Failure::InvalidResponse) => Err(Event::ReportInvalid),
    }
}
pub(super) fn reconciliation(finished: bool, exists: bool, same: bool) -> Option<Event> {
    if finished {
        Some(Event::TaskFinished)
    } else if !exists {
        Some(Event::PlanWithdrawn)
    } else if !same {
        Some(Event::PlanChanged)
    } else {
        None
    }
}
pub(super) fn terminal(result: &anyhow::Result<()>, cancelled: bool) -> Event {
    if cancelled {
        return Event::SessionCancelled;
    }
    let Err(error) = result else {
        return Event::SessionClosed;
    };
    if error.is::<relay::Reconnecting>() {
        return Event::Reconnecting;
    }
    if error.is::<relay::Reconfigure>() {
        return Event::PlannedRestart;
    }
    for cause in error.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return Event::Io(io.kind());
        }
        if let Some(ws) = cause.downcast_ref::<tokio_tungstenite::tungstenite::Error>() {
            match ws {
                tokio_tungstenite::tungstenite::Error::ConnectionClosed
                | tokio_tungstenite::tungstenite::Error::AlreadyClosed => {
                    return Event::ControlClosed
                }
                tokio_tungstenite::tungstenite::Error::Protocol(_) => {
                    return Event::ControlProtocol
                }
                _ => {}
            }
        }
    }
    Event::SessionOther
}

const WINDOW: Duration = Duration::from_secs(60);
const LIMIT: u8 = 8;
#[derive(Default)]
struct Budget {
    start: Option<Instant>,
    emitted: u8,
    suppressed: u64,
}
impl Budget {
    fn admit(&mut self, now: Instant) -> Option<u64> {
        if self
            .start
            .is_none_or(|start| now.saturating_duration_since(start) >= WINDOW)
        {
            self.start = Some(now);
            self.emitted = 0;
        }
        if self.emitted == LIMIT {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        self.emitted += 1;
        Some(std::mem::take(&mut self.suppressed))
    }
}
#[derive(Clone, Default)]
pub(super) struct Events(Arc<Mutex<Budget>>);
impl Events {
    pub(super) fn process() -> Self {
        static EVENTS: OnceLock<Events> = OnceLock::new();
        EVENTS.get_or_init(Events::default).clone()
    }
    pub(super) fn record(&self, event: Event, role: Role, phase: Phase, affected: usize) {
        if affected == 0 {
            return;
        }
        let admitted = self
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .admit(Instant::now());
        if let Some(suppressed) = admitted {
            tracing::info!(
                reason = ?event,
                role = ?role,
                phase = ?phase,
                affected_sessions = affected.min(64),
                suppressed,
                "USB session transition"
            );
        }
    }
}

pub(super) fn carrier(event: Event, phase: Phase) {
    Events::process().record(event, Role::Carrier, phase, 1);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_budget_reports_suppression_and_idle_is_silent() {
        let now = Instant::now();
        let mut gate = Budget::default();
        for _ in 0..LIMIT {
            assert_eq!(gate.admit(now), Some(0));
        }
        for _ in 0..100 {
            assert_eq!(gate.admit(now + WINDOW - Duration::from_millis(1)), None);
        }
        assert_eq!(gate.admit(now + WINDOW), Some(100));
        let events = Events::default();
        events.record(Event::PolicyChanged, Role::Controller, Phase::Control, 0);
        assert_eq!(events.0.lock().unwrap().emitted, 0);
    }
    #[test]
    fn report_failures_never_publish_server_error_material() {
        for (failure, event) in [
            (Failure::Unavailable, Event::ReportUnavailable),
            (Failure::Rejected(401), Event::ReportDenied),
            (Failure::Rejected(403), Event::ReportDenied),
            (Failure::Rejected(410), Event::ReportDenied),
            (Failure::Rejected(500), Event::ReportRejected),
            (Failure::InvalidResponse, Event::ReportInvalid),
        ] {
            assert_eq!(report_response(Err(failure)).unwrap_err(), event);
        }
        let reply = Reply {
            authenticated_tls: true,
            status: reqwest::StatusCode::OK,
            headers: Default::default(),
            bytes: b"private-invalid-response".to_vec(),
        };
        assert_eq!(
            report_response(Ok(reply)).unwrap_err(),
            Event::ReportInvalid
        );
    }
    #[test]
    fn reconcile_preserves_original_fail_closed_retention_predicate() {
        for finished in [false, true] {
            for exists in [false, true] {
                for same in [false, true] {
                    if same && !exists {
                        continue;
                    }
                    assert_eq!(
                        reconciliation(finished, exists, same).is_none(),
                        !finished && same
                    );
                }
            }
        }
        assert_eq!(
            reconciliation(false, false, false),
            Some(Event::PlanWithdrawn)
        );
        assert_eq!(reconciliation(false, true, false), Some(Event::PlanChanged));
        assert_eq!(reconciliation(true, true, true), Some(Event::TaskFinished));
    }
    #[test]
    fn terminal_does_not_confuse_cancellation_clean_eof_or_error_chains() {
        assert_eq!(terminal(&Ok(()), false), Event::SessionClosed);
        assert_eq!(terminal(&Ok(()), true), Event::SessionCancelled);
        assert_eq!(
            terminal(
                &Err(anyhow::Error::new(relay::Reconnecting).context("private context")),
                false
            ),
            Event::Reconnecting
        );
        assert_eq!(
            terminal(
                &Err(
                    anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
                        .context("private context")
                ),
                false
            ),
            Event::Io(std::io::ErrorKind::ConnectionReset)
        );
        assert_eq!(
            terminal(
                &Err(anyhow::anyhow!("credential-shaped private material")),
                false
            ),
            Event::SessionOther
        );
    }
    #[test]
    fn classification_never_formats_untrusted_error_display() {
        #[derive(Debug)]
        struct PrivateError;
        impl std::fmt::Display for PrivateError {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("Raw private error must not be rendered")
            }
        }
        impl std::error::Error for PrivateError {}
        assert_eq!(
            terminal(&Err(anyhow::Error::new(PrivateError)), false),
            Event::SessionOther
        );
    }
    #[test]
    fn carrier_and_worker_use_one_process_budget() {
        assert!(Arc::ptr_eq(&Events::process().0, &Events::process().0));
    }
}
