//! Local-only traffic envelopes. The broker supplies the profile/session scope;
//! reports cannot select a machine, account or another connection's epoch.
use anyhow::{ensure, Result};
use porthub_terminal::{
    protocol::{random_token, token},
    traffic::Snapshot,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};
const MAX_PROFILES: usize = 128;
const MAX_SESSIONS: usize = 1024;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    #[serde(rename = "type")]
    kind: PolicyKind,
    pub epoch: String,
}
#[derive(Deserialize, Serialize)]
enum PolicyKind {
    #[serde(rename = "terminal_traffic_policy")]
    Policy,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Report {
    #[serde(rename = "type")]
    kind: ReportKind,
    pub epoch: String,
    pub sequence: u64,
    pub counters: Snapshot,
}
#[derive(Clone, Deserialize, Serialize)]
enum ReportKind {
    #[serde(rename = "terminal_local_traffic")]
    Report,
}
pub(crate) struct Emitter {
    epoch: String,
    sequence: u64,
}
impl Emitter {
    pub fn new(policy: Policy) -> Result<Self> {
        ensure!(token(&policy.epoch, 32), "invalid terminal traffic epoch");
        Ok(Self {
            epoch: policy.epoch,
            sequence: 0,
        })
    }
    pub fn report(&mut self, counters: Snapshot) -> Result<Report> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("terminal telemetry sequence exhausted"))?;
        Ok(Report {
            kind: ReportKind::Report,
            epoch: self.epoch.clone(),
            sequence: self.sequence,
            counters,
        })
    }
}
pub(crate) use porthub_terminal::traffic_report::Summary;
static PROFILES: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<Summary>>>>> = OnceLock::new();
fn profiles() -> &'static Mutex<HashMap<PathBuf, Arc<Mutex<Summary>>>> {
    PROFILES.get_or_init(Default::default)
}
pub(crate) fn snapshot(profile: &Path) -> Summary {
    profiles()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(profile)
        .map(|state| {
            state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone()
        })
        .unwrap_or_default()
}
pub(crate) struct Lease {
    state: Arc<Mutex<Summary>>,
    epoch: String,
    sequence: u64,
    counters: Snapshot,
    participants: usize,
    limit: usize,
}
impl Lease {
    pub fn open(profile: &Path, limit: usize) -> Result<Self> {
        ensure!(
            (1..=porthub_terminal::protocol::MAX_VIEWERS).contains(&limit),
            "invalid terminal telemetry limit"
        );
        let mut profiles = profiles().lock().unwrap_or_else(|error| error.into_inner());
        ensure!(
            profiles.contains_key(profile) || profiles.len() < MAX_PROFILES,
            "terminal telemetry profile limit reached"
        );
        let state = profiles.entry(profile.into()).or_default().clone();
        Self::start(state, limit)
    }
    fn start(state: Arc<Mutex<Summary>>, limit: usize) -> Result<Self> {
        let epoch = random_token(16);
        {
            let mut summary = state.lock().unwrap_or_else(|error| error.into_inner());
            ensure!(
                summary.active_sessions < MAX_SESSIONS,
                "terminal telemetry session limit reached"
            );
            if summary.instance.is_empty() {
                summary.instance = random_token(16);
            }
            summary.observed_at = Some(porthub_terminal::protocol::now());
            summary.active_sessions += 1;
            summary.revision = summary.revision.saturating_add(1);
        }
        Ok(Self {
            state,
            epoch,
            sequence: 0,
            counters: Snapshot::default(),
            participants: 0,
            limit,
        })
    }
    pub fn policy(&self) -> Policy {
        Policy {
            kind: PolicyKind::Policy,
            epoch: self.epoch.clone(),
        }
    }
    pub fn participants(&mut self, count: usize) {
        let count = count.min(self.limit);
        if count == self.participants {
            return;
        }
        let mut summary = self.state.lock().unwrap_or_else(|error| error.into_inner());
        summary.active_participants = summary
            .active_participants
            .saturating_sub(self.participants)
            .saturating_add(count);
        summary.revision = summary.revision.saturating_add(1);
        summary.observed_at = Some(porthub_terminal::protocol::now());
        self.participants = count;
    }
    pub fn relay(&self, sent: bool, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let mut summary = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if sent {
            summary.relay_sent_payload_bytes = summary
                .relay_sent_payload_bytes
                .saturating_add(bytes as u64);
        } else {
            summary.relay_received_payload_bytes = summary
                .relay_received_payload_bytes
                .saturating_add(bytes as u64);
        }
        summary.observed_at = Some(porthub_terminal::protocol::now());
        summary.revision = summary.revision.saturating_add(1);
    }
    pub fn record(&mut self, report: Report) -> Result<()> {
        ensure!(
            report.epoch == self.epoch && report.sequence > 0,
            "invalid scoped terminal traffic report"
        );
        if report.sequence == self.sequence {
            ensure!(
                report.counters == self.counters,
                "conflicting terminal traffic replay"
            );
            return Ok(());
        }
        ensure!(
            report.sequence > self.sequence,
            "stale terminal traffic report"
        );
        let old = self.counters;
        let next = report.counters;
        ensure!(
            next.input_bytes >= old.input_bytes
                && next.output_bytes >= old.output_bytes
                && next.direct_udp_sent_bytes >= old.direct_udp_sent_bytes
                && next.direct_udp_received_bytes >= old.direct_udp_received_bytes,
            "terminal traffic counters regressed"
        );
        let mut summary = self.state.lock().unwrap_or_else(|error| error.into_inner());
        summary.counters.input_bytes = summary
            .counters
            .input_bytes
            .saturating_add(next.input_bytes - old.input_bytes);
        summary.counters.output_bytes = summary
            .counters
            .output_bytes
            .saturating_add(next.output_bytes - old.output_bytes);
        summary.counters.direct_udp_sent_bytes = summary
            .counters
            .direct_udp_sent_bytes
            .saturating_add(next.direct_udp_sent_bytes - old.direct_udp_sent_bytes);
        summary.counters.direct_udp_received_bytes = summary
            .counters
            .direct_udp_received_bytes
            .saturating_add(next.direct_udp_received_bytes - old.direct_udp_received_bytes);
        if self.sequence == 0 {
            summary.reported_sessions = summary.reported_sessions.saturating_add(1);
            summary.active_reporting_sessions += 1;
        }
        summary.observed_at = Some(porthub_terminal::protocol::now());
        summary.revision = summary.revision.saturating_add(1);
        self.sequence = report.sequence;
        self.counters = next;
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut summary = self.state.lock().unwrap_or_else(|error| error.into_inner());
        summary.active_sessions = summary.active_sessions.saturating_sub(1);
        if self.sequence > 0 {
            summary.active_reporting_sessions = summary.active_reporting_sessions.saturating_sub(1);
        }
        summary.observed_at = Some(porthub_terminal::protocol::now());
        summary.revision = summary.revision.saturating_add(1);
        summary.active_participants = summary
            .active_participants
            .saturating_sub(self.participants);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reconnect_epochs_replays_and_closed_sessions_keep_exact_profile_totals() -> Result<()> {
        let state = Arc::new(Mutex::new(Summary::default()));
        let mut first = Lease::start(state.clone(), 2)?;
        let mut sender = Emitter::new(first.policy())?;
        let report = sender.report(Snapshot {
            input_bytes: 7,
            output_bytes: 11,
            ..Default::default()
        })?;
        first.participants(2);
        first.record(report.clone())?;
        let revision = state.lock().unwrap().revision;
        first.record(report)?;
        assert_eq!(
            state.lock().unwrap().revision,
            revision,
            "duplicate reports must be idempotent for upstream sampling"
        );
        let mut second = Lease::start(state.clone(), 1)?;
        let mut other = Emitter::new(second.policy())?;
        let report = other.report(Snapshot {
            input_bytes: 3,
            direct_udp_sent_bytes: 19,
            ..Default::default()
        })?;
        assert!(
            first.record(report.clone()).is_err(),
            "another stream's epoch must not choose this scope"
        );
        second.participants(1);
        second.record(report)?;
        first.relay(true, 23);
        second.relay(false, 29);
        drop(first);
        let value = state.lock().unwrap().clone();
        assert!(token(&value.instance, 32));
        assert_eq!(value.relay_sent_payload_bytes, 23);
        assert_eq!(value.relay_received_payload_bytes, 29);
        assert_eq!(value.counters.input_bytes, 10);
        assert_eq!(value.counters.output_bytes, 11);
        assert_eq!(value.counters.direct_udp_sent_bytes, 19);
        assert_eq!(value.active_sessions, 1);
        assert_eq!(value.active_participants, 1);
        let bad = other.report(Snapshot {
            input_bytes: 2,
            ..Default::default()
        })?;
        assert!(second.record(bad).is_err());
        drop(second);
        assert_eq!(state.lock().unwrap().active_participants, 0);
        assert_eq!(state.lock().unwrap().counters.input_bytes, 10);
        Ok(())
    }
    #[test]
    fn local_traffic_cannot_become_a_gateway_event_or_choose_an_identity() -> Result<()> {
        let state = Arc::new(Mutex::new(Summary::default()));
        let lease = Lease::start(state, 1)?;
        let mut emitter = Emitter::new(lease.policy())?;
        let mut report = serde_json::to_value(emitter.report(Snapshot::default())?)?;
        assert!(
            serde_json::from_value::<porthub_terminal::protocol::HostOutput>(report.clone())
                .is_err()
        );
        assert!(
            serde_json::from_value::<porthub_terminal::protocol::HostEvent>(serde_json::to_value(
                lease.policy()
            )?)
            .is_err()
        );
        assert!(
            serde_json::from_value::<porthub_terminal::protocol::ViewerInput>(report.clone())
                .is_err()
        );
        report["machine_id"] = "another-machine".into();
        assert!(serde_json::from_value::<Report>(report).is_err());
        Ok(())
    }
}
