use anyhow::{ensure, Result};
use porthub_terminal::{protocol::token, traffic::Snapshot};
use serde::{Deserialize, Serialize};
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
