//! Cumulative, content-free service measurements shared by agent and gateway.
//! An instance changes on service restart. Revisions order snapshots within it.
use crate::traffic::Snapshot;
use serde::{Deserialize, Serialize};

pub const MAX_COUNTER: u64 = (1_u64 << 53) - 1;
#[derive(Default, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub counters: Snapshot,
    pub instance: String,
    pub revision: u64,
    pub relay_sent_payload_bytes: u64,
    pub relay_received_payload_bytes: u64,
    pub active_sessions: usize,
    pub active_participants: usize,
    pub reported_sessions: u64,
    pub active_reporting_sessions: usize,
    pub observed_at: Option<i64>,
}
impl Summary {
    /// Numeric values remain exact in MongoDB and browser JSON consumers.
    pub fn valid(&self) -> bool {
        self.instance.len() == 32
            && self
                .instance
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && (1..=MAX_COUNTER).contains(&self.revision)
            && self.values().iter().all(|value| *value <= MAX_COUNTER)
            && self.reported_sessions <= MAX_COUNTER
            && self.active_sessions <= 1024
            && self.active_participants <= 65536
            && self.active_reporting_sessions <= self.active_sessions
    }
    /// Independent scopes: callers must not sum PTY payload and UDP traffic.
    pub fn values(&self) -> [u64; 6] {
        [
            self.counters.input_bytes,
            self.counters.output_bytes,
            self.counters.direct_udp_sent_bytes,
            self.counters.direct_udp_received_bytes,
            self.relay_sent_payload_bytes,
            self.relay_received_payload_bytes,
        ]
    }
    pub fn monotonic_after(&self, previous: &Self) -> bool {
        self.instance == previous.instance
            && self.revision > previous.revision
            && self.reported_sessions >= previous.reported_sessions
            && self
                .values()
                .iter()
                .zip(previous.values())
                .all(|(next, old)| *next >= old)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reports_reject_unsafe_numbers_selectors_and_impossible_gauges() {
        let mut row = Summary {
            instance: "a".repeat(32),
            revision: 1,
            ..Default::default()
        };
        assert!(row.valid());
        row.counters.input_bytes = MAX_COUNTER + 1;
        assert!(!row.valid());
        row.counters.input_bytes = 0;
        row.active_reporting_sessions = 1;
        assert!(!row.valid());
        row.active_sessions = 1;
        assert!(row.valid());
        let mut value = serde_json::to_value(&row).unwrap();
        value["owner_id"] = "another-account".into();
        assert!(serde_json::from_value::<Summary>(value).is_err());
    }
    #[test]
    fn revisions_and_cumulative_scopes_cannot_regress_or_change_instance() {
        let previous = Summary {
            instance: "b".repeat(32),
            revision: 9,
            ..Default::default()
        };
        let mut next = previous.clone();
        assert!(!next.monotonic_after(&previous));
        next.revision += 1;
        next.counters.direct_udp_sent_bytes = 17;
        assert!(next.monotonic_after(&previous));
        assert!(!previous.monotonic_after(&next));
        next.instance = "c".repeat(32);
        assert!(!next.monotonic_after(&previous));
    }
}
