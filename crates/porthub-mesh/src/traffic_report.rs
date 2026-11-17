//! Bounded immutable private-carrier observations. No addresses or application payloads.
use serde::{Deserialize, Serialize};
pub const MAX_ROWS: usize = 256;
pub const MAX_PENDING: usize = 16_384;
pub const MAX_COUNTER: u64 = (1_u64 << 53) - 1;
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub sequence: u64,
    pub peer_id: String,
    pub at: i64,
    pub duration_seconds: u32,
    pub observed_at: i64,
    pub direct_sent: u64,
    pub direct_received: u64,
    pub relay_sent: u64,
    pub relay_received: u64,
}
impl Row {
    pub fn values(&self) -> [u64; 4] {
        [
            self.direct_sent,
            self.direct_received,
            self.relay_sent,
            self.relay_received,
        ]
    }
    pub fn valid(&self) -> bool {
        self.sequence > 0
            && self.sequence <= MAX_COUNTER
            && peer_id(&self.peer_id)
            && self.at > 0
            && self.at % 60_000 == 0
            && (1..=120).contains(&self.duration_seconds)
            && self.observed_at > self.at
            && self.observed_at <= self.at + 180_000
            && self.values().iter().all(|n| *n <= MAX_COUNTER)
    }
}
pub fn peer_id(value: &str) -> bool {
    value.len() == 49
        && value.as_bytes()[24] == b':'
        && value
            .bytes()
            .enumerate()
            .all(|(i, b)| i == 24 || b.is_ascii_hexdigit())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub instance: String,
    pub rows: Vec<Row>,
    pub dropped_rows: u64,
}
impl Report {
    pub fn valid(&self) -> bool {
        self.instance.len() == 32
            && self.instance.bytes().all(|b| b.is_ascii_hexdigit())
            && self.rows.len() <= MAX_ROWS
            && self.dropped_rows <= MAX_COUNTER
            && self.rows.iter().all(Row::valid)
            && self.rows.windows(2).all(|w| w[0].sequence < w[1].sequence)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unordered_unbounded_or_foreign_shaped_reports() {
        let row = Row {
            sequence: 1,
            peer_id: format!("{}:{}", "a".repeat(24), "b".repeat(24)),
            at: 60_000,
            duration_seconds: 30,
            observed_at: 90_000,
            direct_sent: 12,
            ..Default::default()
        };
        let mut report = Report {
            instance: "a".repeat(32),
            rows: vec![row.clone()],
            dropped_rows: 0,
        };
        assert!(report.valid());
        report.rows.push(row);
        assert!(!report.valid());
        report.rows.pop();
        report.rows[0].direct_sent = MAX_COUNTER + 1;
        assert!(!report.valid());
    }
}
