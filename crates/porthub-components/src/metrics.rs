//! Bounded machine utilization reports; no process names, paths or command lines.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Memory {
    pub used: u64,
    pub total: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Gpu {
    pub name: String,
    pub utilization: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fan_speed: Option<f32>,
    pub memory: Option<Memory>,
    /// Driver-reported shared system-memory use, separate from dedicated VRAM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_memory: Option<Memory>,
    /// Maximum shareable system memory; neither reserved memory nor a budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_memory_capacity: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrated: Option<bool>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Disk {
    pub id: String,
    pub name: String,
    pub used: u64,
    pub total: u64,
}
/// Physical-drive SMART state. Unknown/removed readings are never healthy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriveStatus {
    Healthy,
    Warning,
    Critical,
    Unavailable,
    Sleeping,
    Removed,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriveHealth {
    /// Hash of the hardware identity; raw hardware serials are not uploaded.
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub capacity: u64,
    pub present: bool,
    pub status: DriveStatus,
    pub observed_at: i64,
    pub checked_at: Option<i64>,
    pub temperature: Option<f32>,
    pub percentage_used: Option<u8>,
    pub available_spare: Option<u8>,
    pub spare_threshold: Option<u8>,
    pub power_on_hours: Option<u64>,
    pub power_cycles: Option<u64>,
    pub unsafe_shutdowns: Option<u64>,
    pub media_errors: Option<u64>,
    pub reallocated_sectors: Option<u64>,
    pub pending_sectors: Option<u64>,
    pub uncorrectable_sectors: Option<u64>,
    pub short_test_supported: bool,
    pub self_test: String,
    pub last_test_started: Option<i64>,
    pub next_test_at: Option<i64>,
    pub reasons: Vec<String>,
}
impl DriveHealth {
    pub fn valid(&self) -> bool {
        let bounded =
            |s: &str, n| !s.is_empty() && s.len() <= n && !s.chars().any(char::is_control);
        self.id.len() == 64
            && self.id.bytes().all(|b| b.is_ascii_hexdigit())
            && bounded(&self.name, 120)
            && bounded(&self.protocol, 24)
            && self.capacity <= i64::MAX as u64
            && self.observed_at > 0
            && self
                .checked_at
                .is_none_or(|at| at > 0 && at <= self.observed_at)
            && self
                .temperature
                .is_none_or(|v| v.is_finite() && (-40.0..=150.0).contains(&v))
            && [self.available_spare, self.spare_threshold]
                .into_iter()
                .flatten()
                .all(|v| v <= 100)
            && [
                self.power_on_hours,
                self.power_cycles,
                self.unsafe_shutdowns,
                self.media_errors,
                self.reallocated_sectors,
                self.pending_sectors,
                self.uncorrectable_sectors,
            ]
            .into_iter()
            .flatten()
            .all(|v| v <= i64::MAX as u64)
            && matches!(
                self.self_test.as_str(),
                "not_run"
                    | "running"
                    | "passed"
                    | "failed"
                    | "aborted"
                    | "unsupported"
                    | "deferred"
            )
            && self
                .last_test_started
                .is_none_or(|at| at > 0 && at <= self.observed_at)
            && self.next_test_at.is_none_or(|at| at > 0)
            && self.reasons.len() <= 8
            && self.reasons.iter().all(|s| bounded(s, 160))
            && (self.present == (self.status != DriveStatus::Removed))
            && (!matches!(
                self.status,
                DriveStatus::Healthy | DriveStatus::Warning | DriveStatus::Critical
            ) || self.checked_at.is_some())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub cpu: f32,
    #[serde(default = "enabled_by_default")]
    pub cpu_available: bool,
    pub cores: u32,
    pub ram: Memory,
    pub disk: Memory,
    pub gpus: Vec<Gpu>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disks: Vec<Disk>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drive_health: Vec<DriveHealth>,
    #[serde(default = "enabled_by_default")]
    pub drive_health_enabled: bool,
    #[serde(default = "enabled_by_default")]
    pub drive_tests_enabled: bool,
}
fn enabled_by_default() -> bool {
    true
}
impl Sample {
    pub fn valid(&self) -> bool {
        let percent = |v: f32| v.is_finite() && (0.0..=100.0).contains(&v);
        let memory = |v: &Memory| v.used <= v.total && v.total <= i64::MAX as u64;
        percent(self.cpu)
            && self.cores > 0
            && self.cores < 65536
            && memory(&self.ram)
            && memory(&self.disk)
            && self.drive_health.len() <= 64
            && self.drive_health.iter().all(DriveHealth::valid)
            && self
                .drive_health
                .iter()
                .map(|d| &d.id)
                .collect::<std::collections::HashSet<_>>()
                .len()
                == self.drive_health.len()
            && self.disks.len() <= 128
            && self.disks.iter().all(|d| {
                !d.id.is_empty()
                    && d.id.len() <= 256
                    && d.name.len() <= 120
                    && !d.id.chars().chain(d.name.chars()).any(char::is_control)
                    && d.used <= d.total
                    && d.total <= i64::MAX as u64
            })
            && self.gpus.len() <= 16
            && self.gpus.iter().all(|g| {
                g.name.len() <= 120
                    && !g.name.chars().any(char::is_control)
                    && g.id.as_ref().is_none_or(|id| {
                        !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control)
                    })
                    && g.temperature
                        .is_none_or(|t| t.is_finite() && (-40.0..=150.0).contains(&t))
                    && g.fan_speed.is_none_or(percent)
                    && g.utilization.is_none_or(percent)
                    && g.memory.as_ref().is_none_or(memory)
                    && g.shared_memory.as_ref().is_none_or(memory)
                    && g.shared_memory_capacity.is_none_or(|v| v > 0 && v <= i64::MAX as u64)
                    && g.shared_memory.as_ref().zip(g.shared_memory_capacity).is_none_or(|(m, capacity)| m.total == capacity)
            })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_utilization_and_storage() {
        let mut s = Sample {
            cpu: 1.,
            cpu_available: true,
            cores: 2,
            ram: Memory { used: 1, total: 2 },
            disk: Memory { used: 3, total: 4 },
            gpus: vec![],
            disks: vec![],
            drive_health: vec![],
            drive_health_enabled: true,
            drive_tests_enabled: true,
        };
        assert!(s.valid());
        s.cpu = f32::NAN;
        assert!(!s.valid());
        s.cpu = 101.;
        assert!(!s.valid());
        s.cpu = 0.;
        s.ram.used = 3;
        assert!(!s.valid());
    }
    #[test]
    fn drive_health_bounds_identity_and_missing_states_are_explicit() {
        let mut drive:DriveHealth=serde_json::from_value(serde_json::json!({"id":"a".repeat(64),"name":"Drive","protocol":"nvme","capacity":1000,"present":true,"status":"healthy","observed_at":1000,"checked_at":1000,"temperature":40,"percentage_used":10,"available_spare":100,"spare_threshold":10,"power_on_hours":10,"power_cycles":2,"unsafe_shutdowns":0,"media_errors":0,"reallocated_sectors":null,"pending_sectors":null,"uncorrectable_sectors":null,"short_test_supported":false,"self_test":"unsupported","last_test_started":null,"next_test_at":null,"reasons":[]})).unwrap();
        assert!(drive.valid());
        drive.temperature = Some(f32::NAN);
        assert!(!drive.valid());
        drive.temperature = Some(40.);
        drive.available_spare = Some(101);
        assert!(!drive.valid());
        drive.available_spare = Some(100);
        drive.checked_at = None;
        assert!(!drive.valid());
        drive.status = DriveStatus::Unavailable;
        assert!(drive.valid());
        drive.present = false;
        assert!(!drive.valid());
        drive.status = DriveStatus::Removed;
        assert!(drive.valid());
        drive.id = "raw-device-serial".into();
        assert!(!drive.valid());
    }
}
