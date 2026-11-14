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
    pub memory: Option<Memory>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub cpu: f32,
    pub cores: u32,
    pub ram: Memory,
    pub disk: Memory,
    pub gpus: Vec<Gpu>,
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
            && self.gpus.len() <= 16
            && self.gpus.iter().all(|g| {
                g.name.len() <= 120
                    && !g.name.chars().any(char::is_control)
                    && g.utilization.is_none_or(percent)
                    && g.memory.as_ref().is_none_or(memory)
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
            cores: 2,
            ram: Memory { used: 1, total: 2 },
            disk: Memory { used: 3, total: 4 },
            gpus: vec![],
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
}
