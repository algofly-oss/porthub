//! USB forwarding contracts shared by the gateway and native agent.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub busid: String,
    pub vendor: String,
    pub product: String,
    pub serial: String,
    pub name: String,
    pub busnum: u16,
    pub devnum: u16,
    pub speed: u32,
    pub blocked: Option<String>,
}
impl Device {
    pub fn valid(&self) -> bool {
        valid_busid(&self.busid)
            && [&self.vendor, &self.product]
                .iter()
                .all(|s| s.len() == 4 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            && self.serial.len() <= 256
            && self.name.len() <= 256
            && self.busnum > 0
            && self.devnum > 0
            && (1..=6).contains(&self.speed)
    }
    pub fn same_device(&self, other: &Self) -> bool {
        self.busid == other.busid
            && self.vendor == other.vendor
            && self.product == other.product
            && self.serial == other.serial
    }
}
pub fn valid_busid(value: &str) -> bool {
    let Some((bus, ports)) = value.split_once('-') else {
        return false;
    };
    value.len() <= 32
        && !bus.is_empty()
        && bus.bytes().all(|c| c.is_ascii_digit())
        && !ports.is_empty()
        && ports
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Forward {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub device: Device,
    pub persistent: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub id: String,
    pub state: String,
    pub error: Option<String>,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn busids_never_escape_sysfs() {
        for v in ["1-2", "2-1.3.4"] {
            assert!(valid_busid(v))
        }
        for v in ["../1-2", "1-2/driver", "1-2:1.0", "1-", "1--2", "1-2\n"] {
            assert!(!valid_busid(v))
        }
    }
}
