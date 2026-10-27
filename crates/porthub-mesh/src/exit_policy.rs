//! Selection applies to new connections; a connection retains its exit identity.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Selection {
    #[default]
    Sticky,
    RoundRobin,
    Random,
}

/// Independent from balancing: LAN routes use destination prefixes and peer
/// priority, while internet flows use the configured selection strategy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="snake_case")]
pub enum TrafficMode {
    All,
    #[default]
    InternetOnly,
    LanOnly,
}
impl TrafficMode {
    pub fn internet(self)->bool {self!=Self::LanOnly}
    pub fn lan(self)->bool {self!=Self::InternetOnly}
    pub fn permits(self, destination: std::net::Ipv4Addr) -> bool {
        if destination.is_private() { self.lan() } else { self.internet() }
    }
}

#[cfg(test)]
mod traffic_mode_tests {
    use super::*;
    #[test]
    fn modes_separate_private_destinations_from_internet() {
        let internet = "1.1.1.1".parse().unwrap();
        for lan in ["10.1.2.3", "172.16.0.1", "192.168.80.1"] {
            let lan = lan.parse().unwrap();
            assert!(TrafficMode::All.permits(lan));
            assert!(TrafficMode::All.permits(internet));
            assert!(!TrafficMode::InternetOnly.permits(lan));
            assert!(TrafficMode::InternetOnly.permits(internet));
            assert!(TrafficMode::LanOnly.permits(lan));
            assert!(!TrafficMode::LanOnly.permits(internet));
        }
        assert_eq!(TrafficMode::default(), TrafficMode::InternetOnly);
        assert!(serde_json::from_str::<TrafficMode>("\"unknown\"").is_err());
    }
}
