//! Desired host routing, prepared by the policy owner and applied by a separate
//! OS worker. Native route changes never run in the packet forwarding loop.
use porthub_mesh::{exit_policy::TrafficMode, lan_routes::Network};
use std::net::Ipv4Addr;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub index: u32,
    pub own: Ipv4Addr,
    pub mode: TrafficMode,
    pub bypass: bool,
    pub networks: Vec<Network>,
}
impl Plan {
    pub fn internet_bypass(&self) -> bool {
        self.bypass || !self.mode.internet()
    }
    pub fn lan_networks(&self) -> &[Network] {
        if self.mode.lan() {
            &self.networks
        } else {
            &[]
        }
    }
}
impl From<(u32, Ipv4Addr, bool)> for Plan {
    fn from((index, own, bypass): (u32, Ipv4Addr, bool)) -> Self {
        Self {
            index,
            own,
            bypass,
            mode: TrafficMode::InternetOnly,
            networks: Vec::new(),
        }
    }
}

/// Match host route coverage to the cached per-flow LAN selector. A sole
/// available peer can reach private destinations through its own router even
/// when other configured peers are temporarily offline.
pub fn lan_networks(
    peers: &[(String, Vec<Network>)],
    mut available: impl FnMut(&str) -> bool,
) -> Vec<Network> {
    if peers.len() == 1 || peers.iter().filter(|(id, _)| available(id)).count() == 1 {
        return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
            .iter()
            .map(|network| network.parse().expect("valid private prefix"))
            .collect();
    }
    peers
        .iter()
        .flat_map(|(_, networks)| networks.iter().copied())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn route_coverage_tracks_single_available_peer_without_claiming_ambiguous_networks() {
        let peers = vec![
            ("first".into(), vec!["10.20.0.0/16".parse().unwrap()]),
            ("second".into(), vec!["172.20.0.0/16".parse().unwrap()]),
        ];
        let all = lan_networks(&peers, |_| true);
        assert!(!all
            .iter()
            .any(|network| network.contains("192.168.0.153".parse().unwrap())));
        let sole = lan_networks(&peers, |id| id == "first");
        assert!(sole
            .iter()
            .any(|network| network.contains("192.168.0.153".parse().unwrap())));
        assert_eq!(lan_networks(&peers, |_| false), all);
        assert_eq!(lan_networks(&peers[..1], |_| false), sole);
    }
}
