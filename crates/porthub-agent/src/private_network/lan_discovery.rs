//! Advertise connected private networks only from eligible underlay addresses.
//! Advertisements describe reachability; they never grant exit access.
use porthub_mesh::lan_routes::Network;
use std::{collections::BTreeSet, net::{IpAddr, Ipv4Addr, SocketAddr}};

fn network(address: Ipv4Addr, mask: Ipv4Addr) -> Option<Network> {
    let mask = u32::from(mask);
    let prefix = mask.leading_ones() as u8;
    if prefix == 0 || mask != u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0) {
        return None;
    }
    Network::from_address(address, prefix).ok()
}

pub(super) fn connected(underlay: &[SocketAddr]) -> anyhow::Result<Vec<Network>> {
    let eligible: BTreeSet<_> = underlay.iter().map(SocketAddr::ip).collect();
    let mut networks = BTreeSet::new();
    for interface in getifaddrs::getifaddrs()? {
        let Some(IpAddr::V4(address)) = interface.address.ip_addr() else { continue; };
        if !eligible.contains(&IpAddr::V4(address)) { continue; }
        let Some(IpAddr::V4(mask)) = interface.address.netmask() else { continue; };
        if let Some(network) = network(address, mask) { networks.insert(network); }
    }
    Ok(networks.into_iter().take(32).collect())
}

/// Existing local/VPN routes take precedence, even when a remote prefix is
/// more specific. Default and split-default internet routes are not LANs.
#[cfg(any(target_os="macos",test))]
pub(super) fn conflicts(network: Network, address: Ipv4Addr, prefix: u8) -> bool {
    if !(2..=32).contains(&prefix) { return false; }
    let length = prefix.min(network.prefix());
    let mask = u32::MAX << (32 - length);
    u32::from(network.address()) & mask == u32::from(address) & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_disjoint_masks_and_non_private_advertisements() {
        for (address, mask) in [
            ("192.168.80.118", "255.0.255.0"),
            ("192.168.80.118", "0.0.0.0"),
            ("1.1.1.1", "255.255.255.0"),
            ("169.254.1.1", "255.255.0.0"),
        ] {
            assert!(network(address.parse().unwrap(), mask.parse().unwrap()).is_none());
        }
        assert_eq!(network("192.168.80.118".parse().unwrap(), "255.255.255.0".parse().unwrap()).unwrap().to_string(), "192.168.80.0/24");
        assert_eq!(network("10.1.2.3".parse().unwrap(), "255.255.255.255".parse().unwrap()).unwrap().to_string(), "10.1.2.3/32");
    }
    #[test]
    fn remote_routes_cannot_steal_a_more_general_local_or_vpn_network() {
        let remote = "192.168.80.0/24".parse().unwrap();
        assert!(conflicts(remote, "192.168.0.0".parse().unwrap(), 16));
        assert!(conflicts(remote, "192.168.80.1".parse().unwrap(), 32));
        assert!(!conflicts(remote, "192.168.86.0".parse().unwrap(), 24));
        assert!(!conflicts(remote, "0.0.0.0".parse().unwrap(), 0));
        assert!(!conflicts(remote, "128.0.0.0".parse().unwrap(), 1));
    }
}

/// A broader remote route leaves more-specific local routes intact. Equal or
/// narrower remote routes would steal local/VPN destinations and are rejected.
#[cfg(any(target_os="macos",test))]
pub(super) fn would_shadow_local(network:Network,address:Ipv4Addr,prefix:u8)->bool {
    prefix<=network.prefix() && conflicts(network,address,prefix)
}
#[cfg(test)]
mod shadow_tests {
    use super::*;
    #[test]
    fn broad_fallback_preserves_connected_lan_but_never_overrides_a_vpn() {
        let broad="192.168.0.0/16".parse().unwrap();
        assert!(!would_shadow_local(broad,"192.168.86.0".parse().unwrap(),24));
        assert!(would_shadow_local(broad,"192.168.0.0".parse().unwrap(),16));
        assert!(would_shadow_local("192.168.86.0/24".parse().unwrap(),"192.168.0.0".parse().unwrap(),16));
        assert!(!would_shadow_local(broad,"0.0.0.0".parse().unwrap(),0));
    }
}
