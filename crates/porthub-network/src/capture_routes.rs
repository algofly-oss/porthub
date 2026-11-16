//! A capture prefix routes unknown private destinations to the policy engine, never around ACLs.
//! All platform adapters must feed their actual route inventory, including VPN/VM/container routes.
use anyhow::{ensure, Result};
use porthub_mesh::lan_routes::Network;
use std::{collections::BTreeSet, net::Ipv4Addr};
pub const MAX_CAPTURE_PREFIXES: usize = 32;
#[derive(Clone, Copy, Debug)]
pub struct ExistingRoute {
    pub destination: Ipv4Addr,
    pub prefix: u8,
    pub interface: Option<u32>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct CapturePlan {
    pub accepted: Vec<Network>,
    pub conflicting: Vec<Network>,
}

pub fn plan(
    requested: &[Network],
    existing: &[ExistingRoute],
    owned_interface: u32,
) -> Result<CapturePlan> {
    ensure!(
        owned_interface != 0,
        "capture routes require an owned interface"
    );
    ensure!(
        requested.len() <= MAX_CAPTURE_PREFIXES && existing.len() <= 65536,
        "route inventory exceeds bounds"
    );
    ensure!(
        existing.iter().all(|r| r.prefix <= 32),
        "invalid existing route prefix"
    );
    let mut accepted = BTreeSet::new();
    let mut conflicting = BTreeSet::new();
    for candidate in requested {
        // Do not ignore a foreign /32 inside our pool: the broad capture route must never
        // turn a physical/VPN address into a PortHub identity lookup or shadow that network.
        let collision = existing.iter().any(|route| {
            if route.prefix == 0 || route.interface == Some(owned_interface) {
                return false;
            }
            let prefix = candidate.prefix().min(route.prefix);
            let mask = u32::MAX << (32 - prefix);
            u32::from(candidate.address()) & mask == u32::from(route.destination) & mask
        });
        if collision {
            conflicting.insert(*candidate);
        } else {
            accepted.insert(*candidate);
        }
    }
    Ok(CapturePlan {
        accepted: accepted.into_iter().collect(),
        conflicting: conflicting.into_iter().collect(),
    })
}
/// A fresh route-table audit includes already-installed hosts and the local TUN
/// address. Checking only additions misses a later VPN/LAN/WSL collision.
#[derive(Debug,PartialEq,Eq)]
pub struct SparseAudit {
    pub capture:CapturePlan,
    pub accepted_peers:Vec<Ipv4Addr>,
    pub conflicting_peers:Vec<Ipv4Addr>,
    pub own_conflict:bool,
}
pub fn audit(requested:&[Network],own:Ipv4Addr,peers:&[Ipv4Addr],existing:&[ExistingRoute],owned_interface:u32)->Result<SparseAudit>{
    ensure!(own.is_private()&&peers.len()<=crate::policy::MAX_PAIR_LEASES+1&&peers.iter().all(Ipv4Addr::is_private),"invalid or oversized sparse host-route set");
    let capture=plan(requested,existing,owned_interface)?;
    let conflict=|ip:Ipv4Addr|existing.iter().any(|r|{
        if r.prefix==0||r.interface==Some(owned_interface){return false;}
        let mask=u32::MAX<<(32-r.prefix);u32::from(ip)&mask==u32::from(r.destination)&mask
    });
    let mut accepted_peers=BTreeSet::new();let mut conflicting_peers=BTreeSet::new();
    for ip in peers.iter().copied().filter(|ip|*ip!=own){if conflict(ip){conflicting_peers.insert(ip);}else{accepted_peers.insert(ip);}}
    Ok(SparseAudit{capture,accepted_peers:accepted_peers.into_iter().collect(),conflicting_peers:conflicting_peers.into_iter().collect(),own_conflict:conflict(own)})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fresh_audit_retires_retained_hosts_but_can_prewarm_unambiguous_hosts_in_conflicting_pool(){
        let own="10.203.7.1".parse().unwrap();let safe="10.203.7.2".parse().unwrap();let conflicted="10.203.8.2".parse().unwrap();
        let pools=["10.203.0.0/16".parse().unwrap()];let peers=[safe,conflicted];
        let before=audit(&pools,own,&peers,&[],9).unwrap();assert_eq!(before.accepted_peers.len(),2);assert!(!before.own_conflict);
        let routes=[ExistingRoute{destination:"10.203.8.0".parse().unwrap(),prefix:24,interface:Some(2)},ExistingRoute{destination:conflicted,prefix:32,interface:Some(9)}];
        let after=audit(&pools,own,&peers,&routes,9).unwrap();
        assert_eq!(after.capture.conflicting,pools);assert!(after.capture.accepted.is_empty());
        assert_eq!(after.accepted_peers,vec![safe]);assert_eq!(after.conflicting_peers,vec![conflicted]);assert!(!after.own_conflict);
        let own_lan=[ExistingRoute{destination:"10.203.7.0".parse().unwrap(),prefix:24,interface:Some(3)}];
        assert!(audit(&pools,own,&peers,&own_lan,9).unwrap().own_conflict);
    }
    #[test]
    fn lan_vpn_wsl_collision_rejects_only_affected_pool_and_default_is_not_a_collision() {
        let pools = [
            "10.203.0.0/23".parse().unwrap(),
            "172.20.0.0/24".parse().unwrap(),
            "192.168.99.0/24".parse().unwrap(),
        ];
        let routes = [
            ExistingRoute {
                destination: "0.0.0.0".parse().unwrap(),
                prefix: 0,
                interface: Some(1),
            },
            ExistingRoute {
                destination: "172.16.0.0".parse().unwrap(),
                prefix: 12,
                interface: Some(2),
            },
            ExistingRoute {
                destination: "192.168.99.17".parse().unwrap(),
                prefix: 32,
                interface: Some(3),
            },
        ];
        let result = plan(&pools, &routes, 9).unwrap();
        assert_eq!(result.accepted, vec![pools[0]]);
        assert_eq!(result.conflicting, vec![pools[1], pools[2]]);
    }
    #[test]
    fn owned_tun_routes_are_not_foreign_but_another_porthub_interface_is() {
        let pool = "10.203.0.0/24".parse().unwrap();
        let mut route = ExistingRoute {
            destination: "10.203.0.5".parse().unwrap(),
            prefix: 32,
            interface: Some(9),
        };
        assert_eq!(plan(&[pool], &[route], 9).unwrap().accepted, vec![pool]);
        route.interface = Some(10);
        assert!(plan(&[pool], &[route], 9).unwrap().accepted.is_empty());
    }
    #[test]
    fn foreign_noncanonical_route_is_normalized_without_broadening_capture() {
        let pool = "10.203.0.0/24".parse().unwrap();
        let route = ExistingRoute {
            destination: "10.203.1.7".parse().unwrap(),
            prefix: 16,
            interface: None,
        };
        assert_eq!(plan(&[pool], &[route], 8).unwrap().conflicting, vec![pool]);
    }
}
