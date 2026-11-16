//! Route notifications and underlay-address changes have different consumers.
//! An unchanged NIC address list must not hide a new VPN/LAN route from capture audits.
use std::net::SocketAddr;
use tokio::sync::watch;
pub(crate) fn publish(output:&watch::Sender<Vec<SocketAddr>>,routes:Option<&watch::Sender<u64>>,addresses:Option<Vec<SocketAddr>>){
    if let Some(addresses)=addresses{output.send_if_modified(|previous|{if *previous==addresses{return false;}*previous=addresses;true});}
    if let Some(routes)=routes{routes.send_modify(|revision|*revision=revision.wrapping_add(1));}
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn route_only_events_and_address_snapshot_failure_still_notify_audit_without_ice_churn(){
  let addresses=vec!["192.168.0.169:0".parse().unwrap()];let(nic,underlay)=watch::channel(addresses.clone());let(routes,mut audit)=watch::channel(0);
  publish(&nic,Some(&routes),Some(addresses));assert!(!underlay.has_changed().unwrap());assert!(audit.has_changed().unwrap());assert_eq!(*audit.borrow_and_update(),1);
  publish(&nic,Some(&routes),None);assert!(!underlay.has_changed().unwrap());assert!(audit.has_changed().unwrap());assert_eq!(*audit.borrow_and_update(),2);
 }
}
