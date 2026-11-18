//! Explicit negotiated cold-flow selection. Cursors are metadata, never grants.
use super::{PairLease, MAX_PAIR_LEASES};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet,net::Ipv4Addr};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExitPickRequest {
    pub route_id:String,
    #[serde(default)] pub selection_epoch:String,
    pub flow_id:String,
    pub ordinal:u64,
    pub destination:Ipv4Addr,
    #[serde(default)] pub local_tor_ready:bool,
    /// None: gateway carrier ready; Some: exact currently direct-ready peers.
    #[serde(default)] pub available_peers:Option<Vec<String>>,
    #[serde(default)] pub cursor:Option<String>,
    #[serde(default)] pub warmup:bool,
    /// Discover a cold-flow candidate before its direct carrier is ready.
    #[serde(default)] pub discover:bool,
    #[serde(default)] pub unavailable_peers:Vec<String>,
}
impl ExitPickRequest {
    pub fn validate(&self)->Result<()> {
        ensure!(self.selection_epoch.len()==64&&self.selection_epoch.bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase()),"invalid exit selection generation");
        ensure!(!self.route_id.is_empty()&&self.route_id.len()<=60&&self.route_id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'),"invalid exit route identity");
        ensure!(self.flow_id.len()==64&&self.flow_id.bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase()),"invalid exit flow correlation");
        ensure!(self.cursor.as_ref().is_none_or(|cursor|!cursor.is_empty()&&cursor.len()<=2048&&cursor.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_'||b==b'.')),"invalid exit picker cursor");
        if let Some(peers)=&self.available_peers {
            let mut unique=HashSet::new();
            ensure!(peers.len()<=MAX_PAIR_LEASES&&peers.iter().all(|id|!id.is_empty()&&id.len()<=60&&id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b':')&&unique.insert(id)),"invalid available exit peers");
        }
        let mut failed=HashSet::new();
        ensure!(self.unavailable_peers.len()<=MAX_PAIR_LEASES&&self.unavailable_peers.iter().all(|id|!id.is_empty()&&id.len()<=60&&id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b':')&&failed.insert(id)),"invalid unavailable exit peers");
        ensure!(self.available_peers.as_ref().is_none_or(|peers|peers.iter().all(|id|!failed.contains(id))),"exit peer cannot be both ready and failed");
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all="snake_case")]
pub enum ExitPickStatus {Pending,Ready,Unavailable,UpgradeRequired}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag="kind",rename_all="snake_case",deny_unknown_fields)]
pub enum ExitChoice {Peer{id:String},LocalTor}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExitPickResponse {
    pub route_id:String,
    #[serde(default)] pub selection_epoch:String,
    pub flow_id:String,
    pub ordinal:u64,
    pub warmup:bool,
    #[serde(default)] pub discover:bool,
    pub epoch:String,
    pub status:ExitPickStatus,
    #[serde(default,skip_serializing_if="Option::is_none")] pub choice:Option<ExitChoice>,
    #[serde(default,skip_serializing_if="Option::is_none")] pub lease:Option<PairLease>,
    #[serde(default,skip_serializing_if="Option::is_none")] pub cursor:Option<String>,
}
impl ExitPickResponse {
    pub fn validate_for(&self,request:&ExitPickRequest,epoch:&str)->Result<()> {
        request.validate()?;
        ensure!(self.route_id==request.route_id&&self.flow_id==request.flow_id&&self.ordinal==request.ordinal&&self.warmup==request.warmup&&self.discover==request.discover&&self.selection_epoch==request.selection_epoch
            &&self.epoch==epoch&&epoch.len()==64&&epoch.bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase()),"exit picker response scope changed");
        match self.status {
            ExitPickStatus::Pending=>{
                let mut check=request.clone();check.cursor=self.cursor.clone();check.validate()?;
                ensure!(self.cursor.is_some()&&self.choice.is_none()&&self.lease.is_none(),"invalid pending exit selection");
            },
            ExitPickStatus::Ready=>{
                ensure!(self.cursor.is_none(),"completed exit selection retained a cursor");
                match &self.choice {
                    Some(ExitChoice::Peer{id})=>{
                        let lease=self.lease.as_ref().ok_or_else(||anyhow::anyhow!("selected exit has no exact lease"))?;
                        ensure!(lease.peer.id==*id&&lease.exit.as_ref().is_some_and(|exit|exit.route_id==self.route_id&&exit.epoch==self.epoch&&exit.client==lease.self_&&exit.router==*id),"selected exit lease changed");
                        ensure!(!request.unavailable_peers.contains(id),"selected exit has a failed carrier");
                        ensure!(request.warmup||request.discover||request.available_peers.as_ref().is_none_or(|peers|peers.contains(id)),"selected exit is outside available carrier set");
                    },
                    Some(ExitChoice::LocalTor)=>ensure!(self.lease.is_none()&&request.local_tor_ready&&!request.destination.is_private(),"local Tor choice is unavailable"),
                    None=>anyhow::bail!("completed exit selection has no choice"),
                }
            },
            ExitPickStatus::Unavailable|ExitPickStatus::UpgradeRequired=>ensure!(self.choice.is_none()&&self.lease.is_none()&&self.cursor.is_none(),"unavailable exit selection exposed authority"),
        }
        Ok(())
    }
}
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn picker_metadata_is_strict_bounded_and_correlation_preserved(){
  let value=serde_json::json!({"route_id":"route","selection_epoch":"c".repeat(64),"flow_id":"a".repeat(64),"ordinal":0,"destination":"1.1.1.1"});
  let request:ExitPickRequest=serde_json::from_value(value.clone()).unwrap();request.validate().unwrap();assert!(!request.warmup&&request.available_peers.is_none());
  for field in ["flow_id","cursor","available_peers"] {
   let mut changed=value.clone();changed[field]=match field{"flow_id"=>serde_json::json!("A".repeat(64)),"cursor"=>serde_json::json!("x".repeat(2049)),_=>serde_json::json!(["same","same"])};
   assert!(serde_json::from_value::<ExitPickRequest>(changed).unwrap().validate().is_err());
  }
  let mut changed=value;changed["authorization"]=serde_json::json!(true);assert!(serde_json::from_value::<ExitPickRequest>(changed).is_err());
 }
 #[test]fn selected_peer_requires_client_to_router_roles_even_during_warmup(){
  let epoch="a".repeat(64);
  let request:ExitPickRequest=serde_json::from_value(serde_json::json!({"route_id":"route","selection_epoch":"c".repeat(64),"flow_id":"b".repeat(64),"ordinal":1,"destination":"1.1.1.1","warmup":true})).unwrap();
  let peer=|id:&str,ip:&str|serde_json::json!({"id":id,"ip":ip,"fingerprint":format!("fp-{id}"),"instance":format!("instance-{id}"),"hostname":format!("{id}.phub")});
  let lease:PairLease=serde_json::from_value(serde_json::json!({"workspace":"w","self":"client","epoch":epoch,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(15),"revision":1,"local":peer("client","10.203.0.2"),"peer":peer("router","10.203.0.3"),"grants":[],"exit":{"route_id":"route","epoch":epoch,"client":"client","router":"router","traffic_mode":"internet_only"}})).unwrap();
  let mut response=ExitPickResponse{route_id:"route".into(),selection_epoch:request.selection_epoch.clone(),flow_id:request.flow_id.clone(),ordinal:1,warmup:true,discover:false,epoch:epoch.clone(),status:ExitPickStatus::Ready,choice:Some(ExitChoice::Peer{id:"router".into()}),lease:Some(lease),cursor:None};
  response.validate_for(&request,&epoch).unwrap();
  response.lease.as_mut().unwrap().exit.as_mut().unwrap().client="router".into();
  assert!(response.validate_for(&request,&epoch).is_err());
  response.lease.as_mut().unwrap().exit.as_mut().unwrap().client="client".into();
  response.lease.as_mut().unwrap().exit.as_mut().unwrap().router="client".into();
  assert!(response.validate_for(&request,&epoch).is_err());
  response.lease.as_mut().unwrap().exit.as_mut().unwrap().router="router".into();
  let mut discovery=request.clone();discovery.warmup=false;discovery.discover=true;discovery.available_peers=Some(vec![]);
  response.warmup=false;response.discover=true;
  response.validate_for(&discovery,&epoch).unwrap();
  response.discover=false;assert!(response.validate_for(&discovery,&epoch).is_err());response.discover=true;
  discovery.unavailable_peers.push("router".into());assert!(response.validate_for(&discovery,&epoch).is_err());

 }

 #[test]fn cold_flow_discovery_is_scoped_and_failed_peers_never_become_choices(){
  let mut request:ExitPickRequest=serde_json::from_value(serde_json::json!({"route_id":"route","selection_epoch":"c".repeat(64),"flow_id":"a".repeat(64),"ordinal":7,"destination":"1.1.1.1","discover":true,"available_peers":[],"unavailable_peers":["failed"]})).unwrap();
  request.validate().unwrap();
  request.available_peers=Some(vec!["failed".into()]);assert!(request.validate().is_err());
  request.available_peers=Some(vec![]);request.unavailable_peers=vec!["failed".into();2];assert!(request.validate().is_err());
  request.unavailable_peers=(0..257).map(|i|format!("failed-{i}")).collect();assert!(request.validate().is_err());
 }

}
