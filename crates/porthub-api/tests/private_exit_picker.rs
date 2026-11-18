#![cfg(feature="private-sparse")]
use anyhow::{ensure,Result};
use axum::http::StatusCode;
use mongodb::bson::{doc,oid::ObjectId,DateTime};
use porthub_api::{config::Config,domain::workspaces::token_digest};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
mod support;
use support::Case;
const TOKEN:&str="fixture-token-0123456789abcdef0123456789";
fn request(id:&str)->Value {json!({"peer_id":id,"token":TOKEN,"fingerprint":vec!["AB";32].join(":"),"instance":"instance-full-exits","exit_pair_protocol":1,"exit_ready":true,"lan_exit":true,"lan_networks":if id.ends_with("04096"){vec!["192.168.99.0/24"]}else if id.starts_with("full-exit-router-"){vec!["192.168.0.0/16"]}else{vec![]},"sparse":{"protocol":1,"sequence":1,"wanted":[]}})}
async fn ready(case:&Case,request:&mut Value)->Result<Value>{
 for _ in 0..40 {
  let response=case.status("POST","/api/access/private/sync","",request.clone(),StatusCode::OK).await?;
  if response["exit_pick"]["status"]!="pending"{return Ok(response)}
  request["exit_pick"]["cursor"]=response["exit_pick"]["cursor"].clone();
 }
 anyhow::bail!("bounded picker failed to finish4097 candidates")
}
#[tokio::test]
#[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn all_4097_router_selection_preserves_tail_sticky_random_and_lan_priority()->Result<()> {
 let case=Case::new(Config::default()).await?;
 let result=async {
  let(owner,_)=case.user("full-exit-picker@test.invalid","user").await?;
  let source=ObjectId::new();let group=ObjectId::new();let route=ObjectId::new();
  case.app.collection("machines").insert_one(doc!{"_id":source,"user_id":owner,"name":"Exit source"}).await?;
  case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
  let ids:Vec<_>=(0..4097).map(|_|ObjectId::new()).collect();
  let peers:Vec<_>=(0..4097).map(|i|format!("full-exit-router-{i:05}")).collect();
  case.app.collection("machines").insert_many(ids.iter().enumerate().map(|(i,id)|doc!{"_id":id,"user_id":owner,"name":format!("Router{i}"),"group_ids":[group]})).await?;
  let now=DateTime::now();
  let mut rows:Vec<_>=ids.iter().enumerate().map(|(i,id)|doc!{"_id":&peers[i],"workspace_id":owner,"owner_id":owner,"machine_id":id,"ip":std::net::Ipv4Addr::from(u32::from(std::net::Ipv4Addr::new(10,212,0,2))+i as u32).to_string(),"enabled":true,"credential_hash":token_digest(TOKEN),"fingerprint":vec!["AB";32].join(":"),"instance":"instance-full-exits","last_seen_at":now,"exit_pair_protocol":1,"exit_ready":true,"lan_exit":true,"lan_networks":if i==4096{vec!["192.168.99.0/24"]}else{vec!["192.168.0.0/16"]},"revision":1_i64}).collect();
  rows.push(doc!{"_id":"full-exit-source","workspace_id":owner,"owner_id":owner,"machine_id":source,"ip":"10.212.0.1","enabled":true,"credential_hash":token_digest(TOKEN)});
  case.app.collection("private_peers").insert_many(rows).await?;
  case.app.collection("private_networks").insert_one(doc!{"_id":owner.to_hex(),"cidr":"10.212.0.0/19","dns_suffix":"phub"}).await?;
  case.app.collection("private_exit_nodes").insert_one(doc!{"_id":route,"workspace_id":owner,"enabled":true,"name":"Full roster","selection":"round_robin","routing_selectors":[{"kind":"group","id":group.to_hex()}],"distribution_selectors":[{"kind":"machine","id":source.to_hex()}]}).await?;
  // Seed derived discovery hints, not grants: normal sync below freshly
  // authorizes every scanned machine and the chosen router gets its ordinary
  // authenticated control/Hub lease. No4097 live agents/sockets are claimed.
  case.app.collection("private_exit_routers").insert_many(peers.iter().enumerate().map(|(i,id)|doc!{"_id":format!("{owner}:{route}:{id}"),"workspace_id":owner,"route_id":route.to_hex(),"peer":id,"protocol":true,"ready":true,"lan_networks":if i==4096{vec!["192.168.99.0/24"]}else{vec!["192.168.0.0/16"]},"expires_at":DateTime::from_millis(now.timestamp_millis()+15_000)})).await?;
  let tail=&peers[4096];
  let mut selected=std::collections::HashSet::new();
  for mode in ["round_robin","sticky","random","lan_only"] {
   let expected=if mode=="sticky"{
    let mut table=porthub_network::exit_selection::FlowTable::new("full-exit-source".into());table.configure(peers.clone(),porthub_mesh::exit_policy::Selection::Sticky);
    table.select(0u64,std::time::Instant::now(),std::time::Duration::from_secs(15)).unwrap().to_owned()
   }else{tail.clone()};
   let now=DateTime::now();
   case.app.collection("private_peers").update_many(doc!{"workspace_id":owner},doc!{"$set":{"last_seen_at":now}}).await?;
   case.app.collection("private_exit_routers").update_many(doc!{"workspace_id":owner},doc!{"$set":{"expires_at":DateTime::from_millis(now.timestamp_millis()+15_000)}}).await?;
   let change=if mode=="lan_only"{doc!{"selection":"sticky","traffic_mode":"lan_only"}}else{doc!{"selection":mode,"traffic_mode":"internet_only"}};
   case.app.collection("private_exit_nodes").update_one(doc!{"_id":route},doc!{"$set":change}).await?;
   case.status("POST","/api/access/private/sync","",request(&expected),StatusCode::OK).await?;
   let flow="c".repeat(64);
   let ordinal=if mode=="random"{
    (0..1_000_000u64).find(|n|{let bytes=Sha256::digest(format!("{flow}:{n}:{owner}"));u64::from_be_bytes(bytes[..8].try_into().unwrap())%4097==4096}).ok_or_else(||anyhow::anyhow!("could not derive bounded deterministic tail fixture"))?
   }else{4096};
   let mut body=request("full-exit-source");
   let initial=case.status("POST","/api/access/private/sync","",body.clone(),StatusCode::OK).await?;
   body["exit_pick"]=json!({"selection_epoch":initial["snapshot"]["sparse"]["selection_epoch"],"route_id":route.to_hex(),"flow_id":flow,"ordinal":ordinal,"destination":if mode=="lan_only"{"192.168.99.42"}else{"8.8.8.8"}});
   let reply=ready(&case,&mut body).await?;
   ensure!(reply["exit_pick"]["status"]=="ready"&&reply["exit_pick"]["choice"]["id"]==expected,"{mode} did not select full-roster expected peer: {}",reply["exit_pick"]);
   selected.insert(expected.clone());
   let pairs=reply["pair_responses"].as_array().unwrap();
   ensure!(reply["snapshot"]["peers"].as_array().unwrap().len()==1&&pairs.len()<=selected.len()
    &&pairs.iter().all(|response|response["query"]["value"].as_str().is_some_and(|id|selected.contains(id))
      &&(response["status"]!="allowed"||response["lease"]["peer"]["id"].as_str().is_some_and(|id|selected.contains(id)))),"unselected full-roster peer leaked into bounded reply");
  }
  // A stale directory hint cannot authorize a disabled/revoked machine.
  case.app.collection("machines").update_one(doc!{"_id":ids[4096]},doc!{"$set":{"private_owner_revoked":true}}).await?;
  let mut body=request("full-exit-source");
  let initial=case.status("POST","/api/access/private/sync","",body.clone(),StatusCode::OK).await?;
  body["exit_pick"]=json!({"selection_epoch":initial["snapshot"]["sparse"]["selection_epoch"],"route_id":route.to_hex(),"flow_id":"d".repeat(64),"ordinal":0,"destination":"192.168.99.42","available_peers":[tail]});
  let denied=ready(&case,&mut body).await?;
  ensure!(denied["exit_pick"]["status"]=="unavailable"&&denied["exit_pick"]["lease"].is_null(),"revoked target inherited directory authority");
  Ok::<_,anyhow::Error>(())
 }.await;case.db.drop().await?;result
}
