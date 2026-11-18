#![cfg(feature="private-sparse")]
use anyhow::{ensure,Result};
use axum::http::StatusCode;
use mongodb::bson::{doc,oid::ObjectId,DateTime,Document};
use porthub_api::{config::Config,domain::workspaces::token_digest};
use serde_json::{json,Value};
use std::time::Duration;
use futures_util::TryStreamExt;
mod support;
use support::Case;
fn request(i:usize,networks:&[&str])->Value{json!({"peer_id":format!("capture-{i}"),"token":"fixture-token-0123456789abcdef0123456789","fingerprint":vec!["AB";32].join(":"),"instance":"instance-capture-0","exit_pair_protocol":1,"exit_ready":true,"lan_exit":true,"lan_networks":networks,"sparse":{"protocol":1,"sequence":1,"wanted":[]}})}
async fn query_count(case:&Case,route:ObjectId)->Result<u64>{Ok(case.db.collection::<Document>("system.profile").count_documents(doc!{"command.find":"private_exit_routers","command.filter.route_id":route.to_hex()}).await?)}
async fn client(case:&Case,i:usize)->Result<Vec<String>>{
 let value=case.status("POST","/api/access/private/sync","",request(i,&[]),StatusCode::OK).await?;
 ensure!(value["snapshot"]["peers"].as_array().is_some_and(|r|r.len()==1),"capture cache changed sparse identity disclosure");
 let intent=&value["snapshot"]["sparse"]["exit_intents"][0];ensure!(intent.is_object()&&intent["role"]=="client","exact client intent missing");match intent.get("lan_networks"){None=>Ok(Vec::new()),Some(networks)=>{ensure!(networks.is_array(),"invalid capture metadata");Ok(serde_json::from_value(networks.clone())?)}}
}
#[tokio::test]
#[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn concurrent_client_polls_share_capture_queries_and_publish_invalidates_semantics_only()->Result<()>{
 let case=Case::new(Config::default()).await?;
 let result=async{
  let(owner,_)=case.user("capture-cache@test.invalid","user").await?;let route=ObjectId::new();let group=ObjectId::new();let ids:Vec<_>=(0..8).map(|_|ObjectId::new()).collect();
  case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
  case.app.collection("machines").insert_many(ids.iter().enumerate().map(|(i,id)|{let mut d=doc!{"_id":id,"user_id":owner,"name":format!("Capture{i}")};if i>=2{d.insert("group_ids",vec![group]);}d})).await?;
  case.app.collection("private_peers").insert_many(ids.iter().enumerate().map(|(i,id)|doc!{"_id":format!("capture-{i}"),"workspace_id":owner,"owner_id":owner,"machine_id":id,"enabled":true,"ip":format!("10.220.0.{}",i+1),"credential_hash":token_digest("fixture-token-0123456789abcdef0123456789")})).await?;
  case.app.collection("private_networks").insert_one(doc!{"_id":owner.to_hex(),"cidr":"10.220.0.0/24","dns_suffix":"phub"}).await?;
  case.app.collection("private_exit_nodes").insert_one(doc!{"_id":route,"workspace_id":owner,"enabled":true,"name":"Shared capture","traffic_mode":"lan_only","routing_selectors":[{"kind":"machine","id":ids[0].to_hex()},{"kind":"machine","id":ids[1].to_hex()}],"distribution_selectors":[{"kind":"group","id":group.to_hex()}]}).await?;
  case.status("POST","/api/access/private/sync","",request(0,&["10.50.0.0/16"]),StatusCode::OK).await?;
  case.status("POST","/api/access/private/sync","",request(1,&["172.20.0.0/16"]),StatusCode::OK).await?;
  case.db.run_command(doc!{"profile":1,"filter":{"command.find":"private_exit_routers","command.filter.route_id":route.to_hex()}}).await?;
  for _ in 0..2{
   let results=futures_util::future::join_all((2..8).map(|i|client(&case,i))).await;
   for value in results{ensure!(value?==vec!["10.50.0.0/16","172.20.0.0/16"],"exact union changed or unrelated prefix was invented");}
  }
  ensure!(query_count(&case,route).await?==1,"concurrent/repeated clients rescanned router fleet");
  // A stable heartbeat extends its own row, not the cache's original deadline.
  case.status("POST","/api/access/private/sync","",request(0,&["10.50.0.0/16"]),StatusCode::OK).await?;client(&case,2).await?;
  ensure!(query_count(&case,route).await?==1,"TTL-only heartbeat invalidated shared capture cache");
  tokio::time::sleep(Duration::from_millis(5100)).await;client(&case,2).await?;
  ensure!(query_count(&case,route).await?==2,"capture metadata outlived its five-second cache deadline");
  case.status("POST","/api/access/private/sync","",request(0,&["10.60.0.0/16"]),StatusCode::OK).await?;
  ensure!(client(&case,3).await?==vec!["10.60.0.0/16","172.20.0.0/16"],"semantic network publication reused stale capture union");
  ensure!(query_count(&case,route).await?==3,"semantic network change did not force one fresh shared scan");
  case.app.collection("private_exit_nodes").update_one(doc!{"_id":route},doc!{"$set":{"routing_selectors":[{"kind":"machine","id":ids[0].to_hex()}]}}).await?;
  case.status("POST","/api/access/private/sync","",request(1,&["172.20.0.0/16"]),StatusCode::OK).await?;
  ensure!(client(&case,4).await?==vec!["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"],"withdrawal changed original sole-router fallback semantics");
  ensure!(query_count(&case,route).await?==4,"router withdrawal did not invalidate capture metadata");
  // Prime a new generation whose actual row expires earlier than five seconds.
  case.status("POST","/api/access/private/sync","",request(0,&["10.61.0.0/16"]),StatusCode::OK).await?;
  case.app.collection("private_exit_routers").update_one(doc!{"workspace_id":owner,"peer":"capture-0"},doc!{"$set":{"expires_at":DateTime::from_millis(DateTime::now().timestamp_millis()+1000)}}).await?;
  ensure!(client(&case,5).await?==vec!["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"],"row expired before the expiry fixture could prime a nonempty plan");let before=query_count(&case,route).await?;
  tokio::time::sleep(Duration::from_millis(1200)).await;
  ensure!(client(&case,5).await?.is_empty(),"expired router row remained in cached metadata");
  let after=query_count(&case,route).await?;ensure!(after==before+1,"cache expiry scan count mismatch: before={before}, after={after}");
  // Same-network publication revives an inactive row and must invalidate a
  // cached empty plan even if the TTL monitor has not deleted that row yet.
  case.app.collection("private_exit_routers").update_one(doc!{"_id":format!("{owner}:{route}:capture-0")},doc!{"$set":{"workspace_id":owner,"route_id":route.to_hex(),"peer":"capture-0","protocol":true,"ready":true,"lan_networks":["10.61.0.0/16"],"expires_at":DateTime::from_millis(DateTime::now().timestamp_millis()-1)}}).upsert(true).await?;
  let empty_count=query_count(&case,route).await?;
  case.status("POST","/api/access/private/sync","",request(0,&["10.61.0.0/16"]),StatusCode::OK).await?;
  let after_publisher=query_count(&case,route).await?;
  ensure!(client(&case,6).await?==vec!["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"],"same-network revival left cached empty capture plan");
  let after_client=query_count(&case,route).await?;
  let phase_rows:Vec<Document>=case.db.collection("system.profile").find(doc!{"command.find":"private_exit_routers","command.filter.route_id":route.to_hex()}).projection(doc!{"_id":0,"ts":1,"command.filter":1,"nreturned":1}).sort(doc!{"ts":1}).await?.try_collect().await?;
  println!("capture_revival_diagnostic={}",json!({"before_publisher":empty_count,"after_publisher":after_publisher,"after_client":after_client,"queries":phase_rows}));
  ensure!(after_client==empty_count+1,"same-network revival scan count mismatch: before={empty_count}, after_publisher={after_publisher}, after_client={after_client}");
  println!("capture_cache_queries={{\"profiler_capture_only\":true,\"concurrent_client_polls\":12,\"initial_full_scans\":1,\"stable_heartbeat_extra_scans\":0,\"five_second_refresh\":true,\"semantic_publish_refresh\":true,\"withdrawal_refresh\":true,\"earliest_row_expiry_refresh\":true}}");
  Ok::<_,anyhow::Error>(())
 }.await;case.db.drop().await?;result
}

#[tokio::test]
#[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn router_role_capacity_is_checked_before_any_directory_publication()->Result<()>{
 let case=Case::new(Config::default()).await?;
 let result=async{
  let(owner,_)=case.user("capture-capacity@test.invalid","user").await?;let machine=ObjectId::new();
  case.app.collection("machines").insert_one(doc!{"_id":machine,"user_id":owner,"name":"Over-capacity router"}).await?;
  case.app.collection("private_peers").insert_one(doc!{"_id":"capture-0","workspace_id":owner,"owner_id":owner,"machine_id":machine,"enabled":true,"ip":"10.221.0.1","credential_hash":token_digest("fixture-token-0123456789abcdef0123456789")}).await?;
  case.app.collection("private_networks").insert_one(doc!{"_id":owner.to_hex(),"cidr":"10.221.0.0/24","dns_suffix":"phub"}).await?;
  case.app.collection("private_exit_nodes").insert_many((0..257).map(|i|doc!{"_id":ObjectId::new(),"workspace_id":owner,"enabled":true,"name":format!("Role{i}"),"routing_selectors":[{"kind":"machine","id":machine.to_hex()}],"distribution_selectors":[]})).await?;
  case.status("POST","/api/access/private/sync","",request(0,&[]),StatusCode::BAD_REQUEST).await?;
  ensure!(case.app.collection("private_exit_routers").count_documents(doc!{"workspace_id":owner}).await?==0,"over-capacity router partially published role metadata before failure");
  Ok::<_,anyhow::Error>(())
 }.await;case.db.drop().await?;result
}
