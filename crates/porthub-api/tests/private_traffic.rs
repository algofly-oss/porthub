use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use porthub_api::{config::Config, domain::workspaces::token_digest};
use porthub_mesh::traffic_report::{Report, Row};
use serde_json::{json, Value};
mod support;
use support::Case;
const TOKEN: &str = "private-traffic-fixture-0123456789abcdef0123456789";
fn body(peer: &str, report: Value) -> Value {
    json!({"peer_id":peer,"token":TOKEN,"fingerprint":vec!["AB";32].join(":"),"instance":"instance-0123456789","traffic":report})
}
fn row(peer: &str, seq: u64, at: i64, sent: u64, received: u64) -> Row {
    Row {
        sequence: seq,
        peer_id: peer.into(),
        at,
        duration_seconds: 30,
        observed_at: at + 30_000,
        direct_sent: sent,
        direct_received: received,
        ..Default::default()
    }
}
fn report(rows: Vec<Row>) -> Value {
    serde_json::to_value(Report {
        instance: "a".repeat(32),
        rows,
        dropped_rows: 0,
    })
    .unwrap()
}
#[tokio::test]
#[ignore = "requires isolated MongoDB"]
async fn private_pair_history_is_account_scoped_idempotent_and_canonical_before_display_rollup(
) -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
  let(owner,cookie)=case.user("private-traffic-owner@test.invalid","user").await?;
  let(foreign,foreign_cookie)=case.user("private-traffic-other@test.invalid","admin").await?;
  let mut machines=Vec::new();let mut peers=Vec::new();
  for (index,user) in [(0,owner),(1,owner),(2,foreign)] {
   let machine=ObjectId::new();let peer=format!("{}:{}",user,machine);machines.push(machine);peers.push(peer.clone());
   case.app.collection("machines").insert_one(doc!{"_id":machine,"user_id":user,"enabled":true,"name":format!("Private machine {index}")}).await?;
   case.app.collection("private_peers").insert_one(doc!{"_id":peer,"workspace_id":user,"owner_id":user,"machine_id":machine,"enabled":true,"credential_hash":token_digest(TOKEN),"ip":format!("10.203.0.{}",index+10)}).await?;
  }
  let now=DateTime::now().timestamp_millis();let at=now.div_euclid(900_000)*900_000-900_000;
  let source=report(vec![row(&peers[1],1,at,100,0)]);
  let first=case.status("POST","/api/access/private/sync","",body(&peers[0],source.clone()),StatusCode::OK).await?;
  ensure!(first["snapshot"].is_object() && first["traffic_ack"]==1,"{first}");
  case.status("POST","/api/access/private/sync","",body(&peers[0],source),StatusCode::OK).await?;
  // Same coarse display interval, DIFFERENT native minute: sender evidence in
  // minute0 remains authoritative; receiver-only minute1 is diagnostic only. Duplicate retries add0.
  let receiver=report(vec![row(&peers[0],1,at,0,150),row(&peers[0],2,at+60_000,0,300)]);
  case.status("POST","/api/access/private/sync","",body(&peers[1],receiver.clone()),StatusCode::OK).await?;
  case.status("POST","/api/access/private/sync","",body(&peers[1],receiver),StatusCode::OK).await?;
  for range in ["1h","24h","7d","30d"] {
   let page=case.status("GET",&format!("/api/private/traffic?range={range}"),&cookie,Value::Null,StatusCode::OK).await?;
   let flow=page["flows"].as_array().unwrap().iter().find(|f|f["source_peer_id"]==peers[0]&&f["destination_peer_id"]==peers[1]).unwrap();
   ensure!(flow["total_bytes"]==100,"{range}: {page}");
   ensure!(flow["source_name"]=="Private machine 0"&&flow["destination_name"]=="Private machine 1");
   ensure!(flow["recent_bytes_per_second"].is_null(),"delayed upload must not become a current rate");
   ensure!(!page.to_string().contains(&peers[2])&&!page.to_string().contains(TOKEN));
  }

  // Receiver arrives first but never enters authoritative totals. Later sender
  // adds exactly100 to minute/hour/day totals, and replay cannot add twice.
  let late_at=at+120_000;
  let rx=report(vec![row(&peers[0],3,late_at,0,150)]);
  case.status("POST","/api/access/private/sync","",body(&peers[1],rx),StatusCode::OK).await?;
  let late=report(vec![row(&peers[1],2,late_at,100,0)]);
  for _ in 0..2 {case.status("POST","/api/access/private/sync","",body(&peers[0],late.clone()),StatusCode::OK).await?;}
  for range in ["1h","24h","7d","30d"] {
    let page=case.status("GET",&format!("/api/private/traffic?range={range}"),&cookie,Value::Null,StatusCode::OK).await?;
    ensure!(page["flows"][0]["total_bytes"]==200,"late sender correction {range}: {page}");
  }
  // Offline delivery from two days ago retains that day, not reconnect time.
  let old_at=now.div_euclid(86400_000)*86400_000-2*86400_000+3600_000;
  case.status("POST","/api/access/private/sync","",body(&peers[0],report(vec![row(&peers[1],3,old_at,70,0)])),StatusCode::OK).await?;
  for range in ["7d","30d"] {
    let page=case.status("GET",&format!("/api/private/traffic?range={range}"),&cookie,Value::Null,StatusCode::OK).await?;
    ensure!(page["flows"][0]["total_bytes"]==270,"offline old day {range}: {page}");
  }
  // Force ONLY the reverse directional write to fail after forward committed.
  // Retry must finish reverse while leaving forward exactly once.
  case.db.run_command(doc!{"collMod":"private_traffic","validator":{"source":&peers[0]},"validationLevel":"strict"}).await?;
  let mut partial=report(vec![row(&peers[1],1,at+180_000,20,30)]);partial["instance"]=json!("b".repeat(32));
  let failed=case.status("POST","/api/access/private/sync","",body(&peers[0],partial.clone()),StatusCode::OK).await?;
  ensure!(failed["traffic_ack"]==0 && failed["snapshot"].is_object(),"{failed}");
  case.db.run_command(doc!{"collMod":"private_traffic","validator":{}}).await?;
  let repaired=case.status("POST","/api/access/private/sync","",body(&peers[0],partial),StatusCode::OK).await?;ensure!(repaired["traffic_ack"]==1,"{repaired}");
  let page=case.status("GET","/api/private/traffic?range=24h",&cookie,Value::Null,StatusCode::OK).await?;
  ensure!(page["flows"].as_array().unwrap().iter().find(|f|f["source_peer_id"]==peers[0]).unwrap()["total_bytes"]==220,"{page}");
  ensure!(page["flows"].as_array().unwrap().iter().find(|f|f["source_peer_id"]==peers[1]).unwrap()["total_bytes"]==0,"{page}");
  // Saturating a valid persisted counter must reject/discard telemetry visibly,
  // never promote toDouble then turn into silent0 in the API projector.
  let mut overflow=report(vec![row(&peers[1],1,at+240_000,porthub_mesh::traffic_report::MAX_COUNTER,0)]);overflow["instance"]=json!("c".repeat(32));
  let rejected=case.status("POST","/api/access/private/sync","",body(&peers[0],overflow),StatusCode::OK).await?;
  ensure!(rejected["traffic_ack"]==1 && rejected["traffic_discarded_rows"]==1,"{rejected}");
  let stable=case.status("GET","/api/private/traffic?range=24h",&cookie,Value::Null,StatusCode::OK).await?;
  ensure!(stable["flows"].as_array().unwrap().iter().find(|f|f["source_peer_id"]==peers[0]).unwrap()["total_bytes"]==220,"overflow changed canonical bytes: {stable}");
  //128 remembered instances are a hard bound. A NEW identity is discarded and
  // acknowledged without eviction/replay risk or poisoning the policy queue.
  let day=at.div_euclid(86400_000)*86400_000;
  let key=format!("{}:{}:{}:{}",owner,peers[0],peers[1],day);
  let original=case.app.collection("private_traffic").find_one(doc!{"_id":&key}).await?.unwrap();
  let mut cursors=original.get_document("cursors")?.clone();let mut n=0;
  while cursors.len()<128 {cursors.insert(format!("s{:032x}",100+n),1_i64);n+=1;}
  case.app.collection("private_traffic").update_one(doc!{"_id":&key},doc!{"$set":{"cursors":cursors}}).await?;
  let mut capped=report(vec![row(&peers[1],1,at+300_000,1,0)]);capped["instance"]=json!("d".repeat(32));
  let rejected=case.status("POST","/api/access/private/sync","",body(&peers[0],capped),StatusCode::OK).await?;
  ensure!(rejected["traffic_ack"]==1 && rejected["traffic_discarded_rows"]==1,"{rejected}");
  let stored=case.app.collection("private_traffic").find_one(doc!{"_id":&key}).await?.unwrap();ensure!(stored.get_document("cursors")?.len()==128);
  // An existing instance still advances while full; no existing cursor evicted.
  let existing=case.status("POST","/api/access/private/sync","",body(&peers[0],report(vec![row(&peers[1],4,at+300_000,1,0)])),StatusCode::OK).await?;ensure!(existing["traffic_ack"]==4&&existing["traffic_discarded_rows"]==0,"{existing}");

  let full=case.status("GET","/api/private/traffic?range=24h",&cookie,Value::Null,StatusCode::OK).await?;
  ensure!(full["totals"]["total_bytes"]==221 && full["pagination"]["total_pairs"]==2,"{full}");
  ensure!(full["flows"].as_array().unwrap().iter().all(|f|f.get("points").is_none()),"pair pages must not carry every history");
  for suffix in ["&page=2","&search=NoMatchingMachine"] {
    let empty=case.status("GET",&format!("/api/private/traffic?range=24h{suffix}"),&cookie,Value::Null,StatusCode::OK).await?;
    ensure!(empty["flows"]==json!([]) && empty["totals"]==full["totals"] && empty["points"]==full["points"],"paging/search must not change account totals/history");
  }
  let selected=case.status("GET",&format!("/api/private/traffic?range=24h&source_peer_id={}&destination_peer_id={}",peers[0],peers[1]),&cookie,Value::Null,StatusCode::OK).await?;
  ensure!(selected["selected_flow"]["total_bytes"]==221,"{selected}");
  let sum:u64=selected["selected_flow"]["points"].as_array().unwrap().iter().map(|p|p["direct_bytes"].as_u64().unwrap()+p["relay_bytes"].as_u64().unwrap()).sum();ensure!(sum==221);
  let hidden=case.status("GET",&format!("/api/private/traffic?source_peer_id={}&destination_peer_id={}",peers[0],peers[2]),&cookie,Value::Null,StatusCode::OK).await?;ensure!(hidden["selected_flow"].is_null());

  // A newer receiver observation cannot refresh the selected sender's older
  // rate timestamp in that same native minute.
  let rate_at=now.div_euclid(60_000)*60_000-60_000;
  let mut sent=row(&peers[1],5,rate_at,10,0);sent.duration_seconds=1;sent.observed_at=rate_at+1000;
  case.status("POST","/api/access/private/sync","",body(&peers[0],report(vec![sent.clone()])),StatusCode::OK).await?;
  let mut received=row(&peers[0],4,rate_at,0,900);received.duration_seconds=60;received.observed_at=now;
  case.status("POST","/api/access/private/sync","",body(&peers[1],report(vec![received])),StatusCode::OK).await?;
  let rate=case.status("GET",&format!("/api/private/traffic?source_peer_id={}&destination_peer_id={}",peers[0],peers[1]),&cookie,Value::Null,StatusCode::OK).await?;
  let flow=&rate["selected_flow"];
  ensure!(flow["rate_at"].is_null()||flow["rate_at"]==sent.observed_at,"receiver timestamp must not refresh sender rate: {flow}");
  if !flow["recent_bytes_per_second"].is_null(){ensure!(flow["recent_bytes_per_second"].as_f64()==Some(10.0)&&flow["recent_interval_seconds"]==1,"{flow}")}
  let other=case.status("GET","/api/private/traffic?range=24h",&foreign_cookie,Value::Null,StatusCode::OK).await?;ensure!(other["flows"]==json!([]),"admin must not broaden account scope");
  let forged=report(vec![row(&peers[2],6,at,999,0)]);
  let discarded=case.status("POST","/api/access/private/sync","",body(&peers[0],forged),StatusCode::OK).await?;ensure!(discarded["traffic_ack"]==6&&discarded["snapshot"].is_object());
  let malformed=case.status("POST","/api/access/private/sync","",body(&peers[0],json!({"token":"must-not-be-echoed"})),StatusCode::OK).await?;ensure!(malformed["traffic_rejected"]==true&&malformed["snapshot"].is_object()&&!malformed.to_string().contains("must-not-be-echoed"));
  let filtered=case.status("GET",&format!("/api/private/traffic?range=24h&machine_id={}",machines[2]),&cookie,Value::Null,StatusCode::OK).await?;ensure!(filtered["flows"]==json!([]));

  // A real sender observation with TX0 (and opposite-direction RX) is retained
  // as observed zero in selected history, distinct from missing-sender gaps.
  let zero_at=at+360_000;
  case.status("POST","/api/access/private/sync","",body(&peers[0],report(vec![row(&peers[1],7,zero_at,0,1)])),StatusCode::OK).await?;
  let zero=case.status("GET",&format!("/api/private/traffic?range=1h&source_peer_id={}&destination_peer_id={}",peers[0],peers[1]),&cookie,Value::Null,StatusCode::OK).await?;
  let point=zero["selected_flow"]["points"].as_array().unwrap().iter().find(|p|p["at"]==zero_at).unwrap();
  ensure!(point["direct_bytes"]==0&&point["relay_bytes"]==0&&point["coverage"]=="sender_reported"&&point["sender_coverage_complete"]==true,"explicit observed zero lost: {point}");
  case.app.collection("machines").update_one(doc!{"_id":machines[1]},doc!{"$set":{"user_id":foreign}}).await?;
  let removed=case.status("GET","/api/private/traffic?range=24h",&cookie,Value::Null,StatusCode::OK).await?;ensure!(removed["flows"]==json!([]),"current ownership removal must remove old peer measurements");
  Ok(())
 }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB"]
async fn private_pair_pages_keep_full_totals_and_selected_history_with_real_recent_duration(
) -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
        let(owner,cookie)=case.user("private-page-owner@test.invalid","user").await?;
        let source_machine=ObjectId::new();let source=format!("{}:{}",owner,source_machine);
        case.app.collection("machines").insert_one(doc!{"_id":source_machine,"user_id":owner,"enabled":true,"name":"Source"}).await?;
        case.app.collection("private_peers").insert_one(doc!{"_id":&source,"workspace_id":owner,"owner_id":owner,"machine_id":source_machine,"enabled":true,"credential_hash":token_digest(TOKEN),"ip":"10.203.0.10"}).await?;
        let now=DateTime::now().timestamp_millis();let at=(now-10_000).div_euclid(60_000)*60_000;
        let mut rows=Vec::new();let mut destinations=Vec::new();
        for n in 0..85 {
            let machine=ObjectId::new();let peer=format!("{}:{}",owner,machine);destinations.push(peer.clone());
            case.app.collection("machines").insert_one(doc!{"_id":machine,"user_id":owner,"enabled":true,"name":format!("Destination {n:02}")}).await?;
            case.app.collection("private_peers").insert_one(doc!{"_id":&peer,"workspace_id":owner,"owner_id":owner,"machine_id":machine,"enabled":true,"credential_hash":token_digest(TOKEN),"ip":format!("10.203.0.{}",n+11)}).await?;
            let mut value=row(&peer,n+1,at,n+1,0);value.duration_seconds=10;value.observed_at=now;rows.push(value);
        }
        let mut last_ack=0;
        for _ in 0..10 {
            let reply=case.status("POST","/api/access/private/sync","",body(&source,report(rows.clone())),StatusCode::OK).await?;
            let ack=reply["traffic_ack"].as_u64().unwrap_or(0);ensure!(ack>=last_ack,"ack must not regress");
            rows.retain(|r|r.sequence>ack);last_ack=ack;if rows.is_empty(){break}
        }
        ensure!(rows.is_empty(),"bounded partial upload must make progress to all85 observations");
        let started=std::time::Instant::now();
        let first=case.status("GET","/api/private/traffic?range=1h",&cookie,Value::Null,StatusCode::OK).await?;
        ensure!(first["totals"]["total_bytes"]==3655 && first["pagination"]["total_pairs"]==85 && first["flows"].as_array().unwrap().len()==40,"{first}");
        for (page,count) in [(2,40),(3,5)] {
            let response=case.status("GET",&format!("/api/private/traffic?range=1h&page={page}"),&cookie,Value::Null,StatusCode::OK).await?;
            ensure!(response["flows"].as_array().unwrap().len()==count && response["totals"]==first["totals"] && response["points"]==first["points"]);
        }
        let search=case.status("GET","/api/private/traffic?range=1h&search=Destination%2084",&cookie,Value::Null,StatusCode::OK).await?;
        ensure!(search["flows"].as_array().unwrap().len()==1 && search["pagination"]["filtered_pairs"]==1 && search["totals"]==first["totals"]);
        for range in ["1h","24h","7d","30d"] {
            let selected=case.status("GET",&format!("/api/private/traffic?range={range}&page=3&source_peer_id={source}&destination_peer_id={}",destinations[84]),&cookie,Value::Null,StatusCode::OK).await?;
            let flow=&selected["selected_flow"];ensure!(flow["total_bytes"]==85 && flow["recent_interval_seconds"]==10 && flow["recent_bytes_per_second"].as_f64()==Some(8.5) && flow["rate_at"]==now && flow["rate_stale"]==false,"recent rate {range}: {flow}");
            ensure!(flow["points"].as_array().unwrap().iter().map(|p|p["direct_bytes"].as_u64().unwrap()).sum::<u64>()==85);
        }
        println!("PRIVATE_TRAFFIC_API_MEASURE pairs=85 page_rows=40 first_response_bytes={} pages_and_ranges_elapsed_ms={}",first.to_string().len(),started.elapsed().as_millis());
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB"]
async fn sender_history_excludes_clock_offset_receiver_observations_in_every_range() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
  let(owner,cookie)=case.user("sender-only-owner@test.invalid","user").await?;
  let machines=[ObjectId::new(),ObjectId::new()];let peers:Vec<_>=machines.iter().map(|m|format!("{owner}:{m}")).collect();
  for(index,machine)in machines.iter().enumerate(){
   case.app.collection("machines").insert_one(doc!{"_id":machine,"user_id":owner,"enabled":true,"name":format!("Offset node {index}")}).await?;
   case.app.collection("private_peers").insert_one(doc!{"_id":&peers[index],"workspace_id":owner,"owner_id":owner,"machine_id":machine,"enabled":true,"credential_hash":token_digest(TOKEN),"ip":format!("10.203.0.{}",index+10)}).await?;
  }
  let now=DateTime::now().timestamp_millis();let at=now.div_euclid(60_000)*60_000-120_000;
  let received=report(vec![row(&peers[0],1,at+60_000,0,100)]);
  case.status("POST","/api/access/private/sync","",body(&peers[1],received.clone()),StatusCode::OK).await?;
  for range in ["1h","24h","7d","30d"] {
   let page=case.status("GET",&format!("/api/private/traffic?range={range}&source_peer_id={}&destination_peer_id={}",peers[0],peers[1]),&cookie,Value::Null,StatusCode::OK).await?;
   let flow=&page["selected_flow"];ensure!(flow["coverage"]=="missing_sender"&&flow["total_bytes"]==0&&flow["received_total_bytes"]==100&&flow["recent_bytes_per_second"].is_null()&&flow["sender_coverage_complete"]==false,"receiver-only {range}: {page}");
   ensure!(page["totals"]["total_bytes"]==0&&page["points"]==json!([])&&flow["points"]==json!([])&&page["coverage"]["missing_sender_pairs"]==1);
  }
  let sent=report(vec![row(&peers[1],1,at,100,0)]);
  for _ in 0..2 {
   case.status("POST","/api/access/private/sync","",body(&peers[0],sent.clone()),StatusCode::OK).await?;
   case.status("POST","/api/access/private/sync","",body(&peers[1],received.clone()),StatusCode::OK).await?;
  }
  for range in ["1h","24h","7d","30d"] {
   let page=case.status("GET",&format!("/api/private/traffic?range={range}&source_peer_id={}&destination_peer_id={}",peers[0],peers[1]),&cookie,Value::Null,StatusCode::OK).await?;
   let flow=&page["selected_flow"];ensure!(page["totals"]["total_bytes"]==100&&flow["total_bytes"]==100&&flow["received_total_bytes"]==100&&flow["coverage"]=="sender_reported"&&flow["sender_coverage_complete"]==false,"cross-minute burst doublecounted {range}: {page}");
   ensure!(flow["points"].as_array().unwrap().iter().map(|r|r["direct_bytes"].as_u64().unwrap()).sum::<u64>()==100);
   ensure!(flow["receiver_points"].as_array().unwrap().iter().map(|r|r["direct_received"].as_u64().unwrap()).sum::<u64>()==100);
  }
  Ok(())
 }.await;
    case.db.drop().await?;
    result
}

/// Bounded lookup is independent of sparse selection. This exercises the real
/// lookup and ordinary sync; the sparse build also exercises an empty selected
/// peer batch through the actual HTTP endpoint.
#[tokio::test]
#[ignore = "requires isolated MongoDB"]
async fn historical_report_authorization_is_independent_of_pair_batch_and_rechecks_both_owners() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (owner, cookie) = case.user("historical-owner@test.invalid", "user").await?;
        let (member, _) = case.user("historical-member@test.invalid", "user").await?;
        let (foreign, _) = case.user("historical-foreign@test.invalid", "user").await?;
        case.app.collection("workspace_members").insert_one(doc!{"workspace_id":owner,"user_id":member,"role":"member"}).await?;
        let mut peers = Vec::new(); let mut machines = Vec::new();
        for (index, user) in [owner, member, foreign].into_iter().enumerate() {
            let machine = ObjectId::new(); let peer = format!("{user}:{machine}");
            case.app.collection("machines").insert_one(doc!{"_id":machine,"user_id":user,"enabled":true,"name":format!("History{index}")}).await?;
            case.app.collection("private_peers").insert_one(doc!{"_id":&peer,"workspace_id":if index==2 {foreign}else{owner},"owner_id":user,"machine_id":machine,"enabled":true,"credential_hash":token_digest(TOKEN),"ip":format!("10.203.0.{}",index+20)}).await?;
            peers.push(peer); machines.push(machine);
        }
        let at = DateTime::now().timestamp_millis().div_euclid(60_000)*60_000-60_000;
        let report: Report = serde_json::from_value(report(vec![row(&peers[1],1,at,100,200),row(&peers[2],2,at,999,999)]))?;
        let resolve = || porthub_api::private_traffic::authorized_report_peers(&case.app,owner,&peers[0],&report);
        let authorized = resolve().await.map_err(|error|anyhow::anyhow!("authorization failed: {}",error.detail))?;
        ensure!(authorized.iter().any(|p|p.get_str("_id")==Ok(peers[1].as_str())));
        ensure!(!authorized.iter().any(|p|p.get_str("_id")==Ok(peers[2].as_str())));
        // Both historically supported BSON identity representations must match
        // the same member, while machine.user_id remains equal to peer.owner_id.
        case.app.collection("private_peers").update_one(doc!{"_id":&peers[1]},doc!{"$set":{"owner_id":member.to_hex()}}).await?;
        case.app.collection("machines").update_one(doc!{"_id":machines[1]},doc!{"$set":{"user_id":member.to_hex()}}).await?;
        ensure!(resolve().await.map_err(|e|anyhow::anyhow!("{}",e.detail))?.iter().any(|p|p.get_str("_id")==Ok(peers[1].as_str())));
        case.app.collection("private_peers").update_one(doc!{"_id":&peers[1]},doc!{"$set":{"owner_id":member}}).await?;
        case.app.collection("machines").update_one(doc!{"_id":machines[1]},doc!{"$set":{"user_id":member}}).await?;
        case.app.collection("workspace_members").update_one(doc!{"workspace_id":owner,"user_id":member},doc!{"$set":{"user_id":member.to_hex()}}).await?;
        ensure!(resolve().await.map_err(|e|anyhow::anyhow!("{}",e.detail))?.iter().any(|p|p.get_str("_id")==Ok(peers[1].as_str())));
        case.app.collection("workspace_members").update_one(doc!{"workspace_id":owner,"user_id":member.to_hex()},doc!{"$set":{"user_id":member}}).await?;
        // ACL/online/lease state is intentionally irrelevant to historical data.
        #[cfg(feature="private-sparse")]
        {
            case.app.collection("private_networks").update_one(doc!{"_id":owner.to_hex()},doc!{"$setOnInsert":{"cidr":"10.203.0.0/24","dns_suffix":"phub"}}).upsert(true).await?;
            let mut sparse_body=body(&peers[0],serde_json::to_value(&report)?);
            sparse_body["sparse"]=json!({"protocol":1,"sequence":1,"wanted":[]});
            let sparse=case.status("POST","/api/access/private/sync","",sparse_body,StatusCode::OK).await?;
            ensure!(sparse["snapshot"]["sparse"].is_object(),"sparse path not exercised: {sparse}");
            ensure!(sparse["snapshot"]["peers"].as_array().unwrap().iter().all(|p|p["id"]==peers[0]),"historical target leaked into selected batch: {sparse}");
            ensure!(sparse["traffic_ack"]==2 && sparse["traffic_discarded_rows"]==1,"bounded historical target lost: {sparse}");
            let history=case.status("GET","/api/private/traffic?range=1h",&cookie,Value::Null,StatusCode::OK).await?;
            ensure!(history["totals"]["total_bytes"]==100,"sparse report lost sender history: {history}");
        }
        let first = case.status("POST","/api/access/private/sync","",body(&peers[0],serde_json::to_value(&report)?),StatusCode::OK).await?;
        ensure!(first["traffic_ack"]==2 && first["traffic_discarded_rows"]==1,"{first}");
        case.status("POST","/api/access/private/sync","",body(&peers[0],serde_json::to_value(&report)?),StatusCode::OK).await?;
        let saved = case.app.collection("private_traffic").find_one(doc!{"source":&peers[0],"destination":&peers[1]}).await?.unwrap();
        ensure!(saved.get_str("source")?==peers[0]);
        let history = case.status("GET","/api/private/traffic?range=1h",&cookie,Value::Null,StatusCode::OK).await?;
        ensure!(history["totals"]["total_bytes"]==100,"retry or RX changed sender-only total: {history}");
        ensure!(history["flows"][0]["received_total_bytes"]==0);

        // Every subsequent lookup observes current target eligibility.
        for field in ["enabled","deletion_pending","private_owner_revoked"] {
            let bad = field != "enabled";
            case.app.collection("machines").update_one(doc!{"_id":machines[1]},doc!{"$set":{field:bad}}).await?;
            ensure!(!resolve().await.map_err(|error|anyhow::anyhow!("authorization failed: {}",error.detail))?.iter().any(|p|p.get_str("_id")==Ok(peers[1].as_str())),"{field}");
            case.app.collection("machines").update_one(doc!{"_id":machines[1]},doc!{"$set":{field:!bad}}).await?;
        }
        case.app.collection("users").update_one(doc!{"_id":member},doc!{"$set":{"account_deletion":{}}}).await?;
        ensure!(!resolve().await.map_err(|error|anyhow::anyhow!("authorization failed: {}",error.detail))?.iter().any(|p|p.get_str("_id")==Ok(peers[1].as_str())));
        case.app.collection("users").update_one(doc!{"_id":member},doc!{"$unset":{"account_deletion":""}}).await?;
        case.app.collection("users").update_one(doc!{"_id":owner},doc!{"$set":{"account_deletion":{}}}).await?;
        ensure!(resolve().await.is_err(),"retiring workspace cannot authorize history");
        case.app.collection("users").update_one(doc!{"_id":owner},doc!{"$unset":{"account_deletion":""}}).await?;
        case.app.collection("workspace_members").delete_one(doc!{"workspace_id":owner,"user_id":member}).await?;
        ensure!(!resolve().await.map_err(|error|anyhow::anyhow!("authorization failed: {}",error.detail))?.iter().any(|p|p.get_str("_id")==Ok(peers[1].as_str())));
        let mut maximum = report.clone(); maximum.rows.clear();
        for index in 0..porthub_mesh::traffic_report::MAX_ROWS {
            let peer = format!("{owner}:{}",ObjectId::new());
            case.app.collection("private_peers").insert_one(doc!{"_id":&peer,"workspace_id":owner,"owner_id":owner,"machine_id":machines[0],"enabled":true}).await?;
            maximum.rows.push(row(&peer,index as u64+1,at,1,0));
        }
        ensure!(porthub_api::private_traffic::authorized_report_peers(&case.app,owner,&peers[0],&maximum).await.map_err(|error|anyhow::anyhow!("authorization failed: {}",error.detail))?.len()==257);
        maximum.rows.push(row("overflow",257,at,1,0));
        ensure!(porthub_api::private_traffic::authorized_report_peers(&case.app,owner,&peers[0],&maximum).await.is_err());
        case.app.collection("machines").update_one(doc!{"_id":machines[0]},doc!{"$set":{"private_owner_revoked":true}}).await?;
        ensure!(resolve().await.is_err(),"revoked reporter cannot authorize writes");
        Ok::<_,anyhow::Error>(())
    }.await;
    let cleanup = case.db.drop().await;
    result?; cleanup?; Ok(())
}
