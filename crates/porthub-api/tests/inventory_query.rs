use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use porthub_api::{config::Config, inventory_query::Params};
use serde_json::json;
mod support;
use support::Case;
#[test]
fn query_limits_are_bounded_and_numeric_terms_are_not_fuzzy() {
    assert!(Params::default().validate().is_ok());
    for p in [
        Params {
            page_size: 101,
            ..Params::default()
        },
        Params {
            page: 0,
            ..Params::default()
        },
        Params {
            q: "x".repeat(257),
            ..Params::default()
        },
    ] {
        assert!(p.validate().is_err());
    }
    assert!(porthub_api::inventory_query::patterns("8000").1.is_none());
    assert!(porthub_api::inventory_query::patterns("reid").1.is_some());
    assert_eq!(
        porthub_api::inventory_query::patterns("cafe").0,
        porthub_api::inventory_query::patterns("café").0
    );
}
#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn database_search_pages_totals_relevance_and_owner_scoping() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async{
  let(owner,cookie)=case.user("inventory@example.invalid","user").await?;let(foreign,_)=case.user("hidden-inventory@example.invalid","user").await?;
  let mut docs=Vec::new();let mut machine_ids=Vec::new();
  for i in 0..130{
   let id=ObjectId::new();machine_ids.push(id);
   docs.push(doc!{"_id":id,"user_id":owner,"name":format!("worker-{i:03}"),"hostname":"node.example","token":"test-secret-must-not-appear-in-options","enabled":true,"last_seen_at":DateTime::now(),"created_at":DateTime::now()});
  }
  docs.extend([doc!{"_id":ObjectId::new(),"user_id":owner,"name":"Reid","enabled":true},doc!{"_id":ObjectId::new(),"user_id":owner,"name":"café-01","enabled":true},doc!{"_id":ObjectId::new(),"user_id":foreign,"name":"Reid hidden foreign"}]);
  case.app.collection("machines").insert_many(docs).await?;
  case.app.collection("machines").update_one(doc!{"_id":machine_ids[129]},doc!{"$set":{"last_seen_at":mongodb::bson::Bson::Null}}).await?;
  let offline=case.status("GET","/api/inventory/machines?status=offline",&cookie,json!(null),StatusCode::OK).await?;
  ensure!(offline["pagination"]["total"]==3,"Never-connected machines with null timestamps must be offline: {offline}");

  case.app.collection("connections").insert_many([doc!{"_id":ObjectId::new(),"user_id":owner,"machine_id":machine_ids[3],"service_name":"special pipeline","external_port":8000_i64},doc!{"_id":ObjectId::new(),"user_id":foreign,"machine_id":machine_ids[3],"service_name":"foreign hidden match","external_port":9000_i64}]).await?;
  let endpoint="/api/inventory/machines?page=2&page_size=25&sort=name";
  let(status,headers,page)=case.call("GET",endpoint,&cookie,json!(null),&[]).await?;ensure!(status==StatusCode::OK,"{page}");
  ensure!(page["data"].as_array().unwrap().len()==25 && page["pagination"]["total"]==132 && page["pagination"]["pages"]==6);
  let names:Vec<_>=page["data"].as_array().unwrap().iter().map(|m|m["name"].as_str().unwrap()).collect();ensure!(names.windows(2).all(|n|n[0]<=n[1]));
  let(status,_,_)=case.call("GET",endpoint,&cookie,json!(null),&[("if-none-match",headers["etag"].to_str()?)]).await?;ensure!(status==StatusCode::NOT_MODIFIED);
  let weak=format!("W/{}",headers["etag"].to_str()?);
  let(status,_,_)=case.call("GET",endpoint,&cookie,json!(null),&[("if-none-match",&weak)]).await?;ensure!(status==StatusCode::NOT_MODIFIED,"Compressed public proxies may return weak validators");
  for query in ["Reid","reod","redi"]{
   let body=case.status("GET",&format!("/api/inventory/machines?q={query}"),&cookie,json!(null),StatusCode::OK).await?;
   ensure!(body["pagination"]["total"]==1 && body["data"][0]["name"]=="Reid","{query}: {body}");
  }
  let exact=case.status("GET","/api/inventory/machines?q=8000",&cookie,json!(null),StatusCode::OK).await?;ensure!(exact["pagination"]["total"]==1);
  let near=case.status("GET","/api/inventory/machines?q=8001",&cookie,json!(null),StatusCode::OK).await?;ensure!(near["pagination"]["total"]==0);
  let hidden=case.status("GET","/api/inventory/machines?q=foreign",&cookie,json!(null),StatusCode::OK).await?;ensure!(hidden["pagination"]["total"]==0);
  let accent=case.status("GET","/api/inventory/machines?q=cafe",&cookie,json!(null),StatusCode::OK).await?;ensure!(accent["pagination"]["total"]==1);
  let options=case.status("GET","/api/inventory/machines?options=true&page_size=10",&cookie,json!(null),StatusCode::OK).await?;ensure!(options["data"].as_array().unwrap().len()==10);ensure!(!options.to_string().contains("test-secret"));
  let full=case.status("GET","/api/machines/list",&cookie,json!(null),StatusCode::OK).await?;
  ensure!(serde_json::to_vec(&options)?.len()*4<serde_json::to_vec(&full)?.len(),"Option response should be bounded and substantially smaller");
  // The editor receives bounded previews but complete counts and policy fields.
  let group_id=ObjectId::new();
  case.app.collection("machine_groups").insert_one(doc!{"_id":group_id,"user_id":owner,"name":"Compute"}).await?;
  case.app.collection("machines").update_one(doc!{"_id":machine_ids[0]},doc!{"$set":{"group_ids":[group_id]}}).await?;
  let ports=(0..150).map(|i|doc!{"_id":ObjectId::new(),"user_id":owner,"machine_id":machine_ids[0],"service_name":format!("port-{i}"),"external_port":10000_i64+i,"enabled":i!=149,"firewall":{"is_public":false,"allowed_ips":["192.0.2.10"]}}).collect::<Vec<_>>();
  case.app.collection("connections").insert_many(ports).await?;
  let bounded=case.status("GET",&format!("/api/inventory/machines?ids={}",machine_ids[0]),&cookie,json!(null),StatusCode::OK).await?;
  ensure!(bounded["data"][0]["num_ports"]==149 && bounded["data"][0]["ports_total"]==150 && bounded["data"][0]["ports_truncated"]==true,"{bounded}");
  ensure!(bounded["connections"].as_array().unwrap().len()==10);
  ensure!(bounded["connections"][0]["firewall"]["allowed_ips"][0]=="192.0.2.10","{bounded}");
  ensure!(bounded["data"][0]["group_labels"][0]["name"]=="Compute");
  let groups=case.status("GET","/api/inventory/groups",&cookie,json!(null),StatusCode::OK).await?;
  ensure!(groups["data"][0]["machineCount"]==1,"{groups}");
  let(status,summary_headers,summary)=case.call("GET","/api/inventory/summary",&cookie,json!(null),&[]).await?;
  ensure!(status==StatusCode::OK && summary["data"]["machines"]["total"]==132 && summary["data"]["ports"]==151,"{summary}");
  case.app.collection("machines").update_one(doc!{"_id":machine_ids[0]},doc!{"$set":{"last_seen_at":DateTime::now()}}).await?;
  let(status,_,_)=case.call("GET","/api/inventory/summary",&cookie,json!(null),&[("if-none-match",summary_headers["etag"].to_str()?)]).await?;ensure!(status==StatusCode::NOT_MODIFIED,"Heartbeat should not invalidate unchanged counts");
  let state=case.status("GET",&format!("/api/inventory-status?ids={}",machine_ids[0]),&cookie,json!(null),StatusCode::OK).await?;
  ensure!(state["data"].as_array().unwrap().len()==1 && state["data"][0].get("token").is_none());
  let empty=case.status("GET","/api/inventory-status",&cookie,json!(null),StatusCode::OK).await?;ensure!(empty["data"].as_array().unwrap().is_empty());
  let foreign_machine=case.app.collection("machines").find_one(doc!{"user_id":foreign}).await?.unwrap().get_object_id("_id")?;
  let hidden_status=case.status("GET",&format!("/api/inventory-status?ids={foreign_machine}"),&cookie,json!(null),StatusCode::OK).await?;ensure!(hidden_status["data"].as_array().unwrap().is_empty());
  // Additive startup indexes are safe to run twice and never rewrite records.
  porthub_api::inventory_query::ensure_indexes(&case.app).await.map_err(|_|anyhow::anyhow!("Index setup failed"))?;
  porthub_api::inventory_query::ensure_indexes(&case.app).await.map_err(|_|anyhow::anyhow!("Index setup failed"))?;
  case.status("GET","/api/inventory/machines?page_size=10000",&cookie,json!(null),StatusCode::BAD_REQUEST).await?;
  case.status("GET","/api/inventory/machines","",json!(null),StatusCode::BAD_REQUEST).await?;
  Ok(())
 }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn traffic_pages_rank_the_full_match_and_delta_only_visible_rows() -> Result<()> {
    use porthub_api::inventory_traffic::Snapshot;
    use std::{sync::Arc, time::Instant};
    let case = Case::new(Config::default()).await?;
    let result=async {
        let (owner,cookie)=case.user("traffic-page@example.invalid","user").await?;
        let (foreign,_)=case.user("traffic-other@example.invalid","user").await?;
        let alpha=ObjectId::new();let beta=ObjectId::new();
        case.app.collection("machines").insert_many([doc!{"_id":alpha,"user_id":owner,"name":"Alpha"},doc!{"_id":beta,"user_id":owner,"name":"Beta"}]).await?;
        let ids=[ObjectId::new(),ObjectId::new(),ObjectId::new(),ObjectId::new()];
        case.app.collection("connections").insert_many(ids.iter().enumerate().map(|(i,id)|doc!{"_id":id,"user_id":if i==3 {foreign}else{owner},"machine_id":if i==0 {alpha}else{beta},"service_name":format!("service-{i}"),"external_port":(8000+i) as i64})).await?;
        let now=DateTime::now().timestamp_millis() as u64/1000;
        let mut snapshot=Snapshot::default();
        for (i,id) in ids.iter().enumerate() {
            let samples=vec![json!({"timestamp":now-10,"in_bytes":(i+1)*100,"out_bytes":0,"in_rate":(i+1)*100,"out_rate":0,"drop_bytes":0,"drop_rate":0,"interval_seconds":1,"incoming_ips":["192.0.2.10"],"outgoing_ips":[],"blocked_ips":[]})];
            snapshot.ports.insert(id.to_hex(),porthub_api::inventory_traffic::numeric(&samples));
            case.app.inventory_traffic.1.lock().await.insert(format!("{owner}:{id}:{}",8000+i),(Instant::now(),Arc::new(samples)));
        }
        snapshot.machine_ports.insert(alpha.to_hex(),vec![ids[0].to_hex()]);
        snapshot.machine_ports.insert(beta.to_hex(),vec![ids[1].to_hex(),ids[2].to_hex()]);
        case.app.inventory_traffic.0.lock().await.insert(owner.to_hex(),(Instant::now(),Arc::new(snapshot)));
        let page=case.status("GET","/api/inventory/traffic?sort=traffic&page_size=1&seconds=60",&cookie,json!(null),StatusCode::OK).await?;
        ensure!(page["pagination"]["total"]==3 && page["data"].as_array().unwrap().len()==1,"{page}");
        ensure!(page["data"][0]["connection"]["_id"]==ids[2].to_hex(),"Ranks beyond the first page before selecting rows");
        ensure!(page["aggregate"][0]["in_bytes"]==600.,"Aggregate covers all owned matching ports, not only the page: {page}");
        ensure!(page["data"][0]["traffic"][0].get("incoming_ips").is_none(),"Collapsed rows must not download source IP lists");
        let expanded=case.status("GET",&format!("/api/inventory/traffic?sort=traffic&page_size=1&seconds=60&expanded={}",ids[2]),&cookie,json!(null),StatusCode::OK).await?;
        ensure!(expanded["data"][0]["traffic"][0]["incoming_ips"][0]=="192.0.2.10");
        let delta=case.status("GET",&format!("/api/inventory/traffic?sort=traffic&page_size=1&seconds=60&since={}&known={}",now-1,ids[2]),&cookie,json!(null),StatusCode::OK).await?;
        ensure!(delta["data"][0]["traffic"].as_array().unwrap().is_empty() && delta["aggregate"].as_array().unwrap().is_empty());
        let newly_visible=case.status("GET",&format!("/api/inventory/traffic?sort=traffic&page_size=1&page=2&seconds=60&since={}&known={}",now-1,ids[2]),&cookie,json!(null),StatusCode::OK).await?;
        ensure!(newly_visible["data"][0]["traffic"].as_array().unwrap().len()==1,"A newly ranked row needs its initial history even with an advanced cursor");
        let machines=case.status("GET","/api/inventory/machines?sort=traffic&page_size=1",&cookie,json!(null),StatusCode::OK).await?;
        ensure!(machines["data"][0]["_id"]==beta.to_hex());
        let empty=case.status("GET",&format!("/api/inventory/traffic?ids={}",ids[3]),&cookie,json!(null),StatusCode::OK).await?;
        ensure!(empty["pagination"]["total"]==0 && empty["aggregate"].as_array().unwrap().is_empty(),"Foreign ports cannot enter traffic pages or aggregates");
        case.app.collection("connections").delete_one(doc!{"_id":ids[0]}).await?;
        let reset=case.status("GET",&format!("/api/inventory/traffic?sort=traffic&page_size=1&seconds=60&scope_revision={}&since={}&row_cursors={}:{}",page["scope_revision"].as_str().unwrap(),now-1,ids[2],now-1),&cookie,json!(null),StatusCode::OK).await?;
        ensure!(reset["reset"]==true && reset["data"][0]["traffic"].as_array().unwrap().len()==1 && reset["aggregate"][0]["in_bytes"]==500.,"Removing a matching port must discard stale aggregate and row cursors: {reset}");

        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn account_pages_require_admin_and_nested_reads_stay_with_the_selected_owner() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
        let (_,admin)=case.user("admin-paging@example.invalid","admin").await?;
        let (owner,cookie)=case.user("fleet-owner@example.invalid","user").await?;
        let (foreign,_)=case.user("other-fleet@example.invalid","user").await?;
        let machine=ObjectId::new();
        case.app.collection("machines").insert_many([doc!{"_id":machine,"user_id":owner,"name":"AccountSearchReid","enabled":true,"last_seen_at":DateTime::now()},doc!{"_id":ObjectId::new(),"user_id":foreign,"name":"Other machine"}]).await?;
        case.app.collection("connections").insert_one(doc!{"_id":ObjectId::new(),"user_id":owner,"machine_id":machine,"service_name":"AccountPipeline","external_port":8123_i64}).await?;
        case.status("GET","/api/inventory/accounts",&cookie,json!(null),StatusCode::FORBIDDEN).await?;
        case.status("GET",&format!("/api/inventory/machines?account={foreign}"),&cookie,json!(null),StatusCode::FORBIDDEN).await?;
        let result=case.status("GET","/api/inventory/accounts?page_size=1&sort=machines",&admin,json!(null),StatusCode::OK).await?;
        ensure!(result["pagination"]["total"]==3 && result["data"].as_array().unwrap().len()==1);
        ensure!(!result.to_string().contains("password") && result["data"][0].get("machines").is_none(),"Account rows must be summaries, not complete child inventories");
        for query in ["AccountSearchReid","AccountPipeline","8123"] {
            let result=case.status("GET",&format!("/api/inventory/accounts?q={query}"),&admin,json!(null),StatusCode::OK).await?;
            ensure!(result["pagination"]["total"]==1 && result["data"][0]["user"]["id"]==owner.to_hex(),"{query}: {result}");
            ensure!(result["data"][0]["machine_count"]==1 && result["data"][0]["online_count"]==1 && result["data"][0]["port_count"]==1,"{result}");
        }
        let machines=case.status("GET",&format!("/api/inventory/machines?account={owner}&options=true"),&admin,json!(null),StatusCode::OK).await?;
        ensure!(machines["pagination"]["total"]==1 && machines["data"][0]["_id"]==machine.to_hex() && machines["data"][0].get("token").is_none());
        let ports=case.status("GET",&format!("/api/inventory/connections?account={foreign}&machine={machine}"),&admin,json!(null),StatusCode::OK).await?;
        ensure!(ports["pagination"]["total"]==0,"Nested account reads cannot join ports across owners");
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn bounded_activity_and_private_domains_preserve_owner_boundaries() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
        let (owner,cookie)=case.user("bounded-meta@example.invalid","user").await?;
        let (foreign,_)=case.user("bounded-meta-foreign@example.invalid","user").await?;
        let machines=[ObjectId::new(),ObjectId::new()];
        case.app.collection("machines").insert_many(machines.iter().map(|id|doc!{"_id":id,"user_id":owner,"name":"Same Name"})).await?;
        case.app.collection("private_networks").insert_one(doc!{"_id":owner.to_hex(),"cidr":"10.203.8.0/24","dns_suffix":"corp.internal"}).await?;
        case.app.collection("private_peers").insert_many(machines.iter().enumerate().map(|(i,id)|doc!{"_id":ObjectId::new(),"owner_id":owner,"workspace_id":owner,"machine_id":id,"enabled":true,"hostname":"","created_at":DateTime::now(),"ip":format!("10.203.8.{}",i+2)})).await?;
        let inventory=case.status("GET","/api/inventory/machines",&cookie,json!(null),StatusCode::OK).await?;
        let domains=inventory["data"].as_array().unwrap().iter().map(|m|m["default_private_domain"].as_str().unwrap()).collect::<std::collections::BTreeSet<_>>();
        ensure!(domains.len()==2 && domains.iter().all(|name|name.ends_with(".corp.internal")),"Default names include collision suffixes and the actual workspace DNS suffix: {inventory}");
        case.app.collection("machines").update_one(doc!{"_id":machines[0]},doc!{"$set":{"private_owner_revoked":true}}).await?;
        let revoked=case.status("GET",&format!("/api/inventory/machines?ids={}",machines[0]),&cookie,json!(null),StatusCode::OK).await?;
        ensure!(revoked["data"][0]["private_ips"].as_array().unwrap().is_empty() && revoked["data"][0]["default_private_domain"]=="");
        let routes=[ObjectId::new(),ObjectId::new(),ObjectId::new()];
        case.app.collection("traffic_routes").insert_many(routes.iter().enumerate().map(|(i,id)|doc!{"_id":id,"user_id":if i==2 {foreign}else{owner},"name":format!("route-{i}"),"hosts":[format!("route-{i}.invalid")]})).await?;
        let mut metrics=mongodb::bson::Document::new();
        for (i,id) in routes.iter().enumerate() {metrics.insert(id.to_hex(),doc!{"requests":(i+1) as i64,"last_requested_at":format!("2026-10-30T10:00:0{i}+00:00")});}
        case.app.collection("proxy_activity").insert_one(doc!{"_id":"traefik-requests-v1","metrics":metrics,"tracking_since":"2026-10-01T00:00:00+00:00"}).await?;
        let selected=case.status("GET",&format!("/api/inventory/proxy-activity?ids={},{}",routes[0],routes[2]),&cookie,json!(null),StatusCode::OK).await?;
        ensure!(selected["data"].as_array().unwrap().len()==1 && selected["data"][0]["route_id"]==routes[0].to_hex());
        let (_,headers,recent)=case.call("GET","/api/inventory/proxy-activity?recent=1",&cookie,json!(null),&[]).await?;
        ensure!(recent["data"].as_array().unwrap().len()==1 && recent["data"][0]["route_id"]==routes[1].to_hex() && recent["routes"][0]["_id"]==routes[1].to_hex(),"Recent proxies must be ranked across owned routes only: {recent}");
        let (status,_,_)=case.call("GET","/api/inventory/proxy-activity?recent=1",&cookie,json!(null),&[("if-none-match",headers["etag"].to_str()?)]).await?;ensure!(status==StatusCode::NOT_MODIFIED);
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn access_pages_check_membership_bound_previews_and_resolve_only_scoped_entities(
) -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
        let (owner,owner_cookie)=case.user("access-owner@example.invalid","user").await?;
        let (member,member_cookie)=case.user("access-member@example.invalid","user").await?;
        let (foreign,_)=case.user("access-foreign@example.invalid","user").await?;
        case.app.collection("workspace_members").insert_one(doc!{"_id":format!("{owner}:{member}"),"workspace_id":owner,"user_id":member,"role":"member"}).await?;
        let group=ObjectId::new();let machine=ObjectId::new();
        case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner,"name":"Private production","user_ids":[member,foreign]}).await?;
        case.app.collection("machines").insert_many([doc!{"_id":machine,"user_id":owner,"name":"WorkspaceReid","token":"must-not-leak","group_ids":[group]},doc!{"_id":ObjectId::new(),"user_id":foreign,"name":"HiddenForeignMachine","token":"foreign-secret"}]).await?;
        let rule=json!({"id":"r1","name":"Remote shell","enabled":true,"sources":[{"kind":"user","id":member.to_hex()}],"destinations":[{"kind":"machine","id":machine.to_hex()}],"protocol":"tcp","ports":"22","bidirectional":false});
        let book=ObjectId::new();
        case.app.collection("access_rulebooks").insert_one(doc!{"_id":book,"user_id":owner,"name":"Remote shell access","group_id":group.to_hex(),"enabled":true,"revision":7_i64,"rules":mongodb::bson::to_bson(&vec![rule;40])?}).await?;
        let route=format!("/api/inventory/access-books?workspace={owner}&page_size=10&q=WorkspaceReid");
        let books=case.status("GET",&route,&member_cookie,json!(null),StatusCode::OK).await?;
        ensure!(books["role"]=="member" && books["pagination"]["total"]==1 && books["data"][0]["rules"].as_array().unwrap().len()==2 && books["data"][0]["rules_count"]==40,"{books}");
        ensure!(books["data"][0]["group_name"]=="Private production" && books["labels"][format!("machine:{machine}")]=="WorkspaceReid");
        let detail=case.status("GET",&format!("/api/inventory/access-books?workspace={owner}&ids={book}&detail=true&page_size=1"),&member_cookie,json!(null),StatusCode::OK).await?;
        ensure!(detail["data"][0]["rules"].as_array().unwrap().len()==40 && detail["data"][0]["revision"]==7,"Opening an editor must load the entire selected policy for a safe revision-checked save");
        case.status("GET",&format!("/api/inventory/access-books?workspace={owner}&detail=true"),&member_cookie,json!(null),StatusCode::BAD_REQUEST).await?;
        let machines=case.status("GET",&format!("/api/inventory/access-machines?workspace={owner}&membership={group}"),&member_cookie,json!(null),StatusCode::OK).await?;
        ensure!(machines["pagination"]["total"]==1 && machines["data"][0]["member"]==true && !machines.to_string().contains("token") && !machines.to_string().contains("must-not-leak"));
        let groups=case.status("GET",&format!("/api/inventory/access-groups?workspace={owner}"),&member_cookie,json!(null),StatusCode::OK).await?;
        ensure!(groups["data"][0]["machine_count"]==1 && groups["data"][0]["book_count"]==1 && groups["data"][0]["user_count"]==1 && groups["data"][0].get("user_ids").is_none(),"Group summaries must omit complete membership lists and exclude revoked people: {groups}");
        let entities=case.status("GET",&format!("/api/inventory/access-entities?workspace={owner}&q=HiddenForeign"),&member_cookie,json!(null),StatusCode::OK).await?;
        ensure!(entities["pagination"]["total"]==0);
        let entity=case.status("GET",&format!("/api/inventory/access-entities?workspace={owner}&ids=machine:{machine}"),&member_cookie,json!(null),StatusCode::OK).await?;
        ensure!(entity["pagination"]["total"]==1 && entity["data"][0]["_id"]==format!("machine:{machine}"));
        case.status("GET",&format!("/api/inventory/access-invitations?workspace={owner}"),&member_cookie,json!(null),StatusCode::FORBIDDEN).await?;
        let summary=case.status("GET","/api/inventory/access-summary",&owner_cookie,json!(null),StatusCode::OK).await?;
        ensure!(summary["data"]["counts"]["machines"]==1 && summary["data"]["counts"]["people"]==2 && summary["data"].get("machines").is_none());
        case.app.collection("workspace_members").delete_one(doc!{"workspace_id":owner,"user_id":member}).await?;
        case.status("GET",&route,&member_cookie,json!(null),StatusCode::FORBIDDEN).await?;
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn partial_group_membership_saves_preserve_unseen_members_and_check_authorization(
) -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
        let (owner,cookie)=case.user("patch-owner@example.invalid","user").await?;
        let (person,person_cookie)=case.user("patch-person@example.invalid","user").await?;
        let (unseen,_)=case.user("patch-unseen@example.invalid","user").await?;
        let (foreign,_)=case.user("patch-foreign@example.invalid","user").await?;
        for user in [person,unseen] {case.app.collection("workspace_members").insert_one(doc!{"_id":format!("{owner}:{user}"),"workspace_id":owner,"user_id":user,"role":"member"}).await?;}
        let group=ObjectId::new();let other_group=ObjectId::new();
        case.app.collection("machine_groups").insert_many([doc!{"_id":group,"user_id":owner,"name":"Paged membership","user_ids":[person,unseen]},doc!{"_id":other_group,"user_id":owner,"name":"Unrelated","user_ids":[unseen]}]).await?;
        let machines=(0..6).map(|_|ObjectId::new()).collect::<Vec<_>>();
        case.app.collection("machines").insert_many(machines.iter().enumerate().map(|(i,id)|doc!{"_id":id,"user_id":if i==5 {foreign}else{owner},"name":format!("Paged machine {i}"),"group_ids":if i<4 {vec![group,other_group]}else{vec![other_group]}})).await?;
        let endpoint=format!("/api/access/groups/{group}/members");
        let body=json!({"machine_add":[machines[4].to_hex()],"machine_remove":[machines[0].to_hex()],"user_add":[],"user_remove":[person.to_hex()]});
        case.status("PATCH",&format!("{endpoint}?workspace={owner}"),&person_cookie,body.clone(),StatusCode::FORBIDDEN).await?;
        case.status("PATCH",&endpoint,&cookie,body,StatusCode::OK).await?;
        let group_record=case.app.collection("machine_groups").find_one(doc!{"_id":group}).await?.unwrap();
        ensure!(group_record.get_array("user_ids")?==&vec![mongodb::bson::Bson::ObjectId(unseen)],"An unloaded person must remain a member");
        for (i,id) in machines.iter().take(5).enumerate(){let record=case.app.collection("machines").find_one(doc!{"_id":id}).await?.unwrap();let groups=porthub_api::domain::inventory::group_ids(&record);ensure!(groups.contains(&group)==(i!=0) && groups.contains(&other_group),"Only the explicit checkbox edits can affect membership: {i}");}
        let invalid=json!({"machine_add":[machines[5].to_hex()],"machine_remove":[],"user_add":[],"user_remove":[]});
        case.status("PATCH",&endpoint,&cookie,invalid,StatusCode::BAD_REQUEST).await?;
        let overlap=json!({"machine_add":[machines[1].to_hex()],"machine_remove":[machines[1].to_hex()],"user_add":[],"user_remove":[]});
        case.status("PATCH",&endpoint,&cookie,overlap,StatusCode::BAD_REQUEST).await?;
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn proxy_lists_bound_binding_previews_but_search_and_edit_the_complete_proxy() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
        let (owner,cookie)=case.user("proxy-pages@example.invalid","user").await?;
        let (foreign,_)=case.user("proxy-pages-foreign@example.invalid","user").await?;
        let id=ObjectId::new();
        let bindings=(0..128).map(|i|doc!{"id":format!("binding-{i}"),"label":if i==127 {"HiddenBackupRoute".to_owned()}else{format!("Target {i}")},"target_mode":"manual","target_url":format!("https://target-{i}.example.invalid/app"),"enabled":true,"priority":i+1,"weight":1}).collect::<Vec<_>>();
        case.app.collection("traffic_routes").insert_many([doc!{"_id":id,"user_id":owner,"name":"Many routes","hosts":["many.example.invalid"],"bindings":&bindings},doc!{"_id":ObjectId::new(),"user_id":foreign,"name":"Hidden foreign proxy","hosts":["foreign.example.invalid"],"bindings":&bindings}]).await?;
        let page=case.status("GET","/api/inventory/proxies?q=HiddenBackupRoute",&cookie,json!(null),StatusCode::OK).await?;
        ensure!(page["pagination"]["total"]==1 && page["data"][0]["bindings"].as_array().unwrap().len()==2 && page["data"][0]["bindings_count"]==128 && page["data"][0]["bindings_truncated"]==true,"{page}");
        let detail=case.status("GET",&format!("/api/inventory/proxies?ids={id}&detail=true&page_size=1"),&cookie,json!(null),StatusCode::OK).await?;
        ensure!(detail["data"][0]["bindings"].as_array().unwrap().len()==128 && detail["data"][0]["bindings_truncated"]==false);
        ensure!(serde_json::to_vec(&page)?.len()*8<serde_json::to_vec(&detail)?.len(),"List responses must not download all binding configuration");
        case.status("GET","/api/inventory/proxies?detail=true",&cookie,json!(null),StatusCode::BAD_REQUEST).await?;
        let legacy=case.status("GET","/api/traffic-routes/list",&cookie,json!(null),StatusCode::OK).await?;
        ensure!(legacy["data"][0]["bindings"].as_array().unwrap().len()==128,"The old endpoint remains complete for existing clients");
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn aggregate_delta_bases_correct_older_buckets_and_cannot_cross_scopes() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
        use porthub_api::inventory_traffic::{numeric,series_delta,Sample};
        ensure!(std::mem::size_of::<Sample>()<=64,"Fleet history must retain fixed-size numeric data, not JSON/IP objects");
        let first=numeric(&[json!({"timestamp":100,"in_bytes":10}),json!({"timestamp":101,"in_bytes":20})]);
        let base=series_delta(&case.app,"owner-one:all-ports".into(),"",&first).await;
        ensure!(base.replace && base.points.len()==2 && base.token.len()==22);
        let corrected=numeric(&[json!({"timestamp":100,"in_bytes":30}),json!({"timestamp":102,"in_bytes":40})]);
        let delta=series_delta(&case.app,"owner-one:all-ports".into(),&base.token,&corrected).await;
        ensure!(!delta.replace && delta.points.iter().any(|sample|sample.timestamp==100 && sample.in_bytes==30.) && delta.removed==vec![101],"An old partial bucket must be corrected even when a newer timestamp has already been sent");
        let unchanged=series_delta(&case.app,"owner-one:all-ports".into(),&delta.token,&corrected).await;
        ensure!(!unchanged.replace && unchanged.points.is_empty() && unchanged.removed.is_empty());
        let foreign=series_delta(&case.app,"owner-two:all-ports".into(),&base.token,&corrected).await;
        ensure!(foreign.replace && foreign.points.len()==2 && foreign.token!=delta.token,"Delta bases belong to an exact owner/query scope");
        let evicted=series_delta(&case.app,"owner-one:all-ports".into(),"unknown-base",&corrected).await;
        ensure!(evicted.replace && evicted.points.len()==2,"An unavailable base must replace, not merge with, stale client history");
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}
