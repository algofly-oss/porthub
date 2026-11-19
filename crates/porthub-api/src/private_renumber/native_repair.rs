//! Durable collision feedback, bound to an authenticated current assignment.
//! Reports cannot choose target ranges or mutate peer/rule/DNS identities.
use crate::{App,error::{ApiError,ApiResult}};
use mongodb::bson::{doc,oid::ObjectId,Document};
use porthub_network::native_repair::Request;
use super::{journal,recovery::Assignment};
use futures_util::TryStreamExt;
fn invalid(message:&str)->ApiError{ApiError::new(axum::http::StatusCode::CONFLICT,message)}
pub async fn record(app:&App,owner:ObjectId,peer:&Document,request:&Request)->ApiResult<()>{
    request.validate().map_err(|_|ApiError::bad_request("Invalid native collision report"))?;
    if peer.get_str("ip").ok()!=Some(request.source.to_string().as_str()){return Ok(());} // stale completed request
    if crate::private_sparse::machine(app,owner,peer).await?.is_none(){return Err(ApiError::new(axum::http::StatusCode::FORBIDDEN,"Native repair enrollment is no longer authorized"));}
    let prefs=app.collection("private_networks").find_one(doc!{"_id":owner.to_hex()}).await?.unwrap_or_default();
    let pools=crate::domain::private_networks::pools(&prefs)?;
    if request.blocked.iter().any(|blocked|!pools.iter().any(|p|p.cidr()==blocked.to_string())){return Err(ApiError::bad_request("Native repair does not match assigned capture pools"));}
    let peer_id=peer.get_str("_id").map_err(|_|invalid("Invalid repair enrollment"))?;
    let row=doc!{"_id":peer_id,"workspace":owner,"machine":peer.get("machine_id"),"credential_hash":peer.get("credential_hash"),"enrollment_generation":peer.get_str("enrollment_generation").unwrap_or("legacy"),"source":request.source.to_string(),"nonce":&request.nonce,"blocked":request.blocked.iter().map(ToString::to_string).collect::<Vec<_>>()};
    let queue=journal::durable(app,"private_native_repairs");
    if queue.find_one(doc!{"_id":peer_id}).await?.as_ref()==Some(&row){return Ok(());}
    queue.replace_one(doc!{"_id":peer_id},row).upsert(true).await?;Ok(())
}
/// Caller holds the workspace publication guard (and allocation for writers).
/// A stable head and the published pool generation must agree; pool expansion
/// may legitimately add current pools not listed in the prior migration plan.
pub(crate) async fn published_generation(app:&App,owner:ObjectId,prefs:&Document)->ApiResult<i64>{
    let head=app.collection("private_renumber_heads").find_one(doc!{"_id":owner.to_hex()}).await?;
    match head {
        None if !prefs.contains_key("_address_generation") && !prefs.contains_key("_renumber_job")=>Ok(0),
        Some(head) if head.get_str("state").ok()==Some("stable")=>{
            let generation=head.get_i64("generation").map_err(|_|invalid("Invalid published address generation"))?;
            if generation==0 && !prefs.contains_key("_address_generation") && !prefs.contains_key("_renumber_job") && !head.contains_key("job"){return Ok(0);}
            if generation<=0 || prefs.get_i64("_address_generation").ok()!=Some(generation) || prefs.get_str("_renumber_job").ok()!=head.get_str("job").ok() || head.get_str("job").is_err(){return Err(invalid("Published address generation differs from stable migration"));}
            Ok(generation)
        },
        _=>Err(invalid("Private address publication is not stable")),
    }
}
/// Compatibility for enrollments created by the former missing-generation bug.
/// Never reinterpret explicit stale generations or a migrated peer with erased
/// metadata. Exact assignment/credential CAS preserves concurrent foreign edits.
async fn repair_missing_generation(app:&App,owner:ObjectId,prefs:&Document,row:&Document,generation:i64,migrated:&std::collections::HashSet<String>,retired:&[crate::domain::enrollment::Network],addresses:&[std::net::Ipv4Addr])->ApiResult<()>{
    if row.contains_key("address_generation"){return Err(invalid("Native repair peer generation changed"));}
    let ip=row.get_str("ip").map_err(|_|invalid("Missing repair assignment"))?.parse::<std::net::Ipv4Addr>().map_err(|_|invalid("Invalid repair assignment"))?;
    if !crate::domain::private_networks::pools(prefs)?.iter().any(|pool|pool.contains(ip)){return Err(invalid("Historical enrollment is outside published pools"));}
    if retired.iter().any(|pool|pool.contains(ip))||addresses.contains(&ip){return Err(invalid("Historical enrollment uses a retired source"));}
    if migrated.contains(row.get_str("_id").map_err(|_|invalid("Missing enrollment identity"))?){return Err(invalid("Migrated peer lost its address generation"));}
    let mut filter=doc!{"_id":row.get("_id"),"workspace_id":owner,"ip":row.get("ip"),"address_generation":{"$exists":false}};
    for field in ["machine_id","credential_hash","enrollment_generation"]{filter.insert(field,row.get(field).cloned().unwrap_or_else(||mongodb::bson::Bson::Document(doc!{"$exists":false})));}
    let result=journal::durable(app,"private_peers").update_one(filter,doc!{"$set":{"address_generation":generation}}).await?;
    if result.matched_count!=1{return Err(invalid("Historical enrollment changed during generation repair"));}
    Ok(())
}

/// Repair only demonstrably post-migration enrollments. The caller must hold
/// the workspace publication guard; this function grants no network authority.
pub(crate) async fn ensure_assignment_generations(app:&App,owner:ObjectId,prefs:&Document,rows:&[Document])->ApiResult<i64>{
    let generation=published_generation(app,owner,prefs).await?;
    let head=app.collection("private_renumber_heads").find_one(doc!{"_id":owner.to_hex()}).await?;
    let mut migrated=std::collections::HashSet::new();
    let mut retained=(Vec::new(),Vec::new());
    if generation>0 && rows.iter().any(|row|!row.contains_key("address_generation")) {
        let head=head.as_ref().ok_or_else(||invalid("Missing migration origin"))?;
        let job=head.get_str("job").map_err(|_|invalid("Missing stable migration origin"))?;
        if head.get_i64("applied").ok()!=head.get_i64("count").ok(){return Err(invalid("Stable migration progress is incomplete"));}
        super::apply::verify(app,owner,job,head).await?;
        let mut previous=app.collection("private_renumber_assignments").find(doc!{"job":job}).projection(doc!{"peer":1}).batch_size(256).await?;
        while let Some(row)=previous.try_next().await?{migrated.insert(row.get_str("peer").map_err(|_|invalid("Invalid prior migration identity"))?.to_owned());}
        retained=super::retirement::occupied(app).await?;
    }
    for row in rows {
        if row.get_i64("address_generation").ok()==Some(generation) || generation==0 && !row.contains_key("address_generation"){continue;}
        repair_missing_generation(app,owner,prefs,row,generation,&migrated,&retained.0,&retained.1).await?;
    }
    Ok(generation)
}

/// A complete immutable plan is prepared under the existing allocation and
/// publication guards. The normal roll-forward worker, not this report, applies it.
pub async fn plan_once(app:&App,request:&Document)->ApiResult<bool>{
    let owner=request.get_object_id("workspace").map_err(|_|invalid("Invalid repair workspace"))?;
    let guard=super::fence::exclusive(app,owner).await?;
    let mut filter=doc!{"_id":request.get("_id"),"workspace_id":owner,"enabled":true,"credential_hash":request.get("credential_hash"),"ip":request.get("source")};
    if request.get_str("enrollment_generation").ok()==Some("legacy"){filter.insert("$or",vec![doc!{"enrollment_generation":"legacy"},doc!{"enrollment_generation":{"$exists":false}}]);}
    else{filter.insert("enrollment_generation",request.get("enrollment_generation"));}
    let peer=app.collection("private_peers").find_one(filter).await?;
    let Some(peer)=peer else{return Ok(true)};
    if crate::private_sparse::machine(app,owner,&peer).await?.is_none(){return Ok(true);}
    let head=app.collection("private_renumber_heads").find_one(doc!{"_id":owner.to_hex()}).await?;
    if head.as_ref().is_some_and(|h|h.get_str("state").ok()!=Some("stable")){return Ok(false);}
    let generation=head.as_ref().map_or(Ok(0),|h|h.get_i64("generation")).map_err(|_|invalid("Invalid repair generation"))?;
    if generation<0||generation==i64::MAX{return Err(invalid("Native repair generation exhausted"));}
    let prefs=app.collection("private_networks").find_one(doc!{"_id":owner.to_hex()}).await?.unwrap_or_default();
    let pools=crate::domain::private_networks::pools(&prefs)?;
    if published_generation(app,owner,&prefs).await?!=generation{return Err(invalid("Native repair generation changed"));}
    let blocked=request.get_array("blocked").map_err(|_|invalid("Missing native repair scope"))?;
    if blocked.is_empty()||blocked.len()>porthub_network::capture_routes::MAX_CAPTURE_PREFIXES||blocked.iter().any(|b|!pools.iter().any(|p|Some(p.cidr().as_str())==b.as_str())){return Ok(true);}
    let rows:Vec<_>=app.collection("private_peers").find(doc!{"workspace_id":owner}).projection(doc!{"_id":1,"machine_id":1,"workspace_id":1,"enrollment_generation":1,"address_generation":1,"credential_hash":1,"ip":1}).sort(doc!{"_id":1}).limit(65537).batch_size(256).await?.try_collect().await?;
    if rows.is_empty()||rows.len()>65536{return Err(invalid("Native repair workspace exceeds migration budget"));}
    ensure_assignment_generations(app,owner,&prefs,&rows).await?;
    let targets=crate::domain::private_networks::migration_targets_locked(app,&owner.to_hex(),rows.len(),blocked).await?;
    let mut slots=targets.iter().flat_map(|pool|(0..pool.capacity()).map(move|offset|pool.migration_address(offset).expect("bounded planned pool")));
    let mut assignments=Vec::with_capacity(rows.len());
    for row in rows{
        let peer=row.get_str("_id").map_err(|_|invalid("Invalid migration peer"))?.to_owned();
        let machine=crate::store::id(row.get("machine_id"));
        let old=row.get_str("ip").map_err(|_|invalid("Missing migration address"))?.parse().map_err(|_|invalid("Invalid migration address"))?;
        let new=slots.next().ok_or_else(||invalid("Native repair target capacity changed"))?;
        assignments.push(Assignment{peer,machine,workspace:owner.to_hex(),credential_generation:row.get_str("enrollment_generation").unwrap_or("legacy").into(),old,new,previous_generation:generation as u64,generation:generation as u64+1});
    }
    let job=uuid::Uuid::new_v4().simple().to_string();
    let reporting_peer = peer.get_str("_id").map_err(|_| invalid("Missing reporting enrollment"))?;
    journal::prepare(&guard,&job,&assignments,&targets.iter().map(|p|p.cidr()).collect::<Vec<_>>(),Some(reporting_peer)).await?;
    Ok(true)
}
// Delete only the exact immutable binding that was processed. A nonce may be
// reused after credential/source rotation; matching nonce alone loses that report.
async fn remove_processed(app:&App,row:&Document)->ApiResult<()>{
    journal::durable(app,"private_native_repairs").delete_one(row.clone()).await?;
    Ok(())
}
/// Bounded keyset discovery; exact queued binding cannot erase a replacement.
pub async fn pending_once(app:&App,after:Option<String>)->ApiResult<Option<String>>{
    let queue=journal::durable(app,"private_native_repairs");
    let filter=after.map(|id|doc!{"_id":{"$gt":id}}).unwrap_or_default();
    let rows:Vec<_>=queue.find(filter).sort(doc!{"_id":1}).limit(8).await?.try_collect().await?;
    let mut last=None;
    for row in rows{let id=row.get_str("_id").map_err(|_|invalid("Invalid queued repair identity"))?.to_owned();last=Some(id.clone());
        match plan_once(app,&row).await{
            Ok(true)=>{remove_processed(app,&row).await?;},
            Ok(false)=>{},Err(_)=>tracing::warn!("Native collision repair remains queued; bounded discovery continues"),
        }
    }Ok(last)
}

#[cfg(test)]mod tests{
    use super::*;
    use std::sync::Arc;
    use tower::ServiceExt;
    use futures_util::FutureExt;
    async fn post(app:Arc<App>,peer:&str,token:&str,repair:Option<Request>)->anyhow::Result<axum::http::StatusCode>{
        let body=serde_json::json!({"peer_id":peer,"token":token,"fingerprint":vec!["AB";32].join(":"),"instance":"repair-instance-0123456789","sparse":{"protocol":1,"sequence":1,"wanted":[]},"native_repair":repair});
        let response=crate::routes::private_sync::router().with_state(app).oneshot(axum::http::Request::builder().method("POST").uri("/api/access/private/sync").header("Content-Type","application/json").body(axum::body::Body::from(serde_json::to_vec(&body)?))?).await?;
        Ok(response.status())
    }
    pub(super) async fn seed(app:&App,owner:ObjectId,token:&str)->anyhow::Result<Vec<Document>>{
        app.collection("users").insert_one(doc!{"_id":owner,"email":"private-repair-fixture.invalid"}).await?;
        app.collection("private_networks").insert_one(doc!{"_id":owner.to_hex(),"cidr":"10.203.0.0/24","dns_suffix":"kept.private","custom_setting":"preserved"}).await?;
        let mut peers=Vec::new();
        for i in 0..2{let machine=ObjectId::new();
            app.collection("machines").insert_one(doc!{"_id":machine,"user_id":owner,"name":format!("Repair {i}"),"aliases":[format!("stable-{i}")]}).await?;
            let peer=doc!{"_id":format!("{owner}:{machine}"),"workspace_id":owner,"owner_id":owner,"machine_id":machine,"enabled":true,"credential_hash":crate::domain::workspaces::token_digest(token),"ip":format!("10.203.0.{}",i+2),"custom_hostname":format!("stable-{i}.kept.private"),"created_at":mongodb::bson::DateTime::now()};
            app.collection("private_peers").insert_one(peer.clone()).await?;peers.push(peer);
        }
        app.collection("access_rulebooks").insert_one(doc!{"_id":ObjectId::new(),"user_id":owner,"enabled":true,"rules":[]}).await?;
        Ok(peers)
    }
    pub(super) fn report()->Request{Request{protocol:1,nonce:"a".repeat(32),source:"10.203.0.2".parse().unwrap(),blocked:vec!["10.203.0.0/24".parse().unwrap()]}}
    #[tokio::test]
    #[ignore="requires Root-owned isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
    async fn processed_queue_binding_cannot_delete_same_nonce_replacement()->anyhow::Result<()>{
        let client=mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;
        let db=client.database(&format!("porthub_repair_nonce_{}",uuid::Uuid::new_v4().simple()));
        let result=std::panic::AssertUnwindSafe(async{
            let app=App::new(crate::config::Config::default(),db.clone());
            let owner=ObjectId::new();let machine=ObjectId::new();
            let id=format!("{owner}:{machine}");let nonce="c".repeat(32);
            let original=doc!{"_id":&id,"workspace":owner,"machine":machine,"credential_hash":"old-credential-digest","enrollment_generation":"old-generation","source":"10.203.0.2","nonce":&nonce,"blocked":["10.203.0.0/24"]};
            let queue=journal::durable(&app,"private_native_repairs");
            queue.insert_one(original.clone()).await?;
            // Deterministic interleave: worker retained original; a new report
            // replaces its authority binding while deliberately retaining nonce.
            let mut replacement=original.clone();
            replacement.insert("credential_hash","new-credential-digest");
            replacement.insert("enrollment_generation","new-generation");
            replacement.insert("source","10.204.0.2");
            replacement.insert("blocked",vec!["10.204.0.0/24"]);
            queue.replace_one(doc!{"_id":&id},replacement.clone()).await?;
            remove_processed(&app,&original).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            assert_eq!(queue.find_one(doc!{"_id":&id}).await?,Some(replacement.clone()));
            // An unchanged processed binding remains removable, so no perpetual
            // queue leak is introduced by the stronger compare-and-delete.
            remove_processed(&app,&replacement).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            assert!(queue.find_one(doc!{"_id":&id}).await?.is_none());
            Ok::<_,anyhow::Error>(())
        }).catch_unwind().await;
        db.drop().await?;
        match result{Ok(value)=>value,Err(panic)=>std::panic::resume_unwind(panic)}
    }
    #[tokio::test]
    #[ignore="requires Root-owned isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
    async fn actual_sync_collision_queue_full_plan_restart_preserves_ids_rules_dns_and_never_reuses_old_source()->anyhow::Result<()>{
        let client=mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;
        let db=client.database(&format!("porthub_native_repair_{}",uuid::Uuid::new_v4().simple()));
        let result=std::panic::AssertUnwindSafe(async{
            let app=Arc::new(App::new(crate::config::Config::default(),db.clone()));let owner=ObjectId::new();let token="fixture-credential-0123456789abcdef0123456789";
            let peers=seed(&app,owner,token).await?;let id=peers[0].get_str("_id")?;
            let book=app.collection("access_rulebooks").find_one(doc!{"user_id":owner}).await?.unwrap();
            assert_eq!(post(app.clone(),id,token,Some(report())).await?,axum::http::StatusCode::OK);
            let before:Vec<_>=app.collection("private_peers").find(doc!{"workspace_id":owner}).sort(doc!{"_id":1}).await?.try_collect().await?;
            let queued=app.collection("private_native_repairs").find_one(doc!{"_id":id}).await?.unwrap();
            assert!(plan_once(&app,&queued).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?);
            let head=app.collection("private_renumber_heads").find_one(doc!{"_id":owner.to_hex()}).await?.unwrap();assert_eq!(head.get_str("state")?,"applying");
            let job=head.get_str("job")?.to_owned();
            let reservation=app.collection("private_retired_sources").find_one(doc!{"_id":&job}).await?.unwrap();assert_eq!(reservation.get_bool("activated")?,true);
            // Simulate ACK lost after head activation: the durable head still
            // activates the prepared old-range reservation on a fresh process.
            app.collection("private_retired_sources").update_one(doc!{"_id":&job},doc!{"$unset":{"activated":""}}).await?;
            let restarted=App::new(crate::config::Config::default(),db.clone());
            let (reserved,old)=super::super::retirement::occupied(&restarted).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            assert!(reserved.iter().any(|p|p.cidr()=="10.203.0.0/24"));assert!(old.contains(&report().source));
            assert_eq!(super::super::recover::workspace(&restarted,owner).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?,super::super::recover::Outcome::Committed);
            remove_processed(&restarted, &queued).await.map_err(|e| anyhow::anyhow!("{}", e.detail))?;
            let plans = restarted.collection("private_renumber_assignments");
            let reporter_filter = doc!{"job": &job, "reported_native_collision": true};
            assert_eq!(plans.count_documents(reporter_filter.clone()).await?, 1);
            let reporter = plans.find_one(reporter_filter).await?.unwrap();
            assert_eq!(reporter.get_str("peer")?, id);
            assert_eq!(reporter.get_str("old")?, report().source.to_string());
            let prefs=restarted.collection("private_networks").find_one(doc!{"_id":owner.to_hex()}).await?.unwrap();
            assert_eq!(prefs.get_str("dns_suffix")?,"kept.private");assert_eq!(prefs.get_str("custom_setting")?,"preserved");
            for mut original in before{
                let after=restarted.collection("private_peers").find_one(doc!{"_id":original.get("_id")}).await?.unwrap();
                assert_ne!(after.get_str("ip")?,original.get_str("ip")?);
                assert_eq!(after.get_i64("address_generation")?,1);
                original.insert("ip",after.get("ip").unwrap().clone());original.insert("address_generation",1_i64);assert_eq!(after,original);
            }
            assert_eq!(restarted.collection("access_rulebooks").find_one(doc!{"_id":book.get("_id")}).await?.unwrap(),book);
            // Stable completion and even later head removal cannot recycle the
            // old source pool: activated denial records are independent.
            restarted.collection("private_renumber_heads").delete_one(doc!{"_id":owner.to_hex()}).await?;
            let fresh=App::new(crate::config::Config::default(),db.clone());
            assert!(crate::domain::private_networks::save(&fresh,&ObjectId::new().to_hex(),crate::domain::enrollment::Network::parse("10.203.0.0/24").unwrap(),"other.private").await.is_err());
            assert!(super::super::retirement::occupied(&fresh).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?.1.contains(&report().source));
            Ok::<_,anyhow::Error>(())
        }).catch_unwind().await;let cleanup=db.drop().await;cleanup?;match result{Ok(value)=>value,Err(panic)=>std::panic::resume_unwind(panic)}
    }
    #[tokio::test]
    #[ignore="requires Root-owned isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
    async fn actual_http_auth_stale_foreign_pool_and_rotated_enrollment_cannot_authorize_repair()->anyhow::Result<()>{
        let client=mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;let db=client.database(&format!("porthub_native_repair_deny_{}",uuid::Uuid::new_v4().simple()));
        let result=std::panic::AssertUnwindSafe(async{
            let app=Arc::new(App::new(crate::config::Config::default(),db.clone()));let owner=ObjectId::new();let token="fixture-credential-0123456789abcdef0123456789";let peers=seed(&app,owner,token).await?;let id=peers[0].get_str("_id")?;
            assert_eq!(post(app.clone(),id,"wrong-credential-0123456789abcdef0123456789",Some(report())).await?,axum::http::StatusCode::FORBIDDEN);
            let mut stale=report();stale.source="10.203.0.99".parse()?;assert_eq!(post(app.clone(),id,token,Some(stale)).await?,axum::http::StatusCode::OK);
            let mut foreign=report();foreign.blocked=vec!["10.204.0.0/24".parse()?];assert_eq!(post(app.clone(),id,token,Some(foreign)).await?,axum::http::StatusCode::BAD_REQUEST);
            assert_eq!(app.collection("private_native_repairs").count_documents(doc!{}).await?,0);
            assert_eq!(post(app.clone(),id,token,Some(report())).await?,axum::http::StatusCode::OK);
            app.collection("private_peers").update_one(doc!{"_id":id},doc!{"$set":{"credential_hash":"rotated-only-fixture"}}).await?;
            pending_once(&app,None).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            assert_eq!(app.collection("private_native_repairs").count_documents(doc!{}).await?,0);assert_eq!(app.collection("private_renumber_heads").count_documents(doc!{}).await?,0);
            Ok::<_,anyhow::Error>(())
        }).catch_unwind().await;let cleanup=db.drop().await;cleanup?;match result{Ok(value)=>value,Err(panic)=>std::panic::resume_unwind(panic)}
    }
    #[tokio::test]
    #[ignore="requires Root-owned isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
    async fn actual_4097_identity_plan_has_disjoint_capacity_and_complete_bounded_assignments()->anyhow::Result<()>{
        let client=mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;let db=client.database(&format!("porthub_native_repair_scale_{}",uuid::Uuid::new_v4().simple()));
        let result=std::panic::AssertUnwindSafe(async{
            let app=App::new(crate::config::Config::default(),db.clone());let owner=ObjectId::new();let peers=seed(&app,owner,"fixture-credential-0123456789abcdef0123456789").await?;
            let mut rows=Vec::new();let mut machines=Vec::new();for n in 2..4097u32{let machine=ObjectId::new();machines.push(doc!{"_id":machine,"user_id":owner,"name":format!("Scale {n}")});rows.push(doc!{"_id":format!("{owner}:{machine}"),"workspace_id":owner,"owner_id":owner,"machine_id":machine,"enabled":true,"credential_hash":"scale-fixture-not-runtime","ip":std::net::Ipv4Addr::from(0x0acb0000+n+2).to_string()});}
            app.collection("machines").insert_many(machines).await?;app.collection("private_peers").insert_many(rows).await?;
            record(&app,owner,&peers[0],&report()).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            let queue=app.collection("private_native_repairs").find_one(doc!{"_id":peers[0].get("_id")}).await?.unwrap();
            assert!(plan_once(&app,&queue).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?);
            let head=app.collection("private_renumber_heads").find_one(doc!{"_id":owner.to_hex()}).await?.unwrap();assert_eq!(head.get_i64("count")?,4097);
            let job=head.get_str("job")?;
            let planned:Vec<_>=app.collection("private_renumber_assignments").find(doc!{"job":job}).await?.try_collect().await?;
            assert_eq!(planned.len(),4097);let mut addresses=std::collections::HashSet::new();let mut ids=std::collections::HashSet::new();
            for row in planned{assert!(addresses.insert(row.get_str("new")?.to_owned()));assert!(ids.insert(row.get_str("peer")?.to_owned()));assert_ne!(row.get_str("new")?,row.get_str("old")?);}
            let targets=head.get_array("target_cidrs")?.iter().map(|p|crate::domain::enrollment::Network::parse(p.as_str().unwrap()).unwrap()).collect::<Vec<_>>();
            assert!(targets.iter().map(|p|p.capacity()as usize).sum::<usize>()>=4097);assert!(targets.iter().all(|p|!p.contains(report().source)));
            assert_eq!(app.collection("private_peers").count_documents(doc!{"workspace_id":owner}).await?,4097);
            println!("native_repair_scale identities=4097 planned=4097 pools={} assignment_work=one_pass no_peer_writes=true",targets.len());
            Ok::<_,anyhow::Error>(())
        }).catch_unwind().await;db.drop().await?;match result{Ok(value)=>value,Err(panic)=>std::panic::resume_unwind(panic)}
    }
    #[tokio::test]
    #[ignore="requires Root-owned isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
    async fn prepared_orphan_does_not_reserve_but_head_activation_survives_lost_ack()->anyhow::Result<()>{
        let client=mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;let db=client.database(&format!("porthub_native_repair_orphan_{}",uuid::Uuid::new_v4().simple()));
        let result=std::panic::AssertUnwindSafe(async{
            let app=App::new(crate::config::Config::default(),db.clone());let owner=ObjectId::new();let machine=ObjectId::new();let job="b".repeat(32);
            let row=Assignment{peer:format!("{owner}:{machine}"),machine:machine.to_hex(),workspace:owner.to_hex(),credential_generation:"legacy".into(),old:report().source,new:"10.204.0.2".parse()?,previous_generation:0,generation:1};
            super::super::retirement::stage(&app,&job,&[row],None).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            assert!(super::super::retirement::occupied(&app).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?.0.is_empty());
            app.collection("private_renumber_heads").insert_one(doc!{"_id":owner.to_hex(),"job":&job,"generation":1_i64,"state":"applying"}).await?;
            let reopened=App::new(crate::config::Config::default(),db.clone());
            assert!(super::super::retirement::occupied(&reopened).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?.1.contains(&report().source));
            super::super::retirement::activate(&reopened,owner,&job).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            reopened.collection("private_renumber_heads").delete_one(doc!{"_id":owner.to_hex()}).await?;
            assert!(super::super::retirement::occupied(&reopened).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?.1.contains(&report().source));
            Ok::<_,anyhow::Error>(())
        }).catch_unwind().await;db.drop().await?;match result{Ok(value)=>value,Err(panic)=>std::panic::resume_unwind(panic)}
    }

}

#[cfg(test)]
mod generation_tests {
    use super::*;
    use futures_util::FutureExt;
    #[tokio::test]
    #[ignore="requires owned isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
    async fn actual_expansion_enrollments_missing_generation_repair_without_certifying_stale_or_migrated_rows()->anyhow::Result<()> {
        let client=mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;
        let db=client.database(&format!("porthub_repair_generation_{}",uuid::Uuid::new_v4().simple()));
        let result=std::panic::AssertUnwindSafe(async {
            let app=App::new(crate::config::Config::default(),db.clone());let owner=ObjectId::new();
            let original=super::tests::seed(&app,owner,"generation-fixture-credential-0123456789").await?;
            let initial=app.collection("private_networks").find_one(doc!{"_id":owner.to_hex()}).await?.unwrap();
            app.collection("private_renumber_heads").insert_one(doc!{"_id":owner.to_hex(),"generation":0_i64,"state":"stable"}).await?;
            assert_eq!(published_generation(&app,owner,&initial).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?,0);
            let mut bad_zero=initial.clone();bad_zero.insert("_address_generation",0_i64);assert!(published_generation(&app,owner,&bad_zero).await.is_err());
            let request=super::tests::report();record(&app,owner,&original[0],&request).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            let queued=app.collection("private_native_repairs").find_one(doc!{"_id":original[0].get("_id")}).await?.unwrap();
            assert!(plan_once(&app,&queued).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?);
            assert_eq!(super::super::recover::workspace(&app,owner).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?,super::super::recover::Outcome::Committed);
            let head=app.collection("private_renumber_heads").find_one(doc!{"_id":owner.to_hex()}).await?.unwrap();
            let mut prefs=app.collection("private_networks").find_one(doc!{"_id":owner.to_hex()}).await?.unwrap();
            // Legitimate expansion beyond the committed job's target is current
            // authoritative allocation state, not a stale original pool.
            let expansion="10.252.251.0/24";
            let mut pools=prefs.get_array("additional_cidrs").cloned().unwrap_or_default();pools.push(expansion.into());prefs.insert("additional_cidrs",pools);
            app.collection("private_networks").replace_one(doc!{"_id":owner.to_hex()},prefs.clone()).await?;
            assert_eq!(published_generation(&app,owner,&prefs).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?,1);
            let automatic_machine=doc!{"_id":ObjectId::new(),"user_id":owner,"name":"Automatic generation fixture"};
            app.collection("machines").insert_one(automatic_machine.clone()).await?;
            crate::domain::enrollment::ensure(&app,&automatic_machine).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            let automatic=app.collection("private_peers").find_one(doc!{"machine_id":automatic_machine.get("_id")}).await?.unwrap();
            assert_eq!(automatic.get_i64("address_generation")?,1);
            let mut fresh=Vec::new();
            for n in 1..=5 {let machine=ObjectId::new();app.collection("machines").insert_one(doc!{"_id":machine,"user_id":owner,"name":format!("Expansion {n}")}).await?;
                let row=doc!{"_id":format!("{owner}:{machine}"),"workspace_id":owner,"owner_id":owner,"machine_id":machine,"enabled":true,"credential_hash":"fresh-fixture-unchanged","enrollment_generation":"fresh-enrollment","ip":format!("10.252.251.{n}")};
                app.collection("private_peers").insert_one(row.clone()).await?;fresh.push(row);}
            let migrated=original.iter().map(|p|p.get_str("_id").unwrap().to_owned()).collect::<std::collections::HashSet<_>>();
            let retained=super::super::retirement::occupied(&app).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            let mut stale=fresh[0].clone();stale.insert("address_generation",0_i64);
            assert!(repair_missing_generation(&app,owner,&prefs,&stale,1,&migrated,&retained.0,&retained.1).await.is_err());
            let mut lost=app.collection("private_peers").find_one(doc!{"_id":original[0].get("_id")}).await?.unwrap();lost.remove("address_generation");
            assert!(repair_missing_generation(&app,owner,&prefs,&lost,1,&migrated,&retained.0,&retained.1).await.is_err());
            let mut corrupt_prefs=prefs.clone();corrupt_prefs.insert("_address_generation",2_i64);
            assert!(published_generation(&app,owner,&corrupt_prefs).await.is_err());
            let mut retired=fresh[0].clone();retired.insert("ip","10.203.0.2");
            assert!(repair_missing_generation(&app,owner,&prefs,&retired,1,&migrated,&retained.0,&retained.1).await.is_err());
            assert_eq!(ensure_assignment_generations(&app,owner,&prefs,&fresh[..1]).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?,1);
            let mut moved=app.collection("private_peers").find_one(doc!{"_id":original[0].get("_id")}).await?.unwrap();
            let source=moved.get_str("ip")?.parse()?;
            let blocked=crate::domain::private_networks::pools(&prefs).map_err(|e|anyhow::anyhow!("{}",e.detail))?.into_iter().filter(|p|p.contains(source)).map(|p|p.cidr().parse().unwrap()).collect();
            let next=Request{protocol:1,source,blocked,nonce:"b".repeat(32)};
            record(&app,owner,&moved,&next).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
            let queued=app.collection("private_native_repairs").find_one(doc!{"_id":moved.get("_id")}).await?.unwrap();
            assert!(plan_once(&app,&queued).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?);
            for mut row in fresh {let after=app.collection("private_peers").find_one(doc!{"_id":row.get("_id")}).await?.unwrap();row.insert("address_generation",1_i64);assert_eq!(after,row);}
            let next_head=app.collection("private_renumber_heads").find_one(doc!{"_id":owner.to_hex()}).await?.unwrap();assert_eq!(next_head.get_i64("generation")?,2);assert_eq!(next_head.get_i64("count")?,8);
            // No peer addresses, credential generations, names or rules were
            // changed by metadata repair; the ordinary worker owns migration.
            moved=app.collection("private_peers").find_one(doc!{"_id":moved.get("_id")}).await?.unwrap();assert_eq!(moved.get_str("ip")?.parse::<std::net::Ipv4Addr>()?,source);
            assert_eq!(head.get_i64("generation")?,1);
            Ok::<_,anyhow::Error>(())
        }).catch_unwind().await;
        db.drop().await?;match result{Ok(value)=>value,Err(panic)=>std::panic::resume_unwind(panic)}
    }
}
