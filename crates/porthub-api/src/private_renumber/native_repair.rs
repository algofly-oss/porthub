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
    let blocked=request.get_array("blocked").map_err(|_|invalid("Missing native repair scope"))?;
    if blocked.is_empty()||blocked.len()>porthub_network::capture_routes::MAX_CAPTURE_PREFIXES||blocked.iter().any(|b|!pools.iter().any(|p|Some(p.cidr().as_str())==b.as_str())){return Ok(true);}
    let rows:Vec<_>=app.collection("private_peers").find(doc!{"workspace_id":owner}).projection(doc!{"_id":1,"machine_id":1,"workspace_id":1,"enrollment_generation":1,"address_generation":1,"ip":1}).sort(doc!{"_id":1}).limit(65537).batch_size(256).await?.try_collect().await?;
    if rows.is_empty()||rows.len()>65536{return Err(invalid("Native repair workspace exceeds migration budget"));}
    let targets=crate::domain::private_networks::migration_targets_locked(app,&owner.to_hex(),rows.len(),blocked).await?;
    let mut slots=targets.iter().flat_map(|pool|(0..pool.capacity()).map(move|offset|pool.migration_address(offset).expect("bounded planned pool")));
    let mut assignments=Vec::with_capacity(rows.len());
    for row in rows{
        let peer=row.get_str("_id").map_err(|_|invalid("Invalid migration peer"))?.to_owned();
        let machine=crate::store::id(row.get("machine_id"));
        if row.get_i64("address_generation").unwrap_or(0)!=generation{return Err(invalid("Native repair peer generation changed"));}
        let old=row.get_str("ip").map_err(|_|invalid("Missing migration address"))?.parse().map_err(|_|invalid("Invalid migration address"))?;
        let new=slots.next().ok_or_else(||invalid("Native repair target capacity changed"))?;
        assignments.push(Assignment{peer,machine,workspace:owner.to_hex(),credential_generation:row.get_str("enrollment_generation").unwrap_or("legacy").into(),old,new,previous_generation:generation as u64,generation:generation as u64+1});
    }
    let job=uuid::Uuid::new_v4().simple().to_string();
    journal::prepare(&guard,&job,&assignments,&targets.iter().map(|p|p.cidr()).collect::<Vec<_>>()).await?;
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
    async fn seed(app:&App,owner:ObjectId,token:&str)->anyhow::Result<Vec<Document>>{
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
    fn report()->Request{Request{protocol:1,nonce:"a".repeat(32),source:"10.203.0.2".parse().unwrap(),blocked:vec!["10.203.0.0/24".parse().unwrap()]}}
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
