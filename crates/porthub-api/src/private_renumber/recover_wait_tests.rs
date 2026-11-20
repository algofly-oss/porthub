//! Actual standalone-Mongo publication handoff with a real queued sync route.
use super::{fence,journal,recover,recovery::Assignment};
use crate::{App,domain::workspaces::token_digest};
use anyhow::{ensure,Context,Result};
use futures_util::FutureExt;
use mongodb::bson::{doc,oid::ObjectId};
use std::{sync::Arc,time::Duration};
use tower::ServiceExt;

#[tokio::test]
#[ignore="requires exclusively owned standalone Mongo via PORTHUB_TEST_MONGO_URI; actual16s drain"]
async fn queued_actual_sync_cannot_strand_completed_assignment_publication()->Result<()>{
    let client=mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;
    let db=client.database(&format!("porthub_handoff_{}",uuid::Uuid::new_v4().simple()));
    let app=Arc::new(App::new(crate::config::Config::default(),db.clone()));let mut tasks=tokio::task::JoinSet::new();
    let result=std::panic::AssertUnwindSafe(async{
        let owner=ObjectId::new();let token="queued-sync-fixture-0123456789abcdef0123456789";
        app.collection("users").insert_one(doc!{"_id":owner,"enabled":true}).await?;
        app.collection("private_networks").insert_one(doc!{"_id":owner.to_hex(),"cidr":"10.203.0.0/24","dns_suffix":"handoff.private"}).await?;
        let mut rows=Vec::new();for n in 0..2u8{
            let machine=ObjectId::new();let peer=format!("{owner}:{machine}");
            app.collection("machines").insert_one(doc!{"_id":machine,"user_id":owner,"name":format!("Owned handoff {n}")}).await?;
            let row=Assignment{peer:peer.clone(),machine:machine.to_hex(),workspace:owner.to_hex(),credential_generation:"handoff-v1".into(),old:std::net::Ipv4Addr::new(10,203,0,n+2),new:std::net::Ipv4Addr::new(10,204,0,n+2),previous_generation:0,generation:1};
            app.collection("private_peers").insert_one(doc!{"_id":&peer,"workspace_id":owner,"owner_id":owner,"machine_id":machine,"enabled":true,"credential_hash":token_digest(token),"enrollment_generation":"handoff-v1","ip":row.old.to_string()}).await?;rows.push(row);
        }
        let job=uuid::Uuid::new_v4().simple().to_string();let guard=fence::exclusive(&app,owner).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        journal::prepare(&guard,&job,&rows,&["10.204.0.0/24".into()],None).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;drop(guard);
        let (finished,completion)=tokio::sync::oneshot::channel();let recovery_app=app.clone();
        tasks.spawn(async move{let _=finished.send(recover::workspace(&recovery_app,owner).await);});
        tokio::time::timeout(Duration::from_secs(3),async{while !app.private_sparse.workspace_fences.held(&owner.to_hex()).await{tokio::task::yield_now().await;}}).await.context("actual migration did not acquire workspace")?;
        let request=serde_json::json!({"peer_id":rows[0].peer,"token":token,"fingerprint":vec!["AB";32].join(":"),"instance":"handoff-instance-00000000","sparse":{"protocol":1,"sequence":1,"wanted":[]}});
        let request=axum::http::Request::builder().method("POST").uri("/api/access/private/sync").header("Content-Type","application/json").body(axum::body::Body::from(serde_json::to_vec(&request)?))?;
        let (synced,sync_completion)=tokio::sync::oneshot::channel();let router=crate::routes::private_sync::router().with_state(app.clone());
        tasks.spawn(async move{let _=synced.send(router.oneshot(request).await);});
        tokio::time::timeout(Duration::from_secs(3),async{while !app.private_sparse.workspace_fences.waiting(&owner.to_hex()).await{tokio::task::yield_now().await;}}).await.context("real private sync did not queue behind migration")?;
        println!("actual_handoff queued_sync=true real_drain_seconds=16");
        let recovered=tokio::time::timeout(Duration::from_secs(25),completion).await.context("actual recovery completion deadline")??;
        let response=tokio::time::timeout(Duration::from_secs(5),sync_completion).await.context("actual queued sync completion deadline")???;
        let status=response.status();let body=axum::body::to_bytes(response.into_body(),4*1024*1024).await?;
        let head=app.collection("private_renumber_heads").find_one(doc!{"_id":owner.to_hex()}).await?.context("owned head missing")?;
        let prefs=app.collection("private_networks").find_one(doc!{"_id":owner.to_hex()}).await?.context("owned preferences missing")?;
        let busy=recovered.as_ref().err().is_some_and(|e|e.detail=="Private workspace is busy or migrating; retry later");
        println!("actual_handoff recover_ok={} recover_workspace_busy={} sync_status={} head_state={} applied={} count={} preferences_new={}",recovered.is_ok(),busy,status.as_u16(),head.get_str("state").unwrap_or("invalid"),head.get_i64("applied").unwrap_or(-1),head.get_i64("count").unwrap_or(-1),prefs.get_str("cidr").ok()==Some("10.204.0.0/24"));
        ensure!(matches!(recovered,Ok(recover::Outcome::Committed)),"queued real sync stranded apply-to-finish publication; workspace_busy={busy}");
        ensure!(status==axum::http::StatusCode::OK,"queued sync did not receive completed current authority");
        let value:serde_json::Value=serde_json::from_slice(&body)?;
        ensure!(value["snapshot"]["peers"].as_array().is_some_and(|peers|peers.iter().any(|peer|peer["id"].as_str()==Some(rows[0].peer.as_str())&&peer["ip"].as_str()==Some(rows[0].new.to_string().as_str()))),"queued sync leaked old assignment");
        ensure!(head.get_str("state")?=="stable"&&prefs.get_str("cidr")?=="10.204.0.0/24","recovery did not commit exact preferences/head");Ok::<(),anyhow::Error>(())
    }).catch_unwind().await;
    tasks.abort_all();while tasks.join_next().await.is_some(){}let cleanup=db.drop().await;cleanup?;
    println!("actual_handoff owned_tasks_reaped=true own_db_dropped=true");
    match result{Ok(result)=>result,Err(panic)=>std::panic::resume_unwind(panic)}
}
