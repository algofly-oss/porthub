use anyhow::{ensure, Context, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document};
use porthub_api::{config::Config, machine_delete};
use serde_json::{json, Value};
use std::time::Duration;
mod support;
use support::Case;

fn journal(phase: &str, next: DateTime) -> Document {
    doc! {"id":uuid::Uuid::new_v4().to_string(),"phase":phase,"requested_at":DateTime::from_millis(1700000000000),"next_attempt_at":next,"attempts":0}
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn configured_edge_without_snapshot_path_cannot_authorize_deletion() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let case = Case::new(Config {
        edge_socket: Some(temporary.path().join("edge.sock")),
        ..Default::default()
    })
    .await?;
    let result = async {
        let (owner, cookie) = case.user("missing-snapshot@test.invalid", "user").await?;
        let id = ObjectId::new();
        let original =
            doc! {"_id":id,"user_id":owner,"name":"Luna","token":"secret","enabled":true};
        case.app
            .collection("machines")
            .insert_one(&original)
            .await?;
        case.status(
            "POST",
            "/api/machines/delete",
            &cookie,
            json!({"data_id":id.to_hex()}),
            StatusCode::SERVICE_UNAVAILABLE,
        )
        .await?;
        ensure!(record(&case, id).await? == original);
        Ok(())
    }
    .await;
    case.db.drop().await?;
    result
}
async fn record(case: &Case, id: ObjectId) -> Result<Document> {
    case.app
        .collection("machines")
        .find_one(doc! {"_id":id})
        .await?
        .context("machine record")
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn deletion_preserves_owner_contract_tombstone_and_authenticated_ack() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("gateway.toml");
    let case = Case::new(Config {
        gateway_config_path: Some(path.clone()),
        ..Default::default()
    })
    .await?;
    let result=async {
        let (owner,cookie)=case.user("delete-owner@test.invalid","user").await?;
        let (other,other_cookie)=case.user("delete-other@test.invalid","user").await?;
        let machine=ObjectId::new();let foreign=ObjectId::new();
        let original=doc! {"_id":machine,"user_id":owner,"name":"Luna","enabled":true,"token":"owned-secret","log_tokens":["older"],
            "client_setup_public_base_url":"https://old.invalid","client_setup_rathole_server_address":"old.invalid:443",
            "client_setup_service_domain":"old.invalid","auth_required":true,"last_seen_at":DateTime::now()};
        case.app.collection("machines").insert_many([original.clone(),doc! {"_id":foreign,"user_id":other,"name":"Other","enabled":true,"token":"other-secret"}]).await?;
        let foreign_connection=doc! {"_id":ObjectId::new(),"user_id":other,"machine_id":foreign,"external_port":39121,"internal_port":22,"enabled":true};
        case.app.collection("connections").insert_many([
            doc! {"_id":ObjectId::new(),"machine_id":machine,"user_id":owner,"external_port":39119,"internal_port":8080,"enabled":true},
            doc! {"_id":ObjectId::new(),"machine_id":machine,"user_id":owner,"external_port":39120,"internal_port":8081,"enabled":false},foreign_connection.clone()]).await?;
        let body=json!({"data_id":machine.to_hex()});
        for credential in ["",other_cookie.as_str()] {
            case.status("POST","/api/machines/delete",credential,body.clone(),StatusCode::BAD_REQUEST).await?;
        }
        ensure!(record(&case,machine).await?==original);
        case.status("POST","/api/machines/delete",&cookie,json!({}),StatusCode::UNPROCESSABLE_ENTITY).await?;
        case.status("POST","/api/machines/delete",&cookie,json!({"data_id":"bad"}),StatusCode::BAD_REQUEST).await?;
        let deleted=case.status("POST","/api/machines/delete",&cookie,body.clone(),StatusCode::OK).await?;
        ensure!(deleted["msg"]=="Machine deleted successfully");
        // Legacy callers receive the pre-deletion view, not the new tombstone.
        ensure!(deleted["data"]["enabled"]==true && deleted["data"]["token"]=="owned-secret");
        let stored=record(&case,machine).await?;
        ensure!(stored.get_bool("deletion_pending")? && !stored.get_bool("enabled")? && !stored.get_bool("auth_required")?);
        ensure!(stored.get("last_seen_at")==Some(&Bson::Null) && stored.contains_key("deleted_at"));
        for key in ["native_deletion","log_tokens","client_setup_public_base_url","client_setup_rathole_server_address","client_setup_service_domain"] {
            ensure!(!stored.contains_key(key));
        }
        ensure!(case.app.collection("connections").count_documents(doc! {"machine_id":machine}).await?==0);
        ensure!(case.app.collection("connections").find_one(doc! {"_id":foreign_connection.get("_id")}).await?.unwrap()==foreign_connection);
        ensure!(std::fs::read_to_string(&path)?.contains("39121") && !std::fs::read_to_string(&path)?.contains("39119"));
        let list=case.status("GET","/api/machines/list",&cookie,Value::Null,StatusCode::OK).await?;
        ensure!(list["data"]==json!([]));
        let (status,headers,_)=case.call("POST","/api/machines/client/sync","",json!({"machine_id":machine.to_hex(),"token":"owned-secret"}),&[]).await?;
        ensure!(status==StatusCode::GONE && headers["x-porthub-machine-deleted"]=="true");
        case.status("POST","/api/machines/delete",&cookie,body,StatusCode::OK).await?;
        let wrong=case.status("POST","/api/machines/client/deletion-ack","",json!({"machine_id":machine.to_hex(),"token":"wrong"}),StatusCode::OK).await?;
        ensure!(wrong["data"]["removed"]==false && record(&case,machine).await?.get_bool("deletion_pending")?);
        let ack=case.status("POST","/api/machines/client/deletion-ack","",json!({"machine_id":machine.to_hex(),"token":"owned-secret"}),StatusCode::OK).await?;
        ensure!(ack["data"]["removed"]==true && case.app.collection("machines").find_one(doc! {"_id":machine}).await?.is_none());
        ensure!(record(&case,foreign).await?.get_str("token")?=="other-secret");
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn failed_closing_rolls_back_without_uninstall_and_disconnected_requests_finish() -> Result<()>
{
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("gateway.toml");
    std::fs::create_dir(&path)?;
    let case = Case::new(Config {
        gateway_config_path: Some(path.clone()),
        ..Default::default()
    })
    .await?;
    let result=async {
        let (owner,cookie)=case.user("closing-owner@test.invalid","user").await?;
        let machine=ObjectId::new();
        let original=doc! {"_id":machine,"user_id":owner,"name":"Luna","token":"secret","enabled":true,"log_tokens":["prior"]};
        case.app.collection("machines").insert_one(&original).await?;
        let connection=doc! {"_id":ObjectId::new(),"machine_id":machine,"external_port":39119,"internal_port":8080,"enabled":true};
        case.app.collection("connections").insert_one(&connection).await?;
        let publication=case.app.gateway_config_lock.lock().await;
        let deletion=case.call("POST","/api/machines/delete",&cookie,json!({"data_id":machine.to_hex()}),&[]);
        tokio::pin!(deletion);
        ensure!(tokio::time::timeout(Duration::from_millis(100),deletion.as_mut()).await.is_err());
        let staged=record(&case,machine).await?;
        ensure!(staged.get_document("native_deletion")?.get_str("phase")?=="closing" && !staged.get_bool("enabled")?);
        let (status,headers,_)=case.call("POST","/api/machines/client/sync","",json!({"machine_id":machine.to_hex(),"token":"secret"}),&[]).await?;
        ensure!(status==StatusCode::FORBIDDEN && !headers.contains_key("x-porthub-machine-deleted"));
        drop(publication);
        ensure!(deletion.await?.0==StatusCode::INTERNAL_SERVER_ERROR);
        ensure!(record(&case,machine).await?==original);
        ensure!(case.app.collection("connections").find_one(doc! {"_id":connection.get("_id")}).await?.unwrap()==connection);
        // Dropping the HTTP caller must not abandon an authorized deletion.
        std::fs::remove_dir(&path)?;std::fs::write(&path,"[server.services]\n")?;
        let publication=case.app.gateway_config_lock.lock().await;
        let mut disconnected=Box::pin(case.call("POST","/api/machines/delete",&cookie,json!({"data_id":machine.to_hex()}),&[]));
        ensure!(tokio::time::timeout(Duration::from_millis(100),disconnected.as_mut()).await.is_err());
        ensure!(record(&case,machine).await?.contains_key("native_deletion"));
        drop(disconnected);drop(publication);
        tokio::time::timeout(Duration::from_secs(2),async {
            loop {
                let current=record(&case,machine).await?;
                if current.get_bool("deletion_pending")==Ok(true) && !current.contains_key("native_deletion") {break;}
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<(),anyhow::Error>(())
        }).await??;
        ensure!(case.app.collection("connections").count_documents(doc! {"machine_id":machine}).await?==0);
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn journal_recovery_handles_early_ack_and_notified_future_jobs() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("gateway.toml");
    let case = Case::new(Config {
        gateway_config_path: Some(path),
        ..Default::default()
    })
    .await?;
    let mut worker = None;
    let result=async {
        let (owner,cookie)=case.user("recovery-owner@test.invalid","user").await?;
        let ids=[ObjectId::new(),ObjectId::new(),ObjectId::new()];
        let future=DateTime::from_millis(DateTime::now().timestamp_millis()+60_000);
        let due=DateTime::from_millis(0);
        case.app.collection("machines").insert_many([
            doc! {"_id":ids[0],"user_id":owner,"name":"Closing","token":"closing","enabled":false,"native_deletion":journal("closing",due)},
            doc! {"_id":ids[1],"user_id":owner,"name":"Committing","token":"committing","enabled":false,"deletion_pending":true,"native_deletion":journal("committing",due)},
            doc! {"_id":ids[2],"user_id":owner,"name":"Waiting","token":"waiting","enabled":false,"native_deletion":journal("closing",future)},
        ]).await?;
        case.app.collection("connections").insert_many(ids.iter().enumerate().map(|(i,id)|doc! {"_id":ObjectId::new(),"machine_id":id,
            "external_port":39119+i as i32,"internal_port":8080,"enabled":true})).await?;
        machine_delete::initialize(&case.app).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        let busy=case.app.connection_lock.lock().await;
        let ack=tokio::time::timeout(Duration::from_secs(1),case.status("POST","/api/machines/client/deletion-ack","",json!({"machine_id":ids[1].to_hex(),"token":"committing"}),StatusCode::OK)).await??;
        drop(busy);
        ensure!(ack["data"]["removed"]==false && record(&case,ids[1]).await?.get_document("native_deletion")?.get_bool("acknowledged")?);
        case.status("PUT","/api/machines/update",&cookie,json!({"data_id":ids[0].to_hex(),"name":"Resurrect","enabled":true}),StatusCode::CONFLICT).await?;
        case.status("POST","/api/machines/refresh-token",&cookie,json!({"data_id":ids[0].to_hex()}),StatusCode::CONFLICT).await?;
        let waiting=record(&case,ids[2]).await?;
        let next=machine_delete::recover_due(&case.app).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        ensure!(next==Some(future));
        ensure!(record(&case,ids[0]).await?.get_bool("deletion_pending")?);
        ensure!(case.app.collection("machines").find_one(doc! {"_id":ids[1]}).await?.is_none());
        ensure!(case.app.collection("connections").count_documents(doc! {"machine_id":{"$in":[ids[0],ids[1]]}}).await?==0);
        ensure!(record(&case,ids[2]).await?==waiting);
        let (stop,stopping)=tokio::sync::watch::channel(false);
        worker=Some((stop,tokio::spawn(machine_delete::run(case.app.clone(),stopping))));
        // Move a queued job forward and notify the single sleeping worker.
        case.app.collection("machines").update_one(doc! {"_id":ids[2]},doc! {"$set":{"native_deletion.next_attempt_at":due}}).await?;
        case.app.deletion_changes.notify_one();
        tokio::time::timeout(Duration::from_secs(2),async {
            loop {
                let current=record(&case,ids[2]).await?;
                if !current.contains_key("native_deletion") {ensure!(current.get_bool("deletion_pending")?);break;}
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<(),anyhow::Error>(())
        }).await??;
        Ok(())
    }.await;
    if let Some((stop, mut task)) = worker {
        let _ = stop.send(true);
        if tokio::time::timeout(Duration::from_secs(2), &mut task)
            .await
            .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn failed_recovery_schedules_bounded_retry_and_preserves_journal() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("gateway.toml");
    std::fs::create_dir(&path)?;
    let case = Case::new(Config {
        gateway_config_path: Some(path.clone()),
        ..Default::default()
    })
    .await?;
    let result=async {
        let id=ObjectId::new();let job=journal("closing",DateTime::from_millis(0));
        case.app.collection("machines").insert_one(doc! {"_id":id,"name":"Retry","enabled":false,"token":"retry","native_deletion":&job}).await?;
        let next=machine_delete::recover_due(&case.app).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?.context("retry time")?;
        let current=record(&case,id).await?;
        let retry=current.get_document("native_deletion")?;
        ensure!(retry.get("id")==job.get("id") && retry.get_str("phase")?=="closing" && retry.get_i32("attempts")?==1);
        ensure!(next.timestamp_millis()>DateTime::now().timestamp_millis());
        ensure!(!current.contains_key("deletion_pending"));
        std::fs::remove_dir(&path)?;std::fs::write(&path,"[server.services]\n")?;
        case.app.collection("machines").update_one(doc! {"_id":id},doc! {"$set":{"native_deletion.next_attempt_at":DateTime::from_millis(0)}}).await?;
        ensure!(machine_delete::recover_due(&case.app).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?.is_none());
        ensure!(record(&case,id).await?.get_bool("deletion_pending")?);
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn acknowledgements_racing_finalization_do_not_leave_acknowledged_tombstones() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("gateway.toml");
    let case = Case::new(Config {
        gateway_config_path: Some(path),
        ..Default::default()
    })
    .await?;
    let result=async {
        let ids:Vec<ObjectId>=(0..20).map(|_|ObjectId::new()).collect();
        case.app.collection("machines").insert_many(ids.iter().map(|id|doc! {"_id":id,"name":"Retiring","enabled":false,
            "token":"owned-secret","deletion_pending":true,"native_deletion":journal("committing",DateTime::from_millis(0))})).await?;
        let recovery=async {
                machine_delete::recover_due(&case.app).await.map_err(|e|anyhow::anyhow!("{}",e.detail))
        };
        let acknowledgements=futures_util::future::join_all(ids.iter().enumerate().map(|(i,id)| {
            let case=&case;
            async move {
                tokio::time::sleep(Duration::from_millis((i as u64)*3)).await;
                case.status("POST","/api/machines/client/deletion-ack","",json!({"machine_id":id.to_hex(),"token":"owned-secret"}),StatusCode::OK).await
            }
        }));
        let (recovered,acknowledged)=tokio::time::timeout(Duration::from_secs(5),async {tokio::join!(recovery,acknowledgements)}).await?;
        recovered?;for ack in acknowledged {ack?;}
        ensure!(case.app.collection("machines").count_documents(doc! {"_id":{"$in":&ids}}).await?==0);
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}
