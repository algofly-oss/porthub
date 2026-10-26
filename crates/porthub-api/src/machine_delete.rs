//! Durable machine retirement. Closing remains reversible; committing is an
//! accepted deletion and is completed after a crash or early client ACK.
use crate::{
    domain::{inventory, machines},
    error::{ApiError, ApiResult},
    firewall, generated, store, App,
};
use axum::http::StatusCode;
use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId, Bson, DateTime, Document},
    options::IndexOptions,
    IndexModel,
};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

pub async fn initialize(app: &App) -> ApiResult<()> {
    app.collection("machines")
        .create_index(
            IndexModel::builder()
                .keys(doc! {"native_deletion.next_attempt_at":1,"_id":1})
                .options(
                    IndexOptions::builder()
                        .name("porthub_native_deletion_queue".to_owned())
                        .partial_filter_expression(doc! {"native_deletion":{"$exists":true}})
                        .build(),
                )
                .build(),
        )
        .await?;
    app.collection("users").create_index(
        IndexModel::builder().keys(doc! {"account_deletion.next_attempt_at":1})
            .options(IndexOptions::builder().name("porthub_account_deletion_queue".to_owned())
                .partial_filter_expression(doc! {"account_deletion":{"$exists":true}}).build()).build()
    ).await?;
    Ok(())
}

/// Caller holds connection_lock, shared with mapping mutations and client ACK.
pub(crate) async fn delete(app: &App, owner: &Bson, id: ObjectId) -> ApiResult<Value> {
    let previous = app
        .collection("machines")
        .find_one(doc! {"_id":id,"user_id":owner})
        .await?
        .ok_or_else(|| ApiError::bad_request("Machine not found"))?;
    let response =
        json!({"msg":"Machine deleted successfully","data":inventory::machine(app,&previous)});
    if previous.contains_key("native_deletion") {
        resume(app, &previous).await?;
        return Ok(response);
    }
    if previous.get_bool("deletion_pending") == Ok(true) {
        return Ok(response);
    }
    let now = DateTime::now();
    let job = doc! {"id":uuid::Uuid::new_v4().to_string(),"phase":"closing","requested_at":now,
    "next_attempt_at":now,"attempts":0};
    let set = doc! {"enabled":false,"native_deletion":&job,"updated_at":now};
    app.collection("machines")
        .update_one(doc! {"_id":id,"user_id":owner}, doc! {"$set":&set})
        .await?;
    let mut staged = previous.clone();
    staged.extend(set.clone());
    if let Err(error) = resume(app, &staged).await {
        app.deletion_changes.notify_one();
        let current = app
            .collection("machines")
            .find_one(doc! {"_id":id,"native_deletion.id":job.get("id")})
            .await?;
        // Never roll back an accepted committing phase: a client may already
        // have received 410 and stopped its installed agent.
        if current
            .as_ref()
            .and_then(|m| m.get_document("native_deletion").ok())
            .and_then(|job| job.get_str("phase").ok())
            == Some("closing")
        {
            app.collection("machines")
                .update_one(
                    doc! {"_id":id,"native_deletion.id":job.get("id")},
                    machines::recovery(&previous, &set, &Document::new()),
                )
                .await?;
            // Some policies may already be removed. Restore restrictions before
            // publishing the previous enabled snapshot.
            let recovery = async {
                firewall::sync_machine(app, id).await?;
                generated::rebuild(app).await
            }
            .await;
            if let Err(recovery) = recovery {
                tracing::error!(detail=%recovery.detail,"machine deletion rollback needs reconciliation");
                app.firewall_changes.notify_one();
            }
        }
        return Err(error);
    }
    Ok(response)
}

/// Resume a journaled deletion with connection_lock held. The phase transition
/// precedes destructive database cleanup, making retries idempotent.
pub(crate) async fn resume(app: &App, machine: &Document) -> ApiResult<()> {
    let id = machine
        .get_object_id("_id")
        .map_err(|_| ApiError::bad_request("Invalid machine id"))?;
    let job = machine
        .get_document("native_deletion")
        .map_err(|_| invalid_job())?;
    let key = job.get_str("id").map_err(|_| invalid_job())?;
    let requested = job
        .get_datetime("requested_at")
        .map_err(|_| invalid_job())?;
    let filter = doc! {"_id":id,"native_deletion.id":key};
    match job.get_str("phase").map_err(|_| invalid_job())? {
        "closing" => {
            // enabled=false yields a reversible 403, never a premature 410.
            generated::rebuild(app).await?;
            let connections: Vec<Document> = app
                .collection("connections")
                .find(doc! {"machine_id":id})
                .await?
                .try_collect()
                .await?;
            firewall::remove_many(app, &connections).await?;
            app.collection("machines").update_one(filter.clone(),doc! {
                "$set":{"native_deletion.phase":"committing","deletion_pending":true,"deleted_at":requested,
                    "enabled":false,"auth_required":false,"last_seen_at":Bson::Null,"updated_at":requested},
                "$unset":{"log_tokens":"","client_setup_public_base_url":"","client_setup_rathole_server_address":"","client_setup_service_domain":""}
            }).await?;
            app.realtime.disconnect_machine(&id.to_hex());
            app.config_signals.changed(&id.to_hex());
        }
        "committing" => {}
        _ => return Err(invalid_job()),
    }
    // Re-apply on recovery too. The edge may have restarted since the journal
    // was committed; restrictions are not removed based on an old receipt.
    if job.get_str("phase") == Ok("committing") {
        generated::rebuild(app).await?;
        let connections: Vec<Document> = app
            .collection("connections")
            .find(doc! {"machine_id":id})
            .await?
            .try_collect()
            .await?;
        firewall::remove_many(app, &connections).await?;
    }
    app.collection("connections")
        .delete_many(doc! {"machine_id":id})
        .await?;
    // ACK can be recorded without connection_lock. Retire the journal only
    // while unacknowledged; if ACK races that compare-and-set, remove the
    // acknowledged record instead. Failed physical deletion retains the job.
    let mut acknowledged = filter.clone();
    acknowledged.insert("native_deletion.acknowledged", true);
    if app
        .collection("machines")
        .delete_one(acknowledged.clone())
        .await?
        .deleted_count
        == 0
    {
        let mut unacknowledged = filter;
        unacknowledged.insert("native_deletion.acknowledged", doc! {"$ne":true});
        let retired = app
            .collection("machines")
            .update_one(unacknowledged, doc! {"$unset":{"native_deletion":""}})
            .await?;
        if retired.matched_count == 0 {
            app.collection("machines").delete_one(acknowledged).await?;
        }
    }
    app.realtime.disconnect_machine(&id.to_hex());
    app.config_signals.changed(&id.to_hex());
    Ok(())
}

fn invalid_job() -> ApiError {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Invalid machine deletion journal",
    )
}

/// Returns the next scheduled attempt. No pending work means no timer or scan.
pub async fn recover_due(app: &App) -> ApiResult<Option<DateTime>> {
    let due: Vec<Document> = app
        .collection("machines")
        .find(doc! {"native_deletion.next_attempt_at":{"$lte":DateTime::now()}})
        .sort(doc! {"native_deletion.next_attempt_at":1,"_id":1})
        .limit(25)
        .await?
        .try_collect()
        .await?;
    for candidate in due {
        // Revalidate after acquiring the lock, and release it between jobs so
        // a recovery batch cannot monopolize unrelated browser mutations.
        let _guard = app.connection_lock.lock().await;
        let key = candidate
            .get_document("native_deletion")
            .map_err(|_| invalid_job())?
            .get("id");
        let Some(machine) = app
            .collection("machines")
            .find_one(doc! {"_id":candidate.get("_id"),
            "native_deletion.id":key,"native_deletion.next_attempt_at":{"$lte":DateTime::now()}})
            .await?
        else {
            continue;
        };
        if let Err(error) = resume(app, &machine).await {
            let job = machine
                .get_document("native_deletion")
                .map_err(|_| invalid_job())?;
            let attempts = job
                .get_i32("attempts")
                .unwrap_or(0)
                .saturating_add(1)
                .max(1);
            let delay = (1i64 << (attempts - 1).min(5)).min(30);
            app.collection("machines").update_one(doc! {"_id":machine.get("_id"),"native_deletion.id":job.get("id")},
                doc! {"$set":{"native_deletion.attempts":attempts,"native_deletion.next_attempt_at":DateTime::from_millis(DateTime::now().timestamp_millis()+delay*1000)}}).await?;
            tracing::warn!(machine=%store::id(machine.get("_id")),detail=%error.detail,"machine deletion recovery will retry");
        }
    }
    let next = app
        .collection("machines")
        .find_one(doc! {"native_deletion":{"$exists":true}})
        .sort(doc! {"native_deletion.next_attempt_at":1,"_id":1})
        .await?;
    next.map(|record| {
        record
            .get_document("native_deletion")
            .map_err(|_| invalid_job())?
            .get_datetime("next_attempt_at")
            .copied()
            .map_err(|_| invalid_job())
    })
    .transpose()
}

pub async fn run(app: Arc<App>, mut stop: watch::Receiver<bool>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        if *stop.borrow() {
            return;
        }
        let attempt = async {
            let machine = recover_due(&app).await?;
            let account = crate::account_delete::recover_due(&app).await?;
            Ok::<_, ApiError>(match (machine, account) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            })
        };
        let result = tokio::select! {result=attempt=>result,_=stop.changed()=>return};
        let wait = match result {
            Ok(next) => {
                backoff = Duration::from_secs(1);
                next.map(|next| {
                    Duration::from_millis(
                        next.timestamp_millis()
                            .saturating_sub(DateTime::now().timestamp_millis())
                            .max(0) as u64,
                    )
                })
            }
            Err(error) => {
                tracing::warn!(detail=%error.detail,"deletion queue will retry");
                let delay = backoff;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                Some(delay)
            }
        };
        match wait {
            Some(delay) => {
                tokio::select! {_=tokio::time::sleep(delay)=>{},_=app.deletion_changes.notified()=>{},_=stop.changed()=>return}
            }
            None => tokio::select! {_=app.deletion_changes.notified()=>{},_=stop.changed()=>return},
        }
    }
}
