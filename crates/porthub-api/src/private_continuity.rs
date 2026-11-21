//! An optional stability witness. Ordinary private-network admission never
//! depends on this facility. All writers using a database must participate.
use crate::{
    error::{ApiError, ApiResult},
    App,
};
use axum::http::StatusCode;
use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId, DateTime, Document},
    options::{Acknowledgment, CollectionOptions, ReadPreference, SelectionCriteria, WriteConcern},
    Collection,
};
use std::{future::Future, sync::LazyLock};
use uuid::Uuid;

static PROCESS: LazyLock<String> = LazyLock::new(|| Uuid::new_v4().to_string());
const GLOBAL: &str = "cross-workspace-v1";
const FLEET: &str = "fleet-activation-v1";
/// Operates on the current deployment's durable activation epoch. It never
/// clears outstanding writers or changes an ACL, machine, route or enrollment.
pub async fn fleet_command(app: &App, action: &str) -> anyhow::Result<serde_json::Value> {
    let c = collection(app);
    let mode = if app.config.private_continuity_fenced_writers {
        "all-v1"
    } else if app.config.fences_private_writes() {
        "staged-v1"
    } else {
        "off"
    };
    match action {
        "status" => {}
        "enable" | "disable" => {
            anyhow::ensure!(
                action != "enable" || mode == "all-v1",
                "enable requires all-v1 writer attestation"
            );
            c.update_one(doc!{"_id":FLEET},doc!{"$set":{"enabled":action=="enable","generation":Uuid::new_v4().to_string(),"updated_at":DateTime::now()}})
                .upsert(true).await?;
        }
        _ => anyhow::bail!("Expected status, enable, or disable"),
    }
    let row = c.find_one(doc! {"_id":FLEET}).await?;
    let generation = row
        .as_ref()
        .and_then(|r| r.get_str("generation").ok())
        .and_then(|s| s.parse::<Uuid>().ok());
    let enabled = generation.is_some() && row.is_some_and(|r| r.get_bool("enabled") == Ok(true));
    Ok(
        serde_json::json!({"process_mode":mode,"fleet_enabled":enabled,"generation":generation,
        "issues_witnesses":mode=="all-v1" && enabled}),
    )
}
pub(super) fn process() -> &'static str {
    PROCESS.as_str()
}
pub(super) fn app_name(process: &str) -> String {
    format!("porthub-policy-{process}")
}
pub(super) fn collection(app: &App) -> Collection<Document> {
    app.db.collection_with_options(
        "private_policy_write_fences",
        CollectionOptions::builder()
            .selection_criteria(SelectionCriteria::ReadPreference(ReadPreference::Primary))
            .write_concern(
                WriteConcern::builder()
                    .w(Acknowledgment::Majority)
                    .journal(true)
                    .build(),
            )
            .build(),
    )
}
fn stable(row: &Document) -> Option<Uuid> {
    if !row.get_document("writers").ok()?.is_empty() {
        return None;
    }
    row.get_str("generation").ok()?.parse().ok()
}
/// Empty historical scopes have no changes. The application never deletes fence
/// documents. A cross-workspace writer (e.g. machine or account deletion) also
/// changes every affected workspace's observed generation.
pub(crate) async fn before(app: &App, workspace: ObjectId) -> Option<Uuid> {
    if !app.config.private_continuity_fenced_writers {
        return None;
    }
    if let Some((old, _)) = app
        .policy_witness_cache
        .lock()
        .ok()?
        .get(&workspace)
        .copied()
    {
        return Some(old);
    }
    witness(app, workspace).await
}
pub(crate) async fn witness(app: &App, workspace: ObjectId) -> Option<Uuid> {
    if !app.config.private_continuity_fenced_writers {
        return None;
    }
    let value = tokio::time::timeout(std::time::Duration::from_millis(200), read(app, workspace))
        .await
        .ok()
        .flatten();
    if let Ok(mut cache) = app.policy_witness_cache.lock() {
        match value {
            Some(generation) => {
                if cache.len() >= 4096 && !cache.contains_key(&workspace) {
                    cache.retain(|_, (_, t)| t.elapsed() < std::time::Duration::from_secs(60));
                }
                if cache.len() < 4096 || cache.contains_key(&workspace) {
                    cache.insert(workspace, (generation, std::time::Instant::now()));
                }
            }
            None => {
                cache.remove(&workspace);
            }
        }
    }
    value
}
async fn read(app: &App, workspace: ObjectId) -> Option<Uuid> {
    let key = workspace.to_hex();
    let mut rows = collection(app)
        .find(doc! {"_id":{"$in":[FLEET,GLOBAL,&key]}})
        .limit(3)
        .await
        .ok()?;
    let mut combined = 0u128;
    let mut fleet = None;
    while let Some(row) = rows.try_next().await.ok()? {
        if row.get_str("_id").ok()? == FLEET {
            if row.get_bool("enabled").ok()? != true {
                return None;
            }
            fleet = Some(row.get_str("generation").ok()?.parse::<Uuid>().ok()?);
            continue;
        }
        if let Some(stable) = stable(&row) {
            combined ^= stable.as_u128();
        } else {
            if let Some(writer) = &app.policy_writer {
                writer.recover(app, &row).await;
            }
            return None;
        }
    }
    Some(Uuid::from_u128(combined ^ fleet?.as_u128()))
}
/// Publish dirtiness before dispatch. Only the owner of this exact write can
/// clear it. Concurrent requests cannot accidentally clear each other's markers.
pub(crate) async fn write<T>(
    app: &App,
    scope: Option<ObjectId>,
    operation: impl Future<Output = ApiResult<T>>,
) -> ApiResult<T> {
    if !app.config.fences_private_writes() {
        return operation.await;
    }
    let key = scope.map(|w| w.to_hex()).unwrap_or_else(|| GLOBAL.into());
    let id = Uuid::new_v4().simple().to_string();
    let ticket = format!("writers.{id}");
    let c = collection(app);
    const MAX_WRITERS: i32 = 128;
    // MongoDB disallows $expr on an upsert. Create the empty historical
    // scope separately; every actual write is gated by the second operation.
    c.update_one(
        doc! {"_id":&key},
        doc! {"$setOnInsert":{"writers":Document::new(),"generation":Uuid::new_v4().to_string()}},
    )
    .upsert(true)
    .await?;
    let begins=c.update_one(doc!{"_id":&key,"$expr":{"$lt":[{"$size":{"$objectToArray":"$writers"}},MAX_WRITERS]}},
        doc!{"$set":{&ticket:{"process":PROCESS.as_str(),"tagged":app.policy_writer.is_some(),"owner":app.policy_writer.as_ref().map(|w|w.identity()),"started_at":DateTime::now()},"generation":Uuid::new_v4().to_string()}}).await?;
    if begins.matched_count != 1 {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Private policy write capacity is busy; retry",
        ));
    }
    let result = operation.await;
    if result.as_ref().is_err_and(|e| e.storage_uncertain) {
        return result;
    }
    let finished = c
        .update_one(
            doc! {"_id":&key,format!("{ticket}.process"):PROCESS.as_str()},
            doc! {"$unset":{&ticket:""},"$set":{"generation":Uuid::new_v4().to_string()}},
        )
        .await?;
    if finished.matched_count != 1 {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Private policy writer ownership changed",
        ));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, private_continuity_recovery::Writer};
    use std::sync::Arc;

    async fn app(uri: &str, name: &str) -> anyhow::Result<App> {
        let mut options = mongodb::options::ClientOptions::parse(uri).await?;
        options.app_name = Some(app_name(process()));
        let db = mongodb::Client::with_options(options)?.database(name);
        Ok(App::new(
            Config {
                private_continuity_fenced_writers: true,
                ..Default::default()
            },
            db,
        ))
    }
    #[tokio::test]
    #[ignore = "requires a disposable standalone MongoDB"]
    async fn multiple_writers_denial_regrant_and_abandoned_writer_drain() -> anyhow::Result<()> {
        use anyhow::{ensure, Context};
        let uri = std::env::var("PORTHUB_TEST_MONGO_URI")?;
        let name = format!("tcp_fence_{}", Uuid::new_v4().simple());
        let mut reader = app(&uri, &name).await?;
        let writer = Arc::new(app(&uri, &name).await?);
        let host = ObjectId::new();
        let other = ObjectId::new();
        let directory = tempfile::TempDir::new()?;
        reader.policy_writer = Writer::start(directory.path().into(), process());
        ensure!(reader.policy_writer.is_some());
        ensure!(witness(&reader, host).await.is_none());
        ensure!(fleet_command(&reader, "status").await?["fleet_enabled"] == false);
        let mut staged = app(&uri, &name).await?;
        staged.config.private_continuity_fenced_writers = false;
        staged.config.private_continuity_fence_only = true;
        ensure!(fleet_command(&staged, "enable").await.is_err());
        ensure!(write(&staged, Some(host), async { Ok(()) }).await.is_ok());
        ensure!(witness(&staged, host).await.is_none());
        ensure!(fleet_command(&reader, "enable").await?["issues_witnesses"] == true);
        let first = witness(&reader, host).await.context("first activation")?;
        ensure!(fleet_command(&staged, "disable").await?["fleet_enabled"] == false);
        ensure!(witness(&reader, host).await.is_none());
        ensure!(fleet_command(&reader, "enable").await?["issues_witnesses"] == true);
        let original = witness(&reader, host)
            .await
            .context("reactivation witness")?;
        ensure!(original != first);
        let other_before = witness(&reader, other).await.context("other workspace")?;
        let opened = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let active = tokio::spawn({
            let s = writer.clone();
            let o = opened.clone();
            let r = release.clone();
            async move {
                write(&s, Some(host), async {
                    o.notify_one();
                    r.notified().await;
                    Ok(())
                })
                .await
                .is_ok()
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), opened.notified())
            .await
            .context("writer did not enter the protected operation")?;
        // The earlier cached observation cannot by itself certify a grant.
        ensure!(before(&reader, host).await == Some(original));
        ensure!(witness(&reader, host).await.is_none());
        ensure!(witness(&reader, other).await == Some(other_before));
        ensure!(write(&writer, Some(host), async { Ok(()) }).await.is_ok());
        ensure!(witness(&reader, host).await.is_none());
        release.notify_one();
        ensure!(active.await?);
        let after = witness(&reader, host).await.context("finished writes")?;
        ensure!(after != original);
        ensure!(write(&writer, Some(host), async {
            Err::<(), _>(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "unrelated downstream",
            ))
        })
        .await
        .is_err());
        ensure!(witness(&reader, host).await.is_some());
        let crashed = Uuid::new_v4().to_string();
        let old = Writer::start(directory.path().into(), &crashed).context("old process lock")?;
        let mut opts = mongodb::options::ClientOptions::parse(&uri).await?;
        opts.app_name = Some(app_name(&crashed));
        let dangling = mongodb::Client::with_options(opts)?;
        dangling
            .database(&name)
            .run_command(doc! {"ping":1})
            .await?;
        let ticket = Uuid::new_v4().simple().to_string();
        let field = format!("writers.{ticket}");
        collection(&reader)
            .update_one(
                doc! {"_id":host.to_hex()},
                doc! {"$set":{&field:{"process":&crashed,"tagged":true,"owner":old.identity()}}},
            )
            .await?;
        let row = collection(&reader)
            .find_one(doc! {"_id":host.to_hex()})
            .await?
            .unwrap();
        reader
            .policy_writer
            .as_ref()
            .unwrap()
            .recover(&reader, &row)
            .await;
        ensure!(collection(&reader)
            .find_one(doc! {"_id":host.to_hex(),&field:{"$exists":true}})
            .await?
            .is_some());
        drop(old);
        reader.policy_writer.as_ref().unwrap().reset_throttle();
        reader
            .policy_writer
            .as_ref()
            .unwrap()
            .recover(&reader, &row)
            .await;
        ensure!(
            collection(&reader)
                .find_one(doc! {"_id":host.to_hex(),&field:{"$exists":true}})
                .await?
                .is_some(),
            "active database connection was not drained"
        );
        dangling.shutdown().await;
        for _ in 0..20 {
            reader.policy_writer.as_ref().unwrap().reset_throttle();
            reader
                .policy_writer
                .as_ref()
                .unwrap()
                .recover(&reader, &row)
                .await;
            if witness(&reader, host).await.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        ensure!(
            witness(&reader, host).await.is_some(),
            "abandoned writer did not recover"
        );
        reader.db.drop().await?;
        Ok(())
    }
}
