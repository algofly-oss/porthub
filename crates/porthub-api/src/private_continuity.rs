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
pub(crate) async fn witness(app: &App, workspace: ObjectId) -> Option<Uuid> {
    if !app.config.private_continuity_fenced_writers {
        return None;
    }
    let key = workspace.to_hex();
    let mut rows = collection(app)
        .find(doc! {"_id":{"$in":[GLOBAL,&key]}})
        .limit(2)
        .await
        .ok()?;
    let mut combined = 0u128;
    while let Some(row) = rows.try_next().await.ok()? {
        if let Some(stable) = stable(&row) {
            combined ^= stable.as_u128();
        } else {
            if let Some(writer) = &app.policy_writer {
                writer.recover(app, &row).await;
            }
            return None;
        }
    }
    Some(Uuid::from_u128(combined))
}
/// Publish dirtiness before dispatch. Only the owner of this exact write can
/// clear it. Concurrent requests cannot accidentally clear each other's markers.
pub(crate) async fn write<T>(
    app: &App,
    scope: Option<ObjectId>,
    operation: impl Future<Output = ApiResult<T>>,
) -> ApiResult<T> {
    if !app.config.private_continuity_fenced_writers {
        return operation.await;
    }
    let key = scope.map(|w| w.to_hex()).unwrap_or_else(|| GLOBAL.into());
    let id = Uuid::new_v4().simple().to_string();
    let ticket = format!("writers.{id}");
    let c = collection(app);
    const MAX_WRITERS: i32 = 128;
    let begins=c.update_one(doc!{"_id":&key,"$expr":{"$lt":[{"$size":{"$objectToArray":{"$ifNull":["$writers",Document::new()]}}},MAX_WRITERS]}},
        doc!{"$set":{&ticket:{"process":PROCESS.as_str(),"tagged":app.policy_writer.is_some(),"owner":app.policy_writer.as_ref().map(|w|w.identity()),"started_at":DateTime::now()},"generation":Uuid::new_v4().to_string()}}).upsert(true).await;
    if let Err(error) = begins {
        if crate::store::duplicate(&error) {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Private policy write capacity is busy; retry",
            ));
        }
        return Err(error.into());
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
