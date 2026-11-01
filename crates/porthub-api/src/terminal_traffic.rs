//! Machine-authenticated terminal measurements. Baselines and bounded rollups
//! change atomically in one document, including on standalone MongoDB servers.
use crate::{
    domain::machine_client,
    error::{ApiError, ApiResult},
    input::ApiBody,
    App,
};
use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{self, doc, Bson, DateTime, Document},
    options::{IndexOptions, ReturnDocument},
    IndexModel,
};
use porthub_terminal::traffic_report::Summary;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};

pub const COLLECTION: &str = "terminal_traffic";
const FIELDS: [&str; 6] = [
    "pty_input",
    "pty_output",
    "udp_sent",
    "udp_received",
    "relay_sent",
    "relay_received",
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upload {
    machine_id: String,
    token: String,
    summary: Summary,
}

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/machines/client/terminal-traffic", post(upload))
        .route("/api/terminal/traffic", get(series))
        .layer(DefaultBodyLimit::max(8192))
}
async fn indexes(app: &App) -> ApiResult<()> {
    app.terminal_traffic_initialized
        .get_or_try_init(|| async {
            app.collection(COLLECTION)
                .create_indexes([
                    IndexModel::builder()
                        .keys(doc! {"expires_at":1})
                        .options(IndexOptions::builder().expire_after(Duration::ZERO).build())
                        .build(),
                    IndexModel::builder()
                        .keys(doc! {"owner_id":1,"machine_id":1})
                        .build(),
                ])
                .await?;
            Ok::<_, ApiError>(())
        })
        .await?;
    Ok(())
}
async fn upload(State(app): State<Arc<App>>, ApiBody(body): ApiBody) -> ApiResult<Json<Value>> {
    // Do not echo deserialization errors: they can contain supplied credentials.
    let upload: Upload = serde_json::from_value(body)
        .map_err(|_| ApiError::bad_request("Invalid terminal traffic report"))?;
    if !upload.summary.valid() || upload.token.is_empty() || upload.token.len() > 1024 {
        return Err(ApiError::bad_request("Invalid terminal traffic report"));
    }
    let _lifecycle = app.account_lifecycle.read().await;
    let _connections = app.connection_lock.lock().await;
    let machine = machine_client::authenticate(&app, &upload.machine_id, &upload.token).await?;
    let owner = machine
        .get_object_id("user_id")
        .map_err(|_| ApiError::bad_request("Machine has no account owner"))?;
    let machine_id = machine
        .get_object_id("_id")
        .map_err(|_| ApiError::bad_request("Invalid machine"))?;
    indexes(&app).await?;
    let summary = upload.summary;
    let key = format!(
        "{}:{}:{}",
        owner.to_hex(),
        machine_id.to_hex(),
        summary.instance
    );
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let report = bson::to_document(&summary)
        .map_err(|_| ApiError::bad_request("Invalid terminal traffic report"))?;
    let now = DateTime::now();
    let pipeline = update_pipeline(
        owner.into(),
        machine_id.into(),
        report,
        &summary,
        now,
        &nonce,
    );
    let collection = app.collection(COLLECTION);
    // Seed only the immutable identity. Concurrent first uploads share _id;
    // duplicate-key races are harmless and followed by the same atomic update.
    if let Err(error) = collection.update_one(doc! {"_id":&key}, doc! {"$setOnInsert":{"owner_id":owner,"machine_id":machine_id,"expires_at":DateTime::from_millis(now.timestamp_millis()+30*86400*1000)}}).upsert(true).await {
        if !crate::store::duplicate(&error) { return Err(error.into()); }
    }
    let saved = collection
        .find_one_and_update(doc! {"_id":&key}, pipeline)
        .return_document(ReturnDocument::After)
        .projection(doc! {"summary":1,"accepted_nonce":1})
        .await?
        .ok_or_else(|| ApiError::bad_request("Terminal traffic state expired; retry report"))?;
    let previous: Summary = bson::from_document(
        saved
            .get_document("summary")
            .map_err(|_| ApiError::bad_request("Invalid terminal traffic state"))?
            .clone(),
    )
    .map_err(|_| ApiError::bad_request("Invalid terminal traffic state"))?;
    let accepted = saved.get_str("accepted_nonce") == Ok(nonce.as_str());
    if !accepted && summary.revision >= previous.revision && summary != previous {
        return Err(ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "Terminal traffic revision conflicts with stored counters",
        ));
    }
    Ok(Json(
        json!({"accepted":accepted,"revision":previous.revision}),
    ))
}

fn update_pipeline(
    owner: Bson,
    machine: Bson,
    report: Document,
    summary: &Summary,
    now: DateTime,
    nonce: &str,
) -> Vec<Document> {
    let old_paths = [
        "$summary.counters.input_bytes",
        "$summary.counters.output_bytes",
        "$summary.counters.direct_udp_sent_bytes",
        "$summary.counters.direct_udp_received_bytes",
        "$summary.relay_sent_payload_bytes",
        "$summary.relay_received_payload_bytes",
    ];
    let values = summary.values();
    let mut conditions = vec![
        Bson::Document(doc! {"$gt":[summary.revision as i64,{"$ifNull":["$summary.revision",-1]}]}),
        Bson::Document(
            doc! {"$gte":[summary.reported_sessions as i64,{"$ifNull":["$summary.reported_sessions",0]}]},
        ),
    ];
    for (path, value) in old_paths.iter().zip(values) {
        conditions.push(doc! {"$gte":[value as i64,{"$ifNull":[*path,0]}]}.into());
    }
    let mut replacement = doc! {
        "_id":"$_id", "owner_id":{"$literal":owner}, "machine_id":{"$literal":machine},
        "summary":{"$literal":report}, "accepted_nonce":{"$literal":nonce},
        "received_at":{"$literal":now},
        "expires_at":{"$literal":DateTime::from_millis(now.timestamp_millis()+30*86400*1000)},
    };
    // Server receipt time assigns buckets; client clocks cannot inject history.
    for (name, seconds, count) in [
        ("recent", 5_i64, 120_i64),
        ("minutes", 60, 1440),
        ("hours", 3600, 168),
        ("days", 86400, 30),
    ] {
        let at = now.timestamp_millis().div_euclid(seconds * 1000) * seconds * 1000;
        let source = format!("${name}");
        let mut fresh = doc! {"at":at};
        let mut changed = doc! {"at":"$$row.at"};
        for ((field, path), value) in FIELDS.iter().zip(old_paths).zip(values) {
            let delta = doc! {"$subtract":[value as i64,{"$ifNull":[path,value as i64]}]};
            fresh.insert(*field, delta.clone());
            changed.insert(*field, doc! {"$add":[format!("$$row.{field}"),delta]});
        }
        replacement.insert(name, doc! {"$let":{
            "vars":{"rows":{"$filter":{"input":{"$ifNull":[source,[]]},"as":"row","cond":{"$gte":["$$row.at",at-(count-1)*seconds*1000]}}}},
            "in":{"$slice":[{"$cond":[{"$in":[at,{"$map":{"input":"$$rows","as":"row","in":"$$row.at"}}]},
                {"$map":{"input":"$$rows","as":"row","in":{"$cond":[{"$eq":["$$row.at",at]},changed,"$$row"]}}},
                {"$concatArrays":["$$rows",[fresh]]}]},-count]}
        }});
    }
    vec![doc! {"$replaceWith":{"$cond":[{"$and":conditions},replacement,"$$ROOT"]}}]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    #[serde(default = "default_range")]
    range: String,
    machine_id: Option<String>,
}
fn default_range() -> String {
    "1h".into()
}
async fn series(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<Selection>,
) -> ApiResult<Json<Value>> {
    let _lifecycle = app.account_lifecycle.read().await;
    let user = crate::auth::current_user(&app, &headers).await?;
    let owner = user
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())?;
    let (array, range_seconds, step_seconds) = match query.range.as_str() {
        "10m" => ("recent", 600_i64, 5_i64),
        "1h" => ("minutes", 3600, 60),
        "24h" => ("minutes", 86400, 900),
        "7d" => ("hours", 7 * 86400, 7200),
        "30d" => ("days", 30 * 86400, 86400),
        _ => return Err(ApiError::bad_request("Invalid terminal traffic range")),
    };
    let now = DateTime::now();
    let end = now.timestamp_millis().div_euclid(step_seconds * 1000) * step_seconds * 1000;
    let start = end - range_seconds * 1000 + step_seconds * 1000;
    let mut filter = doc! {"owner_id":owner,"expires_at":{"$gt":now}};
    if let Some(machine) = &query.machine_id {
        filter.insert(
            "machine_id",
            crate::domain::workspaces::object_id(machine, "Invalid machine id")?,
        );
    }
    let mut group = doc! {"_id":{"$subtract":["$rows.at",{"$mod":["$rows.at",step_seconds*1000]}]}};
    let mut project = doc! {"_id":0,"at":"$_id"};
    for field in FIELDS {
        group.insert(field, doc! {"$sum":format!("$rows.{field}")});
        project.insert(field, 1);
    }
    // Re-check current ownership in the DB. Admin status never broadens this
    // account view, and deleted/transferred machines cannot leak old records.
    let pipeline = vec![
        doc! {"$match":filter},
        doc! {"$lookup":{"from":"machines","let":{"machine":"$machine_id"},"pipeline":[
        {"$match":{"$expr":{"$and":[{"$eq":["$_id","$$machine"]},{"$eq":["$user_id",owner]}]},"deletion_pending":{"$ne":true},"native_deletion":{"$exists":false}}},
        {"$project":{"_id":1}}],"as":"owned"}},
        doc! {"$match":{"owned.0":{"$exists":true}}},
        doc! {"$project":{"rows":format!("${array}")}},
        doc! {"$unwind":"$rows"},
        doc! {"$match":{"rows.at":{"$gte":start,"$lt":end+step_seconds*1000}}},
        doc! {"$group":group},
        doc! {"$sort":{"_id":1}},
        doc! {"$limit":120},
        doc! {"$project":project},
    ];
    let points: Vec<Document> = app
        .collection(COLLECTION)
        .aggregate(pipeline)
        .await?
        .try_collect()
        .await?;
    Ok(Json(
        json!({"range":query.range,"start":start,"end":end,"interval_seconds":step_seconds,
        "points":points.iter().map(|row| crate::store::json(&Bson::Document(row.clone()))).collect::<Vec<_>>(),
        "scope":"terminal_host_measurements","baseline":"first snapshot per service instance establishes a baseline",
        "pty_scope":"attachment payload including redraws; not unique application bytes",
        "udp_scope":"observed direct RTC datagrams including protocol overhead; excludes discovery probes",
        "relay_scope":"decoded terminal payload relayed through the gateway; excludes control frames"}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires isolated MongoDB"]
    async fn atomic_rollups_preserve_baselines_across_midnight_and_expire_old_buckets(
    ) -> anyhow::Result<()> {
        let client =
            mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;
        let db = client.database(&format!(
            "porthub_rust_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let result = exercise(&db).await;
        db.drop().await?;
        result
    }
    async fn exercise(db: &mongodb::Database) -> anyhow::Result<()> {
        let collection = db.collection::<Document>(COLLECTION);
        let owner = mongodb::bson::oid::ObjectId::new();
        let machine = mongodb::bson::oid::ObjectId::new();
        collection.insert_one(doc! {"_id":"fixture"}).await?;
        let mut summary = Summary {
            instance: "a".repeat(32),
            revision: 1,
            ..Default::default()
        };
        summary.counters.input_bytes = 100;
        let before_midnight = 86_400_000_i64 * 100 - 5_000;
        for (revision, input, timestamp) in [
            (1, 100, before_midnight),
            (2, 110, before_midnight + 10_000),
            (3, 120, before_midnight + 31 * 86_400_000),
        ] {
            summary.revision = revision;
            summary.counters.input_bytes = input;
            let pipeline = update_pipeline(
                owner.into(),
                machine.into(),
                bson::to_document(&summary)?,
                &summary,
                DateTime::from_millis(timestamp),
                "fixture-nonce",
            );
            collection
                .update_one(doc! {"_id":"fixture"}, pipeline)
                .await?;
            let saved = collection.find_one(doc! {"_id":"fixture"}).await?.unwrap();
            let expected = if revision == 1 { 0 } else { 10 };
            let days = saved.get_array("days")?;
            assert_eq!(
                days.last()
                    .unwrap()
                    .as_document()
                    .unwrap()
                    .get_i64("pty_input")?,
                expected
            );
            if revision == 3 {
                for name in ["recent", "minutes", "hours", "days"] {
                    assert_eq!(
                        saved.get_array(name)?.len(),
                        1,
                        "expired {name} buckets were retained"
                    );
                }
            }
        }
        // A regressing report must leave the complete document untouched.
        let before = collection.find_one(doc! {"_id":"fixture"}).await?.unwrap();
        summary.revision = 4;
        summary.counters.input_bytes = 119;
        collection
            .update_one(
                doc! {"_id":"fixture"},
                update_pipeline(
                    owner.into(),
                    machine.into(),
                    bson::to_document(&summary)?,
                    &summary,
                    DateTime::now(),
                    "rejected",
                ),
            )
            .await?;
        assert_eq!(
            collection.find_one(doc! {"_id":"fixture"}).await?.unwrap(),
            before
        );
        for offset in 1..=125_i64 {
            summary.revision = 4 + offset as u64;
            summary.counters.input_bytes = 120 + offset as u64;
            let timestamp = before_midnight + 31 * 86_400_000 + offset * 5_000;
            collection
                .update_one(
                    doc! {"_id":"fixture"},
                    update_pipeline(
                        owner.into(),
                        machine.into(),
                        bson::to_document(&summary)?,
                        &summary,
                        DateTime::from_millis(timestamp),
                        "bounded",
                    ),
                )
                .await?;
        }
        let saved = collection.find_one(doc! {"_id":"fixture"}).await?.unwrap();
        let recent = saved.get_array("recent")?;
        assert_eq!(recent.len(), 120);
        assert_eq!(
            recent
                .iter()
                .map(|row| row.as_document().unwrap().get_i64("pty_input").unwrap())
                .sum::<i64>(),
            120
        );
        Ok(())
    }
}
