//! Owner-scoped host utilization, with bounded seven-day minute history.
use crate::{
    auth,
    domain::machine_client,
    error::{ApiError, ApiResult},
    App,
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{self, doc, oid::ObjectId, DateTime, Document},
    options::IndexOptions,
    IndexModel,
};
use porthub_components::metrics::Sample;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
const RETENTION: i64 = 7 * 24 * 60 * 60 * 1000;
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/machines/client/metrics", post(report))
        .route("/api/machines/metrics", get(fleet))
        .route("/api/machines/metrics/{id}", get(history))
        .layer(DefaultBodyLimit::max(16384))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    machine_id: String,
    token: String,
    sample: Sample,
}
async fn report(State(app): State<Arc<App>>, Json(body): Json<Report>) -> ApiResult<Json<Value>> {
    if !body.sample.valid() {
        return Err(ApiError::bad_request("Invalid machine metrics"));
    }
    let machine = machine_client::authenticate(&app, &body.machine_id, &body.token).await?;
    if machine.get_bool("enabled") == Ok(false) {
        return Err(ApiError::bad_request("Machine disabled"));
    }
    let owner = machine
        .get_object_id("user_id")
        .map_err(|_| ApiError::unauthenticated())?;
    let id = machine
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())?;
    app.machine_metrics_initialized
        .get_or_try_init(|| async {
            app.collection("machine_metrics_history")
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"expires_at":1})
                        .options(IndexOptions::builder().expire_after(Duration::ZERO).build())
                        .build(),
                )
                .await?;
            app.collection("machine_metrics_history")
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"machine_id":1,"at":1})
                        .build(),
                )
                .await?;
            Ok::<_, ApiError>(())
        })
        .await?;
    let now = DateTime::now();
    let minute = now.timestamp_millis() / 60000;
    let sample =
        bson::to_document(&body.sample).map_err(|_| ApiError::bad_request("Invalid metrics"))?;
    let current = doc! {"machine_id":id,"owner_id":owner,"at":now,"sample":sample};
    app.collection("machine_metrics_latest")
        .update_one(doc! {"_id":id}, doc! {"$set":&current})
        .upsert(true)
        .await?;
    let mut retained = current;
    retained.insert(
        "expires_at",
        DateTime::from_millis(now.timestamp_millis() + RETENTION),
    );
    app.collection("machine_metrics_history")
        .update_one(
            doc! {"_id":format!("{}:{minute}",id.to_hex())},
            doc! {"$setOnInsert":retained},
        )
        .upsert(true)
        .await?;
    Ok(Json(json!({"ok":true})))
}
fn output(row: &Document) -> Value {
    json!({"at":row.get_datetime("at").ok().map(|at|at.timestamp_millis()),"sample":row.get_document("sample").ok().and_then(|d|bson::from_document::<Sample>(d.clone()).ok())})
}
async fn fleet(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let user = auth::current_user(&app, &headers).await?;
    let owner = user
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())?;
    let machines: Vec<Document> = app
        .collection("machines")
        .find(doc! {"user_id":owner,"deletion_pending":{"$ne":true}})
        .projection(doc! {"_id":1,"name":1,"enabled":1})
        .limit(1000)
        .await?
        .try_collect()
        .await?;
    let ids: Vec<ObjectId> = machines
        .iter()
        .filter_map(|m| m.get_object_id("_id").ok())
        .collect();
    let readings: Vec<Document> = app
        .collection("machine_metrics_latest")
        .find(doc! {"_id":{"$in":ids},"owner_id":owner})
        .limit(1000)
        .await?
        .try_collect()
        .await?;
    let rows:Vec<Value>=machines.iter().filter_map(|m|{let id=m.get_object_id("_id").ok()?;let r=readings.iter().find(|r|r.get_object_id("_id")==Ok(id));let enabled=m.get_bool("enabled")!=Ok(false);Some(json!({"id":id.to_hex(),"name":m.get_str("name").unwrap_or("Machine"),"enabled":enabled,"live":enabled&&r.and_then(|r|r.get_datetime("at").ok()).is_some_and(|at|DateTime::now().timestamp_millis()-at.timestamp_millis()<45000),"reading":r.map(output)}))}).collect();
    Ok(Json(
        json!({"machines":rows,"limit":1000,"retention_days":7}),
    ))
}
#[derive(Deserialize)]
struct Range {
    #[serde(default = "default_hours")]
    hours: u32,
}
fn default_hours() -> u32 {
    24
}
async fn history(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(range): Query<Range>,
) -> ApiResult<Json<Value>> {
    let user = auth::current_user(&app, &headers).await?;
    let owner = user
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())?;
    let id = ObjectId::parse_str(id).map_err(|_| ApiError::bad_request("Invalid machine"))?;
    if app
        .collection("machines")
        .find_one(doc! {"_id":id,"user_id":owner,"deletion_pending":{"$ne":true}})
        .await?
        .is_none()
    {
        return Err(ApiError::bad_request("Machine unavailable"));
    }
    let hours = range.hours.clamp(1, 168);
    let since =
        DateTime::from_millis(DateTime::now().timestamp_millis() - i64::from(hours) * 3600000);
    // Read at most 10,080 minute points, return <=720 buckets with averages.
    let rows: Vec<Document> = app
        .collection("machine_metrics_history")
        .find(doc! {"machine_id":id,"owner_id":owner,"at":{"$gte":since}})
        .sort(doc! {"at":1})
        .limit(10080)
        .await?
        .try_collect()
        .await?;
    let latest = app
        .collection("machine_metrics_latest")
        .find_one(doc! {"_id":id,"owner_id":owner})
        .await?;
    let interval_ms = ((i64::from(hours) * 60 + 719) / 720).max(1) * 60000;
    let mut buckets = std::collections::BTreeMap::<i64, Vec<&Document>>::new();
    for row in &rows {
        if let Ok(at) = row.get_datetime("at") {
            buckets
                .entry(at.timestamp_millis() / interval_ms)
                .or_default()
                .push(row);
        }
    }
    let history: Vec<_> = buckets
        .iter()
        .map(|(bucket,chunk)| {
            let mut value = output(chunk[chunk.len() - 1]);
            value["at"] = json!(bucket * interval_ms);
            let samples: Vec<Sample> = chunk
                .iter()
                .filter_map(|r| bson::from_document(r.get_document("sample").ok()?.clone()).ok())
                .collect();
            if !samples.is_empty() {
                let n = samples.len() as f64;
                value["sample"]["cpu"] =
                    json!(samples.iter().map(|s| f64::from(s.cpu)).sum::<f64>() / n);
                for key in ["ram", "disk"] {
                    let memories: Vec<_> = samples
                        .iter()
                        .map(|s| if key == "ram" { &s.ram } else { &s.disk })
                        .collect();
                    value["sample"][key]["used"] =
                        json!((memories.iter().map(|m| m.used as f64).sum::<f64>() / n) as u64);
                    value["sample"][key]["total"] =
                        json!((memories.iter().map(|m| m.total as f64).sum::<f64>() / n) as u64);
                }
                let mut gpu_groups = std::collections::BTreeMap::<String, Vec<&porthub_components::metrics::Gpu>>::new();
                let mut disk_groups = std::collections::BTreeMap::<String, Vec<&porthub_components::metrics::Disk>>::new();
                for sample in &samples {
                    for (index,gpu) in sample.gpus.iter().enumerate() {
                        let id = gpu.id.clone().unwrap_or_else(|| format!("{}:{index}",gpu.name));
                        gpu_groups.entry(id).or_default().push(gpu);
                    }
                    for disk in &sample.disks { disk_groups.entry(disk.id.clone()).or_default().push(disk); }
                }
                let average = |values: Vec<f32>| if values.is_empty() { Value::Null } else { json!(values.iter().map(|v| f64::from(*v)).sum::<f64>() / values.len() as f64) };
                value["sample"]["gpus"] = json!(gpu_groups.values().map(|readings| {
                    let mut gpu = serde_json::to_value(readings[readings.len()-1]).unwrap();
                    gpu["utilization"] = average(readings.iter().filter_map(|g|g.utilization).collect());
                    gpu["temperature"] = average(readings.iter().filter_map(|g|g.temperature).collect());
                    gpu["fan_speed"] = average(readings.iter().filter_map(|g|g.fan_speed).collect());
                    let memory: Vec<_> = readings.iter().filter_map(|g|g.memory.as_ref()).collect();
                    if !memory.is_empty() { gpu["memory"] = json!({"used":(memory.iter().map(|m|m.used as f64).sum::<f64>()/memory.len() as f64) as u64,"total":(memory.iter().map(|m|m.total as f64).sum::<f64>()/memory.len() as f64) as u64}); }
                    gpu
                }).collect::<Vec<_>>());
                value["sample"]["disks"] = json!(disk_groups.values().map(|readings| {
                    let last = readings[readings.len()-1];
                    json!({"id":last.id,"name":last.name,"used":(readings.iter().map(|d|d.used as f64).sum::<f64>()/readings.len() as f64) as u64,"total":(readings.iter().map(|d|d.total as f64).sum::<f64>()/readings.len() as f64) as u64})
                }).collect::<Vec<_>>());
            }
            value
        })
        .collect();
    Ok(Json(
        json!({"latest":latest.as_ref().map(output),"history":history,"hours":hours,"retention_days":7,"interval_ms":interval_ms}),
    ))
}
