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
const DRIVE_RETENTION: i64 = 90 * 24 * 60 * 60 * 1000;
const RETENTION: i64 = 7 * 24 * 60 * 60 * 1000;
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/machines/client/metrics", post(report))
        .route("/api/machines/metrics", get(fleet))
        .route("/api/machines/metrics/{id}", get(history))
        .route("/api/machines/metrics/{id}/drives", get(drive_history))
        .layer(DefaultBodyLimit::max(131072))
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
            app.collection("machine_drive_health_history")
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"expires_at":1})
                        .options(IndexOptions::builder().expire_after(Duration::ZERO).build())
                        .build(),
                )
                .await?;
            app.collection("machine_drive_health_history")
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"machine_id":1,"drive_id":1,"at":1})
                        .build(),
                )
                .await?;
            Ok::<_, ApiError>(())
        })
        .await?;
    let now = DateTime::now();
    let minute = now.timestamp_millis() / 60000;
    let (sample, gpu_memory_details, drive_details) = storage_sample(&body.sample)
        .map_err(|_| ApiError::bad_request("Invalid metrics"))?;
    let previous = app
        .collection("machine_metrics_latest")
        .find_one(doc! {"_id":id,"owner_id":owner})
        .projection(doc! {"sample.drive_health.id":1,"sample.drive_health.observed_at":1})
        .await?;
    let previous_drives = previous
        .as_ref()
        .and_then(|r| r.get_document("sample").ok())
        .and_then(|s| s.get_array("drive_health").ok());
    let current = doc! {"machine_id":id,"owner_id":owner,"at":now,"sample":sample,"gpu_memory_details":gpu_memory_details,"drive_details":drive_details};
    // SMART is sampled much less often than utilization. Keep one immutable
    // history point per drive observation/topology event, not every 15s upload.
    for drive in &body.sample.drive_health {
        if previous_drives.is_some_and(|rows| {
            rows.iter().filter_map(|r| r.as_document()).any(|r| {
                r.get_str("id") == Ok(drive.id.as_str())
                    && r.get_i64("observed_at") == Ok(drive.observed_at)
            })
        }) {
            continue;
        }
        let mut snapshot = bson::to_document(drive).map_err(|_| ApiError::bad_request("Invalid drive health"))?;
        let details = strip_drive_details(&mut snapshot);
        app.collection("machine_drive_health_history").update_one(
            doc!{"_id":format!("{}:{}:{}",id.to_hex(),drive.id,drive.observed_at)},
            doc!{"$setOnInsert":{"machine_id":id,"owner_id":owner,"drive_id":&drive.id,"at":now,"snapshot":snapshot,"details":details,
                "expires_at":DateTime::from_millis(now.timestamp_millis()+DRIVE_RETENTION)}}).upsert(true).await?;
    }
    // Advance the cache marker only after durable SMART history succeeds. A
    // partial database failure must leave identical observations retryable.
    app.collection("machine_metrics_latest")
        .update_one(doc! {"_id":id}, doc! {"$set":&current})
        .upsert(true)
        .await?;
    let mut retained = current;
    retained.remove("drive_details");
    if let Ok(sample) = retained.get_document_mut("sample") {
        sample.remove("drive_health");
    }
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
// Keep the strict legacy Sample in storage readable by rolling/rollback
// gateways. New GPU and drive details live beside it in the same atomic document.
fn storage_sample(sample: &Sample) -> Result<(Document, Vec<Document>, Vec<Document>), bson::ser::Error> {
    let mut document = bson::to_document(sample)?;
    let mut details = Vec::new();
    if let Ok(gpus) = document.get_array_mut("gpus") {
        for (index, gpu) in gpus.iter_mut().enumerate() {
            let Some(gpu) = gpu.as_document_mut() else { continue };
            let mut extra = Document::new();
            for key in ["shared_memory", "shared_memory_capacity", "integrated"] {
                if let Some(value) = gpu.remove(key) { extra.insert(key, value); }
            }
            if !extra.is_empty() {
                extra.insert("index", index as i64);
                extra.insert("name", gpu.get_str("name").unwrap_or_default());
                extra.insert("id", gpu.get("id").cloned().unwrap_or(bson::Bson::Null));
                details.push(extra);
            }
        }
    }
    let mut drives = Vec::new();
    if let Ok(readings) = document.get_array_mut("drive_health") {
        for drive in readings.iter_mut().filter_map(|v| v.as_document_mut()) {
            let mut extra = strip_drive_details(drive);
            if !extra.is_empty() {
                extra.insert("id", drive.get_str("id").unwrap_or_default());
                extra.insert("observed_at", drive.get("observed_at").cloned().unwrap_or(bson::Bson::Null));
                drives.push(extra);
            }
        }
    }
    Ok((document, details, drives))
}
const DRIVE_DETAIL_KEYS: [&str; 3] = ["reported_uncorrectable_errors", "lifetime_read_bytes", "lifetime_written_bytes"];
fn strip_drive_details(drive: &mut Document) -> Document {
    let mut extra = Document::new();
    for key in DRIVE_DETAIL_KEYS {
        if let Some(value) = drive.remove(key) { extra.insert(key, value); }
    }
    extra
}
fn drive_from_storage(snapshot: &Document, details: Option<&Document>) -> Option<porthub_components::metrics::DriveHealth> {
    let original: porthub_components::metrics::DriveHealth = bson::from_document(snapshot.clone()).ok()?;
    let mut merged = snapshot.clone();
    if let Some(details) = details {
        for key in DRIVE_DETAIL_KEYS { if let Some(value) = details.get(key) { merged.insert(key, value.clone()); } }
    }
    let value: porthub_components::metrics::DriveHealth = match bson::from_document(merged) { Ok(value) => value, Err(_) => return Some(original) };
    Some(if value.valid() { value } else { original })
}
fn sample_from_row(row: &Document) -> Option<Sample> {
    let original: Sample = bson::from_document(row.get_document("sample").ok()?.clone()).ok()?;
    let mut sample = original.clone();
    if let Ok(details) = row.get_array("gpu_memory_details") {
        for extra in details.iter().take(16).filter_map(|v| v.as_document()) {
            let Some(index) = extra.get_i64("index").ok().and_then(|v| usize::try_from(v).ok()) else { continue };
            let Some(gpu) = sample.gpus.get_mut(index) else { continue };
            if extra.get_str("name").ok() != Some(gpu.name.as_str()) { continue }
            let expected = gpu.id.as_ref().map(|id| bson::Bson::String(id.clone())).unwrap_or(bson::Bson::Null);
            if extra.get("id") != Some(&expected) { continue }
            let mut merged = bson::to_document(gpu).ok()?;
            for key in ["shared_memory", "shared_memory_capacity", "integrated"] {
                if let Some(value) = extra.get(key) { merged.insert(key, value.clone()); }
            }
            if let Ok(reading) = bson::from_document(merged) { *gpu = reading; }
        }
    }
    if let Ok(details) = row.get_array("drive_details") {
        for drive in &mut sample.drive_health {
            let extra = details.iter().filter_map(|v| v.as_document()).find(|d| d.get_str("id").ok() == Some(drive.id.as_str()) && d.get_i64("observed_at").ok() == Some(drive.observed_at));
            if let Ok(snapshot) = bson::to_document(&drive) {
                if let Some(restored) = drive_from_storage(&snapshot, extra) { *drive = restored; }
            }
        }
    }
    Some(if sample.valid() { sample } else { original })
}
fn output(row: &Document) -> Value {
    json!({"at":row.get_datetime("at").ok().map(|at|at.timestamp_millis()),"sample":sample_from_row(row)})
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
                .filter_map(|r| sample_from_row(r))
                .collect();
            if !samples.is_empty() {
                let n = samples.len() as f64;
                let cpus:Vec<_>=samples.iter().filter(|s|s.cpu_available).collect();
                value["sample"]["cpu_available"]=json!(!cpus.is_empty());
                value["sample"]["cpu"]=if cpus.is_empty(){json!(0)}else{json!(cpus.iter().map(|s|f64::from(s.cpu)).sum::<f64>()/cpus.len() as f64)};
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
                    let shared: Vec<_> = readings.iter().filter_map(|g|g.shared_memory.as_ref()).collect();
                    let capacity = readings.last().and_then(|g| g.shared_memory_capacity);
                    if !shared.is_empty() && shared.iter().all(|m| Some(m.total) == capacity) {
                        gpu["shared_memory"] = json!({"used":(shared.iter().map(|m|m.used as f64).sum::<f64>()/shared.len() as f64) as u64,"total":capacity});
                    }
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

#[derive(Deserialize)]
struct DriveRange {
    #[serde(default = "drive_days")]
    days: u32,
    drive: Option<String>,
}
fn drive_days() -> u32 {
    7
}
async fn drive_history(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(range): Query<DriveRange>,
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
    let days = range.days.clamp(1, 90);
    let since = DateTime::from_millis(
        DateTime::now().timestamp_millis() - i64::from(days) * 24 * 60 * 60 * 1000,
    );
    // 64 drives * 48 checks/day * 90 days can be large. Return <=96 evenly
    // spaced observations per drive, always retaining state changes and newest
    // observations within a bounded database scan and response.
    let mut filter = doc! {"machine_id":id,"owner_id":owner,"at":{"$gte":since}};
    if let Some(drive) = &range.drive {
        if drive.len() != 64 || !drive.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ApiError::bad_request("Invalid physical drive"));
        }
        filter.insert("drive_id", drive);
    }
    let limit = if range.drive.is_some() { 8192 } else { 32768 };
    let rows: Vec<Document> = app
        .collection("machine_drive_health_history")
        .find(filter)
        .sort(doc! {"at":-1})
        .limit(limit)
        .await?
        .try_collect()
        .await?;
    let mut groups = std::collections::BTreeMap::<String, Vec<Value>>::new();
    for row in &rows {
        if let (Ok(drive), Ok(at), Ok(snapshot)) = (
            row.get_str("drive_id"),
            row.get_datetime("at"),
            row.get_document("snapshot"),
        ) {
            if let Some(snapshot) =
                drive_from_storage(snapshot, row.get_document("details").ok())
            {
                groups
                    .entry(drive.into())
                    .or_default()
                    .push(json!({"at":at.timestamp_millis(),"snapshot":snapshot}));
            }
        }
    }
    let mut history = Vec::new();
    for readings in groups.values_mut() {
        readings.reverse();
        let step = (readings.len() + 95) / 96;
        for (index, point) in readings.iter().enumerate() {
            let changed = index > 0
                && (point["snapshot"]["status"] != readings[index - 1]["snapshot"]["status"]
                    || point["snapshot"]["present"] != readings[index - 1]["snapshot"]["present"]
                    || point["snapshot"]["self_test"]
                        != readings[index - 1]["snapshot"]["self_test"]);
            if index == 0 || index + 1 == readings.len() || index % step.max(1) == 0 || changed {
                history.push(point.clone());
            }
        }
    }
    history.sort_by_key(|point| point["at"].as_i64().unwrap_or_default());
    // State-change storms are bounded independently of regular sample buckets.
    if history.len() > 8192 {
        history.drain(..history.len() - 8192);
    }
    let latest = app
        .collection("machine_metrics_latest")
        .find_one(doc! {"_id":id,"owner_id":owner})
        .await?;
    let drives = latest
        .as_ref()
        .and_then(sample_from_row)
        .map(|sample| sample.drive_health)
        .unwrap_or_default();
    Ok(Json(
        json!({"drives":drives,"history":history,"days":days,"retention_days":90,"scan_interval_seconds":60,"smart_interval_minutes":30,"short_test_interval_days":7,"truncated":rows.len()>=limit as usize}),
    ))
}

#[cfg(test)]
mod gpu_storage_tests {
    use super::*;

    fn reading() -> Sample {
        serde_json::from_value(json!({
            "cpu":12.0,"cores":4,"ram":{"used":1024,"total":8192},
            "disk":{"used":512,"total":4096},
            "gpus":[{"name":"Intel Iris Xe","id":"luid-16019","utilization":2.0,
                "memory":{"used":0,"total":134217728},
                "shared_memory":{"used":248737792,"total":8447553536u64},
                "shared_memory_capacity":8447553536u64,"integrated":true}]
        })).unwrap()
    }

    #[test]
    fn drive_details_round_trip_without_breaking_strict_legacy_snapshots() {
        let drive = serde_json::json!({"id":"a".repeat(64),"name":"Toshiba","protocol":"ata","capacity":1000,"present":true,"status":"warning","observed_at":1000,"checked_at":1000,"temperature":31,"percentage_used":null,"available_spare":null,"spare_threshold":null,"power_on_hours":6790,"power_cycles":1933,"unsafe_shutdowns":null,"media_errors":null,"reallocated_sectors":0,"pending_sectors":0,"uncorrectable_sectors":null,"short_test_supported":false,"self_test":"not_run","last_test_started":null,"next_test_at":null,"reasons":[],"reported_uncorrectable_errors":2,"lifetime_read_bytes":22409203712000u64});
        let mut original = reading(); original.drive_health = vec![serde_json::from_value(drive).unwrap()];
        let (sample, gpu, details) = storage_sample(&original).unwrap();
        let stored = sample.get_array("drive_health").unwrap()[0].as_document().unwrap();
        for key in DRIVE_DETAIL_KEYS { assert!(!stored.contains_key(key)); }
        assert!(bson::from_document::<Sample>(sample.clone()).unwrap().valid());
        let restored = sample_from_row(&doc! {"sample":sample.clone(),"gpu_memory_details":gpu,"drive_details":details.clone()}).unwrap();
        assert_eq!(restored.drive_health[0].reported_uncorrectable_errors,Some(2));
        assert_eq!(restored.drive_health[0].lifetime_read_bytes,Some(22409203712000));
        assert_eq!(sample_from_row(&doc! {"sample":sample.clone()}).unwrap().drive_health[0].reported_uncorrectable_errors,None);
        let mut wrong = details; wrong[0].insert("observed_at",999i64);
        assert_eq!(sample_from_row(&doc! {"sample":sample,"drive_details":wrong}).unwrap().drive_health[0].reported_uncorrectable_errors,None);
        let mut snapshot = bson::to_document(&original.drive_health[0]).unwrap();
        let extra = strip_drive_details(&mut snapshot);
        assert_eq!(drive_from_storage(&snapshot,Some(&extra)).unwrap().reported_uncorrectable_errors,Some(2));
        let mut invalid = extra; invalid.insert("lifetime_read_bytes",-1i64);
        assert_eq!(drive_from_storage(&snapshot,Some(&invalid)).unwrap().reported_uncorrectable_errors,None);
    }
    #[test]
    fn shared_gpu_details_round_trip_without_polluting_legacy_storage() {
        let original = reading();
        assert!(original.valid());
        let (sample, details, _) = storage_sample(&original).unwrap();
        let legacy_gpu = sample.get_array("gpus").unwrap()[0].as_document().unwrap();
        for key in ["shared_memory", "shared_memory_capacity", "integrated"] {
            assert!(!legacy_gpu.contains_key(key));
        }
        let legacy: Sample = bson::from_document(sample.clone()).unwrap();
        assert!(legacy.valid());
        assert!(legacy.gpus[0].shared_memory.is_none());
        let row = doc! {"sample":sample,"gpu_memory_details":details};
        let restored = sample_from_row(&row).unwrap();
        assert_eq!(serde_json::to_value(restored).unwrap(), serde_json::to_value(original).unwrap());
    }

    #[test]
    fn old_rows_and_mismatched_adapters_never_inherit_shared_memory() {
        let (sample, mut details, _) = storage_sample(&reading()).unwrap();
        assert!(sample_from_row(&doc! {"sample":sample.clone()}).unwrap().gpus[0].shared_memory.is_none());
        details[0].insert("id", "different-adapter");
        let restored = sample_from_row(&doc! {"sample":sample,"gpu_memory_details":details}).unwrap();
        assert!(restored.gpus[0].shared_memory.is_none());
        assert!(restored.gpus[0].integrated.is_none());
    }

    #[test]
    fn invalid_shared_capacity_falls_back_to_valid_legacy_reading() {
        let (sample, mut details, _) = storage_sample(&reading()).unwrap();
        details[0].insert("shared_memory_capacity", -1i64);
        let restored = sample_from_row(&doc! {"sample":sample,"gpu_memory_details":details}).unwrap();
        assert!(restored.valid());
        assert!(restored.gpus[0].shared_memory.is_none());
        assert_eq!(restored.gpus[0].memory.as_ref().unwrap().total, 134217728);
    }
}
