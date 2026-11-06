//! Background ingestion of edge-owned aggregate counters. Counts, batch IDs and
//! the read checkpoint share one revision-guarded Mongo document.
use crate::{auth, error::ApiResult, store, App};
use anyhow::{Context, Result};
use axum::{extract::{State, Query}, http::HeaderMap, response::Response};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, Bson, Document};
use porthub_runtime::web_activity::{self as journal, Checkpoint};
use serde_json::{json, Value};
use std::{
    collections::{HashSet, VecDeque},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;

const STATE_ID: &str = "traefik-requests-v1";
const RECENT_BATCHES: usize = 512;
const MAX_RECENT_VISITORS: usize = 32_768;
fn integer(doc: &Document, key: &str) -> i64 {
    match doc.get(key) {
        Some(Bson::Int64(n)) => *n,
        Some(Bson::Int32(n)) => *n as i64,
        _ => 0,
    }
}
fn stamp(millis: i64) -> String {
    format!("{}+00:00", store::datetime(millis))
}
fn month(value: &str) -> &str {
    value.get(..7).unwrap_or("")
}
fn checkpoint(state: &Document) -> Option<Checkpoint> {
    let identity = state.get_str("native_identity").ok()?.to_owned();
    let offset = integer(state, "native_offset").try_into().ok()?;
    Some(Checkpoint { identity, offset })
}
fn merge(state: &Document, read: &journal::Read, valid: &HashSet<String>, now: &str) -> Document {
    let mut metrics: Document = state
        .get_document("metrics")
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|(id, _)| valid.contains(id))
        .collect();
    let tracking = store::string(state, "tracking_since");
    for (_, metric) in metrics.iter_mut() {
        if let Bson::Document(metric) = metric {
            let last = store::string(metric, "last_requested_at");
            if !metric.contains_key("month")
                && !tracking.is_empty()
                && month(last) == month(tracking)
            {
                let value = month(last).to_owned();
                let count = integer(metric, "requests");
                metric.insert("month", value);
                metric.insert("monthly_requests", count);
            }
        }
    }
    let mut recent: VecDeque<String> = state
        .get_array("native_batches")
        .into_iter()
        .flatten()
        .filter_map(Bson::as_str)
        .map(str::to_owned)
        .collect();
    let mut warning = state.get_bool("coverage_warning").unwrap_or(false) || read.gap;
    let mut visitors = state.get_document("recent_visitors").cloned().unwrap_or_default();
    let mut watermark = integer(state, "visits_watermark");
    let window = journal::VISIT_WINDOW_SECONDS * 1000;
    // Retain enough history to deduplicate a late minute bucket still inside
    // the accepted 30-minute lateness window, including its first request.
    let retention = 2 * window + 60_000;
    visitors = visitors.into_iter().filter(|(_, value)| value.as_i64().is_some_and(|seen| seen >= watermark.saturating_sub(retention))).collect();
    let mut visit_events = Vec::new();
    for batch in &read.batches {
        if recent.contains(&batch.id) {
            continue;
        }
        warning |= batch.coverage_warning;
        for record in &batch.records {
            if !valid.contains(&record.route_id) {
                continue;
            }
            if !matches!(metrics.get(&record.route_id), Some(Bson::Document(_))) {
                metrics.insert(
                    &record.route_id,
                    doc! {"requests":0_i64,"last_requested_at":Bson::Null},
                );
            }
            let metric = metrics.get_document_mut(&record.route_id).unwrap();
            metric.insert(
                "requests",
                integer(metric, "requests").saturating_add(record.count),
            );
            let timestamp = stamp(record.timestamp);
            let record_month = month(&timestamp);
            if record_month > store::string(metric, "month") {
                metric.insert("month", record_month);
                metric.insert("monthly_requests", 0_i64);
                metric.insert("monthly_visits", 0_i64);
            }
            if record_month == store::string(metric, "month") {
                metric.insert(
                    "monthly_requests",
                    integer(metric, "monthly_requests").saturating_add(record.count),
                );
            }
            // Compare parsed instants, since older ISO strings have varying precision.
            let previous =
                chrono::DateTime::parse_from_rfc3339(store::string(metric, "last_requested_at"))
                    .ok()
                    .map(|time| time.timestamp_millis());
            if previous.is_none_or(|previous| record.timestamp >= previous) {
                metric.insert("last_requested_at", timestamp);
                metric.insert("last_host", &record.host);
            }
            if record.client.is_some() { visit_events.push(record); }
        }
        recent.push_back(batch.id.clone());
        while recent.len() > RECENT_BATCHES {
            recent.pop_front();
        }
    }
    // Keep the ledger, counters and journal checkpoint in the same CAS write.
    // Replayed batches and a restarted edge/core cannot add a second visit.
    visit_events.sort_by_key(|record| record.first_timestamp.unwrap_or(record.timestamp));
    let mut visits_since = state.get_str("visits_tracking_since").ok().map(str::to_owned);
    for record in visit_events {
        let (Some(client), Some(first)) = (&record.client, record.first_timestamp) else { continue };
        if record.timestamp < watermark.saturating_sub(window) {
            warning = true; // Too old to prove uniqueness; never inflate the estimate.
            continue;
        }
        let previous = visitors.get_i64(client).ok();
        watermark = watermark.max(record.timestamp);
        if previous.is_none() && visitors.len() >= MAX_RECENT_VISITORS {
            visitors = visitors.into_iter().filter(|(_, value)| value.as_i64().is_some_and(|seen| seen >= watermark.saturating_sub(retention))).collect();
            if visitors.len() >= MAX_RECENT_VISITORS { warning = true; continue; }
        }
        visitors.insert(client, previous.unwrap_or(first).max(record.timestamp));
        visits_since.get_or_insert_with(|| stamp(first));
        let metric = metrics.get_document_mut(&record.route_id).unwrap();
        if previous.is_none_or(|last| first.saturating_sub(last) >= window) {
            metric.insert("visits", integer(metric, "visits").saturating_add(1));
            if month(&stamp(first)) == store::string(metric, "month") {
                metric.insert("monthly_visits", integer(metric, "monthly_visits").saturating_add(1));
            }
            let last = chrono::DateTime::parse_from_rfc3339(store::string(metric, "last_visited_at"))
                .ok().map(|date| date.timestamp_millis()).unwrap_or(i64::MIN);
            if first >= last { metric.insert("last_visited_at", stamp(first)); }
        }
    }
    visitors = visitors.into_iter().filter(|(_, value)| value.as_i64().is_some_and(|seen| seen >= watermark.saturating_sub(retention))).collect();
    let monthly = state
        .get_str("monthly_tracking_since")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            if month(tracking) == month(now) {
                tracking
            } else {
                now
            }
        });
    doc! {"native_identity":&read.checkpoint.identity,"native_offset":read.checkpoint.offset as i64,
    "native_batches":recent.into_iter().map(Bson::String).collect::<Vec<_>>(),"metrics":metrics,
    "updated_at":now,"monthly_tracking_since":monthly,"coverage_warning":warning,
    "recent_visitors":visitors,"visits_watermark":watermark,
    "visits_tracking_since":visits_since.map(Bson::String).unwrap_or(Bson::Null)}
}

/// Returns true if the bounded read needs another immediate chunk.
pub async fn collect(app: &App, path: &Path) -> Result<bool> {
    for _ in 0..8 {
        let state = app
            .collection("proxy_activity")
            .find_one(doc! {"_id":STATE_ID})
            .await?;
        let cp = state.as_ref().and_then(checkpoint);
        let path = path.to_owned();
        let read_cp = cp.clone();
        let Some(read) =
            tokio::task::spawn_blocking(move || journal::read_batch(&path, read_cp.as_ref()))
                .await??
        else {
            return Ok(false);
        };
        if cp.as_ref() == Some(&read.checkpoint) && read.batches.is_empty() && !read.gap {
            return Ok(read.more);
        }
        let now = stamp(chrono::Utc::now().timestamp_millis());
        let previous = state
            .clone()
            .unwrap_or_else(|| doc! {"revision":0_i64,"tracking_since":&now});
        let routes: Vec<Document> = app
            .collection("traffic_routes")
            .find(doc! {})
            .projection(doc! {"_id":1})
            .await?
            .try_collect()
            .await?;
        let valid = routes
            .iter()
            .map(|route| store::id(route.get("_id")))
            .collect();
        let fields = merge(&previous, &read, &valid, &now);
        if state.is_none() {
            let mut initial = previous;
            initial.extend(fields);
            initial.insert("_id", STATE_ID);
            initial.insert("revision", 1_i64);
            match app.collection("proxy_activity").insert_one(initial).await {
                Ok(_) => return Ok(read.more),
                Err(error) if store::duplicate(&error) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        let revision = previous.get("revision").cloned().unwrap_or(Bson::Null);
        let result = app
            .collection("proxy_activity")
            .update_one(
                doc! {"_id":STATE_ID,"revision":revision},
                doc! {"$set":fields,"$inc":{"revision":1_i64}},
            )
            .await?;
        if result.modified_count == 1 {
            return Ok(read.more);
        }
    }
    anyhow::bail!("activity state changed repeatedly; retry later")
}

pub async fn run(
    app: Arc<App>,
    path: std::path::PathBuf,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let paths = journal::segments(&path);
    let mut changes =
        porthub_runtime::file_watch::FileChanges::new(&paths).context("watch activity journal")?;
    let mut backoff = Duration::from_secs(1);
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        let result =
            tokio::select! {result=collect(&app,&path)=>result,_=stop.changed()=>return Ok(())};
        match result {
            Ok(true) => {
                backoff = Duration::from_secs(1);
                tokio::task::yield_now().await;
                continue;
            }
            Ok(false) => backoff = Duration::from_secs(1),
            Err(error) => {
                tracing::warn!("web activity ingestion unavailable; retrying");
                tracing::debug!(%error,"web activity ingestion details");
                tokio::select! {_=tokio::time::sleep(backoff)=>{},_=stop.changed()=>return Ok(())}
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        }
        tokio::select! {event=changes.changed()=>event.context("activity journal watcher stopped")?,_=stop.changed()=>return Ok(())}
    }
}

pub async fn activity(State(app): State<Arc<App>>, Query(query): Query<std::collections::HashMap<String,String>>, headers: HeaderMap) -> ApiResult<Response> {
    let user = auth::current_user(&app, &headers).await?;
    let mut filter=doc! {"user_id":user.get("_id").cloned().unwrap_or(Bson::Null)};
    let scoped=query.contains_key("ids");
    if let Some(ids)=query.get("ids") {
        let ids=ids.split(',').filter(|id|!id.is_empty()).map(|id|mongodb::bson::oid::ObjectId::parse_str(id).map_err(|_|crate::error::ApiError::bad_request("Invalid proxy ID"))).collect::<ApiResult<Vec<_>>>()?;
        if ids.len()>100 {return Err(crate::error::ApiError::bad_request("At most 100 proxy IDs are supported"));}
        filter.insert("_id",doc! {"$in":ids});
    }
    let recent=query.get("recent").map(|v|v.parse::<usize>()).transpose().map_err(|_|crate::error::ApiError::bad_request("Invalid recent proxy limit"))?;
    if recent.is_some_and(|n|n==0 || n>25) {return Err(crate::error::ApiError::bad_request("Recent proxy limit must be 1–25"));}
    let routes: Vec<Document> = app
        .collection("traffic_routes")
        .find(filter)
        .projection(if recent.is_some() {doc! {"_id":1,"name":1,"hosts":1,"entry_points":1,"connection.data_id":1}}else{doc! {"_id":1}})
        .await?
        .try_collect()
        .await?;
    let state = app
        .collection("proxy_activity")
        .find_one(doc! {"_id":STATE_ID})
        .await?;
    let available = state.is_some();
    let state = state.unwrap_or_default();
    let metrics = state.get_document("metrics").cloned().unwrap_or_default();
    let month = chrono::Utc::now().format("%Y-%m").to_string();
    let mut data: Vec<Value> = routes
        .iter()
        .map(|route| {
            let id = store::id(route.get("_id"));
            let mut metric = metrics
                .get_document(&id)
                .cloned()
                .unwrap_or_else(|_| doc! {"requests":0_i64,"last_requested_at":Bson::Null});
            let monthly = if store::string(&metric, "month") == month {
                integer(&metric, "monthly_requests")
            } else if !metric.contains_key("month")
                && self::month(store::string(&state, "tracking_since")) == month
            {
                integer(&metric, "requests")
            } else {
                0
            };
            metric.insert("route_id", id);
            metric.insert("monthly_requests", monthly);
            let monthly_visits = if store::string(&metric, "month") == month { integer(&metric, "monthly_visits") } else { 0 };
            metric.insert("monthly_visits", monthly_visits);
            store::document(&metric)
        })
        .collect();
    let mut previews=Vec::new();
    if let Some(limit)=recent {
        data.retain(|metric|metric["last_requested_at"].as_str().is_some_and(|s|!s.is_empty()));
        data.sort_by(|a,b|b["last_requested_at"].as_str().cmp(&a["last_requested_at"].as_str()).then_with(||a["route_id"].as_str().cmp(&b["route_id"].as_str())));
        data.truncate(limit);
        for metric in &data {
            if let Some(route)=routes.iter().find(|route|store::id(route.get("_id"))==metric["route_id"].as_str().unwrap_or("")) {previews.push(store::document(route));}
        }
    }
    let mut body=json!({"tracking_since":store::field(&state,"tracking_since"),"month":month,"monthly_tracking_since":store::field(&state,"monthly_tracking_since"),"available":available,"coverage_warning":state.get_bool("coverage_warning").unwrap_or(false),"data":data});
    body["visits_tracking_since"] = store::field(&state,"visits_tracking_since");
    body["visit_window_seconds"] = json!(journal::VISIT_WINDOW_SECONDS);
    if !scoped && recent.is_none() {body["updated_at"]=store::field(&state,"updated_at");}
    if recent.is_some() {body["routes"]=json!(previews);}
    crate::inventory_query::conditional(&headers,body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use journal::{Batch, Read, Record};
    fn visitor_record(route: &str, client: Option<&str>, timestamp: i64, count: i64) -> Record {
        Record { route_id:route.into(),host:"app.invalid".into(),timestamp,count,
            client:client.map(str::to_owned),first_timestamp:client.map(|_|timestamp) }
    }
    fn visitor_read(records: Vec<Record>) -> Read {
        Read { checkpoint:Checkpoint{identity:"visit-journal".into(),offset:100},
            batches:vec![Batch{version:2,id:uuid::Uuid::new_v4().to_string(),coverage_warning:false,records}],gap:false,more:false }
    }
    fn apply_visitors(state: &mut Document, read: &Read) {
        let fields=merge(state,read,&HashSet::from(["a".into(),"b".into()]),"2026-11-06T00:00:00Z");
        state.extend(fields);
    }
    #[test]
    fn visits_debounce_refreshes_inactivity_and_persists_with_replay_checkpoint() {
        let start=1_783_000_000_000;let a="a".repeat(64);let b="b".repeat(64);let c="c".repeat(64);
        let mut state=doc!{};
        let first=visitor_read(vec![visitor_record("a",Some(&a),start,3),visitor_record("a",Some(&a),start+600_000,50)]);
        apply_visitors(&mut state,&first);apply_visitors(&mut state,&first);
        let metric=state.get_document("metrics").unwrap().get_document("a").unwrap();
        assert_eq!(integer(metric,"requests"),53);assert_eq!(integer(metric,"visits"),1);
        apply_visitors(&mut state,&visitor_read(vec![visitor_record("a",Some(&b),start+300_000,1),visitor_record("b",Some(&c),start+300_000,1)]));
        apply_visitors(&mut state,&visitor_read(vec![visitor_record("a",Some(&a),start+35*60_000,1)]));
        assert_eq!(integer(state.get_document("metrics").unwrap().get_document("a").unwrap(),"visits"),2,"35 minutes after first request is only 25 minutes after last activity");
        // Rehydrate exactly the BSON state stored by the Mongo CAS operation.
        state=mongodb::bson::from_slice(&mongodb::bson::to_vec(&state).unwrap()).unwrap();
        apply_visitors(&mut state,&visitor_read(vec![visitor_record("a",Some(&a),start+65*60_000,1)]));
        let metrics=state.get_document("metrics").unwrap();
        assert_eq!(integer(metrics.get_document("a").unwrap(),"visits"),3);
        assert_eq!(integer(metrics.get_document("a").unwrap(),"monthly_visits"),3);
        assert_eq!(integer(metrics.get_document("b").unwrap(),"visits"),1);
    }
    #[test]
    fn historical_requests_are_not_relabelled_as_visitors() {
        let mut state=doc!{"metrics":{"a":{"requests":999_i64}}};
        apply_visitors(&mut state,&visitor_read(vec![visitor_record("a",None,1_783_000_000_000,1)]));
        assert_eq!(integer(state.get_document("metrics").unwrap().get_document("a").unwrap(),"visits"),0);
        assert!(state.get_str("visits_tracking_since").is_err());
        apply_visitors(&mut state,&visitor_read(vec![visitor_record("a",Some(&"a".repeat(64)),1_783_000_000_001,1)]));
        let metric=state.get_document("metrics").unwrap().get_document("a").unwrap();
        assert_eq!(integer(metric,"requests"),1001);assert_eq!(integer(metric,"visits"),1);
    }
    #[test]
    fn active_visit_crossing_utc_month_is_not_counted_again() {
        let start=chrono::DateTime::parse_from_rfc3339("2026-10-31T23:55:00Z").unwrap().timestamp_millis();
        let client="a".repeat(64);let mut state=doc!{};
        for minutes in [0,10,35] {
            apply_visitors(&mut state,&visitor_read(vec![visitor_record("a",Some(&client),start+minutes*60_000,1)]));
        }
        let metric=state.get_document("metrics").unwrap().get_document("a").unwrap();
        assert_eq!(integer(metric,"visits"),1);assert_eq!(integer(metric,"monthly_visits"),0);
        apply_visitors(&mut state,&visitor_read(vec![visitor_record("a",Some(&client),start+75*60_000,1)]));
        let metric=state.get_document("metrics").unwrap().get_document("a").unwrap();
        assert_eq!(integer(metric,"visits"),2);assert_eq!(integer(metric,"monthly_visits"),1);
    }
    #[test]
    fn delayed_repeat_is_not_recounted_when_another_proxy_advances_event_time() {
        let start=1_783_000_000_000;let mut state=doc!{};
        apply_visitors(&mut state,&visitor_read(vec![visitor_record("a",Some(&"a".repeat(64)),start,1)]));
        apply_visitors(&mut state,&visitor_read(vec![visitor_record("b",Some(&"b".repeat(64)),start+40*60_000,1)]));
        apply_visitors(&mut state,&visitor_read(vec![visitor_record("a",Some(&"a".repeat(64)),start+15*60_000,1)]));
        assert_eq!(integer(state.get_document("metrics").unwrap().get_document("a").unwrap(),"visits"),1);
    }
    #[test]
    fn visit_ledger_capacity_never_evicts_active_visitors_and_inflates_counts() {
        let start=1_783_000_000_000;
        let visitors:Document=(0..MAX_RECENT_VISITORS).map(|i|(format!("{i:064x}"),Bson::Int64(start))).collect();
        let mut state=doc!{"recent_visitors":visitors,"visits_watermark":start};
        apply_visitors(&mut state,&visitor_read(vec![visitor_record("a",Some(&"f".repeat(64)),start,1)]));
        assert!(state.get_bool("coverage_warning").unwrap());
        assert_eq!(state.get_document("recent_visitors").unwrap().len(),MAX_RECENT_VISITORS);
        assert_eq!(integer(state.get_document("metrics").unwrap().get_document("a").unwrap(),"visits"),0);
        apply_visitors(&mut state,&visitor_read(vec![visitor_record("a",Some(&"f".repeat(64)),start+62*60_000,1)]));
        assert_eq!(state.get_document("recent_visitors").unwrap().len(),1);
        assert_eq!(integer(state.get_document("metrics").unwrap().get_document("a").unwrap(),"visits"),1);
    }
    #[test]
    fn preserves_history_deduplicates_and_handles_out_of_order_months() {
        let valid = HashSet::from(["a".to_owned(), "b".to_owned()]);
        let state = doc! {"tracking_since":"2026-10-01T00:00:00+00:00","identity":"legacy-inode","offset":100_i64,
        "metrics":{"a":{"requests":5_i64,"last_requested_at":"2026-10-01T00:00:00+00:00"},"gone":{"requests":99_i64}}};
        let timestamp = |value: &str| {
            chrono::DateTime::parse_from_rfc3339(value)
                .unwrap()
                .timestamp_millis()
        };
        let batch = Batch {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            coverage_warning: false,
            records: vec![
                Record {
                    route_id: "a".into(),
                    count: 3,
                    timestamp: timestamp("2026-11-02T00:00:00Z"),
                    host: "new.invalid".into(),
                    client: None, first_timestamp: None,
                },
                Record {
                    route_id: "a".into(),
                    count: 2,
                    timestamp: timestamp("2026-10-30T00:00:00Z"),
                    host: "old.invalid".into(),
                    client: None, first_timestamp: None,
                },
                Record {
                    route_id: "b".into(),
                    count: 7,
                    timestamp: timestamp("2026-10-20T00:00:00Z"),
                    host: "b.invalid".into(),
                    client: None, first_timestamp: None,
                },
                Record {
                    route_id: "gone".into(),
                    count: 100,
                    timestamp: timestamp("2026-10-20T00:00:00Z"),
                    host: "deleted.invalid".into(),
                    client: None, first_timestamp: None,
                },
            ],
        };
        let read = Read {
            checkpoint: Checkpoint {
                identity: "native-inode".into(),
                offset: 500,
            },
            batches: vec![batch.clone(), batch],
            gap: false,
            more: false,
        };
        let merged = merge(&state, &read, &valid, "2026-11-03T00:00:00+00:00");
        let metrics = merged.get_document("metrics").unwrap();
        let a = metrics.get_document("a").unwrap();
        assert_eq!(integer(a, "requests"), 10);
        assert_eq!(integer(a, "monthly_requests"), 3);
        assert_eq!(store::string(a, "last_host"), "new.invalid");
        assert!(!metrics.contains_key("gone"));
        assert_eq!(integer(metrics.get_document("b").unwrap(), "requests"), 7);
        assert_eq!(merged.get_array("native_batches").unwrap().len(), 1);
        let mut next = state.clone();
        next.extend(merged.clone());
        let merged = merge(&next, &read, &valid, "2026-11-03T00:00:00+00:00");
        assert_eq!(
            merged
                .get_document("metrics")
                .unwrap()
                .get_document("a")
                .unwrap(),
            a
        );
        assert_eq!(next.get_str("identity").unwrap(), "legacy-inode");
        assert_eq!(integer(&next, "offset"), 100);
    }
}
