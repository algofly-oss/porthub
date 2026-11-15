//! Bounded contributor drill-down for a single displayed second, not per-IP byte accounting.
use crate::{
    auth,
    error::{ApiError, ApiResult},
    inventory_traffic::{self, Sample},
    store,
    traffic_observations::Accepted,
    App,
};
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::bson::{self, doc, Bson, DateTime, Document};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
#[derive(Default)]
pub struct Cache(tokio::sync::Mutex<HashMap<String, (Instant, Value)>>);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    timestamp: u64,
    limit: Option<usize>,
}
pub fn router() -> Router<Arc<App>> {
    Router::new().route("/api/traffic/hover", get(hover))
}
fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "Traffic details unavailable",
    )
}
/// Mirrors chart interval expansion: an actual endpoint wins over an averaged bucket.
fn measurement(samples: &[Sample], time: u64) -> Option<Sample> {
    samples
        .iter()
        .skip_while(|s| s.timestamp < time)
        .find(|s| {
            s.interval_seconds.is_finite()
                && s.interval_seconds > 0.
                && (time as f64) > s.timestamp as f64 - s.interval_seconds
        })
        .copied()
}
fn target_host(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.len() > 2048 || raw.chars().any(char::is_control) {
        return None;
    }
    let input = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("http://{raw}")
    };
    let url = url::Url::parse(&input).ok()?;
    url.host_str()
        .map(|s| s.trim_matches(['[', ']']).to_owned())
}
fn bounded_text(record: &Document, key: &str) -> String {
    record
        .get_str(key)
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect()
}
async fn hover(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<Params>,
) -> ApiResult<(HeaderMap, Json<Value>)> {
    let _lifecycle = app.account_lifecycle.read().await;
    let user = auth::current_user(&app, &headers).await?;
    let owner = user
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())?;
    let now = DateTime::now().timestamp_millis() / 1000;
    let timestamp = i64::try_from(query.timestamp)
        .map_err(|_| ApiError::bad_request("Invalid hover timestamp"))?;
    if timestamp <= now - crate::firewall_history::RETENTION_SECONDS || timestamp > now + 1 {
        return Err(ApiError::bad_request(
            "Hover timestamp is outside retained history",
        ));
    }
    let limit = query.limit.unwrap_or(6);
    if !(1..=10).contains(&limit) {
        return Err(ApiError::bad_request(
            "Hover limit must be between 1 and 10",
        ));
    }
    let metadata_permit = app
        .inventory_traffic
        .3
        .acquire()
        .await
        .map_err(|_| unavailable())?;
    // Revalidate current ownership/configuration BEFORE using any cached response.
    let records=app.collection("connections").find(doc!{"user_id":owner})
        .projection(doc!{"_id":1,"machine_id":1,"service_name":1,"external_port":1,"internal_ip":1,"internalIp":1,"internal_port":1})
        .sort(doc!{"_id":1}).await?.try_collect::<Vec<_>>().await?;
    let machine_ids = records
        .iter()
        .filter_map(|r| r.get_object_id("machine_id").ok())
        .collect::<Vec<_>>();
    let machines = app
        .collection("machines")
        .find(doc! {"user_id":owner,"_id":{"$in":machine_ids}})
        .projection(doc! {"_id":1,"name":1})
        .sort(doc! {"_id":1})
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    let key = format!(
        "{owner}:{}:{limit}:{:x}",
        query.timestamp,
        Sha256::digest(
            bson::to_vec(&doc! {"connections":&records,"machines":&machines})
                .map_err(|_| unavailable())?
        )
    );
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::CACHE_CONTROL, "private, no-store".parse().unwrap());
    {
        let cache = app.traffic_hover.0.lock().await;
        if let Some((at, value)) = cache
            .get(&key)
            .filter(|(at, _)| at.elapsed() < Duration::from_secs(2))
        {
            let _ = at;
            return Ok((response_headers, Json(value.clone())));
        }
    }
    drop(metadata_permit);
    let snapshot = inventory_traffic::snapshot(&app, &Bson::ObjectId(owner)).await?;
    let mut selected = records
        .iter()
        .filter_map(|record| {
            let id = store::id(record.get("_id"));
            let sample = measurement(snapshot.ports.get(&id)?, query.timestamp)?;
            let rate = sample.in_rate + sample.out_rate + sample.drop_rate;
            (rate.is_finite() && rate > 0.).then_some((record, id, sample, rate))
        })
        .collect::<Vec<_>>();
    selected.sort_by(|a, b| b.3.total_cmp(&a.3).then_with(|| a.1.cmp(&b.1)));
    let total = selected.len();
    selected.truncate(limit);
    let _permit = app
        .inventory_traffic
        .3
        .acquire()
        .await
        .map_err(|_| unavailable())?;
    // Exact selected samples only: never reload a fleet's raw source-IP hour per hover.
    let clauses=selected.iter().filter_map(|(record,_,sample,_)|Some(doc!{"connection_id":record.get_object_id("_id").ok()?,"timestamp":i64::try_from(sample.timestamp).ok()?})).collect::<Vec<_>>();
    let raw = if clauses.is_empty() {
        Vec::new()
    } else {
        app.collection(crate::firewall_history::COLLECTION)
            .find(doc! {"owner_id":owner,"$or":clauses})
            .projection(doc! {"connection_id":1,"sample":1,"public_port":1})
            .limit(limit as i64)
            .await?
            .try_collect::<Vec<_>>()
            .await?
    };
    let mut contributors = Vec::new();
    for (record, id, sample, _) in selected {
        let raw = raw.iter().find(|r| store::id(r.get("connection_id")) == id);
        let value = raw
            .and_then(|r| r.get("sample"))
            .and_then(|s| bson::from_bson::<Value>(s.clone()).ok());
        let accepted = value.as_ref().and_then(Accepted::parse);
        let within = accepted
            .as_ref()
            .is_some_and(|a| query.timestamp as f64 > sample.timestamp as f64 - a.window);
        let source_status = if accepted.is_none() {
            "unavailable"
        } else if within {
            "observed"
        } else {
            "outside_observation_window"
        };
        let ips = accepted
            .as_ref()
            .filter(|_| within)
            .map(|a| a.ips.iter().take(16).cloned().collect::<Vec<_>>());
        let machine = machines
            .iter()
            .find(|m| m.get("_id") == record.get("machine_id"));
        let port = raw
            .and_then(|r| {
                r.get_i64("public_port")
                    .ok()
                    .or_else(|| r.get_i32("public_port").ok().map(i64::from))
            })
            .filter(|p| (1..=65535).contains(p));
        let target = record
            .get_str("internal_ip")
            .or_else(|_| record.get_str("internalIp"))
            .ok()
            .and_then(target_host);
        let target_port = record
            .get_i64("internal_port")
            .ok()
            .or_else(|| record.get_i32("internal_port").ok().map(i64::from))
            .filter(|p| (1..=65535).contains(p));
        contributors.push(json!({"connection_id":id,"machine_id":store::id(record.get("machine_id")),"machine_name":machine.map(|m|bounded_text(m,"name")).unwrap_or_default(),"service_name":bounded_text(record,"service_name"),
            "public_port":port,"public_port_scope":if port.is_some(){"recorded_measurement"}else{"unavailable"},
            "configured_target":{"host":target,"port":target_port,"scope":"current_configuration"},
            "measurement":{"start_timestamp":sample.timestamp as f64-sample.interval_seconds,"end_timestamp":sample.timestamp,"interval_seconds":sample.interval_seconds},
            "incoming_bytes_per_second":sample.in_rate,"outgoing_bytes_per_second":sample.out_rate,"dropped_bytes_per_second":sample.drop_rate,
            "accepted_incoming_ips":ips,"accepted_incoming_ips_window_seconds":accepted.as_ref().map(|a|a.window),"accepted_incoming_ips_address_families":accepted.as_ref().map(|a|&a.families),
            "source_status":source_status,"source_ips_truncated":within&&accepted.as_ref().is_some_and(|a|a.ips.len()>16),"source_semantics":"packets_accepted_by_porthub_policy_not_application_delivery"}));
    }
    let response = json!({"timestamp":query.timestamp,"contributors":contributors,"total_contributors":total,"truncated":total>limit});
    let mut cache = app.traffic_hover.0.lock().await;
    cache.retain(|_, (at, _)| at.elapsed() < Duration::from_secs(2));
    while cache.len() >= 64 {
        if let Some(old) = cache
            .iter()
            .min_by_key(|(_, v)| v.0)
            .map(|(k, _)| k.clone())
        {
            cache.remove(&old);
        } else {
            break;
        }
    }
    cache.insert(key, (Instant::now(), response.clone()));
    Ok((response_headers, Json(response)))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn averaged_bucket_uses_covering_measurement_without_claiming_outside_span() {
        let samples = [
            Sample {
                timestamp: 100,
                interval_seconds: 1.,
                in_rate: 1.,
                ..Default::default()
            },
            Sample {
                timestamp: 105,
                interval_seconds: 4.2,
                in_rate: 2.,
                ..Default::default()
            },
        ];
        assert_eq!(measurement(&samples, 100).unwrap().in_rate, 1.);
        assert_eq!(measurement(&samples, 101).unwrap().timestamp, 105);
        assert!(measurement(&samples, 99).is_none());
        assert!(measurement(&samples, 106).is_none());
    }
    #[test]
    fn target_never_exposes_url_credentials_or_paths() {
        assert_eq!(
            target_host("https://user:secret@example.com:443/private?token=x"),
            Some("example.com".into())
        );
        assert_eq!(target_host("192.0.2.1"), Some("192.0.2.1".into()));
        assert_eq!(target_host("[::1]"), Some("::1".into()));
        assert!(target_host("host\nsecret").is_none());
    }
}
