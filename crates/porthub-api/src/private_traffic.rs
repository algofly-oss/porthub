//! Account-scoped private carrier history. Observations are immutable, sequenced
//! deltas; each directed pair/bucket prefers sender evidence over receiver-only.
use crate::{
    error::{ApiError, ApiResult},
    store, App,
};
use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{self, doc, oid::ObjectId, Bson, DateTime, Document},
    options::IndexOptions,
    IndexModel,
};
use porthub_mesh::traffic_report::{Report, Row};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};
pub const COLLECTION: &str = "private_traffic";
pub fn router() -> Router<Arc<App>> {
    Router::new().route("/api/private/traffic", get(series))
}
async fn indexes(app: &App) -> ApiResult<()> {
    app.private_traffic_initialized
        .get_or_try_init(|| async {
            app.collection(COLLECTION)
                .create_indexes([
                    IndexModel::builder()
                        .keys(doc! {"expires_at":1})
                        .options(IndexOptions::builder().expire_after(Duration::ZERO).build())
                        .build(),
                    IndexModel::builder()
                        .keys(doc! {"workspace_id":1,"day":1,"source":1,"destination":1})
                        .build(),
                ])
                .await?;
            Ok::<_, ApiError>(())
        })
        .await?;
    Ok(())
}
/// Called only AFTER private sync authenticated/revalidated the reporter against
/// current enabled machines and workspace membership. Destination identities
/// must come from that SAME snapshot; clients cannot invent a cross-account row.
pub(crate) async fn ingest(
    app: &App,
    workspace: ObjectId,
    reporter: &str,
    peers: &[Document],
    report: &Report,
) -> ApiResult<(u64, u64)> {
    if !report.valid() {
        return Err(ApiError::bad_request("Invalid private traffic report"));
    }
    let now = DateTime::now();
    let oldest = now.timestamp_millis() - 30 * 86400_000;
    indexes(app).await?;

    let started = std::time::Instant::now();
    let mut ack = 0;
    let mut rejected = 0;
    for row in &report.rows {
        if started.elapsed() > Duration::from_millis(300) {
            break;
        }
        if row.peer_id == reporter
            || !peers
                .iter()
                .any(|p| p.get_str("_id") == Ok(row.peer_id.as_str()))
            || row.at < oldest
            || row.observed_at > now.timestamp_millis() + 120_000
        {
            ack = row.sequence;
            rejected += 1;
            continue;
        }
        let result=tokio::time::timeout(Duration::from_millis(100),async {
            for sender in [true,false] {
                let (source,destination)=if sender{(reporter,row.peer_id.as_str())}else{(row.peer_id.as_str(),reporter)};
                let day=row.at.div_euclid(86400_000)*86400_000;
                let key=format!("{}:{}:{}:{}",workspace,source,destination,day);
                let cursor=format!("{}{}",if sender{'s'}else{'r'},report.instance);
                let collection=app.collection(COLLECTION);
                // A bounded cursor set is never evicted: evicting an identity
                // could count its late retry twice. Saturation rejects only
                // telemetry; it never affects the private policy lease.
                let mut update=pipeline(row,now,sender,&cursor);
                update.insert(0,doc!{"$set":{"workspace_id":{"$ifNull":["$workspace_id",workspace]},"source":{"$ifNull":["$source",source]},"destination":{"$ifNull":["$destination",destination]},"day":{"$ifNull":["$day",day]},"cursors":{"$ifNull":["$cursors",{}]},"expires_at":{"$ifNull":["$expires_at",DateTime::from_millis(day+31*86400_000)]}}});
                // One atomic upsert per direction (no read-before-write or
                // separate seed roundtrip); a lost response retries idempotently.
                let saved=collection.find_one_and_update(doc!{"_id":&key},update).upsert(true).return_document(mongodb::options::ReturnDocument::After).projection(doc!{"cursors":1}).await?.ok_or_else(||ApiError::bad_request("Private traffic state unavailable"))?;
                if saved.get_document("cursors").ok().and_then(|c|c.get_i64(&cursor).ok()).is_none_or(|seq|seq<row.sequence as i64){return Ok(false)}
            }
            Ok::<_,ApiError>(true)
        }).await;
        match result {
            Ok(Ok(accepted)) => {
                ack = row.sequence;
                if !accepted {
                    rejected += 1
                }
            }
            _ => break,
        }
    }
    let _=tokio::time::timeout(Duration::from_millis(75),app.collection("private_peers").update_one(doc!{"_id":reporter,"workspace_id":workspace,"enabled":true},doc!{"$set":{"traffic_reported_at":now,"traffic_dropped_rows":report.dropped_rows as i64},"$max":{"traffic_rejected_rows":rejected}})).await;
    Ok((ack, rejected as u64))
}
/// One atomic canonical pair/day update. Raw sparse minute evidence remains
/// bounded by1440 cells. Late sender evidence corrects materialized hour/day
/// totals by NEW canonical minus OLD canonical, including a negative correction.
fn pipeline(row: &Row, now: DateTime, sender: bool, cursor: &str) -> Vec<Document> {
    let zero = doc! {"t":row.at,"sd":0_i64,"sr":0_i64,"rd":0_i64,"rr":0_i64,"s":false,"ds":0_i64,"dr":0_i64,"os":0_i64,"or":0_i64,"exists":false};
    let values = row.values();
    let direct = if sender { values[0] } else { values[1] } as i64;
    let relay = if sender { values[2] } else { values[3] } as i64;
    let add = |field: &str, value: i64| doc! {"$add":[format!("$__old.{field}"),value]};
    let mut new = doc! {"t":row.at,"exists":true,"s":{"$or":["$__old.s",sender]}};
    for (name, value) in [
        ("sd", if sender { direct } else { 0 }),
        ("sr", if sender { relay } else { 0 }),
        ("rd", if sender { 0 } else { direct }),
        ("rr", if sender { 0 } else { relay }),
    ] {
        new.insert(name, add(name, value));
    }
    new.insert(
        "ds",
        doc! {"$min":[120,add("ds",if sender{row.duration_seconds as i64}else{0})]},
    );
    new.insert(
        "dr",
        doc! {"$min":[120,add("dr",if sender{0}else{row.duration_seconds as i64})]},
    );
    new.insert(
        "os",
        doc! {"$max":["$__old.os",if sender{row.observed_at}else{0}]},
    );
    new.insert(
        "or",
        doc! {"$max":["$__old.or",if sender{0}else{row.observed_at}]},
    );
    let canonical = |prefix: &str, direct: bool| doc! {"$cond":[format!("${prefix}.s"),format!("${prefix}.{}",if direct{"sd"}else{"sr"}),format!("${prefix}.{}",if direct{"rd"}else{"rr"})]};
    let mut updates = doc! {"received_at":now,"cursors":{"$mergeObjects":["$cursors",{cursor:row.sequence as i64}]},"minutes":{"$cond":["$__old.exists",{"$map":{"input":{"$ifNull":["$minutes",[]]},"as":"m","in":{"$cond":[{"$eq":["$$m.t",row.at]},"$__new","$$m"]}}},{"$concatArrays":[{"$ifNull":["$minutes",[]]},["$__new"]]}]}};
    for (array, seconds) in [("hours", 3600_i64), ("days", 86400_i64)] {
        let at = row.at.div_euclid(seconds * 1000) * seconds * 1000;
        let mut fresh = doc! {"at":at,"direct_bytes":"$__direct_delta","relay_bytes":"$__relay_delta","fallback_count":"$__fallback_delta","received_direct":if sender{0}else{direct},"received_relay":if sender{0}else{relay},"observed_at":{"$cond":["$__new.s","$__new.os","$__new.or"]}};
        let mut changed = doc! {"at":"$$m.at","direct_bytes":{"$add":["$$m.direct_bytes","$__direct_delta"]},"relay_bytes":{"$add":["$$m.relay_bytes","$__relay_delta"]},"fallback_count":{"$add":["$$m.fallback_count","$__fallback_delta"]},"received_direct":{"$add":["$$m.received_direct",if sender{0}else{direct}]},"received_relay":{"$add":["$$m.received_relay",if sender{0}else{relay}]},"observed_at":{"$max":["$$m.observed_at",{"$cond":["$__new.s","$__new.os","$__new.or"]}]}};
        // Explicit nonnegative canonical values; any impossible overflow/error
        // aborts the atomic update rather than publishing inaccurate counters.
        fresh.insert("duration_seconds", 0_i64);
        changed.insert("duration_seconds", 0_i64);
        updates.insert(array,doc!{"$let":{"vars":{"rows":{"$ifNull":[format!("${array}"),[]]}},"in":{"$cond":[{"$in":[at,{"$map":{"input":"$$rows","as":"m","in":"$$m.at"}}]},{"$map":{"input":"$$rows","as":"m","in":{"$cond":[{"$eq":["$$m.at",at]},changed,"$$m"]}}},{"$concatArrays":["$$rows",[fresh]]}]}}});
    }
    let max = porthub_mesh::traffic_report::MAX_COUNTER as i64;
    let mut bounds: Vec<Bson> = vec![];
    for field in ["sd", "sr", "rd", "rr"] {
        bounds.push(doc! {"$gte":[format!("$__new.{field}"),0]}.into());
        bounds.push(doc! {"$lte":[format!("$__new.{field}"),max]}.into());
    }
    for (array, seconds) in [("hours", 3600_i64), ("days", 86400_i64)] {
        let at = row.at.div_euclid(seconds * 1000) * seconds * 1000;
        let old = doc! {"$ifNull":[{"$arrayElemAt":[{"$filter":{"input":{"$ifNull":[format!("${array}"),[]]},"as":"h","cond":{"$eq":["$$h.at",at]}}},0]},{"direct_bytes":0,"relay_bytes":0}]};
        for (field, delta) in [
            ("direct_bytes", "$__direct_delta"),
            ("relay_bytes", "$__relay_delta"),
        ] {
            let value = doc! {"$let":{"vars":{"h":old.clone()},"in":{"$add":[format!("$$h.{field}"),delta]}}};
            bounds.push(doc! {"$gte":[value.clone(),0]}.into());
            bounds.push(doc! {"$lte":[value,max]}.into());
        }
        bounds.push(doc!{"$let":{"vars":{"h":old},"in":{"$lte":[{"$add":["$$h.direct_bytes","$$h.relay_bytes","$__direct_delta","$__relay_delta"]},max]}}}.into());
    }
    vec![
        doc! {"$set":{"__old":{"$ifNull":[{"$arrayElemAt":[{"$filter":{"input":{"$ifNull":["$minutes",[]]},"as":"m","cond":{"$eq":["$$m.t",row.at]}}},0]},zero]},"__cursor":{"$getField":{"field":{"$literal":cursor},"input":{"$ifNull":["$cursors",{}]}}}}},
        doc! {"$set":{"__new":new,"__accept":{"$and":[{"$gt":[row.sequence as i64,{"$ifNull":["$__cursor",0]}]},{"$or":[{"$ne":[{"$type":"$__cursor"},"missing"]},{"$lt":[{"$size":{"$objectToArray":{"$ifNull":["$cursors",{}]}}},128]}]}]}}},
        doc! {"$set":{"__direct_delta":{"$subtract":[canonical("__new",true),canonical("__old",true)]},"__relay_delta":{"$subtract":[canonical("__new",false),canonical("__old",false)]},"__fallback_delta":{"$subtract":[{"$cond":["$__new.s",0,1]},{"$cond":[{"$and":["$__old.exists",{"$not":["$__old.s"]}]},1,0]}]}}},
        doc! {"$set":{"__accept":{"$and":["$__accept",{"$and":bounds}]}}},
        doc! {"$replaceWith":{"$cond":["$__accept",{"$mergeObjects":["$$ROOT",updates]},"$$ROOT"]}},
        doc! {"$unset":["__old","__new","__cursor","__accept","__direct_delta","__relay_delta","__fallback_delta"]},
    ]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    #[serde(default = "default_range")]
    range: String,
    machine_id: Option<String>,
    source_peer_id: Option<String>,
    destination_peer_id: Option<String>,
    #[serde(default)]
    search: String,
    #[serde(default = "first_page")]
    page: usize,
}
fn first_page() -> usize {
    1
}
fn default_range() -> String {
    "1h".into()
}
fn range(value: &str) -> Option<(&'static str, i64, i64)> {
    match value {
        "1h" => Some(("minutes", 3600, 60)),
        "24h" => Some(("minutes", 86400, 900)),
        "7d" => Some(("hours", 604800, 7200)),
        "30d" => Some(("days", 2592000, 86400)),
        _ => None,
    }
}

fn number(row: &Document, key: &str) -> u64 {
    row.get_i64(key).ok().filter(|v| *v >= 0).unwrap_or(0) as u64
}

fn history_pipeline(
    workspace: ObjectId,
    ids: &[String],
    array: &str,
    start: i64,
    end: i64,
    step: i64,
    machine_peers: Option<&[String]>,
) -> Vec<Document> {
    let first_day = start.div_euclid(86400_000) * 86400_000;
    let mut filter = doc! {"workspace_id":workspace,"source":{"$in":ids},"destination":{"$in":ids},"day":{"$gte":first_day,"$lt":end},"expires_at":{"$gt":DateTime::now()}};
    if let Some(ids) = machine_peers {
        filter.insert(
            "$or",
            vec![
                doc! {"source":{"$in":ids}},
                doc! {"destination":{"$in":ids}},
            ],
        );
    }
    let minute_rows = doc! {"$map":{"input":{"$ifNull":["$minutes",[]]},"as":"m","in":{"at":"$$m.t","direct_bytes":{"$cond":["$$m.s","$$m.sd","$$m.rd"]},"relay_bytes":{"$cond":["$$m.s","$$m.sr","$$m.rr"]},"received_direct":"$$m.rd","received_relay":"$$m.rr","fallback_count":{"$cond":["$$m.s",0,1]},"duration_seconds":{"$cond":["$$m.s","$$m.ds","$$m.dr"]},"observed_at":{"$cond":["$$m.s","$$m.os","$$m.or"]}}}};
    let input: Bson = if array == "minutes" {
        minute_rows.into()
    } else {
        doc! {"$ifNull":[format!("${array}"),[]]}.into()
    };
    vec![
        doc! {"$match":filter},
        doc! {"$project":{"source":1,"destination":1,"received_at":1,"rows":{"$filter":{"input":input,"as":"r","cond":{"$and":[{"$gte":["$$r.at",start]},{"$lt":["$$r.at",end]}]}}}}},
        doc! {"$unwind":"$rows"},
        doc! {"$group":{"_id":{"source":"$source","destination":"$destination","at":{"$subtract":["$rows.at",{"$mod":["$rows.at",step*1000]}]}},"direct":{"$sum":"$rows.direct_bytes"},"relay":{"$sum":"$rows.relay_bytes"},"received_direct":{"$sum":"$rows.received_direct"},"received_relay":{"$sum":"$rows.received_relay"},"receiver_only":{"$max":{"$gt":["$rows.fallback_count",0]}},"duration":{"$sum":"$rows.duration_seconds"},"observed_at":{"$max":"$rows.observed_at"},"received_at":{"$max":"$received_at"}}},
        doc! {"$sort":{"_id.at":1}},
        doc! {"$group":{"_id":{"source":"$_id.source","destination":"$_id.destination"},"direct":{"$sum":"$direct"},"relay":{"$sum":"$relay"},"receiver_only":{"$max":"$receiver_only"},"received_at":{"$max":"$received_at"},"points":{"$push":{"at":"$_id.at","direct_bytes":"$direct","relay_bytes":"$relay","received_direct":"$received_direct","received_relay":"$received_relay","receiver_only":"$receiver_only","duration_seconds":"$duration","observed_at":"$observed_at"}}}},
        doc! {"$limit":4097},
    ]
}

fn paged_pipeline(
    workspace: ObjectId,
    ids: &[String],
    array: &str,
    start: i64,
    end: i64,
    step: i64,
    machine_peers: Option<&[String]>,
    selected: Option<(&str, &str)>,
) -> Vec<Document> {
    let mut pipeline = history_pipeline(workspace, ids, array, start, end, step, machine_peers);
    pipeline.truncate(4); // one pass through the bounded canonical day cells
    let summary = doc! {"$group":{"_id":{"source":"$_id.source","destination":"$_id.destination"},"direct":{"$sum":"$direct"},"relay":{"$sum":"$relay"},"receiver_only":{"$max":"$receiver_only"},"received_at":{"$max":"$received_at"}}};
    let account = vec![
        doc! {"$group":{"_id":"$_id.at","direct":{"$sum":"$direct"},"relay":{"$sum":"$relay"},"received_direct":{"$sum":"$received_direct"},"received_relay":{"$sum":"$received_relay"}}},
        doc! {"$sort":{"_id":1}},
    ];
    let selected = if let Some((source, destination)) = selected {
        vec![
            doc! {"$match":{"_id.source":source,"_id.destination":destination}},
            doc! {"$sort":{"_id.at":1}},
            doc! {"$group":{"_id":{"source":"$_id.source","destination":"$_id.destination"},"points":{"$push":{"at":"$_id.at","direct_bytes":"$direct","relay_bytes":"$relay","coverage":{"$cond":["$receiver_only","receiver_only","sender_reported"]}}}}},
        ]
    } else {
        vec![doc! {"$match":{"_id":{"$exists":false}}}]
    };
    pipeline.push(
        doc! {"$facet":{"flows":[summary,{"$limit":4097}],"points":account,"selected":selected}},
    );
    pipeline
}

async fn series(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<Selection>,
) -> ApiResult<Json<Value>> {
    let _life = app.account_lifecycle.read().await;
    let user = crate::auth::current_user(&app, &headers).await?;
    let workspace = user
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())?;
    if query.page == 0
        || query.page > 100_000
        || query.search.chars().count() > 128
        || query.source_peer_id.is_some() != query.destination_peer_id.is_some()
    {
        return Err(ApiError::bad_request("Invalid private traffic selection"));
    }
    if query
        .source_peer_id
        .iter()
        .chain(query.destination_peer_id.iter())
        .any(|p| !porthub_mesh::traffic_report::peer_id(p))
    {
        return Err(ApiError::bad_request("Invalid private traffic pair"));
    }
    let (array, span, step) = range(&query.range)
        .ok_or_else(|| ApiError::bad_request("Invalid private traffic range"))?;
    let machine = query
        .machine_id
        .as_ref()
        .map(|m| crate::domain::workspaces::object_id(m, "Invalid machine id"))
        .transpose()?;
    let (peers, inventory) = crate::routes::private_sync::active(&app, workspace).await?;
    let ids: Vec<_> = peers
        .iter()
        .filter_map(|p| p.get_str("_id").ok())
        .map(str::to_owned)
        .collect();
    let selected: Vec<_> = peers
        .iter()
        .filter(|p| machine.is_some_and(|m| p.get_object_id("machine_id") == Ok(m)))
        .filter_map(|p| p.get_str("_id").ok().map(str::to_owned))
        .collect();
    let machine_peers = machine.map(|_| selected.as_slice());
    let metadata: HashMap<_, _> = peers
        .iter()
        .filter_map(|p| {
            let id = p.get_str("_id").ok()?;
            let m = p.get_object_id("machine_id").ok()?;
            let row = inventory.get(&m.to_hex())?;
            let name = store::string(row, "name");
            let hostname = store::string(row, "hostname");
            Some((
                id.to_owned(),
                (
                    m,
                    if !name.is_empty() {
                        name.to_owned()
                    } else if !hostname.is_empty() {
                        hostname.to_owned()
                    } else {
                        "Unnamed machine".to_owned()
                    },
                ),
            ))
        })
        .collect();
    let now = DateTime::now();
    let end = now.timestamp_millis().div_euclid(step * 1000) * step * 1000;
    let start = end - span * 1000 + step * 1000;
    let collection = app.collection(COLLECTION);
    let response: Vec<Document> = collection
        .aggregate(paged_pipeline(
            workspace,
            &ids,
            array,
            start,
            end + step * 1000,
            step,
            machine_peers,
            query
                .source_peer_id
                .as_deref()
                .zip(query.destination_peer_id.as_deref()),
        ))
        .max_time(Duration::from_secs(2))
        .await?
        .try_collect()
        .await?;
    let response = response.first().cloned().unwrap_or_default();
    let documents: Vec<_> = response
        .get_array("flows")
        .into_iter()
        .flatten()
        .filter_map(Bson::as_document)
        .cloned()
        .collect();
    if documents.len() > 4096 {
        return Err(ApiError::bad_request(
            "Private traffic query has too many directed pairs; select a machine",
        ));
    }

    // Fetch recent native minute evidence only for the visible40 summaries and
    // selected pair. Historical account totals never depend on pagination.
    let search = query.search.trim().to_lowercase();
    let mut ranked: Vec<_> = documents
        .iter()
        .filter_map(|d| {
            let id = d.get_document("_id").ok()?;
            let source = id.get_str("source").ok()?;
            let destination = id.get_str("destination").ok()?;
            let src = metadata.get(source)?;
            let dst = metadata.get(destination)?;
            let volume = number(d, "direct").saturating_add(number(d, "relay"));
            (volume > 0
                && (search.is_empty()
                    || format!("{} {}", src.1, dst.1)
                        .to_lowercase()
                        .contains(&search)))
            .then_some((volume, source, destination))
        })
        .collect();
    ranked.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.cmp(b.1))
            .then_with(|| a.2.cmp(b.2))
    });
    let mut rate_pairs: Vec<_> = ranked
        .into_iter()
        .skip((query.page - 1) * 40)
        .take(40)
        .map(|(_, s, d)| doc! {"source":s,"destination":d})
        .collect();
    if let Some((s, d)) = query
        .source_peer_id
        .as_deref()
        .zip(query.destination_peer_id.as_deref())
    {
        if metadata.contains_key(s) && metadata.contains_key(d) {
            rate_pairs.push(doc! {"source":s,"destination":d});
        }
    }
    let minute = now.timestamp_millis().div_euclid(60_000) * 60_000;
    let recent_docs: Vec<Document> = if rate_pairs.is_empty() {
        Vec::new()
    } else {
        let mut pipeline = history_pipeline(
            workspace,
            &ids,
            "minutes",
            minute - 60_000,
            minute + 60_000,
            60,
            machine_peers,
        );
        pipeline.insert(1, doc! {"$match":{"$or":rate_pairs}});
        collection
            .aggregate(pipeline)
            .max_time(Duration::from_secs(2))
            .await?
            .try_collect()
            .await?
    };
    let mut recent = HashMap::new();
    for doc in recent_docs {
        if let Ok(id) = doc.get_document("_id") {
            if let (Ok(source), Ok(destination)) = (id.get_str("source"), id.get_str("destination"))
            {
                if let Some(row) = doc
                    .get_array("points")
                    .ok()
                    .and_then(|rows| rows.last())
                    .and_then(Bson::as_document)
                {
                    let observed = row.get_i64("observed_at").unwrap_or(0);
                    let duration = number(row, "duration_seconds");
                    if duration > 0
                        && observed >= now.timestamp_millis() - 90_000
                        && observed <= now.timestamp_millis() + 120_000
                    {
                        recent.insert(
                            (source.to_owned(), destination.to_owned()),
                            (
                                (number(row, "direct_bytes") + number(row, "relay_bytes")) as f64
                                    / duration as f64,
                                duration,
                                observed,
                            ),
                        );
                    }
                }
            }
        }
    }
    let mut points: BTreeMap<i64, [u64; 4]> = BTreeMap::new();
    for row in response
        .get_array("points")
        .into_iter()
        .flatten()
        .filter_map(Bson::as_document)
    {
        if let Ok(at) = row.get_i64("_id") {
            points.insert(
                at,
                [
                    number(row, "direct"),
                    number(row, "relay"),
                    number(row, "received_direct"),
                    number(row, "received_relay"),
                ],
            );
        }
    }

    let mut flows = Vec::new();
    for doc in documents {
        let Ok(id) = doc.get_document("_id") else {
            continue;
        };
        let (Ok(source), Ok(destination)) = (id.get_str("source"), id.get_str("destination"))
        else {
            continue;
        };
        let (Some(src), Some(dst)) = (metadata.get(source), metadata.get(destination)) else {
            continue;
        };
        let direct = number(&doc, "direct");
        let relay = number(&doc, "relay");
        if direct == 0 && relay == 0 {
            continue;
        }
        let rate = recent.get(&(source.to_owned(), destination.to_owned()));
        flows.push(json!({"source_peer_id":source,"destination_peer_id":destination,"source_machine_id":src.0.to_hex(),"destination_machine_id":dst.0.to_hex(),"source_name":src.1,"destination_name":dst.1,"direct_bytes":direct,"relay_bytes":relay,"total_bytes":direct+relay,"bytes_per_second":(direct+relay)as f64/span as f64,"recent_bytes_per_second":rate.map(|v|v.0),"recent_interval_seconds":rate.map_or(60,|v|v.1),"rate_at":rate.map(|v|v.2),"rate_stale":rate.is_none(),"latest_report_at":doc.get_datetime("received_at").map_or(0,|d|d.timestamp_millis()),"coverage":if doc.get_bool("receiver_only")==Ok(true){"receiver_only"}else{"sender_reported"}}));
    }
    for flow in &flows {
        for key in ["direct_bytes", "relay_bytes", "total_bytes"] {
            if flow[key]
                .as_u64()
                .is_none_or(|v| v > porthub_mesh::traffic_report::MAX_COUNTER)
            {
                return Err(ApiError::bad_request(
                    "Private traffic exceeds exact display counter capacity",
                ));
            }
        }
    }
    for value in points.values() {
        if value
            .iter()
            .any(|v| *v > porthub_mesh::traffic_report::MAX_COUNTER)
        {
            return Err(ApiError::bad_request(
                "Private traffic exceeds exact display counter capacity",
            ));
        }
    }

    let total_direct = flows
        .iter()
        .map(|f| f["direct_bytes"].as_u64().unwrap_or(0))
        .try_fold(0_u64, |a, b| a.checked_add(b))
        .ok_or_else(|| {
            ApiError::bad_request("Private traffic exceeds exact display counter capacity")
        })?;
    let total_relay = flows
        .iter()
        .map(|f| f["relay_bytes"].as_u64().unwrap_or(0))
        .try_fold(0_u64, |a, b| a.checked_add(b))
        .ok_or_else(|| {
            ApiError::bad_request("Private traffic exceeds exact display counter capacity")
        })?;
    let total = total_direct
        .checked_add(total_relay)
        .filter(|v| *v <= porthub_mesh::traffic_report::MAX_COUNTER)
        .ok_or_else(|| {
            ApiError::bad_request("Private traffic exceeds exact display counter capacity")
        })?;
    let mut selected_flow = Value::Null;
    if let Some((source, destination)) = query
        .source_peer_id
        .as_deref()
        .zip(query.destination_peer_id.as_deref())
    {
        if let Some(flow) = flows
            .iter()
            .find(|f| f["source_peer_id"] == source && f["destination_peer_id"] == destination)
        {
            if let Some(selected) = response
                .get_array("selected")
                .ok()
                .and_then(|a| a.first())
                .and_then(Bson::as_document)
            {
                selected_flow = flow.clone();
                selected_flow["points"] = json!(selected
                    .get_array("points")
                    .into_iter()
                    .flatten()
                    .map(|r| store::json(r))
                    .collect::<Vec<_>>());
            }
        }
    }
    let total_pairs = flows.len();
    let search = query.search.trim().to_lowercase();
    flows.retain(|f| {
        search.is_empty()
            || format!(
                "{} {}",
                f["source_name"].as_str().unwrap_or(""),
                f["destination_name"].as_str().unwrap_or("")
            )
            .to_lowercase()
            .contains(&search)
    });
    flows.sort_by(|a, b| {
        b["total_bytes"]
            .as_u64()
            .cmp(&a["total_bytes"].as_u64())
            .then_with(|| {
                a["source_peer_id"]
                    .as_str()
                    .cmp(&b["source_peer_id"].as_str())
            })
            .then_with(|| {
                a["destination_peer_id"]
                    .as_str()
                    .cmp(&b["destination_peer_id"].as_str())
            })
    });
    let filtered_pairs = flows.len();
    let flows: Vec<_> = flows
        .into_iter()
        .skip((query.page - 1) * 40)
        .take(40)
        .collect();
    let reported = peers
        .iter()
        .filter(|p| {
            p.get_datetime("traffic_reported_at")
                .is_ok_and(|t| t.timestamp_millis() >= now.timestamp_millis() - 90_000)
        })
        .count();
    let dropped: u64 = peers
        .iter()
        .map(|p| number(p, "traffic_dropped_rows"))
        .sum();
    let rejected: u64 = peers
        .iter()
        .map(|p| number(p, "traffic_rejected_rows"))
        .sum();
    let points:Vec<_>=points.into_iter().map(|(at,v)|json!({"at":at,"direct_sent":v[0],"relay_sent":v[1],"direct_received":v[2],"relay_received":v[3]})).collect();
    Ok(Json(
        json!({"range":query.range,"start":start,"end":end,"interval_seconds":step,"points":points,"flows":flows,"selected_flow":selected_flow,"totals":{"direct_bytes":total_direct,"relay_bytes":total_relay,"total_bytes":total,"bytes_per_second":total as f64/span as f64},"pagination":{"page":query.page,"page_size":40,"total_pairs":total_pairs,"filtered_pairs":filtered_pairs},"coverage":{"reporting_peers":reported,"eligible_peers":peers.len(),"unreported_peers":peers.len()-reported,"dropped_rows":dropped,"discarded_rows":rejected,"history_incomplete":dropped>0||rejected>0},"scope":"private_peer_carrier_payload","total_scope":"sender primary per directed pair and native bucket; receiver-only fallback never added twice","path_scope":"successfully queued authenticated carrier payload; includes native stream retransmission/envelopes, excludes discovery/signaling/probes; queue acceptance is not socket delivery","retention":"24h minute,7d hour,30d day; bounded pending journal drops oldest observations explicitly"}),
    ))
}
