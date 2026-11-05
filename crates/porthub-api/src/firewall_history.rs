//! MongoDB owns traffic history. The isolated firewall supplies a bounded local
//! replay buffer over authenticated IPC; it never receives database credentials.
use crate::{firewall, inventory_traffic, App};
use anyhow::{ensure, Context, Result};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{self, doc, oid::ObjectId, Bson, DateTime, Document},
    options::IndexOptions,
    IndexModel,
};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::watch;
pub const COLLECTION: &str = "firewall_traffic";
pub const RETENTION_SECONDS: i64 = 3600;

pub async fn initialize(app: &App) -> Result<()> {
    app.collection(COLLECTION)
        .create_indexes([
            IndexModel::builder()
                .keys(doc! {"expires_at":1})
                .options(IndexOptions::builder().expire_after(Duration::ZERO).build())
                .build(),
            IndexModel::builder()
                .keys(doc! {"owner_id":1,"connection_id":1,"timestamp":1})
                .build(),
        ])
        .await?;
    Ok(())
}
/// Idempotent batches make retries and API restarts safe. Identity belongs to a
/// connection, not a recycled public port, so history cannot move between owners.
pub async fn persist(app: &App, record: &Document, samples: &[Value]) -> Result<()> {
    let connection = record.get_object_id("_id")?;
    let owner = record.get("user_id").context("traffic connection has no owner")?.clone();
    let created = record
        .get_datetime("created_at")
        .map(|time| time.timestamp_millis() / 1000)
        .unwrap_or_else(|_| connection.timestamp().timestamp_millis() / 1000);
    let now = DateTime::now().timestamp_millis() / 1000;
    let mut updates = Vec::new();
    for sample in inventory_traffic::normalize(samples) {
        let Some(timestamp) = sample["timestamp"]
            .as_u64()
            .and_then(|value| i64::try_from(value).ok())
        else {
            continue;
        };
        if timestamp < created || timestamp <= now - RETENTION_SECONDS || timestamp > now + 1 {
            continue;
        }
        let id = format!("{connection}:{timestamp}");
        let value = doc! {"owner_id":&owner,"connection_id":connection,"timestamp":timestamp,
        "expires_at":DateTime::from_millis((timestamp + RETENTION_SECONDS)*1000),"sample":bson::to_bson(&sample)?};
        // Upsert replaces overlapping measurements, rather than double-counting
        // them, and accepts corrected source-IP lists from the sampler.
        updates.push(doc! {"q":{"_id":id},"u":{"$set":value},"upsert":true});
    }
    for chunk in updates.chunks(128) {
        let reply = app
            .db
            .run_command(doc! {"update":COLLECTION,"updates":chunk.to_vec(),"ordered":false})
            .await?;
        ensure!(
            reply
                .get_array("writeErrors")
                .map_or(true, |errors| errors.is_empty())
                && !reply.contains_key("writeConcernError"),
            "traffic history write was not acknowledged"
        );
    }
    Ok(())
}
pub async fn read(
    app: &App,
    owner: &Bson,
    connections: &[ObjectId],
) -> Result<HashMap<String, Vec<Value>>> {
    if connections.is_empty() {
        return Ok(HashMap::new());
    }
    let cutoff = DateTime::now().timestamp_millis() / 1000 - RETENTION_SECONDS;
    let mut cursor = app
        .collection(COLLECTION)
        .find(
            doc! {"owner_id":owner,"connection_id":{"$in":connections},"timestamp":{"$gt":cutoff}},
        )
        .projection(doc! {"connection_id":1,"sample":1})
        .sort(doc! {"timestamp":1})
        .await?;
    let mut result = HashMap::<String, Vec<Value>>::new();
    while let Some(row) = cursor.try_next().await? {
        let id = row.get_object_id("connection_id")?.to_hex();
        if let Some(sample) = row.get("sample") {
            result
                .entry(id)
                .or_default()
                .push(bson::from_bson(sample.clone())?);
        }
    }
    Ok(result)
}
pub async fn collect(app: &App, since: i64) -> Result<()> {
    let client = app
        .firewall
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("firewall IPC is not configured"))?;
    let records = app
        .collection("connections")
        .find(doc! {})
        .projection(doc! {"_id":1,"user_id":1,"external_port":1,"created_at":1})
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    for chunk in records.chunks(4) {
        // Match mutation lock order. A removed/reassigned connection or retiring
        // account cannot have its history recreated by a delayed collection.
        let _lifecycle = app.account_lifecycle.read().await;
        let _connections = app.connection_lock.lock().await;
        let owners = crate::account_delete::retiring_owners(app)
            .await
            .map_err(|_| anyhow::anyhow!("account lifecycle unavailable"))?;
        let requested: Vec<_> = chunk
            .iter()
            .filter_map(|record| record.get_object_id("_id").ok())
            .collect();
        let current = app
            .collection("connections")
            .find(doc! {"_id":{"$in":requested},"user_id":{"$nin":owners}})
            .await?
            .try_collect::<Vec<_>>()
            .await?;
        let chunk = current.as_slice();
        let ports: Vec<_> = chunk.iter().filter_map(firewall::port).collect();
        if ports.is_empty() {
            continue;
        }
        let reply = client
            .request(
                reqwest::Method::POST,
                "/ports/traffic/snapshot",
                Some(json!({"ports":ports,"since":since})),
            )
            .await
            .map_err(|_| anyhow::anyhow!("firewall traffic IPC unavailable"))?;
        for record in chunk {
            let Some(port) = firewall::port(record) else {
                continue;
            };
            if let Some(samples) = reply[port.to_string()].as_array() {
                persist(app, record, samples).await?;
            }
        }
    }
    // Remove history of deleted connections without allowing port reuse to
    // resurrect it. TTL separately expires old timestamps even when idle.
    let _lifecycle = app.account_lifecycle.read().await;
    let _connections = app.connection_lock.lock().await;
    let current = app
        .collection("connections")
        .find(doc! {})
        .projection(doc! {"_id":1})
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    let ids: Vec<_> = current
        .iter()
        .filter_map(|record| record.get_object_id("_id").ok())
        .collect();
    app.collection(COLLECTION)
        .delete_many(doc! {"connection_id":{"$nin":ids}})
        .await?;
    Ok(())
}
pub async fn run(app: Arc<App>, mut stop: watch::Receiver<bool>) {
    let mut initialized = false;
    let mut since = 0;
    let mut backoff = 1;
    loop {
        let started = DateTime::now().timestamp_millis() / 1000;
        let work = async {
            if !initialized {
                initialize(&app).await?;
                initialized = true;
            }
            collect(&app, since).await
        };
        let succeeded = tokio::select! { biased; _ = stop.changed() => return,
            result = work => result.is_ok(),
        };
        let delay = if succeeded {
            since = (started - 5).max(0);
            backoff = 1;
            1
        } else {
            // Static diagnostics avoid including MongoDB credentials in errors.
            tracing::warn!(
                "MongoDB firewall traffic collection unavailable; retaining firewall replay buffer"
            );
            let delay = backoff;
            backoff = (backoff * 2).min(30);
            delay
        };
        tokio::select! { _ = stop.changed() => return, _ = tokio::time::sleep(Duration::from_secs(delay)) => {} }
    }
}
