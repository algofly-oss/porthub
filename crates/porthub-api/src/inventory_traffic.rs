//! Short-lived owner-scoped traffic read model. Firewall histories stay on the
//! server; inventory sorting never downloads an entire fleet into the browser.
use crate::{
    error::{ApiError, ApiResult},
    firewall, store, App,
};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};

type Histories = HashMap<String, (Instant, Arc<Snapshot>)>;
type Details = HashMap<String, (Instant, Arc<Vec<Value>>)>;
pub struct Cache(
    pub tokio::sync::Mutex<Histories>,
    pub tokio::sync::Mutex<Details>,
    tokio::sync::Mutex<HashMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>>,
    tokio::sync::Semaphore,
    tokio::sync::Mutex<SeriesCache>,
);
impl Default for Cache {
    fn default() -> Self {
        Self(
            Default::default(),
            Default::default(),
            Default::default(),
            tokio::sync::Semaphore::new(4),
            Default::default(),
        )
    }
}
async fn request_lock(cache: &Cache, key: String) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = cache.2.lock().await;
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&key).and_then(std::sync::Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}
#[derive(Default)]
pub struct Snapshot {
    pub ports: HashMap<String, Vec<Sample>>,
    pub machine_ports: HashMap<String, Vec<String>>,
    pub port_numbers: HashMap<String, i64>,
}
// Fixed-size numeric samples avoid retaining hundreds of thousands of JSON
// objects and repeated source-IP strings in every workspace's live cache.
#[derive(Clone, Copy, Default, Debug, PartialEq, Serialize)]
pub struct Sample {
    pub timestamp: u64,
    pub interval_seconds: f64,
    pub in_bytes: f64,
    pub out_bytes: f64,
    pub drop_bytes: f64,
    pub in_rate: f64,
    pub out_rate: f64,
    pub drop_rate: f64,
}
impl Sample {
    fn parse(value: &Value) -> Option<Self> {
        let timestamp = nonnegative(value.get("timestamp")).floor() as u64;
        if timestamp == 0 {
            return None;
        }
        let duration = nonnegative(value.get("interval_seconds"));
        let duration = if duration == 0. { 1. } else { duration };
        let bytes = |key: &str| nonnegative(value.get(key));
        let rate = |key: &str, count: f64| {
            value
                .get(key)
                .map(|v| nonnegative(Some(v)))
                .unwrap_or(count / duration)
        };
        Some(Self {
            timestamp,
            interval_seconds: duration,
            in_bytes: bytes("in_bytes"),
            out_bytes: bytes("out_bytes"),
            drop_bytes: bytes("drop_bytes"),
            in_rate: rate("in_rate", bytes("in_bytes")),
            out_rate: rate("out_rate", bytes("out_bytes")),
            drop_rate: rate("drop_rate", bytes("drop_bytes")),
        })
    }
    fn merge(&mut self, other: Self) {
        self.interval_seconds = self.interval_seconds.max(other.interval_seconds);
        self.in_bytes += other.in_bytes;
        self.out_bytes += other.out_bytes;
        self.drop_bytes += other.drop_bytes;
        self.in_rate += other.in_rate;
        self.out_rate += other.out_rate;
        self.drop_rate += other.drop_rate;
    }
}
pub fn aggregate(samples: impl IntoIterator<Item = Sample>) -> Vec<Sample> {
    let mut buckets = BTreeMap::<u64, Sample>::new();
    for sample in samples {
        buckets
            .entry(sample.timestamp)
            .or_insert(Sample {
                timestamp: sample.timestamp,
                ..Default::default()
            })
            .merge(sample);
    }
    buckets
        .into_values()
        .rev()
        .take(300)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}
pub fn numeric(samples: &[Value]) -> Vec<Sample> {
    aggregate(samples.iter().filter_map(Sample::parse))
}
fn numeric_volume(samples: &[Sample], sort: &str, seconds: f64, now: f64) -> f64 {
    samples
        .iter()
        .filter(|sample| {
            sample.timestamp as f64 > now - seconds && sample.timestamp as f64 <= now + 1.
        })
        .map(|sample| match sort {
            "incoming" => sample.in_bytes,
            "outgoing" => sample.out_bytes,
            "blocked" => sample.drop_bytes,
            _ => sample.in_bytes + sample.out_bytes,
        })
        .sum()
}
impl Snapshot {
    fn retained_bytes(&self) -> usize {
        self.ports
            .values()
            .map(|samples| samples.capacity() * std::mem::size_of::<Sample>())
            .sum::<usize>()
            + self.ports.len() * 256
    }
}
fn nonnegative(value: Option<&Value>) -> f64 {
    value
        .and_then(Value::as_f64)
        .filter(|n| n.is_finite())
        .unwrap_or(0.)
        .max(0.)
}
pub fn normalize(samples: &[Value]) -> Vec<Value> {
    let mut buckets = BTreeMap::<i64, Value>::new();
    for sample in samples {
        let timestamp = nonnegative(sample.get("timestamp")).floor() as i64;
        if timestamp <= 0 {
            continue;
        }
        let duration = nonnegative(sample.get("interval_seconds"));
        let duration = if duration == 0. { 1. } else { duration };
        let bucket=buckets.entry(timestamp).or_insert_with(||json!({"timestamp":timestamp,"interval_seconds":0,"in_bytes":0,"out_bytes":0,"drop_bytes":0,"in_rate":0,"out_rate":0,"drop_rate":0,"incoming_ips":[],"outgoing_ips":[],"blocked_ips":[]}));
        bucket["interval_seconds"] =
            json!(nonnegative(bucket.get("interval_seconds")).max(duration));
        for (bytes, rate) in [
            ("in_bytes", "in_rate"),
            ("out_bytes", "out_rate"),
            ("drop_bytes", "drop_rate"),
        ] {
            let count = nonnegative(sample.get(bytes));
            bucket[bytes] = json!(nonnegative(bucket.get(bytes)) + count);
            bucket[rate] = json!(
                nonnegative(bucket.get(rate))
                    + sample
                        .get(rate)
                        .map(|v| nonnegative(Some(v)))
                        .unwrap_or(count / duration)
            );
        }
        for key in ["incoming_ips", "outgoing_ips", "blocked_ips"] {
            let ips = bucket[key]
                .as_array()
                .into_iter()
                .flatten()
                .chain(sample[key].as_array().into_iter().flatten())
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|ip| !ip.is_empty())
                .collect::<BTreeSet<_>>();
            bucket[key] = json!(ips);
        }
    }
    buckets
        .into_values()
        .rev()
        .take(300)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}
pub fn volume(samples: &[Value], sort: &str, seconds: f64, now: f64) -> f64 {
    samples
        .iter()
        .filter(|s| {
            let time = nonnegative(s.get("timestamp"));
            time > now - seconds && time <= now + 1.
        })
        .map(|s| match sort {
            "incoming" => nonnegative(s.get("in_bytes")),
            "outgoing" => nonnegative(s.get("out_bytes")),
            "blocked" => nonnegative(s.get("drop_bytes")),
            _ => nonnegative(s.get("in_bytes")) + nonnegative(s.get("out_bytes")),
        })
        .sum()
}
impl Snapshot {
    pub fn revision<'a>(&self, ids: impl IntoIterator<Item = &'a str>) -> String {
        use sha2::{Digest, Sha256};
        let mut ids = ids.into_iter().collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        let mut hash = Sha256::new();
        for id in ids {
            hash.update(id.as_bytes());
            hash.update(
                self.port_numbers
                    .get(id)
                    .copied()
                    .unwrap_or(0)
                    .to_be_bytes(),
            );
        }
        format!("{:x}", hash.finalize())
    }
    pub fn watermark<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a str>,
        seconds: f64,
        now: f64,
    ) -> Option<u64> {
        ids.into_iter()
            .filter_map(|id| self.ports.get(id)?.last())
            .map(|sample| sample.timestamp)
            .filter(|time| *time as f64 > now - seconds && *time as f64 <= now + 1.)
            .min()
    }
    pub fn metric(
        &self,
        kind: &str,
        record: &mongodb::bson::Document,
        sort: &str,
        seconds: f64,
        now: f64,
    ) -> f64 {
        let ids = if kind == "machines" {
            self.machine_ports
                .get(&store::id(record.get("_id")))
                .cloned()
                .unwrap_or_default()
        } else if kind == "proxies" {
            // Preserve the established proxy traffic meaning: its primary machine port.
            record
                .get_document("connection")
                .ok()
                .map(|c| vec![store::string(c, "data_id").to_owned()])
                .unwrap_or_default()
        } else {
            vec![store::id(record.get("_id"))]
        };
        ids.iter()
            .filter_map(|id| self.ports.get(id))
            .map(|samples| numeric_volume(samples, sort, seconds, now))
            .sum()
    }
}
fn cached(
    cache: &Histories,
    key: &str,
    owner: &str,
    connections: Option<&[ObjectId]>,
) -> Option<Arc<Snapshot>> {
    cache
        .iter()
        .filter(|(candidate, (time, snapshot))| {
            time.elapsed() < Duration::from_secs(2)
                && (candidate.as_str() == owner
                    || candidate.as_str() == key
                    || connections.is_some_and(|ids| {
                        candidate.starts_with(&format!("{owner}:"))
                            && ids
                                .iter()
                                .all(|id| snapshot.ports.contains_key(&id.to_hex()))
                    }))
        })
        .max_by_key(|(_, (time, _))| *time)
        .map(|(_, (_, snapshot))| snapshot.clone())
}
pub async fn snapshot(app: &App, owner: &Bson) -> ApiResult<Arc<Snapshot>> {
    load(app, owner, None).await
}
pub async fn connections(app: &App, owner: &Bson, ids: Vec<ObjectId>) -> ApiResult<Arc<Snapshot>> {
    if ids.is_empty() {
        return Ok(Arc::new(Snapshot::default()));
    }
    load(app, owner, Some(("_id", ids))).await
}
pub async fn machines(app: &App, owner: &Bson, ids: Vec<ObjectId>) -> ApiResult<Arc<Snapshot>> {
    if ids.is_empty() {
        return Ok(Arc::new(Snapshot::default()));
    }
    load(app, owner, Some(("machine_id", ids))).await
}
async fn load(
    app: &App,
    owner: &Bson,
    mut selection: Option<(&str, Vec<ObjectId>)>,
) -> ApiResult<Arc<Snapshot>> {
    use sha2::{Digest, Sha256};
    let owner_key = store::id(Some(owner));
    let mut filter = doc! {"user_id":owner};
    let key = if let Some((field, ids)) = selection.as_mut() {
        ids.sort_unstable();
        ids.dedup();
        filter.insert(*field, doc! {"$in":&*ids});
        format!(
            "{owner_key}:{field}:{:x}",
            Sha256::digest(ids.iter().flat_map(|id| id.bytes()).collect::<Vec<_>>())
        )
    } else {
        owner_key.clone()
    };
    let selected_connections = selection
        .as_ref()
        .filter(|(field, _)| *field == "_id")
        .map(|(_, ids)| ids.as_slice());
    {
        let cache = app.inventory_traffic.0.lock().await;
        if let Some(snapshot) = cached(&cache, &key, &owner_key, selected_connections) {
            return Ok(snapshot);
        }
    }
    let lock = request_lock(&app.inventory_traffic, format!("snapshot:{owner_key}")).await;
    let _guard = lock.lock().await;
    {
        let cache = app.inventory_traffic.0.lock().await;
        if let Some(snapshot) = cached(&cache, &key, &owner_key, selected_connections) {
            return Ok(snapshot);
        }
    }
    let _permit = app.inventory_traffic.3.acquire().await.map_err(|_| {
        ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Traffic reader unavailable",
        )
    })?;
    let records = app
        .collection("connections")
        .find(filter)
        .projection(doc! {"_id":1,"machine_id":1,"external_port":1})
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    let ports = records
        .iter()
        .filter_map(firewall::port)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut by_port = HashMap::<i64, Vec<Sample>>::new();
    if let Some(client) = app.firewall.as_ref() {
        // The IPC client deliberately caps a response at 16 MiB. A whole fleet's
        // five-minute history can exceed that; each read stays bounded instead.
        for chunk in ports.chunks(64) {
            let histories = client
                .request(
                    reqwest::Method::POST,
                    "/ports/traffic/snapshot",
                    Some(json!({"ports":chunk})),
                )
                .await?;
            for port in chunk {
                let samples = histories[port.to_string()]
                    .as_array()
                    .map(|rows| numeric(rows))
                    .unwrap_or_default();
                by_port.insert(*port, samples);
            }
        }
    }
    let mut snapshot = Snapshot::default();
    for record in records {
        let id = store::id(record.get("_id"));
        let samples = firewall::port(&record)
            .and_then(|port| by_port.remove(&port))
            .unwrap_or_default();
        snapshot
            .machine_ports
            .entry(store::id(record.get("machine_id")))
            .or_default()
            .push(id.clone());
        snapshot
            .port_numbers
            .insert(id.clone(), firewall::port(&record).unwrap_or_default());
        snapshot.ports.insert(id, samples);
    }
    let mut cache = app.inventory_traffic.0.lock().await;
    cache.retain(|_, (time, _)| time.elapsed() < Duration::from_secs(30));
    cache.remove(&key);
    const LIMIT: usize = 64 * 1024 * 1024;
    let bytes = snapshot.retained_bytes();
    while !cache.is_empty()
        && (cache.len() >= 16
            || cache
                .values()
                .map(|(_, snapshot)| snapshot.retained_bytes())
                .sum::<usize>()
                + bytes
                > LIMIT)
    {
        let oldest = cache
            .iter()
            .min_by_key(|(_, (time, _))| *time)
            .map(|(id, _)| id.clone())
            .unwrap();
        cache.remove(&oldest);
    }
    let snapshot = Arc::new(snapshot);
    if bytes <= LIMIT {
        cache.insert(key, (Instant::now(), snapshot.clone()));
    }
    Ok(snapshot)
}
// IP detail is requested only for the explicitly expanded, currently owned row.
pub async fn expanded(
    app: &App,
    owner: &Bson,
    record: &mongodb::bson::Document,
) -> ApiResult<Arc<Vec<Value>>> {
    let port = firewall::port(record).unwrap_or_default();
    let key = format!(
        "{}:{}:{port}",
        store::id(Some(owner)),
        store::id(record.get("_id"))
    );
    let lock = request_lock(&app.inventory_traffic, format!("detail:{key}")).await;
    let _guard = lock.lock().await;
    {
        let cache = app.inventory_traffic.1.lock().await;
        if let Some((time, rows)) = cache.get(&key) {
            if time.elapsed() < Duration::from_secs(2) {
                return Ok(rows.clone());
            }
        }
    }
    let _permit = app.inventory_traffic.3.acquire().await.map_err(|_| {
        ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Traffic reader unavailable",
        )
    })?;
    let data = if let Some(client) = app.firewall.as_ref() {
        client
            .request(
                reqwest::Method::POST,
                "/ports/traffic/snapshot",
                Some(json!({"ports":[port]})),
            )
            .await?
    } else {
        json!({})
    };
    let rows = Arc::new(
        data[port.to_string()]
            .as_array()
            .map(|samples| normalize(samples))
            .unwrap_or_default(),
    );
    let mut cache = app.inventory_traffic.1.lock().await;
    cache.retain(|_, (time, _)| time.elapsed() < Duration::from_secs(2));
    if cache.len() >= 16 {
        if let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, (time, _))| *time)
            .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest);
        }
    }
    // A large IP sample can be shown without retaining it across requests.
    let size = rows.len() * 1024
        + serde_json::to_vec(&*rows)
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX / 2);
    if size <= 512 * 1024 {
        cache.insert(key, (Instant::now(), rows.clone()));
    }
    Ok(rows)
}
#[derive(Default)]
struct SeriesCache {
    frames: HashMap<String, SeriesFrame>,
    bytes: usize,
}
struct SeriesFrame {
    context: String,
    samples: Arc<Vec<Sample>>,
    used: Instant,
}
pub struct SeriesDelta {
    pub points: Vec<Sample>,
    pub removed: Vec<u64>,
    pub token: String,
    pub replace: bool,
}
// Content-addressed bases allow exact corrections to older aggregate buckets
// after chunked reads. A timestamp alone cannot identify partially aggregated
// seconds. Evicted bases safely fall back to a complete bounded series.
pub async fn series_delta(
    app: &App,
    context: String,
    previous: &str,
    samples: &[Sample],
) -> SeriesDelta {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(context.as_bytes());
    for sample in samples {
        digest.update(sample.timestamp.to_be_bytes());
        for value in [
            sample.interval_seconds,
            sample.in_bytes,
            sample.out_bytes,
            sample.drop_bytes,
            sample.in_rate,
            sample.out_rate,
            sample.drop_rate,
        ] {
            digest.update(value.to_bits().to_be_bytes());
        }
    }
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest.finalize()[..16]);
    let mut cache = app.inventory_traffic.4.lock().await;
    let old = cache
        .frames
        .get_mut(previous)
        .filter(|frame| frame.context == context)
        .map(|frame| {
            frame.used = Instant::now();
            frame.samples.clone()
        });
    let replace = old.is_none();
    let by_time = old
        .as_ref()
        .map(|samples| {
            samples
                .iter()
                .map(|sample| (sample.timestamp, sample))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    let points = samples
        .iter()
        .filter(|sample| {
            by_time
                .get(&sample.timestamp)
                .is_none_or(|old| **old != **sample)
        })
        .copied()
        .collect();
    let times = samples
        .iter()
        .map(|sample| sample.timestamp)
        .collect::<BTreeSet<_>>();
    let removed = old
        .iter()
        .flat_map(|samples| samples.iter())
        .filter(|sample| !times.contains(&sample.timestamp))
        .map(|sample| sample.timestamp)
        .collect();
    if let Some(frame) = cache.frames.get_mut(&token) {
        frame.used = Instant::now();
    } else {
        cache.bytes += samples.len() * std::mem::size_of::<Sample>();
        cache.frames.insert(
            token.clone(),
            SeriesFrame {
                context,
                samples: Arc::new(samples.to_vec()),
                used: Instant::now(),
            },
        );
    }
    while cache.frames.len() > 512 || cache.bytes > 8 * 1024 * 1024 {
        if let Some(key) = cache
            .frames
            .iter()
            .min_by_key(|(_, frame)| frame.used)
            .map(|(key, _)| key.clone())
        {
            if let Some(frame) = cache.frames.remove(&key) {
                cache.bytes = cache
                    .bytes
                    .saturating_sub(frame.samples.len() * std::mem::size_of::<Sample>());
            }
        } else {
            break;
        }
    }
    SeriesDelta {
        points,
        removed,
        token,
        replace,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merges_directions_without_adding_overlapping_coverage() {
        let rows = normalize(&[
            json!({"timestamp":100,"in_bytes":40,"interval_seconds":2,"incoming_ips":["192.0.2.1"]}),
            json!({"timestamp":100,"out_bytes":10,"interval_seconds":2}),
        ]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["interval_seconds"], 2.);
        assert_eq!(rows[0]["in_rate"], 20.);
        assert_eq!(rows[0]["out_rate"], 5.);
        assert_eq!(volume(&rows, "traffic", 30., 101.), 50.);
        assert_eq!(volume(&rows, "incoming", 30., 131.), 0.);
    }
}
