use crate::{kernel::Kernel, store::Store, Policy, Sample};
use anyhow::Result;
use axum::{
    extract::{Path, Query, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::Path as FilePath,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{watch, Mutex};

struct KernelState {
    kernel: Kernel,
    policies: BTreeMap<u16, Policy>,
}
pub struct Service {
    live: watch::Sender<Arc<Value>>,
    state: Mutex<KernelState>,
    store: Store,
    key: String,
}
impl Service {
    pub async fn new(database: &FilePath, table: &str, key: String) -> Result<Arc<Self>> {
        anyhow::ensure!(
            key.len() >= 16,
            "firewall API key must have at least 16 characters"
        );
        let store = Store::open(database).await?;
        let policies = store.policies().await?;
        let kernel = Kernel::new(table, Duration::from_secs(300))?;
        kernel.apply(&policies).await?;
        let (live, _) = watch::channel(Arc::new(json!({})));
        Ok(Arc::new(Self {
            live,
            state: Mutex::new(KernelState { kernel, policies }),
            store,
            key,
        }))
    }
    async fn change(&self, port: u16, policy: Option<Policy>) -> Result<()> {
        anyhow::ensure!(port > 0, "invalid firewall port");
        let mut state = self.state.lock().await;
        let previous = state.policies.get(&port).cloned();
        let mut candidate = state.policies.clone();
        if let Some(policy) = &policy {
            candidate.insert(port, policy.clone());
        } else {
            candidate.remove(&port);
        }
        crate::kernel::rules(&candidate, "porthub", Duration::from_secs(300))?;
        // Persist before applying. A crash restarts from the intended policy.
        // Netlink applies atomically; refusal restores the persisted old state.
        self.store.policy(port, policy).await?;
        if let Err(error) = state.kernel.apply(&candidate).await {
            self.store.policy(port, previous).await?;
            return Err(error);
        }
        state.policies = candidate;
        Ok(())
    }
    pub async fn sample(self: Arc<Self>, mut stop: watch::Receiver<bool>) -> Result<()> {
        let mut baseline: BTreeMap<u16, ([u64; 3], Instant)> = BTreeMap::new();
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {_=stop.changed()=>return Ok(()),_=timer.tick()=>{}}
            let state = self.state.lock().await;
            baseline.retain(|port, _| state.policies.contains_key(port));
            if state.policies.is_empty() {
                continue;
            }
            let totals = state.kernel.counters().await?;
            let now = Instant::now();
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
            let mut samples = Vec::new();
            let mut next = baseline.clone();
            for &port in state.policies.keys() {
                let counters = ["in", "out", "drop"].map(|direction| {
                    totals
                        .get(&format!("cnt_{direction}_{port}"))
                        .copied()
                        .unwrap_or(0)
                });
                if let Some((last, at)) = baseline.get(&port) {
                    let delta = std::array::from_fn::<_, 3, _>(|i| {
                        counters[i].saturating_sub(last[i]).min(i64::MAX as u64) as i64
                    });
                    let interval = now.duration_since(*at).as_secs_f64().max(0.001);
                    let window = Duration::from_secs_f64((interval + 1.).max(2.));
                    let mut ips: [Vec<String>; 3] = Default::default();
                    for (i, direction) in ["in", "out", "drop"].iter().enumerate() {
                        if delta[i] > 0 {
                            ips[i] = state.kernel.recent(port, direction, window).await?;
                        }
                    }
                    let [incoming_ips, outgoing_ips, blocked_ips] = ips;
                    samples.push((
                        port,
                        Sample {
                            timestamp,
                            interval_seconds: interval,
                            in_bytes: delta[0],
                            out_bytes: delta[1],
                            drop_bytes: delta[2],
                            incoming_ips,
                            outgoing_ips,
                            blocked_ips,
                        },
                    ));
                }
                next.insert(port, (counters, now));
            }
            if !samples.is_empty() {
                let latest = samples
                    .iter()
                    .map(|(port, sample)| (port.to_string(), json!(sample)))
                    .collect::<serde_json::Map<_, _>>();
                self.store.record(samples).await?;
                self.live.send_replace(Arc::new(Value::Object(latest)));
            }
            drop(state);
            baseline = next;
        }
    }
}
fn fail(error: impl std::fmt::Display) -> Response {
    tracing::error!(%error,"firewall operation failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"detail":"Internal Server Error"})),
    )
        .into_response()
}
async fn authenticate(
    State(service): State<Arc<Service>>,
    request: Request,
    next: Next,
) -> Response {
    let actual = request
        .headers()
        .get("x-api-key")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    use subtle::ConstantTimeEq;
    if actual.as_bytes().ct_eq(service.key.as_bytes()).unwrap_u8() != 1 {
        return (StatusCode::FORBIDDEN, Json(json!({"detail":"Forbidden"}))).into_response();
    }
    next.run(request).await
}
async fn policy(State(service): State<Arc<Service>>, Path(port): Path<u16>) -> Json<Value> {
    let state = service.state.lock().await;
    let policy = state.policies.get(&port).cloned().unwrap_or(Policy {
        is_public: true,
        allowed_ips: vec![],
    });
    Json(
        json!({"msg":"Port policy fetched successfully","data":{"port":port,"is_public":policy.is_public,"allowed_ips":policy.allowed_ips}}),
    )
}
async fn update(
    State(service): State<Arc<Service>>,
    Path(port): Path<u16>,
    Json(policy): Json<Policy>,
) -> Response {
    if port == 0
        || policy.allowed_ips.len() > 4096
        || policy.is_public && !policy.allowed_ips.is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"detail":"Invalid port policy"})),
        )
            .into_response();
    }
    match service.change(port,Some(policy.clone())).await {
        Ok(())=>Json(json!({"msg":"Port policy updated successfully","data":{"port":port,"is_public":policy.is_public,"allowed_ips":policy.allowed_ips}})).into_response(),Err(error)=>fail(error),
    }
}
async fn delete(State(service): State<Arc<Service>>, Path(port): Path<u16>) -> Response {
    match service.change(port,None).await {
        Ok(())=>Json(json!({"msg":"Port policy deleted successfully","data":{"port":port,"is_public":true,"allowed_ips":[]}})).into_response(),Err(error)=>fail(error),
    }
}
async fn purge_history(State(service): State<Arc<Service>>, Path(port): Path<u16>) -> Response {
    let state=service.state.lock().await;
    if state.policies.contains_key(&port) {
        return (StatusCode::CONFLICT, Json(json!({"detail":"Remove the port policy before purging its history"}))).into_response();
    }
    match service.store.purge(port).await {
        Ok(())=>{
            service.live.send_modify(|snapshot| {
                let mut value=(**snapshot).clone();
                if let Some(object)=value.as_object_mut(){object.remove(&port.to_string());}
                *snapshot=Arc::new(value);
            });
            Json(json!({"data":{"port":port}})).into_response()
        },
        Err(error)=>fail(error),
    }
}
async fn list(State(service): State<Arc<Service>>) -> Json<Value> {
    let state = service.state.lock().await;
    Json(
        json!({"msg":"Port policies listed successfully","data":state.policies.iter().map(|(&port,policy)|json!({"port":port,"is_public":policy.is_public,"allowed_ips":policy.allowed_ips})).collect::<Vec<_>>()}),
    )
}
#[derive(Deserialize)]
struct Snapshot {
    #[serde(default)]
    ports: Vec<u16>,
}
async fn snapshot(State(service): State<Arc<Service>>, Json(body): Json<Snapshot>) -> Response {
    match service.store.snapshot(body.ports).await {
        Ok(data) => {
            Json(json!({"msg":"Traffic snapshot fetched successfully","data":data})).into_response()
        }
        Err(error) => fail(error),
    }
}
async fn active(State(service): State<Arc<Service>>) -> Response {
    match service.store.active().await {
        Ok(data) => {
            Json(json!({"msg":"Active ports listed successfully","data":data})).into_response()
        }
        Err(error) => fail(error),
    }
}
#[derive(Deserialize)]
struct Limit {
    #[serde(default = "default_limit")]
    limit: u16,
}
fn default_limit() -> u16 {
    10
}
async fn hits(
    State(service): State<Arc<Service>>,
    Path(port): Path<u16>,
    Query(query): Query<Limit>,
) -> Response {
    if !(1..=50).contains(&query.limit) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match service.store.hits(port, query.limit).await {
        Ok(data) => {
            Json(json!({"msg":"Recent IP hits fetched successfully","data":data})).into_response()
        }
        Err(error) => fail(error),
    }
}
async fn live(
    State(service): State<Arc<Service>>,
    upgrade: axum::extract::ws::WebSocketUpgrade,
) -> Response {
    let mut changes = service.live.subscribe();
    upgrade.on_upgrade(move |mut socket|async move {
        loop {
            tokio::select! {
                event=socket.recv()=>match event {
                    Some(Ok(axum::extract::ws::Message::Close(_)))|None|Some(Err(_))=>break,
                    Some(Ok(axum::extract::ws::Message::Ping(data)))=>{
                        if socket.send(axum::extract::ws::Message::Pong(data)).await.is_err(){break}
                    },
                    _=>{},
                },
                result=changes.changed()=>{
                    if result.is_err(){break}
                    let data=changes.borrow_and_update().to_string();
                    if !matches!(tokio::time::timeout(Duration::from_secs(5),socket.send(axum::extract::ws::Message::Text(data.into()))).await,Ok(Ok(()))){break}
                },
            }
        }
    })
}

pub fn router(service: Arc<Service>) -> Router {
    Router::new()
        .route(
            "/api/ping",
            get(|| async { Json(json!({"msg":"pong","service":"firewall"})) }),
        )
        .route(
            "/api/ports/{port}/policy",
            get(policy).put(update).delete(delete),
        )
        .route("/api/ports/{port}/history", axum::routing::delete(purge_history))
        .route("/api/ports/policies/list", get(list))
        .route("/api/ports/active", get(active))
        .route("/api/ports/{port}/recent-ip-hits", get(hits))
        .route("/api/ports/traffic/snapshot", post(snapshot))
        .route("/api/ports/traffic/ws", get(live))
        .layer(axum::middleware::from_fn_with_state(
            service.clone(),
            authenticate,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(512 * 1024))
        .with_state(service)
}
