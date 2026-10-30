//! Health-aware upstream selection. Configuration is immutable; health and
//! counters survive unchanged snapshot reloads. Request bodies remain streamed.
use crate::proxy::{HttpProxy, ProxyPool};
use anyhow::{ensure, Result};
use axum::{
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use futures_util::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    #[default]
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Priority,
    Balance,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PriorityPolicy {
    #[default]
    Manual,
    Health,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct HealthConfig {
    pub enabled: bool,
    pub path: String,
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    pub unhealthy_after: u32,
    pub healthy_after: u32,
    pub cooldown_seconds: u64,
    pub expected_status_min: u16,
    pub expected_status_max: u16,
}
impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: "/".into(),
            interval_seconds: 10,
            timeout_seconds: 3,
            unhealthy_after: 2,
            healthy_after: 2,
            cooldown_seconds: 10,
            expected_status_min: 200,
            expected_status_max: 399,
        }
    }
}
impl HealthConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.path.starts_with('/')
                && !self.path.starts_with("//")
                && self.path.len() <= 2048
                && !self.path.contains(['\r', '\n', '#']),
            "Health path must be a relative path starting with /"
        );
        ensure!(
            (1..=300).contains(&self.interval_seconds),
            "Health interval must be 1–300 seconds"
        );
        ensure!(
            (1..=30).contains(&self.timeout_seconds),
            "Health timeout must be 1–30 seconds"
        );
        ensure!(
            (1..=10).contains(&self.unhealthy_after) && (1..=10).contains(&self.healthy_after),
            "Health thresholds must be 1–10 checks"
        );
        ensure!(
            (1..=300).contains(&self.cooldown_seconds),
            "Cooldown must be 1–300 seconds"
        );
        ensure!(
            (200..=599).contains(&self.expected_status_min)
                && self.expected_status_max >= self.expected_status_min
                && self.expected_status_max <= 599,
            "Invalid healthy status range"
        );
        ensure!(
            self.path.parse::<axum::http::Uri>().is_ok(),
            "Invalid health path"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub id: String,
    pub target_url: String,
    pub pass_host: bool,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "one")]
    pub priority: u32,
    #[serde(default = "one")]
    pub weight: u32,
    #[serde(default)]
    pub health_path: Option<String>,
}
fn yes() -> bool {
    true
}
fn one() -> u32 {
    1
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Routing {
    pub mode: Mode,
    pub priority_policy: PriorityPolicy,
    pub strategy: Strategy,
    #[serde(default = "attempts")]
    pub max_attempts: usize,
    pub sticky_sessions: bool,
    pub health: HealthConfig,
    /// Applied after the request upload completes, never to the streamed body.
    #[serde(default = "response_timeout")]
    pub response_timeout_seconds: u64,
}
fn response_timeout() -> u64 {
    310
}
fn attempts() -> usize {
    4
}
impl Routing {
    pub fn validate(&self) -> Result<()> {
        self.health.validate()?;
        ensure!(
            self.mode != Mode::Priority
                || self.priority_policy != PriorityPolicy::Health
                || self.health.enabled,
            "Health priority requires active health checks"
        );
        ensure!(
            (1..=128).contains(&self.max_attempts),
            "Attempt limit must be 1–128"
        );
        ensure!(
            (1..=310).contains(&self.response_timeout_seconds),
            "Response timeout must be 1–310 seconds"
        );
        Ok(())
    }
}
// Derive(Default) would use zero for a missing struct-level timeout.
impl Default for Routing {
    fn default() -> Self {
        Self {
            mode: Mode::Priority,
            priority_policy: PriorityPolicy::Manual,
            strategy: Strategy::RoundRobin,
            max_attempts: 4,
            sticky_sessions: false,
            health: HealthConfig::default(),
            response_timeout_seconds: 310,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct BindingStatus {
    pub id: String,
    pub state: &'static str,
    pub requests: u64,
    pub failures: u64,
    pub active_connections: usize,
    pub last_checked_at: Option<i64>,
    pub latency_ms: Option<u64>,
    pub last_status: Option<u16>,
    pub last_error: Option<&'static str>,
}
struct Health {
    down: bool,
    successes: u32,
    failures: u32,
    checked: bool,
    retry_at: Instant,
    checked_at: Option<i64>,
    latency: Option<u64>,
    status: Option<u16>,
    error: Option<&'static str>,
}
struct Endpoint {
    config: Binding,
    proxy: HttpProxy,
    health: Mutex<Health>,
    requests: AtomicU64,
    failures: AtomicU64,
    active: AtomicUsize,
}
struct State {
    config: Routing,
    endpoints: Vec<Arc<Endpoint>>,
    cursor: AtomicU64,
    weighted: Mutex<std::collections::HashMap<String, i64>>,
    next_probe: Mutex<Instant>,
    probing: AtomicUsize,
    gate: Option<Arc<crate::public_access::Gate>>,
    cookie_name: String,
    probe_host: String,
}
#[derive(Clone)]
pub struct Upstreams(Arc<State>);
struct Lease(Arc<Endpoint>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}
struct TrackedBody {
    inner: Body,
    _lease: Arc<Lease>,
}
impl hyper::body::Body for TrackedBody {
    type Data = axum::body::Bytes;
    type Error = axum::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}
impl Upstreams {
    pub fn new(
        id: &str,
        hosts: &[String],
        bindings: Vec<Binding>,
        config: Routing,
        access: Option<crate::public_access::Config>,
        pool: ProxyPool,
    ) -> Result<Self> {
        config.validate()?;
        ensure!(
            !bindings.is_empty() && bindings.len() <= 128,
            "A proxy must contain 1–128 bindings"
        );
        let mut ids = HashSet::new();
        let mut endpoints = Vec::new();
        for b in bindings {
            ensure!(
                !b.id.is_empty()
                    && b.id.len() <= 80
                    && b.id
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
                    && ids.insert(b.id.clone()),
                "Binding IDs must be unique identifiers"
            );
            ensure!(
                (1..=10000).contains(&b.priority) && (1..=100).contains(&b.weight),
                "Priority must be 1–10000 and weight 1–100"
            );
            if let Some(path) = &b.health_path {
                let mut health = config.health.clone();
                health.path = path.clone();
                health.validate()?;
            }
            let proxy = HttpProxy::web(&b.target_url, b.pass_host, pool.clone())?;
            endpoints.push(Arc::new(Endpoint {
                config: b,
                proxy,
                health: Mutex::new(Health {
                    down: false,
                    successes: 0,
                    failures: 0,
                    checked: false,
                    retry_at: Instant::now(),
                    checked_at: None,
                    latency: None,
                    status: None,
                    error: None,
                }),
                requests: AtomicU64::new(0),
                failures: AtomicU64::new(0),
                active: AtomicUsize::new(0),
            }));
        }
        // Stable sort preserves the user's explicit order for equal priorities.
        endpoints.sort_by_key(|e| e.config.priority);
        let cookie_name = format!(
            "ph_upstream_{}",
            id.bytes()
                .map(|b| if b.is_ascii_alphanumeric() {
                    b as char
                } else {
                    '_'
                })
                .collect::<String>()
        );
        Ok(Self(Arc::new(State {
            config,
            endpoints,
            cursor: AtomicU64::new(0),
            weighted: Mutex::new(std::collections::HashMap::new()),
            next_probe: Mutex::new(Instant::now()),
            probing: AtomicUsize::new(0),
            gate: access
                .map(|a| crate::public_access::Gate::new(id, a).map(Arc::new))
                .transpose()?,
            cookie_name,
            probe_host: hosts.first().cloned().unwrap_or_default(),
        })))
    }
    fn candidates(&self, excluded: &HashSet<String>, sticky: Option<&str>) -> Vec<Arc<Endpoint>> {
        let now = Instant::now();
        let mut list: Vec<_> = self
            .0
            .endpoints
            .iter()
            .filter(|e| {
                let h = e.health.lock().unwrap_or_else(|p| p.into_inner());
                e.config.enabled
                    && !excluded.contains(&e.config.id)
                    && (!h.down || (!self.0.config.health.enabled && now >= h.retry_at))
            })
            .cloned()
            .collect();
        if list.is_empty() {
            return list;
        }
        if self.0.config.mode == Mode::Priority {
            if self.0.config.priority_policy == PriorityPolicy::Health {
                list.sort_by_key(|e| {
                    let h = e.health.lock().unwrap_or_else(|p| p.into_inner());
                    (h.failures, h.latency.unwrap_or(u64::MAX))
                });
            }
            return list;
        }
        let pick = if self.0.config.mode == Mode::Balance {
            sticky.and_then(|id| list.iter().position(|e| e.config.id == id))
        } else {
            None
        };
        let pick = pick.unwrap_or_else(|| match self.0.config.strategy {
            Strategy::RoundRobin => {
                (self.0.cursor.fetch_add(1, Ordering::Relaxed) % (list.len() as u64)) as usize
            }
            Strategy::WeightedRoundRobin => {
                // Smooth weighted round robin avoids sending every high-weight
                // request to one binding in a burst before selecting the next.
                let mut scores = self.0.weighted.lock().unwrap_or_else(|p| p.into_inner());
                scores.retain(|id, _| list.iter().any(|e| e.config.id == *id));
                let mut total = 0i64;
                let mut best = 0;
                let mut best_score = i64::MIN;
                for (index, e) in list.iter().enumerate() {
                    let weight = e.config.weight as i64;
                    total += weight;
                    let score = scores.entry(e.config.id.clone()).or_default();
                    *score += weight;
                    if *score > best_score {
                        best = index;
                        best_score = *score;
                    }
                }
                *scores.get_mut(&list[best].config.id).unwrap() -= total;
                best
            }
            Strategy::LeastConnections => {
                let start =
                    (self.0.cursor.fetch_add(1, Ordering::Relaxed) % (list.len() as u64)) as usize;
                (0..list.len())
                    .map(|n| (start + n) % list.len())
                    .min_by_key(|&n| list[n].active.load(Ordering::Relaxed))
                    .unwrap_or(0)
            }
        });
        list.swap(0, pick);
        list
    }
    fn outcome(&self, e: &Endpoint, success: bool, status: Option<u16>, latency: u64, probe: bool) {
        let mut h = e.health.lock().unwrap_or_else(|p| p.into_inner());
        h.checked = true;
        h.checked_at = Some(chrono::Utc::now().timestamp_millis());
        // A moving average of probe latency avoids reacting to a single sample.
        // Application request duration is not comparable across different paths.
        if probe {
            h.latency = Some(h.latency.map_or(latency, |previous| {
                (previous.saturating_mul(3) + latency) / 4
            }));
        }
        h.status = status;
        if success {
            h.failures = 0;
            h.successes = h.successes.saturating_add(1);
            h.error = None;
            if !h.down || !probe || h.successes >= self.0.config.health.healthy_after {
                h.down = false;
            }
        } else {
            h.successes = 0;
            h.failures = h.failures.saturating_add(1);
            h.error = Some(if status.is_some() {
                "unexpected_status"
            } else {
                "connection_or_timeout"
            });
            if !probe || h.failures >= self.0.config.health.unhealthy_after {
                h.down = true;
                h.retry_at =
                    Instant::now() + Duration::from_secs(self.0.config.health.cooldown_seconds);
            }
            if !probe {
                e.failures.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn status(&self) -> Vec<BindingStatus> {
        self.0
            .endpoints
            .iter()
            .map(|e| {
                let h = e.health.lock().unwrap_or_else(|p| p.into_inner());
                BindingStatus {
                    id: e.config.id.clone(),
                    state: if !e.config.enabled {
                        "disabled"
                    } else if h.down {
                        "unhealthy"
                    } else if !h.checked {
                        "unknown"
                    } else if h.failures > 0 {
                        "degraded"
                    } else {
                        "healthy"
                    },
                    requests: e.requests.load(Ordering::Relaxed),
                    failures: e.failures.load(Ordering::Relaxed),
                    active_connections: e.active.load(Ordering::Relaxed),
                    last_checked_at: h.checked_at,
                    latency_ms: h.latency,
                    last_status: h.status,
                    last_error: h.error,
                }
            })
            .collect()
    }
    pub async fn check_health(&self) {
        if !self.0.config.health.enabled {
            return;
        }
        {
            let mut next = self.0.next_probe.lock().unwrap_or_else(|p| p.into_inner());
            if Instant::now() < *next
                || self
                    .0
                    .probing
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
                    .is_err()
            {
                return;
            }
            *next = Instant::now() + Duration::from_secs(self.0.config.health.interval_seconds);
        }
        struct Reset<'a>(&'a AtomicUsize);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.store(0, Ordering::Release);
            }
        }
        let _reset = Reset(&self.0.probing);
        stream::iter(self.0.endpoints.iter().filter(|e| e.config.enabled))
            .for_each_concurrent(8, |e| async move {
                {
                    let h = e.health.lock().unwrap_or_else(|p| p.into_inner());
                    if h.down && Instant::now() < h.retry_at {
                        return;
                    }
                }
                let path = e
                    .config
                    .health_path
                    .as_deref()
                    .unwrap_or(&self.0.config.health.path);
                let request = Request::builder()
                    .method("GET")
                    .uri(path)
                    .header(header::HOST, &self.0.probe_host)
                    .header(header::USER_AGENT, "PortHub-Health/1")
                    .body(Body::empty())
                    .unwrap();
                let started = Instant::now();
                let result = tokio::time::timeout(
                    Duration::from_secs(self.0.config.health.timeout_seconds),
                    e.proxy.try_forward(
                        request,
                        Duration::from_secs(self.0.config.health.timeout_seconds),
                        None,
                    ),
                )
                .await;
                let status = match result {
                    Ok(Ok(response)) => Some(response.status().as_u16()),
                    _ => None,
                };
                let success = status.is_some_and(|s| {
                    (self.0.config.health.expected_status_min
                        ..=self.0.config.health.expected_status_max)
                        .contains(&s)
                });
                self.outcome(
                    e,
                    success,
                    status,
                    started.elapsed().as_millis() as u64,
                    true,
                );
            })
            .await;
    }
    pub async fn forward(&self, request: Request<Body>) -> Response<Body> {
        self.forward_with_security(request, false).await
    }
    pub async fn forward_with_security(
        &self,
        request: Request<Body>,
        secure: bool,
    ) -> Response<Body> {
        let request = if let Some(gate) = &self.0.gate {
            match gate.authorize(request, secure).await {
                Ok(r) => r,
                Err(r) => return r,
            }
        } else {
            request
        };
        let sticky = if self.0.config.sticky_sessions {
            request
                .headers()
                .get(header::COOKIE)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| {
                    s.split(';').find_map(|v| {
                        let (k, v) = v.trim().split_once('=')?;
                        (k == self.0.cookie_name).then(|| v.to_owned())
                    })
                })
        } else {
            None
        };
        use hyper::body::Body as _;
        let replayable = matches!(
            *request.method(),
            axum::http::Method::GET | axum::http::Method::HEAD
        ) && request.body().is_end_stream()
            && !request.headers().contains_key(header::UPGRADE);
        let (parts, body) = request.into_parts();
        let mut body = Some(body);
        let mut excluded = HashSet::new();
        // A bounded attempt budget prevents a large pool extending a request indefinitely.
        for _ in 0..self.0.endpoints.len().min(self.0.config.max_attempts) {
            let Some(e) = self
                .candidates(&excluded, sticky.as_deref())
                .into_iter()
                .next()
            else {
                break;
            };
            excluded.insert(e.config.id.clone());
            e.requests.fetch_add(1, Ordering::Relaxed);
            e.active.fetch_add(1, Ordering::Relaxed);
            let lease = Arc::new(Lease(e.clone()));
            let mut request = Request::new(if replayable {
                Body::empty()
            } else {
                body.take().unwrap()
            });
            *request.method_mut() = parts.method.clone();
            *request.uri_mut() = parts.uri.clone();
            *request.version_mut() = parts.version;
            *request.headers_mut() = parts.headers.clone();
            *request.extensions_mut() = parts.extensions.clone();
            // Internal affinity cookies must never be forwarded to applications.
            if self.0.config.sticky_sessions {
                strip_cookie(request.headers_mut(), &self.0.cookie_name);
            }
            let started = Instant::now();
            match e
                .proxy
                .try_forward(
                    request,
                    Duration::from_secs(self.0.config.response_timeout_seconds),
                    Some(lease.clone()),
                )
                .await
            {
                Ok(mut response) => {
                    // Application errors do not prove another route is unavailable.
                    // Only gateway/unavailable responses trigger safe GET/HEAD retry.
                    let failed = matches!(
                        response.status(),
                        StatusCode::BAD_GATEWAY
                            | StatusCode::SERVICE_UNAVAILABLE
                            | StatusCode::GATEWAY_TIMEOUT
                    );
                    self.outcome(
                        &e,
                        !failed,
                        Some(response.status().as_u16()),
                        started.elapsed().as_millis() as u64,
                        false,
                    );
                    if failed && replayable && !self.candidates(&excluded, None).is_empty() {
                        continue;
                    }
                    if self.0.config.sticky_sessions && self.0.config.mode == Mode::Balance {
                        let value = format!(
                            "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400{}",
                            self.0.cookie_name,
                            e.config.id,
                            if secure { "; Secure" } else { "" }
                        );
                        response
                            .headers_mut()
                            .append(header::SET_COOKIE, value.parse().unwrap());
                    }
                    let (parts, body) = response.into_parts();
                    return Response::from_parts(
                        parts,
                        Body::new(TrackedBody {
                            inner: body,
                            _lease: lease,
                        }),
                    );
                }
                Err(()) => {
                    self.outcome(&e, false, None, started.elapsed().as_millis() as u64, false);
                    if !replayable {
                        break;
                    }
                }
            }
        }
        Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header(header::RETRY_AFTER, "5")
            .body(Body::from("No healthy upstream is available"))
            .unwrap()
    }
}
fn strip_cookie(headers: &mut axum::http::HeaderMap, name: &str) {
    let value = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(str::trim)
        .filter(|s| !s.split_once('=').is_some_and(|(k, _)| k == name))
        .collect::<Vec<_>>()
        .join("; ");
    headers.remove(header::COOKIE);
    if !value.is_empty() {
        if let Ok(value) = value.parse() {
            headers.insert(header::COOKIE, value);
        }
    }
}
