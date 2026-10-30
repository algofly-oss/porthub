//! A validated, atomically swapped routing snapshot. Requests clone a prepared
//! proxy then release the lock before I/O; unchanged routes retain their pools.
use crate::proxy::ProxyPool;
use crate::upstreams::{Binding, Routing, Upstreams};
use anyhow::{ensure, Result};
use axum::http::{header, Request};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub routes: Vec<Route>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub id: String,
    pub hosts: Vec<String>,
    #[serde(default)]
    pub target_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<Binding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<Routing>,
    pub pass_host: bool,
    pub http: bool,
    pub https: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<crate::public_access::Config>,
}
struct Prepared {
    route: Route,
    proxy: Upstreams,
}
#[derive(Default)]
struct Snapshot {
    by_id: HashMap<String, Arc<Prepared>>,
    hosts: HashMap<String, Arc<Prepared>>,
}
pub enum Selection {
    Proxy(Upstreams),
    Disabled,
    Unmatched,
}
pub struct WebRoutes {
    snapshot: RwLock<Arc<Snapshot>>,
    pool: ProxyPool,
    gateways: HashSet<String>,
    activity: Option<Arc<crate::web_activity::WebActivity>>,
}
impl WebRoutes {
    pub fn new(canonical: Option<String>) -> Self {
        Self::with_gateway_hosts(canonical)
    }
    pub fn with_gateway_hosts(hosts: impl IntoIterator<Item = String>) -> Self {
        Self {
            snapshot: RwLock::new(Arc::new(Snapshot::default())),
            pool: ProxyPool::default(),
            gateways: hosts
                .into_iter()
                .map(|host| host.to_ascii_lowercase())
                .collect(),
            activity: None,
        }
    }
    pub fn with_activity(mut self, activity: Arc<crate::web_activity::WebActivity>) -> Self {
        self.activity = Some(activity);
        self
    }
    pub fn reload(&self, config: Config) -> Result<()> {
        let previous = self
            .snapshot
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut next = Snapshot::default();
        for mut route in config.routes {
            ensure!(
                !route.id.is_empty() && route.id.len() <= 128,
                "web route ID must contain 1 to 128 bytes"
            );
            ensure!(
                !next.by_id.contains_key(&route.id),
                "duplicate web route ID"
            );
            ensure!(!route.hosts.is_empty(), "web route must have hosts");
            let mut seen = HashSet::new();
            route.hosts = route
                .hosts
                .into_iter()
                .map(|host| host.trim().to_ascii_lowercase())
                .filter(|host| seen.insert(host.clone()))
                .collect();
            for host in &route.hosts {
                ensure!(valid_host(host), "invalid web route host");
                ensure!(
                    !self.gateways.contains(host),
                    "web route conflicts with the gateway domain"
                );
                ensure!(!next.hosts.contains_key(host), "duplicate web route host");
            }
            let prepared = if let Some(old) = previous
                .by_id
                .get(&route.id)
                .filter(|old| old.route == route)
            {
                old.clone()
            } else {
                let mut routing = route.routing.clone().unwrap_or_default();
                let bindings = if route.bindings.is_empty() {
                    // Existing single-target records keep passive-only health checks.
                    routing.health.enabled = false;
                    vec![Binding {
                        id: "primary".into(),
                        target_url: route.target_url.clone(),
                        pass_host: route.pass_host,
                        enabled: true,
                        priority: 1,
                        weight: 1,
                        health_path: None,
                    }]
                } else {
                    route.bindings.clone()
                };
                let proxy = Upstreams::new(
                    &route.id,
                    &route.hosts,
                    bindings,
                    routing,
                    route.access.clone(),
                    self.pool.clone(),
                )?;
                Arc::new(Prepared { route, proxy })
            };
            next.by_id
                .insert(prepared.route.id.clone(), prepared.clone());
            for host in &prepared.route.hosts {
                next.hosts.insert(host.clone(), prepared.clone());
            }
        }
        *self.snapshot.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(next);
        Ok(())
    }
    pub fn health_snapshot(&self) -> serde_json::Value {
        let snapshot = self.snapshot.read().unwrap_or_else(|p| p.into_inner());
        serde_json::json!({"updated_at":chrono::Utc::now().timestamp_millis(),"routes":snapshot.by_id.iter().map(|(id,prepared)| (id.clone(),serde_json::json!(prepared.proxy.status()))).collect::<std::collections::BTreeMap<_,_>>()})
    }
    pub async fn check_health(&self) {
        use futures_util::StreamExt;
        let pools: Vec<_> = {
            let snapshot = self.snapshot.read().unwrap_or_else(|p| p.into_inner());
            snapshot.by_id.values().map(|p| p.proxy.clone()).collect()
        };
        // A single edge worker bounds probes across routes; no per-route timers.
        futures_util::stream::iter(pools)
            .for_each_concurrent(8, |pool| async move { pool.check_health().await })
            .await;
    }
    pub fn select<B>(&self, request: &Request<B>, secure: bool) -> Selection {
        let authority = request
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.parse::<axum::http::uri::Authority>().ok())
            .or_else(|| request.uri().authority().cloned());
        let Some(authority) = authority else {
            return Selection::Unmatched;
        };
        let host = authority.host().trim_end_matches('.').to_ascii_lowercase();
        let snapshot = self.snapshot.read().unwrap_or_else(|p| p.into_inner());
        let Some(route) = snapshot.hosts.get(&host) else {
            // Only gateway identities may reach the portal. A removed proxy
            // hostname must not become an alias for the gateway application.
            return if self.gateways.contains(&host)
                || host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok()
            {
                Selection::Unmatched
            } else {
                Selection::Disabled
            };
        };
        if (secure && route.route.https) || (!secure && route.route.http) {
            if let Some(activity) = &self.activity {
                activity.record(&route.route.id, &host);
            }
            Selection::Proxy(route.proxy.clone())
        } else {
            Selection::Disabled
        }
    }
}
pub fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn removed_proxy_hosts_never_fall_through_to_the_portal() {
        let routes =
            WebRoutes::with_gateway_hosts(["gateway.example".into(), "fallback.example".into()]);
        let request = |host: &str| {
            Request::builder()
                .uri("/account/signin")
                .header("host", host)
                .body(())
                .unwrap()
        };
        let config = Config {
            routes: vec![Route {
                id: "temp".into(),
                hosts: vec!["temp.example".into()],
                target_url: "http://127.0.0.1:8000".into(),
                pass_host: true,
                http: true,
                https: true,
                access: None,
                bindings: vec![],
                routing: None,
            }],
        };
        routes.reload(config).unwrap();
        assert!(matches!(
            routes.select(&request("temp.example"), true),
            Selection::Proxy(_)
        ));
        routes.reload(Config::default()).unwrap();
        for secure in [false, true] {
            assert!(matches!(
                routes.select(&request("temp.example"), secure),
                Selection::Disabled
            ));
            assert!(matches!(
                routes.select(&request("unknown.example"), secure),
                Selection::Disabled
            ));
            for host in [
                "gateway.example",
                "fallback.example:8345",
                "127.0.0.1:8345",
                "[::1]:8345",
                "localhost",
            ] {
                assert!(
                    matches!(routes.select(&request(host), secure), Selection::Unmatched),
                    "{host}"
                );
            }
        }
    }
}

/// Bounded health work and an atomically replaced, credential-free status file.
/// Core mounts the existing activity volume read-only and filters these IDs by owner.
impl WebRoutes {
    pub async fn run_health(
        self: Arc<Self>,
        path: Option<std::path::PathBuf>,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let mut ticks = tokio::time::interval(std::time::Duration::from_secs(2));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {biased;_=stop.changed()=>return Ok(()),_=ticks.tick()=>{}}
            tokio::select! {biased;_=stop.changed()=>return Ok(()),_=self.check_health()=>{}}
            if let Some(path) = &path {
                let data = serde_json::to_vec(&self.health_snapshot())?;
                if data.len() > 8 * 1024 * 1024 {
                    tracing::warn!("proxy health snapshot exceeds size limit");
                    continue;
                }
                let path = path.clone();
                if let Err(error) = tokio::task::spawn_blocking(move || -> Result<()> {
                    use std::io::Write;
                    let parent = path
                        .parent()
                        .ok_or_else(|| anyhow::anyhow!("Health snapshot needs a parent"))?;
                    std::fs::create_dir_all(parent)?;
                    let temporary =
                        parent.join(format!(".web-health-{}.tmp", uuid::Uuid::new_v4().simple()));
                    let result = (|| -> Result<()> {
                        let mut f = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&temporary)?;
                        f.write_all(&data)?;
                        std::fs::rename(&temporary, &path)?;
                        Ok(())
                    })();
                    let _ = std::fs::remove_file(temporary);
                    result
                })
                .await?
                {
                    tracing::warn!(%error,"proxy health status publication failed");
                }
            }
        }
    }
}
