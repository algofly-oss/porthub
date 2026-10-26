//! A validated, atomically swapped routing snapshot. Requests clone a prepared
//! proxy then release the lock before I/O; unchanged routes retain their pools.
use crate::proxy::{HttpProxy, ProxyPool};
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
    pub target_url: String,
    pub pass_host: bool,
    pub http: bool,
    pub https: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<crate::public_access::Config>,
}
struct Prepared {
    route: Route,
    proxy: HttpProxy,
}
#[derive(Default)]
struct Snapshot {
    by_id: HashMap<String, Arc<Prepared>>,
    hosts: HashMap<String, Arc<Prepared>>,
}
pub enum Selection {
    Proxy(HttpProxy),
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
                let proxy = HttpProxy::web(&route.target_url, route.pass_host, self.pool.clone())?
                    .with_access(&route.id, route.access.clone())?;
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
            return Selection::Unmatched;
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
