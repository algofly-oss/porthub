//! Gateway egress-IP discovery, shared across authenticated callers. It provides
//! an origin candidate; inbound reachability still has to be checked by agents.
use serde::Serialize;
use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const FRESH: Duration = Duration::from_secs(300);
const RETRY: Duration = Duration::from_secs(30);
const MAX_STALE: Duration = Duration::from_secs(3600);

/// Explicit operator advertisements may name a private/routed address. Only
/// automatic third-party discovery is restricted to public Internet addresses.
pub fn advertised_ipv4(value: &str) -> Option<Ipv4Addr> {
    let ip: Ipv4Addr = value.trim().parse().ok()?;
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 240
    {
        None
    } else {
        Some(ip)
    }
}
pub fn public_ipv4(value: &str) -> Option<Ipv4Addr> {
    let ip: Ipv4Addr = value.trim().parse().ok()?;
    let [a, b, c, _] = ip.octets();
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_documentation()
        || ip.is_broadcast()
        || ip.is_multicast()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && (b == 18 || b == 19))
        || (a == 192 && b == 0 && c == 0)
    {
        None
    } else {
        Some(ip)
    }
}

#[derive(Clone, Serialize)]
pub struct Origin {
    pub public_ip: Ipv4Addr,
    pub observed_at: i64,
    pub refresh_after_seconds: u64,
    pub stale: bool,
}
struct Cached {
    origin: Origin,
    at: Instant,
}
#[derive(Default)]
struct State {
    cached: Option<Cached>,
    attempted: Option<Instant>,
}
#[derive(Default)]
pub struct OriginDiscovery {
    state: Mutex<State>,
}

impl OriginDiscovery {
    pub fn cached(&self) -> Option<Origin> {
        let state = self.state.try_lock().ok()?;
        let cached = state.cached.as_ref()?;
        (cached.at.elapsed() < MAX_STALE).then(|| cached.origin.clone())
    }
    pub async fn get(
        &self,
        http: &reqwest::Client,
        sources: &[String],
        configured: Option<&str>,
    ) -> Option<Origin> {
        let mut state = self.state.lock().await;
        let due = state
            .cached
            .as_ref()
            .is_none_or(|c| c.at.elapsed() >= FRESH);
        if due && state.attempted.is_none_or(|at| at.elapsed() >= RETRY) {
            state.attempted = Some(Instant::now());
            let mut ip = configured.and_then(advertised_ipv4);
            if configured.is_none() {
                // Only the gateway contacts these services. No machine IDs,
                // credentials, URLs or request bodies are forwarded to them.
                for source in sources {
                    if let Ok(Some(value)) =
                        tokio::time::timeout(Duration::from_secs(3), fetch(http, source)).await
                    {
                        ip = Some(value);
                        break;
                    }
                }
            }
            if let Some(public_ip) = ip {
                state.cached = Some(Cached {
                    at: Instant::now(),
                    origin: Origin {
                        public_ip,
                        observed_at: chrono::Utc::now().timestamp(),
                        refresh_after_seconds: FRESH.as_secs(),
                        stale: false,
                    },
                });
            }
        }
        let cached = state.cached.as_ref()?;
        let age = cached.at.elapsed();
        if age >= MAX_STALE {
            return None;
        }
        let mut origin = cached.origin.clone();
        origin.stale = age >= FRESH;
        origin.refresh_after_seconds = if origin.stale {
            RETRY.as_secs()
        } else {
            FRESH.saturating_sub(age).as_secs().max(1)
        };
        Some(origin)
    }
}

async fn fetch(http: &reqwest::Client, source: &str) -> Option<Ipv4Addr> {
    let mut response = http.get(source).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if body.len() + chunk.len() > 128 {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    public_ipv4(std::str::from_utf8(&body).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_non_public_or_non_address_responses() {
        for value in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.1.1",
            "198.19.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "0.1.2.3",
            "240.1.1.1",
            "224.1.1.1",
            "::1",
            "<html>error</html>",
        ] {
            assert!(public_ipv4(value).is_none(), "{value}");
        }
        assert_eq!(
            public_ipv4(" 93.184.216.34\n"),
            Some(Ipv4Addr::new(93, 184, 216, 34))
        );
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn discovery_failure_is_backed_off_and_stale_results_expire() {
        let hits = Arc::new(AtomicUsize::new(0));
        let count = hits.clone();
        let mock = axum::Router::new().route(
            "/",
            axum::routing::get(move || {
                let count = count.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    "not an address"
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source = format!("http://{}", listener.local_addr().unwrap());
        let serving = tokio::spawn(async move { axum::serve(listener, mock).await });
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let discovery = OriginDiscovery::default();
        let sources = vec![source];
        assert!(discovery.get(&http, &sources, None).await.is_none());
        assert!(discovery.get(&http, &sources, None).await.is_none());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let origin = Origin {
            public_ip: Ipv4Addr::new(93, 184, 216, 34),
            observed_at: 0,
            refresh_after_seconds: 300,
            stale: false,
        };
        {
            let mut state = discovery.state.lock().await;
            state.cached = Some(Cached {
                origin: origin.clone(),
                at: Instant::now() - Duration::from_secs(301),
            });
        }
        let stale = discovery.get(&http, &sources, None).await.unwrap();
        assert!(stale.stale);
        assert_eq!(stale.refresh_after_seconds, 30);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        {
            let mut state = discovery.state.lock().await;
            state.cached = Some(Cached {
                origin,
                at: Instant::now() - Duration::from_secs(3601),
            });
        }
        assert!(discovery.get(&http, &sources, None).await.is_none());
        {
            let mut state = discovery.state.lock().await;
            state.attempted = Some(Instant::now() - Duration::from_secs(31));
        }
        assert!(discovery.get(&http, &sources, None).await.is_none());
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        serving.abort();
    }
}

pub fn metadata(app: &crate::App) -> Option<porthub_identity::origin::Metadata> {
    porthub_identity::origin::Metadata::read(
        &app.config
            .edge_socket
            .as_ref()?
            .with_file_name("origin.json"),
    )
    .ok()
}

#[cfg(test)]
mod operator_tests {
    use super::*;
    #[tokio::test]
    async fn explicit_operator_address_bypasses_discovery_and_accepts_routed_private_addresses() {
        let unavailable = vec!["http://127.0.0.1:1/never-contact".into()];
        let discovery = OriginDiscovery::default();
        let client = reqwest::Client::new();
        let origin = discovery
            .get(&client, &unavailable, Some("10.90.80.70"))
            .await
            .unwrap();
        assert_eq!(origin.public_ip, Ipv4Addr::new(10, 90, 80, 70));
        assert!(!origin.stale);
        assert!(public_ipv4("10.90.80.70").is_none());
        for invalid in [
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "example.invalid",
            "10.0.0.0/24",
        ] {
            assert!(advertised_ipv4(invalid).is_none());
        }
    }
}

/// A client-facing origin, independent of the gateway's bind address and port.
pub fn advertised_url(value: &str) -> anyhow::Result<url::Url> {
    let url = url::Url::parse(value.trim())?;
    anyhow::ensure!(
        ["http", "https"].contains(&url.scheme())
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/"
            && url.port_or_known_default().is_some_and(|port| port > 0)
            && value.len() <= 1024,
        "invalid advertised gateway origin"
    );
    Ok(url)
}
pub fn tunnel_endpoint(app: &crate::App) -> Option<String> {
    if let Some(value) = &app.config.gateway_advertised_url {
        let mut url = advertised_url(value).ok()?;
        url.set_path("/api/tunnel");
        return Some(url.into());
    }
    let metadata = metadata(app)?;
    let ip = app
        .config
        .gateway_public_ip
        .as_deref()
        .and_then(advertised_ipv4)
        .or_else(|| app.gateway_origin.cached().map(|origin| origin.public_ip))?;
    Some(format!("https://{ip}:{}/api/tunnel", metadata.tls_port))
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;
    #[test]
    fn operator_endpoint_keeps_the_external_scheme_host_and_forwarded_port() {
        for (raw, scheme, port) in [
            ("http://192.0.2.5:18445", "http", 18445),
            ("https://masked.example:23456", "https", 23456),
            ("https://[2001:db8::5]:3443", "https", 3443),
        ] {
            let url = advertised_url(raw).unwrap();
            assert_eq!(url.scheme(), scheme);
            assert_eq!(url.port_or_known_default(), Some(port));
        }
        for raw in [
            "https://user:secret@host:443",
            "https://host:443/path",
            "https://host:443/?key=secret",
            "https://host:443/#fragment",
            "wss://host:443",
            "https://host:0",
        ] {
            assert!(advertised_url(raw).is_err());
        }
    }
}
