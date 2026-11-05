//! Optional downloads use socket-local policy; host routes and DNS are untouched.
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use porthub_components::transport::{Routed, Routing};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use url::Url;

pub struct Routes {
    settings: crate::outbound::Settings,
    state: Mutex<HashMap<String, crate::outbound::Selection>>,
}
impl Routes {
    pub fn new() -> Result<Self> {
        Ok(Self {
            settings: crate::outbound::Settings::from_env()?,
            state: Mutex::new(HashMap::new()),
        })
    }
    fn client() -> reqwest::ClientBuilder {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("PortHub component manager")
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(300))
    }
}
#[async_trait]
impl Routing for Routes {
    async fn route(&self, url: &Url) -> Result<Routed> {
        if self.settings.system {
            return Ok(Routed {
                client: Self::client().build()?,
                ticket: String::new(),
            });
        }
        let (host, port) = crate::outbound::http_connection_target(
            url,
            &hyper_util::client::proxy::matcher::Matcher::from_system(),
        )?;
        let destinations: Vec<_> = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await
        .context("component endpoint DNS deadline exceeded")?
        .context("component endpoint DNS failed")?
        .take(16)
        .collect();
        ensure!(
            !destinations.is_empty(),
            "component endpoint has no resolved addresses"
        );
        if destinations
            .iter()
            .all(|address| address.ip().is_loopback())
            && self.settings.interface.is_none()
            && self.settings.source.is_none()
        {
            return Ok(Routed {
                client: Self::client().build()?,
                ticket: String::new(),
            });
        }
        let candidates = tokio::time::timeout(
            Duration::from_secs(2),
            crate::outbound::discover(&self.settings, &destinations),
        )
        .await
        .context("component route discovery deadline exceeded")??;
        let authority = format!("{host}:{port}");
        let candidate = {
            let mut state = self.state.lock().await;
            ensure!(
                state.len() < 64 || state.contains_key(&authority),
                "component route authority limit reached"
            );
            state
                .entry(authority.clone())
                .or_default()
                .order(&candidates, Instant::now())
                .into_iter()
                .next()
                .context("no policy-permitted component route is currently available")?
        };
        let builder = Self::client()
            .local_address(candidate.source)
            .resolve_to_addrs(&host, &[candidate.destination]);
        #[cfg(target_os = "macos")]
        let builder = builder.interface(&candidate.interface);
        Ok(Routed {
            client: builder.build()?,
            ticket: serde_json::to_string(&(authority, candidate))?,
        })
    }
    async fn completed(&self, ticket: &str, success: bool) {
        let Ok((authority, candidate)) =
            serde_json::from_str::<(String, crate::outbound::Candidate)>(ticket)
        else {
            return;
        };
        let mut state = self.state.lock().await;
        if let Some(selection) = state.get_mut(&authority) {
            if success {
                selection.success(candidate);
            } else {
                selection.failure(&candidate, Instant::now());
            }
        }
    }
}
