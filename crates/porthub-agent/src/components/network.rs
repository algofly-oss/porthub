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

#[cfg(feature = "private-sparse")]
pub(crate) type ClockReceiver =
    tokio::sync::watch::Receiver<Option<crate::private_network::gateway_time::ClockSample>>;
pub struct Routes {
    #[cfg(feature = "private-sparse")]
    registration: Option<(url::Origin, ClockReceiver)>,
    settings: crate::outbound::Settings,
    state: Mutex<HashMap<String, crate::outbound::Selection>>,
}
impl Routes {
    pub fn new() -> Result<Self> {
        Ok(Self {
            settings: crate::outbound::Settings::from_env()?,
            state: Mutex::new(HashMap::new()),
            #[cfg(feature = "private-sparse")]
            registration: None,
        })
    }
    #[cfg(feature = "private-sparse")]
    pub(crate) fn for_registration(gateway: &str, clock: ClockReceiver) -> Result<Self> {
        let mut routes = Self::new()?;
        routes.registration = Some((Url::parse(gateway)?.origin(), clock));
        Ok(routes)
    }
    fn client(&self, url: &Url) -> Result<reqwest::ClientBuilder> {
        let builder = reqwest::Client::builder();
        #[cfg(feature = "private-sparse")]
        let builder = if let Some(sample) = self
            .registration
            .as_ref()
            .filter(|(origin, _)| *origin == url.origin())
            .and_then(|(_, rx)| *rx.borrow())
        {
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let tls = rustls::ClientConfig::builder_with_details(
                std::sync::Arc::new(rustls::crypto::ring::default_provider()),
                std::sync::Arc::new(sample),
            )
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
            builder.use_preconfigured_tls(tls)
        } else {
            ensure!(
                url.scheme() != "https" || std::time::SystemTime::now() >= std::time::UNIX_EPOCH,
                "component origin has no trusted clock yet"
            );
            builder
        };
        Ok(builder
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("PortHub component manager")
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(300)))
    }
}
#[async_trait]
impl Routing for Routes {
    async fn route(&self, url: &Url) -> Result<Routed> {
        if self.settings.system {
            return Ok(Routed {
                client: self.client(url)?.build()?,
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
                client: self.client(url)?.build()?,
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
        let builder = self
            .client(url)?
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
