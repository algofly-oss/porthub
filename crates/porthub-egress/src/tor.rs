//! One embedded Tor client with bounded, mutually isolated circuit groups.
//! This is a stream API, not a SOCKS listener and not a Tor relay.
use crate::underlay::UnderlayTcp;
use crate::{BoxStream, Connector, Destination, LimitedStream, Resolver};
use anyhow::{ensure, Context, Result};
use arti_client::{config::CfgPath, DormantMode, TorClient, TorClientConfig};
use async_trait::async_trait;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{OnceCell, Semaphore};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tor_rtcompat::{CompoundRuntime, PreferredRuntime, RuntimeSubstExt};

type Runtime = CompoundRuntime<
    PreferredRuntime,
    PreferredRuntime,
    PreferredRuntime,
    UnderlayTcp,
    PreferredRuntime,
    PreferredRuntime,
    PreferredRuntime,
>;
type Client = Arc<TorClient<Runtime>>;
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

pub struct TorPool {
    config: TorClientConfig,
    groups: usize,
    clients: OnceCell<Vec<Client>>,
    cursor: AtomicUsize,
    permits: Arc<Semaphore>,
    sources: Option<tokio::sync::watch::Receiver<Vec<std::net::IpAddr>>>,
}
impl TorPool {
    pub fn new(directory: &Path, groups: usize, max_connections: usize) -> Result<Self> {
        ensure!(
            (1..=16).contains(&groups),
            "Tor circuit groups must be between 1 and 16"
        );
        ensure!(
            (1..=512).contains(&max_connections),
            "Tor connection limit must be between 1 and 512"
        );
        let mut builder = TorClientConfig::builder();
        builder
            .storage()
            .state_dir(CfgPath::new_literal(directory.join("state")))
            .cache_dir(CfgPath::new_literal(directory.join("cache")));
        Ok(Self {
            config: builder.build()?,
            groups,
            clients: OnceCell::new(),
            cursor: AtomicUsize::new(0),
            permits: Arc::new(Semaphore::new(max_connections)),
            sources: None,
        })
    }

    /// Required when embedded in an exit-routing agent. The supplied addresses
    /// come from its existing kernel-driven physical-interface watcher.
    pub fn with_underlay(
        mut self,
        sources: tokio::sync::watch::Receiver<Vec<std::net::IpAddr>>,
    ) -> Self {
        self.sources = Some(sources);
        self
    }

    /// Call in background when a policy enables Tor. No ordinary transfer
    /// should wait for discovery or bootstrap in the packet-processing loop.
    pub async fn bootstrap(&self) -> Result<()> {
        self.clients
            .get_or_try_init(|| async {
                // Keep the provider deterministic when embedded beside reqwest,
                // QUIC and other rustls consumers in the same agent process.
                let _ = rustls::crypto::ring::default_provider().install_default();
                let runtime = PreferredRuntime::current()?.with_tcp_provider(UnderlayTcp {
                    sources: self.sources.clone(),
                });
                let client = tokio::time::timeout(
                    BOOTSTRAP_TIMEOUT,
                    TorClient::with_runtime(runtime)
                        .config(self.config.clone())
                        .create_bootstrapped(),
                )
                .await
                .context("Tor bootstrap timed out")?
                .map_err(|_| anyhow::anyhow!("Tor bootstrap unavailable"))?;
                let mut clients = Vec::with_capacity(self.groups);
                for _ in 0..self.groups {
                    clients.push(client.isolated_client());
                }
                Ok::<_, anyhow::Error>(clients)
            })
            .await?;
        Ok(())
    }

    pub fn ready(&self) -> bool {
        self.clients
            .get()
            .and_then(|clients| clients.first())
            .is_some_and(|client| client.bootstrap_status().ready_for_traffic())
    }

    /// Suspend maintenance when the last consumer goes idle. A subsequent
    /// connection wakes the client; no busy polling is required here.
    pub fn dormant(&self) {
        if let Some(clients) = self.clients.get() {
            if let Some(client) = clients.first() {
                client.set_dormant(DormantMode::Soft);
            }
        }
    }
}

#[async_trait]
impl Connector for TorPool {
    async fn connect(&self, destination: Destination) -> Result<BoxStream> {
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .context("Tor connection limit reached")?;
        self.bootstrap().await?;
        let clients = self.clients.get().expect("bootstrap initialized");
        let client = &clients[self.cursor.fetch_add(1, Ordering::Relaxed) % clients.len()];
        let stream = tokio::time::timeout(
            CONNECT_TIMEOUT,
            client.connect((destination.host.as_str(), destination.port)),
        )
        .await
        .context("Tor connection timed out")?
        .map_err(|_| anyhow::anyhow!("Tor destination unavailable"))?;
        Ok(Box::new(LimitedStream {
            stream: stream.compat(),
            _permit: permit,
        }))
    }
}

#[async_trait]
impl Resolver for TorPool {
    async fn resolve(&self, hostname: &str) -> Result<Vec<std::net::IpAddr>> {
        ensure!(self.ready(), "Tor resolver is not ready");
        let _permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .context("Tor connection limit reached")?;
        let clients = self.clients.get().context("Tor resolver is not ready")?;
        let client = &clients[self.cursor.fetch_add(1, Ordering::Relaxed) % clients.len()];
        tokio::time::timeout(Duration::from_secs(8), client.resolve(hostname))
            .await
            .context("Tor resolution timed out")?
            .map_err(|_| anyhow::anyhow!("Tor name resolution unavailable"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn construction_is_offline_and_limits_are_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let pool = TorPool::new(directory.path(), 4, 64).unwrap();
        assert!(!pool.ready());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        assert!(TorPool::new(directory.path(), 0, 64).is_err());
        assert!(TorPool::new(directory.path(), 17, 64).is_err());
        assert!(TorPool::new(directory.path(), 4, 0).is_err());
        assert!(TorPool::new(directory.path(), 4, 513).is_err());
    }

    #[tokio::test]
    #[ignore = "explicit opt-in: bootstraps real Tor and contacts the Tor Project over verified HTTPS"]
    async fn live_tor_https_uses_a_tor_exit_without_a_listener() -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let directory = tempfile::tempdir()?;
        let route = std::net::UdpSocket::bind("0.0.0.0:0")?;
        // UDP connect selects a source without sending any packet. This is
        // only a test fixture; production uses the agent's interface watcher.
        route.connect("1.1.1.1:53")?;
        let (_sources, receiver) = tokio::sync::watch::channel(vec![route.local_addr()?.ip()]);
        let pool = TorPool::new(directory.path(), 4, 16)?.with_underlay(receiver);
        pool.bootstrap().await?;
        assert!(pool.ready());
        let stream = pool
            .connect(Destination::new("check.torproject.org".into(), 443)?)
            .await?;
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let mut stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
            .connect("check.torproject.org".try_into()?, stream)
            .await?;
        stream
            .write_all(
                b"GET /api/ip HTTP/1.1\r\nHost: check.torproject.org\r\nConnection: close\r\n\r\n",
            )
            .await?;
        stream.flush().await?;
        let mut reply = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(60),
            stream.take(16384).read_to_end(&mut reply),
        )
        .await??;
        let text = std::str::from_utf8(&reply)?;
        ensure!(
            text.starts_with("HTTP/1.1 200") || text.starts_with("HTTP/1.0 200"),
            "Tor verification endpoint returned an unexpected status"
        );
        let body = text
            .split_once("\r\n\r\n")
            .context("missing verification response")?
            .1;
        let json: serde_json::Value = serde_json::from_str(body)?;
        ensure!(
            json.get("IsTor").and_then(|value| value.as_bool()) == Some(true),
            "verification endpoint did not identify a Tor exit"
        );
        pool.dormant();
        Ok(())
    }
}
