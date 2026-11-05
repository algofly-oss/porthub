//! Optional, independently usable Tor runtime. Core keeps all mesh policy and
//! exposes only explicitly authorized streams to this local worker.
use async_trait::async_trait;
use porthub_components::{
    protocol::tor::{Operation, Options, Value},
    rpc::{ErrorCode, Failure, Handler, Reply},
};
use porthub_egress::{tor::TorPool, Connector, Destination, Resolver};
use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
use tokio::sync::{watch, Mutex};
use tokio_util::sync::CancellationToken;
pub const VERSION: &str = match option_env!("PORTHUB_COMPONENT_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

fn storage_directory(options: &Options, version: &str) -> Result<PathBuf, Failure> {
    // Version comes from the immutable executable, never from an RPC caller.
    if version.len() > 64
        || version.is_empty()
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(failure(
            ErrorCode::Internal,
            "Invalid Tor worker version identity",
        ));
    }
    Ok(options.directory.join(format!(
        "worker-{version}-g{}-c{}-{}",
        options.groups,
        options.max_connections,
        if options.sources.is_some() {
            "restricted"
        } else {
            "system"
        }
    )))
}
type Key = (PathBuf, usize, usize, bool);
struct Pool {
    tor: Arc<TorPool>,
    sources: Option<watch::Sender<Vec<std::net::IpAddr>>>,
    last_used: AtomicU64,
}
#[derive(Default)]
pub struct Worker {
    pools: Mutex<HashMap<Key, Arc<Pool>>>,
}
fn failure(code: ErrorCode, message: &str) -> Failure {
    Failure {
        code,
        detail: message.into(),
    }
}
impl Worker {
    async fn pool(&self, options: Options) -> Result<Arc<Pool>, Failure> {
        options.validate().map_err(|_| {
            failure(
                ErrorCode::InvalidRequest,
                "Invalid Tor storage, capacity or underlay options",
            )
        })?;
        let key = (
            options.directory.clone(),
            options.groups,
            options.max_connections,
            options.sources.is_some(),
        );
        let mut pools = self.pools.lock().await;
        pools.retain(|_, pool| {
            Arc::strong_count(pool) > 1
                || now().saturating_sub(pool.last_used.load(Ordering::Relaxed)) < 300
        });
        if let Some(pool) = pools.get(&key) {
            pool.last_used.store(now(), Ordering::Relaxed);
            if let (Some(sender), Some(sources)) = (&pool.sources, options.sources) {
                sender.send_replace(sources);
            }
            return Ok(pool.clone());
        }
        if pools.len() >= 16 {
            return Err(failure(
                ErrorCode::Unavailable,
                "Tor worker profile capacity reached; unused profiles expire after five minutes",
            ));
        }
        let storage = storage_directory(&options, VERSION)?;
        let mut tor = TorPool::new(&storage, options.groups, options.max_connections)
            .map_err(|_| failure(ErrorCode::InvalidRequest, "Cannot configure Tor storage"))?;
        let sources = if let Some(sources) = options.sources {
            let (sender, receiver) = watch::channel(sources);
            tor = tor.with_underlay(receiver);
            Some(sender)
        } else {
            None
        };
        let tor = Arc::new(tor);
        let pool = Arc::new(Pool {
            tor,
            sources,
            last_used: AtomicU64::new(now()),
        });
        pools.insert(key, pool.clone());
        Ok(pool)
    }
}
#[async_trait]
impl Handler for Worker {
    type Operation = Operation;
    type Value = Value;
    fn connection_limit(&self) -> usize {
        128
    }
    async fn handle(
        &self,
        operation: Operation,
        _cancel: CancellationToken,
    ) -> Result<Reply<Value>, Failure> {
        match operation {
            Operation::Configure { options } => {
                self.pool(options).await?;
                Ok(Reply::Message(Value::Configured))
            }
            Operation::Ready { options } => Ok(Reply::Message(Value::Ready {
                ready: self.pool(options).await?.tor.ready(),
            })),
            Operation::Bootstrap { options } => {
                let pool = self.pool(options).await?;
                pool.tor.bootstrap().await.map_err(|_| {
                    failure(
                        ErrorCode::Unavailable,
                        "Tor bootstrap unavailable; inspect connectivity and source restrictions",
                    )
                })?;
                Ok(Reply::Message(Value::Ready {
                    ready: pool.tor.ready(),
                }))
            }
            Operation::Connect {
                options,
                host,
                port,
            } => {
                let destination = Destination::new(host, port)
                    .map_err(|_| failure(ErrorCode::InvalidRequest, "Invalid Tor destination"))?;
                let pool = self.pool(options).await?;
                let stream =
                    pool.tor.connect(destination).await.map_err(|_| {
                        failure(ErrorCode::Unavailable, "Tor destination unavailable")
                    })?;
                Ok(Reply::Stream {
                    value: Value::Connected,
                    remote: Box::new(LeasedStream {
                        stream,
                        _pool: pool,
                    }),
                })
            }
            Operation::Resolve { options, hostname } => {
                Destination::new(hostname.clone(), 1)
                    .map_err(|_| failure(ErrorCode::InvalidRequest, "Invalid Tor hostname"))?;
                let addresses = self
                    .pool(options)
                    .await?
                    .tor
                    .resolve(&hostname)
                    .await
                    .map_err(|_| {
                        failure(ErrorCode::Unavailable, "Tor name resolution unavailable")
                    })?;
                Ok(Reply::Message(Value::Addresses { addresses }))
            }
        }
    }
}

/// Retain the original pool/source watcher for an active stream across profile
/// changes. No detached copy task survives a closed RPC connection.
struct LeasedStream {
    stream: porthub_egress::BoxStream,
    _pool: Arc<Pool>,
}
impl AsyncRead for LeasedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for LeasedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn options(root: &std::path::Path, sources: Option<Vec<std::net::IpAddr>>) -> Options {
        Options {
            directory: root.into(),
            groups: 4,
            max_connections: 64,
            sources,
        }
    }
    #[test]
    fn concurrent_versions_and_profiles_have_independent_storage_but_source_updates_reuse_it() {
        let root = tempfile::tempdir().unwrap();
        let mut profile = options(root.path(), Some(vec!["192.0.2.10".parse().unwrap()]));
        let original = storage_directory(&profile, "0.1.0").unwrap();
        assert!(original.starts_with(root.path()));
        assert_ne!(original, storage_directory(&profile, "0.1.1").unwrap());
        profile.sources = Some(vec![]);
        assert_eq!(original, storage_directory(&profile, "0.1.0").unwrap());
        profile.groups = 8;
        assert_ne!(original, storage_directory(&profile, "0.1.0").unwrap());
        profile.groups = 4;
        profile.max_connections = 128;
        assert_ne!(original, storage_directory(&profile, "0.1.0").unwrap());
        profile.max_connections = 64;
        profile.sources = None;
        assert_ne!(original, storage_directory(&profile, "0.1.0").unwrap());
        assert!(storage_directory(&profile, "../../other").is_err());
    }
    #[tokio::test]
    async fn configured_sources_update_same_pool_and_empty_sources_never_enable_os_routing() {
        let root = tempfile::tempdir().unwrap();
        let worker = Worker::default();
        let ip = "192.0.2.10".parse().unwrap();
        let restricted = worker
            .pool(options(root.path(), Some(vec![ip])))
            .await
            .unwrap();
        assert_eq!(*restricted.sources.as_ref().unwrap().borrow(), vec![ip]);
        let updated = worker
            .pool(options(root.path(), Some(vec![])))
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&restricted, &updated));
        assert!(updated.sources.as_ref().unwrap().borrow().is_empty());
        let standalone = worker.pool(options(root.path(), None)).await.unwrap();
        assert!(!Arc::ptr_eq(&standalone, &restricted));
        assert!(standalone.sources.is_none());
        assert!(
            !restricted.tor.ready(),
            "configuration must not bootstrap or create network traffic"
        );
    }
    #[tokio::test]
    async fn idle_profiles_are_reclaimed_but_leased_profiles_survive_updates() {
        let root = tempfile::tempdir().unwrap();
        let worker = Worker::default();
        let leased = worker
            .pool(options(&root.path().join("first"), Some(vec![])))
            .await
            .unwrap();
        leased.last_used.store(now() - 301, Ordering::Relaxed);
        let expired = worker
            .pool(options(&root.path().join("second"), Some(vec![])))
            .await
            .unwrap();
        expired.last_used.store(now() - 301, Ordering::Relaxed);
        drop(expired);
        let _new = worker
            .pool(options(&root.path().join("third"), Some(vec![])))
            .await
            .unwrap();
        assert_eq!(worker.pools.lock().await.len(), 2);
        assert!(worker
            .pools
            .lock()
            .await
            .values()
            .any(|pool| Arc::ptr_eq(pool, &leased)));
    }
    #[tokio::test]
    async fn invalid_destinations_and_capacity_fail_without_bootstrapping() {
        let root = tempfile::tempdir().unwrap();
        let worker = Worker::default();
        let result = worker
            .handle(
                Operation::Connect {
                    options: options(root.path(), Some(vec![])),
                    host: "name/invalid".into(),
                    port: 443,
                },
                CancellationToken::new(),
            )
            .await;
        assert!(matches!(
            result,
            Err(Failure {
                code: ErrorCode::InvalidRequest,
                ..
            })
        ));
        let mut invalid = options(root.path(), Some(vec![]));
        invalid.groups = 17;
        assert!(worker.pool(invalid).await.is_err());
        assert!(worker.pools.lock().await.is_empty());
    }
}
