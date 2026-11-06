//! Lightweight Tor adapter. No Arti implementation or bootstrap dependency is
//! linked into core; routing policy and physical-interface selection stay here.
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use porthub_components::{
    catalog::Component,
    protocol::tor::{Operation, Options, Value},
};
use porthub_egress::{BoxStream, Connector, Destination, Resolver};
use std::{
    net::IpAddr,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock, Weak,
    },
    time::Duration,
};
use tokio::sync::{watch, OnceCell};
use tokio_util::sync::CancellationToken;
pub struct TorPool {
    options: Options,
    sources: Option<watch::Receiver<Vec<IpAddr>>>,
    ready: Arc<AtomicBool>,
    session: Arc<OnceCell<Generations<porthub_components::worker::Session>>>,
    stop: CancellationToken,
}
// Retired generations are kept alive by their streams, not by maintenance.
// Bound simultaneous versions so long-lived tunnels cannot cause unlimited
// background processes when many releases arrive before those tunnels close.
struct Generations<T> {
    state: RwLock<(Arc<T>, Vec<Weak<T>>)>,
}
impl<T> Generations<T> {
    fn new(initial: T) -> Self {
        Self {
            state: RwLock::new((Arc::new(initial), Vec::new())),
        }
    }
    fn current(&self) -> Arc<T> {
        self.state.read().unwrap().0.clone()
    }
    fn live(&self) -> Vec<Arc<T>> {
        let mut state = self.state.write().unwrap();
        state.1.retain(|generation| generation.strong_count() > 0);
        let mut live = vec![state.0.clone()];
        live.extend(state.1.iter().filter_map(Weak::upgrade));
        live
    }
    fn stage(&self, candidate: T) -> Result<Arc<T>> {
        let mut state = self.state.write().unwrap();
        state.1.retain(|generation| generation.strong_count() > 0);
        ensure!(
            state.1.len() < 15,
            "Tor update deferred while older generations have active streams"
        );
        let candidate = Arc::new(candidate);
        state.1.push(Arc::downgrade(&candidate));
        Ok(candidate)
    }
    fn promote(&self, candidate: &Arc<T>) {
        let mut state = self.state.write().unwrap();
        state.1.retain(|generation| {
            generation.strong_count() > 0 && !generation.ptr_eq(&Arc::downgrade(candidate))
        });
        let old = std::mem::replace(&mut state.0, candidate.clone());
        state.1.push(Arc::downgrade(&old));
    }
}
type Sessions = OnceCell<Generations<porthub_components::worker::Session>>;
async fn generations<'a>(
    session: &'a Sessions,
    stop: &CancellationToken,
) -> Result<&'a Generations<porthub_components::worker::Session>> {
    session
        .get_or_try_init(|| async {
            Ok(Generations::new(
                crate::components::persistent_session(Component::Tor, stop).await?,
            ))
        })
        .await
}
async fn worker(
    session: &Sessions,
    stop: &CancellationToken,
) -> Result<(
    Arc<porthub_components::worker::Session>,
    porthub_components::rpc::Client,
)> {
    let generation = generations(session, stop).await?.current();
    let client = generation.connect(stop).await?;
    Ok((generation, client))
}
struct GenerationStream<S, T> {
    stream: S,
    _generation: Arc<T>,
}
impl<S: tokio::io::AsyncRead + Unpin, T: Unpin> tokio::io::AsyncRead for GenerationStream<S, T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl<S: tokio::io::AsyncWrite + Unpin, T: Unpin> tokio::io::AsyncWrite for GenerationStream<S, T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
impl TorPool {
    pub fn new(directory: &Path, groups: usize, max_connections: usize) -> Result<Self> {
        let options = Options {
            directory: directory.into(),
            groups,
            max_connections,
            sources: None,
        };
        options.validate()?;
        Ok(Self {
            options,
            sources: None,
            ready: Arc::new(AtomicBool::new(false)),
            session: Arc::new(OnceCell::new()),
            stop: CancellationToken::new(),
        })
    }
    pub fn with_underlay(mut self, sources: watch::Receiver<Vec<IpAddr>>) -> Self {
        self.sources = Some(sources.clone());
        let mut sources = sources;
        let mut options = self.options.clone();
        let ready = self.ready.clone();
        let stop = self.stop.clone();
        let session = self.session.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let update_stop = stop.clone();
            let update_session = session.clone();
            let mut update_sources = sources.clone();
            let update_options = options.clone();
            let _updates = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(60));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {biased; _=update_stop.cancelled()=>break, _=tick.tick()=>{}}
                    if update_sources.has_changed().is_err() || update_sources.borrow().is_empty() {
                        continue;
                    }
                    let Some(generations) = update_session.get() else {
                        continue;
                    };
                    if generations.live().len() >= 16 {
                        continue;
                    }
                    let active = generations.current();
                    let candidate = tokio::select! {biased; _=update_stop.cancelled()=>break, result=active.newer(&update_stop)=>result};
                    let Ok(Some(candidate)) = candidate else {
                        continue;
                    };
                    let Ok(candidate) = generations.stage(candidate) else {
                        continue;
                    };
                    let mut prepared = update_options.clone();
                    prepared.sources = Some(update_sources.borrow_and_update().clone());
                    if prepared.sources.as_ref().is_none_or(Vec::is_empty) {
                        continue;
                    }
                    let result = async {
                        let mut client = candidate.connect(&update_stop).await?;
                        client
                            .call::<_, Value>(
                                Operation::Bootstrap { options: prepared },
                                Duration::from_secs(240),
                            )
                            .await
                    };
                    let result = tokio::select! {biased;
                        _=update_stop.cancelled()=>break,
                        _=update_sources.changed()=>Err(anyhow::anyhow!("Tor update interrupted by routing policy change")),
                        result=result=>result
                    };
                    if matches!(result, Ok(Value::Ready { ready: true }))
                        && update_sources.has_changed().is_ok()
                        && !update_sources.borrow().is_empty()
                        && candidate.artifact().version > generations.current().artifact().version
                    {
                        generations.promote(&candidate);
                    } else {
                        let retired = (*candidate).clone();
                        drop(candidate);
                        let mut revoked = update_options.clone();
                        revoked.sources = Some(vec![]);
                        let _ = tokio::time::timeout(Duration::from_secs(2), async {
                            let mut client = retired.connect_existing().await?;
                            client
                                .call::<_, Value>(
                                    Operation::Ready { options: revoked },
                                    Duration::from_secs(2),
                                )
                                .await
                        })
                        .await;
                    }
                }
            }));
            loop {
                tokio::select! {biased; _=stop.cancelled()=>break, _=tick.tick()=>{}, changed=sources.changed()=>{if changed.is_err(){break;}}}
                options.sources = Some(sources.borrow_and_update().clone());
                if session.get().is_none() && options.sources.as_ref().is_some_and(Vec::is_empty) {
                    ready.store(false, Ordering::Release);
                    continue;
                }
                let sessions = tokio::select! {biased; _=stop.cancelled()=>break, result=generations(&session,&stop)=>result};
                let Ok(sessions) = sessions else {
                    ready.store(false, Ordering::Release);
                    continue;
                };
                let active = sessions.current();
                let mut requests = tokio::task::JoinSet::new();
                for generation in sessions.live() {
                    let options = options.clone();
                    let stop = stop.clone();
                    let current = Arc::ptr_eq(&active, &generation);
                    requests.spawn(async move {
                        let response = async {
                            let mut client = generation.connect(&stop).await?;
                            client
                                .call::<_, Value>(
                                    Operation::Ready { options },
                                    Duration::from_secs(15),
                                )
                                .await
                        }
                        .await;
                        (
                            current,
                            matches!(response, Ok(Value::Ready { ready: true })),
                        )
                    });
                }
                // A policy change cancels the old batch before sending fresh
                // source restrictions to every active/retired generation.
                loop {
                    tokio::select! {biased;
                        _=stop.cancelled()=>break,
                        changed=sources.changed()=>{if changed.is_err(){stop.cancel();} break;},
                        result=requests.join_next()=> match result {
                            Some(Ok((true,active)))=>ready.store(active,Ordering::Release),
                            Some(_)=>{}, None=>break,
                        }
                    }
                }
            }
            ready.store(false, Ordering::Release);
            stop.cancel();
            drop(_updates);
            if let Some(sessions) = session.get() {
                let mut shutdown = tokio::task::JoinSet::new();
                for generation in sessions.live() {
                    let mut options = options.clone();
                    options.sources = Some(vec![]);
                    shutdown.spawn(async move {
                        let _ = tokio::time::timeout(Duration::from_secs(2), async {
                            let mut client = generation.connect_existing().await?;
                            client
                                .call::<_, Value>(
                                    Operation::Ready { options },
                                    Duration::from_secs(2),
                                )
                                .await
                        })
                        .await;
                    });
                }
                while shutdown.join_next().await.is_some() {}
            }
        });
        self
    }
    fn options(&self) -> Result<Options> {
        let sources = self
            .sources
            .as_ref()
            .context("managed Tor requires an explicit physical-interface source watcher")?;
        ensure!(
            sources.has_changed().is_ok() && !sources.borrow().is_empty(),
            "managed Tor has no permitted physical-interface sources"
        );
        let mut options = self.options.clone();
        options.sources = Some(sources.borrow().clone());
        Ok(options)
    }
    pub async fn bootstrap(&self) -> Result<()> {
        let options = self.options()?;
        let (_generation, mut worker) = worker(&self.session, &self.stop).await?;
        let response: Value = tokio::select! {biased; _=self.stop.cancelled()=>anyhow::bail!("Tor preparation cancelled"),result=worker.call(Operation::Bootstrap {options},Duration::from_secs(240))=>result?};
        let Value::Ready { ready } = response else {
            anyhow::bail!("unexpected Tor bootstrap response")
        };
        self.options()?;
        self.ready.store(ready, Ordering::Release);
        ensure!(ready, "Tor is not ready for traffic");
        Ok(())
    }
    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
            && self.sources.as_ref().is_some_and(|sources| {
                sources.has_changed().is_ok() && !sources.borrow().is_empty()
            })
    }
}
impl Drop for TorPool {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
#[async_trait]
impl Connector for TorPool {
    async fn connect(&self, destination: Destination) -> Result<BoxStream> {
        let options = self.options()?;
        let (generation, worker) = worker(&self.session, &self.stop).await?;
        let (response, stream) = worker
            .upgrade::<_, Value>(
                Operation::Connect {
                    options,
                    host: destination.host,
                    port: destination.port,
                },
                Duration::from_secs(240),
            )
            .await?;
        ensure!(
            matches!(response, Value::Connected),
            "unexpected Tor connection response"
        );
        self.options()?;
        Ok(Box::new(GenerationStream {
            stream,
            _generation: generation,
        }))
    }
}
#[async_trait]
impl Resolver for TorPool {
    async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        ensure!(self.ready(), "Tor resolver is not ready");
        let options = self.options()?;
        let (_generation, mut worker) = worker(&self.session, &self.stop).await?;
        let response: Value = worker
            .call(
                Operation::Resolve {
                    options,
                    hostname: hostname.into(),
                },
                Duration::from_secs(15),
            )
            .await?;
        let Value::Addresses { addresses } = response else {
            anyhow::bail!("unexpected Tor resolution response")
        };
        ensure!(
            addresses.len() <= 256,
            "Tor resolution exceeded address limit"
        );
        self.options()?;
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn handover_preserves_old_stream_and_releases_retired_generation_on_drop() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let generations = Generations::new("old");
        let old = generations.current();
        let old_weak = Arc::downgrade(&old);
        let (local, mut peer) = tokio::io::duplex(64);
        let mut stream = GenerationStream {
            stream: local,
            _generation: old,
        };
        let candidate = generations.stage("new").unwrap();
        assert_eq!(*generations.current(), "old");
        generations.promote(&candidate);
        drop(candidate);
        assert_eq!(*generations.current(), "new");
        assert_eq!(generations.live().len(), 2);
        peer.write_all(b"still open").await.unwrap();
        let mut bytes = [0; 10];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"still open");
        drop(stream);
        assert!(old_weak.upgrade().is_none());
        assert_eq!(generations.live().len(), 1);
    }
    #[test]
    fn failed_candidate_never_replaces_current_and_retired_versions_are_bounded() {
        let generations = Generations::new(0);
        let failed = generations.stage(1).unwrap();
        assert_eq!(*generations.current(), 0);
        drop(failed);
        assert_eq!(generations.live().len(), 1);
        let mut leases = vec![];
        for version in 1..=15 {
            leases.push(generations.current());
            let candidate = generations.stage(version).unwrap();
            generations.promote(&candidate);
        }
        assert_eq!(generations.live().len(), 16);
        assert!(generations.stage(16).is_err());
        leases.clear();
        assert_eq!(generations.live().len(), 1);
        assert!(generations.stage(16).is_ok());
    }
    #[test]
    fn empty_or_closed_authority_immediately_invalidates_managed_readiness() {
        let root = tempfile::tempdir().unwrap();
        let mut pool = TorPool::new(root.path(), 4, 64).unwrap();
        let (sender, receiver) = watch::channel(vec!["192.0.2.10".parse().unwrap()]);
        pool.sources = Some(receiver);
        pool.ready.store(true, Ordering::Release);
        assert!(pool.ready());
        assert!(pool.options().is_ok());
        sender.send_replace(vec![]);
        assert!(!pool.ready());
        assert!(pool.options().is_err());
        sender.send_replace(vec!["192.0.2.10".parse().unwrap()]);
        assert!(pool.options().is_ok());
        drop(sender);
        assert!(!pool.ready());
        assert!(pool.options().is_err());
    }
    #[tokio::test]
    async fn managed_tor_requires_sources_before_fetch_or_network_access() {
        let root = tempfile::tempdir().unwrap();
        let pool = TorPool::new(root.path(), 4, 64).unwrap();
        let bootstrap = pool.bootstrap().await.unwrap_err();
        assert!(bootstrap
            .to_string()
            .contains("explicit physical-interface source watcher"));
        let connect = pool
            .connect(Destination::new("example.invalid".into(), 443).unwrap())
            .await;
        assert!(connect.is_err());
        assert!(!pool.ready());
    }
}

#[cfg(all(test, unix))]
#[path = "tor_component_live.rs"]
mod live;
