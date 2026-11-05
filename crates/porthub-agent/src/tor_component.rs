//! Lightweight Tor adapter. No Arti implementation or bootstrap dependency is
//! linked into core; routing policy and physical-interface selection stay here.
use anyhow::{ensure, Result};
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
        Arc,
    },
    time::Duration,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
pub struct TorPool {
    options: Options,
    sources: Option<watch::Receiver<Vec<IpAddr>>>,
    ready: Arc<AtomicBool>,
    stop: CancellationToken,
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
            stop: CancellationToken::new(),
        })
    }
    pub fn with_underlay(mut self, sources: watch::Receiver<Vec<IpAddr>>) -> Self {
        self.sources = Some(sources.clone());
        let mut sources = sources;
        let mut options = self.options.clone();
        let ready = self.ready.clone();
        let stop = self.stop.clone();
        tokio::spawn(async move {
            let mut client = None;
            let mut retry = Duration::from_secs(2);
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {biased; _=stop.cancelled()=>break, _=tick.tick()=>{}, changed=sources.changed()=>{if changed.is_err(){break;}}}
                options.sources = Some(sources.borrow_and_update().clone());
                if client.is_none() {
                    client = tokio::select! {biased; _=stop.cancelled()=>break,result=crate::components::persistent_worker(Component::Tor,&stop)=>result.ok()};
                }
                let Some(connection) = client.as_mut() else {
                    ready.store(false, Ordering::Release);
                    tokio::select! {biased; _=stop.cancelled()=>break,_=tokio::time::sleep(retry)=>{}}
                    retry = (retry * 2).min(Duration::from_secs(60));
                    continue;
                };
                retry = Duration::from_secs(2);
                let response = tokio::select! {biased; _=stop.cancelled()=>break,result=connection.call::<_,Value>(Operation::Ready {options:options.clone()},Duration::from_secs(15))=>result};
                match response {
                    Ok(Value::Ready { ready: active }) => ready.store(active, Ordering::Release),
                    _ => {
                        ready.store(false, Ordering::Release);
                        client = None;
                    }
                }
            }
        });
        self
    }
    fn options(&self) -> Result<Options> {
        ensure!(
            self.sources.is_some(),
            "managed Tor requires an explicit physical-interface source watcher"
        );
        let mut options = self.options.clone();
        options.sources = self.sources.as_ref().map(|source| source.borrow().clone());
        Ok(options)
    }
    pub async fn bootstrap(&self) -> Result<()> {
        let options = self.options()?;
        let mut worker = crate::components::persistent_worker(Component::Tor, &self.stop).await?;
        let response: Value = tokio::select! {biased; _=self.stop.cancelled()=>anyhow::bail!("Tor preparation cancelled"),result=worker.call(Operation::Bootstrap {options},Duration::from_secs(240))=>result?};
        let Value::Ready { ready } = response else {
            anyhow::bail!("unexpected Tor bootstrap response")
        };
        self.ready.store(ready, Ordering::Release);
        ensure!(ready, "Tor is not ready for traffic");
        Ok(())
    }
    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
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
        let worker = crate::components::persistent_worker(Component::Tor, &self.stop).await?;
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
        Ok(Box::new(stream))
    }
}
#[async_trait]
impl Resolver for TorPool {
    async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        ensure!(self.ready(), "Tor resolver is not ready");
        let options = self.options()?;
        let mut worker = crate::components::persistent_worker(Component::Tor, &self.stop).await?;
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
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
