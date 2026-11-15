//! Exclusive native stream routing for an already authenticated import. The
//! original USB/IP stream is restarted at ownership changes; never replay URBs.
use anyhow::{ensure, Context, Result};
use porthub_components::usb::{Device, Forward};
use serde::Serialize;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};
use tokio::{
    net::TcpStream,
    sync::{oneshot, watch},
};
use tokio_util::sync::CancellationToken;
#[derive(Debug)]
pub(super) struct Reconfigure;
impl std::fmt::Display for Reconfigure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("USB ownership is being rerouted")
    }
}
impl std::error::Error for Reconfigure {}
#[derive(Clone)]
pub(super) struct Metadata {
    pub device: Device,
    pub wire: Vec<u8>,
    pub restart: bool,
}
struct Child {
    key: String,
    producer: Option<TcpStream>,
    ready: Option<oneshot::Sender<Metadata>>,
    cancel: CancellationToken,
}
struct State {
    metadata: Option<Metadata>,
    child: Option<Child>,
    closed: bool,
    local_port: Option<u32>,
    routed: bool,
}
struct Entry {
    alias: String,
    plan: Forward,
    state: Mutex<State>,
    changed: watch::Sender<u64>,
}
#[derive(Default)]
struct Registry {
    entries: HashMap<(PathBuf, String), Weak<Entry>>,
    gateways: HashMap<PathBuf, bool>,
}
fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(Mutex::default)
}
fn alias(id: &str) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(id.as_bytes());
    format!("0-{}", u64::from_be_bytes(h[..8].try_into().unwrap()))
}
pub(super) fn is_alias(busid: &str) -> bool {
    busid.starts_with("0-")
}
pub(super) fn gateway(path: &Path, supported: bool) {
    registry()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .gateways
        .insert(path.into(), supported);
    if !supported {
        for entry in entries(path) {
            let mut s = entry.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(child) = s.child.take() {
                child.cancel.cancel();
                drop(s);
                changed(&entry);
            }
        }
    }
}
fn supported(path: &Path) -> bool {
    registry()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .gateways
        .get(path)
        .copied()
        .unwrap_or(false)
}
fn entries(path: &Path) -> Vec<Arc<Entry>> {
    let mut r = registry().lock().unwrap_or_else(|p| p.into_inner());
    r.entries.retain(|_, e| e.strong_count() > 0);
    r.entries
        .iter()
        .filter(|((p, _), _)| p == path)
        .filter_map(|(_, e)| e.upgrade())
        .collect()
}
fn find(path: &Path, busid: &str) -> Result<Arc<Entry>> {
    entries(path)
        .into_iter()
        .find(|e| e.alias == busid)
        .context("Imported USB session no longer exists")
}
fn changed(entry: &Entry) {
    entry.changed.send_modify(|n| *n = n.wrapping_add(1));
}
fn descriptor(entry: &Entry, state: &State, gate: bool) -> Option<Device> {
    let meta = state.metadata.as_ref()?;
    let mut d = meta.device.clone();
    d.busid = entry.alias.clone();
    while d.name.len() > 244 {
        d.name.pop();
    }
    d.name.push_str(" (forwarded)");
    d.blocked = if !gate {
        Some("Gateway upgrade required for multi-hop USB".into())
    } else if !meta.restart {
        Some("Upstream agent upgrade required for safe USB rerouting".into())
    } else if state.child.is_some() {
        Some("Device is forwarded onward; stop its downstream session first".into())
    } else if !state.routed && state.local_port.is_none() {
        Some("Waiting for the imported USB controller".into())
    } else {
        #[cfg(target_os = "linux")]
        {
            state.local_port.and_then(|port| {
                super::linux::relay_import(port, &meta.device)
                    .err()
                    .map(|error| error.to_string().chars().take(256).collect())
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    };
    Some(d)
}
pub(super) fn inventory(path: &Path) -> Vec<Device> {
    let gate = supported(path);
    entries(path)
        .into_iter()
        .filter_map(|e| {
            let s = e.state.lock().unwrap_or_else(|p| p.into_inner());
            if s.closed {
                None
            } else {
                descriptor(&e, &s, gate)
            }
        })
        .collect()
}
#[derive(Serialize)]
pub(super) struct Import {
    pub busid: String,
    pub upstream_id: String,
}
pub(super) fn imports(path: &Path) -> Vec<Import> {
    if !supported(path) {
        return vec![];
    }
    entries(path)
        .into_iter()
        .filter_map(|e| {
            let s = e.state.lock().unwrap_or_else(|p| p.into_inner());
            (!s.closed && s.metadata.is_some()).then(|| Import {
                busid: e.alias.clone(),
                upstream_id: e.plan.id.clone(),
            })
        })
        .collect()
}
pub(super) struct ImportGuard {
    path: PathBuf,
    entry: Arc<Entry>,
}
impl ImportGuard {
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.entry.changed.subscribe()
    }
}
impl Drop for ImportGuard {
    fn drop(&mut self) {
        let mut r = registry().lock().unwrap_or_else(|p| p.into_inner());
        let key = (self.path.clone(), self.entry.plan.id.clone());
        if r.entries
            .get(&key)
            .is_some_and(|e| Weak::ptr_eq(e, &Arc::downgrade(&self.entry)))
        {
            r.entries.remove(&key);
        }
        drop(r);
        let mut s = self.entry.state.lock().unwrap_or_else(|p| p.into_inner());
        s.closed = true;
        if let Some(child) = s.child.take() {
            child.cancel.cancel();
        }
        drop(s);
        changed(&self.entry);
    }
}
pub(super) fn register(path: &Path, plan: &Forward) -> Result<ImportGuard> {
    let alias = alias(&plan.id);
    let mut r = registry().lock().unwrap_or_else(|p| p.into_inner());
    let key = (path.to_owned(), plan.id.clone());
    ensure!(
        !r.entries.get(&key).is_some_and(|e| e.strong_count() > 0),
        "USB import already registered"
    );
    ensure!(
        !r.entries
            .iter()
            .any(|((p, _), e)| p == path && e.upgrade().is_some_and(|e| e.alias == alias)),
        "USB import alias collision"
    );
    let (changed, _) = watch::channel(0);
    let entry = Arc::new(Entry {
        alias,
        plan: plan.clone(),
        state: Mutex::new(State {
            metadata: None,
            child: None,
            closed: false,
            local_port: None,
            routed: false,
        }),
        changed,
    });
    r.entries.insert(key, Arc::downgrade(&entry));
    Ok(ImportGuard {
        path: path.into(),
        entry,
    })
}
/// Called only after the parent peer's device and descriptor authentication.
pub(super) fn destination(
    path: &Path,
    plan: &Forward,
    metadata: Metadata,
) -> Result<Option<TcpStream>> {
    let entry = entries(path)
        .into_iter()
        .find(|e| e.plan.id == plan.id)
        .context("USB import registry unavailable")?;
    super::protocol::validate(&metadata.wire, &metadata.device)?;
    ensure!(
        metadata.device.same_device(&plan.device),
        "USB import identity changed"
    );
    let mut s = entry.state.lock().unwrap_or_else(|p| p.into_inner());
    ensure!(!s.closed, "USB import ended");
    s.metadata = Some(metadata.clone());
    s.local_port = None;
    s.routed = s.child.is_some();
    if let Some(child) = s.child.as_mut() {
        ensure!(
            metadata.restart,
            "Upstream agent no longer supports safe USB rerouting"
        );
        let stream = child
            .producer
            .take()
            .context("USB relay epoch already consumed")?;
        let ready = child
            .ready
            .take()
            .context("USB relay readiness already consumed")?;
        ensure!(
            ready.send(metadata).is_ok(),
            "USB downstream lease ended before readiness"
        );
        Ok(Some(stream))
    } else {
        Ok(None)
    }
}
pub(super) fn local(path: &Path, id: &str, port: u32) -> Result<()> {
    let entry = entries(path)
        .into_iter()
        .find(|e| e.plan.id == id)
        .context("USB import registry unavailable")?;
    let mut s = entry.state.lock().unwrap_or_else(|p| p.into_inner());
    ensure!(
        !s.closed && s.child.is_none(),
        "USB import ownership changed"
    );
    s.local_port = Some(port);
    s.routed = false;
    Ok(())
}
fn pair() -> Result<(TcpStream, TcpStream)> {
    let l = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let a = std::net::TcpStream::connect(l.local_addr()?)?;
    let (b, remote) = l.accept()?;
    ensure!(
        remote == a.local_addr()?,
        "USB relay loopback ownership mismatch"
    );
    a.set_nodelay(true)?;
    b.set_nodelay(true)?;
    a.set_nonblocking(true)?;
    b.set_nonblocking(true)?;
    Ok((TcpStream::from_std(a)?, TcpStream::from_std(b)?))
}
pub(super) struct Lease {
    entry: Arc<Entry>,
    key: String,
    ready: Option<oneshot::Receiver<Metadata>>,
    stream: Option<TcpStream>,
    cancel: CancellationToken,
}
impl Lease {
    pub async fn ready(&mut self) -> Result<(TcpStream, Metadata)> {
        let receive = self
            .ready
            .take()
            .context("USB relay lease already started")?;
        let mut metadata = tokio::select! {_ = self.cancel.cancelled()=>anyhow::bail!("USB upstream session ended"),r=receive=>r.context("USB upstream rerouting failed")?};
        metadata.device = super::protocol::validate(&metadata.wire, &metadata.device)?;
        metadata.device.busid = self.entry.alias.clone();
        metadata.wire[256..288].fill(0);
        let alias = metadata.device.busid.as_bytes();
        ensure!(alias.len() < 32, "Invalid USB relay alias");
        metadata.wire[256..256 + alias.len()].copy_from_slice(alias);
        super::protocol::validate(&metadata.wire, &metadata.device)?;
        Ok((
            self.stream
                .take()
                .context("USB relay stream already consumed")?,
            metadata,
        ))
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut s = self.entry.state.lock().unwrap_or_else(|p| p.into_inner());
        if s.child.as_ref().is_some_and(|c| c.key == self.key) {
            if let Some(child) = s.child.take() {
                child.cancel.cancel();
            }
            drop(s);
            changed(&self.entry);
        }
    }
}
pub(super) fn upstream(path: &Path, busid: &str) -> Result<String> {
    Ok(find(path, busid)?.plan.id.clone())
}
pub(super) fn claim(path: &Path, busid: &str, child_id: &str) -> Result<Lease> {
    claim_checked(path, busid, child_id, |state, meta| {
        #[cfg(target_os = "linux")]
        {
            if let Some(port) = state.local_port {
                super::linux::relay_import(port, &meta.device)?;
            } else {
                ensure!(
                    state.routed,
                    "Imported USB is still changing ownership; retry shortly"
                );
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (state, meta);
            anyhow::bail!("This native USB relay requires Linux");
        }
        Ok(())
    })
}
fn claim_checked(
    path: &Path,
    busid: &str,
    child_id: &str,
    validate: impl FnOnce(&State, &Metadata) -> Result<()>,
) -> Result<Lease> {
    ensure!(
        supported(path),
        "Gateway does not support USB relay lineage"
    );
    let entry = find(path, busid)?;
    let (producer, consumer) = pair()?;
    let mut s = entry.state.lock().unwrap_or_else(|p| p.into_inner());
    ensure!(!s.closed, "USB upstream session ended");
    ensure!(
        s.metadata.as_ref().is_some_and(|m| m.restart),
        "Upstream agent upgrade required for safe USB rerouting"
    );
    ensure!(
        s.child.is_none(),
        "Imported USB device already has a downstream consumer"
    );
    validate(
        &s,
        s.metadata
            .as_ref()
            .context("USB import metadata unavailable")?,
    )?;
    let (ready, receive) = oneshot::channel();
    let cancel = CancellationToken::new();
    let key = format!("{child_id}:{}", uuid::Uuid::new_v4());
    s.child = Some(Child {
        key: key.clone(),
        producer: Some(producer),
        ready: Some(ready),
        cancel: cancel.clone(),
    });
    drop(s);
    changed(&entry);
    Ok(Lease {
        entry,
        key,
        ready: Some(receive),
        stream: Some(consumer),
        cancel,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn plan() -> Forward {
        Forward {
            id: uuid::Uuid::new_v4().simple().to_string(),
            source: "a".repeat(24),
            destination: "b".repeat(24),
            device: Device {
                busid: "1-5".into(),
                vendor: "1377".into(),
                product: "1100".into(),
                serial: "test".into(),
                name: "Mic".into(),
                busnum: 1,
                devnum: 5,
                speed: 3,
                blocked: None,
            },
            persistent: false,
        }
    }
    #[tokio::test]
    async fn exclusive_routing_preserves_bytes_and_releases_to_local_import() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let p = plan();
        gateway(dir.path(), true);
        let guard = register(dir.path(), &p)?;
        let mut change = guard.subscribe();
        let meta = Metadata {
            device: p.device.clone(),
            wire: super::super::protocol::legacy_device(&p.device)?,
            restart: true,
        };
        assert!(destination(dir.path(), &p, meta.clone())?.is_none());
        let d = inventory(dir.path()).remove(0);
        let mut lease = claim_checked(dir.path(), &d.busid, "child", |_, _| Ok(()))?;
        assert!(claim_checked(dir.path(), &d.busid, "other", |_, _| Ok(())).is_err());
        change.changed().await?;
        let mut producer = destination(dir.path(), &p, meta.clone())?.unwrap();
        let (mut consumer, actual) = lease.ready().await?;
        assert_eq!(&actual.wire[288..], &meta.wire[288..]);
        assert_eq!(actual.device.busnum, 1);
        assert_eq!(actual.device.devnum, 5);
        assert_eq!(actual.device.busid, d.busid);
        producer.write_all(b"opaque-iso").await?;
        let mut bytes = [0; 10];
        consumer.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"opaque-iso");
        consumer.write_all(b"urb").await?;
        let mut b = [0; 3];
        producer.read_exact(&mut b).await?;
        assert_eq!(&b, b"urb");
        drop(lease);
        change.changed().await?;
        assert!(destination(dir.path(), &p, meta)?.is_none());
        drop(guard);
        assert!(inventory(dir.path()).is_empty());
        Ok(())
    }
    #[tokio::test]
    async fn failed_safety_guard_does_not_reserve_and_gateway_loss_revokes() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let other = tempfile::tempdir()?;
        let p = plan();
        gateway(dir.path(), true);
        let _guard = register(dir.path(), &p)?;
        let metadata = Metadata {
            device: p.device.clone(),
            wire: super::super::protocol::legacy_device(&p.device)?,
            restart: true,
        };
        destination(dir.path(), &p, metadata)?;
        let alias = inventory(dir.path()).remove(0).busid;
        assert!(claim_checked(other.path(), &alias, "foreign-profile", |_, _| Ok(())).is_err());
        assert!(
            claim_checked(dir.path(), &alias, "unsafe-mounted", |_, _| anyhow::bail!(
                "mounted device"
            ))
            .is_err()
        );
        let mut lease = claim_checked(dir.path(), &alias, "safe", |_, _| Ok(()))?;
        gateway(dir.path(), false);
        assert!(lease.ready().await.is_err());
        assert!(imports(dir.path()).is_empty());
        assert!(claim_checked(dir.path(), &alias, "offline-gateway", |_, _| Ok(())).is_err());
        gateway(dir.path(), true);
        assert!(claim_checked(dir.path(), &alias, "new", |_, _| Ok(())).is_ok());
        Ok(())
    }
    #[tokio::test]
    async fn serialless_identity_keeps_numeric_ids_and_requires_restart_capability() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut p = plan();
        p.device.serial.clear();
        gateway(dir.path(), true);
        let _guard = register(dir.path(), &p)?;
        let mut metadata = Metadata {
            device: p.device.clone(),
            wire: super::super::protocol::legacy_device(&p.device)?,
            restart: false,
        };
        destination(dir.path(), &p, metadata.clone())?;
        let alias = inventory(dir.path()).remove(0).busid;
        assert!(claim_checked(dir.path(), &alias, "legacy", |_, _| Ok(())).is_err());
        metadata.restart = true;
        destination(dir.path(), &p, metadata.clone())?;
        let mut lease = claim_checked(dir.path(), &alias, "current", |_, _| Ok(()))?;
        let _producer = destination(dir.path(), &p, metadata.clone())?.unwrap();
        let (_consumer, actual) = lease.ready().await?;
        assert_eq!(actual.device.serial, "");
        assert_eq!(actual.device.busid, alias);
        assert_eq!(actual.device.busnum, p.device.busnum);
        assert_eq!(actual.device.devnum, p.device.devnum);
        assert_eq!(&actual.wire[288..], &metadata.wire[288..]);
        Ok(())
    }
    #[tokio::test]
    async fn upstream_revocation_cancels_waiting_lease_and_never_reuses_epoch() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let p = plan();
        gateway(dir.path(), true);
        let guard = register(dir.path(), &p)?;
        destination(
            dir.path(),
            &p,
            Metadata {
                device: p.device.clone(),
                wire: super::super::protocol::legacy_device(&p.device)?,
                restart: true,
            },
        )?;
        let d = inventory(dir.path()).remove(0);
        let mut lease = claim_checked(dir.path(), &d.busid, "child", |_, _| Ok(()))?;
        drop(guard);
        assert!(lease.ready().await.is_err());
        assert!(claim_checked(dir.path(), &d.busid, "other", |_, _| Ok(())).is_err());
        let _replacement = register(dir.path(), &p)?;
        assert!(claim_checked(dir.path(), &d.busid, "other", |_, _| Ok(())).is_err());
        Ok(())
    }
}

/// Local consumer teardown and its lease notification are adjacent operations.
/// Delay only EOF briefly so the authenticated planned-restart handshake wins
/// over a faster local TCP FIN. Ordinary payload reads/writes are unchanged.
pub(super) struct RoutedStream<S> {
    stream: S,
    guarded: bool,
    eof: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}
impl<S> RoutedStream<S> {
    pub fn new(stream: S, guarded: bool) -> Self {
        Self {
            stream,
            guarded,
            eof: None,
        }
    }
}
impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for RoutedStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::{future::Future, pin::Pin, task::Poll};
        if let Some(wait) = self.eof.as_mut() {
            return wait.as_mut().poll(cx).map(|_| Ok(()));
        }
        let before = buf.filled().len();
        let capacity = buf.remaining();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if self.guarded
            && capacity > 0
            && matches!(result, Poll::Ready(Ok(())))
            && buf.filled().len() == before
        {
            let mut wait = Box::pin(tokio::time::sleep(std::time::Duration::from_millis(500)));
            let result = wait.as_mut().poll(cx).map(|_| Ok(()));
            self.eof = Some(wait);
            result
        } else {
            result
        }
    }
}
impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for RoutedStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, bytes)
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
