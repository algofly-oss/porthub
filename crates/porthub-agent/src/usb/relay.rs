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
/// A registered alias exists, but this epoch has no authenticated metadata yet.
#[derive(Debug)]
pub(super) struct Reconnecting;
impl std::fmt::Display for Reconnecting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("USB upstream session is reconnecting; retry shortly")
    }
}
impl std::error::Error for Reconnecting {}
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
    #[cfg(windows)] local_windows:Option<super::windows::Marker>,
    routed: bool,
}
struct Entry {
    alias: String,
    plan: Forward,
    state: Mutex<State>,
    changed: watch::Sender<u64>,
}
#[cfg(windows)]
struct Retirement {marker:super::windows::Marker,plan:Forward}
#[derive(Default)]
struct Registry {
    entries: HashMap<(PathBuf, String), Weak<Entry>>,
    gateways: HashMap<PathBuf, bool>,
    #[cfg(windows)] retiring:HashMap<(PathBuf,String),Retirement>,
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
    #[cfg(windows)] registry_prune_retired(&mut r);
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
    } else if !state.routed && !has_local(state) {
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
        #[cfg(windows)] {None}
        #[cfg(not(any(target_os = "linux",windows)))] {None}
    };
    Some(d)
}
pub(super) fn inventory(path: &Path) -> Vec<Device> {
    let gate=supported(path);
    #[cfg(windows)] {
        let candidates=entries(path).into_iter().filter_map(|entry| {
            let state=entry.state.lock().unwrap_or_else(|p|p.into_inner());
            if state.closed {return None}
            let device=descriptor(&entry,&state,gate)?;
            let marker=if device.blocked.is_none(){state.local_windows.clone()}else{None};
            Some((device,marker))
        }).collect::<Vec<_>>();
        // One bounded storage inventory for all displayed aliases, never one
        // full disk/volume scan per alias. Claims always take a fresh snapshot.
        let snapshot=candidates.iter().any(|(_,m)|m.is_some()).then(super::windows::StorageSnapshot::capture);
        return candidates.into_iter().map(|(mut device,marker)| {
            if let (Some(marker),Some(snapshot))=(marker,snapshot.as_ref()) {
                if let Err(error)=marker.validate_with(snapshot){device.blocked=Some(error.to_string().chars().take(256).collect());}
            }
            device
        }).collect();
    }
    #[cfg(not(windows))] {
        entries(path).into_iter().filter_map(|entry| {
            let state=entry.state.lock().unwrap_or_else(|p|p.into_inner());
            if state.closed {None}else{descriptor(&entry,&state,gate)}
        }).collect()
    }
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
        let mut registry=registry().lock().unwrap_or_else(|p|p.into_inner());
        let key=(self.path.clone(),self.entry.plan.id.clone());
        let mut state=self.entry.state.lock().unwrap_or_else(|p|p.into_inner());
        state.closed=true;
        if let Some(child)=state.child.take(){child.cancel.cancel();}
        #[cfg(windows)] let retiring=state.local_windows.clone().filter(|marker|!marker.settled());
        #[cfg(windows)] if let Some(marker)=&retiring {registry.retiring.insert(key.clone(),Retirement{marker:marker.clone(),plan:self.entry.plan.clone()});}
        if registry.entries.get(&key).is_some_and(|entry|Weak::ptr_eq(entry,&Arc::downgrade(&self.entry))) {registry.entries.remove(&key);}
        drop(state);drop(registry);
        #[cfg(windows)] if let Some(marker)=retiring {marker.retire();}
        changed(&self.entry);
    }
}

#[cfg(windows)]
fn registry_prune_retired(registry:&mut Registry) {registry.retiring.retain(|_,record|!record.marker.settled());}
#[cfg(windows)]
fn retired_conflicts(path:&Path,plan:&Forward,key:&(PathBuf,String),record:&Retirement)->bool {
    key.0==path && (alias(&key.1)==alias(&plan.id) || (record.plan.source==plan.source && record.plan.device.vendor==plan.device.vendor && record.plan.device.product==plan.device.product && (record.plan.device.serial.is_empty() || plan.device.serial.is_empty() || record.plan.device.serial==plan.device.serial)))
}
pub(super) fn register(path: &Path, plan: &Forward) -> Result<ImportGuard> {
    #[cfg(windows)] {
        let pending=registry().lock().unwrap_or_else(|p|p.into_inner()).retiring.iter().filter(|(key,record)|retired_conflicts(path,plan,key,record)).map(|(_,record)|record.marker.clone()).collect::<Vec<_>>();
        for marker in pending {ensure!(marker.settled()||marker.reconcile_retired()?,"Previous owned USB attachment for this source/device is still settling");}
    }
    let alias = alias(&plan.id);
    let mut r = registry().lock().unwrap_or_else(|p| p.into_inner());
    let key = (path.to_owned(), plan.id.clone());
    #[cfg(windows)] {
        registry_prune_retired(&mut r);
        ensure!(!r.retiring.iter().any(|(key,record)|retired_conflicts(path,plan,key,record)),"Previous owned USB source/device remains fenced");
        ensure!(r.entries.len()+r.retiring.len()<128,"Native USB import/retirement capacity reached");
    }
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
            #[cfg(windows)] local_windows:None,
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
    #[cfg(windows)] check_local_settled(s.local_windows.as_ref().map(|marker|marker.settled()))?;
    s.metadata = Some(metadata.clone());
    s.local_port = None;
    #[cfg(windows)] {s.local_windows=None;}
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
#[cfg(any(windows,test))]
fn check_local_settled(settled:Option<bool>)->Result<()> {
    ensure!(settled!=Some(false),"Owned imported USB controller has not settled before rerouting");Ok(())
}
fn has_local(state:&State)->bool {
    #[cfg(windows)] {state.local_windows.is_some()}
    #[cfg(not(windows))] {state.local_port.is_some()}
}
#[cfg(windows)]
pub(super) fn local_windows(path:&Path,id:&str,marker:super::windows::Marker)->Result<()> {
    let entry=entries(path).into_iter().find(|e|e.plan.id==id).context("USB import registry unavailable")?;
    let mut state=entry.state.lock().unwrap_or_else(|p|p.into_inner());
    ensure!(!state.closed && state.child.is_none(),"USB import ownership changed");
    state.local_windows=Some(marker);state.routed=false;Ok(())
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
    #[cfg(windows)] let checked={
        let entry=find(path,busid)?;
        let marker=entry.state.lock().unwrap_or_else(|p|p.into_inner()).local_windows.clone();
        if let Some(marker)=&marker {marker.validate()?;}
        marker
    };
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
        #[cfg(windows)] {
            let _=meta;
            match (&checked,&state.local_windows) {
                (Some(checked),Some(current))=>ensure!(current.same(checked)&&current.active(),"Imported USB ownership changed during claim"),
                (None,None)=>ensure!(state.routed,"Imported USB is still changing ownership; retry shortly"),
                _=>anyhow::bail!("Imported USB ownership changed during claim"),
            }
        }
        #[cfg(not(any(target_os="linux",windows)))] {let _=(state,meta);anyhow::bail!("Native USB relay unavailable on this platform");}
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
    // A stable alias can outlive an upstream connection epoch. Its replacement
    // entry is intentionally unready until fresh authenticated descriptors arrive.
    let metadata = s
        .metadata
        .as_ref()
        .ok_or(Reconnecting)?;
    ensure!(
        metadata.restart,
        "Upstream agent upgrade required for safe USB rerouting"
    );
    ensure!(
        s.child.is_none(),
        "Imported USB device already has a downstream consumer"
    );
    validate(&s, metadata)?;
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
    #[cfg(windows)]
    #[test]
    fn canceled_pending_plug_late_success_cleanup_busy_keeps_exact_key_fenced()->Result<()> {
        let dir=tempfile::tempdir()?;let p=plan();gateway(dir.path(),true);
        let import=register(dir.path(),&p)?;
        let marker=super::super::windows::Marker::pending_test(p.device.clone());
        local_windows(dir.path(),&p.id,marker.clone())?;
        drop(import); // Cancellation before PLUG returns a positive port.
        assert!(registry().lock().unwrap_or_else(|p|p.into_inner()).retiring.contains_key(&(dir.path().to_owned(),p.id.clone())));
        assert!(register(dir.path(),&p).is_err());
        // The real completion/cleanup reducers receive a late owned inert File.
        // Busy/failed cleanup cannot prove settlement or erase the retirement.
        marker.late_success_test(false)?;
        assert!(!marker.settled());assert!(register(dir.path(),&p).is_err());
        assert!(!marker.reconcile_test(false));assert!(register(dir.path(),&p).is_err());
        let mut unrelated=plan();unrelated.device.serial="different-owned-device".into();let other=register(dir.path(),&unrelated)?;drop(other);
        assert!(marker.reconcile_test(true));
        let next=register(dir.path(),&p)?;drop(next);
        Ok(())
    }
    #[cfg(windows)]
    #[test]
    fn recreated_plan_and_serialless_bus_change_cannot_bypass_pending_device_fence()->Result<()> {
        let dir=tempfile::tempdir()?;let mut p=plan();p.device.serial.clear();gateway(dir.path(),true);
        let import=register(dir.path(),&p)?;let marker=super::super::windows::Marker::pending_test(p.device.clone());local_windows(dir.path(),&p.id,marker.clone())?;drop(import);
        let mut recreated=p.clone();recreated.id=uuid::Uuid::new_v4().simple().to_string();recreated.device.busid="7-9".into();
        assert!(register(dir.path(),&recreated).is_err());marker.late_success_test(false)?;assert!(register(dir.path(),&recreated).is_err());
        let mut other_source=recreated.clone();other_source.source="c".repeat(24);let other=register(dir.path(),&other_source)?;drop(other);
        assert!(marker.reconcile_test(true));let next=register(dir.path(),&recreated)?;drop(next);Ok(())
    }
    #[cfg(windows)]
    #[test]
    fn failed_local_detach_then_import_drop_cannot_erase_the_retirement_fence()->Result<()> {
        let dir=tempfile::tempdir()?;let p=plan();gateway(dir.path(),true);
        let import=register(dir.path(),&p)?;let marker=super::super::windows::Marker::pending_test(p.device.clone());
        local_windows(dir.path(),&p.id,marker.clone())?;
        marker.retire();marker.late_success_test(false)?;
        assert!(!marker.settled());drop(import);
        assert!(register(dir.path(),&p).is_err());assert!(!marker.reconcile_test(false));
        assert!(marker.reconcile_test(true));let next=register(dir.path(),&p)?;drop(next);Ok(())
    }
    #[cfg(windows)]
    #[test]
    fn canceled_pending_plug_late_success_requires_completed_cleanup_before_reregister()->Result<()> {
        let dir=tempfile::tempdir()?;let p=plan();gateway(dir.path(),true);
        let import=register(dir.path(),&p)?;let marker=super::super::windows::Marker::pending_test(p.device.clone());
        local_windows(dir.path(),&p.id,marker.clone())?;drop(import);
        assert!(register(dir.path(),&p).is_err());marker.late_success_test(true)?;
        assert!(marker.settled());let next=register(dir.path(),&p)?;drop(next);Ok(())
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn windows_child_cannot_receive_epoch_until_owned_local_settles()->Result<()> {
        let dir=tempfile::tempdir()?;let p=plan();gateway(dir.path(),true);
        let _import=register(dir.path(),&p)?;
        let metadata=Metadata{device:p.device.clone(),wire:super::super::protocol::legacy_device(&p.device)?,restart:true};
        assert!(destination(dir.path(),&p,metadata.clone())?.is_none());
        let marker=super::super::windows::Marker::pending_test(p.device.clone());
        local_windows(dir.path(),&p.id,marker.clone())?;
        let d=inventory(dir.path()).remove(0);
        let mut lease=claim_checked(dir.path(),&d.busid,"child",|_,_|Ok(()))?;
        assert!(destination(dir.path(),&p,metadata.clone()).is_err());
        // A failed/pending detach leaves the old marker false; no stream or
        // metadata is handed to the child and its readiness remains pending.
        assert!(tokio::time::timeout(std::time::Duration::from_millis(5),lease.ready()).await.is_err());
        // ready() is single-use, so obtain a fresh owned lease after cancellation.
        drop(lease);
        let mut lease=claim_checked(dir.path(),&d.busid,"next",|_,_|Ok(()))?;
        marker.settle_test();
        let _producer=destination(dir.path(),&p,metadata)?.context("Fresh downstream stream missing")?;
        let (_consumer,received)=lease.ready().await?;
        assert_eq!(received.device.busid,d.busid);
        Ok(())
    }
    #[test]
    fn downstream_epoch_requires_explicit_local_settlement() {
        assert!(check_local_settled(None).is_ok());
        // Attachment remains unready throughout unplug/pending PnP removal,
        // timeout, and failed detach. Only explicit settled success releases it.
        assert!(check_local_settled(Some(false)).is_err());
        assert!(check_local_settled(Some(true)).is_ok());
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
    async fn reconnecting_alias_is_unready_without_claiming_legacy_capability() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let p = plan();
        gateway(dir.path(), true);
        let guard = register(dir.path(), &p)?;
        let mut metadata = Metadata {
            device: p.device.clone(),
            wire: super::super::protocol::legacy_device(&p.device)?,
            restart: true,
        };
        destination(dir.path(), &p, metadata.clone())?;
        let alias = inventory(dir.path()).remove(0).busid;
        // Reconnect recreates the same public alias before any new authenticated
        // descriptor/capability publication. A stale selection must fail closed.
        drop(guard);
        let _replacement = register(dir.path(), &p)?;
        let validated = std::cell::Cell::new(false);
        let result = claim_checked(dir.path(), &alias, "unready", |_, _| {
            validated.set(true);
            Ok(())
        });
        let error = result.err().unwrap();
        assert!(error.is::<Reconnecting>());
        assert_eq!(
            error.to_string(),
            "USB upstream session is reconnecting; retry shortly"
        );
        assert!(!validated.get());
        assert!(find(dir.path(), &alias)?.state.lock().unwrap().child.is_none());
        // A genuinely negotiated old peer still gets the upgrade diagnostic.
        metadata.restart = false;
        destination(dir.path(), &p, metadata.clone())?;
        let result = claim_checked(dir.path(), &alias, "legacy", |_, _| {
            validated.set(true);
            Ok(())
        });
        assert_eq!(
            result.err().unwrap().to_string(),
            "Upstream agent upgrade required for safe USB rerouting"
        );
        assert!(!validated.get());
        // Only a fresh authenticated, restart-capable epoch permits a child.
        metadata.restart = true;
        destination(dir.path(), &p, metadata)?;
        let _lease = claim_checked(dir.path(), &alias, "current", |_, _| {
            validated.set(true);
            Ok(())
        })?;
        assert!(validated.get());
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
