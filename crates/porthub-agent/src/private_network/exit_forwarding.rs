//! Reference-counted return-path forwarding for Linux exit registrations.
//! Interfaces that previously could not forward remain restricted to tracked
//! replies into PortHub TUNs. The journal lets later services recover cleanup.
use anyhow::{ensure, Context, Result};
use nlink::netlink::{
    nftables::{config::NftablesConfig, BaseChain, CtState, Family, FilterHook, Priority},
    Connection, Nftables, Route,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
    time::Duration,
};

const DIRECTORY: &str = "/run/porthub-exits";
const TABLE: &str = "porthub_exit_return";

/// Readiness is metadata only; packet authority remains the caller's concern.
#[derive(Clone, Debug)]
pub(crate) struct Plan {
    generation: u64,
    clients: std::sync::Arc<BTreeSet<std::net::Ipv4Addr>>,
}
#[cfg(feature="netns-tests")]
impl Plan {pub(crate) fn diagnostic_generation(&self)->u64{self.generation}}
impl PartialEq for Plan {fn eq(&self,other:&Self)->bool{self.generation==other.generation&&std::sync::Arc::ptr_eq(&self.clients,&other.clients)}}
impl Eq for Plan {}
#[derive(Clone)]
pub(crate) struct Readiness {
    desired: tokio::sync::watch::Sender<Plan>,
    applied: tokio::sync::watch::Receiver<Option<Plan>>,
    failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(feature="netns-tests")] fixture_withheld:std::sync::Arc<std::sync::atomic::AtomicBool>,
}
pub(crate) struct Requests {
    desired: tokio::sync::watch::Receiver<Plan>,
    applied: tokio::sync::watch::Sender<Option<Plan>>,
}
pub(crate) fn readiness_channel() -> (Readiness, Requests) {
    let (desired, requests) = tokio::sync::watch::channel(Plan {
        generation: 0,
        clients: std::sync::Arc::new(BTreeSet::new()),
    });
    let (applied, observed) = tokio::sync::watch::channel(None);
    (
        Readiness {
            desired,
            applied: observed,
            failed: Default::default(),
            #[cfg(feature="netns-tests")] fixture_withheld:Default::default(),
        },
        Requests {
            desired: requests,
            applied,
        },
    )
}
impl Readiness {
    /// Semantic changes only. Overflow fails closed rather than reusing an ACK.
    pub(crate) fn request(&self, clients: BTreeSet<std::net::Ipv4Addr>) -> Result<Plan> {
        let mut result = Ok(());
        self.desired.send_if_modified(|current| {
            if *current.clients == clients {
                return false;
            }
            let Some(next) = current.generation.checked_add(1) else {
                result = Err(anyhow::anyhow!("exit readiness generation exhausted"));
                return false;
            };
            *current = Plan {
                generation: next,
                clients: std::sync::Arc::new(clients),
            };
            true
        });
        if result.is_err() {
            // No old success may survive a failed desired-state transition.
            self.failed.store(true, std::sync::atomic::Ordering::SeqCst);
            return result.map(|_| unreachable!());
        }
        Ok(self.desired.borrow().clone())
    }
    #[cfg(feature="netns-tests")]
    pub(crate) fn fixture_withhold(&self,held:bool){self.fixture_withheld.store(held,std::sync::atomic::Ordering::SeqCst);}
    pub(crate) fn ready(&self, plan: &Plan) -> bool {
        #[cfg(feature="netns-tests")]
        if self.fixture_withheld.load(std::sync::atomic::Ordering::SeqCst){return false;}
        !self.failed.load(std::sync::atomic::Ordering::SeqCst)
            && !self.applied.has_changed().is_err()
            // Plan equality is generation+immutable publication Arc identity,
            // never a per-packet source-set scan or cross-channel value match.
            && *self.desired.borrow() == *plan
            && self.applied.borrow().as_ref() == Some(plan)
    }
    pub(crate) async fn changed(&mut self) -> Result<()> {
        self.applied.changed().await.map_err(Into::into)
    }
}
impl Requests {
    fn acknowledge(&self, plan: &Plan, success: bool) {
        // Even an old ACK cannot become ready again after a source-set roundtrip.
        if success && *self.desired.borrow() == *plan {
            self.applied.send_replace(Some(plan.clone()));
        } else {
            self.applied.send_replace(None);
        }
    }
}
/// Opt-in successor to `watch`; legacy callers retain unchanged behavior.
/// The ACK follows the WHOLE apply (including NAT, host forwarding and sysctl).
pub(crate) async fn watch_ready(
    owner: String,
    mut requests: Requests,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let kernel = super::exit_kernel::Kernel::new(&owner)?;
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut retry = false;
    let mut used = false;
    let result: Result<()> = async {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                changed = requests.desired.changed() => { changed?; tick.reset(); },
                _ = tick.tick(), if !requests.desired.borrow().clients.is_empty() || retry => {},
            }
            let plan = requests.desired.borrow_and_update().clone();
            used |= !plan.clients.is_empty();
            // A full apply is multi-step; prior success is not proof mid-refresh.
            requests.applied.send_replace(None);
            #[cfg(all(feature="private-sparse",feature="netns-tests"))]
            super::runtime::provider_fixture_phase("native_apply_begin",plan.generation,plan.clients.len());
            let applied = kernel.apply(&plan.clients).await;
            requests.acknowledge(&plan, applied.is_ok());
            #[cfg(all(feature="private-sparse",feature="netns-tests"))]
            super::runtime::provider_fixture_phase(if applied.is_ok(){"native_apply_acked"}else{"native_apply_failed"},plan.generation,plan.clients.len());
            if applied.is_err() && !retry {
                tracing::warn!("exit forwarding refresh failed; readiness remains unproven");
            }
            retry = applied.is_err();
        }
        Ok(())
    }
    .await;
    requests.applied.send_replace(None);
    if used {
        kernel.clear().await?;
    }
    result
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    fn clients(n: u8) -> BTreeSet<std::net::Ipv4Addr> {
        [std::net::Ipv4Addr::new(10, 203, 0, n)].into()
    }
    #[test]
    fn cloned_publication_is_shared_but_equal_foreign_channel_is_not_its_ack(){
        let(a,worker)=readiness_channel();let plan=a.request(clients(1)).unwrap();worker.acknowledge(&plan,true);let clone=plan.clone();
        assert!(std::sync::Arc::ptr_eq(&plan.clients,&clone.clients));assert!(a.ready(&clone));
        let(b,other)=readiness_channel();let foreign=b.request(clients(1)).unwrap();other.acknowledge(&foreign,true);
        assert_ne!(plan,foreign);assert!(!a.ready(&foreign));assert!(!b.ready(&plan));
    }
    #[test]
    fn only_exact_successful_generation_and_source_set_is_ready() {
        let (ready, worker) = readiness_channel();
        let first = ready.request(clients(1)).unwrap();
        assert!(!ready.ready(&first));
        worker.acknowledge(&first, false);
        assert!(!ready.ready(&first));
        worker.acknowledge(&first, true);
        assert!(ready.ready(&first));
        assert_eq!(ready.request(clients(1)).unwrap(), first);
        let second = ready.request(clients(2)).unwrap();
        assert!(!ready.ready(&first));
        worker.acknowledge(&first, true);
        assert!(!ready.ready(&second));
        worker.acknowledge(&second, true);
        assert!(ready.ready(&second));
        let third = ready.request(clients(1)).unwrap();
        assert_ne!(third, first);
        worker.acknowledge(&first, true);
        assert!(!ready.ready(&third));
        worker.acknowledge(&third, true);
        assert!(ready.ready(&third));
        drop(worker);
        assert!(!ready.ready(&third));
    }
    #[test]
    fn generation_overflow_permanently_invalidates_previous_success() {
        let (ready, worker) = readiness_channel();
        ready.desired.send_modify(|plan| {
            plan.generation = u64::MAX;
            plan.clients = clients(1).into();
        });
        let old = ready.desired.borrow().clone();
        worker.acknowledge(&old, true);
        assert!(ready.ready(&old));
        assert!(ready.request(clients(2)).is_err());
        assert!(!ready.ready(&old));
        worker.acknowledge(&old, true);
        assert!(!ready.ready(&old));
    }
    #[tokio::test]
    async fn failure_and_withdrawal_wake_observers_without_claiming_readiness() {
        let (mut ready, worker) = readiness_channel();
        let first = ready.request(clients(1)).unwrap();
        worker.acknowledge(&first, false);
        ready.changed().await.unwrap();
        assert!(!ready.ready(&first));
        worker.acknowledge(&first, true);
        ready.changed().await.unwrap();
        assert!(ready.ready(&first));
        let empty = ready.request(BTreeSet::new()).unwrap();
        assert!(!ready.ready(&first));
        assert!(!ready.ready(&empty));
        worker.acknowledge(&empty, true);
        ready.changed().await.unwrap();
        assert!(ready.ready(&empty));
    }
}

pub async fn watch(
    owner: String,
    mut enabled: tokio::sync::watch::Receiver<BTreeSet<std::net::Ipv4Addr>>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let kernel = super::exit_kernel::Kernel::new(&owner)?;
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut retry = false;
    let mut used = false;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            changed = enabled.changed() => {
                if changed.is_err() { break; }
                tick.reset();
            },
            _ = tick.tick(), if !enabled.borrow().is_empty() || retry => {},
        }
        let wanted = enabled.borrow_and_update().clone();
        used |= !wanted.is_empty();
        // A host firewall writer can invalidate our snapshot. Exhausted
        // retries leave the last committed rules intact and keep private
        // control/heartbeats running while this worker retries later.
        let result = kernel.apply(&wanted).await;
        if result.is_err() && !retry {
            tracing::warn!(
                "exit forwarding refresh failed; retrying while private control stays connected"
            );
        }
        retry = result.is_err();
    }
    if used {
        kernel.clear().await?;
    }
    Ok(())
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    index: u32,
    original: bool,
    owners: BTreeSet<String>,
}
type Journal = BTreeMap<String, Entry>;

fn private_directory() -> Result<()> {
    match std::fs::DirBuilder::new().mode(0o700).create(DIRECTORY) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    let meta = std::fs::symlink_metadata(DIRECTORY)?;
    ensure!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o077 == 0,
        "invalid exit state directory"
    );
    Ok(())
}
fn save(journal: &Journal) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(DIRECTORY)?;
    serde_json::to_writer(file.as_file_mut(), journal)?;
    file.flush()?;
    file.as_file().sync_all()?;
    file.persist(Path::new(DIRECTORY).join("forwarding.json"))?;
    Ok(())
}
pub(super) async fn lock() -> Result<File> {
    private_directory()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(DIRECTORY).join("lock"))?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == 0 && meta.mode() & 0o077 == 0 && meta.nlink() == 1,
        "invalid exit state lock"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match fs2::FileExt::try_lock_exclusive(&file) {
                Ok(()) => return Ok::<_, std::io::Error>(()),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(20)).await
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .context("exit state is busy")??;
    Ok(file)
}
fn load() -> Result<Journal> {
    let path = Path::new(DIRECTORY).join("forwarding.json");
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Journal::new()),
        Err(error) => return Err(error.into()),
    };
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == 0 && meta.mode() & 0o077 == 0 && meta.len() <= 1_048_576,
        "invalid exit forwarding journal"
    );
    Ok(serde_json::from_reader(file.take(1_048_576))?)
}
fn path(name: &str) -> String {
    format!("/proc/sys/net/ipv4/conf/{name}/forwarding")
}

pub async fn update(owner: &str, enabled: bool) -> Result<()> {
    let _lock = lock().await?;
    let route = Connection::<Route>::new()?;
    let nft = Connection::<Nftables>::new()?;
    let links = route.get_links().await?;
    let live: BTreeMap<_, _> = links
        .iter()
        .filter_map(|link| link.name().map(|name| (name.to_owned(), link.ifindex())))
        .collect();
    let mut journal = load()?;
    let previous = journal.clone();
    // Removed TUNs cannot own forwarding. A reused underlay index must not
    // inherit or restore settings captured for a previous interface.
    journal.retain(|name, entry| live.get(name) == Some(&entry.index));
    for entry in journal.values_mut() {
        entry
            .owners
            .retain(|id| live.contains_key(id) && id != owner);
    }
    if enabled {
        let egress: BTreeSet<_> = route
            .get_routes()
            .await?
            .iter()
            .filter(|r| r.table_id() == 254 && r.is_ipv4())
            .filter_map(|r| r.oif())
            .collect();
        for (name, index) in &live {
            if !egress.contains(index) || name == owner || name == "lo" {
                continue;
            }
            if !journal.contains_key(name) {
                let value = tokio::fs::read_to_string(path(name)).await?;
                ensure!(
                    matches!(value.trim(), "0" | "1"),
                    "invalid interface forwarding setting"
                );
                journal.insert(
                    name.clone(),
                    Entry {
                        index: *index,
                        original: value.trim() == "1",
                        owners: BTreeSet::new(),
                    },
                );
            }
            journal
                .get_mut(name)
                .unwrap()
                .owners
                .insert(owner.to_owned());
        }
    }
    // Journal before mutation: an interrupted update is recoverable.
    if journal != previous {
        save(&journal)?;
    }
    let persisted = journal.clone();
    for (name, entry) in &journal {
        if entry.owners.is_empty() && !entry.original {
            tokio::fs::write(path(name), b"0\n").await?;
        }
    }
    journal.retain(|_, entry| !entry.owners.is_empty());
    let guarded: Vec<_> = journal
        .iter()
        .filter(|(_, entry)| !entry.original)
        .map(|(name, _)| name)
        .collect();
    if guarded.is_empty() {
        nft.del_table_if_exists(TABLE, Family::Ip).await?;
    } else {
        let rules = NftablesConfig::new().table(TABLE, Family::Ip, |mut table| {
            table = table.chain("forward", |chain| {
                chain
                    .base(BaseChain::filter(FilterHook::Forward, Priority::Filter))
                    .exclusive()
            });
            for name in &guarded {
                table = table
                    .rule_keyed("forward", format!("reply_{name}"), |r| {
                        r.match_iif(name)
                            .match_oif_prefix("ph")
                            .match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
                            .accept()
                    })
                    .rule_keyed("forward", format!("deny_{name}"), |r| {
                        r.match_iif(name).drop()
                    });
            }
            table
        });
        super::nft::apply(&rules, &nft).await?;
    }
    for name in guarded {
        if tokio::fs::read_to_string(path(name)).await?.trim() != "1" {
            tokio::fs::write(path(name), b"1\n").await?;
        }
    }
    if journal != persisted {
        save(&journal)?;
    }
    Ok(())
}
