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

pub async fn watch(
    owner: String,
    mut enabled: tokio::sync::watch::Receiver<BTreeSet<std::net::Ipv4Addr>>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut retry = false;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            changed = enabled.changed() => {
                if changed.is_err() { return Ok(()); }
                tick.reset();
            },
            _ = tick.tick(), if !enabled.borrow().is_empty() || retry => {},
        }
        let wanted = enabled.borrow_and_update().clone();
        let result = async {
            super::exit_kernel::Kernel::new(&owner)?.docker_forwarding(&wanted).await?;
            update(&owner, !wanted.is_empty()).await
        }.await;
        if result.is_err() && !retry {
            tracing::warn!("exit forwarding refresh failed; retrying while private control stays connected");
        }
        retry = result.is_err();
    }
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
        rules.diff(&nft).await?.apply(&nft).await?;
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
