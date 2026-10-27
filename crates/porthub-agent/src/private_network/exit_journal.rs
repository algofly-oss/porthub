//! Exact policy ownership, written before mutation and recovered after a crash.
use super::exit_routes::{FIRST, LAST, PROTOCOL};
use anyhow::{ensure, Result};
use nlink::netlink::{
    route::Ipv4Route, rule::RuleBuilder, types::route::RouteScope, Connection, Route,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::Ipv4Addr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

const PATH: &str = "/run/porthub-exits/consumer.json";
#[derive(Serialize, Deserialize)]
pub(super) struct Journal {
    pub index: u32,
    pub name: String,
    pub own: Ipv4Addr,
    pub sources: Vec<(Ipv4Addr, u32)>,
    #[serde(default)]
    pub ipv6_guard: bool,
    #[serde(default)]
    pub own_source_rule: bool,
    #[serde(default)]
    pub container_forwarding: bool,
}
impl Journal {
    pub fn table(&self) -> u32 {
        100_000 + self.index
    }
    pub fn save(&self) -> Result<()> {
        let mut file = tempfile::NamedTempFile::new_in("/run/porthub-exits")?;
        serde_json::to_writer(file.as_file_mut(), self)?;
        file.flush()?;
        file.as_file().sync_all()?;
        file.persist(PATH)?;
        Ok(())
    }
    fn load() -> Result<Option<Self>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(PATH)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let meta = file.metadata()?;
        ensure!(
            meta.is_file()
                && meta.uid() == 0
                && meta.nlink() == 1
                && meta.mode() & 0o077 == 0
                && meta.len() <= 65536,
            "invalid exit routing journal"
        );
        let journal: Self = serde_json::from_reader(file.take(65536))?;
        ensure!(
            journal.index > 0
                && journal.index <= u32::MAX - 100_000
                && journal.own.is_private()
                && journal.name.len() == 10
                && journal.name.starts_with("ph")
                && journal.name[2..].bytes().all(|c| c.is_ascii_hexdigit())
                && journal.sources.len() <= 128
                && journal
                    .sources
                    .iter()
                    .all(|(_, priority)| (FIRST + 1..FIRST + 65).contains(priority)),
            "invalid exit routing ownership"
        );
        Ok(Some(journal))
    }
    pub async fn recover(netlink: &Connection<Route>) -> Result<()> {
        let Some(old) = Self::load()? else {
            return Ok(());
        };
        ensure!(
            !netlink
                .get_link_by_index(old.index)
                .await?
                .is_some_and(|link| link.name() == Some(old.name.as_str())),
            "another exit route owns this host"
        );
        old.clear(netlink).await
    }
    pub async fn clear(&self, netlink: &Connection<Route>) -> Result<()> {
        if let Some(current) = Self::load()? {
            ensure!(
                current.index == self.index && current.name == self.name && current.own == self.own,
                "exit route ownership changed"
            );
        }
        if self.container_forwarding {
            super::exit_containers::clear(&self.name).await?;
            for rule in super::exit_containers::routes(self.index, self.table())? {
                netlink.del_rule_if_exists(rule).await?;
            }
        }
        if self.ipv6_guard {
            super::exit_ipv6::clear(&self.name).await?;
        }
        netlink
            .del_rule_if_exists(
                RuleBuilder::v4()
                    .priority(LAST)
                    .protocol(PROTOCOL)
                    .table(self.table()),
            )
            .await?;
        if self.own_source_rule {
            netlink.del_rule_if_exists(RuleBuilder::v4().priority(FIRST + 65).protocol(PROTOCOL)
                .from_prefix(&self.own.to_string(), 32).table(self.table())).await?;
        }
        for (ip, priority) in &self.sources {
            netlink
                .del_rule_if_exists(
                    RuleBuilder::v4()
                        .priority(*priority)
                        .protocol(PROTOCOL)
                        .from_prefix(&ip.to_string(), 32)
                        .table(254),
                )
                .await?;
        }
        netlink
            .del_rule_if_exists(
                RuleBuilder::v4()
                    .priority(FIRST)
                    .protocol(PROTOCOL)
                    .table(254)
                    .suppress_prefixlen(0),
            )
            .await?;
        netlink
            .del_route_if_exists(
                Ipv4Route::new(Ipv4Addr::UNSPECIFIED, 0)
                    .table(self.table())
                    .dev_index(self.index)
                    .prefsrc(self.own)
                    .scope(RouteScope::Link),
            )
            .await?;
        match std::fs::remove_file(PATH) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}
