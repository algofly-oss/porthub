//! Consumer policy routing. Existing underlay-bound connections retain their
//! original route; new unbound internet connections use the selected exit TUN.
use anyhow::{ensure, Result};
use nlink::netlink::{
    route::Ipv4Route, rule::RuleBuilder, types::route::RouteScope, Connection, Route,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

pub(super) const FIRST: u32 = 22500;
pub(super) const LAST: u32 = 22600;
pub(super) const PROTOCOL: u8 = 186;
pub(super) const LAN_PRIORITY:u32=FIRST+68;
pub(super) const PRIVATE_BYPASS_PRIORITY:u32=FIRST+69;
pub(super) const PRIVATE_NETWORKS:[(Ipv4Addr,u8);3]=[(Ipv4Addr::new(10,0,0,0),8),(Ipv4Addr::new(172,16,0,0),12),(Ipv4Addr::new(192,168,0,0),16)];

pub async fn watch(
    desired: tokio::sync::watch::Receiver<Option<(u32, Ipv4Addr, bool)>>,
    interfaces: tokio::sync::watch::Receiver<Vec<std::net::SocketAddr>>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    watch_reported(desired, interfaces, cancel, None).await
}

pub async fn watch_reported(
    desired:tokio::sync::watch::Receiver<Option<(u32,Ipv4Addr,bool)>>,
    interfaces:tokio::sync::watch::Receiver<Vec<std::net::SocketAddr>>,
    cancel:tokio_util::sync::CancellationToken,
    report:Option<tokio::sync::watch::Sender<&'static str>>,
)->Result<()> {watch_configuration(desired,interfaces,cancel,report).await}

pub async fn watch_plans_reported(
    desired:tokio::sync::watch::Receiver<Option<super::exit_plan::Plan>>,
    interfaces:tokio::sync::watch::Receiver<Vec<std::net::SocketAddr>>,
    cancel:tokio_util::sync::CancellationToken,
    report:Option<tokio::sync::watch::Sender<&'static str>>,
)->Result<()> {watch_configuration(desired,interfaces,cancel,report).await}

async fn watch_configuration<T:Clone+Into<super::exit_plan::Plan>>(
    mut desired:tokio::sync::watch::Receiver<Option<T>>,
    mut interfaces:tokio::sync::watch::Receiver<Vec<std::net::SocketAddr>>,
    cancel:tokio_util::sync::CancellationToken,
    report:Option<tokio::sync::watch::Sender<&'static str>>,
)->Result<()> {
    let mut active: Option<Consumer> = None;
    let mut retry = false;
    let mut timer = tokio::time::interval(std::time::Duration::from_secs(30));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            changed = desired.changed() => if changed.is_err() { break; },
            changed = interfaces.changed() => if changed.is_err() { break; },
            _ = timer.tick(), if retry || active.is_some() => {},
        }
        let wanted:Option<super::exit_plan::Plan> = desired.borrow_and_update().clone().map(Into::into);
        let next: BTreeSet<_> = interfaces
            .borrow_and_update()
            .iter()
            .filter_map(|address| match address.ip() {
                std::net::IpAddr::V4(ip) => Some(ip),
                _ => None,
            })
            .collect();
        let update: Result<()> = async {
            if active
                .as_ref()
                .is_some_and(|route| Some((route.index, route.own)) != wanted.as_ref().map(|plan| (plan.index, plan.own)))
            {
                active.as_mut().unwrap().clear().await?;
                active = None;
            }
            if let Some(plan) = &wanted {
                if let Some(route) = &mut active {
                    route.refresh(&next).await?;
                } else if !next.is_empty() {
                    active = Some(Consumer::activate_with_bypass(plan.index, plan.own, &next,plan.internet_bypass()).await?);
                }
                if let Some(route) = &mut active {
                    route.set_lan_networks(plan.lan_networks()).await?;
                    route.set_bypass(plan.internet_bypass()).await?;
                }
            }
            Ok(())
        }
        .await;
        if update.is_err() && !retry {
            tracing::warn!("exit route configuration failed; private control remains connected");
            timer.reset();
        }
        retry = update.is_err();
        if let Some(report) = &report {
            let state = if retry { "configuration error" }
                else if let Some(route) = &active { if wanted.as_ref().is_some_and(|plan|!plan.mode.internet()) { "LAN routing active" } else if route.bypass { "normal internet fallback" } else { "exit routing active" } }
                else if wanted.is_some() { "waiting for underlay" } else { "inactive" };
            if *report.borrow() != state { report.send_replace(state); }
        }
    }
    if let Some(route) = &mut active {
        route.clear().await?;
    }
    if let Some(report) = report { report.send_replace("inactive"); }
    Ok(())
}

pub struct Consumer {
    netlink: Connection<Route>,
    index: u32,
    own: Ipv4Addr,
    table: u32,
    rules: Vec<RuleBuilder>,
    sources: BTreeMap<Ipv4Addr, u32>,
    installed_route: bool,
    claimed: bool,
    bypass: bool,
    lan_applied:bool,
    journal: super::exit_journal::Journal,
}

impl Consumer {
    pub async fn activate(
        index: u32,
        own: Ipv4Addr,
        underlay: &BTreeSet<Ipv4Addr>,
    ) -> Result<Self> {
        Self::activate_with_bypass(index,own,underlay,false).await
    }
    /// Prepare ownership and physical-source bypasses without briefly taking
    /// over internet traffic when installing a LAN-only policy.
    pub async fn activate_with_bypass(index:u32,own:Ipv4Addr,underlay:&BTreeSet<Ipv4Addr>,bypass:bool)->Result<Self> {
        ensure!(
            own.is_private()
                && !underlay.is_empty()
                && underlay.len() <= 64
                && !underlay.contains(&own),
            "invalid exit source bindings"
        );
        ensure!(
            underlay
                .iter()
                .all(|ip| !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()),
            "invalid underlay address"
        );
        let _lock = super::exit_forwarding::lock().await?;
        let netlink = Connection::<Route>::new()?;
        let link = netlink
            .get_link_by_index(index)
            .await?
            .ok_or_else(|| anyhow::anyhow!("exit interface is unavailable"))?;
        let name = link.name().unwrap_or("").to_owned();
        ensure!(
            name.len() == 10
                && name.starts_with("ph")
                && name[2..].bytes().all(|c| c.is_ascii_hexdigit()),
            "exit interface is not owned by PortHub"
        );
        super::exit_journal::Journal::recover(&netlink).await?;
        // A host can have many registrations, but only one system-wide default
        // route policy. Never silently supersede another owner or another VPN.
        ensure!(
            !netlink
                .get_rules_v4()
                .await?
                .iter()
                .any(|rule| (FIRST..=LAST).contains(&rule.priority())),
            "another default-route policy uses the PortHub priority range"
        );
        let table = 100_000u32
            .checked_add(index)
            .ok_or_else(|| anyhow::anyhow!("invalid exit table"))?;
        ensure!(
            netlink.get_routes_for_table(table).await?.is_empty(),
            "exit route table is already in use"
        );
        let mut owner = Self {
            netlink,
            index,
            own,
            table,
            rules: Vec::new(),
            sources: BTreeMap::new(),
            installed_route: false,
            claimed: true,
            bypass,
            lan_applied:false,
            journal: super::exit_journal::Journal {
                index,
                name,
                own,
                sources: Vec::new(),
                lan_networks:Vec::new(),
                private_bypass:true,
                ipv6_guard: true,
                own_source_rule: true,
                container_forwarding: true,
            },
        };
        owner.journal.save()?;
        if let Err(error) = owner.install(underlay).await {
            let _ = owner.clear_inner().await;
            return Err(error);
        }
        Ok(owner)
    }
    fn route(&self) -> Ipv4Route {
        Ipv4Route::new(Ipv4Addr::UNSPECIFIED, 0)
            .table(self.table)
            .dev_index(self.index)
            .prefsrc(self.own)
            .scope(RouteScope::Link)
    }
    async fn add(&mut self, rule: RuleBuilder) -> Result<()> {
        self.netlink.add_rule(rule.clone()).await?;
        self.rules.push(rule);
        Ok(())
    }
    async fn install(&mut self, underlay: &BTreeSet<Ipv4Addr>) -> Result<()> {
        self.netlink.add_route(self.route()).await?;
        self.installed_route = true;
        self.add(
            RuleBuilder::v4()
                .priority(FIRST)
                .protocol(PROTOCOL)
                .table(254)
                .suppress_prefixlen(0),
        )
        .await?;
        self.add(RuleBuilder::v4().priority(FIRST + 65).protocol(PROTOCOL)
            .from_prefix(&self.own.to_string(), 32).table(self.table)).await?;
        self.update_sources(underlay).await?;
        for (address,prefix) in PRIVATE_NETWORKS {
            self.add(RuleBuilder::v4().priority(PRIVATE_BYPASS_PRIORITY).protocol(PROTOCOL)
                .to_prefix(&address.to_string(),prefix).table(254)).await?;
        }
        for rule in super::exit_containers::routes(self.index, self.table)? { self.add(rule).await?; }
        super::exit_containers::apply_with_lan(&self.journal.name, self.index, self.bypass,&self.journal.lan_networks).await?;
        super::exit_ipv6::apply_mode(&self.netlink, &self.journal.name,self.bypass).await?;
        // Install the catch-all last, once every management bypass is present.
        if self.bypass {return Ok(());}
        self.add(
            RuleBuilder::v4()
                .priority(LAST)
                .protocol(PROTOCOL)
                .table(self.table),
        )
        .await
    }
    fn source_rule(ip: Ipv4Addr, priority: u32) -> RuleBuilder {
        RuleBuilder::v4()
            .priority(priority)
            .protocol(PROTOCOL)
            .from_prefix(&ip.to_string(), 32)
            .table(254)
    }
    /// Destination rules follow existing local routes and physical-source
    /// bypasses. Main-table routes stay untouched, including gateway routes.
    pub async fn set_lan_networks(&mut self,networks:&[porthub_mesh::lan_routes::Network])->Result<()> {
        ensure!(networks.len()<=256,"too many exit LAN prefixes");
        let _lock=super::exit_forwarding::lock().await?;
        let wanted:BTreeSet<_>=networks.iter().copied().collect();
        let previous:BTreeSet<_>=self.journal.lan_networks.iter().copied().collect();
        if self.lan_applied && wanted==previous {return Ok(());}
        self.lan_applied=false;
        let actual:BTreeSet<_>=self.netlink.get_rules_v4().await?.iter()
            .filter(|rule|rule.priority()==LAN_PRIORITY && rule.protocol()==Some(PROTOCOL) && rule.table_id()==self.table)
            .filter_map(|rule|match rule.destination(){Some(std::net::IpAddr::V4(ip))=>porthub_mesh::lan_routes::Network::from_address(ip,rule.dst_len()).ok(),_=>None}).collect();
        // Record both old and new ownership before mutation. An interrupted
        // update remains recoverable without deleting unrelated policy rules.
        self.journal.lan_networks=previous.union(&wanted).copied().collect();self.journal.save()?;
        let rule=|network:porthub_mesh::lan_routes::Network|RuleBuilder::v4().priority(LAN_PRIORITY).protocol(PROTOCOL)
            .to_prefix(&network.address().to_string(),network.prefix()).table(self.table);
        for network in previous.difference(&wanted) {self.netlink.del_rule_if_exists(rule(*network)).await?;}
        for network in wanted.difference(&actual) {self.netlink.add_rule(rule(*network)).await?;}
        self.journal.lan_networks=wanted.into_iter().collect();self.journal.save()?;
        super::exit_containers::apply_with_lan(&self.journal.name,self.index,self.bypass,&self.journal.lan_networks).await?;
        self.lan_applied=true;
        Ok(())
    }
    pub async fn refresh(&mut self, underlay: &BTreeSet<Ipv4Addr>) -> Result<()> {
        let _lock = super::exit_forwarding::lock().await?;
        self.update_sources(underlay).await?;
        super::exit_containers::apply_with_lan(&self.journal.name, self.index, self.bypass,&self.journal.lan_networks).await?;
        super::exit_ipv6::apply_mode(&self.netlink, &self.journal.name, self.bypass).await?;
        Ok(())
    }
    /// Change only new-connection routing. Overlay-source connections retain
    /// their TUN rule; underlay-source connections retain their main-table rule.
    pub async fn set_bypass(&mut self, bypass: bool) -> Result<()> {
        if self.bypass == bypass { return Ok(()); }
        let _lock = super::exit_forwarding::lock().await?;
        let catch_all = RuleBuilder::v4().priority(LAST).protocol(PROTOCOL).table(self.table);
        if bypass {
            super::exit_ipv6::apply_mode(&self.netlink, &self.journal.name, true).await?;
            self.netlink.del_rule_if_exists(catch_all).await?;
        } else {
            super::exit_ipv6::apply(&self.netlink, &self.journal.name).await?;
            self.netlink.add_rule(catch_all).await?;
        }
        super::exit_containers::apply_with_lan(&self.journal.name, self.index, bypass,&self.journal.lan_networks).await?;
        self.bypass = bypass;
        Ok(())
    }
    async fn update_sources(&mut self, underlay: &BTreeSet<Ipv4Addr>) -> Result<()> {
        ensure!(
            underlay.len() <= 64
                && !underlay.contains(&self.own)
                && underlay
                    .iter()
                    .all(|ip| !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()),
            "invalid exit source bindings"
        );
        let stale: Vec<_> = self
            .sources
            .iter()
            .filter(|(ip, _)| !underlay.contains(ip))
            .map(|(ip, priority)| (*ip, *priority))
            .collect();
        for (ip, priority) in stale {
            self.netlink
                .del_rule_if_exists(Self::source_rule(ip, priority))
                .await?;
            self.sources.remove(&ip);
        }
        for ip in underlay {
            if self.sources.contains_key(ip) {
                continue;
            }
            let priority = (FIRST + 1..FIRST + 65)
                .find(|priority| !self.sources.values().any(|used| used == priority))
                .ok_or_else(|| anyhow::anyhow!("exit source capacity exceeded"))?;
            self.journal.sources.push((*ip, priority));
            self.journal.save()?;
            self.netlink
                .add_rule(Self::source_rule(*ip, priority))
                .await?;
            self.sources.insert(*ip, priority);
        }
        let recorded: Vec<_> = self
            .sources
            .iter()
            .map(|(ip, priority)| (*ip, *priority))
            .collect();
        if self.journal.sources != recorded {
            self.journal.sources = recorded;
            self.journal.save()?;
        }
        Ok(())
    }
    pub async fn clear(&mut self) -> Result<()> {
        let _lock = super::exit_forwarding::lock().await?;
        self.clear_inner().await
    }
    async fn clear_inner(&mut self) -> Result<()> {
        if !self.claimed {
            return Ok(());
        }
        self.journal.clear(&self.netlink).await?;
        self.rules.clear();
        self.sources.clear();
        self.installed_route = false;
        self.claimed = false;
        Ok(())
    }
}
