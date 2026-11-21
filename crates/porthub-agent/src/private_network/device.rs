//! Nonpersistent, exclusively owned Linux TUN. Only private /32 routes are
//! added, with exclusive netlink operations; no existing route is replaced.
use anyhow::{ensure, Result};
#[path = "linux_tun_queue.rs"]
mod queue;
use porthub_network::capture_routes::SparseAudit;
use nlink::netlink::{route::Ipv4Route, types::route::RouteScope, Connection, Route};
use std::{
    collections::HashSet,
    fs::File,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr},
    os::fd::AsRawFd,
};
use tokio::{io::unix::AsyncFd, sync::Mutex};
pub struct Tun {
    fd: AsyncFd<File>,
    netlink: Connection<Route>,
    anchor: Option<File>,
    journal: Option<LinkJournal>,
    published: std::sync::atomic::AtomicBool,
    pub index: u32,
    pub name: String,
    own:Ipv4Addr,
    routes: Mutex<HashSet<Ipv4Addr>>,
    capture_routes: Mutex<std::collections::BTreeSet<porthub_mesh::lan_routes::Network>>,
    pub(super) source_restored: std::sync::atomic::AtomicBool,
    _source_lease: super::native_owner::source::OwnerLease,
}
#[derive(Debug)]
pub(super) struct LinkDown;
impl std::fmt::Display for LinkDown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("owned private interface is down")
    }
}
impl std::error::Error for LinkDown {}

fn safe<T, E>(result: std::result::Result<T, E>, message: &'static str) -> Result<T> {
    result.map_err(|_| anyhow::anyhow!(message))
}
/// Some VPNs implement the default route as two /1s. Treat only an
/// unambiguous, equivalent pair on one kernel VPN device like a /0. This
/// filters a copy used for overlap checks; the native routes remain installed.
async fn conflict_inventory(
    netlink: &Connection<Route>,
) -> Result<Vec<nlink::netlink::messages::RouteMessage>> {
    use nlink::netlink::messages::RouteMessage;

    let mut routes = netlink.get_routes().await?;
    let mut halves = routes
        .iter()
        .enumerate()
        .filter(|(_, r)| r.is_ipv4() && r.dst_len() == 1);
    let (Some((i, left)), Some((j, right)), None) = (halves.next(), halves.next(), halves.next())
    else {
        return Ok(routes);
    };
    let eligible = |r: &RouteMessage| {
        r.table_id() == 254
            && r.route_type() == 1.into()
            && r.tos() == 0
            && r.src_len() == 0
            && r.source().is_none()
            && r.iif().is_none()
            && r.multipath().is_none()
            && r.nh_id().is_none()
            && r.encap_type().is_none()
            && r.flow().is_none()
            && r.expires().is_none()
    };
    let endpoints = [left.destination(), right.destination()];
    let first = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let second = IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0));
    let Some(index) = left.oif() else {
        return Ok(routes);
    };
    if !eligible(left)
        || !eligible(right)
        || !endpoints.contains(&Some(&first))
        || !endpoints.contains(&Some(&second))
        || right.oif() != Some(index)
        || left.gateway() != right.gateway()
        || left.priority() != right.priority()
        || left.scope() != right.scope()
        || left.protocol() != right.protocol()
        || left.flags() != right.flags()
        || left.pref() != right.pref()
        || left.prefsrc() != right.prefsrc()
        || left.metrics() != right.metrics()
    {
        return Ok(routes);
    }
    let vpn = netlink.get_links().await?.into_iter().any(|link| {
        link.ifindex() == index
            && matches!(link.kind(), Some("tun" | "wireguard"))
            && !porthub_mesh::underlay::porthub_tun_name(link.name().unwrap_or(""))
    });
    if vpn {
        routes.remove(j);
        routes.remove(i);
    }
    Ok(routes)
}

pub(super) struct RetainedLink {
    anchor: File,
    state: LinkState,
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkState {
    binding: String,
    name: String,
    index: u32,
    own: Ipv4Addr,
    peers: HashSet<Ipv4Addr>,
    pools: std::collections::BTreeSet<porthub_mesh::lan_routes::Network>,
}

struct LinkJournal {
    file: File,
    state: std::sync::Mutex<LinkState>,
}

impl Drop for Tun {
    fn drop(&mut self) {
        if self.published.load(std::sync::atomic::Ordering::Acquire) && !super::linux_handoff::exiting() {
            if let Err(error) = super::linux_handoff::clear() {
                tracing::warn!(%error, "could not release the service's private link reference");
            }
        }
    }
}

/// Only a detached native link reference crosses the worker boundary. Its TUN
/// queue cannot contain traffic. Each recovering worker obtains a new queue
/// which this wrapper exposes exclusively for local packet reads.
pub(super) struct RetrySource { anchor:File, name:String, index:u32 }
pub(super) struct RetryReader(AsyncFd<File>);
impl RetrySource {
    pub(super) fn open(self)->Result<RetryReader>{
        Ok(RetryReader(AsyncFd::new(queue::resume(&self.anchor,&self.name,self.index)?)?))
    }
}
impl RetryReader {
    pub(super) async fn read(&self,buffer:&mut [u8])->Result<usize>{
        loop{let mut ready=self.0.readable().await?;match ready.try_io(|fd|fd.get_ref().read(buffer)){Ok(result)=>return Ok(result?),Err(_)=>continue}}
    }
}
impl RetainedLink {
    pub(super) fn matches(&self, binding: &str, pin: Option<&super::native_owner::source::Pin>, own: Ipv4Addr) -> bool {
        self.state.binding == binding && self.state.own == own
            && matches!(pin, Some(super::native_owner::source::Pin::Interface { name, index }) if *name == self.state.name && *index == self.state.index)
    }

    #[cfg(all(test, feature="netns-tests"))]
    fn export(self) -> Result<(File, Vec<u8>)> {
        Ok((self.anchor, serde_json::to_vec(&self.state)?))
    }

    pub(super) fn import(anchor: File, state: &[u8]) -> Result<Self> {
        ensure!(state.len() <= 1024 * 1024, "retained route inventory exceeds bound");
        let state: LinkState = serde_json::from_slice(state)?;
        ensure!(state.binding.len() == 64 && state.binding.bytes().all(|v| v.is_ascii_hexdigit())
            && state.own.is_private() && state.peers.iter().all(Ipv4Addr::is_private)
            && state.pools.len() <= porthub_network::capture_routes::MAX_CAPTURE_PREFIXES,
            "invalid private link checkpoint");
        Ok(Self { anchor, state })
    }
}

impl Tun {
    pub(super) fn retry_source(&self)->Option<RetrySource>{
        Some(RetrySource{anchor:self.anchor.as_ref()?.try_clone().ok()?,name:self.name.clone(),index:self.index})
    }
    pub(super) fn own_ip(&self)->Ipv4Addr{self.own}
    pub(super) fn bind_source_lease(&self,lease:crate::profile::Lease)->Result<()>{self._source_lease.bind(lease)}
    pub(super) fn has_source_lease(&self)->Result<bool>{self._source_lease.held()}
    pub(super) fn source_pin(&self)->super::native_owner::source::Pin{super::native_owner::source::Pin::Interface{name:self.name.clone(),index:self.index}}

    /// Fresh native inventory BEFORE assigning a source address. Never recreate
    /// an old bound source transiently while a conflicting LAN is still live.
    pub(super) async fn preflight_sparse(own:Ipv4Addr,pools:&[porthub_mesh::lan_routes::Network],peers:&[Ipv4Addr])->Result<()>{
        let netlink=Connection::<Route>::new()?;let native=conflict_inventory(&netlink).await?;
        let existing:Vec<_>=native.iter().filter_map(|r|match r.destination(){Some(IpAddr::V4(address))=>Some(porthub_network::capture_routes::ExistingRoute{destination:*address,prefix:r.dst_len(),interface:r.oif()}),_=>None}).collect();
        super::native_owner::conflict(porthub_network::capture_routes::audit(pools,own,peers,&existing,u32::MAX)?)?;Ok(())
    }
    pub async fn open(name: &str, own: Ipv4Addr, peers: &[Ipv4Addr]) -> Result<Self> {
        Self::create(name, own, peers, false).await
    }

    pub(super) async fn create(name: &str, own: Ipv4Addr, peers: &[Ipv4Addr], restartable: bool) -> Result<Self> {
        ensure!(
            porthub_mesh::underlay::porthub_tun_name(name)
                && own.is_private(),
            "invalid private interface configuration"
        );
        let netlink = safe(
            Connection::<Route>::new(),
            "private netlink connection failed",
        )?;
        ensure!(
            safe(
                netlink.get_link_by_name(name).await,
                "private interface lookup failed"
            )?
            .is_none(),
            "private interface already exists"
        );
        check_routes(&netlink, &[peers, &[own]].concat(), None).await?;
        let file = queue::create(name, restartable)?;
        let link = safe(
            netlink.get_link_by_name(name).await,
            "private TUN lookup failed",
        )?
        .ok_or_else(|| anyhow::anyhow!("private TUN unavailable"))?;
        let index = link.ifindex();
        let anchor = restartable.then(|| queue::detach_anchor(&file, name, index)).transpose()?;
        // Allow bursts of locally segmented TCP packets to reach the TUN reader.
        // A full Linux TUN transmit ring discards packets before userspace sees them.
        if let Err(error) = netlink.set_link_txqlen_by_index(index, 4096).await {
            tracing::debug!(%error, "retaining native TUN transmit queue length");
        }
        safe(
            netlink
                .add_address_by_index(index, IpAddr::V4(own), 32)
                .await,
            "private address configuration failed",
        )?;
        safe(
            netlink
                .set_link_mtu_by_index(index, porthub_mesh::MAX_PACKET as u32)
                .await,
            "private MTU configuration failed",
        )?;
        safe(
            netlink.set_link_up_by_index(index).await,
            "private interface activation failed",
        )?;
        let tun = Self {
            // File owns a stable, nonblocking descriptor until AsyncFd is dropped.
            fd: unsafe { AsyncFd::register(file)? },
            netlink,
            anchor,
            journal: None,
            published: Default::default(),
            index,
            own,
            name: name.into(),
            routes: Mutex::new(HashSet::new()),
            capture_routes: Mutex::new(std::collections::BTreeSet::new()),
            source_restored: Default::default(),
            _source_lease: Default::default(),
        };
        tun.update_routes(peers).await?;
        super::linux_tcp::configure_send_autotuning();
        Ok(tun)
    }
    pub(super) async fn journal_routes(&mut self, binding: &str, previous: Option<File>) -> Result<()> {
        use std::os::fd::FromRawFd;
        let state = self.route_state(binding).await;
        let file = if let Some(file) = previous { file } else {
            let fd = unsafe { libc::memfd_create(c"porthub-private-routes".as_ptr(), libc::MFD_CLOEXEC) };
            ensure!(fd >= 0, "unable to allocate private route checkpoint");
            unsafe { File::from_raw_fd(fd) }
        };
        Self::checkpoint(&file, &state)?;
        self.journal = Some(LinkJournal { file, state: std::sync::Mutex::new(state) });
        Ok(())
    }
    fn checkpoint(file: &File, state: &LinkState) -> Result<()> {
        use std::os::unix::fs::FileExt;
        let bytes = serde_json::to_vec(state)?;
        ensure!(bytes.len() <= 1024 * 1024, "route checkpoint exceeds size bound");
        // If a process exits during a write the replacement must cold-start.
        // Clearing the length prefix before writing keeps partial JSON invalid.
        file.write_all_at(&0u64.to_le_bytes(), 0)?;
        file.write_all_at(&bytes, 8)?;
        file.set_len(8 + bytes.len() as u64)?;
        file.write_all_at(&(bytes.len() as u64).to_le_bytes(), 0)?;
        Ok(())
    }
    async fn checkpoint_routes(&self) -> Result<()> {
        let Some(journal) = &self.journal else { return Ok(()); };
        let peers = self.routes.lock().await.clone();
        let pools = self.capture_routes.lock().await.clone();
        let mut state = journal.state.lock().map_err(|_| anyhow::anyhow!("private route checkpoint poisoned"))?;
        if state.peers != peers || state.pools != pools {
            state.peers = peers;
            state.pools = pools;
            Self::checkpoint(&journal.file, &state)?;
        }
        Ok(())
    }
    #[cfg(feature="private-sparse")]
    pub(super) fn recovery_handles(&self, udp: File, tcp: File) -> Result<Option<super::linux_handoff::Stored>> {
        let (Some(anchor),Some(journal)) = (&self.anchor,&self.journal) else {return Ok(None)};
        Ok(Some(super::linux_handoff::Stored { anchor:anchor.try_clone()?, state:journal.file.try_clone()?, udp, tcp }))
    }

    pub(super) fn publish(&self, dns: &super::dns::Server) -> Result<()> {
        use std::os::fd::AsFd;
        if !super::linux_handoff::available() || self.published.load(std::sync::atomic::Ordering::Acquire) { return Ok(()); }
        if let (Some(anchor), Some(journal)) = (&self.anchor, &self.journal) {
            let (udp, tcp) = dns.socket_fds();
            super::linux_handoff::publish([anchor.as_fd(),journal.file.as_fd(),udp,tcp])?;
            self.published.store(true,std::sync::atomic::Ordering::Release);
        }
        Ok(())
    }
    pub(super) fn mark_restored(&self) {
        self.published.store(true,std::sync::atomic::Ordering::Release);
    }

    async fn route_state(&self, binding: &str) -> LinkState {
        LinkState {
            binding: binding.into(),
            index: self.index,
            own: self.own,
            name: self.name.clone(),
            peers: self.routes.lock().await.clone(),
            pools: self.capture_routes.lock().await.clone(),
        }
    }

    #[cfg(all(test, feature="netns-tests"))]
    async fn handoff(&self, binding: &str) -> Result<RetainedLink> {
        let anchor = self.anchor.as_ref().ok_or_else(|| anyhow::anyhow!("private link is not retained"))?.try_clone()?;
        Ok(RetainedLink {anchor, state:self.route_state(binding).await})
    }

    pub(super) async fn restore(
        retained: RetainedLink,
        name: &str,
        own: Ipv4Addr,
        pools: &[porthub_mesh::lan_routes::Network],
        peers: &[Ipv4Addr],
    ) -> Result<Self> {
        ensure!(own.is_private() && own == retained.state.own && name == retained.state.name,
            "retained private link assignment changed");
        let fd = queue::resume(&retained.anchor, name, retained.state.index)?;
        let netlink = Connection::<Route>::new()?;
        // A crash can interrupt a route update before its checkpoint. Never
        // adopt a route we cannot attribute to the previous worker.
        for route in netlink.get_routes().await?.iter().filter(|r|
            r.is_ipv4() && r.oif() == Some(retained.state.index) && r.table_id() == 254)
        {
            use nlink::netlink::types::route::{RouteProtocol, RouteType};
            let Some(IpAddr::V4(destination)) = route.destination() else {
                anyhow::bail!("unexpected route on retained private link");
            };
            let length = route.dst_len();
            let recorded = (length == 32 && retained.state.peers.contains(destination))
                || retained.state.pools.iter().any(|p| p.prefix() == length && p.address() == *destination);
            ensure!(recorded && route.scope() == RouteScope::Link && route.protocol() == RouteProtocol::Boot
                && route.route_type() == RouteType::Unicast && route.gateway().is_none() && route.priority().is_none()
                && route.source().is_none() && route.iif().is_none() && route.prefsrc().is_none()
                && route.multipath().is_none() && route.nh_id().is_none() && route.encap_type().is_none()
                && route.flow().is_none() && route.metrics().is_none() && route.via().is_none(),
                "unrecognized route on retained private link");
        }
        let addresses = netlink.get_addresses().await?;
        ensure!(!addresses.iter().any(|address| address.ifindex() == retained.state.index
            && matches!(address.primary_address(), Some(IpAddr::V4(ip)) if *ip != own)),
            "retained private link has an unexpected IPv4 address");
        let tun = Self {
            fd: unsafe { AsyncFd::register(fd)? },
            netlink,
            anchor: Some(retained.anchor),
            journal: None,
            published: Default::default(),
            name: retained.state.name,
            index: retained.state.index,
            own,
            routes: Mutex::new(retained.state.peers),
            capture_routes: Mutex::new(retained.state.pools),
            source_restored: Default::default(),
            _source_lease: Default::default(),
        };
        // Reconcile both removals and additions against current authority and
        // current OS routes before the caller starts either packet direction.
        tun.reconcile_sparse(pools, peers).await?;
        Ok(tun)
    }

    /// Reconcile only prefixes validated against the current native route inventory.
    /// A conflicting pool is reported separately; other safe pools remain usable.
    pub async fn update_capture_routes(&self, pools: &[porthub_mesh::lan_routes::Network]) -> Result<porthub_network::capture_routes::CapturePlan> {
        use porthub_network::capture_routes::{self, ExistingRoute};
        let native = conflict_inventory(&self.netlink).await?;
        let existing:Vec<_> = native.iter().filter_map(|route| match route.destination() {
            Some(IpAddr::V4(address)) => Some(ExistingRoute { destination:*address, prefix:route.dst_len(), interface:route.oif() }), _=>None,
        }).collect();
        let mut plan=capture_routes::plan(pools,&existing,self.index)?;
        let wanted:std::collections::BTreeSet<_>=plan.accepted.iter().copied().collect();
        let mut owned=self.capture_routes.lock().await;
        for prefix in owned.difference(&wanted).copied().collect::<Vec<_>>() {
            safe(self.netlink.del_route(Ipv4Route::new(prefix.address(),prefix.prefix()).dev_index(self.index).scope(RouteScope::Link)).await,"capture route removal failed")?;
            owned.remove(&prefix);
        }
        for prefix in wanted.difference(&owned).copied().collect::<Vec<_>>() {
            if self.netlink.add_route(Ipv4Route::new(prefix.address(),prefix.prefix()).dev_index(self.index).scope(RouteScope::Link)).await.is_ok() { owned.insert(prefix); }
            else {plan.accepted.retain(|p|*p!=prefix);plan.conflicting.push(prefix);}
        }
        Ok(plan)
    }

    /// The routes can survive the loss of the local address. A successful
    /// route audit alone is insufficient for DNS and newly opened sockets.
    async fn restore_source(&self, mut audit: SparseAudit) -> Result<SparseAudit> {
        let own = IpAddr::V4(self.own);
        let link = self
            .netlink
            .get_link_by_index(self.index)
            .await?
            .ok_or_else(|| anyhow::anyhow!("owned private interface disappeared"))?;
        ensure!(
            link.name() == Some(self.name.as_str()),
            "private interface identity changed"
        );
        let addresses = self.netlink.get_addresses().await?;
        let mut assigned = false;
        for address in addresses
            .iter()
            .filter(|address| address.primary_address() == Some(&own))
        {
            if address.ifindex() != self.index {
                audit.own_conflict = true;
                return Err(super::native_owner::Conflict(audit).into());
            }
            ensure!(
                address.prefix_len() == 32 && address.peer().is_none(),
                "private source address configuration changed"
            );
            assigned = true;
        }
        if assigned && link.is_up() {
            return Ok(audit);
        }

        // A disappearing device can release its numeric index. Confirm that
        // our open TUN file is still attached before changing kernel state.
        {
            let mut info: libc::ifreq = unsafe { std::mem::zeroed() };
            ensure!(
                unsafe { libc::ioctl(self.fd.get_ref().as_raw_fd(), libc::TUNGETIFF, &mut info) } == 0
                    && info
                        .ifr_name
                        .iter()
                        .map(|c| *c as u8)
                        .take_while(|c| *c != 0)
                        .eq(self.name.bytes()),
                "private TUN file is no longer attached to its original interface"
            );
        }
        ensure!(!addresses.iter().any(|address| address.ifindex() == self.index
            && matches!(address.primary_address(), Some(IpAddr::V4(ip)) if *ip != self.own)),
            "additional IPv4 address on the private interface during recovery");
        if !assigned {
            self.netlink
                .add_address_by_index(self.index, own, 32)
                .await?;
        }
        if !link.is_up() {
            self.netlink.set_link_up_by_index(self.index).await?;
        }
        self.source_restored.store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(audit)
    }

    /// Revalidate retained host routes as well as broad capture prefixes. The
    /// packet owner calls this after route notifications and before exposing a new
    /// pair to DNS; it never reuses the additions-only legacy preflight.
    pub async fn reconcile_sparse(&self,pools:&[porthub_mesh::lan_routes::Network],peers:&[Ipv4Addr])->Result<porthub_network::capture_routes::SparseAudit>{
        use porthub_network::capture_routes::{self,ExistingRoute};
        let native=conflict_inventory(&self.netlink).await?;
        let existing:Vec<_>=native.iter().filter_map(|r|match r.destination(){Some(IpAddr::V4(address))=>Some(ExistingRoute{destination:*address,prefix:r.dst_len(),interface:r.oif()}),_=>None}).collect();
        let audit=super::native_owner::conflict(capture_routes::audit(pools,self.own,peers,&existing,self.index)?)?;
        let mut audit = self.restore_source(audit).await?;
        // A route removed outside PortHub is not still a valid ownership claim.
        // Forget missing entries so an exclusive add can repair them, never adopt
        // an arbitrary existing entry just because it points at our interface.
        let present=|address:Ipv4Addr,prefix:u8|existing.iter().any(|r|r.destination==address&&r.prefix==prefix&&r.interface==Some(self.index));
        let current_peers={let mut held=self.routes.lock().await;held.retain(|ip|present(*ip,32));held.iter().copied().filter(|ip|*ip!=self.own).collect::<std::collections::BTreeSet<_>>()};
        let current_capture={let mut held=self.capture_routes.lock().await;held.retain(|p|present(p.address(),p.prefix()));held.clone()};
        if current_peers==audit.accepted_peers.iter().copied().collect()&&current_capture==audit.capture.accepted.iter().copied().collect(){self.checkpoint_routes().await?;return Ok(audit);}
        // Remove obsolete/now-conflicting capture and host entries before adding
        // new ones. A safe known /32 may still work outside a conflicting subnet.
        let retained_capture:Vec<_>=self.capture_routes.lock().await.iter().copied().filter(|p|audit.capture.accepted.contains(p)).collect();
        self.update_capture_routes(&retained_capture).await?;
        let retained_peers:Vec<_>=self.routes.lock().await.iter().copied().filter(|p|audit.accepted_peers.contains(p)).collect();
        self.update_routes(&retained_peers).await?;
        audit.capture=self.update_capture_routes(pools).await?;
        self.update_routes(&audit.accepted_peers).await?;
        self.checkpoint_routes().await?;
        Ok(audit)
    }

    pub async fn update_routes(&self, peers: &[Ipv4Addr]) -> Result<()> {
        let wanted: HashSet<_> = peers.iter().copied().collect();
        let mut current = self.routes.lock().await;
        let additions: Vec<_> = wanted.difference(&current).copied().collect();
        check_routes(&self.netlink, &wanted.iter().copied().collect::<Vec<_>>(), Some(self.index)).await?;
        for address in additions {
            safe(
                self.netlink
                    .add_route(
                        Ipv4Route::new(address, 32)
                            .dev_index(self.index)
                            .scope(RouteScope::Link),
                    )
                    .await,
                "private route addition failed",
            )?;
            current.insert(address);
        }
        let removals: Vec<_> = current.difference(&wanted).copied().collect();
        for address in removals {
            safe(
                self.netlink
                    .del_route(
                        Ipv4Route::new(address, 32)
                            .dev_index(self.index)
                            .scope(RouteScope::Link),
                    )
                    .await,
                "private route removal failed",
            )?;
            current.remove(&address);
        }
        Ok(())
    }
    pub async fn exit_mtu(&self, enabled: bool) -> Result<()> {
        let mtu = porthub_mesh::MAX_PACKET - if enabled { 20 } else { 0 };
        safe(self.netlink.set_link_mtu_by_index(self.index, mtu as u32).await,
            "exit MTU configuration failed")
    }
    async fn packet_error(&self, error: std::io::Error) -> anyhow::Error {
        if error.raw_os_error() == Some(libc::EIO)
            && self.netlink.get_link_by_index(self.index).await.ok().flatten()
                .is_some_and(|link| !link.is_up() && link.name() == Some(self.name.as_str()))
        {
            LinkDown.into()
        } else {
            error.into()
        }
    }

    pub async fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        loop {
            let mut ready = self.fd.readable().await?;
            match ready.try_io(|fd| fd.get_ref().read(buffer)) {
                Ok(Ok(size)) => return Ok(size),
                Ok(Err(error)) => return Err(self.packet_error(error).await),
                Err(_) => continue,
            }
        }
    }
    pub async fn write(&self, bytes: &[u8]) -> Result<()> {
        loop {
            let mut ready = self.fd.writable().await?;
            match ready.try_io(|fd| fd.get_ref().write(bytes)) {
                Ok(Err(error)) => return Err(self.packet_error(error).await),
                Ok(Ok(size)) => {
                    ensure!(size == bytes.len(), "short private packet write");
                    return Ok(());
                }
                Err(_) => continue,
            }
        }
    }
}
async fn check_routes(
    netlink: &Connection<Route>,
    addresses: &[Ipv4Addr],
    own: Option<u32>,
) -> Result<()> {
    ensure!(
        addresses.iter().all(Ipv4Addr::is_private),
        "invalid private route address"
    );
    if addresses.is_empty() {
        return Ok(());
    }
    let routes = conflict_inventory(netlink).await?;
    for route in routes {
        if route.dst_len() == 0 || own.is_some_and(|own| route.oif() == Some(own)) {
            continue;
        }
        if let Some(IpAddr::V4(network)) = route.destination() {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(route.dst_len().min(32)))
                .unwrap_or(0);
            ensure!(
                !addresses
                    .iter()
                    .any(|ip| u32::from(*ip) & mask == u32::from(*network) & mask),
                "private address conflicts with an existing network route"
            );
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "netns-tests"))]
mod vpn_default_tests {
    use super::*;
    use nlink::netlink::link::WireguardLink;

    #[tokio::test]
    #[ignore = "requires an owned disposable container namespace, NET_ADMIN and WireGuard"]
    async fn split_default_equivalence_preserves_host_collisions_and_native_routes() -> Result<()> {
        ensure!(
            std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1")
                && std::path::Path::new("/.dockerenv").is_file(),
            "owned namespace required"
        );
        let connection = Connection::<Route>::new()?;
        let name = "vpn-fixture";
        ensure!(connection.get_link_by_name(name).await?.is_none());
        connection.add_link(WireguardLink::new(name)).await?;
        let result = async {
            let index = connection.get_link_by_name(name).await?.unwrap().ifindex();
            connection.set_link_up(name).await?;
            let low = Ipv4Addr::UNSPECIFIED;
            let high = Ipv4Addr::new(128, 0, 0, 0);
            let peer = Ipv4Addr::new(10, 203, 9, 3);
            let half = |ip, metric| Ipv4Route::new(ip, 1).dev_index(index).metric(metric);
            connection.add_route(half(low, 20)).await?;
            ensure!(check_routes(&connection, &[peer], None).await.is_err());
            connection.add_route(half(high, 40)).await?;
            ensure!(check_routes(&connection, &[peer], None).await.is_err());
            connection.del_route(half(high, 40)).await?;
            connection.add_route(half(high, 20)).await?;
            check_routes(&connection, &[peer], None).await?;
            connection
                .add_route(Ipv4Route::new(peer, 32).dev_index(index))
                .await?;
            ensure!(check_routes(&connection, &[peer], None).await.is_err());
            let pools = ["10.203.9.0/24".parse()?];
            ensure!(
                Tun::preflight_sparse(Ipv4Addr::new(10, 203, 9, 2), &pools, &[peer])
                    .await
                    .is_err()
            );
            let native = connection.get_routes().await?;
            ensure!(
                native
                    .iter()
                    .filter(|r| r.oif() == Some(index) && r.dst_len() == 1)
                    .count()
                    == 2
            );
            ensure!(native.iter().any(|r| r.oif() == Some(index)
                && r.dst_len() == 32
                && r.destination() == Some(&IpAddr::V4(peer))));
            anyhow::Ok(())
        }
        .await;
        connection.del_link_if_exists(name).await?;
        result
    }
}

#[cfg(test)]
mod source_recovery_tests {
    use super::*;
    use nlink::netlink::link::DummyLink;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    #[ignore = "requires a disposable network namespace with NET_ADMIN and /dev/net/tun"]
    async fn recovers_the_owned_source_and_link_after_external_changes() -> Result<()> {
        ensure!(
            std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1")
                && std::path::Path::new("/.dockerenv").is_file(),
            "owned namespace required"
        );
        let own = Ipv4Addr::new(10, 219, 93, 2);
        let peer = Ipv4Addr::new(10, 219, 93, 3);
        let pools = ["10.219.93.0/24".parse()?];
        let tun = Tun::open("phabcdef01", own, &[]).await?;
        let native = Connection::<Route>::new()?;
        tun.reconcile_sparse(&pools, &[peer]).await?;

        let held = tokio::net::UdpSocket::bind((own, 0)).await?;
        held.connect((peer, 9234)).await?;
        for incident in ["address removed", "link down", "address removed while down"] {
            if incident != "address removed" {
                native.set_link_down_by_index(tun.index).await?;
                // Real inbound IPv4 traffic can reach the packet owner before
                // the route notification. It must reach the local repair path.
                let mut packet = [0u8; 20];
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&20u16.to_be_bytes());
                packet[12..16].copy_from_slice(&peer.octets());
                packet[16..20].copy_from_slice(&own.octets());
                ensure!(tun.write(&packet).await.unwrap_err().is::<LinkDown>());
            }
            if incident != "link down" {
                native
                    .del_address_by_index(tun.index, IpAddr::V4(own), 32)
                    .await?;
            }
            let audit = tun.reconcile_sparse(&pools, &[peer]).await?;
            ensure!(audit.accepted_peers.contains(&peer) && audit.capture.accepted == pools);
            let live = native.get_link_by_name(&tun.name).await?.unwrap();
            ensure!(
                live.ifindex() == tun.index && live.is_up(),
                "{incident}: link still down"
            );
            let fresh = tokio::net::UdpSocket::bind((own, 0)).await.map_err(|e| {
                anyhow::anyhow!("{incident}: active audit without a usable source: {e}")
            })?;
            for (socket, marker) in [(&held, "held"), (&fresh, "fresh")] {
                let bytes = format!("{incident}: {marker}");
                socket.send_to(bytes.as_bytes(), (peer, 9234)).await?;
                timeout(Duration::from_secs(1), async {
                    let mut packet = [0; 2048];
                    loop {
                        let size = tun.read(&mut packet).await?;
                        if packet[..size].ends_with(bytes.as_bytes()) {
                            return Ok::<(), anyhow::Error>(());
                        }
                    }
                })
                .await??;
            }
        }

        native
            .del_address_by_index(tun.index, IpAddr::V4(own), 32)
            .await?;
        native.add_link(DummyLink::new("foreign-fixture")).await?;
        let other = native
            .get_link_by_name("foreign-fixture")
            .await?
            .unwrap()
            .ifindex();
        native
            .add_address_by_index(other, IpAddr::V4(own), 32)
            .await?;
        let error = tun.reconcile_sparse(&pools, &[peer]).await.unwrap_err();
        ensure!(error
            .downcast_ref::<super::super::native_owner::Conflict>()
            .is_some());
        let owners: Vec<_> = native
            .get_addresses()
            .await?
            .into_iter()
            .filter(|row| row.primary_address() == Some(&IpAddr::V4(own)))
            .map(|row| row.ifindex())
            .collect();
        ensure!(
            owners == [other],
            "foreign address changed or was duplicated"
        );
        Ok(())
    }
}

#[cfg(all(test, feature = "netns-tests"))]
#[tokio::test]
#[ignore = "requires a disconnected namespace and /dev/net/tun"]
async fn retained_link_reconciles_routes_and_discards_previous_worker_packets() -> Result<()> {
    use std::net::UdpSocket;
    use std::time::Duration;

    ensure!(std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1"));
    ensure!(std::path::Path::new("/.dockerenv").is_file());
    ensure!(std::fs::read_dir("/sys/class/net")?.count() == 1);
    let name = "tun0ph1234abcd";
    let own = Ipv4Addr::new(10, 219, 94, 2);
    let old = Ipv4Addr::new(10, 219, 94, 7);
    let next = Ipv4Addr::new(10, 219, 94, 9);
    let pools = ["10.219.94.0/24".parse()?];
    let first = Tun::create(name, own, &[old], true).await?;
    first.reconcile_sparse(&pools, &[old]).await?;
    let idx = first.index;
    let sender = UdpSocket::bind((own, 0))?;
    sender.send_to(b"old-worker", (old, 47111))?;
    let binding = "a".repeat(64);
    let retained = first.handoff(&binding).await?;
    assert!(queue::resume(first.fd.get_ref(), name, idx).is_err());
    assert!(queue::resume(&retained.anchor, name, idx + 1).is_err());
    assert!(queue::resume(&File::open("/dev/null")?, name, idx).is_err());
    drop(first);
    sender.send_to(b"no-worker", (old, 47111))?;
    let (anchor, state) = retained.export()?;
    let retained = RetainedLink::import(anchor, &state)?;
    assert!(!retained.matches(&"b".repeat(64), None, own));
    let pin = super::native_owner::source::Pin::Interface { name: name.into(), index: idx };
    assert!(retained.matches(&binding, Some(&pin), own));
    let second = Tun::restore(retained, name, own, &pools, &[next]).await?;
    assert_eq!(idx, second.index);
    let native = second.netlink.get_routes().await?;
    let has = |ip| native.iter().any(|r| r.dst_len() == 32 && r.oif() == Some(idx)
        && r.destination() == Some(&IpAddr::V4(ip)));
    assert!(!has(old));
    assert!(has(next));
    let mut bytes = [0u8; 2048];
    assert!(tokio::time::timeout(Duration::from_millis(100), second.read(&mut bytes)).await.is_err());
    sender.send_to(b"fresh-worker", (next, 47111))?;
    let size = tokio::time::timeout(Duration::from_secs(2), second.read(&mut bytes)).await??;
    assert!(bytes[..size].ends_with(b"fresh-worker"));
    let retained = second.handoff(&binding).await?;
    drop(second);
    assert!(Tun::restore(retained, name, old, &pools, &[next]).await.is_err());
    let nl = Connection::<Route>::new()?;
    assert!(nl.get_link_by_name(name).await?.is_none());
    Ok(())
}
