//! Nonpersistent, exclusively owned Linux TUN. Only private /32 routes are
//! added, with exclusive netlink operations; no existing route is replaced.
use anyhow::{ensure, Result};
use nlink::netlink::{route::Ipv4Route, types::route::RouteScope, Connection, Route};
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
};
use tokio::{io::unix::AsyncFd, sync::Mutex};
pub struct Tun {
    fd: AsyncFd<File>,
    netlink: Connection<Route>,
    pub index: u32,
    pub name: String,
    own:Ipv4Addr,
    routes: Mutex<HashSet<Ipv4Addr>>,
    capture_routes: Mutex<std::collections::BTreeSet<porthub_mesh::lan_routes::Network>>,
    _source_lease: super::native_owner::source::OwnerLease,
}
fn safe<T, E>(result: std::result::Result<T, E>, message: &'static str) -> Result<T> {
    result.map_err(|_| anyhow::anyhow!(message))
}
impl Tun {
    pub(super) fn own_ip(&self)->Ipv4Addr{self.own}
    pub(super) fn bind_source_lease(&self,lease:crate::profile::Lease)->Result<()>{self._source_lease.bind(lease)}
    pub(super) fn has_source_lease(&self)->Result<bool>{self._source_lease.held()}
    pub(super) fn source_pin(&self)->super::native_owner::source::Pin{super::native_owner::source::Pin::Interface{name:self.name.clone(),index:self.index}}

    /// Fresh native inventory BEFORE assigning a source address. Never recreate
    /// an old bound source transiently while a conflicting LAN is still live.
    pub(super) async fn preflight_sparse(own:Ipv4Addr,pools:&[porthub_mesh::lan_routes::Network],peers:&[Ipv4Addr])->Result<()>{
        let netlink=Connection::<Route>::new()?;let native=netlink.get_routes().await?;
        let existing:Vec<_>=native.iter().filter_map(|r|match r.destination(){Some(IpAddr::V4(address))=>Some(porthub_network::capture_routes::ExistingRoute{destination:*address,prefix:r.dst_len(),interface:r.oif()}),_=>None}).collect();
        super::native_owner::conflict(porthub_network::capture_routes::audit(pools,own,peers,&existing,u32::MAX)?)?;Ok(())
    }
    pub async fn open(name: &str, own: Ipv4Addr, peers: &[Ipv4Addr]) -> Result<Self> {
        ensure!(
            name.len() == 10
                && name.starts_with("ph")
                && name[2..].bytes().all(|c| c.is_ascii_hexdigit())
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
        let file = safe(
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
                .open("/dev/net/tun"),
            "cannot open private TUN device",
        )?;
        // Keep the ioctl union local to the synchronous attachment. Its raw
        // pointer variants must not remain live across an asynchronous wait.
        {
            // ifreq is entirely zero-initialized before setting its defined fields.
            let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
            for (slot, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
                *slot = byte as libc::c_char;
            }
            request.ifr_ifru.ifru_flags =
                (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;
            ensure!(
                unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) } == 0,
                "private TUN attachment failed"
            );
        }
        let link = safe(
            netlink.get_link_by_name(name).await,
            "private TUN lookup failed",
        )?
        .ok_or_else(|| anyhow::anyhow!("private TUN unavailable"))?;
        let index = link.ifindex();
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
            index,
            own,
            name: name.into(),
            routes: Mutex::new(HashSet::new()),
            capture_routes: Mutex::new(std::collections::BTreeSet::new()),
            _source_lease: Default::default(),
        };
        tun.update_routes(peers).await?;
        Ok(tun)
    }
    /// Reconcile only prefixes validated against the current native route inventory.
    /// A conflicting pool is reported separately; other safe pools remain usable.
    pub async fn update_capture_routes(&self, pools: &[porthub_mesh::lan_routes::Network]) -> Result<porthub_network::capture_routes::CapturePlan> {
        use porthub_network::capture_routes::{self, ExistingRoute};
        let native = safe(self.netlink.get_routes().await, "capture route inventory failed")?;
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

    /// Revalidate retained host routes as well as broad capture prefixes. The
    /// packet owner calls this after route notifications and before exposing a new
    /// pair to DNS; it never reuses the additions-only legacy preflight.
    pub async fn reconcile_sparse(&self,pools:&[porthub_mesh::lan_routes::Network],peers:&[Ipv4Addr])->Result<porthub_network::capture_routes::SparseAudit>{
        use porthub_network::capture_routes::{self,ExistingRoute};
        let native=safe(self.netlink.get_routes().await,"sparse route audit failed")?;
        let existing:Vec<_>=native.iter().filter_map(|r|match r.destination(){Some(IpAddr::V4(address))=>Some(ExistingRoute{destination:*address,prefix:r.dst_len(),interface:r.oif()}),_=>None}).collect();
        let mut audit=super::native_owner::conflict(capture_routes::audit(pools,self.own,peers,&existing,self.index)?)?;
        // A route removed outside PortHub is not still a valid ownership claim.
        // Forget missing entries so an exclusive add can repair them, never adopt
        // an arbitrary existing entry just because it points at our interface.
        let present=|address:Ipv4Addr,prefix:u8|existing.iter().any(|r|r.destination==address&&r.prefix==prefix&&r.interface==Some(self.index));
        let current_peers={let mut held=self.routes.lock().await;held.retain(|ip|present(*ip,32));held.iter().copied().filter(|ip|*ip!=self.own).collect::<std::collections::BTreeSet<_>>()};
        let current_capture={let mut held=self.capture_routes.lock().await;held.retain(|p|present(p.address(),p.prefix()));held.clone()};
        if current_peers==audit.accepted_peers.iter().copied().collect()&&current_capture==audit.capture.accepted.iter().copied().collect(){return Ok(audit);}
        // Remove obsolete/now-conflicting capture and host entries before adding
        // new ones. A safe known /32 may still work outside a conflicting subnet.
        let retained_capture:Vec<_>=self.capture_routes.lock().await.iter().copied().filter(|p|audit.capture.accepted.contains(p)).collect();
        self.update_capture_routes(&retained_capture).await?;
        let retained_peers:Vec<_>=self.routes.lock().await.iter().copied().filter(|p|audit.accepted_peers.contains(p)).collect();
        self.update_routes(&retained_peers).await?;
        audit.capture=self.update_capture_routes(pools).await?;
        self.update_routes(&audit.accepted_peers).await?;
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
    pub async fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        loop {
            let mut ready = self.fd.readable().await?;
            match ready.try_io(|fd| fd.get_ref().read(buffer)) {
                Ok(result) => return Ok(result?),
                Err(_) => continue,
            }
        }
    }
    pub async fn write(&self, bytes: &[u8]) -> Result<()> {
        loop {
            let mut ready = self.fd.writable().await?;
            match ready.try_io(|fd| fd.get_ref().write(bytes)) {
                Ok(result) => {
                    ensure!(result? == bytes.len(), "short private packet write");
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
    let routes = safe(netlink.get_routes().await, "private route preflight failed")?;
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
