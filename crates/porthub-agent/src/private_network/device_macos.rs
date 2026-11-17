//! macOS utun device and explicit peer /32 routing. Only PortHub's own private
//! addresses are routed through this interface; existing/default routes stay
//! untouched.
use anyhow::{ensure, Context, Result};
use route_manager::{AsyncRouteManager, Route};
use std::{
    collections::HashSet,
    ffi::CString,
    net::{IpAddr, Ipv4Addr},
};
use tokio::sync::Mutex;
use tun_rs::DeviceBuilder;
#[path="address_route_macos.rs"]
mod address_route;

pub struct Tun {
    device: tun_rs::AsyncDevice,
    pub index: u32,
    pub name: String,
    own: Ipv4Addr,
    address_route: address_route::AddressRoute,
    packet_loop: super::owned_packet_loop::OwnedPacketLoop,
    routes: Mutex<HashSet<Ipv4Addr>>,
    capture_routes: Mutex<std::collections::BTreeSet<porthub_mesh::lan_routes::Network>>,
}

fn conflicts_with_route(address: Ipv4Addr, route: &Route) -> bool {
    let prefix = route.prefix().min(32);
    if prefix == 0 {
        return false;
    }
    let IpAddr::V4(network) = route.destination() else {
        return false;
    };
    let mask = u32::MAX << (32 - u32::from(prefix));
    u32::from(address) & mask == u32::from(network) & mask
}

impl Tun {
    pub(super) fn own_ip(&self)->Ipv4Addr{self.own}
    pub(super) fn packet_loop(&self)->&super::owned_packet_loop::OwnedPacketLoop{&self.packet_loop}
    /// Fresh native inventory BEFORE assigning a source address. Never recreate
    /// an old bound source transiently while a conflicting LAN is still live.
    pub(super) async fn preflight_sparse(own:Ipv4Addr,pools:&[porthub_mesh::lan_routes::Network],peers:&[Ipv4Addr])->Result<()>{
        let mut manager=AsyncRouteManager::new()?;let native=manager.list().await?;
        let existing:Vec<_>=native.iter().filter_map(|r|match r.destination(){IpAddr::V4(address)=>Some(porthub_network::capture_routes::ExistingRoute{destination:address,prefix:r.prefix(),interface:r.if_index()}),_=>None}).collect();
        super::native_owner::conflict(porthub_network::capture_routes::audit(pools,own,peers,&existing,u32::MAX)?)?;Ok(())
    }
    pub async fn open(_name: &str, own: Ipv4Addr, peers: &[Ipv4Addr]) -> Result<Self> {
        ensure!(own.is_private(), "invalid private interface address");
        ensure!(
            peers.iter().all(Ipv4Addr::is_private),
            "invalid private route address"
        );

        // Require positive pre-address absence; unknown is never absence/adoption.
        let local_before=address_route::BeforeAddress::observe(own);
        local_before.validate()?; // No address is assigned on unknown/foreign pre-state.
        let device = DeviceBuilder::new()
            .ipv4(own, 32, None)
            .mtu(porthub_mesh::MAX_PACKET as u16)
            .with(|builder| {
                builder.associate_route(false);
            })
            .build_async()
            .context("cannot create macOS private utun device")?;
        let name = device
            .name()
            .context("cannot identify macOS private utun device")?;
        let interface_name =
            CString::new(name.as_bytes()).context("invalid utun interface name")?;
        // SAFETY: the interface name is a live NUL-terminated CString.
        let index = unsafe { libc::if_nametoindex(interface_name.as_ptr()) };
        ensure!(index != 0, "cannot find macOS private utun interface");
        let address_route=address_route::AddressRoute::confirm(&name,index,own,local_before)?;
        let packet_loop=super::owned_packet_loop::OwnedPacketLoop::new(own,index)?;
        let tun = Self {
            device,
            index,
            name,
            own,
            address_route,
            packet_loop,
            routes: Mutex::new(HashSet::new()),
            capture_routes: Mutex::new(std::collections::BTreeSet::new()),
        };
        tun.update_routes(peers).await?;
        Ok(tun)
    }

    /// Prefix capture does not authorize packets. Preserve foreign routes and isolate pool conflicts.
    pub async fn update_capture_routes(&self,pools:&[porthub_mesh::lan_routes::Network])->Result<porthub_network::capture_routes::CapturePlan>{
        use porthub_network::capture_routes::{self,ExistingRoute};
        let mut manager=AsyncRouteManager::new().context("cannot open capture route manager")?;
        let native=manager.list().await.context("cannot inspect capture routes")?;
        self.address_route.verify()?;
        let existing:Vec<_>=native.iter().filter(|r|!self.address_route.matches(r)).filter_map(|r|match r.destination(){IpAddr::V4(address)=>Some(ExistingRoute{destination:address,prefix:r.prefix(),interface:r.if_index()}),_=>None}).collect();
        let mut plan=capture_routes::plan(pools,&existing,self.index)?;
        let wanted:std::collections::BTreeSet<_>=plan.accepted.iter().copied().collect();let mut owned=self.capture_routes.lock().await;
        for prefix in owned.difference(&wanted).copied().collect::<Vec<_>>(){
            manager.delete(&Route::new(IpAddr::V4(prefix.address()),prefix.prefix()).with_if_index(self.index)).await.context("cannot remove owned capture route")?;owned.remove(&prefix);
        }
        for prefix in wanted.difference(&owned).copied().collect::<Vec<_>>(){
            if manager.add(&Route::new(IpAddr::V4(prefix.address()),prefix.prefix()).with_if_index(self.index)).await.is_ok(){owned.insert(prefix);}
            else{plan.accepted.retain(|p|*p!=prefix);plan.conflicting.push(prefix);}
        }
        Ok(plan)
    }

    /// Revalidate retained host routes as well as broad capture prefixes. The
    /// packet owner calls this after route notifications and before exposing a new
    /// pair to DNS; it never reuses the additions-only legacy preflight.
    pub async fn reconcile_sparse(&self,pools:&[porthub_mesh::lan_routes::Network],peers:&[Ipv4Addr])->Result<porthub_network::capture_routes::SparseAudit>{
        use porthub_network::capture_routes::{self,ExistingRoute};
        let mut manager=AsyncRouteManager::new().context("cannot open sparse route audit")?;
        let native=manager.list().await.context("cannot inspect sparse route audit")?;
        self.address_route.verify()?;
        let existing:Vec<_>=native.iter().filter(|r|!self.address_route.matches(r)).filter_map(|r|match r.destination(){IpAddr::V4(address)=>Some(ExistingRoute{destination:address,prefix:r.prefix(),interface:r.if_index()}),_=>None}).collect();
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
        ensure!(
            peers.iter().all(Ipv4Addr::is_private),
            "invalid private route address"
        );
        self.address_route.verify()?;
        let wanted: HashSet<_> = peers.iter().copied().filter(|ip|*ip!=self.own).collect();
        let mut current = self.routes.lock().await;
        let additions: Vec<_> = wanted.difference(&current).copied().collect();
        let mut routes = AsyncRouteManager::new().context("cannot open macOS route manager")?;
        let existing = routes.list().await.context("cannot inspect macOS routes")?;

        for address in &wanted {
            for route in &existing {
                if route.prefix() == 0 || route.if_index() == Some(self.index)
                    || self.address_route.matches(route) {
                    continue;
                }
                if conflicts_with_route(*address, route) {
                    anyhow::bail!("private address conflicts with an existing network route");
                }
            }
        }

        for address in additions {
            // Remote hosts require an exclusive ADD. Own traffic stays on the
            // address-born utun host route and the production local dispatcher.
            let route = Route::new(IpAddr::V4(address), 32).with_if_index(self.index);
            routes
                .add(&route)
                .await
                .context("cannot add macOS private host route")?;
            current.insert(address);
        }
        let removals: Vec<_> = current.difference(&wanted).copied().collect();
        for address in removals {
            let route = Route::new(IpAddr::V4(address), 32).with_if_index(self.index);
            routes
                .delete(&route)
                .await
                .context("cannot remove macOS private host route")?;
            current.remove(&address);
        }
        Ok(())
    }

    pub async fn exit_mtu(&self, enabled: bool) -> Result<()> {
        let mtu = porthub_mesh::MAX_PACKET - if enabled { 20 } else { 0 };
        if self.device.mtu()? != mtu as u16 {
            self.device.set_mtu(mtu as u16).context("exit MTU configuration failed")?;
        }
        Ok(())
    }

    pub async fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        self.device
            .recv(buffer)
            .await
            .context("macOS utun read failed")
    }

    pub async fn write(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= porthub_mesh::MAX_PACKET,
            "private packet exceeds MTU"
        );
        ensure!(
            self.device
                .send(bytes)
                .await
                .context("macOS utun write failed")?
                == bytes.len(),
            "short private packet write"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::conflicts_with_route;
    use route_manager::Route;
    use std::net::IpAddr;

    #[test]
    fn route_preflight_detects_only_overlapping_ipv4_networks() {
        let lan = Route::new("192.168.80.0".parse::<IpAddr>().unwrap(), 24);
        assert!(conflicts_with_route("192.168.80.9".parse().unwrap(), &lan));
        assert!(!conflicts_with_route("10.203.0.9".parse().unwrap(), &lan));
        let default = Route::new("0.0.0.0".parse().unwrap(), 0);
        assert!(!conflicts_with_route(
            "10.203.0.9".parse().unwrap(),
            &default
        ));
        let ipv6 = Route::new("fd00::".parse().unwrap(), 64);
        assert!(!conflicts_with_route("10.203.0.9".parse().unwrap(), &ipv6));
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        self.packet_loop.retire();
        // Kernel retires its address-born host route with the owned device.
        let routes = self.routes.get_mut();
        let captures=self.capture_routes.get_mut();
        if routes.is_empty() && captures.is_empty() {
            return;
        }
        let Ok(mut manager) = route_manager::RouteManager::new() else {
            return;
        };
        for prefix in std::mem::take(captures) {
            let route=Route::new(IpAddr::V4(prefix.address()),prefix.prefix()).with_if_index(self.index);
            if manager.delete(&route).is_err(){tracing::warn!("could not remove owned capture route during shutdown");}
        }
        for address in routes.drain() {
            let route = Route::new(IpAddr::V4(address), 32).with_if_index(self.index);
            if manager.delete(&route).is_err() {
                tracing::warn!("could not remove an owned macOS private route during shutdown");
            }
        }
    }
}
