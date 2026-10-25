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

pub struct Tun {
    device: tun_rs::AsyncDevice,
    pub index: u32,
    pub name: String,
    own: Ipv4Addr,
    routes: Mutex<HashSet<Ipv4Addr>>,
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
    pub async fn open(_name: &str, own: Ipv4Addr, peers: &[Ipv4Addr]) -> Result<Self> {
        ensure!(own.is_private(), "invalid private interface address");
        ensure!(
            peers.iter().all(Ipv4Addr::is_private),
            "invalid private route address"
        );

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
        let tun = Self {
            device,
            index,
            name,
            own,
            routes: Mutex::new(HashSet::new()),
        };
        tun.update_routes(peers).await?;
        Ok(tun)
    }

    pub async fn update_routes(&self, peers: &[Ipv4Addr]) -> Result<()> {
        ensure!(
            peers.iter().all(Ipv4Addr::is_private),
            "invalid private route address"
        );
        let mut wanted: HashSet<_> = peers.iter().copied().collect();
        wanted.insert(self.own);
        let mut current = self.routes.lock().await;
        let additions: Vec<_> = wanted.difference(&current).copied().collect();
        let mut routes = AsyncRouteManager::new().context("cannot open macOS route manager")?;
        let existing = routes.list().await.context("cannot inspect macOS routes")?;

        for address in &additions {
            for route in &existing {
                if route.prefix() == 0 || route.if_index() == Some(self.index) {
                    continue;
                }
                if conflicts_with_route(*address, route) {
                    anyhow::bail!("private address conflicts with an existing network route");
                }
            }
        }

        for address in additions {
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
        let routes = self.routes.get_mut();
        if routes.is_empty() {
            return;
        }
        let Ok(mut manager) = route_manager::RouteManager::new() else {
            return;
        };
        for address in routes.drain() {
            let route = Route::new(IpAddr::V4(address), 32).with_if_index(self.index);
            if manager.delete(&route).is_err() {
                tracing::warn!("could not remove an owned macOS private route during shutdown");
            }
        }
    }
}
