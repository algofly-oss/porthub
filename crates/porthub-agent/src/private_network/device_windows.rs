//! Native Windows Wintun device and explicit peer /32 routing.
use anyhow::{ensure, Context, Result};
use route_manager::{AsyncRouteManager, Route};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};
use tokio::sync::Mutex;
use tun_rs::DeviceBuilder;

#[cfg(target_arch = "x86_64")]
const WINTUN: &[u8] = include_bytes!("../../assets/wintun/amd64/wintun.dll");
#[cfg(target_arch = "x86")]
const WINTUN: &[u8] = include_bytes!("../../assets/wintun/x86/wintun.dll");
#[cfg(target_arch = "aarch64")]
const WINTUN: &[u8] = include_bytes!("../../assets/wintun/arm64/wintun.dll");
#[cfg(target_arch = "arm")]
const WINTUN: &[u8] = include_bytes!("../../assets/wintun/arm/wintun.dll");
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm"
)))]
compile_error!(
    "PortHub private networking has no bundled Wintun for this Windows CPU architecture"
);

pub struct Tun {
    device: tun_rs::AsyncDevice,
    pub index: u32,
    pub name: String,
    own: Ipv4Addr,
    routes: Mutex<HashSet<Ipv4Addr>>,
    _driver: PathBuf,
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

fn install_driver() -> Result<PathBuf> {
    let root = crate::service::windows_acl::managed_root()?;
    fs::create_dir_all(&root).context("cannot create PortHub state directory")?;
    crate::service::windows_acl::secure(&root, true)?;
    let directory = root.join("drivers");
    fs::create_dir_all(&directory).context("cannot create PortHub driver directory")?;
    crate::service::windows_acl::secure(&directory, true)?;
    let path = directory.join("wintun.dll");
    if path.exists() {
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "PortHub driver path is not a regular file"
        );
        ensure!(
            fs::read(&path)? == WINTUN,
            "installed PortHub Wintun does not match the bundled driver"
        );
        crate::service::windows_acl::secure(&path, false)?;
        return Ok(path);
    }
    let mut nonce = [0; 8];
    getrandom::fill(&mut nonce).context("cannot allocate private Wintun staging name")?;
    let temporary = directory.join(format!(
        "wintun-{}-{:016x}.tmp",
        std::process::id(),
        u64::from_le_bytes(nonce)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .context("cannot install bundled PortHub Wintun runtime")?;
    let publish = (|| -> Result<()> {
        file.write_all(WINTUN)?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&temporary, &path)
            .context("cannot publish bundled PortHub Wintun runtime")?;
        fs::remove_file(&temporary)?;
        Ok(())
    })();
    if publish.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    publish?;
    crate::service::windows_acl::secure(&path, false)?;
    Ok(path)
}

impl Tun {
    pub async fn open(name: &str, own: Ipv4Addr, peers: &[Ipv4Addr]) -> Result<Self> {
        ensure!(own.is_private(), "invalid private interface address");
        ensure!(
            peers.iter().all(Ipv4Addr::is_private),
            "invalid private route address"
        );
        let driver = install_driver()?;
        ensure!(
            name.len() == 10
                && name.starts_with("ph")
                && name[2..].bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid private adapter identity"
        );
        let device = DeviceBuilder::new()
            .name(name)
            .ipv4(own, 32, None)
            .mtu(porthub_mesh::MAX_PACKET as u16)
            .wintun_file(driver.to_string_lossy().into_owned())
            .build_async()
            .context("cannot create Windows private Wintun adapter")?;
        let name = device
            .name()
            .context("cannot identify Windows private adapter")?;
        let index = device
            .if_index()
            .context("cannot identify Windows private adapter index")?;
        let tun = Self {
            device,
            index,
            name,
            own,
            routes: Mutex::new(HashSet::new()),
            _driver: driver,
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
        let mut routes = AsyncRouteManager::new().context("cannot open Windows route manager")?;
        let existing = routes
            .list()
            .await
            .context("cannot inspect Windows routes")?;
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
                .context("cannot add Windows private host route")?;
            current.insert(address);
        }
        let removals: Vec<_> = current.difference(&wanted).copied().collect();
        for address in removals {
            let route = Route::new(IpAddr::V4(address), 32).with_if_index(self.index);
            routes
                .delete(&route)
                .await
                .context("cannot remove Windows private host route")?;
            current.remove(&address);
        }
        Ok(())
    }

    pub async fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        self.device
            .recv(buffer)
            .await
            .context("Windows Wintun read failed")
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
                .context("Windows Wintun write failed")?
                == bytes.len(),
            "short private packet write"
        );
        Ok(())
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
                tracing::warn!("could not remove an owned Windows private route during shutdown");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::conflicts_with_route;
    use route_manager::Route;
    use std::net::IpAddr;

    #[test]
    fn route_preflight_detects_overlaps_but_allows_default_and_other_family_routes() {
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
