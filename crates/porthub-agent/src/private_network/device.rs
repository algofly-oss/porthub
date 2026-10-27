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
    routes: Mutex<HashSet<Ipv4Addr>>,
}
fn safe<T, E>(result: std::result::Result<T, E>, message: &'static str) -> Result<T> {
    result.map_err(|_| anyhow::anyhow!(message))
}
impl Tun {
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
            name: name.into(),
            routes: Mutex::new(HashSet::new()),
        };
        tun.update_routes(peers).await?;
        Ok(tun)
    }
    pub async fn update_routes(&self, peers: &[Ipv4Addr]) -> Result<()> {
        let wanted: HashSet<_> = peers.iter().copied().collect();
        let mut current = self.routes.lock().await;
        let additions: Vec<_> = wanted.difference(&current).copied().collect();
        check_routes(&self.netlink, &additions, Some(self.index)).await?;
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
