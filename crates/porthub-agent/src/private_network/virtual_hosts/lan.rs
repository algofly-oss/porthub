//! Resolve an explicit LAN address to a currently connected provider interface.
//! Pin the source and egress interface for every target socket.
use anyhow::{Context, Result, bail, ensure};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::net::{TcpSocket, UdpSocket};

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Lan {
    address: Ipv4Addr,
    name: String,
    index: u32,
    target: Ipv4Addr,
}

fn attached(source: Ipv4Addr, mask: Ipv4Addr, target: Ipv4Addr) -> bool {
    let mask = u32::from(mask);
    let bits = mask.leading_ones();
    if bits == 0 || bits > 31 || mask != u32::MAX << (32 - bits) {
        return false;
    }
    let src = u32::from(source);
    let dst = u32::from(target);
    source.is_private()
        && target.is_private()
        && src != dst
        && src & mask == dst & mask
        && (bits == 31 || (dst & !mask != 0 && dst & !mask != !mask))
}

impl Lan {
    pub(super) fn find(target: Ipv4Addr, sources: &[SocketAddr]) -> Result<Self> {
        let mut matches = Vec::new();
        for i in getifaddrs::getifaddrs()? {
            let (Some(std::net::IpAddr::V4(source)), Some(std::net::IpAddr::V4(mask))) =
                (i.address.ip_addr(), i.address.netmask())
            else {
                continue;
            };
            ensure!(
                source != target,
                "virtual host target belongs to this provider"
            );
            if !i.flags.contains(getifaddrs::InterfaceFlags::UP)
                || !sources.iter().any(|s| s.ip() == source)
                || !attached(source, mask, target)
            {
                continue;
            }
            if let Some(index) = i.index {
                matches.push((
                    u32::from(mask).count_ones(),
                    Self {
                        address: source,
                        name: i.name,
                        index,
                        target,
                    },
                ));
            }
        }
        matches.sort_by_key(|(bits, lan)| (std::cmp::Reverse(*bits), lan.index, lan.address));
        let (bits, lan) = matches.first().context("virtual host LAN is unavailable")?;
        ensure!(
            !matches
                .iter()
                .any(|(other, candidate)| other == bits && candidate.index != lan.index),
            "virtual host LAN address is ambiguous"
        );
        Ok(lan.clone())
    }

    fn socket(&self, ty: Type, proto: Protocol) -> Result<Socket> {
        let socket = Socket::new(Domain::IPV4, ty, Some(proto))?;
        #[cfg(target_os = "linux")]
        socket.bind_device(Some(self.name.as_bytes()))?;
        #[cfg(target_os = "macos")]
        socket.bind_device_by_index_v4(Some(
            std::num::NonZeroU32::new(self.index).context("missing LAN index")?,
        ))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let enabled: libc::c_int = 1;
            // Only connected routes can carry a virtual host socket.
            let rc = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_DONTROUTE,
                    (&enabled as *const libc::c_int).cast(),
                    std::mem::size_of_val(&enabled) as _,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            use windows_sys::Win32::Networking::WinSock::{
                IP_UNICAST_IF, IPPROTO_IP, WSAGetLastError, setsockopt,
            };
            let network_index = self.index.to_be();
            let rc = unsafe {
                setsockopt(
                    socket.as_raw_socket() as _,
                    IPPROTO_IP,
                    IP_UNICAST_IF,
                    (&network_index as *const u32).cast(),
                    4,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }).into());
            }
        }
        socket.bind(&SocketAddrV4::new(self.address, 0).into())?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    }
    pub(super) async fn tcp(&self, port: u16) -> Result<tokio::net::TcpStream> {
        if port == 0 {
            bail!("invalid virtual port");
        }
        let sock = TcpSocket::from_std_stream(self.socket(Type::STREAM, Protocol::TCP)?.into());
        Ok(tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sock.connect(SocketAddrV4::new(self.target, port).into()),
        )
        .await??)
    }
    pub(super) async fn udp(&self, port: u16) -> Result<UdpSocket> {
        ensure!(port != 0, "invalid virtual port");
        let sock = UdpSocket::from_std(self.socket(Type::DGRAM, Protocol::UDP)?.into())?;
        sock.connect(SocketAddrV4::new(self.target, port)).await?;
        Ok(sock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selects_only_distinct_unicast_hosts_on_the_connected_network() {
        let a = "192.168.0.3".parse().unwrap();
        let mask = "255.255.255.0".parse().unwrap();
        assert!(attached(a, mask, "192.168.0.166".parse().unwrap()));
        for bad in [
            "192.168.0.3",
            "192.168.0.0",
            "192.168.0.255",
            "192.168.1.7",
            "127.0.0.1",
            "169.254.169.254",
            "8.8.8.8",
        ] {
            assert!(!attached(a, mask, bad.parse().unwrap()));
        }
        assert!(!attached(
            a,
            "255.0.255.0".parse().unwrap(),
            "192.168.0.166".parse().unwrap()
        ));
    }
}

#[cfg(all(test, target_os = "linux"))]
impl Lan {
    pub(super) fn loopback_fixture() -> Self {
        Self {
            address: Ipv4Addr::LOCALHOST,
            target: Ipv4Addr::LOCALHOST,
            name: "lo".into(),
            index: 1,
        }
    }
}
