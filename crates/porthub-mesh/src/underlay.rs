//! Control transports bind an advertised physical address before connecting.
//! Consumer source rules then keep these sockets outside the exit tunnel.
use anyhow::{ensure, Result};
use std::net::{IpAddr, SocketAddr};
use tokio::net::{TcpSocket, TcpStream};

/// Addresses suitable for exchanging unscoped ICE candidates. Link-local IPv6
/// needs an interface scope meaningful only on its own host and is not shared.
pub fn candidate_ip(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(ip) => !ip.is_link_local() && !ip.is_broadcast(),
            IpAddr::V6(ip) => !ip.is_unicast_link_local() && ip.to_ipv4_mapped().is_none(),
        }
}

/// Keep IPv4 control-source preference while reserving room for both families.
/// A host with many temporary IPv6 addresses must not crowd out IPv4 (or vice
/// versa). Interface eligibility is decided by each native discovery owner.
pub fn candidates(mut addresses: Vec<(u32, SocketAddr)>) -> Vec<SocketAddr> {
    addresses.retain(|(_, address)| candidate_ip(address.ip()));
    addresses.sort_unstable();
    let mut seen = std::collections::HashSet::new();
    addresses.retain(|(_, address)| seen.insert(address.ip()));
    let v4 = addresses
        .iter()
        .filter(|(_, address)| address.is_ipv4())
        .count();
    let v6 = addresses.len() - v4;
    let limit4 = v4.min(16 - v6.min(8));
    let limit6 = v6.min(16 - limit4);
    addresses
        .iter()
        .filter(|(_, address)| address.is_ipv4())
        .take(limit4)
        .chain(
            addresses
                .iter()
                .filter(|(_, address)| address.is_ipv6())
                .take(limit6),
        )
        .map(|(_, address)| *address)
        .collect()
}

pub async fn connect(url: &url::Url, local: &[IpAddr]) -> Result<TcpStream> {
    ensure!(local.len() <= 16, "too many underlay bindings");
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing transport host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("missing transport port"))?;
    let addresses: Vec<_> = match url.host() {
        Some(url::Host::Ipv4(ip)) => vec![SocketAddr::new(ip.into(), port)],
        Some(url::Host::Ipv6(ip)) => vec![SocketAddr::new(ip.into(), port)],
        _ => tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| anyhow::anyhow!("transport address lookup failed"))?
            .take(16)
            .collect(),
    };
    connect_addresses(&addresses, local).await
}
async fn connect_addresses(addresses: &[SocketAddr], local: &[IpAddr]) -> Result<TcpStream> {
    // Race address families, with at most two connection attempts active.
    // A broken IPv6 route cannot spend the caller's whole timeout before IPv4
    // is tried. Dropping the losing future closes its socket; no task survives.
    let ipv4 = connect_family(addresses, local, true);
    let ipv6 = connect_family(addresses, local, false);
    tokio::pin!(ipv4, ipv6);
    tokio::select! {
        result = &mut ipv4 => match result { Ok(stream) => Ok(stream), Err(_) => ipv6.await },
        result = &mut ipv6 => match result { Ok(stream) => Ok(stream), Err(_) => ipv4.await },
    }
}
async fn connect_family(
    addresses: &[SocketAddr],
    local: &[IpAddr],
    ipv4: bool,
) -> Result<TcpStream> {
    for remote in addresses.iter().filter(|address| address.is_ipv4() == ipv4) {
        if local.is_empty() {
            if let Ok(Ok(stream)) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                TcpStream::connect(remote),
            )
            .await
            {
                return Ok(stream);
            }
        } else {
            for source in local.iter().filter(|source| source.is_ipv4() == ipv4) {
                let socket = if ipv4 {
                    TcpSocket::new_v4()
                } else {
                    TcpSocket::new_v6()
                };
                let Ok(socket) = socket else {
                    continue;
                };
                #[cfg(target_os = "macos")]
                if bind_interface(&socket2::SockRef::from(&socket), *source).is_err() {
                    continue;
                }
                if socket.bind(SocketAddr::new(*source, 0)).is_err() {
                    continue;
                }
                if let Ok(Ok(stream)) =
                    tokio::time::timeout(std::time::Duration::from_secs(1), socket.connect(*remote))
                        .await
                {
                    return Ok(stream);
                }
            }
        }
    }
    anyhow::bail!("underlay transport connection failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_retains_both_families_without_unroutable_or_duplicate_hints() {
        let mut addresses = Vec::new();
        for n in 1..=20 {
            addresses.push((0, format!("192.168.1.{n}:0").parse().unwrap()));
            addresses.push((1, format!("[2001:db8::{n}]:0").parse().unwrap()));
        }
        addresses.extend(
            [
                "[::]:0",
                "[::1]:0",
                "[fe80::1]:0",
                "[ff02::1]:0",
                "[::ffff:192.168.1.1]:0",
                "0.0.0.0:0",
                "127.0.0.1:0",
                "169.254.1.1:0",
                "224.0.0.1:0",
                "255.255.255.255:0",
                "192.168.1.1:0",
            ]
            .map(|s| (0, s.parse().unwrap())),
        );
        let selected = candidates(addresses);
        assert_eq!(selected.len(), 16);
        assert_eq!(selected.iter().filter(|a| a.is_ipv4()).count(), 8);
        assert_eq!(selected.iter().filter(|a| a.is_ipv6()).count(), 8);
        assert_eq!(selected[0], "192.168.1.1:0".parse::<SocketAddr>().unwrap());
        assert_eq!(
            selected
                .iter()
                .map(SocketAddr::ip)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            16
        );
        assert!(candidate_ip("fd12:3456::1".parse().unwrap()));
        assert_eq!(
            candidates(vec![(1, "[fd12:3456::1]:0".parse().unwrap())]).len(),
            1
        );
    }
    #[tokio::test]
    async fn dual_stack_control_dials_retain_explicit_source_and_other_family_fallback(
    ) -> Result<()> {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let listener = tokio::net::TcpListener::bind(bind).await?;
            let port = listener.local_addr()?.port();
            let addresses = [
                SocketAddr::new("127.0.0.1".parse()?, port),
                SocketAddr::new("::1".parse()?, port),
            ];
            let source = listener.local_addr()?.ip();
            let stream = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                connect_addresses(
                    &addresses,
                    &["192.0.2.123".parse()?, "2001:db8::123".parse()?, source],
                ),
            )
            .await??;
            let (_, remote) = listener.accept().await?;
            assert_eq!(stream.local_addr()?.ip(), source);
            assert_eq!(remote, stream.local_addr()?);
        }
        Ok(())
    }
    #[tokio::test]
    async fn control_connections_bind_the_requested_source_without_unbound_fallback() -> Result<()>
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = url::Url::parse(&format!("http://{}", listener.local_addr()?))?;
        let stream = connect(&url, &["192.0.2.123".parse()?, "127.0.0.1".parse()?]).await?;
        let (_, remote) = listener.accept().await?;
        assert_eq!(stream.local_addr()?.ip(), "127.0.0.1".parse::<IpAddr>()?);
        assert_eq!(remote, stream.local_addr()?);
        assert!(connect(&url, &["192.0.2.123".parse()?]).await.is_err());
        Ok(())
    }
}

/// Bind the physical interface as well as its address. macOS source binding
/// alone does not bypass an unrelated VPN's more-specific routes or PF states.
#[cfg(target_os = "macos")]
pub fn bind_interface(socket: &socket2::Socket, source: IpAddr) -> std::io::Result<()> {
    let index = getifaddrs::getifaddrs()?
        .find(|interface| interface.address.ip_addr() == Some(source))
        .and_then(|interface| interface.index)
        .and_then(std::num::NonZeroU32::new)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "physical interface unavailable",
            )
        })?;
    if source.is_ipv4() {
        socket.bind_device_by_index_v4(Some(index))
    } else {
        socket.bind_device_by_index_v6(Some(index))
    }
}
#[cfg(target_os = "macos")]
pub fn interface_name(source: IpAddr) -> std::io::Result<String> {
    getifaddrs::getifaddrs()?
        .find(|interface| interface.address.ip_addr() == Some(source))
        .map(|interface| interface.name)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "physical interface unavailable",
            )
        })
}
