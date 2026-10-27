//! Control transports bind an advertised physical address before connecting.
//! Consumer source rules then keep these sockets outside the exit tunnel.
use anyhow::{ensure, Result};
use std::net::{IpAddr, SocketAddr};
use tokio::net::{TcpSocket, TcpStream};

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
    for remote in addresses {
        if local.is_empty() {
            if let Ok(stream) = TcpStream::connect(remote).await {
                return Ok(stream);
            }
        } else {
            for source in local
                .iter()
                .filter(|source| source.is_ipv4() == remote.is_ipv4())
            {
                let socket = if remote.is_ipv4() {
                    TcpSocket::new_v4()?
                } else {
                    TcpSocket::new_v6()?
                };
                #[cfg(target_os = "macos")]
                if bind_interface(&socket2::SockRef::from(&socket), *source).is_err() { continue; }
                if socket.bind(SocketAddr::new(*source, 0)).is_err() {
                    continue;
                }
                if let Ok(Ok(stream)) =
                    tokio::time::timeout(std::time::Duration::from_secs(1), socket.connect(remote))
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
    let index = getifaddrs::getifaddrs()?.find(|interface| interface.address.ip_addr() == Some(source))
        .and_then(|interface| interface.index).and_then(std::num::NonZeroU32::new)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "physical interface unavailable"))?;
    if source.is_ipv4() { socket.bind_device_by_index_v4(Some(index)) }
    else { socket.bind_device_by_index_v6(Some(index)) }
}
#[cfg(target_os = "macos")]
pub fn interface_name(source: IpAddr) -> std::io::Result<String> {
    getifaddrs::getifaddrs()?.find(|interface| interface.address.ip_addr() == Some(source))
        .map(|interface| interface.name)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "physical interface unavailable"))
}
