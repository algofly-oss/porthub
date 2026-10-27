//! Bounded forwarding for names captured by a DNS rule's resolver route but not
//! matched by that rule. Private-zone answers never reach this module. Upstream
//! configuration is refreshed lazily; an idle agent does no DNS polling.
use anyhow::{ensure, Context, Result};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use std::{net::SocketAddr, time::{Duration, Instant}};
#[cfg(target_os = "linux")]
use std::net::IpAddr;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpStream, UdpSocket}, sync::Mutex};

#[derive(Default)]
pub(super) struct Upstream {
    cache: Mutex<Option<(Instant, Vec<SocketAddr>)>>,
}

impl Upstream {
    #[cfg(test)]
    pub(super) fn fixture(server: SocketAddr) -> Self {
        Self { cache: Mutex::new(Some((Instant::now(), vec![server]))) }
    }
    async fn servers(&self, own: SocketAddr) -> Vec<SocketAddr> {
        let mut cache = self.cache.lock().await;
        if cache.as_ref().is_none_or(|(at, _)| at.elapsed() >= Duration::from_secs(30)) {
            let discovered = tokio::time::timeout(Duration::from_secs(2), discover()).await;
            let servers = discovered.ok().and_then(Result::ok).unwrap_or_default();
            let mut unique = Vec::new();
            for server in servers {
                if usable(server, own) && !unique.contains(&server) { unique.push(server); }
                if unique.len() == 4 { break; }
            }
            *cache = Some((Instant::now(), unique));
        }
        cache.as_ref().unwrap().1.clone()
    }

    pub(super) async fn answer(&self, bytes: &[u8], own: SocketAddr, tcp: bool) -> Option<Vec<u8>> {
        let query = Message::from_vec(bytes).ok()?;
        let servers = self.servers(own).await;
        for server in servers {
            let result = tokio::time::timeout(Duration::from_secs(2), exchange(bytes, &query, server, tcp)).await;
            if let Ok(Ok(reply)) = result { return Some(reply); }
        }
        failure(&query)
    }
}

fn usable(server: SocketAddr, own: SocketAddr) -> bool {
    server.ip() != own.ip() && !server.ip().is_unspecified() && !server.ip().is_multicast()
        // System stubs route these names back to PortHub. Read their real
        // upstream configuration instead, preventing recursive forwarding.
        && !server.ip().is_loopback()
}

fn failure(query: &Message) -> Option<Vec<u8>> {
    let mut reply = Message::new(query.metadata.id, MessageType::Response, query.metadata.op_code);
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.metadata.response_code = ResponseCode::ServFail;
    for question in &query.queries { reply.add_query(question.clone()); }
    reply.to_vec().ok()
}

async fn exchange(bytes: &[u8], query: &Message, server: SocketAddr, tcp: bool) -> Result<Vec<u8>> {
    let mut bytes = bytes.to_vec();
    let id = getrandom::u32()? as u16;
    bytes[..2].copy_from_slice(&id.to_be_bytes());
    let reply = if tcp {
        let mut stream = TcpStream::connect(server).await?;
        stream.write_u16(bytes.len() as u16).await?;
        stream.write_all(&bytes).await?;
        let len = stream.read_u16().await? as usize;
        ensure!(len >= 12, "invalid upstream DNS response");
        let mut reply = vec![0; len];
        stream.read_exact(&mut reply).await?;
        reply
    } else {
        let local: SocketAddr = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse()?;
        let socket = UdpSocket::bind(local).await?;
        socket.connect(server).await?;
        socket.send(&bytes).await?;
        let mut reply = vec![0; 65535];
        let len = socket.recv(&mut reply).await?;
        reply.truncate(len);
        reply
    };
    let response = Message::from_vec(&reply)?;
    ensure!(response.metadata.id == id && response.metadata.message_type == MessageType::Response
        && response.metadata.op_code == query.metadata.op_code && response.queries == query.queries,
        "upstream DNS response does not match query");
    ensure!(!matches!(response.metadata.response_code, ResponseCode::ServFail | ResponseCode::Refused), "upstream DNS unavailable");
    let mut reply = reply;
    reply[..2].copy_from_slice(&query.metadata.id.to_be_bytes());
    if !tcp {
        // Do not turn a small local UDP request into an oversized datagram.
        // The client retries truncated responses over our TCP listener.
        let limit = query.edns.as_ref().map_or(512, |edns| usize::from(edns.max_payload()).clamp(512, 4096));
        if reply.len() > limit {
            let mut truncated = Message::new(query.metadata.id, MessageType::Response, query.metadata.op_code);
            truncated.metadata.truncation = true;
            truncated.metadata.recursion_desired = query.metadata.recursion_desired;
            truncated.metadata.recursion_available = response.metadata.recursion_available;
            for question in &query.queries { truncated.add_query(question.clone()); }
            return Ok(truncated.to_vec()?);
        }
    }
    Ok(reply)
}

async fn discover() -> Result<Vec<SocketAddr>> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(servers) = resolved_servers().await {
            if !servers.is_empty() { return Ok(servers); }
        }
        // resolved's upstream file excludes its local stub and is maintained
        // when DHCP/VPN configuration changes. It is read, never modified.
        if let Ok(bytes) = tokio::fs::read("/run/systemd/resolve/resolv.conf").await {
            ensure!(bytes.len() <= 65536, "DNS configuration exceeds size limit");
            let (config, _) = hickory_resolver::system_conf::parse_resolv_conf(bytes)?;
            return Ok(config.name_servers().iter().map(|server| SocketAddr::new(server.ip, 53)).collect());
        }
    }
    // macOS uses SystemConfiguration; Windows enumerates active adapters. No
    // public DNS provider is hardcoded and no helper needs to be installed.
    tokio::task::spawn_blocking(|| {
        let (config, _) = hickory_resolver::system_conf::read_system_conf()?;
        Ok(config.name_servers().iter().map(|server| SocketAddr::new(server.ip, 53)).collect())
    }).await.context("DNS configuration reader stopped")?
}

#[cfg(target_os = "linux")]
async fn resolved_servers() -> Result<Vec<SocketAddr>> {
    use nlink::netlink::{Connection, Route};
    let links = Connection::<Route>::new()?.get_links().await?;
    let owned: std::collections::HashSet<_> = links.iter()
        .filter(|link| link.name().is_some_and(|name| name.starts_with("ph")))
        .map(|link| link.ifindex() as i32).collect();
    let connection = zbus::Connection::system().await?;
    let manager = zbus::Proxy::new(&connection, "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager").await?;
    let servers: Vec<(i32, i32, Vec<u8>, u16, String)> = manager.get_property("DNSEx").await?;
    Ok(servers.into_iter().filter(|(index, _, _, _, _)| !owned.contains(index))
        .filter_map(|(_, family, bytes, port, _)| {
            let ip = match family {
                libc::AF_INET => IpAddr::V4(<[u8; 4]>::try_from(bytes).ok()?.into()),
                libc::AF_INET6 => IpAddr::V6(<[u8; 16]>::try_from(bytes).ok()?.into()),
                _ => return None,
            };
            Some(SocketAddr::new(ip, if port == 0 { 53 } else { port }))
        }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{op::Query, rr::{Name, RecordType}};

    #[tokio::test]
    async fn tcp_upstream_uses_dns_framing_and_restores_client_id() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let len = stream.read_u16().await? as usize;
            let mut bytes = vec![0; len];
            stream.read_exact(&mut bytes).await?;
            let mut response = Message::from_vec(&bytes)?;
            response.metadata.message_type = MessageType::Response;
            response.metadata.response_code = ResponseCode::NXDomain;
            let bytes = response.to_vec()?;
            stream.write_u16(bytes.len() as u16).await?;
            stream.write_all(&bytes).await?;
            anyhow::Ok(())
        });
        let mut query = Message::query();
        query.metadata.id = 567;
        query.add_query(Query::query(Name::from_ascii("example.test.")?, RecordType::AAAA));
        let bytes = query.to_vec()?;
        let query = Message::from_vec(&bytes)?;
        let response = Message::from_vec(&exchange(&bytes, &query, address, true).await?)?;
        assert_eq!(response.metadata.id, 567);
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn upstream_checks_question_and_id_and_preserves_negative_answers() -> Result<()> {
        let listener = UdpSocket::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let mut query = Message::query();
        query.metadata.id = 123;
        query.add_query(Query::query(Name::from_ascii("example.test")?, RecordType::A));
        let wire = query.to_vec()?;
        let query = Message::from_vec(&wire)?;
        let server = tokio::spawn(async move {
            for invalid in [false, true] {
                let mut buffer = [0; 1500];
                let (n, peer) = listener.recv_from(&mut buffer).await?;
                let request = Message::from_vec(&buffer[..n])?;
                let mut reply = request.clone();
                reply.metadata.message_type = MessageType::Response;
                reply.metadata.response_code = ResponseCode::NXDomain;
                if invalid { reply.metadata.id = reply.metadata.id.wrapping_add(1); }
                listener.send_to(&reply.to_vec()?, peer).await?;
            }
            anyhow::Ok(())
        });
        let reply = exchange(&wire, &query, address, false).await?;
        let reply = Message::from_vec(&reply)?;
        assert_eq!(reply.metadata.id, 123);
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        assert!(exchange(&wire, &query, address, false).await.is_err());
        server.await??;
        assert!(!usable(address, address));
        assert!(!usable("127.0.0.53:53".parse()?, address));
        assert!(usable("192.0.2.53:53".parse()?, address));
        Ok(())
    }
}
