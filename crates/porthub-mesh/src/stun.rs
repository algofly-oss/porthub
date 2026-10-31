//! Bounded server-reflexive gathering on the actual ICE UDP socket. A STUN
//! response is only an address hint; enrolled identity is still proved by DTLS.
use std::{net::SocketAddr, time::Duration};
use stun::{
    agent::TransactionId,
    message::{Getter, Message, BINDING_REQUEST, BINDING_SUCCESS},
    xoraddr::XorMappedAddress,
};
use tokio::net::UdpSocket;

fn authority(raw: &str) -> Option<(String, u16)> {
    if raw.len() > 2048 {
        return None;
    }
    let raw = raw.strip_prefix("stun:")?;
    let raw = raw.strip_suffix("?transport=udp").unwrap_or(raw);
    let url = url::Url::parse(&format!("stun://{raw}")).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return None;
    }
    let host = match url.host()? {
        url::Host::Domain(host) => host.to_string(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => ip.to_string(),
    };
    let port = url.port().unwrap_or(3478);
    (port != 0).then_some((host, port))
}
/// Resolve independently: one broken DNS response/address must not consume the
/// other server's entire discovery budget. A single receive owner below matches
/// every response to its exact source and unpredictable transaction ID.
async fn targets(servers: &[String], ipv4: bool) -> Vec<SocketAddr> {
    let mut lookups = tokio::task::JoinSet::new();
    for (host, port) in servers.iter().filter_map(|url| authority(url)).take(2) {
        lookups.spawn(async move {
            tokio::time::timeout(
                Duration::from_millis(300),
                tokio::net::lookup_host((host, port)),
            )
            .await
            .ok()
            .and_then(Result::ok)
            .map(|addresses| {
                addresses
                    .filter(|address| address.is_ipv4() == ipv4)
                    .take(4)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
        });
    }
    let mut targets = Vec::new();
    while let Some(Ok(addresses)) = lookups.join_next().await {
        for address in addresses {
            if !targets.contains(&address) {
                targets.push(address);
            }
        }
    }
    targets
}
async fn query(socket: &UdpSocket, targets: Vec<SocketAddr>) -> Option<SocketAddr> {
    let ipv4 = socket.local_addr().ok()?.is_ipv4();
    let requests: Vec<_> = targets
        .into_iter()
        .filter_map(|target| {
            let mut request = Message::new();
            request
                .build(&[Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)])
                .ok()?;
            Some((target, request))
        })
        .collect();
    if requests.is_empty() {
        return None;
    }
    let mut retry = tokio::time::interval(Duration::from_millis(250));
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut bytes = [0u8; 2048];
    let mut sent = 0;
    loop {
        tokio::select! {
            _ = retry.tick() => {
                if sent >= 3 { return None; }
                for (target, request) in &requests {
                    // An unreachable address is not evidence that every other
                    // configured STUN address is unreachable too.
                    let _ = socket.send_to(&request.raw, target).await;
                }
                sent += 1;
            },
            packet = socket.recv_from(&mut bytes) => {
                let (size, source) = match packet {
                    Ok(packet) => packet,
                    Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::Interrupted) => {
                        // Some platforms surface ICMP from one destination on
                        // this unconnected socket. Do not abandon the others.
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        continue;
                    }
                    Err(_) => return None,
                };
                if size < 20 { continue; }
                let mut response = Message::new();
                if response.unmarshal_binary(&bytes[..size]).is_err()
                    || response.typ != BINDING_SUCCESS
                    || !requests.iter().any(|(target, request)| *target == source && request.transaction_id == response.transaction_id) { continue; }
                let mut mapped = XorMappedAddress::default();
                if mapped.get_from(&response).is_err() || mapped.port == 0
                    || mapped.ip.is_ipv4() != ipv4 || mapped.ip.is_unspecified()
                    || mapped.ip.is_multicast() { continue; }
                if let std::net::IpAddr::V6(ip) = mapped.ip {
                    if ip.is_unicast_link_local() || ip.to_ipv4_mapped().is_some() { continue; }
                }
                return Some(SocketAddr::new(mapped.ip, mapped.port));
            }
        }
    }
}
/// Gather before the packet reader owns this socket. Both families use only
/// matching STUN endpoints. Up to two servers/four addresses each share a
/// 1.5-second DNS+retry budget; no idle task or transfer-path probing is added.
pub async fn mapped(socket: &UdpSocket, servers: &[String]) -> Option<SocketAddr> {
    let ipv4 = socket.local_addr().ok()?.is_ipv4();
    tokio::time::timeout(Duration::from_millis(1500), async {
        query(socket, targets(servers, ipv4).await).await
    })
    .await
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn server_authority_accepts_udp_stun_only_without_embedded_credentials() {
        assert_eq!(
            authority("stun:example.com"),
            Some(("example.com".into(), 3478))
        );
        assert_eq!(
            authority("stun:example.com:19302?transport=udp"),
            Some(("example.com".into(), 19302))
        );
        assert_eq!(
            authority("stun:[2001:db8::1]:3478"),
            Some(("2001:db8::1".into(), 3478))
        );
        for raw in [
            "turn:example.com:3478",
            "stun:user:password@example.com",
            "stun:example.com/path",
            "stun:example.com?transport=tcp",
            "stun:example.com#fragment",
            "stun:example.com:0",
        ] {
            assert!(authority(raw).is_none());
        }
    }
}
