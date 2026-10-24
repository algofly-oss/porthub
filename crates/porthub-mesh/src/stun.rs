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
async fn query(socket: &UdpSocket, target: SocketAddr) -> Option<SocketAddr> {
    let mut request = Message::new();
    request
        .build(&[Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)])
        .ok()?;
    let mut retry = tokio::time::interval(Duration::from_millis(250));
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut bytes = [0u8; 2048];
    let mut sent = 0;
    loop {
        tokio::select! {
            _ = retry.tick() => {
                if sent >= 3 { return None; }
                socket.send_to(&request.raw, target).await.ok()?;
                sent += 1;
            },
            packet = socket.recv_from(&mut bytes) => {
                let (size, source) = packet.ok()?;
                if source != target || size < 20 { continue; }
                let mut response = Message::new();
                if response.unmarshal_binary(&bytes[..size]).is_err() || response.typ != BINDING_SUCCESS || response.transaction_id != request.transaction_id { continue; }
                let mut mapped = XorMappedAddress::default();
                if mapped.get_from(&response).is_err() || mapped.port == 0 || !mapped.ip.is_ipv4() || mapped.ip.is_unspecified() || mapped.ip.is_multicast() { continue; }
                return Some(SocketAddr::new(mapped.ip, mapped.port));
            }
        }
    }
}
/// Gather once, before the packet reader owns this socket. DNS, retries and
/// all configured servers share a 1.5-second budget. No idle probing task is
/// created and no discovery request runs in the transfer path.
pub async fn mapped(socket: &UdpSocket, servers: &[String]) -> Option<SocketAddr> {
    tokio::time::timeout(Duration::from_millis(1500), async {
        for (host, port) in servers.iter().filter_map(|url| authority(url)).take(2) {
            let addresses = tokio::time::timeout(
                Duration::from_millis(300),
                tokio::net::lookup_host((host, port)),
            )
            .await;
            let Ok(Ok(mut addresses)) = addresses else {
                continue;
            };
            let Some(target) = addresses.find(SocketAddr::is_ipv4) else {
                continue;
            };
            if let Some(address) = query(socket, target).await {
                return Some(address);
            }
        }
        None
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
