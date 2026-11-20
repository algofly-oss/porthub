//! A short NAT-PMP lease for a live, peer-authenticated mesh socket (RFC 6886).
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

const LIFETIME: u32 = 120;
static ACTIVE: std::sync::LazyLock<Arc<Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(Semaphore::new(8)));

struct Lease {
    control: UdpSocket,
    _data: Arc<UdpSocket>,
    _slot: OwnedSemaphorePermit,
    internal: u16,
    external: u16,
    lifetime: u32,
}

fn request(internal: u16, external: u16, lifetime: u32) -> [u8; 12] {
    let mut data = [0; 12];
    data[1] = 1; // UDP
    data[4..6].copy_from_slice(&internal.to_be_bytes());
    data[6..8].copy_from_slice(&external.to_be_bytes());
    data[8..].copy_from_slice(&lifetime.to_be_bytes());
    data
}

async fn exchange(socket: &UdpSocket, request: &[u8], response: &mut [u8]) -> Option<usize> {
    timeout(Duration::from_millis(450), async {
        socket.send(request).await.ok()?;
        socket.recv(response).await.ok()
    })
    .await
    .ok()?
}

impl Lease {
    async fn renew(&mut self) -> Option<()> {
        let msg = request(self.internal, self.external, LIFETIME);
        let mut buf = [0; 64];
        if exchange(&self.control, &msg, &mut buf).await? != 16
            || buf[..4] != [0, 129, 0, 0]
            || buf[8..10] != self.internal.to_be_bytes()
        {
            return None;
        }
        let external = u16::from_be_bytes([buf[10], buf[11]]);
        let lifetime = u32::from_be_bytes(buf[12..16].try_into().ok()?);
        if external == 0
            || !(10..=LIFETIME).contains(&lifetime)
            || (self.external != 0 && self.external != external)
        {
            return None;
        }
        self.external = external;
        self.lifetime = lifetime;
        Some(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        // Keep ownership of this exact bound port through the deletion send.
        // A lost request or a process crash falls back to finite router expiry.
        if self.external != 0 {
            let _ = self.control.try_send(&request(self.internal, 0, 0));
        }
    }
}

pub(crate) struct Mapping {
    pub endpoint: SocketAddrV4,
    cancel: tokio_util::sync::CancellationToken,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl Mapping {
    pub(crate) async fn acquire(
        data: Arc<UdpSocket>,
        gateway: Ipv4Addr,
        observed: Ipv4Addr,
    ) -> Option<Self> {
        let base = match data.local_addr().ok()? {
            std::net::SocketAddr::V4(v) => v,
            _ => return None,
        };
        if !base.ip().is_private()
            || !gateway.is_private()
            || base.ip() == &gateway
            || base.port() == 0
        {
            return None;
        }
        // The external IP must also match the independent STUN observation.
        if observed.is_private()
            || observed.is_loopback()
            || observed.is_link_local()
            || observed.is_multicast()
            || observed.is_broadcast()
            || observed.is_unspecified()
            || observed.octets()[0] == 0
            || observed.octets()[0] >= 240
            || (u32::from(observed) >> 22) == (u32::from(Ipv4Addr::new(100, 64, 0, 0)) >> 22)
        {
            return None;
        }
        let slot = ACTIVE.clone().try_acquire_owned().ok()?;
        let control = UdpSocket::bind(SocketAddrV4::new(*base.ip(), 0))
            .await
            .ok()?;
        #[cfg(target_os = "macos")]
        crate::underlay::bind_interface(&socket2::SockRef::from(&control), (*base.ip()).into())
            .ok()?;
        control.connect((gateway, 5351)).await.ok()?;
        Self::confirmed(data, control, observed, slot).await
    }

    async fn confirmed(
        data: Arc<UdpSocket>,
        control: UdpSocket,
        observed: Ipv4Addr,
        slot: OwnedSemaphorePermit,
    ) -> Option<Self> {
        let internal = data.local_addr().ok()?.port();
        let mut buf = [0; 64];
        if exchange(&control, &[0, 0], &mut buf).await? != 12
            || buf[..4] != [0, 128, 0, 0]
            || buf[8..12] != observed.octets()
        {
            return None;
        }
        let mut lease = Lease {
            control,
            _data: data,
            _slot: slot,
            internal,
            external: 0,
            lifetime: 0,
        };
        lease.renew().await?;
        let endpoint = SocketAddrV4::new(observed, lease.external);
        let cancel = tokio_util::sync::CancellationToken::new();
        let stop = cancel.clone();
        tokio::spawn(async move {
            loop {
                let half = Duration::from_secs(u64::from(lease.lifetime) / 2);
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = tokio::time::sleep(half) => {}
                }
                if lease.renew().await.is_none() {
                    // Allow one missed router response before retiring this lease.
                    tokio::select! {
                        _ = stop.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                    if lease.renew().await.is_none() {
                        break;
                    }
                }
            }
            // Hold the bound data port until the router responds or the deadline expires.
            let mut reply = [0; 64];
            let msg = request(lease.internal, 0, 0);
            let _ = exchange(&lease.control, &msg, &mut reply).await;
            lease.external = 0;
        });
        Some(Self { endpoint, cancel })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn sockets() -> (Arc<UdpSocket>, UdpSocket, UdpSocket, OwnedSemaphorePermit) {
        let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let control = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        control.connect(router.local_addr().unwrap()).await.unwrap();
        let data = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let slot = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
        (data, control, router, slot)
    }

    async fn address_reply(router: &UdpSocket, ip: Ipv4Addr) -> std::net::SocketAddr {
        let mut buf = [0; 64];
        let (n, peer) = router.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0, 0]);
        let mut reply = [0, 128, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        reply[8..].copy_from_slice(&ip.octets());
        router.send_to(&reply, peer).await.unwrap();
        peer
    }

    #[tokio::test]
    async fn different_external_address_never_requests_a_mapping() {
        let (data, control, router, slot) = sockets().await;
        let observed = Ipv4Addr::new(1, 1, 1, 1);
        let work = tokio::spawn(Mapping::confirmed(data, control, observed, slot));
        address_reply(&router, Ipv4Addr::new(100, 64, 0, 3)).await;
        assert!(work.await.unwrap().is_none());
        assert!(router.try_recv(&mut [0; 64]).is_err());
    }

    #[tokio::test]
    async fn lease_renews_and_releases_only_its_bound_udp_port() {
        let (data, control, router, slot) = sockets().await;
        let internal = data.local_addr().unwrap().port();
        let observed = Ipv4Addr::new(1, 1, 1, 1);
        let work = tokio::spawn(Mapping::confirmed(data, control, observed, slot));
        let peer = address_reply(&router, observed).await;
        let mut mapping = None;
        let mut work = Some(work);
        for (suggested, duration) in [(0, LIFETIME), (49158, LIFETIME), (0, 0)] {
            let mut buf = [0; 64];
            let (n, from) = timeout(Duration::from_secs(8), router.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(from, peer);
            assert_eq!(&buf[..n], &request(internal, suggested, duration));
            let mut reply = [0, 129, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
            reply[8..10].copy_from_slice(&internal.to_be_bytes());
            if duration != 0 {
                reply[10..12].copy_from_slice(&49158u16.to_be_bytes());
                reply[12..].copy_from_slice(&10u32.to_be_bytes());
            }
            router.send_to(&reply, peer).await.unwrap();
            if let Some(work) = work.take() {
                let live = work.await.unwrap().unwrap();
                assert_eq!(live.endpoint, SocketAddrV4::new(observed, 49158));
                mapping = Some(live);
            } else {
                drop(mapping.take());
            }
        }
    }
}
