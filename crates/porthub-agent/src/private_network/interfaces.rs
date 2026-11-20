//! Kernel-driven underlay discovery. Updates only affect future negotiations;
//! established sessions retain their bound sockets until transport failure.
use anyhow::Result;
use futures_util::StreamExt;
use nlink::netlink::{Connection, Route, RtnetlinkGroup};
use std::{collections::HashMap, net::SocketAddr, time::Duration};
use tokio::{
    sync::watch,
    time::{Instant, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;

pub(crate) async fn current() -> Result<Vec<SocketAddr>> {
    let netlink = Connection::<Route>::new()?;
    let links = netlink.get_links().await?;
    let default = netlink
        .get_routes()
        .await?
        .iter()
        .filter(|route| route.is_ipv4() && route.table_id() == 254 && route.dst_len() == 0)
        .min_by_key(|route| route.priority().unwrap_or(0))
        .and_then(|route| route.oif());
    let preference: HashMap<_, _> = links
        .iter()
        .filter(|link| {
            let name = link.name().unwrap_or("");
            link.is_up()
                && !porthub_mesh::underlay::overlay_interface(name, link.kind().unwrap_or(""))
                && ![
                    "lo", "ph", "docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "lxc",
                ]
                .iter()
                .any(|prefix| name.starts_with(prefix))
        })
        .map(|link| {
            let name = link.name().unwrap_or("");
            let rank = if ["en", "eth", "wl"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
            {
                0
            } else {
                1
            };
            (
                link.ifindex(),
                if Some(link.ifindex()) == default {
                    0
                } else {
                    rank + 1
                },
            )
        })
        .collect();
    let interfaces: Vec<_> = netlink
        .get_addresses()
        .await?
        .iter()
        // A link created between the two dumps is unknown until the next
        // refresh. Never accidentally advertise a newly created overlay TUN.
        .filter(|address| {
            preference.contains_key(&address.ifindex())
                && !address.is_tentative()
                && !address.is_dad_failed()
                && !address.is_deprecated()
        })
        .filter_map(|address| {
            let ip = *address.local().or(address.address())?;
            Some((
                preference.get(&address.ifindex()).copied().unwrap_or(1),
                SocketAddr::new(ip, 0),
            ))
        })
        .collect();
    Ok(porthub_mesh::underlay::candidates(interfaces))
}

pub(crate) async fn watch(output:watch::Sender<Vec<SocketAddr>>,cancel:CancellationToken)->Result<()>{watch_with_routes(output,None,cancel).await}
pub(crate) async fn watch_with_routes(
    output: watch::Sender<Vec<SocketAddr>>,
    route_changes:Option<watch::Sender<u64>>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut backoff = Duration::from_secs(1);
    loop {
        let subscription = (|| {
            let connection = Connection::<Route>::new()?;
            connection.subscribe(&[
                RtnetlinkGroup::Link,
                RtnetlinkGroup::Ipv4Addr,
                RtnetlinkGroup::Ipv4Route,
                RtnetlinkGroup::Ipv6Addr,
                RtnetlinkGroup::Ipv6Route,
            ])?;
            Ok::<_, nlink::Error>(connection)
        })();
        if let Ok(connection) = subscription {
            let mut events = connection.into_events().await;
            // Subscribe before the first snapshot, then occasionally resync in
            // case the kernel reports a buffer overflow or drops an event.
            let mut resync = tokio::time::interval(Duration::from_secs(120));
            resync.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let mut deadline = None;
            loop {
                let refresh = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    _ = output.closed() => return Ok(()),
                    event = events.next() => match event {
                        Some(Ok(_)) => {
                            deadline.get_or_insert(Instant::now() + Duration::from_millis(250));
                            false
                        }
                        Some(Err(_)) | None => break,
                    },
                    _ = resync.tick() => true,
                    _ = async {
                        match deadline {
                            Some(at) => tokio::time::sleep_until(at).await,
                            None => std::future::pending().await,
                        }
                    } => true,
                };
                if refresh {
                    deadline = None;
                    let result = tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        result = tokio::time::timeout(Duration::from_secs(2), current()) => result,
                    };
                    if let Ok(Ok(addresses)) = result {
                        backoff = Duration::from_secs(1);
                        super::topology::publish(&output,route_changes.as_ref(),Some(addresses));
                    }else{super::topology::publish(&output,route_changes.as_ref(),None);}
                }
            }
        }
        // Failed subscriptions never spin or stop a healthy packet owner.
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = output.closed() => return Ok(()),
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn kernel_monitor_publishes_a_bounded_snapshot_and_releases_its_subscription(
    ) -> Result<()> {
        // This sentinel is excluded from discovery even on an offline host,
        // so the first subscribed snapshot must replace it.
        let (output, mut input) = watch::channel(vec!["127.0.0.1:1".parse()?]);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(watch(output, cancel.clone()));
        let observed = tokio::time::timeout(Duration::from_secs(5), input.changed()).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), task).await???;
        observed??;
        let snapshot = input.borrow();
        anyhow::ensure!(snapshot.len() <= 16);
        anyhow::ensure!(snapshot
            .iter()
            .all(
                |address| porthub_mesh::underlay::candidate_ip(address.ip()) && address.port() == 0
            ));
        Ok(())
    }

    #[cfg(feature = "netns-tests")]
    #[tokio::test]
    #[ignore = "requires an owned disposable container namespace and NET_ADMIN"]
    async fn kernel_events_refresh_underlay_addresses_and_ignore_owned_overlay_links() -> Result<()>
    {
        use nlink::netlink::link::DummyLink;
        anyhow::ensure!(
            std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1")
                && std::path::Path::new("/.dockerenv").is_file(),
            "owned namespace required"
        );
        let connection = Connection::<Route>::new()?;
        let underlay = "enphverify0";
        let overlays = ["phverify0", "tun0ph1234abcd", "tailscale0", "wt0", "zt01234567"];
        for name in std::iter::once(underlay).chain(overlays) {
            anyhow::ensure!(connection.get_link_by_name(name).await?.is_none());
        }
        let (output, mut input) = watch::channel(vec!["127.0.0.1:1".parse()?]);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(watch(output, cancel.clone()));
        let result = async {
            wait_snapshot(&mut input, &[]).await?;
            connection.add_link(DummyLink::new(underlay)).await?;
            let underlay_index = connection
                .get_link_by_name(underlay)
                .await?
                .ok_or_else(|| anyhow::anyhow!("test interface missing"))?
                .ifindex();
            connection
                .add_address_by_index(underlay_index, "192.0.2.10".parse()?, 32)
                .await?;
            connection.set_link_up(underlay).await?;
            wait_snapshot(&mut input, &["192.0.2.10:0".parse()?]).await?;
            connection
                .del_address_by_index(underlay_index, "192.0.2.10".parse()?, 32)
                .await?;
            connection
                .add_address_by_index(underlay_index, "192.0.2.11".parse()?, 32)
                .await?;
            wait_snapshot(&mut input, &["192.0.2.11:0".parse()?]).await?;
            for (i, overlay) in overlays.into_iter().enumerate() {
                connection.add_link(DummyLink::new(overlay)).await?;
                let index = connection.get_link_by_name(overlay).await?
                    .ok_or_else(|| anyhow::anyhow!("test tunnel missing"))?.ifindex();
                let ip = std::net::Ipv4Addr::new(10, 203, 0, i as u8 + 1);
                connection.add_address_by_index(index, ip.into(), 32).await?;
                connection.set_link_up(overlay).await?;
            }
            anyhow::ensure!(current().await? == vec!["192.0.2.11:0".parse::<SocketAddr>()?],
                "VPN addresses entered the physical candidate list");
            tokio::time::sleep(Duration::from_millis(600)).await;
            anyhow::ensure!(
                !input.has_changed()?,
                "overlay changes were published as underlay changes"
            );
            connection.set_link_down(underlay).await?;
            wait_snapshot(&mut input, &[]).await?;
            anyhow::Ok(())
        }
        .await;
        cancel.cancel();
        let stopped = tokio::time::timeout(Duration::from_secs(1), task).await;
        let _ = connection.del_link_if_exists(underlay).await;
        for overlay in overlays {
            let _ = connection.del_link_if_exists(overlay).await;
        }
        result?;
        stopped???;
        Ok(())
    }

    #[cfg(feature = "netns-tests")]
    #[tokio::test]
    #[ignore = "requires an owned disposable container namespace, NET_ADMIN and WireGuard"]
    async fn a_vpn_route_to_the_gateway_can_carry_relay_traffic_without_becoming_a_direct_candidate() -> Result<()> {
        use nlink::netlink::link::WireguardLink;

        anyhow::ensure!(
            std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1")
                && std::path::Path::new("/.dockerenv").is_file(),
            "owned namespace required"
        );
        let connection = Connection::<Route>::new()?;
        let name = "workmesh0";
        anyhow::ensure!(connection.get_link_by_name(name).await?.is_none());
        connection.add_link(WireguardLink::new(name)).await?;
        let result = async {
            let index = connection.get_link_by_name(name).await?.unwrap().ifindex();
            let source = "192.0.2.44".parse()?;
            connection.add_address_by_index(index, source, 24).await?;
            connection.set_link_up(name).await?;
            let gateway = "192.0.2.1:443".parse()?;
            let settings = crate::outbound::Settings::default();
            let routes = crate::outbound::discover(&settings, &[gateway]).await?;
            anyhow::ensure!(routes.iter().any(|route|
                route.interface == name && route.source == source && route.destination == gateway
            ), "relay lost the kernel-selected VPN route");
            anyhow::ensure!(current().await?.iter().all(|local| local.ip() != source),
                "the VPN source was advertised as a physical peer address");
            anyhow::Ok(())
        }.await;
        connection.del_link_if_exists(name).await?;
        result
    }

    #[cfg(feature = "netns-tests")]
    async fn wait_snapshot(
        input: &mut watch::Receiver<Vec<SocketAddr>>,
        wanted: &[SocketAddr],
    ) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if *input.borrow_and_update() == wanted {
                    return anyhow::Ok(());
                }
                input.changed().await?;
            }
        })
        .await?
    }
}
