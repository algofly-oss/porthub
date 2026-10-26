//! Kernel-driven underlay discovery. Updates only affect future negotiations;
//! established sessions retain their bound sockets until transport failure.
use anyhow::Result;
use futures_util::StreamExt;
use nlink::netlink::{Connection, Route, RtnetlinkGroup};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    sync::watch,
    time::{Instant, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;

pub(super) async fn current() -> Result<Vec<SocketAddr>> {
    let netlink = Connection::<Route>::new()?;
    let links = netlink.get_links().await?;
    let default = netlink.get_routes().await?.iter()
        .filter(|route| route.is_ipv4() && route.table_id() == 254 && route.dst_len() == 0)
        .min_by_key(|route| route.priority().unwrap_or(0)).and_then(|route| route.oif());
    let preference: HashMap<_, _> = links
        .iter()
        .filter(|link| {
            let name = link.name().unwrap_or("");
            link.is_up()
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
            } else if ["zt", "wg", "tun", "tap", "tailscale"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
            {
                2
            } else {
                1
            };
            (link.ifindex(), if Some(link.ifindex()) == default { 0 } else { rank + 1 })
        })
        .collect();
    let mut interfaces: Vec<_> = netlink
        .get_addresses()
        .await?
        .iter()
        // A link created between the two dumps is unknown until the next
        // refresh. Never accidentally advertise a newly created overlay TUN.
        .filter(|address| preference.contains_key(&address.ifindex()))
        .filter_map(|address| match address.local().or(address.address()) {
            Some(IpAddr::V4(ip))
                if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() =>
            {
                Some((
                    preference.get(&address.ifindex()).copied().unwrap_or(1),
                    SocketAddr::new(IpAddr::V4(*ip), 0),
                ))
            }
            _ => None,
        })
        .collect();
    interfaces.sort();
    let mut unique = HashSet::new();
    interfaces.retain(|(_, address)| unique.insert(*address));
    interfaces.truncate(16);
    Ok(interfaces.into_iter().map(|(_, address)| address).collect())
}

pub(super) async fn watch(
    output: watch::Sender<Vec<SocketAddr>>,
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
                        output.send_if_modified(|previous| {
                            if *previous == addresses {
                                return false;
                            }
                            *previous = addresses;
                            true
                        });
                    }
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
        anyhow::ensure!(snapshot.iter().all(|address| address.is_ipv4()
            && !address.ip().is_loopback()
            && !address.ip().is_unspecified()
            && address.port() == 0));
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
        let overlay = "phverify0";
        anyhow::ensure!(
            connection.get_link_by_name(underlay).await?.is_none()
                && connection.get_link_by_name(overlay).await?.is_none()
        );
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
            connection.add_link(DummyLink::new(overlay)).await?;
            let overlay_index = connection
                .get_link_by_name(overlay)
                .await?
                .ok_or_else(|| anyhow::anyhow!("test overlay missing"))?
                .ifindex();
            connection
                .add_address_by_index(overlay_index, "10.203.251.1".parse()?, 32)
                .await?;
            connection.set_link_up(overlay).await?;
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
        let _ = connection.del_link_if_exists(overlay).await;
        result?;
        stopped???;
        Ok(())
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
