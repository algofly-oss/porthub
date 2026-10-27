//! Windows underlay discovery from native adapter state and route notifications.
use anyhow::Result;
use futures_util::FutureExt;
use getifaddrs::{getifaddrs, InterfaceFlags};
use route_manager::AsyncRouteManager;
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{sync::watch, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;

pub(crate) async fn current() -> Result<Vec<SocketAddr>> {
    let mut found = Vec::new();
    for interface in getifaddrs()? {
        if !interface.flags.contains(InterfaceFlags::UP)
            || interface.flags.contains(InterfaceFlags::LOOPBACK)
            || interface.name.to_ascii_lowercase().starts_with("ph")
            || interface
                .description
                .to_ascii_lowercase()
                .contains("porthub")
            || interface
                .description
                .to_ascii_lowercase()
                .contains("wintun")
        {
            continue;
        }
        let rank = if interface
            .description
            .to_ascii_lowercase()
            .contains("ethernet")
            || interface.description.to_ascii_lowercase().contains("wi-fi")
        {
            0
        } else {
            1
        };
        let Some(IpAddr::V4(ip)) = interface.address.ip_addr() else {
            continue;
        };
        if ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || ip.is_multicast() {
            continue;
        }
        found.push((rank, SocketAddr::new(IpAddr::V4(ip), 0)));
    }
    found.sort();
    let mut unique = HashSet::new();
    found.retain(|(_, address)| unique.insert(*address));
    found.truncate(16);
    Ok(found.into_iter().map(|(_, address)| address).collect())
}

pub(crate) async fn watch(
    output: watch::Sender<Vec<SocketAddr>>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut backoff = Duration::from_secs(1);
    loop {
        let mut listener = match AsyncRouteManager::listener() {
            Ok(listener) => listener,
            Err(_) => {
                tokio::select! { _ = cancel.cancelled() => return Ok(()), _ = tokio::time::sleep(backoff) => {} }
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        refresh(&output, &cancel).await?;
        let mut interval = tokio::time::interval(Duration::from_secs(120));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut changed = false;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = output.closed() => return Ok(()),
                _ = interval.tick() => changed = true,
                event = listener.listen().boxed() => {
                    if event.is_err() { break; }
                    changed = true;
                }
                _ = async { if changed { tokio::time::sleep(Duration::from_millis(250)).await } else { std::future::pending::<()>().await } } => {
                    changed = false;
                    refresh(&output, &cancel).await?;
                    backoff = Duration::from_secs(1);
                }
            }
        }
        tokio::select! { _ = cancel.cancelled() => return Ok(()), _ = tokio::time::sleep(backoff) => {} }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn refresh(
    output: &watch::Sender<Vec<SocketAddr>>,
    cancel: &CancellationToken,
) -> Result<()> {
    let result = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = tokio::time::timeout(Duration::from_secs(3), current()) => result,
    };
    if let Ok(Ok(addresses)) = result {
        output.send_if_modified(|previous| {
            if *previous == addresses {
                return false;
            }
            *previous = addresses;
            true
        });
    }
    Ok(())
}
