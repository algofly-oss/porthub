//! Windows underlay discovery from native adapter state and route notifications.
use anyhow::Result;
use futures_util::FutureExt;
use getifaddrs::{getifaddrs, InterfaceFlags};
use route_manager::AsyncRouteManager;
use std::{net::SocketAddr, time::Duration};
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
        let Some(ip) = interface.address.ip_addr() else {
            continue;
        };
        found.push((rank, SocketAddr::new(ip, 0)));
    }
    Ok(porthub_mesh::underlay::candidates(found))
}

pub(crate) async fn watch(output:watch::Sender<Vec<SocketAddr>>,cancel:CancellationToken)->Result<()>{watch_with_routes(output,None,cancel).await}
pub(crate) async fn watch_with_routes(
    output: watch::Sender<Vec<SocketAddr>>,
    route_changes:Option<watch::Sender<u64>>,
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
        refresh(&output,route_changes.as_ref(), &cancel).await?;
        let mut interval = tokio::time::interval(Duration::from_secs(120));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut changed = super::route_debounce::Debounce::default();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = output.closed() => return Ok(()),
                _ = interval.tick() => changed.notify(tokio::time::Instant::now()),
                event = listener.listen().boxed() => {
                    if event.is_err() { break; }
                    changed.notify(tokio::time::Instant::now());
                }
                _ = changed.wait() => {
                    changed.clear();
                    refresh(&output,route_changes.as_ref(), &cancel).await?;
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
    route_changes:Option<&watch::Sender<u64>>,
    cancel: &CancellationToken,
) -> Result<()> {
    let result = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = tokio::time::timeout(Duration::from_secs(3), current()) => result,
    };
    if let Ok(Ok(addresses)) = result {
        super::topology::publish(output,route_changes,Some(addresses));
    }else{super::topology::publish(output,route_changes,None);}
    Ok(())
}
