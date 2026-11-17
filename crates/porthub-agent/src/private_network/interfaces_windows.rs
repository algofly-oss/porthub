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
    watch_inner(output, route_changes, cancel, #[cfg(test)] None).await
}
#[cfg(test)]
pub(crate) async fn watch_witness(
    output: watch::Sender<Vec<SocketAddr>>, route_changes: watch::Sender<u64>,
    cancel: CancellationToken, witness: std::sync::Arc<super::route_debounce::witness::Witness>,
) -> Result<()> { watch_inner(output, Some(route_changes), cancel, Some(witness)).await }
async fn watch_inner(
    output: watch::Sender<Vec<SocketAddr>>, route_changes: Option<watch::Sender<u64>>,
    cancel: CancellationToken,
    #[cfg(test)] witness: Option<std::sync::Arc<super::route_debounce::witness::Witness>>,
) -> Result<()> {
    let mut backoff = Duration::from_secs(1);
    loop {
        let mut listener = match AsyncRouteManager::listener() {
            Ok(listener) => listener,
            Err(error) => {
                #[cfg(test)] if let Some(w)=&witness {w.listener_error(error.raw_os_error());}
                #[cfg(not(test))] let _=error;
                tokio::select! { _ = cancel.cancelled() => return Ok(()), _ = tokio::time::sleep(backoff) => {} }
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        refresh(&output,route_changes.as_ref(), &cancel, #[cfg(test)] witness.as_deref()).await?;
        let mut interval = tokio::time::interval(Duration::from_secs(120));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        #[cfg(test)] if let Some(witness)=&witness { witness.ready(); }
        let mut changed = super::route_debounce::Debounce::default();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = output.closed() => return Ok(()),
                _ = interval.tick() => changed.notify(tokio::time::Instant::now()),
                event = listener.listen().boxed() => {
                    let event = match event { Ok(event) => event, Err(error) => {
                        #[cfg(test)] if let Some(w)=&witness {w.listener_error(error.raw_os_error());}
                        #[cfg(not(test))] let _=error;
                        break
                    } };
                    #[cfg(test)] if let Some(witness)=&witness { witness.event(&event); }
                    #[cfg(not(test))] let _ = event;
                    changed.notify(tokio::time::Instant::now());
                }
                _ = changed.wait() => {
                    changed.clear();
                    let success = refresh(&output,route_changes.as_ref(), &cancel, #[cfg(test)] witness.as_deref()).await?;
                    #[cfg(test)] if success { if let Some(witness)=&witness {
                        if let Some(remaining)=witness.readback_remaining(){
                            witness.readback_started(remaining);
                            let native=async {match AsyncRouteManager::new(){Ok(mut manager)=>manager.list().await,Err(error)=>Err(error)}};
                            match super::route_debounce::witness::bounded_readback(&cancel,remaining,native).await {
                                Ok(Ok(rows))=>witness.published_native(&rows),
                                Ok(Err(error))=>witness.readback_failed(error.raw_os_error()),
                                Err(stop)=>witness.readback_stopped(stop),
                            }
                        }
                    } }
                    #[cfg(not(test))] let _ = success;
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
    #[cfg(test)] witness:Option<&super::route_debounce::witness::Witness>,
) -> Result<bool> {
    #[cfg(test)] if let Some(w)=witness {w.refresh_started(route_changes.map(|r|*r.borrow()));}
    let result = tokio::select! {
        _ = cancel.cancelled() => return Ok(false),
        result = tokio::time::timeout(Duration::from_secs(3), current()) => result,
    };
    #[cfg(test)] let diagnostic=match &result {Ok(Ok(_))=>(true,false,None),Ok(Err(e))=>(false,false,e.chain().find_map(|e|e.downcast_ref::<std::io::Error>().and_then(|e|e.raw_os_error()))),Err(_)=>(false,true,None)};
    if let Ok(Ok(addresses)) = result {
        super::topology::publish(output,route_changes,Some(addresses));
        #[cfg(test)] if let Some(w)=witness {w.refreshed(diagnostic.0,diagnostic.1,diagnostic.2,route_changes.map(|r|*r.borrow()));}
        Ok(true)
    }else{super::topology::publish(output,route_changes,None);
        #[cfg(test)] if let Some(w)=witness {w.refreshed(diagnostic.0,diagnostic.1,diagnostic.2,route_changes.map(|r|*r.borrow()));}
        Ok(false)}
}
