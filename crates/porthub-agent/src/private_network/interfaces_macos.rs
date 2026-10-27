//! Bounded-cost macOS underlay discovery using getifaddrs and route socket events.
use anyhow::Result;
use futures_util::FutureExt;
use route_manager::AsyncRouteManager;
use std::{
    collections::HashSet,
    ffi::CStr,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{sync::watch, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;

pub(crate) async fn current() -> Result<Vec<SocketAddr>> {
    let mut head = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes head, and the list is freed below.
    anyhow::ensure!(
        unsafe { libc::getifaddrs(&mut head) } == 0,
        "cannot inspect macOS interfaces"
    );
    struct Guard(*mut libc::ifaddrs);
    impl Drop for Guard {
        fn drop(&mut self) {
            // SAFETY: head came from getifaddrs exactly once.
            unsafe { libc::freeifaddrs(self.0) }
        }
    }
    let _guard = Guard(head);
    let mut found = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: cursor is a node in the live getifaddrs list.
        let item = unsafe { &*cursor };
        cursor = item.ifa_next;
        if item.ifa_addr.is_null()
            || item.ifa_name.is_null()
            // SAFETY: null was rejected above; this field is common to sockaddr.
            || unsafe { (*item.ifa_addr).sa_family as i32 } != libc::AF_INET
        {
            continue;
        }
        if item.ifa_flags as i32 & (libc::IFF_UP as i32) == 0 {
            continue;
        }
        // SAFETY: AF_INET guarantees sockaddr_in layout.
        let address = unsafe {
            (*(item.ifa_addr.cast::<libc::sockaddr_in>()))
                .sin_addr
                .s_addr
        };
        let ip = Ipv4Addr::from(u32::from_be(address));
        if ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || ip.is_multicast() {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated interface name from getifaddrs.
        let name = unsafe { CStr::from_ptr(item.ifa_name) }.to_string_lossy();
        if ["lo", "utun", "bridge", "awdl", "llw", "gif", "stf", "ph"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            continue;
        }
        let rank = if ["en", "eth", "wl"].iter().any(|p| name.starts_with(p)) {
            0
        } else {
            1
        };
        found.push((rank, SocketAddr::new(IpAddr::V4(ip), 0)));
    }
    found.sort();
    let mut unique = HashSet::new();
    found.retain(|(_, address)| unique.insert(*address));
    found.truncate(16);
    Ok(found.into_iter().map(|(_, address)| address).collect())
}

pub(super) async fn watch(
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
        let snapshot = tokio::time::timeout(Duration::from_secs(2), current()).await;
        if let Ok(Ok(addresses)) = snapshot {
            output.send_if_modified(|previous| {
                if *previous == addresses {
                    return false;
                }
                *previous = addresses;
                true
            });
        }
        let mut refresh = tokio::time::interval(Duration::from_secs(120));
        refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut changed = false;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = output.closed() => return Ok(()),
                _ = refresh.tick() => changed = true,
                event = listener.listen().boxed() => {
                    if event.is_err() { break; }
                    changed = true;
                }
                _ = async { if changed { tokio::time::sleep(Duration::from_millis(250)).await } else { std::future::pending::<()>().await } } => {
                    changed = false;
                    if let Ok(Ok(addresses)) = tokio::time::timeout(Duration::from_secs(2), current()).await {
                        output.send_if_modified(|previous| {
                            if *previous == addresses { return false; }
                            *previous = addresses;
                            true
                        });
                    }
                    backoff = Duration::from_secs(1);
                }
            }
        }
        tokio::select! { _ = cancel.cancelled() => return Ok(()), _ = tokio::time::sleep(backoff) => {} }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}
