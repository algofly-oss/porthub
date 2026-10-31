//! Bounded-cost macOS underlay discovery using getifaddrs and route socket events.
use anyhow::Result;
use futures_util::FutureExt;
use route_manager::AsyncRouteManager;
use std::{
    ffi::CStr,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
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
        if item.ifa_addr.is_null() || item.ifa_name.is_null() {
            continue;
        }
        if item.ifa_flags as i32 & (libc::IFF_UP as i32) == 0 {
            continue;
        }
        // SAFETY: the non-null sockaddr family selects its native layout.
        let ip = match unsafe { (*item.ifa_addr).sa_family as i32 } {
            libc::AF_INET => {
                let address = unsafe {
                    (*(item.ifa_addr.cast::<libc::sockaddr_in>()))
                        .sin_addr
                        .s_addr
                };
                IpAddr::V4(Ipv4Addr::from(u32::from_be(address)))
            }
            libc::AF_INET6 => {
                let address = unsafe {
                    (*(item.ifa_addr.cast::<libc::sockaddr_in6>()))
                        .sin6_addr
                        .s6_addr
                };
                IpAddr::V6(Ipv6Addr::from(address))
            }
            _ => continue,
        };
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
        found.push((rank, SocketAddr::new(ip, 0)));
    }
    Ok(porthub_mesh::underlay::candidates(found))
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
