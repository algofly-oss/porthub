//! Opt-in physical macOS regression for the same-interface handoff.
use super::Tun;
use crate::private_network::native_owner;
use anyhow::{ensure, Context, Result};
use porthub_mesh::lan_routes::Network;
use std::{
    net::{IpAddr, Ipv4Addr, UdpSocket},
    os::fd::{AsRawFd, RawFd},
    time::Duration,
};

async fn wait_for_queued_marker(fd: RawFd, marker: &[u8]) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut bytes = [0; 2048];
        loop {
            let size = unsafe {
                libc::recv(
                    fd,
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT | libc::MSG_PEEK,
                )
            };
            if size > 0 {
                ensure!(
                    bytes[..size as usize].ends_with(marker),
                    "unexpected datagram at the isolated utun"
                );
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            ensure!(
                size < 0 && error.kind() == std::io::ErrorKind::WouldBlock,
                "could not identify kernel receive backlog: {error}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?
}

#[tokio::test]
#[ignore = "requires root on an explicitly selected physical Mac"]
async fn same_utun_rearms_with_a_fresh_owner_and_two_empty_queue_boundaries() -> Result<()> {
    ensure!(
        std::env::var("PORTHUB_VERIFY_PHYSICAL_RETRY_READER").as_deref() == Ok("isolated-utun")
            && unsafe { libc::geteuid() } == 0,
        "explicit privileged utun test required"
    );
    let id = uuid::Uuid::new_v4();
    let bytes = id.as_bytes();
    let mut assignment = None;
    for (first, second, third) in [
        (172, 28, bytes[0]),
        (10, 253, bytes[1]),
        (192, 168, bytes[2]),
    ] {
        let own = Ipv4Addr::new(first, second, third, 201);
        let peer = Ipv4Addr::new(first, second, third, 202);
        let pools = [Network::from_address(own, 29)?];
        if Tun::preflight_sparse(own, &pools, &[peer]).await.is_ok() {
            assignment = Some((own, peer, pools));
            break;
        }
    }
    let (own, peer, pools) = assignment.context("no conflict-free isolated fixture prefix")?;
    let scratch = tempfile::tempdir()?;
    let profile = scratch.path().join("private.json");
    let enrollment = serde_json::json!({"server":"https://utun.test.invalid","workspace": id, "peer_id":format!("native-{id}")});
    crate::profile::write_private(&profile, &serde_json::to_vec(&enrollment)?, false)?;
    let tun = native_owner::open(&profile, "utun-rearm-test", own, &pools, &[peer]).await?;
    let original = (
        tun.name.clone(),
        tun.index,
        tun.packet_loop().test_generation(),
    );
    let fd = tun.device.as_raw_fd();
    let socket = UdpSocket::bind((own, 0))?;
    let destination = (peer, 39468);
    let mut bytes = [0; 2048];

    socket.send_to(b"prior-worker", destination)?;
    wait_for_queued_marker(fd, b"prior-worker").await?;
    let source = tun
        .retry_source()
        .context("original native owner unavailable")?;
    drop(tun);
    let reader = source.open()?;
    socket.send_to(b"fresh-recovery-worker", destination)?;
    let size = tokio::time::timeout(Duration::from_secs(3), reader.read(&mut bytes)).await??;
    ensure!(
        bytes[..size].ends_with(b"fresh-recovery-worker"),
        "prior worker datagram survived"
    );

    socket.send_to(b"prior-admission", destination)?;
    wait_for_queued_marker(fd, b"prior-admission").await?;
    let (resumed, _) = native_owner::open_with_dns(
        &profile,
        "utun-rearm-test",
        own,
        &pools,
        &[peer],
        Some(reader),
    )
    .await?;
    ensure!(
        resumed.name == original.0 && resumed.index == original.1 && resumed.has_source_lease()?,
        "kernel interface or source lease changed"
    );
    ensure!(
        resumed.packet_loop().test_generation() != original.2,
        "prior packet-loop owner survived"
    );
    socket.send_to(b"fresh-admission", destination)?;
    let size = tokio::time::timeout(Duration::from_secs(3), resumed.read(&mut bytes)).await??;
    ensure!(
        bytes[..size].ends_with(b"fresh-admission"),
        "pre-admission datagram survived"
    );

    drop(resumed);
    drop(socket);
    ensure!(
        !getifaddrs::getifaddrs()?.any(|row| row.address.ip_addr() == Some(IpAddr::V4(own))),
        "fixture source address survived"
    );
    let mut routes = route_manager::AsyncRouteManager::new()?;
    ensure!(
        !routes
            .list()
            .await?
            .iter()
            .any(|route| route.if_index() == Some(original.1)
                && ((route.destination() == IpAddr::V4(peer) && route.prefix() == 32)
                    || (route.destination() == IpAddr::V4(pools[0].address())
                        && route.prefix() == pools[0].prefix()))),
        "fixture peer or capture route survived"
    );
    Ok(())
}
