//! Ignored native Linux contract. Execute ONLY in the reviewed, read-only
//! chroot of a disposable --network=none container. No host execution is allowed.
use super::device::Tun;
use anyhow::{ensure, Result};
use nlink::netlink::{route::Ipv4Route, types::route::RouteScope, Connection, Route};
use serde::Deserialize;
use std::{
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::MetadataExt,
    sync::Arc,
};
use tokio::time::{timeout, Duration};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    authorization: String,
    nonce: String,
    parent_netns_inode: u64,
}
fn guard() -> Result<Spec> {
    ensure!(
        std::env::var("PORTHUB_SPARSE_NATIVE_FIXTURE").as_deref()
            == Ok("reviewed-disposable-netns-v1"),
        "native fixture not authorized"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "native fixture requires disposable namespace root"
    );
    let path = std::path::Path::new("/spec.json");
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.nlink() == 1
            && meta.mode() & 0o022 == 0
            && meta.len() <= 2048,
        "invalid native fixture specification"
    );
    let raw = std::fs::read(path)?;
    let expected = std::env::var("PORTHUB_SPARSE_NATIVE_SPEC_SHA256")?;
    use sha2::{Digest, Sha256};
    ensure!(
        expected.len() == 64 && format!("{:x}", Sha256::digest(&raw)) == expected,
        "native fixture specification changed"
    );
    let spec: Spec = serde_json::from_slice(&raw)?;
    ensure!(
        spec.authorization == "reviewed-disposable-netns-v1"
            && spec.nonce.len() == 32
            && spec
                .nonce
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid native fixture identity"
    );
    ensure!(
        std::fs::metadata("/proc/self/ns/net")?.ino() != spec.parent_netns_inode,
        "refusing parent/host network namespace"
    );
    let mut vfs = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(c"/".as_ptr(), vfs.as_mut_ptr()) } == 0,
        "cannot inspect fixture filesystem"
    );
    ensure!(
        unsafe { vfs.assume_init() }.f_flag & libc::ST_RDONLY != 0,
        "native fixture root must be read-only"
    );
    Ok(spec)
}
async fn absent(connection: &Connection<Route>, names: &[String]) -> Result<()> {
    timeout(Duration::from_secs(2), async {
        loop {
            let mut any = false;
            for name in names {
                any |= connection.get_link_by_name(name).await?.is_some();
            }
            if !any {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
async fn udp_seen(tun: &Tun, own: Ipv4Addr, remote: Ipv4Addr, bound: Duration) -> Result<bool> {
    match timeout(bound, async {
        let mut bytes = [0u8; 2048];
        for _ in 0..32 {
            let read = tun.read(&mut bytes).await?;
            if read >= 28
                && bytes[0] >> 4 == 4
                && bytes[9] == 17
                && bytes[12..16] == own.octets()
                && bytes[16..20] == remote.octets()
            {
                return Ok::<_, anyhow::Error>(true);
            }
        }
        anyhow::bail!("unexpected packet volume in isolated native fixture")
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Ok(false),
    }
}
#[tokio::test]
#[ignore = "requires Root-reviewed disposable native netns wrapper; NEVER run on a host"]
async fn linux_owned_capture_overlap_withdrawal_connected_socket_and_drop_boundaries() -> Result<()>
{
    let spec = guard()?;
    let connection = Connection::<Route>::new()?;
    let links = connection.get_links().await?;
    ensure!(
        links.len() == 1 && links[0].name() == Some("lo"),
        "fixture namespace is not empty/isolated"
    );
    let source_name = format!("ph{}", &spec.nonce[..8]);
    let foreign_name = format!("ph{}", &spec.nonce[8..16]);
    ensure!(source_name != foreign_name, "fixture names collide");
    let names = [source_name.clone(), foreign_name.clone()];
    let own = Ipv4Addr::new(10, 254, 253, 1);
    let remote = Ipv4Addr::new(10, 254, 254, 2);
    let foreign_own = Ipv4Addr::new(10, 254, 252, 10);
    let pools = ["10.254.253.0/24".parse()?, "10.254.254.0/24".parse()?];
    let mut source = None;
    let mut foreign = None;
    let result=timeout(Duration::from_secs(12),async{
        let tun=Arc::new(Tun::open(&source_name,own,&[]).await?);source=Some(tun.clone());
        let audit=tun.reconcile_sparse(&pools,&[remote]).await?;
        ensure!(audit.capture.conflicting.is_empty()&&audit.capture.accepted.len()==2&&audit.accepted_peers.contains(&remote),"clean private capture not installed");
        // No /32 for these unknown destinations exists: both aggregate
        // prefixes must actually intercept packets before pair discovery.
        for unknown in [Ipv4Addr::new(10,254,253,99),Ipv4Addr::new(10,254,254,99)] {
            let probe=tokio::net::UdpSocket::bind((own,0)).await?;probe.connect((unknown,9001)).await?;probe.send(b"private-native-unknown").await?;
            ensure!(udp_seen(&tun,own,unknown,Duration::from_secs(1)).await?,"unknown raw private IP escaped aggregate capture");
        }
        let socket=tokio::net::UdpSocket::bind((own,0)).await?;socket.connect((remote,9000)).await?;
        socket.send(b"private-native-before").await?;
        ensure!(udp_seen(&tun,own,remote,Duration::from_secs(1)).await?,"actual private UDP did not enter owned TUN");
        let other=Arc::new(Tun::open(&foreign_name,foreign_own,&[]).await?);foreign=Some(other.clone());
        // Simulate an independently configured LAN/VPN route. Product code is
        // deliberately NOT used to preflight/admit this external mutation.
        connection.add_route(Ipv4Route::new(Ipv4Addr::new(10,254,254,0),24).dev_index(other.index).scope(RouteScope::Link).metric(7)).await?;
        let audit=tun.reconcile_sparse(&pools,&[remote]).await?;
        ensure!(audit.capture.conflicting.contains(&pools[1])&&!audit.accepted_peers.contains(&remote),"fresh LAN conflict retained private capture/peer authority");
        let native=connection.get_routes().await?;
        ensure!(native.iter().any(|row|row.destination()==Some(&IpAddr::V4(Ipv4Addr::new(10,254,254,0)))&&row.dst_len()==24&&row.oif()==Some(other.index)&&row.priority()==Some(7)),"foreign sentinel route was removed or adopted");
        // A route-table-only success is insufficient: a previously connected
        // private socket must not silently emit its next datagram on that LAN.
        let send=socket.send(b"private-native-after").await;
        let escaped=udp_seen(&other,own,remote,Duration::from_millis(250)).await?;
        println!("native_capture_before=true conflict_detected=true foreign_route_preserved=true connected_send_succeeded={} foreign_egress_after_withdrawal={}",send.is_ok(),escaped);
        ensure!(!escaped,"connected private socket escaped via foreign route after capture withdrawal; native fail-closed contract remains OPEN");
        drop(socket);drop(tun);drop(other);Ok::<_,anyhow::Error>(())
    }).await;
    drop(source);
    drop(foreign);
    let cleanup = absent(&connection, &names).await;
    println!(
        "native_owned_interfaces_and_routes_absent={}",
        cleanup.is_ok()
    );
    cleanup?;
    result??;
    Ok(())
}
