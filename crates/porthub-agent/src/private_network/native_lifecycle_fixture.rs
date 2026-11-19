//! Ignored native Linux contract. Execute ONLY in the reviewed, read-only
//! chroot of a disposable --network=none container. No host execution is allowed.
use super::device::Tun;
use anyhow::{ensure, Context, Result};
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
    let mut state_fs=std::mem::MaybeUninit::<libc::statfs>::uninit();
    ensure!(unsafe{libc::statfs(c"/state".as_ptr(),state_fs.as_mut_ptr())}==0,"cannot inspect private fixture state");
    let state_fs=unsafe{state_fs.assume_init()};
    let state=std::fs::symlink_metadata("/state")?;
    ensure!(state.is_dir()&&!state.file_type().is_symlink()&&state.uid()==0&&state.mode()&0o777==0o700
        &&state_fs.f_type==libc::TMPFS_MAGIC&&state_fs.f_blocks as u64*state_fs.f_bsize as u64==1048576,
        "fixture state must be exact private 1MiB tmpfs");
    let mut state_vfs=std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(unsafe{libc::statvfs(c"/state".as_ptr(),state_vfs.as_mut_ptr())}==0,"cannot inspect state flags");
    let flags=unsafe{state_vfs.assume_init()}.f_flag;
    ensure!(flags&(libc::ST_NODEV|libc::ST_NOSUID|libc::ST_NOEXEC)==libc::ST_NODEV|libc::ST_NOSUID|libc::ST_NOEXEC
        &&flags&libc::ST_RDONLY==0,"fixture state mount restrictions changed");
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
    // Metadata-only causal witness before the production open strips errno.
    // Never create a node, load a module or relax cgroup/device permissions.
    use std::os::unix::fs::{FileTypeExt,OpenOptionsExt};
    let device=std::fs::symlink_metadata("/dev/net/tun")?;
    println!("fixture_tun_char={} fixture_tun_major={} fixture_tun_minor={}",device.file_type().is_char_device(),libc::major(device.rdev()),libc::minor(device.rdev()));
    ensure!(device.file_type().is_char_device()&&libc::major(device.rdev())==10&&libc::minor(device.rdev())==200,"fixture /dev/net/tun is not the exact existing TUN character device");
    match std::fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_CLOEXEC|libc::O_NOFOLLOW|libc::O_NONBLOCK).open("/dev/net/tun"){
        Ok(probe)=>drop(probe),Err(error)=>{println!("fixture_tun_open_errno={:?}",error.raw_os_error());return Err(error.into());}
    }
    let source_name = format!("ph{}", &spec.nonce[..8]);
    let foreign_name = format!("ph{}", &spec.nonce[8..16]);
    ensure!(source_name != foreign_name, "fixture names collide");
    let names = [source_name.clone(), foreign_name.clone()];
    let own = Ipv4Addr::new(10, 254, 253, 1);
    let remote = Ipv4Addr::new(10, 254, 254, 2);
    let foreign_own = Ipv4Addr::new(10, 254, 252, 10);
    let pools = ["10.254.253.0/24".parse()?, "10.254.254.0/24".parse()?];
    let profile=std::path::Path::new("/state/profile.json");
    crate::profile::write_private(profile,br#"{"server":"https://fixture.invalid","workspace":"private-native-fixture","peer_id":"private-native-fixture"}"#,false)?;
    let mut source = None;
    let mut foreign = None;
    let result=timeout(Duration::from_secs(12),async{
        source=Some(super::native_owner::open(profile,&source_name,own,&pools,&[]).await?);
        let audit=match super::native_owner::reconcile(&mut source,profile,own,&pools,&[remote]).await?{
            super::native_owner::Outcome::Active(audit)=>audit,super::native_owner::Outcome::Retired(_)=>anyhow::bail!("clean owner retired")};
        let tun=source.as_ref().unwrap();
        let link = connection.get_link_by_index(tun.index).await?.context("owned TUN missing")?;
        ensure!(link.txqlen() == Some(4096), "owned TUN transmit queue was not configured");
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
        let audit=match super::native_owner::reconcile(&mut source,profile,own,&pools,&[remote]).await?{
            super::native_owner::Outcome::Retired(audit)=>audit,super::native_owner::Outcome::Active(_)=>anyhow::bail!("conflicting native owner was not retired")};
        ensure!(source.is_none(),"production native owner remains open");
        ensure!(super::native_owner::open(profile,&source_name,own,&pools,&[]).await.is_err(),"quarantined source was reopened");
        ensure!(connection.get_link_by_name(&source_name).await?.is_none(),"native source interface/address survived retirement");
        ensure!(audit.capture.conflicting.contains(&pools[1])&&!audit.accepted_peers.contains(&remote),"fresh LAN conflict retained private capture/peer authority");
        let native=connection.get_routes().await?;
        ensure!(native.iter().any(|row|row.destination()==Some(&IpAddr::V4(Ipv4Addr::new(10,254,254,0)))&&row.dst_len()==24&&row.oif()==Some(other.index)&&row.priority()==Some(7)),"foreign sentinel route was removed or adopted");
        // A route-table-only success is insufficient: a previously connected
        // private socket must not silently emit its next datagram on that LAN.
        let send=socket.send(b"private-native-after").await;
        let escaped=udp_seen(&other,own,remote,Duration::from_millis(250)).await?;
        println!("native_capture_before=true conflict_detected=true foreign_route_preserved=true connected_send_succeeded={} foreign_egress_after_withdrawal={}",send.is_ok(),escaped);
        ensure!(!escaped,"connected private socket escaped via foreign route after capture withdrawal; native fail-closed contract remains OPEN");
        let repair=super::native_owner::repair_request(profile)?.ok_or_else(||anyhow::anyhow!("native conflict feedback was not durable"))?;
        ensure!(repair.source==own&&repair.blocked==vec![pools[1]],"repair feedback lost exact conflicted source/prefix");
        // A new validated allocation may reopen the same owned interface name.
        // This native fixture supplies the allocation explicitly; the separate
        // real HTTP/Mongo test proves the allocator/journal half of this path.
        let next_own=Ipv4Addr::new(10,254,251,1);let next_remote=Ipv4Addr::new(10,254,250,2);
        let next_pools=["10.254.251.0/24".parse()?,"10.254.250.0/24".parse()?];
        source=Some(super::native_owner::open(profile,&source_name,next_own,&next_pools,&[]).await?);
        ensure!(matches!(super::native_owner::reconcile(&mut source,profile,next_own,&next_pools,&[next_remote]).await?,super::native_owner::Outcome::Active(_)),"fresh allocation failed native reopening");
        ensure!(super::native_owner::repair_request(profile)?.is_none(),"completed new allocation retained stale repair feedback");
        let next_socket=tokio::net::UdpSocket::bind((next_own,0)).await?;next_socket.connect((next_remote,9002)).await?;next_socket.send(b"private-native-reallocated").await?;
        ensure!(udp_seen(source.as_ref().unwrap(),next_own,next_remote,Duration::from_secs(1)).await?,"new allocation did not restore actual native capture");
        let old_send=socket.send(b"private-native-old-after-reallocation").await;
        let old_escaped=udp_seen(&other,own,remote,Duration::from_millis(250)).await?;
        ensure!(!old_escaped,"old connected private socket escaped after native reallocation");
        println!("native_new_allocation_capture=true old_source_quarantined=true old_socket_send_after_reallocation={} foreign_egress_after_reallocation={}",old_send.is_ok(),old_escaped);
        drop(next_socket);drop(socket);drop(other);Ok::<_,anyhow::Error>(())
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
