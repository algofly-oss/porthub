//! Opt-in actual native desktop lifecycle. No enrollment/service/profile reuse.
//! Outer must be a reviewed disposable GitHub-hosted runner with independent
//! adapter/route/resolver baseline+cleanup. Not an approval/readiness override.
use super::{device::Tun, dns};
use anyhow::{ensure, Result};
use route_manager::{AsyncRouteManager, Route};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    authorization: String,
    nonce: String,
    profile: PathBuf,
}
fn guard() -> Result<Spec> {
    ensure!(
        std::env::var("PORTHUB_SPARSE_NATIVE_FIXTURE").as_deref()
            == Ok("reviewed-disposable-desktop-v1"),
        "native desktop fixture not opted in"
    );
    ensure!(
        std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
            && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted"),
        "requires disposable hosted runner, never a user host"
    );
    let path = PathBuf::from(
        std::env::var_os("PORTHUB_SPARSE_NATIVE_SPEC")
            .ok_or_else(|| anyhow::anyhow!("native spec missing"))?,
    );
    let metadata = std::fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 2048,
        "native spec not bounded regular file"
    );
    let raw = std::fs::read(&path)?;
    use sha2::{Digest, Sha256};
    ensure!(
        std::env::var("PORTHUB_SPARSE_NATIVE_SPEC_SHA256")?
            == format!("{:x}", Sha256::digest(&raw)),
        "native spec changed"
    );
    let spec: Spec = serde_json::from_slice(&raw)?;
    ensure!(
        spec.authorization == "reviewed-disposable-desktop-v1"
            && spec.nonce.len() == 32
            && spec
                .nonce
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid native fixture identity"
    );
    ensure!(
        spec.profile.file_name().and_then(|s| s.to_str()) == Some("profile.json")
            && spec.profile.parent() == path.parent(),
        "fixture profile escaped exact spec root"
    );
    let expected = format!("native-lifecycle-{}", spec.nonce);
    ensure!(
        path.parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            == Some(expected.as_str()),
        "fixture root not nonce bound"
    );
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "native utun/resolver test requires disposable runner root"
        );
        let root = std::fs::symlink_metadata(path.parent().unwrap())?;
        ensure!(
            root.uid() == 0 && root.mode() & 0o077 == 0 && !root.file_type().is_symlink(),
            "fixture root not private root-owned"
        );
    }
    #[cfg(windows)]
    {
        let _ = super::windows_state::state_path(&spec.profile, ".fixture-check")?;
    }
    let gate = path.parent().unwrap().join("start.gate");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::read(&gate) {
            Ok(bytes) => {
                ensure!(
                    bytes == spec.nonce.as_bytes(),
                    "native start gate identity changed"
                );
                break;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(spec)
}
async fn open(spec: &Spec, slot: usize, own: Ipv4Addr) -> Result<Tun> {
    let name = format!("ph{}", &spec.nonce[slot * 8..slot * 8 + 8]);
    #[cfg(windows)]
    {
        let profile = if slot == 0 {
            spec.profile.clone()
        } else {
            spec.profile.with_file_name("foreign.json")
        };
        Tun::open_owned(
            &profile,
            &name,
            own,
            &[],
            super::native_ownership::HostAdmission::Sparse,
        )
        .await
    }
    #[cfg(target_os = "macos")]
    {
        Tun::open(&name, own, &[]).await
    }
}
fn rows(routes: &[Route]) -> BTreeSet<String> {
    routes.iter().map(|r| format!("{r:?}")).collect()
}
async fn udp_seen(tun: &Tun, own: Ipv4Addr, target: Ipv4Addr) -> Result<()> {
    timeout(Duration::from_secs(2), async {
        let mut bytes = [0; 2048];
        for _ in 0..64 {
            let n = tun.read(&mut bytes).await?;
            if n >= 28
                && bytes[0] >> 4 == 4
                && bytes[9] == 17
                && bytes[12..16] == own.octets()
                && bytes[16..20] == target.octets()
            {
                return Ok::<_, anyhow::Error>(());
            }
        }
        anyhow::bail!("unexpected native packet volume")
    })
    .await??;
    Ok(())
}
#[tokio::test]
#[ignore = "actual native adapter/routes/resolver; ONLY reviewed disposable hosted runner outer"]
async fn native_interface_resolver_collision_connected_owner_and_drop() -> Result<()> {
    let spec = guard()?;
    let mut manager = AsyncRouteManager::new()?;
    let baseline = rows(&manager.list().await?);
    let own = Ipv4Addr::new(10, 254, 253, 1);
    let remote = Ipv4Addr::new(10, 254, 254, 2);
    let suffix = format!("s{}.phub", spec.nonce);
    let next_suffix = format!("t{}.phub", spec.nonce);
    #[cfg(target_os = "macos")]
    for s in [&suffix, &next_suffix] {
        ensure!(
            !Path::new("/etc/resolver").join(s).exists(),
            "foreign resolver already uses fixture suffix"
        );
    }
    let cancel = CancellationToken::new();
    let mut dns_task = None;
    let mut socket_task = None;
    let mut registration = None;
    let mut source = None;
    let mut foreign = None;
    let mut sentinel = None;
    let mut indices = Vec::new();
    let mut source_name = String::new();
    let result=timeout(Duration::from_secs(45),async {
        let tun=Arc::new(open(&spec,0,own).await?);source_name=tun.name.clone();indices.push(tun.index);source=Some(tun.clone());
        let pools=["10.254.253.0/24".parse()?,"10.254.254.0/24".parse()?];
        let audit=tun.reconcile_sparse(&pools,&[remote]).await?;
        ensure!(audit.capture.accepted.len()==2&&audit.capture.conflicting.is_empty()&&audit.accepted_peers==vec![remote],"native prefixes/peer were not admitted");
        for target in [Ipv4Addr::new(10,254,253,99),Ipv4Addr::new(10,254,254,99)]{
            let socket=tokio::net::UdpSocket::bind((own,0)).await?;socket.connect((target,9001)).await?;socket.send(b"native-probe").await?;udp_seen(&tun,own,target).await?;
        }
        let server=dns::Server::bind(own).await?;let port=server.port()?;let zone=server.zone.clone();
        zone.write().await.update(&snapshot(own,remote,&suffix)?)?;dns_task=Some(tokio::spawn(server.serve(cancel.child_token())));
        dns::replace_registration(&mut registration,&spec.profile,tun.index,own,port,&[suffix.clone()]).await?;
        let answer=timeout(Duration::from_secs(8),tokio::net::lookup_host((format!("peer.{suffix}"),443))).await??;
        ensure!(answer.into_iter().any(|s|s.ip()==IpAddr::V4(remote)),"actual system resolver did not use owned namespace");
        zone.write().await.update(&snapshot(own,remote,&next_suffix)?)?;
        dns::replace_registration(&mut registration,&spec.profile,tun.index,own,port,&[next_suffix.clone()]).await?;
        let answer=timeout(Duration::from_secs(8),tokio::net::lookup_host((format!("peer.{next_suffix}"),443))).await??;
        ensure!(answer.into_iter().any(|s|s.ip()==IpAddr::V4(remote)),"dynamic custom suffix not registered with actual OS resolver");
        // Own a real connected native socket in an explicit task, then prove its
        // cancellation releases the exact endpoint. No unrelated app is closed.
        let socket=tokio::net::UdpSocket::bind((own,0)).await?;socket.connect((remote,9000)).await?;let endpoint=socket.local_addr()?;
        let close=cancel.child_token();let closed=close.clone();socket_task=Some(tokio::spawn(async move{closed.cancelled().await;drop(socket);}));
        close.cancel();timeout(Duration::from_secs(2),socket_task.take().unwrap()).await??;
        let rebound=tokio::net::UdpSocket::bind(endpoint).await?;drop(rebound);
        let other=Arc::new(open(&spec,1,Ipv4Addr::new(10,254,252,10)).await?);indices.push(other.index);foreign=Some(other.clone());
        let route=Route::new(IpAddr::V4(Ipv4Addr::new(10,254,254,0)),25).with_if_index(other.index);
        #[cfg(windows)]let route=route.with_metric(77);
        manager.add(&route).await?;sentinel=Some(route.clone());
        let audit=tun.reconcile_sparse(&pools,&[remote]).await?;
        ensure!(audit.capture.conflicting.contains(&pools[1])&&!audit.accepted_peers.contains(&remote),"changed native LAN/VPN overlap retained capture/peer");
        ensure!(manager.list().await?.iter().any(|r|r.destination()==route.destination()&&r.prefix()==route.prefix()&&r.if_index()==route.if_index()),"foreign sentinel route changed");
        let listener=tokio::net::TcpListener::bind((own,0)).await?;
        let (connected,accepted)=tokio::join!(tokio::net::TcpStream::connect(listener.local_addr()?),listener.accept());
        let connected=connected?;let(mut accepted,_)=accepted?;
        let tcp_owner=CancellationToken::new();let closed=tcp_owner.clone();
        let task=tokio::spawn(async move{closed.cancelled().await;drop(connected);});
        tcp_owner.cancel();timeout(Duration::from_secs(2),task).await??;
        use tokio::io::AsyncReadExt;let mut byte=[0;1];
        ensure!(timeout(Duration::from_secs(2),accepted.read(&mut byte)).await??==0,"fixture-owned native TCP socket did not close");
        drop(accepted);drop(listener);
        println!("native_aggregate_capture=true actual_system_dns=true dynamic_suffix=true foreign_collision_withdrawal=true connected_fixture_socket_closed=true owned_tcp_closed=true");
        Ok::<_,anyhow::Error>(())
    }).await;
    // Independent native cleanup executes after body error/timeout as well.
    cancel.cancel();
    if let Some(task) = socket_task.take() {
        task.abort();
        let _ = task.await;
    }
    let dns_cleanup = dns::shutdown_registration(&mut registration).await;
    let dns_join = if let Some(mut task) = dns_task.take() {
        match timeout(Duration::from_secs(3), &mut task).await {
            Ok(joined) => joined.map_err(anyhow::Error::from).and_then(|r| r),
            Err(error) => {
                task.abort();
                let _ = task.await;
                Err(anyhow::Error::from(error))
            }
        }
    } else {
        Ok(())
    };
    let sentinel_cleanup = if let Some(route) = sentinel.take() {
        manager.delete(&route).await.map_err(anyhow::Error::from)
    } else {
        Ok(())
    };
    drop(source);
    drop(foreign);
    let cleanup = timeout(Duration::from_secs(5), async {
        loop {
            let native = manager.list().await?;
            let addresses = getifaddrs::getifaddrs()?
                .filter(|a| indices.contains(&a.index.unwrap_or(0)))
                .any(|a| {
                    a.address
                        .ip_addr()
                        .is_some_and(|ip| matches!(ip,IpAddr::V4(ip) if ip.octets()[..2]==[10,254]))
                });
            let owned_routes = native.iter().any(|r| {
                r.if_index().is_some_and(|i| indices.contains(&i))
                    && matches!(r.destination(),IpAddr::V4(ip) if ip.octets()[..2]==[10,254])
            });
            if !addresses && !owned_routes {
                ensure!(
                    baseline.is_subset(&rows(&native)),
                    "preexisting foreign routes changed"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    #[cfg(target_os = "macos")]
    let resolver_absent = [&suffix, &next_suffix]
        .iter()
        .all(|s| !Path::new("/etc/resolver").join(s).exists());
    #[cfg(windows)]
    let resolver_absent = dns_cleanup.is_ok(); // outer independently queries exact NRPT IDs/namespace.
    println!("native_owned_routes_addresses_retired={} native_owned_resolver_retired={} adapter_name_recorded={}",cleanup.as_ref().is_ok_and(|r|r.is_ok()),resolver_absent,!source_name.is_empty());
    let native_cleanup = dns_cleanup
        .and(dns_join)
        .and(sentinel_cleanup)
        .and(cleanup.map_err(anyhow::Error::from).and_then(|r| r))
        .and(if resolver_absent {
            Ok(())
        } else {
            Err(anyhow::anyhow!("owned resolver remained after teardown"))
        });
    match (
        result.map_err(anyhow::Error::from).and_then(|r| r),
        native_cleanup,
    ) {
        (Err(body), Err(cleanup)) => {
            Err(body.context(format!("native cleanup also failed: {cleanup}")))
        }
        (Err(body), _) => Err(body),
        (_, Err(cleanup)) => Err(cleanup),
        _ => Ok(()),
    }
}

fn snapshot(
    own: Ipv4Addr,
    remote: Ipv4Addr,
    suffix: &str,
) -> Result<porthub_network::policy::Snapshot> {
    Ok(serde_json::from_value(
        serde_json::json!({"workspace":"native-fixture","self":"self","revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(60),"peers":[{"id":"self","ip":own,"fingerprint":"fixture","instance":"fixture","hostname":format!("owner.{suffix}")},{"id":"peer","ip":remote,"fingerprint":"peer","instance":"peer","hostname":format!("peer.{suffix}")}],"grants":[]}),
    )?)
}

#[test]
fn native_fixture_snapshot_is_typed_and_updates_actual_zone() -> Result<()> {
    let own = Ipv4Addr::new(10, 254, 253, 1);
    let remote = Ipv4Addr::new(10, 254, 254, 2);
    let first = snapshot(own, remote, "first-fixture.phub")?;
    let second = snapshot(own, remote, "second-fixture.phub")?;
    let mut zone = dns::Zone::default();
    zone.update(&first)?;
    zone.update(&second)?;
    ensure!(
        first.peers[0].instance == "fixture" && second.peers[1].ip == remote,
        "fixture lost identity metadata"
    );
    Ok(())
}
