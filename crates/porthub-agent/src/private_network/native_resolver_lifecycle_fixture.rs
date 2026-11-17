//! Actual systemd-resolved transaction on a disposable hosted Linux VM.
//! Separate from netns capture fixture: a namespace without resolved is no proof.
use super::{device::Tun, dns};
use anyhow::{ensure, Result};
use std::{
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::Arc,
};
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;
#[tokio::test]
#[ignore = "requires reviewed disposable hosted Linux VM with active resolved; no user host"]
async fn linux_real_resolver_suffix_replace_and_native_owner_teardown() -> Result<()> {
    ensure!(
        std::env::var("PORTHUB_SPARSE_NATIVE_FIXTURE").as_deref()
            == Ok("reviewed-disposable-resolved-v1")
            && std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
            && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted")
            && unsafe { libc::geteuid() } == 0,
        "not an opted-in disposable root runner"
    );
    let spec = PathBuf::from(
        std::env::var_os("PORTHUB_SPARSE_NATIVE_SPEC")
            .ok_or_else(|| anyhow::anyhow!("fixture spec missing"))?,
    );
    let metadata = std::fs::symlink_metadata(&spec)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= 2048,
        "fixture spec not protected/bounded"
    );
    let raw = std::fs::read(&spec)?;
    use sha2::{Digest, Sha256};
    ensure!(
        std::env::var("PORTHUB_SPARSE_NATIVE_SPEC_SHA256")?
            == format!("{:x}", Sha256::digest(&raw)),
        "fixture spec changed"
    );
    let value: serde_json::Value = serde_json::from_slice(&raw)?;
    let nonce = value["nonce"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("nonce missing"))?;
    ensure!(
        value["authorization"] == "reviewed-disposable-resolved-v1"
            && nonce.len() == 32
            && nonce
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "fixture identity invalid"
    );
    let root = spec.parent().unwrap();
    ensure!(
        root.file_name().and_then(|s| s.to_str())
            == Some(format!("native-lifecycle-{nonce}").as_str()),
        "fixture spec root identity mismatch"
    );
    let root_meta = std::fs::symlink_metadata(root)?;
    ensure!(
        root_meta.uid() == 0
            && root_meta.mode() & 0o077 == 0
            && !root_meta.file_type().is_symlink(),
        "fixture root not protected"
    );
    let gate = root.join("start.gate");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::read(&gate) {
            Ok(bytes) => {
                ensure!(
                    bytes == nonce.as_bytes(),
                    "native start gate identity changed"
                );
                break;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(5)).await
            }
            Err(error) => return Err(error.into()),
        }
    }
    let bus = zbus::Connection::system().await?;
    let daemon = zbus::Proxy::new(
        &bus,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await?;
    let available: bool = daemon
        .call("NameHasOwner", &("org.freedesktop.resolve1",))
        .await?;
    ensure!(
        available,
        "systemd-resolved not already running; test never starts/reconfigures service"
    );
    let name = format!("ph{}", &nonce[..8]);
    let own = Ipv4Addr::new(10, 254, 253, 1);
    let remote = Ipv4Addr::new(10, 254, 254, 2);
    let suffix = format!("s{nonce}.phub");
    let next = format!("t{nonce}.phub");
    let cancel = CancellationToken::new();
    let mut registration = None;
    let mut owner = None;
    let mut reader = None;
    let netlink = nlink::netlink::Connection::<nlink::netlink::Route>::new()?;
    let result=timeout(Duration::from_secs(30),async {
        let tun=Arc::new(Tun::open(&name,own,&[remote]).await?);owner=Some(tun.clone());
        let server=dns::Server::bind(own).await?;let port=server.port()?;let zone=server.zone.clone();
        zone.write().await.update(&snapshot(own,remote,&suffix)?)?;reader=Some(tokio::spawn(server.serve(cancel.child_token())));
        dns::replace_registration(&mut registration,&root.join("profile.json"),tun.index,own,port,&[suffix.clone()]).await?;
        let answer=timeout(Duration::from_secs(8),tokio::net::lookup_host((format!("peer.{suffix}"),443))).await??;ensure!(answer.into_iter().any(|s|s.ip()==IpAddr::V4(remote)),"application resolver bypassed new private namespace");
        zone.write().await.update(&snapshot(own,remote,&next)?)?;dns::replace_registration(&mut registration,&root.join("profile.json"),tun.index,own,port,&[next.clone()]).await?;
        let answer=timeout(Duration::from_secs(8),tokio::net::lookup_host((format!("peer.{next}"),443))).await??;ensure!(answer.into_iter().any(|s|s.ip()==IpAddr::V4(remote)),"application resolver missed replaced private namespace");
        let socket=tokio::net::UdpSocket::bind((own,0)).await?;socket.connect((remote,9000)).await?;let endpoint=socket.local_addr()?;
        let stopped=cancel.child_token();let stop=stopped.clone();let task=tokio::spawn(async move{stopped.cancelled().await;drop(socket);});stop.cancel();timeout(Duration::from_secs(2),task).await??;
        drop(tokio::net::UdpSocket::bind(endpoint).await?);
        let listener=tokio::net::TcpListener::bind((own,0)).await?;
        let (connected,accepted)=tokio::join!(tokio::net::TcpStream::connect(listener.local_addr()?),listener.accept());
        let connected=connected?;let(mut accepted,_)=accepted?;
        let tcp_owner=CancellationToken::new();let closed=tcp_owner.clone();
        let task=tokio::spawn(async move{closed.cancelled().await;drop(connected);});
        tcp_owner.cancel();timeout(Duration::from_secs(2),task).await??;
        use tokio::io::AsyncReadExt;let mut byte=[0;1];
        ensure!(timeout(Duration::from_secs(2),accepted.read(&mut byte)).await??==0,"fixture-owned native TCP socket did not close");
        drop(accepted);drop(listener);
        println!("actual_system_resolved_initial=true actual_system_resolved_replaced=true owned_connected_fixture_socket_reaped=true owned_tcp_closed=true");Ok::<_,anyhow::Error>(())
    }).await;
    cancel.cancel();
    let dns_cleanup = dns::shutdown_registration(&mut registration).await;
    let dns_join = if let Some(mut task) = reader.take() {
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
    drop(owner);
    let cleanup = timeout(Duration::from_secs(5), async {
        while netlink.get_link_by_name(&name).await?.is_some() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    println!(
        "owned_resolved_link_and_native_fd_absent={}",
        cleanup.as_ref().is_ok_and(|r| r.is_ok())
    );
    let native_cleanup = dns_cleanup
        .and(dns_join)
        .and(cleanup.map_err(anyhow::Error::from).and_then(|r| r));
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
        serde_json::json!({"workspace":"fixture","self":"self","revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(60),"peers":[{"id":"self","ip":own,"fingerprint":"fixture","instance":"fixture","hostname":format!("owner.{suffix}")},{"id":"peer","ip":remote,"fingerprint":"peer","instance":"peer","hostname":format!("peer.{suffix}")}],"grants":[]}),
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
