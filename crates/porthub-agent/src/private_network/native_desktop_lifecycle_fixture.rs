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
#[cfg(target_os="macos")]
fn tcp_phase(value:&str)->Result<()>{
    use std::io::Write;
    println!("native_tcp_phase={value}");std::io::stdout().flush()?;Ok(())
}
#[cfg(target_os="macos")]
async fn direct_dns_witness(port:u16,name:&str,observer:&std::sync::Arc<dns::fixture_witness::Observer>,expected:Ipv4Addr)->Result<()> {
    use hickory_proto::{op::{Message,MessageType,OpCode,Query},rr::RecordType};
    timeout(Duration::from_millis(500),async {
        let socket=tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST,0)).await?;
        observer.direct_port(socket.local_addr()?.port());socket.connect((Ipv4Addr::LOCALHOST,port)).await?;
        let mut query=Message::new(63701,MessageType::Query,OpCode::Query);query.add_query(Query::query(name.parse()?,RecordType::A));socket.send(&query.to_vec()?).await?;
        let mut bytes=[0u8;1501];let size=socket.recv(&mut bytes).await?;
        dns::fixture_witness::direct_answer(&bytes[..size],name,expected)
    }).await.map_err(|_|anyhow::anyhow!("direct owned DNS witness timed out"))?
}
#[cfg(target_os="macos")]
fn dns_counts(stage:&str,observer:&dns::fixture_witness::Observer)->Result<()> {
    use std::io::Write;
    println!("native_owned_dns_counts stage={stage} counters={}",serde_json::to_string(&observer.snapshot())?);std::io::stdout().flush()?;Ok(())
}
#[cfg(target_os="macos")]
fn fixed_tcp_header(bytes:&[u8],own:Ipv4Addr,port:u16)->Option<(u16,u16,u8)>{
    if bytes.len()<20||bytes[0]>>4!=4||bytes[9]!=6||bytes[12..16]!=own.octets()||bytes[16..20]!=own.octets(){return None;}
    if u16::from_be_bytes([bytes[6],bytes[7]])&0x1fff!=0{return None;}
    let total=usize::from(u16::from_be_bytes([bytes[2],bytes[3]]));
    if total>bytes.len(){return None;}
    let ihl=usize::from(bytes[0]&15)*4;
    if ihl<20||bytes.len()<ihl+20{return None;}
    let tcp=usize::from(bytes[ihl+12]>>4)*4;
    if tcp<20||total<ihl+tcp||bytes.len()<ihl+tcp{return None;}
    let source=u16::from_be_bytes([bytes[ihl],bytes[ihl+1]]);let destination=u16::from_be_bytes([bytes[ihl+2],bytes[ihl+3]]);
    if destination!=port{return None;}Some((source,destination,bytes[ihl+13]))
}
#[cfg(target_os = "macos")]
async fn production_local_tcp_udp(tun: &Tun, own: Ipv4Addr) -> Result<()> {
    use super::owned_packet_loop::Read;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let owner = super::authority_event::Owner::new();
    #[cfg(feature = "private-sparse")]
    let witness = Some(super::authority_clock::RequestWindow::start(
        std::sync::Arc::new(super::authority_clock::NativeClock),
    )?);
    #[cfg(not(feature = "private-sparse"))]
    let witness = None;
    let authority = super::authority_event::Authority::new(
        (),
        witness,
        chrono::Utc::now() + chrono::Duration::seconds(15),
    )
    .retired_with(owner.domain());
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let cancel = CancellationToken::new();
    let reflected = std::cell::Cell::new(0u64);
    let pump = async {
        let mut buffer = [0; porthub_mesh::MAX_PACKET + 1];
        loop {
            match tun
                .packet_loop()
                .read_next(tun, &authority, deadline, &cancel, &mut buffer)
                .await?
            {
                Read::Local => reflected.set(reflected.get() + 1),
                Read::Remote(_) => anyhow::bail!(
                    "unexpected remote packet during isolated native self-routing proof"
                ),
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let transport = async {
        tcp_phase("listener_bind_start")?;
        let listener = tokio::net::TcpListener::bind((own, 0)).await?;
        let address = listener.local_addr()?;
        tcp_phase("listener_bind_complete")?;
        let connect = async {
            tcp_phase("connect_start")?;
            let stream = tokio::net::TcpStream::connect(address).await?;
            tcp_phase("connect_complete")?;
            Ok::<_, anyhow::Error>(stream)
        };
        let accept = async {
            tcp_phase("accept_start")?;
            let accepted = listener.accept().await?;
            tcp_phase("accept_complete")?;
            Ok::<_, anyhow::Error>(accepted)
        };
        let (mut connected, (mut accepted, _)) = tokio::try_join!(connect, accept)?;
        connected.write_all(b"native-private-source").await?;
        let mut request = [0; 21];
        accepted.read_exact(&mut request).await?;
        ensure!(
            &request == b"native-private-source",
            "actual native TCP request differs"
        );
        accepted.write_all(b"native-private-reply").await?;
        let mut reply = [0; 20];
        connected.read_exact(&mut reply).await?;
        ensure!(
            &reply == b"native-private-reply",
            "actual native TCP reply differs"
        );
        // Real OS FIN/ACK and closure of fixture-owned sockets; no synthesized ACK.
        connected.shutdown().await?;
        let mut byte = [0];
        ensure!(
            accepted.read(&mut byte).await? == 0,
            "actual native TCP FIN absent"
        );
        accepted.shutdown().await?;
        ensure!(
            connected.read(&mut byte).await? == 0,
            "actual native TCP reverse FIN absent"
        );
        drop(connected);
        drop(accepted);
        drop(listener);
        let left = tokio::net::UdpSocket::bind((own, 0)).await?;
        let right = tokio::net::UdpSocket::bind((own, 0)).await?;
        left.send_to(b"native-udp", right.local_addr()?).await?;
        let mut data = [0; 32];
        let (n, peer) = right.recv_from(&mut data).await?;
        ensure!(
            &data[..n] == b"native-udp" && peer == left.local_addr()?,
            "actual native UDP request differs"
        );
        right.send_to(b"native-reply", peer).await?;
        let (n, peer) = left.recv_from(&mut data).await?;
        ensure!(
            &data[..n] == b"native-reply" && peer == right.local_addr()?,
            "actual native UDP response differs"
        );
        drop(left);
        drop(right);
        Ok::<_, anyhow::Error>(())
    };
    tokio::pin!(pump);
    // Production read_next is unchanged. Only the real sockets are fixture-owned.
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {result=transport=>result,result=&mut pump=>result}
    })
    .await;
    cancel.cancel();
    owner.revoke(); // no spawned reader, Arc, or surviving task
    result.map_err(|_| {
        anyhow::anyhow!("actual native production self-routing TCP/UDP exceeded3s")
    })??;
    ensure!(
        timeout(Duration::from_millis(100), &mut pump)
            .await
            .map_err(|_| anyhow::anyhow!(
                "production native reader survived authority/owner cancellation"
            ))?
            .is_err(),
        "production native reader ignored retirement"
    );
    ensure!(
        reflected.get() >= 6,
        "actual production self-routing saw insufficient native packets"
    );
    println!("native_production_self_routing=true tcp_duplex=true native_fin=true udp_duplex=true native_reader_retired=true reflected_packets={} synthetic_transport=false",reflected.get());
    Ok(())
}

// Observe configd's trailing DNS-change notification in the disposable runner.
// The notification is system-wide. The first OS lookup below remains the test
// of whether this particular suffix was published to the system resolver.
#[cfg(target_os = "macos")]
mod change_notification {
    use anyhow::{ensure, Context, Result};
    use std::ffi::{c_char, c_int};
    use std::time::Duration;
    unsafe extern "C" {
        fn notify_register_check(name: *const c_char, token: *mut c_int) -> u32;
        fn notify_check(token: c_int, changed: *mut c_int) -> u32;
        fn notify_cancel(token: c_int) -> u32;
    }

    pub(super) struct Watch(c_int);
    impl Watch {
        pub(super) fn arm() -> Result<Self> {
            let mut token = 0;
            let name = c"com.apple.system.config.network_change.dns";
            ensure!(unsafe { notify_register_check(name.as_ptr(), &mut token) } == 0,
                "cannot observe configd DNS changes");
            let watch = Self(token);
            watch.changed()?; // consume the initial registration event
            Ok(watch)
        }

        fn changed(&self) -> Result<bool> {
            let mut changed = 0;
            ensure!(unsafe { notify_check(self.0, &mut changed) } == 0,
                "cannot read configd DNS change notification");
            Ok(changed != 0)
        }

        pub(super) async fn wait(&self) -> Result<()> {
            tokio::time::timeout(Duration::from_secs(8), async {
                while !self.changed()? {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok(())
            }).await.context("configd DNS change notification timed out")?
        }
    }

    impl Drop for Watch {
        fn drop(&mut self) {
            unsafe { notify_cancel(self.0); }
        }
    }
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
    let restart_suffix = format!("u{}.phub", spec.nonce);
    let reallocated_suffix = format!("v{}.phub", spec.nonce);
    #[cfg(target_os = "macos")]
    for s in [&suffix, &next_suffix, &restart_suffix, &reallocated_suffix] {
        ensure!(
            !Path::new("/etc/resolver").join(s).exists(),
            "foreign resolver already uses fixture suffix"
        );
    }
    let cancel = CancellationToken::new();
    let mut dns_task = None;
    let mut watch_task = None;
    let mut watch_receivers = None;
    let mut socket_task = None;
    let mut registration = None;
    let mut source = None;
    let mut foreign = None;
    let mut sentinel = None;
    let mut indices = Vec::new();
    let mut source_name = String::new();
    let result=timeout(Duration::from_secs(45),async {
        let pools=["10.254.253.0/24".parse()?,"10.254.254.0/24".parse()?];
        let mut tun=super::native_owner::open(&spec.profile,&format!("ph{}",&spec.nonce[..8]),own,&pools,&[]).await?;
        source_name=tun.name.clone();indices.push(tun.index);source=Some(tun.clone());
        let audit=tun.reconcile_sparse(&pools,&[remote]).await?;
        ensure!(audit.capture.accepted.len()==2&&audit.capture.conflicting.is_empty()&&audit.accepted_peers==vec![remote],"native prefixes/peer were not admitted");
        for target in [Ipv4Addr::new(10,254,253,99),Ipv4Addr::new(10,254,254,99)]{
            let socket=tokio::net::UdpSocket::bind((own,0)).await?;socket.connect((target,9001)).await?;socket.send(b"native-probe").await?;udp_seen(&tun,own,target).await?;
        }
        let mut server=dns::Server::bind(own).await?;let port=server.port()?;let zone=server.zone.clone();
        #[cfg(target_os="macos")]
        let observer={let o=Arc::new(dns::fixture_witness::Observer::new(format!("peer.{suffix}."),&spec.nonce,remote)?);server.fixture_observer=Some(o.clone());o};
        zone.write().await.update(&snapshot(own,remote,&suffix)?)?;dns_task=Some(tokio::spawn(server.serve(cancel.child_token())));
        #[cfg(target_os="macos")]
        let direct={
            use std::io::Write;
            let start=std::time::Instant::now();let result=direct_dns_witness(port,&format!("peer.{suffix}."),&observer,remote).await;
            println!("native_owned_dns_direct success={} elapsed_ms={}",result.is_ok(),start.elapsed().as_millis());std::io::stdout().flush()?;result
        };
        #[cfg(target_os="macos")]let dns_change=change_notification::Watch::arm()?;
        #[cfg(target_os="macos")]tcp_phase("dns_initial_publication_start")?;
        dns::replace_registration(&mut registration,&spec.profile,tun.index,own,port,&[suffix.clone()]).await?;
        #[cfg(target_os="macos")]tcp_phase("dns_initial_publication_effective_ready")?;
        #[cfg(target_os="macos")]{dns_change.wait().await?;tcp_phase("dns_configd_notification_observed")?;}
        #[cfg(target_os="macos")]
        {if super::dns_convergence_macos::fixture_owned_projection(&super::dns_convergence_macos::Endpoint{suffix:suffix.clone(),port},"before_initial_lookup").await.is_err(){let _=tcp_phase("dns_initial_config_observation_unavailable");}let _=dns_counts("before_initial_lookup",&observer);}
        #[cfg(target_os="macos")]tcp_phase("dns_initial_lookup_start")?;
        let lookup=timeout(Duration::from_secs(8),tokio::net::lookup_host((format!("peer.{suffix}"),443))).await;
        #[cfg(target_os="macos")]
        {
            use std::io::Write;
            let (outcome,errno)=match &lookup {Ok(Ok(_))=>("complete",None),Ok(Err(error))=>("os_error",error.raw_os_error()),Err(_)=>("timeout",None)};
            println!("native_dns_lookup_phase=initial outcome={outcome} errno={errno:?}");std::io::stdout().flush()?;
        }
        #[cfg(target_os="macos")]
        {
            let _=dns_counts("after_initial_lookup",&observer);
            if !matches!(&lookup,Ok(Ok(_))) {
                // Passive only: never issue a second lookup or replace the primary error.
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _=dns_counts("after_failed_lookup_passive500ms",&observer);
                let _=super::dns_convergence_macos::fixture_owned_projection(&super::dns_convergence_macos::Endpoint{suffix:suffix.clone(),port},"after_initial_failure").await;
            }
        }
        let answer=lookup??;
        #[cfg(target_os="macos")]direct?;
        ensure!(answer.into_iter().any(|s|s.ip()==IpAddr::V4(remote)),"actual system resolver did not use owned namespace");
        zone.write().await.update(&snapshot(own,remote,&next_suffix)?)?;
        #[cfg(target_os="macos")]let dns_change=change_notification::Watch::arm()?;
        #[cfg(target_os="macos")]tcp_phase("dns_replacement_publication_start")?;
        dns::replace_registration(&mut registration,&spec.profile,tun.index,own,port,&[next_suffix.clone()]).await?;
        #[cfg(target_os="macos")]tcp_phase("dns_replacement_publication_effective_ready")?;
        #[cfg(target_os="macos")]{dns_change.wait().await?;tcp_phase("dns_configd_notification_observed")?;}
        #[cfg(target_os="macos")]let _=dns_counts("before_replacement_lookup",&observer);
        #[cfg(target_os="macos")]tcp_phase("dns_replacement_lookup_start")?;
        let lookup=timeout(Duration::from_secs(8),tokio::net::lookup_host((format!("peer.{next_suffix}"),443))).await;
        #[cfg(target_os="macos")]
        {
            use std::io::Write;
            let (outcome,errno)=match &lookup {Ok(Ok(_))=>("complete",None),Ok(Err(error))=>("os_error",error.raw_os_error()),Err(_)=>("timeout",None)};
            println!("native_dns_lookup_phase=replacement outcome={outcome} errno={errno:?}");std::io::stdout().flush()?;
        }
        #[cfg(target_os="macos")]let _=dns_counts("after_replacement_lookup",&observer);
        let answer=lookup??;
        ensure!(answer.into_iter().any(|s|s.ip()==IpAddr::V4(remote)),"dynamic custom suffix not registered with actual OS resolver");
        // Normal same-profile restart must reuse only its protected intent,
        // after the previous native owner actually disappears. Open exactly
        // once; no retry/adoption if a foreign replacement appears.
        dns::shutdown_registration(&mut registration).await?;
        let previous_index=tun.index;
        #[cfg(windows)]let previous_guid=super::device::adapter_guid(previous_index)?;
        #[cfg(target_os="macos")]let previous_name=std::ffi::CString::new(tun.name.as_bytes())?;
        drop(source.take());drop(tun);
        timeout(Duration::from_secs(5),async {
            loop {
                #[cfg(windows)]let present=super::device::fixture_adapter_exists(&previous_guid)?;
                #[cfg(target_os="macos")]let present=unsafe{libc::if_nametoindex(previous_name.as_ptr())}==previous_index;
                if !present{break;}
                tokio::time::sleep(Duration::from_millis(25)).await;
            }Ok::<_,anyhow::Error>(())
        }).await??;
        {tun=super::native_owner::open(&spec.profile,&format!("ph{}",&spec.nonce[..8]),own,&pools,&[]).await?;}
        indices.push(tun.index);source=Some(tun.clone());
        let restarted=tun.reconcile_sparse(&pools,&[remote]).await?;
        ensure!(restarted.capture.accepted.len()==2&&restarted.accepted_peers==vec![remote],"same-profile restart lost native capture ownership");
        zone.write().await.update(&snapshot(own,remote,&restart_suffix)?)?;
        #[cfg(target_os="macos")]let dns_change=change_notification::Watch::arm()?;
        #[cfg(target_os="macos")]tcp_phase("dns_restart_publication_start")?;
        dns::replace_registration(&mut registration,&spec.profile,tun.index,own,port,&[restart_suffix.clone()]).await?;
        #[cfg(target_os="macos")]tcp_phase("dns_restart_publication_effective_ready")?;
        #[cfg(target_os="macos")]{dns_change.wait().await?;tcp_phase("dns_configd_notification_observed")?;}
        #[cfg(target_os="macos")]let _=dns_counts("before_restart_lookup",&observer);
        #[cfg(target_os="macos")]tcp_phase("dns_restart_lookup_start")?;
        let lookup=timeout(Duration::from_secs(8),tokio::net::lookup_host((format!("peer.{restart_suffix}"),443))).await;
        #[cfg(target_os="macos")]
        {
            use std::io::Write;
            let (outcome,errno)=match &lookup {Ok(Ok(_))=>("complete",None),Ok(Err(error))=>("os_error",error.raw_os_error()),Err(_)=>("timeout",None)};
            println!("native_dns_lookup_phase=restart outcome={outcome} errno={errno:?}");std::io::stdout().flush()?;
        }
        #[cfg(target_os="macos")]let _=dns_counts("after_restart_lookup",&observer);
        let answer=lookup??;
        ensure!(answer.into_iter().any(|s|s.ip()==IpAddr::V4(remote)),"actual resolver did not rebind to restarted native owner");
        // Own a real connected native socket in an explicit task, then prove its
        // cancellation releases the exact endpoint. No unrelated app is closed.
        let socket=tokio::net::UdpSocket::bind((own,0)).await?;socket.connect((remote,9000)).await?;let endpoint=socket.local_addr()?;
        let close=cancel.child_token();let closed=close.clone();socket_task=Some(tokio::spawn(async move{closed.cancelled().await;drop(socket);}));
        close.cancel();timeout(Duration::from_secs(2),socket_task.take().unwrap()).await??;
        let rebound=tokio::net::UdpSocket::bind(endpoint).await?;drop(rebound);
        let retained={
            let socket=tokio::net::UdpSocket::bind((own,0)).await?;
            socket.connect((remote,9000)).await?;socket.send(b"native-retained-before-conflict").await?;
            udp_seen(&tun,own,remote).await?;socket
        };
        let other=Arc::new(open(&spec,1,Ipv4Addr::new(10,254,252,10)).await?);indices.push(other.index);foreign=Some(other.clone());
        let route=Route::new(IpAddr::V4(Ipv4Addr::new(10,254,254,0)),25).with_if_index(other.index);
        #[cfg(windows)]let route=route.with_metric(77);
        let before_underlay=super::interfaces::current().await?;
        let (underlay_tx,underlay_rx)=tokio::sync::watch::channel(before_underlay.clone());
        let (revision_tx,revision_rx)=tokio::sync::watch::channel(0u64);
        let witness=Arc::new(super::route_debounce::witness::Witness::new(super::route_debounce::witness::Key::route(&route)));
        watch_task=Some(tokio::spawn(super::interfaces::watch_witness(underlay_tx,revision_tx,cancel.child_token(),witness.clone())));
        timeout(Duration::from_secs(4),async {
            while !witness.is_ready() { tokio::time::sleep(Duration::from_millis(10)).await; }
        }).await.map_err(|_|{eprintln!("PORTHUB_NATIVE_ROUTE_WATCH {}",witness.diagnostic(*revision_rx.borrow()));anyhow::anyhow!("native route watcher did not subscribe and initialize")})?;
        let revision_before=*revision_rx.borrow();
        witness.add_started();manager.add(&route).await?;witness.add_acknowledged();sentinel=Some(route.clone());
        timeout(Duration::from_secs(4),async {
            while !witness.completed() { tokio::time::sleep(Duration::from_millis(10)).await; }
        }).await.map_err(|_|{eprintln!("PORTHUB_NATIVE_ROUTE_WATCH {}",witness.diagnostic(*revision_rx.borrow()));anyhow::anyhow!("sentinel native Add did not produce successful bounded refresh/publication")})?;
        eprintln!("PORTHUB_NATIVE_ROUTE_WATCH {}",witness.diagnostic(*revision_rx.borrow()));
        ensure!(*revision_rx.borrow()>revision_before,"native route refresh did not publish a revision");
        ensure!(*underlay_rx.borrow()==before_underlay,"owned sentinel unexpectedly changed underlay candidates");
        watch_receivers=Some((underlay_rx,revision_rx));
        println!("native_route_callback_refresh=true underlay_candidates_unchanged=true");
        let tcp_own={
            // Only the production owner remains strongly referenced. The SAME
            // warmed socket stays open through retirement and fresh allocation.
            drop(tun);
            let outcome=super::native_owner::reconcile(&mut source,&spec.profile,own,&pools,&[remote]).await?;
            ensure!(matches!(outcome,super::native_owner::Outcome::Retired(_))&&source.is_none(),"conflict did not retire the entire native source owner");
            let repair=super::native_owner::repair_request(&spec.profile)?.ok_or_else(||anyhow::anyhow!("native conflict feedback missing"))?;
            ensure!(repair.source==own&&repair.blocked==vec![pools[1]],"native feedback lost exact source/conflicting pool");
            let _=retained.send(b"native-retained-after-retirement").await;
            match timeout(Duration::from_millis(250),udp_seen(&other,own,remote)).await{
                Err(_)=>{},Ok(Ok(()))=>anyhow::bail!("old connected socket escaped via foreign route"),Ok(Err(error))=>return Err(error),
            }
            dns::shutdown_registration(&mut registration).await?;
            if let Some(task)=dns_task.take(){
                task.abort();match task.await{Err(error) if error.is_cancelled()=>{},Ok(result)=>result?,Err(error)=>return Err(error.into())}
            }
            let next_own=Ipv4Addr::new(10,254,251,1);let next_remote=Ipv4Addr::new(10,254,250,2);
            let next_pools=["10.254.251.0/24".parse()?,"10.254.250.0/24".parse()?];
            let next=super::native_owner::open(&spec.profile,&format!("ph{}",&spec.nonce[..8]),next_own,&next_pools,&[]).await?;
            indices.push(next.index);source=Some(next);
            ensure!(matches!(super::native_owner::reconcile(&mut source,&spec.profile,next_own,&next_pools,&[next_remote]).await?,super::native_owner::Outcome::Active(_)),"new allocation failed native reconciliation");
            ensure!(super::native_owner::repair_request(&spec.profile)?.is_none(),"new allocation retained stale repair feedback");
            super::native_owner::fixture_assignment_ready(&spec.profile,own,next_own)?;
            let fresh=tokio::net::UdpSocket::bind((next_own,0)).await?;fresh.connect((next_remote,9002)).await?;
            fresh.send(b"native-fresh-allocation").await?;udp_seen(source.as_ref().unwrap(),next_own,next_remote).await?;
            let _=retained.send(b"native-retained-after-reallocation").await;
            match timeout(Duration::from_millis(250),udp_seen(&other,own,remote)).await{
                Err(_)=>{},Ok(Ok(()))=>anyhow::bail!("old connected socket escaped after fresh allocation"),Ok(Err(error))=>return Err(error),
            }
            let mut server=dns::Server::bind(next_own).await?;let next_port=server.port()?;
            #[cfg(target_os="macos")]
            let reallocation_observer=Arc::new(dns::fixture_witness::Observer::new(format!("peer.{reallocated_suffix}."),&spec.nonce,next_remote)?);
            #[cfg(target_os="macos")]{server.fixture_observer=Some(reallocation_observer.clone());}
            server.zone.write().await.update(&snapshot(next_own,next_remote,&reallocated_suffix)?)?;
            dns_task=Some(tokio::spawn(server.serve(cancel.child_token())));
            #[cfg(target_os="macos")]
            let direct_reallocation={
                use std::io::Write;
                let start=std::time::Instant::now();let result=direct_dns_witness(next_port,&format!("peer.{reallocated_suffix}."),&reallocation_observer,next_remote).await;
                println!("native_owned_dns_direct_reallocation success={} elapsed_ms={}",result.is_ok(),start.elapsed().as_millis());std::io::stdout().flush()?;result
            };
            #[cfg(target_os="macos")]let dns_change=change_notification::Watch::arm()?;
        #[cfg(target_os="macos")]tcp_phase("dns_reallocation_publication_start")?;
            dns::replace_registration(&mut registration,&spec.profile,source.as_ref().unwrap().index,next_own,next_port,&[reallocated_suffix.clone()]).await?;
            #[cfg(target_os="macos")]tcp_phase("dns_reallocation_publication_effective_ready")?;
        #[cfg(target_os="macos")]{dns_change.wait().await?;tcp_phase("dns_configd_notification_observed")?;}
            #[cfg(target_os="macos")]
            if super::dns_convergence_macos::fixture_owned_projection(&super::dns_convergence_macos::Endpoint{suffix:reallocated_suffix.clone(),port:next_port},"before_reallocation_lookup").await.is_err(){let _=tcp_phase("dns_reallocation_config_observation_unavailable");}
            #[cfg(target_os="macos")]let _=dns_counts("before_reallocation_lookup",&reallocation_observer);
            #[cfg(target_os="macos")]tcp_phase("dns_reallocation_lookup_start")?;
        let lookup=timeout(Duration::from_secs(8),tokio::net::lookup_host((format!("peer.{reallocated_suffix}"),443))).await;
        #[cfg(target_os="macos")]
        {
            use std::io::Write;
            let (outcome,errno)=match &lookup {Ok(Ok(_))=>("complete",None),Ok(Err(error))=>("os_error",error.raw_os_error()),Err(_)=>("timeout",None)};
            println!("native_dns_lookup_phase=reallocation outcome={outcome} errno={errno:?}");std::io::stdout().flush()?;
        }
        #[cfg(target_os="macos")]let _=dns_counts("after_reallocation_lookup",&reallocation_observer);
        #[cfg(target_os="macos")]
        if !matches!(&lookup,Ok(Ok(_))) {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let _=dns_counts("after_failed_reallocation_passive500ms",&reallocation_observer);
            let _=super::dns_convergence_macos::fixture_owned_projection(&super::dns_convergence_macos::Endpoint{suffix:reallocated_suffix.clone(),port:next_port},"after_reallocation_failure").await;
        }
        let answer=lookup??;
        #[cfg(target_os="macos")]direct_reallocation?;
            ensure!(answer.into_iter().any(|s|s.ip()==IpAddr::V4(next_remote)),"actual resolver did not follow fresh native source allocation");
            println!("native_source_retirement_ack=true repair_feedback_bound=true fresh_source_record=true");
            println!("native_whole_source_retirement=true retained_external_socket_no_escape=true fresh_allocation_capture=true fresh_allocation_system_dns=true");
            drop(fresh);drop(retained);next_own
        };
        #[cfg(target_os="macos")]
        tcp_phase("sentinel_inventory_start")?;
        #[cfg(target_os="macos")]
        let before_tcp=timeout(Duration::from_secs(3),manager.list()).await.map_err(|_|anyhow::anyhow!("native TCP diagnostic sentinel inventory exceeded3s"))??;
        #[cfg(windows)]
        let before_tcp=manager.list().await?;
        #[cfg(target_os="macos")]
        {
            tcp_phase("sentinel_inventory_complete")?;
            let local_index=source.as_ref().ok_or_else(||anyhow::anyhow!("native source absent"))?.index;
            ensure!(before_tcp.iter().any(|r|r.destination()==IpAddr::V4(tcp_own)&&r.prefix()==32&&r.if_index()==Some(local_index)),"actual address-born own route absent");
            let local:Vec<_>=before_tcp.iter().filter(|r|r.destination()==IpAddr::V4(tcp_own)&&r.prefix()==32).collect();
            ensure!(local.len()<=8,"own /32 route diagnostic exceeds eight rows");
            println!("native_tcp_own_route_rows={} flags_exposed_by_route_manager=false",local.len());
            for row in local{println!("native_tcp_own_route destination={tcp_own} prefix=32 interface={:?} metric_exposed_by_route_manager=false",row.if_index());}
        }
        ensure!(before_tcp.iter().any(|r|r.destination()==route.destination()&&r.prefix()==route.prefix()&&r.if_index()==route.if_index()),"foreign sentinel route changed");
        #[cfg(windows)]{
        let listener=tokio::net::TcpListener::bind((tcp_own,0)).await?;
        #[cfg(windows)]
        let (connected,accepted)=tokio::join!(tokio::net::TcpStream::connect(listener.local_addr()?),listener.accept());
        let connected=connected?;let(mut accepted,_)=accepted?;
        let tcp_owner=CancellationToken::new();let closed=tcp_owner.clone();
        let task=tokio::spawn(async move{closed.cancelled().await;drop(connected);});
        tcp_owner.cancel();timeout(Duration::from_secs(2),task).await??;
        use tokio::io::AsyncReadExt;let mut byte=[0;1];
        ensure!(timeout(Duration::from_secs(2),accepted.read(&mut byte)).await??==0,"fixture-owned native TCP socket did not close");
        drop(accepted);drop(listener);
        }
        #[cfg(target_os="macos")]
        production_local_tcp_udp(source.as_ref().ok_or_else(||anyhow::anyhow!("native production packet owner absent"))?,tcp_own).await?;
        println!("native_aggregate_capture=true actual_system_dns=true dynamic_suffix=true same_profile_native_restart=true foreign_collision_withdrawal=true connected_fixture_socket_closed=true owned_tcp_closed=true");
        Ok::<_,anyhow::Error>(())
    }).await;
    // Independent native cleanup executes after body error/timeout as well.
    cancel.cancel();
    if let Some(task) = socket_task.take() {
        task.abort();
        let _ = task.await;
    }
    let dns_cleanup = dns::shutdown_registration(&mut registration).await;
    // Both owned watcher/server joins share the existing 3s cleanup bound.
    let joined=timeout(Duration::from_secs(3),async {
        let dns=async { if let Some(task)=dns_task.as_mut() { task.await.map_err(anyhow::Error::from).and_then(|r|r) } else { Ok(()) } };
        let watcher=async { if let Some(task)=watch_task.as_mut() { task.await.map_err(anyhow::Error::from).and_then(|r|r) } else { Ok(()) } };
        let (dns,watcher)=tokio::join!(dns,watcher); dns.and(watcher)
    }).await;
    let dns_join=match joined {
        Ok(result)=>result,
        Err(error)=>{
            if let Some(task)=dns_task.take() { if !task.is_finished() { task.abort(); let _=task.await; } }
            if let Some(task)=watch_task.take() { if !task.is_finished() { task.abort(); let _=task.await; } }
            Err(anyhow::Error::from(error))
        }
    };
    drop(watch_receivers);
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
            #[cfg(target_os="macos")]
            let local_owned=native.iter().any(|r|r.prefix()==32&&[own,Ipv4Addr::new(10,254,251,1),Ipv4Addr::new(10,254,252,10)].iter().any(|ip|r.destination()==IpAddr::V4(*ip)));
            #[cfg(not(target_os="macos"))]let local_owned=false;
            if !addresses && !owned_routes && !local_owned {
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
    let resolver_absent = [&suffix, &next_suffix, &restart_suffix, &reallocated_suffix]
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
    let body_result=result.map_err(anyhow::Error::from).and_then(|r|r);
    if let Err(error)=&body_result {eprintln!("PORTHUB_NATIVE_FAILURE_CHAIN {}",super::native_owner::fixture_failure_chain(error));}
    if let Err(error)=&native_cleanup {eprintln!("PORTHUB_NATIVE_CLEANUP_CHAIN {}",super::native_owner::fixture_failure_chain(error));}
    match (
        body_result,
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

#[cfg(target_os="macos")]
#[test]
fn native_mac_tcp_diagnostic_header_is_fixed_scope_and_truncation_safe(){
    let own:Ipv4Addr="10.254.251.1".parse().unwrap();let mut bytes=[0u8;40];bytes[0]=0x45;bytes[2..4].copy_from_slice(&40u16.to_be_bytes());bytes[9]=6;bytes[12..16].copy_from_slice(&own.octets());bytes[16..20].copy_from_slice(&own.octets());bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());bytes[22..24].copy_from_slice(&45678u16.to_be_bytes());bytes[32]=0x50;bytes[33]=2;
    assert_eq!(fixed_tcp_header(&bytes,own,45678),Some((12345,45678,2)));
    for n in 0..40{assert_eq!(fixed_tcp_header(&bytes[..n],own,45678),None);}
    assert_eq!(fixed_tcp_header(&bytes,own,45679),None);bytes[12]=11;assert_eq!(fixed_tcp_header(&bytes,own,45678),None);bytes[12]=10;bytes[0]=0x4f;assert_eq!(fixed_tcp_header(&bytes,own,45678),None);
}
