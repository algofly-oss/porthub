#![cfg(all(target_os = "linux", feature = "netns-tests"))]
use anyhow::{ensure, Context, Result};
use std::{collections::BTreeMap, net::IpAddr, time::Duration};
use tokio::{io::{AsyncBufReadExt, AsyncWriteExt, BufReader}, net::TcpStream};
use tokio_util::sync::CancellationToken;

async fn wait_for_selection(mode: &str) -> Result<()> {
    let expected: porthub_mesh::exit_policy::Selection = serde_json::from_value(serde_json::json!(mode))?;
    let mut updates = porthub_agent::private_network::exit_selection::test_selection_updates();
    tokio::time::timeout(Duration::from_secs(30), updates.wait_for(|state| *state == Some((expected, 2))))
        .await.context("exit mode did not reach packet-path selection")??;
    Ok(())
}

type Stream = BufReader<TcpStream>;
async fn open(target: &str) -> Result<(Stream, IpAddr)> {
    let mut stream = BufReader::new(tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(target)).await.context("TCP connect timeout")??);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_line(&mut line)).await.context("TCP response timeout")??;
    Ok((stream, line.trim().parse()?))
}
async fn ping(stream: &mut Stream) -> Result<IpAddr> {
    stream.get_mut().write_all(b"ping\n").await?;
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_line(&mut line)).await.context("TCP response timeout")??;
    Ok(line.trim().parse()?)
}
async fn udp_ip(socket: &tokio::net::UdpSocket) -> Result<IpAddr> {
    socket.send(b"exit UDP identity").await?;
    let mut bytes = [0u8; 128];
    let size = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut bytes)).await.context("UDP exit response timeout")??;
    Ok(std::str::from_utf8(&bytes[..size])?.parse()?)
}
fn icmp_echo(target: std::net::Ipv4Addr) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    ensure!(raw >= 0, "cannot open scoped ICMP test socket");
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let timeout = libc::timeval { tv_sec: 3, tv_usec: 0 };
    ensure!(unsafe { libc::setsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&timeout as *const libc::timeval).cast(), std::mem::size_of_val(&timeout) as _) } == 0, "cannot bound ICMP test");
    let address = libc::sockaddr_in { sin_family: libc::AF_INET as _, sin_port: 0, sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(target.octets()) }, sin_zero: [0; 8] };
    let mut echo = [8u8, 0, 0, 0, 0x50, 0x48, 0, 1, 0x45, 0x58, 0x49, 0x54];
    let mut sum: u32 = echo.as_chunks::<2>().0.iter().map(|bytes| u16::from_be_bytes(*bytes) as u32).sum();
    while sum >> 16 != 0 { sum = (sum & 65535) + (sum >> 16); }
    echo[2..4].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    ensure!(unsafe { libc::sendto(socket.as_raw_fd(), echo.as_ptr().cast(), echo.len(), 0, (&address as *const libc::sockaddr_in).cast(), std::mem::size_of_val(&address) as _) } == echo.len() as isize, "ICMP exit send failed");
    let mut bytes = [0u8; 2048];
    let size = unsafe { libc::recv(socket.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    ensure!(size >= 32, "ICMP exit reply did not arrive");
    let header = usize::from(bytes[0] & 15) * 4;
    ensure!(header + echo.len() <= size as usize && bytes[header] == 0 && bytes[header + 4..header + echo.len()] == echo[4..], "ICMP exit reply mismatch");
    Ok(())
}
async fn relay_origin_consumer(target:&str)->Result<()> {
    tokio::time::timeout(Duration::from_secs(20),async{while !std::path::Path::new("/state/release-send").is_file(){tokio::time::sleep(Duration::from_millis(25)).await;}}).await.context("owned relay transport bootstrap not released")?;
    let nonce=std::env::var("PORTHUB_TEST_FIXTURE_NONCE")?;let expected=format!("relay-origin-first-{nonce}");
    let socket=tokio::time::timeout(Duration::from_secs(20),async{loop{
        let socket=tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        if socket.connect(target).await.is_ok()&&socket.local_addr()?.ip()=="10.234.240.10".parse::<IpAddr>()?{break Ok::<_,anyhow::Error>(socket);}
        tokio::time::sleep(Duration::from_millis(25)).await;
    }}).await.context("owned native exit route did not become ready")??;
    ensure!(socket.send(expected.as_bytes()).await?==expected.len(),"owned relay UDP send incomplete");println!("native_relay_first_udp sent_once=true");
    let mut response=[0u8;256];let n=tokio::time::timeout(Duration::from_secs(3),socket.recv(&mut response)).await.context("first relay EXIT UDP response timeout")??;
    ensure!(&response[..n]==expected.as_bytes(),"owned relay UDP payload mismatch");println!("native_relay_first_udp payload_verified=true sends=1");Ok(())
}
async fn consumer(target: &str) -> Result<()> {
    let phase_started=std::time::Instant::now();
    let phase=|name:&'static str|println!("native_exit_phase phase={name} elapsed_ms={}",phase_started.elapsed().as_millis());
    let expected: Vec<IpAddr> = ["203.0.113.2", "203.0.113.3"].into_iter().map(|s| s.parse().unwrap()).collect();
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut seen = std::collections::BTreeSet::new();
        loop {
            if let Ok((_, ip)) = open(target).await { if expected.contains(&ip) { seen.insert(ip); } }
            if seen.len() == 2 { return Ok::<_,anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }).await??;
    println!("both exits reached; opening persistent connection");
    let (mut established, original) = open(target).await.context("open persistent connection")?;
    let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(target).await?;
    let udp_exit = udp_ip(&udp).await?;
    ensure!(expected.contains(&udp_exit), "UDP traffic bypassed exits");
    let target_ip = target.parse::<std::net::SocketAddr>()?.ip();
    if let IpAddr::V4(target_ip) = target_ip { tokio::task::spawn_blocking(move || icmp_echo(target_ip)).await??; }
    println!("UDP and ICMP traffic used the IP exit transport");
    for mode in ["round_robin", "sticky", "random"] {
        established.get_mut().write_all(format!("mode:{mode}\n").as_bytes()).await?;
        let mut confirmation = String::new(); established.read_line(&mut confirmation).await?;
        ensure!(confirmation.trim() == "updated", "mode update failed");
        wait_for_selection(mode).await?;
        ensure!(udp_ip(&udp).await? == udp_exit, "established UDP flow changed exit on policy update");
        let count = if mode == "random" { 64 } else { 16 };
        let mut counts = BTreeMap::new();
        for index in 0..count {
            let connect_started=std::time::Instant::now();
            println!("native_exit_connect mode={mode} index={index} phase=begin");
            let (_, ip) = open(target).await.with_context(|| format!("new {mode} connection {index}"))?;
            println!("native_exit_connect mode={mode} index={index} phase=connected elapsed_ms={}",connect_started.elapsed().as_millis());
            ensure!(expected.contains(&ip), "traffic bypassed the exits");
            *counts.entry(ip).or_insert(0usize) += 1;
            ensure!(ping(&mut established).await.with_context(|| format!("persistent connection during {mode} iteration {index}"))? == original, "established connection changed exit");
        }
        match mode {
            "round_robin" => ensure!(counts.len() == 2 && counts.values().all(|n| *n == 8), "uneven round robin: {counts:?}"),
            "sticky" => ensure!(counts.len() == 1, "sticky changed exits: {counts:?}"),
            _ => ensure!(counts.len() == 2, "random did not use both exits: {counts:?}"),
        }
        println!("{mode}: {count} new connections verified; established connection preserved");
        let (mut half_closed, exit) = open(target).await?;
        half_closed.get_mut().shutdown().await?;
        let mut final_reply = String::new();
        tokio::time::timeout(Duration::from_secs(3), half_closed.read_line(&mut final_reply)).await??;
        ensure!(final_reply.trim().parse::<IpAddr>()? == exit, "half-closed connection lost its final reply");
        final_reply.clear();
        ensure!(tokio::time::timeout(Duration::from_secs(3), half_closed.read_line(&mut final_reply)).await?? == 0, "server close was not delivered");
        println!("{mode}: half-close preserved final response and orderly shutdown");
    }
    phase("single_outage_begin");
    let offline = expected.iter().find(|ip| **ip != original).unwrap();
    established.get_mut().write_all(format!("offline:{offline}\n").as_bytes()).await?;
    let mut confirmation = String::new(); established.read_line(&mut confirmation).await?;
    ensure!(confirmation.trim() == "updated", "exit shutdown failed");
    tokio::time::sleep(Duration::from_secs(20)).await;
    for _ in 0..16 {
        let (_, ip) = open(target).await.context("new connection after exit shutdown")?;
        ensure!(ip == original, "offline exit remained eligible");
        ensure!(ping(&mut established).await? == original, "healthy established flow broke");
    }
    phase("single_outage_survivor16_complete");
    println!("offline exit excluded: 16 new connections used the surviving exit; established connection preserved");
    let control = std::env::var("PORTHUB_TEST_CONTROL_TARGET")?;
    async fn command(control: &str, command: &str) -> Result<()> {
        let (mut stream, _) = open(control).await?;
        stream.get_mut().write_all(format!("{command}\n").as_bytes()).await?;
        let mut reply = String::new();
        tokio::time::timeout(Duration::from_secs(20), stream.read_line(&mut reply)).await??;
        ensure!(reply.trim() == "updated", "fixture command failed");
        Ok(())
    }
    phase("all_outage_stop_begin");
    command(&control, "exits:stop").await?;
    phase("all_outage_stopped");
    ensure!(open(target).await.is_err(), "blocked exit route leaked normal internet access");
    phase("all_outage_first_blocked");
    tokio::time::sleep(Duration::from_secs(20)).await;
    ensure!(open(target).await.is_err(), "blocked exit route leaked after presence expiry");
    phase("all_outage_after_presence_blocked");
    phase("fallback_enable_begin");
    command(&control, "fallback:on").await?;
    phase("fallback_policy_requested");
    let (mut direct, direct_ip) = tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            if let Ok(pair) = open(target).await {
                if !expected.contains(&pair.1) { break pair; }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }).await.context("authorized normal internet fallback did not activate")?;
    phase("fallback_active");
    ensure!(direct_ip == "198.18.10.2".parse::<IpAddr>()?, "unexpected fallback source");
    phase("recovery_begin");
    command(&control, "exits:start").await?;
    phase("recovery_started");
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            ensure!(ping(&mut direct).await? == direct_ip, "existing direct connection moved on exit recovery");
            if let Ok((_, ip)) = open(target).await {
                if expected.contains(&ip) { break Ok::<_, anyhow::Error>(()); }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }).await.context("recovered exits did not resume new connections")??;
    phase("recovery_connections_verified");
    command(&control, "fallback:off").await?;
    phase("fallback_disabled");
    println!("all-exit outage: default blocking, opt-in direct fallback, recovery and direct TCP pinning verified");
    Ok(())
}

fn authority_callback_samples()->Option<(u64,u64,u64)>{
    #[cfg(all(feature="private-sparse",feature="private-stream"))]
    {Some(porthub_agent::private_network::sparse_dispatch::test_current_callback_samples())}
    #[cfg(not(all(feature="private-sparse",feature="private-stream")))]
    {None}
}
fn process_cpu_nanos()->Option<u128>{
    let mut value=libc::timespec{tv_sec:0,tv_nsec:0};
    if unsafe{libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID,&mut value)}!=0||value.tv_sec<0||value.tv_nsec<0||value.tv_nsec>=1_000_000_000{return None;}
    Some(value.tv_sec as u128*1_000_000_000+value.tv_nsec as u128)
}
fn own_cgroup_cpu()->Option<BTreeMap<String,u64>> {
    use std::io::Read;
    let file=std::fs::File::open("/sys/fs/cgroup/cpu.stat").ok()?;
    let mut bytes=Vec::new();file.take(4097).read_to_end(&mut bytes).ok()?;
    if bytes.len()>4096{return None;}
    let text=std::str::from_utf8(&bytes).ok()?;let mut fields=BTreeMap::new();
    for line in text.lines(){let mut split=line.split_whitespace();let key=split.next()?;let value=split.next()?;
        if ["usage_usec","user_usec","system_usec","nr_periods","nr_throttled","throttled_usec","nr_bursts","burst_usec"].contains(&key){fields.insert(key.into(),value.parse().ok()?);}
    }
    fields.contains_key("usage_usec").then_some(fields)
}
fn print_cgroup_cpu(before:Option<&BTreeMap<String,u64>>,after:Option<&BTreeMap<String,u64>>,elapsed:Duration){
    let mut delta=BTreeMap::new();
    if let(Some(before),Some(after))=(before,after){for(key,value)in after{if let Some(old)=before.get(key){delta.insert(key,value.saturating_sub(*old));}}}
    println!("native_fixture_cpu available={} elapsed_ms={} delta={}",before.is_some()&&after.is_some(),elapsed.as_millis(),serde_json::to_string(&delta).unwrap());
}

fn guarded_native_payload_bytes()->Result<u64> {
    #[cfg(all(feature="private-sparse",feature="private-stream"))]
    {Ok(porthub_agent::private_network::runtime::test_guarded_native_payload_bytes())}
    #[cfg(not(all(feature="private-sparse",feature="private-stream")))]
    {anyhow::bail!("guarded native observation requires sparse stream test build")}
}
async fn paired_native_tcp(role:&str)->Result<()> {
    use tokio::io::AsyncReadExt;
    use sha2::{Digest,Sha256};
    ensure!(cfg!(feature="private-sparse"),"native paired fixture requires sparse build");
    let target=std::env::var("PORTHUB_TEST_PEER_TARGET")?;
    let nonce=std::env::var("PORTHUB_TEST_FIXTURE_NONCE")?;
    ensure!(nonce.starts_with("porthub-exit-test-")&&nonce.len()<80,"fixture nonce missing");
    let seed=Sha256::digest(nonce.as_bytes());
    let started=std::time::Instant::now();let cpu_before=process_cpu_nanos();let callbacks_before=authority_callback_samples();
    fn progress(stage:&str,marker:&str,count:usize,started:std::time::Instant){println!("native_pair_progress stage={stage} marker={marker} bytes={count} elapsed_ms={}",started.elapsed().as_millis());}
    const BYTES:usize=256*1024;
    let before=guarded_native_payload_bytes()?;
    async fn control(command:&str)->Result<String> {
        let target=std::env::var("PORTHUB_TEST_CONTROL_TARGET")?;
        let(mut stream,_)=open(&target).await?;stream.get_mut().write_all(format!("{command}\n").as_bytes()).await?;
        let mut reply=String::new();tokio::time::timeout(Duration::from_secs(3),stream.read_line(&mut reply)).await??;Ok(reply.trim().into())
    }
    async fn send(stream:&mut TcpStream,seed:&[u8],sent:&mut usize,started:std::time::Instant,stage:&str)->Result<()> {
        progress(stage,"start",*sent,started);let mut block=[0;4096];
        while *sent<BYTES {
            for(i,b)in block.iter_mut().enumerate(){*b=seed[(*sent+i)%seed.len()]^((*sent+i)as u8);}
            let remaining=(BYTES-*sent).min(block.len());let n=stream.write(&block[..remaining]).await?;
            ensure!(n>0,"native paired write returned zero");let previous=*sent;*sent+=n;
            if previous/(64*1024)!=*sent/(64*1024){progress(stage,"boundary",*sent,started);}
        }
        progress(stage,"half-close-start",*sent,started);stream.shutdown().await?;progress(stage,"half-close-complete",*sent,started);Ok(())
    }
    async fn receive(stream:&mut TcpStream,seed:&[u8],received:&mut usize,started:std::time::Instant,stage:&str)->Result<()> {
        progress(stage,"start",*received,started);let mut block=[0;4096];
        while *received<BYTES {
            let remaining=(BYTES-*received).min(block.len());let n=stream.read(&mut block[..remaining]).await?;
            ensure!(n>0,"native paired payload ended early");
            ensure!(block[..n].iter().enumerate().all(|(i,b)|*b==seed[(*received+i)%seed.len()]^((*received+i)as u8)),"native paired payload mismatch");let previous=*received;*received+=n;
            if previous==0||previous/(64*1024)!=*received/(64*1024){progress(stage,"boundary",*received,started);}
        }
        progress(stage,"payload-complete",*received,started);
        let mut byte=[0;1];ensure!(stream.read(&mut byte).await?==0,"native paired half-close missing");progress(stage,"peer-eof",*received,started);Ok(())
    }
    let mut phase="starting";let mut sent=0usize;let mut received=0usize;
    let transaction=async {
    if role=="private-provider" {
        phase="bind";let listener=tokio::time::timeout(Duration::from_secs(60),async {
            loop {match tokio::net::TcpListener::bind(&target).await {
                Ok(listener)=>return Ok::<_,anyhow::Error>(listener),
                Err(error) if error.kind()==std::io::ErrorKind::AddrNotAvailable=>tokio::time::sleep(Duration::from_millis(100)).await,
                Err(error)=>return Err(error.into()),
            }}
        }).await.context("native peer address did not appear")??;
        phase="accept";let(mut stream,_)=tokio::time::timeout(Duration::from_secs(60),listener.accept()).await.context("native provider accept timeout")??;
        tokio::time::timeout(Duration::from_secs(30),async{phase="provider-receive";receive(&mut stream,&seed,&mut received,started,"provider-receive").await?;phase="provider-send";send(&mut stream,&seed,&mut sent,started,"provider-send").await}).await.context("native provider data transaction timeout")??;
        tokio::time::timeout(Duration::from_secs(30),async{loop {
            if control("native:consumer-done?").await?=="ready"{return Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(100)).await;
        }}).await.context("consumer did not verify native reply before provider shutdown")??;
    } else {
        phase="quic3-capability";tokio::time::timeout(Duration::from_secs(60),async {
            loop {
                if control("quic3:ready").await?=="ready"{return Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }).await.context("two native agents did not negotiate quic3-credit")??;
        phase="connect";let mut stream=tokio::time::timeout(Duration::from_secs(30),TcpStream::connect(&target)).await.context("native peer TCP443 connect failed")??;
        tokio::time::timeout(Duration::from_secs(30),async{phase="consumer-send";send(&mut stream,&seed,&mut sent,started,"consumer-send").await?;phase="consumer-receive";receive(&mut stream,&seed,&mut received,started,"consumer-receive").await}).await.context("native consumer data transaction timeout")??;
        ensure!(guarded_native_payload_bytes()?.saturating_sub(before)>=BYTES as u64,"native reply used no guarded stream delivery");
        ensure!(control("native:consumer-complete").await?=="updated","fixture completion not acknowledged");
    }
    Ok::<_,anyhow::Error>(())
    }.await;
    let observation=guarded_native_payload_bytes();
    println!("native_pair_phase={phase} elapsed_ms={} sent_bytes={sent} received_bytes={received} guarded_counter_available={} guarded_native_payload_delta={}",started.elapsed().as_millis(),observation.is_ok(),observation.as_ref().map(|value|value.saturating_sub(before)).unwrap_or(0));
    if let Some((before,after))=callbacks_before.zip(authority_callback_samples()) {
        println!("native_authority_callback calls={} sample_count={} sampled_ns={} sample_every=128",after.0.saturating_sub(before.0),after.1.saturating_sub(before.1),after.2.saturating_sub(before.2));
    }
    let cpu_delta=cpu_before.zip(process_cpu_nanos()).map(|(before,after)|after.saturating_sub(before));
    println!("native_pair_cpu available={} cpu_us={} elapsed_ms={}",cpu_delta.is_some(),cpu_delta.map(|value|value/1000).unwrap_or(0),started.elapsed().as_millis());
    transaction?;
    let delivered=guarded_native_payload_bytes()?.saturating_sub(before);
    ensure!(delivered>=BYTES as u64,"application succeeded without guarded native stream payload");
    println!("actual_guarded_native_payload_bytes={delivered} raw_fallback_excluded_by_counter=true");
    println!("actual_native_pair_memory_duplex=true bytes_each={BYTES} seeded_payload=true half_close=true role={role}");
    Ok(())
}

#[tokio::test]
#[ignore = "worker for verify-exit-network.py; disposable owned namespace only"]
async fn isolated_exit_worker() -> Result<()> {
    ensure!(std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1") && std::path::Path::new("/.dockerenv").is_file(), "requires owned test container");
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init();
    let cpu_start=std::time::Instant::now();let cpu_before=own_cgroup_cpu();
    let profile = std::env::var("PORTHUB_TEST_PROFILE")?;
    let private: porthub_agent::private_profile::Profile = serde_json::from_str(&profile)?;
    use sha2::{Digest, Sha256};
    let id = format!("{:x}", Sha256::digest(format!("private\n{}\n{}", private.server, private.peer_id).as_bytes()));
    let path = std::path::PathBuf::from(format!("/state/{id}.json"));
    porthub_agent::profile::write_private(&path, profile.as_bytes(), false)?;
    let role = std::env::var("PORTHUB_TEST_ROLE")?;
    if role.starts_with("private-")||role.starts_with("relay-origin-") {
        porthub_agent::private_network::strategy::save(&path,porthub_agent::private_network::strategy::Mode::PreferGateway)?;
    }
    let cancel = CancellationToken::new();
    let public_path = std::path::PathBuf::from("/state/profile.json");
    let unified = std::env::var("PORTHUB_TEST_PUBLIC_PROFILE").ok();
    let combined = unified.is_some();
    let runtime: std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>>>> = if let Some(public) = unified {
        porthub_agent::profile::write_private(&public_path, public.as_bytes(), false)?;
        porthub_agent::profile::write_private(&porthub_agent::profile::sibling(&public_path, ".private-module.json"),
            &serde_json::to_vec(&serde_json::json!({"format_version":1,"private_profile":path,"enabled":true}))?, false)?;
        Box::pin(porthub_agent::runtime::run(public_path.clone(), cancel.clone(), Default::default()))
    } else {
        Box::pin(porthub_agent::private_network::runtime::run(path.clone(), cancel.clone()))
    };
    tokio::pin!(runtime);
    // Real foreign firewall commits race the provider's initial exit setup.
    // The private runtime must stay alive and retry after the writer settles.
    // This worker only runs inside the explicitly owned disposable namespace.
    let churn = if role == "exit" {
        Some(tokio::spawn(async {
            use nlink::netlink::{nftables::Family, Connection, Nftables};
            let connection = Connection::<Nftables>::new()?;
            let until = tokio::time::Instant::now() + Duration::from_secs(5);
            while tokio::time::Instant::now() < until {
                connection.add_table("foreign_exit_test", Family::Ip).await?;
                connection.del_table("foreign_exit_test", Family::Ip).await?;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Ok::<_, anyhow::Error>(())
        }))
    } else { None };
    if role == "consumer" {
        // Internal Docker networks omit a default route. Supply a normal
        // underlay inside this disposable namespace to exercise opt-in bypass.
        use nlink::netlink::{Connection, Route, route::Ipv4Route};
        let connection = Connection::<Route>::new()?;
        let link = connection.get_link_by_name("eth0").await?.context("fixture underlay missing")?;
        connection.add_route(Ipv4Route::new(std::net::Ipv4Addr::UNSPECIFIED, 0)
            .gateway("198.18.10.1".parse()?).dev_index(link.ifindex())).await?;
        let (_, source) = open(&std::env::var("PORTHUB_TEST_TARGET")?).await.context("normal underlay preflight")?;
        ensure!(source == "198.18.10.2".parse::<IpAddr>()?, "fixture underlay source differs");
        println!("normal underlay verified before activating exit policy");
    }
    let result = if role=="private-provider"||role=="private-consumer" {
        tokio::select! {
            result=paired_native_tcp(&role)=>result,
            result=&mut runtime=>anyhow::bail!("agent stopped during native paired test: {result:?}"),
        }
    } else if role == "http-consumer" {
        tokio::select! {
            result = http_consumer() => result,
            result = &mut runtime => anyhow::bail!("agent stopped: {result:?}"),
        }
    } else if role=="relay-origin-consumer" {
        let target=std::env::var("PORTHUB_TEST_TARGET")?;
        tokio::select!{result=relay_origin_consumer(&target)=>result,result=&mut runtime=>anyhow::bail!("agent stopped during owned relay payload proof: {result:?}")}
    } else if role == "consumer" {
        let target = std::env::var("PORTHUB_TEST_TARGET")?;
        tokio::select! {
            result = consumer(&target) => result,
            result = &mut runtime => anyhow::bail!("agent stopped: {result:?}"),
        }
    } else {
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = terminate.recv() => Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(420)) => Ok(()),
            result = &mut runtime => anyhow::bail!("agent stopped: {result:?}"),
        }
    };
    let result = result.and_then(|()| {
        if combined {
            let public = porthub_agent::runtime::status(&public_path)?;
            let private = porthub_agent::runtime::status(&path)?;
            ensure!(public.pid == std::process::id() && private.pid == public.pid,
                "public and private packet runtimes do not share one process");
            ensure!(public.state == "running", "unified public control is unavailable");
            println!("one process verified for public control and private IP packet transport");
        }
        Ok(())
    });
    print_cgroup_cpu(cpu_before.as_ref(),own_cgroup_cpu().as_ref(),cpu_start.elapsed());
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), runtime).await??;
    if let Some(churn) = churn { churn.await??; }
    result
}


async fn http_consumer() -> Result<()> {
    let expected: Vec<IpAddr> = serde_json::from_str(&std::env::var("PORTHUB_TEST_EXIT_IPS")?)?;
    ensure!(expected.len() == 2 && expected[0] != expected[1], "test requires distinct exit addresses");
    let control = std::env::var("PORTHUB_TEST_CONTROL_URL")?;
    let key = std::env::var("PORTHUB_TEST_CONTROL_KEY")?;
    let probe = reqwest::Client::builder().no_proxy().pool_max_idle_per_host(0).timeout(Duration::from_secs(10)).build()?;
    let management = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(10)).build()?;
    async fn observed(client: &reqwest::Client) -> Result<IpAddr> {
        Ok(client.get("https://api4.ipify.org").send().await?.error_for_status()?.text().await?.trim().parse()?)
    }
    tokio::time::timeout(Duration::from_secs(120), async {
        let mut seen = std::collections::BTreeSet::new();
        loop {
            let netlink = nlink::netlink::Connection::<nlink::netlink::Route>::new()?;
            if netlink.get_rules_v4().await?.iter().any(|rule| rule.priority() == 22600) {
                if let Ok(ip) = observed(&probe).await {
                    ensure!(expected.contains(&ip), "unexpected exit identity");
                    seen.insert(ip);
                }
                if seen.len() == 2 { return Ok::<_, anyhow::Error>(()); }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }).await.context("both live exits did not become ready")??;
    println!("Both real exit addresses verified (addresses omitted)");
    for mode in ["round_robin", "sticky", "random"] {
        management.post(format!("{control}/_test/mode")).header("x-test-key", &key).json(&serde_json::json!({"mode":mode})).send().await?.error_for_status()?;
        wait_for_selection(mode).await?;
        let count = if mode == "random" { 16 } else { 8 };
        let mut counts = [0usize; 2];
        for _ in 0..count {
            let ip = observed(&probe).await?;
            let index = expected.iter().position(|candidate| *candidate == ip).context("unexpected exit identity")?;
            counts[index] += 1;
        }
        match mode {
            "round_robin" => ensure!(counts == [4,4], "round robin distribution mismatch: {counts:?}"),
            "sticky" => ensure!(counts.contains(&8), "sticky exit changed: {counts:?}"),
            _ => ensure!(counts.iter().all(|count| *count > 0), "random did not use both exits"),
        }
        println!("{mode}: verified connection distribution {counts:?}");
    }
    Ok(())
}
