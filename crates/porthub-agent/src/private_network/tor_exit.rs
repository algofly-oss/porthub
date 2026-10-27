//! Locally authorized, portless Tor exit adapter. No peer can address this
//! module through the mesh: only the local TUN owner's selected flows enter.
use super::{
    controller::Event,
    tcp_stream::{self, Flow},
};
use anyhow::Result;
use bytes::Bytes;
use porthub_egress::{tor::TorPool, Connector, Destination};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

pub const LOCAL_TOR: &str = "@local-tor";
const MAX_FLOWS: usize = 64;

pub(super) fn reconcile(
    current: &mut Option<LocalTor>,
    ui_groups: Option<usize>,
    settings: &super::tor_preferences::Settings,
    directory: &Path,
    interfaces: watch::Receiver<Vec<SocketAddr>>,
    events: mpsc::Sender<Event>,
    stop: CancellationToken,
) -> Result<()> {
    use super::tor_preferences::Mode;
    let enabled = match settings.mode {
        Mode::Auto => ui_groups.is_some(),
        Mode::Enabled => true,
        Mode::Disabled => false,
    };
    if !enabled {
        *current = None;
        return Ok(());
    }
    let groups = settings.circuit_groups.or(ui_groups).unwrap_or(4);
    if let Some(client) = current {
        client.set_groups(groups)?;
    } else {
        *current = Some(LocalTor::new(directory, groups, interfaces, events, stop)?);
    }
    Ok(())
}

pub struct LocalTor {
    stack: tcp_stream::Handle,
    pool: Arc<TorPool>,
    groups: usize,
    directory: PathBuf,
    sources: watch::Receiver<Vec<std::net::IpAddr>>,
    bootstrap_stop: CancellationToken,
    limit: Arc<Semaphore>,
    tasks: JoinSet<Result<()>>,
    stop: CancellationToken,
}
impl LocalTor {
    pub fn new(
        directory: &Path,
        groups: usize,
        mut interfaces: watch::Receiver<Vec<SocketAddr>>,
        events: mpsc::Sender<Event>,
        stop: CancellationToken,
    ) -> Result<Self> {
        let (sources, receiver) =
            watch::channel(interfaces.borrow().iter().map(SocketAddr::ip).collect());
        let pool =
            Arc::new(TorPool::new(directory, groups, MAX_FLOWS)?.with_underlay(receiver.clone()));
        let (stack, mut output, runner) = tcp_stream::exit_stack()?;
        let mut tasks = JoinSet::new();
        tasks.spawn(runner.run(stop.clone()));
        let cancelled = stop.clone();
        tasks.spawn(async move {
            loop { tokio::select! {
                _=cancelled.cancelled()=>break,
                result=interfaces.changed()=>{
                    if result.is_err(){break;}
                    sources.send_replace(interfaces.borrow_and_update().iter().map(SocketAddr::ip).collect());
                }
            }}
            Ok(())
        });
        let cancelled = stop.clone();
        tasks.spawn(async move {
            loop { tokio::select! {
                _=cancelled.cancelled()=>break,
                packet=output.recv()=>{
                    let Some(bytes)=packet else {break;};
                    tokio::select! {
                        _=cancelled.cancelled()=>break,
                        result=events.send(Event::TorLocal {bytes})=>{if result.is_err(){break;}}
                    }
                }
            }}
            Ok(())
        });
        let bootstrap_stop = stop.child_token();
        spawn_bootstrap(&mut tasks, pool.clone(), bootstrap_stop.clone());
        Ok(Self {
            stack,
            pool,
            groups,
            directory: directory.into(),
            sources: receiver,
            bootstrap_stop,
            limit: Arc::new(Semaphore::new(MAX_FLOWS)),
            tasks,
            stop,
        })
    }
    pub fn set_groups(&mut self, groups: usize) -> Result<()> {
        if groups == self.groups {
            return Ok(());
        }
        let pool = Arc::new(
            TorPool::new(&self.directory, groups, MAX_FLOWS)?.with_underlay(self.sources.clone()),
        );
        self.bootstrap_stop.cancel();
        self.bootstrap_stop = self.stop.child_token();
        spawn_bootstrap(&mut self.tasks, pool.clone(), self.bootstrap_stop.clone());
        // Existing streams retain their original pool and circuit. Only new
        // connections use the new group configuration after it is ready.
        self.pool = pool;
        self.groups = groups;
        Ok(())
    }
    pub fn resolver(&self) -> Arc<dyn porthub_egress::Resolver> {
        self.pool.clone()
    }
    pub fn ready(&self) -> bool {
        self.pool.ready()
    }
    pub fn owns(&self, bytes: &[u8]) -> bool {
        Flow::from_packet(bytes).is_some_and(|flow| self.stack.owns(flow))
    }
    pub fn packet(&mut self, bytes: Bytes) {
        while self.tasks.try_join_next().is_some() {}
        if self.owns(&bytes) {
            let _ = self.stack.packet(bytes);
            return;
        }
        let Some(packet) = super::policy::Packet::parse(&bytes) else {
            return;
        };
        if packet.opening_sequence().is_none() || !self.ready() {
            return;
        }
        let Ok(permit) = self.limit.clone().try_acquire_owned() else {
            return;
        };
        let stack = self.stack.clone();
        let pool = self.pool.clone();
        let stop = self.stop.clone();
        self.tasks.spawn(async move {
            let _permit=permit;
            let accepted=tokio::select! {_=stop.cancelled()=>return Ok(()),result=stack.accept_syn(bytes)=>result};
            let Ok((flow,mut application))=accepted else {return Ok(());};
            let connected=tokio::select! {
                _=stop.cancelled()=>return Ok(()),
                result=pool.connect(Destination::new(flow.destination.ip().to_string(),flow.destination.port())?)=>result
            };
            if let Ok(mut upstream)=connected {
                tokio::select! {_=stop.cancelled()=>{},_=tokio::io::copy_bidirectional(&mut application,&mut upstream)=>{}}
            }
            let _=stack.close(flow).await;
            Ok(())
        });
    }
}
impl Drop for LocalTor {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

fn spawn_bootstrap(
    tasks: &mut JoinSet<Result<()>>,
    bootstrap: Arc<TorPool>,
    cancelled: CancellationToken,
) {
    tasks.spawn(async move {
        let mut retry = Duration::from_secs(5);
        loop {
            tokio::select! {
                _=cancelled.cancelled()=>return Ok(()),
                result=bootstrap.bootstrap()=>{if result.is_ok(){return Ok(());}}
            }
            tokio::select! {_=cancelled.cancelled()=>return Ok(()),_=tokio::time::sleep(retry)=>{}}
            retry = (retry * 2).min(Duration::from_secs(60));
        }
    });
}

#[cfg(all(test,target_os="linux",feature="netns-tests"))]
mod live_tests {
    use super::*;
    use std::{collections::BTreeSet,net::{IpAddr,Ipv4Addr,SocketAddr},time::Instant};
    #[tokio::test]
    #[ignore="requires Tor network access and an explicitly owned disposable network namespace"]
    async fn transparent_https_uses_tor_and_fallback_changes_only_new_routes()->Result<()> {
        anyhow::ensure!(std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref()==Ok("1")
            && std::env::var("PORTHUB_TEST_LIVE_TOR").as_deref()==Ok("1")
            && std::path::Path::new("/.dockerenv").is_file(),"requires owned live-test container");
        let mut directory=tempfile::Builder::new();
        use std::os::unix::fs::PermissionsExt;
        directory.permissions(std::fs::Permissions::from_mode(0o700));
        let directory=directory.tempdir()?;
        let interfaces=super::super::interfaces::current().await?;
        let underlay:BTreeSet<Ipv4Addr>=interfaces.iter().filter_map(|address|match address.ip(){IpAddr::V4(ip)=>Some(ip),_=>None}).collect();
        anyhow::ensure!(!underlay.is_empty(),"test underlay is unavailable");
        let (_updates,sources)=watch::channel(interfaces);
        let (output,mut events)=mpsc::channel(1024);
        let stop=CancellationToken::new();
        let mut tor=LocalTor::new(directory.path(),4,sources,output,stop.clone())?;
        println!("Preparing embedded Tor inside the isolated namespace");
        tokio::time::timeout(Duration::from_secs(190),async {
            while !tor.ready(){tokio::time::sleep(Duration::from_millis(250)).await;}
        }).await?;
        let addresses=tor.resolver().resolve("check.torproject.org").await?;
        let destination=addresses.into_iter().find_map(|ip|match ip {IpAddr::V4(ip)=>Some(ip),_=>None}).ok_or_else(||anyhow::anyhow!("Tor did not resolve an IPv4 verification target"))?;
        let own=Ipv4Addr::new(10,234,251,1);
        let tun=super::super::device::Tun::open("phab12cd61",own,&[]).await?;
        tun.exit_mtu(true).await?;
        let mut routes=super::super::exit_routes::Consumer::activate(tun.index,own,&underlay).await?;
        println!("Ordinary application HTTPS is now routed through the owned TUN");
        let request=async {
            let http=reqwest::Client::builder().no_proxy().http1_only()
                .resolve("check.torproject.org",SocketAddr::new(destination.into(),443))
                .connect_timeout(Duration::from_secs(45)).timeout(Duration::from_secs(60)).build()?;
            let value:serde_json::Value=http.get("https://check.torproject.org/api/ip").send().await?.error_for_status()?.json().await?;
            anyhow::ensure!(value.get("IsTor").and_then(serde_json::Value::as_bool)==Some(true),"transparent connection did not use Tor");
            Ok::<_,anyhow::Error>(())
        };
        tokio::pin!(request);
        let mut packet=[0u8;porthub_mesh::MAX_PACKET];
        let mut sent=0usize;let mut received=0usize;
        let started=Instant::now();
        let result=loop {
            tokio::select! {
                result=&mut request=>break result,
                bytes=tun.read(&mut packet)=>{
                    let size=bytes?;sent+=size;tor.packet(Bytes::copy_from_slice(&packet[..size]));
                },
                event=events.recv()=>if let Some(Event::TorLocal{bytes})=event {
                    anyhow::ensure!(super::super::policy::Packet::parse(&bytes).is_some_and(|packet|packet.destination()==own),"Tor returned an unrelated packet");
                    received+=bytes.len();tun.write(&bytes).await?;
                },
            }
        };
        println!("Transparent transfer finished in {:.1}s; TUN bytes sent={sent}, received={received}",started.elapsed().as_secs_f64());
        result?;
        // Disabling the backend with fallback off leaves new TCP blocked in the
        // TUN; it must never escape through the physical default route.
        drop(tor);stop.cancel();
        let blocked=tokio::time::timeout(Duration::from_millis(500),tokio::net::TcpStream::connect((destination,443))).await;
        anyhow::ensure!(blocked.is_err(),"unavailable Tor unexpectedly bypassed the exit route");
        routes.set_bypass(true).await?;
        let direct=tokio::time::timeout(Duration::from_secs(5),tokio::net::TcpStream::connect((destination,443))).await??;
        anyhow::ensure!(direct.local_addr()?.ip()!=IpAddr::V4(own),"normal-internet fallback retained the overlay source");
        drop(direct);routes.clear().await?;drop(tun);
        println!("Fail-closed and explicit normal-internet fallback verified; owned routes cleaned");
        Ok(())
    }
}
