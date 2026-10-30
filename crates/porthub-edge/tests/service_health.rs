use anyhow::{ensure, Context, Result};
use porthub_tunnel::{gateway_config, Config, EmbeddedClient, EmbeddedServer};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{watch, RwLock},
    task::JoinSet,
};
async fn unused() -> Result<SocketAddr> {
    Ok(TcpListener::bind("127.0.0.1:0").await?.local_addr()?)
}
async fn exchange(stream: &mut TcpStream, byte: u8) -> Result<()> {
    let data = vec![byte; 128 * 1024];
    stream.write_all(&data).await?;
    let mut received = vec![0; data.len()];
    stream.read_exact(&mut received).await?;
    ensure!(data == received);
    Ok(())
}
struct Fixture {
    agent: EmbeddedClient,
    server: Arc<RwLock<EmbeddedServer>>,
    workers: JoinSet<()>,
    public: SocketAddr,
    controls: Arc<AtomicUsize>,
    block_control: watch::Sender<bool>,
    block_idle: watch::Sender<bool>,
}
impl Fixture {
    async fn new(reject_extension: bool) -> Result<Self> {
        let mut workers = JoinSet::new();
        let backend = TcpListener::bind("127.0.0.1:0").await?;
        let target = backend.local_addr()?;
        workers.spawn(async move {
            let mut copies = JoinSet::new();
            while let Ok((mut stream, _)) = backend.accept().await {
                copies.spawn(async move {
                    let (mut r, mut w) = stream.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
                while copies.try_join_next().is_some() {}
            }
        });
        let public = unused().await?;
        let server=Arc::new(RwLock::new(EmbeddedServer::new(gateway_config(&format!("[server]\nheartbeat_interval=1\n[server.services.fixture]\ntoken='health-fixture'\nbind_addr='{public}'\n"))?).await?));
        let gateway = TcpListener::bind("127.0.0.1:0").await?;
        let address = gateway.local_addr()?;
        let served = server.clone();
        workers.spawn(async move {
            let mut tasks = JoinSet::new();
            while let Ok((stream, _)) = gateway.accept().await {
                let work = served.read().await.accept(Box::new(stream));
                tasks.spawn(async move {
                    let _ = work.await;
                });
                while tasks.try_join_next().is_some() {}
            }
        });
        let proxy = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_address = proxy.local_addr()?;
        let controls = Arc::new(AtomicUsize::new(0));
        let seen = controls.clone();
        let (block_control, control) = watch::channel(false);
        let (block_idle, idle) = watch::channel(false);
        workers.spawn(async move {
            let mut tasks=JoinSet::new();
            while let Ok((mut incoming,_))=proxy.accept().await {
                let seen=seen.clone();let mut control=control.clone();let mut idle=idle.clone();let old_idle=!*idle.borrow();
                tasks.spawn(async move {
                    let run=async {
                        let mut hello=[0u8;37];incoming.read_exact(&mut hello).await?;
                        let kind=u32::from_le_bytes(hello[..4].try_into().unwrap());
                        if reject_extension && kind==2 {return Ok::<(),anyhow::Error>(());}
                        let mut outgoing=TcpStream::connect(address).await?;outgoing.write_all(&hello).await?;
                        if kind==0 || kind==2 {
                            let first=seen.fetch_add(1,Ordering::SeqCst)==0;
                            if first {tokio::select!{_=tokio::io::copy_bidirectional(&mut incoming,&mut outgoing)=>{},_=control.changed()=>{std::future::pending::<()>().await;}}}
                            else {let _=tokio::io::copy_bidirectional(&mut incoming,&mut outgoing).await;}
                        }else if old_idle && !reject_extension {
                            // Carry negotiated health commands transparently.
                            // After the test signal only previously idle carriers
                            // silently blackhole; an established copy stays live.
                            loop {
                                let mut command=[0u8;4];
                                tokio::select!{result=outgoing.read_exact(&mut command)=>{result?;},_=idle.changed()=>{std::future::pending::<()>().await;}}
                                incoming.write_all(&command).await?;
                                if u32::from_le_bytes(command)==2 {
                                    let mut ack=[0u8;4];incoming.read_exact(&mut ack).await?;outgoing.write_all(&ack).await?;continue;
                                }
                                let _=tokio::io::copy_bidirectional(&mut incoming,&mut outgoing).await;break;
                            }
                        }else {let _=tokio::io::copy_bidirectional(&mut incoming,&mut outgoing).await;}
                        Ok(())
                    };let _=run.await;
                });
                while tasks.try_join_next().is_some(){}
            }
        });
        let agent=EmbeddedClient::new(Config::from_str(&format!("[client]\nremote_addr='{proxy_address}'\nheartbeat_timeout=2\nretry_interval=1\n[client.services.fixture]\ntoken='health-fixture'\nlocal_addr='{target}'\n"))?).await?;
        Ok(Self {
            agent,
            server,
            workers,
            public,
            controls,
            block_control,
            block_idle,
        })
    }
    async fn connect(&self) -> Result<TcpStream> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(mut stream) = TcpStream::connect(self.public).await {
                    if exchange(&mut stream, 1).await.is_ok() {
                        return Ok::<_, anyhow::Error>(stream);
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?
    }
    async fn shutdown(mut self) {
        self.agent.shutdown().await;
        self.server.write().await.shutdown().await;
        self.workers.shutdown().await;
    }
}
#[tokio::test]
async fn healthy_checks_never_restart_a_serving_tunnel() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = Fixture::new(false).await?;
        let mut stream = fixture.connect().await?;
        let handle = fixture.agent.health_handles()["fixture"].clone();
        for byte in 2..40 {
            let health = handle.check();
            ensure!(health.state == "healthy" && health.data_health_acknowledged);
            exchange(&mut stream, byte).await?;
        }
        ensure!(
            fixture.controls.load(Ordering::SeqCst) == 1,
            "healthy checks restarted a control channel"
        );
        ensure!(handle.check().control_recoveries == 0);
        drop(stream);
        fixture.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
#[tokio::test]
async fn expired_control_recovers_without_stopping_established_data() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let fixture = Fixture::new(false).await?;
        let mut stream = fixture.connect().await?;
        let handle = fixture.agent.health_handles()["fixture"].clone();
        fixture.block_control.send_replace(true);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
        while fixture.controls.load(Ordering::SeqCst) < 2 {
            ensure!(
                tokio::time::Instant::now() < deadline,
                "stale control did not recover"
            );
            handle.check();
            exchange(&mut stream, 81).await?;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        exchange(&mut stream, 82).await?;
        let mut new = fixture.connect().await?;
        exchange(&mut new, 83).await?;
        ensure!(handle.check().control_recoveries > 0);
        drop(new);
        drop(stream);
        fixture.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
#[tokio::test]
async fn silently_stale_idle_pool_recovers_without_a_mapping_reset() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20),async {
        let fixture=Fixture::new(false).await?;let mut established=fixture.connect().await?;
        fixture.block_idle.send_replace(true);tokio::time::sleep(Duration::from_millis(100)).await;
        let mut visitor=TcpStream::connect(fixture.public).await?;
        let recovery=exchange(&mut visitor,61);tokio::pin!(recovery);
        loop {tokio::select!{result=&mut recovery=>{result.context("new visitor did not recover from stale idle carriers")?;break;},_=tokio::time::sleep(Duration::from_millis(50))=>{exchange(&mut established,62).await?;}}}
        ensure!(fixture.controls.load(Ordering::SeqCst)==1,"data recovery restarted healthy control");exchange(&mut established,63).await?;
        drop(established);fixture.shutdown().await;Ok::<_,anyhow::Error>(())
    }).await??;
    Ok(())
}
#[tokio::test]
async fn new_agent_falls_back_to_the_legacy_gateway_handshake() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = Fixture::new(true).await?;
        let mut stream = fixture.connect().await?;
        let handle = fixture.agent.health_handles()["fixture"].clone();
        let health = handle.check();
        ensure!(health.state == "healthy" && !health.data_health_acknowledged);
        exchange(&mut stream, 91).await?;
        ensure!(fixture.controls.load(Ordering::SeqCst) == 1);
        drop(stream);
        fixture.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
