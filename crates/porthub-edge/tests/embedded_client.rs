use anyhow::{ensure, Result};
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
    sync::RwLock,
    task::JoinSet,
};

struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
async fn echo(listener: TcpListener, active: Arc<AtomicUsize>) {
    let mut tasks = JoinSet::new();
    loop {
        while tasks.try_join_next().is_some() {}
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        active.fetch_add(1, Ordering::SeqCst);
        let guard = Active(active.clone());
        tasks.spawn(async move {
            let _guard = guard;
            let (mut read, mut write) = stream.into_split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });
    }
}
async fn unused() -> Result<SocketAddr> {
    Ok(TcpListener::bind("127.0.0.1:0").await?.local_addr()?)
}
async fn exchange(stream: &mut TcpStream, value: u8) -> Result<()> {
    let payload = vec![value; 128 * 1024];
    stream.write_all(&payload).await?;
    let mut received = vec![0; payload.len()];
    stream.read_exact(&mut received).await?;
    ensure!(received == payload);
    Ok(())
}
async fn closed(stream: &mut TcpStream) -> Result<()> {
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut [0])).await?;
    ensure!(
        !matches!(result,Ok(n) if n>0),
        "removed service remained usable"
    );
    Ok(())
}
fn client(http: SocketAddr, targets: &[(String, SocketAddr)]) -> Result<Config> {
    Config::from_str(&client_text(http, targets))
}
fn client_text(http: SocketAddr, targets: &[(String, SocketAddr)]) -> String {
    let mut content=format!("[client]\nremote_addr=\"{http}\"\n[client.transport]\ntype=\"websocket\"\n[client.transport.websocket]\ntls=false\npath=\"/api/tunnel\"\nporthub_framing=true\nhttp_upgrade=true\n[client.services]\n");
    for (name, address) in targets {
        content += &format!(
            "[client.services.{name}]\ntoken=\"fixture-secret\"\nlocal_addr=\"{address}\"\n"
        );
    }
    content
}

#[tokio::test]
async fn memory_reload_preserves_unchanged_streams_and_removes_only_revoked_services() -> Result<()>
{
    tokio::time::timeout(Duration::from_secs(15),async {
        let active=Arc::new(AtomicUsize::new(0));let mut workers=JoinSet::new();
        let mut targets=Vec::new();let mut public=Vec::new();let mut server_config=String::from("[server.services]\n");
        for name in ["first","second"] {
            let listener=TcpListener::bind("127.0.0.1:0").await?;targets.push((name.into(),listener.local_addr()?));
            workers.spawn(echo(listener,active.clone()));let address=unused().await?;public.push(address);
            server_config+=&format!("[server.services.{name}]\ntoken=\"fixture-secret\"\nbind_addr=\"{address}\"\n");
        }
        let server=Arc::new(RwLock::new(EmbeddedServer::new(gateway_config(&server_config)?).await?));
        let http=TcpListener::bind("127.0.0.1:0").await?;let address=http.local_addr()?;
        let router=porthub_edge::router(server.clone());workers.spawn(async move {let _=axum::serve(http,router).await;});
        let initial=client(address,&targets[..1])?;let mut agent=EmbeddedClient::new(initial.clone()).await?;
        let mut first=loop {match TcpStream::connect(public[0]).await {Ok(stream)=>break stream,Err(_)=>tokio::time::sleep(Duration::from_millis(10)).await}};
        exchange(&mut first,17).await?;ensure!(active.load(Ordering::SeqCst)==1);
        agent.reload(initial).await?;exchange(&mut first,18).await?;
        agent.reload(client(address,&targets)?).await?;exchange(&mut first,19).await?;
        let mut second=loop {match TcpStream::connect(public[1]).await {Ok(stream)=>break stream,Err(_)=>tokio::time::sleep(Duration::from_millis(10)).await}};
        exchange(&mut second,43).await?;ensure!(active.load(Ordering::SeqCst)==2);
        let invalid=Config::from_str(&format!("[client]\nremote_addr=\"{address}\"\n[client.services]\n[client.transport]\ntype=\"tls\"\n[client.transport.tls]\ntrusted_root=\"/nonexistent/porthub-test-invalid-root.pem\"\n"))?;
        ensure!(agent.reload(invalid).await.is_err());exchange(&mut first,20).await?;exchange(&mut second,44).await?;
        agent.reload(client(address,&targets[1..])?).await?;closed(&mut first).await?;exchange(&mut second,45).await?;
        agent.shutdown().await;closed(&mut second).await?;
        for _ in 0..100 {if active.load(Ordering::SeqCst)==0 {break;}tokio::time::sleep(Duration::from_millis(5)).await;}
        ensure!(active.load(Ordering::SeqCst)==0,"agent shutdown left target connections open");
        let abandoned=EmbeddedClient::new(client(address,&targets[1..])?).await?;
        let mut connection=loop {
            if let Ok(mut stream)=TcpStream::connect(public[1]).await {
                if exchange(&mut stream,91).await.is_ok() {break stream;}
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        drop(abandoned);closed(&mut connection).await?;
        server.write().await.reload(gateway_config("[server.services]\n")?).await?;workers.shutdown().await;
        Ok::<_,anyhow::Error>(())
    }).await??;
    Ok(())
}

#[tokio::test]
async fn shutdown_interrupts_control_connection_backoff() -> Result<()> {
    let address = unused().await?;
    let config=Config::from_str(&format!("[client]\nremote_addr=\"{address}\"\nretry_interval=3600\n[client.services.fixture]\ntoken=\"fixture\"\nlocal_addr=\"127.0.0.1:1\"\n"))?;
    let agent = EmbeddedClient::new(config).await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    tokio::time::timeout(Duration::from_millis(300), agent.shutdown()).await?;
    Ok(())
}

#[tokio::test]
async fn udp_forwarders_stop_with_their_owning_client() -> Result<()> {
    use tokio::net::UdpSocket;
    tokio::time::timeout(Duration::from_secs(10),async {
        let backend=UdpSocket::bind("127.0.0.1:0").await?;let target=backend.local_addr()?;
        let reserve=UdpSocket::bind("127.0.0.1:0").await?;let public=reserve.local_addr()?;drop(reserve);
        let count=Arc::new(AtomicUsize::new(0));let observed=count.clone();let mut workers=JoinSet::new();
        workers.spawn(async move {let mut bytes=[0;4096];while let Ok((n,source))=backend.recv_from(&mut bytes).await {
            observed.fetch_add(1,Ordering::SeqCst);let _=backend.send_to(&bytes[..n],source).await;
        }});
        let server=Arc::new(RwLock::new(EmbeddedServer::new(gateway_config(&format!("[server.services.fixture]\ntoken=\"fixture\"\ntype=\"udp\"\nbind_addr=\"{public}\"\n"))?).await?));
        let http=TcpListener::bind("127.0.0.1:0").await?;let address=http.local_addr()?;
        let router=porthub_edge::router(server.clone());workers.spawn(async move {let _=axum::serve(http,router).await;});
        let config=Config::from_str(&format!("[client]\nremote_addr=\"{address}\"\n[client.transport]\ntype=\"websocket\"\n[client.transport.websocket]\ntls=false\npath=\"/api/tunnel\"\nporthub_framing=true\nhttp_upgrade=true\n[client.services.fixture]\ntoken=\"fixture\"\ntype=\"udp\"\nlocal_addr=\"{target}\"\n"))?;
        let agent=EmbeddedClient::new(config.clone()).await?;
        let visitor=UdpSocket::bind("127.0.0.1:0").await?;visitor.connect(public).await?;
        let mut packet=[0;4096];
        loop {
            let _=visitor.send(b"before shutdown").await;
            if let Ok(Ok(n))=tokio::time::timeout(Duration::from_millis(50),visitor.recv(&mut packet)).await {
                ensure!(&packet[..n]==b"before shutdown");break;
            }
        }
        agent.shutdown().await;
        // Drain any packets sent during the startup retry above, then ensure
        // a new payload cannot reach the backend through a detached UDP task.
        while let Ok(Ok(_))=tokio::time::timeout(Duration::from_millis(20),visitor.recv(&mut packet)).await {}
        let previous=count.load(Ordering::SeqCst);let _=visitor.send(b"after shutdown").await;
        let response=tokio::time::timeout(Duration::from_millis(150),visitor.recv(&mut packet)).await;
        ensure!(!matches!(response,Ok(Ok(_))),"UDP forwarder outlived its client");
        ensure!(count.load(Ordering::SeqCst)==previous,"detached UDP forwarder still reached the target");
        // Reconnect and revoke on the server side while UDP forwarding is live.
        // No test sleep may hide socket release after reload acknowledges it.
        let agent=EmbeddedClient::new(config).await?;
        loop {
            let _=visitor.send(b"before revoke").await;
            if let Ok(Ok(n))=tokio::time::timeout(Duration::from_millis(50),visitor.recv(&mut packet)).await {
                if &packet[..n]==b"before revoke" {break;}
            }
        }
        server.write().await.reload(gateway_config("[server.services]\n")?).await?;
        let rebound=std::net::UdpSocket::bind(public)?;drop(rebound);
        agent.shutdown().await;workers.shutdown().await;
        Ok::<_,anyhow::Error>(())
    }).await??;
    Ok(())
}

#[tokio::test]
async fn file_runner_handles_atomic_replacement_and_retains_services_on_invalid_edits() -> Result<()>
{
    tokio::time::timeout(Duration::from_secs(12), async {
        use std::io::Write;
        let mut workers = JoinSet::new();
        let active = Arc::new(AtomicUsize::new(0));
        let backend = TcpListener::bind("127.0.0.1:0").await?;
        let target = backend.local_addr()?;
        workers.spawn(echo(backend, active));
        let public = unused().await?;
        let server = Arc::new(RwLock::new(
            EmbeddedServer::new(gateway_config(&format!(
                "[server.services.fixture]\ntoken=\"fixture-secret\"\nbind_addr=\"{public}\"\n"
            ))?)
            .await?,
        ));
        let http = TcpListener::bind("127.0.0.1:0").await?;
        let address = http.local_addr()?;
        let router = porthub_edge::router(server.clone());
        workers.spawn(async move {
            let _ = axum::serve(http, router).await;
        });
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("client.toml");
        let original = client_text(address, &[("fixture".into(), target)]);
        std::fs::write(&path, &original)?;
        let (stop, done) = tokio::sync::oneshot::channel::<()>();
        let (finished, result) = tokio::sync::oneshot::channel();
        let watched = path.clone();
        workers.spawn(async move {
            let outcome = porthub_tunnel::run_client_until(watched, async {
                let _ = done.await;
            })
            .await;
            let _ = finished.send(outcome);
        });
        let mut visitor = loop {
            match TcpStream::connect(public).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        };
        exchange(&mut visitor, 12).await?;
        std::fs::write(&path, "[client this is invalid")?;
        tokio::time::sleep(Duration::from_millis(80)).await;
        exchange(&mut visitor, 13).await?;
        let mut replacement = tempfile::NamedTempFile::new_in(directory.path())?;
        replacement.write_all(client_text(address, &[]).as_bytes())?;
        replacement.persist(&path)?;
        closed(&mut visitor).await?;
        std::fs::write(&path, &original)?;
        let mut resumed = loop {
            if let Ok(mut stream) = TcpStream::connect(public).await {
                if exchange(&mut stream, 14).await.is_ok() {
                    break stream;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let _ = stop.send(());
        tokio::time::timeout(Duration::from_secs(1), result).await???;
        closed(&mut resumed).await?;
        server
            .write()
            .await
            .reload(gateway_config("[server.services]\n")?)
            .await?;
        workers.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn locked_public_port_and_hostname_proxy_share_enforcement() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        use axum::{body::Body, http::{Request, StatusCode}, routing::any, Router};
        use porthub_runtime::web_routes::{Config as WebConfig, Route, WebRoutes};
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let target_address = target.local_addr()?;
        let app = Router::new().fallback(any(move |request: Request<Body>| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                assert!(!request.headers().contains_key("x-porthub-key"));
                "protected response"
            }
        }));
        let mut workers = JoinSet::new();
        workers.spawn(async move { let _ = axum::serve(target, app).await; });
        let public = unused().await?;
        let verifier = bcrypt::hash("123456", 10)?;
        let configuration = format!("[server.services.fixture]\ntoken=\"fixture-secret\"\nbind_addr=\"{public}\"\n[server.services.fixture.access]\nverifier=\"{verifier}\"\npin=true\n");
        let gateway = Arc::new(RwLock::new(EmbeddedServer::new(gateway_config(&configuration)?).await?));
        let web = Arc::new(WebRoutes::new(None));
        // Machine proxies target the protected public listener, so there is
        // one authoritative gate and no second credential-stripping gate.
        web.reload(WebConfig { routes: vec![Route { id: "protected".into(), hosts: vec!["protected.example".into()], target_url: format!("http://{public}"), pass_host: true, http: true, https: true, access: None }] })?;
        let ingress = TcpListener::bind("127.0.0.1:0").await?;
        let address = ingress.local_addr()?;
        let router = porthub_edge::router_with_web(gateway.clone(), None, web);
        workers.spawn(async move { let _ = axum::serve(ingress, router).await; });
        let agent = EmbeddedClient::new(client(address, &[("fixture".into(), target_address)])?).await?;
        loop {
            if TcpStream::connect(public).await.is_ok() { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;
        for (url, host) in [(format!("http://{public}/"), None), (format!("http://{address}/"), Some("protected.example"))] {
            let mut request = http.get(&url);
            if let Some(host) = host { request = request.header("host", host); }
            ensure!(request.send().await?.status() == StatusCode::UNAUTHORIZED);
            let mut request = http.get(&url).header("x-porthub-key", "123456");
            if let Some(host) = host { request = request.header("host", host); }
            let response = request.send().await?;
            ensure!(response.status() == StatusCode::OK);
            ensure!(response.text().await? == "protected response");
        }
        ensure!(hits.load(Ordering::SeqCst) == 2);
        agent.shutdown().await;
        gateway.write().await.shutdown().await;
        workers.shutdown().await;
        Ok::<_, anyhow::Error>(())
    }).await??;
    Ok(())
}
