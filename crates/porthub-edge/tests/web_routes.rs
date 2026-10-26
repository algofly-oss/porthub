use anyhow::{ensure, Result};
use axum::{body::Body, extract::Request, http::StatusCode, Router};
use porthub_runtime::web_routes::{Config, Route, WebRoutes};
use porthub_tunnel::{gateway_config, EmbeddedServer};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::RwLock,
    task::JoinSet,
};

#[tokio::test]
async fn edge_binary_reloads_atomic_web_configuration_without_idle_rescans() -> Result<()> {
    use std::io::Write;
    tokio::time::timeout(Duration::from_secs(12), async {
        let mut workers = JoinSet::new();
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let backend = target.local_addr()?;
        workers.spawn(async move {
            let _ = axum::serve(
                target,
                Router::new().fallback(|| async { "native web fixture" }),
            )
            .await;
        });
        let directory = tempfile::tempdir()?;
        let gateway = directory.path().join("gateway.toml");
        let web = directory.path().join("web-routes.json");
        std::fs::write(&gateway, "[server.services]\n")?;
        let config = Config {
            routes: vec![Route {
                id: "fixture".into(),
                hosts: vec!["docs.example".into()],
                target_url: format!("http://{backend}"),
                pass_host: true,
                http: true,
                https: true,
                access: None,
            }],
        };
        std::fs::write(&web, serde_json::to_vec(&config)?)?;
        let reservation = TcpListener::bind("127.0.0.1:0").await?;
        let address = reservation.local_addr()?;
        drop(reservation);
        let mut edge = tokio::process::Command::new(env!("CARGO_BIN_EXE_porthub-edge"))
            .arg("--config")
            .arg(&gateway)
            .arg("--listen")
            .arg(address.to_string())
            .env("PORTHUB_EDGE_TLS_LISTEN", "")
            .env("PORT_HUB_PUBLIC_BASE_URL", "https://gateway.example")
            .env_remove("PORTHUB_API_SOCKET")
            .env_remove("PORTHUB_WEB_ROUTES_CONFIG_PATH")
            .env_remove("PORT_HUB_FALLBACK_BASE_URLS")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let client = reqwest::Client::new();
        let url = format!("http://{address}/site");
        loop {
            if let Ok(response) = client.get(&url).header("host", "docs.example").send().await {
                if response.status() == StatusCode::OK {
                    ensure!(response.text().await? == "native web fixture");
                    break;
                }
            }
            ensure!(edge.try_wait()?.is_none(), "edge exited during startup");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        std::fs::write(&web, "invalid web configuration")?;
        tokio::time::sleep(Duration::from_millis(80)).await;
        ensure!(
            client
                .get(&url)
                .header("host", "docs.example")
                .send()
                .await?
                .status()
                == StatusCode::OK
        );
        let mut replacement = tempfile::NamedTempFile::new_in(directory.path())?;
        replacement.write_all(serde_json::to_string(&Config::default())?.as_bytes())?;
        replacement.persist(&web)?;
        loop {
            if client
                .get(&url)
                .header("host", "docs.example")
                .send()
                .await?
                .status()
                == StatusCode::NOT_FOUND
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        edge.kill().await?;
        edge.wait().await?;
        workers.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn custom_hosts_take_precedence_over_api_paths_and_reload_atomically() -> Result<()> {
    let mut workers = JoinSet::new();
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let address = target.local_addr()?;
    let upstream = Router::new().fallback(|request: Request| async move {
        format!(
            "{}|{}",
            request.headers()["host"].to_str().unwrap(),
            request.uri()
        )
    });
    workers.spawn(async move {
        let _ = axum::serve(target, upstream).await;
    });
    let web = Arc::new(WebRoutes::new(Some("gateway.example".into())));
    let route = Route {
        id: "fixture".into(),
        hosts: vec!["docs.example".into()],
        target_url: format!("http://{address}/base"),
        pass_host: true,
        http: true,
        https: true,
                access: None,
    };
    web.reload(Config {
        routes: vec![route.clone()],
    })?;
    let gateway = Arc::new(RwLock::new(
        EmbeddedServer::new(gateway_config("[server.services]\n")?).await?,
    ));
    let router = porthub_edge::listener_router(
        porthub_edge::router_with_web(gateway, None, web.clone()),
        false,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    workers.spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let client = reqwest::Client::new();
    let url = format!("http://{address}/api/tunnel?q=one");
    let response = client
        .get(&url)
        .header("host", "DOCS.EXAMPLE:8080")
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK
            && response.text().await? == "DOCS.EXAMPLE:8080|/base/api/tunnel?q=one"
    );
    let mut invalid = route.clone();
    invalid.target_url = "ftp://invalid.example".into();
    ensure!(web
        .reload(Config {
            routes: vec![invalid]
        })
        .is_err());
    ensure!(
        client
            .get(&url)
            .header("host", "docs.example")
            .send()
            .await?
            .status()
            == StatusCode::OK
    );
    let mut conflict = route.clone();
    conflict.id = "another".into();
    ensure!(web
        .reload(Config {
            routes: vec![route.clone(), conflict]
        })
        .is_err());
    let mut reserved = route.clone();
    reserved.hosts = vec!["gateway.example".into()];
    ensure!(web
        .reload(Config {
            routes: vec![reserved]
        })
        .is_err());
    let mut https_only = route.clone();
    https_only.http = false;
    web.reload(Config {
        routes: vec![https_only],
    })?;
    ensure!(
        client
            .get(&url)
            .header("host", "docs.example")
            .header("x-forwarded-proto", "https")
            .send()
            .await?
            .status()
            == StatusCode::NOT_FOUND
    );
    web.reload(Config::default())?;
    ensure!(
        client
            .get(format!("http://{address}/regular"))
            .header("host", "docs.example")
            .send()
            .await?
            .status()
            == StatusCode::NOT_FOUND
    );
    workers.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn mapped_websocket_upgrade_preserves_pipelined_bytes_and_half_close() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5),async {
        let mut workers=JoinSet::new();let target=TcpListener::bind("127.0.0.1:0").await?;let address=target.local_addr()?;
        let upstream=Router::new().fallback(|mut request:Request|async move {
            let upgrade=hyper::upgrade::on(&mut request);
            tokio::spawn(async move {if let Ok(stream)=upgrade.await {
                let mut stream=hyper_util::rt::TokioIo::new(stream);let mut bytes=Vec::new();
                stream.read_to_end(&mut bytes).await.unwrap();stream.write_all(&bytes).await.unwrap();stream.shutdown().await.unwrap();
            }});
            use axum::response::IntoResponse;
            (StatusCode::SWITCHING_PROTOCOLS,[("connection","Upgrade"),("upgrade","fixture.stream")],Body::empty()).into_response()
        });
        workers.spawn(async move {let _=axum::serve(target,upstream).await;});
        let web=Arc::new(WebRoutes::new(None));web.reload(Config {routes:vec![Route {id:"fixture".into(),hosts:vec!["socket.example".into()],target_url:format!("http://{address}"),pass_host:true,http:true,https:true,access:None}]})?;
        let gateway=Arc::new(RwLock::new(EmbeddedServer::new(gateway_config("[server.services]\n")?).await?));
        let router=porthub_edge::router_with_web(gateway,None,web);let listener=TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;
        workers.spawn(async move {let _=axum::serve(listener,router).await;});
        let mut connection=TcpStream::connect(address).await?;
        connection.write_all(b"GET /api/tunnel HTTP/1.1\r\nHost: socket.example\r\nConnection: Upgrade\r\nUpgrade: fixture.stream\r\n\r\npipelined payload").await?;
        let mut reader=BufReader::new(connection);let mut headers=String::new();
        while !headers.ends_with("\r\n\r\n") {ensure!(reader.read_line(&mut headers).await?>0);}
        ensure!(headers.starts_with("HTTP/1.1 101"));reader.get_mut().shutdown().await?;
        let mut body=Vec::new();reader.read_to_end(&mut body).await?;ensure!(body==b"pipelined payload");
        workers.shutdown().await;Ok::<_,anyhow::Error>(())
    }).await??;
    Ok(())
}
