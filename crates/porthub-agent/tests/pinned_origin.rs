#![cfg(unix)]
use anyhow::{ensure, Result};
use axum::{
    extract::Request,
    middleware::{self, Next},
};
use porthub_tunnel::{client_plan::ClientPlan, gateway_config, EmbeddedServer};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
#[tokio::test]
async fn transport_probe_verifies_key_identity_and_canonical_host_before_http() -> Result<()> {
    let identity = rcgen::generate_simple_self_signed(vec!["origin.invalid".into()])?;
    let pin = porthub_identity::spki_sha256(identity.cert.der())?;
    let pin = pin
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let tls = axum_server::tls_rustls::RustlsConfig::from_der(
        vec![identity.cert.der().to_vec()],
        identity.signing_key.serialize_der(),
    )
    .await?;
    let server = Arc::new(tokio::sync::RwLock::new(
        EmbeddedServer::new(gateway_config("[server.services]\n")?).await?,
    ));
    let requests = Arc::new(AtomicUsize::new(0));
    let captured = requests.clone();
    let router = porthub_edge::router_with_web(
        server.clone(),
        None,
        Arc::new(porthub_runtime::web_routes::WebRoutes::with_gateway_hosts(
            ["porthub.example".into()],
        )),
    )
    .layer(middleware::from_fn(move |request: Request, next: Next| {
        let count = captured.clone();
        async move {
            assert_eq!(
                request.headers().get("host").and_then(|h| h.to_str().ok()),
                Some("porthub.example")
            );
            count.fetch_add(1, Ordering::SeqCst);
            next.run(request).await
        }
    }));
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let handle = axum_server::Handle::new();
    let serving = axum_server::from_tcp_rustls(listener, tls)?.handle(handle.clone());
    let task = tokio::spawn(async move { serving.serve(router.into_make_service()).await });
    for scheme in ["https", "wss"] {
        let text=format!("[client]\nremote_addr='wss://porthub.example/api/tunnel'\ndirect_addr='{scheme}://{address}/api/tunnel'\ndirect_spki_sha256='{pin}'\ndirect_host='porthub.example'\n[client.services]\n");
        let plan = ClientPlan::parse(&text)?;
        let origin = plan.candidates.last().unwrap();
        origin.probe(Duration::from_secs(2)).await?;
        let before = requests.load(Ordering::SeqCst);
        let wrong = text.replace(&pin, &"00".repeat(32));
        let plan = ClientPlan::parse(&wrong)?;
        ensure!(plan
            .candidates
            .last()
            .unwrap()
            .probe(Duration::from_secs(2))
            .await
            .is_err());
        ensure!(
            requests.load(Ordering::SeqCst) == before,
            "wrong-key probe reached HTTP before authentication"
        );
    }
    let unpinned =
        format!("[client]\nremote_addr='https://{address}/api/tunnel'\n[client.services]\n");
    ensure!(
        ClientPlan::parse(&unpinned)?.candidates[0]
            .probe(Duration::from_secs(2))
            .await
            .is_err(),
        "self-signed origin was trusted without its authenticated key pin"
    );
    handle.graceful_shutdown(Some(Duration::from_secs(1)));
    task.await??;
    server.write().await.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn https_authority_can_stream_through_an_explicit_http_origin_port() -> Result<()> {
    use porthub_tunnel::{client_plan::RouteKind, EmbeddedClient};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let local = echo.local_addr()?;
    let echo_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut input, mut output) = stream.split();
                let _ = tokio::io::copy(&mut input, &mut output).await;
            });
        }
    });
    let reservation = TcpListener::bind("127.0.0.1:0").await?;
    let public = reservation.local_addr()?;
    drop(reservation);
    let gateway = Arc::new(tokio::sync::RwLock::new(
        EmbeddedServer::new(gateway_config(&format!(
            "[server.services.echo]\nbind_addr='{public}'\ntoken='http-origin-fixture'\n"
        ))?)
        .await?,
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let origin = listener.local_addr()?;
    let requests = Arc::new(AtomicUsize::new(0));
    let captured = requests.clone();
    let router = porthub_edge::router_with_web(
        gateway.clone(),
        None,
        Arc::new(porthub_runtime::web_routes::WebRoutes::with_gateway_hosts(
            ["porthub.example".into()],
        )),
    )
    .layer(middleware::from_fn(move |request: Request, next: Next| {
        let count = captured.clone();
        async move {
            assert_eq!(request.uri().path(), "/api/tunnel");
            assert_eq!(request.headers()["host"], "porthub.example");
            count.fetch_add(1, Ordering::SeqCst);
            next.run(request).await
        }
    }));
    let edge = tokio::spawn(async move { axum::serve(listener, router).await });
    let plan = ClientPlan::parse(&format!(
        "[client]\nremote_addr='wss://porthub.example/api/tunnel'\n\
         direct_addr='http://{origin}/api/tunnel'\ndirect_host='porthub.example'\n\
         [client.services.echo]\ntoken='http-origin-fixture'\nlocal_addr='{local}'\n"
    ))?;
    // Probe only the operator-supplied origin. The canonical HTTPS authority
    // remains in the plan and is not contacted for this isolated stream check.
    let candidate = plan.candidates.last().unwrap();
    ensure!(candidate.kind == RouteKind::Origin);
    candidate.probe(Duration::from_secs(2)).await?;
    let client = EmbeddedClient::new(candidate.config.clone()).await?;
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = loop {
            let Ok(mut stream) = TcpStream::connect(public).await else {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            };
            let mut reply = [0; 5];
            if matches!(
                tokio::time::timeout(Duration::from_millis(200), async {
                    stream.write_all(b"ready").await?;
                    stream.read_exact(&mut reply).await
                })
                .await,
                Ok(Ok(_))
            ) && reply == *b"ready"
            {
                break stream;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let payload: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let (mut input, mut output) = stream.split();
        let send = async {
            output.write_all(&payload).await?;
            output.shutdown().await
        };
        let receive = async {
            let mut received = Vec::new();
            input.read_to_end(&mut received).await?;
            ensure!(
                received == payload,
                "HTTP origin stream lost or changed data"
            );
            anyhow::Ok(())
        };
        let (sent, received) = tokio::join!(send, receive);
        sent?;
        received?;
        ensure!(requests.load(Ordering::SeqCst) >= 3);
        anyhow::Ok(())
    })
    .await;
    client.shutdown().await;
    gateway.write().await.shutdown().await;
    edge.abort();
    echo_task.abort();
    result??;
    Ok(())
}
