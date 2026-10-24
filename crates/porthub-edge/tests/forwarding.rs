use anyhow::Result;
use porthub_tunnel::{gateway_config, EmbeddedServer};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{broadcast, RwLock},
};

// Exercise the actual upstream Rathole client against our embedded server over
// the same HTTP path used by the API. No standalone tunnel port is opened.
#[tokio::test]
async fn native_client_forwards_binary_data_on_shared_http_path() -> Result<()> {
    forwarding(false, false).await
}

#[tokio::test]
async fn framed_native_client_preserves_half_close_on_shared_http_path() -> Result<()> {
    forwarding(true, false).await
}

#[tokio::test]
async fn http_upgrade_client_preserves_half_close_on_shared_http_path() -> Result<()> {
    forwarding(true, true).await
}

async fn forwarding(framed: bool, direct: bool) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let local = TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = local.local_addr()?;
        let target = tokio::spawn(async move {
            let (mut stream, _) = local.accept().await?;
            let mut data = vec![0; 2 * 1024 * 1024];
            for _ in 0..2 {
                stream.read_exact(&mut data).await?;
                stream.write_all(&data).await?;
                stream.flush().await?;
            }
            let mut byte = [0];
            let result = stream.read(&mut byte).await;
            if framed {
                assert_eq!(result?, 0, "target did not receive request EOF");
                stream.write_all(b"response after EOF").await?;
                stream.shutdown().await?;
            }
            Ok::<_, anyhow::Error>(())
        });
        let reservation = TcpListener::bind("127.0.0.1:0").await?;
        let public_addr = reservation.local_addr()?;
        drop(reservation);
        let config = format!(
            r#"
[server.services.echo]
token = "test-secret"
bind_addr = "{public_addr}"
"#
        );
        let server = Arc::new(RwLock::new(
            EmbeddedServer::new(gateway_config(&config)?).await?,
        ));
        let http = TcpListener::bind("127.0.0.1:0").await?;
        let http_addr = http.local_addr()?;
        let router = porthub_edge::router(server.clone());
        let http_task = tokio::spawn(async move { axum::serve(http, router).await });
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("client.toml");
        tokio::fs::write(
            &path,
            format!(
                r#"
[client]
remote_addr = "{http_addr}"
retry_interval = 1
[client.transport]
type = "websocket"
[client.transport.websocket]
tls = false
path = "/api/tunnel"
porthub_framing = {framed}
http_upgrade = {direct}
[client.services.echo]
token = "test-secret"
local_addr = "{local_addr}"
"#
            ),
        )
        .await?;
        let (shutdown, _) = broadcast::channel(1);
        let client = tokio::spawn(rathole::run(
            rathole::Cli {
                config_path: Some(path),
                client: true,
                ..Default::default()
            },
            shutdown.subscribe(),
        ));
        let mut visitor = loop {
            match TcpStream::connect(public_addr).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        };
        let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        visitor.write_all(&payload).await?;
        let mut received = vec![0; payload.len()];
        visitor.read_exact(&mut received).await?;
        assert_eq!(received, payload);
        // An unchanged reload must leave the authenticated session operational.
        server
            .write()
            .await
            .reload(gateway_config(&config)?)
            .await?;
        visitor.write_all(&payload).await?;
        visitor.read_exact(&mut received).await?;
        assert_eq!(
            received, payload,
            "unchanged reload interrupted an active forward"
        );
        if framed {
            visitor.shutdown().await?;
            let mut response = Vec::new();
            visitor.read_to_end(&mut response).await?;
            assert_eq!(response, b"response after EOF");
        }
        // Removing the service revokes its control channel and public listener.
        if !framed {
            // Poll one close on this single-thread runtime, then cancel it
            // before its owned socket tasks can run. A retry must still await
            // that cleanup even though the service map is already updated.
            let mut guard = server.write().await;
            let mut interrupted = Box::pin(guard.reload(gateway_config("[server.services]\n")?));
            let pending = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(
                    std::future::Future::poll(interrupted.as_mut(), cx).is_pending(),
                )
            })
            .await;
            assert!(pending, "revocation did not exercise pending cleanup");
            drop(interrupted);
        }
        server
            .write()
            .await
            .reload(gateway_config("[server.services]\n")?)
            .await?;
        assert!(
            TcpStream::connect(public_addr).await.is_err(),
            "reload returned before the removed listener closed"
        );
        // bind is synchronous, so success cannot be hidden by the test yielding
        // to a detached listener task after reload returned prematurely.
        let rebound = tokio::net::TcpSocket::new_v4()?;
        rebound.set_reuseaddr(true)?;
        rebound.bind(public_addr)?;
        drop(rebound);
        let mut byte = [0];
        assert!(
            !matches!(visitor.read(&mut byte).await, Ok(n) if n > 0),
            "revoked forward still sends data"
        );
        let _ = shutdown.send(true);
        client.await??;
        target.await??;
        http_task.abort();
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn native_runner_reports_listener_startup_failure_to_its_owner() -> Result<()> {
    let occupied = TcpListener::bind("127.0.0.1:0").await?;
    let address = occupied.local_addr()?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("occupied.toml");
    tokio::fs::write(
        &path,
        format!("[server]\nbind_addr = \"{address}\"\n[server.services]\n"),
    )
    .await?;
    let (_shutdown, receiver) = broadcast::channel(1);
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        rathole::run(
            rathole::Cli {
                config_path: Some(path),
                server: true,
                ..Default::default()
            },
            receiver,
        ),
    )
    .await?;
    assert!(
        result.is_err(),
        "server startup failure was hidden by the runtime"
    );
    Ok(())
}
