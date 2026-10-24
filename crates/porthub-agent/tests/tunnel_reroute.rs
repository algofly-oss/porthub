#![cfg(unix)]
use anyhow::{ensure, Result};
use porthub_tunnel::{client_plan::ClientPlan, gateway_config, EmbeddedClient, EmbeddedServer};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
};

async fn exchange(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    stream.write_all(data).await?;
    let mut received = vec![0; data.len()];
    stream.read_exact(&mut received).await?;
    ensure!(received == data);
    Ok(())
}

async fn connected(public: std::net::SocketAddr) -> Result<TcpStream> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(mut stream) = TcpStream::connect(public).await {
                if matches!(
                    tokio::time::timeout(
                        Duration::from_millis(100),
                        exchange(&mut stream, b"ready")
                    )
                    .await,
                    Ok(Ok(()))
                ) {
                    return Ok(stream);
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?
}

async fn closed(stream: &mut TcpStream) -> Result<()> {
    let mut byte = [0];
    ensure!(
        !matches!(stream.read(&mut byte).await, Ok(n) if n > 0),
        "revoked generation still returned application data"
    );
    Ok(())
}

enum Revocation {
    ServerRemoval,
    ClientRemoval,
    TokenRotation,
}

async fn exercise(revocation: Revocation) -> Result<()> {
    let local = TcpListener::bind("127.0.0.1:0").await?;
    let local_address = local.local_addr()?;
    let echo = tokio::spawn(async move {
        while let Ok((mut stream, _)) = local.accept().await {
            tokio::spawn(async move {
                let (mut input, mut output) = stream.split();
                let _ = tokio::io::copy(&mut input, &mut output).await;
            });
        }
    });
    let reservation = TcpListener::bind("127.0.0.1:0").await?;
    let public = reservation.local_addr()?;
    drop(reservation);
    let gateway = Arc::new(RwLock::new(
        EmbeddedServer::new(gateway_config(&format!(
            "[server.services.echo]\nbind_addr='{public}'\ntoken='route-fixture'\n"
        ))?)
        .await?,
    ));
    let mut edges = Vec::new();
    let mut configs = Vec::new();
    for scheme in ["http", "ws", "http"] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let router = porthub_edge::router(gateway.clone());
        edges.push(tokio::spawn(
            async move { axum::serve(listener, router).await },
        ));
        configs.push(
            ClientPlan::parse(&format!(
                "[client]\nremote_addr='{scheme}://{address}/api/tunnel'\n\
             [client.services.echo]\nlocal_addr='{local_address}'\ntoken='route-fixture'\n"
            ))?
            .candidates
            .remove(0)
            .config,
        );
    }
    let mut client = EmbeddedClient::new(configs[0].clone()).await?;
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        let mut streams = vec![connected(public).await?];
        // A policy change cannot be disguised as a non-disruptive route switch.
        let mut foreign = configs[1].clone();
        foreign
            .client
            .as_mut()
            .unwrap()
            .services
            .get_mut("echo")
            .unwrap()
            .token = Some("foreign-token".into());
        ensure!(client.reroute(foreign).await.is_err());
        exchange(&mut streams[0], b"retained after rejected route update").await?;
        for (index, config) in configs.iter().enumerate().skip(1) {
            if index == 1 {
                // Authenticated configuration refreshes can change only the
                // endpoint too; ordinary reload must use the same drain path.
                client.reload(config.clone()).await?;
            } else {
                client.reroute(config.clone()).await?;
            }
            streams.push(connected(public).await?);
            let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
            for stream in &mut streams {
                exchange(stream, &payload).await?;
            }
        }
        match revocation {
            Revocation::ServerRemoval => {
                gateway
                    .write()
                    .await
                    .reload(gateway_config("[server.services]\n")?)
                    .await?;
            }
            Revocation::ClientRemoval => {
                let mut removed = configs[2].clone();
                removed.client.as_mut().unwrap().services.clear();
                client.reload(removed).await?;
            }
            Revocation::TokenRotation => {
                gateway
                    .write()
                    .await
                    .reload(gateway_config(&format!(
                    "[server.services.echo]\nbind_addr='{public}'\ntoken='rotated-route-fixture'\n"
                ))?)
                    .await?;
            }
        }
        for stream in &mut streams {
            closed(stream).await?;
        }
        anyhow::Ok(())
    })
    .await;
    client.shutdown().await;
    gateway.write().await.shutdown().await;
    for edge in edges {
        edge.abort();
    }
    echo.abort();
    result??;
    Ok(())
}

#[tokio::test]
async fn endpoint_changes_preserve_tcp_generations_and_server_revocation_closes_every_generation(
) -> Result<()> {
    exercise(Revocation::ServerRemoval).await
}

#[tokio::test]
async fn endpoint_changes_preserve_tcp_generations_and_client_removal_closes_every_generation(
) -> Result<()> {
    exercise(Revocation::ClientRemoval).await
}

#[tokio::test]
async fn server_token_rotation_closes_retired_and_current_tcp_generations() -> Result<()> {
    exercise(Revocation::TokenRotation).await
}
