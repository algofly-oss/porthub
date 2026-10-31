use anyhow::{ensure, Result};
use futures_util::{SinkExt, StreamExt};
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{config::Config, terminal_grants};
use porthub_terminal::protocol::*;
use std::time::Duration;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
    MaybeTlsStream, WebSocketStream,
};
mod support;
use support::Case;
type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
async fn receive(socket: &mut Socket) -> Result<serde_json::Value> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let message = socket
                .next()
                .await
                .ok_or_else(|| anyhow::anyhow!("socket closed"))??;
            if let Message::Text(text) = message {
                let value: serde_json::Value = serde_json::from_str(&text)?;
                if value["type"] == "ping" {
                    socket
                        .send(Message::Text("{\"type\":\"pong\"}".into()))
                        .await?;
                    continue;
                }
                return Ok(value);
            }
        }
    })
    .await?
}
async fn event(socket: &mut Socket, kind: &str) -> Result<serde_json::Value> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let value = receive(socket).await?;
            if value["type"] == kind {
                return Ok(value);
            }
        }
    })
    .await?
}
async fn send(socket: &mut Socket, value: impl serde::Serialize) -> Result<()> {
    socket
        .send(Message::Text(serde_json::to_string(&value)?.into()))
        .await?;
    Ok(())
}
async fn join(base: &str, token: &str, resume: bool) -> Result<(Socket, String, u64)> {
    let (mut socket, _) = connect_async(format!("{base}/api/terminal/join")).await?;
    send(
        &mut socket,
        if resume {
            serde_json::json!({"resume_token":token,"cols":80,"rows":24})
        } else {
            serde_json::json!({"token":token,"cols":80,"rows":24})
        },
    )
    .await?;
    let recovery = event(&mut socket, "recovery").await?;
    let raw = recovery["token"].as_str().unwrap().to_owned();
    let identity = recovery["participant"].as_u64().unwrap();
    event(&mut socket, "welcome").await?;
    Ok((socket, raw, identity))
}

#[tokio::test]
#[ignore = "requires isolated MongoDB"]
async fn actual_websocket_recovery_survives_invite_expiry_and_host_kick_revokes_only_one_guest(
) -> Result<()> {
    let case = Case::new(Config::default()).await?;
    terminal_grants::ensure_indexes(&case.app)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
    let (owner, owner_cookie) = case.user("terminal-socket@example.test", "user").await?;
    let machine = ObjectId::new();
    let credential = random_token(32);
    case.app
        .collection("machines")
        .insert_one(doc! {"_id":machine,"user_id":owner,"enabled":true,"token":&credential})
        .await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut base = format!("ws://{}", listener.local_addr()?);
    let router = case.router.clone();
    let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        axum::serve(listener, router).await
    }));
    let request = format!("{base}/api/terminal/host");
    ensure!(
        connect_async(&request).await.is_err(),
        "machine authorization required"
    );
    let mut request = request.into_client_request()?;
    request
        .headers_mut()
        .insert("x-porthub-machine-id", machine.to_hex().parse()?);
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {credential}").parse()?);
    let (mut host, _) = connect_async(request).await?;
    let hello = HostHello {
        id: random_token(16),
        secret: random_token(32),
        write_token: random_token(32),
        read_token: random_token(32),
        options: Options {
            name: "amberotter".into(),
            expires_at: now() + 2,
            session_expires_at: None,
            idle_timeout: 0,
            reconnect_timeout: 60,
            history_limit: 100000,
            mouse: true,
            read_only: false,
            size_policy: SizePolicy::Smallest,
            access: Access::Both,
            max_viewers: 16,
        },
    };
    send(&mut host, &hello).await?;
    event(&mut host, "ready").await?;
    let (mut reader, recovery, identity) = join(&base, &hello.read_token, false).await?;
    let first_attach = event(&mut host, "attach").await?;
    ensure!(first_attach["read_only"] == true);
    let first = first_attach["client"].as_u64().unwrap();
    let (mut writer, writer_recovery, _) = join(&base, &hello.write_token, false).await?;
    let writer_attach = event(&mut host, "attach").await?;
    let writer_client = writer_attach["client"].as_u64().unwrap();
    reader.close(None).await?;
    drop(reader);
    while now() <= hello.options.expires_at {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (mut expired, _) = connect_async(format!("{base}/api/terminal/join")).await?;
    send(
        &mut expired,
        serde_json::json!({"token":hello.read_token,"cols":80,"rows":24}),
    )
    .await?;
    event(&mut expired, "closed").await?;
    let (mut resumed, same, restored) = join(&base, &recovery, true).await?;
    ensure!(same == recovery && restored == identity);
    let attach = event(&mut host, "attach").await?;
    let client = attach["client"].as_u64().unwrap();
    ensure!(client != first && attach["read_only"] == true);
    send(&mut host, HostOutput::Closed { client: first }).await?;
    send(
        &mut host,
        HostOutput::Output {
            client,
            data: encode_data(b"recovered-output"),
        },
    )
    .await?;
    ensure!(
        decode_data(
            event(&mut resumed, "output").await?["data"]
                .as_str()
                .unwrap()
        )? == b"recovered-output"
    );
    send(
        &mut resumed,
        ViewerInput::History {
            request: 77,
            pane: "%0".into(),
            before: 0,
            lines: 200,
        },
    )
    .await?;
    let capture = event(&mut host, "history").await?;
    ensure!(capture["client"].as_u64() == Some(client) && capture["request"] == 77);
    send(
        &mut host,
        HostOutput::History {
            client,
            page: HistoryChunk {
                request: 77,
                data: encode_data(b"read-only-scrollback"),
                done: true,
                total: 100,
                before: 0,
                lines: 1,
                truncated: false,
                error: None,
            },
        },
    )
    .await?;
    let capture = event(&mut resumed, "history").await?;
    ensure!(decode_data(capture["page"]["data"].as_str().unwrap())? == b"read-only-scrollback");
    send(&mut host, HostOutput::RevokeInvitations).await?;
    event(&mut host, "invitations_revoked").await?;
    case.status(
        "POST",
        &format!("/api/terminal/{}/invitations/revoke", hello.id),
        &owner_cookie,
        serde_json::json!({}),
        axum::http::StatusCode::OK,
    )
    .await?;
    ensure!(case
        .app
        .terminals
        .sessions()
        .iter()
        .find(|s| s.id == hello.id)
        .unwrap()
        .invitations_revoked());
    send(&mut host, HostOutput::Kick { client: identity }).await?;
    ensure!(event(&mut resumed, "closed").await?["reason"] == "removed by the host");
    let (mut rejected, _) = connect_async(format!("{base}/api/terminal/join")).await?;
    send(
        &mut rejected,
        serde_json::json!({"resume_token":recovery,"cols":80,"rows":24}),
    )
    .await?;
    let closed = event(&mut rejected, "closed").await?;
    ensure!(closed["retryable"] == false);
    send(
        &mut host,
        HostOutput::Output {
            client: writer_client,
            data: encode_data(b"writer-uninterrupted"),
        },
    )
    .await?;
    ensure!(
        decode_data(
            event(&mut writer, "output").await?["data"]
                .as_str()
                .unwrap()
        )? == b"writer-uninterrupted"
    );
    // Rebuild the API's in-memory hub against the same isolated database.
    // The original invitation is expired, but the writer's recovery grant lives.
    case.app
        .terminals
        .disconnect(&hello.id, "gateway restarting");
    ensure!(event(&mut writer, "closed").await?["retryable"] == true);
    event(&mut host, "reconnect").await?;
    drop(_server);
    let restarted = std::sync::Arc::new(porthub_api::App::new(Config::default(), case.db.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    base = format!("ws://{}", listener.local_addr()?);
    let router = porthub_api::router(restarted.clone());
    let _restarted_server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        axum::serve(listener, router).await
    }));
    let mut request = format!("{base}/api/terminal/host").into_client_request()?;
    request
        .headers_mut()
        .insert("x-porthub-machine-id", machine.to_hex().parse()?);
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {credential}").parse()?);
    let (mut replacement, _) = connect_async(request).await?;
    send(&mut replacement, &hello).await?;
    ensure!(
        event(&mut replacement, "ready").await?["invitations_revoked"] == true,
        "invitation revocation must survive API restart"
    );
    let (mut writer_after_restart, _, _) = join(&base, &writer_recovery, true).await?;
    let attach = event(&mut replacement, "attach").await?;
    send(
        &mut replacement,
        HostOutput::Output {
            client: attach["client"].as_u64().unwrap(),
            data: encode_data(b"api-restart-recovered"),
        },
    )
    .await?;
    ensure!(
        decode_data(
            event(&mut writer_after_restart, "output").await?["data"]
                .as_str()
                .unwrap()
        )? == b"api-restart-recovered"
    );
    ensure!(
        terminal_grants::resume(&restarted, &recovery)
            .await
            .is_err(),
        "guest revocation must survive API restart"
    );
    host = replacement;
    send(&mut host, HostOutput::End).await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if case
                .app
                .collection("terminal_sessions")
                .find_one(doc! {"_id":&hello.id,"state":"ended"})
                .await?
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    ensure!(terminal_grants::resume(&case.app, &writer_recovery)
        .await
        .is_err());
    drop(writer_after_restart);
    drop(writer);
    drop(resumed);
    drop(host);
    drop(expired);
    drop(rejected);
    case.db.drop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB; checks real 45-second liveness deadline"]
async fn nonresponsive_peers_release_live_slots_but_keep_bounded_recovery() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    terminal_grants::ensure_indexes(&case.app)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
    let (owner, _) = case.user("terminal-liveness@example.test", "user").await?;
    let machine = ObjectId::new();
    let credential = random_token(32);
    case.app
        .collection("machines")
        .insert_one(doc! {"_id":machine,"user_id":owner,"enabled":true,"token":&credential})
        .await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("ws://{}", listener.local_addr()?);
    let router = case.router.clone();
    let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        axum::serve(listener, router).await
    }));
    let mut request = format!("{base}/api/terminal/host").into_client_request()?;
    request
        .headers_mut()
        .insert("x-porthub-machine-id", machine.to_hex().parse()?);
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {credential}").parse()?);
    let (mut host, _) = connect_async(request).await?;
    let hello = HostHello {
        id: random_token(16),
        secret: random_token(32),
        write_token: random_token(32),
        read_token: random_token(32),
        options: Options {
            name: "amberotter".into(),
            expires_at: 0,
            session_expires_at: None,
            idle_timeout: 0,
            reconnect_timeout: 60,
            history_limit: 100000,
            mouse: true,
            read_only: false,
            size_policy: SizePolicy::Smallest,
            access: Access::Both,
            max_viewers: 1,
        },
    };
    send(&mut host, &hello).await?;
    event(&mut host, "ready").await?;
    let (browser, recovery, identity) = join(&base, &hello.read_token, false).await?;
    let session = case
        .app
        .terminals
        .sessions()
        .into_iter()
        .find(|session| session.id == hello.id)
        .unwrap();
    ensure!(session.participants() == 1);
    let started = tokio::time::Instant::now();
    // Hold the TCP connection open without processing pings or sending pongs.
    tokio::time::timeout(Duration::from_secs(52), async {
        while session.participants() != 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    ensure!(
        started.elapsed() >= Duration::from_secs(40),
        "an idle but valid connection must not be dropped early"
    );
    ensure!(
        !session.stop.is_cancelled(),
        "a dead browser must not end the shared workspace"
    );
    ensure!(
        case.app.terminals.resolve(&hello.write_token).is_err(),
        "the unresponsive host must also lose its live transport"
    );
    let mut request = format!("{base}/api/terminal/host").into_client_request()?;
    request
        .headers_mut()
        .insert("x-porthub-machine-id", machine.to_hex().parse()?);
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {credential}").parse()?);
    let (mut host_reconnected, _) = connect_async(request).await?;
    send(&mut host_reconnected, &hello).await?;
    event(&mut host_reconnected, "ready").await?;
    let (replacement, _, same) = join(&base, &recovery, true).await?;
    ensure!(
        same == identity && session.participants() == 1,
        "recovery must restore the guest after reclaiming its slot"
    );
    drop(browser);
    drop(replacement);
    case.app.terminals.end(&hello.id, "fixture ended");
    drop(host_reconnected);
    drop(host);
    drop(_server);
    case.db.drop().await?;
    Ok(())
}
