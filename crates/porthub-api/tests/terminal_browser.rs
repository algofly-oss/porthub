#![cfg(unix)]
//! Real browser -> authenticated API routing -> bundled tmux PTYs. Only the
//! registered host transport is supplied by this fixture; no production data.
use anyhow::{ensure, Context, Result};
use futures_util::{SinkExt, StreamExt};
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{config::Config, terminal_grants};
use porthub_terminal::{
    host::Attachments,
    multiplexer::{create_directory, Start, Workspace},
    protocol::*,
};
use std::{path::PathBuf, time::Duration};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
};
mod support;
use support::Case;
struct Cleanup(Workspace);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.0.stop();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires isolated MongoDB, running UI, bundled runtime and Playwright"]
async fn anonymous_browser_and_machine_admin_share_real_shell_history_recovery_and_revocation(
) -> Result<()> {
    let ui = std::env::var("PORTHUB_TEST_UI_ORIGIN").context("set isolated UI origin")?;
    let fixture = tempfile::Builder::new()
        .prefix("phterm-browser-")
        .tempdir_in("/tmp")?;
    let cache = fixture.path().join("runtime");
    create_directory(&cache)?;
    let runtime = porthub_terminal::runtime::install(
        &std::fs::read(std::env::var("PORTHUB_TEST_TERMINAL_BUNDLE")?)?,
        &cache,
        &std::env::var("PORTHUB_TEST_TERMINAL_TARGET")?,
    )?;
    let path = fixture.path().join("workspace");
    create_directory(&path)?;
    let workspace = Workspace::open(runtime.executable, runtime.terminfo, path)?;
    let _cleanup = Cleanup(workspace.clone());
    workspace.start(&Start {
        cwd: fixture.path().into(),
        shell: PathBuf::from("/bin/sh"),
        command: vec![],
        environment: vec![
            ("ENV".into(), "".into()),
            ("BASH_ENV".into(), "".into()),
            ("PS1".into(), "porthub-test$ ".into()),
        ],
        history_limit: 100000,
        mouse: true,
        prefix: "C-a".into(),
        cols: 100,
        rows: 30,
    })?;
    let ssh_directory = fixture.path().join("ssh");
    create_directory(&ssh_directory)?;
    let ssh_socket = ssh_directory.join("gateway.sock");
    let ssh_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let ssh_port = ssh_listener.local_addr()?.port();
    let terminal = porthub_api::terminal::Settings {
        ssh_socket: Some(ssh_socket.clone()),
        host_key: ssh_directory.join("host_key"),
        ssh_host: "127.0.0.1".into(),
        ssh_port,
    };
    let case = Case::new(Config {
        terminal,
        ui_upstream: ui,
        ..Config::default()
    })
    .await?;
    terminal_grants::ensure_indexes(&case.app)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
    let ssh_app = case.app.clone();
    let cancel = tokio_util::sync::CancellationToken::new();
    let _ssh_server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        porthub_api::terminal::serve_ssh(ssh_app, cancel).await
    }));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if tokio::net::UnixStream::connect(&ssh_socket).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    let (_edge_stop, receiver) = tokio::sync::watch::channel(false);
    let _ssh_edge = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        porthub_edge::terminal::run(ssh_listener, ssh_socket, receiver).await
    }));
    let (owner, cookie) = case
        .user("terminal-browser-owner@example.test", "user")
        .await?;
    let machine = ObjectId::new();
    let credential = random_token(32);
    case.app
        .collection("machines")
        .insert_one(doc! {"_id":machine,"user_id":owner,"enabled":true,"token":&credential})
        .await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let router = case.router.clone();
    let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        axum::serve(listener, router).await
    }));
    let mut request = format!("{}/api/terminal/host", origin.replacen("http:", "ws:", 1))
        .into_client_request()?;
    request
        .headers_mut()
        .insert("x-porthub-machine-id", machine.to_hex().parse()?);
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {credential}").parse()?);
    let (mut socket, _) = connect_async(request).await?;
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
            max_viewers: 16,
        },
    };
    socket
        .send(Message::Text(serde_json::to_string(&hello)?.into()))
        .await?;
    let mut attachments = Attachments::new(workspace.clone(), 16)?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let message = socket.next().await.context("host closed")??;
            if let Message::Text(text) = message {
                let event: HostEvent = serde_json::from_str(&text)?;
                let ready = matches!(event, HostEvent::Ready { .. });
                attachments.apply(event)?;
                if ready {
                    break;
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    let workspace_state = workspace.clone();
    let host = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                message=socket.next()=>match message {
                    Some(Ok(Message::Text(text)))=>{if !attachments.apply(serde_json::from_str(&text)?)?{break;}},
                    Some(Ok(Message::Ping(_)|Message::Pong(_)))=>{},_=>break,
                },
                output=attachments.next()=>{let Some(output)=output else{break;};socket.send(Message::Text(serde_json::to_string(&output)?.into())).await?;},
                _=tick.tick()=>{if !workspace_state.is_alive(){socket.send(Message::Text(serde_json::to_string(&HostOutput::End)?.into())).await?;break;}},
            }
        }
        Ok::<_, anyhow::Error>(())
    }));
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../ui/tests/terminal-live.cjs");
    let mut command = tokio::process::Command::new("node");
    command
        .arg(script)
        .env("REVIEW_ORIGIN", &origin)
        .env("PORTHUB_TEST_TERMINAL_WRITE", &hello.write_token)
        .env("PORTHUB_TEST_TERMINAL_READ", &hello.read_token)
        .env("PORTHUB_TEST_TERMINAL_SESSION", &hello.id)
        .env("PORTHUB_TEST_TERMINAL_COOKIE", cookie)
        .env("PORTHUB_TEST_TERMINAL_SSH_PORT", ssh_port.to_string())
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(120), command.output()).await??;
    ensure!(
        output.status.success(),
        "browser flow failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{}", String::from_utf8_lossy(&output.stdout));
    tokio::time::timeout(Duration::from_secs(5), host).await???;
    ensure!(
        !workspace.is_alive(),
        "explicit shell exit must end workspace"
    );
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
    case.db.drop().await?;
    Ok(())
}
