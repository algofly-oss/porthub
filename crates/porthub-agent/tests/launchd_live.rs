//! Opt-in macOS user-domain lifecycle test. Only the disposable fixture label
//! is controlled; installed machine agents and system daemons are untouched.
#![cfg(target_os = "macos")]
mod common;
use anyhow::{ensure, Result};
use axum::{
    routing::{get, post},
    Json, Router,
};
use porthub_agent::{
    profile::Profile,
    service::{self, Action, Layout, Manager, Readiness, RuntimeReady, Spec},
};
use porthub_tunnel::{gateway_config, EmbeddedServer};
use serde_json::json;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore = "requires an authorized macOS user session and PORTHUB_TEST_LAUNCHD=1"]
async fn native_launchd_user_agent_forwards_restarts_stops_and_is_removed() -> Result<()> {
    ensure!(
        std::env::var("PORTHUB_TEST_LAUNCHD").as_deref() == Ok("1"),
        "explicit launchd test opt-in required"
    );
    let temp = common::private_dir()?;
    let root = temp.path().canonicalize()?;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_porthub"));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let local = echo_listener.local_addr()?;
    let echo = tokio::spawn(async move {
        let mut jobs = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                connection = echo_listener.accept() => {
                    let (mut stream, _) = connection.unwrap();
                    jobs.spawn(async move {
                        let (mut read, mut write) = stream.split();
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    });
                },
                _ = jobs.join_next(), if !jobs.is_empty() => {}
            }
        }
    });
    let reserve = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let public = reserve.local_addr()?;
    drop(reserve);
    let gateway = Arc::new(tokio::sync::RwLock::new(
        EmbeddedServer::new(gateway_config(&format!(
            "[server.services.launchd]\ntoken='launchd-fixture-secret'\nbind_addr='{public}'\n"
        ))?)
        .await?,
    ));
    let machine = format!(
        "{:024x}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    );
    let sync_id = machine.clone();
    let changes_id = machine.clone();
    let app = Router::new()
        .route("/api/machines/client/sync", post(move || {
            let id = sync_id.clone();
            async move { Json(json!({"data":{"config":{"machine_id":id,"version":"launchd-fixture-v1","files":{"client.toml":format!("[client]\nremote_addr='ws://{address}/api/tunnel'\n[client.services.launchd]\ntoken='launchd-fixture-secret'\nlocal_addr='{local}'\n")}}}})) }
        }))
        .route("/api/machines/client/changes.toml", get(move || {
            let id = changes_id.clone();
            async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                (axum::http::StatusCode::NO_CONTENT, [("x-porthub-machine-id", id), ("x-porthub-config-version", "launchd-fixture-v1".into())])
            }
        })).merge(porthub_edge::router(gateway.clone()));
    let api = tokio::spawn(async move { axum::serve(listener, app).await });
    let profile = Profile {
        format_version: 1,
        server: format!("http://{address}"),
        machine_id: machine,
        token: "launchd-fixture-secret".into(),
        account_email: None,
        fallback_servers: Vec::new(),
        setup_overrides: Default::default(),
        allow_insecure_http_for_tests: true,
    };
    let source = root.join("source.json");
    profile.save_new(&source)?;
    // XML metacharacters, spaces, dollar signs and percent signs must survive
    // as literal argv values instead of expansion or plist injection.
    let layout = Layout {
        user: true,
        state: root.join("config & \"quoted\"/native"),
        releases: root.join("releases %q $PORTHUB_UNSET_ENV"),
        units: root.join("LaunchAgents"),
    };
    let id = service::identity(&profile);
    let label = format!("porthub-{}", &id[..24]);
    let cleanup_spec = Spec {
        user: true,
        identity: id.clone(),
        service: label.clone(),
        profile: layout.state.join(format!("{id}.json")),
        executable: executable.clone(),
        unit: layout.units.join(format!("{label}.plist")),
        cli: None,
    };
    let manager = service::launchd::Launchd::connect(true).await?;
    let result = async {
        let spec = service::install(&layout, &source, &executable, &manager).await?;
        RuntimeReady.wait(&spec).await?;
        let first = porthub_agent::runtime::status(&spec.profile)?;
        ensure!(first.pid != std::process::id());
        let state = manager.state(&spec).await?;
        ensure!(state.installed && state.active && state.enabled);
        transfer(public).await?;
        service::action(&layout, &spec.profile, Action::Restart, &manager).await?;
        RuntimeReady.wait(&spec).await?;
        ensure!(porthub_agent::runtime::status(&spec.profile)?.pid != first.pid);
        transfer(public).await?;
        service::action(&layout, &spec.profile, Action::Stop, &manager).await?;
        ensure!(!manager.state(&spec).await?.active);
        ensure!(!porthub_agent::profile::Lease::running(&spec.profile)?);
        service::action(&layout, &spec.profile, Action::Start, &manager).await?;
        RuntimeReady.wait(&spec).await?;
        transfer(public).await?;
        service::action(
            &layout,
            &spec.profile,
            Action::Uninstall { purge: true },
            &manager,
        )
        .await?;
        let state = manager.state(&spec).await?;
        ensure!(!state.installed && !state.active && !state.enabled);
        ensure!(!spec.unit.exists() && !spec.profile.exists());
        anyhow::Ok(())
    }
    .await;
    // Always unload the one unique test label, even if an assertion failed.
    let stopped = manager.stop(&cleanup_spec).await;
    let disabled = manager.disable(&cleanup_spec).await;
    api.abort();
    echo.abort();
    gateway.write().await.shutdown().await;
    result?;
    stopped?;
    disabled?;
    Ok(())
}

async fn transfer(address: std::net::SocketAddr) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(mut connection) = tokio::net::TcpStream::connect(address).await {
                let payload = vec![0x69u8; 4 * 1024 * 1024];
                let mut received = vec![0u8; payload.len()];
                let attempt = tokio::time::timeout(Duration::from_secs(3), async {
                    let (mut read, mut write) = connection.split();
                    let (sent, got) =
                        tokio::join!(write.write_all(&payload), read.read_exact(&mut received));
                    sent?;
                    got?;
                    ensure!(received == payload);
                    anyhow::Ok(())
                })
                .await;
                if attempt.is_ok_and(|result| result.is_ok()) {
                    return anyhow::Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?
}
