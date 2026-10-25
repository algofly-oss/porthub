//! Explicit opt-in: creates and removes exactly one owned user service. Never
//! writes system units, asks for elevation or controls an existing service.
#![cfg(target_os = "linux")]
mod common;
use anyhow::{ensure, Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use porthub_agent::{
    profile::Profile,
    service::{self, systemd::Systemd, Layout, Manager, Spec},
};
use porthub_tunnel::{gateway_config, EmbeddedServer};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
const AUTO_REQUEST: &str = "native-auto-fixture-request-1";
struct AutoSignals {
    foreign: AtomicBool,
    requested: AtomicBool,
    acks: AtomicUsize,
    assets: AtomicUsize,
    unacked_new: AtomicBool,
    target: String,
    source: Mutex<Option<PathBuf>>,
}
impl AutoSignals {
    fn headers(&self) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        let pending =
            self.requested.load(Ordering::SeqCst) && self.acks.load(Ordering::SeqCst) == 0;
        headers.insert(
            "x-porthub-client-update-requested",
            if pending { "true" } else { "false" }.parse().unwrap(),
        );
        if pending {
            headers.insert(
                "x-porthub-client-update-request-id",
                AUTO_REQUEST.parse().unwrap(),
            );
            headers.insert(
                "x-porthub-client-target-version",
                self.target.parse().unwrap(),
            );
        }
        headers
    }
    fn observe(&self, body: &Value) -> Result<()> {
        let handled = body["client_update_last_handled_request_id"]
            .as_str()
            .unwrap_or("");
        if self.requested.load(Ordering::SeqCst)
            && body["client_version"] == self.target
            && handled.is_empty()
        {
            self.unacked_new.store(true, Ordering::SeqCst);
        }
        if !handled.is_empty() {
            ensure!(
                handled == AUTO_REQUEST && body["client_version"] == self.target,
                "wrong update acknowledgement"
            );
            let source = self
                .source
                .lock()
                .unwrap()
                .clone()
                .context("update source not installed")?;
            let index: Value = serde_json::from_slice(&std::fs::read(
                porthub_agent::profile::sibling(&source, ".update-commit.json"),
            )?)?;
            let journal: Value = serde_json::from_slice(&std::fs::read(
                source
                    .parent()
                    .unwrap()
                    .join(index["receipt"].as_str().unwrap())
                    .join("journal.json"),
            )?)?;
            ensure!(
                journal["state"] == "committed" && journal["request"]["id"] == AUTO_REQUEST,
                "acknowledged an uncommitted update"
            );
            self.acks.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
}
#[tokio::test]
#[ignore = "requires an isolated or explicitly authorized systemd user session; opt in with PORTHUB_TEST_USER_SERVICE=1"]
async fn actual_systemd_user_service_runs_native_agent_restarts_and_is_removed() -> Result<()> {
    ensure!(
        std::env::var("PORTHUB_TEST_USER_SERVICE").as_deref() == Ok("1"),
        "explicit user-service test opt-in required"
    );
    let temp = common::private_dir()?;
    let executable = PathBuf::from(
        std::env::var("PORTHUB_TEST_AGENT_EXECUTABLE")
            .context("provide the tested release agent executable")?,
    );
    let update_executable = std::env::var_os("PORTHUB_TEST_UPDATE_EXECUTABLE")
        .map(PathBuf::from)
        .unwrap_or_else(|| executable.clone());
    let update_output = tokio::process::Command::new(&update_executable)
        .arg("version")
        .kill_on_drop(true)
        .output()
        .await?;
    ensure!(
        update_output.status.success(),
        "update fixture must be a native executable"
    );
    let update_version = String::from_utf8(update_output.stdout)?
        .trim()
        .strip_prefix("porthub ")
        .context("native fixture version missing")?
        .to_owned();
    let update_bytes = axum::body::Bytes::from(tokio::fs::read(&update_executable).await?);
    use sha2::{Digest, Sha256};
    let update_hash = format!("{:x}", Sha256::digest(&update_bytes));
    let update_target = porthub_agent::update::native_target()?.to_owned();
    let reject_update = std::env::var("PORTHUB_TEST_UPDATE_REJECT_VERSION").as_deref() == Ok("1");
    let automatic = std::env::var("PORTHUB_TEST_AUTO_UPDATE").as_deref() == Ok("1");
    let signals = Arc::new(AutoSignals {
        foreign: AtomicBool::new(false),
        requested: AtomicBool::new(false),
        acks: AtomicUsize::new(0),
        assets: AtomicUsize::new(0),
        unacked_new: AtomicBool::new(false),
        target: update_version.clone(),
        source: Mutex::new(None),
    });
    ensure!(
        !reject_update || std::env::var_os("PORTHUB_TEST_UPDATE_EXECUTABLE").is_some(),
        "rejection fixture needs a distinct native version"
    );
    let machine = format!(
        "{:024x}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    );
    let syncs = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let local = target.local_addr()?;
    let echo = tokio::spawn(async move {
        let mut jobs = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                connection=target.accept()=>{let(mut stream,_)=connection.unwrap();jobs.spawn(async move{let(mut read,mut write)=stream.split();let _=tokio::io::copy(&mut read,&mut write).await;});},
                _=jobs.join_next(),if !jobs.is_empty()=>{},
            }
        }
    });
    let reserve = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let public = reserve.local_addr()?;
    drop(reserve);
    let gateway=Arc::new(tokio::sync::RwLock::new(EmbeddedServer::new(gateway_config(&format!("[server.services.lifecycle]\ntoken='local-service-fixture-secret'\nbind_addr='{public}'\n"))?).await?));
    let expected = machine.clone();
    let rejected = reject_update.then(|| update_version.clone());
    let sync_signals = signals.clone();
    let sync = post(
        move |State(calls): State<Arc<AtomicUsize>>, Json(body): Json<Value>| {
            let id = expected.clone();
            let rejected = rejected.clone();
            let signals = sync_signals.clone();
            async move {
                assert_eq!(body["machine_id"], id);
                calls.fetch_add(1, Ordering::SeqCst);
                signals.observe(&body).unwrap();
                if rejected
                    .as_ref()
                    .is_some_and(|version| body["client_version"] == *version)
                {
                    return StatusCode::FORBIDDEN.into_response();
                }
                let id = if signals.foreign.load(Ordering::SeqCst) {
                    "ffffffffffffffffffffffff".to_owned()
                } else {
                    id
                };
                (signals.headers(),Json(
                    json!({"data":{"config":{"machine_id":id,"version":"service-fixture-v1","files":{"client.toml":format!("[client]\nremote_addr='ws://{address}/api/tunnel'\n[client.services.lifecycle]\ntoken='local-service-fixture-secret'\nlocal_addr='{local}'\n")}}}}),
                )).into_response()
            }
        },
    );
    let expected = machine.clone();
    let change_signals = signals.clone();
    let changes = get(move || {
        let id = expected.clone();
        let signals = change_signals.clone();
        async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let id = if signals.foreign.load(Ordering::SeqCst) {
                "ffffffffffffffffffffffff".to_owned()
            } else {
                id
            };
            (
                signals.headers(),
                (
                    StatusCode::NO_CONTENT,
                    [
                        ("x-porthub-machine-id", id),
                        ("x-porthub-config-version", "service-fixture-v1".into()),
                    ],
                ),
            )
                .into_response()
        }
    });
    let bootstrap_machine = machine.clone();
    let release = json!({"target":update_target,"os":std::env::consts::OS,"arch":std::env::consts::ARCH,
        "asset":format!("porthub-{update_target}"),"version":update_version,"sha256":update_hash,"size":update_bytes.len(),
        "url":"https://unconfigured.invalid/never-follow-catalog-url"});
    let release_machine = machine.clone();
    let release_json = release.clone();
    let release_version = update_version.clone();
    let release_hash = update_hash.clone();
    let release_target = update_target.clone();
    let asset_signals = signals.clone();
    let app = Router::new()
        .route(&format!("/api/machines/{machine}/local-service-fixture-secret/downloads/releases"),get(move ||{
            let machine=release_machine.clone();let release=release_json.clone();async move {Json(json!({"format_version":1,"machine_id":machine,"releases":[release]}))}
        }))
        .route(&format!("/api/machines/{machine}/local-service-fixture-secret/downloads/agent/{update_target}"),get(move ||{
            let bytes=update_bytes.clone();let version=release_version.clone();let hash=release_hash.clone();let target=release_target.clone();
            asset_signals.assets.fetch_add(1,Ordering::SeqCst);
            async move {([("x-porthub-agent-release",version),("x-porthub-agent-sha256",hash),("x-porthub-agent-target",target)],bytes)}
        }))
        .route("/install/ServiceBootstrap",get(move |headers:axum::http::HeaderMap|{
            let id=bootstrap_machine.clone();async move {
                assert_eq!(headers["accept"],"application/json");
                ([("x-porthub-machine-id",id.clone())],Json(json!({"format_version":1,"profile":{
                    "format_version":1,"server":format!("http://{address}"),"machine_id":id,"token":"local-service-fixture-secret",
                    "fallback_servers":[],"setup_overrides":{"public_base_url":format!("http://{address}")},"allow_insecure_http_for_tests":false}})))
            }
        }))
        .route("/api/machines/client/sync", sync)
        .route("/api/machines/client/changes.toml", changes)
        .with_state(syncs.clone())
        .merge(porthub_edge::router(gateway.clone()));
    let api = tokio::spawn(async move { axum::serve(listener, app).await });
    let profile = Profile {
        format_version: 1,
        server: format!("http://{address}"),
        machine_id: machine,
        token: "local-service-fixture-secret".into(),
        account_email: None,
        setup_overrides: Default::default(),
        fallback_servers: vec![],
        allow_insecure_http_for_tests: true,
    };
    let source = temp.path().join("source.json");
    profile.save_new(&source)?;
    let root = temp.path().join("agent path %q $PORTHUB_UNSET_ENV");
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    }
    let layout = Layout {
        user: true,
        state: root.join("config \"quoted\"/porthub/native"),
        releases: root.join("data/porthub/releases"),
        units: root.join("config \"quoted\"/systemd/user"),
    };
    let id = service::identity(&profile);
    let key = format!("porthub-{}", &id[..24]);
    let cleanup_spec = Spec {
        cli: None,
        user: true,
        identity: id.clone(),
        service: key.clone(),
        profile: layout.state.join(format!("{id}.json")),
        unit: layout.units.join(format!("{key}.service")),
        executable: executable.clone(),
    };
    let manager = Systemd::connect_user().await?;
    let command = |verb: &str| {
        let mut command = tokio::process::Command::new(root.join("bin/porthub"));
        command
            .args([verb, "--user", &id[..12]])
            .env("XDG_CONFIG_HOME", root.join("config \"quoted\""))
            .env("XDG_DATA_HOME", root.join("data"))
            .kill_on_drop(true);
        command
    };
    let result = async {
        let output = tokio::process::Command::new(&executable)
            .args([
                "setup",
                "--user",
                "--ticket",
                &format!("http://{address}/install/ServiceBootstrap"),
                "--allow-insecure-http-for-tests",
                "--bin-dir",
                root.join("bin").to_str().unwrap(),
                "--profile",
            ])
            .arg(&source)
            .env("XDG_CONFIG_HOME", root.join("config \"quoted\""))
            .env("XDG_DATA_HOME", root.join("data"))
            .kill_on_drop(true)
            .output()
            .await?;
        ensure!(
            output.status.success(),
            "native CLI install failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        ensure!(!String::from_utf8_lossy(&output.stdout).contains("local-service-fixture-secret"));
        let spec: Spec = serde_json::from_slice(&std::fs::read(
            layout.state.join(format!("{id}.service.json")),
        )?)?;
        ensure!(std::fs::read_link(root.join("bin/porthub"))? == spec.executable);
        let version = tokio::process::Command::new(root.join("bin/porthub"))
            .arg("version")
            .output()
            .await?;
        ensure!(
            version.status.success()
                && String::from_utf8_lossy(&version.stdout).starts_with("porthub ")
        );
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if porthub_agent::runtime::status(&spec.profile).is_ok_and(|s| s.state == "running")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await?;
        let first = porthub_agent::runtime::status(&spec.profile)?;
        ensure!(first.pid != std::process::id() && syncs.load(Ordering::SeqCst) > 0);
        ensure!(std::fs::read_link(format!("/proc/{}/exe", first.pid))? == spec.executable);
        let status = manager.state(&spec).await?;
        ensure!(status.active && status.enabled);
        let listing = tokio::process::Command::new(root.join("bin/porthub"))
            .args(["ls", "--user", "--json"])
            .env("XDG_CONFIG_HOME", root.join("config \"quoted\""))
            .env("XDG_DATA_HOME", root.join("data"))
            .output()
            .await?;
        ensure!(listing.status.success());
        let entries: Value = serde_json::from_slice(&listing.stdout)?;
        ensure!(
            entries.as_array().unwrap().len() == 1
                && entries[0]["id"] == id
                && entries[0]["active"] == true
        );
        ensure!(
            !String::from_utf8_lossy(&listing.stdout).contains("local-service-fixture-secret")
                && !String::from_utf8_lossy(&listing.stdout).contains("127.0.0.1")
        );
        transfer(public).await?;
        let update_command = || {
            let mut command = tokio::process::Command::new(root.join("bin/porthub"));
            command
                .args(["update", "--user", "--profile"])
                .arg(&spec.profile)
                .arg("--bin-dir")
                .arg(root.join("bin"))
                .env("XDG_CONFIG_HOME", root.join("config \"quoted\""))
                .env("XDG_DATA_HOME", root.join("data"))
                .kill_on_drop(true);
            command
        };
        if automatic {
            *signals.source.lock().unwrap() = Some(spec.profile.clone());
            signals.foreign.store(true, Ordering::SeqCst);
            signals.requested.store(true, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(2)).await;
            ensure!(
                signals.assets.load(Ordering::SeqCst) == 0
                    && signals.acks.load(Ordering::SeqCst) == 0,
                "foreign machine configuration triggered a native update"
            );
            transfer(public).await?;
            signals.foreign.store(false, Ordering::SeqCst);
        } else {
            let checked = update_command().arg("--check").output().await?;
            ensure!(
                checked.status.success(),
                "native update check failed: {}",
                String::from_utf8_lossy(&checked.stderr)
            );
            let queued = update_command().output().await?;
            ensure!(
                queued.status.success(),
                "native update queue failed: {}",
                String::from_utf8_lossy(&queued.stderr)
            );
            ensure!(String::from_utf8_lossy(&queued.stdout).contains("porthub-update-"));
        }
        let receipt = tokio::time::timeout(
            Duration::from_secs(if reject_update {
                85
            } else if automatic {
                30
            } else {
                15
            }),
            async {
                loop {
                    for entry in std::fs::read_dir(&layout.state).unwrap().flatten() {
                        if !entry.file_name().to_string_lossy().starts_with("upgrade-") {
                            continue;
                        }
                        if let Ok(bytes) = std::fs::read(entry.path().join("journal.json")) {
                            if serde_json::from_slice::<Value>(&bytes).is_ok_and(|journal| {
                                journal["state"]
                                    == if reject_update {
                                        "rolled-back"
                                    } else {
                                        "committed"
                                    }
                            }) {
                                return entry.path();
                            }
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            },
        )
        .await?;
        if !reject_update {
            let updated: Spec = serde_json::from_slice(&std::fs::read(
                layout.state.join(format!("{id}.service.json")),
            )?)?;
            ensure!(
                updated.executable.parent().unwrap().file_name().unwrap() == update_hash.as_str()
            );
            ensure!(std::fs::read_link(root.join("bin/porthub"))? == updated.executable);
            let status = porthub_agent::runtime::status(&spec.profile)?;
            ensure!(status.state == "running" && status.agent_version == update_version);
            if updated.executable != spec.executable {
                ensure!(status.pid != first.pid);
            } else {
                ensure!(
                    status.pid == first.pid,
                    "an unchanged release restarted a healthy service"
                );
            }
            transfer(public).await?;
            if automatic {
                tokio::time::timeout(Duration::from_secs(8), async {
                    while signals.acks.load(Ordering::SeqCst) == 0 {
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                })
                .await?;
                ensure!(
                    signals.unacked_new.load(Ordering::SeqCst),
                    "new version acknowledged before its readiness/commit phase"
                );
                ensure!(
                    signals.assets.load(Ordering::SeqCst) == 1,
                    "duplicate downloads for a single native update request"
                );
            }
            let restored = tokio::process::Command::new(root.join("bin/porthub"))
                .args(["update", "--user", "--rollback"])
                .arg(&receipt)
                .env("XDG_CONFIG_HOME", root.join("config \"quoted\""))
                .env("XDG_DATA_HOME", root.join("data"))
                .kill_on_drop(true)
                .output()
                .await?;
            ensure!(
                restored.status.success(),
                "native update rollback failed: {}",
                String::from_utf8_lossy(&restored.stderr)
            );
        } else {
            let restored: Spec = serde_json::from_slice(&std::fs::read(
                layout.state.join(format!("{id}.service.json")),
            )?)?;
            ensure!(
                restored == spec,
                "failed readiness did not restore the prior service manifest"
            );
            if automatic {
                ensure!(
                    signals.acks.load(Ordering::SeqCst) == 0,
                    "rolled-back request was acknowledged"
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
                ensure!(
                    signals.assets.load(Ordering::SeqCst) == 1,
                    "rolled-back request retried automatically"
                );
            }
        }
        ensure!(std::fs::read_link(root.join("bin/porthub"))? == spec.executable);
        transfer(public).await?;
        ensure!(command("status").output().await?.status.success());
        ensure!(command("stop").output().await?.status.success());
        ensure!(!manager.state(&spec).await?.active);
        ensure!(command("start").output().await?.status.success());
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if porthub_agent::runtime::status(&spec.profile)
                    .is_ok_and(|s| s.state == "running" && s.pid != first.pid)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await?;
        ensure!(syncs.load(Ordering::SeqCst) >= 2);
        transfer(public).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let cleanup = async {
        let output = command("remove").output().await?;
        ensure!(
            output.status.success(),
            "native CLI cleanup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if cleanup.is_err() {
        let _ = manager.stop(&cleanup_spec).await;
        let _ = manager.disable(&cleanup_spec).await;
        let _ = manager.reload().await;
    }
    api.abort();
    echo.abort();
    gateway.write().await.shutdown().await;
    result?;
    cleanup?;
    ensure!(!cleanup_spec.unit.exists() && !cleanup_spec.profile.exists());
    ensure!(
        root.join("bin/porthub").exists(),
        "removing one service must preserve the interactive CLI"
    );
    let state = manager.state(&cleanup_spec).await?;
    ensure!(!state.active && !state.enabled && !state.installed);
    println!(
        "Verified native CLI bootstrap, independent update/rollback, user-service sync, 4 MiB forwarding, stop/start and scoped removal"
    );
    Ok(())
}

async fn transfer(public: std::net::SocketAddr) -> Result<()> {
    let mut stream = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(mut stream) = tokio::net::TcpStream::connect(public).await {
                let probe = async {
                    stream.write_all(&[0x17]).await?;
                    let mut byte = [0];
                    stream.read_exact(&mut byte).await?;
                    Ok::<bool, std::io::Error>(byte == [0x17])
                };
                if matches!(
                    tokio::time::timeout(Duration::from_millis(200), probe).await,
                    Ok(Ok(true))
                ) {
                    break stream;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    let payload: Vec<u8> = (0..4 * 1024 * 1024).map(|n| (n % 251) as u8).collect();
    let mut received = vec![0; payload.len()];
    let (mut read, mut write) = stream.split();
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(write.write_all(&payload), read.read_exact(&mut received))
    })
    .await??;
    ensure!(
        payload == received,
        "native OS service changed forwarded payload"
    );
    Ok(())
}
