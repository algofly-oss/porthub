#![cfg(target_os = "linux")]
//! Actual API/Mongo request -> installed native service -> independent update
//! worker -> API acknowledgement. Only one disposable user unit is modified.
mod support;
use anyhow::{ensure, Context, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_agent::{
    profile::Profile,
    service::{self, systemd::Systemd, Layout, Manager, Spec},
    update,
};
use porthub_api::config::Config;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Duration};
use support::Case;

#[tokio::test]
#[ignore = "requires isolated MongoDB, authorized user systemd, current agent and distinct update executable"]
async fn real_api_update_request_is_acknowledged_only_after_native_worker_commit() -> Result<()> {
    ensure!(
        std::env::var("PORTHUB_TEST_USER_SERVICE").as_deref() == Ok("1"),
        "explicit user service opt-in required"
    );
    let old = PathBuf::from(
        std::env::var_os("PORTHUB_TEST_AGENT_EXECUTABLE")
            .context("current native executable required")?,
    );
    let new = PathBuf::from(
        std::env::var_os("PORTHUB_TEST_UPDATE_EXECUTABLE")
            .context("distinct native update executable required")?,
    );
    let version = tokio::process::Command::new(&new)
        .arg("version")
        .kill_on_drop(true)
        .output()
        .await?;
    ensure!(version.status.success());
    let version = String::from_utf8(version.stdout)?
        .trim()
        .strip_prefix("porthub ")
        .context("native version missing")?
        .to_owned();
    let bytes = tokio::fs::read(&new).await?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let target = update::native_target()?;
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let bundle = root.path().join("bundle");
    std::fs::create_dir(&bundle)?;
    let asset = format!("porthub-{target}");
    std::fs::write(bundle.join(&asset), bytes)?;
    std::fs::write(bundle.join(format!("{asset}.version")), &version)?;
    std::fs::write(
        bundle.join(format!("{asset}.sha256")),
        format!("{digest}  {asset}\n"),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let case = Case::new(Config {
        public_base_url: base.clone(),
        client_version: version.clone(),
        client_binary_dir: Some(bundle),
        long_poll_timeout: Duration::from_secs(1),
        ..Config::default()
    })
    .await?;
    let (owner, cookie) = case
        .user("native-update-owner@test.invalid", "user")
        .await?;
    let id = ObjectId::new();
    let token = "native-api-update-private-token";
    case.app.collection("machines").insert_one(doc!{"_id":id,"user_id":owner,"name":"Native updater fixture","token":token,"enabled":true}).await?;
    let router = case.router.clone();
    let api = tokio::spawn(async move { axum::serve(listener, router).await });
    let profile = Profile {
        format_version: 1,
        server: base,
        machine_id: id.to_hex(),
        token: token.into(),
        setup_overrides: Default::default(),
        fallback_servers: vec![],
        allow_insecure_http_for_tests: true,
    };
    let source = root.path().join("source.json");
    profile.save_new(&source)?;
    let layout = Layout {
        user: true,
        state: root.path().join("config/porthub/native"),
        units: root.path().join("config/systemd/user"),
        releases: root.path().join("data/porthub/releases"),
    };
    let bin = root.path().join("bin");
    let cli = bin.join("porthub");
    let identity = service::identity(&profile);
    let manager = Systemd::connect_user().await?;
    let cleanup_spec = Spec {
        user: true,
        identity: identity.clone(),
        service: format!("porthub-{}", &identity[..24]),
        profile: layout.state.join(format!("{identity}.json")),
        unit: layout
            .units
            .join(format!("porthub-{}.service", &identity[..24])),
        executable: old.clone(),
        cli: Some(cli.clone()),
    };
    let result: Result<()> = async {
        let spec = service::install_published(&layout, &source, &old, &manager, Some(&cli)).await?;
        tokio::time::timeout(Duration::from_secs(10), async {
            while !porthub_agent::runtime::status(&spec.profile)
                .is_ok_and(|status| status.state == "running")
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await?;
        let original = porthub_agent::runtime::status(&spec.profile)?;
        ensure!(
            original.agent_version != version,
            "update fixture must use a distinct version"
        );
        let reply = case
            .status(
                "POST",
                "/api/machines/request-client-update",
                &cookie,
                json!({"data_id":id.to_hex()}),
                StatusCode::OK,
            )
            .await?;
        let request = reply["data"]["client_update_request_id"]
            .as_str()
            .context("API update request identity missing")?
            .to_owned();
        let mut saw_unacknowledged_new_version = false;
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                let machine = case
                    .app
                    .collection("machines")
                    .find_one(doc! {"_id":id})
                    .await?
                    .context("machine disappeared")?;
                let current = machine.get_str("client_version").unwrap_or("");
                let handled = machine
                    .get_str("client_update_last_handled_request_id")
                    .unwrap_or("");
                if current == version && handled != request {
                    saw_unacknowledged_new_version = true;
                }
                if handled == request {
                    ensure!(
                        current == version
                            && machine.get_str("client_update_target_version") == Ok("")
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            anyhow::Ok(())
        })
        .await??;
        ensure!(
            saw_unacknowledged_new_version,
            "new version was not observed before commit acknowledgement"
        );
        let running = porthub_agent::runtime::status(&spec.profile)?;
        ensure!(running.agent_version == version && running.pid != original.pid);
        let index: serde_json::Value = serde_json::from_slice(&std::fs::read(
            porthub_agent::profile::sibling(&spec.profile, ".update-commit.json"),
        )?)?;
        let receipt = layout.state.join(index["receipt"].as_str().unwrap());
        let journal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(receipt.join("journal.json"))?)?;
        ensure!(journal["state"] == "committed" && journal["request"]["id"] == request);
        let installed: Spec = serde_json::from_slice(&std::fs::read(
            layout.state.join(format!("{identity}.service.json")),
        )?)?;
        ensure!(
            installed.executable.parent().unwrap().file_name().unwrap() == digest.as_str()
                && std::fs::read_link(&cli)? == installed.executable
        );
        Ok(())
    }
    .await;
    let removed = service::action(
        &layout,
        &cleanup_spec.profile,
        service::Action::Uninstall { purge: true },
        &manager,
    )
    .await;
    if removed.is_err() {
        let _ = manager.stop(&cleanup_spec).await;
        let _ = manager.disable(&cleanup_spec).await;
        let _ = manager.reload().await;
    }
    api.abort();
    case.db.drop().await?;
    result?;
    removed?;
    Ok(())
}
