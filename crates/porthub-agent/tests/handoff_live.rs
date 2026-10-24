//! Explicit opt-in; creates one disposable user/system transient service. No
//! actual PortHub registration, gateway or host network interface is changed.
#![cfg(all(target_os = "linux", feature = "handoff-service-test"))]
mod common;
use anyhow::{ensure, Context, Result};
use porthub_agent::service::{systemd::Systemd, Manager, Spec};
use serde_json::Value;
use std::{path::PathBuf, time::Duration};
use tokio::io::AsyncReadExt;
#[tokio::test]
#[ignore = "requires explicit user/system systemd handoff opt-in and development-only fixture"]
async fn real_transient_native_child_survives_caller_exit_with_literal_arguments() -> Result<()> {
    ensure!(
        std::env::var("PORTHUB_TEST_HANDOFF_SERVICE").as_deref() == Ok("1"),
        "explicit transient-service opt-in required"
    );
    let system = std::env::var("PORTHUB_TEST_HANDOFF_SYSTEM").as_deref() == Ok("1");
    ensure!(
        !system || rustix::process::getuid().is_root(),
        "system fixture needs authorized administrator execution"
    );
    let executable = PathBuf::from(
        std::env::var_os("PORTHUB_TEST_HANDOFF_EXECUTABLE")
            .context("build the development-only adoption_handoff example")?,
    );
    let root = common::private_dir()?;
    let directory = root.path().join("literal $PORTHUB_NATIVE_UNSET %q");
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(&executable)
            .arg(if system {
                "--system-caller"
            } else {
                "--caller"
            })
            .arg(&directory)
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    ensure!(
        output.status.success(),
        "native handoff caller failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let caller: Value = serde_json::from_slice(&output.stdout)?;
    let unit = caller["unit"].as_str().context("missing transient unit")?;
    ensure!(unit.starts_with("porthub-adoption-") && unit.ends_with(".service"));
    let manager = if system {
        Systemd::connect().await?
    } else {
        Systemd::connect_user().await?
    };
    let spec = Spec {
        cli: None,
        user: !system,
        identity: String::new(),
        service: unit.trim_end_matches(".service").into(),
        profile: directory.join("profile"),
        executable: executable.clone(),
        unit: directory.join("unused.service"),
    };
    let result = async {
        let proof: Value = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(bytes) = tokio::fs::read(directory.join("ready.json")).await {
                    if let Ok(proof) = serde_json::from_slice::<Value>(&bytes) {
                        break proof;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        let pid = proof["pid"].as_u64().context("missing child pid")?;
        ensure!(
            proof["pid"] != caller["caller_pid"]
                && !std::path::Path::new(&format!(
                    "/proc/{}",
                    caller["caller_pid"].as_u64().unwrap()
                ))
                .exists()
        );
        ensure!(std::path::Path::new(&format!("/proc/{pid}")).exists());
        ensure!(proof["cgroup"]
            .as_str()
            .is_some_and(|cgroup| cgroup.contains(unit)));
        ensure!(
            proof["arguments"][3] == directory.to_str().unwrap()
                && proof["arguments"][5] == "https://gateway.invalid/$PORTHUB_NATIVE_UNSET%q"
        );
        let mut stream = tokio::net::UnixStream::connect(directory.join("release.sock")).await?;
        let mut done = Vec::new();
        stream.read_to_end(&mut done).await?;
        ensure!(done == b"done");
        tokio::time::timeout(Duration::from_secs(5), async {
            while std::path::Path::new(&format!("/proc/{pid}")).exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        anyhow::Ok(())
    }
    .await;
    let _ = manager.stop(&spec).await;
    result
}
