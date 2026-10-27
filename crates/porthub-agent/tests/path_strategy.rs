#![cfg(unix)]
use anyhow::{Context,Result};
use porthub_agent::{
    private_network::strategy::{self, Mode, Settings},
    private_profile::Profile,
    profile,
};
use std::{path::Path, process::Command, time::Duration};
use tokio_util::sync::CancellationToken;

fn fixture(directory: &Path) -> Result<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    let path = directory.join("private profile.json");
    let value = Profile {
        server: "https://gateway.example".into(),
        workspace: "0123456789abcdef01234567".into(),
        peer_id: "0123456789abcdef01234567:abcdef0123456789abcdef01".into(),
        token: "private-credential-never-shown-in-output".into(),
        account_email: None,
        fallback_servers: vec![],
        allow_insecure_http_for_tests: false,
    };
    profile::write_private(&path, &serde_json::to_vec(&value)?, false)?;
    Ok(path)
}
fn cli(path: &Path, args: &[&str]) -> Result<serde_json::Value> {
    let output = Command::new(env!("CARGO_BIN_EXE_porthub"))
        .arg("path")
        .args(args)
        .arg("--profile")
        .arg(path)
        .arg("--json")
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout)?;
    assert!(!text.contains("private-credential"));
    assert!(!text.contains("gateway.example"));
    Ok(serde_json::from_str(&text)?)
}

#[test]
fn cli_overrides_persist_reset_to_defaults_and_preserve_enrollment() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = fixture(directory.path())?;
    let before = std::fs::read(&path)?;
    let shown = cli(&path, &["show"])?;
    assert_eq!(shown["mode"], "auto");
    assert_eq!(shown["source"], "default");
    for mode in ["prefer-direct", "prefer-gateway", "auto"] {
        assert_eq!(cli(&path, &["set", mode])?["mode"], mode);
        let shown = cli(&path, &["show"])?;
        assert_eq!(shown["mode"], mode);
        assert_eq!(shown["source"], "override");
    }
    for _ in 0..2 {
        assert_eq!(cli(&path, &["reset"])?["mode"], "auto");
        assert_eq!(cli(&path, &["show"])?["source"], "default");
    }
    assert!(!strategy::path(&path).exists());
    assert_eq!(std::fs::read(&path)?, before);
    let output = Command::new(env!("CARGO_BIN_EXE_porthub"))
        .args(["path", "set", "invalid", "--profile"])
        .arg(&path)
        .output()?;
    assert!(!output.status.success());
    assert!(!strategy::path(&path).exists());
    Ok(())
}

#[tokio::test]
async fn background_control_reloads_atomic_overrides_and_retains_last_good_setting() -> Result<()> {
    let _=tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE).with_test_writer().try_init();
    let directory = tempfile::tempdir()?;
    let path = fixture(directory.path())?;
    let (updates, mut current) = tokio::sync::watch::channel(Mode::PreferGateway);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(strategy::run(path.clone(), updates, cancel.clone()));
    tokio::time::timeout(Duration::from_secs(3), current.changed()).await.context("initial preference load timed out")??;
    assert_eq!(*current.borrow_and_update(), Mode::Auto);
    strategy::save(&path, Mode::PreferGateway)?;
    tokio::time::timeout(Duration::from_secs(3), current.changed()).await.context("atomic preference replacement timed out")??;
    assert_eq!(*current.borrow_and_update(), Mode::PreferGateway);
    profile::write_private(&strategy::path(&path), b"invalid settings", true)?;
    assert!(
        tokio::time::timeout(Duration::from_millis(150), current.changed())
            .await
            .is_err()
    );
    assert_eq!(*current.borrow(), Mode::PreferGateway);
    strategy::reset(&path)?;
    tokio::time::timeout(Duration::from_secs(3), current.changed()).await.context("preference reset timed out")??;
    assert_eq!(*current.borrow_and_update(), Mode::Auto);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), task).await???;
    Ok(())
}

#[test]
fn unsafe_overrides_are_rejected_and_explicit_reset_repairs_corrupt_settings() -> Result<()> {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let directory = tempfile::tempdir()?;
    let path = fixture(directory.path())?;
    let target = strategy::path(&path);
    symlink(&path, &target)?;
    assert!(strategy::load(&path).is_err());
    assert!(strategy::save(&path, Mode::PreferDirect).is_err());
    assert!(strategy::reset(&path).is_err());
    std::fs::remove_file(&target)?;
    strategy::save(&path, Mode::PreferGateway)?;
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))?;
    assert!(strategy::load(&path).is_err());
    assert!(strategy::reset(&path).is_err());
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))?;
    profile::write_private(&target, b"corrupt", true)?;
    assert!(strategy::load(&path).is_err());
    assert_eq!(strategy::reset(&path)?, Settings::default());
    assert_eq!(strategy::load(&path)?, Settings::default());
    assert!(!Mode::PreferGateway.prefer_peer_transport(false, true));
    assert!(Mode::PreferGateway.prefer_peer_transport(true, true));
    assert!(Mode::PreferGateway.prefer_peer_transport(false, false));
    Ok(())
}
