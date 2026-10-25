#![cfg(target_os = "linux")]
mod common;
use anyhow::{ensure, Result};
use async_trait::async_trait;
use porthub_agent::{
    profile::Profile,
    service::{self, Action, Layout, Manager, Spec, State},
};
use std::{
    collections::HashMap,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};
#[derive(Default)]
struct Fake {
    states: Mutex<HashMap<String, State>>,
    fail_start: AtomicBool,
    fail_reload: AtomicBool,
    calls: Mutex<Vec<(String, String)>>,
}
impl Fake {
    fn state_value(&self, spec: &Spec) -> State {
        self.states
            .lock()
            .unwrap()
            .get(&spec.service)
            .cloned()
            .unwrap_or(State {
                installed: false,
                enabled: false,
                active: false,
            })
    }
    fn call(&self, method: &str, spec: &Spec) {
        self.calls
            .lock()
            .unwrap()
            .push((method.into(), spec.service.clone()));
    }
}
#[async_trait]
impl Manager for Fake {
    async fn state(&self, spec: &Spec) -> Result<State> {
        Ok(self.state_value(spec))
    }
    async fn reload(&self) -> Result<()> {
        if self.fail_reload.swap(false, Ordering::SeqCst) {
            anyhow::bail!("fixture reload failed")
        }
        Ok(())
    }
    async fn enable(&self, spec: &Spec) -> Result<()> {
        self.call("enable", spec);
        let mut value = self.state_value(spec);
        value.installed = true;
        value.enabled = true;
        self.states
            .lock()
            .unwrap()
            .insert(spec.service.clone(), value);
        Ok(())
    }
    async fn disable(&self, spec: &Spec) -> Result<()> {
        self.call("disable", spec);
        let mut value = self.state_value(spec);
        value.enabled = false;
        self.states
            .lock()
            .unwrap()
            .insert(spec.service.clone(), value);
        Ok(())
    }
    async fn start(&self, spec: &Spec) -> Result<()> {
        self.call("start", spec);
        if self.fail_start.swap(false, Ordering::SeqCst) {
            anyhow::bail!("fixture start failed")
        };
        let mut value = self.state_value(spec);
        value.active = true;
        self.states
            .lock()
            .unwrap()
            .insert(spec.service.clone(), value);
        Ok(())
    }
    async fn stop(&self, spec: &Spec) -> Result<()> {
        self.call("stop", spec);
        let mut value = self.state_value(spec);
        value.active = false;
        self.states
            .lock()
            .unwrap()
            .insert(spec.service.clone(), value);
        Ok(())
    }
}
fn layout(path: &Path) -> Layout {
    Layout {
        user: false,
        state: path.join("state"),
        releases: path.join("releases"),
        units: path.join("units"),
    }
}
fn profile(path: &Path, id: &str) -> Result<std::path::PathBuf> {
    let path = path.join(format!("source-{id}.json"));
    Profile {
        format_version: 1,
        server: "https://porthub.example".into(),
        machine_id: id.into(),
        token: "service-fixture-secret".into(),
        account_email: None,
        setup_overrides: Default::default(),
        fallback_servers: vec![],
        allow_insecure_http_for_tests: false,
    }
    .save_new(&path)?;
    Ok(path)
}
#[tokio::test]
async fn service_installs_are_scoped_share_immutable_releases_and_restore_failed_upgrades(
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let temp = common::private_dir()?;
    let layout = layout(temp.path());
    let source = profile(temp.path(), "0123456789abcdef01234567")?;
    let other_source = profile(temp.path(), "ffffffffffffffffffffffff")?;
    let executable = temp.path().join("source-binary");
    std::fs::write(&executable, b"first native release")?;
    let manager = Fake::default();
    let first = service::install(&layout, &source, &executable, &manager).await?;
    ensure!(manager.state_value(&first).active && manager.state_value(&first).enabled);
    ensure!(Profile::load(&first.profile)?.token == "service-fixture-secret");
    ensure!(std::fs::metadata(&first.profile)?.permissions().mode() & 0o777 == 0o600);
    let unit = std::fs::read(&first.unit)?;
    ensure!(!String::from_utf8_lossy(&unit).contains("service-fixture-secret"));
    ensure!(String::from_utf8_lossy(&unit).contains("Restart=on-failure"));
    let other = service::install(&layout, &other_source, &executable, &manager).await?;
    ensure!(other.service != first.service && other.executable == first.executable);
    let starts = manager
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(method, _)| method == "start")
        .count();
    service::action(&layout, &source, Action::Start, &manager).await?;
    ensure!(
        manager
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(method, _)| method == "start")
            .count()
            == starts,
        "start interrupted an active service"
    );
    std::fs::write(&executable, b"second native release")?;
    manager.fail_start.store(true, Ordering::SeqCst);
    ensure!(service::install(&layout, &source, &executable, &manager)
        .await
        .is_err());
    ensure!(std::fs::read(&first.unit)? == unit && manager.state_value(&first).active);
    ensure!(manager.state_value(&other).active);
    ensure!(std::fs::read(&first.executable)? == b"first native release");
    // A reload failure before activation must leave the old process running.
    let stops = manager
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(method, _)| method == "stop")
        .count();
    manager.fail_reload.store(true, Ordering::SeqCst);
    ensure!(service::install(&layout, &source, &executable, &manager)
        .await
        .is_err());
    ensure!(
        manager
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(method, _)| method == "stop")
            .count()
            == stops
    );
    let upgraded = service::install(&layout, &source, &executable, &manager).await?;
    ensure!(
        upgraded.executable != first.executable
            && std::fs::read(&upgraded.executable)? == b"second native release"
    );
    service::action(
        &layout,
        &source,
        Action::Uninstall { purge: true },
        &manager,
    )
    .await?;
    ensure!(!upgraded.unit.exists() && !upgraded.profile.exists());
    ensure!(other.unit.exists() && other.profile.exists() && manager.state_value(&other).active);
    ensure!(
        other.executable.exists(),
        "purging one profile removed a shared release"
    );
    service::action(
        &layout,
        &other_source,
        Action::Uninstall { purge: false },
        &manager,
    )
    .await?;
    ensure!(other.profile.exists() && !other.unit.exists());
    Ok(())
}
#[tokio::test]
async fn foreign_units_symlink_directories_and_modified_release_binaries_are_not_overwritten(
) -> Result<()> {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let temp = common::private_dir()?;
    let layout = layout(temp.path());
    let source = profile(temp.path(), "0123456789abcdef01234567")?;
    let executable = temp.path().join("binary");
    std::fs::write(&executable, b"release")?;
    let manager = Fake::default();
    let first = service::install(&layout, &source, &executable, &manager).await?;
    std::fs::write(&first.unit, b"foreign administrator unit\n")?;
    ensure!(service::install(&layout, &source, &executable, &manager)
        .await
        .is_err());
    ensure!(service::action(
        &layout,
        &source,
        Action::Uninstall { purge: true },
        &manager
    )
    .await
    .is_err());
    ensure!(std::fs::read(&first.unit)? == b"foreign administrator unit\n");
    std::fs::write(&first.unit, service::unit(&first)?)?;
    std::fs::write(&first.executable, b"changed")?;
    ensure!(service::install(&layout, &source, &executable, &manager)
        .await
        .is_err());
    ensure!(std::fs::read(&first.executable)? == b"changed");
    let outside = temp.path().join("outside");
    std::fs::create_dir(&outside)?;
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o700))?;
    let linked = temp.path().join("linked");
    symlink(&outside, &linked)?;
    let unsafe_layout = Layout {
        user: false,
        state: linked,
        releases: layout.releases,
        units: layout.units,
    };
    ensure!(
        service::install(&unsafe_layout, &source, &executable, &manager)
            .await
            .is_err()
    );
    ensure!(std::fs::read_dir(outside)?.next().is_none());
    Ok(())
}

#[tokio::test]
async fn bootstrap_activation_failure_restores_source_and_installed_credentials_and_preserves_other_tenants(
) -> Result<()> {
    let temp = common::private_dir()?;
    let layout = layout(temp.path());
    let source = profile(temp.path(), "0123456789abcdef01234567")?;
    let other_source = profile(temp.path(), "ffffffffffffffffffffffff")?;
    let executable = temp.path().join("agent");
    std::fs::write(&executable, b"native release")?;
    let manager = Fake::default();
    let original = Profile::load(&source)?;
    let bytes = std::fs::read(&source)?;
    let first = porthub_agent::bootstrap::install(
        original.clone(),
        Some(&source),
        &layout,
        &executable,
        &manager,
    )
    .await?;
    let other = service::install(&layout, &other_source, &executable, &manager).await?;
    let mut updated = original.clone();
    updated.token = "new-bootstrap-token".into();
    manager.fail_start.store(true, Ordering::SeqCst);
    ensure!(porthub_agent::bootstrap::install(
        updated.clone(),
        Some(&source),
        &layout,
        &executable,
        &manager
    )
    .await
    .is_err());
    ensure!(
        std::fs::read(&source)? == bytes && Profile::load(&first.profile)?.token == original.token
    );
    ensure!(
        manager.state_value(&first).active
            && manager.state_value(&other).active
            && other.unit.exists()
    );
    let live = porthub_agent::profile::Lease::acquire(&source)?;
    ensure!(porthub_agent::bootstrap::save(updated.clone(), &source).is_err());
    drop(live);
    ensure!(std::fs::read(&source)? == bytes);
    let unknown = temp.path().join("new-source.json");
    updated.machine_id = "aaaaaaaaaaaaaaaaaaaaaaaa".into();
    manager.fail_start.store(true, Ordering::SeqCst);
    ensure!(porthub_agent::bootstrap::install(
        updated,
        Some(&unknown),
        &layout,
        &executable,
        &manager
    )
    .await
    .is_err());
    ensure!(!unknown.exists() && manager.state_value(&other).active);
    Ok(())
}

#[tokio::test]
async fn cli_publication_tracks_verified_releases_rolls_back_failed_activation_and_survives_tenant_removal(
) -> Result<()> {
    let temp = common::private_dir()?;
    let layout = layout(temp.path());
    let source = profile(temp.path(), "0123456789abcdef01234567")?;
    let other_source = profile(temp.path(), "ffffffffffffffffffffffff")?;
    let executable = temp.path().join("downloaded-agent");
    std::fs::write(&executable, b"release one")?;
    let cli = temp.path().join("bin/porthub");
    let manager = Fake::default();
    let first =
        service::install_published(&layout, &source, &executable, &manager, Some(&cli)).await?;
    let other = service::install(&layout, &other_source, &executable, &manager).await?;
    ensure!(std::fs::read_link(&cli)? == first.executable);
    std::fs::write(&executable, b"release two")?;
    manager.fail_start.store(true, Ordering::SeqCst);
    ensure!(
        service::install_published(&layout, &source, &executable, &manager, Some(&cli))
            .await
            .is_err()
    );
    ensure!(std::fs::read_link(&cli)? == first.executable && manager.state_value(&other).active);
    let latest =
        service::install_published(&layout, &source, &executable, &manager, Some(&cli)).await?;
    ensure!(
        std::fs::read_link(&cli)? == latest.executable && std::fs::read(&cli)? == b"release two"
    );
    service::action(
        &layout,
        &source,
        Action::Uninstall { purge: true },
        &manager,
    )
    .await?;
    ensure!(cli.exists() && other.unit.exists() && manager.state_value(&other).active);
    Ok(())
}

#[tokio::test]
async fn cli_publication_rejects_foreign_files_links_and_service_directory_overlap_before_activation(
) -> Result<()> {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let temp = common::private_dir()?;
    let layout = layout(temp.path());
    let source = profile(temp.path(), "0123456789abcdef01234567")?;
    let executable = temp.path().join("downloaded-agent");
    std::fs::write(&executable, b"native agent")?;
    let cli = temp.path().join("bin/porthub");
    std::fs::create_dir(cli.parent().unwrap())?;
    std::fs::set_permissions(
        cli.parent().unwrap(),
        std::fs::Permissions::from_mode(0o755),
    )?;
    std::fs::write(&cli, b"unrelated tool")?;
    std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755))?;
    let manager = Fake::default();
    ensure!(
        service::install_published(&layout, &source, &executable, &manager, Some(&cli))
            .await
            .is_err()
    );
    ensure!(std::fs::read(&cli)? == b"unrelated tool" && manager.calls.lock().unwrap().is_empty());
    std::fs::remove_file(&cli)?;
    symlink(&executable, &cli)?;
    ensure!(
        service::install_published(&layout, &source, &executable, &manager, Some(&cli))
            .await
            .is_err()
    );
    ensure!(std::fs::read_link(&cli)? == executable);
    let installed = service::install(&layout, &source, &executable, &manager).await?;
    let bytes = std::fs::read(&installed.executable)?;
    ensure!(service::install_published(
        &layout,
        &source,
        &executable,
        &manager,
        Some(&installed.executable)
    )
    .await
    .is_err());
    ensure!(
        std::fs::read(&installed.executable)? == bytes
            && !std::fs::symlink_metadata(&installed.executable)?
                .file_type()
                .is_symlink()
    );
    let alias = temp.path().join("release-alias");
    symlink(&layout.releases, &alias)?;
    let disguised = alias
        .join(installed.executable.parent().unwrap().file_name().unwrap())
        .join("porthub");
    ensure!(
        service::install_published(&layout, &source, &executable, &manager, Some(&disguised))
            .await
            .is_err()
    );
    ensure!(std::fs::read(&installed.executable)? == bytes);
    Ok(())
}

#[tokio::test]
async fn identical_native_cli_files_are_adopted_and_rollback_restores_original_permissions(
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let temp = common::private_dir()?;
    let layout = layout(temp.path());
    let source = profile(temp.path(), "0123456789abcdef01234567")?;
    let executable = temp.path().join("downloaded-agent");
    std::fs::write(&executable, b"native agent")?;
    let cli = temp.path().join("bin/porthub");
    std::fs::create_dir(cli.parent().unwrap())?;
    std::fs::set_permissions(
        cli.parent().unwrap(),
        std::fs::Permissions::from_mode(0o755),
    )?;
    std::fs::write(&cli, b"native agent")?;
    std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o751))?;
    let original_inode = std::fs::metadata(&cli)?.ino();
    let manager = Fake::default();
    manager.fail_reload.store(true, Ordering::SeqCst);
    ensure!(
        service::install_published(&layout, &source, &executable, &manager, Some(&cli))
            .await
            .is_err()
    );
    ensure!(
        !std::fs::symlink_metadata(&cli)?.file_type().is_symlink()
            && std::fs::read(&cli)? == b"native agent"
    );
    ensure!(std::fs::metadata(&cli)?.permissions().mode() & 0o777 == 0o751);
    ensure!(
        std::fs::metadata(&cli)?.ino() == original_inode,
        "rollback must restore the original inode and its metadata"
    );
    let installed =
        service::install_published(&layout, &source, &executable, &manager, Some(&cli)).await?;
    ensure!(std::fs::read_link(&cli)? == installed.executable);
    Ok(())
}

#[tokio::test]
async fn explicit_bootstrap_adoption_replaces_legacy_cli_and_restores_it_on_failure() -> Result<()>
{
    use std::os::unix::fs::PermissionsExt;
    let temp = common::private_dir()?;
    let layout = layout(temp.path());
    let source = profile(temp.path(), "0123456789abcdef01234567")?;
    let executable = temp.path().join("downloaded-agent");
    std::fs::write(&executable, b"first native agent release")?;
    let cli = temp.path().join("bin/porthub");
    std::fs::create_dir(cli.parent().unwrap())?;
    std::fs::set_permissions(
        cli.parent().unwrap(),
        std::fs::Permissions::from_mode(0o755),
    )?;
    let manager = Fake::default();
    service::install_published(&layout, &source, &executable, &manager, Some(&cli)).await?;
    std::fs::remove_file(&cli)?;
    std::fs::write(&cli, b"previous PortHub CLI")?;
    std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755))?;
    std::fs::write(&executable, b"updated native agent release")?;
    manager.fail_start.store(true, Ordering::SeqCst);
    ensure!(
        service::install_published_adopting_cli(&layout, &source, &executable, &manager, &cli)
            .await
            .is_err()
    );
    ensure!(std::fs::read(&cli)? == b"previous PortHub CLI");

    let installed =
        service::install_published_adopting_cli(&layout, &source, &executable, &manager, &cli)
            .await?;
    ensure!(std::fs::read_link(&cli)? == installed.executable);
    ensure!(std::fs::read(&cli)? == b"updated native agent release");
    Ok(())
}

#[tokio::test]
async fn native_registration_selection_is_scoped_unambiguous_and_does_not_accept_arbitrary_paths(
) -> Result<()> {
    let temp = common::private_dir()?;
    let mut layout = layout(temp.path());
    layout.user = true;
    ensure!(service::registrations(&layout)?.is_empty());
    let a = profile(temp.path(), "0123456789abcdef01234567")?;
    let b = profile(temp.path(), "012345ffffffffffffffffff")?;
    let executable = temp.path().join("agent");
    std::fs::write(&executable, b"native release")?;
    let manager = Fake::default();
    let first = service::install(&layout, &a, &executable, &manager).await?;
    ensure!(service::select(&layout, None)?.spec.identity == first.identity);
    let second = service::install(&layout, &b, &executable, &manager).await?;
    std::fs::write(
        layout.state.join("unrelated.service.json"),
        b"not a managed manifest",
    )?;
    let entries = service::registrations(&layout)?;
    ensure!(entries.len() == 2);
    ensure!(
        service::select(&layout, None).is_err()
            && service::select(&layout, Some("012345")).is_err()
    );
    ensure!(
        service::select(&layout, Some(&first.identity[..12]))?
            .spec
            .identity
            == first.identity
    );
    ensure!(
        service::select(&layout, Some(&second.service))?
            .spec
            .identity
            == second.identity
    );
    ensure!(
        service::select(&layout, Some("0123456789abcdef01234567"))?
            .spec
            .identity
            == first.identity
    );
    for invalid in [
        "../source.json",
        "/tmp/profile",
        "a",
        "a*b",
        "porthub-../../elsewhere",
    ] {
        ensure!(service::select(&layout, Some(invalid)).is_err());
    }
    let bad = layout
        .state
        .join(format!("{}.service.json", "a".repeat(64)));
    std::os::unix::fs::symlink(temp.path().join("private-secrets"), &bad)?;
    ensure!(service::registrations(&layout).is_err());
    ensure!(manager.state_value(&first).active && manager.state_value(&second).active);
    Ok(())
}
#[test]
fn systemd_unit_arguments_cannot_expand_shell_environment_or_unit_specifiers() -> Result<()> {
    let spec = Spec {
        cli: None,
        user: false,
        identity: "a".repeat(64),
        service: "porthub-fixture".into(),
        profile: "/tmp/path with spaces/$TOKEN%q\".json".into(),
        executable: "/tmp/native agent".into(),
        unit: "/tmp/unit.service".into(),
    };
    let text = service::unit(&spec)?;
    ensure!(text.contains("ExecStart=:\"/tmp/native agent\""));
    ensure!(text.contains("$TOKEN%%q\\\".json"));
    ensure!(service::unit(&Spec {
        user: false,
        profile: "/tmp/line\nbreak".into(),
        ..spec
    })
    .is_err());
    Ok(())
}

#[tokio::test]
async fn private_service_registration_preserves_private_wire_format_and_scopes_identity(
) -> Result<()> {
    let directory = common::private_dir()?;
    let layout = layout(directory.path());
    let source = directory.path().join("private-source.json");
    let peer = "0123456789abcdef01234567:abcdef0123456789abcdef01";
    let profile = serde_json::json!({"server":"https://porthub.example","peer_id":peer,
        "workspace":"0123456789abcdef01234567","token":"fixture-private-token-0123456789abcdef"});
    porthub_agent::profile::write_private(&source, &serde_json::to_vec(&profile)?, false)?;
    let manager = Fake::default();
    let executable = directory.path().join("test-agent-binary");
    std::fs::write(&executable, b"test agent executable")?;
    let spec = service::install(&layout, &source, &executable, &manager).await?;
    let saved = porthub_agent::private_profile::Profile::load(&spec.profile)?;
    ensure!(saved.peer_id == peer && saved.workspace == "0123456789abcdef01234567");
    ensure!(service::status(&layout, &source, &manager).await?.installed);
    service::action(&layout, &spec.profile, Action::Stop, &manager).await?;
    ensure!(!manager.state_value(&spec).active);
    service::action(&layout, &spec.profile, Action::Start, &manager).await?;
    ensure!(manager.state_value(&spec).active);
    service::action(
        &layout,
        &spec.profile,
        Action::Uninstall { purge: true },
        &manager,
    )
    .await?;
    ensure!(
        !spec.profile.exists() && !service::status(&layout, &source, &manager).await?.installed
    );
    Ok(())
}
