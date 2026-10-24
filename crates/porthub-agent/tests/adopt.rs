#![cfg(target_os = "linux")]
mod common;
use anyhow::{ensure, Result};
use async_trait::async_trait;
use porthub_agent::{
    adopt::{self, Options, Readiness},
    service::{Layout, Manager, Spec, State},
};
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

fn create_directory(path: impl AsRef<Path>) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}
fn write(path: impl AsRef<Path>, data: impl AsRef<[u8]>) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::write(&path, data)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}
#[derive(Default)]
struct Fake {
    states: Mutex<HashMap<String, State>>,
    starts: Mutex<Vec<String>>,
}
#[async_trait]
impl Manager for Fake {
    async fn state(&self, spec: &Spec) -> Result<State> {
        Ok(self
            .states
            .lock()
            .unwrap()
            .get(&spec.service)
            .cloned()
            .unwrap_or(State {
                installed: false,
                enabled: false,
                active: false,
            }))
    }
    async fn reload(&self) -> Result<()> {
        Ok(())
    }
    async fn enable(&self, spec: &Spec) -> Result<()> {
        let mut state = self.state(spec).await?;
        state.installed = true;
        state.enabled = true;
        self.states
            .lock()
            .unwrap()
            .insert(spec.service.clone(), state);
        Ok(())
    }
    async fn disable(&self, spec: &Spec) -> Result<()> {
        let mut state = self.state(spec).await?;
        state.enabled = false;
        self.states
            .lock()
            .unwrap()
            .insert(spec.service.clone(), state);
        Ok(())
    }
    async fn start(&self, spec: &Spec) -> Result<()> {
        self.starts.lock().unwrap().push(spec.service.clone());
        let mut state = self.state(spec).await?;
        state.active = true;
        self.states
            .lock()
            .unwrap()
            .insert(spec.service.clone(), state);
        Ok(())
    }
    async fn stop(&self, spec: &Spec) -> Result<()> {
        let mut state = self.state(spec).await?;
        state.active = false;
        self.states
            .lock()
            .unwrap()
            .insert(spec.service.clone(), state);
        Ok(())
    }
}
struct Ready {
    calls: AtomicUsize,
    fail_at: usize,
}
#[async_trait]
impl Readiness for Ready {
    async fn wait(&self, _: &Spec) -> Result<()> {
        ensure!(
            self.calls.fetch_add(1, Ordering::SeqCst) + 1 != self.fail_at,
            "fixture readiness failed"
        );
        Ok(())
    }
}
fn fixture(root: &Path) -> Result<(Layout, Options, Fake)> {
    let layout = Layout {
        user: false,
        state: root.join("native"),
        releases: root.join("releases"),
        units: root.join("units"),
    };
    create_directory(&layout.units)?;
    create_directory(root.join("bin"))?;
    let cli = root.join("bin/porthub");
    write(
        &cli,
        b"#!/usr/bin/env bash\nPORT_HUB_CLIENT_VERSION=\"fixture\"\n# __service-run\n",
    )?;
    let legacy_root = root.join("legacy");
    create_directory(&legacy_root)?;
    create_directory(legacy_root.join("tenants"))?;
    let fake = Fake::default();
    for (index, tenant) in ["tenant-a", "tenant-b"].into_iter().enumerate() {
        let directory = legacy_root.join("tenants").join(tenant);
        create_directory(&directory)?;
        write(directory.join("client.env"),format!("PORT_HUB_TENANT={tenant}\nPORT_HUB_API_URL=http://old.invalid/api\nPORT_HUB_MACHINE_ID={:024x}\nPORT_HUB_MACHINE_TOKEN=adoption-secret-must-not-leak\nPORT_HUB_SELF_PATH={}\n",index+1,cli.display()))?;
        write(layout.units.join(format!("porthub-{tenant}.service")),format!("[Unit]\nDescription=PortHub client ({tenant})\n[Service]\nExecStart={} __service-run --tenant {tenant}\n",cli.display()))?;
        fake.states.lock().unwrap().insert(
            format!("porthub-{tenant}"),
            State {
                installed: true,
                enabled: index == 0,
                active: index == 0,
            },
        );
    }
    let options = Options {
        legacy_root,
        cli,
        server: Some("https://stable.example".into()),
        fallback_servers: vec!["https://fallback.example".into()],
        ..Default::default()
    };
    Ok((layout, options, fake))
}

#[tokio::test]
async fn batch_adoption_preserves_stopped_tenants_and_can_restore_the_exact_legacy_cli(
) -> Result<()> {
    let root = common::private_dir()?;
    let (layout, options, fake) = fixture(root.path())?;
    let original = fs::read(&options.cli)?;
    let candidate = root.path().join("candidate");
    write(&candidate, b"native release fixture")?;
    let plan = adopt::plan(&layout, &options, &fake).await?;
    ensure!(plan.registrations() == 2 && !layout.state.exists());
    let readiness = Ready {
        calls: AtomicUsize::new(0),
        fail_at: usize::MAX,
    };
    let receipt = adopt::apply(&layout, plan, &candidate, &fake, &readiness).await?;
    ensure!(fs::symlink_metadata(&options.cli)?.file_type().is_symlink());
    ensure!(readiness.calls.load(Ordering::SeqCst) == 1);
    let entries: serde_json::Value =
        serde_json::from_slice(&fs::read(receipt.join("journal.json"))?)?;
    ensure!(entries["state"] == "committed" && !entries.to_string().contains("adoption-secret"));
    let receipts = adopt::receipts(&layout)?;
    ensure!(
        receipts.len() == 1
            && receipts[0].state == "committed"
            && receipts[0].registrations == 2
            && !serde_json::to_string(&receipts)?.contains("adoption-secret")
    );
    for (index, entry) in entries["entries"].as_array().unwrap().iter().enumerate() {
        let id = entry["id"].as_str().unwrap();
        let native = fake
            .states
            .lock()
            .unwrap()
            .get(&format!("porthub-{}", &id[..24]))
            .cloned();
        if index == 0 {
            ensure!(native.is_some_and(|state| state.active && state.enabled));
        } else {
            ensure!(native.is_none_or(|state| !state.active && !state.enabled));
        }
        ensure!(fs::read_to_string(layout.state.join(format!("{id}.json")))?
            .contains("https://stable.example"));
    }
    adopt::rollback(&layout, &receipt, &fake).await?;
    ensure!(
        fs::read(&options.cli)? == original
            && !fs::symlink_metadata(&options.cli)?.file_type().is_symlink()
    );
    ensure!(
        fake.states.lock().unwrap()["porthub-tenant-a"]
            == State {
                installed: true,
                enabled: true,
                active: true
            }
    );
    ensure!(
        fake.states.lock().unwrap()["porthub-tenant-b"]
            == State {
                installed: true,
                enabled: false,
                active: false
            }
    );
    ensure!(!fs::read_dir(&layout.state)?.any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .ends_with(".service.json")));
    let starts = fake.starts.lock().unwrap().len();
    adopt::rollback(&layout, &receipt, &fake).await?;
    ensure!(fake.starts.lock().unwrap().len() == starts);
    Ok(())
}

#[tokio::test]
async fn failed_native_readiness_restores_old_services_and_retains_private_recovery_data(
) -> Result<()> {
    let root = common::private_dir()?;
    let (layout, options, fake) = fixture(root.path())?;
    let original = fs::read(&options.cli)?;
    let candidate = root.path().join("candidate");
    write(&candidate, b"native release fixture")?;
    let plan = adopt::plan(&layout, &options, &fake).await?;
    let error = adopt::apply(
        &layout,
        plan,
        &candidate,
        &fake,
        &Ready {
            calls: AtomicUsize::new(0),
            fail_at: 1,
        },
    )
    .await
    .unwrap_err();
    ensure!(!error.to_string().contains("adoption-secret"));
    ensure!(fs::read(&options.cli)? == original);
    ensure!(fake.states.lock().unwrap()["porthub-tenant-a"].active);
    ensure!(!fake.states.lock().unwrap()["porthub-tenant-b"].active);
    let receipt = fs::read_dir(&layout.state)?
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.file_name().to_string_lossy().starts_with("adoption-"))
        .unwrap()
        .path();
    let journal: serde_json::Value =
        serde_json::from_slice(&fs::read(receipt.join("journal.json"))?)?;
    ensure!(journal["state"] == "rolled-back");
    use std::os::unix::fs::PermissionsExt;
    ensure!(fs::metadata(receipt.join("0.json"))?.permissions().mode() & 0o777 == 0o600);
    Ok(())
}

#[tokio::test]
async fn omitted_units_and_changed_cli_are_rejected_before_any_legacy_service_stops() -> Result<()>
{
    let root = common::private_dir()?;
    let (layout, options, fake) = fixture(root.path())?;
    let omitted = layout.units.join("porthub-omitted.service");
    write(
        &omitted,
        format!(
            "[Service]\nExecStart={} __service-run --tenant omitted\n",
            options.cli.display()
        ),
    )?;
    ensure!(adopt::plan(&layout, &options, &fake).await.is_err());
    fs::remove_file(omitted)?;
    let plan = adopt::plan(&layout, &options, &fake).await?;
    write(&options.cli, b"changed executable")?;
    let candidate = root.path().join("candidate");
    write(&candidate, b"native release fixture")?;
    ensure!(adopt::apply(
        &layout,
        plan,
        &candidate,
        &fake,
        &Ready {
            calls: AtomicUsize::new(0),
            fail_at: usize::MAX
        }
    )
    .await
    .is_err());
    ensure!(
        fake.states.lock().unwrap()["porthub-tenant-a"].active
            && fake.starts.lock().unwrap().is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn private_adoption_preserves_identity_and_credentials_while_replacing_legacy_http_endpoints(
) -> Result<()> {
    let root = common::private_dir()?;
    let (layout, options, fake) = fixture(root.path())?;
    let private = options.legacy_root.join("private.json");
    let workspace = "0123456789abcdef01234567";
    let peer = format!("{workspace}:abcdef0123456789abcdef01");
    let credential = "private-adoption-token-0123456789abcdef";
    let bytes = serde_json::to_vec(
        &serde_json::json!({"server":"http://old.invalid","peer_id":peer,"workspace":workspace,"token":credential,"fallback_servers":["http://old-fallback.invalid"]}),
    )?;
    write(&private, &bytes)?;
    write(layout.units.join("porthub-private.service"),format!("[Unit]\nDescription=PortHub private network agent\n[Service]\nExecStart={} run --profile {}\n",options.private_executable.display(),private.display()))?;
    fake.states.lock().unwrap().insert(
        "porthub-private".into(),
        State {
            installed: true,
            enabled: true,
            active: true,
        },
    );
    let plan = adopt::plan(&layout, &options, &fake).await?;
    ensure!(plan.registrations() == 3);
    let candidate = root.path().join("candidate");
    write(&candidate, b"native fixture")?;
    let receipt = adopt::apply(
        &layout,
        plan,
        &candidate,
        &fake,
        &Ready {
            calls: AtomicUsize::new(0),
            fail_at: usize::MAX,
        },
    )
    .await?;
    let profile = porthub_agent::private_profile::Profile::load(&receipt.join("2.json"))?;
    ensure!(
        profile.peer_id == peer
            && profile.workspace == workspace
            && profile.token == credential
            && profile.server == "https://stable.example"
            && profile.fallback_servers == ["https://fallback.example"]
    );
    ensure!(fs::read(&private)? == bytes);
    adopt::rollback(&layout, &receipt, &fake).await?;
    ensure!(fake.states.lock().unwrap()["porthub-private"].active && fs::read(private)? == bytes);
    Ok(())
}

#[tokio::test]
async fn recovery_uses_staged_credentials_when_a_copied_profile_was_removed_during_interrupted_retirement(
) -> Result<()> {
    let root = common::private_dir()?;
    let (layout, options, fake) = fixture(root.path())?;
    let original = fs::read(&options.cli)?;
    let candidate = root.path().join("candidate");
    write(&candidate, b"native fixture")?;
    let plan = adopt::plan(&layout, &options, &fake).await?;
    let receipt = adopt::apply(
        &layout,
        plan,
        &candidate,
        &fake,
        &Ready {
            calls: AtomicUsize::new(0),
            fail_at: usize::MAX,
        },
    )
    .await?;
    let mut journal: serde_json::Value =
        serde_json::from_slice(&fs::read(receipt.join("journal.json"))?)?;
    journal["state"] = serde_json::json!("rolling-back");
    write(receipt.join("journal.json"), serde_json::to_vec(&journal)?)?;
    let id = journal["entries"][0]["id"].as_str().unwrap();
    fs::remove_file(layout.state.join(format!("{id}.json")))?;
    fs::hard_link(receipt.join("legacy-cli"), receipt.join("restore-cli"))?;
    adopt::rollback(&layout, &receipt, &fake).await?;
    ensure!(
        fs::read(options.cli)? == original
            && fake.states.lock().unwrap()["porthub-tenant-a"].active
    );
    Ok(())
}

#[tokio::test]
async fn queued_handoff_stages_an_immutable_binary_without_stopping_any_existing_registration(
) -> Result<()> {
    let root = common::private_dir()?;
    let (layout, options, fake) = fixture(root.path())?;
    let cli = fs::read(&options.cli)?;
    let candidate = root.path().join("downloaded");
    write(&candidate, b"native handoff fixture")?;
    let handoff = adopt::prepare_handoff(&layout, &options, &candidate, &fake).await?;
    ensure!(handoff.registrations == 2 && handoff.executable.starts_with(&layout.releases));
    fs::remove_file(candidate)?;
    ensure!(fs::read(&handoff.executable)? == b"native handoff fixture");
    ensure!(
        handoff.arguments.first().map(String::as_str) == Some("adopt-legacy")
            && handoff
                .arguments
                .iter()
                .any(|argument| argument == "--apply")
            && !handoff
                .arguments
                .iter()
                .any(|argument| argument == "--handoff")
    );
    ensure!(!handoff
        .arguments
        .iter()
        .any(|argument| argument.contains("adoption-secret")));
    ensure!(
        fs::read(options.cli)? == cli
            && fake.starts.lock().unwrap().is_empty()
            && fake.states.lock().unwrap()["porthub-tenant-a"].active
    );
    Ok(())
}

#[tokio::test]
async fn installer_handoff_is_scoped_to_one_matching_enrollment_and_keeps_tokens_out_of_arguments(
) -> Result<()> {
    let root = common::private_dir()?;
    let (layout, options, fake) = fixture(root.path())?;
    let candidate = root.path().join("downloaded");
    write(&candidate, b"native installer fixture")?;
    let enrollment = porthub_agent::profile::Profile {
        format_version: 1,
        server: "https://stable.example".into(),
        machine_id: format!("{:024x}", 1),
        token: "adoption-secret-must-not-leak".into(),
        fallback_servers: options.fallback_servers.clone(),
        setup_overrides: std::collections::BTreeMap::from([(
            "service_domain".into(),
            "requested.example".into(),
        )]),
        allow_insecure_http_for_tests: false,
    };
    ensure!(
        adopt::prepare_enrollment_handoff(&layout, &options, &candidate, &fake, &enrollment)
            .await
            .is_err()
    );
    ensure!(
        !layout.state.exists(),
        "ambiguous multi-tenant inspection must not stage installer credentials"
    );
    fs::remove_file(options.legacy_root.join("tenants/tenant-b/client.env"))?;
    fs::remove_file(layout.units.join("porthub-tenant-b.service"))?;
    let mut foreign = enrollment.clone();
    foreign.token = "foreign-installer-token".into();
    ensure!(
        adopt::prepare_enrollment_handoff(&layout, &options, &candidate, &fake, &foreign)
            .await
            .is_err()
    );
    ensure!(!layout.state.exists());
    let handoff =
        adopt::prepare_enrollment_handoff(&layout, &options, &candidate, &fake, &enrollment)
            .await?;
    let index = handoff
        .arguments
        .iter()
        .position(|argument| argument == "--enrollment")
        .unwrap();
    let source = std::path::PathBuf::from(&handoff.arguments[index + 1]);
    ensure!(
        !handoff
            .arguments
            .iter()
            .any(|argument| argument.contains("adoption-secret"))
            && fake.starts.lock().unwrap().is_empty()
    );
    let incoming = porthub_agent::profile::Profile::load(&source)?;
    ensure!(
        incoming.token == enrollment.token
            && incoming.setup_overrides["service_domain"] == "requested.example"
    );
    let plan = adopt::plan(&layout, &options, &fake)
        .await?
        .for_enrollment(&incoming)?;
    let receipt = adopt::apply(
        &layout,
        plan,
        &candidate,
        &fake,
        &Ready {
            calls: AtomicUsize::new(0),
            fail_at: usize::MAX,
        },
    )
    .await?;
    let staged = porthub_agent::profile::Profile::load(&receipt.join("0.json"))?;
    ensure!(staged.setup_overrides["service_domain"] == "requested.example");
    adopt::rollback(&layout, &receipt, &fake).await?;
    Ok(())
}
