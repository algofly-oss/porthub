#![cfg(target_os = "linux")]
mod common;
use anyhow::{ensure, Result};
use async_trait::async_trait;
use porthub_agent::{
    private_profile,
    profile::Profile,
    service::{self, Layout, Manager, Readiness, Spec, State},
    upgrade,
};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

#[derive(Default)]
struct Fake {
    states: Mutex<HashMap<String, State>>,
    calls: Mutex<Vec<(String, String)>>,
}
impl Fake {
    fn change(&self, spec: &Spec, name: &str, f: impl FnOnce(&mut State)) {
        self.calls
            .lock()
            .unwrap()
            .push((name.into(), spec.identity.clone()));
        f(self
            .states
            .lock()
            .unwrap()
            .entry(spec.identity.clone())
            .or_insert(State {
                installed: true,
                active: false,
                enabled: false,
            }));
    }
}
#[async_trait]
impl Manager for Fake {
    async fn state(&self, spec: &Spec) -> Result<State> {
        Ok(self
            .states
            .lock()
            .unwrap()
            .get(&spec.identity)
            .cloned()
            .unwrap_or(State {
                installed: false,
                active: false,
                enabled: false,
            }))
    }
    async fn reload(&self) -> Result<()> {
        Ok(())
    }
    async fn enable(&self, spec: &Spec) -> Result<()> {
        self.change(spec, "enable", |state| {
            state.installed = true;
            state.enabled = true;
        });
        Ok(())
    }
    async fn disable(&self, spec: &Spec) -> Result<()> {
        self.change(spec, "disable", |state| state.enabled = false);
        Ok(())
    }
    async fn start(&self, spec: &Spec) -> Result<()> {
        self.change(spec, "start", |state| state.active = true);
        Ok(())
    }
    async fn stop(&self, spec: &Spec) -> Result<()> {
        self.change(spec, "stop", |state| state.active = false);
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
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        ensure!(call != self.fail_at, "fixture readiness failed");
        Ok(())
    }
}
struct Block {
    entered: tokio::sync::Notify,
}
#[async_trait]
impl Readiness for Block {
    async fn wait(&self, _: &Spec) -> Result<()> {
        self.entered.notify_one();
        std::future::pending().await
    }
}
struct Fixture {
    _root: tempfile::TempDir,
    layout: Layout,
    manager: Arc<Fake>,
    public: Profile,
    specs: Vec<Spec>,
    cli: PathBuf,
    new: PathBuf,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let root = common::private_dir()?;
        let layout = Layout {
            user: false,
            state: root.path().join("state"),
            releases: root.path().join("releases"),
            units: root.path().join("units"),
        };
        let public = Profile {
            format_version: 1,
            server: "https://gateway.example".into(),
            machine_id: "0123456789abcdef01234567".into(),
            token: "native-upgrade-private-enrollment-token".into(),
            account_email: None,
            fallback_servers: vec![],
            setup_overrides: Default::default(),
            allow_insecure_http_for_tests: false,
        };
        let source = root.path().join("public.json");
        public.save_new(&source)?;
        let old = root.path().join("old-binary");
        std::fs::write(&old, b"old native release fixture")?;
        let new = root.path().join("new-binary");
        std::fs::write(&new, b"new native release fixture")?;
        use std::os::unix::fs::DirBuilderExt;
        let bin = root.path().join("bin");
        std::fs::DirBuilder::new().mode(0o755).create(&bin)?;
        let cli = bin.join("porthub");
        let manager = Arc::new(Fake::default());
        let first =
            service::install_published(&layout, &source, &old, manager.as_ref(), Some(&cli))
                .await?;
        let private = private_profile::Profile {
            server: public.server.clone(),
            workspace: "abcdef0123456789abcdef01".into(),
            peer_id: format!("abcdef0123456789abcdef01:{}", public.machine_id),
            token: "private-upgrade-credential-0123456789".into(),
            account_email: None,
            fallback_servers: vec![],
            allow_insecure_http_for_tests: false,
        };
        let source = root.path().join("private.json");
        porthub_agent::profile::write_private(
            &source,
            &serde_json::to_vec_pretty(&private)?,
            false,
        )?;
        let second = service::install(&layout, &source, &old, manager.as_ref()).await?;
        let mut foreign = public.clone();
        foreign.machine_id = "ffffffffffffffffffffffff".into();
        let source = root.path().join("foreign.json");
        foreign.save_new(&source)?;
        let third = service::install(&layout, &source, &old, manager.as_ref()).await?;
        manager.calls.lock().unwrap().clear();
        Ok(Self {
            _root: root,
            layout,
            manager,
            public,
            specs: vec![first, second, third],
            cli,
            new,
        })
    }
    fn spec(&self, id: &str) -> Result<Spec> {
        Ok(serde_json::from_slice(&std::fs::read(
            self.layout.state.join(format!("{id}.service.json")),
        )?)?)
    }
    fn receipt(&self) -> Result<PathBuf> {
        Ok(std::fs::read_dir(&self.layout.state)?
            .filter_map(|entry| entry.ok())
            .find(|entry| entry.file_name().to_string_lossy().starts_with("upgrade-"))
            .ok_or_else(|| anyhow::anyhow!("receipt missing"))?
            .path())
    }
    fn foreign_untouched(&self) -> Result<()> {
        ensure!(self.spec(&self.specs[2].identity)? == self.specs[2]);
        ensure!(self
            .manager
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|(_, id)| id != &self.specs[2].identity));
        Ok(())
    }
    async fn restored(&self) -> Result<()> {
        for spec in &self.specs {
            ensure!(self.spec(&spec.identity)? == *spec);
        }
        ensure!(std::fs::read_link(&self.cli)? == self.specs[0].executable);
        self.foreign_untouched()
    }
}

#[tokio::test]
async fn native_update_activates_its_pair_preserves_stopped_state_and_can_restore_the_committed_release(
) -> Result<()> {
    let f = Fixture::new().await?;
    f.manager.stop(&f.specs[1]).await?;
    f.manager.disable(&f.specs[1]).await?;
    f.manager.calls.lock().unwrap().clear();
    let plan = upgrade::plan(&f.layout, &f.public, Some(&f.cli), f.manager.as_ref()).await?;
    ensure!(plan.registrations() == 2);
    let ready = Ready {
        calls: AtomicUsize::new(0),
        fail_at: 0,
    };
    let receipt = upgrade::apply(&f.layout, plan, &f.new, f.manager.as_ref(), &ready).await?;
    ensure!(ready.calls.load(Ordering::SeqCst) == 1);
    for spec in &f.specs[..2] {
        ensure!(f.spec(&spec.identity)?.executable != spec.executable);
    }
    ensure!(std::fs::read_link(&f.cli)? == f.spec(&f.specs[0].identity)?.executable);
    ensure!(
        !f.manager.state(&f.specs[1]).await?.active && !f.manager.state(&f.specs[1]).await?.enabled
    );
    ensure!(f
        .manager
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|(name, id)| name != "start" || id != &f.specs[1].identity));
    f.foreign_untouched()?;
    upgrade::rollback(&f.layout, &receipt, f.manager.as_ref()).await?;
    f.restored().await?;
    ensure!(
        f.manager.state(&f.specs[0]).await?.active && !f.manager.state(&f.specs[1]).await?.active
    );
    let calls = f.manager.calls.lock().unwrap().len();
    upgrade::rollback(&f.layout, &receipt, f.manager.as_ref()).await?;
    ensure!(f.manager.calls.lock().unwrap().len() == calls);
    Ok(())
}

#[tokio::test]
async fn failed_second_readiness_restores_both_registrations_and_does_not_publish_the_new_cli(
) -> Result<()> {
    let f = Fixture::new().await?;
    let plan = upgrade::plan(&f.layout, &f.public, Some(&f.cli), f.manager.as_ref()).await?;
    let error = upgrade::apply(
        &f.layout,
        plan,
        &f.new,
        f.manager.as_ref(),
        &Ready {
            calls: AtomicUsize::new(0),
            fail_at: 2,
        },
    )
    .await
    .err()
    .unwrap();
    ensure!(
        error.to_string().contains("previous services restored")
            && !error.to_string().contains(&f.public.token)
    );
    f.restored().await?;
    for spec in &f.specs[..2] {
        ensure!(f.manager.state(spec).await?.active);
    }
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(f.receipt()?.join("journal.json"))?)?;
    ensure!(journal["state"] == "rolled-back");
    Ok(())
}

#[tokio::test]
async fn interrupted_activation_and_partial_unit_manifest_writes_recover_without_restarting_untouched_services(
) -> Result<()> {
    for partial in [false, true] {
        let f = Fixture::new().await?;
        let plan = upgrade::plan(&f.layout, &f.public, Some(&f.cli), f.manager.as_ref()).await?;
        let ready = Arc::new(Block {
            entered: tokio::sync::Notify::new(),
        });
        let manager = f.manager.clone();
        let layout = f.layout.clone();
        let executable = f.new.clone();
        let readiness = ready.clone();
        let worker = tokio::spawn(async move {
            upgrade::apply(
                &layout,
                plan,
                &executable,
                manager.as_ref(),
                readiness.as_ref(),
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(3), ready.entered.notified()).await?;
        worker.abort();
        let _ = worker.await;
        let receipt = f.receipt()?;
        let journal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(receipt.join("journal.json"))?)?;
        let entries = journal["entries"].as_array().unwrap();
        let changed: Vec<_> = entries
            .iter()
            .enumerate()
            .filter_map(|(i, entry)| {
                let id = entry["spec"]["identity"].as_str().unwrap();
                (f.spec(id).unwrap().executable != f.specs[0].executable)
                    .then_some((i, id.to_owned()))
            })
            .collect();
        ensure!(changed.len() == 1);
        if partial {
            let (i, id) = &changed[0];
            std::fs::copy(
                receipt.join(format!("{i}.manifest")),
                f.layout.state.join(format!("{id}.service.json")),
            )?;
        }
        f.manager.calls.lock().unwrap().clear();
        upgrade::rollback(&f.layout, &receipt, f.manager.as_ref()).await?;
        f.restored().await?;
        let starts: Vec<_> = f
            .manager
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| name == "start")
            .cloned()
            .collect();
        ensure!(starts.len() == 1 && starts[0].1 == changed[0].1);
    }
    Ok(())
}

#[tokio::test]
async fn update_recovery_refuses_later_credential_changes_before_stopping_services_or_replacing_cli(
) -> Result<()> {
    let f = Fixture::new().await?;
    let plan = upgrade::plan(&f.layout, &f.public, Some(&f.cli), f.manager.as_ref()).await?;
    let receipt = upgrade::apply(
        &f.layout,
        plan,
        &f.new,
        f.manager.as_ref(),
        &Ready {
            calls: AtomicUsize::new(0),
            fail_at: 0,
        },
    )
    .await?;
    let mut changed = f.public.clone();
    changed.token = "manually-rotated-enrollment".into();
    std::fs::write(&f.specs[0].profile, serde_json::to_vec_pretty(&changed)?)?;
    let cli = std::fs::read_link(&f.cli)?;
    f.manager.calls.lock().unwrap().clear();
    ensure!(upgrade::rollback(&f.layout, &receipt, f.manager.as_ref())
        .await
        .is_err());
    ensure!(f.manager.calls.lock().unwrap().is_empty() && std::fs::read_link(&f.cli)? == cli);
    ensure!(Profile::load(&f.specs[0].profile)?.token == changed.token);
    Ok(())
}

#[tokio::test]
async fn native_update_preflight_rejects_foreign_credentials_cli_and_changed_state_without_mutation(
) -> Result<()> {
    let f = Fixture::new().await?;
    let mut wrong = f.public.clone();
    wrong.token = "another-token".into();
    ensure!(
        upgrade::plan(&f.layout, &wrong, Some(&f.cli), f.manager.as_ref())
            .await
            .is_err()
    );
    let foreign = f._root.path().join("foreign");
    std::fs::create_dir(&foreign)?;
    std::fs::write(foreign.join("porthub"), b"other program")?;
    ensure!(upgrade::plan(
        &f.layout,
        &f.public,
        Some(&foreign.join("porthub")),
        f.manager.as_ref()
    )
    .await
    .is_err());
    let plan = upgrade::plan(&f.layout, &f.public, Some(&f.cli), f.manager.as_ref()).await?;
    f.manager.disable(&f.specs[0]).await?;
    f.manager.calls.lock().unwrap().clear();
    ensure!(upgrade::apply(
        &f.layout,
        plan,
        &f.new,
        f.manager.as_ref(),
        &Ready {
            calls: AtomicUsize::new(0),
            fail_at: 0
        }
    )
    .await
    .is_err());
    ensure!(f.manager.calls.lock().unwrap().is_empty());
    ensure!(std::fs::read_dir(&f.layout.state)?.all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("upgrade-")));
    let outside = f._root.path().join("outside");
    std::fs::create_dir(&outside)?;
    use std::os::unix::fs::PermissionsExt;
    let before = std::fs::metadata(&outside)?.permissions().mode();
    ensure!(upgrade::rollback(&f.layout, &outside, f.manager.as_ref())
        .await
        .is_err());
    ensure!(std::fs::metadata(&outside)?.permissions().mode() == before);
    Ok(())
}

#[tokio::test]
async fn acknowledgement_requires_matching_committed_request_enrollment_and_executable_and_is_revoked_by_rollback(
) -> Result<()> {
    let f = Fixture::new().await?;
    let request = porthub_agent::update::Request {
        id: "proof-fixture-request-1".into(),
        target_version: porthub_agent::VERSION.into(),
    };
    let plan = upgrade::plan(&f.layout, &f.public, Some(&f.cli), f.manager.as_ref()).await?;
    let receipt = upgrade::apply_requested(
        &f.layout,
        plan,
        &f.new,
        f.manager.as_ref(),
        &Ready {
            calls: AtomicUsize::new(0),
            fail_at: 0,
        },
        Some(request.clone()),
    )
    .await?;
    let current = f.spec(&f.specs[0].identity)?.executable.canonicalize()?;
    ensure!(upgrade::committed(
        &f.layout,
        &f.specs[0].profile,
        &f.public,
        &request,
        &current
    )?);
    let mut other = request.clone();
    other.id = "another-request".into();
    ensure!(!upgrade::committed(
        &f.layout,
        &f.specs[0].profile,
        &f.public,
        &other,
        &current
    )?);
    ensure!(!upgrade::committed(
        &f.layout,
        &f.specs[0].profile,
        &f.public,
        &request,
        &f.specs[0].executable
    )?);
    // Rebuild the index from the committed receipt after an interrupted index write.
    std::fs::remove_file(porthub_agent::profile::sibling(
        &f.specs[0].profile,
        ".update-commit.json",
    ))?;
    ensure!(upgrade::committed(
        &f.layout,
        &f.specs[0].profile,
        &f.public,
        &request,
        &current
    )?);
    upgrade::rollback(&f.layout, &receipt, f.manager.as_ref()).await?;
    ensure!(!upgrade::committed(
        &f.layout,
        &f.specs[0].profile,
        &f.public,
        &request,
        &current
    )?);
    ensure!(upgrade::failed(&f.layout, &f.specs[0].profile, &request)?);
    Ok(())
}

#[tokio::test]
async fn running_new_version_before_transaction_commit_is_not_an_update_acknowledgement(
) -> Result<()> {
    let f = Fixture::new().await?;
    let request = porthub_agent::update::Request {
        id: "uncommitted-proof-request".into(),
        target_version: porthub_agent::VERSION.into(),
    };
    let plan = upgrade::plan(&f.layout, &f.public, Some(&f.cli), f.manager.as_ref()).await?;
    let ready = Arc::new(Block {
        entered: tokio::sync::Notify::new(),
    });
    let manager = f.manager.clone();
    let layout = f.layout.clone();
    let executable = f.new.clone();
    let readiness = ready.clone();
    let requested = request.clone();
    let worker = tokio::spawn(async move {
        upgrade::apply_requested(
            &layout,
            plan,
            &executable,
            manager.as_ref(),
            readiness.as_ref(),
            Some(requested),
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), ready.entered.notified()).await?;
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(f.receipt()?.join("journal.json"))?)?;
    let candidate = PathBuf::from(journal["executable"].as_str().unwrap()).canonicalize()?;
    ensure!(!upgrade::committed(
        &f.layout,
        &f.specs[0].profile,
        &f.public,
        &request,
        &candidate
    )?);
    worker.abort();
    let _ = worker.await;
    upgrade::rollback(&f.layout, &f.receipt()?, f.manager.as_ref()).await?;
    ensure!(upgrade::failed(&f.layout, &f.specs[0].profile, &request)?);
    Ok(())
}
