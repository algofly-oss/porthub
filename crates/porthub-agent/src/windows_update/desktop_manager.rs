//! Delegate the actual service transaction unchanged while directing its strict
//! existing-desktop refresh at the independently selected shared image.
use crate::service::{Layout, Manager, Spec, State};
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;
pub(super) struct DesktopManager<M> {
    pub inner: M,
    pub target: PathBuf,
}
#[async_trait]
impl<M: Manager> Manager for DesktopManager<M> {
    async fn prepare_private(&self) -> Result<()> {
        self.inner.prepare_private().await
    }
    async fn state(&self, s: &Spec) -> Result<State> {
        self.inner.state(s).await
    }
    async fn reload(&self) -> Result<()> {
        self.inner.reload().await
    }
    fn reconfigure_may_stop(&self) -> bool {
        self.inner.reconfigure_may_stop()
    }
    async fn reconfigure(&self, a: &Spec, b: &Spec) -> Result<()> {
        self.inner.reconfigure(a, b).await
    }
    async fn enable(&self, s: &Spec) -> Result<()> {
        self.inner.enable(s).await
    }
    async fn disable(&self, s: &Spec) -> Result<()> {
        self.inner.disable(s).await
    }
    async fn start(&self, s: &Spec) -> Result<()> {
        self.inner.start(s).await
    }
    async fn stop(&self, s: &Spec) -> Result<()> {
        self.inner.stop(s).await
    }
    async fn remove(&self, s: &Spec) -> Result<()> {
        self.inner.remove(s).await
    }
    async fn reset_failed(&self, s: &Spec) -> Result<()> {
        self.inner.reset_failed(s).await
    }
    async fn refresh_desktop_after_update(&self, l: &Layout, s: &Spec) -> Result<()> {
        let mut desktop = s.clone();
        desktop.executable = self.target.clone();
        // This synthetic descriptor is only a GUI callback argument. It is
        // never written as a service manifest or passed to SCM operations.
        self.inner.refresh_desktop_after_update(l, &desktop).await
    }
}
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{profile::Profile, service};
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };
    #[derive(Clone, Default)]
    struct Fake {
        states: Arc<Mutex<HashMap<String, State>>>,
        gui: Arc<Mutex<Vec<PathBuf>>>,
    }
    #[async_trait]
    impl Manager for Fake {
        async fn state(&self, s: &Spec) -> Result<State> {
            Ok(self
                .states
                .lock()
                .unwrap()
                .get(&s.identity)
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
        async fn enable(&self, s: &Spec) -> Result<()> {
            self.states
                .lock()
                .unwrap()
                .entry(s.identity.clone())
                .or_insert(State {
                    installed: true,
                    enabled: true,
                    active: false,
                })
                .enabled = true;
            Ok(())
        }
        async fn disable(&self, s: &Spec) -> Result<()> {
            self.states
                .lock()
                .unwrap()
                .get_mut(&s.identity)
                .unwrap()
                .enabled = false;
            Ok(())
        }
        async fn start(&self, s: &Spec) -> Result<()> {
            self.states
                .lock()
                .unwrap()
                .get_mut(&s.identity)
                .unwrap()
                .active = true;
            Ok(())
        }
        async fn stop(&self, s: &Spec) -> Result<()> {
            self.states
                .lock()
                .unwrap()
                .get_mut(&s.identity)
                .unwrap()
                .active = false;
            Ok(())
        }
        async fn refresh_desktop_after_update(&self, _: &Layout, s: &Spec) -> Result<()> {
            self.gui.lock().unwrap().push(s.executable.clone());
            Ok(())
        }
    }
    fn profile(root: &std::path::Path, id: &str) -> Result<PathBuf> {
        let path = root.join(format!("source-{id}.json"));
        Profile {
            format_version: 1,
            server: "https://fixture.invalid".into(),
            machine_id: id.into(),
            token: "fixture-local-only".into(),
            account_email: None,
            fallback_servers: vec![],
            setup_overrides: Default::default(),
            allow_insecure_http_for_tests: false,
        }
        .save_new(&path)?;
        Ok(path)
    }
    #[tokio::test]
    async fn real_install_transaction_preserves_other_tenant_cli_and_gui_on_success_and_rollback(
    ) -> Result<()> {
        let root = tempfile::tempdir()?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        let layout = Layout {
            user: false,
            state: root.path().join("native"),
            releases: root.path().join("releases"),
            units: root.path().join("units"),
        };
        let a = profile(root.path(), "aaaaaaaaaaaaaaaaaaaaaaaa")?;
        let b = profile(root.path(), "bbbbbbbbbbbbbbbbbbbbbbbb")?;
        let executable = root.path().join("build");
        let cli = root.path().join("bin/porthub");
        let fake = Fake::default();
        std::fs::write(&executable, b"tenant-B-core33")?;
        let b33 = service::install_published(&layout, &b, &executable, &fake, Some(&cli)).await?;
        std::fs::write(&executable, b"tenant-A-core35")?;
        let a35 = service::install_published(&layout, &a, &executable, &fake, Some(&cli)).await?;
        let protected = std::fs::read(&b33.profile)?;
        let a_manifest =
            std::fs::read(layout.state.join(format!("{}.service.json", a35.identity)))?;
        let lease = service::lock(&layout)?;
        assert!(
            service::lock(&layout).is_err(),
            "another tenant must not interleave while readiness/rollback is pending"
        );
        let manager = DesktopManager {
            inner: fake.clone(),
            target: a35.executable.clone(),
        };
        std::fs::write(&executable, b"tenant-B-requested34")?;
        let b34 = service::install_locked(&layout, &b, &executable, &manager, None).await?;
        assert_ne!(b34.executable, b33.executable);
        assert_eq!(std::fs::read_link(&cli)?, a35.executable);
        assert_eq!(fake.gui.lock().unwrap().last(), Some(&a35.executable));
        service::install_locked(&layout, &b, &b33.executable, &manager, None).await?;
        assert_eq!(std::fs::read_link(&cli)?, a35.executable);
        assert!(fake
            .gui
            .lock()
            .unwrap()
            .iter()
            .all(|p| p == &a35.executable));
        assert_eq!(std::fs::read(&b33.profile)?, protected);
        assert_eq!(
            std::fs::read(layout.state.join(format!("{}.service.json", a35.identity)))?,
            a_manifest
        );
        assert!(fake.state(&a35).await?.active);
        drop(lease);
        Ok(())
    }
}
