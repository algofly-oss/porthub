#![cfg(target_os = "linux")]
use anyhow::{ensure, Result};
use porthub_agent::service::{systemd::Systemd, Manager, Spec};
use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    Arc, Mutex,
};
use zbus::{
    object_server::SignalEmitter,
    zvariant::{OwnedObjectPath, OwnedValue},
};
type Properties = Vec<(String, OwnedValue)>;
const UNIT: &str = "porthub-systemd-fixture.service";
const PATH: &str = "/org/freedesktop/systemd1/unit/porthub_fixture_2eservice";
#[derive(Default)]
struct State {
    active: AtomicBool,
    enabled: AtomicBool,
    subscribed: AtomicUsize,
    jobs: AtomicU32,
    fail: AtomicBool,
    calls: Mutex<Vec<String>>,
}
struct FakeUnit(Arc<State>);
#[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
impl FakeUnit {
    #[zbus(property)]
    fn active_state(&self) -> &str {
        if self.0.active.load(Ordering::SeqCst) {
            "active"
        } else {
            "inactive"
        }
    }
}
struct FakeManager(Arc<State>);
#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl FakeManager {
    fn start_transient_unit(
        &self,
        name: &str,
        mode: &str,
        properties: Properties,
        auxiliary: Vec<(String, Properties)>,
    ) -> OwnedObjectPath {
        assert!(
            (name.starts_with("porthub-adoption-") || name.starts_with("porthub-update-"))
                && name.ends_with(".service")
        );
        assert_eq!(mode, "fail");
        assert!(auxiliary.is_empty());
        let mut properties: std::collections::HashMap<_, _> = properties.into_iter().collect();
        assert_eq!(
            String::try_from(properties.remove("Type").unwrap()).unwrap(),
            "exec"
        );
        assert_eq!(
            u32::try_from(properties.remove("UMask").unwrap()).unwrap(),
            0o077
        );
        assert!(bool::try_from(properties.remove("NoNewPrivileges").unwrap()).unwrap());
        assert!(!properties.contains_key("PartOf") && !properties.contains_key("BindsTo"));
        let commands: Vec<(String, Vec<String>, Vec<String>)> = properties
            .remove("ExecStartEx")
            .unwrap()
            .try_into()
            .unwrap();
        let updating = name.starts_with("porthub-update-");
        assert_eq!(
            commands,
            vec![(
                "/private/immutable/porthub".into(),
                vec![
                    "/private/immutable/porthub".into(),
                    if updating {
                        "update".into()
                    } else {
                        "adopt-legacy".into()
                    },
                    "--apply".into(),
                    if updating {
                        "--profile".into()
                    } else {
                        "--legacy-root".into()
                    },
                    "/private/literal $PORTHUB_UNSET %q".into()
                ],
                vec!["no-env-expand".into()]
            )]
        );
        self.0.calls.lock().unwrap().push("handoff".into());
        OwnedObjectPath::try_from("/org/freedesktop/systemd1/job/999").unwrap()
    }
    fn subscribe(&self) {
        self.0.subscribed.fetch_add(1, Ordering::SeqCst);
    }
    fn reset_failed_unit(&self, name: &str) {
        assert_eq!(name, UNIT);
        self.0.calls.lock().unwrap().push("reset-failed".into());
    }
    fn reload(&self) {
        self.0.calls.lock().unwrap().push("reload".into());
    }
    fn get_unit_file_state(&self, name: &str) -> zbus::fdo::Result<String> {
        if name != UNIT {
            return Err(zbus::fdo::Error::FileNotFound("fixture absent".into()));
        }
        Ok(if self.0.enabled.load(Ordering::SeqCst) {
            "enabled"
        } else {
            "disabled"
        }
        .into())
    }
    fn load_unit(&self, name: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        assert_eq!(name, UNIT);
        Ok(OwnedObjectPath::try_from(PATH).unwrap())
    }
    fn enable_unit_files(
        &self,
        files: Vec<String>,
        runtime: bool,
        force: bool,
    ) -> (bool, Vec<(String, String, String)>) {
        assert_eq!(files, vec!["/private/unit"]);
        assert!(!runtime && !force);
        self.0.enabled.store(true, Ordering::SeqCst);
        self.0.calls.lock().unwrap().push("enable".into());
        (true, vec![])
    }
    fn disable_unit_files(
        &self,
        files: Vec<String>,
        runtime: bool,
    ) -> Vec<(String, String, String)> {
        assert_eq!(files, vec![UNIT]);
        assert!(!runtime);
        self.0.enabled.store(false, Ordering::SeqCst);
        self.0.calls.lock().unwrap().push("disable".into());
        vec![]
    }
    async fn restart_unit(
        &self,
        name: &str,
        mode: &str,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> OwnedObjectPath {
        assert_eq!(name, UNIT);
        assert_eq!(mode, "replace");
        self.0.calls.lock().unwrap().push("restart".into());
        self.queue(true, emitter.to_owned()).await
    }
    async fn stop_unit(
        &self,
        name: &str,
        mode: &str,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> OwnedObjectPath {
        assert_eq!(name, UNIT);
        assert_eq!(mode, "replace");
        self.0.calls.lock().unwrap().push("stop".into());
        self.queue(false, emitter.to_owned()).await
    }
    #[zbus(signal)]
    async fn job_removed(
        emitter: &SignalEmitter<'_>,
        id: u32,
        job: OwnedObjectPath,
        unit: &str,
        result: &str,
    ) -> zbus::Result<()>;
}

#[tokio::test]
#[allow(deprecated)]
async fn adoption_handoff_uses_typed_literal_arguments_and_an_independent_transient_service(
) -> Result<()> {
    let (server, client) = tokio::net::UnixStream::pair()?;
    let state = Arc::new(State::default());
    let server = zbus::connection::Builder::unix_stream(server)
        .server(zbus::Guid::generate())?
        .p2p()
        .serve_at("/org/freedesktop/systemd1", FakeManager(state.clone()))?;
    let client = zbus::connection::Builder::unix_stream(client).p2p();
    let (_server, client) = tokio::try_join!(server.build(), client.build())?;
    let controller = Systemd::from_connection(client);
    let arguments = vec![
        "adopt-legacy".into(),
        "--apply".into(),
        "--legacy-root".into(),
        "/private/literal $PORTHUB_UNSET %q".into(),
    ];
    let unit = controller
        .schedule_adoption(
            std::path::Path::new("/private/immutable/porthub"),
            &arguments,
        )
        .await?;
    ensure!(
        unit.starts_with("porthub-adoption-")
            && state.calls.lock().unwrap().as_slice() == ["handoff"]
    );
    ensure!(controller
        .schedule_adoption(
            std::path::Path::new("/private/immutable/porthub"),
            &["other-command".into(), "--apply".into()]
        )
        .await
        .is_err());
    let update_arguments = vec![
        "update".into(),
        "--apply".into(),
        "--profile".into(),
        "/private/literal $PORTHUB_UNSET %q".into(),
    ];
    ensure!(controller
        .schedule_update(
            std::path::Path::new("/private/immutable/porthub"),
            &update_arguments
        )
        .await?
        .starts_with("porthub-update-"));
    ensure!(controller
        .schedule_update(
            std::path::Path::new("/private/immutable/porthub"),
            &arguments
        )
        .await
        .is_err());
    Ok(())
}
impl FakeManager {
    async fn queue(&self, start: bool, emitter: SignalEmitter<'static>) -> OwnedObjectPath {
        let id = self.0.jobs.fetch_add(1, Ordering::SeqCst) + 1;
        let path =
            OwnedObjectPath::try_from(format!("/org/freedesktop/systemd1/job/{id}")).unwrap();
        let job = path.clone();
        let state = self.0.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let fail = state.fail.swap(false, Ordering::SeqCst);
            if !fail {
                state.active.store(start, Ordering::SeqCst);
            }
            FakeManager::job_removed(
                &emitter,
                id,
                job,
                UNIT,
                if fail { "failed" } else { "done" },
            )
            .await
            .unwrap();
        });
        path
    }
}
#[tokio::test]
#[allow(deprecated)]
async fn native_dbus_controller_waits_for_its_job_and_reports_failed_restarts() -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (server, client) = tokio::net::UnixStream::pair()?;
        let guid = zbus::Guid::generate();
        let state = Arc::new(State::default());
        let server = zbus::connection::Builder::unix_stream(server)
            .server(guid)?
            .p2p()
            .serve_at("/org/freedesktop/systemd1", FakeManager(state.clone()))?
            .serve_at(PATH, FakeUnit(state.clone()))?;
        let client = zbus::connection::Builder::unix_stream(client).p2p();
        let (_server, client) = tokio::try_join!(server.build(), client.build())?;
        let controller = Systemd::from_connection(client);
        let spec = Spec {
            cli: None,
            user: false,
            identity: "a".repeat(64),
            service: "porthub-systemd-fixture".into(),
            profile: "/private/profile".into(),
            executable: "/private/executable".into(),
            unit: "/private/unit".into(),
        };
        ensure!(!controller.state(&spec).await?.enabled);
        controller.reload().await?;
        controller.reset_failed(&spec).await?;
        controller.enable(&spec).await?;
        controller.start(&spec).await?;
        ensure!(controller.state(&spec).await?.active);
        // Old state stays active while a failing restart is queued. Treating
        // that state as completion would silently accept a failed installation.
        state.fail.store(true, Ordering::SeqCst);
        let started = std::time::Instant::now();
        ensure!(controller.start(&spec).await.is_err());
        ensure!(started.elapsed() >= std::time::Duration::from_millis(90));
        controller.stop(&spec).await?;
        controller.disable(&spec).await?;
        let status = controller.state(&spec).await?;
        ensure!(!status.active && !status.enabled);
        ensure!(state.subscribed.load(Ordering::SeqCst) == 1);
        ensure!(state.calls.lock().unwrap().iter().all(|call| [
            "reload",
            "enable",
            "restart",
            "stop",
            "disable",
            "reset-failed"
        ]
        .contains(&call.as_str())));
        Ok::<(), anyhow::Error>(())
    })
    .await?
}
