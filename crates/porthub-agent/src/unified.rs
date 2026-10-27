//! One service owns independently supervised public and private modules.
//! Private failures must not restart established public forwarding streams.
use anyhow::Result;
use std::{
    future::Future,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// Pair by enrolled authority and machine identity, never email, IP, or a
/// fallback URL shared by otherwise unrelated registrations.
pub(crate) fn matches(
    public: &crate::profile::Profile,
    private: &crate::private_profile::Profile,
) -> bool {
    public.server == private.server
        && !private.workspace.is_empty()
        && private.peer_id == format!("{}:{}", private.workspace, public.machine_id)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    pub format_version: u32,
    pub private_profile: PathBuf,
    pub enabled: bool,
}

pub(crate) fn configuration_path(public_path: &Path) -> PathBuf {
    crate::profile::sibling(public_path, ".private-module.json")
}

pub(crate) fn load(
    public_path: &Path,
    public: &crate::profile::Profile,
) -> Result<Option<Configuration>> {
    let path = configuration_path(public_path);
    if !path.try_exists()? {
        return Ok(None);
    }
    let configuration: Configuration =
        serde_json::from_slice(&crate::profile::read_private(&path)?)?;
    anyhow::ensure!(
        configuration.format_version == 1,
        "unsupported private module configuration"
    );
    let private = crate::private_profile::Profile::load(&configuration.private_profile)?;
    let id = crate::service::RegistrationProfile::Private(private.clone()).identity();
    anyhow::ensure!(
        matches(public, &private)
            && configuration.private_profile
                == public_path
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("registration directory missing"))?
                    .join(format!("{id}.json")),
        "private module does not belong to this registration"
    );
    Ok(Some(configuration))
}

pub(crate) fn save(
    public_path: &Path,
    public: &crate::profile::Profile,
    configuration: &Configuration,
) -> Result<()> {
    let private = crate::private_profile::Profile::load(&configuration.private_profile)?;
    let id = crate::service::RegistrationProfile::Private(private.clone()).identity();
    anyhow::ensure!(
        configuration.format_version == 1
            && matches(public, &private)
            && Some(configuration.private_profile.as_path())
                == public_path
                    .parent()
                    .map(|root| root.join(format!("{id}.json")))
                    .as_deref(),
        "private module does not belong to this registration"
    );
    crate::profile::write_private(
        &configuration_path(public_path),
        &serde_json::to_vec(configuration)?,
        true,
    )
}

pub(crate) struct Controller {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Controller {
    pub(crate) fn start(
        public_path: &Path,
        public: &crate::profile::Profile,
        logs: crate::logs::Buffer,
    ) -> Result<Self> {
        use notify::Watcher;
        let wanted = configuration_path(public_path);
        let (changes, mut changed) = tokio::sync::mpsc::channel(1);
        let notifications = changes.clone();
        let target = wanted.clone();
        let mut watcher = (|| -> Result<notify::RecommendedWatcher> {
            let mut watcher = notify::recommended_watcher(
                move |event: notify::Result<notify::Event>| match event {
                    Ok(event)
                        if event.paths.iter().any(|path| path == &target)
                            && matches!(
                                event.kind,
                                notify::EventKind::Create(_)
                                    | notify::EventKind::Modify(_)
                                    | notify::EventKind::Remove(_)
                            ) =>
                    {
                        let _ = notifications.try_send(false);
                    }
                    Err(_) => {
                        let _ = notifications.try_send(true);
                    }
                    _ => {}
                },
            )?;
            watcher.watch(
                wanted
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("module directory missing"))?,
                notify::RecursiveMode::NonRecursive,
            )?;
            Ok(watcher)
        })()
        .ok();
        let configuration = load(public_path, public).unwrap_or_else(|_| {
            tracing::warn!(
                "private module configuration rejected; waiting for a valid replacement"
            );
            None
        });
        if let Some(config) = &configuration {
            if let Ok(private) = crate::private_profile::Profile::load(&config.private_profile) {
                logs.include_private(&private);
            }
        }
        let selected = configuration
            .filter(|config| config.enabled)
            .map(|config| config.private_profile);
        let (configuration, receiver) = watch::channel(selected);
        let cancel = CancellationToken::new();
        let supervisor = tokio::spawn(supervise(receiver, cancel.clone(), move |path, cancel| {
            crate::private_network::runtime::run_embedded(path, cancel)
        }));
        let path = public_path.to_owned();
        let public = public.clone();
        let stop = cancel.clone();
        let updates = configuration.clone();
        let task = tokio::spawn(async move {
            let _keepalive = changes;
            let mut fallback = tokio::time::interval(Duration::from_secs(60));
            fallback.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    event = changed.recv() => {
                        if event == Some(true) { watcher = None; }
                        if event.is_none() { break; }
                    },
                    _ = fallback.tick(), if watcher.is_none() => {},
                }
                match load(&path, &public) {
                    Ok(value) => {
                        if let Some(value) = &value {
                            if let Ok(private) =
                                crate::private_profile::Profile::load(&value.private_profile)
                            {
                                logs.include_private(&private);
                            }
                        }
                        let selected = value
                            .filter(|value| value.enabled)
                            .map(|value| value.private_profile);
                        updates.send_if_modified(|current| {
                            if *current == selected {
                                false
                            } else {
                                *current = selected;
                                true
                            }
                        });
                    }
                    Err(_) => tracing::warn!(
                        "private module change rejected; retaining the current configuration"
                    ),
                }
            }
            stop.cancel();
            let _ = supervisor.await;
        });
        Ok(Self { cancel, task })
    }
    pub(crate) async fn stop(&mut self) {
        self.cancel.cancel();
        let _ = (&mut self.task).await;
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

struct Worker {
    stop: CancellationToken,
    task: tokio::task::JoinHandle<Result<()>>,
}
impl Worker {
    async fn shutdown(mut self) {
        self.stop.cancel();
        if tokio::time::timeout(Duration::from_secs(30), &mut self.task)
            .await
            .is_err()
        {
            tracing::warn!("private module shutdown exceeded its deadline");
            self.task.abort();
            let _ = (&mut self.task).await;
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}

/// Watch-based supervision: no idle polling, one worker at a time, bounded
/// retry on failure, and graceful cleanup before replacing a private runtime.
pub(crate) async fn supervise<F, Fut>(
    mut configuration: watch::Receiver<Option<PathBuf>>,
    cancel: CancellationToken,
    mut start: F,
) where
    F: FnMut(PathBuf, CancellationToken) -> Fut,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let mut retry = Duration::from_secs(5);
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let selected = configuration.borrow_and_update().clone();
        let Some(path) = selected.clone() else {
            tokio::select! {
                _ = cancel.cancelled() => return,
                changed = configuration.changed() => if changed.is_err() { return; },
            }
            retry = Duration::from_secs(5);
            continue;
        };
        let stop = cancel.child_token();
        let mut worker = Worker {
            task: tokio::spawn(start(path, stop.clone())),
            stop,
        };
        let began = tokio::time::Instant::now();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => { worker.shutdown().await; return; },
                changed = configuration.changed() => {
                    if changed.is_err() { worker.shutdown().await; return; }
                    if *configuration.borrow_and_update() == selected { continue; }
                    worker.shutdown().await;
                    retry = Duration::from_secs(5);
                    break;
                },
                _ = &mut worker.task => {
                    // Panics and unexpected clean exits receive the same
                    // backoff; neither escapes into the public runtime.
                    worker.stop.cancel();
                    tracing::warn!("private module stopped; retry scheduled");
                    if began.elapsed() >= Duration::from_secs(60) { retry = Duration::from_secs(5); }
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        changed = configuration.changed() => {
                            if changed.is_err() { return; }
                            retry = Duration::from_secs(5);
                        },
                        _ = tokio::time::sleep(retry) => retry = (retry * 2).min(Duration::from_secs(60)),
                    }
                    break;
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    fn profiles() -> (crate::profile::Profile, crate::private_profile::Profile) {
        let public: crate::profile::Profile = serde_json::from_value(serde_json::json!({
            "server":"https://gateway.example", "machine_id":"0123456789abcdef01234567", "token":"public-secret"
        })).unwrap();
        let private = crate::private_profile::Profile {
            server: public.server.clone(),
            workspace: "abcdef0123456789abcdef01".into(),
            peer_id: format!("abcdef0123456789abcdef01:{}", public.machine_id),
            token: "private-secret-0123456789012345678901".into(),
            account_email: None,
            fallback_servers: vec![],
            allow_insecure_http_for_tests: false,
        };
        (public, private)
    }

    #[test]
    fn module_binding_rejects_other_gateways_machines_and_external_profile_paths() -> Result<()> {
        let (mut public, mut private) = profiles();
        assert!(matches(&public, &private));
        private.server = "https://other.example".into();
        public.fallback_servers.push(private.server.clone());
        assert!(!matches(&public, &private));
        private.server = public.server.clone();
        private.peer_id = "abcdef0123456789abcdef01:ffffffffffffffffffffffff".into();
        assert!(!matches(&public, &private));
        let (public, private) = profiles();
        let mut directory = tempfile::Builder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            directory.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let root = directory.tempdir()?;
        let public_path = root.path().join("public.json");
        let id = crate::service::RegistrationProfile::Private(private.clone()).identity();
        let private_path = root.path().join(format!("{id}.json"));
        crate::profile::write_private(&private_path, &serde_json::to_vec(&private)?, false)?;
        let configuration = Configuration {
            format_version: 1,
            private_profile: private_path.clone(),
            enabled: false,
        };
        save(&public_path, &public, &configuration)?;
        assert!(!load(&public_path, &public)?.unwrap().enabled);
        let external = root.path().join("elsewhere.json");
        crate::profile::write_private(&external, &serde_json::to_vec(&private)?, false)?;
        assert!(save(
            &public_path,
            &public,
            &Configuration {
                private_profile: external,
                ..configuration.clone()
            }
        )
        .is_err());
        let mut other = public.clone();
        other.machine_id = "ffffffffffffffffffffffff".into();
        assert!(load(&public_path, &other).is_err());
        assert_eq!(
            load(&public_path, &public)?.unwrap().private_profile,
            private_path
        );
        Ok(())
    }

    #[test]
    fn shared_log_buffer_redacts_both_credentials() {
        let (public, private) = profiles();
        let logs = crate::logs::Buffer::default();
        logs.configure(&public);
        logs.include_private(&private);
        use std::io::Write;
        use tracing_subscriber::fmt::MakeWriter;
        write!(logs.make_writer(), "{} {}", public.token, private.token).unwrap();
        let output = logs.batch(None, 100, 100).lines.join("\n");
        assert!(!output.contains(&public.token));
        assert!(!output.contains(&private.token));
        assert!(output.contains("[redacted]"));
    }

    #[tokio::test]
    async fn replacement_and_shutdown_clean_up_before_starting_another_worker() {
        let (config, receiver) = watch::channel(None);
        let stop = CancellationToken::new();
        let alive = Arc::new(AtomicUsize::new(0));
        let (events, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(supervise(receiver, stop.clone(), {
            let alive = alive.clone();
            move |path, cancel| {
                let alive = alive.clone();
                let events = events.clone();
                async move {
                    assert_eq!(alive.fetch_add(1, Ordering::SeqCst), 0);
                    events.send(path).unwrap();
                    cancel.cancelled().await;
                    alive.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                }
            }
        }));
        config.send(Some("first".into())).unwrap();
        assert_eq!(observed.recv().await.unwrap(), PathBuf::from("first"));
        config.send(Some("second".into())).unwrap();
        assert_eq!(observed.recv().await.unwrap(), PathBuf::from("second"));
        config.send(None).unwrap();
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(alive.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn failed_private_worker_does_not_spin_or_terminate_supervision() {
        let (config, receiver) = watch::channel(Some(PathBuf::from("broken")));
        let stop = CancellationToken::new();
        let attempts = Arc::new(AtomicUsize::new(0));
        let (events, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(supervise(receiver, stop.clone(), {
            let attempts = attempts.clone();
            move |path, cancel| {
                let attempts = attempts.clone();
                let events = events.clone();
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    events.send(path.clone()).unwrap();
                    if path == PathBuf::from("broken") {
                        anyhow::bail!("injected failure");
                    }
                    cancel.cancelled().await;
                    Ok(())
                }
            }
        }));
        assert_eq!(observed.recv().await.unwrap(), PathBuf::from("broken"));
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(!task.is_finished());
        config.send(Some("recovered".into())).unwrap();
        assert_eq!(observed.recv().await.unwrap(), PathBuf::from("recovered"));
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }
}
