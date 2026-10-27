//! Installed public services only. One dormant worker handles requested native
//! updates; forwarding and connection establishment never wait on maintenance.
use crate::{
    profile::{self, Profile},
    service::{self, Layout, Spec},
    update::Request,
    upgrade,
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct Native {
    layout: Layout,
    source: PathBuf,
    public: Profile,
    executable: PathBuf,
}
impl Native {
    async fn inspect(source: &Path, public: &Profile) -> Result<Option<Self>> {
        let id = service::identity(public);
        let Some(state) = source.parent() else {
            return Ok(None);
        };
        let manifest = state.join(format!("{id}.service.json"));
        if !manifest.try_exists()? {
            return Ok(None);
        }
        let spec: Spec = serde_json::from_slice(&profile::read_private(&manifest)?)?;
        ensure!(
            spec.profile == source && spec.identity == id,
            "native update profile identity mismatch"
        );
        let layout = Layout {
            user: spec.user,
            state: state.into(),
            units: spec
                .unit
                .parent()
                .context("native unit directory missing")?
                .into(),
            releases: spec
                .executable
                .parent()
                .and_then(Path::parent)
                .context("native release directory missing")?
                .into(),
        };
        ensure!(
            service::installed(&layout, &id)?.as_ref() == Some(&spec),
            "invalid native update registration"
        );
        let executable = std::env::current_exe()?.canonicalize()?;
        // A foreground process using a copied managed profile cannot update a
        // different installed executable or act as that service's updater.
        ensure!(
            spec.executable.canonicalize()? == executable,
            "running executable does not match native registration"
        );
        #[cfg(target_os = "linux")]
        {
            let cgroup = std::fs::read_to_string("/proc/self/cgroup")?;
            ensure!(
                cgroup.contains(&format!("{}.service", spec.service)),
                "automatic updates require the registered service process"
            );
        }
        #[cfg(target_os = "macos")]
        ensure!(
            crate::service::launchd::Launchd::connect(spec.user)
                .await?
                .owns_process(&spec, std::process::id())
                .await?,
            "automatic updates require the registered launchd service process"
        );
        Ok(Some(Self {
            layout,
            source: source.into(),
            public: public.clone(),
            executable,
        }))
    }
    fn cli(&self) -> Result<PathBuf> {
        let spec = service::installed(&self.layout, &service::identity(&self.public))?
            .context("native registration disappeared")?;
        let cli = spec
            .cli
            .unwrap_or(crate::bootstrap::cli_path(self.layout.user, None)?);
        service::publication::managed_link(&self.layout, &cli)?;
        Ok(cli)
    }
    fn committed(&self, request: &Request) -> Result<bool> {
        upgrade::committed(
            &self.layout,
            &self.source,
            &self.public,
            request,
            &self.executable,
        )
    }
}
pub(crate) struct Controller {
    native: Native,
    settings: watch::Sender<Option<Request>>,
    current: Option<Request>,
    events: mpsc::Receiver<()>,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Controller {
    pub async fn new(source: &Path, public: &Profile) -> Result<Option<Self>> {
        let Some(native) = Native::inspect(source, public).await? else {
            return Ok(None);
        };
        let (settings, receiver) = watch::channel(None);
        let (sender, events) = mpsc::channel(1);
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(native.clone(), receiver, sender, stop.clone()));
        Ok(Some(Self {
            native,
            settings,
            current: None,
            events,
            stop,
            task,
        }))
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn private_activation_context(&self) -> Option<(Layout, PathBuf)> {
        (!self.native.layout.user)
            .then(|| (self.native.layout.clone(), self.native.executable.clone()))
    }
    pub fn request(&mut self, request: Option<Request>) {
        if self.current != request {
            self.settings.send_replace(request.clone());
            self.current = request;
        }
    }
    pub fn handled(&self) -> String {
        self.current
            .as_ref()
            .filter(|request| self.native.committed(request).unwrap_or(false))
            .map(|request| request.id.clone())
            .unwrap_or_default()
    }
    pub async fn next(&mut self) -> Option<()> {
        self.events.recv().await
    }
    pub async fn stop(&mut self) {
        self.stop.cancel();
        if tokio::time::timeout(Duration::from_secs(5), &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
        }
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.task.abort();
    }
}
#[derive(Serialize, Deserialize)]
struct Attempt {
    request: Request,
    started: u64,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn cooldown(native: &Native, request: &Request) -> Result<bool> {
    let path = profile::sibling(&native.source, ".update-attempt.json");
    if !path.try_exists()? {
        return Ok(false);
    }
    let attempt: Attempt = serde_json::from_slice(&profile::read_private(&path)?)?;
    let now = now();
    Ok(attempt.request == *request && now.abs_diff(attempt.started) < 300)
}
async fn terminate(child: &mut tokio::process::Child) {
    if let Some(pid) = child
        .id()
        .and_then(|pid| rustix::process::Pid::from_raw(pid as i32))
    {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
    }
    if tokio::time::timeout(Duration::from_secs(3), child.wait())
        .await
        .is_err()
    {
        let _ = child.kill().await;
    }
}
async fn run(
    native: Native,
    mut settings: watch::Receiver<Option<Request>>,
    events: mpsc::Sender<()>,
    stop: CancellationToken,
) {
    let mut terminal: Option<Request> = None;
    loop {
        let request = settings.borrow_and_update().clone();
        let Some(request) = request else {
            tokio::select! {_=stop.cancelled()=>return,result=settings.changed()=>if result.is_err(){return;}}
            continue;
        };
        if terminal.as_ref() == Some(&request) {
            tokio::select! {_=stop.cancelled()=>return,result=settings.changed()=>if result.is_err(){return;}}
            continue;
        }
        if native.committed(&request).unwrap_or(false) {
            let _ = events.try_send(());
            terminal = Some(request);
            continue;
        }
        if upgrade::failed(&native.layout, &native.source, &request).unwrap_or(false) {
            tracing::warn!("requested native update rolled back; waiting for another request");
            terminal = Some(request);
            continue;
        }
        let cli = native.cli();
        let attempt = if let Ok(cli) = cli {
            if cooldown(&native, &request).unwrap_or(true) || service::lock(&native.layout).is_err()
            {
                None
            } else {
                Some(cli)
            }
        } else {
            None
        };
        if let Some(cli) = attempt {
            let result: Result<tokio::process::Child> = (|| {
                profile::write_private(
                    &profile::sibling(&native.source, ".update-attempt.json"),
                    &serde_json::to_vec(&Attempt {
                        request: request.clone(),
                        started: now(),
                    })?,
                    true,
                )?;
                let mut command = tokio::process::Command::new(&native.executable);
                command
                    .arg("update")
                    .arg("--profile")
                    .arg(&native.source)
                    .arg("--request-id")
                    .arg(&request.id)
                    .arg("--target-version")
                    .arg(&request.target_version)
                    .arg("--bin-dir")
                    .arg(cli.parent().context("native CLI directory missing")?)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .kill_on_drop(true);
                if native.layout.user {
                    command.arg("--user");
                    command.env(
                        "XDG_CONFIG_HOME",
                        native
                            .layout
                            .state
                            .parent()
                            .and_then(Path::parent)
                            .context("native config directory missing")?,
                    );
                    command.env(
                        "XDG_DATA_HOME",
                        native
                            .layout
                            .releases
                            .parent()
                            .and_then(Path::parent)
                            .context("native data directory missing")?,
                    );
                }
                Ok(command.spawn()?)
            })();
            match result {
                Ok(mut child) => tokio::select! {
                    _=stop.cancelled()=>{terminate(&mut child).await;return;},
                    result=settings.changed()=>{terminate(&mut child).await;if result.is_err(){return;}continue;},
                    result=tokio::time::timeout(Duration::from_secs(720),child.wait())=>{
                        if !matches!(result,Ok(Ok(status)) if status.success()) {
                            terminate(&mut child).await;
                            tracing::warn!("native update preparation failed; retry is delayed");
                        }
                    },
                },
                Err(_) => {
                    tracing::warn!("native update preparation unavailable; retry is delayed");
                }
            }
        }
        tokio::select! {_=stop.cancelled()=>return,result=settings.changed()=>if result.is_err(){return;},_=tokio::time::sleep(Duration::from_secs(1))=>{}}
    }
}
