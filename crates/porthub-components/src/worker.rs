//! Process startup is separate from requests. A verified executable serves many
//! typed calls; mutation failures are never replayed automatically.
use crate::{
    catalog::{Artifact, Component},
    local::Endpoint,
    rpc::Client,
    store::Manager,
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct ContextOptions {
    pub state_directory: PathBuf,
}
#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Attempts {
    count: u8,
    last_start: u64,
    retry_at: u64,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
/// Administrator-selected transport. Auto only falls back during startup,
/// before a tool request is sent; it never replays a failed operation.
#[derive(Clone, Copy, Debug, Default)]
pub enum Mode {
    #[default]
    Auto,
    Rpc,
    Cli,
}
impl Manager {
    pub async fn connect(
        &self,
        component: Component,
        context: &ContextOptions,
        mode: Mode,
        cancel: &CancellationToken,
    ) -> Result<Client> {
        ensure!(
            context.state_directory.is_absolute(),
            "component state requires an absolute directory"
        );
        // Policy, compatibility, catalog authorization and verification failures
        // propagate directly. They must never trigger a different download path.
        let (artifact, executable) = self.resolve(component, cancel).await?;
        let result = self
            .connect_resolved(component, context, mode, cancel, &artifact, &executable)
            .await;
        match result {
            Ok(client) => {
                self.record_activation(context, &artifact)?;
                Ok(client)
            }
            Err(error) => {
                if cancel.is_cancelled() {
                    return Err(error);
                }
                // Only tools that completed a handshake in this context qualify.
                // installed() rechecks hashes, compatibility, disabled policy and pins.
                let mut tried = 0;
                for (previous, path) in self
                    .installed(component)
                    .await?
                    .into_iter()
                    .filter(|(candidate, _)| candidate.version < artifact.version)
                {
                    if !self.was_activated(context, &previous)? {
                        continue;
                    }
                    if tried >= 4 {
                        break;
                    }
                    tried += 1;
                    if let Ok(client) = self
                        .connect_resolved(component, context, mode, cancel, &previous, &path)
                        .await
                    {
                        tracing::warn!(component = %component, version = %previous.version,
                            "using previously activated compatible component after candidate startup failure");
                        return Ok(client);
                    }
                    if cancel.is_cancelled() {
                        break;
                    }
                }
                Err(error)
            }
        }
    }

    fn activation_path(&self, context: &ContextOptions, artifact: &Artifact) -> Result<PathBuf> {
        let identity = self.cache_root().join(format!(
            "{:x}",
            Sha256::digest(context.state_directory.as_os_str().as_encoded_bytes())
        ));
        let key = Endpoint::for_artifact(&identity, artifact)?.startup_key();
        Ok(self
            .cache_root()
            .join(format!("activated-{}-{key}.json", artifact.component)))
    }
    fn was_activated(&self, context: &ContextOptions, artifact: &Artifact) -> Result<bool> {
        let path = self.activation_path(context, artifact)?;
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                ensure!(
                    crate::store::regular(&path)?.len() <= 16384,
                    "invalid component activation receipt"
                );
                let previous: Artifact = serde_json::from_slice(&std::fs::read(path)?)?;
                Ok(previous.same_tool(artifact))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    fn record_activation(&self, context: &ContextOptions, artifact: &Artifact) -> Result<()> {
        use std::io::Write;
        let path = self.activation_path(context, artifact)?;
        let mut receipt = tempfile::NamedTempFile::new_in(self.cache_root())?;
        receipt.write_all(&serde_json::to_vec(artifact)?)?;
        receipt.as_file().sync_all()?;
        receipt.persist(path).map_err(|error| error.error)?;
        Ok(())
    }
    async fn connect_resolved(
        &self,
        component: Component,
        context: &ContextOptions,
        mode: Mode,
        cancel: &CancellationToken,
        artifact: &Artifact,
        executable: &Path,
    ) -> Result<Client> {
        if !matches!(mode, Mode::Cli) {
            match self
                .worker_resolved(component, context, cancel, &artifact, &executable)
                .await
            {
                Ok(client) => return Ok(client),
                Err(error) if matches!(mode, Mode::Rpc) || cancel.is_cancelled() => {
                    return Err(error)
                }
                Err(_) => tracing::debug!(
                    "local component worker unavailable; invoking verified CLI over private pipes"
                ),
            }
        }
        ensure!(!cancel.is_cancelled(), "component invocation cancelled");
        use std::process::Stdio;
        let mut process = crate::process::retry_spawn(cancel, || {
            tokio::process::Command::new(&executable)
                .arg("__porthub-stdio")
                .env("PORTHUB_STATE_DIR", &context.state_directory)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .context("cannot invoke verified component CLI")
        })
        .await?;
        let reader = process
            .stdout
            .take()
            .context("component stdout unavailable")?;
        let writer = process
            .stdin
            .take()
            .context("component stdin unavailable")?;
        let stream = Box::new(crate::stdio::Child {
            pipes: crate::stdio::Pair::new(reader, writer),
            process,
        });
        tokio::select! { biased; _ = cancel.cancelled() => anyhow::bail!("component invocation cancelled"), result = Client::from_stream(stream, artifact) => result }
    }

    pub async fn worker(
        &self,
        component: Component,
        context: &ContextOptions,
        cancel: &CancellationToken,
    ) -> Result<Client> {
        ensure!(
            context.state_directory.is_absolute(),
            "component state requires an absolute directory"
        );
        self.connect(component, context, Mode::Rpc, cancel).await
    }
    async fn worker_resolved(
        &self,
        component: Component,
        context: &ContextOptions,
        cancel: &CancellationToken,
        artifact: &Artifact,
        executable: &Path,
    ) -> Result<Client> {
        let context_digest = format!(
            "{:x}",
            Sha256::digest(context.state_directory.as_os_str().as_encoded_bytes())
        );
        let identity = self.cache_root().join(context_digest);
        let endpoint = Endpoint::for_artifact(&identity, artifact)?;
        if let Ok(client) = Client::connect(&endpoint, artifact).await {
            return Ok(client);
        }
        let startup_key = endpoint.startup_key();
        let _lock = crate::store::lock(
            self.cache_root(),
            &format!("{component}.{startup_key}.worker.lock"),
            cancel,
        )
        .await?;
        // A concurrent CLI/service may have started it while this caller waited.
        if let Ok(client) = Client::connect(&endpoint, artifact).await {
            return Ok(client);
        }
        let attempt_path = self
            .cache_root()
            .join(format!("{component}.{startup_key}.worker-attempts.json"));
        let mut attempts = read_attempts(&attempt_path)?;
        ensure!(
            now() >= attempts.retry_at,
            "component worker is backing off after an unsuccessful start; retry shortly"
        );
        attempts.count = if now().saturating_sub(attempts.last_start) >= 60 {
            1
        } else {
            attempts.count.saturating_add(1).min(6)
        };
        attempts.last_start = now();
        let delay = 1u64 << attempts.count;
        attempts.retry_at = now().saturating_add(delay);
        write_attempts(&attempt_path, &attempts)?;
        let mut child = Starting {
            child: Some(
                crate::process::retry_spawn(cancel, || {
                    crate::process::spawn(executable, endpoint.address(), &context.state_directory)
                })
                .await?,
            ),
        };
        let ready = tokio::time::timeout(Duration::from_secs(10), async {
            let mut delay = Duration::from_millis(25);
            loop {
                if let Ok(client) = Client::connect(&endpoint, artifact).await { return Ok(client); }
                ensure!(!child.exited()?, "component worker exited during startup");
                tokio::select! { biased; _ = cancel.cancelled() => anyhow::bail!("component worker start cancelled"), _ = tokio::time::sleep(delay) => {} }
                delay = (delay * 2).min(Duration::from_millis(500));
            }
        }).await;
        match ready {
            Ok(Ok(client)) => {
                // Reap on exit without terminating the persistent shared worker
                // when an interactive launcher finishes. Idle workers self-exit.
                let mut process = child.child.take().context("component child unavailable")?;
                tokio::spawn(async move {
                    let _ = process.wait().await;
                });
                Ok(client)
            }
            result => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                attempts.retry_at = now().saturating_add(delay);
                write_attempts(&attempt_path, &attempts)?;
                match result {
                    Ok(Err(error)) => Err(error),
                    _ => anyhow::bail!("component worker did not become ready within ten seconds"),
                }
            }
        }
    }
}
struct Starting {
    child: Option<crate::process::Child>,
}
impl std::ops::Deref for Starting {
    type Target = crate::process::Child;
    fn deref(&self) -> &Self::Target {
        self.child.as_ref().expect("startup guard owns a child")
    }
}
impl std::ops::DerefMut for Starting {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.child.as_mut().expect("startup guard owns a child")
    }
}
impl Drop for Starting {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let _ = child.wait().await;
                });
            }
        }
    }
}
fn read_attempts(path: &Path) -> Result<Attempts> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 4096,
                "invalid worker retry state"
            );
            Ok(serde_json::from_slice(&std::fs::read(path)?)?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Attempts::default()),
        Err(error) => Err(error.into()),
    }
}
fn write_attempts(path: &Path, attempts: &Attempts) -> Result<()> {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new_in(
        path.parent()
            .context("worker retry state requires a parent")?,
    )?;
    file.write_all(&serde_json::to_vec(attempts)?)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    Ok(())
}
