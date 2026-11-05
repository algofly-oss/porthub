//! Process startup is separate from requests. A verified executable serves many
//! typed calls; mutation failures are never replayed automatically.
use crate::{catalog::Component, local::Endpoint, rpc::Client, store::Manager};
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
impl Manager {
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
        let (artifact, executable) = self.resolve(component, cancel).await?;
        let context_digest = format!(
            "{:x}",
            Sha256::digest(context.state_directory.as_os_str().as_encoded_bytes())
        );
        let identity = self.cache_root().join(context_digest);
        let endpoint = Endpoint::for_artifact(&identity, &artifact)?;
        if let Ok(client) = Client::connect(&endpoint, &artifact).await {
            return Ok(client);
        }
        let _lock = crate::store::lock(
            self.cache_root(),
            &format!("{component}.worker.lock"),
            cancel,
        )
        .await?;
        // A concurrent CLI/service may have started it while this caller waited.
        if let Ok(client) = Client::connect(&endpoint, &artifact).await {
            return Ok(client);
        }
        let attempt_path = self
            .cache_root()
            .join(format!("{component}.worker-attempts.json"));
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
            child: Some(crate::process::spawn(
                &executable,
                endpoint.address(),
                &context.state_directory,
            )?),
        };
        let ready = tokio::time::timeout(Duration::from_secs(10), async {
            let mut delay = Duration::from_millis(25);
            loop {
                if let Ok(client) = Client::connect(&endpoint, &artifact).await { return Ok(client); }
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
