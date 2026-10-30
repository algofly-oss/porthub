//! Built-in local tunnel supervision, independent of API/UI refresh requests.
//! The explicit force-refresh controls keep their existing reconnect semantics.
use crate::profile;
use porthub_tunnel::{ServiceHealth, ServiceHealthHandle};
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::watch;
const CHECK_INTERVAL: Duration = Duration::from_secs(30);
pub struct Monitor {
    settings: watch::Sender<HashMap<String, ServiceHealthHandle>>,
    task: tokio::task::JoinHandle<()>,
}
impl Monitor {
    pub fn new(path: &Path) -> Self {
        let (settings, receiver) = watch::channel(HashMap::new());
        let output = profile::sibling(path, ".service-health.json");
        let task = tokio::spawn(run(receiver, output));
        Self { settings, task }
    }
    pub fn configure(&self, handles: HashMap<String, ServiceHealthHandle>) {
        self.settings.send_replace(handles);
    }
    pub fn clear(&self) {
        self.settings.send_replace(HashMap::new());
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn run(mut settings: watch::Receiver<HashMap<String, ServiceHealthHandle>>, output: PathBuf) {
    let mut interval = tokio::time::interval(CHECK_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut previous: BTreeMap<String, ServiceHealth> = BTreeMap::new();
    loop {
        tokio::select! {
            changed=settings.changed()=>if changed.is_err(){return;},
            _=interval.tick()=>{
                let handles=settings.borrow().clone();
                previous.retain(|service,_|handles.contains_key(service));
                if handles.is_empty(){continue;}
                for (service,handle) in &handles {
                    let status=handle.check();
                    if status.state=="healthy" && previous.get(service).is_some_and(|old|status.control_recoveries>old.control_recoveries){
                        tracing::info!(service=service.as_str(),recoveries=status.control_recoveries,"tunnel control recovered; existing transfers retained");
                    }
                    previous.insert(service.clone(),status);
                }
                let observed=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                let snapshot=serde_json::json!({"observed_at":observed,"services":previous});
                if let Ok(bytes)=serde_json::to_vec(&snapshot){
                    if profile::write_private(&output,&bytes,true).is_err(){tracing::debug!("local tunnel health snapshot unavailable");}
                }
            },
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    #[tokio::test(start_paused = true)]
    async fn builtin_checks_run_without_api_or_ui_preferences() -> Result<()> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let path = directory.path().join("profile.json");
        // A transport that accepts TCP but never completes its protocol. There
        // is no API client, HTTP server, UI setting or saved schedule here.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let client=porthub_tunnel::EmbeddedClient::new(porthub_tunnel::Config::from_str(&format!("[client]\nremote_addr='{address}'\n[client.services.fixture]\ntoken='fixture'\nlocal_addr='127.0.0.1:1'\n"))?).await?;
        let handle = client.health_handles()["fixture"].clone();
        let monitor = Monitor::new(&path);
        monitor.configure(client.health_handles());
        tokio::task::yield_now().await;
        let first = handle.check().checks;
        tokio::time::advance(CHECK_INTERVAL).await;
        tokio::task::yield_now().await;
        assert!(
            handle.check().checks > first + 1,
            "local schedule stopped without API access"
        );
        let snapshot = profile::sibling(&path, ".service-health.json");
        assert!(snapshot.exists());
        let data: serde_json::Value = serde_json::from_slice(&std::fs::read(&snapshot)?)?;
        assert!(data["services"]["fixture"]["checks"].as_u64().unwrap() > 0);
        monitor.clear();
        tokio::task::yield_now().await;
        let before = handle.check().checks;
        tokio::time::advance(CHECK_INTERVAL * 3).await;
        tokio::task::yield_now().await;
        assert_eq!(
            handle.check().checks,
            before + 1,
            "revoked services must not be checked"
        );
        drop(monitor);
        client.shutdown().await;
        Ok(())
    }
}
