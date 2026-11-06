use anyhow::Result;
use async_trait::async_trait;
use porthub_components::{
    maintenance::{Guard, Options},
    store::{Manager, Settings, Sources},
    transport::Transport,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use url::Url;
struct Stalled {
    entered: Notify,
    active: Arc<AtomicBool>,
}
struct Active(Arc<AtomicBool>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}
#[async_trait]
impl Transport for Stalled {
    async fn fetch(&self, _: &Url, _: &Path, _: u64) -> Result<()> {
        self.active.store(true, Ordering::SeqCst);
        let _guard = Active(self.active.clone());
        self.entered.notify_one();
        std::future::pending().await
    }
}
#[tokio::test]
async fn blocked_component_download_does_not_block_startup_and_is_cancelled_on_shutdown() {
    let root = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let active = Arc::new(AtomicBool::new(false));
    let transport = Arc::new(Stalled {
        entered: Notify::new(),
        active: active.clone(),
    });
    let manager = Manager::new(
        root.path().join("components"),
        Settings {
            gateway: None,
            sources: Sources::GithubOnly,
            core: "1.10.1".parse().unwrap(),
            target: "x86_64-unknown-linux-gnu".into(),
            disabled: BTreeSet::new(),
            pins: BTreeMap::new(),
        },
        transport.clone(),
    )
    .unwrap();
    let cancel = CancellationToken::new();
    let guard = Guard::start(manager, Options::default(), &cancel);
    let status = guard.status();
    tokio::time::timeout(Duration::from_secs(2), transport.entered.notified())
        .await
        .unwrap();
    // Normal work is schedulable while the download remains pending.
    assert_eq!(tokio::spawn(async { 42 }).await.unwrap(), 42);
    assert!(status.borrow().running && active.load(Ordering::SeqCst));
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), async {
        while active.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(guard);
}
