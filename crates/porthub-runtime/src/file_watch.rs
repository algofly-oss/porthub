//! Bounded native filesystem notifications for server configuration. Watching
//! directories also catches atomically replaced files, without idle rescans.
use anyhow::{Context, Result};
use notify::{RecursiveMode, Watcher};
use std::{collections::HashSet, path::PathBuf};
pub struct FileChanges {
    _watcher: notify::RecommendedWatcher,
    events: tokio::sync::mpsc::Receiver<()>,
}
impl FileChanges {
    pub fn new(paths: &[PathBuf]) -> Result<Self> {
        let root = std::env::current_dir()?;
        let wanted: HashSet<PathBuf> = paths
            .iter()
            .map(|path| {
                if path.is_absolute() {
                    path.clone()
                } else {
                    root.join(path)
                }
            })
            .collect();
        let parents: HashSet<PathBuf> = wanted
            .iter()
            .map(|path| {
                path.parent()
                    .map(PathBuf::from)
                    .context("configuration needs a parent directory")
            })
            .collect::<Result<_>>()?;
        let (sender, events) = tokio::sync::mpsc::channel(1);
        let mut watcher =
            notify::recommended_watcher(move |event: notify::Result<notify::Event>| match event {
                Ok(event)
                    if matches!(
                        event.kind,
                        notify::EventKind::Create(_)
                            | notify::EventKind::Modify(_)
                            | notify::EventKind::Remove(_)
                    ) && event.paths.iter().any(|path| wanted.contains(path)) =>
                {
                    let _ = sender.try_send(());
                }
                Err(error) => {
                    tracing::warn!("configuration watcher reported an error");
                    tracing::debug!(%error,"configuration watcher details");
                }
                _ => {}
            })?;
        for parent in parents {
            watcher.watch(&parent, RecursiveMode::NonRecursive)?;
        }
        Ok(Self {
            _watcher: watcher,
            events,
        })
    }
    pub async fn changed(&mut self) -> Option<()> {
        self.events.recv().await
    }
}
