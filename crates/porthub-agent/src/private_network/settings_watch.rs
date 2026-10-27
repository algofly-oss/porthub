//! Shared bounded filesystem notifications for local agent preferences.
use anyhow::Result;
use notify::{RecursiveMode, Watcher};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

pub(crate) async fn run<T: Clone + PartialEq + Send + Sync + 'static>(
    profile: PathBuf,
    settings_path: fn(&Path) -> PathBuf,
    load: fn(&Path) -> Result<T>,
    updates: watch::Sender<T>,
    label: &'static str,
    cancel: CancellationToken,
) -> Result<()> {
    let profile = std::fs::canonicalize(profile)?;
    let wanted = settings_path(&profile);
    let (sender, mut changes) = mpsc::channel(1);
    let notifications = sender.clone();
    let target = wanted.clone();
    let mut watcher = (|| -> Result<notify::RecommendedWatcher> {
        let mut watcher =
            notify::recommended_watcher(move |event: notify::Result<notify::Event>| match event {
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
            })?;
        watcher.watch(wanted.parent().unwrap(), RecursiveMode::NonRecursive)?;
        Ok(watcher)
    })()
    .ok();
    if watcher.is_none() {
        tracing::warn!(
            settings = label,
            "settings notifications unavailable; using a slow background refresh"
        );
    }
    // Avoid a closed-channel busy loop if watcher creation fails.
    let _keepalive = sender;
    let mut fallback = tokio::time::interval(Duration::from_secs(60));
    fallback.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Watch before the initial read so an atomic CLI write cannot be missed.
    match load(&profile) {
        Ok(settings) => {
            updates.send_replace(settings);
        }
        Err(_) => tracing::warn!(
            settings = label,
            "settings update rejected; retaining previous preference"
        ),
    }
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            event = changes.recv() => {
                if event.is_none() { return Ok(()); }
                if event == Some(true) && watcher.take().is_some() {
                    tracing::warn!(settings = label, "settings notifications stopped; using a slow background refresh");
                }
            }
            _ = fallback.tick(), if watcher.is_none() => {}
        }
        // File reads/fsync never run in the packet forwarding task.
        let file = profile.clone();
        let value = tokio::task::spawn_blocking(move || load(&file)).await?;
        match value {
            Ok(settings) => {
                updates.send_if_modified(|current| {
                    if *current == settings {
                        false
                    } else {
                        *current = settings.clone();
                        true
                    }
                });
            }
            Err(_) => {
                tracing::warn!(
                    settings = label,
                    "settings update rejected; retaining previous preference"
                )
            }
        }
    }
}
