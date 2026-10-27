//! Shared bounded filesystem notifications for local agent preferences.
use anyhow::Result;
use notify::{RecursiveMode, Watcher};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
// Preference directories are small. Kqueue gives macOS immediate vnode events
// without FSEvents batching/coalescing an atomic replacement with its removal.
#[cfg(target_os="macos")]
type SettingsWatcher=notify::KqueueWatcher;
#[cfg(not(target_os="macos"))]
type SettingsWatcher=notify::RecommendedWatcher;

fn relevant(event:&notify::Event,target:&Path)->bool {
    if event.need_rescan(){return true;}
    if !matches!(event.kind,notify::EventKind::Any|notify::EventKind::Other|notify::EventKind::Create(_)|notify::EventKind::Modify(_)|notify::EventKind::Remove(_)){return false;}
    event.paths.iter().any(|path|path==target || target.parent()==Some(path.as_path()))
}

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
    let mut watcher = (|| -> Result<SettingsWatcher> {
        let mut watcher =
            SettingsWatcher::new(move |event: notify::Result<notify::Event>| {
                if let Ok(event)=&event {tracing::trace!(settings=label,kind=?event.kind,paths=?event.paths,"preference filesystem notification");}
                match event {
                Ok(event) if relevant(&event,&target) =>
                {
                    let _ = notifications.try_send(false);
                }
                Err(_) => {
                    let _ = notifications.try_send(true);
                }
                _ => {}
                }
            },notify::Config::default())?;
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
        Err(error) => {
            tracing::debug!(settings=label,error=%error,"initial preference read failed");
            tracing::warn!(settings = label,"settings update rejected; retaining previous preference");
        },
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn atomic_file_and_parent_notifications_reload_but_unrelated_files_do_not() {
        let target=Path::new("/owned/agent.json.tor-settings.json");
        let event=|kind,path:&str|notify::Event::new(kind).add_path(path.into());
        assert!(relevant(&event(notify::EventKind::Modify(notify::event::ModifyKind::Any),target.to_str().unwrap()),target));
        assert!(relevant(&event(notify::EventKind::Other,"/owned"),target));
        assert!(!relevant(&event(notify::EventKind::Modify(notify::event::ModifyKind::Any),"/owned/other-profile.json"),target));
        assert!(!relevant(&event(notify::EventKind::Access(notify::event::AccessKind::Read),target.to_str().unwrap()),target));
    }
}
