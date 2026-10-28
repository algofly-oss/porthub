//! Shared bounded filesystem notifications for local agent preferences.
use anyhow::Result;
use notify::RecursiveMode;
#[cfg(not(target_os="macos"))]
use notify::Watcher;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
// Watch only the directory vnode on macOS. notify's kqueue backend discovers
// children after directory writes, including recursively populated Tor caches.
// A preference watcher must never open those children or their descendants.
#[cfg(target_os="macos")]
#[path="settings_watch_macos.rs"]
mod macos;
#[cfg(target_os="macos")]
type SettingsWatcher=macos::DirectoryWatcher;
#[cfg(not(target_os="macos"))]
type SettingsWatcher=notify::RecommendedWatcher;

fn relevant(event:&notify::Event,target:&Path)->bool {
    if event.need_rescan(){return true;}
    if !matches!(event.kind,notify::EventKind::Any|notify::EventKind::Other|notify::EventKind::Create(_)|notify::EventKind::Modify(_)|notify::EventKind::Remove(_)){return false;}
    event.paths.iter().any(|path|path==target || target.parent()==Some(path.as_path())
        // Directory vnode events represent mutations of any direct entry,
        // including atomic preference replacements.
        || cfg!(target_os="macos") && path.parent()==target.parent())
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
    fn atomic_file_and_owned_directory_notifications_reload() {
        let target=Path::new("/owned/agent.json.tor-settings.json");
        let event=|kind,path:&str|notify::Event::new(kind).add_path(path.into());
        assert!(relevant(&event(notify::EventKind::Modify(notify::event::ModifyKind::Any),target.to_str().unwrap()),target));
        assert!(relevant(&event(notify::EventKind::Other,"/owned"),target));
        assert_eq!(relevant(&event(notify::EventKind::Modify(notify::event::ModifyKind::Any),"/owned/other-profile.json"),target),cfg!(target_os="macos"));
        assert!(!relevant(&event(notify::EventKind::Modify(notify::event::ModifyKind::Any),"/other/other-profile.json"),target));
        assert!(!relevant(&event(notify::EventKind::Access(notify::event::AccessKind::Read),target.to_str().unwrap()),target));
    }

    #[cfg(target_os="macos")]
    #[tokio::test]
    async fn mac_preferences_do_not_watch_populated_sibling_trees() -> Result<()> {
        fn path(profile:&Path)->PathBuf {profile.with_extension("prefs")}
        fn load(profile:&Path)->Result<u64> {Ok(std::fs::read_to_string(path(profile))?.parse()?)}
        fn descriptors()->usize {
            // SAFETY: F_GETFD only queries a descriptor and never takes ownership.
            (0..4096).filter(|fd| unsafe {libc::fcntl(*fd,libc::F_GETFD)}>=0).count()
        }
        let root=tempfile::tempdir()?;
        let profile=root.path().join("agent.json");
        std::fs::write(&profile,b"profile")?;
        std::fs::write(path(&profile),b"1")?;
        let before=descriptors();
        // General agent/job watches share this parent too. Arti's additive
        // backend features must not make them enumerate its descendants.
        use notify::Watcher;
        let mut general=Vec::new();
        for _ in 0..2 {
            let mut watcher=porthub_transfer::notifications::watcher(|_:notify::Result<notify::Event>|{})?;
            watcher.watch(root.path(),RecursiveMode::NonRecursive)?;
            general.push(watcher);
        }
        let (updates,mut values)=watch::channel(0);
        let cancel=CancellationToken::new();
        let task=tokio::spawn(run(profile.clone(),path,load,updates,"test",cancel.clone()));
        tokio::time::timeout(Duration::from_secs(3),values.changed()).await??;
        assert_eq!(*values.borrow_and_update(),1);
        // Simulate a Tor cache or upgrade backup appearing after registration.
        // A non-recursive preference watch must not open these descendants.
        let cache=root.path().join("tor-cache");
        for directory in 0..40 {
            let directory=cache.join(directory.to_string());
            std::fs::create_dir_all(&directory)?;
            for file in 0..32 {std::fs::write(directory.join(file.to_string()),b"cache")?;}
            tokio::task::yield_now().await;
        }
        for value in 2..=24 {
            let next=root.path().join("next-setting");
            std::fs::write(&next,value.to_string())?;
            std::fs::rename(next,path(&profile))?;
            tokio::time::timeout(Duration::from_secs(3),async {
                while *values.borrow_and_update()!=value {values.changed().await?;}
                Ok::<_,watch::error::RecvError>(())
            }).await??;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Other tests may create their own runtime descriptors concurrently.
        assert!(descriptors()<=before+32,"preference notifications opened sibling files");
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(3),task).await???;
        drop(general);
        tokio::task::yield_now().await;
        assert!(descriptors()<=before+32,"cancelled preference watcher retained descriptors");
        Ok(())
    }
}
