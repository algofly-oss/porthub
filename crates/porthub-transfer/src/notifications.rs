//! Stable platform watcher selection even when other crates enable backends.
use notify::{Config, EventHandler, Watcher};

// Arti enables notify's macos_kqueue feature additively. RecommendedWatcher
// then changes globally, even for unrelated non-recursive application watches.
// FSEvents does not open a descriptor for every file in a populated tree.
#[cfg(target_os = "macos")]
pub type FileWatcher = notify::FsEventWatcher;
#[cfg(not(target_os = "macos"))]
pub type FileWatcher = notify::RecommendedWatcher;

pub fn watcher(handler: impl EventHandler) -> notify::Result<FileWatcher> {
    FileWatcher::new(handler, Config::default())
}
