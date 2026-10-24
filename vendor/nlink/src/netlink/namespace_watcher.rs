//! Filesystem-based namespace watcher using inotify.
//!
//! Monitors `/var/run/netns/` for named namespace creation and deletion.
//! This is the recommended way to track namespaces created via `ip netns add`.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::namespace_watcher::{NamespaceWatcher, NamespaceEvent};
//!
//! let mut watcher = NamespaceWatcher::new().await?;
//!
//! while let Some(event) = watcher.recv().await? {
//!     match event {
//!         NamespaceEvent::Created { name } => println!("New namespace: {}", name),
//!         NamespaceEvent::Deleted { name } => println!("Deleted: {}", name),
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::path::Path;

use inotify::{EventMask, EventStream, Inotify, WatchDescriptor, WatchMask};
use tokio_stream::StreamExt;

use super::error::{Error, Result};

const NETNS_DIR: &str = "/var/run/netns";
const PARENT_DIR: &str = "/var/run";

/// Events emitted when named namespaces change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NamespaceEvent {
    /// A named namespace was created in /var/run/netns/
    Created { name: String },
    /// A named namespace was deleted from /var/run/netns/
    Deleted { name: String },
    /// The /var/run/netns/ directory itself was created.
    /// After this event, namespace Created/Deleted events will be emitted.
    DirectoryCreated,
    /// The /var/run/netns/ directory was deleted.
    /// After this event, no namespace events will be emitted until DirectoryCreated.
    DirectoryDeleted,
    /// The kernel's inotify queue overflowed (`IN_Q_OVERFLOW`): events were
    /// lost. Re-list with [`namespace::list`](super::namespace::list) to
    /// learn where things stand. It used to be ignored (#510).
    Overflow,
}

/// Configuration for the namespace watcher.
#[derive(Debug, Clone)]
pub struct NamespaceWatcherConfig {
    /// Whether to watch /var/run/ when /var/run/netns/ doesn't exist (default: true)
    pub watch_parent: bool,
    /// Whether to emit DirectoryCreated/DirectoryDeleted events (default: false)
    pub emit_directory_events: bool,
}

impl Default for NamespaceWatcherConfig {
    fn default() -> Self {
        Self {
            watch_parent: true,
            emit_directory_events: false,
        }
    }
}

/// Watches for network namespace changes using inotify.
///
/// Monitors `/var/run/netns/` for namespace creation and deletion.
/// If the directory doesn't exist and `watch_parent` is enabled,
/// watches `/var/run/` for its creation.
///
/// This watcher is fully async and integrates natively with tokio:
/// [`recv`](Self::recv) parks the task on the inotify fd via the
/// `inotify` crate's tokio [`EventStream`] until an event arrives.
pub struct NamespaceWatcher {
    /// Tokio-native event stream over the inotify fd. The raw
    /// `Inotify::read_events` API must NOT be used here: the fd is
    /// always `IN_NONBLOCK`, so a direct read returns `WouldBlock`
    /// when the queue is empty instead of waiting (#183).
    stream: EventStream<Vec<u8>>,
    config: NamespaceWatcherConfig,
    netns_wd: Option<WatchDescriptor>,
    parent_wd: Option<WatchDescriptor>,
    /// Events discovered during watch transitions (e.g., namespaces created
    /// between parent directory event and watch setup on netns directory),
    /// delivered in the order found — they were popped from the back (#510).
    pending_events: std::collections::VecDeque<NamespaceEvent>,
}

#[nlink_macros::send_futures]
impl NamespaceWatcher {
    /// Create a new namespace watcher with default configuration.
    pub async fn new() -> Result<Self> {
        Self::with_config(NamespaceWatcherConfig::default()).await
    }

    /// Create a namespace watcher with custom configuration.
    pub async fn with_config(config: NamespaceWatcherConfig) -> Result<Self> {
        let inotify = Inotify::init().map_err(Error::from)?;

        let netns_path = Path::new(NETNS_DIR);
        let mut netns_wd = None;
        let mut parent_wd = None;

        if netns_path.exists() {
            // Directory exists - watch it directly
            let wd = inotify
                .watches()
                .add(
                    NETNS_DIR,
                    WatchMask::CREATE | WatchMask::DELETE | WatchMask::DELETE_SELF,
                )
                .map_err(Error::from)?;
            netns_wd = Some(wd);
        } else if config.watch_parent {
            // Directory doesn't exist - watch parent for its creation
            let wd = inotify
                .watches()
                .add(PARENT_DIR, WatchMask::CREATE | WatchMask::MOVED_TO)
                .map_err(Error::from)?;
            parent_wd = Some(wd);
        }

        let stream = inotify
            .into_event_stream(vec![0u8; 4096])
            .map_err(Error::from)?;

        Ok(Self {
            stream,
            config,
            netns_wd,
            parent_wd,
            pending_events: std::collections::VecDeque::new(),
        })
    }

    /// List current namespaces and create a watcher for changes.
    ///
    /// The watcher is created FIRST, then namespaces are listed.
    /// This ensures no events are missed between listing and watching.
    ///
    /// Callers should handle potential duplicates: a namespace in the
    /// returned list might also generate a Created event if it was
    /// created during the brief window between watch setup and listing.
    ///
    /// Only live namespaces are listed: a stale marker, a file with no
    /// namespace mounted over it, is not one (#510, #348).
    pub async fn list_and_watch() -> Result<(Vec<String>, Self)> {
        // Start watcher FIRST to avoid missing events
        let watcher = Self::new().await?;
        // Then list current namespaces
        let current = super::namespace::list()?
            .into_iter()
            .filter(|name| super::namespace::is_namespace_path(Path::new(NETNS_DIR).join(name)))
            .collect();
        Ok((current, watcher))
    }

    /// Wait for the namespace `name` to be mounted over its marker.
    ///
    /// `ip netns add`, and nlink's own `create`, make the marker first and
    /// mount the namespace on it after, and a mount raises no inotify event.
    /// `Created` used to fire on the marker, so a `connection_for(name)` in
    /// response raced into `NamespaceNotFound` (#510). Gives up after two
    /// seconds — a marker that never gets a namespace is not one.
    async fn mounted(name: &str) -> bool {
        let path = Path::new(NETNS_DIR).join(name);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if super::namespace::is_namespace_path(&path) {
                return true;
            }
            if tokio::time::Instant::now() >= deadline || !path.exists() {
                tracing::debug!(name, "netns marker never got a namespace; no Created");
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    /// Check if the watcher is actively monitoring /var/run/netns/.
    ///
    /// Returns `false` if only watching the parent directory (waiting for netns creation).
    pub fn is_watching_netns(&self) -> bool {
        self.netns_wd.is_some()
    }

    /// Receive the next namespace event.
    ///
    /// This method is async and will wait until an event is available.
    /// Returns `Ok(None)` if the watcher has been closed.
    pub async fn recv(&mut self) -> Result<Option<NamespaceEvent>> {
        loop {
            // First drain any pending events from watch transitions
            if let Some(event) = self.pending_events.pop_front() {
                if let NamespaceEvent::Created { name } = &event
                    && !Self::mounted(name).await
                {
                    continue;
                }
                return Ok(Some(event));
            }

            // Awaiting the EventStream parks the task until the inotify fd
            // is readable — the fd is nonblocking, so this is the only
            // correct way to wait (#183).
            let Some(event) = self.stream.next().await else {
                // End-of-stream: the inotify fd was closed.
                return Ok(None);
            };
            let event = event.map_err(Error::from)?;

            let name = match event.name {
                Some(name) => match name.into_string() {
                    Ok(name) => Some(name),
                    Err(raw) => {
                        // A namespace with a non-UTF-8 name can't be carried
                        // by the String-shaped NamespaceEvent; skip it loudly
                        // rather than misreporting it as a directory event.
                        tracing::warn!(
                            name = ?raw,
                            "skipping inotify event with non-UTF-8 name"
                        );
                        continue;
                    }
                },
                None => None,
            };

            if event.mask.contains(EventMask::Q_OVERFLOW) {
                tracing::warn!("namespace watcher: inotify queue overflowed; events lost");
                return Ok(Some(NamespaceEvent::Overflow));
            }
            if let Some(ns_event) = self.process_event(event.wd, event.mask, name)? {
                if let NamespaceEvent::Created { name } = &ns_event
                    && !Self::mounted(name).await
                {
                    continue;
                }
                return Ok(Some(ns_event));
            }
        }
    }

    /// Process a single inotify event and optionally return a NamespaceEvent.
    fn process_event(
        &mut self,
        wd: WatchDescriptor,
        mask: EventMask,
        name: Option<String>,
    ) -> Result<Option<NamespaceEvent>> {
        // Check if this is an event on the netns directory
        if Some(wd.clone()) == self.netns_wd {
            // Event in /var/run/netns/
            if mask.contains(EventMask::DELETE_SELF) {
                // The netns directory itself was deleted
                self.netns_wd = None;

                // Start watching parent if configured
                if self.config.watch_parent
                    && let Ok(new_wd) = self
                        .stream
                        .watches()
                        .add(PARENT_DIR, WatchMask::CREATE | WatchMask::MOVED_TO)
                {
                    self.parent_wd = Some(new_wd);
                }

                if self.config.emit_directory_events {
                    return Ok(Some(NamespaceEvent::DirectoryDeleted));
                }
            } else if mask.contains(EventMask::CREATE) {
                if let Some(name) = name {
                    return Ok(Some(NamespaceEvent::Created { name }));
                }
            } else if mask.contains(EventMask::DELETE)
                && let Some(name) = name
            {
                return Ok(Some(NamespaceEvent::Deleted { name }));
            }
        } else if Some(wd) == self.parent_wd {
            // Event in /var/run/ - check if netns directory was created
            let is_netns = name.as_deref() == Some("netns");

            if is_netns && (mask.contains(EventMask::CREATE) || mask.contains(EventMask::MOVED_TO))
            {
                // netns directory appeared - switch to watching it
                if let Ok(new_wd) = self.stream.watches().add(
                    NETNS_DIR,
                    WatchMask::CREATE | WatchMask::DELETE | WatchMask::DELETE_SELF,
                ) {
                    // Remove parent watch
                    if let Some(parent_wd) = self.parent_wd.take() {
                        let _ = self.stream.watches().remove(parent_wd);
                    }
                    self.netns_wd = Some(new_wd);

                    // Scan for existing namespaces that were created during the switch.
                    // This handles the race condition where `ip netns add` creates both
                    // the directory and the namespace file in rapid succession, and we
                    // miss the file creation event.
                    if let Ok(entries) = std::fs::read_dir(NETNS_DIR) {
                        for entry in entries.flatten() {
                            if let Some(name) = entry.file_name().to_str() {
                                self.pending_events.push_back(NamespaceEvent::Created {
                                    name: name.to_string(),
                                });
                            }
                        }
                    }

                    if self.config.emit_directory_events {
                        return Ok(Some(NamespaceEvent::DirectoryCreated));
                    }

                    // If we found namespaces during the scan, return the first one
                    if let Some(event) = self.pending_events.pop_front() {
                        return Ok(Some(event));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Get an async stream of namespace events.
    ///
    /// This consumes the watcher and returns a stream that yields events.
    pub fn into_stream(self) -> NamespaceEventStream {
        NamespaceEventStream {
            state: StreamState::Idle(self),
        }
    }
}

/// An async stream of namespace events: a [`Stream`] (#510), so it
/// composes with `StreamExt`, `StreamMap` and `select!`.
///
/// [`Stream`]: tokio_stream::Stream
pub struct NamespaceEventStream {
    state: StreamState,
}

/// The watcher between events, or moved into the receive in flight.
enum StreamState {
    Idle(NamespaceWatcher),
    Receiving(PendingRecv),
    Done,
}

type PendingRecv = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = (NamespaceWatcher, Result<Option<NamespaceEvent>>)> + Send,
    >,
>;

#[nlink_macros::send_futures]
impl NamespaceEventStream {
    /// Receive the next event from the stream.
    pub async fn next(&mut self) -> Option<Result<NamespaceEvent>> {
        tokio_stream::StreamExt::next(self).await
    }
}

// The watcher is moved into a boxed future, never pinned in place.
impl Unpin for NamespaceEventStream {}

impl tokio_stream::Stream for NamespaceEventStream {
    type Item = Result<NamespaceEvent>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;
        loop {
            match std::mem::replace(&mut self.state, StreamState::Done) {
                StreamState::Idle(mut watcher) => {
                    self.state = StreamState::Receiving(Box::pin(async move {
                        let result = watcher.recv().await;
                        (watcher, result)
                    }));
                }
                StreamState::Receiving(mut recv) => {
                    let Poll::Ready((watcher, result)) = recv.as_mut().poll(cx) else {
                        self.state = StreamState::Receiving(recv);
                        return Poll::Pending;
                    };
                    return match result {
                        Ok(Some(event)) => {
                            self.state = StreamState::Idle(watcher);
                            Poll::Ready(Some(Ok(event)))
                        }
                        Ok(None) => Poll::Ready(None),
                        Err(e) => {
                            self.state = StreamState::Idle(watcher);
                            Poll::Ready(Some(Err(e)))
                        }
                    };
                }
                StreamState::Done => return Poll::Ready(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = NamespaceWatcherConfig::default();
        assert!(config.watch_parent);
        assert!(!config.emit_directory_events);
    }

    #[tokio::test]
    async fn test_watcher_creation() {
        // May fail if /var/run doesn't exist (unlikely on Linux)
        let result = NamespaceWatcher::new().await;
        // Don't assert success - depends on system state
        if let Ok(watcher) = result {
            // Watcher should know whether it's watching netns or parent
            let watching = watcher.is_watching_netns();
            println!("Watching netns directly: {}", watching);
        }
    }

    #[tokio::test]
    async fn test_list_and_watch() {
        if let Ok((namespaces, watcher)) = NamespaceWatcher::list_and_watch().await {
            println!("Current namespaces: {:?}", namespaces);
            println!("Watching netns: {}", watcher.is_watching_netns());
        }
    }

    /// Regression test for #183: with no events queued, `recv()` must park
    /// the task, not surface the nonblocking fd's `WouldBlock` as an error.
    /// Runs unprivileged — creating the watcher needs no root.
    #[tokio::test]
    async fn recv_waits_instead_of_erroring() {
        let mut watcher = NamespaceWatcher::new()
            .await
            .expect("watcher creation should not require root");

        // Unrelated processes may legitimately create/delete namespaces
        // while this runs; drain any real events and only fail on Err.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(500);
        loop {
            match tokio::time::timeout_at(deadline, watcher.recv()).await {
                // Timed out while pending — the correct behavior.
                Err(_elapsed) => break,
                Ok(Ok(Some(_unrelated_event))) => continue,
                Ok(Ok(None)) => panic!("watcher closed unexpectedly"),
                Ok(Err(e)) => panic!("recv() must wait for events, got error: {e}"),
            }
        }
    }

    #[tokio::test]
    async fn test_custom_config() {
        let config = NamespaceWatcherConfig {
            watch_parent: false,
            emit_directory_events: true,
        };

        // This might fail if /var/run/netns doesn't exist and watch_parent is false
        let result = NamespaceWatcher::with_config(config).await;
        // Just verify it doesn't panic
        let _ = result;
    }
}
