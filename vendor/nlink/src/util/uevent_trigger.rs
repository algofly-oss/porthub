//! Uevent re-enumeration: asking the kernel to re-broadcast a
//! device's uevent (#252).
//!
//! # Why this exists
//!
//! Every other multicast subscriber in nlink can recover from a
//! dropped frame. [`events_with_resync`] takes a factory that
//! re-dumps the subsystem, and on `ENOBUFS` it emits
//! [`ResyncMarker::ResyncStart`], replays the dump, and emits
//! [`ResyncMarker::ResyncEnd`]. That works because every other
//! protocol has a dump command: `RTM_GETLINK`, `NFT_MSG_GETRULE`,
//! `XFRM_MSG_GETSA`.
//!
//! `NETLINK_KOBJECT_UEVENT` has none. It is broadcast-only — there is
//! no `GETUEVENT`, and nothing to put in the factory. A uevent
//! consumer that overflows its receive buffer has, on its own, no path
//! back to truth.
//!
//! The kernel's answer is `/sys/.../uevent`: writing an action to that
//! file makes the kernel re-broadcast the device's uevent. That is all
//! `udevadm trigger` is — a walk over `/sys/**/uevent`. This module
//! wraps that so a uevent consumer can build a resync factory like
//! everyone else.
//!
//! It lives in `util` rather than `netlink` deliberately. The sysfs
//! audit gate (`scripts/audit-sysfs-in-lib.sh`) keeps `/sys` reads out
//! of the protocol layer because they resolve in the *calling
//! process's mount namespace*, not the connection's netns; a sysfs
//! *write* is further still from what belongs there.
//! [`crate::util::ifname`] is the precedent.
//!
//! # Three things that make this sharper than it looks
//!
//! **1. It is a privileged write on an unprivileged stream.** Reading
//! uevents needs no privilege — the broadcast group is open to
//! anyone. Triggering them needs write access to `/sys/.../uevent`,
//! which is root-only. So the recovery path has a *strictly higher*
//! privilege requirement than the stream it repairs, and a monitor
//! running unprivileged will subscribe happily and only discover at
//! `ENOBUFS` time that it cannot recover. Call
//! [`UeventTrigger::can_trigger`] at startup, not at overflow time.
//!
//! **2. The blast radius is the whole machine.** A write to `uevent`
//! broadcasts to *every* listener, not just the caller. On any normal
//! system that means **udevd re-runs its full rule set** for each
//! triggered device: re-applying permissions and ownership, re-running
//! `NAME=`/`SYMLINK=` assignments, re-creating symlinks, and
//! restarting systemd units bound to the device. This is not a
//! read-only recovery step; it perturbs the host. Hence the default
//! action is [`TriggerAction::Change`] rather than `Add` (`add` tells
//! udev the device is new), and hence [`UeventTrigger::device`] —
//! one device — is the ergonomic path while
//! [`UeventTrigger::subtree`] makes you name a root and hands back a
//! summary of what it touched.
//!
//! **3. It is best-effort re-announcement, not a snapshot.** The
//! dump-based resyncs elsewhere in the crate are *consistent*:
//! `RTM_GETLINK` returns the kernel's state at one point in time. A
//! trigger is not that. It asks the kernel to re-emit events, which
//! then race with live events on the same socket, can themselves be
//! dropped if the buffer is still under pressure, and describe the
//! device *at re-emission time* rather than at the moment of the
//! event that was lost. See [`resync_factory`] for what that means for
//! the `ResyncedEvent` contract.
//!
//! [`events_with_resync`]: crate::netlink::resync::events_with_resync
//! [`ResyncMarker::ResyncStart`]: crate::netlink::resync::ResyncMarker::ResyncStart
//! [`ResyncMarker::ResyncEnd`]: crate::netlink::resync::ResyncMarker::ResyncEnd

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use crate::{Error, Result};

/// Default sysfs mount point.
pub const DEFAULT_SYSFS_ROOT: &str = "/sys";

/// The action written to `/sys/.../uevent`.
///
/// The kernel accepts these verbatim (`kobject_action_type` in
/// `lib/kobject_uevent.c`) and re-broadcasts a uevent naming the
/// action given — so a consumer keyed on `add` will not see anything
/// from a `change` trigger, and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TriggerAction {
    /// Re-announce the device as changed. **The default**, and what
    /// `udevadm trigger` uses, because it is the least disruptive
    /// thing udevd can be told: it re-runs rules without treating the
    /// device as newly discovered.
    #[default]
    Change,
    /// Re-announce the device as newly added. Heavier: udevd treats
    /// this as discovery and will re-create device nodes and
    /// re-evaluate naming. Use only when the consumer genuinely keys
    /// on `add`.
    Add,
    /// Announce removal. Almost never what a resync wants — it tells
    /// every listener the device is gone.
    Remove,
    /// Driver bind.
    Bind,
    /// Driver unbind.
    Unbind,
    /// Device moved within the hierarchy.
    Move,
    /// Device brought online.
    Online,
    /// Device taken offline.
    Offline,
}

impl TriggerAction {
    /// The token written to the `uevent` file.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Change => "change",
            Self::Move => "move",
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Bind => "bind",
            Self::Unbind => "unbind",
        }
    }
}

impl std::fmt::Display for TriggerAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a [`UeventTrigger::subtree`] walk actually did.
///
/// The walk is best-effort on purpose: sysfs is full of `uevent` files
/// that are unwritable, and devices come and go underneath a walk. One
/// `EACCES` two thousand entries in should not throw away the other
/// 1999 re-announcements.
#[derive(Debug, Default)]
pub struct TriggerSummary {
    /// Devices whose `uevent` file was written successfully.
    pub triggered: usize,
    /// Per-device failures, in walk order. A device that vanished
    /// mid-walk shows up here as `NotFound`.
    pub failures: Vec<(PathBuf, std::io::Error)>,
}

impl TriggerSummary {
    /// Total devices attempted.
    pub fn attempted(&self) -> usize {
        self.triggered + self.failures.len()
    }

    /// Whether every attempted device was triggered.
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Re-broadcasts device uevents by writing to `/sys/.../uevent`.
///
/// Read the module docs before using this — particularly the second
/// caveat. This is not a read-only operation.
///
/// ```no_run
/// use nlink::util::uevent_trigger::{TriggerAction, UeventTrigger};
///
/// let trigger = UeventTrigger::new().action(TriggerAction::Change).build();
///
/// // Learn about the privilege requirement at startup, not at
/// // ENOBUFS time.
/// if !trigger.can_trigger() {
///     eprintln!("not privileged to re-enumerate; uevent loss will be permanent");
/// }
///
/// // DEVPATH as it arrives on a uevent, e.g. "/devices/virtual/net/veth0".
/// trigger.device("/devices/virtual/net/veth0")?;
/// # Ok::<(), nlink::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct UeventTrigger {
    sysfs_root: PathBuf,
    action: TriggerAction,
}

impl Default for UeventTrigger {
    fn default() -> Self {
        Self::new()
    }
}

impl UeventTrigger {
    /// A trigger rooted at `/sys` emitting [`TriggerAction::Change`].
    pub fn new() -> Self {
        Self {
            sysfs_root: PathBuf::from(DEFAULT_SYSFS_ROOT),
            action: TriggerAction::default(),
        }
    }

    /// Point at a sysfs mounted somewhere other than `/sys`.
    ///
    /// Note what this does *not* do: it does not make the trigger
    /// namespace-aware. A sysfs path resolves in the calling process's
    /// mount namespace, so triggering a device inside another netns
    /// means entering that namespace, not renaming the path. See the
    /// namespace policy in `CLAUDE.md`.
    pub fn sysfs_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.sysfs_root = root.into();
        self
    }

    /// Set the action written to the `uevent` file.
    pub fn action(mut self, action: TriggerAction) -> Self {
        self.action = action;
        self
    }

    /// Terminal no-op, for symmetry with the crate's other typed
    /// configs.
    pub fn build(self) -> Self {
        self
    }

    /// The configured action.
    pub fn configured_action(&self) -> TriggerAction {
        self.action
    }

    /// The absolute path of a device's `uevent` file, given a
    /// `DEVPATH` as it appears on a uevent.
    ///
    /// A leading `/` on the devpath is stripped: `DEVPATH` is
    /// sysfs-relative even though it starts with a slash, so joining
    /// it naively would discard the sysfs root.
    pub fn uevent_path(&self, devpath: &str) -> PathBuf {
        self.sysfs_root
            .join(devpath.trim_start_matches('/'))
            .join("uevent")
    }

    /// Whether this process can trigger re-enumeration at all.
    ///
    /// Probes writability of the sysfs root's own `uevent`-bearing
    /// tree rather than trusting a uid check: a container may hold
    /// `CAP_DAC_OVERRIDE` without being root, and may equally be root
    /// with `/sys` mounted read-only. Both are common, and both are
    /// invisible to `geteuid()`.
    ///
    /// Cheap enough to call at startup, which is the point — a
    /// consumer that discovers this at `ENOBUFS` time has already lost
    /// the events it cannot recover.
    pub fn can_trigger(&self) -> bool {
        // `/sys/devices` exists on every kernel with sysfs mounted and
        // is the parent of everything a devpath can name. If it is not
        // writable, nothing under it is.
        let probe = self.sysfs_root.join("devices");
        match std::fs::metadata(&probe) {
            Ok(_) => access_writable(&probe),
            Err(_) => false,
        }
    }

    /// Re-broadcast one device's uevent.
    ///
    /// `devpath` is a `DEVPATH` as it arrives on a uevent
    /// (`/devices/virtual/net/veth0`) — or equivalently the sysfs path
    /// with the mount point stripped.
    ///
    /// This is the narrow, ergonomic path, and the one to reach for:
    /// its blast radius is one device rather than the whole machine.
    pub fn device(&self, devpath: &str) -> Result<()> {
        let path = self.uevent_path(devpath);
        write_uevent(&path, self.action).map_err(|e| {
            tracing::debug!(path = %path.display(), action = %self.action, error = %e,
                            "uevent trigger failed");
            Error::from(e)
        })
    }

    /// Re-broadcast every device under `relative`, best-effort.
    ///
    /// `relative` is sysfs-relative like [`Self::device`]'s argument;
    /// pass `"devices"` to sweep everything, which is what `udevadm
    /// trigger` does and which will make udevd re-run its rule set for
    /// every device on the machine. Prefer a narrower root
    /// (`"class/net"`, `"devices/virtual/net"`).
    ///
    /// Individual failures are collected rather than propagated — see
    /// [`TriggerSummary`]. Only a failure to walk the root at all is
    /// returned as an error.
    #[tracing::instrument(level = "info", skip(self), fields(action = %self.action))]
    pub fn subtree(&self, relative: &str) -> Result<TriggerSummary> {
        let root = self.sysfs_root.join(relative.trim_start_matches('/'));
        // Probe the root before walking. A mistyped root that
        // silently returned an empty summary would be indistinguishable
        // from a successful resync — and the caller would go on
        // believing its state had been re-announced. Propagating the
        // raw `io::Error` also keeps the errno, so `is_not_found()` and
        // friends work on the result.
        std::fs::read_dir(&root).map_err(Error::from)?;

        let mut summary = TriggerSummary::default();
        let mut stack = vec![root];

        while let Some(dir) = stack.pop() {
            let uevent = dir.join("uevent");
            // `is_file` follows symlinks and answers false when the
            // path is gone, which is exactly the "device vanished
            // mid-walk" case we want to skip silently.
            if uevent.is_file() {
                match write_uevent(&uevent, self.action) {
                    Ok(()) => summary.triggered += 1,
                    Err(e) => summary.failures.push((uevent, e)),
                }
            }

            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                // Do not follow symlinks: sysfs is a graph, and
                // `/sys/class/net/eth0` is a link back into
                // `/sys/devices/...`. Following them would trigger
                // every device several times over and can loop.
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if file_type.is_dir() {
                    stack.push(entry.path());
                }
            }
        }

        tracing::info!(
            triggered = summary.triggered,
            failed = summary.failures.len(),
            "uevent subtree trigger complete"
        );
        Ok(summary)
    }
}

/// Build a resync factory for [`events_with_resync`] out of a trigger.
///
/// # What `ResyncEnd` means here, and what it doesn't
///
/// For every other protocol the contract is: at `ResyncEnd`, your
/// state matches the kernel's, because a dump ran and its items were
/// replayed as `Resynced`. **That contract does not hold for
/// uevents.** There is no dump. This factory writes the trigger and
/// returns an empty batch, so the sequence a consumer sees is
/// `ResyncStart`, `ResyncEnd`, and then the re-announcements arriving
/// as ordinary live `Event`s — racing with genuinely new events,
/// droppable in turn if the buffer is still under pressure, and
/// describing each device as it is *now*.
///
/// So treat `ResyncEnd` from a uevent stream as "a re-announcement has
/// been requested", not "state is rebuilt". A consumer that needs a
/// consistent snapshot of network devices should take it from
/// rtnetlink, which has a real dump, and use uevents only for the
/// annotations rtnetlink doesn't carry.
///
/// ```no_run
/// use nlink::netlink::{Connection, KobjectUevent};
/// use nlink::netlink::resync::events_with_resync;
/// use nlink::util::uevent_trigger::{UeventTrigger, resync_factory};
///
/// # async fn demo() -> nlink::Result<()> {
/// let conn = Connection::<KobjectUevent>::new()?;
/// let events = conn.events().await;
///
/// let trigger = UeventTrigger::new().build();
/// let mut stream = events_with_resync(events, resync_factory(trigger, "class/net"));
/// # let _ = &mut stream;
/// # Ok(())
/// # }
/// ```
///
/// [`events_with_resync`]: crate::netlink::resync::events_with_resync
pub fn resync_factory<T: Send + 'static>(
    trigger: UeventTrigger,
    relative: impl Into<String>,
) -> impl FnMut() -> std::pin::Pin<Box<dyn Future<Output = Result<Vec<T>>> + Send>> + Unpin {
    let relative = relative.into();
    move || {
        let trigger = trigger.clone();
        let relative = relative.clone();
        Box::pin(async move {
            // Blocking sysfs writes: bounded by the subtree size and
            // measured in microseconds per device, but a full
            // "devices" sweep is thousands of them. Keep it off the
            // async worker.
            let summary =
                tokio::task::spawn_blocking(move || trigger.subtree(&relative)).await
                    .map_err(|e| {
                        Error::from(std::io::Error::other(format!("trigger task panicked: {e}")))
                    })??;
            tracing::info!(
                triggered = summary.triggered,
                failed = summary.failures.len(),
                "uevent resync requested; re-announcements will arrive as live events"
            );
            // Deliberately empty: the re-announcements are not a dump,
            // they come back through the live stream. See the note
            // above about what ResyncEnd does and doesn't mean.
            Ok(Vec::new())
        })
    }
}

/// `write(2)` the action token into an already-open-able uevent file.
///
/// Uses a fresh `File` per device rather than `fs::write` so the
/// action is a single write with no truncation — sysfs attributes
/// reject `O_TRUNC`-style rewrites and parse one write as one command.
fn write_uevent(path: &Path, action: TriggerAction) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(action.as_str().as_bytes())
}

/// `access(2)` with `W_OK`, which asks the kernel the question the
/// caller actually has — "may *I* write here" — rather than
/// reconstructing it from uid, mode bits and capabilities.
fn access_writable(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: access(2) with a valid NUL-terminated path and a valid
    // mode; it only reads.
    unsafe { libc::access(c_path.as_ptr(), libc::W_OK) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_tokens_match_the_kernel_vocabulary() {
        // kobject_actions[] in lib/kobject_uevent.c.
        assert_eq!(TriggerAction::Add.as_str(), "add");
        assert_eq!(TriggerAction::Remove.as_str(), "remove");
        assert_eq!(TriggerAction::Change.as_str(), "change");
        assert_eq!(TriggerAction::Move.as_str(), "move");
        assert_eq!(TriggerAction::Online.as_str(), "online");
        assert_eq!(TriggerAction::Offline.as_str(), "offline");
        assert_eq!(TriggerAction::Bind.as_str(), "bind");
        assert_eq!(TriggerAction::Unbind.as_str(), "unbind");
    }

    /// `change` is the least disruptive thing udevd can be told, so it
    /// is what a resync uses unless the caller says otherwise.
    #[test]
    fn default_action_is_change() {
        assert_eq!(TriggerAction::default(), TriggerAction::Change);
        assert_eq!(
            UeventTrigger::new().configured_action(),
            TriggerAction::Change
        );
    }

    /// A `DEVPATH` starts with `/` but is sysfs-relative. Joining it
    /// without stripping that would silently discard the sysfs root
    /// and write to `/devices/...`, which does not exist.
    #[test]
    fn devpath_is_joined_relative_to_the_sysfs_root() {
        let trigger = UeventTrigger::new();
        assert_eq!(
            trigger.uevent_path("/devices/virtual/net/veth0"),
            PathBuf::from("/sys/devices/virtual/net/veth0/uevent")
        );
        // Same answer without the leading slash.
        assert_eq!(
            trigger.uevent_path("devices/virtual/net/veth0"),
            PathBuf::from("/sys/devices/virtual/net/veth0/uevent")
        );
    }

    #[test]
    fn sysfs_root_is_honoured() {
        let trigger = UeventTrigger::new().sysfs_root("/mnt/sys").build();
        assert_eq!(
            trigger.uevent_path("/devices/x"),
            PathBuf::from("/mnt/sys/devices/x/uevent")
        );
    }

    #[test]
    fn summary_arithmetic() {
        let mut s = TriggerSummary {
            triggered: 3,
            failures: Vec::new(),
        };
        assert!(s.is_complete());
        assert_eq!(s.attempted(), 3);

        s.failures.push((
            PathBuf::from("/sys/devices/x/uevent"),
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        ));
        assert!(!s.is_complete());
        assert_eq!(s.attempted(), 4);
    }

    #[test]
    fn missing_subtree_root_is_an_error_not_an_empty_summary() {
        let trigger = UeventTrigger::new()
            .sysfs_root("/nonexistent-sysfs-for-tests")
            .build();
        let err = trigger.subtree("devices").unwrap_err();
        assert!(err.is_not_found(), "{err}");
    }

    #[test]
    fn cannot_trigger_when_the_sysfs_root_is_not_there() {
        let trigger = UeventTrigger::new()
            .sysfs_root("/nonexistent-sysfs-for-tests")
            .build();
        assert!(!trigger.can_trigger());
    }

    /// Build a fake sysfs under a unique temp root.
    fn fake_sysfs(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "nlink-uevent-trigger-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        base
    }

    /// `device()` is the narrow path and the one callers should reach
    /// for, so pin that it writes the configured action to the file
    /// the devpath names — and nowhere else.
    #[test]
    fn device_writes_the_action_to_the_devpath() {
        let base = fake_sysfs("device");
        let dev = base.join("devices/virtual/net/veth0");
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::write(dev.join("uevent"), b"").unwrap();

        // A sibling that must not be touched.
        let other = base.join("devices/virtual/net/veth1");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("uevent"), b"").unwrap();

        let trigger = UeventTrigger::new()
            .sysfs_root(&base)
            .action(TriggerAction::Add)
            .build();
        trigger.device("/devices/virtual/net/veth0").unwrap();

        assert_eq!(
            std::fs::read_to_string(dev.join("uevent")).unwrap(),
            "add"
        );
        assert_eq!(std::fs::read_to_string(other.join("uevent")).unwrap(), "");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// A devpath naming nothing must surface as a not-found error the
    /// caller can branch on, not a silent success.
    #[test]
    fn device_reports_a_missing_devpath() {
        let base = fake_sysfs("missing");
        std::fs::create_dir_all(base.join("devices")).unwrap();

        let trigger = UeventTrigger::new().sysfs_root(&base).build();
        let err = trigger.device("/devices/nope").unwrap_err();
        assert!(err.is_not_found(), "{err}");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// sysfs is a graph — `/sys/class/net/eth0` links back into
    /// `/sys/devices/...` — so a walk that followed symlinks would
    /// trigger devices several times over, and can loop.
    #[test]
    #[cfg(unix)]
    fn subtree_does_not_follow_symlinks() {
        let base = fake_sysfs("symlink");
        let dev = base.join("devices/virtual/net/veth0");
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::write(dev.join("uevent"), b"").unwrap();

        let class = base.join("class/net");
        std::fs::create_dir_all(&class).unwrap();
        std::os::unix::fs::symlink(&dev, class.join("veth0")).unwrap();

        let trigger = UeventTrigger::new().sysfs_root(&base).build();
        let summary = trigger.subtree("class").unwrap();
        assert_eq!(
            summary.attempted(),
            0,
            "the walk followed a symlink out of class/"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// The factory's whole contract is caveat 3: it triggers, and
    /// returns an **empty** batch, because the re-announcements come
    /// back through the live stream rather than as a dump. A future
    /// change that made it return items would silently turn
    /// `ResyncEnd` back into a promise the source cannot keep.
    #[tokio::test]
    async fn resync_factory_triggers_and_returns_no_dump_items() {
        let base = fake_sysfs("resync");
        let dev = base.join("devices/virtual/net/veth0");
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::write(dev.join("uevent"), b"").unwrap();

        let trigger = UeventTrigger::new().sysfs_root(&base).build();
        let mut factory = resync_factory::<u32>(trigger, "devices");

        let items = factory().await.unwrap();
        assert!(items.is_empty(), "the factory must not fabricate a dump");
        assert_eq!(
            std::fs::read_to_string(dev.join("uevent")).unwrap(),
            "change"
        );

        // Reusable: `events_with_resync` calls it on every overflow.
        std::fs::write(dev.join("uevent"), b"").unwrap();
        assert!(factory().await.unwrap().is_empty());
        assert_eq!(
            std::fs::read_to_string(dev.join("uevent")).unwrap(),
            "change"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn action_display_matches_the_written_token() {
        for action in [
            TriggerAction::Add,
            TriggerAction::Change,
            TriggerAction::Bind,
            TriggerAction::Offline,
        ] {
            assert_eq!(action.to_string(), action.as_str());
        }
    }

    /// The walk over a temporary tree: exercises directory recursion,
    /// the `uevent`-file predicate, and per-entry failure collection
    /// without needing sysfs or root.
    #[test]
    fn subtree_walks_directories_and_collects_failures() {
        let base = std::env::temp_dir().join(format!("nlink-uevent-trigger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let devices = base.join("devices");
        let child = devices.join("virtual").join("net").join("veth0");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::write(child.join("uevent"), b"").unwrap();
        std::fs::write(devices.join("uevent"), b"").unwrap();
        // A directory without a uevent file must simply be walked
        // through, not counted.
        std::fs::create_dir_all(devices.join("virtual").join("block")).unwrap();

        let trigger = UeventTrigger::new().sysfs_root(&base).build();
        let summary = trigger.subtree("devices").unwrap();
        assert_eq!(summary.attempted(), 2);
        assert_eq!(summary.triggered, 2);
        assert!(summary.is_complete());

        // The action token is what landed in the file.
        assert_eq!(
            std::fs::read_to_string(child.join("uevent")).unwrap(),
            "change"
        );

        // An unwritable uevent file is collected, not fatal.
        let readonly = devices.join("uevent");
        let mut perms = std::fs::metadata(&readonly).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(true);
        std::fs::set_permissions(&readonly, perms).unwrap();

        let summary = trigger.subtree("devices").unwrap();
        assert_eq!(summary.attempted(), 2);
        // Running as root defeats the read-only bit, so accept either
        // outcome and assert only that the walk stayed complete.
        assert!(summary.triggered >= 1);
        assert_eq!(summary.triggered + summary.failures.len(), 2);

        let _ = std::fs::remove_dir_all(&base);
    }
}
