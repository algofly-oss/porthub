//! Network namespace utilities.
//!
//! This module provides utilities for working with Linux network namespaces,
//! including executing operations in specific namespaces and managing namespace
//! file descriptors.
//!
//! [`create`]/[`delete`] persist a netns at the `ip netns` convention
//! `/var/run/netns/<name>`. [`create_path`]/[`delete_path`] persist it at any
//! caller-chosen path, so an application can own its netns directory (clearer
//! ownership, no collisions with operator `ip netns add`).
//!
//! # Example
//!
//! Every entry point that works in a namespace takes `impl
//! Into<`[`NetnsTarget`]`>` (#532): an `ip netns` name, an open
//! [`Netns`], a [`NetnsRef`], a path, a borrowed namespace fd.
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::path::Path;
//!
//! use nlink::netlink::namespace::{Netns, NetnsRef};
//! use nlink::netlink::{Connection, Generic, Route};
//!
//! // A Route connection in a named namespace
//! let conn = Connection::<Route>::new_in("myns")?;
//! let links = conn.get_links().await?;
//!
//! // Any other protocol the same way; GENL families use `new_in_async`
//! let genl = Connection::<Generic>::new_in("myns")?;
//!
//! // A container's namespace, by path or by pid
//! let conn = Connection::<Route>::new_in(Path::new("/proc/1234/ns/net"))?;
//! let conn = Connection::<Route>::new_in(NetnsRef::Pid(1234))?;
//!
//! // Open it once to be sure every connection is in the same one
//! let ns = Netns::open("myns")?;
//! let (a, b) = (Connection::<Route>::new_in(&ns)?, Connection::<Route>::new_in(&ns)?);
//! # Ok(())
//! # }
//! ```

use std::{
    fs::File,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::{ffi::OsStrExt, io::{AsRawFd, RawFd}},
    },
    path::{Path, PathBuf},
};

use super::{
    connection::Connection,
    error::{Error, Result},
    protocol::{
        construction::{AsyncConstructible, SyncConstructible},
        AsyncProtocolInit, ProtocolState,
    },
};

mod command;
mod vrf_exec;
mod netns;

pub use netns::{Netns, NetnsId, NetnsRef, NetnsTarget, Sysctl};
pub use command::{NetnsCommand, Overlay, etc_overlay_supported};
pub use vrf_exec::vrf_cgroup;

/// Specification for which network namespace to use.
///
/// This enum provides a unified way to specify a network namespace,
/// whether it's the default namespace, a named namespace, a path,
/// or a process's namespace.
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use std::path::Path;
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::namespace::NamespaceSpec;
///
/// // Different ways to specify a namespace
/// let default = NamespaceSpec::Default;
/// let named = NamespaceSpec::Named("myns");
/// let by_path = NamespaceSpec::Path(Path::new("/proc/1234/ns/net"));
/// let by_pid = NamespaceSpec::Pid(1234);
///
/// // Create connections (generic over protocol type)
/// let conn = Connection::<Route>::new_in(named)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum NamespaceSpec<'a> {
    /// Use the current/default namespace.
    Default,
    /// Use a named namespace (from /var/run/netns/).
    Named(&'a str),
    /// Use a namespace specified by path.
    Path(&'a Path),
    /// Use a process's namespace by PID.
    Pid(u32),
}

#[nlink_macros::send_futures]
impl<'a> NamespaceSpec<'a> {
    /// Create a connection for this namespace specification.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::Connection;
    /// use nlink::netlink::namespace::NamespaceSpec;
    /// use nlink::netlink::Route;
    ///
    /// let spec = NamespaceSpec::Named("myns");
    /// let conn = Connection::<Route>::new_in(spec)?;
    /// let links = conn.get_links().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[deprecated(since = "0.32.0", note = "use `Connection::new_in(spec)` (#532)")]
    pub fn connection<P: ProtocolState + Default + SyncConstructible>(&self) -> Result<Connection<P>> {
        Connection::<P>::new_in(self)
    }

    /// Create an async-initialized connection (GENL families that
    /// need family-ID resolution — WireGuard, MACsec, …) for this
    /// namespace specification. Async counterpart of
    /// [`connection`](Self::connection) (#169).
    #[deprecated(since = "0.32.0", note = "use `Connection::new_in_async(spec)` (#532)")]
    pub async fn connection_async<P: AsyncProtocolInit + AsyncConstructible>(
        &self,
    ) -> Result<Connection<P>> {
        Connection::<P>::new_in_async(self).await
    }

    /// Check if this refers to the default namespace.
    #[inline]
    pub fn is_default(&self) -> bool {
        matches!(self, NamespaceSpec::Default)
    }

    /// Spawn a process in this namespace.
    ///
    /// For [`NamespaceSpec::Default`], the command is spawned normally without
    /// any namespace switching.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::namespace::NamespaceSpec;
    /// use std::process::Command;
    ///
    /// let spec = NamespaceSpec::Named("myns");
    /// let mut cmd = Command::new("ip");
    /// cmd.arg("link");
    /// let mut child = spec.spawn(cmd)?;
    /// child.wait()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn spawn(&self, cmd: std::process::Command) -> Result<std::process::Child> {
        match self {
            NamespaceSpec::Default => {
                let mut cmd = cmd;
                cmd.spawn().map_err(Error::from)
            }
            NamespaceSpec::Named(name) => spawn(name, cmd),
            NamespaceSpec::Path(path) => spawn_path(path, cmd),
            NamespaceSpec::Pid(pid) => {
                let path = format!("/proc/{}/ns/net", pid);
                spawn_path(&path, cmd)
            }
        }
    }

    /// Spawn a process and collect its output in this namespace.
    ///
    /// See [`spawn_output`] for details.
    pub fn spawn_output(&self, cmd: std::process::Command) -> Result<std::process::Output> {
        match self {
            NamespaceSpec::Default => {
                let mut cmd = cmd;
                cmd.stdout(std::process::Stdio::piped());
                cmd.stderr(std::process::Stdio::piped());
                let child = cmd.spawn().map_err(Error::from)?;
                child.wait_with_output().map_err(Error::from)
            }
            NamespaceSpec::Named(name) => spawn_output(name, cmd),
            NamespaceSpec::Path(path) => spawn_output_path(path, cmd),
            NamespaceSpec::Pid(pid) => {
                let path = format!("/proc/{}/ns/net", pid);
                spawn_output_path(&path, cmd)
            }
        }
    }

    /// The name under which this namespace can have an `/etc/netns/<name>/`
    /// overlay, if it has one at all.
    ///
    /// The overlay directory is keyed by the **name** `ip netns` gave the
    /// namespace, so only a namespace with a name can have one:
    /// [`Named`](Self::Named) always, and [`Path`](Self::Path) when the
    /// path is an entry of [`NETNS_RUN_DIR`] (its file name is the
    /// namespace name). A path anywhere else, and
    /// [`Pid`](Self::Pid) — `/proc/<pid>/ns/net` — name nothing, and
    /// `None` here is why [`spawn_with_etc`](Self::spawn_with_etc)
    /// applies no overlay for them (#331). Ask this before switching a
    /// caller from `Named` to `Pid` and wondering where `hosts` went.
    pub fn etc_overlay_name(&self) -> Option<&'a str> {
        match self {
            NamespaceSpec::Named(name) => Some(name),
            NamespaceSpec::Path(path) => {
                let parent = path.parent()?;
                let run_dir = Path::new(NETNS_RUN_DIR);
                // `/var/run` is a symlink to `/run` on every modern
                // distribution; accept either spelling. Only a
                // canonicalization that *succeeded* on both sides
                // counts — when neither directory exists yet (no
                // namespace has been created on this host), two
                // failures must not compare equal.
                let is_run_dir = parent == run_dir
                    || matches!(
                        (std::fs::canonicalize(parent), std::fs::canonicalize(run_dir)),
                        (Ok(a), Ok(b)) if a == b
                    );
                if !is_run_dir {
                    return None;
                }
                path.file_name()?.to_str()
            }
            NamespaceSpec::Default | NamespaceSpec::Pid(_) => None,
        }
    }

    /// Spawn a process with `/etc/netns/` file overlays.
    ///
    /// See [`spawn_with_etc`] for details. The overlay is applied for
    /// every spec that has a name — [`Named`](Self::Named), and
    /// [`Path`](Self::Path) when the path is an entry of
    /// [`NETNS_RUN_DIR`] — and there is none to apply for a path
    /// elsewhere or a [`Pid`](Self::Pid): the overlay directory is keyed
    /// by the `ip netns` name, and those have none. Until 0.27 `Path`
    /// never got the overlay either, silently (#331);
    /// [`etc_overlay_name`](Self::etc_overlay_name) says which case a
    /// spec is in.
    pub fn spawn_with_etc(&self, cmd: std::process::Command) -> Result<std::process::Child> {
        match self {
            NamespaceSpec::Default => {
                let mut cmd = cmd;
                cmd.spawn().map_err(Error::from)
            }
            NamespaceSpec::Named(name) => spawn_with_etc(name, cmd),
            NamespaceSpec::Path(path) => match self.etc_overlay_name() {
                Some(name) => spawn_path_with_etc(path, name, cmd),
                None => spawn_path(path, cmd),
            },
            NamespaceSpec::Pid(pid) => {
                let path = format!("/proc/{}/ns/net", pid);
                spawn_path(&path, cmd)
            }
        }
    }

    /// Spawn a process and collect its output with `/etc/netns/` file overlays.
    ///
    /// See [`spawn_with_etc`](Self::spawn_with_etc) for which specs get
    /// the overlay.
    pub fn spawn_output_with_etc(
        &self,
        cmd: std::process::Command,
    ) -> Result<std::process::Output> {
        match self {
            NamespaceSpec::Default => {
                let mut cmd = cmd;
                cmd.stdout(std::process::Stdio::piped());
                cmd.stderr(std::process::Stdio::piped());
                let child = cmd.spawn().map_err(Error::from)?;
                child.wait_with_output().map_err(Error::from)
            }
            NamespaceSpec::Named(name) => spawn_output_with_etc(name, cmd),
            NamespaceSpec::Path(path) => match self.etc_overlay_name() {
                Some(name) => spawn_output_path_with_etc(path, name, cmd),
                None => spawn_output_path(path, cmd),
            },
            NamespaceSpec::Pid(pid) => {
                let path = format!("/proc/{}/ns/net", pid);
                spawn_output_path(&path, cmd)
            }
        }
    }
}

/// The runtime directory where named network namespaces are stored.
pub const NETNS_RUN_DIR: &str = "/var/run/netns";

/// Check a namespace name the way `ip netns` does (`invalid_name`):
/// non-empty, no `/`, not `.` or `..`, at most `NAME_MAX` (255) bytes, no
/// NUL.
///
/// Every by-name function here joins the name onto [`NETNS_RUN_DIR`] —
/// and `delete` then lazily unmounts what it names, as root. Unchecked,
/// `delete("")` detached `/var/run/netns` itself, and every named
/// namespace on the host with it; `delete("..")` detached `/run`; an
/// absolute name replaced the base directory altogether (#463).
pub fn validate_name(name: &str) -> Result<()> {
    let reason = if name.is_empty() {
        Some("is empty")
    } else if name == "." || name == ".." {
        Some("is `.` or `..`")
    } else if name.contains('/') {
        Some("contains `/`")
    } else if name.contains('\0') {
        Some("contains NUL")
    } else if name.len() > 255 {
        Some("is longer than 255 bytes")
    } else {
        None
    };
    match reason {
        Some(reason) => Err(Error::invalid_message(format!(
            "invalid namespace name {name:?}: it {reason}"
        ))),
        None => Ok(()),
    }
}

/// `NETNS_RUN_DIR/<name>`, for a name [`validate_name`] accepts.
fn named_path(name: &str) -> Result<PathBuf> {
    validate_name(name)?;
    Ok(PathBuf::from(NETNS_RUN_DIR).join(name))
}

/// Get a connection for a named network namespace.
///
/// Named namespaces are those created via `ip netns add <name>` and stored
/// in `/var/run/netns/`.
///
/// # Errors
///
/// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) (matched by `is_not_found()`) unless
/// `/var/run/netns/<name>` is a live namespace — a stale marker with no
/// mount behind it counts as not found (#348).
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::Connection;
/// use nlink::netlink::namespace;
/// use nlink::netlink::Route;
///
/// // Create a connection to work in the "production" namespace
/// let conn: Connection<Route> = Connection::new_in("production")?;
/// let links = conn.get_links().await?;
/// # Ok(())
/// # }
/// ```
#[deprecated(since = "0.32.0", note = "use `Connection::new_in(name)` (#532)")]
pub fn connection_for<P: ProtocolState + Default + SyncConstructible>(name: &str) -> Result<Connection<P>> {
    Connection::<P>::new_in(name)
}

/// Get a connection for a network namespace specified by path.
///
/// This works with any namespace file path, including:
/// - Named namespaces: `/var/run/netns/<name>`
/// - Process namespaces: `/proc/<pid>/ns/net`
/// - Container namespaces: `/proc/<container_init_pid>/ns/net`
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::Connection;
/// use nlink::netlink::namespace;
/// use nlink::netlink::Route;
///
/// // For a container's namespace
/// let conn: Connection<Route> = Connection::new_in(std::path::Path::new("/proc/1234/ns/net"))?;
/// let links = conn.get_links().await?;
/// # Ok(())
/// # }
/// ```
#[deprecated(since = "0.32.0", note = "use `Connection::new_in(path)` (#532)")]
pub fn connection_for_path<P: ProtocolState + Default + SyncConstructible, T: AsRef<Path>>(
    path: T,
) -> Result<Connection<P>> {
    Connection::<P>::new_in(path.as_ref())
}

/// Get a connection for a process's network namespace.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::Connection;
/// use nlink::netlink::namespace;
/// use nlink::netlink::Route;
///
/// // Get interfaces visible to process 1234
/// let conn: Connection<Route> = Connection::new_in(namespace::NetnsRef::Pid(1234))?;
/// let links = conn.get_links().await?;
/// # Ok(())
/// # }
/// ```
#[deprecated(since = "0.32.0", note = "use `Connection::new_in(NetnsRef::Pid(pid))` (#532)")]
pub fn connection_for_pid<P: ProtocolState + Default + SyncConstructible>(pid: u32) -> Result<Connection<P>> {
    Connection::<P>::new_in(NetnsRef::Pid(pid))
}

/// Get an async-initialized connection for a named network namespace.
///
/// This is for GENL protocols (WireGuard, MACsec, MPTCP, Ethtool, nl80211, Devlink)
/// that need async family ID resolution after socket creation. The socket is created
/// in the target namespace, then the GENL family is resolved through that socket.
///
/// # Errors
///
/// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) (matched by `is_not_found()`) unless
/// `/var/run/netns/<name>` is a live namespace — a stale marker with no
/// mount behind it counts as not found (#348).
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::{Connection, Wireguard, namespace};
///
/// let conn: Connection<Wireguard> = Connection::new_in_async("myns").await?;
/// let device = conn.get_device("wg0").await?;
/// # Ok(())
/// # }
/// ```
#[deprecated(since = "0.32.0", note = "use `Connection::new_in_async(name)` (#532)")]
#[nlink_macros::send_futures]
pub async fn connection_for_async<P: AsyncProtocolInit + AsyncConstructible>(name: &str) -> Result<Connection<P>> {
    Connection::<P>::new_in_async(name).await
}

/// Get an async-initialized connection for a namespace specified by path.
///
/// See [`connection_for_async`] for details.
#[deprecated(since = "0.32.0", note = "use `Connection::new_in_async(path)` (#532)")]
#[nlink_macros::send_futures]
pub async fn connection_for_path_async<P: AsyncProtocolInit + AsyncConstructible, T: AsRef<Path>>(
    path: T,
) -> Result<Connection<P>> {
    Connection::<P>::new_in_async(path.as_ref()).await
}

/// Get an async-initialized connection for a process's network namespace.
///
/// See [`connection_for_async`] for details.
#[deprecated(since = "0.32.0", note = "use `Connection::new_in_async(NetnsRef::Pid(pid))` (#532)")]
#[nlink_macros::send_futures]
pub async fn connection_for_pid_async<P: AsyncProtocolInit + AsyncConstructible>(pid: u32) -> Result<Connection<P>> {
    Connection::<P>::new_in_async(NetnsRef::Pid(pid)).await
}

/// Open a namespace file and return its file descriptor.
///
/// The returned `NamespaceFd` keeps the file open and can be used with
/// [`Connection::new_in_namespace`] or [`enter`].
///
/// # Errors
///
/// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) (matched by `is_not_found()`) unless
/// `/var/run/netns/<name>` is a live namespace — a stale marker with no
/// mount behind it counts as not found (#348).
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::namespace;
/// use nlink::netlink::{Connection, Route};
///
/// let ns = namespace::open("myns")?;
/// let conn = Connection::<Route>::new_in_namespace(&ns)?;
/// # Ok(())
/// # }
/// ```
pub fn open(name: &str) -> Result<NamespaceFd> {
    let path = live_named_path(name)?;
    open_path(&path)
}

/// Map a failed open of a namespace path to a classifiable error (#184):
/// ENOENT becomes a namespace not-found error — matching `is_not_found()`
/// and carrying the path in `name`, the same shape [`delete_path`] uses —
/// and everything else passes through as `Error::from`, preserving the raw
/// errno so `is_permission_denied()` & co. keep working. Never wrap these
/// opens in stringly `InvalidMessage`: it defeats every recovery predicate.
pub(crate) fn namespace_open_error(path: &Path, e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        Error::namespace_not_found(path.display().to_string())
    } else {
        Error::from(e)
    }
}

/// Open a namespace file by path and return its file descriptor.
///
/// # Errors
///
/// Returns [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) if the path doesn't exist
/// (matchable via [`Error::is_not_found`]); other open failures surface
/// as [`Error::from`] with their errno intact (e.g. for
/// [`Error::is_permission_denied`]).
pub fn open_path<P: AsRef<Path>>(path: P) -> Result<NamespaceFd> {
    let file =
        File::open(path.as_ref()).map_err(|e| namespace_open_error(path.as_ref(), e))?;
    Ok(NamespaceFd { file })
}

/// Open a process's namespace and return its file descriptor.
pub fn open_pid(pid: u32) -> Result<NamespaceFd> {
    let path = format!("/proc/{}/ns/net", pid);
    open_path(&path)
}

/// A handle to an open namespace file.
///
/// This keeps the namespace file open so it can be used multiple times
/// with [`Connection::new_in_namespace`].
#[derive(Debug)]
pub struct NamespaceFd {
    file: File,
}

impl NamespaceFd {
    /// Get the raw file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl AsRawFd for NamespaceFd {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

/// I/O-safe borrow of the namespace fd (#186). Pass it to
/// [`Connection::new_in`] (as `fd.as_fd()`), or to any parameter that
/// takes `impl AsFd`, and the borrow checker keeps the fd alive for the
/// call.
impl AsFd for NamespaceFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

/// Enter a network namespace temporarily.
///
/// This function switches the current thread to the specified network namespace.
/// Use [`NamespaceGuard::restore`] or drop the guard to return to the original namespace.
///
/// # Warning
///
/// This affects the entire thread. In async contexts, prefer using
/// [`connection_for`] or [`Connection::new_in_namespace_path`] instead,
/// which create a socket in the namespace without affecting the thread.
///
/// If the guard's restore fails (`setns` back errors), the calling thread
/// stays in the target namespace — on a tokio worker that silently poisons
/// every task later scheduled there. The guard is `!Send`, so it cannot
/// leave the entering thread, but the restore-failure hazard is inherent
/// to switching a shared thread; APIs that need a namespace only briefly
/// should follow the dedicated-worker-thread pattern instead (see
/// [`get_sysctl`] and `NetlinkSocket::new_in_namespace`, #185).
///
/// # Errors
///
/// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) (matched by `is_not_found()`) unless
/// `/var/run/netns/<name>` is a live namespace — a stale marker with no
/// mount behind it counts as not found (#348).
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::namespace;
///
/// let guard = namespace::enter("myns")?;
/// // Now in "myns" namespace
/// // ... do something ...
/// guard.restore()?;  // Or just drop it
/// # Ok(())
/// # }
/// ```
pub fn enter(name: &str) -> Result<NamespaceGuard> {
    let path = live_named_path(name)?;
    enter_path(&path)
}

/// Enter a network namespace by path.
///
/// # Errors
///
/// Returns [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) if the path doesn't exist; other
/// failures (open or `setns`) surface as [`Error::from`] with errno intact.
pub fn enter_path<P: AsRef<Path>>(path: P) -> Result<NamespaceGuard> {
    // Save the current namespace
    let original = File::open("/proc/thread-self/ns/net")
        .map_err(|e| Error::from(e).with_context("open the current namespace"))?;

    // Open and enter the target namespace
    let target =
        File::open(path.as_ref()).map_err(|e| namespace_open_error(path.as_ref(), e))?;

    // SAFETY: libc::setns is a standard Linux syscall for switching namespaces.
    // target.as_raw_fd() is a valid fd to a namespace file, CLONE_NEWNET
    // specifies we're switching the network namespace.
    let ret = unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) };
    if ret < 0 {
        return Err(Error::from(std::io::Error::last_os_error()));
    }

    Ok(NamespaceGuard {
        original: Some(original),
        _thread_pinned: std::marker::PhantomData,
    })
}

/// Put a worker thread back in the namespace it started in when dropped
/// (#797). A thread that exits inside a namespace holds it for a moment
/// after `join` returns: the kernel wakes the joiner when it clears the
/// thread's TID (`exit_mm`), before it releases the thread's namespaces
/// (`exit_task_namespaces`). For that moment `Netns::pids` lists the
/// process, and a namespace being deleted looks held. Leaving first makes
/// the worker's return the end of its stay. Made before the `setns` in;
/// panics included.
pub(crate) struct ReturnHome(Option<File>);

impl ReturnHome {
    /// The calling thread's namespace, to come back to.
    pub(crate) fn new() -> Self {
        Self(File::open("/proc/thread-self/ns/net").ok())
    }
}

impl Drop for ReturnHome {
    fn drop(&mut self) {
        if let Some(home) = &self.0 {
            // SAFETY: switches only the calling thread, back to the
            // namespace it was in; the fd is open.
            unsafe { libc::setns(home.as_raw_fd(), libc::CLONE_NEWNET) };
        }
    }
}

/// A guard that restores the original namespace when dropped.
///
/// The guard is `!Send` (#185): namespace membership is **per-thread**, so a
/// guard dropped on a different thread than the one that called [`enter`]
/// would `setns` the wrong thread — switching that thread's namespace while
/// leaving the entering thread stuck in the target. Moving the guard across
/// threads (including holding it across an `.await` in a multi-threaded
/// runtime, which requires the future — and thus the guard — to be `Send`)
/// is therefore a compile error:
///
/// ```compile_fail
/// fn assert_send<T: Send>(_: T) {}
/// let guard = nlink::netlink::namespace::enter("myns").unwrap();
/// assert_send(guard); // NamespaceGuard is deliberately !Send
/// ```
#[derive(Debug)]
pub struct NamespaceGuard {
    /// `Some` while the guard is armed; [`Self::restore`] takes it out so
    /// `Drop` doesn't run a second, redundant restore after an explicit one.
    original: Option<File>,
    /// `*mut ()` is `!Send + !Sync`, pinning the guard to the entering thread.
    _thread_pinned: std::marker::PhantomData<*mut ()>,
}

impl NamespaceGuard {
    /// Restore the original namespace explicitly.
    ///
    /// This is called automatically on drop, but calling it explicitly
    /// allows you to handle errors. After this call the guard is disarmed:
    /// `Drop` will not attempt a second restore.
    pub fn restore(mut self) -> Result<()> {
        let result = self.do_restore();
        // Disarm: Drop must not re-run the restore the explicit call just
        // performed (pre-#185 it did, harmlessly but redundantly — and a
        // failed explicit restore also fired a second attempt + error log).
        self.original = None;
        result
    }

    fn do_restore(&self) -> Result<()> {
        let Some(original) = &self.original else {
            return Ok(());
        };
        // SAFETY: libc::setns restores the original namespace. The fd is valid
        // (opened from /proc/thread-self/ns/net when the guard was created).
        let ret = unsafe { libc::setns(original.as_raw_fd(), libc::CLONE_NEWNET) };
        if ret < 0 {
            return Err(Error::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

impl Drop for NamespaceGuard {
    fn drop(&mut self) {
        if self.original.is_none() {
            return; // explicitly restored already
        }
        if let Err(e) = self.do_restore() {
            // We cannot return an error from Drop. Emit a structured
            // tracing event so observers see the failure (replaces the
            // pre-0.16.0 `eprintln!` — consistent with the broader
            // eprintln→tracing audit in Plan 147 §9.2). Callers that
            // need explicit detection should restore the namespace via
            // an explicit call before dropping the guard.
            tracing::error!(
                error = %e,
                "NamespaceGuard::drop: failed to restore original namespace; thread may be stuck"
            );
        }
    }
}

/// Check if a named namespace exists.
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::{Connection, Route, namespace};
///
/// if namespace::exists("myns") {
///     let conn: Connection<Route> = Connection::new_in("myns")?;
///     // ...
/// }
/// # Ok(())
/// # }
/// ```
pub fn exists(name: &str) -> bool {
    named_path(name).is_ok_and(|path| path.exists())
}

/// Convert a filesystem path to a `CString`, preserving its exact bytes.
/// Linux paths aren't necessarily UTF-8, so this goes through `OsStr` bytes
/// rather than `to_string_lossy` (which would mangle non-UTF-8 paths into a
/// different path than the one on disk). Errors only on an interior NUL.
fn path_to_cstring(path: &Path) -> Result<std::ffi::CString> {
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::invalid_message(format!("invalid namespace path '{}'", path.display())))
}

/// `nsfs` superblock magic (`NSFS_MAGIC` from `<linux/magic.h>` — ASCII
/// "nsfs"). Backs `/proc/<pid>/ns/*` and bind-mounts of them. Not exported by
/// the `libc` crate, so defined here. Compared as `u64`: `statfs.f_type`
/// varies in type across libc/arch (`__fsword_t` on glibc x86_64, `c_ulong`
/// on musl, `c_uint` on s390x), so we widen at the comparison rather than pin
/// a type the field doesn't always have.
const NSFS_MAGIC: u64 = 0x6e_73_66_73;

/// Return `true` if `path` is a *live* network-namespace bind-mount.
///
/// A persistent netns (see [`create_path`]) is a bind-mount of an `nsfs` inode
/// onto a marker file. After an unclean shutdown the marker can linger as an
/// ordinary file with the bind-mount gone — present on disk but no longer a
/// namespace. This distinguishes the two via `statfs(2)`: a live netns
/// bind-mount sits on the `nsfs` pseudo-filesystem; a stale marker sits on
/// whatever backs its parent directory (typically `tmpfs`).
///
/// Returns `false` (never errors) when the path is absent, unreadable, or
/// backed by any non-`nsfs` filesystem, mirroring [`exists`].
///
/// `/proc/mounts` is deliberately **not** consulted: mount-namespace
/// propagation can hide a working bind-mount from it. `statfs` reflects the
/// actual backing filesystem regardless of propagation.
///
/// **Caveat**: `NSFS_MAGIC` identifies the nsfs filesystem, not the
/// namespace *type* — a bind-mount of any namespace (PID, mount, UTS, …)
/// also returns `true` (as does e.g. `/proc/self/ns/pid`). Distinguishing
/// types would need `ioctl(NS_GET_NSTYPE)`; for the stale-marker workflow
/// this predicate exists for, the distinction doesn't arise.
pub fn is_namespace_path<P: AsRef<Path>>(path: P) -> bool {
    let Ok(c_path) = path_to_cstring(path.as_ref()) else {
        return false; // interior NUL — cannot be a real path
    };
    // SAFETY: `c_path` outlives the call, so the path pointer stays valid;
    // `f_type` is read only when `rc == 0`.
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut buf) };
    rc == 0 && buf.f_type as u64 == NSFS_MAGIC
}

/// Named-namespace counterpart to [`is_namespace_path`], resolving against the
/// `ip netns` convention `/var/run/netns/<name>`.
///
/// Pairs with [`exists`]: `exists` only checks the marker is present; this
/// checks it is a live netns.
pub fn is_namespace(name: &str) -> bool {
    named_path(name).is_ok_and(is_namespace_path)
}

/// Resolve `ip netns` name → path, refusing anything that is not a live
/// namespace.
///
/// Every by-name entry point (`spawn*`, `connection_for*`, `open`, `enter`,
/// the sysctl helpers) funnels through here so that a **stale marker** —
/// the empty file `ip netns add` leaves behind once its nsfs bind-mount is
/// gone, after a crash or a bare `umount` — is a namespace not-found error,
/// the variant `is_not_found()` matches and callers reconcile on. Gating on
/// `Path::exists()` let the marker through, and the failure then surfaced
/// from `setns(2)` as an `EINVAL` nothing downstream recognised as "the
/// namespace is gone" (#348). The stale case is also logged at `warn`,
/// because a marker with no mount behind it is usually a bug the operator
/// wants to know about.
/// The file a namespaced socket was opened through, and the namespace it
/// named then (#504).
///
/// A socket holds a reference on its network namespace, so deleting the
/// namespace — unmounting and removing its marker — does not free it while
/// the socket is open: its interfaces, the root-side ends of its veths
/// included, live on, and nothing tells the socket's owner. The namespace
/// sends no `RTM_DELNSID` either, because it is not being destroyed: the
/// socket is what holds it. So a stream watches the marker instead.
#[derive(Debug, Clone)]
pub(crate) struct NamespaceMarker {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl NamespaceMarker {
    /// The marker for a namespace opened at `path` as `file`. `None` for a
    /// `/proc/<pid>/ns/net` path: that file goes when the process exits,
    /// which does not end its namespace. Following a process's namespace
    /// needs a pidfd (#520).
    pub(crate) fn of(path: &Path, file: &std::fs::File) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        if path.starts_with("/proc") {
            return None;
        }
        let meta = file.metadata().ok()?;
        Some(Self {
            path: path.to_path_buf(),
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }

    /// Whether the marker still names the namespace it named at open. One
    /// that is gone, or now is something else — the plain file left once
    /// the namespace is unmounted, or a new namespace under the same name —
    /// does not. Any other error (`EACCES`) cannot tell, and counts as live.
    pub(crate) fn is_live(&self) -> bool {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(&self.path) {
            Ok(meta) => meta.dev() == self.dev && meta.ino() == self.ino,
            Err(e) => !matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ),
        }
    }

    /// The marker's path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) fn live_named_path(ns_name: &str) -> Result<PathBuf> {
    live_path_in(Path::new(NETNS_RUN_DIR), ns_name)
}

/// [`live_named_path`] over an explicit run directory, so the stale-marker
/// classification is testable without root.
fn live_path_in(run_dir: &Path, ns_name: &str) -> Result<PathBuf> {
    validate_name(ns_name)?;
    let path = run_dir.join(ns_name);
    if is_namespace_path(&path) {
        return Ok(path);
    }
    if path.exists() {
        tracing::warn!(
            namespace = ns_name,
            path = %path.display(),
            "stale ip-netns marker: file present but no namespace mounted over it"
        );
    }
    Err(Error::namespace_not_found(ns_name))
}

/// Create a named network namespace.
///
/// This is equivalent to `ip netns add <name>`. It creates the namespace
/// directory if needed, creates a new network namespace, and bind-mounts
/// it to `/var/run/netns/<name>`.
///
/// # Errors
///
/// Returns an error if:
/// - The namespace already exists
/// - Permission is denied (requires root or CAP_SYS_ADMIN)
/// - The namespace directory cannot be created
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::namespace;
///
/// namespace::create("myns")?;
/// // Now "myns" exists and can be used
/// let conn = nlink::Connection::<nlink::Route>::new_in("myns")?;
/// # Ok(())
/// # }
/// ```
///
/// See also [`create_path`] to persist a netns at an arbitrary path.
pub fn create(name: &str) -> Result<()> {
    create_path(named_path(name)?)
}

/// Where [`create_with`] writes the owner tags: one file per named
/// namespace, holding its owner. Not under `/run/netns`, which `ip netns`
/// lists as namespaces, and not an xattr, which tmpfs may not keep (#522).
pub const OWNER_TAG_DIR: &str = "/run/nlink/netns-owners";

/// How [`create_with`] creates a named namespace (#522).
///
/// ```no_run
/// # fn example() -> nlink::Result<()> {
/// use nlink::netlink::namespace::{self, CreateOptions};
///
/// namespace::create_with("lab-r1", CreateOptions::new().owner("nlink-lab").reclaim_stale(true))?;
/// assert_eq!(namespace::owner_of("lab-r1")?.as_deref(), Some("nlink-lab"));
/// for name in namespace::list_owned("nlink-lab")? {
///     println!("{name}");
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct CreateOptions {
    owner: Option<String>,
    reclaim_stale: bool,
}

impl CreateOptions {
    /// The defaults: no owner, and an existing marker is an error.
    pub fn new() -> Self {
        Self::default()
    }

    /// Tag the namespace as `owner`'s, under [`OWNER_TAG_DIR`]. The tag is
    /// written before the namespace is made, so a crash between the two
    /// leaves a tag with no namespace — which [`list_owned`] still lists —
    /// and never a namespace with no tag.
    pub fn owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = Some(owner.into());
        self
    }

    /// Remove a stale marker in the name's place — a `/run/netns` file
    /// nothing is mounted on, left by a crash — instead of failing. A live
    /// namespace is never touched: that is still an error.
    pub fn reclaim_stale(mut self, reclaim: bool) -> Self {
        self.reclaim_stale = reclaim;
        self
    }
}

/// The owner tag's path for `name`.
fn owner_tag_path(name: &str) -> Result<PathBuf> {
    validate_name(name)?;
    Ok(PathBuf::from(OWNER_TAG_DIR).join(name))
}

/// Create a named namespace as [`create`] does, with an owner tag and stale
/// marker reclaim (#522).
///
/// # Errors
///
/// As [`create`]; and [`Error::is_already_exists`] for a live namespace of
/// the name even with [`CreateOptions::reclaim_stale`]. A failed create
/// removes the tag it wrote.
pub fn create_with(name: &str, opts: CreateOptions) -> Result<()> {
    let path = named_path(name)?;
    if opts.reclaim_stale && path.exists() && !is_namespace_path(&path) {
        std::fs::remove_file(&path)
            .map_err(|e| Error::from(e).with_context(format!("remove stale marker {}", path.display())))?;
    }
    let tag = match &opts.owner {
        Some(owner) => Some(write_owner_tag(name, owner)?),
        None => None,
    };
    match create_path(&path) {
        Ok(()) => Ok(()),
        Err(e) => {
            if let Some(tag) = tag {
                let _ = std::fs::remove_file(tag);
            }
            Err(e)
        }
    }
}

/// Write `owner` as `name`'s tag, atomically: a temporary file renamed
/// over the tag.
fn write_owner_tag(name: &str, owner: &str) -> Result<PathBuf> {
    let tag = owner_tag_path(name)?;
    std::fs::create_dir_all(OWNER_TAG_DIR)
        .map_err(|e| Error::from(e).with_context(format!("create {OWNER_TAG_DIR}")))?;
    let tmp = tag.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, owner)
        .and_then(|()| std::fs::rename(&tmp, &tag))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            Error::from(e).with_context(format!("write owner tag {}", tag.display()))
        })?;
    Ok(tag)
}

/// The owner [`create_with`] tagged `name` with, if any (#522). The tag
/// outlives a crash that left no namespace; [`exists`] says whether there
/// is one.
pub fn owner_of(name: &str) -> Result<Option<String>> {
    match std::fs::read_to_string(owner_tag_path(name)?) {
        Ok(owner) => Ok(Some(owner)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::from(e)),
    }
}

/// The names [`create_with`] tagged as `owner`'s (#522), sorted: the
/// namespaces it made, and any whose create a crash cut short — the tag is
/// written first. A reaper deletes the namespaces that exist and the tags
/// of those that do not, with [`delete`] and [`remove_owner_tag`].
pub fn list_owned(owner: &str) -> Result<Vec<String>> {
    let entries = match std::fs::read_dir(OWNER_TAG_DIR) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::from(e)),
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        // A rename in flight.
        .filter(|name| !name.contains(".tmp."))
        .filter(|name| owner_of(name).ok().flatten().as_deref() == Some(owner))
        .collect();
    names.sort();
    Ok(names)
}

/// Remove `name`'s owner tag, if it has one (#522). [`delete`] does this
/// for a namespace it deletes; this is for a tag with no namespace.
pub fn remove_owner_tag(name: &str) -> Result<()> {
    match std::fs::remove_file(owner_tag_path(name)?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::from(e)),
    }
}

/// The EEXIST-shaped error [`create_path`] returns for an already-present
/// path. Built as `ErrorKind::AlreadyExists` (rather than a stringly
/// `InvalidMessage`) so callers can classify it with
/// [`Error::is_already_exists`] — the detect-stale-and-retry loop around
/// [`is_namespace_path`] depends on that.
fn already_exists_error(path: &Path) -> Error {
    Error::from(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("namespace '{}' already exists", path.display()),
    ))
}

/// Highest ancestor of `dir` that does not yet exist — the directory that
/// `create_dir_all(dir)` will materialize first. Removing it on rollback
/// undoes exactly what we created and nothing pre-existing.
fn topmost_missing_ancestor(dir: &Path) -> PathBuf {
    let mut topmost = dir.to_path_buf();
    let mut cursor = dir;
    while let Some(parent) = cursor.parent() {
        if parent.exists() {
            break;
        }
        topmost = parent.to_path_buf();
        cursor = parent;
    }
    topmost
}

/// Rollback counterpart to the `create_dir_all` in [`create_path`]: remove
/// the directories it materialized, walking upward from `parent` to
/// `topmost` (inclusive) with `remove_dir`, which only deletes *empty*
/// directories. `remove_dir_all` would be wrong here: a concurrent
/// `create_path` under a shared ancestor may have installed its own marker
/// since we created the tree — `remove_dir` stops at the first non-empty
/// (or already-removed) directory instead of deleting a sibling's namespace
/// out from under it.
fn remove_empty_dirs_upward(parent: &Path, topmost: &Path) {
    let mut cursor = parent;
    loop {
        if std::fs::remove_dir(cursor).is_err() {
            // Non-empty (a sibling moved in) or already gone (a racing
            // rollback) — every ancestor is non-empty too, so stop.
            return;
        }
        if cursor == topmost {
            return;
        }
        let Some(next) = cursor.parent() else { return };
        cursor = next;
    }
}

/// Create a persistent network namespace bind-mounted at an arbitrary `path`.
///
/// Like [`create`], but the namespace lives at the caller's path instead of
/// the `ip netns` convention `/var/run/netns/<name>`. The parent directory is
/// created if needed.
///
/// `path` should be absolute. A relative path resolves against the current
/// working directory, which a multi-threaded program can change mid-call —
/// surprising for both the bind mount and the parent-rollback target.
///
/// # Errors
///
/// Returns an error if the path already exists (EEXIST-shaped — matchable
/// via [`Error::is_already_exists`]), the parent cannot be created, or the
/// unshare/mount sequence fails (requires root or CAP_SYS_ADMIN).
pub fn create_path<P: AsRef<Path>>(path: P) -> Result<()> {
    let ns_path = path.as_ref().to_path_buf();

    // Check if namespace already exists
    if ns_path.exists() {
        return Err(already_exists_error(&ns_path));
    }

    // Remember the created directory span (deepest, topmost) so a later
    // failure can roll back the tree instead of leaking it.
    let created_dirs = match ns_path.parent() {
        Some(parent) if !parent.exists() => {
            let topmost = topmost_missing_ancestor(parent);
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::from(e).with_context(format!("create {}", parent.display()))
            })?;
            Some((parent.to_path_buf(), topmost))
        }
        _ => None,
    };

    let rollback_dirs = |created: &Option<(PathBuf, PathBuf)>| {
        if let Some((parent, topmost)) = created {
            remove_empty_dirs_upward(parent, topmost);
        }
    };

    // Create an empty file for the bind mount. `create_new` closes the
    // TOCTOU on the exists() check above: if a concurrent create_path (or an
    // operator `ip netns add`) won the race since, this fails with EEXIST
    // instead of truncating the winner's marker.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&ns_path)
        .map_err(|e| {
            rollback_dirs(&created_dirs);
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                already_exists_error(&ns_path)
            } else {
                Error::from(e).with_context(format!("create namespace file {}", ns_path.display()))
            }
        })?;

    // 0.19 N1 fix — isolate the unshare+mount+setns sequence on
    // a dedicated OS thread.
    //
    // The kernel scopes `unshare(CLONE_NEWNET)` to the *calling
    // thread*, not the process. When this function is called from
    // an async context (tokio `LabNamespace::new`, integration
    // test setup), the calling thread is a tokio worker. Until
    // the matching `setns()` restores the original netns, every
    // other tokio task scheduled on that worker temporarily
    // observes the new (empty) namespace — including any
    // `Connection<P>` they construct in that window, which
    // silently binds to the wrong netns. The same mechanism
    // affects sync callers from a multi-threaded program because
    // `mount(2)` can block on disk I/O long enough for any other
    // thread to be scheduled.
    //
    // The fix: do the unshare+mount+setns on a freshly-spawned
    // `std::thread`, then `join()`. The dedicated thread has no
    // co-scheduled work, and its destructor is the only observer
    // of the transient netns membership; we wait for setns to
    // complete before returning.
    let ns_path_owned = ns_path.clone();
    let label = ns_path.display().to_string();
    // `thread::spawn` panics when no thread can be made (#510).
    let worker = std::thread::Builder::new().name("nlink-netns".into());
    let thread_result = match worker
        .spawn(move || -> Result<()> { create_namespace_in_current_thread(&label, &ns_path_owned) })
    {
        Ok(handle) => handle.join(),
        Err(e) => {
            let _ = std::fs::remove_file(&ns_path);
            rollback_dirs(&created_dirs);
            return Err(Error::from(e));
        }
    };

    match thread_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            // Worker already tore down its marker (and any live mount) on every
            // error path; retry here in case it raced, then roll back parent dirs.
            let _ = std::fs::remove_file(&ns_path);
            rollback_dirs(&created_dirs);
            Err(e)
        }
        Err(_panic) => {
            // Worker panicked — leaves the bind mount in an
            // undefined state. Remove the file so we don't leak
            // an empty netns marker.
            let _ = std::fs::remove_file(&ns_path);
            rollback_dirs(&created_dirs);
            Err(Error::internal(format!(
                "namespace {}: the worker thread panicked during create",
                ns_path.display()
            )))
        }
    }
}

/// Inner half of [`create`] — runs on a dedicated `std::thread`
/// so the `unshare(CLONE_NEWNET)` + `mount(MS_BIND)` + `setns()`
/// sequence is isolated from tokio worker threads. See [`create`]
/// for the rationale.
fn create_namespace_in_current_thread(name: &str, ns_path: &Path) -> Result<()> {
    // Save the current namespace so we can restore after unshare.
    // Without this, unshare(CLONE_NEWNET) permanently changes the calling
    // thread's namespace, breaking subsequent namespace operations.
    let original_ns = File::open("/proc/thread-self/ns/net").map_err(|e| {
        let _ = std::fs::remove_file(ns_path);
        Error::from(e).with_context("save the current namespace")
    })?;

    // Create a new network namespace
    // SAFETY: unshare is a standard Linux syscall. CLONE_NEWNET creates a new
    // network namespace for the current process.
    let ret = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    if ret < 0 {
        // Clean up the file we created
        let _ = std::fs::remove_file(ns_path);
        return Err(Error::from(std::io::Error::last_os_error()));
    }

    // Bind mount the namespace to the file
    let ns_path_cstr = path_to_cstring(ns_path).inspect_err(|_| {
        let _ = std::fs::remove_file(ns_path);
    })?;

    let self_ns = std::ffi::CString::new("/proc/thread-self/ns/net").unwrap();

    // SAFETY: mount is a standard Linux syscall. We're bind-mounting the current
    // process's network namespace (which we just created) to the namespace file.
    let ret = unsafe {
        libc::mount(
            self_ns.as_ptr(),
            ns_path_cstr.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        // Try to restore original namespace before returning
        unsafe { libc::setns(original_ns.as_raw_fd(), libc::CLONE_NEWNET) };
        let _ = std::fs::remove_file(ns_path);
        return Err(Error::from(err));
    }

    // Restore the calling thread to its original namespace.
    // SAFETY: setns is a standard Linux syscall. original_ns is a valid FD
    // to the namespace we opened before unshare().
    let ret = unsafe { libc::setns(original_ns.as_raw_fd(), libc::CLONE_NEWNET) };
    if ret < 0 {
        let restore_err = std::io::Error::last_os_error();
        // Bind mount is live but we couldn't restore the caller's netns, so the
        // create has failed as a whole. Tear down the mount + marker here so the
        // caller's rollback isn't racing a pinned mount.
        if let Ok(c) = path_to_cstring(ns_path) {
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
        }
        let _ = std::fs::remove_file(ns_path);
        return Err(Error::from(restore_err)
            .with_context(format!("namespace {name}: restore the original namespace")));
    }

    Ok(())
}

/// Delete a named network namespace.
///
/// This is equivalent to `ip netns del <name>`. It unmounts and removes
/// the namespace file from `/var/run/netns/<name>`.
///
/// # Errors
///
/// Returns an error if:
/// - The namespace doesn't exist
/// - Permission is denied
/// - The unmount fails (e.g., namespace is in use)
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::namespace;
///
/// namespace::delete("myns")?;
/// # Ok(())
/// # }
/// ```
///
/// See also [`delete_path`] to delete a netns at an arbitrary path.
pub fn delete(name: &str) -> Result<()> {
    delete_path(named_path(name)?)?;
    // Its owner tag, if [`create_with`] wrote one (#522).
    remove_owner_tag(name)
}

/// Delete a persistent network namespace at an arbitrary `path`.
///
/// The path-based counterpart to [`delete`], for namespaces created via
/// [`create_path`]. Lazily unmounts the bind mount (`MNT_DETACH`) and removes
/// the marker file.
///
/// Removes only the marker file and bind mount; parent directories that
/// [`create_path`] created are left in place — delete cannot know which
/// ancestors were pre-existing. The caller owns teardown of its directory
/// tree.
///
/// # Errors
///
/// Returns an error if:
/// - The path doesn't exist — a not-found error whose
///   [`ErrorObject::Namespace`](crate::ErrorObject::Namespace) carries the
///   path string for path-based deletes.
/// - The unmount fails with anything other than `EINVAL` (which covers the
///   "not a mount point" case — a stale marker with no live bind mount).
/// - The marker file cannot be removed.
pub fn delete_path<P: AsRef<Path>>(path: P) -> Result<()> {
    let ns_path = path.as_ref();

    if !ns_path.exists() {
        return Err(Error::namespace_not_found(ns_path.display().to_string()));
    }
    // A namespace is a file — the nsfs inode bind-mounted over a marker, or
    // a stale marker. Lazily unmounting a directory detaches everything
    // mounted under it (#463).
    let is_file = std::fs::symlink_metadata(ns_path).is_ok_and(|m| m.file_type().is_file());
    if !is_file {
        return Err(Error::invalid_message(format!(
            "refusing to delete {}: not a namespace file",
            ns_path.display()
        )));
    }

    let ns_path_cstr = path_to_cstring(ns_path)?;

    // Unmount the namespace
    // SAFETY: umount2 is a standard Linux syscall. MNT_DETACH allows lazy
    // unmounting which succeeds even if the mount is busy.
    let ret = unsafe { libc::umount2(ns_path_cstr.as_ptr(), libc::MNT_DETACH) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        // EINVAL means it's not a mount point (maybe already unmounted)
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(Error::from(err));
        }
    }

    // Remove the file
    std::fs::remove_file(ns_path).map_err(|e| {
        Error::from(e).with_context(format!("remove namespace file {}", ns_path.display()))
    })?;

    Ok(())
}

/// Execute a function in a network namespace and return to the original.
///
/// This is a convenience wrapper around [`enter`] that ensures the original
/// namespace is restored even if the function panics.
///
/// # Warning
///
/// This affects the entire thread. In async contexts, prefer using
/// [`connection_for`] which creates a socket in the namespace without
/// affecting the thread state.
///
/// The closure runs on the **calling** thread; if the restore afterwards
/// fails, that thread stays in the target namespace (see [`enter`]'s
/// warning), and the restore's error is returned — the closure's result
/// is lost. When the closure is `Send + 'static`, prefer spawning a
/// scoped thread that enters the namespace and exits without restoring —
/// the pattern the [`get_sysctl`]-family helpers use internally (#185).
///
/// Reading the namespace's `/proc` files: `/proc/net` is a link to
/// `/proc/self/net`, which follows the thread-group leader, so in a
/// multithreaded program it shows the **main thread's** namespace. Read
/// `/proc/thread-self/net` instead.
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::namespace;
///
/// let result = namespace::execute_in("myns", || {
///     // Code here runs in "myns" namespace
///     std::fs::read_to_string("/proc/thread-self/net/dev")
/// })??;
/// // Back in original namespace
/// # Ok(())
/// # }
/// ```
pub fn execute_in<F, T>(name: &str, f: F) -> Result<T>
where
    F: FnOnce() -> T,
{
    let guard = enter(name)?;
    let result = f();
    guard.restore()?;
    Ok(result)
}

/// Execute a function in a network namespace specified by path.
///
/// See [`execute_in`] for details, including what a failed restore does
/// with the closure's result.
pub fn execute_in_path<F, T, P: AsRef<Path>>(path: P, f: F) -> Result<T>
where
    F: FnOnce() -> T,
{
    let guard = enter_path(path)?;
    let result = f();
    guard.restore()?;
    Ok(result)
}

/// List all named network namespaces.
///
/// Returns the names of every entry in `/var/run/netns/` — including a
/// **stale marker**: `ip netns add` creates the file and bind-mounts the
/// namespace over it, and after a crash or a `umount` the empty file can
/// remain with no namespace behind it. [`list_live`] filters those out
/// through [`is_namespace_path`]. Names are `to_string_lossy`'d, so a
/// non-UTF-8 name comes back mangled (the `Vec<String>` API predates the
/// concern; use `std::fs::read_dir` on [`NETNS_RUN_DIR`] if the bytes
/// matter).
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::namespace;
///
/// for ns in namespace::list()? {
///     println!("Namespace: {}", ns);
/// }
/// # Ok(())
/// # }
/// ```
pub fn list() -> Result<Vec<String>> {
    let dir = match std::fs::read_dir(NETNS_RUN_DIR) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // No namespaces directory means no namespaces
            return Ok(Vec::new());
        }
        Err(e) => {
            return Err(Error::from(e));
        }
    };

    let mut names = Vec::new();
    for entry in dir {
        let entry = entry.map_err(Error::from)?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name != "." && name != ".." {
            names.push(name);
        }
    }

    names.sort();
    Ok(names)
}

/// [`list`], keeping only names with a live namespace behind them
/// (#186).
///
/// A directory entry under [`NETNS_RUN_DIR`] is a namespace only while
/// an `nsfs` mount sits on it; an unmounted marker file is what
/// [`is_namespace_path`] rejects and what [`connection_for`] on that
/// name would fail on with `EINVAL` from `setns`. Same ordering and
/// `to_string_lossy` caveat as [`list`].
pub fn list_live() -> Result<Vec<String>> {
    let mut names = list()?;
    names.retain(|name| is_namespace_path(PathBuf::from(NETNS_RUN_DIR).join(name)));
    Ok(names)
}

// ─────────────────────────────────────────────────
// Sysctl operations (namespace-aware)
// ─────────────────────────────────────────────────

/// Run `f` on a dedicated worker thread that has entered the namespace at
/// `path`, joining before return.
///
/// The worker exits **without restoring** — a thread's netns membership dies
/// with it — so there is no restore step that can fail and leave a shared
/// (e.g. tokio worker) thread stuck in the target namespace (#185). This is
/// the same thread discipline as [`create_path`] and
/// `NetlinkSocket::new_in_namespace`. Contrast with [`execute_in`], which
/// runs `f` on the *calling* thread and carries that hazard.
fn run_in_namespace_thread<T, F>(path: PathBuf, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    // `thread::spawn` panics when no thread can be made (#510).
    let worker = std::thread::Builder::new().name("nlink-netns".into());
    let thread_result = worker
        .spawn(move || -> Result<T> {
        let target = File::open(&path).map_err(|e| namespace_open_error(&path, e))?;
        let _home = ReturnHome::new();
        // SAFETY: setns switches only this freshly-spawned worker thread,
        // which leaves again before it returns (#797).
        let ret = unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) };
        if ret < 0 {
            return Err(Error::from(std::io::Error::last_os_error()));
        }
        f()
    })
        .map_err(Error::from)?
        .join();

    match thread_result {
        Ok(result) => result,
        Err(_panic) => Err(Error::internal("namespace worker thread panicked")),
    }
}

/// Read a sysctl value inside a named namespace.
///
/// Reads the value from `/proc/sys/` on a dedicated worker thread entered
/// into the namespace; the calling thread's namespace is untouched (#185).
///
/// # Errors
///
/// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) (matched by `is_not_found()`) unless
/// `/var/run/netns/<name>` is a live namespace — a stale marker with no
/// mount behind it counts as not found (#348).
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::namespace;
///
/// let val = namespace::get_sysctl("myns", "net.ipv4.ip_forward")?;
/// assert!(val == "0" || val == "1");
/// # Ok(())
/// # }
/// ```
pub fn get_sysctl(ns_name: &str, key: &str) -> Result<String> {
    get_sysctl_path(live_named_path(ns_name)?, key)
}

/// Set a sysctl value inside a named namespace.
///
/// Writes the value to `/proc/sys/` on a dedicated worker thread entered
/// into the namespace; the calling thread's namespace is untouched (#185).
/// Requires root or `CAP_SYS_ADMIN`.
///
/// # Errors
///
/// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) (matched by `is_not_found()`) unless
/// `/var/run/netns/<name>` is a live namespace — a stale marker with no
/// mount behind it counts as not found (#348).
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::namespace;
///
/// namespace::set_sysctl("myns", "net.ipv4.ip_forward", "1")?;
/// # Ok(())
/// # }
/// ```
pub fn set_sysctl(ns_name: &str, key: &str, value: &str) -> Result<()> {
    set_sysctl_path(live_named_path(ns_name)?, key, value)
}

/// Set multiple sysctl values inside a named namespace.
///
/// Enters the namespace once (on a dedicated worker thread) and applies all
/// entries. If any entry fails, returns the error immediately without
/// applying remaining entries.
///
/// # Errors
///
/// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) (matched by `is_not_found()`) unless
/// `/var/run/netns/<name>` is a live namespace — a stale marker with no
/// mount behind it counts as not found (#348).
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::namespace;
///
/// namespace::set_sysctls("myns", &[
///     ("net.ipv4.ip_forward", "1"),
///     ("net.ipv6.conf.all.forwarding", "1"),
/// ])?;
/// # Ok(())
/// # }
/// ```
pub fn set_sysctls(ns_name: &str, entries: &[(&str, &str)]) -> Result<()> {
    set_sysctls_path(live_named_path(ns_name)?, entries)
}

/// Read a sysctl value inside a namespace specified by path.
///
/// See [`get_sysctl`] for details.
pub fn get_sysctl_path<P: AsRef<Path>>(path: P, key: &str) -> Result<String> {
    let key = key.to_owned();
    run_in_namespace_thread(path.as_ref().to_path_buf(), move || {
        super::sysctl::get(&key)
    })
}

/// Set a sysctl value inside a namespace specified by path.
///
/// See [`set_sysctl`] for details.
pub fn set_sysctl_path<P: AsRef<Path>>(path: P, key: &str, value: &str) -> Result<()> {
    let (key, value) = (key.to_owned(), value.to_owned());
    run_in_namespace_thread(path.as_ref().to_path_buf(), move || {
        super::sysctl::set(&key, &value)
    })
}

/// Set multiple sysctl values inside a namespace specified by path.
///
/// See [`set_sysctls`] for details.
pub fn set_sysctls_path<P: AsRef<Path>>(path: P, entries: &[(&str, &str)]) -> Result<()> {
    let entries: Vec<(String, String)> = entries
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    run_in_namespace_thread(path.as_ref().to_path_buf(), move || {
        let borrowed: Vec<(&str, &str)> = entries
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        super::sysctl::set_many(&borrowed)
    })
}

// ─────────────────────────────────────────────────
// Process spawning (namespace-aware)
// ─────────────────────────────────────────────────

/// Spawn a process inside a named network namespace.
///
/// Uses `pre_exec` + `setns()` to switch the child process into the target
/// namespace between `fork()` and `exec()`. The parent process is unaffected.
///
/// **Not with `CommandExt::uid`/`gid`/`groups`.** std applies those in the
/// child *before* any `pre_exec` closure, so the `setns` this does would
/// run unprivileged and fail with `EPERM` (#502). To run the process as
/// another user, use [`spawn_as`] / [`spawn_with_etc_as`], which drop
/// privileges after entering the namespace.
///
/// # Errors
///
/// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) (matched by `is_not_found()`) unless
/// `/var/run/netns/<name>` is a live namespace — a stale marker with no
/// mount behind it counts as not found (#348).
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::namespace;
/// use std::process::Command;
///
/// let mut cmd = Command::new("ip");
/// cmd.arg("link");
/// let mut child = namespace::spawn("myns", cmd)?;
/// child.wait()?;
/// # Ok(())
/// # }
/// ```
pub fn spawn(ns_name: &str, cmd: std::process::Command) -> Result<std::process::Child> {
    let path = live_named_path(ns_name)?;
    spawn_path(&path, cmd)
}

/// Spawn a process and collect its output inside a named namespace.
///
/// This is a convenience wrapper that spawns the process with stdout and
/// stderr captured, waits for it to complete, and returns the output.
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::namespace;
/// use std::process::Command;
///
/// let mut cmd = Command::new("ip");
/// cmd.arg("addr");
/// let output = namespace::spawn_output("myns", cmd)?;
/// println!("{}", String::from_utf8_lossy(&output.stdout));
/// # Ok(())
/// # }
/// ```
pub fn spawn_output(ns_name: &str, mut cmd: std::process::Command) -> Result<std::process::Output> {
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let child = spawn(ns_name, cmd)?;
    child.wait_with_output().map_err(Error::from)
}

/// Spawn a process inside a namespace specified by path.
///
/// See [`spawn`] for details.
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::namespace;
/// use std::process::Command;
///
/// let mut cmd = Command::new("ip");
/// cmd.arg("link");
/// let child = namespace::spawn_path("/proc/1234/ns/net", cmd)?;
/// # Ok(())
/// # }
/// ```
pub fn spawn_path<P: AsRef<Path>>(
    path: P,
    cmd: std::process::Command,
) -> Result<std::process::Child> {
    spawn_path_inner(path.as_ref(), cmd, None)
}

/// Who a namespaced child runs as: [`spawn_as`], [`spawn_with_etc_as`].
///
/// Applied in the child after it has entered the namespace (and, with
/// `/etc` overlays, after the mounts), where `CommandExt::uid` would run
/// before them and leave `setns` without the privilege it needs (#502).
/// The order is `setgroups`, `setgid`, `setuid`, as std's own is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpawnUser {
    /// User id to run as.
    pub uid: u32,
    /// Group id to run as.
    pub gid: u32,
    /// Supplementary groups; empty drops them all.
    pub groups: Vec<u32>,
}

impl SpawnUser {
    /// Run as `uid`:`gid`, with no supplementary groups.
    pub fn new(uid: u32, gid: u32) -> Self {
        Self {
            uid,
            gid,
            groups: Vec::new(),
        }
    }

    /// Set the supplementary groups.
    pub fn groups(mut self, groups: impl IntoIterator<Item = u32>) -> Self {
        self.groups = groups.into_iter().collect();
        self
    }

    /// Register the privilege drop on `cmd`. `pre_exec` closures run in
    /// the order they were added, so this goes after nlink's own.
    fn install(&self, cmd: &mut std::process::Command) {
        use std::os::unix::process::CommandExt;
        let (uid, gid) = (self.uid, self.gid);
        let groups: Vec<libc::gid_t> = self.groups.clone();
        // SAFETY: setgroups/setgid/setuid are raw syscalls; `groups` was
        // allocated before the fork and is only read here.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

/// [`spawn`], running the process as `user` (#502).
///
/// The child enters the namespace first and then drops to `user`.
/// `CommandExt::uid` on `cmd` cannot do this: std applies it before any
/// `pre_exec` closure, so `setns` would fail with `EPERM`.
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::namespace::{self, SpawnUser};
/// use std::process::Command;
///
/// let child = namespace::spawn_as("myns", Command::new("id"), &SpawnUser::new(1000, 1000))?;
/// # Ok(())
/// # }
/// ```
pub fn spawn_as(
    ns_name: &str,
    cmd: std::process::Command,
    user: &SpawnUser,
) -> Result<std::process::Child> {
    let path = live_named_path(ns_name)?;
    spawn_path_inner(&path, cmd, Some(user))
}

fn spawn_path_inner(
    path: &Path,
    mut cmd: std::process::Command,
    user: Option<&SpawnUser>,
) -> Result<std::process::Child> {
    use std::os::unix::process::CommandExt;

    let ns_fd = open_path(path)?;
    let raw_fd = ns_fd.as_raw_fd();

    // SAFETY: setns is async-signal-safe (it's a syscall). pre_exec runs in
    // the child process after fork() but before exec(). The fd is valid
    // because ns_fd is kept alive until after spawn() returns — the closure
    // captures raw_fd by value, and ns_fd is dropped only after spawn().
    unsafe {
        cmd.pre_exec(move || {
            if libc::setns(raw_fd, libc::CLONE_NEWNET) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    if let Some(user) = user {
        user.install(&mut cmd);
    }

    let child = cmd.spawn().map_err(Error::from)?;
    drop(ns_fd);
    Ok(child)
}

/// Spawn a process and collect its output inside a namespace specified by path.
///
/// See [`spawn_output`] for details.
pub fn spawn_output_path<P: AsRef<Path>>(
    path: P,
    mut cmd: std::process::Command,
) -> Result<std::process::Output> {
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let child = spawn_path(path, cmd)?;
    child.wait_with_output().map_err(Error::from)
}

// ============================================================================
// Process spawning with /etc/netns/ overlay (mirrors `ip netns exec`)
// ============================================================================

/// Pre-compute bind mount pairs from `/etc/netns/<name>/`.
///
/// This runs in the parent process where memory allocation is safe.
/// The returned `CString` pairs are captured by the `pre_exec` closure
/// so that only raw syscalls (no allocations) happen after fork.
fn prepare_etc_binds(ns_name: &str) -> Result<Vec<(std::ffi::CString, std::ffi::CString)>> {
    validate_name(ns_name)?;
    let etc_netns = PathBuf::from("/etc/netns").join(ns_name);

    let entries = match std::fs::read_dir(&etc_netns) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::from(e)),
    };

    let mut binds = Vec::new();
    for entry in entries {
        let entry = entry.map_err(Error::from)?;
        let file_name = entry.file_name();
        let src = entry.path();
        let dst = Path::new("/etc").join(&file_name);

        // Only overlay if the target exists (can't bind-mount over nothing)
        if !dst.exists() {
            continue;
        }

        binds.push((path_to_cstring(&src)?, path_to_cstring(&dst)?));
    }

    Ok(binds)
}

/// Spawn a process in a network namespace with `/etc/netns/` file overlays.
///
/// Like [`spawn`], but also creates a private mount namespace in the child and:
/// 1. Bind-mounts files from `/etc/netns/<ns_name>/` over `/etc/`
/// 2. Remounts `/sys` (sysfs) to reflect the new network namespace
///
/// This mirrors the behavior of `ip netns exec <name> <cmd>`.
///
/// If `/etc/netns/<ns_name>/` does not exist, the mount overlay step is skipped
/// and behavior is identical to [`spawn`] — including the child seeing the
/// **host's** `/sys/class/net`. That is a deliberate divergence from
/// `ip netns exec`, which always unshares and remounts `/sys` (#186): with
/// nothing to overlay, a mount namespace buys the child only a sysfs view
/// that nlink itself never reads, at the price of `CAP_SYS_ADMIN` and the
/// container caveats below. A caller that wants the remount without an
/// overlay can create an empty `/etc/netns/<ns>/` directory with one file
/// in it that also exists in `/etc`.
///
/// # What is fatal, and what is not
///
/// Requires `CAP_SYS_ADMIN` (for `unshare(CLONE_NEWNS)`) — necessary, not
/// sufficient: a container runtime's seccomp/AppArmor profile, or the
/// kernel's own rules for mounting sysfs in a user namespace, can refuse
/// individual steps to a root process that holds it. The rule the child
/// follows is: **never run with no `/sys`, never refuse to run over a
/// merely stale one.**
///
/// - `setns`, `unshare(CLONE_NEWNS)`, the `MS_SLAVE` remount of `/` and
///   every `/etc/netns/<ns>/*` bind mount are fatal — the spawn fails
///   with the step's errno. An overlay the caller set up and did not
///   get is an error, not a degradation.
/// - The `/sys` remount is best effort in one precise case. `/sys` is
///   detached with `umount2(MNT_DETACH)` and a fresh sysfs mounted for
///   the target netns, copying the read-only / `nosuid` / `nodev` /
///   `noexec` flags of the `/sys` that was there (the kernel refuses a
///   less restrictive sysfs than the one it sees, which is what made
///   this fail with `EPERM` in Docker and Podman, where `/sys` is
///   `ro,nosuid,nodev,noexec` — #334). If the detach failed and the
///   mount then fails too, the host's `/sys` is still in place: the
///   child runs on with a stale `/sys/class/net` (what plain [`spawn`]
///   gives) and the bind mounts proceed. If the detach *succeeded* and
///   the mount fails, the child would have no `/sys` at all, which is
///   worse than a stale one for anything that enumerates interfaces
///   through sysfs (#282); that case stays fatal.
///
/// The netlink-driven parts of nlink never read `/sys`; the remount is
/// for the child's own benefit (`ip link` and friends).
///
/// **Not with `CommandExt::uid`/`gid`/`groups`**, for the reason given at
/// [`spawn`]: use [`spawn_with_etc_as`] (#502).
///
/// # Errors
///
/// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) (matched by `is_not_found()`) unless
/// `/var/run/netns/<name>` is a live namespace — a stale marker with no
/// mount behind it counts as not found (#348).
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::namespace;
/// use std::process::Command;
///
/// // Create /etc/netns/myns/hosts with custom DNS entries, then:
/// let mut cmd = Command::new("cat");
/// cmd.arg("/etc/hosts");
/// let output = namespace::spawn_output_with_etc("myns", cmd)?;
/// // The process sees the custom /etc/hosts, not the host's
/// # Ok(())
/// # }
/// ```
pub fn spawn_with_etc(ns_name: &str, cmd: std::process::Command) -> Result<std::process::Child> {
    let path = live_named_path(ns_name)?;
    spawn_path_with_etc(&path, ns_name, cmd)
}

/// [`spawn_with_etc`], running the process as `user`: it drops to `user`
/// after entering the namespace and making the `/etc` mounts (#502). See
/// [`spawn_as`].
pub fn spawn_with_etc_as(
    ns_name: &str,
    cmd: std::process::Command,
    user: &SpawnUser,
) -> Result<std::process::Child> {
    let path = live_named_path(ns_name)?;
    spawn_path_with_etc_inner(&path, ns_name, cmd, Some(user))
}

/// Spawn a process and collect its output with `/etc/netns/` file overlays.
///
/// See [`spawn_with_etc`] for details.
pub fn spawn_output_with_etc(
    ns_name: &str,
    mut cmd: std::process::Command,
) -> Result<std::process::Output> {
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let child = spawn_with_etc(ns_name, cmd)?;
    child.wait_with_output().map_err(Error::from)
}

/// The `mount(2)` flags a replacement sysfs must carry so the kernel
/// accepts it next to the `/sys` already visible.
///
/// `fs/namespace.c: mount_too_revealing()` refuses to mount proc or
/// sysfs in a mount namespace where an instance is already fully
/// visible unless the new mount is at least as restrictive on every
/// locked flag: read-only, `nosuid`, `nodev`, `noexec`. Container
/// runtimes mount `/sys` with all four, so a bare `mount(sysfs)` there
/// is `EPERM` even for root with `CAP_SYS_ADMIN`. `ip netns exec`
/// copies only `ST_RDONLY`; this copies all four (#334).
///
/// Input is `statfs(2)`'s `f_flags` (the `ST_*` bits), output the
/// `MS_*` bits for `mount(2)`.
fn sysfs_mount_flags(st_flags: libc::c_ulong) -> libc::c_ulong {
    let mut flags = 0;
    if st_flags & libc::ST_RDONLY != 0 {
        flags |= libc::MS_RDONLY;
    }
    if st_flags & libc::ST_NOSUID != 0 {
        flags |= libc::MS_NOSUID;
    }
    if st_flags & libc::ST_NODEV != 0 {
        flags |= libc::MS_NODEV;
    }
    if st_flags & libc::ST_NOEXEC != 0 {
        flags |= libc::MS_NOEXEC;
    }
    flags
}

/// Spawn a process in a namespace specified by path with `/etc/netns/` file overlays.
///
/// The `ns_name` parameter is needed to locate the `/etc/netns/<name>/` directory.
///
/// See [`spawn_with_etc`] for details.
pub fn spawn_path_with_etc<P: AsRef<Path>>(
    path: P,
    ns_name: &str,
    cmd: std::process::Command,
) -> Result<std::process::Child> {
    spawn_path_with_etc_inner(path.as_ref(), ns_name, cmd, None)
}

fn spawn_path_with_etc_inner(
    path: &Path,
    ns_name: &str,
    mut cmd: std::process::Command,
    user: Option<&SpawnUser>,
) -> Result<std::process::Child> {
    use std::os::unix::process::CommandExt;

    let ns_fd = open_path(path)?;
    let raw_fd = ns_fd.as_raw_fd();

    // Pre-compute ALL data before fork — no allocations in pre_exec.
    let bind_mounts = prepare_etc_binds(ns_name)?;
    let ns_name_c = std::ffi::CString::new(ns_name)
        .map_err(|_| Error::invalid_message("null byte in namespace name"))?;

    // Pre-computed string literals for syscalls (avoid allocation after fork).
    let c_root = std::ffi::CString::new("/").unwrap();
    let c_none = std::ffi::CString::new("none").unwrap();
    let c_sys = std::ffi::CString::new("/sys").unwrap();
    let c_sysfs = std::ffi::CString::new("sysfs").unwrap();

    // SAFETY: All operations in pre_exec use only raw syscalls (setns, unshare,
    // mount, umount2). No memory allocation occurs — all CStrings are pre-computed
    // above and captured by the closure. This is async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            // 1. Enter network namespace
            if libc::setns(raw_fd, libc::CLONE_NEWNET) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            // 2. If no /etc overlay files, skip mount namespace setup entirely
            if bind_mounts.is_empty() {
                return Ok(());
            }

            // 3. Create private mount namespace for the child
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            // 4. Make mount tree slave to prevent propagation back to host.
            //    MS_SLAVE (not MS_PRIVATE) so parent->child propagation still works.
            if libc::mount(
                c_none.as_ptr(),
                c_root.as_ptr(),
                std::ptr::null(),
                libc::MS_SLAVE | libc::MS_REC,
                std::ptr::null(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }

            // 5. Remount /sys so sysfs reflects the new network namespace.
            //    Without this, /sys/class/net/ shows the host's interfaces.
            //
            //    The mount's failure used to be swallowed by an empty
            //    `if` — after the detach had already succeeded. So in a
            //    nested or restricted namespace the child ran on with
            //    **no /sys at all**. A stale /sys showing the host's
            //    interfaces is bad; nothing there is worse, because
            //    anything enumerating interfaces through sysfs
            //    (`util::ifname`, which is what the bins use) then fails
            //    outright instead of reading the wrong thing (#282).
            //
            //    Detach-then-mount is the order that works — `umount2`
            //    takes the topmost mount, so mounting the replacement
            //    first and unmounting after would just remove the
            //    replacement. That leaves the window between the two
            //    calls. If the detach succeeded and the mount fails,
            //    the only safe thing to do is refuse to exec: returning
            //    the error aborts the spawn rather than handing the
            //    caller a child whose /sys is gone.
            //
            //    Inside a container the detach itself is what fails —
            //    /sys is a read-only bind the runtime does not let go
            //    of — and then a plain `mount(sysfs)` fails too, with
            //    EPERM: the kernel's `mount_too_revealing` refuses a
            //    sysfs less restrictive than the one already visible,
            //    and Docker/Podman mount /sys `ro,nosuid,nodev,noexec`.
            //    `ip netns exec` handles this by statvfs'ing /sys and
            //    passing MS_RDONLY; this copies every lock-relevant
            //    flag (`statfs64`, because glibc's `statvfs` reads
            //    /proc/mounts — not async-signal-safe here). And if the
            //    mount still fails after a *failed* detach, the host's
            //    /sys is still there: stale, but present, exactly what
            //    plain `spawn` gives — so the exec proceeds and the
            //    /etc binds still apply (#334). The rule: never no
            //    /sys (#282), never refuse over a stale one.
            let detached = libc::umount2(c_sys.as_ptr(), libc::MNT_DETACH) == 0;
            let mut flags: libc::c_ulong = 0;
            if !detached {
                let mut st: libc::statfs64 = std::mem::zeroed();
                if libc::statfs64(c_sys.as_ptr(), &mut st) == 0 {
                    flags = sysfs_mount_flags(st.f_flags as libc::c_ulong);
                }
            }
            if libc::mount(
                ns_name_c.as_ptr(),
                c_sys.as_ptr(),
                c_sysfs.as_ptr(),
                flags,
                std::ptr::null(),
            ) != 0
                && detached
            {
                return Err(std::io::Error::last_os_error());
            }

            // 6. Apply pre-computed /etc bind mounts
            for (src, dst) in &bind_mounts {
                if libc::mount(
                    src.as_ptr(),
                    dst.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }

            Ok(())
        });
    }
    if let Some(user) = user {
        user.install(&mut cmd);
    }

    let child = cmd.spawn().map_err(Error::from)?;
    drop(ns_fd);
    Ok(child)
}

/// Spawn a process and collect output in a namespace by path with `/etc/netns/` overlays.
///
/// See [`spawn_path_with_etc`] for details.
pub fn spawn_output_path_with_etc<P: AsRef<Path>>(
    path: P,
    ns_name: &str,
    mut cmd: std::process::Command,
) -> Result<std::process::Output> {
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let child = spawn_path_with_etc(path, ns_name, cmd)?;
    child.wait_with_output().map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names `ip netns` would refuse are refused before anything touches
    /// the filesystem, and the by-name queries answer "no" for them (#463).
    #[test]
    fn invalid_namespace_names_are_refused() {
        for bad in ["", ".", "..", "a/b", "/etc/passwd", "../../tmp", "x\0y"] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
            assert!(delete(bad).is_err(), "{bad:?}");
            assert!(create(bad).is_err(), "{bad:?}");
            assert!(open(bad).is_err(), "{bad:?}");
            assert!(!exists(bad), "{bad:?}");
            assert!(!is_namespace(bad), "{bad:?}");
        }
        assert!(validate_name(&"n".repeat(256)).is_err());
        for good in ["lab", "lab.1", "node-a_b", &"n".repeat(255)] {
            validate_name(good).unwrap();
        }
    }

    /// `delete_path` refuses a directory instead of lazily unmounting
    /// everything under it (#463).
    #[test]
    fn delete_path_refuses_a_directory() {
        let dir = std::env::temp_dir().join(format!("nlink-ns-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let err = delete_path(&dir).unwrap_err();
        assert!(err.to_string().contains("not a namespace file"), "{err}");
        assert!(dir.is_dir());
        std::fs::remove_dir(&dir).unwrap();
    }

    /// #186 — `NamespaceFd` borrows as an I/O-safe fd, the same fd the
    /// raw accessor reports.
    #[test]
    fn namespace_fd_is_io_safe() {
        let Ok(fd) = open_path("/proc/self/ns/net") else {
            return; // no /proc (sandbox); nothing to check
        };
        assert_eq!(fd.as_fd().as_raw_fd(), fd.as_raw_fd());
    }

    /// #331 — which specs can carry an `/etc/netns/<name>/` overlay.
    #[test]
    fn etc_overlay_name_follows_the_ip_netns_name() {
        assert_eq!(NamespaceSpec::Named("lab").etc_overlay_name(), Some("lab"));
        let run = PathBuf::from(NETNS_RUN_DIR).join("lab");
        assert_eq!(NamespaceSpec::Path(&run).etc_overlay_name(), Some("lab"));
        let elsewhere = PathBuf::from("/tmp/netns/lab");
        assert_eq!(NamespaceSpec::Path(&elsewhere).etc_overlay_name(), None);
        // Neither directory exists: two failed canonicalizations are
        // not "the same directory". (This is the case on a fresh CI
        // container before any namespace has been created.)
        let nowhere = PathBuf::from("/nonexistent-nlink-test/netns/lab");
        assert_eq!(NamespaceSpec::Path(&nowhere).etc_overlay_name(), None);
        let procfs = PathBuf::from("/proc/1/ns/net");
        assert_eq!(NamespaceSpec::Path(&procfs).etc_overlay_name(), None);
        assert_eq!(NamespaceSpec::Pid(1).etc_overlay_name(), None);
        assert_eq!(NamespaceSpec::Default.etc_overlay_name(), None);
    }

    /// #334 — the replacement sysfs copies every flag the kernel locks
    /// (`mount_too_revealing`), not just read-only.
    #[test]
    fn sysfs_mount_flags_mirror_every_locked_flag() {
        assert_eq!(sysfs_mount_flags(0), 0, "a plain rw /sys needs no flags");
        assert_eq!(sysfs_mount_flags(libc::ST_RDONLY), libc::MS_RDONLY);
        let container = libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
        assert_eq!(
            sysfs_mount_flags(container),
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "Docker/Podman mount /sys ro,nosuid,nodev,noexec"
        );
        // Unrelated statfs bits (relatime, etc.) are not mount flags here.
        assert_eq!(sysfs_mount_flags(libc::ST_RELATIME), 0);
    }

    #[test]
    fn test_netns_run_dir() {
        assert_eq!(NETNS_RUN_DIR, "/var/run/netns");
    }

    #[test]
    fn test_list_namespaces() {
        // This should not fail even if the directory doesn't exist
        let result = list();
        assert!(result.is_ok());
    }

    #[test]
    fn test_exists_nonexistent() {
        assert!(!exists("definitely_does_not_exist_12345"));
    }

    #[test]
    fn test_topmost_missing_ancestor() {
        let base = std::env::temp_dir().join(format!("nlink-tma-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        // base does not exist; the topmost missing ancestor of base/a/b is base.
        assert_eq!(topmost_missing_ancestor(&base.join("a/b")), base);

        std::fs::create_dir_all(&base).unwrap();
        // base exists now; the topmost missing ancestor of base/a/b is base/a.
        assert_eq!(topmost_missing_ancestor(&base.join("a/b")), base.join("a"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_create_path_rejects_existing_marker() {
        // The already-exists check runs before any privileged syscall, so this
        // exercises the error path without root.
        let path = std::env::temp_dir().join(format!("nlink-exists-{}", std::process::id()));
        std::fs::File::create(&path).unwrap();
        let err = create_path(&path).expect_err("existing path must be rejected");
        assert!(err.to_string().contains("already exists"));
        assert!(
            err.is_already_exists(),
            "rejection must be classifiable via is_already_exists()"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_remove_empty_dirs_upward_full_chain() {
        let base = std::env::temp_dir().join(format!("nlink-rb-full-{}", std::process::id()));
        let parent = base.join("a/b");
        std::fs::create_dir_all(&parent).unwrap();
        remove_empty_dirs_upward(&parent, &base);
        assert!(!base.exists(), "empty chain should be removed up to topmost");
    }

    #[test]
    fn test_remove_empty_dirs_upward_stops_at_nonempty() {
        // Simulates a concurrent create_path having installed its own marker
        // under a shared ancestor: rollback must stop at the non-empty
        // directory instead of deleting the sibling.
        let base = std::env::temp_dir().join(format!("nlink-rb-stop-{}", std::process::id()));
        let parent = base.join("a/b");
        std::fs::create_dir_all(&parent).unwrap();
        let sibling = base.join("a/sibling-marker");
        std::fs::File::create(&sibling).unwrap();

        remove_empty_dirs_upward(&parent, &base);

        assert!(!parent.exists(), "empty leaf dir should be removed");
        assert!(sibling.exists(), "sibling marker must survive rollback");
        assert!(base.join("a").exists(), "non-empty ancestor must survive");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_delete_path_missing_is_not_found() {
        let path =
            std::env::temp_dir().join(format!("nlink-missing-del-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let err = delete_path(&path).expect_err("missing path must be rejected");
        assert!(err.is_not_found());
    }

    #[test]
    fn is_namespace_path_false_for_missing() {
        let path =
            std::env::temp_dir().join(format!("nlink-isns-missing-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(!is_namespace_path(&path));
    }

    #[test]
    fn is_namespace_path_false_for_plain_file() {
        // A regular file (the shape of a *stale* marker) is not a live netns.
        let path = std::env::temp_dir().join(format!("nlink-isns-plain-{}", std::process::id()));
        std::fs::File::create(&path).unwrap();
        assert!(!is_namespace_path(&path));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn is_namespace_false_for_nonexistent_name() {
        assert!(!is_namespace("definitely_does_not_exist_12345"));
    }

    /// #348 — a stale `ip netns` marker (plain file, no nsfs mount over
    /// it) resolves to a namespace not-found error, not to a path that `setns`
    /// will later refuse with EINVAL.
    #[test]
    fn live_path_in_rejects_a_plain_file_marker() {
        let dir = std::env::temp_dir().join(format!("nlink-stale-marker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("stale"), b"").unwrap();
        let stale = live_path_in(&dir, "stale");
        let missing = live_path_in(&dir, "missing");
        let _ = std::fs::remove_dir_all(&dir);

        let err = stale.expect_err("a plain file is not a namespace");
        assert!(err.is_not_found(), "got unclassifiable error: {err}");
        assert!(matches!(err.detail(), crate::netlink::ErrorDetail::NotFound { object: crate::ErrorObject::Namespace { name } } if name == "stale"));
        let err = missing.expect_err("an absent marker is not a namespace");
        assert!(err.is_not_found(), "got unclassifiable error: {err}");
    }

    /// #504: a marker is live while the path names what was opened. A
    /// namespace deleted under a socket leaves a plain file (unmounted) or
    /// nothing (removed); a new namespace of the same name is a new inode.
    /// Plain files stand in for the nsfs mounts here — the check is the
    /// same `stat`.
    #[test]
    fn a_namespace_marker_is_live_until_its_path_names_something_else() {
        let dir = std::env::temp_dir().join(format!("nlink-ns-marker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lab");
        std::fs::write(&path, b"").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let marker = NamespaceMarker::of(&path, &file).expect("a marker path");
        let opened = marker.is_live();

        // Replaced: same name, another file.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"").unwrap();
        let replaced = marker.is_live();
        // Removed.
        std::fs::remove_file(&path).unwrap();
        let removed = marker.is_live();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(opened, "the marker names what was opened");
        assert!(
            !replaced,
            "a new file under the same name is not the namespace"
        );
        assert!(!removed, "a removed marker is not the namespace");

        // A process's namespace file is not a marker: it goes when the
        // process does, which does not end the namespace.
        let own = std::fs::File::open("/proc/self/ns/net").unwrap();
        assert!(NamespaceMarker::of(Path::new("/proc/self/ns/net"), &own).is_none());
    }

    /// The resolver accepts a real nsfs path: `/proc/self/ns` is the one
    /// run directory every process has.
    #[test]
    fn live_path_in_accepts_the_callers_own_net_namespace() {
        let path = live_path_in(Path::new("/proc/self/ns"), "net").expect("own netns is live");
        assert_eq!(path, PathBuf::from("/proc/self/ns/net"));
    }

    // #184 — missing-namespace opens must classify via is_not_found(),
    // across every entry point that funnels through namespace_open_error.
    #[test]
    fn open_path_missing_is_not_found() {
        let path =
            std::env::temp_dir().join(format!("nlink-open-missing-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let err = open_path(&path).expect_err("missing path must fail");
        assert!(err.is_not_found(), "got unclassifiable error: {err}");
    }

    #[test]
    fn enter_path_missing_is_not_found() {
        let path =
            std::env::temp_dir().join(format!("nlink-enter-missing-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let err = enter_path(&path).expect_err("missing path must fail");
        assert!(err.is_not_found(), "got unclassifiable error: {err}");
    }

    #[test]
    fn connection_for_missing_name_is_not_found() {
        let Err(err) = Connection::<crate::Route>::new_in("definitely_does_not_exist_12345") else {
            panic!("missing namespace must fail");
        };
        assert!(err.is_not_found(), "got unclassifiable error: {err}");
    }

    #[test]
    fn is_namespace_path_true_for_own_net_ns() {
        // /proc/self/ns/net is a live nsfs inode in any process, so this pins
        // NSFS_MAGIC against the kernel's real value without needing root.
        assert!(is_namespace_path("/proc/self/ns/net"));
    }
}
