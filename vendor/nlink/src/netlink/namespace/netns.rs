//! An owned network namespace handle (#520).
//!
//! [`Netns`] owns an open fd to a namespace, so the namespace it names
//! cannot change under it: a namespace deleted and recreated under the same
//! name is a different one, with a different [`NetnsId`]. Everything that
//! needs "the namespace" — a connection, a socket, a closure run inside it —
//! derives from the fd, not from a name or pid looked up again.
//!
//! [`NetnsRef`] is the owned, serializable description of where a namespace
//! is (`Named`, `Path`, `Pid`, or the caller's own), for configs and state
//! files; [`NetnsRef::open`] turns it into a [`Netns`].

use std::{
    fmt,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    path::{Path, PathBuf},
    sync::Arc,
};

use super::{NamespaceMarker, NamespaceSpec, live_named_path, namespace_open_error};
use crate::netlink::{
    connection::Connection,
    error::{Error, Result},
    protocol::{
        AsyncProtocolInit, ProtocolState,
        construction::{AsyncConstructible, SyncConstructible},
    },
    socket::NetlinkSocket,
};

/// `NS_GET_NSTYPE` (`_IO(0xb7, 0x3)`, Linux 4.11): the `CLONE_NEW*` type of
/// the namespace an nsfs fd names.
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
/// `PIDFD_GET_NET_NAMESPACE` (`_IO(0xff, 4)`, Linux 6.11): an fd for the
/// network namespace of the process a pidfd names.
const PIDFD_GET_NET_NAMESPACE: libc::c_ulong = 0xff04;

/// A network namespace's identity: the device and inode of its nsfs file,
/// as `stat` reports them and as `readlink /proc/<pid>/ns/net` prints the
/// inode (`net:[4026531840]`).
///
/// Two handles to one namespace have the same id however they were opened;
/// a namespace deleted and recreated under the same name has a new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NetnsId {
    dev: u64,
    ino: u64,
}

impl NetnsId {
    /// An id from its parts, for tests that need two.
    #[cfg(test)]
    pub(crate) fn from_parts(dev: u64, ino: u64) -> Self {
        Self { dev, ino }
    }

    /// The id of the namespace `fd` names.
    pub fn of(fd: impl AsFd) -> Result<Self> {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat writes a `stat` into the buffer on success, and the
        // fd is borrowed for the call.
        let ret = unsafe { libc::fstat(fd.as_fd().as_raw_fd(), st.as_mut_ptr()) };
        if ret < 0 {
            return Err(Error::from(std::io::Error::last_os_error()));
        }
        // SAFETY: fstat returned 0, so the struct is initialized.
        let st = unsafe { st.assume_init() };
        Ok(Self {
            dev: st.st_dev,
            // PortHub: ino_t may be 32 bits on Linux 32-bit targets.
            ino: st.st_ino as u64,
        })
    }

    /// The nsfs device number.
    pub fn dev(&self) -> u64 {
        self.dev
    }

    /// The namespace's inode number, as `/proc/<pid>/ns/net` prints it.
    pub fn ino(&self) -> u64 {
        self.ino
    }
}

impl fmt::Display for NetnsId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "net:[{}]", self.ino)
    }
}

/// An open network namespace.
///
/// It owns an fd to the namespace, which keeps the namespace alive while
/// the handle exists, even if its name is deleted: interfaces in it live
/// on. Open one with [`open`](Self::open) (an `ip netns` name),
/// [`from_path`](Self::from_path), [`from_pid`](Self::from_pid),
/// [`from_pidfd`](Self::from_pidfd), [`current`](Self::current) or
/// [`init`](Self::init), or make one with [`create`](Self::create).
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// use nlink::netlink::namespace::Netns;
/// use nlink::{Connection, Route};
///
/// let ns = Netns::open("myns")?;
/// let conn = Connection::<Route>::new_in(&ns)?;
/// let links = conn.get_links().await?;
///
/// // Code that needs to be inside the namespace, on a thread of its own.
/// let net_dev = ns.run(|| std::fs::read_to_string("/proc/thread-self/net/dev"))??;
/// # let _ = (links, net_dev);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Netns {
    fd: OwnedFd,
    id: NetnsId,
    name: Option<Arc<str>>,
    label: Arc<str>,
    /// The marker it was opened through, when that was a name or a path
    /// outside `/proc`: whether the namespace is still there (#504).
    marker: Option<NamespaceMarker>,
    /// The thread that makes this namespace's sockets, started on first
    /// use and ended when the handle drops (#520).
    worker: std::sync::Mutex<Option<Worker>>,
}

/// A job for a namespace's worker thread.
type Job = Box<dyn FnOnce() + Send + 'static>;

/// A namespace's worker thread: its job queue, and the thread to join once
/// the queue is closed.
#[derive(Debug)]
struct Worker {
    jobs: Option<std::sync::mpsc::Sender<Job>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Closing the queue ends the thread, which leaves the namespace on
        // its way out. Joining it makes that part of dropping the handle: a
        // detached thread held the namespace for a moment after (#797).
        drop(self.jobs.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[nlink_macros::send_futures]
impl Netns {
    /// Open the namespace `ip netns` knows as `name` (`/var/run/netns/<name>`).
    ///
    /// # Errors
    ///
    /// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) (`is_not_found()`) when there is no
    /// live namespace by that name: no marker, or a stale marker with no
    /// mount behind it.
    pub fn open(name: &str) -> Result<Self> {
        let path = live_named_path(name)?;
        let mut ns = Self::open_nsfs(&path, name)?;
        ns.name = Some(Arc::from(name));
        Ok(ns)
    }

    /// Open the namespace at `path`: a bind-mounted marker, a
    /// `/proc/<pid>/ns/net`, or any other nsfs file of a network namespace.
    ///
    /// # Errors
    ///
    /// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound) when nothing is at `path`, and an
    /// invalid-argument error when it is not a network namespace.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        Self::open_nsfs(path, &path.display().to_string())
    }

    /// Open the network namespace of process `pid`.
    ///
    /// A pid can be reused once the process exits. If the process might be
    /// gone, open its namespace from a pidfd with
    /// [`from_pidfd`](Self::from_pidfd), which cannot be reused.
    pub fn from_pid(pid: u32) -> Result<Self> {
        Self::open_nsfs(
            Path::new(&format!("/proc/{pid}/ns/net")),
            &format!("pid {pid}"),
        )
    }

    /// Open the network namespace of the process `pidfd` names
    /// (`pidfd_open(2)`).
    ///
    /// Asks the pidfd itself (`PIDFD_GET_NET_NAMESPACE`, Linux 6.11). On an
    /// older kernel it reads the pid from `/proc/self/fdinfo`, opens that
    /// process's namespace, and then checks the pidfd still names a live
    /// process, so a reused pid cannot hand back someone else's namespace.
    pub fn from_pidfd(pidfd: impl AsFd) -> Result<Self> {
        let pidfd = pidfd.as_fd();
        // SAFETY: the ioctl takes no argument and returns a new fd or -1.
        let fd = unsafe { libc::ioctl(pidfd.as_raw_fd(), PIDFD_GET_NET_NAMESPACE as _, 0) };
        if fd >= 0 {
            // SAFETY: the kernel returned a fresh fd that nothing else owns.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            return Self::from_owned(fd, "pidfd".into(), None);
        }
        let err = std::io::Error::last_os_error();
        if !matches!(err.raw_os_error(), Some(libc::ENOTTY | libc::EINVAL)) {
            return Err(Error::from(err));
        }
        let pid = pidfd_pid(pidfd)?;
        let ns = Self::from_pid(pid)?;
        // SAFETY: signal 0 checks for existence and sends nothing.
        let alive = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if alive < 0 {
            return Err(Error::from(std::io::Error::last_os_error()));
        }
        Ok(ns)
    }

    /// The calling thread's network namespace.
    pub fn current() -> Result<Self> {
        Self::open_nsfs(Path::new("/proc/thread-self/ns/net"), "current")
    }

    /// The initial network namespace, the one PID 1 is in. Opening it needs
    /// the privilege to inspect PID 1 (root, or `CAP_SYS_PTRACE`).
    pub fn init() -> Result<Self> {
        Self::open_nsfs(Path::new("/proc/1/ns/net"), "init")
    }

    /// Create a namespace `ip netns` will know as `name`, and open it.
    ///
    /// See [`create`](super::create) for what is created and the errors.
    pub fn create(name: &str) -> Result<Self> {
        super::create(name)?;
        Self::open(name)
    }

    /// [`create`](Self::create) with an owner tag and stale marker
    /// reclaim (#522); see [`create_with`](super::create_with).
    pub fn create_with(name: &str, opts: super::CreateOptions) -> Result<Self> {
        super::create_with(name, opts)?;
        Self::open(name)
    }

    /// Delete this namespace's `ip netns` name, as `ip netns delete` does.
    ///
    /// Only a namespace opened or created by name has one. The name is
    /// deleted only while it still names *this* namespace; if it was
    /// deleted and recreated since, the call fails and the new one is left
    /// alone. The namespace itself goes once nothing holds it: no process,
    /// no socket, no other handle.
    pub fn delete(self) -> Result<()> {
        let Some(name) = self.name.clone() else {
            return Err(Error::invalid_message(format!(
                "namespace {}: only a namespace opened by name can be deleted",
                self.label
            )));
        };
        let now = Self::open(&name)?;
        if now.id != self.id {
            return Err(Error::invalid_message(format!(
                "namespace {name}: the name now names another namespace ({}, not {}); \
                 not deleting it",
                now.id, self.id
            )));
        }
        drop(now);
        drop(self);
        super::delete(&name)
    }

    /// `cmd`, to spawn in this namespace with the options of
    /// [`NetnsCommand`](super::NetnsCommand) (#521). An `/etc/netns`
    /// overlay needs a namespace opened by name.
    pub fn command(&self, cmd: std::process::Command) -> Result<super::NetnsCommand> {
        use std::os::fd::AsFd;
        let fd = self.as_fd().try_clone_to_owned().map_err(Error::from)?;
        Ok(super::NetnsCommand::with_fd(fd, self.name.as_deref().map(str::to_string), cmd))
    }

    /// The namespace's identity.
    pub fn id(&self) -> NetnsId {
        self.id
    }

    /// The `ip netns` name, when it was opened or created by one.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// What it was opened as, for messages: the name, the path, `pid 42`,
    /// `current`, `init` or `pidfd`.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Run `f` on a thread of its own inside the namespace, and return what
    /// it returns.
    ///
    /// The thread enters the namespace, runs `f` and exits, so there is
    /// nothing to switch back: the calling thread, and any runtime it
    /// belongs to, never leaves its namespace. `f` may borrow from the
    /// caller. Entering a namespace needs `CAP_SYS_ADMIN` over it; a thread
    /// already in it (the caller's own namespace) does not enter it again.
    ///
    /// # Errors
    ///
    /// An I/O error when the thread cannot be made or cannot enter the
    /// namespace, and an error when `f` panics.
    pub fn run<T: Send>(&self, f: impl FnOnce() -> T + Send) -> Result<T> {
        let fd = self.fd.as_fd();
        let target = self.id;
        std::thread::scope(|scope| {
            let worker = std::thread::Builder::new()
                .name("nlink-netns".into())
                .spawn_scoped(scope, move || -> Result<T> {
                    // A new thread starts in its creator's namespace, and
                    // setns refuses even that one without CAP_SYS_ADMIN.
                    let here = Netns::current().map(|n| n.id).ok();
                    if here == Some(target) {
                        return Ok(f());
                    }
                    // Leave before returning, panic or not (#797): see
                    // `ReturnHome`.
                    let _home = super::ReturnHome::new();
                    // SAFETY: setns switches only this thread.
                    if unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWNET) } < 0 {
                        return Err(Error::from(std::io::Error::last_os_error()));
                    }
                    Ok(f())
                })
                .map_err(Error::from)?;
            worker.join().unwrap_or_else(|_| {
                Err(Error::internal(format!(
                    "namespace {}: the closure panicked",
                    self.label
                )))
            })
        })
    }

    /// A socket in the namespace: `socket(domain, ty | SOCK_CLOEXEC,
    /// protocol)` made on a thread inside it. A socket stays in the
    /// namespace it was made in, so this is how to capture with `AF_PACKET`
    /// or connect over TCP from inside the namespace without a process
    /// there.
    ///
    /// ```no_run
    /// # fn example() -> nlink::Result<()> {
    /// use std::net::UdpSocket;
    /// use nlink::netlink::namespace::Netns;
    ///
    /// let ns = Netns::open("myns")?;
    /// let fd = ns.socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    /// let socket = UdpSocket::from(fd);
    /// socket.send_to(b"ping", "10.0.0.2:9")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn socket(&self, domain: i32, ty: i32, protocol: i32) -> Result<OwnedFd> {
        self.on_worker(move || {
            // SAFETY: socket(2) returns a fresh fd or -1.
            let fd = unsafe { libc::socket(domain, ty | libc::SOCK_CLOEXEC, protocol) };
            if fd < 0 {
                Err(Error::from(std::io::Error::last_os_error()))
            } else {
                // SAFETY: the fd was just made and nothing else owns it.
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        })?
    }

    /// A new netlink connection in the namespace.
    ///
    /// For the generic-netlink families that resolve their id
    /// asynchronously (WireGuard, ethtool, …), use
    /// [`connection_async`](Self::connection_async).
    ///
    /// The socket is made on the handle's worker thread, so a thousand
    /// connections cost one thread, not a thousand. A stream on it ends
    /// with [`ErrorDetail::NamespaceDeleted`](crate::ErrorDetail::NamespaceDeleted) once the namespace's name is
    /// deleted, as one opened by path does.
    pub(crate) fn connection<P: ProtocolState + Default + SyncConstructible>(
        &self,
    ) -> Result<Connection<P>> {
        Ok(Connection::from_parts(
            self.netlink_socket(P::PROTOCOL)?,
            P::default(),
        ))
    }

    /// A new connection to a generic-netlink family in the namespace, its
    /// family id resolved inside it.
    pub(crate) async fn connection_async<P: AsyncProtocolInit + AsyncConstructible>(
        &self,
    ) -> Result<Connection<P>> {
        let socket = self.netlink_socket(P::PROTOCOL)?;
        let state = P::resolve_async(&socket).await?;
        Ok(Connection::from_parts(socket, state))
    }

    /// Another handle to the same namespace, with its own fd.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            fd: self.fd.try_clone().map_err(Error::from)?,
            id: self.id,
            name: self.name.clone(),
            label: self.label.clone(),
            marker: self.marker.clone(),
            worker: std::sync::Mutex::new(None),
        })
    }

    /// A handle to the namespace an open nsfs fd names: one from
    /// `/proc/<pid>/ns/net`, `ioctl(SIOCGSKNS)`, a pidfd ioctl, or another
    /// process. It is refused unless it names a network namespace.
    pub fn from_fd(fd: OwnedFd) -> Result<Self> {
        Self::from_owned(fd, "fd".into(), None)
    }

    fn open_nsfs(path: &Path, label: &str) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(|e| namespace_open_error(path, e))?;
        let marker = NamespaceMarker::of(path, &file);
        let mut ns = Self::from_owned(OwnedFd::from(file), label.into(), None)?;
        ns.marker = marker;
        Ok(ns)
    }

    fn from_owned(fd: OwnedFd, label: Arc<str>, name: Option<Arc<str>>) -> Result<Self> {
        // SAFETY: the ioctl takes no argument; on an nsfs fd it returns the
        // namespace's CLONE_NEW* type.
        let ty = unsafe { libc::ioctl(fd.as_raw_fd(), NS_GET_NSTYPE as _, 0) };
        if ty < 0 {
            // Keep the errno: ENOTTY is "not nsfs", EBADF a closed fd (#718).
            return Err(Error::from(std::io::Error::last_os_error())
                .with_context(format!("{label}: not a namespace file")));
        }
        if ty != libc::CLONE_NEWNET {
            return Err(Error::invalid_message(format!(
                "{label}: not a network namespace"
            )));
        }
        let id = NetnsId::of(&fd)?;
        Ok(Self {
            fd,
            id,
            name,
            label,
            marker: None,
            worker: std::sync::Mutex::new(None),
        })
    }

    /// Run `f` on this namespace's worker thread, starting it on first use.
    ///
    /// One thread per handle makes all of its sockets, where
    /// `NetlinkSocket::new_in_namespace` spawns and joins one per socket
    /// (#520). The thread has left the namespace and ended by the time the
    /// handle's drop returns (#797).
    fn on_worker<T: Send + 'static>(&self, f: impl FnOnce() -> T + Send + 'static) -> Result<T> {
        let mut worker = self.worker.lock().unwrap_or_else(|e| e.into_inner());
        if worker.is_none() {
            *worker = Some(self.start_worker()?);
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let job: Job = Box::new(move || {
            let _ = tx.send(f());
        });
        let jobs = worker.as_ref().and_then(|w| w.jobs.as_ref());
        if jobs.is_some_and(|jobs| jobs.send(job).is_err()) {
            *worker = None;
            return Err(Error::internal(format!(
                "namespace {}: the worker thread has gone",
                self.label
            )));
        }
        drop(worker);
        rx.recv().map_err(|_| {
            Error::internal(format!("namespace {}: the job panicked", self.label))
        })
    }

    fn start_worker(&self) -> Result<Worker> {
        let fd = self.fd.try_clone().map_err(Error::from)?;
        let target = self.id;
        let (jobs, inbox) = std::sync::mpsc::channel::<Job>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<()>>();
        let thread = std::thread::Builder::new()
            .name("nlink-netns".into())
            .spawn(move || {
                let here = Netns::current().map(|n| n.id).ok();
                // Leave again once the queue closes, before the thread ends
                // (#797): see `ReturnHome`.
                let _home = (here != Some(target)).then(super::ReturnHome::new);
                // SAFETY: setns switches only this thread, which stays as
                // long as the handle's queue is open.
                if here != Some(target)
                    && unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWNET) } < 0
                {
                    let _ = ready_tx.send(Err(Error::from(std::io::Error::last_os_error())));
                    return;
                }
                drop(fd);
                let _ = ready_tx.send(Ok(()));
                while let Ok(job) = inbox.recv() {
                    // A panicking job must not take the thread with it.
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                }
            })
            .map_err(Error::from)?;
        let worker = Worker { jobs: Some(jobs), thread: Some(thread) };
        ready_rx.recv().map_err(|_| {
            Error::internal(format!("namespace {}: the worker thread died", self.label))
        })??;
        Ok(worker)
    }

    /// A netlink socket made in the namespace by its worker, carrying the
    /// namespace and its marker (#504, #520).
    fn netlink_socket(&self, protocol: crate::netlink::Protocol) -> Result<NetlinkSocket> {
        let (raw, pid) = self.on_worker(move || NetlinkSocket::create_raw_socket(protocol))??;
        let mut socket = NetlinkSocket::from_raw_socket(raw, pid, protocol)?;
        let fd = self.fd.try_clone().map_err(Error::from)?;
        socket.set_namespace(Arc::new(fd), self.marker.clone(), Some(self.label.clone()));
        Ok(socket)
    }

    /// Whether the namespace is still where it was opened: its name or
    /// marker still names it. A handle opened any other way (a pid, a
    /// pidfd, an fd) has nothing to check and answers `true`; the handle
    /// keeps the namespace itself alive regardless.
    pub fn is_live(&self) -> bool {
        self.marker.as_ref().is_none_or(NamespaceMarker::is_live)
    }

    /// The error for a namespace whose marker is gone.
    pub(crate) fn deleted(&self) -> Error {
        Error::from(crate::netlink::ErrorDetail::NamespaceDeleted {
            path: self
                .marker
                .as_ref()
                .map_or_else(|| PathBuf::from(&*self.label), |m| m.path().to_path_buf()),
        })
    }

    /// The namespace's sysctls (#520): `/proc/sys`, read and written on
    /// the handle's worker thread, inside the namespace.
    ///
    /// ```no_run
    /// # fn example() -> nlink::Result<()> {
    /// use nlink::netlink::namespace::Netns;
    ///
    /// let ns = Netns::open("lab-r1")?;
    /// ns.sysctl().set("net.ipv4.ip_forward", "1")?;
    /// assert_eq!(ns.sysctl().get("net.ipv4.ip_forward")?, "1");
    /// # Ok(())
    /// # }
    /// ```
    pub fn sysctl(&self) -> Sysctl<'_> {
        Sysctl { netns: self }
    }

    /// The processes with a thread in the namespace (#520), sorted: what
    /// keeps it alive besides sockets and handles. A thread that entered
    /// it counts, so this process is listed while a
    /// [`run`](Self::run) or a handle's worker thread is inside. Processes
    /// whose `/proc` entries the caller may not read are left out.
    pub fn pids(&self) -> Result<Vec<u32>> {
        pids_in(self.id)
    }

    /// Delete the namespace's name, as [`delete`](Self::delete) does, and
    /// wait until the kernel is destroying the namespace (#520), which
    /// tells a namespace that is going from one something still holds.
    ///
    /// The kernel destroys a namespace once nothing holds it — no process,
    /// no socket, no other handle — and asynchronously even then. This
    /// waits for the `RTM_DELNSID` it sends as the destruction begins, in
    /// the calling thread's namespace, giving the namespace an id there
    /// first if it has none. Past that point nothing can bring the
    /// namespace back; its interfaces go in the same kernel work, just
    /// after, so a veth's far end in another namespace can outlive the
    /// return by a moment.
    ///
    /// # Errors
    ///
    /// [`Error::timeout()`] (`is_timeout()`) when the namespace outlives
    /// `timeout`: something still holds it. [`pids`](Self::pids) names the
    /// processes, and the warning this logs lists them; a socket or handle
    /// of this process's — a [`Connection`] from
    /// [`Connection::new_in`] — holds it too. The errors of
    /// [`delete`](Self::delete) otherwise.
    pub async fn delete_and_wait(self, timeout: std::time::Duration) -> Result<()> {
        use tokio_stream::StreamExt;

        use crate::netlink::{NetworkEvent, Route, RtnetlinkGroup};

        let here = Connection::<Route>::new()?;
        let nsid = match here.get_nsid(&self.fd).await? {
            NSID_NOT_ASSIGNED => {
                here.set_nsid(&self.fd, -1).await?;
                here.get_nsid(&self.fd).await?
            }
            nsid => nsid,
        };
        here.subscribe(&[RtnetlinkGroup::NsId])?;
        let mut events = here.events().await;

        let (id, label) = (self.id, self.label.clone());
        self.delete()?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match tokio::time::timeout_at(deadline, events.next()).await {
                Ok(Some(Ok(NetworkEvent::DelNsId(m)))) if m.nsid() == Some(nsid) => return Ok(()),
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(e))) => return Err(e),
                Ok(None) => {
                    return Err(Error::internal(format!(
                        "namespace {label}: the nsid event stream ended"
                    )));
                }
                Err(_) => {
                    tracing::warn!(
                        namespace = %label,
                        ?timeout,
                        pids = ?pids_in(id).unwrap_or_default(),
                        "namespace deleted but not destroyed: something still holds it"
                    );
                    return Err(Error::timeout());
                }
            }
        }
    }
}

/// `NETNSA_NSID_NOT_ASSIGNED` (-1), as `get_nsid` reads it.
const NSID_NOT_ASSIGNED: u32 = u32::MAX;

/// The processes with a thread in namespace `id`.
fn pids_in(id: NetnsId) -> Result<Vec<u32>> {
    use std::os::unix::fs::MetadataExt;

    let in_ns = |path: PathBuf| {
        std::fs::metadata(path).is_ok_and(|m| m.dev() == id.dev && m.ino() == id.ino)
    };
    let mut pids = Vec::new();
    for entry in std::fs::read_dir("/proc").map_err(Error::from)?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let tasks = std::fs::read_dir(entry.path().join("task"));
        if tasks
            .into_iter()
            .flatten()
            .flatten()
            .any(|task| in_ns(task.path().join("ns/net")))
        {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    Ok(pids)
}

/// A namespace's sysctls, from [`Netns::sysctl`]. Keys are dotted
/// (`net.ipv4.ip_forward`) or slashed, as in
/// [`sysctl::get`](crate::netlink::sysctl::get); every error names the key.
#[derive(Debug, Clone, Copy)]
pub struct Sysctl<'a> {
    netns: &'a Netns,
}

impl Sysctl<'_> {
    /// Read `key`.
    pub fn get(&self, key: &str) -> Result<String> {
        let key = key.to_string();
        self.netns.on_worker(move || crate::netlink::sysctl::get(&key))?
    }

    /// Write `value` to `key`. Needs `CAP_NET_ADMIN` over the namespace.
    pub fn set(&self, key: &str, value: &str) -> Result<()> {
        let (key, value) = (key.to_string(), value.to_string());
        self.netns.on_worker(move || crate::netlink::sysctl::set(&key, &value))?
    }

    /// Write each `(key, value)` in order, stopping at the first error.
    pub fn set_many(&self, entries: &[(&str, &str)]) -> Result<()> {
        let entries: Vec<(String, String)> = entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        self.netns.on_worker(move || {
            entries
                .iter()
                .try_for_each(|(k, v)| crate::netlink::sysctl::set(k, v))
        })?
    }
}

impl AsFd for Netns {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Two handles are equal when they name the same namespace.
impl PartialEq for Netns {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Netns {}

impl std::hash::Hash for Netns {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl fmt::Display for Netns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.label, self.id)
    }
}

/// The pid a pidfd names, from its `/proc/self/fdinfo` entry.
fn pidfd_pid(pidfd: BorrowedFd<'_>) -> Result<u32> {
    let path = format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd());
    let info = std::fs::read_to_string(&path).map_err(Error::from)?;
    let pid = info
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .map(str::trim)
        .and_then(|p| p.parse::<i64>().ok());
    match pid {
        Some(p) if p > 0 => Ok(p as u32),
        // -1: the process has exited (and been reaped).
        Some(_) => Err(Error::from(std::io::Error::from_raw_os_error(libc::ESRCH))),
        None => Err(Error::invalid_message(format!("{path}: not a pidfd"))),
    }
}

/// Where a network namespace is, as configs and state files say it.
///
/// Owned, `Clone + Eq + Hash`, and with the `serde` feature serializable:
/// `"default"`, `{"named": "red"}`, `{"path": "/proc/42/ns/net"}`,
/// `{"pid": 42}`. [`open`](Self::open) gives the [`Netns`] it describes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum NetnsRef {
    /// The namespace of whoever opens it.
    #[default]
    Default,
    /// A namespace `ip netns` knows by this name.
    Named(String),
    /// The namespace at this nsfs path.
    Path(PathBuf),
    /// The namespace of this process.
    Pid(u32),
}

impl NetnsRef {
    /// Open the namespace this describes. `Default` is the calling thread's
    /// namespace.
    pub fn open(&self) -> Result<Netns> {
        match self {
            Self::Default => Netns::current(),
            Self::Named(name) => Netns::open(name),
            Self::Path(path) => Netns::from_path(path),
            Self::Pid(pid) => Netns::from_pid(*pid),
        }
    }

    /// `true` for [`NetnsRef::Default`].
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Default)
    }
}

impl fmt::Display for NetnsRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => f.write_str("default"),
            Self::Named(name) => f.write_str(name),
            Self::Path(path) => write!(f, "{}", path.display()),
            Self::Pid(pid) => write!(f, "pid {pid}"),
        }
    }
}

/// The namespace an entry point works in (#532): what
/// [`Connection::new_in`], the facade's `*_in` functions and
/// [`ConnectionPoolBuilder::namespace`](crate::netlink::pool::ConnectionPoolBuilder::namespace)
/// take, as `impl Into<NetnsTarget>`.
///
/// It is an open [`Netns`], or where one is: a [`NetnsRef`], an `ip netns`
/// name, a path, a [`NamespaceSpec`], or a borrowed namespace fd.
///
/// ```no_run
/// # fn example(fd: std::os::fd::BorrowedFd<'_>) -> nlink::Result<()> {
/// use nlink::netlink::namespace::{Netns, NetnsRef};
/// use nlink::netlink::{Connection, Route};
///
/// let by_name = Connection::<Route>::new_in("red")?;
/// let red = Netns::open("red")?;
/// let by_handle = Connection::<Route>::new_in(&red)?;
/// let by_pid = Connection::<Route>::new_in(NetnsRef::Pid(1234))?;
/// let by_fd = Connection::<Route>::new_in(fd)?;
/// let here = Connection::<Route>::new_in(NetnsRef::Default)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum NetnsTarget<'a> {
    /// A namespace already open. Its connections are made on its worker
    /// thread.
    Netns(&'a Netns),
    /// Where a namespace is. It is opened when used.
    Ref(NetnsRef),
    /// A namespace fd, `/var/run/netns/<name>` or `/proc/<pid>/ns/net`
    /// opened. It is duplicated when used.
    Fd(BorrowedFd<'a>),
}

impl NetnsTarget<'_> {
    /// `true` for [`NetnsRef::Default`]: the calling thread's namespace,
    /// which needs nothing opened.
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Ref(r) if r.is_default())
    }

    /// Open it, as a handle of its own: `None` for the default namespace.
    pub fn open(&self) -> Result<Option<Netns>> {
        match self {
            Self::Netns(netns) => netns.try_clone().map(Some),
            Self::Ref(r) if r.is_default() => Ok(None),
            Self::Ref(r) => r.open().map(Some),
            Self::Fd(fd) => Netns::from_fd(fd.try_clone_to_owned().map_err(Error::from)?).map(Some),
        }
    }

    /// A connection in it.
    pub(crate) fn connection<P: ProtocolState + Default + SyncConstructible>(
        &self,
    ) -> Result<Connection<P>> {
        match self {
            Self::Netns(netns) => netns.connection(),
            _ => match self.open()? {
                Some(netns) => netns.connection(),
                None => Connection::<P>::new(),
            },
        }
    }

    /// A generic-netlink connection in it, its family resolved there.
    pub(crate) async fn connection_async<P: AsyncProtocolInit + AsyncConstructible>(
        &self,
    ) -> Result<Connection<P>> {
        match self {
            Self::Netns(netns) => netns.connection_async().await,
            _ => match self.open()? {
                Some(netns) => netns.connection_async().await,
                None => Connection::<P>::new_async().await,
            },
        }
    }
}

impl fmt::Display for NetnsTarget<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Netns(netns) => f.write_str(netns.label()),
            Self::Ref(r) => r.fmt(f),
            Self::Fd(fd) => write!(f, "fd {}", fd.as_raw_fd()),
        }
    }
}

impl<'a> From<&'a Netns> for NetnsTarget<'a> {
    fn from(netns: &'a Netns) -> Self {
        Self::Netns(netns)
    }
}

impl From<NetnsRef> for NetnsTarget<'_> {
    fn from(r: NetnsRef) -> Self {
        Self::Ref(r)
    }
}

impl From<&NetnsRef> for NetnsTarget<'_> {
    fn from(r: &NetnsRef) -> Self {
        Self::Ref(r.clone())
    }
}

/// An `ip netns` name.
impl From<&str> for NetnsTarget<'_> {
    fn from(name: &str) -> Self {
        Self::Ref(NetnsRef::Named(name.to_string()))
    }
}

/// An `ip netns` name.
impl From<String> for NetnsTarget<'_> {
    fn from(name: String) -> Self {
        Self::Ref(NetnsRef::Named(name))
    }
}

/// An `ip netns` name.
impl From<&String> for NetnsTarget<'_> {
    fn from(name: &String) -> Self {
        Self::Ref(NetnsRef::Named(name.clone()))
    }
}

/// An nsfs path.
impl From<&Path> for NetnsTarget<'_> {
    fn from(path: &Path) -> Self {
        Self::Ref(NetnsRef::Path(path.to_path_buf()))
    }
}

/// An nsfs path.
impl From<PathBuf> for NetnsTarget<'_> {
    fn from(path: PathBuf) -> Self {
        Self::Ref(NetnsRef::Path(path))
    }
}

impl From<NamespaceSpec<'_>> for NetnsTarget<'_> {
    fn from(spec: NamespaceSpec<'_>) -> Self {
        Self::Ref(spec.into())
    }
}

impl From<&NamespaceSpec<'_>> for NetnsTarget<'_> {
    fn from(spec: &NamespaceSpec<'_>) -> Self {
        Self::Ref(spec.into())
    }
}

impl<'a> From<BorrowedFd<'a>> for NetnsTarget<'a> {
    fn from(fd: BorrowedFd<'a>) -> Self {
        Self::Fd(fd)
    }
}

impl From<&NamespaceSpec<'_>> for NetnsRef {
    fn from(spec: &NamespaceSpec<'_>) -> Self {
        match spec {
            NamespaceSpec::Default => Self::Default,
            NamespaceSpec::Named(name) => Self::Named((*name).to_string()),
            NamespaceSpec::Path(path) => Self::Path(path.to_path_buf()),
            NamespaceSpec::Pid(pid) => Self::Pid(*pid),
        }
    }
}

impl From<NamespaceSpec<'_>> for NetnsRef {
    fn from(spec: NamespaceSpec<'_>) -> Self {
        Self::from(&spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One namespace, opened two ways, has one id; a thread inside it sees
    /// the same one. None of this needs privileges.
    #[test]
    fn the_same_namespace_has_the_same_id_however_it_is_opened() {
        let current = Netns::current().unwrap();
        let by_path = Netns::from_path("/proc/self/ns/net").unwrap();
        assert_eq!(current.id(), by_path.id());
        assert_eq!(current, by_path);
        let seen = current
            .run(|| Netns::current().map(|n| n.id()))
            .unwrap()
            .unwrap();
        assert_eq!(seen, current.id());
        assert!(
            current.to_string().starts_with("current (net:["),
            "{current}"
        );
    }

    /// `run` can borrow from the caller.
    #[test]
    fn run_borrows() {
        let ns = Netns::current().unwrap();
        let words = ["a", "b"];
        let n = ns.run(|| words.len()).unwrap();
        assert_eq!(n, 2);
    }

    /// A file that is not a namespace, or a namespace that is not a
    /// network one, is refused.
    #[test]
    fn only_a_network_namespace_opens() {
        let err = Netns::from_path("/proc/self/status").unwrap_err();
        assert!(err.to_string().contains("not a namespace file"), "{err}");
        // The ioctl's errno survives (#718).
        assert_eq!(err.errno(), Some(libc::ENOTTY), "{err:?}");
        let err = Netns::from_path("/proc/self/ns/uts").unwrap_err();
        assert!(err.to_string().contains("not a network namespace"), "{err}");
        let err = Netns::from_path("/nonexistent/ns").unwrap_err();
        assert!(err.is_not_found(), "{err}");
    }

    /// A pidfd of this process opens this namespace, on any kernel.
    #[test]
    fn a_pidfd_opens_its_process_namespace() {
        // SAFETY: pidfd_open returns a fresh fd or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
        if fd < 0 {
            // Kernels before 5.3 have no pidfds.
            return;
        }
        // SAFETY: the fd was just made and nothing else owns it.
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let ns = Netns::from_pidfd(&pidfd).unwrap();
        assert_eq!(ns.id(), Netns::current().unwrap().id());
        assert_eq!(pidfd_pid(pidfd.as_fd()).unwrap(), std::process::id());
    }

    /// The worker makes sockets in the handle's namespace; in the caller's
    /// own it needs no privilege (#520).
    #[test]
    fn the_worker_makes_sockets_and_survives_a_panic() {
        let ns = Netns::current().unwrap();
        for _ in 0..3 {
            let fd = ns.socket(libc::AF_INET, libc::SOCK_DGRAM, 0).unwrap();
            assert!(fd.as_raw_fd() >= 0);
        }
        let err = ns.on_worker(|| panic!("boom")).unwrap_err();
        assert!(err.to_string().contains("panicked"), "{err}");
        assert!(ns.socket(libc::AF_INET, libc::SOCK_DGRAM, 0).is_ok());
    }

    /// A connection made with `new()` is in the caller's namespace.
    #[tokio::test]
    async fn a_plain_connection_knows_its_namespace() {
        let conn = Connection::<crate::netlink::Route>::new().unwrap();
        assert_eq!(conn.netns().unwrap().id(), Netns::current().unwrap().id());
        let nft = conn.sibling::<crate::netlink::Nftables>().unwrap();
        assert_eq!(nft.netns().unwrap().id(), Netns::current().unwrap().id());
    }

    #[test]
    fn netns_ref_displays_and_opens_default() {
        assert_eq!(NetnsRef::Named("red".into()).to_string(), "red");
        assert_eq!(NetnsRef::Pid(7).to_string(), "pid 7");
        assert_eq!(NetnsRef::default().to_string(), "default");
        let spec = NamespaceSpec::Named("red");
        assert_eq!(NetnsRef::from(&spec), NetnsRef::Named("red".into()));
        let here = NetnsRef::Default.open().unwrap();
        assert_eq!(here.id(), Netns::current().unwrap().id());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn netns_ref_serde_shape() {
        let refs = [
            NetnsRef::Default,
            NetnsRef::Named("red".into()),
            NetnsRef::Path("/proc/42/ns/net".into()),
            NetnsRef::Pid(42),
        ];
        let json = serde_json::to_string(&refs).unwrap();
        assert_eq!(
            json,
            r#"["default",{"named":"red"},{"path":"/proc/42/ns/net"},{"pid":42}]"#
        );
        let back: Vec<NetnsRef> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, refs);
    }
}
