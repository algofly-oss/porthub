//! Low-level async netlink socket operations.

use std::{
    fs::File,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::io::{AsRawFd, RawFd},
    },
    path::Path,
    sync::atomic::{AtomicU32, Ordering},
    task::{Context, Poll},
};

use bytes::BytesMut;
use netlink_sys::{Socket, SocketAddr, protocols};
use tokio::io::{Interest, unix::AsyncFd};

use super::{
    dispatcher::Dispatcher,
    error::{Error, Result},
};

/// Netlink protocol families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Protocol {
    /// Routing/device hook (ip, tc, etc.)
    Route,
    /// Generic netlink
    Generic,
    /// Socket diagnostics (ss-like queries)
    SockDiag,
    /// Netfilter
    Netfilter,
    /// Kernel connector
    Connector,
    /// Kobject uevent
    KobjectUevent,
    /// XFRM (IPsec)
    Xfrm,
    /// SELinux event notifications
    SELinux,
    /// Linux Audit
    Audit,
    /// FIB lookup
    FibLookup,
}

/// NETLINK_XFRM protocol number (6).
const NETLINK_XFRM: isize = 6;

/// NETLINK_SELINUX protocol number (7).
const NETLINK_SELINUX: isize = 7;

/// NETLINK_AUDIT protocol number (9).
const NETLINK_AUDIT: isize = 9;

/// NETLINK_FIB_LOOKUP protocol number (10).
const NETLINK_FIB_LOOKUP: isize = 10;

impl Protocol {
    fn as_isize(self) -> isize {
        match self {
            Protocol::Route => protocols::NETLINK_ROUTE,
            Protocol::Generic => protocols::NETLINK_GENERIC,
            Protocol::SockDiag => protocols::NETLINK_SOCK_DIAG,
            Protocol::Netfilter => protocols::NETLINK_NETFILTER,
            Protocol::Connector => protocols::NETLINK_CONNECTOR,
            Protocol::KobjectUevent => protocols::NETLINK_KOBJECT_UEVENT,
            Protocol::Xfrm => NETLINK_XFRM,
            Protocol::SELinux => NETLINK_SELINUX,
            Protocol::Audit => NETLINK_AUDIT,
            Protocol::FibLookup => NETLINK_FIB_LOOKUP,
        }
    }
}

/// Async netlink socket.
pub struct NetlinkSocket {
    /// The underlying async file descriptor.
    fd: AsyncFd<Socket>,
    /// Sequence number counter.
    seq: AtomicU32,
    /// Local port ID (assigned by kernel).
    pid: u32,
    /// Protocol this socket uses.
    protocol: Protocol,
    /// Plan 234 (0.21.0) — optional Dispatcher hook. When the recv
    /// path detects ENOBUFS, it calls `dispatcher.emit_enobufs()`
    /// to fan `ResyncMarker::ResyncStart` out to every active
    /// multicast subscriber. Set by `Connection::new()` via
    /// [`Self::install_dispatcher`]; absent for sockets constructed
    /// directly (the standalone `NetlinkSocket::new` path used by
    /// integration tests and macro-emitted family-resolution code
    /// — those don't have multicast subscribers anyway).
    ///
    /// Atomic load/store via `OnceLock` so the read path on `recv_msg`
    /// is a single relaxed load.
    dispatcher: std::sync::OnceLock<Dispatcher>,
    /// #504 — the marker this socket's namespace was opened through, if
    /// it was opened through one. Event streams watch it so they can end
    /// when the namespace is deleted instead of keeping it alive, silent.
    namespace_marker: Option<super::namespace::NamespaceMarker>,
    /// #520 — the namespace this socket was made in, when it was made in
    /// one by fd, path or `Netns`: `Connection::netns` and `sibling` read
    /// it. `None` for a socket made in its creating thread's namespace.
    netns: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
    /// #718 — what that namespace was opened as (`Netns::label`), which
    /// every error from this socket carries: see [`Self::stamp`].
    netns_label: Option<std::sync::Arc<str>>,
    /// #168 — a recording of this socket's traffic, or one it answers
    /// from instead of the kernel.
    #[cfg(feature = "replay")]
    hook: Option<crate::replay::Hook>,
}

#[nlink_macros::send_futures]
impl NetlinkSocket {
    /// Create a new netlink socket for the given protocol.
    pub fn new(protocol: Protocol) -> Result<Self> {
        Self::create_socket(protocol)
    }

    /// Create a netlink socket that operates in a specific network namespace.
    ///
    /// The namespace is specified by an open file descriptor to a namespace file
    /// (e.g., `/proc/<pid>/ns/net` or `/var/run/netns/<name>`).
    ///
    /// The socket is created inside the target namespace and operates there for
    /// all subsequent operations; the calling thread's namespace is untouched.
    ///
    /// # Thread discipline (#185)
    ///
    /// The netns-sensitive part — `setns()` + `socket(2)` — runs on a dedicated
    /// worker thread that **exits instead of restoring**: a thread's namespace
    /// membership dies with it, so there is no restore step that can fail and
    /// no window in which the calling thread (possibly a tokio worker shared
    /// with unrelated tasks) observes the target namespace. A panic during
    /// socket creation kills the worker, not the caller's netns state. The
    /// pre-#185 implementation `setns`'d the calling thread and could fail to
    /// restore it; the error that reported that is gone since 0.32.0 (#532).
    ///
    /// The tokio reactor registration (`AsyncFd`) happens afterwards on the
    /// calling thread — epoll registration is not namespace-sensitive, and the
    /// caller is where a runtime context is guaranteed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use std::fs::File;
    ///
    /// use nlink::netlink::{NetlinkSocket, Protocol};
    ///
    /// let ns_file = File::open("/var/run/netns/myns")?;
    /// let socket = NetlinkSocket::new_in_namespace(Protocol::Route, &ns_file)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_in_namespace(protocol: Protocol, ns_fd: impl AsFd) -> Result<Self> {
        // `ns_fd` stays valid for the worker's lifetime: fds are process-wide
        // and the caller's borrow outlives the synchronous join() below.
        let ns_fd = ns_fd.as_fd().as_raw_fd();
        // `thread::spawn` panics when no thread can be made (`pids.max`,
        // `RLIMIT_NPROC`); this returns `Result` (#510).
        let worker = std::thread::Builder::new().name("nlink-netns".into());
        let thread_result = worker
            .spawn(move || -> Result<(Socket, u32)> {
                let _home = crate::netlink::namespace::ReturnHome::new();
                // SAFETY: libc::setns switches this worker thread to the namespace
                // specified by ns_fd, a valid namespace-file descriptor. Only this
                // freshly-spawned thread is affected, and it leaves again before
                // it returns (#797).
                let ret = unsafe { libc::setns(ns_fd, libc::CLONE_NEWNET) };
                if ret < 0 {
                    return Err(Error::from(std::io::Error::last_os_error()));
                }
                Self::create_raw_socket(protocol)
            })
            .map_err(Error::from)?
            .join();

        match thread_result {
            Ok(Ok((socket, pid))) => {
                let mut socket = Self::from_raw_socket(socket, pid, protocol)?;
                // SAFETY: `ns_fd` is open for the caller, and F_DUPFD_CLOEXEC
                // returns a new fd or -1.
                let dup = unsafe { libc::fcntl(ns_fd, libc::F_DUPFD_CLOEXEC, 0) };
                if dup >= 0 {
                    use std::os::fd::FromRawFd;
                    // SAFETY: the duplicate is ours alone.
                    socket.netns = Some(std::sync::Arc::new(unsafe {
                        std::os::fd::OwnedFd::from_raw_fd(dup)
                    }));
                }
                Ok(socket)
            }
            Ok(Err(e)) => Err(e),
            Err(_panic) => Err(Error::internal("namespace socket worker thread panicked")),
        }
    }

    /// [`new_in_namespace`](Self::new_in_namespace), which takes `AsFd`
    /// itself now (#532).
    #[deprecated(since = "0.32.0", note = "`new_in_namespace` takes `impl AsFd` now (#532)")]
    pub fn new_in_namespace_fd(protocol: Protocol, ns_fd: impl AsFd) -> Result<Self> {
        Self::new_in_namespace(protocol, ns_fd)
    }

    /// Create a netlink socket that operates in a network namespace specified by path.
    ///
    /// This is a convenience method that opens the namespace file and calls
    /// [`new_in_namespace`](Self::new_in_namespace).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{NetlinkSocket, Protocol};
    ///
    /// // For a named namespace
    /// let socket = NetlinkSocket::new_in_namespace_path(
    ///     Protocol::Route,
    ///     "/var/run/netns/myns"
    /// )?;
    ///
    /// // For a process namespace
    /// let socket = NetlinkSocket::new_in_namespace_path(
    ///     Protocol::Route,
    ///     "/proc/1234/ns/net"
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_in_namespace_path<P: AsRef<Path>>(protocol: Protocol, ns_path: P) -> Result<Self> {
        // #184: ENOENT → a namespace not-found error (is_not_found()), other
        // errors keep their errno — never a stringly InvalidMessage.
        let ns_file = File::open(ns_path.as_ref())
            .map_err(|e| super::namespace::namespace_open_error(ns_path.as_ref(), e))?;
        let mut socket = Self::new_in_namespace(protocol, &ns_file)?;
        socket.namespace_marker = super::namespace::NamespaceMarker::of(ns_path.as_ref(), &ns_file);
        Ok(socket)
    }

    /// A file descriptor for the network namespace this socket lives in
    /// (`ioctl(SIOCGSKNS)`, Linux 4.9). The kernel wants `CAP_NET_ADMIN`
    /// over that namespace (#497).
    pub(crate) fn netns_fd(&self) -> std::io::Result<std::os::fd::OwnedFd> {
        use std::os::fd::FromRawFd;
        // linux/sockios.h; not in the libc crate.
        const SIOCGSKNS: libc::c_ulong = 0x894C;
        // SAFETY: SIOCGSKNS takes no argument and returns a new fd or -1.
        let fd = unsafe { libc::ioctl(self.as_raw_fd(), SIOCGSKNS as _) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the kernel just handed us this fd; nothing else owns it.
        Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
    }

    /// The cookie of the network namespace this socket lives in
    /// (`SO_NETNS_COOKIE`, Linux 5.14): equal cookies, same namespace.
    /// Needs no privilege.
    pub(crate) fn netns_cookie(&self) -> std::io::Result<u64> {
        // asm-generic/socket.h; not in every libc crate release.
        const SO_NETNS_COOKIE: libc::c_int = 71;
        let mut cookie = 0u64;
        let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
        // SAFETY: a u64 out-parameter of the size we pass.
        let rc = unsafe {
            libc::getsockopt(
                self.as_raw_fd(),
                libc::SOL_SOCKET,
                SO_NETNS_COOKIE,
                (&raw mut cookie).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(cookie)
    }

    /// The marker this socket's namespace was opened through (#504).
    pub(crate) fn namespace_marker(&self) -> Option<&super::namespace::NamespaceMarker> {
        self.namespace_marker.as_ref()
    }

    /// Internal helper to create the socket.
    fn create_socket(protocol: Protocol) -> Result<Self> {
        let (socket, pid) = Self::create_raw_socket(protocol)?;
        Self::from_raw_socket(socket, pid, protocol)
    }

    /// Create and bind the raw netlink socket. This is the namespace-sensitive
    /// half of construction — `socket(2)` binds the socket to the calling
    /// thread's netns at creation time — and is runtime-independent, so
    /// `new_in_namespace` can run it on a dedicated worker thread (#185).
    pub(crate) fn create_raw_socket(protocol: Protocol) -> Result<(Socket, u32)> {
        let mut socket = Socket::new(protocol.as_isize())?;
        socket.set_non_blocking(true)?;

        // Bind to get a port ID
        let mut addr = SocketAddr::new(0, 0);
        socket.bind(&addr)?;
        socket.get_address(&mut addr)?;
        let pid = addr.port_number();

        // Enable extended ACK for better error messages…
        socket.set_ext_ack(true).ok(); // Ignore if not supported
        // …and cap the echoed request, which is what makes them
        // readable. See `set_cap_ack`.
        socket.set_cap_ack(true).ok(); // Ignore if not supported

        Ok((socket, pid))
    }

    /// Wrap a raw bound socket into the async `NetlinkSocket`. Must run on a
    /// thread with a tokio runtime context (`AsyncFd::new` registers with the
    /// reactor); the socket's netns membership is already fixed, so this half
    /// is namespace-insensitive.
    pub(crate) fn from_raw_socket(socket: Socket, pid: u32, protocol: Protocol) -> Result<Self> {
        // `AsyncFd::new` panics outside a tokio runtime, which `Connection::
        // new()` and `connection_for()` reached while promising a `Result`
        // (#510).
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(Error::from(std::io::Error::other(
                "nlink: a netlink socket needs a tokio runtime; create it inside one",
            )));
        }
        let fd = AsyncFd::new(socket)?;

        Ok(Self {
            fd,
            seq: AtomicU32::new(1),
            pid,
            protocol,
            dispatcher: std::sync::OnceLock::new(),
            namespace_marker: None,
            netns: None,
            netns_label: None,
            #[cfg(feature = "replay")]
            hook: None,
        })
    }

    /// Record this socket's traffic, or answer from a recording (#168).
    #[cfg(feature = "replay")]
    pub(crate) fn with_hook(mut self, hook: crate::replay::Hook) -> Self {
        self.hook = Some(hook);
        self
    }

    /// The recording this socket answers from, if it does.
    #[cfg(feature = "replay")]
    fn replaying(&self) -> Option<&crate::replay::Replay> {
        self.hook.as_ref().and_then(crate::replay::Hook::as_replay)
    }

    /// Note a datagram that went out, for a recording.
    #[inline]
    fn sent(&self, _msg: &[u8]) {
        #[cfg(feature = "replay")]
        if let Some(hook) = &self.hook {
            hook.after_send(_msg);
        }
    }

    /// Note a datagram that came in, for a recording.
    #[inline]
    fn received(&self, _data: &[u8], _multicast: bool) {
        #[cfg(feature = "replay")]
        if let Some(hook) = &self.hook {
            hook.after_recv(_data, _multicast);
        }
    }

    /// Record the namespace a socket was made in, the marker its streams
    /// watch, and the label its errors carry (#504, #520, #718).
    pub(crate) fn set_namespace(
        &mut self,
        netns: std::sync::Arc<std::os::fd::OwnedFd>,
        marker: Option<super::namespace::NamespaceMarker>,
        label: Option<std::sync::Arc<str>>,
    ) {
        self.netns = Some(netns);
        self.namespace_marker = marker;
        self.netns_label = label;
    }

    /// The label of the namespace this socket was made in, if it was made
    /// through a [`Netns`](super::namespace::Netns) (#718).
    pub(crate) fn netns_label(&self) -> Option<&std::sync::Arc<str>> {
        self.netns_label.as_ref()
    }

    /// Note on an error where it came from: this socket's protocol, for a
    /// kernel refusal (#722), and its namespace (#718). Neither overwrites
    /// what the error already says. The socket stamps what it sends and
    /// receives itself; `Connection::with_timeout`, the request primitives
    /// and the streams stamp what leaves them, kernel refusals included.
    pub(crate) fn stamp(&self, e: Error) -> Error {
        let e = e.in_protocol(self.protocol);
        match &self.netns_label {
            Some(label) => e.in_netns(label),
            None => e,
        }
    }

    /// The namespace this socket was made in, when it was made in one by
    /// fd, path or `Netns` (#520).
    pub(crate) fn origin_netns(&self) -> Option<&std::sync::Arc<std::os::fd::OwnedFd>> {
        self.netns.as_ref()
    }

    /// Plan 234 — install the per-Connection
    /// [`Dispatcher`] hook on this socket. Called once by
    /// `Connection::new()` / `from_parts()`; the recv path then
    /// fans ENOBUFS into the dispatcher's broadcast channels via
    /// `dispatcher.emit_enobufs()`.
    ///
    /// No-op if already installed (subsequent calls are silently
    /// ignored by `OnceLock::set`). The contract is "set once per
    /// socket, at Connection construction time."
    pub fn install_dispatcher(&self, dispatcher: Dispatcher) {
        let _ = self.dispatcher.set(dispatcher);
    }

    /// Plan 234 — internal helper. If a Dispatcher is installed,
    /// forward an ENOBUFS event to every active subscriber.
    /// Called from the recv error paths.
    fn fan_out_enobufs(&self) {
        if let Some(d) = self.dispatcher.get() {
            d.emit_enobufs();
        }
    }

    /// Plan 234 — test-only synthetic ENOBUFS injection so the
    /// dispatcher path can be exercised without a real overflowing
    /// kernel queue. Hidden from the public surface; only the
    /// integration tests under `crates/nlink/tests/` call this.
    #[cfg(any(test, feature = "lab"))]
    pub fn synth_enobufs_for_test(&self) {
        self.fan_out_enobufs();
    }

    /// Plan 234 — accessor for tests that need to confirm the
    /// dispatcher is wired up. Returns `None` if `install_dispatcher`
    /// was never called.
    #[cfg(any(test, feature = "lab"))]
    pub fn dispatcher_for_test(&self) -> Option<&Dispatcher> {
        self.dispatcher.get()
    }

    /// Get the next sequence number.
    ///
    /// **Skips 0** (#134): the dispatcher treats `nlmsg_seq == 0` as the
    /// multicast-notification marker and fans those frames out to event
    /// subscribers. A unicast request that wrapped to seq 0 would be
    /// misrouted, so the counter never hands out 0 (after `u32::MAX` it
    /// resumes at 1).
    pub fn next_seq(&self) -> u32 {
        next_nonzero_seq(&self.seq)
    }

    /// Get the local port ID.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Get the protocol.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Toggle extended-ack reception (`NETLINK_EXT_ACK`, kernel
    /// 4.12+). Enabled by default during socket construction;
    /// rarely useful to disable. Exposed for parity with neli and
    /// for callers that want to suppress the trailing TLVs in
    /// error responses (e.g. for tighter timing-sensitive
    /// measurements).
    ///
    /// Returns `Ok(())` on pre-4.12 kernels where the sockopt is
    /// not supported (`ENOPROTOOPT`) — graceful degradation.
    pub fn set_ext_ack(&self, on: bool) -> Result<()> {
        Self::set_netlink_sockopt(self.as_raw_fd(), libc::NETLINK_EXT_ACK, on)
    }

    /// `NETLINK_CAP_ACK` value from `linux/netlink.h`. Not in `libc`.
    const NETLINK_CAP_ACK: libc::c_int = 10;

    /// Ask the kernel to omit the echoed request from ACK and error
    /// responses (`NETLINK_CAP_ACK`, kernel 4.3+). **Enabled by default
    /// during socket construction**, and switching it off breaks
    /// extended-ack parsing.
    ///
    /// `netlink_ack()` decides the payload layout on this flag:
    ///
    /// ```c
    /// if (err && !(nlk->flags & NETLINK_F_CAP_ACK))
    ///         payload += nlmsg_len(nlh);   /* echo the WHOLE request */
    /// else
    ///         flags |= NLM_F_CAPPED;
    /// ```
    ///
    /// so uncapped, the extended-ack TLVs sit after a copy of the entire
    /// request rather than at a fixed offset. `NlMsgError::attrs` reads
    /// them at `sizeof(errno) + sizeof(nlmsghdr)`, which is only where
    /// they are in the capped form — so without this, **every
    /// `ext_ack` came back `None`** and every kernel rejection read as a
    /// bare errno (#292). Measured on the same request:
    ///
    /// ```text
    /// CAP_ACK off: payload=72B, TLVs at payload[40] -> nlink finds nothing
    /// CAP_ACK on:  payload=52B, TLVs at payload[20] -> "Parent Qdisc doesn't exists"
    /// ```
    ///
    /// Capping also shrinks every ACK by the size of the request, which
    /// matters for the batch paths that ACK per operation.
    ///
    /// Returns `Ok(())` on pre-4.3 kernels where the sockopt is not
    /// supported — graceful degradation, at the cost of unparsed
    /// ext-acks there.
    pub fn set_cap_ack(&self, on: bool) -> Result<()> {
        Self::set_netlink_sockopt(self.as_raw_fd(), Self::NETLINK_CAP_ACK, on)
    }

    /// Set the kernel-side receive buffer (`SO_RCVBUF`), escalating
    /// to `SO_RCVBUFFORCE` only when the plain call could not reach
    /// the requested size.
    ///
    /// **Growing is the primary use.** A multicast subscriber runs on
    /// `net.core.rmem_default` (~208 KiB on a stock kernel) unless it
    /// says otherwise, and a burst that outruns the buffer is dropped
    /// with `ENOBUFS` — for most protocols that costs a resync, and
    /// for `NETLINK_KOBJECT_UEVENT` there is no resync to be had
    /// (#252). Size up front.
    ///
    /// The kernel doubles what you pass (bookkeeping overhead) and
    /// clamps the plain `SO_RCVBUF` path to `net.core.rmem_max`.
    /// [`Self::rcvbuf`] reports what was actually granted — the
    /// *doubled* figure, as `getsockopt` returns it.
    ///
    /// Escalation: if the readback comes back below `bytes`, the
    /// request was capped by `rmem_max`, so this retries with
    /// `SO_RCVBUFFORCE`, which skips the cap. That needs
    /// `CAP_NET_ADMIN`; when the caller doesn't have it the `EPERM`
    /// is swallowed and the best-effort size stands. Uevent
    /// subscribers are routinely unprivileged, so failing there would
    /// make the knob unusable for exactly the consumers that need it.
    /// Check [`Self::rcvbuf`] if the exact size matters.
    ///
    /// Shrinking works too — `crates/nlink/tests/integration/`
    /// shrinks a subscriber to a few hundred bytes so a handful of
    /// mutations overflow it deterministically. Note the kernel's
    /// `SOCK_MIN_RCVBUF` floor applies to both paths, so a shrink
    /// below it lands on the floor rather than erroring.
    pub fn set_rcvbuf(&self, bytes: usize) -> Result<()> {
        let fd = self.as_raw_fd();
        Self::set_sock_int(fd, libc::SO_RCVBUF, bytes as libc::c_int)?;

        // Under the cap? Then the plain path was enough — including
        // every shrink, which `rmem_max` never limits.
        if Self::get_sock_int(fd, libc::SO_RCVBUF)? >= bytes as libc::c_int {
            return Ok(());
        }

        match Self::set_sock_int(fd, libc::SO_RCVBUFFORCE, bytes as libc::c_int) {
            Ok(()) => Ok(()),
            // No CAP_NET_ADMIN: keep the capped size rather than
            // failing a call the caller can't satisfy anyway.
            Err(e) if e.errno() == Some(libc::EPERM) => {
                tracing::debug!(
                    requested = bytes,
                    "SO_RCVBUF capped by net.core.rmem_max and SO_RCVBUFFORCE \
                     needs CAP_NET_ADMIN; keeping the granted size"
                );
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Read the granted receive-buffer size (`getsockopt(SO_RCVBUF)`).
    ///
    /// This is the kernel's internal `sk_rcvbuf`, i.e. **twice** the
    /// value handed to [`Self::set_rcvbuf`] (minus any clamping).
    /// Compare against `2 * requested` to tell a satisfied request
    /// from a capped one.
    pub fn rcvbuf(&self) -> Result<usize> {
        Ok(Self::get_sock_int(self.as_raw_fd(), libc::SO_RCVBUF)? as usize)
    }

    /// Attach a classic-BPF program as a socket filter
    /// (`SO_ATTACH_FILTER`), so the kernel drops uninteresting frames
    /// before they are ever queued to this socket.
    ///
    /// `prog` is a flat instruction stream in `struct sock_filter`
    /// layout — 8 bytes per instruction — as produced by
    /// [`crate::netlink::uevent_filter::UeventFilter::compile`]. The
    /// kernel's verifier rejects a malformed program with `EINVAL`.
    ///
    /// A filter returning 0 drops the frame; returning `u32::MAX`
    /// accepts it whole. Returning a smaller non-zero value would
    /// *truncate* the frame, which no nlink-generated program does —
    /// a truncated netlink message is worse than a dropped one.
    ///
    /// Attaching replaces any previously attached filter.
    pub fn attach_filter(&self, prog: &[u8]) -> Result<()> {
        const SOCK_FILTER_SIZE: usize = 8;
        if prog.is_empty() || !prog.len().is_multiple_of(SOCK_FILTER_SIZE) {
            return Err(Error::invalid_message(format!(
                "attach_filter: program is {} bytes, expected a non-empty \
                 multiple of {SOCK_FILTER_SIZE} (struct sock_filter)",
                prog.len()
            )));
        }
        let len = prog.len() / SOCK_FILTER_SIZE;
        if len > u16::MAX as usize {
            return Err(Error::invalid_message(format!(
                "attach_filter: {len} instructions exceeds the u16 \
                 sock_fprog.len field"
            )));
        }

        let fprog = libc::sock_fprog {
            len: len as u16,
            filter: prog.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: SO_ATTACH_FILTER on a valid fd with a sock_fprog
        // whose `filter` points at `len` well-formed instructions
        // (length checked above) that outlive the call — the kernel
        // copies the program in.
        let rc = unsafe {
            libc::setsockopt(
                self.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &fprog as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(Error::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Remove the socket filter (`SO_DETACH_FILTER`).
    ///
    /// Returns `Ok(())` when no filter was attached (`ENOENT`), so
    /// teardown paths can call it unconditionally.
    pub fn detach_filter(&self) -> Result<()> {
        let val: libc::c_int = 0;
        // SAFETY: SO_DETACH_FILTER on a valid fd; the optval is
        // ignored by the kernel but must be readable.
        let rc = unsafe {
            libc::setsockopt(
                self.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_DETACH_FILTER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(());
            }
            return Err(Error::from(err));
        }
        Ok(())
    }

    /// Pin the attached filter (`SO_LOCK_FILTER`) so it can no longer
    /// be detached or replaced on this socket.
    ///
    /// One-way: there is no unlock. Only worth it when the fd is
    /// about to be handed to less-trusted code that must not be able
    /// to widen what it sees.
    pub fn lock_filter(&self) -> Result<()> {
        Self::set_sock_int(self.as_raw_fd(), libc::SO_LOCK_FILTER, 1)
    }

    /// Internal helper: `setsockopt(SOL_SOCKET, optname, int)`.
    fn set_sock_int(fd: RawFd, optname: libc::c_int, val: libc::c_int) -> Result<()> {
        // SAFETY: setsockopt with a valid fd, SOL_SOCKET level, a
        // pointer to a stack int and the matching size.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                optname,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(Error::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Internal helper: `getsockopt(SOL_SOCKET, optname) -> int`.
    fn get_sock_int(fd: RawFd, optname: libc::c_int) -> Result<libc::c_int> {
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt with a valid fd, SOL_SOCKET level, and a
        // pointer to a stack int with its size in `len`; the kernel
        // writes at most `len` bytes and updates it.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                optname,
                &mut val as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc < 0 {
            return Err(Error::from(std::io::Error::last_os_error()));
        }
        Ok(val)
    }

    /// Enable kernel-side strict checking (`NETLINK_GET_STRICT_CHK`,
    /// kernel 5.0+). When enabled, the kernel validates dump request
    /// filters strictly and returns an error if they reference
    /// unknown attributes — useful for catching
    /// client/kernel-version mismatches early.
    ///
    /// Off by default. Returns `Ok(())` silently on pre-5.0 kernels
    /// where the sockopt is not supported (`ENOPROTOOPT`).
    pub fn set_strict_checking(&self, on: bool) -> Result<()> {
        // NETLINK_GET_STRICT_CHK = 12 per include/uapi/linux/netlink.h.
        // Not in libc as of writing; define inline.
        const NETLINK_GET_STRICT_CHK: libc::c_int = 12;
        Self::set_netlink_sockopt(self.as_raw_fd(), NETLINK_GET_STRICT_CHK, on)
    }

    /// Receive each datagram's multicast group with it
    /// (`NETLINK_PKTINFO`), for [`EventMeta::group`](super::EventMeta::group)
    /// (#523). Event streams turn it on in `with_meta()`.
    pub fn set_pktinfo(&self, on: bool) -> Result<()> {
        Self::set_netlink_sockopt(self.as_raw_fd(), NETLINK_PKTINFO, on)
    }

    /// Receive notifications from every namespace that has an id in this
    /// socket's (`NETLINK_LISTEN_ALL_NSID`, kernel 4.6+), each with that
    /// id, for [`EventMeta::nsid`](super::EventMeta::nsid) (#523). Needs
    /// `CAP_NET_BROADCAST`.
    pub fn set_listen_all_nsid(&self, on: bool) -> Result<()> {
        Self::set_netlink_sockopt(self.as_raw_fd(), NETLINK_LISTEN_ALL_NSID, on)
    }

    /// Internal helper: setsockopt(SOL_NETLINK, optname, on as int).
    /// Treats `ENOPROTOOPT` as success (graceful degradation when
    /// the running kernel doesn't recognize the optname).
    fn set_netlink_sockopt(fd: RawFd, optname: libc::c_int, on: bool) -> Result<()> {
        let val: libc::c_int = if on { 1 } else { 0 };
        // SAFETY: setsockopt with a valid fd + SOL_NETLINK level +
        // pointer to a stack-allocated int + correct size. Returns
        // -1 on failure; we check it.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_NETLINK,
                optname,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
                // Kernel doesn't support this sockopt — silently
                // succeed so callers can `enable_strict_checking(true)`
                // unconditionally and it's a no-op on old kernels.
                return Ok(());
            }
            return Err(Error::from(err));
        }
        Ok(())
    }

    /// Subscribe to multicast groups.
    ///
    /// Takes `&self` (changed in 0.19, Finding A). The underlying
    /// syscall is `setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP)`
    /// which is fd-level — no shared state to mutate. Matches the
    /// pattern set by [`Self::set_strict_checking`] /
    /// [`Self::set_ext_ack`]. The `&mut` requirement was a stale
    /// artefact of routing through `AsyncFd::get_mut`; it blocked
    /// subscribe-through-`ConnectionPool` and concurrent
    /// subscribe-from-different-tasks, both legitimate uses.
    pub fn add_membership(&self, group: u32) -> Result<()> {
        Self::set_membership_sockopt(self.as_raw_fd(), libc::NETLINK_ADD_MEMBERSHIP, group)
    }

    /// Unsubscribe from multicast groups. See [`Self::add_membership`].
    pub fn drop_membership(&self, group: u32) -> Result<()> {
        Self::set_membership_sockopt(self.as_raw_fd(), libc::NETLINK_DROP_MEMBERSHIP, group)
    }

    /// Internal helper: `setsockopt(SOL_NETLINK, optname, group)`.
    fn set_membership_sockopt(fd: RawFd, optname: libc::c_int, group: u32) -> Result<()> {
        let val: libc::c_int = group as libc::c_int;
        // SAFETY: setsockopt with a valid fd + SOL_NETLINK level +
        // pointer to a stack-allocated int + correct size.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_NETLINK,
                optname,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(Error::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Send a message.
    ///
    /// Plan 232 B19 — surface backpressure as
    /// [`ErrorDetail::Backpressure`](crate::ErrorDetail::Backpressure) after a small number of
    /// back-to-back `WouldBlock` returns from the kernel. The 30 s
    /// connection timeout (Plan 171) would eventually surface as
    /// `Timeout`; surfacing backpressure sooner lets a caller back
    /// off without waiting the full timeout window.
    pub async fn send(&self, msg: &[u8]) -> Result<()> {
        self.send_unstamped(msg).await.map_err(|e| self.stamp(e))
    }

    /// [`send`](Self::send), its errors not yet stamped with the
    /// socket's protocol and namespace.
    async fn send_unstamped(&self, msg: &[u8]) -> Result<()> {
        #[cfg(feature = "replay")]
        if let Some(sent) = self.hook.as_ref().and_then(|h| h.before_send(msg)) {
            return sent;
        }
        let mut would_block_count: u32 = 0;
        loop {
            let mut guard = self.fd.ready(Interest::WRITABLE).await?;

            match guard.try_io(|inner| inner.get_ref().send(msg, 0)) {
                Ok(result) => {
                    result?;
                    self.sent(msg);
                    return Ok(());
                }
                Err(_would_block) => {
                    would_block_count += 1;
                    if would_block_count >= SEND_WOULDBLOCK_LIMIT {
                        return Err(Error::from(crate::netlink::ErrorDetail::Backpressure {
                            send_buffer_full: true,
                        }));
                    }
                    continue;
                }
            }
        }
    }

    /// Send a netlink message with file descriptors attached as an
    /// `SCM_RIGHTS` ancillary control message via `sendmsg(2)`.
    ///
    /// With an empty `fds` slice this is exactly [`Self::send`].
    ///
    /// # Netlink semantics — read before reaching for this
    ///
    /// Unlike `AF_UNIX` sockets, the kernel's netlink layer does **not**
    /// hand `SCM_RIGHTS` file descriptors to generic-netlink command
    /// handlers: a genl `doit`/`dumpit` callback has no access to the
    /// received `scm_fp_list`. So for most in-tree families (including
    /// OpenVPN DCO) this primitive does not attach the fd to anything —
    /// it is provided as a general building block for protocols (or
    /// out-of-tree kernels) that genuinely consume passed fds, and for
    /// fd-relay scenarios (handing the message+fd to a broker over a
    /// Unix socket). For the OpenVPN DCO family, cross-netns socket
    /// attach is done via the `OVPN_A_PEER_SOCKET` +
    /// `OVPN_A_PEER_SOCKET_NETNSID` attributes instead — see
    /// [`Connection::<Ovpn>::attach_socket`](crate::netlink::Connection).
    pub async fn send_with_fds(&self, msg: &[u8], fds: &[BorrowedFd<'_>]) -> Result<()> {
        self.send_with_fds_unstamped(msg, fds).await.map_err(|e| self.stamp(e))
    }

    /// [`send_with_fds`](Self::send_with_fds), its errors not yet stamped with the
    /// socket's protocol and namespace.
    async fn send_with_fds_unstamped(&self, msg: &[u8], fds: &[BorrowedFd<'_>]) -> Result<()> {
        if fds.is_empty() {
            return self.send(msg).await;
        }
        #[cfg(feature = "replay")]
        if let Some(sent) = self.hook.as_ref().and_then(|h| h.before_send(msg)) {
            return sent;
        }

        let fds: Vec<RawFd> = fds.iter().map(|fd| fd.as_raw_fd()).collect();
        let (mut cmsg_buf, cmsg_space) = build_scm_rights_control(&fds);

        let mut would_block_count: u32 = 0;
        loop {
            let mut guard = self.fd.ready(Interest::WRITABLE).await?;

            // Build the `msghdr` inside the synchronous closure so the
            // raw pointers it holds never cross the `.await` above —
            // keeping the returned future `Send` (only the `Vec<u64>`
            // control buffer, which is `Send`, is held across the await).
            let res = guard.try_io(|inner| {
                let mut iov = libc::iovec {
                    iov_base: msg.as_ptr() as *mut libc::c_void,
                    iov_len: msg.len(),
                };
                let mut mhdr: libc::msghdr = unsafe { std::mem::zeroed() };
                mhdr.msg_iov = &mut iov;
                mhdr.msg_iovlen = 1;
                mhdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
                mhdr.msg_controllen = cmsg_space as _;

                let n = unsafe { libc::sendmsg(inner.get_ref().as_raw_fd(), &mhdr, 0) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });

            match res {
                Ok(result) => {
                    result?;
                    self.sent(msg);
                    return Ok(());
                }
                Err(_would_block) => {
                    would_block_count += 1;
                    if would_block_count >= SEND_WOULDBLOCK_LIMIT {
                        return Err(Error::from(crate::netlink::ErrorDetail::Backpressure {
                            send_buffer_full: true,
                        }));
                    }
                    continue;
                }
            }
        }
    }

    /// Receive a message, allocating a buffer.
    ///
    /// Reads each datagram whole, however large, up to a 1 MiB cap: it
    /// peeks the size first (#505; see `recv_whole`). A datagram past
    /// the cap is dropped and reported as [`ErrorDetail::FrameTruncated`](crate::ErrorDetail::FrameTruncated)
    /// rather than lost without a word.
    pub async fn recv_msg(&self) -> Result<Vec<u8>> {
        Ok(self.recv_msg_from().await?.0)
    }

    /// [`recv_msg`](Self::recv_msg), and whether the datagram was a
    /// **multicast** copy: `sockaddr_nl.nl_groups != 0` in `msg_name`.
    ///
    /// That is the only place the kernel says so. A notification caused by
    /// a request carries the request's seq and portid in its header —
    /// `rtmsg_fib(…, info->nlh, info->portid)` — so a socket subscribed to
    /// the group gets its own notification looking exactly like a reply,
    /// and another process's (`ip`, `nft`) with a seq that is not 0. Only
    /// changes the kernel originates carry seq 0 (#465).
    pub async fn recv_msg_from(&self) -> Result<(Vec<u8>, bool)> {
        self.recv_msg_from_unstamped().await.map_err(|e| self.stamp(e))
    }

    /// [`recv_msg_from`](Self::recv_msg_from), its errors not yet stamped with the
    /// socket's protocol and namespace.
    async fn recv_msg_from_unstamped(&self) -> Result<(Vec<u8>, bool)> {
        #[cfg(feature = "replay")]
        if let Some(replay) = self.replaying() {
            return replay.recv().await;
        }
        loop {
            let mut guard = self.fd.ready(Interest::READABLE).await?;
            match guard.try_io(|inner| recv_whole(inner.get_ref(), 0)) {
                Ok(Ok(got)) => {
                    let got = got.into_result()?;
                    self.received(&got.0, got.1);
                    return Ok(got);
                }
                Ok(Err(e)) => {
                    // Plan 234 §4 — route ENOBUFS to multicast
                    // subscribers via the dispatcher BEFORE
                    // propagating the error to the caller. Slow
                    // subscribers see `ResyncMarker::ResyncStart`
                    // even though the request path also surfaces
                    // the error. Pre-dispatcher, ENOBUFS
                    // surfaced into whichever caller happened to
                    // be in `recv_msg` — typically a request,
                    // not the subscriber that should care.
                    if e.raw_os_error() == Some(libc::ENOBUFS) {
                        self.fan_out_enobufs();
                    }
                    return Err(e.into());
                }
                Err(_would_block) => continue,
            }
        }
    }

    /// Receive the next datagram addressed to this socket alone, skipping
    /// multicast copies — for request/reply loops. A connection that has
    /// joined a group would otherwise read its own notification, which
    /// carries its request's seq, as the reply (#465).
    pub async fn recv_unicast(&self) -> Result<Vec<u8>> {
        loop {
            let (data, multicast) = self.recv_msg_from().await?;
            if !multicast {
                return Ok(data);
            }
            tracing::trace!("skipping a multicast datagram while waiting for a reply");
        }
    }

    /// [`try_recv_msg`](Self::try_recv_msg) for request/reply loops:
    /// multicast copies are skipped, as in
    /// [`recv_unicast`](Self::recv_unicast).
    pub fn try_recv_unicast(&self) -> Result<Option<Vec<u8>>> {
        loop {
            match self.try_recv_inner()? {
                Some((_, true)) => continue,
                Some((data, false)) => return Ok(Some(data)),
                None => return Ok(None),
            }
        }
    }

    /// Receive a message if one is already queued, without waiting.
    ///
    /// Returns `Ok(None)` when the socket has nothing readable. Unlike
    /// [`Self::recv_msg`] this issues the `recvmsg` directly with
    /// `MSG_DONTWAIT` rather than going through the reactor's
    /// readiness bookkeeping — a "try" that returned `None` merely
    /// because tokio had not yet observed the fd as readable would be
    /// useless for draining a backlog. Stale readiness left behind is
    /// harmless: [`Self::recv_msg`] and [`Self::poll_recv`] already
    /// treat a `WouldBlock` from `try_io` as "clear and retry".
    ///
    /// `MSG_TRUNC` semantics match [`Self::recv_msg`]: on truncation
    /// the buffer is regrown from the kernel's reported size, up to
    /// the same 1 MiB cap, and a frame past the cap surfaces as
    /// [`ErrorDetail::FrameTruncated`](crate::ErrorDetail::FrameTruncated).
    pub fn try_recv_msg(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.try_recv_inner()?.map(|(data, _)| data))
    }

    /// [`try_recv_msg`](Self::try_recv_msg) with the multicast tag, as in
    /// [`recv_msg_from`](Self::recv_msg_from).
    pub(crate) fn try_recv_inner(&self) -> Result<Option<(Vec<u8>, bool)>> {
        self.try_recv_inner_unstamped().map_err(|e| self.stamp(e))
    }

    /// [`try_recv_inner`](Self::try_recv_inner), its errors not yet stamped with the
    /// socket's protocol and namespace.
    fn try_recv_inner_unstamped(&self) -> Result<Option<(Vec<u8>, bool)>> {
        #[cfg(feature = "replay")]
        if let Some(replay) = self.replaying() {
            return Ok(replay.try_recv());
        }
        match recv_whole(self.fd.get_ref(), libc::MSG_DONTWAIT) {
            Ok(got) => {
                let got = got.into_result()?;
                self.received(&got.0, got.1);
                Ok(Some(got))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => {
                // Same routing as recv_msg: multicast subscribers
                // need the resync marker even when the overflow
                // surfaces on a non-blocking drain.
                if e.raw_os_error() == Some(libc::ENOBUFS) {
                    self.fan_out_enobufs();
                }
                Err(e.into())
            }
        }
    }

    /// Poll for incoming data.
    ///
    /// This is the poll-based version of `recv_msg()` for use with `Stream` implementations.
    /// Returns `Poll::Ready(Ok(data))` when data is available.
    ///
    /// Reads each datagram whole, as [`recv_msg`](Self::recv_msg) does
    /// (#505): it used to receive into a fixed 32 KiB buffer, so a larger
    /// frame was consumed, lost, and ended an event stream for good. Only
    /// a datagram past the 1 MiB cap surfaces as
    /// [`ErrorDetail::FrameTruncated`](crate::ErrorDetail::FrameTruncated), which an event stream reports as an
    /// overrun and survives.
    pub fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<Vec<u8>>> {
        self.poll_recv_meta(cx).map(|r| r.map(|(data, _)| data))
    }

    /// [`poll_recv`](Self::poll_recv), with what the datagram's control
    /// messages say: its multicast group and its namespace's id, when the
    /// socket asked for them ([`set_pktinfo`](Self::set_pktinfo),
    /// [`set_listen_all_nsid`](Self::set_listen_all_nsid)) (#523).
    pub(crate) fn poll_recv_meta(&self, cx: &mut Context<'_>) -> Poll<Result<(Vec<u8>, RecvMeta)>> {
        #[cfg(feature = "replay")]
        if let Some(replay) = self.replaying() {
            return replay
                .poll_recv(cx)
                .map(|r| r.map(|(data, _)| (data, RecvMeta::default())));
        }
        loop {
            let mut guard = match self.fd.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => return Poll::Pending,
            };

            match guard.try_io(|inner| recv_whole_meta(inner.get_ref(), 0, RECV_MAX_CAPACITY)) {
                Ok(result) => match result {
                    Ok((got, meta)) => {
                        let got = got.into_result();
                        if let Ok((data, multicast)) = &got {
                            self.received(data, *multicast);
                        }
                        return Poll::Ready(got.map(|(data, _)| (data, meta)));
                    }
                    Err(e) => {
                        // Plan 234 §4 — see recv_msg for the
                        // ENOBUFS routing rationale. poll_recv is
                        // the streaming entrypoint, so a multicast
                        // subscriber that overflows will see the
                        // error AND get a ResyncStart marker
                        // delivered to any other subscriber sharing
                        // this socket's dispatcher.
                        if e.raw_os_error() == Some(libc::ENOBUFS) {
                            self.fan_out_enobufs();
                        }
                        return Poll::Ready(Err(e.into()));
                    }
                },
                Err(_would_block) => continue,
            }
        }
    }
}

/// Plan 232 B19 — back-to-back `WouldBlock` returns from `send`
/// that exceed this threshold surface as
/// [`ErrorDetail::Backpressure`](crate::ErrorDetail::Backpressure). The kernel send buffer is full and
/// retrying immediately is futile.
///
/// 32 matches the historic `NL_BATCH_SIZE` heuristic. The full
/// 30 s connection timeout (Plan 171) is still in place as an
/// upper bound; this lets callers react faster.
pub(crate) const SEND_WOULDBLOCK_LIMIT: u32 = 32;

/// The buffer every receive peeks into (Plan 224). 32 KiB is what the
/// kernel packs a dump skb up to, so nearly every datagram fits it; a
/// larger one gets a buffer of its exact size (`recv_whole`).
pub(crate) const RECV_INITIAL_CAPACITY: usize = 32 * 1024;

/// Receive one whole datagram: peek it (`MSG_PEEK | MSG_TRUNC`, which
/// reports its full length), then consume it — the way iproute2's
/// `rtnl_recvmsg` does.
///
/// Receiving with `MSG_TRUNC` alone consumed a datagram larger than the
/// buffer before its size was known: the "grow and retry" that followed
/// read the *next* datagram, and the large one — a link with many VFs, a
/// big notification — was gone without a word (#505). A datagram past
/// [`RECV_MAX_CAPACITY`] is consumed and reported as
/// [`ErrorDetail::FrameTruncated`](crate::ErrorDetail::FrameTruncated). Returns the bytes and whether the datagram
/// was a multicast copy.
fn recv_whole(socket: &Socket, flags: libc::c_int) -> std::io::Result<RecvWhole> {
    recv_whole_capped(socket, flags, RECV_MAX_CAPACITY)
}

/// [`recv_whole`] with the cap as a parameter, so a test can reach it
/// without a megabyte of socket buffer.
fn recv_whole_capped(
    socket: &Socket,
    flags: libc::c_int,
    max: usize,
) -> std::io::Result<RecvWhole> {
    let mut buf = BytesMut::with_capacity(RECV_INITIAL_CAPACITY);
    let (len, addr) =
        past_dump_race(|| socket.recv_from(&mut buf, flags | libc::MSG_PEEK | libc::MSG_TRUNC))?;
    let multicast = addr.multicast_groups() != 0;
    if len > max {
        // Drop it, and say so.
        let mut none = BytesMut::new();
        past_dump_race(|| socket.recv_from(&mut none, flags))?;
        return Ok(RecvWhole::TooLarge(len));
    }
    if len <= RECV_INITIAL_CAPACITY {
        // The peek has it all; consume it without copying it again.
        let mut none = BytesMut::new();
        past_dump_race(|| socket.recv_from(&mut none, flags))?;
        return Ok(RecvWhole::Frame(buf.to_vec(), multicast));
    }
    let mut big = BytesMut::with_capacity(len);
    past_dump_race(|| socket.recv_from(&mut big, flags))?;
    Ok(RecvWhole::Frame(big.to_vec(), multicast))
}

/// How many times [`past_dump_race`] retries before it believes an `EINVAL`.
const DUMP_RACE_RETRIES: usize = 3;

/// One receive, retried past the `EINVAL` a dump's end can leave in
/// `sk_err` (#870).
///
/// After it hands over a datagram, `netlink_recvmsg` continues the dump it
/// sees running. The thread that started the dump can be finishing it at
/// that moment: in its `sendmsg`, `netlink_dump` queues the last skb, wakes
/// the reader and only then clears `cb_running`. A reader on another CPU —
/// a dispatcher's driver, whose request task started the dump — can take
/// that skb in between. Its own `netlink_dump` then waits for the dumper's
/// mutex, finds no dump, and its `-EINVAL` lands in `sk_err`. The next
/// receive returns it, and clears it, before it dequeues anything. Nothing
/// is lost, so the receive is tried again. It reproduced as back-to-back
/// empty dumps on a dispatcher connection: the driver died one run in two,
/// on the consume after the peek of the dump's `NLMSG_DONE`.
///
/// Bounded: each spurious `EINVAL` needs the race again, so a few in a row
/// mean the error is real.
fn past_dump_race<T>(mut recv: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    let mut retries = 0;
    loop {
        match recv() {
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) && retries < DUMP_RACE_RETRIES => {
                retries += 1;
                tracing::debug!(retries, "netlink recv: EINVAL left by a finished dump; retrying");
            }
            other => return other,
        }
    }
}

/// `NETLINK_PKTINFO` from `linux/netlink.h`.
const NETLINK_PKTINFO: libc::c_int = 3;
/// `NETLINK_LISTEN_ALL_NSID` from `linux/netlink.h`.
const NETLINK_LISTEN_ALL_NSID: libc::c_int = 8;

/// What a datagram's control messages said (#523).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RecvMeta {
    /// The multicast group it was sent to (`NETLINK_PKTINFO`).
    pub(crate) group: Option<u32>,
    /// The id of the namespace it came from, as this socket's namespace
    /// knows it (`NETLINK_LISTEN_ALL_NSID`). Absent for its own.
    pub(crate) nsid: Option<i32>,
}

/// [`recv_whole`], keeping the control messages: the peek reads them,
/// since netlink attaches them to every receive of the datagram.
fn recv_whole_meta(
    socket: &Socket,
    flags: libc::c_int,
    max: usize,
) -> std::io::Result<(RecvWhole, RecvMeta)> {
    let fd = socket.as_raw_fd();
    let mut buf = vec![0u8; RECV_INITIAL_CAPACITY];
    let (len, meta, multicast) =
        past_dump_race(|| recvmsg_meta(fd, &mut buf, flags | libc::MSG_PEEK | libc::MSG_TRUNC))?;
    if len > max || len <= buf.len() {
        let mut none = BytesMut::new();
        past_dump_race(|| socket.recv_from(&mut none, flags))?;
        if len > max {
            return Ok((RecvWhole::TooLarge(len), meta));
        }
        buf.truncate(len);
        return Ok((RecvWhole::Frame(buf, multicast), meta));
    }
    let mut big = vec![0u8; len];
    let (got, _, _) = past_dump_race(|| recvmsg_meta(fd, &mut big, flags))?;
    big.truncate(got);
    Ok((RecvWhole::Frame(big, multicast), meta))
}

/// One `recvmsg` into `buf`, returning the datagram's full length (with
/// `MSG_TRUNC`), its netlink control messages, and whether it was a
/// multicast copy.
fn recvmsg_meta(
    fd: RawFd,
    buf: &mut [u8],
    flags: libc::c_int,
) -> std::io::Result<(usize, RecvMeta, bool)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // Room for both control messages; u64 for cmsghdr's alignment.
    let mut control = [0u64; 8];
    // SAFETY: sockaddr_nl and msghdr are plain data; all-zero is valid.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw mut addr).cast();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as _;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control) as _;
    // SAFETY: `msg` points at `addr`, `iov` (over `buf`) and `control`,
    // all live and writable for the call.
    let n = unsafe { libc::recvmsg(fd, &mut msg, flags) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut meta = RecvMeta::default();
    // SAFETY: the CMSG_* macros walk the control buffer the kernel just
    // filled, bounded by `msg_controllen`; each data read stays within
    // its cmsg, whose length the kernel set for the type read.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_NETLINK {
                let data = libc::CMSG_DATA(cmsg);
                match (*cmsg).cmsg_type {
                    NETLINK_PKTINFO => meta.group = Some(data.cast::<u32>().read_unaligned()),
                    NETLINK_LISTEN_ALL_NSID => meta.nsid = Some(data.cast::<i32>().read_unaligned()),
                    _ => {}
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok((n as usize, meta, addr.nl_groups != 0))
}

/// What [`recv_whole`] got.
enum RecvWhole {
    /// The datagram, and whether it was a multicast copy.
    Frame(Vec<u8>, bool),
    /// A datagram of this many bytes, past [`RECV_MAX_CAPACITY`], dropped.
    TooLarge(usize),
}

impl RecvWhole {
    fn into_result(self) -> Result<(Vec<u8>, bool)> {
        match self {
            RecvWhole::Frame(data, multicast) => Ok((data, multicast)),
            RecvWhole::TooLarge(received) => Err(Error::from(crate::netlink::ErrorDetail::FrameTruncated {
                received,
                buffer_size: RECV_MAX_CAPACITY,
            })),
        }
    }
}

/// Max recv buffer capacity for [`NetlinkSocket::recv_msg`]
/// (Plan 224). 1 MiB is the cap before nlink surfaces
/// [`ErrorDetail::FrameTruncated`](crate::ErrorDetail::FrameTruncated) instead of growing further.
///
/// The kernel's `NLMSG_GOODSIZE` per-frame budget is roughly
/// `SKB_WITH_OVERHEAD(PAGE_SIZE_MAX)` (≈32-64 KiB on x86, up to
/// ~56 KiB on 64 KiB-page arm64). 1 MiB covers every plausible
/// kernel-side frame with a 16× margin; anything beyond is a
/// kernel bug or a protocol-extension nlink hasn't been
/// updated for.
pub(crate) const RECV_MAX_CAPACITY: usize = 1024 * 1024;

impl AsRawFd for NetlinkSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.get_ref().as_raw_fd()
    }
}

impl AsFd for NetlinkSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.get_ref().as_fd()
    }
}

// ============================================================================
// Batched I/O via recvmmsg(2) / sendmmsg(2)
// Plan 158 — opt-in `syscall_batch` feature flag for 0.16; default-on in 0.17.
// ============================================================================

/// Maximum number of frames batched in one `recvmmsg`/`sendmmsg`
/// syscall. Matches quinn-udp's choice; above 64 cache footprint
/// outweighs syscall amortization.
#[cfg(feature = "syscall_batch")]
pub const NL_BATCH_SIZE: usize = 32;

/// Per-slot recv buffer size. Sized to exceed any realistic
/// single netlink frame; MSG_TRUNC is a hard error rather than
/// silent truncation.
#[cfg(feature = "syscall_batch")]
pub const NL_BUF_SIZE: usize = 32 * 1024;

#[cfg(feature = "syscall_batch")]
struct BatchBufs {
    /// Owned per-slot recv storage. Allocated once; pointers
    /// reused across calls.
    storage: Vec<Vec<u8>>,
    /// iovec entries pointing into `storage`. Set up at
    /// construction; the pointers stay valid because `storage`
    /// is never resized.
    ///
    /// Held here even though we don't read the field directly —
    /// `msgs[i].msg_hdr.msg_iov` is a raw `*mut iovec` into this
    /// `Vec`, and dropping `iovecs` would dangle those pointers.
    /// Keeping ownership in the same struct guarantees the
    /// lifetime extends across `recvmmsg` calls.
    #[allow(dead_code)]
    iovecs: Vec<libc::iovec>,
    /// Per-slot sender address; `msg_hdr.msg_name` points into it, and
    /// `nl_groups` marks a multicast copy (#465). Held for the same
    /// lifetime reason as `iovecs`.
    names: Vec<libc::sockaddr_nl>,
    /// mmsghdr array; msg_hdr.msg_iov points into `iovecs`.
    msgs: Vec<libc::mmsghdr>,
}

#[cfg(feature = "syscall_batch")]
impl BatchBufs {
    fn new() -> Self {
        let mut storage: Vec<Vec<u8>> =
            (0..NL_BATCH_SIZE).map(|_| vec![0u8; NL_BUF_SIZE]).collect();
        let mut iovecs: Vec<libc::iovec> = storage
            .iter_mut()
            .map(|buf| libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            })
            .collect();
        let mut msgs: Vec<libc::mmsghdr> = (0..NL_BATCH_SIZE)
            .map(|_| unsafe { std::mem::zeroed() })
            .collect();
        // SAFETY: sockaddr_nl is plain old data; all-zero is a valid value.
        let mut names: Vec<libc::sockaddr_nl> = (0..NL_BATCH_SIZE)
            .map(|_| unsafe { std::mem::zeroed() })
            .collect();
        for (i, msg) in msgs.iter_mut().enumerate() {
            msg.msg_hdr.msg_iov = &mut iovecs[i] as *mut _;
            msg.msg_hdr.msg_iovlen = 1;
            msg.msg_hdr.msg_name = &mut names[i] as *mut libc::sockaddr_nl as *mut libc::c_void;
            msg.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            msg.msg_hdr.msg_control = std::ptr::null_mut();
            msg.msg_hdr.msg_controllen = 0;
            msg.msg_hdr.msg_flags = 0;
            msg.msg_len = 0;
        }
        BatchBufs {
            storage,
            iovecs,
            names,
            msgs,
        }
    }

    /// Reset per-call mutable fields on the first `n` slots. The
    /// iov_base / iov_len / msg_iov bindings stay valid.
    fn prepare(&mut self, n: usize) {
        for i in 0..n {
            self.msgs[i].msg_len = 0;
            self.msgs[i].msg_hdr.msg_flags = 0;
            // The kernel writes the address length back; reset it.
            self.msgs[i].msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            self.names[i].nl_groups = 0;
        }
    }
}

#[cfg(feature = "syscall_batch")]
#[nlink_macros::send_futures]
impl NetlinkSocket {
    /// Poll-based batched recv for `Stream` implementations
    /// (`DumpStream`, multicast event streams). Same semantics as
    /// [`Self::recv_batch`] but exposes the batch via the
    /// `Poll<Result<Vec<Vec<u8>>>>` shape.
    pub fn poll_recv_batch(&self, cx: &mut Context<'_>, max: usize) -> Poll<Result<Vec<Vec<u8>>>> {
        #[cfg(feature = "replay")]
        if let Some(replay) = self.replaying() {
            return replay.poll_recv(cx).map(|r| r.map(|(data, _)| vec![data]));
        }
        let max = max.clamp(1, NL_BATCH_SIZE);
        loop {
            let mut guard = match self.fd.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => return Poll::Pending,
            };
            let result: std::result::Result<std::io::Result<Vec<Vec<u8>>>, _> =
                guard.try_io(|inner| Self::recv_batch_inner(inner.get_ref().as_raw_fd(), max));
            match result {
                Ok(Ok(frames)) => {
                    for frame in &frames {
                        self.received(frame, false);
                    }
                    return Poll::Ready(Ok(frames));
                }
                Ok(Err(e)) => {
                    // Mirror recv_msg/poll_recv: tell the resync subscribers the
                    // kernel dropped multicast frames *before* handing the error
                    // to whoever happened to be reading (#220). Without this, a
                    // `syscall_batch` build's resync streams never learn they
                    // missed anything and never re-dump.
                    if e.raw_os_error() == Some(libc::ENOBUFS) {
                        self.fan_out_enobufs();
                    }
                    return Poll::Ready(Err(Error::from(e)));
                }
                Err(_would_block) => continue,
            }
        }
    }

    /// Receive up to `max` netlink datagrams in one `recvmmsg(2)`
    /// syscall.
    ///
    /// Pushes each successfully-received frame as an owned `Vec<u8>`
    /// onto `out` (not cleared). Returns the count received in
    /// this call. `max` is clamped to `NL_BATCH_SIZE` (32 frames).
    ///
    /// On `EAGAIN`/`EWOULDBLOCK` returns `Ok(0)` after the
    /// `AsyncFd` re-arms — caller can poll again or back off.
    /// Other syscall errors propagate. `MSG_TRUNC` on any slot is
    /// promoted to `Error::invalid_message` ("frame exceeded
    /// `NL_BUF_SIZE`") — the 32 KiB per-slot buffer exceeds every
    /// realistic netlink frame, so this signals a kernel ABI
    /// violation worth screaming about rather than silently
    /// dropping bytes.
    ///
    /// The per-socket buffer pool is lazily allocated on first
    /// call (`NL_BATCH_SIZE * NL_BUF_SIZE = 1 MiB`) and reused
    /// across subsequent calls.
    ///
    /// # Cancellation safety
    ///
    /// Cancellation-safe: dropping the future before the syscall
    /// completes leaves the socket state intact (AsyncFd has not
    /// consumed any data). Re-polling resumes cleanly.
    pub async fn recv_batch(&self, out: &mut Vec<Vec<u8>>, max: usize) -> Result<usize> {
        self.recv_batch_unstamped(out, max).await.map_err(|e| self.stamp(e))
    }

    /// [`recv_batch`](Self::recv_batch), its errors not yet stamped with the
    /// socket's protocol and namespace.
    async fn recv_batch_unstamped(&self, out: &mut Vec<Vec<u8>>, max: usize) -> Result<usize> {
        #[cfg(feature = "replay")]
        if let Some(replay) = self.replaying() {
            out.push(replay.recv().await?.0);
            return Ok(1);
        }
        let max = max.clamp(1, NL_BATCH_SIZE);
        loop {
            let mut guard = self.fd.ready(Interest::READABLE).await?;
            // try_io expects io::Result<T> so it can spot
            // WouldBlock — we map nlink::Error back through Io to
            // satisfy that contract, then unwrap at the outer
            // layer. The Other-shaped Error::invalid_message stays
            // typed via the OS-error roundtrip below.
            let result: std::result::Result<std::io::Result<Vec<Vec<u8>>>, _> =
                guard.try_io(|inner| Self::recv_batch_inner(inner.get_ref().as_raw_fd(), max));
            match result {
                Ok(Ok(frames)) => {
                    let n = frames.len();
                    for frame in &frames {
                        self.received(frame, false);
                    }
                    out.extend(frames);
                    return Ok(n);
                }
                Ok(Err(e)) => {
                    // Same as recv_msg (#220) — see poll_recv_batch.
                    if e.raw_os_error() == Some(libc::ENOBUFS) {
                        self.fan_out_enobufs();
                    }
                    return Err(Error::from(e));
                }
                Err(_would_block) => continue,
            }
        }
    }

    fn recv_batch_inner(fd: RawFd, max: usize) -> std::io::Result<Vec<Vec<u8>>> {
        // Per-call buffer pool — lazily initialized in TLS to keep
        // recv_batch &self (no Mutex contention). The cost is one
        // BatchBufs per thread that ever calls recv_batch on any
        // socket; for the per-connection single-flight pattern
        // that's exactly one.
        thread_local! {
            static BUFS: std::cell::RefCell<Option<BatchBufs>> =
                const { std::cell::RefCell::new(None) };
        }

        BUFS.with(|cell| {
            let mut borrow = cell.borrow_mut();
            let bufs = borrow.get_or_insert_with(BatchBufs::new);
            bufs.prepare(max);

            // SAFETY: `recvmmsg` requires the mmsghdr array to be
            // valid for reads and writes for `max` entries; we own
            // it via the thread-local BatchBufs and the iovec
            // pointers reference owned storage that outlives this
            // call (storage is never resized after BatchBufs::new).
            // MSG_DONTWAIT skips blocking; timeout = NULL because
            // the kernel `timeout` arg has been buggy since 2010
            // (see `man recvmmsg(2)` BUGS) — tokio::time::timeout
            // is the right tool.
            let n = past_dump_race(|| {
                let n = unsafe {
                    libc::recvmmsg(
                        fd,
                        bufs.msgs.as_mut_ptr(),
                        max as libc::c_uint,
                        libc::MSG_DONTWAIT,
                        std::ptr::null_mut(),
                    )
                };
                if n < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(n)
            })?;

            let mut frames = Vec::with_capacity(n as usize);
            for i in 0..n as usize {
                let len = bufs.msgs[i].msg_len as usize;
                let flags = bufs.msgs[i].msg_hdr.msg_flags;
                if flags & libc::MSG_TRUNC != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "netlink frame {} exceeded NL_BUF_SIZE ({} bytes > {} buffer); \
                             file an issue with the kernel version + subsystem",
                            i, len, NL_BUF_SIZE
                        ),
                    ));
                }
                // Batched receives serve dumps, which are request/reply: a
                // multicast copy here is a notification, not part of the
                // dump, and is dropped (#465).
                if bufs.names[i].nl_groups != 0 {
                    continue;
                }
                frames.push(bufs.storage[i][..len].to_vec());
            }
            Ok(frames)
        })
    }

    /// Send up to `msgs.len()` netlink request frames in one
    /// `sendmmsg(2)` syscall. `msgs.len()` clamped to
    /// `NL_BATCH_SIZE` (32 frames).
    ///
    /// Returns the count successfully sent. Partial sends are
    /// possible — per `sendmmsg(2)`, if slot K errors the call
    /// returns K (the successful prefix) and the K-th error is
    /// silently dropped. Caller handles partial-send by re-calling
    /// from the returned offset; the resulting `-1` return will
    /// carry the real errno.
    ///
    /// **Important**: per-request kernel processing errors (the
    /// kernel's `NLMSG_ERROR` responses to malformed requests)
    /// are NOT surfaced here — they arrive asynchronously on the
    /// receive side, matched by `nlmsg_seq`. `send_batch` only
    /// reports syscall-level errors (`ENOBUFS`, `EMSGSIZE`, etc.).
    pub async fn send_batch(&self, msgs: &[&[u8]]) -> Result<usize> {
        self.send_batch_unstamped(msgs).await.map_err(|e| self.stamp(e))
    }

    /// [`send_batch`](Self::send_batch), its errors not yet stamped with the
    /// socket's protocol and namespace.
    async fn send_batch_unstamped(&self, msgs: &[&[u8]]) -> Result<usize> {
        if msgs.is_empty() {
            return Ok(0);
        }
        let n = msgs.len().min(NL_BATCH_SIZE);
        #[cfg(feature = "replay")]
        if self.replaying().is_some() {
            for msg in &msgs[..n] {
                self.send_unstamped(msg).await?;
            }
            return Ok(n);
        }

        loop {
            let mut guard = self.fd.ready(Interest::WRITABLE).await?;
            let result: std::result::Result<std::io::Result<usize>, _> = guard
                .try_io(|inner| Self::send_batch_inner(inner.get_ref().as_raw_fd(), &msgs[..n]));
            match result {
                Ok(Ok(sent)) => {
                    for msg in &msgs[..sent] {
                        self.sent(msg);
                    }
                    return Ok(sent);
                }
                Ok(Err(e)) => return Err(Error::from(e)),
                Err(_would_block) => continue,
            }
        }
    }

    fn send_batch_inner(fd: RawFd, msgs: &[&[u8]]) -> std::io::Result<usize> {
        let mut iovecs: Vec<libc::iovec> = msgs
            .iter()
            .map(|m| libc::iovec {
                iov_base: m.as_ptr() as *mut libc::c_void,
                iov_len: m.len(),
            })
            .collect();
        let mut mmsg: Vec<libc::mmsghdr> = (0..msgs.len())
            .map(|i| unsafe {
                let mut hdr: libc::mmsghdr = std::mem::zeroed();
                hdr.msg_hdr.msg_iov = &mut iovecs[i] as *mut _;
                hdr.msg_hdr.msg_iovlen = 1;
                hdr
            })
            .collect();

        // SAFETY: mmsghdr + iovec arrays are owned for the duration
        // of the call; pointers from `msgs.iter().as_ptr()` are
        // valid for `msg.len()` bytes (the slice's invariant).
        // MSG_DONTWAIT avoids blocking the executor thread.
        let n = unsafe {
            libc::sendmmsg(
                fd,
                mmsg.as_mut_ptr(),
                msgs.len() as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Verify each successful slot wrote the full input length;
        // partial writes shouldn't happen on netlink (datagram
        // semantics) but if they do, surface as WriteZero.
        for (i, slot) in mmsg.iter().enumerate().take(n as usize) {
            if slot.msg_len as usize != msgs[i].len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    format!(
                        "sendmmsg slot {i}: wrote {} of {} bytes",
                        slot.msg_len,
                        msgs[i].len()
                    ),
                ));
            }
        }
        Ok(n as usize)
    }
}

/// Build an `SCM_RIGHTS` control buffer carrying `fds`.
///
/// Returned as a `Vec<u64>` so the backing storage is 8-byte aligned
/// (the alignment `cmsghdr` requires); the `usize` is the valid
/// `msg_controllen` (`CMSG_SPACE`). Split out from
/// [`NetlinkSocket::send_with_fds`] so the on-wire control-message
/// layout is unit-testable without a live socket.
fn build_scm_rights_control(fds: &[RawFd]) -> (Vec<u64>, usize) {
    let fd_bytes = std::mem::size_of_val(fds);
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(fd_bytes as u32) } as usize;
    let mut buf = vec![0u64; space.div_ceil(std::mem::size_of::<u64>())];

    // A throwaway msghdr drives CMSG_FIRSTHDR / CMSG_DATA; it is never
    // sent — only used to compute the cmsg/data offsets into `buf`.
    let mut mhdr: libc::msghdr = unsafe { std::mem::zeroed() };
    mhdr.msg_control = buf.as_mut_ptr() as *mut libc::c_void;
    mhdr.msg_controllen = space as _;

    // SAFETY: `buf` is `space` bytes (rounded up to u64) and 8-byte
    // aligned; CMSG_FIRSTHDR returns a pointer within it, and we copy
    // exactly `fd_bytes` into the CMSG_DATA region which `CMSG_SPACE`
    // accounts for.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&mhdr);
        debug_assert!(!cmsg.is_null());
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr() as *const u8, libc::CMSG_DATA(cmsg), fd_bytes);
    }

    (buf, space)
}

/// Fetch-and-increment a sequence counter, skipping 0 (#134). Pulled out
/// of [`NetlinkSocket::next_seq`] so the wrap behavior is unit-testable
/// without opening a socket fd.
fn next_nonzero_seq(counter: &AtomicU32) -> u32 {
    loop {
        let s = counter.fetch_add(1, Ordering::Relaxed);
        if s != 0 {
            return s;
        }
    }
}

#[cfg(test)]
mod seq_tests {
    use super::*;

    #[test]
    fn next_seq_skips_zero_on_wrap() {
        // Seed just below wrap: u32::MAX is handed out, then the counter
        // is at 0 and must be skipped, yielding 1.
        let counter = AtomicU32::new(u32::MAX);
        assert_eq!(next_nonzero_seq(&counter), u32::MAX);
        assert_eq!(next_nonzero_seq(&counter), 1, "0 must be skipped");
        assert_eq!(next_nonzero_seq(&counter), 2);
    }

    #[test]
    fn next_seq_is_monotonic_from_one() {
        let counter = AtomicU32::new(1);
        assert_eq!(next_nonzero_seq(&counter), 1);
        assert_eq!(next_nonzero_seq(&counter), 2);
        assert_eq!(next_nonzero_seq(&counter), 3);
    }
}

#[cfg(test)]
mod dump_race_tests {
    use super::*;

    fn einval() -> std::io::Error {
        std::io::Error::from_raw_os_error(libc::EINVAL)
    }

    /// The `EINVAL` a finished dump leaves in `sk_err` is returned once and
    /// cleared; the datagram is still queued, so the next try gets it (#870).
    #[test]
    fn a_spurious_einval_is_retried() {
        let mut calls = 0;
        let got = past_dump_race(|| {
            calls += 1;
            if calls < 3 { Err(einval()) } else { Ok(calls) }
        });
        assert_eq!(got.unwrap(), 3);
    }

    /// An `EINVAL` that keeps coming is not the race: it surfaces.
    #[test]
    fn a_persistent_einval_surfaces() {
        let mut calls = 0;
        let got: std::io::Result<()> = past_dump_race(|| {
            calls += 1;
            Err(einval())
        });
        assert_eq!(got.unwrap_err().raw_os_error(), Some(libc::EINVAL));
        assert_eq!(calls, DUMP_RACE_RETRIES + 1);
    }

    #[test]
    fn other_errors_are_not_retried() {
        let mut calls = 0;
        let got: std::io::Result<()> = past_dump_race(|| {
            calls += 1;
            Err(std::io::Error::from_raw_os_error(libc::ENOBUFS))
        });
        assert_eq!(got.unwrap_err().raw_os_error(), Some(libc::ENOBUFS));
        assert_eq!(calls, 1);
    }
}

#[cfg(test)]
mod scm_rights_tests {
    use super::*;

    /// The control buffer must round-trip through `CMSG_FIRSTHDR` /
    /// `CMSG_DATA` with the SCM_RIGHTS level/type and the exact fd
    /// payload — this pins the on-wire cmsg layout.
    #[test]
    fn scm_rights_control_roundtrips_fds() {
        let fds = [7i32, 9, 11];
        let (mut buf, space) = build_scm_rights_control(&fds);

        let mut mhdr: libc::msghdr = unsafe { std::mem::zeroed() };
        mhdr.msg_control = buf.as_mut_ptr() as *mut libc::c_void;
        mhdr.msg_controllen = space as _;

        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&mhdr);
            assert!(!cmsg.is_null());
            assert_eq!((*cmsg).cmsg_level, libc::SOL_SOCKET);
            assert_eq!((*cmsg).cmsg_type, libc::SCM_RIGHTS);
            assert_eq!(
                (*cmsg).cmsg_len as usize,
                libc::CMSG_LEN((std::mem::size_of::<RawFd>() * fds.len()) as u32) as usize
            );
            let data = libc::CMSG_DATA(cmsg) as *const RawFd;
            for (i, &want) in fds.iter().enumerate() {
                assert_eq!(*data.add(i), want, "fd {i} mismatch");
            }
        }
    }

    /// Compile-time guard: the `send_with_fds` future must stay `Send`.
    /// The `msghdr`/`iovec` raw pointers are built inside the sync
    /// `try_io` closure precisely so they never cross the `.await`; if a
    /// refactor leaked one into the await-held state, this stops
    /// compiling. Never executed.
    #[allow(dead_code)]
    fn assert_send_with_fds_future_is_send(s: &NetlinkSocket) {
        fn assert_send<T: Send>(_: &T) {}
        let fut = s.send_with_fds(&[], &[]);
        assert_send(&fut);
    }

    #[test]
    fn scm_rights_control_single_fd() {
        let (mut buf, space) = build_scm_rights_control(&[42]);
        let mut mhdr: libc::msghdr = unsafe { std::mem::zeroed() };
        mhdr.msg_control = buf.as_mut_ptr() as *mut libc::c_void;
        mhdr.msg_controllen = space as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&mhdr);
            assert!(!cmsg.is_null());
            assert_eq!(*(libc::CMSG_DATA(cmsg) as *const RawFd), 42);
        }
    }
}

#[cfg(all(test, feature = "syscall_batch"))]
mod batch_tests {
    use super::*;

    #[test]
    fn batch_bufs_initialization_wires_iovecs() {
        let bufs = BatchBufs::new();
        assert_eq!(bufs.storage.len(), NL_BATCH_SIZE);
        assert_eq!(bufs.iovecs.len(), NL_BATCH_SIZE);
        assert_eq!(bufs.msgs.len(), NL_BATCH_SIZE);
        for i in 0..NL_BATCH_SIZE {
            assert_eq!(bufs.storage[i].len(), NL_BUF_SIZE);
            assert_eq!(bufs.iovecs[i].iov_len, NL_BUF_SIZE);
            assert_eq!(
                bufs.iovecs[i].iov_base as *const u8,
                bufs.storage[i].as_ptr()
            );
            // msg_iov should point at the i-th iovec.
            assert_eq!(
                bufs.msgs[i].msg_hdr.msg_iov as *const libc::iovec,
                &bufs.iovecs[i] as *const libc::iovec
            );
            assert_eq!(bufs.msgs[i].msg_hdr.msg_iovlen, 1);
        }
    }

    #[test]
    fn batch_bufs_prepare_resets_mutable_fields() {
        let mut bufs = BatchBufs::new();
        // Pretend a previous recvmmsg populated these.
        bufs.msgs[0].msg_len = 1234;
        bufs.msgs[0].msg_hdr.msg_flags = libc::MSG_TRUNC;
        bufs.msgs[5].msg_len = 567;
        bufs.prepare(8);
        assert_eq!(bufs.msgs[0].msg_len, 0);
        assert_eq!(bufs.msgs[0].msg_hdr.msg_flags, 0);
        assert_eq!(bufs.msgs[5].msg_len, 0);
    }
}

/// Plan 224 / #505 — receiving datagrams of any size. `usersock_pair`
/// queues them between two userspace netlink sockets, so no kernel
/// subsystem has to produce a large frame.
#[cfg(test)]
mod recv_msg_truncate_tests {
    use super::*;

    #[test]
    fn recv_msg_size_math() {
        // Sanity-check the constants — sane values.
        const _: () = assert!(RECV_INITIAL_CAPACITY <= RECV_MAX_CAPACITY);
        assert_eq!(RECV_INITIAL_CAPACITY, 32 * 1024);
        assert_eq!(RECV_MAX_CAPACITY, 1024 * 1024);
    }

    #[test]
    fn b19_backpressure_predicate_and_constant() {
        // Plan 232 B19 — the SEND_WOULDBLOCK_LIMIT constant is the
        // threshold past which back-to-back WouldBlocks surface
        // as Backpressure instead of looping into the 30s
        // connection timeout. Verify the constant is sane.
        assert_eq!(SEND_WOULDBLOCK_LIMIT, 32);

        let err = Error::from(crate::netlink::ErrorDetail::Backpressure {
            send_buffer_full: true,
        });
        assert!(err.is_backpressure());
        // Other errors must NOT match.
        assert!(!Error::timeout().is_backpressure());
    }

    /// A receiving socket and a sender, both `NETLINK_USERSOCK`: unicast
    /// between userspace ports needs no privilege, so a test can queue a
    /// datagram of any size without the kernel producing one.
    fn usersock_pair() -> (NetlinkSocket, Socket, SocketAddr) {
        let bound = || {
            let mut socket = Socket::new(protocols::NETLINK_USERSOCK).expect("usersock");
            let mut addr = SocketAddr::new(0, 0);
            socket.bind(&addr).expect("bind");
            socket.get_address(&mut addr).expect("address");
            (socket, addr)
        };
        let (rx, rx_addr) = bound();
        rx.set_non_blocking(true).expect("non-blocking");
        let pid = rx_addr.port_number();
        let rx = NetlinkSocket::from_raw_socket(rx, pid, Protocol::Route).expect("wrap");
        (rx, bound().0, SocketAddr::new(pid, 0))
    }

    /// #505: a datagram larger than the initial receive buffer was consumed
    /// by the `MSG_TRUNC` probe that measured it, and the retry read the
    /// *next* datagram. Every receive path must return it whole, in order.
    #[tokio::test]
    async fn a_datagram_past_the_initial_buffer_arrives_whole() {
        let (rx, tx, to) = usersock_pair();
        let big: Vec<u8> = (0..RECV_INITIAL_CAPACITY + 8192).map(|i| i as u8).collect();
        let small = vec![0xcd; 64];
        for _ in 0..3 {
            tx.send_to(&big, &to, 0).expect("send big");
            tx.send_to(&small, &to, 0).expect("send small");
        }

        let (got, multicast) = rx.recv_msg_from().await.expect("recv_msg_from");
        assert!(!multicast);
        assert!(got == big, "recv_msg_from: got {} bytes", got.len());
        assert_eq!(rx.recv_msg_from().await.expect("small").0, small);

        let got = rx.try_recv_msg().expect("try_recv_msg").expect("queued");
        assert!(got == big, "try_recv_msg: got {} bytes", got.len());
        assert_eq!(rx.try_recv_msg().expect("small"), Some(small.clone()));

        let got = std::future::poll_fn(|cx| rx.poll_recv(cx))
            .await
            .expect("poll_recv");
        assert!(got == big, "poll_recv: got {} bytes", got.len());
        let got = std::future::poll_fn(|cx| rx.poll_recv(cx)).await;
        assert_eq!(got.expect("small"), small);
    }

    /// A datagram past the cap is dropped and reported; the one behind it
    /// is still there (#505).
    #[tokio::test]
    async fn a_datagram_past_the_cap_is_reported_and_the_next_survives() {
        let (rx, tx, to) = usersock_pair();
        let cap = RECV_INITIAL_CAPACITY + 4096;
        tx.send_to(&vec![1u8; cap + 1], &to, 0).expect("send big");
        tx.send_to(&[2u8; 16], &to, 0).expect("send small");
        let socket = rx.fd.get_ref();
        match recv_whole_capped(socket, 0, cap).expect("recv") {
            RecvWhole::TooLarge(len) => assert_eq!(len, cap + 1),
            RecvWhole::Frame(data, _) => panic!("got a {}-byte frame past the cap", data.len()),
        }
        match recv_whole_capped(socket, 0, cap).expect("recv") {
            RecvWhole::Frame(data, _) => assert_eq!(data, [2u8; 16]),
            RecvWhole::TooLarge(len) => panic!("next datagram reported as {len} bytes"),
        }
    }

    /// #510: `AsyncFd::new` panics outside a tokio runtime; `new()` returns
    /// a `Result` and now says why instead.
    #[test]
    fn a_socket_outside_a_runtime_is_an_error_not_a_panic() {
        let err = NetlinkSocket::new(Protocol::Route)
            .err()
            .expect("no runtime here");
        assert!(err.to_string().contains("tokio runtime"), "{err}");
    }

    #[test]
    fn frame_truncated_predicate() {
        // Construct the error variant directly and assert the
        // predicate matches.
        let err = Error::from(crate::netlink::ErrorDetail::FrameTruncated {
            received: 2_000_000,
            buffer_size: RECV_MAX_CAPACITY,
        });
        assert!(err.is_truncated());
        // Non-truncated errors must NOT match.
        let other = Error::timeout();
        assert!(!other.is_truncated());
        let other2 = Error::from(crate::netlink::ErrorDetail::Truncated {
            expected: 8,
            actual: 4,
        });
        // The pre-existing parser-short-buffer `Truncated`
        // variant has a different semantic; `is_truncated()`
        // surfaces frame-truncation specifically.
        assert!(!other2.is_truncated());
    }
}

/// Multicast groups for NETLINK_ROUTE.
pub mod rtnetlink_groups {
    pub const RTNLGRP_LINK: u32 = 1;
    pub const RTNLGRP_NOTIFY: u32 = 2;
    pub const RTNLGRP_NEIGH: u32 = 3;
    pub const RTNLGRP_TC: u32 = 4;
    pub const RTNLGRP_IPV4_IFADDR: u32 = 5;
    pub const RTNLGRP_IPV4_MROUTE: u32 = 6;
    pub const RTNLGRP_IPV4_ROUTE: u32 = 7;
    pub const RTNLGRP_IPV4_RULE: u32 = 8;
    pub const RTNLGRP_IPV6_IFADDR: u32 = 9;
    pub const RTNLGRP_IPV6_MROUTE: u32 = 10;
    pub const RTNLGRP_IPV6_ROUTE: u32 = 11;
    pub const RTNLGRP_IPV6_IFINFO: u32 = 12;
    pub const RTNLGRP_IPV6_PREFIX: u32 = 18;
    pub const RTNLGRP_IPV6_RULE: u32 = 19;
    pub const RTNLGRP_IPV4_NETCONF: u32 = 24;
    pub const RTNLGRP_IPV6_NETCONF: u32 = 25;
    pub const RTNLGRP_MDB: u32 = 26;
    pub const RTNLGRP_NSID: u32 = 28;
    pub const RTNLGRP_NEXTHOP: u32 = 32;
    pub const RTNLGRP_BRVLAN: u32 = 33;
}
