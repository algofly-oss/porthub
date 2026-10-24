//! [`NetnsCommand`]: a process spawned in a network namespace, with what a
//! lab needs around it (#521) — an `/etc/netns` overlay policy, the user to
//! run as once inside, the cgroup to start in, a VRF to bind its sockets to
//! (`ip vrf exec`, #257), and a parent-death signal.
//!
//! ```no_run
//! # fn example() -> nlink::Result<()> {
//! use std::process::Command;
//! use nlink::netlink::namespace::{NetnsCommand, Overlay, SpawnUser};
//!
//! let mut cmd = Command::new("dnsmasq");
//! cmd.arg("--keep-in-foreground");
//! let child = NetnsCommand::new("lab-r1", cmd)?
//!     .etc_overlay(Overlay::BestEffort)
//!     .cgroup("/sys/fs/cgroup/lab/r1")
//!     .user(SpawnUser::new(1000, 1000))
//!     .pdeathsig(libc::SIGTERM)
//!     .spawn()?;
//! # let _ = child;
//! # Ok(())
//! # }
//! ```

use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};

use super::{SpawnUser, live_named_path, open_path, path_to_cstring, prepare_etc_binds, sysfs_mount_flags};
use crate::{Error, Result};

/// What a spawned process gets of `/etc/netns/<name>/` (#521), the files
/// `ip netns exec` binds over `/etc` in a private mount namespace, with a
/// `/sys` remounted for the namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Overlay {
    /// No mount namespace: the host's `/etc` and `/sys`, as
    /// [`spawn`](super::spawn) gives.
    #[default]
    Off,
    /// The overlay, or the spawn fails: [`spawn_with_etc`](super::spawn_with_etc)'s
    /// rules. An overlay the caller set up and did not get is an error.
    Strict,
    /// The overlay where the environment allows it, and never a failure
    /// for want of it.
    ///
    /// - A container runtime that refuses the private mount namespace
    ///   (`unshare(CLONE_NEWNS)`) or its `MS_SLAVE` remount leaves the
    ///   process with the host's `/etc` and `/sys`: nothing is bound into a
    ///   mount tree that propagates to the host.
    /// - The namespace's sysfs is mounted on top of `/sys`, not in place of
    ///   it. Strict detaches the old one first, and a kernel that then
    ///   refuses the new one — in a user namespace once no sysfs is fully
    ///   visible — would leave no `/sys`, so Strict fails there. On top,
    ///   a refused mount leaves the old `/sys`, stale but present.
    /// - A file whose bind is refused is left out.
    BestEffort,
}

/// A process spawned in a network namespace (#521). See the
/// [module docs](self).
#[derive(Debug)]
#[must_use = "a command does nothing until spawned"]
pub struct NetnsCommand {
    ns_fd: OwnedFd,
    /// The `ip netns` name, for `/etc/netns/<name>/`.
    name: Option<String>,
    cmd: Command,
    overlay: Overlay,
    user: Option<SpawnUser>,
    cgroup: Option<PathBuf>,
    vrf: Option<String>,
    pdeathsig: Option<libc::c_int>,
    exit_status_file: Option<PathBuf>,
}

/// What [`NetnsCommand::prepare`] keeps open until the spawn returns; the
/// namespace fd stays in the command itself.
struct KeepOpen {
    _cgroup: Option<std::fs::File>,
}

#[nlink_macros::send_futures]
impl NetnsCommand {
    /// `cmd`, to run in the namespace `ip netns` knows as `name`.
    pub fn new(name: &str, cmd: Command) -> Result<Self> {
        let path = live_named_path(name)?;
        Ok(Self::with_fd(OwnedFd::from(open_path(&path)?.file), Some(name.to_string()), cmd))
    }

    /// `cmd`, to run in the namespace at `path` (an nsfs file, such as
    /// `/proc/<pid>/ns/net`). It has no `/etc/netns` overlay to give.
    pub fn path(path: impl AsRef<Path>, cmd: Command) -> Result<Self> {
        Ok(Self::with_fd(OwnedFd::from(open_path(path.as_ref())?.file), None, cmd))
    }

    pub(crate) fn with_fd(ns_fd: OwnedFd, name: Option<String>, cmd: Command) -> Self {
        Self {
            ns_fd,
            name,
            cmd,
            overlay: Overlay::Off,
            user: None,
            cgroup: None,
            vrf: None,
            pdeathsig: None,
            exit_status_file: None,
        }
    }

    /// The `/etc/netns/<name>/` overlay policy; [`Overlay::Off`] by
    /// default. A namespace with no name has no overlay to give.
    pub fn etc_overlay(mut self, overlay: Overlay) -> Self {
        self.overlay = overlay;
        self
    }

    /// Run as `user`, dropped to once inside the namespace and its mounts.
    /// `CommandExt::uid` cannot do this: std applies it before the
    /// `setns`, which then fails with `EPERM`.
    pub fn user(mut self, user: SpawnUser) -> Self {
        self.user = Some(user);
        self
    }

    /// Start the process in the cgroup (v2) at `dir`: it joins before it
    /// enters the namespace, so the processes it starts are in the cgroup
    /// from the first. Writing the pid after the spawn let them escape the
    /// limits.
    pub fn cgroup(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cgroup = Some(dir.into());
        self
    }

    /// Bind every inet socket the process opens to the VRF device `name`
    /// in its namespace, as `ip vrf exec` does (#257): a
    /// `BPF_PROG_TYPE_CGROUP_SOCK` program that sets the socket's
    /// `bound_dev_if` is attached to the process's cgroup at
    /// `BPF_CGROUP_INET_SOCK_CREATE`, so its routes come from the VRF's
    /// table, and so do its children's.
    ///
    /// The cgroup is the one given with [`cgroup`](Self::cgroup), or by
    /// default `vrf/<netns inode>/<name>` under this process's own cgroup
    /// (iproute2 uses `vrf/<name>`; the namespace keeps two `red` VRFs
    /// apart), created if it is missing and left for the next exec. Needs
    /// cgroup v2, `CAP_SYS_ADMIN` and `CAP_BPF` (or root) in the initial
    /// user namespace.
    pub fn vrf(mut self, name: impl Into<String>) -> Self {
        self.vrf = Some(name.into());
        self
    }

    /// The signal the process gets when the thread that spawned it ends
    /// (`PR_SET_PDEATHSIG`) — the thread, not the process.
    pub fn pdeathsig(mut self, signal: libc::c_int) -> Self {
        self.pdeathsig = Some(signal);
        self
    }

    /// Run it detached from the caller (#521), and return its pid: a double
    /// fork, so it is no child of the caller's and never needs reaping —
    /// a lab's long-running processes, which outlive whoever started them.
    ///
    /// - With [`exit_status_file`](Self::exit_status_file), a monitor
    ///   process stays its parent, waits for it, and writes its exit code
    ///   to the file — `128 + n` for a death by signal `n`, as a shell
    ///   reports it — when it ends.
    /// - Its stdin, stdout and stderr are `/dev/null`: a detached process
    ///   has no one to read them. Redirect inside the command (`sh -c '…
    ///   > log'`) for its output.
    /// - The program is found on `PATH` here, before the fork. The
    ///   command's environment changes and working directory apply;
    ///   `Command::env_clear` cannot be seen, and does not.
    /// - [`pdeathsig`](Self::pdeathsig) does not apply: its parent is the
    ///   monitor, or init.
    ///
    /// A failure to start it — the namespace, the overlay, the cgroup,
    /// the user, the exec — is the error returned here.
    pub fn spawn_detached(mut self) -> Result<u32> {
        use std::os::unix::ffi::OsStrExt;
        let (prepared, keep) = self.prepare()?;
        let program = resolve_program(&self.cmd)?;
        let argv: Vec<CString> = std::iter::once(self.cmd.get_program())
            .chain(self.cmd.get_args())
            .map(|a| CString::new(a.as_bytes()))
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| Error::invalid_message("null byte in an argument"))?;
        let mut env: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> = std::env::vars_os().collect();
        for (k, v) in self.cmd.get_envs() {
            match v {
                Some(v) => env.insert(k.to_owned(), v.to_owned()),
                None => env.remove(k),
            };
        }
        let envp: Vec<CString> = env
            .iter()
            .map(|(k, v)| CString::new([k.as_bytes(), b"=", v.as_bytes()].concat()))
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| Error::invalid_message("null byte in the environment"))?;
        let cwd = match self.cmd.get_current_dir() {
            Some(dir) => Some(path_to_cstring(dir)?),
            None => None,
        };
        let status_file = match &self.exit_status_file {
            Some(path) => Some(path_to_cstring(path)?),
            None => None,
        };
        let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());
        let mut envp_ptrs: Vec<*const libc::c_char> = envp.iter().map(|e| e.as_ptr()).collect();
        envp_ptrs.push(std::ptr::null());
        let devnull = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(Error::from)?;
        let devnull_raw = devnull.as_raw_fd();

        // The report pipe: tagged 5-byte messages, each atomic — `P` and
        // the pid, `E` and the errno of a failed start. Close-on-exec, so a
        // successful exec closes the command's end.
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: pipe2 fills `fds` with two new descriptors.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(Error::from(std::io::Error::last_os_error()));
        }
        let (rd, wr) = (fds[0], fds[1]);

        // SAFETY: after each fork only async-signal-safe calls run, on
        // what was built above; every path ends in execve or _exit, so no
        // destructor or allocator runs in a child.
        let first = unsafe { libc::fork() };
        if first < 0 {
            let e = std::io::Error::last_os_error();
            unsafe {
                libc::close(rd);
                libc::close(wr);
            }
            return Err(Error::from(e));
        }
        if first == 0 {
            unsafe {
                libc::close(rd);
                libc::setsid();
                let start = |wr: libc::c_int| -> ! {
                    // The command: its setup, then the exec.
                    if let Err(e) = prepared.enter_detached() {
                        report(wr, b'E', e.raw_os_error().unwrap_or(libc::EIO) as u32);
                        libc::_exit(127);
                    }
                    libc::dup2(devnull_raw, 0);
                    libc::dup2(devnull_raw, 1);
                    libc::dup2(devnull_raw, 2);
                    if let Some(dir) = &cwd
                        && libc::chdir(dir.as_ptr()) != 0
                    {
                        report(wr, b'E', *libc::__errno_location() as u32);
                        libc::_exit(127);
                    }
                    libc::execve(program.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
                    report(wr, b'E', *libc::__errno_location() as u32);
                    libc::_exit(127)
                };
                let pid = libc::fork();
                if pid < 0 {
                    report(wr, b'E', *libc::__errno_location() as u32);
                    libc::_exit(1);
                }
                if pid == 0 {
                    match &status_file {
                        None => start(wr),
                        Some(path) => {
                            // The monitor: the command's parent, which
                            // writes its exit code when it ends.
                            let cmd = libc::fork();
                            if cmd < 0 {
                                report(wr, b'E', *libc::__errno_location() as u32);
                                libc::_exit(1);
                            }
                            if cmd == 0 {
                                start(wr);
                            }
                            report(wr, b'P', cmd as u32);
                            libc::close(wr);
                            let mut status = 0;
                            while libc::waitpid(cmd, &mut status, 0) < 0 && *libc::__errno_location() == libc::EINTR {}
                            let code = if libc::WIFEXITED(status) {
                                libc::WEXITSTATUS(status)
                            } else {
                                128 + libc::WTERMSIG(status)
                            };
                            write_exit_code(path, code);
                            libc::_exit(0);
                        }
                    }
                }
                if status_file.is_none() {
                    report(wr, b'P', pid as u32);
                }
                libc::_exit(0);
            }
        }

        // The caller: reap the first child, then read the report to EOF.
        unsafe { libc::close(wr) };
        let mut status = 0;
        // SAFETY: `first` is our child.
        while unsafe { libc::waitpid(first, &mut status, 0) } < 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
        {}
        let mut report = Vec::new();
        {
            use std::io::Read;
            // SAFETY: `rd` is ours, and the File closes it.
            let mut file = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(rd) };
            file.read_to_end(&mut report).map_err(Error::from)?;
        }
        drop(keep);
        drop(devnull);
        let (pid, errno) = parse_report(&report);
        match (pid, errno) {
            (_, Some(errno)) => Err(Error::from(std::io::Error::from_raw_os_error(errno as i32))),
            (Some(pid), None) => Ok(pid),
            (None, None) => Err(Error::invalid_message("the detached spawn reported no pid")),
        }
    }

    /// With [`spawn_detached`](Self::spawn_detached), write the process's
    /// exit code to `path` when it ends.
    pub fn exit_status_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.exit_status_file = Some(path.into());
        self
    }

    /// Spawn it.
    pub fn spawn(mut self) -> Result<Child> {
        let (prepared, keep) = self.prepare()?;
        self.install(prepared);
        let child = self.cmd.spawn().map_err(Error::from);
        drop(keep);
        child
    }

    /// Run it to completion and collect its output.
    pub fn output(mut self) -> Result<Output> {
        let (prepared, keep) = self.prepare()?;
        self.install(prepared);
        let output = self.cmd.output().map_err(Error::from);
        drop(keep);
        output
    }

    /// Spawn it as a tokio child process (#521), to `.wait().await` on.
    #[cfg(feature = "process")]
    pub fn spawn_tokio(mut self) -> Result<tokio::process::Child> {
        let (prepared, keep) = self.prepare()?;
        self.install(prepared);
        let child = tokio::process::Command::from(self.cmd).spawn().map_err(Error::from);
        drop(keep);
        child
    }

    /// Run it to completion and collect its output, without blocking the
    /// runtime's thread (#521).
    #[cfg(feature = "process")]
    pub async fn output_async(mut self) -> Result<Output> {
        let (prepared, keep) = self.prepare()?;
        self.install(prepared);
        let output = tokio::process::Command::from(self.cmd).output().await.map_err(Error::from);
        drop(keep);
        output
    }

    /// Register the child's setup on the command.
    fn install(&mut self, prepared: Prepared) {
        // SAFETY: `enter` runs raw syscalls only, on data computed
        // before the fork; nothing allocates.
        unsafe {
            self.cmd.pre_exec(move || prepared.enter());
        }
    }

    /// Compute everything the child does between `fork` and `exec`.
    fn prepare(&mut self) -> Result<(Prepared, KeepOpen)> {
        let binds = match (self.overlay, &self.name) {
            (Overlay::Off, _) => Vec::new(),
            (_, Some(name)) => prepare_etc_binds(name)?,
            (_, None) => {
                return Err(Error::invalid_message(
                    "an /etc/netns overlay needs a namespace opened by name",
                ));
            }
        };
        if let Some(vrf) = &self.vrf {
            use std::os::fd::AsFd;
            let ifindex = super::vrf_exec::ifindex_in(self.ns_fd.as_fd(), vrf)?;
            let dir = match &self.cgroup {
                Some(dir) => dir.clone(),
                None => super::vrf_exec::default_cgroup(self.ns_fd.as_fd(), vrf)?,
            };
            super::vrf_exec::bind_sockets(&dir, ifindex)?;
            self.cgroup = Some(dir);
        }
        let cgroup = match &self.cgroup {
            Some(dir) => Some(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(dir.join("cgroup.procs"))
                    .map_err(|e| Error::from(e).with_context(format!("cgroup {}", dir.display())))?,
            ),
            None => None,
        };
        let prepared = Prepared {
            ns_raw: self.ns_fd.as_raw_fd(),
            cgroup_raw: cgroup.as_ref().map(|f| f.as_raw_fd()),
            pdeathsig: self.pdeathsig,
            strict: self.overlay == Overlay::Strict,
            binds,
            ns_name: CString::new(self.name.clone().unwrap_or_default())
                .map_err(|_| Error::invalid_message("null byte in namespace name"))?,
            c_root: path_to_cstring(Path::new("/"))?,
            c_none: CString::new("none").expect("no null byte"),
            c_sys: path_to_cstring(Path::new("/sys"))?,
            c_sysfs: CString::new("sysfs").expect("no null byte"),
            user: self
                .user
                .as_ref()
                .map(|u| (u.uid, u.gid, u.groups.iter().map(|g| *g as libc::gid_t).collect())),
        };
        Ok((prepared, KeepOpen { _cgroup: cgroup }))
    }
}

/// What the child does between `fork` and `exec`, computed before the
/// fork.
struct Prepared {
    ns_raw: RawFd,
    cgroup_raw: Option<RawFd>,
    pdeathsig: Option<libc::c_int>,
    strict: bool,
    binds: Vec<(CString, CString)>,
    ns_name: CString,
    c_root: CString,
    c_none: CString,
    c_sys: CString,
    c_sysfs: CString,
    user: Option<(u32, u32, Vec<libc::gid_t>)>,
}

impl Prepared {
    /// The child's setup: the cgroup, the parent-death signal, the
    /// namespace, the overlay and the user, in that order. Raw syscalls
    /// only.
    fn enter(&self) -> std::io::Result<()> {
        if let Some(sig) = self.pdeathsig {
            // SAFETY: a raw syscall.
            if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, sig as libc::c_ulong, 0, 0, 0) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        self.enter_detached()
    }

    /// [`enter`](Self::enter) without the parent-death signal, which a
    /// detached process does not take.
    fn enter_detached(&self) -> std::io::Result<()> {
        let err = std::io::Error::last_os_error;
        // SAFETY: raw syscalls only, on fds and CStrings that outlive the
        // fork in the parent.
        unsafe {
            // The cgroup first, so everything after is in it.
            if let Some(fd) = self.cgroup_raw
                && libc::write(fd, b"0".as_ptr().cast(), 1) != 1
            {
                return Err(err());
            }
            if libc::setns(self.ns_raw, libc::CLONE_NEWNET) != 0 {
                return Err(err());
            }
            self.overlay()?;
            if let Some((uid, gid, groups)) = &self.user
                && (libc::setgroups(groups.len(), groups.as_ptr()) != 0
                    || libc::setgid(*gid) != 0
                    || libc::setuid(*uid) != 0)
            {
                return Err(err());
            }
        }
        Ok(())
    }

    /// The `/etc/netns` overlay, by the policy.
    unsafe fn overlay(&self) -> std::io::Result<()> {
        let err = std::io::Error::last_os_error;
        if self.binds.is_empty() {
            return Ok(());
        }
        // SAFETY (all below): raw syscalls on CStrings built before the
        // fork.
        unsafe {
            // A private mount namespace, its tree a slave of the host's.
            // Refused, best effort runs with the host's /etc: a bind into a
            // tree that propagates would reach the host.
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return if self.strict { Err(err()) } else { Ok(()) };
            }
            if libc::mount(
                self.c_none.as_ptr(),
                self.c_root.as_ptr(),
                std::ptr::null(),
                libc::MS_SLAVE | libc::MS_REC,
                std::ptr::null(),
            ) != 0
            {
                return if self.strict { Err(err()) } else { Ok(()) };
            }
            // `/sys` for the namespace, as `spawn_with_etc` does it (#282,
            // #334): never none, never refused over a stale one. Best
            // effort mounts it on top instead of detaching first, so a
            // refused mount can only leave the old one.
            let detached = self.strict && libc::umount2(self.c_sys.as_ptr(), libc::MNT_DETACH) == 0;
            let mut flags: libc::c_ulong = 0;
            if !detached {
                let mut st: libc::statfs64 = std::mem::zeroed();
                if libc::statfs64(self.c_sys.as_ptr(), &mut st) == 0 {
                    flags = sysfs_mount_flags(st.f_flags as libc::c_ulong);
                }
            }
            if libc::mount(
                self.ns_name.as_ptr(),
                self.c_sys.as_ptr(),
                self.c_sysfs.as_ptr(),
                flags,
                std::ptr::null(),
            ) != 0
                && detached
            {
                return Err(err());
            }
            for (src, dst) in &self.binds {
                if libc::mount(src.as_ptr(), dst.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) != 0
                    && self.strict
                {
                    return Err(err());
                }
            }
        }
        Ok(())
    }
}

/// The program to exec: the command's, found on its `PATH` when it names
/// no directory.
fn resolve_program(cmd: &Command) -> Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    let program = Path::new(cmd.get_program());
    if program.as_os_str().as_bytes().contains(&b'/') {
        return path_to_cstring(program);
    }
    let path = cmd
        .get_envs()
        .find(|(k, _)| *k == "PATH")
        .and_then(|(_, v)| v.map(|v| v.to_owned()))
        .or_else(|| std::env::var_os("PATH"))
        .unwrap_or_else(|| "/usr/bin:/bin".into());
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(candidate).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
        .ok_or_else(|| {
            Error::from(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{} not found on PATH", program.display()),
            ))
        })
        .and_then(|found| path_to_cstring(&found))
}

/// Write a tagged report to the pipe: async-signal-safe.
unsafe fn report(fd: libc::c_int, tag: u8, value: u32) {
    let b = value.to_ne_bytes();
    let msg = [tag, b[0], b[1], b[2], b[3]];
    // SAFETY: a raw write of five bytes, atomic on a pipe.
    unsafe {
        libc::write(fd, msg.as_ptr().cast(), msg.len());
    }
}

/// Write `code` and a newline to `path`, replacing it: async-signal-safe.
unsafe fn write_exit_code(path: &CString, code: libc::c_int) {
    let mut buf = [0u8; 16];
    let mut n = buf.len() - 1;
    buf[n] = b'\n';
    let mut v = code.unsigned_abs();
    loop {
        n -= 1;
        buf[n] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    // SAFETY: open, write and close are raw syscalls.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC, 0o644);
        if fd >= 0 {
            libc::write(fd, buf[n..].as_ptr().cast(), buf.len() - n);
            libc::close(fd);
        }
    }
}

/// The pid and the errno in a detached spawn's report.
fn parse_report(report: &[u8]) -> (Option<u32>, Option<u32>) {
    let (mut pid, mut errno) = (None, None);
    let (messages, _) = report.as_chunks::<5>();
    for m in messages {
        let value = u32::from_ne_bytes([m[1], m[2], m[3], m[4]]);
        match m[0] {
            b'P' => pid = Some(value),
            b'E' => errno = Some(value),
            _ => {}
        }
    }
    (pid, errno)
}

/// Whether [`Overlay::Strict`] can work here (#521): a private mount
/// namespace (`unshare(CLONE_NEWNS)`) and its `MS_SLAVE` remount, which
/// container runtimes commonly deny, a fresh sysfs in place of `/sys`,
/// which a rootless container's user namespace refuses, and a bind over
/// `/etc`. Probed once, by a child that does all of it in a mount namespace
/// of its own and exits. Where it is false, [`Overlay::BestEffort`] gives
/// what the environment allows.
pub fn etc_overlay_supported() -> bool {
    static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        let c_root = CString::new("/").expect("no null byte");
        let c_none = CString::new("none").expect("no null byte");
        let c_sys = CString::new("/sys").expect("no null byte");
        let c_sysfs = CString::new("sysfs").expect("no null byte");
        let c_etc = CString::new("/etc").expect("no null byte");
        let mut cmd = Command::new("true");
        // SAFETY: raw syscalls only, on CStrings made before the fork.
        unsafe {
            cmd.pre_exec(move || {
                let err = std::io::Error::last_os_error;
                if libc::unshare(libc::CLONE_NEWNS) != 0
                    || libc::mount(
                        c_none.as_ptr(),
                        c_root.as_ptr(),
                        std::ptr::null(),
                        libc::MS_SLAVE | libc::MS_REC,
                        std::ptr::null(),
                    ) != 0
                {
                    return Err(err());
                }
                // Strict's `/sys` step: detach, then mount afresh.
                let detached = libc::umount2(c_sys.as_ptr(), libc::MNT_DETACH) == 0;
                let mut flags: libc::c_ulong = 0;
                if !detached {
                    let mut st: libc::statfs64 = std::mem::zeroed();
                    if libc::statfs64(c_sys.as_ptr(), &mut st) == 0 {
                        flags = sysfs_mount_flags(st.f_flags as libc::c_ulong);
                    }
                }
                if libc::mount(c_sysfs.as_ptr(), c_sys.as_ptr(), c_sysfs.as_ptr(), flags, std::ptr::null()) != 0
                    && detached
                {
                    return Err(err());
                }
                if libc::mount(c_etc.as_ptr(), c_etc.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) != 0 {
                    return Err(err());
                }
                Ok(())
            });
        }
        cmd.status().is_ok_and(|s| s.success())
    })
}
