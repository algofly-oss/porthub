//! Socket → process attribution (#162).
//!
//! sock_diag deliberately reports no PID — a socket can be shared by
//! any number of processes — so every `ss -p`-style consumer ends up
//! re-implementing the same `/proc/<pid>/fd/*` → `socket:[inode]`
//! scan. [`SocketOwnerMap`] is that scan, done once and amortized:
//! build it once per poll cycle, then join each
//! [`InetSocket::inode`](super::InetSocket) (or any other socket
//! type's inode) against it.
//!
//! [`CgroupPathMap`] is the companion join for
//! [`InetSocket::cgroup_id`](super::InetSocket): it maps the kernel's
//! cgroup v2 ID (the cgroup directory's inode on the unified
//! hierarchy) back to its `/sys/fs/cgroup` path, from which systemd
//! units / container IDs are derivable.
//!
//! # PID reuse
//!
//! A bare PID is not a stable identity — PIDs recycle. Every
//! [`ProcessRef`] therefore carries `start_time` (field 22 of
//! `/proc/<pid>/stat`, in clock ticks since boot): the pair
//! `(pid, start_time)` is unique for the machine's uptime. Consumers
//! keying long-lived state by process MUST use the pair, not the PID.
//!
//! # Snapshot semantics (expected races)
//!
//! Both maps are point-in-time snapshots:
//!
//! - Sockets opened and closed between scans are invisible — the
//!   short-flow miss is inherent to polling. Kernel 6.5+ BPF socket
//!   iterators are the race-free successor; this module is the
//!   unprivileged baseline.
//! - A process may exit between the sock_diag dump and the `/proc`
//!   scan (or vice versa); such sockets simply resolve to no owner.
//! - Unreadable `/proc/<pid>/fd` directories (other users' processes
//!   when unprivileged) are silently skipped, matching `ss(8)`.
//!   Run privileged for whole-system attribution.
//!
//! # Namespaces
//!
//! `/proc` is read in the **calling process's** PID+mount namespace.
//! For containers, pass the container's proc mount (e.g. a bind-mount
//! or `/proc/<init-pid>/root/proc`) to
//! [`SocketOwnerMap::scan_with_root`]. Socket inodes are global —
//! they join correctly across network namespaces; it's the *process*
//! view that `proc_root` selects.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, SockDiag};
//! use nlink::sockdiag::{SocketOwnerMap, CgroupPathMap};
//!
//! let conn = Connection::<SockDiag>::new()?;
//! let sockets = conn.query_tcp().await?;
//! let owners = SocketOwnerMap::scan();          // one /proc walk
//! let cgroups = CgroupPathMap::scan();          // one cgroupfs walk
//! for s in &sockets {
//!     for p in owners.resolve(s.inode) {
//!         println!("{}:{} -> {} (pid {}, started {})",
//!             s.local.ip(), s.local.port(), p.comm, p.pid, p.start_time);
//!     }
//!     if let Some(path) = s.cgroup_id.and_then(|id| cgroups.resolve(id)) {
//!         println!("  cgroup: {}", path.display());
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

/// One process holding a socket open, identified stably.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRef {
    /// Process ID at scan time. Not a stable identity on its own —
    /// pair with [`start_time`](Self::start_time) (PID reuse).
    pub pid: i32,
    /// Process start time in clock ticks since boot (`/proc/<pid>/stat`
    /// field 22). `(pid, start_time)` is unique for the uptime of the
    /// machine. `0` if the stat file couldn't be read (process exited
    /// mid-scan).
    pub start_time: u64,
    /// Executable name (`/proc/<pid>/comm`, kernel-truncated to 15
    /// bytes). `"?"` if unreadable.
    pub comm: String,
    /// File-descriptor number the socket is held through.
    pub fd: i32,
}

/// Amortized socket-inode → owning-processes map (one `/proc` walk).
///
/// See the [module docs](self) for snapshot/race semantics.
#[derive(Debug, Default)]
pub struct SocketOwnerMap {
    map: HashMap<u32, Vec<ProcessRef>>,
}

impl SocketOwnerMap {
    /// Empty map (no scan). Useful as the "attribution disabled"
    /// value and for building maps from non-`/proc` sources in tests.
    pub fn new() -> Self {
        Self::default()
    }

    /// Walk `/proc` and build the map. Best-effort and unprivileged:
    /// unreadable processes are skipped silently.
    pub fn scan() -> Self {
        Self::scan_with_root("/proc")
    }

    /// Like [`scan`](Self::scan) against an alternative proc mount —
    /// for containers / foreign PID namespaces (e.g.
    /// `/proc/<init-pid>/root/proc`).
    pub fn scan_with_root(proc_root: impl AsRef<Path>) -> Self {
        let proc_root = proc_root.as_ref();
        let mut map: HashMap<u32, Vec<ProcessRef>> = HashMap::new();

        let Ok(proc_dir) = fs::read_dir(proc_root) else {
            return Self { map };
        };

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(pid) = name.parse::<i32>() else {
                continue; // non-PID entries like "self", "meminfo"
            };

            let pid_dir = proc_root.join(name);
            let Ok(fds) = fs::read_dir(pid_dir.join("fd")) else {
                continue; // permission denied / process gone
            };

            // comm + start_time read lazily, once per process that
            // actually owns a socket.
            let mut identity: Option<(String, u64)> = None;
            for fd_entry in fds.flatten() {
                let Ok(target) = fs::read_link(fd_entry.path()) else {
                    continue;
                };
                let Some(target) = target.to_str() else {
                    continue;
                };
                // Targets look like "socket:[12345]".
                let Some(inode) = parse_socket_inode(target) else {
                    continue;
                };
                let fd = fd_entry
                    .file_name()
                    .to_str()
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(-1);

                let (comm, start_time) = identity.get_or_insert_with(|| {
                    (read_comm(&pid_dir), read_start_time(&pid_dir))
                });
                map.entry(inode).or_default().push(ProcessRef {
                    pid,
                    start_time: *start_time,
                    comm: comm.clone(),
                    fd,
                });
            }
        }

        Self { map }
    }

    /// Processes holding the socket with this inode open. Empty when
    /// unknown (socket closed, process unreadable, or opened after
    /// the scan).
    pub fn resolve(&self, inode: u32) -> &[ProcessRef] {
        self.map.get(&inode).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Number of distinct socket inodes attributed.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` if the scan attributed no sockets at all.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Iterate over `(inode, owners)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &[ProcessRef])> {
        self.map.iter().map(|(k, v)| (*k, v.as_slice()))
    }

    /// Record an owner for an inode manually — for tests and for
    /// merging attribution from sources other than the `/proc` walk
    /// (e.g. a BPF iterator feed).
    pub fn insert(&mut self, inode: u32, owner: ProcessRef) {
        self.map.entry(inode).or_default().push(owner);
    }
}

/// cgroup-v2 ID → cgroup path map (one `/sys/fs/cgroup` walk).
///
/// On the unified (v2) hierarchy the kernel's `cgroup_id` — what
/// sock_diag reports as `INET_DIAG_CGROUP_ID` — is the cgroup
/// directory's inode number, so a recursive walk recording
/// `inode → path` inverts it. v1 hierarchies are not supported (their
/// IDs don't correspond to cgroupfs inodes); on a v1-only host every
/// lookup misses.
#[derive(Debug, Default)]
pub struct CgroupPathMap {
    map: HashMap<u64, PathBuf>,
    root: PathBuf,
}

impl CgroupPathMap {
    /// Walk `/sys/fs/cgroup` and build the map. Best-effort:
    /// unreadable subtrees are skipped.
    pub fn scan() -> Self {
        Self::scan_with_root("/sys/fs/cgroup")
    }

    /// Like [`scan`](Self::scan) against an alternative cgroupfs
    /// mount.
    pub fn scan_with_root(root: impl AsRef<Path>) -> Self {
        use std::os::unix::fs::MetadataExt;

        let root = root.as_ref().to_path_buf();
        let mut map = HashMap::new();
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            if let Ok(meta) = fs::metadata(&dir) {
                map.insert(meta.ino(), dir.clone());
            }
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                // Every directory under cgroupfs is a cgroup; files
                // (cgroup.procs etc.) are skipped via the file_type
                // check without an extra stat.
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(entry.path());
                }
            }
        }
        Self { map, root }
    }

    /// Full cgroupfs path for this cgroup ID, if the scan saw it.
    pub fn resolve(&self, cgroup_id: u64) -> Option<&Path> {
        self.map.get(&cgroup_id).map(PathBuf::as_path)
    }

    /// Path relative to the scanned root (e.g.
    /// `system.slice/sshd.service`) — the shape systemd unit / container
    /// joins want.
    pub fn resolve_relative(&self, cgroup_id: u64) -> Option<&Path> {
        self.resolve(cgroup_id)
            .and_then(|p| p.strip_prefix(&self.root).ok())
    }

    /// Number of cgroups seen by the scan.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` if the scan saw no cgroups (e.g. v1-only host or bad root).
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Parse `socket:[12345]` → `12345`.
fn parse_socket_inode(target: &str) -> Option<u32> {
    let rest = target.strip_prefix("socket:[")?;
    let num = rest.strip_suffix(']')?;
    num.parse().ok()
}

fn read_comm(pid_dir: &Path) -> String {
    fs::read_to_string(pid_dir.join("comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".to_string())
}

fn read_start_time(pid_dir: &Path) -> u64 {
    fs::read_to_string(pid_dir.join("stat"))
        .ok()
        .and_then(|s| parse_stat_start_time(&s))
        .unwrap_or(0)
}

/// Extract field 22 (`starttime`) from a `/proc/<pid>/stat` line.
///
/// The comm field (2) is parenthesized and may itself contain spaces,
/// parentheses and newlines, so fields are counted from AFTER the
/// LAST `)` — the kernel-documented parse (proc_pid_stat(5)). Field 3
/// (`state`) is the first post-paren token; `starttime` is the 20th.
fn parse_stat_start_time(stat: &str) -> Option<u64> {
    let after_comm = &stat[stat.rfind(')')? + 1..];
    after_comm.split_ascii_whitespace().nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn parses_socket_inode() {
        assert_eq!(parse_socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(parse_socket_inode("pipe:[999]"), None);
        assert_eq!(parse_socket_inode("/dev/null"), None);
        assert_eq!(parse_socket_inode("socket:[]"), None);
    }

    #[test]
    fn stat_start_time_survives_hostile_comm() {
        // comm containing spaces, parens and a newline — everything
        // before the LAST ')' must be ignored.
        let stat = "1234 (a (b) \n c)) R 1 1234 1234 0 -1 4194560 \
                    100 0 0 0 10 20 0 0 20 0 1 0 987654321 1000000 42 \
                    18446744073709551615";
        assert_eq!(parse_stat_start_time(stat), Some(987654321));
    }

    #[test]
    fn stat_start_time_rejects_garbage() {
        assert_eq!(parse_stat_start_time(""), None);
        assert_eq!(parse_stat_start_time("no parens here"), None);
        assert_eq!(parse_stat_start_time("1 (x) R 2 3"), None); // too few fields
    }

    /// Build a synthetic proc tree: <root>/<pid>/{comm,stat,fd/<n>}
    /// with fd symlinks pointing at "socket:[inode]" (dangling
    /// symlink targets are fine for read_link).
    fn fake_proc(root: &Path, pid: i32, comm: &str, start_time: u64, fds: &[(i32, u32)]) {
        let pid_dir = root.join(pid.to_string());
        fs::create_dir_all(pid_dir.join("fd")).unwrap();
        fs::write(pid_dir.join("comm"), format!("{comm}\n")).unwrap();
        fs::write(
            pid_dir.join("stat"),
            format!(
                "{pid} ({comm}) S 1 {pid} {pid} 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {start_time} 0 0 0"
            ),
        )
        .unwrap();
        for (fd, inode) in fds {
            std::os::unix::fs::symlink(
                format!("socket:[{inode}]"),
                pid_dir.join("fd").join(fd.to_string()),
            )
            .unwrap();
        }
    }

    #[test]
    fn scan_with_root_attributes_synthetic_tree() {
        let root = std::env::temp_dir().join(format!(
            "nlink-procmap-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        // Non-PID entries must be skipped.
        fs::create_dir_all(root.join("self")).unwrap();

        fake_proc(&root, 100, "server", 5000, &[(3, 777), (4, 888)]);
        fake_proc(&root, 200, "client", 6000, &[(5, 777)]);

        let map = SocketOwnerMap::scan_with_root(&root);
        assert_eq!(map.len(), 2);

        let owners = map.resolve(777);
        assert_eq!(owners.len(), 2);
        let server = owners.iter().find(|p| p.pid == 100).unwrap();
        assert_eq!(server.comm, "server");
        assert_eq!(server.start_time, 5000);
        assert_eq!(server.fd, 3);
        assert!(owners.iter().any(|p| p.pid == 200 && p.start_time == 6000));

        assert_eq!(map.resolve(888).len(), 1);
        assert!(map.resolve(999).is_empty());

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn scan_resolves_own_socket_unprivileged() {
        // A real end-to-end check that needs no privileges: bind a
        // socket, find its inode via /proc/self, then confirm the
        // full scan attributes it to us.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        use std::os::fd::AsRawFd;
        let target = fs::read_link(format!("/proc/self/fd/{}", sock.as_raw_fd())).unwrap();
        let inode = parse_socket_inode(target.to_str().unwrap()).unwrap();

        let map = SocketOwnerMap::scan();
        let me = std::process::id() as i32;
        let owners = map.resolve(inode);
        let mine = owners.iter().find(|p| p.pid == me).expect("own socket attributed");
        assert!(mine.start_time > 0, "start_time populated from /proc/self/stat");
        assert_ne!(mine.comm, "?");
    }

    #[test]
    fn cgroup_map_inverts_inodes() {
        let root = std::env::temp_dir().join(format!(
            "nlink-cgmap-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = fs::remove_dir_all(&root);
        let leaf = root.join("system.slice").join("test.service");
        fs::create_dir_all(&leaf).unwrap();

        let map = CgroupPathMap::scan_with_root(&root);
        let leaf_ino = fs::metadata(&leaf).unwrap().ino();
        assert_eq!(map.resolve(leaf_ino), Some(leaf.as_path()));
        assert_eq!(
            map.resolve_relative(leaf_ino),
            Some(Path::new("system.slice/test.service"))
        );
        assert_eq!(map.resolve(u64::MAX), None);
        assert!(map.len() >= 3); // root + slice + service

        fs::remove_dir_all(&root).unwrap();
    }
}
