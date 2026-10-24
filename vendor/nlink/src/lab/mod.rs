//! Lab / integration-test helpers for building ephemeral network
//! environments.
//!
//! This module promotes the `TestNamespace` helper that previously
//! lived in `crates/nlink/tests/common/mod.rs` to a public, reusable
//! building block. Use it to spin up an isolated network namespace
//! with a dummy interface or a veth pair in a few lines, run your
//! code, and let `Drop` clean up afterward.
//!
//! Gated behind the `lab` feature flag so production consumers don't
//! pay for the command-spawning + tracing surface.
//!
//! # Typical shape
//!
//! ```no_run
//! # async fn example() -> nlink::Result<()> {
//! use nlink::lab::{LabNamespace, with_namespace};
//! use nlink::netlink::link::DummyLink;
//!
//! // Manual lifecycle — the namespace is deleted on Drop.
//! let ns = LabNamespace::new("mytest")?;
//! let conn = ns.connection()?;
//! conn.add_link(DummyLink::new("dummy0")).await?;
//!
//! // Scope-guarded lifecycle — the namespace is always deleted,
//! // even if the closure errors or panics inside a catch_unwind.
//! with_namespace("mytest2", |ns| async move {
//!     let conn = ns.connection()?;
//!     conn.add_link(DummyLink::new("dummy0")).await?;
//!     Ok(())
//! }).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Requirements
//!
//! - Linux with network-namespace support.
//! - `CAP_SYS_ADMIN` (typically root) — the same requirement as
//!   `ip netns add`.
//!
//! Only [`exec`](LabNamespace::exec) runs a program; the `connect_to` /
//! `add_dummy` / `link_up` / `add_addr` helpers are netlink calls.
//!
//! # Identity
//!
//! A `LabNamespace` holds a [`Netns`](namespace::Netns) handle to the
//! namespace it created (#520). Its connections, spawned processes and
//! helpers all go to that namespace through the handle's fd, not by
//! looking the name up again, and `Drop` deletes the name only while it
//! still names that namespace. Like any handle it holds the namespace
//! open: one whose name is deleted elsewhere lives on, unnamed, until the
//! `LabNamespace` drops.
//!
//! # Skips that fail
//!
//! [`require_root!`](crate::require_root), [`require_host_root!`](crate::require_host_root)
//! and [`require_module!`](crate::require_module) return `Ok(())` when the
//! test cannot run, and a skipped test reports `ok`. Each has a variable
//! that makes its skip a failure, for an environment that knows what it
//! provides:
//!
//! | Variable | Gate | Fails when |
//! |---|---|---|
//! | `NLINK_TEST_STRICT_ROOT=1` | `require_root!` | the process is not root ([`strict_root`]) |
//! | `NLINK_TEST_STRICT_HOST_ROOT=1` | `require_host_root!` | it is not root in the initial user namespace ([`strict_host_root`]) |
//! | `NLINK_TEST_STRICT_MODULES=a,b` | `require_module!` | a listed module is missing ([`strict_modules`]) |
//!
//! A CI job that runs its suite as root sets the first, so a job that
//! loses root fails instead of skipping everything.
//!
//! # Naming
//!
//! `LabNamespace::new(prefix)` generates a name of the form
//! `nlink-lab-<prefix>-<pid>-<counter>` so concurrent tests don't
//! collide.

use std::{
    future::Future,
    pin::Pin,
    process::{Child, Command, Output},
    sync::atomic::{AtomicU32, Ordering},
};

mod bridge;
mod veth;

pub use bridge::LabBridge;
pub use veth::LabVeth;

use tracing::warn;

use std::net::IpAddr;

use crate::{
    Result, Route,
    netlink::{
        AsyncProtocolInit, Connection, ProtocolState,
        addr::{Ipv4Address, Ipv6Address},
        link::{DummyLink, VethLink},
        namespace,
    },
};

static NAMESPACE_COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique_ns_name(prefix: &str) -> String {
    let id = NAMESPACE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    format!("nlink-lab-{prefix}-{pid}-{id}")
}

/// An ephemeral, isolated network namespace for local experimentation,
/// tests, or CLI demos.
///
/// The namespace is created in [`LabNamespace::new`] and deleted on
/// `Drop`. Concurrent construction produces non-colliding names via a
/// PID + per-process counter suffix.
///
/// See the [module-level docs](self) for usage.
pub struct LabNamespace {
    name: String,
    netns: namespace::Netns,
}

#[nlink_macros::send_futures]
impl LabNamespace {
    /// Create a uniquely-named namespace.
    ///
    /// The full name is `nlink-lab-<prefix>-<pid>-<counter>`.
    pub fn new(prefix: &str) -> Result<Self> {
        Self::named(&unique_ns_name(prefix))
    }

    /// Create a namespace with a specific name.
    ///
    /// Errors if a namespace with that name already exists.
    pub fn named(name: &str) -> Result<Self> {
        Ok(Self {
            name: name.to_string(),
            netns: namespace::Netns::create(name)?,
        })
    }

    /// Get the full namespace name (suitable for `ip netns exec`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The handle to this namespace (#520): its identity, and
    /// [`run`](namespace::Netns::run), [`socket`](namespace::Netns::socket),
    /// [`sysctl`](namespace::Netns::sysctl) and
    /// [`pids`](namespace::Netns::pids) inside it.
    pub fn netns(&self) -> &namespace::Netns {
        &self.netns
    }

    /// Open a rtnetlink `Connection<Route>` scoped to this namespace.
    pub fn connection(&self) -> Result<Connection<Route>> {
        self.netns.connection()
    }

    /// Open a protocol-generic connection scoped to this namespace.
    ///
    /// Works for protocols whose construction is synchronous
    /// (rtnetlink, netfilter, uevent, sockdiag, etc.). For GENL
    /// families that need async family-ID resolution, use
    /// [`Self::connection_for_async`].
    pub fn connection_for<P>(&self) -> Result<Connection<P>>
    where
        P: ProtocolState
            + Default
            + crate::netlink::construction::SyncConstructible,
    {
        self.netns.connection()
    }

    /// Open a GENL-style connection that resolves its family ID
    /// asynchronously (WireGuard, MACsec, MPTCP, Ethtool, nl80211,
    /// Devlink).
    pub async fn connection_for_async<P>(&self) -> Result<Connection<P>>
    where
        P: AsyncProtocolInit + crate::netlink::construction::AsyncConstructible,
    {
        self.netns.connection_async().await
    }

    /// Spawn a child process inside this namespace.
    ///
    /// The child's network namespace is set via the same `setns()`
    /// mechanism used by `ip netns exec` — no shelling to `ip netns
    /// exec` on the caller's side.
    pub fn spawn(&self, cmd: Command) -> Result<Child> {
        self.netns.command(cmd)?.spawn()
    }

    /// Spawn and collect stdout/stderr.
    pub fn spawn_output(&self, cmd: Command) -> Result<Output> {
        self.netns.command(cmd)?.output()
    }

    /// Run `cmd args...` in this namespace, returning stdout as a
    /// string. Errors if the command exits non-zero.
    ///
    /// Convenience for the common "run `ip` and check status" pattern.
    pub fn exec(&self, cmd: &str, args: &[&str]) -> Result<String> {
        let mut command = Command::new(cmd);
        command.args(args);
        let output = self.spawn_output(command)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::Error::invalid_message(format!(
                "command failed: {cmd} {args:?}: {stderr}"
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Run a command, discarding the output and any error. Useful for
    /// best-effort teardown operations where the next step will fail
    /// loudly anyway if something is wrong.
    pub fn exec_ignore(&self, cmd: &str, args: &[&str]) {
        let mut command = Command::new(cmd);
        command.args(args);
        let _ = self.spawn_output(command);
    }

    /// Run `f` on a connection in this namespace, to completion, from
    /// sync code: on a thread of its own with its own runtime, so it is
    /// callable from inside a tokio runtime too.
    fn route<T: Send>(
        &self,
        f: impl for<'c> FnOnce(&'c Connection<Route>) -> Pin<Box<dyn Future<Output = Result<T>> + 'c>>
        + Send,
    ) -> Result<T> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(crate::Error::from)?;
                    let conn = {
                        let _entered = rt.enter();
                        self.connection()?
                    };
                    rt.block_on(f(&conn))
                })
                .join()
                .unwrap_or_else(|_| {
                    Err(crate::Error::internal(format!(
                        "namespace {}: a lab helper panicked",
                        self.name
                    )))
                })
        })
    }

    /// Create a veth pair with one end in this namespace and the other
    /// in `peer_ns`, both down.
    pub fn connect_to(
        &self,
        peer_ns: &LabNamespace,
        local_name: &str,
        remote_name: &str,
    ) -> Result<()> {
        let veth = VethLink::new(local_name, remote_name)
            .peer_netns_fd(&peer_ns.netns);
        self.route(move |conn| Box::pin(conn.add_link(veth)))
    }

    /// Create a dummy interface inside this namespace, down.
    pub fn add_dummy(&self, name: &str) -> Result<()> {
        let name = name.to_string();
        self.route(move |conn| Box::pin(async move { conn.add_link(DummyLink::new(&name)).await }))
    }

    /// Bring an interface up.
    pub fn link_up(&self, name: &str) -> Result<()> {
        let name = name.to_string();
        self.route(move |conn| Box::pin(async move { conn.set_link_up(name.as_str()).await }))
    }

    /// Add an IPv4 or IPv6 address, `10.0.0.1/24` or `fd00::1/64`, to an
    /// interface. With no prefix length it is a host address (`/32`,
    /// `/128`).
    pub fn add_addr(&self, dev: &str, addr: &str) -> Result<()> {
        let (ip, len) = crate::util::addr::parse_prefix(addr)?;
        let dev = dev.to_string();
        self.route(move |conn| {
            Box::pin(async move {
                match ip {
                    IpAddr::V4(v4) => conn.add_address(Ipv4Address::new(dev.as_str(), v4, len)).await,
                    IpAddr::V6(v6) => conn.add_address(Ipv6Address::new(dev.as_str(), v6, len)).await,
                }
            })
        })
    }
}

/// A lab namespace is a target like its [`Netns`](namespace::Netns):
/// `Connection::<Route>::new_in(&lab)` (#532).
impl<'a> From<&'a LabNamespace> for namespace::NetnsTarget<'a> {
    fn from(lab: &'a LabNamespace) -> Self {
        Self::Netns(&lab.netns)
    }
}

impl Drop for LabNamespace {
    fn drop(&mut self) {
        // Only while the name still names this namespace: one deleted and
        // recreated under it since is someone else's.
        match namespace::Netns::open(&self.name) {
            Ok(now) if now.id() == self.netns.id() => {}
            Ok(_) => {
                warn!(
                    namespace = %self.name,
                    "LabNamespace::drop: the name now names another namespace; not deleting it"
                );
                return;
            }
            // Already gone.
            Err(e) if e.is_not_found() => return,
            Err(_) => {}
        }
        if let Err(e) = namespace::delete(&self.name) {
            warn!(
                namespace = %self.name,
                error = %e,
                "LabNamespace::drop failed to delete namespace — may need manual cleanup via `ip netns del {}`",
                self.name,
            );
        }
    }
}

/// Run an async closure inside a freshly-created namespace, deleting
/// the namespace when the closure resolves.
///
/// Equivalent to `LabNamespace::new(prefix)` + invoking the closure,
/// but makes the "create, use, destroy" idiom a single expression.
/// Cleanup runs via `LabNamespace::Drop`, so it still happens even
/// if the closure returns an error.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// use nlink::lab::with_namespace;
/// use nlink::netlink::link::DummyLink;
///
/// with_namespace("probe", |ns| async move {
///     let conn = ns.connection()?;
///     conn.add_link(DummyLink::new("dummy0")).await?;
///     Ok(())
/// })
/// .await?;
/// # Ok(())
/// # }
/// ```
#[nlink_macros::send_futures]
pub async fn with_namespace<F, Fut, T>(prefix: &str, f: F) -> Result<T>
where
    F: FnOnce(LabNamespace) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let ns = LabNamespace::new(prefix)?;
    f(ns).await
}

/// `true` if the current process has effective UID 0.
pub fn is_root() -> bool {
    // SAFETY: `geteuid()` is a POSIX-mandated read-only syscall that
    // cannot fail and has no preconditions. Always returns the calling
    // process's effective user ID.
    unsafe { libc::geteuid() == 0 }
}

/// `true` if the current process is root in the **initial** user
/// namespace — not merely root inside one.
///
/// [`is_root`] asks `euid == 0`, which is equally true inside a
/// rootless container, where uid 0 is the unprivileged host user
/// wearing a mapping. Most of the suite does not care: a namespace,
/// a link, a qdisc, an nftables table are all owned by the user
/// namespace that created them, so mapped root can do the work.
///
/// A handful of operations check against `init_user_ns` regardless:
/// mounting over `/etc` or remounting `/sys` in a spawned namespace,
/// the TC police rate table, creating a WireGuard device. Those fail
/// `EPERM` under mapped root no matter what capabilities the container
/// was given, so a test that needs one must ask this question and not
/// the other (#357). On the privileged CI lane, whose job containers
/// are rootless, `require_root!()` alone let six such tests run and
/// fail.
///
/// The predicate is the identity mapping in `/proc/self/uid_map`,
/// which the initial namespace alone carries:
///
/// ```text
/// initial:  "         0          0 4294967295"
/// rootless: "         0       1000          1"
/// ```
///
/// A missing or unreadable `uid_map` reads as *not* host root — the
/// conservative answer, since the caller skips rather than asserts.
pub fn is_host_root() -> bool {
    if !is_root() {
        return false;
    }
    std::fs::read_to_string("/proc/self/uid_map").is_ok_and(|map| uid_map_is_identity(&map))
}

/// Whether a `uid_map` grants the full identity mapping, i.e. the
/// initial user namespace's `0 0 4294967295`.
///
/// Split out from [`is_host_root`] so the parse is unit-testable
/// without a container to run in.
fn uid_map_is_identity(map: &str) -> bool {
    map.lines().any(|line| {
        let mut f = line.split_whitespace();
        let (Some(inside), Some(outside), Some(count)) = (f.next(), f.next(), f.next()) else {
            return false;
        };
        // The range must start at 0 on both sides and cover every uid;
        // a container that maps 0 -> 0 for a single uid is still a
        // container (`0 0 1`), and init_user_ns is the only namespace
        // that maps all 2^32 of them.
        inside == "0" && outside == "0" && count.parse::<u64>() == Ok(u64::from(u32::MAX))
    })
}

/// Whether a test that needs [`is_root`] should fail rather than skip when
/// the process is not root.
///
/// Set `NLINK_TEST_STRICT_ROOT=1` where the suite is meant to run as root:
/// a CI job, or a run under `sudo`. A test gated by
/// [`require_root!`](crate::require_root) then fails instead of reporting
/// `ok` without running, which is what every such test did on a job that
/// lost root (#885). A flag, like [`strict_host_root`]: there is one thing
/// being promised. Any value but an empty one, `0`, `false`, `no` or `off`
/// sets it, in any case, so that a typo fails rather than skips.
pub fn strict_root() -> bool {
    env_flag("NLINK_TEST_STRICT_ROOT")
}

/// Whether the variable `name` is set to something other than off: an
/// empty value, `0`, `false`, `no` or `off`, in any case. A value it does
/// not know is on, so that `TRUE` or `yse` does not quietly turn a gate off.
fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| flag_is_on(&v))
}

fn flag_is_on(value: &str) -> bool {
    let value = value.trim();
    !(value.is_empty()
        || ["0", "false", "no", "off"]
            .iter()
            .any(|off| value.eq_ignore_ascii_case(off)))
}

/// What [`require_root!`](crate::require_root) and
/// [`require_root_void!`](crate::require_root_void) do: start the test's
/// tracing, and return `true` when the test should return because the
/// process is not root. Under [`strict_root`] that is a panic instead,
/// reported at the test's line.
#[doc(hidden)]
#[track_caller]
pub fn skip_without_root() -> bool {
    init_test_tracing();
    if is_root() {
        return false;
    }
    assert!(
        !strict_root(),
        "requires root, and NLINK_TEST_STRICT_ROOT makes the skip a failure"
    );
    eprintln!("Skipping test: requires root");
    true
}

/// Whether a test that needs [`is_host_root`] should fail rather than
/// skip when it does not have it.
///
/// Set `NLINK_TEST_STRICT_HOST_ROOT=1` in an environment that *does*
/// run as host root; a skip is then a hard failure. This is the
/// [`strict_modules`] bargain, for the same reason — a silent skip is
/// indistinguishable from a pass — with the difference that there is
/// exactly one thing being promised here, so it is a flag rather than
/// a list.
///
/// The privileged CI lane runs rootless and deliberately does not set
/// it: those tests genuinely cannot run there, and failing on them
/// would only teach everyone to ignore the job. They are covered by
/// the maintainer's local root runs.
///
/// Read as [`strict_root`] is: any value but an empty one, `0`, `false`,
/// `no` or `off` sets it.
pub fn strict_host_root() -> bool {
    env_flag("NLINK_TEST_STRICT_HOST_ROOT")
}

/// `true` if the named kernel feature is usable — loaded, built into
/// the kernel, or available for the kernel to load on demand.
///
/// This used to check `/sys/module/<name>` alone, documented as
/// covering built-ins too. It does not: sysfs only publishes a
/// directory for a built-in feature that exports parameters or a
/// version, which most do not. On the box this was measured on, **124
/// of 150 built-in modules had no `/sys/module` entry** — including
/// `sch_fq_codel`. Nor does it cover a loadable module that simply has
/// not been used yet: `sch_htb` appears the moment something asks for
/// an HTB qdisc, and the kernel autoloads it, but before that the
/// directory is absent.
///
/// Both gaps made [`require_module!`](crate::require_module) skip, and
/// a skipped test reports `ok`. That is not a theoretical risk: it hid
/// twelve TC bugs for an entire release cycle, because the whole
/// `ratelimit` and `impair` integration suite skipped on any machine
/// where `sch_htb` had not happened to be loaded. **A silent skip is
/// indistinguishable from a pass**, which is why this now asks all
/// three questions:
///
/// 1. `/sys/module/<name>` — loaded, or built-in and publishing attrs.
/// 2. `modules.builtin` — built in, publishing nothing.
/// 3. `modules.dep` — loadable; the kernel will bring it in on first
///    use, which is exactly what the test is about to trigger.
///
/// Returns `false` (not an error) when the feature is genuinely
/// unavailable, so the caller can decide whether to skip or fail. Also
/// returns `false` for any name containing `/` or `\0` — kernel module
/// names cannot legally contain those, and `Path::join` would
/// otherwise resolve outside `/sys/module` for an absolute name.
pub fn has_module(name: &str) -> bool {
    if name.is_empty() || name.contains('/') || name.contains('\0') {
        return false;
    }
    if std::path::Path::new("/sys/module").join(name).exists() {
        return true;
    }
    module_index().contains(name)
}

/// Names from `modules.builtin` and `modules.dep`, parsed once.
///
/// Both index files list paths like `kernel/net/sched/sch_htb.ko`
/// (`modules.dep` follows each with `:` and its dependencies, and both
/// may use a compression suffix — `.ko.xz`, `.ko.zst`). The module
/// name is the file stem.
fn module_index() -> &'static std::collections::HashSet<String> {
    use std::sync::OnceLock;
    static INDEX: OnceLock<std::collections::HashSet<String>> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut out = std::collections::HashSet::new();
        let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
            return out;
        };
        let dir = format!("/lib/modules/{}", release.trim());
        for file in ["modules.builtin", "modules.dep"] {
            let Ok(text) = std::fs::read_to_string(format!("{dir}/{file}")) else {
                continue;
            };
            for line in text.lines() {
                // `modules.dep` is "<path>: <dep> <dep>"; take the key.
                let path = line.split(':').next().unwrap_or(line).trim();
                let Some(base) = path.rsplit('/').next() else {
                    continue;
                };
                // Strip `.ko` plus any compression suffix.
                let name = base.split(".ko").next().unwrap_or(base);
                if !name.is_empty() {
                    out.insert(name.to_string());
                }
            }
        }
        out
    })
}

/// Whether a missing `name` should fail the test rather than skip it.
///
/// Set `NLINK_TEST_STRICT_MODULES` to a comma-separated list of modules
/// the environment is *expected* to provide; a skip for any of them is
/// then a hard failure. Anything not listed still skips.
///
/// A list rather than a flag, because the two cases are different. On a
/// runner that has verified `sch_htb` is there, a skipped HTB test is a
/// bug in the gate and should be loud — that is how twelve TC bugs rode
/// out a release cycle. But `ovpn` needs kernel 6.16 and `wireguard`
/// may genuinely be absent; failing on those would just teach everyone
/// to ignore the job.
///
/// The privileged CI workflow sets it to the same list its
/// module-guard step checks. Locally the default is empty, so
/// everything skips as before.
pub fn strict_modules(name: &str) -> bool {
    let Ok(list) = std::env::var("NLINK_TEST_STRICT_MODULES") else {
        return false;
    };
    list.split(',').map(str::trim).any(|m| m == name)
}

/// Initialize a `tracing-subscriber` for integration tests.
///
/// Auto-invoked by [`crate::require_root!`] /
/// [`crate::require_root_void!`] so every test path emits useful
/// logs in CI. Honors `RUST_LOG` (default `info`). Routes through
/// libtest's capture (`with_test_writer`) so output only prints on
/// failure or with `--nocapture`.
///
/// Per Plan 174: every `Connection` method carries
/// `#[tracing::instrument]`, but the spans are silent without a
/// subscriber. The CI workflow for the integration job sets
/// `RUST_LOG=nlink=debug` so a hang/assert produces a span trace
/// pinpointing which method was in flight.
///
/// Safe to call multiple times — the first call wins, subsequent
/// calls are a no-op via `Once`.
pub fn init_test_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_test_writer()
            .try_init();
    });
}

/// Macro that returns early with `Ok(())` if the current process is
/// not running as root, useful for integration tests that need
/// `CAP_SYS_ADMIN`.
///
/// Set `NLINK_TEST_STRICT_ROOT=1` to make the skip a failure — see
/// [`strict_root`](crate::lab::strict_root).
///
/// Also initializes a `tracing-subscriber` (via
/// [`crate::lab::init_test_tracing`]) so CI logs surface the spans on every
/// `Connection` method.
///
/// ```no_run
/// #[tokio::test]
/// async fn needs_root() -> nlink::Result<()> {
///     nlink::require_root!();
///     // ... real test body ...
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! require_root {
    () => {
        if $crate::lab::skip_without_root() {
            return Ok(());
        }
    };
}

/// Macro that returns early with `Ok(())` unless the process is root
/// in the **initial** user namespace ([`is_host_root`]).
///
/// For the few operations the kernel checks against `init_user_ns`
/// whatever the container was granted — mounting over `/etc` or
/// remounting `/sys` in a spawned namespace, the TC police rate table,
/// creating a WireGuard device. Under a rootless container those fail
/// `EPERM`, and [`crate::require_root!`] cannot see the difference,
/// which is how six tests came to fail on the privileged CI lane
/// instead of skipping (#357).
///
/// Pair it with [`crate::require_root!`], which stays the gate for
/// everything else. An environment that does run as host root can set
/// `NLINK_TEST_STRICT_HOST_ROOT=1` to make the skip a failure —
/// see [`strict_host_root`].
///
/// ```no_run
/// #[tokio::test]
/// async fn needs_a_real_mount() -> nlink::Result<()> {
///     nlink::require_root!();
///     nlink::require_host_root!();
///     // ... real test body ...
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! require_host_root {
    () => {
        if !$crate::lab::is_host_root() {
            let msg = "requires root in the initial user namespace; \
                       a rootless container's root cannot mount over /etc, \
                       remount /sys, install a TC police rate table, \
                       create a WireGuard device (#357), become a user \
                       its namespace does not map (#502), or listen to every \
                       namespace's events without CAP_NET_BROADCAST (#523)";
            assert!(!$crate::lab::strict_host_root(), "{msg}");
            eprintln!("Skipping test: {msg}");
            return Ok(());
        }
    };
}

/// Like [`crate::require_host_root!`] but for test functions whose
/// return type is `()` rather than `Result<()>`.
/// `NLINK_TEST_STRICT_HOST_ROOT` makes its skip a failure too.
#[macro_export]
macro_rules! require_host_root_void {
    () => {
        if !$crate::lab::is_host_root() {
            let msg = "requires root in the initial user namespace; \
                       a rootless container's root cannot mount over /etc, \
                       remount /sys, install a TC police rate table, \
                       create a WireGuard device (#357), become a user \
                       its namespace does not map (#502), or listen to every \
                       namespace's events without CAP_NET_BROADCAST (#523)";
            assert!(!$crate::lab::strict_host_root(), "{msg}");
            eprintln!("Skipping test: {msg}");
            return;
        }
    };
}

/// Like [`crate::require_root!`] but for test functions whose
/// return type is `()` rather than `Result<()>`. `NLINK_TEST_STRICT_ROOT`
/// makes its skip a failure too.
#[macro_export]
macro_rules! require_root_void {
    () => {
        if $crate::lab::skip_without_root() {
            return;
        }
    };
}

/// Macro that returns early with `Ok(())` if the named kernel
/// module isn't loaded or built-in. Use this in integration tests
/// that depend on a specific kernel feature (`nf_conntrack`,
/// `cls_flower`, `xfrm_user`, etc.) so a missing module produces a
/// clean skip rather than a cryptic `is_not_supported()` error
/// deep in the test body.
///
/// Wraps [`has_module`]. Pair with [`crate::require_root!`] — the
/// module can only be checked once the test is actually trying to
/// run.
///
/// Set `NLINK_TEST_STRICT_MODULES` to a comma-separated list of modules
/// the environment provides, and a skip for one of them fails instead —
/// see [`strict_modules`].
///
/// ```no_run
/// #[tokio::test]
/// async fn needs_conntrack() -> nlink::Result<()> {
///     nlink::require_root!();
///     nlink::require_module!("nf_conntrack");
///     nlink::require_module!("nf_conntrack_netlink");
///     // ... real test body ...
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! require_module {
    ($name:expr) => {
        if !$crate::lab::has_module($name) {
            let msg = format!(
                "kernel module '{}' is not loaded, not built in, and not \
                 available to load",
                $name
            );
            assert!(!$crate::lab::strict_modules($name), "{msg}");
            eprintln!("Skipping test: {msg}");
            return Ok(());
        }
    };
}

/// Like [`require_module`] but for test functions whose return type
/// is `()` rather than `Result<()>`. `NLINK_TEST_STRICT_MODULES` applies
/// to it too.
#[macro_export]
macro_rules! require_module_void {
    ($name:expr) => {
        if !$crate::lab::has_module($name) {
            let msg = format!(
                "kernel module '{}' is not loaded, not built in, and not \
                 available to load",
                $name
            );
            assert!(!$crate::lab::strict_modules($name), "{msg}");
            eprintln!("Skipping test: {msg}");
            return;
        }
    };
}

/// Require multiple kernel modules in one call. Skips the test
/// (returning `Ok(())`) if any of the named modules is not
/// loaded or built-in, or fails for one `NLINK_TEST_STRICT_MODULES`
/// lists. Convenience for tests that touch several independent
/// kernel features.
///
/// ```no_run
/// #[tokio::test]
/// async fn needs_htb_and_flower() -> nlink::Result<()> {
///     nlink::require_root!();
///     nlink::require_modules!("sch_htb", "cls_flower");
///     // ...
/// }
/// ```
#[macro_export]
macro_rules! require_modules {
    ($($name:expr),+ $(,)?) => {
        $( $crate::require_module!($name); )+
    };
}

/// Require that a sysctl path exists and is writable. Used by
/// sysctl write tests that need `/proc/sys/...` to be RW (some
/// container configurations mount it read-only). Skips the
/// test (returning `Ok(())`) if the path is not writable.
///
/// ```no_run
/// # fn example() -> nlink::Result<()> {
/// nlink::require_writable_sysctl!("/proc/sys/net/ipv4/ip_forward");
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! require_writable_sysctl {
    ($path:expr) => {
        match std::fs::OpenOptions::new().write(true).open($path) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "Skipping test: sysctl '{}' not writable ({}); \
                     /proc/sys may be read-only in this environment",
                    $path, e
                );
                return Ok(());
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #885 review: a strict switch is off only when it says off, so a
    /// typo or another case fails a skip instead of allowing it.
    #[test]
    fn a_strict_switch_is_on_unless_it_says_off() {
        for on in ["1", "true", "TRUE", "yes", "Yes", "on", "yse"] {
            assert!(flag_is_on(on), "{on}");
        }
        for off in ["", " ", "0", "false", "FALSE", "no", "No", "off", "OFF"] {
            assert!(!flag_is_on(off), "{off:?}");
        }
    }

    #[test]
    fn test_unique_ns_name() {
        let n1 = unique_ns_name("probe");
        let n2 = unique_ns_name("probe");
        assert_ne!(n1, n2);
        assert!(n1.starts_with("nlink-lab-probe-"));
    }

    #[test]
    fn has_module_returns_false_for_unknown_name() {
        assert!(!has_module("nlink_definitely_not_a_real_module_xyzzy"));
    }

    #[test]
    fn has_module_rejects_path_traversal() {
        // Names containing '/' or NUL aren't valid kernel module names
        // and would let `Path::join` resolve outside /sys/module on an
        // absolute component.
        assert!(!has_module(""));
        assert!(!has_module("/etc/passwd"));
        assert!(!has_module("../../etc/passwd"));
        assert!(!has_module("nf_conntrack/foo"));
        assert!(!has_module("nf\0conntrack"));
    }

    // ====================================================================
    // #273 — has_module must see built-ins and loadable modules
    // ====================================================================

    #[test]
    fn has_module_rejects_names_that_could_escape_sys_module() {
        assert!(!has_module(""));
        assert!(!has_module("../../etc"));
        assert!(!has_module("/etc/passwd"));
        assert!(!has_module("foo\0bar"));
    }

    #[test]
    fn has_module_sees_more_than_sys_module() {
        // The old implementation was `/sys/module/<name>` alone. sysfs
        // only publishes a directory for a built-in that exports
        // parameters or a version, and for a loadable module only once
        // it is loaded — so that check misses most of what the kernel
        // can actually provide, and every miss became a silent skip.
        //
        // Assert the index is doing work: every name in modules.builtin
        // must be reported present, whether or not sysfs knows it.
        let index = module_index();
        if index.is_empty() {
            // No /lib/modules for this kernel (some containers); the
            // sysfs check is all there is and there is nothing to test.
            return;
        }
        let mut checked = 0;
        let mut invisible_to_sysfs = 0;
        for name in index.iter().take(200) {
            assert!(has_module(name), "index knows {name} but has_module says no");
            if !std::path::Path::new("/sys/module").join(name).exists() {
                invisible_to_sysfs += 1;
            }
            checked += 1;
        }
        assert!(checked > 0);
        // Not an assertion about this machine's config, just a record
        // of why the sysfs-only check was wrong: on any real kernel
        // most index entries have no sysfs directory.
        eprintln!("{invisible_to_sysfs} of {checked} indexed modules have no /sys/module entry");
    }

    #[test]
    fn has_module_says_no_to_something_that_does_not_exist() {
        assert!(!has_module("nlink_definitely_not_a_module_xyzzy"));
    }

    #[test]
    fn only_the_initial_namespaces_uid_map_is_the_identity_mapping() {
        // What /proc/self/uid_map reads outside any user namespace.
        assert!(uid_map_is_identity("         0          0 4294967295\n"));
        // A rootless container: uid 0 inside is the host's ordinary user.
        assert!(!uid_map_is_identity(
            "         0       1000          1\n         1     100000      65536\n"
        ));
        // 0 -> 0, but for a single uid: still a namespace, not the host.
        assert!(!uid_map_is_identity("         0          0          1\n"));
        // Whatever a future kernel or a mangled read hands back.
        assert!(!uid_map_is_identity(""));
        assert!(!uid_map_is_identity("0 0"));
        assert!(!uid_map_is_identity("0 0 not-a-number"));
    }
}
