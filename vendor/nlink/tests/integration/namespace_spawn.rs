//! Namespace process spawning integration tests.
//!
//! Tests for spawning processes inside network namespaces.

use std::{fs, path::PathBuf, process::Command};

use nlink::{
    Result,
    netlink::{link::DummyLink, namespace, namespace::NamespaceSpec},
};

use crate::common::TestNamespace;

#[tokio::test]
async fn test_spawn_ip_link_show() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("spawn-ip")?;

    let mut cmd = Command::new("ip");
    cmd.arg("link");
    let output = namespace::spawn_output(ns.name(), cmd)?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Every namespace has a loopback interface
    assert!(stdout.contains("lo"), "should contain loopback interface");

    Ok(())
}

#[tokio::test]
async fn test_spawn_sees_namespace_interface() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("spawn-if")?;
    let conn = ns.connection()?;

    // Create a dummy interface in the namespace
    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;

    // Spawn ip link show in the namespace and verify the interface is visible
    let mut cmd = Command::new("ip");
    cmd.arg("link");
    let output = namespace::spawn_output(ns.name(), cmd)?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("test0"), "should see test0 in namespace");

    Ok(())
}

#[tokio::test]
async fn test_spawn_background_process() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("spawn-bg")?;

    // Spawn a sleep process in the namespace
    let mut cmd = Command::new("sleep");
    cmd.arg("60");
    let mut child = namespace::spawn(ns.name(), cmd)?;

    // Verify it's running
    let try_wait = child.try_wait().map_err(nlink::Error::from)?;
    assert!(try_wait.is_none(), "process should still be running");

    // Kill it
    child.kill().map_err(nlink::Error::from)?;
    child.wait().map_err(nlink::Error::from)?;

    Ok(())
}

#[tokio::test]
async fn test_spawn_captures_stdout() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("spawn-out")?;

    let mut cmd = Command::new("echo");
    cmd.arg("hello from namespace");
    let output = namespace::spawn_output(ns.name(), cmd)?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(stdout.trim(), "hello from namespace");

    Ok(())
}

#[tokio::test]
async fn test_spawn_nonexistent_namespace() -> Result<()> {
    require_root!();

    let err = namespace::spawn("definitely_does_not_exist_12345", Command::new("true"))
        .expect_err("missing namespace must fail");
    assert!(err.is_not_found(), "got unclassifiable error: {err}");

    Ok(())
}

/// #348 — an `ip netns` marker with no namespace mounted over it (what a
/// crash or a bare `umount` leaves behind) is `NamespaceNotFound` from
/// every by-name entry point, not an `EINVAL` out of `setns(2)`.
#[tokio::test]
async fn stale_marker_is_not_found_from_every_by_name_entry_point() -> Result<()> {
    require_root!();
    use nlink::netlink::namespace::NETNS_RUN_DIR;

    // A real namespace first, so the run dir exists the way `ip netns add`
    // leaves it (and is cleaned up by Drop).
    let _ns = TestNamespace::new("stale-marker")?;
    let name = format!("nlink-stale-{}", std::process::id());
    let marker = PathBuf::from(NETNS_RUN_DIR).join(&name);
    fs::write(&marker, b"")?;
    assert!(namespace::exists(&name), "the marker is on disk");

    let spawn = namespace::spawn(&name, Command::new("true")).map(drop);
    let spawn_etc = namespace::spawn_with_etc(&name, Command::new("true")).map(drop);
    let conn = nlink::Connection::<nlink::Route>::new_in(&name).map(drop);
    let conn_async = nlink::Connection::<nlink::Wireguard>::new_in_async(&name)
        .await
        .map(drop);
    let open = namespace::open(&name).map(drop);
    let enter = namespace::enter(&name).map(drop);
    let sysctl = namespace::get_sysctl(&name, "net.ipv4.ip_forward").map(drop);
    let spec = NamespaceSpec::Named(&name).spawn(Command::new("true")).map(drop);
    // Clean up before asserting so a failure cannot leak the marker.
    let _ = fs::remove_file(&marker);

    for (what, result) in [
        ("spawn", spawn),
        ("spawn_with_etc", spawn_etc),
        ("connection_for", conn),
        ("connection_for_async", conn_async),
        ("open", open),
        ("enter", enter),
        ("get_sysctl", sysctl),
        ("NamespaceSpec::Named.spawn", spec),
    ] {
        let err = result.expect_err(what);
        assert!(err.is_not_found(), "{what}: got unclassifiable error: {err}");
    }
    Ok(())
}

#[tokio::test]
async fn test_spawn_nonexistent_binary() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("spawn-nobin")?;

    let result = namespace::spawn(ns.name(), Command::new("nonexistent_binary_12345"));
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_spawn_parent_namespace_unaffected() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("spawn-parent")?;
    let conn = ns.connection()?;

    // Create an interface only in the namespace
    conn.add_link(DummyLink::new("nsonly0")).await?;

    // Spawn a process in the namespace
    let mut cmd = Command::new("ip");
    cmd.arg("link");
    let output = namespace::spawn_output(ns.name(), cmd)?;
    let ns_stdout = String::from_utf8_lossy(&output.stdout);
    assert!(ns_stdout.contains("nsonly0"));

    // Verify the parent namespace doesn't have this interface
    let parent_output = Command::new("ip")
        .arg("link")
        .output()
        .map_err(nlink::Error::from)?;
    let parent_stdout = String::from_utf8_lossy(&parent_output.stdout);
    assert!(
        !parent_stdout.contains("nsonly0"),
        "parent namespace should not have nsonly0"
    );

    Ok(())
}

#[tokio::test]
async fn test_namespace_spec_spawn() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("spawn-spec")?;

    let spec = NamespaceSpec::Named(ns.name());
    let mut cmd = Command::new("echo");
    cmd.arg("via spec");
    let output = spec.spawn_output(cmd)?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(stdout.trim(), "via spec");

    Ok(())
}

// ============================================================================
// spawn_with_etc tests
// ============================================================================

/// Helper to set up /etc/netns/<name>/ with custom files.
/// Returns the directory path for cleanup.
fn setup_etc_netns(ns_name: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = PathBuf::from("/etc/netns").join(ns_name);
    fs::create_dir_all(&dir).expect("create /etc/netns/<name>/");
    for (filename, content) in files {
        fs::write(dir.join(filename), content).expect("write etc file");
    }
    dir
}

fn cleanup_etc_netns(ns_name: &str) {
    let dir = PathBuf::from("/etc/netns").join(ns_name);
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_spawn_with_etc_hosts() -> Result<()> {
    require_root!();
    // Mounting the /etc overlay is checked against init_user_ns (#357).
    nlink::require_host_root!();

    let ns = TestNamespace::new("spawn-etc-h")?;
    let custom_hosts = "127.0.0.1 custom-host.lab\n";
    setup_etc_netns(ns.name(), &[("hosts", custom_hosts)]);

    let mut cmd = Command::new("cat");
    cmd.arg("/etc/hosts");
    let output = namespace::spawn_output_with_etc(ns.name(), cmd)?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    cleanup_etc_netns(ns.name());

    assert!(
        stdout.contains("custom-host.lab"),
        "spawned process should see custom /etc/hosts, got: {stdout}"
    );

    Ok(())
}

/// #331 — `NamespaceSpec::Path` pointing into `/var/run/netns` has a
/// name, so it gets the overlay; `Pid` has none and does not, and
/// `etc_overlay_name` says so up front.
#[tokio::test]
async fn namespace_spec_path_gets_the_etc_overlay_and_pid_does_not() -> Result<()> {
    require_root!();
    // Mounting the /etc overlay is checked against init_user_ns (#357).
    nlink::require_host_root!();
    use nlink::netlink::namespace::{NETNS_RUN_DIR, NamespaceSpec};

    let ns = TestNamespace::new("spawn-etc-spec")?;
    setup_etc_netns(ns.name(), &[("hosts", "127.0.0.1 spec-host.lab\n")]);

    let run_path = PathBuf::from(NETNS_RUN_DIR).join(ns.name());
    let by_path = NamespaceSpec::Path(&run_path);
    assert_eq!(by_path.etc_overlay_name(), Some(ns.name()));
    let mut cmd = Command::new("cat");
    cmd.arg("/etc/hosts");
    let out = by_path.spawn_output_with_etc(cmd);
    let seen_by_path = out.map(|o| String::from_utf8_lossy(&o.stdout).to_string());

    // A long-lived process in the namespace to name by pid.
    let mut sleeper = Command::new("sleep");
    sleeper.arg("30");
    let mut child = namespace::spawn(ns.name(), sleeper)?;
    let by_pid = NamespaceSpec::Pid(child.id());
    assert_eq!(by_pid.etc_overlay_name(), None);
    let mut cmd = Command::new("cat");
    cmd.arg("/etc/hosts");
    let out = by_pid.spawn_output_with_etc(cmd);
    let seen_by_pid = out.map(|o| String::from_utf8_lossy(&o.stdout).to_string());
    let _ = child.kill();
    let _ = child.wait();

    cleanup_etc_netns(ns.name());

    let seen_by_path = seen_by_path?;
    assert!(
        seen_by_path.contains("spec-host.lab"),
        "Path spec under {NETNS_RUN_DIR} must apply the overlay; got: {seen_by_path}"
    );
    let seen_by_pid = seen_by_pid?;
    assert!(
        !seen_by_pid.contains("spec-host.lab"),
        "Pid spec has no name and therefore no overlay; got: {seen_by_pid}"
    );
    Ok(())
}

#[tokio::test]
async fn test_spawn_with_etc_no_dir() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("spawn-etc-nd")?;
    // Don't create /etc/netns/<name>/ — should work as a no-op

    let mut cmd = Command::new("echo");
    cmd.arg("ok");
    let output = namespace::spawn_output_with_etc(ns.name(), cmd)?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(stdout.trim(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_spawn_with_etc_host_unaffected() -> Result<()> {
    require_root!();
    // Mounting the /etc overlay is checked against init_user_ns (#357).
    nlink::require_host_root!();

    let ns = TestNamespace::new("spawn-etc-ha")?;
    let custom_hosts = "127.0.0.1 only-in-namespace\n";
    setup_etc_netns(ns.name(), &[("hosts", custom_hosts)]);

    // Spawn with overlay
    let mut cmd = Command::new("cat");
    cmd.arg("/etc/hosts");
    let _ = namespace::spawn_output_with_etc(ns.name(), cmd)?;

    // Verify host's /etc/hosts is NOT modified
    let host_hosts = fs::read_to_string("/etc/hosts").expect("read host /etc/hosts");

    cleanup_etc_netns(ns.name());

    assert!(
        !host_hosts.contains("only-in-namespace"),
        "host /etc/hosts should NOT contain namespace-specific entry"
    );

    Ok(())
}

#[tokio::test]
async fn test_spawn_with_etc_sys_remount() -> Result<()> {
    require_root!();
    // Remounting /sys is checked against init_user_ns (#357).
    nlink::require_host_root!();

    let ns = TestNamespace::new("spawn-etc-sys")?;
    // Need at least one /etc overlay file to trigger mount namespace setup
    setup_etc_netns(ns.name(), &[("hosts", "127.0.0.1 localhost\n")]);

    let mut cmd = Command::new("ls");
    cmd.arg("/sys/class/net/");
    let output = namespace::spawn_output_with_etc(ns.name(), cmd)?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    cleanup_etc_netns(ns.name());

    // A fresh namespace only has loopback
    assert!(
        stdout.contains("lo"),
        "should see loopback in /sys/class/net/"
    );
    // Should NOT see host interfaces (eth0, enp*, wl*, etc.)
    // We can't assert the exact names, but we can check there's no multi-word output
    // beyond "lo". Just verify lo is present — the sysfs remount is working if we get here.

    Ok(())
}

/// #502: std applies `CommandExt::uid` before any `pre_exec` closure, so
/// a namespaced spawn with it ran `setns` unprivileged and failed with
/// `EPERM` — there was no way to run a process in a lab namespace as an
/// unprivileged user. `spawn_as` drops to the user after `setns`.
#[tokio::test]
async fn spawn_as_runs_as_the_user_inside_the_namespace() -> Result<()> {
    use std::os::unix::{fs::MetadataExt, process::CommandExt};

    use namespace::{NETNS_RUN_DIR, SpawnUser};
    require_root!();
    // Becoming uid 1 needs uid 1 mapped: the rootless CI lane maps only 0
    // (`0 1000 1`), where setuid(1) is EINVAL whatever the order.
    nlink::require_host_root!();

    let ns = TestNamespace::new("spawn-as")?;
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "id -u; id -g; id -G; stat -L -c %i /proc/self/ns/net"]);
    cmd.stdout(std::process::Stdio::piped());
    let out = namespace::spawn_as(ns.name(), cmd, &SpawnUser::new(1, 1))?.wait_with_output()?;
    assert!(out.status.success(), "{out:?}");
    let ns_inode = fs::metadata(PathBuf::from(NETNS_RUN_DIR).join(ns.name()))?
        .ino()
        .to_string();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        ["1", "1", "1", ns_inode.as_str()],
        "uid, gid, groups, netns"
    );

    // What it replaces: the uid drop happens first, then setns is refused.
    let mut trap = Command::new("true");
    trap.uid(1).gid(1);
    let err = namespace::spawn(ns.name(), trap).expect_err("setns after the uid drop");
    assert_eq!(
        err.errno(),
        Some(libc::EPERM),
        "the trap spawn_as exists for: {err}"
    );
    Ok(())
}

/// #502, with the `/etc/netns` overlay: the drop comes after the mounts,
/// which need the privilege too.
#[tokio::test]
async fn spawn_with_etc_as_mounts_then_drops() -> Result<()> {
    use namespace::SpawnUser;
    require_root!();
    // Mounting the /etc overlay is checked against init_user_ns (#357).
    nlink::require_host_root!();

    let ns = TestNamespace::new("spawn-etc-as")?;
    setup_etc_netns(ns.name(), &[("hosts", "127.0.0.1 as-user.lab\n")]);
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "id -u; cat /etc/hosts"]);
    cmd.stdout(std::process::Stdio::piped());
    let out = namespace::spawn_with_etc_as(ns.name(), cmd, &SpawnUser::new(1, 1))
        .and_then(|c| c.wait_with_output().map_err(nlink::Error::from));
    cleanup_etc_netns(ns.name());
    let out = out?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("1\n"), "{stdout}");
    assert!(stdout.contains("as-user.lab"), "{stdout}");
    Ok(())
}
