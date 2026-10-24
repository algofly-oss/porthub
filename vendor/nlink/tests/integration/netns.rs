//! `Netns`, the owned namespace handle (#520): identity however a namespace
//! is opened, work done inside it, and a delete that cannot hit the wrong
//! namespace.

use std::os::fd::{FromRawFd, OwnedFd};
use std::time::Duration;

use nlink::netlink::addr::Ipv4Address;
use nlink::netlink::link::DummyLink;
use nlink::netlink::namespace::{self, Netns, NetnsRef};
use nlink::{Connection, Route};

use crate::common::TestNamespace;

/// A name, its marker path, a process inside and a pidfd of that process
/// all open the same namespace, and it is not the caller's.
#[tokio::test]
async fn one_namespace_however_it_is_opened() -> nlink::Result<()> {
    nlink::require_root!();

    let ns = TestNamespace::new("netns-id")?;
    let by_name = Netns::open(ns.name())?;
    let by_path = Netns::from_path(format!("/var/run/netns/{}", ns.name()))?;
    assert_eq!(by_name.id(), by_path.id());
    assert_ne!(by_name.id(), Netns::current()?.id());
    assert_eq!(by_name.name(), Some(ns.name()));
    let by_ref = NetnsRef::Named(ns.name().to_string()).open()?;
    assert_eq!(by_ref, by_name);

    let mut cmd = std::process::Command::new("sleep");
    cmd.arg("5");
    let mut child = namespace::spawn(ns.name(), cmd)?;
    let by_pid = Netns::from_pid(child.id())?;
    // SAFETY: pidfd_open returns a fresh fd or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
    assert!(fd >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
    // SAFETY: the fd was just made and nothing else owns it.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let by_pidfd = Netns::from_pidfd(&pidfd)?;
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(by_pid.id(), by_name.id());
    assert_eq!(by_pidfd.id(), by_name.id());
    Ok(())
}

/// `run` and `socket` work inside the namespace: the thread sees its
/// devices, and a socket from it can bind an address only it has.
#[tokio::test]
async fn run_and_socket_are_inside() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("netns-run")?;
    let netns = Netns::open(ns.name())?;
    let conn = Connection::<Route>::new_in(&netns)?;
    conn.add_link(DummyLink::new("d0")).await?;
    conn.set_link_up("d0").await?;
    let addr = std::net::Ipv4Addr::new(10, 77, 0, 1);
    conn.add_address(Ipv4Address::new("d0", addr, 24)).await?;

    let net_dev = netns.run(|| std::fs::read_to_string("/proc/thread-self/net/dev"))??;
    assert!(net_dev.contains("d0:"), "{net_dev}");

    let socket = std::net::UdpSocket::from(netns.socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?);
    let bound = socket2_bind(&socket, std::net::SocketAddrV4::new(addr, 0));
    assert!(bound.is_ok(), "bind inside the namespace: {bound:?}");
    let outside = std::net::UdpSocket::bind((addr, 0));
    assert!(outside.is_err(), "the host should not have {addr}");
    Ok(())
}

/// Bind an already-made socket (`UdpSocket::bind` makes its own).
fn socket2_bind(socket: &std::net::UdpSocket, addr: std::net::SocketAddrV4) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(*addr.ip()).to_be(),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: a valid sockaddr_in of the right length, on a live fd.
    let ret = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&sin as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// A handle keeps its namespace, and its devices, alive after the name is
/// deleted. Deleting through a handle whose name was deleted and recreated
/// since is refused, and the new namespace is left alone.
#[tokio::test]
async fn delete_never_hits_a_recreated_namespace() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    let name = format!("nlk-netns-del-{}", std::process::id());
    let first = Netns::create(&name)?;
    let conn = Connection::<Route>::new_in(&first)?;
    conn.add_link(DummyLink::new("held")).await?;

    namespace::delete(&name)?;
    assert!(Netns::open(&name).is_err_and(|e| e.is_not_found()));
    assert!(
        conn.get_link_by_name("held").await?.is_some(),
        "the handle keeps the namespace and its devices"
    );

    let second = Netns::create(&name)?;
    assert_ne!(second.id(), first.id());
    let err = first
        .delete()
        .expect_err("the name names another namespace now");
    assert!(err.to_string().contains("not deleting"), "{err}");
    assert!(
        Netns::open(&name).is_ok(),
        "the new namespace is still there"
    );

    second.delete()?;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(Netns::open(&name).is_err_and(|e| e.is_not_found()));
    Ok(())
}

/// A generic-netlink family resolves inside the namespace.
#[tokio::test]
async fn an_async_family_connects_inside() -> nlink::Result<()> {
    use nlink::netlink::Wireguard;
    nlink::require_root!();
    nlink::require_modules!("wireguard");

    let ns = TestNamespace::new("netns-genl")?;
    let netns = Netns::open(ns.name())?;
    let wg = Connection::<Wireguard>::new_in_async(&netns).await?;
    drop(wg);
    Ok(())
}

/// A connection made in a namespace knows it, and a sibling of another
/// protocol lands there too, however the first was opened (#520).
#[tokio::test]
async fn connections_know_their_namespace_and_siblings_follow() -> nlink::Result<()> {
    use nlink::netlink::Nftables;
    nlink::require_root!();

    let ns = TestNamespace::new("netns-sib")?;
    let netns = Netns::open(ns.name())?;
    let by_handle = Connection::<Route>::new_in(&netns)?;
    let by_name: Connection<Route> = nlink::Connection::new_in(ns.name())?;
    for conn in [&by_handle, &by_name] {
        assert_eq!(conn.netns()?.id(), netns.id());
        let nft = conn.sibling::<Nftables>()?;
        assert_eq!(nft.netns()?.id(), netns.id());
    }
    let host = Connection::<Route>::new()?;
    assert_eq!(host.netns()?.id(), Netns::current()?.id());
    Ok(())
}

/// An error from a connection made in a namespace says which (#718), on
/// every path: a kernel refusal to a request, a lookup the connection does
/// by name, a sibling of another protocol, an nftables batch and a GENL
/// family. One from the caller's own namespace says nothing.
#[tokio::test]
async fn errors_name_the_namespace_they_came_from() -> nlink::Result<()> {
    use nlink::netlink::nftables::Family;
    use nlink::netlink::route::Ipv4Route;
    use nlink::netlink::{Generic, Nftables};
    nlink::require_root!();

    let ns = TestNamespace::new("netns-err")?;
    let netns = Netns::open(ns.name())?;
    let label = ns.name();
    let suffix = format!(" [netns {label}]");
    let check = |what: &str, e: &nlink::Error| {
        assert_eq!(e.netns(), Some(label), "{what}: {e:?}");
        assert!(e.to_string().ends_with(&suffix), "{what}: {e}");
    };

    // The namespace has no route anywhere: the kernel refuses this.
    let route = || {
        Ipv4Route::new(std::net::Ipv4Addr::new(10, 1, 0, 0), 16)
            .gateway(std::net::Ipv4Addr::new(192, 0, 2, 1))
    };
    let conn = Connection::<Route>::new_in(&netns)?;
    let refused = conn.add_route(route()).await.unwrap_err();
    assert!(refused.errno().is_some(), "{refused}");
    check("a refused request", &refused);

    // Opened by name rather than by handle: the label is the name.
    let by_name: Connection<Route> = Connection::new_in(ns.name())?;
    check("by name", &by_name.add_route(route()).await.unwrap_err());

    let missing = conn.set_link_up("nope0").await.unwrap_err();
    assert!(missing.is_not_found(), "{missing}");
    check("an interface lookup", &missing);

    let nft = conn.sibling::<Nftables>()?;
    let batch = nft.del_table("nope", Family::Inet).await.unwrap_err();
    assert!(batch.is_not_found(), "{batch}");
    check("an nftables batch", &batch);

    let genl = conn.sibling::<Generic>()?;
    let family = genl.get_family("nlink-no-such-family").await.unwrap_err();
    check("a GENL family lookup", &family);

    let host = Connection::<Route>::new()?;
    let here = host.set_link_up("nlink-nope0").await.unwrap_err();
    assert_eq!(here.netns(), None, "{here:?}");
    assert!(!here.to_string().contains("[netns"), "{here}");
    Ok(())
}

/// A pool opens its namespace once. When the name is deleted and a new
/// namespace is created under it, a replacement connection is refused
/// rather than made in the new namespace, which it was before (#520).
#[tokio::test]
async fn a_pool_never_moves_to_a_namespace_recreated_under_its_name() -> nlink::Result<()> {
    use nlink::netlink::pool::ConnectionPoolBuilder;
    nlink::require_root!();

    let name = format!("nlk-pool-{}", std::process::id());
    let first = Netns::create(&name)?;
    let pool = ConnectionPoolBuilder::<Route>::new()
        .namespace(name.as_str())
        .size(1)
        .acquire_timeout(Duration::from_millis(300))
        .build()
        .await?;
    {
        let conn = pool.acquire().await?;
        assert_eq!(conn.netns()?.id(), first.id());
    }

    namespace::delete(&name)?;
    let second = Netns::create(&name)?;
    pool.acquire().await?.invalidate();
    tokio::time::sleep(Duration::from_millis(200)).await;
    match pool.acquire().await {
        Ok(conn) => panic!(
            "the pool replaced its connection with one in {}, the new namespace",
            conn.netns()?.id()
        ),
        Err(e) => assert!(e.is_timeout() || e.is_pool_exhausted(), "{e}"),
    }
    drop(first);
    second.delete()?;
    Ok(())
}

/// A watch stream started through a namespace's name ends with
/// `NamespaceDeleted` when the name is deleted (#504, #520).
#[tokio::test]
async fn a_watch_on_a_named_namespace_ends_when_it_is_deleted() -> nlink::Result<()> {
    use tokio_stream::StreamExt;
    nlink::require_root!();

    let name = format!("nlk-watch-{}", std::process::id());
    let netns = Netns::create(&name)?;
    let mut stream = nlink::facade::watch::route_changes_in(&name).await?;
    namespace::delete(&name)?;
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(item) = stream.next().await {
            if let Err(e) = item {
                return Some(e);
            }
        }
        None
    })
    .await
    .expect("the stream should end within 10 s");
    let err = ended.expect("the stream should end with an error");
    assert!(err.is_namespace_deleted(), "{err}");
    drop(netns);
    Ok(())
}

/// `set_nsid` gives a namespace an id here, and `get_nsid` and
/// `get_nsid_for_pid` read it back (#669). All three padded their one-byte
/// `rtgenmsg` twice, so the attribute sat four bytes past where the kernel
/// looks, and every call failed: "Peer netns reference is missing"
/// (EINVAL).
#[tokio::test]
async fn nsids_are_set_and_read() -> nlink::Result<()> {
    nlink::require_root!();

    let ns = TestNamespace::new("netns-nsid")?;
    let peer = TestNamespace::new("netns-nsid-peer")?;
    let conn = ns.connection()?;
    let netns = Netns::open(peer.name())?;
    // NETNSA_NSID_NOT_ASSIGNED, -1: no id yet.
    assert_eq!(conn.get_nsid(&netns).await?, u32::MAX);
    conn.set_nsid(&netns, 7).await?;
    assert_eq!(conn.get_nsid(&netns).await?, 7);
    let listed = ns.exec("ip", &["netns", "list-id"])?;
    assert!(listed.contains("nsid 7 "), "{listed}");

    // A process inside the namespace: it enters before it execs.
    let mut cmd = std::process::Command::new("sleep");
    cmd.arg("10");
    let mut child = peer.spawn(cmd)?;
    let got = conn.get_nsid_for_pid(child.id()).await;
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(got?, 7);
    Ok(())
}

/// Deletes a named namespace, and its owner tag, when the test is done
/// with it, however it ends.
struct Cleanup(String);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = namespace::delete(&self.0);
        let _ = namespace::remove_owner_tag(&self.0);
        let _ = std::fs::remove_file(format!("/var/run/netns/{}", self.0));
    }
}

/// `create_with` tags a namespace with its owner, `owner_of` and
/// `list_owned` read the tag, and `delete` removes it with the namespace
/// (#522).
#[tokio::test]
async fn an_owner_tag_goes_with_its_namespace() -> nlink::Result<()> {
    use namespace::CreateOptions;
    nlink::require_root!();

    let name = format!("nlink-owned-{}", std::process::id());
    let owner = format!("nlink-test-{}", std::process::id());
    let _cleanup = Cleanup(name.clone());
    let netns = Netns::create_with(&name, CreateOptions::new().owner(&owner))?;
    assert_eq!(netns.name(), Some(name.as_str()));
    assert_eq!(namespace::owner_of(&name)?.as_deref(), Some(owner.as_str()));
    assert_eq!(namespace::list_owned(&owner)?, std::slice::from_ref(&name));
    assert!(namespace::list_owned("someone-else")?.iter().all(|n| *n != name));

    netns.delete()?;
    assert_eq!(namespace::owner_of(&name)?, None);
    assert!(namespace::list_owned(&owner)?.is_empty());
    Ok(())
}

/// A stale marker — a `/run/netns` file nothing is mounted on, left by a
/// crash — is reclaimed with `reclaim_stale`, where `create` refuses it; a
/// live namespace never is, and a create that fails leaves no tag (#522).
#[tokio::test]
async fn reclaim_stale_takes_a_dead_marker_and_never_a_live_namespace() -> nlink::Result<()> {
    use namespace::CreateOptions;
    nlink::require_root!();

    let name = format!("nlink-stale-{}", std::process::id());
    let _cleanup = Cleanup(name.clone());
    std::fs::create_dir_all("/var/run/netns")?;
    std::fs::write(format!("/var/run/netns/{name}"), b"")?;
    assert!(namespace::create(&name).expect_err("a marker is there").is_already_exists());

    namespace::create_with(&name, CreateOptions::new().reclaim_stale(true))?;
    assert!(namespace::is_namespace(&name));

    let err = namespace::create_with(&name, CreateOptions::new().reclaim_stale(true).owner("late"))
        .expect_err("a live namespace is not reclaimed");
    assert!(err.is_already_exists(), "{err}");
    assert!(namespace::is_namespace(&name));
    assert_eq!(namespace::owner_of(&name)?, None, "the failed create removed its tag");
    Ok(())
}

/// Removes `/etc/netns/<name>/` when the test is done with it.
struct EtcNetns(std::path::PathBuf);

impl EtcNetns {
    fn new(name: &str) -> std::io::Result<Self> {
        let dir = std::path::PathBuf::from("/etc/netns").join(name);
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }
}

impl Drop for EtcNetns {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cat_hosts(cmd: namespace::NetnsCommand) -> nlink::Result<String> {
    let out = cmd.output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The `/etc/netns` overlay as asked (#521): off gives the host's
/// `/etc/hosts`, strict and best effort the namespace's. A bind the kernel
/// refuses — here a directory over a file — fails a strict spawn and is
/// left out of a best-effort one. Where the environment refuses the
/// private mount namespace altogether, best effort runs with the host's.
#[tokio::test]
async fn an_etc_overlay_is_given_as_asked() -> nlink::Result<()> {
    use namespace::{NetnsCommand, Overlay};
    use std::process::Command;
    nlink::require_root!();

    let ns = TestNamespace::new("cmd-overlay")?;
    let etc = EtcNetns::new(ns.name())?;
    std::fs::write(etc.0.join("hosts"), "10.9.9.9 overlaid\n")?;
    let cat = || {
        let mut c = Command::new("cat");
        c.arg("/etc/hosts");
        c
    };
    let run = |overlay| cat_hosts(NetnsCommand::new(ns.name(), cat())?.etc_overlay(overlay));
    assert!(!run(Overlay::Off)?.contains("overlaid"));
    if namespace::etc_overlay_supported() {
        assert!(run(Overlay::Strict)?.contains("overlaid"));
    } else {
        assert!(run(Overlay::Strict).is_err(), "the probe says strict cannot work here");
    }
    // Best effort runs either way, and gets the overlay wherever binds over
    // /etc are allowed — everywhere this suite runs.
    assert!(run(Overlay::BestEffort)?.contains("overlaid"));

    // A bind the kernel refuses: a directory over a file.
    std::fs::remove_file(etc.0.join("hosts"))?;
    std::fs::create_dir(etc.0.join("hosts"))?;
    assert!(run(Overlay::Strict).is_err(), "a strict overlay fails without its bind");
    assert!(!run(Overlay::BestEffort)?.contains("overlaid"));

    // Through a `Netns` opened by name, too.
    let netns = Netns::open(ns.name())?;
    let out = cat_hosts(netns.command(cat())?.etc_overlay(Overlay::Off))?;
    assert!(!out.is_empty());
    Ok(())
}

/// A process starts in its cgroup (#521): it joins before it enters the
/// namespace, so nothing it starts escapes the cgroup.
#[tokio::test]
async fn a_process_starts_in_its_cgroup() -> nlink::Result<()> {
    use namespace::NetnsCommand;
    use std::process::Command;
    nlink::require_root!();
    // cgroupfs is the host's to write.
    nlink::require_host_root!();

    let ns = TestNamespace::new("cmd-cgroup")?;
    let name = format!("nlink-test-{}", std::process::id());
    let dir = std::path::PathBuf::from("/sys/fs/cgroup").join(&name);
    std::fs::create_dir(&dir)?;
    let mut cmd = Command::new("cat");
    cmd.arg("/proc/self/cgroup");
    let out = NetnsCommand::new(ns.name(), cmd)?.cgroup(&dir).output();
    let _ = std::fs::remove_dir(&dir);
    let out = String::from_utf8_lossy(&out?.stdout).into_owned();
    assert_eq!(out.trim(), format!("0::/{name}"));
    Ok(())
}

/// The parent-death signal reaches the process when the thread that
/// spawned it ends (#521).
#[test]
fn pdeathsig_ends_the_process_with_its_spawning_thread() -> nlink::Result<()> {
    use namespace::NetnsCommand;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    nlink::require_root!();

    let ns = TestNamespace::new("cmd-pdeath")?;
    let name = ns.name().to_string();
    let mut child = std::thread::spawn(move || {
        let mut cmd = Command::new("sleep");
        cmd.arg("10");
        NetnsCommand::new(&name, cmd)?.pdeathsig(libc::SIGKILL).spawn()
    })
    .join()
    .expect("the spawning thread")?;
    let started = std::time::Instant::now();
    let status = child.wait()?;
    assert_eq!(status.signal(), Some(libc::SIGKILL), "{status:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    Ok(())
}

/// The parent pid of `pid`, from `/proc`.
fn ppid_of(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status.lines().find_map(|l| l.strip_prefix("PPid:")).and_then(|v| v.trim().parse().ok())
}

/// A detached process is no child of the caller's, runs in the namespace,
/// and with an exit-status file has its exit code written when it ends
/// (#521).
#[test]
fn a_detached_process_runs_in_the_namespace_and_reports_its_exit() -> nlink::Result<()> {
    use namespace::NetnsCommand;
    use std::process::Command;
    use std::time::{Duration, Instant};
    nlink::require_root!();

    let ns = TestNamespace::new("cmd-detached")?;
    let dir = std::env::temp_dir().join(format!("nlink-detached-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let (netns_file, status_file) = (dir.join("netns"), dir.join("status"));
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(format!("readlink /proc/self/ns/net > {}; sleep 0.3; exit 7", netns_file.display()));
    let pid = NetnsCommand::new(ns.name(), cmd)?.exit_status_file(&status_file).spawn_detached()?;
    assert_ne!(ppid_of(pid), Some(std::process::id()), "not the caller's child");

    let started = Instant::now();
    while !status_file.exists() && started.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(std::fs::read_to_string(&status_file)?, "7\n");
    let inode = Netns::open(ns.name())?.id().ino();
    assert_eq!(std::fs::read_to_string(&netns_file)?.trim(), format!("net:[{inode}]"));

    // Without the file, the pid is the command's own; a start that fails
    // is an error here.
    let mut cmd = Command::new("sleep");
    cmd.arg("5");
    let pid = NetnsCommand::new(ns.name(), cmd)?.spawn_detached()?;
    assert!(std::fs::read_to_string(format!("/proc/{pid}/cmdline"))?.starts_with("sleep"));
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    let err = NetnsCommand::new(ns.name(), Command::new("/nonexistent/program"))?
        .spawn_detached()
        .expect_err("no such program");
    assert!(err.to_string().contains("No such file"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// A namespace process as a tokio child (#521): spawned, waited on, and
/// its output collected without blocking the runtime.
#[tokio::test]
async fn a_tokio_child_runs_in_the_namespace() -> nlink::Result<()> {
    use namespace::NetnsCommand;
    use std::process::Command;
    nlink::require_root!();

    let ns = TestNamespace::new("cmd-tokio")?;
    let mut cmd = Command::new("readlink");
    cmd.arg("/proc/self/ns/net");
    let out = NetnsCommand::new(ns.name(), cmd)?.output_async().await?;
    let inode = Netns::open(ns.name())?.id().ino();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), format!("net:[{inode}]"));
    let status = NetnsCommand::new(ns.name(), Command::new("true"))?.spawn_tokio()?.wait().await?;
    assert!(status.success());
    Ok(())
}

/// #520: a handle reads and writes its namespace's sysctls — and only its
/// own: the host's value and another path's reading agree.
#[tokio::test]
async fn a_netns_reads_and_writes_its_own_sysctls() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_writable_sysctl!("/proc/sys/net/ipv4/ip_forward");
    let ns = TestNamespace::new("netns-sysctl")?;
    let netns = Netns::open(ns.name())?;
    let key = "net.ipv4.ip_forward";
    let host = nlink::netlink::sysctl::get(key)?;
    // A new namespace may inherit the host's value: flip whatever it has.
    let want = if netns.sysctl().get(key)? == "1" { "0" } else { "1" };
    netns.sysctl().set(key, want)?;
    assert_eq!(netns.sysctl().get(key)?, want);
    assert_eq!(namespace::get_sysctl(ns.name(), key)?, want, "read another way");
    assert_eq!(nlink::netlink::sysctl::get(key)?, host, "the host's is untouched");

    netns
        .sysctl()
        .set_many(&[("net.ipv4.conf.all.rp_filter", "2"), ("net.ipv4.conf.default.rp_filter", "2")])?;
    assert_eq!(netns.sysctl().get("net/ipv4/conf/all/rp_filter")?, "2");
    let err = netns.sysctl().get("net.ipv4.no_such_key").unwrap_err();
    assert!(err.is_not_found(), "{err}");
    Ok(())
}

/// #520: `pids` names the processes in a namespace, a thread that entered
/// it included.
#[tokio::test]
async fn pids_names_what_is_inside() -> nlink::Result<()> {
    nlink::require_root!();
    let ns = TestNamespace::new("netns-pids")?;
    let netns = Netns::open(ns.name())?;
    assert_eq!(netns.pids()?, Vec::<u32>::new());

    let mut cmd = std::process::Command::new("sleep");
    cmd.arg("30");
    let mut child = netns.command(cmd)?.spawn()?;
    assert_eq!(netns.pids()?, [child.id()]);
    let inside = netns.run(|| netns.pids())??;
    assert!(inside.contains(&std::process::id()), "{inside:?}");

    child.kill().map_err(nlink::Error::from)?;
    child.wait().map_err(nlink::Error::from)?;
    assert_eq!(netns.pids()?, Vec::<u32>::new());
    Ok(())
}

/// Whether `dev` exists in `ns`.
async fn has_link(ns: &TestNamespace, dev: &str) -> nlink::Result<bool> {
    Ok(ns.connection()?.get_link_by_name(dev).await?.is_some())
}

/// #520: `delete_and_wait` tells a namespace that is going from one that
/// something still holds — here a socket inside it — and returns once the
/// kernel is destroying it, its veth's far end following.
#[tokio::test]
async fn delete_and_wait_tells_a_held_namespace_from_a_going_one() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("veth");
    let a = TestNamespace::new("dw-a")?;
    let pid = std::process::id();

    let held_name = format!("nlink-dw-held-{pid}");
    let held = Netns::create(&held_name)?;
    a.exec("ip", &["link", "add", "v0", "type", "veth", "peer", "name", "v1", "netns", &held_name])?;
    let socket = Connection::<Route>::new_in(&held)?;
    let err = held
        .delete_and_wait(Duration::from_millis(500))
        .await
        .expect_err("a socket inside holds the namespace");
    assert!(err.is_timeout(), "{err}");
    assert!(has_link(&a, "v0").await?, "a held namespace keeps its veth");
    drop(socket);

    let name = format!("nlink-dw-free-{pid}");
    let free = Netns::create(&name)?;
    a.exec("ip", &["link", "add", "w0", "type", "veth", "peer", "name", "w1", "netns", &name])?;
    free.delete_and_wait(Duration::from_secs(5)).await?;
    // Its devices go in the same kernel work, moments after the id.
    let end = tokio::time::Instant::now() + Duration::from_secs(5);
    while has_link(&a, "w0").await? {
        assert!(tokio::time::Instant::now() < end, "w0 outlived its namespace");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // And the held one, once its socket went.
    while has_link(&a, "v0").await? {
        assert!(tokio::time::Instant::now() < end, "v0 outlived its namespace");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

/// #520: a `LabNamespace` is its namespace, not its name. Its helpers and
/// connections reach the namespace it made, and dropping it leaves alone
/// a namespace recreated under the name since.
#[tokio::test]
async fn a_lab_namespace_is_the_namespace_it_made() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("dummy");
    let name = format!("nlink-lab-ident-{}", std::process::id());
    let lab = nlink::lab::LabNamespace::named(&name)?;
    lab.add_dummy("d0")?;
    lab.add_addr("d0", "10.77.0.1/24")?;
    lab.link_up("d0")?;
    assert_eq!(lab.netns().id(), Netns::open(&name)?.id());

    namespace::delete(&name)?;
    let other = Netns::create(&name)?;
    // The lab's connection still reaches its own namespace, d0 and all.
    let conn = lab.connection()?;
    assert!(conn.get_link_by_name("d0").await?.is_some(), "the lab's d0");
    assert!(Connection::<Route>::new_in(&other)?.get_link_by_name("d0").await?.is_none());
    drop(conn);

    drop(lab);
    let still = Netns::open(&name).expect("dropping the lab left the new namespace alone");
    assert_eq!(still.id(), other.id());
    other.delete()?;
    Ok(())
}

/// #532: one entry point, `Connection::new_in`, takes every way of naming a
/// namespace, and each reaches the same one. So do the facade and the pool.
#[tokio::test]
async fn every_target_reaches_the_same_namespace() -> nlink::Result<()> {
    use std::os::fd::AsFd;

    use nlink::netlink::namespace::NetnsTarget;
    nlink::require_root!();

    let ns = TestNamespace::new("netns-target")?;
    ns.connection()?.add_link(DummyLink::new("mark0")).await?;
    let netns = Netns::open(ns.name())?;
    let path = std::path::PathBuf::from(format!("/var/run/netns/{}", ns.name()));
    let file = std::fs::File::open(&path)?;
    let mut sleeper = ns.spawn({
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("30");
        cmd
    })?;
    let targets: Vec<NetnsTarget<'_>> = vec![
        ns.name().into(),
        ns.name().to_string().into(),
        (&netns).into(),
        (&ns).into(),
        NetnsRef::Named(ns.name().to_string()).into(),
        NetnsRef::Pid(sleeper.id()).into(),
        path.as_path().into(),
        file.as_fd().into(),
        namespace::NamespaceSpec::Named(ns.name()).into(),
    ];
    for target in targets {
        let conn = Connection::<Route>::new_in(target.clone())?;
        assert_eq!(conn.netns()?.id(), netns.id(), "{target}");
        assert!(conn.get_link_by_name("mark0").await?.is_some(), "{target}");
        // A GENL family resolves its id there.
        let ethtool = Connection::<nlink::netlink::Ethtool>::new_in_async(target.clone()).await?;
        assert_eq!(ethtool.netns()?.id(), netns.id(), "{target}");
    }
    let here = Connection::<Route>::new_in(NetnsRef::Default)?;
    assert!(here.get_link_by_name("mark0").await?.is_none());

    // The facade and the pool take the same targets.
    let cfg = nlink::netlink::config::NetworkConfig::new().link("mark0", |b| b.dummy());
    assert!(nlink::facade::diff::network_in(&netns, &cfg).await?.is_empty());
    assert!(nlink::facade::diff::network_in(ns.name(), &cfg).await?.is_empty());
    let pool = nlink::ConnectionPool::<Route>::new_in(&netns, 1).await?;
    assert!(pool.acquire().await?.get_link_by_name("mark0").await?.is_some());

    let _ = sleeper.kill();
    let _ = sleeper.wait();
    Ok(())
}

/// #257: a process run in a VRF has its sockets bound to it, as `ip vrf
/// exec` does. With the peer's subnet routed only in the VRF's table, `ping`
/// reaches it through `vrf("red")` and not without; the default cgroup is
/// `vrf/<netns inode>/red` under the caller's.
#[tokio::test]
async fn a_process_in_a_vrf_routes_through_its_table() -> nlink::Result<()> {
    use namespace::NetnsCommand;
    use nlink::netlink::link::VrfLink;
    use std::process::Command;
    nlink::require_root!();
    // cgroupfs and BPF program loading are the host's.
    nlink::require_host_root!();
    nlink::require_modules!("vrf", "veth");

    let pair = crate::common::topo::NsPair::new("vrfexec", 98).await?;
    let a: Connection<Route> = pair.a.connection()?;
    a.add_link(VrfLink::new("red", 100)).await?;
    a.set_link_up("red").await?;
    // The veth's connected route moves to table 100.
    a.set_link_master(pair.a_if, "red").await?;
    let ping = || {
        let mut cmd = Command::new("ping");
        cmd.args(["-c", "1", "-W", "1", &pair.b_addr.to_string()]);
        cmd
    };

    let plain = NetnsCommand::new(pair.a.name(), ping())?.output()?;
    assert!(!plain.status.success(), "the main table has no route to the peer");

    let dir = std::path::PathBuf::from("/sys/fs/cgroup").join(format!("nlink-test-vrf-{}", std::process::id()));
    std::fs::create_dir(&dir)?;
    let in_vrf = NetnsCommand::new(pair.a.name(), ping())?.cgroup(&dir).vrf("red").output();
    let _ = std::fs::remove_dir(&dir);
    let in_vrf = in_vrf?;
    assert!(
        in_vrf.status.success(),
        "ping in the VRF: {}",
        String::from_utf8_lossy(&in_vrf.stderr)
    );

    // Without a cgroup of its own: `vrf/<netns inode>/red`, kept.
    let mut cat = Command::new("cat");
    cat.arg("/proc/self/cgroup");
    let out = NetnsCommand::new(pair.a.name(), cat)?.vrf("red").output()?;
    let path = String::from_utf8_lossy(&out.stdout).trim().trim_start_matches("0::").to_string();
    let inode = std::fs::metadata(format!("/run/netns/{}", pair.a.name()))
        .map(|m| std::os::unix::fs::MetadataExt::ino(&m))?;
    assert!(path.ends_with(&format!("/vrf/{inode}/red")), "{path}");
    let dir = std::path::Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/'));
    let _ = std::fs::remove_dir(&dir);
    let _ = std::fs::remove_dir(dir.parent().unwrap());
    Ok(())
}

/// What enters a namespace on a worker thread has left it when it returns
/// (#797): `run`, a connection made through a name (a handle's worker, on a
/// handle dropped straight after) or a path, a sysctl read through a path.
/// Each worker used to exit inside the namespace, and the kernel lets
/// `join` return before it releases the thread's namespaces (the TID is
/// cleared in `exit_mm`, ahead of `exit_task_namespaces`), so for a moment
/// afterwards the namespace still held this process: `pids` listed it,
/// and a `delete_and_wait` could find it held. One integration run in
/// three failed on it under load.
#[tokio::test]
async fn workers_leave_the_namespace_before_they_return() -> nlink::Result<()> {
    nlink::require_root!();
    let ns = TestNamespace::new("netns-run-leaves")?;
    let netns = Netns::open(ns.name())?;
    let path = format!("/var/run/netns/{}", ns.name());
    let nobody_left = |what: &str, i: usize| -> nlink::Result<()> {
        let pids = netns.pids()?;
        assert!(pids.is_empty(), "after {what} #{i}: {pids:?} still inside");
        Ok(())
    };
    for i in 0..2000 {
        netns.run(|| ())?;
        nobody_left("run", i)?;
        drop(Connection::<Route>::new_in(ns.name())?);
        nobody_left("new_in(name)", i)?;
        #[allow(deprecated)]
        drop(Connection::<Route>::new_in_namespace_path(&path)?);
        nobody_left("new_in_namespace_path", i)?;
        namespace::get_sysctl_path(&path, "net.ipv4.ip_forward")?;
        nobody_left("get_sysctl_path", i)?;
    }
    Ok(())
}
