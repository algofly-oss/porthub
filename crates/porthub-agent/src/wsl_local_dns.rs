//! WSL's NAT resolver can resolve Windows mDNS names while resolved deliberately
//! rejects `.local` without mDNS. Route only that suffix to the existing NAT DNS.
use anyhow::{ensure, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, path::Path, time::Duration};
use tokio_util::sync::CancellationToken;
type Dns = (i32, Vec<u8>, u16, String);
const ROOT: &str = "/run/porthub-wsl-local-dns";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Snapshot {
    dns: Vec<Dns>,
    domains: Vec<(String, bool)>,
    default_route: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Receipt {
    kind: String,
    interface: String,
    index: i32,
    gateway: Ipv4Addr,
    original: Snapshot,
    managed: Snapshot,
}
#[derive(Debug, PartialEq, Eq)]
struct Candidate {
    interface: String,
    index: i32,
    gateway: Ipv4Addr,
}
fn candidate(routes: &str, resolv: &str) -> Option<(String, Ipv4Addr)> {
    let servers: Vec<_> = resolv
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("nameserver"))
                .then(|| words.next()?.parse::<Ipv4Addr>().ok())
                .flatten()
        })
        .collect();
    routes.lines().skip(1).find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 4
            || fields[0] != "eth0"
            || fields[1] != "00000000"
            || fields[0].is_empty()
            || !fields[0]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        {
            return None;
        }
        let flags = u32::from_str_radix(fields[3], 16).ok()?;
        if flags & 3 != 3 {
            return None;
        }
        let gateway = Ipv4Addr::from(u32::from_str_radix(fields[2], 16).ok()?.to_le_bytes());
        servers
            .contains(&gateway)
            .then(|| (fields[0].to_owned(), gateway))
    })
}
fn discover() -> Option<Candidate> {
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    for file in ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"] {
        let Some((interface, gateway)) = std::fs::read_to_string(file)
            .ok()
            .and_then(|resolv| candidate(&routes, &resolv))
        else {
            continue;
        };
        let index = std::fs::read_to_string(format!("/sys/class/net/{interface}/ifindex"))
            .ok()?
            .trim()
            .parse()
            .ok()?;
        return Some(Candidate {
            interface,
            index,
            gateway,
        });
    }
    None
}
fn desired(
    current: &Snapshot,
    gateway: Ipv4Addr,
    routes: &[(i32, String, bool)],
    mdns: &str,
) -> Option<Snapshot> {
    // Respect existing administrator routing, mDNS and non-NAT link DNS.
    if !matches!(mdns, "no" | "false")
        || routes
            .iter()
            .any(|(_, name, _)| name.trim_end_matches('.').eq_ignore_ascii_case("local"))
    {
        return None;
    }
    let nat = (libc::AF_INET, gateway.octets().to_vec(), 0, String::new());
    if !current.dns.is_empty() && current.dns != vec![nat.clone()] {
        return None;
    }
    let mut next = current.clone();
    if next.dns.is_empty() {
        next.dns.push(nat);
    }
    next.domains.push(("local".into(), true));
    Some(next)
}
fn recognizable(current: &Snapshot, receipt: &Receipt) -> bool {
    // Interrupted writes are recoverable; administrator changes are preserved.
    (current.dns == receipt.original.dns || current.dns == receipt.managed.dns)
        && (current.domains == receipt.original.domains
            || current.domains == receipt.managed.domains)
        && (current.default_route == receipt.original.default_route
            || current.default_route == receipt.managed.default_route)
}
async fn link<'a>(connection: &'a zbus::Connection, index: i32) -> Result<zbus::Proxy<'a>> {
    let manager = manager(connection).await?;
    let path: zbus::zvariant::OwnedObjectPath = manager.call("GetLink", &index).await?;
    Ok(zbus::Proxy::new_owned(
        connection.clone(),
        "org.freedesktop.resolve1",
        path,
        "org.freedesktop.resolve1.Link",
    )
    .await?)
}
async fn manager(connection: &zbus::Connection) -> Result<zbus::Proxy<'_>> {
    Ok(zbus::Proxy::new(
        connection,
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
    )
    .await?)
}
async fn snapshot(connection: &zbus::Connection, index: i32) -> Result<Snapshot> {
    let proxy = link(connection, index).await?;
    Ok(Snapshot {
        dns: proxy.get_property("DNSEx").await?,
        domains: proxy.get_property("Domains").await?,
        default_route: proxy.get_property("DefaultRoute").await?,
    })
}
async fn write(
    connection: &zbus::Connection,
    index: i32,
    expected: &Snapshot,
    state: &Snapshot,
) -> Result<()> {
    let proxy = manager(connection).await?;
    let mut stage = expected.clone();
    ensure!(
        snapshot(connection, index).await? == stage,
        "WSL DNS changed before activation; preserving administrator configuration"
    );
    if stage.dns != state.dns {
        proxy
            .call::<_, _, ()>("SetLinkDNSEx", &(index, &state.dns))
            .await?;
        stage.dns = state.dns.clone();
    }
    ensure!(
        snapshot(connection, index).await? == stage,
        "WSL DNS changed during activation; preserving administrator configuration"
    );
    if stage.domains != state.domains {
        proxy
            .call::<_, _, ()>("SetLinkDomains", &(index, &state.domains))
            .await?;
        stage.domains = state.domains.clone();
    }
    ensure!(
        snapshot(connection, index).await? == stage,
        "WSL DNS changed during activation; preserving administrator configuration"
    );
    if stage.default_route != state.default_route {
        proxy
            .call::<_, _, ()>("SetLinkDefaultRoute", &(index, state.default_route))
            .await?;
    }
    proxy.call::<_, _, ()>("FlushCaches", &()).await?;
    Ok(())
}
async fn reachable(gateway: Ipv4Addr) -> Result<()> {
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RecordType},
    };
    let mut query = Message::new(0x5048, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii("localhost.")?, RecordType::A));
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect((gateway, 53)).await?;
    socket.send(&query.to_vec()?).await?;
    let mut bytes = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut bytes)).await??;
    let reply = Message::from_vec(&bytes[..n])?;
    ensure!(
        reply.id == query.id && reply.message_type == MessageType::Response,
        "WSL NAT resolver did not answer its probe"
    );
    Ok(())
}
async fn revert(connection: &zbus::Connection, receipt: &Receipt, path: &Path) -> Result<()> {
    let current = snapshot(connection, receipt.index).await?;
    ensure!(
        recognizable(&current, receipt),
        "WSL DNS settings changed outside PortHub; preserving administrator configuration"
    );
    if current != receipt.original {
        write(connection, receipt.index, &current, &receipt.original).await?;
    }
    std::fs::remove_file(path)?;
    Ok(())
}
// WSL installs wslinfo as /usr/bin/wslinfo -> /init. Validate its root-owned
// non-writable chain, but execute the original name: /init dispatches by argv0.
fn trusted_wslinfo(root: &Path, owner: u32) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let protected = |path: &Path, directory: bool| {
        std::fs::symlink_metadata(path).is_ok_and(|m| {
            m.uid() == owner
                && m.permissions().mode() & 0o022 == 0
                && if directory {
                    m.is_dir()
                } else {
                    m.is_file() && m.permissions().mode() & 0o111 != 0
                }
        })
    };
    for path in [root.to_owned(), root.join("usr"), root.join("usr/bin")] {
        if !protected(&path, true) {
            return false;
        }
    }
    let path = root.join("usr/bin/wslinfo");
    let Ok(metadata) = std::fs::symlink_metadata(&path) else {
        return false;
    };
    if metadata.file_type().is_symlink() {
        metadata.uid() == owner
            && std::fs::read_link(&path).is_ok_and(|target| target == Path::new("/init"))
            && protected(&root.join("init"), false)
    } else {
        protected(&path, false)
    }
}
async fn nat_mode() -> bool {
    let path = Path::new("/usr/bin/wslinfo");
    if !trusted_wslinfo(Path::new("/"), 0) {
        return false;
    }
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::process::Command::new(path)
            .arg("--networking-mode")
            .kill_on_drop(true)
            .output(),
    )
    .await;
    matches!(result,Ok(Ok(output)) if output.status.success()&&output.stdout==b"nat\n")
}
async fn reconcile() -> Result<()> {
    let integrated = std::fs::read_to_string("/etc/nsswitch.conf")
        .ok()
        .zip(std::fs::read_to_string("/etc/resolv.conf").ok())
        .is_some_and(|(nss, resolv)| crate::private_prerequisites::dns_integrated(&nss, &resolv));
    let wanted = if integrated && nat_mode().await {
        discover()
    } else {
        None
    };
    let root = Path::new(ROOT);
    let path = root.join("state.json");
    if wanted.is_none() && !path.try_exists()? {
        return Ok(());
    }
    crate::service::directory(root, true)?;
    let lock_path = root.join("lock");
    if !lock_path.try_exists()? {
        let _ = crate::profile::write_private(&lock_path, b"", false);
    }
    let lock = crate::profile::open_private_lock(&lock_path)?;
    if let Err(error) = lock.try_lock_exclusive() {
        if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
            return Ok(());
        }
        return Err(error.into());
    }
    let receipt: Option<Receipt> = if path.try_exists()? {
        Some(serde_json::from_slice(&crate::profile::read_private(
            &path,
        )?)?)
    } else {
        None
    };
    if let Some(old) = &receipt {
        ensure!(
            old.kind == "porthub.wsl-local-dns.v1",
            "Unrecognized WSL DNS ownership receipt"
        );
    }
    let connection = zbus::Connection::system().await?;
    let Some(wanted) = wanted else {
        if let Some(old) = receipt {
            revert(&connection, &old, &path).await?;
        }
        return Ok(());
    };
    let mut current = snapshot(&connection, wanted.index).await?;
    let routes: Vec<(i32, String, bool)> =
        manager(&connection).await?.get_property("Domains").await?;
    let mdns: String = link(&connection, wanted.index)
        .await?
        .get_property("MulticastDNS")
        .await?;
    if let Some(old) = &receipt {
        if old.index == wanted.index
            && old.interface == wanted.interface
            && old.gateway == wanted.gateway
        {
            if !matches!(mdns.as_str(), "no" | "false")
                || routes.iter().any(|(index, name, _)| {
                    *index != wanted.index
                        && name.trim_end_matches('.').eq_ignore_ascii_case("local")
                })
            {
                revert(&connection, old, &path).await?;
                return Ok(());
            }
            if current == old.managed {
                return Ok(());
            }
            ensure!(
                recognizable(&current, old),
                "WSL DNS settings changed outside PortHub; preserving administrator configuration"
            );
            reachable(wanted.gateway).await?;
            write(&connection, wanted.index, &current, &old.managed).await?;
            return Ok(());
        }
        revert(&connection, old, &path).await?;
        current = snapshot(&connection, wanted.index).await?;
    }
    let Some(managed) = desired(&current, wanted.gateway, &routes, &mdns) else {
        return Ok(());
    };
    reachable(wanted.gateway).await?;
    let receipt = Receipt {
        kind: "porthub.wsl-local-dns.v1".into(),
        interface: wanted.interface,
        index: wanted.index,
        gateway: wanted.gateway,
        original: current,
        managed,
    };
    crate::profile::write_private(&path, &serde_json::to_vec_pretty(&receipt)?, false)?;
    if let Err(error) = write(
        &connection,
        receipt.index,
        &receipt.original,
        &receipt.managed,
    )
    .await
    {
        revert(&connection, &receipt, &path)
            .await
            .context("WSL local DNS activation and owned rollback failed")?;
        return Err(error);
    }
    Ok(())
}
/// Native runtime reconciliation persists across upgrades and WSL restarts.
/// Leaving the ordinary-DNS route on process shutdown matches the persistent
/// NSS integration; the owned receipt enables safe adoption and reversion.
pub(crate) fn start(parent: &CancellationToken) -> Option<tokio_util::sync::DropGuard> {
    if !crate::os_info::is_wsl() || unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let cancel = parent.child_token();
    let work = cancel.clone();
    tokio::spawn(async move {
        loop {
            if let Err(_) = reconcile().await {
                tracing::debug!("WSL local DNS reconciliation unavailable; administrator DNS configuration preserved");
            }
            tokio::select! {_=work.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(30))=>{}}
        }
    });
    Some(cancel.drop_guard())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn empty() -> Snapshot {
        Snapshot {
            dns: vec![],
            domains: vec![],
            default_route: false,
        }
    }
    #[test]
    fn official_wslinfo_symlink_is_trusted_without_weakening_path_ownership() -> Result<()> {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir()?;
        let root = root.path();
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        let owner = rustix::process::getuid().as_raw();
        std::fs::create_dir(root.join("usr"))?;
        std::fs::create_dir(root.join("usr/bin"))?;
        for path in [root.join("usr"), root.join("usr/bin")] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
        }
        std::fs::write(root.join("init"), b"trusted fixture, never executed")?;
        std::fs::set_permissions(root.join("init"), std::fs::Permissions::from_mode(0o755))?;
        symlink("/init", root.join("usr/bin/wslinfo"))?;
        assert!(
            trusted_wslinfo(root, owner),
            "Official root-protected symlink must be accepted"
        );
        assert!(
            !trusted_wslinfo(root, owner.wrapping_add(1)),
            "Foreign owner must be rejected"
        );
        std::fs::set_permissions(root.join("usr/bin"), std::fs::Permissions::from_mode(0o777))?;
        assert!(
            !trusted_wslinfo(root, owner),
            "Writable parent must be rejected"
        );
        std::fs::set_permissions(root.join("usr/bin"), std::fs::Permissions::from_mode(0o755))?;
        std::fs::set_permissions(root.join("init"), std::fs::Permissions::from_mode(0o777))?;
        assert!(
            !trusted_wslinfo(root, owner),
            "Writable init target must be rejected"
        );
        std::fs::set_permissions(root.join("init"), std::fs::Permissions::from_mode(0o755))?;
        std::fs::remove_file(root.join("usr/bin/wslinfo"))?;
        symlink("/bin/sh", root.join("usr/bin/wslinfo"))?;
        assert!(
            !trusted_wslinfo(root, owner),
            "Unrecognized symlink target must be rejected"
        );
        std::fs::remove_file(root.join("usr/bin/wslinfo"))?;
        std::fs::write(
            root.join("usr/bin/wslinfo"),
            b"regular trusted executable fixture",
        )?;
        std::fs::set_permissions(
            root.join("usr/bin/wslinfo"),
            std::fs::Permissions::from_mode(0o755),
        )?;
        assert!(
            trusted_wslinfo(root, owner),
            "Existing regular root-owned executable remains supported"
        );
        Ok(())
    }
    #[tokio::test]
    #[ignore = "requires explicit root WSL execution with an already owned DNS route"]
    async fn native_wsl_upgrade_adopts_existing_route_without_mutation() -> Result<()> {
        ensure!(
            crate::os_info::is_wsl()
                && unsafe { libc::geteuid() } == 0
                && std::env::var("PORTHUB_TEST_WSL_LOCAL_DNS").as_deref() == Ok("1"),
            "Explicit owned WSL fixture required"
        );
        let path = Path::new(ROOT).join("state.json");
        let before = crate::profile::read_private(&path)?;
        let receipt: Receipt = serde_json::from_slice(&before)?;
        ensure!(
            receipt.kind == "porthub.wsl-local-dns.v1" && receipt.original != receipt.managed,
            "Existing owned bridge fixture required"
        );
        let connection = zbus::Connection::system().await?;
        ensure!(
            snapshot(&connection, receipt.index).await? == receipt.managed,
            "Current DNS must already match its owned receipt"
        );
        let routes: Vec<(i32, String, bool)> =
            manager(&connection).await?.get_property("Domains").await?;
        reconcile().await?;
        reconcile().await?;
        assert_eq!(
            crate::profile::read_private(&path)?,
            before,
            "Upgrade replaced the original snapshot"
        );
        assert_eq!(snapshot(&connection, receipt.index).await?, receipt.managed);
        assert_eq!(
            manager(&connection)
                .await?
                .get_property::<Vec<(i32, String, bool)>>("Domains")
                .await?,
            routes
        );
        Ok(())
    }

    #[test]
    fn only_existing_nat_gateway_dns_qualifies() {
        let route="Iface Destination Gateway Flags\neth0 00000000 01E015AC 0003\npha0 00000000 0100CB0A 0003\n";
        assert_eq!(
            candidate(route, "nameserver 172.21.224.1\n"),
            Some(("eth0".into(), "172.21.224.1".parse().unwrap()))
        );
        for resolv in [
            "nameserver 1.1.1.1",
            "nameserver 127.0.0.53",
            "nameserver 10.203.0.1",
        ] {
            assert!(candidate(route, resolv).is_none());
        }
    }
    #[test]
    fn route_is_local_only_and_preserves_private_suffix_and_default_policy() {
        let current = Snapshot {
            domains: vec![("corp".into(), true)],
            ..empty()
        };
        let next = desired(
            &current,
            "172.21.224.1".parse().unwrap(),
            &[(5, "phub".into(), true)],
            "no",
        )
        .unwrap();
        assert_eq!(
            next.domains,
            vec![("corp".into(), true), ("local".into(), true)]
        );
        assert_eq!(next.default_route, current.default_route);
    }
    #[test]
    fn administrator_local_routes_mdns_and_dns_are_not_overwritten() {
        let ip = "172.21.224.1".parse().unwrap();
        assert!(desired(&empty(), ip, &[(5, "local".into(), true)], "no").is_none());
        assert!(desired(&empty(), ip, &[(5, "LOCAL.".into(), true)], "no").is_none());
        assert!(desired(&empty(), ip, &[], "yes").is_none());
        let changed = Snapshot {
            dns: vec![(2, vec![1, 1, 1, 1], 0, String::new())],
            ..empty()
        };
        assert!(desired(&changed, ip, &[], "no").is_none());
    }
    #[test]
    fn repeated_upgrade_and_partial_rollback_keep_original_snapshot() {
        let original = empty();
        let managed = desired(&original, "172.21.224.1".parse().unwrap(), &[], "no").unwrap();
        let receipt = Receipt {
            kind: "porthub.wsl-local-dns.v1".into(),
            interface: "eth0".into(),
            index: 2,
            gateway: "172.21.224.1".parse().unwrap(),
            original: original.clone(),
            managed: managed.clone(),
        };
        assert!(recognizable(&original, &receipt) && recognizable(&managed, &receipt));
        assert!(recognizable(
            &Snapshot {
                dns: managed.dns.clone(),
                ..original
            },
            &receipt
        ));
        let administrator = Snapshot {
            domains: vec![("local".into(), false)],
            ..managed
        };
        assert!(!recognizable(&administrator, &receipt));
        let decoded: Receipt =
            serde_json::from_slice(&serde_json::to_vec(&receipt).unwrap()).unwrap();
        assert_eq!(decoded.original, empty());
    }
}
