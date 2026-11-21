//! Linux system resolver integration. Preserve administrator DNS servers and PAM;
//! rollback if the real system resolver cannot answer after activation.
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

async fn command(program: &str, args: &[String]) -> Result<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::process::Command::new(program)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("DNS setup command timed out")??;
    // Subprocess diagnostics are intentionally excluded: no arbitrary settings,
    // service credentials, or enrollment URLs enter agent logs.
    anyhow::ensure!(
        output.status.success(),
        "DNS setup command failed; check administrator configuration restrictions"
    );
    String::from_utf8(output.stdout).context("invalid DNS setup response")
}
async fn authselect(args: &[String]) -> Result<String> {
    command("/usr/bin/authselect", args).await
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}

pub(crate) fn integrate_hosts(input: &str) -> Result<String> {
    let mut found = 0;
    let mut result = String::new();
    for line in input.lines() {
        let replacement = if let Some((database, services)) = line.split_once(':') {
            if database.trim() == "hosts" {
                found += 1;
                // Preserve mDNS, SSSD and their administrator action predicates.
                // Insert immediately before ordinary DNS, not before other NSS services.
                let services = services.trim_start();
                anyhow::ensure!(!services.starts_with("files ["),"cannot safely integrate private DNS with administrator-specific files actions; configure the hosts lookup policy explicitly");
                let position = services.match_indices("dns").find_map(|(index, _)| {
                    let before = index == 0 || services.as_bytes()[index - 1].is_ascii_whitespace();
                    let after = index + 3 == services.len()
                        || services.as_bytes()[index + 3].is_ascii_whitespace();
                    (before && after).then_some(index)
                });
                match position {
                    Some(index) => format!(
                        "{database}: {}resolve [!UNAVAIL=return] {}",
                        &services[..index],
                        &services[index..]
                    ),
                    None => format!("{database}: {services} resolve [!UNAVAIL=return]"),
                }
            } else {
                line.to_owned()
            }
        } else {
            line.to_owned()
        };
        result.push_str(&replacement);
        result.push('\n');
    }
    anyhow::ensure!(
        found == 1,
        "cannot safely configure private DNS: expected one hosts entry in nsswitch.conf"
    );
    Ok(result)
}
fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"/._-".contains(&c))
}
fn pam_snapshot() -> Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut result = vec![];
    for name in [
        "system-auth",
        "password-auth",
        "fingerprint-auth",
        "smartcard-auth",
        "switchable-auth",
        "postlogin",
    ] {
        let path = Path::new("/etc/pam.d").join(name);
        match std::fs::read(&path) {
            Ok(bytes) => result.push((path, Sha256::digest(bytes).to_vec())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(result)
}
async fn verify() -> Result<()> {
    let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let backend = if crate::private_prerequisites::resolver_stub(&resolv) {
        "dns"
    } else {
        "resolve"
    };
    let answer = command(
        "/usr/bin/getent",
        &args(&["-s", backend, "ahostsv4", "localhost"]),
    )
    .await
    .context("system hostname resolution through systemd-resolved failed")?;
    anyhow::ensure!(
        answer
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .any(|address| address
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())),
        "systemd-resolved did not return a usable hostname lookup"
    );
    anyhow::ensure!(
        crate::private_prerequisites::dns_status()
            == "system hostname lookups use systemd-resolved",
        "private DNS integration was not applied"
    );
    Ok(())
}
fn nonce() -> Result<String> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("DNS backup identifier unavailable"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
async fn configure_authselect() -> Result<()> {
    authselect(&args(&["check"])).await.context(
        "authselect configuration is invalid; refusing to replace administrator settings",
    )?;
    let raw = authselect(&args(&["current", "--raw"])).await?;
    let current: Vec<String> = raw.split_whitespace().map(str::to_owned).collect();
    anyhow::ensure!(
        !current.is_empty() && current.iter().all(|v| safe_identifier(v)),
        "unsupported authselect profile or features"
    );
    let id = nonce()?;
    let name = format!("porthub-dns-{id}");
    let profile = format!("custom/{name}");
    let root = Path::new("/etc/authselect/custom").join(&name);
    anyhow::ensure!(!root.exists(), "private DNS profile already exists");
    let backup = format!("porthub-before-dns-{id}");
    let pam = pam_snapshot()?;
    authselect(&vec![
        "create-profile".into(),
        name,
        "--base-on".into(),
        current[0].clone(),
        "--symlink-pam".into(),
        "--symlink-dconf".into(),
    ])
    .await?;
    let mut activated = false;
    let result = async {
        let template = root.join("nsswitch.conf");
        let original = std::fs::read_to_string(&template)?;
        std::fs::write(&template, integrate_hosts(&original)?)?;
        authselect(&vec!["test".into(), profile.clone(), "--nsswitch".into()]).await?;
        let mut select = vec!["select".into(), profile];
        select.extend(current.iter().skip(1).cloned());
        select.push(format!("--backup={backup}"));
        // Treat a failed activation as possibly partial and restore the native
        // backup. A missing backup is an explicit rollback failure.
        activated = true;
        authselect(&select).await?;
        for (path, digest) in &pam {
            anyhow::ensure!(
                Sha256::digest(std::fs::read(path)?).as_slice() == digest.as_slice(),
                "PAM changed during DNS setup; restoring the original profile"
            );
        }
        authselect(&args(&["check"])).await?;
        verify().await
    }
    .await;
    if result.is_err() {
        if activated {
            authselect(&vec!["backup-restore".into(),backup]).await.context("private DNS setup failed and authselect rollback failed; restore the authselect backup before retrying")?;
        }
        // Only the fresh, nonce-named directory created by this operation.
        std::fs::remove_dir_all(root).context("remove unused private DNS profile")?;
    }
    result
}
fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new_in(
        path.parent().context("DNS configuration parent missing")?,
    )?;
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    file.write_all(contents)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    std::fs::File::open(path.parent().context("DNS configuration parent missing")?)?.sync_all()?;
    Ok(())
}
async fn configure_plain() -> Result<()> {
    let path = Path::new("/etc/nsswitch.conf");
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o022 == 0,
        "cannot safely modify administrator-managed nsswitch.conf"
    );
    let original = std::fs::read_to_string(path)?;
    anyhow::ensure!(!original.to_ascii_lowercase().contains("generated by"),"nsswitch.conf is managed by another tool; configure private DNS through that administrator tool");
    let replacement = integrate_hosts(&original)?;
    update_plain_verified(
        path,
        &original,
        &replacement,
        metadata.mode() & 0o777,
        verify(),
    )
    .await
}
async fn update_plain_verified<F: std::future::Future<Output = Result<()>>>(
    path: &Path,
    original: &str,
    replacement: &str,
    mode: u32,
    verification: F,
) -> Result<()> {
    use std::io::Write;
    let backup = path.with_file_name(format!("nsswitch.conf.porthub-backup-{}", nonce()?));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&backup)?;
    file.write_all(original.as_bytes())?;
    file.sync_all()?;
    anyhow::ensure!(
        std::fs::read_to_string(path)? == original,
        "nsswitch.conf changed during enrollment; retry after administrator changes finish"
    );
    atomic_write(path, replacement.as_bytes(), mode)?;
    if let Err(error) = verification.await {
        anyhow::ensure!(std::fs::read_to_string(path)?==replacement,"DNS setup failed while administrator configuration changed; original configuration is in the nsswitch.conf.porthub-backup file");
        atomic_write(path,original.as_bytes(),mode).context("private DNS verification failed and rollback failed; restore the nsswitch.conf.porthub-backup file")?;
        return Err(error);
    }
    Ok(())
}

pub(crate) async fn configure() -> Result<()> {
    anyhow::ensure!(
        unsafe { libc::geteuid() } == 0,
        "private DNS integration requires privileged enrollment"
    );
    let nss = std::fs::read_to_string("/etc/nsswitch.conf")?;
    let resolver = std::fs::read_to_string("/etc/resolv.conf")?;
    if crate::private_prerequisites::dns_integrated(&nss, &resolver) {
        return verify().await;
    }
    if Path::new("/usr/bin/authselect").is_file() {
        configure_authselect().await
    } else {
        configure_plain().await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peer_rename_wakes_the_probe_without_changing_its_resolver_link() {
        let address = std::net::Ipv4Addr::new(10, 203, 11, 3);
        let link = LinkDns {
            interface: "phtest0".into(),
            index: 3,
            port: 5353,
            suffixes: vec!["phub".into()],
        };
        let (target, mut updates) = tokio::sync::watch::channel(Some(LookupTarget {
            hostname: "old.phub".into(),
            address,
            link: Some(link.clone()),
        }));

        update_probe_hostname(&target, "old.phub");
        assert!(!updates.has_changed().unwrap());
        update_probe_hostname(&target, "new.phub");
        assert!(updates.has_changed().unwrap());
        {
            let latest = updates.borrow_and_update();
            let probe = latest.as_ref().unwrap();
            assert_eq!(probe.hostname, "new.phub");
            assert_eq!(probe.address, address);
            assert!(probe.link.as_ref() == Some(&link));
        }
        update_probe_hostname(&target, "new.phub");
        assert!(!updates.has_changed().unwrap());
    }

    #[tokio::test]
    #[ignore = "requires a disposable network namespace with a private systemd-resolved and vpn-test-other"]
    async fn skips_repair_on_a_reused_interface_index() -> Result<()> {
        anyhow::ensure!(
            std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1")
                && Path::new("/.dockerenv").is_file(),
            "owned namespace required"
        );
        let index = std::fs::read_to_string("/sys/class/net/vpn-test-other/ifindex")?
            .trim()
            .parse()?;
        let foreign = LinkDns {
            interface: "vpn-test-other".into(),
            index,
            port: 53,
            suffixes: vec!["other-vpn.invalid".into()],
        };
        let dns_server = "192.0.2.9".parse()?;
        assert!(foreign.matches(dns_server).await?);
        let lock = tokio::sync::Mutex::new(());
        for (interface, address) in [("phtest0", "192.0.2.7"), ("vpn-test-other", "10.219.94.2")] {
            let stale = LookupTarget {
                hostname: "fixture.phub".into(),
                address: address.parse()?,
                link: Some(LinkDns {
                    interface: interface.into(),
                    index,
                    port: 5353,
                    suffixes: vec!["phub".into()],
                }),
            };
            let (_sender, target) = tokio::sync::watch::channel(Some(stale.clone()));
            assert!(!stale.repair_if_stale(&target, &lock, Some(5533)).await?);
            assert!(foreign.matches(dns_server).await?);
        }
        Ok(())
    }

    #[test]
    fn integrates_rhel_hosts_without_touching_other_databases_or_authentication() {
        let original="# managed by authselect\npasswd: files systemd\nhosts: files dns myhostname\nshadow: files\n";
        let updated = integrate_hosts(original).unwrap();
        assert!(updated.contains("hosts: files resolve [!UNAVAIL=return] dns myhostname"));
        assert!(updated.contains("passwd: files systemd\n"));
        assert!(updated.contains("shadow: files\n"));
        assert!(crate::private_prerequisites::dns_integrated(
            &updated,
            "nameserver 172.31.0.2"
        ));
    }
    #[test]
    fn preserves_mdns_actions_and_authselect_feature_templates() {
        let original =
            "hosts: files {if \"with-mdns4\":mdns4_minimal [NOTFOUND=return] } dns myhostname\n";
        let updated = integrate_hosts(original).unwrap();
        assert!(updated.contains("{if \"with-mdns4\":mdns4_minimal [NOTFOUND=return] } resolve [!UNAVAIL=return] dns myhostname"));
        assert!(integrate_hosts("passwd: files\n").is_err());
        assert!(integrate_hosts("hosts: files dns\nhosts: files dns\n").is_err());
    }
    #[test]
    fn authselect_profile_and_feature_values_cannot_become_options_or_shell_commands() {
        for value in ["local", "sssd", "custom/company-local", "with-faillock"] {
            assert!(safe_identifier(value));
        }
        for value in ["--force", ";id", "$(id)", "with feature", ""] {
            assert!(!safe_identifier(value));
        }
    }
}

#[cfg(test)]
mod rollback_tests {
    use super::*;
    #[tokio::test]
    async fn failed_system_lookup_restores_the_original_configuration_and_keeps_a_private_backup(
    ) -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("nsswitch.conf");
        let original = "passwd: files\nhosts: files dns\n";
        std::fs::write(&path, original)?;
        let replacement = integrate_hosts(original)?;
        let result = update_plain_verified(&path, original, &replacement, 0o644, async {
            anyhow::bail!("simulated resolver failure")
        })
        .await;
        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(&path)?, original);
        let backup = std::fs::read_dir(directory.path())?
            .filter_map(|entry| entry.ok())
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("nsswitch.conf.porthub-backup-")
            })
            .unwrap();
        assert_eq!(std::fs::read_to_string(backup.path())?, original);
        assert_eq!(backup.metadata()?.mode() & 0o777, 0o600);
        Ok(())
    }
    #[tokio::test]
    async fn concurrent_administrator_edits_are_not_overwritten_during_rollback() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("nsswitch.conf");
        let original = "hosts: files dns\n";
        std::fs::write(&path, original)?;
        let replacement = integrate_hosts(original)?;
        let result = update_plain_verified(&path, original, &replacement, 0o644, async {
            std::fs::write(&path, "hosts: files dns # administrator edit\n")?;
            anyhow::bail!("simulated resolver failure")
        })
        .await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("administrator configuration changed"));
        assert!(std::fs::read_to_string(path)?.contains("administrator edit"));
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LookupTarget {
    pub hostname: String,
    pub address: std::net::Ipv4Addr,
    pub link: Option<LinkDns>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LinkDns {
    pub interface: String,
    pub index: u32,
    pub port: u16,
    pub suffixes: Vec<String>,
}

impl LinkDns {
    async fn matches(&self, own: std::net::Ipv4Addr) -> Result<bool> {
        let bus = zbus::Connection::system().await?;
        let manager = zbus::Proxy::new(
            &bus,
            "org.freedesktop.resolve1",
            "/org/freedesktop/resolve1",
            "org.freedesktop.resolve1.Manager",
        )
        .await?;
        let path: zbus::zvariant::OwnedObjectPath =
            manager.call("GetLink", &(self.index as i32,)).await?;
        let link = zbus::Proxy::new(
            &bus,
            "org.freedesktop.resolve1",
            path,
            "org.freedesktop.resolve1.Link",
        )
        .await?;
        let servers: Vec<(i32, Vec<u8>, u16, String)> = link.get_property("DNSEx").await?;
        let domains: Vec<(String, bool)> = link.get_property("Domains").await?;
        let default_route: bool = link.get_property("DefaultRoute").await?;
        let expected_domains = self
            .suffixes
            .iter()
            .all(|s| domains.iter().any(|(d, routing)| d == s && *routing));
        Ok(!default_route
            && domains.len() == self.suffixes.len()
            && expected_domains
            && servers.len() == 1
            && servers[0].0 == libc::AF_INET
            && servers[0].1 == own.octets()
            && (servers[0].2 == self.port || self.port == 53 && servers[0].2 == 0)
            && servers[0].3.is_empty())
    }
}

pub(crate) fn update_probe_hostname(
    target: &tokio::sync::watch::Sender<Option<LookupTarget>>,
    hostname: &str,
) {
    target.send_if_modified(|current| match current {
        Some(probe) if probe.hostname != hostname => {
            hostname.clone_into(&mut probe.hostname);
            true
        }
        _ => false,
    });
}

impl LookupTarget {
    async fn repair_if_stale(
        &self,
        target: &tokio::sync::watch::Receiver<Option<Self>>,
        registration: &tokio::sync::Mutex<()>,
        alternate: Option<u16>,
    ) -> Result<bool> {
        let Some(link) = &self.link else {
            return Ok(false);
        };
        // Read the owned link before changing anything. NSS can resolve the
        // agent hostname even when a different private suffix has disappeared.
        if alternate.is_none() && link.matches(self.address).await? {
            return Ok(false);
        }
        let _guard = registration.lock().await;
        if target.has_changed()? {
            return Ok(false);
        }
        // A retired device's numeric index can be reused by another VPN.
        let owns_address = getifaddrs::getifaddrs()?.any(|interface| {
            interface.index == Some(link.index)
                && interface.name == link.interface
                && interface.address.ip_addr() == Some(std::net::IpAddr::V4(self.address))
        });
        if !owns_address {
            return Ok(false);
        }
        crate::private_network::dns::configure_linux_link(
            link.index,
            self.address,
            link.port,
            &link.suffixes,
            false,
            alternate,
        )
        .await?;
        Ok(true)
    }
}

/// resolved atomically updates or removes its per-link state file. Directory
/// notifications are wakeups only. D-Bus remains the source of truth.
fn watch_resolved_link(
    index: u32,
    changed: tokio::sync::mpsc::Sender<()>,
) -> notify::Result<notify::RecommendedWatcher> {
    use notify::{EventKind, RecursiveMode, Watcher};
    let directory = Path::new("/run/systemd/resolve/netif");
    let state = directory.join(index.to_string());
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        let relevant = match event {
            Ok(event) => {
                event.need_rescan()
                    || matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    ) && event
                        .paths
                        .iter()
                        .any(|path| path == &state || path == directory)
            }
            Err(_) => true,
        };
        if relevant {
            let _ = changed.try_send(());
        }
    })?;
    watcher.watch(directory, RecursiveMode::NonRecursive)?;
    Ok(watcher)
}

#[derive(Clone, Copy)]
pub(crate) struct RestoredSource {
    pub index: u32,
    pub address: std::net::Ipv4Addr,
    pub port: u16,
    pub alternate: u16,
}

async fn monitor_link_registration(
    mut target: tokio::sync::watch::Receiver<Option<LookupTarget>>,
    registration: std::sync::Arc<tokio::sync::Mutex<()>>,
    mut lookup_failures: tokio::sync::mpsc::Receiver<()>,
    mut restorations: tokio::sync::watch::Receiver<Option<RestoredSource>>,
    repaired: &tokio::sync::Notify,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<()> {
    let (changed, mut changes) = tokio::sync::mpsc::channel(1);
    let mut watcher = None;
    let mut restore: Option<RestoredSource> = None;
    let mut next_failed_probe_check = tokio::time::Instant::now();
    loop {
        let selected = target.borrow_and_update().clone();
        let index = selected
            .as_ref()
            .and_then(|probe| probe.link.as_ref())
            .map(|link| link.index);
        if watcher.as_ref().map(|(index, _)| *index) != index {
            watcher = index.and_then(|index| {
                watch_resolved_link(index, changed.clone())
                    .ok()
                    .map(|w| (index, w))
            });
        }
        restore = restore.filter(|event| selected.as_ref().is_some_and(|probe| {
            probe.address == event.address && probe.link.as_ref().is_some_and(|link|
                link.index == event.index && link.port == event.port)
        }));
        if let Some(probe) = selected.as_ref().filter(|probe| probe.link.is_some()) {
            if matches!(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    probe.repair_if_stale(&target, &registration, restore.map(|event| event.alternate))
                )
                .await,
                Ok(Ok(true))
            ) {
                tracing::debug!("restored private DNS on the tunnel interface");
                restore = None;
                repaired.notify_one();
            }
        }

        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            event = restorations.changed() => {
                if event.is_err() { return Ok(()); }
                restore = *restorations.borrow_and_update();
            }
            _ = tokio::time::sleep(Duration::from_secs(1)), if restore.is_some() => {}
            changed = target.changed() => {
                if changed.is_err() { return Ok(()); }
                next_failed_probe_check = tokio::time::Instant::now();
            }
            _ = changes.recv(), if watcher.is_some() => {
                // Coalesce one resolved transaction and reattach if the daemon
                // replaced the directory. Only D-Bus readback can trigger a write.
                watcher = None;
                tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                }
            }
            failure = lookup_failures.recv(), if index.is_some() && tokio::time::Instant::now() >= next_failed_probe_check => {
                if failure.is_none() { return Ok(()); }
                next_failed_probe_check = tokio::time::Instant::now() + Duration::from_secs(30);
            }
            // Older resolvers may never create the notification directory.
            _ = tokio::time::sleep(Duration::from_secs(30)), if index.is_some() => {}
        }
    }
}

/// Verify the same libc lookup used by SSH, outside packet forwarding. Native
/// resolver repair must keep running even when another NSS provider is slow.
pub(crate) async fn monitor(
    mut target: tokio::sync::watch::Receiver<Option<LookupTarget>>,
    result: tokio::sync::watch::Sender<Option<bool>>,
    restorations: tokio::sync::watch::Receiver<Option<RestoredSource>>,
    registration: std::sync::Arc<tokio::sync::Mutex<()>>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let (failed, failures) = tokio::sync::mpsc::channel(1);
    let repaired = tokio::sync::Notify::new();
    let native =
        monitor_link_registration(target.clone(), registration, failures, restorations, &repaired, &cancel);
    let lookups = async {
        loop {
            let selected = target.borrow_and_update().clone();
            if let Some(selected) = selected {
                let expected = selected.address;
                let lookup_args = vec!["ahostsv4".into(), selected.hostname];
                let ready = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    _ = repaired.notified() => continue,
                    changed = target.changed() => {
                        if changed.is_err() { return Ok(()); }
                        result.send_replace(None);
                        continue;
                    }
                    answer = command("/usr/bin/getent", &lookup_args) => answer.is_ok_and(|answer|
                        answer.lines().filter_map(|line| line.split_whitespace().next())
                            .any(|address| address.parse::<std::net::Ipv4Addr>() == Ok(expected))),
                };
                match target.has_changed() {
                    Ok(true) => continue,
                    Err(_) => return Ok(()),
                    Ok(false) => {}
                }
                result.send_replace(Some(ready));
                if !ready && selected.link.is_some() {
                    let _ = failed.try_send(());
                }
            } else {
                result.send_replace(None);
            }
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                changed = target.changed() => {
                    if changed.is_err() { return Ok(()); }
                    result.send_replace(None);
                }
                _ = repaired.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(10)) => {}
            }
        }
    };
    tokio::try_join!(native, lookups)?;
    Ok(())
}
