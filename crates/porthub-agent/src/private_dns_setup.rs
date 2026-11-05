//! Enrollment-only DNS integration. Preserve administrator DNS servers and PAM;
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

/// Verify the same libc lookup used by SSH, outside packet forwarding. A
/// resolver registration alone must not make an installation appear DNS-ready.
pub(crate) async fn monitor(
    mut target: tokio::sync::watch::Receiver<Option<(String, std::net::Ipv4Addr)>>,
    result: tokio::sync::watch::Sender<Option<bool>>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    loop {
        let selected = target.borrow_and_update().clone();
        if let Some((hostname, expected)) = selected {
            let lookup_args = vec!["ahostsv4".into(), hostname];
            let lookup = command("/usr/bin/getent", &lookup_args);
            let ready = tokio::select! {
                _=cancel.cancelled()=>return Ok(()),
                answer=lookup=>answer.is_ok_and(|answer|answer.lines().filter_map(|line|line.split_whitespace().next()).any(|address|address.parse::<std::net::Ipv4Addr>()==Ok(expected))),
            };
            result.send_replace(Some(ready));
        } else {
            result.send_replace(None);
        }
        tokio::select! {
            _=cancel.cancelled()=>return Ok(()),
            changed=target.changed()=>{if changed.is_err(){return Ok(());}result.send_replace(None);},
            _=tokio::time::sleep(Duration::from_secs(10))=>{},
        }
    }
}
