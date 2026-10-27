//! One-time handover of the generated macOS private launchd service. The public
//! service remains running. A durable journal restores the old service if a
//! handover is interrupted or the native packet runtime does not become ready.
use crate::{private_profile, profile, service::{self, Layout, Readiness}};
use anyhow::{ensure, Context, Result};
use std::{path::Path, time::Duration};
use tokio::process::Command;

const LABEL: &str = "system/com.porthub.private";
const UNIT: &str = "/Library/LaunchDaemons/com.porthub.private.plist";
const PROFILE: &str = "/usr/local/etc/porthub/private.json";

async fn launch(arguments: &[&str]) -> Result<std::process::Output> {
    Ok(tokio::time::timeout(Duration::from_secs(15), Command::new("/bin/launchctl")
        .args(arguments).kill_on_drop(true).output()).await.context("legacy service operation timed out")??)
}
async fn checked(arguments: &[&str]) -> Result<()> {
    ensure!(launch(arguments).await?.status.success(), "legacy service operation failed");
    Ok(())
}
fn identity_matches(private: &private_profile::Profile, public: &profile::Profile) -> bool {
    private.peer_id.rsplit_once(':').is_some_and(|(_, id)| id == public.machine_id)
        && (private.server == public.server || public.fallback_servers.contains(&private.server)
            || private.fallback_servers.contains(&public.server))
}

pub(crate) async fn migrate(public: &profile::Profile, layout: &Layout, executable: &Path) -> Result<bool> {
    if layout.user || !Path::new(UNIT).try_exists()? || !Path::new(PROFILE).try_exists()? { return Ok(false); }
    service::require_administrator()?;
    let legacy_bytes = profile::read_private(Path::new(PROFILE))?;
    ensure!(legacy_bytes.len() <= 65536, "legacy private profile exceeds size limit");
    // Old Go profiles allowed HTTP fallbacks without a native permission flag.
    // Deserialize inert data first; normalize to the authenticated public
    // registration's authorities, then validate before stopping anything.
    let original: private_profile::Profile = serde_json::from_slice(&legacy_bytes)
        .map_err(|_| anyhow::anyhow!("invalid legacy private profile"))?;
    if !identity_matches(&original, public) { return Ok(false); }
    let saved_unit = crate::legacy::read_owned(Path::new(UNIT), 65536)?;
    let parsed = tokio::time::timeout(Duration::from_secs(5), Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-", UNIT]).kill_on_drop(true).output()).await??;
    ensure!(parsed.status.success(), "cannot inspect legacy private service");
    let unit: serde_json::Value = serde_json::from_slice(&parsed.stdout)?;
    ensure!(unit["Label"] == "com.porthub.private" && unit["ProgramArguments"] == serde_json::json!([
        "/usr/local/libexec/porthub/porthub", "run", "--profile", PROFILE
    ]), "legacy private service has custom arguments; automatic migration cannot replace it");
    let directory = layout.state.join("macos-private-migration");
    service::directory(&directory, true)?;
    let journal = directory.join("state.json");
    let staged = directory.join("profile.json");
    let mut private = original.clone();
    private.server = public.server.clone();
    private.fallback_servers = public.fallback_servers.clone();
    private.account_email = public.account_email.clone();
    private.allow_insecure_http_for_tests = public.allow_insecure_http_for_tests;
    private.validate()?;
    let identity = service::RegistrationProfile::Private(private.clone()).identity();
    if journal.try_exists()? {
        let value: serde_json::Value = serde_json::from_slice(&profile::read_private(&journal)?)?;
        ensure!(value["identity"] == identity, "private migration identity changed");
        if value["state"] == "committed" { return Ok(true); }
        // An interrupted attempt must restore connectivity before retrying.
        restore(layout, &identity, &directory).await?;
        std::fs::remove_file(&journal)?;
        anyhow::bail!("interrupted private migration recovered; retry scheduled");
    }
    if let Some(spec) = service::installed(layout, &identity)? {
        // Uninstall may retain credentials and metadata for recovery. Only an
        // actually installed native service counts as an existing registration.
        let manager = service::system_manager(false).await?;
        if manager.state(&spec).await?.installed { return Ok(true); }
    }
    let loaded = launch(&["print", LABEL]).await?;
    if !loaded.status.success() { return Ok(false); } // Never activate an operator-stopped overlay.
    let description = String::from_utf8_lossy(&loaded.stdout);
    ensure!(description.lines().any(|line| line.trim() == format!("path = {UNIT}")), "legacy service ownership mismatch");
    let pid = description.lines().find_map(|line| line.trim().strip_prefix("pid = ").and_then(|v| v.parse::<i32>().ok()));
    profile::write_private(&directory.join("legacy.plist"), &saved_unit, true)?;
    profile::write_private(&staged, &serde_json::to_vec(&private)?, true)?;
    // Resolver files are backed up as data. Only the old generator's marker is
    // eligible; other VPNs' resolvers are never removed or rewritten.
    let mut resolvers = std::collections::BTreeMap::<String, String>::new();
    if Path::new("/etc/resolver").try_exists()? {
        for entry in std::fs::read_dir("/etc/resolver")?.take(256) {
            let entry = entry?;
            if !entry.file_type()?.is_file() { continue; }
            let bytes = crate::legacy::read_owned(&entry.path(), 65536)?;
            if bytes.starts_with(b"# Managed by PortHub private network\n") {
                resolvers.insert(entry.file_name().to_string_lossy().into_owned(), String::from_utf8(bytes)?);
            }
        }
    }
    profile::write_private(&directory.join("resolvers.json"), &serde_json::to_vec(&resolvers)?, true)?;
    profile::write_private(&journal, &serde_json::to_vec(&serde_json::json!({"identity":identity,"state":"prepared"}))?, true)?;
    let result: Result<()> = async {
        checked(&["disable", LABEL]).await?;
        checked(&["bootout", LABEL]).await?;
        if let Some(pid) = pid {
            tokio::time::timeout(Duration::from_secs(10), async {
                // SAFETY: signal zero checks only process existence; no signal
                // or mutation is sent to the old process or a reused PID.
                while unsafe { libc::kill(pid, 0) } == 0 { tokio::time::sleep(Duration::from_millis(100)).await; }
            }).await.context("legacy private process did not stop")?;
        }
        for (name, content) in &resolvers {
            let path = Path::new("/etc/resolver").join(name);
            if std::fs::read(&path).ok().as_deref() == Some(content.as_bytes()) { std::fs::remove_file(path)?; }
        }
        let manager = service::system_manager(false).await?;
        let spec = service::install_published(layout, &staged, &executable.canonicalize()?, manager.as_ref(), None).await?;
        service::RuntimeReady.wait(&spec).await?;
        profile::write_private(&journal, &serde_json::to_vec(&serde_json::json!({"identity":identity,"state":"committed"}))?, true)?;
        Ok(())
    }.await;
    if let Err(error) = result {
        restore(layout, &identity, &directory).await.context("private migration rollback is pending")?;
        std::fs::remove_file(journal)?;
        return Err(error.context("native private migration failed; legacy service restored"));
    }
    tracing::info!("legacy macOS private service migrated to native agent");
    Ok(true)
}

async fn restore(layout: &Layout, identity: &str, directory: &Path) -> Result<()> {
    if let Some(spec) = service::installed(layout, identity)? {
        let manager = service::system_manager(false).await?;
        service::action(layout, &spec.profile, service::Action::Uninstall { purge: false }, manager.as_ref()).await?;
    }
    let resolvers: std::collections::BTreeMap<String,String> = serde_json::from_slice(&profile::read_private(&directory.join("resolvers.json"))?)?;
    for (name, content) in resolvers {
        ensure!(Path::new(&name).file_name().and_then(|part| part.to_str()) == Some(&name), "invalid resolver recovery filename");
        let path = Path::new("/etc/resolver").join(name);
        if !path.try_exists()? { service::atomic(&path, content.as_bytes(), false)?; }
    }
    checked(&["enable", LABEL]).await?;
    if !launch(&["print", LABEL]).await?.status.success() { checked(&["bootstrap", "system", UNIT]).await?; }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn migration_requires_same_machine_and_an_enrolled_gateway_authority() {
        let public: profile::Profile = serde_json::from_value(serde_json::json!({
            "server":"https://hub.example", "machine_id":"0123456789abcdef01234567", "token":"public-secret"
        })).unwrap();
        let mut private: private_profile::Profile = serde_json::from_value(serde_json::json!({
            "server":"https://hub.example", "peer_id":"workspace:0123456789abcdef01234567", "workspace":"workspace", "token":"private-secret"
        })).unwrap();
        assert!(identity_matches(&private, &public));
        private.server = "https://unrelated.example".into();
        assert!(!identity_matches(&private, &public));
        private.fallback_servers.push(public.server.clone());
        assert!(identity_matches(&private, &public));
        private.peer_id = "workspace:another-machine".into();
        assert!(!identity_matches(&private, &public));
    }
}
