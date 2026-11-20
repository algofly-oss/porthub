//! Secure paired-identity terminal egress decisions. Display metadata cannot
//! approve direct traffic. Guest grants are short lived and reveal no credentials.
use anyhow::Result;
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn direct_allowed(path: &Path, public: &crate::profile::Profile) -> bool {
    crate::features::enabled(path,crate::features::Feature::DirectConnections) && checked(path, public, false).unwrap_or(false)
}
pub(crate) fn guest_allowed(path: &Path, public: &crate::profile::Profile) -> bool {
    crate::features::enabled(path,crate::features::Feature::Terminal) && checked(path, public, true).unwrap_or(false)
}
fn checked(path: &Path, public: &crate::profile::Profile, require_pair: bool) -> Result<bool> {
    let Some(module) = crate::unified::load(path, public)? else {
        return Ok(!require_pair);
    };
    if !module.enabled {
        return Ok(false);
    }
    if crate::private_network::tor_preferences::load(&module.private_profile)?.system_wide {
        return Ok(false);
    }
    if crate::private_network::strategy::load(&module.private_profile)?.mode
        == crate::private_network::strategy::Mode::PreferGateway
    {
        return Ok(false);
    }
    let status = crate::runtime::status(&module.private_profile)?;
    Ok(direct_status_allowed(&status, now()?))
}
pub(crate) fn direct_status_allowed(status: &crate::runtime::Status, now: u64) -> bool {
    status.state == "running"
        && status.updated_at <= now
        && now.saturating_sub(status.updated_at) <= 30
        && status
            .private_status
            .as_ref()
            .is_some_and(|private| private.lease_valid && private.exit.is_none())
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio_util::sync::CancellationToken;

    fn fixture() -> Result<(
        crate::profile::Lease,
        tempfile::TempDir,
        crate::profile::Profile,
        std::path::PathBuf,
        std::path::PathBuf,
    )> {
        let root = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let public: crate::profile::Profile = serde_json::from_value(serde_json::json!({
            "server":"https://example.test","machine_id":"0123456789abcdef01234567","token":"public-secret"}))?;
        let private: crate::private_profile::Profile = serde_json::from_value(serde_json::json!({
            "server":"https://example.test","workspace":"111111111111111111111111",
            "peer_id":"111111111111111111111111:0123456789abcdef01234567","token":"c".repeat(64)}))?;
        let path = root.path().join("public.json");
        crate::profile::write_private(&path, &serde_json::to_vec(&public)?, false)?;
        assert!(
            !guest_allowed(&path, &public),
            "an unpaired public profile cannot approve a guest socket"
        );
        let id = crate::service::RegistrationProfile::Private(private.clone()).identity();
        let private_path = root.path().join(format!("{id}.json"));
        crate::profile::write_private(&private_path, &serde_json::to_vec(&private)?, false)?;
        crate::unified::save(
            &path,
            &public,
            &crate::unified::Configuration {
                format_version: 1,
                private_profile: private_path.clone(),
                enabled: true,
            },
        )?;
        let lease = crate::profile::Lease::acquire(&private_path)?;
        let status = serde_json::json!({"pid":std::process::id(),"state":"running","agent_version":"test",
            "config_version":"","service_count":0,"route":"private","updated_at":now()?,"update_request_id":"",
            "private_status":{"revision":1,"grants":0,"dns_rules":0,"lease_valid":true,"exit":null}});
        crate::profile::write_private(
            &crate::profile::sibling(&private_path, ".status.json"),
            &serde_json::to_vec(&status)?,
            false,
        )?;
        Ok((lease, root, public, path, private_path))
    }
    #[test]
    fn paired_underlay_policy_requires_a_live_paired_identity_and_honors_tor_even_without_the_tor_engine(
    ) -> Result<()> {
        let (lease, _root, public, path, private) = fixture()?;
        assert!(!guest_allowed(&path, &public));
        assert!(checked(&path, &public, true)?);
        let mut config = crate::unified::load(&path, &public)?.unwrap();
        config.enabled = false;
        crate::unified::save(&path, &public, &config)?;
        assert!(!checked(&path, &public, true)?);
        config.enabled = true;
        crate::unified::save(&path, &public, &config)?;
        assert!(checked(&path, &public, true)?);
        crate::private_network::tor_preferences::save(
            &private,
            crate::private_network::tor_preferences::Settings {
                system_wide: true,
                ..Default::default()
            },
        )?;
        assert!(!checked(&path, &public, true)?);
        crate::private_network::tor_preferences::save(&private, Default::default())?;
        assert!(checked(&path, &public, true)?);
        crate::private_network::strategy::save(
            &private,
            crate::private_network::strategy::Mode::PreferGateway,
        )?;
        assert!(!checked(&path, &public, true)?);
        crate::private_network::strategy::save(
            &private,
            crate::private_network::strategy::Mode::PreferDirect,
        )?;
        assert!(checked(&path, &public, true)?);
        let other: crate::profile::Profile = serde_json::from_value(serde_json::json!({
            "server":"https://another.test","machine_id":"0123456789abcdef01234567","token":"other-secret"}))?;
        assert!(
            !checked(&path, &other, true).unwrap_or(false),
            "another account or gateway cannot supply privacy approval"
        );
        drop(lease);
        assert!(!checked(&path, &public, true)?);
        Ok(())
    }

    #[tokio::test]
    async fn broker_rejects_terminal_operations_on_an_enrolled_profile() -> Result<()> {
        let (_lease, _root, public, path, _private) = fixture()?;
        let control = std::sync::Arc::new(crate::control::Control::new(public)?);
        for operation in ["terminal_host", "terminal_guest_policy"] {
            let (mut client, server) = tokio::io::duplex(1024);
            let request = serde_json::json!({"operation":operation}).to_string() + "\n";
            client.write_all(request.as_bytes()).await?;
            crate::exposure_protocol::serve_connection(
                server, control.clone(), CancellationToken::new(), path.clone(),
            ).await?;
            let reply = crate::exposure_protocol::line(&mut BufReader::new(client)).await?;
            assert_eq!(serde_json::from_slice::<serde_json::Value>(&reply)?["type"], "disabled");
        }
        Ok(())
    }
}
