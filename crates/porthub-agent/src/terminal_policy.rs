//! Secure paired-identity terminal egress decisions. Display metadata cannot
//! approve direct traffic. Guest grants are short lived and reveal no credentials.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;

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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation: Operation,
}
#[derive(Deserialize)]
enum Operation {
    #[serde(rename = "terminal_guest_policy")]
    Guest,
}
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    allowed: bool,
    expires_at: u64,
}
impl Snapshot {
    #[cfg(test)]
    fn valid(&self, now: u64) -> bool {
        self.allowed && self.expires_at > now && self.expires_at.saturating_sub(now) <= 4
    }
}
/// Called only after the local broker authenticates the OS peer. No gateway
/// request, shell, route or listening socket is created by a policy subscription.
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut reader: BufReader<S>,
    control: &crate::control::Control,
    path: &Path,
    message: serde_json::Value,
    cancel: CancellationToken,
) -> Result<()> {
    let request: Request = serde_json::from_value(message)?;
    let Operation::Guest = request.operation;
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut byte = [0];
    loop {
        tokio::select! {
            _=cancel.cancelled()=>return Ok(()),
            _=reader.read(&mut byte)=>return Ok(()),
            _=tick.tick()=>{
                let allowed=guest_allowed(path,control.profile());
                let snapshot=Snapshot {allowed,expires_at:now()?.saturating_add(4)};
                let mut bytes=serde_json::to_vec(&snapshot)?;bytes.push(b'\n');
                tokio::time::timeout(Duration::from_secs(3),reader.get_mut().write_all(&bytes)).await??;
                if !allowed {return Ok(());}
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_snapshots_cannot_be_expired_future_or_override_identity_with_extra_fields() {
        assert!(Snapshot {
            allowed: true,
            expires_at: 104
        }
        .valid(100));
        for (allowed, expires_at) in [
            (false, 104),
            (true, 100),
            (true, 99),
            (true, 105),
            (true, u64::MAX),
        ] {
            assert!(!Snapshot {
                allowed,
                expires_at
            }
            .valid(100));
        }
        assert!(serde_json::from_value::<Request>(
            serde_json::json!({"operation":"terminal_guest_policy","machine_id":"another-account"})
        )
        .is_err());
        assert!(serde_json::from_value::<Snapshot>(
            serde_json::json!({"allowed":true,"expires_at":104,"token":"secret"})
        )
        .is_err());
    }

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
    fn guest_requires_a_live_paired_identity_and_honors_tor_even_without_the_tor_engine(
    ) -> Result<()> {
        let (lease, _root, public, path, private) = fixture()?;
        assert!(guest_allowed(&path, &public));
        let mut config = crate::unified::load(&path, &public)?.unwrap();
        config.enabled = false;
        crate::unified::save(&path, &public, &config)?;
        assert!(!guest_allowed(&path, &public));
        config.enabled = true;
        crate::unified::save(&path, &public, &config)?;
        assert!(guest_allowed(&path, &public));
        crate::private_network::tor_preferences::save(
            &private,
            crate::private_network::tor_preferences::Settings {
                system_wide: true,
                ..Default::default()
            },
        )?;
        assert!(!guest_allowed(&path, &public));
        crate::private_network::tor_preferences::save(&private, Default::default())?;
        assert!(guest_allowed(&path, &public));
        crate::private_network::strategy::save(
            &private,
            crate::private_network::strategy::Mode::PreferGateway,
        )?;
        assert!(!guest_allowed(&path, &public));
        crate::private_network::strategy::save(
            &private,
            crate::private_network::strategy::Mode::PreferDirect,
        )?;
        assert!(guest_allowed(&path, &public));
        let other: crate::profile::Profile = serde_json::from_value(serde_json::json!({
            "server":"https://another.test","machine_id":"0123456789abcdef01234567","token":"other-secret"}))?;
        assert!(
            !guest_allowed(&path, &other),
            "another account or gateway cannot supply privacy approval"
        );
        drop(lease);
        assert!(!guest_allowed(&path, &public));
        Ok(())
    }

    #[cfg(all(unix, feature = "terminal-direct"))]
    #[tokio::test]
    async fn broker_stream_is_scoped_and_revokes_after_paired_policy_becomes_unknown() -> Result<()>
    {
        let (_lease, _root, public, path, _private) = fixture()?;
        let control = crate::control::Control::new(public)?;
        let (client, server) = tokio::io::duplex(16384);
        let corrupt = crate::unified::configuration_path(&path);
        let task = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            serve(
                BufReader::new(server),
                &control,
                &path,
                serde_json::json!({"operation":"terminal_guest_policy"}),
                CancellationToken::new(),
            )
            .await
        }));
        let mut reader = BufReader::new(client);
        let first = crate::exposure_protocol::line(&mut reader).await?;
        let first: Snapshot = serde_json::from_slice(&first)?;
        assert!(first.valid(now()?));
        crate::profile::write_private(&corrupt, b"unknown paired configuration", true)?;
        let next = tokio::time::timeout(
            Duration::from_secs(3),
            crate::exposure_protocol::line(&mut reader),
        )
        .await??;
        let next: Snapshot = serde_json::from_slice(&next)?;
        assert!(!next.allowed);
        task.await??;
        Ok(())
    }
}
