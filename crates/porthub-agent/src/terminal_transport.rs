//! Bounded, cancel-safe JSON line framing for the local agent broker.
use anyhow::{ensure, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};

pub(crate) async fn frame<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
    bytes: &mut Vec<u8>,
) -> Result<Vec<u8>> {
    // The caller retains partial bytes if select! cancels this read while a
    // gateway event arrives. Never lose a partially received JSON frame.
    let remaining = 32769usize.saturating_sub(bytes.len());
    let count = reader
        .take(remaining as u64)
        .read_until(b'\n', bytes)
        .await?;
    ensure!(
        count > 0 && bytes.len() <= 32768 && bytes.last() == Some(&b'\n'),
        "invalid terminal broker frame"
    );
    Ok(std::mem::take(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal_policy::{direct_allowed, direct_status_allowed};
    use porthub_terminal::protocol::HostOutput;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn interrupted_frame_read_retains_partial_bytes_and_rejects_oversized_frames(
    ) -> Result<()> {
        let (mut writer, reader) = tokio::io::duplex(65536);
        let mut reader = BufReader::new(reader);
        let mut partial = Vec::new();
        writer.write_all(b"{\"type\":").await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), frame(&mut reader, &mut partial))
                .await
                .is_err()
        );
        assert_eq!(partial, b"{\"type\":");
        writer.write_all(b"\"pong\"}\n").await?;
        let bytes = frame(&mut reader, &mut partial).await?;
        assert!(matches!(
            serde_json::from_slice::<HostOutput>(&bytes)?,
            HostOutput::Pong
        ));
        assert!(partial.is_empty());
        writer.write_all(&vec![b'x'; 32769]).await?;
        assert!(frame(&mut reader, &mut partial).await.is_err());
        Ok(())
    }

    #[test]
    fn direct_requires_fresh_known_policy_without_a_selected_exit() -> Result<()> {
        let mut status: crate::runtime::Status = serde_json::from_value(serde_json::json!({
            "pid":1,"state":"running","agent_version":"test","config_version":"", "service_count":0,
            "route":"private","updated_at":100,"update_request_id":"",
            "private_status":{"revision":1,"grants":0,"dns_rules":0,"lease_valid":true,"exit":null}
        }))?;
        assert!(direct_status_allowed(&status,100));
        assert!(direct_status_allowed(&status,130));
        assert!(!direct_status_allowed(&status,131));
        assert!(!direct_status_allowed(&status,99));
        status.private_status.as_mut().unwrap().lease_valid=false;
        assert!(!direct_status_allowed(&status,100));
        status.private_status.as_mut().unwrap().lease_valid=true;
        status.state="connecting".into();
        assert!(!direct_status_allowed(&status,100));
        status.state="running".into();
        for traffic_mode in [porthub_mesh::exit_policy::TrafficMode::All,porthub_mesh::exit_policy::TrafficMode::InternetOnly,porthub_mesh::exit_policy::TrafficMode::LanOnly] {
            status.private_status.as_mut().unwrap().exit=Some(crate::runtime::ExitStatus {
                name:"exit".into(),selection:"sticky".into(),traffic_mode,state:"pending".into(),
                peers:0,available:0,allow_direct_fallback:true,peer_names:vec![],
            });
            assert!(!direct_status_allowed(&status,100));
        }
        status.private_status=None;
        assert!(!direct_status_allowed(&status,100));
        Ok(())
    }

    #[cfg(feature = "local-tor")]
    #[test]
    fn secure_paired_policy_blocks_system_tor_and_a_stopped_owner() -> Result<()> {
        let fixture=tempfile::tempdir()?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(fixture.path(),std::fs::Permissions::from_mode(0o700))?;
        }
        let public:crate::profile::Profile=serde_json::from_value(serde_json::json!({
            "server":"https://example.test","machine_id":"0123456789abcdef01234567","token":"public-secret"
        }))?;
        let private:crate::private_profile::Profile=serde_json::from_value(serde_json::json!({
            "server":"https://example.test","workspace":"111111111111111111111111",
            "peer_id":"111111111111111111111111:0123456789abcdef01234567","token":"c".repeat(64)
        }))?;
        let public_path=fixture.path().join("public.json");
        let identity=crate::service::RegistrationProfile::Private(private.clone()).identity();
        let private_path=fixture.path().join(format!("{identity}.json"));
        crate::profile::write_private(&private_path,&serde_json::to_vec(&private)?,false)?;
        crate::unified::save(&public_path,&public,&crate::unified::Configuration {
            format_version:1,private_profile:private_path.clone(),enabled:true,
        })?;
        let lease=crate::profile::Lease::acquire(&private_path)?;
        let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let status=serde_json::json!({"pid":std::process::id(),"state":"running","agent_version":"test",
            "config_version":"","service_count":0,"route":"private","updated_at":now,"update_request_id":"",
            "private_status":{"revision":1,"grants":0,"dns_rules":0,"lease_valid":true,"exit":null}});
        crate::profile::write_private(&crate::profile::sibling(&private_path,".status.json"),&serde_json::to_vec(&status)?,false)?;
        assert!(direct_allowed(&public_path,&public));
        crate::private_network::tor_preferences::save(&private_path,crate::private_network::tor_preferences::Settings {
            system_wide:true,..Default::default()
        })?;
        assert!(!direct_allowed(&public_path,&public));
        crate::private_network::tor_preferences::save(&private_path,Default::default())?;
        assert!(direct_allowed(&public_path,&public));
        drop(lease);
        assert!(!direct_allowed(&public_path,&public));
        Ok(())
    }

}
