//! Refresh existing authorized desktop tasks after a committed native upgrade.
//! Never installs a task, enables a policy, or infers an enrolling account.
use anyhow::{ensure, Context, Result};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
const SCRIPT: &str = include_str!("windows_refresh.ps1");
// Keep CreateProcess argv small; trusted script bytes travel over our child pipe.
const BOOTSTRAP: &str = r#"$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$buffer=New-Object byte[] 2048;$bytes=New-Object IO.MemoryStream;$inputStream=[Console]::OpenStandardInput()
try{
 while(($count=$inputStream.Read($buffer,0,$buffer.Length)) -gt 0){if($bytes.Length+$count -gt 131072){throw 'Desktop refresh input exceeds bounds'};$bytes.Write($buffer,0,$count)}
 $utf8=New-Object Text.UTF8Encoding($false,$true);$packet=$utf8.GetString($bytes.ToArray())|ConvertFrom-Json
}finally{$bytes.Dispose();$inputStream.Dispose()}
if($packet -isnot [pscustomobject] -or @($packet.PSObject.Properties).Count -ne 2 -or @($packet.PSObject.Properties|Where-Object{$_.Name -cnotin @('script','request')}).Count -or $packet.script -isnot [string] -or $packet.script.Length -gt 49152 -or $packet.request -isnot [pscustomobject]){throw 'Invalid desktop refresh envelope'}
$hash=[Security.Cryptography.SHA256]::Create()
try{$digest=[BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($packet.script))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
if($digest -cne '__SCRIPT_SHA256__'){throw 'Desktop refresh script digest mismatch'}
. ([scriptblock]::Create($packet.script))
@(Invoke-PortHubDesktopRefresh $packet.request)|ConvertTo-Json -Depth 4 -Compress
"#;
fn encoded_bootstrap() -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let text = BOOTSTRAP.replace("__SCRIPT_SHA256__", &format!("{:x}", Sha256::digest(SCRIPT.as_bytes())));
    base64::engine::general_purpose::STANDARD.encode(text.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>())
}
fn valid_sid(sid: &str) -> bool {
    sid.starts_with("S-1-")
        && sid.len() < 184
        && sid
            .split('-')
            .skip(1)
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && !matches!(sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20")
}
pub(super) fn grants(layout: &crate::service::Layout, profiles: &[PathBuf]) -> Result<Vec<String>> {
    ensure!(
        profiles.len() <= 64,
        "Too many upgraded desktop registrations"
    );
    let mut sids = BTreeSet::new();
    for profile in profiles {
        let name = profile
            .file_name()
            .and_then(|n| n.to_str())
            .context("Invalid upgraded profile identity")?;
        ensure!(
            profile.parent() == Some(layout.state.as_path())
                && name
                    .strip_suffix(".json")
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())),
            "Desktop refresh requires managed upgraded profiles"
        );
        let grant = crate::profile::sibling(profile, ".local-access.json");
        let bytes = match crate::profile::read_private(&grant) {
            Ok(bytes) => bytes,
            Err(_) if !grant.try_exists()? => continue,
            Err(error) => {
                return Err(error.context("Cannot read existing desktop account authorization"))
            }
        };
        ensure!(bytes.len() <= 512, "Desktop account grant exceeds bounds");
        let sid: String =
            serde_json::from_slice(&bytes).context("Invalid desktop account grant")?;
        ensure!(
            valid_sid(&sid),
            "Desktop account grant is not an interactive account"
        );
        sids.insert(sid);
    }
    ensure!(
        sids.len() <= 8,
        "Too many authorized desktop accounts for one refresh"
    );
    Ok(sids.into_iter().collect())
}
pub(super) async fn refresh(
    layout: &crate::service::Layout,
    executable: &Path,
    profiles: &[PathBuf],
) -> Result<()> {
    let system = crate::service::Layout::system()?;
    ensure!(
        !layout.user
            && layout.state == system.state
            && layout.releases == system.releases
            && layout.units == system.units,
        "Desktop refresh requires the native system layout"
    );
    crate::service::publication::owned_target(layout, executable)?;
    let sids = grants(layout, profiles)?;
    if sids.is_empty() {
        return Ok(());
    }
    let request = serde_json::to_vec(
        &serde_json::json!({"executable":executable,"release_root":layout.releases,"sids":sids}),
    )?;
    ensure!(
        request.len() <= 16384,
        "Desktop refresh request exceeds bounds"
    );
    ensure!(SCRIPT.len() <= 49152, "Desktop refresh script exceeds bounds");
    let payload = serde_json::to_vec(&serde_json::json!({
        "script": SCRIPT, "request": serde_json::from_slice::<serde_json::Value>(&request)?
    }))?;
    ensure!(payload.len() <= 131072, "Desktop refresh envelope exceeds bounds");
    let command = encoded_bootstrap();
    ensure!(command.len() <= 8192, "Desktop refresh bootstrap exceeds command bounds");
    let powershell =
        PathBuf::from(std::env::var_os("SystemRoot").context("Windows SystemRoot unavailable")?)
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let mut child = tokio::process::Command::new(powershell)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &command,
        ])
        .env_remove("PSModulePath")
        .env_remove("PSModuleAnalysisCachePath")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(0x08000000)
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| {
            let context = format!("Cannot start managed desktop task refresh (OS error {:?})", error.raw_os_error());
            anyhow::Error::new(error).context(context)
        })?;
    let mut input = child
        .stdin
        .take()
        .context("Desktop refresh input unavailable")?;
    let stdout = child
        .stdout
        .take()
        .context("Desktop refresh output unavailable")?;
    let stderr = child
        .stderr
        .take()
        .context("Desktop refresh diagnostics unavailable")?;
    let output = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout.take(32769).read_to_end(&mut bytes).await?;
        Ok::<_, std::io::Error>(bytes)
    }));
    let errors = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.take(4097).read_to_end(&mut bytes).await?;
        Ok::<_, std::io::Error>(bytes)
    }));
    let result = tokio::time::timeout(Duration::from_secs(120), async {
        input.write_all(&payload).await?;
        drop(input);
        let status = child.wait().await?;
        let output = output.await??;
        let errors = errors.await??;
        ensure!(
            output.len() <= 32768 && errors.len() <= 4096,
            "Desktop refresh output exceeds bounds"
        );
        ensure!(
            status.success(),
            "Managed desktop task refresh failed: {}",
            String::from_utf8_lossy(&errors)
        );
        let _: serde_json::Value =
            serde_json::from_slice(&output).context("Invalid desktop refresh completion")?;
        Ok::<_, anyhow::Error>(())
    })
    .await;
    match result {
        Ok(result) => result,
        Err(_) => {
            let _ = tokio::time::timeout(Duration::from_secs(5), child.kill()).await;
            anyhow::bail!("Managed desktop refresh exceeded its deadline")
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refresh_script_does_not_expand_createprocess_command_line() {
        let command = encoded_bootstrap();
        assert!(command.len() <= 8192);
        assert!(SCRIPT.len() <= 49152);
        assert!(!BOOTSTRAP.contains("-ExecutionPolicy"));
        assert!(BOOTSTRAP.contains("Desktop refresh script digest mismatch"));
    }
    #[test]
    fn grants_cannot_infer_service_accounts_or_accept_malformed_sids() {
        assert!(valid_sid("S-1-5-21-123-456-789-1001"));
        assert!(valid_sid("S-1-12-1-123-456-789-123"));
        for sid in [
            "S-1-5-18",
            "S-1-5-19",
            "S-1-5-20",
            "S-1-",
            "S-1--5",
            "S-1-5-21-1\n",
        ] {
            assert!(!valid_sid(sid), "{sid}");
        }
    }
    #[test]
    fn only_explicit_existing_managed_profile_grants_select_desktops() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let state = temp.path().join("native");
        std::fs::create_dir(&state)?;
        let layout = crate::service::Layout {
            user: false,
            state: state.clone(),
            releases: temp.path().join("releases"),
            units: temp.path().join("units"),
        };
        let profile = state.join(format!("{}.json", "a".repeat(64)));
        assert!(
            grants(&layout, &[profile.clone()])?.is_empty(),
            "Missing authorization cannot infer a logged-in account"
        );
        let grant = crate::profile::sibling(&profile, ".local-access.json");
        crate::profile::write_private(
            &grant,
            &serde_json::to_vec("S-1-5-21-123-456-789-1001")?,
            false,
        )?;
        assert_eq!(
            grants(&layout, &[profile.clone(), profile.clone()])?,
            vec!["S-1-5-21-123-456-789-1001"]
        );
        crate::profile::write_private(&grant, &serde_json::to_vec("S-1-5-18")?, true)?;
        assert!(
            grants(&layout, &[profile.clone()]).is_err(),
            "SYSTEM does not authorize an interactive desktop"
        );
        assert!(grants(&layout, &[temp.path().join("outside.json")]).is_err());
        Ok(())
    }
}
