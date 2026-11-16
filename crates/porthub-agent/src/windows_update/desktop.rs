//! Read-only selection of already authorized, checksum-backed desktop images.
//! The existing strict refresh still owns all task validation and mutation.
use super::shared_image::Image;
use crate::service::Layout;
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::AsyncReadExt;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Desktop {
    pub sid: String,
    pub image: Image,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    sid: String,
    paths: Vec<PathBuf>,
}
pub(super) async fn paths(layout: &Layout, source: &Path) -> Result<Vec<(String, Vec<PathBuf>)>> {
    let accounts = crate::keyboard::refresh_accounts(layout, &[source.into()])?;
    if accounts.is_empty() {
        return Ok(vec![]);
    }
    let exe = PathBuf::from(
        std::env::var_os("SystemRoot").context("Windows system directory unavailable")?,
    )
    .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let script = r#"
$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
Import-Module -Name "$PSHOME\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1" -ErrorAction Stop
function Sid($v){if($v -like 'S-1-*'){return $v};return ([Security.Principal.NTAccount]$v).Translate([Security.Principal.SecurityIdentifier]).Value}
$scheduler=[Activator]::CreateInstance([type]::GetTypeFromProgID('Schedule.Service'));$scheduler.Connect();$rows=@()
$accounts=$env:PORTHUB_UPDATE_ACCOUNTS|ConvertFrom-Json
foreach($sid in $accounts){
 try{$task=$scheduler.GetFolder('\').GetTask('PortHubKeyboard-'+$sid)}catch{$e=$_.Exception;while($e.InnerException){$e=$e.InnerException};if($e.HResult -in @(-2147024894,-2147216625)){continue};throw}
 $d=$task.Definition
 if((Sid $d.Principal.UserId) -ne $sid -or [int]$d.Principal.LogonType -ne 3 -or [int]$d.Principal.RunLevel -ne 0 -or $d.Actions.Count -ne 1){continue}
 $a=$d.Actions.Item(1);if([int]$a.Type -ne 0 -or $a.Arguments -notin @('keyboard run','keyboard startup')){continue}
 $paths=@([string]$a.Path)
 foreach($p in @(Get-CimInstance Win32_Process -Filter "Name='porthub.exe'")){
  if($p.SessionId -gt 0 -and $p.CommandLine -match '(?i)\skeyboard\s+(?:run|startup)\s*$'){
   $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
   if($owner.ReturnValue -eq 0 -and $owner.Sid -eq $sid -and $p.ExecutablePath){$paths+=[string]$p.ExecutablePath}
  }
 }
 $rows+=@{sid=$sid;paths=@($paths|Select-Object -Unique)}
}
ConvertTo-Json -InputObject @($rows) -Depth 4 -Compress
"#;
    let probe = async {
        let mut child = tokio::process::Command::new(exe)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .env_remove("PSModulePath")
            .env_remove("PSModuleAnalysisCachePath")
            .env("PORTHUB_UPDATE_ACCOUNTS", serde_json::to_string(&accounts)?)
            .creation_flags(0x08000000)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .context("Desktop metadata unavailable")?
            .take(32769)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= 32768 && child.wait().await?.success(),
            "Desktop metadata inspection failed"
        );
        let rows: Vec<Row> = serde_json::from_slice(&bytes)?;
        ensure!(
            rows.len() <= accounts.len()
                && rows
                    .iter()
                    .all(|r| accounts.contains(&r.sid) && r.paths.len() <= 16),
            "Desktop metadata exceeds authorized scope"
        );
        Ok(rows.into_iter().map(|r| (r.sid, r.paths)).collect())
    };
    tokio::time::timeout(Duration::from_secs(10), probe)
        .await
        .context("Desktop metadata inspection timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn native_powershell_account_iteration_preserves_scalar_rows_for_zero_one_and_two_accounts(
    ) -> Result<()> {
        // Execute the input/iteration boundary extracted from the production
        // script itself. Replace only its read-only Scheduler body with a row
        // projection, so this test never queries or creates a real task.
        let source = include_str!("desktop.rs");
        let script = source
            .split_once("let script = r#\"")
            .context("Production script missing")?
            .1
            .split_once("\"#;")
            .context("Production script terminator missing")?
            .0;
        let start = script.find("$accounts=").context("Account input missing")?;
        let end = script[start..]
            .find(" try{$task=")
            .context("Scheduler boundary missing")?
            + start;
        let boundary = &script[start..end];
        let setup = script
            .split_once("function Sid(")
            .context("Production setup missing")?
            .0;
        let projection = format!("[Console]::Error.WriteLine('porthub-account-stage:started');\n{setup}\n[Console]::Error.WriteLine('porthub-account-stage:setup-complete');\n$rows=@();[Console]::Error.WriteLine('porthub-account-stage:boundary');\n{boundary}\n$rows+=@{{sid=$sid;paths=@()}}\n}}\n[Console]::Error.WriteLine('porthub-account-stage:boundary-complete');\nConvertTo-Json -InputObject @($rows) -Depth 4 -Compress");
        let executable = PathBuf::from(
            std::env::var_os("SystemRoot").context("Windows SystemRoot unavailable")?,
        )
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        for accounts in [
            vec![],
            vec!["S-1-5-21-1-2-3-1001"],
            vec!["S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"],
        ] {
            let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
            let run = async {
                let mut child = tokio::process::Command::new(&executable)
                    .args([
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        &projection,
                    ])
                    .env_remove("PSModulePath")
                    .env_remove("PSModuleAnalysisCachePath")
                    .env("PORTHUB_UPDATE_ACCOUNTS", serde_json::to_string(&accounts)?)
                    .creation_flags(0x08000000)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true)
                    .spawn()?;
                let mut stdout = child.stdout.take().context("Projection output missing")?;
                let mut stderr = child
                    .stderr
                    .take()
                    .context("Projection stage output missing")?;
                let mut bytes = Vec::new();
                let read_stdout = async { stdout.take(4097).read_to_end(&mut bytes).await };
                let read_stages = async {
                    let mut buffer = [0u8; 256];
                    loop {
                        let n = stderr.read(&mut buffer).await?;
                        if n == 0 {
                            break;
                        }
                        let mut output = captured.lock().unwrap();
                        ensure!(
                            output.len() + n <= 1024,
                            "Native stage output exceeds bound"
                        );
                        output.extend_from_slice(&buffer[..n]);
                    }
                    Ok::<_, anyhow::Error>(())
                };
                let (output, stages) = tokio::join!(read_stdout, read_stages);
                output?;
                stages?;
                ensure!(
                    bytes.len() <= 4096 && child.wait().await?.success(),
                    "Native account projection failed"
                );
                let rows: Vec<Row> = serde_json::from_slice(&bytes)?;
                ensure!(rows.len() == accounts.len());
                for (row, expected) in rows.iter().zip(&accounts) {
                    ensure!(
                        row.sid == *expected && row.paths.is_empty(),
                        "Account identity changed during iteration"
                    );
                }
                Ok::<_, anyhow::Error>(())
            };
            let result = tokio::time::timeout(Duration::from_secs(10), run).await;
            // Report only known constant stages, never arbitrary stderr/source.
            let output = captured.lock().unwrap();
            let text = String::from_utf8_lossy(&output);
            let stages: Vec<_> = ["started", "setup-complete", "boundary", "boundary-complete"]
                .into_iter()
                .filter(|stage| {
                    text.lines()
                        .any(|line| line.trim() == format!("porthub-account-stage:{stage}"))
                })
                .collect();
            result
                .with_context(|| {
                    format!(
                        "Native account boundary timed out; accounts={}; stages={stages:?}",
                        accounts.len()
                    )
                })?
                .with_context(|| {
                    format!(
                        "Native account boundary failed; accounts={}; stages={stages:?}",
                        accounts.len()
                    )
                })?;
        }
        // The parser remains strict; the observed PS5 wrapper is not accepted.
        ensure!(serde_json::from_str::<Vec<Row>>(
            r#"[{"sid":{"value":["S-1-5-21-1-2-3-1001"],"Count":1},"paths":[]}]"#
        )
        .is_err());
        Ok(())
    }
}
