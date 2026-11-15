//! Start input in the enrolled user's interactive session, never SCM Session 0.
use anyhow::{ensure, Context, Result};
use std::{
    path::Path,
    process::{Command, Stdio},
};
use windows_sys::Win32::System::{
    RemoteDesktop::ProcessIdToSessionId, Threading::GetCurrentProcessId,
};
pub(super) fn interactive() -> Result<()> {
    let mut session = 0;
    ensure!(
        unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) } != 0,
        "Cannot inspect desktop session"
    );
    ensure!(session!=0,"Desktop input requires an interactive login session; run porthub keyboard enable as the logged-in user");
    Ok(())
}
fn resolve(executable: &Path) -> Result<std::path::PathBuf> {
    // Windows cannot atomically replace a running .exe. Start the immutable
    // native release, leaving the published CLI free for future updates.
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(executable)?;
    let mut hash = Sha256::new();
    let mut bytes = [0; 65536];
    loop {
        let n = file.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    let release = crate::service::Layout::system()?
        .releases
        .join(format!("{:x}", hash.finalize()))
        .join("porthub.exe");
    ensure!(
        release.is_file(),
        "The desktop executable has no managed immutable release"
    );
    Ok(release)
}
fn script(executable: &Path) -> Result<String> {
    let path = executable
        .to_str()
        .context("Invalid desktop executable path")?;
    ensure!(
        !path.contains(['\n', '\r', '\0']),
        "Invalid desktop executable path"
    );
    let path = path.replace('\'', "''");
    Ok(format!(
        r#"$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$sid=$identity.User.Value
if($sid -in @('S-1-5-18','S-1-5-19','S-1-5-20')){{exit 0}}
$path='{path}'
$name='PortHubKeyboard-'+$sid
$releaseRoot=Join-Path $env:ProgramData 'PortHub\releases'
function ManagedHelper($candidate){{
    $item=Get-Item -LiteralPath $candidate -ErrorAction SilentlyContinue
    if(-not $item -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){{return $false}}
    if($item.Directory.Attributes -band [IO.FileAttributes]::ReparsePoint){{return $false}}
    if($item.Name -ne 'porthub.exe' -or $item.Directory.Name -notmatch '^[a-fA-F0-9]{{64}}$' -or $item.Directory.Parent.FullName -ne $releaseRoot){{return $false}}
    return (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -eq $item.Directory.Name
}}
if(-not (ManagedHelper $path)){{throw 'Desktop target is not a verified immutable release'}}
$previous=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if($previous){{
    $priorSid=$previous.Principal.UserId
    if($priorSid -notmatch '^S-1-'){{$priorSid=([Security.Principal.NTAccount]$priorSid).Translate([Security.Principal.SecurityIdentifier]).Value}}
    if($priorSid -ne $sid -or @($previous.Actions).Count -ne 1 -or $previous.Actions[0].Arguments -ne 'keyboard run' -or -not (ManagedHelper $previous.Actions[0].Execute)){{throw 'Refusing to replace an unverified desktop task'}}
    $currentHelper=$false
    foreach($process in @(Get-CimInstance Win32_Process -Filter "Name='porthub.exe'")){{
        if($process.ExecutablePath -eq $path -and $process.SessionId -ne 0 -and $process.CommandLine -match '(?i)\skeyboard\s+run\s*$'){{
            $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
            if($owner.ReturnValue -eq 0 -and $owner.Sid -eq $sid){{$currentHelper=$true}}
        }}
    }}
    # IgnoreNew preserves a running old image even after its action changes.
    # Stop only this verified SID-owned task when its image needs refreshing.
    if($previous.State -eq 'Running' -and ($previous.Actions[0].Execute -ne $path -or -not $currentHelper)){{
        Stop-ScheduledTask -TaskName $name
        for($attempt=0;$attempt -lt 50 -and (Get-ScheduledTask -TaskName $name).State -eq 'Running';$attempt++){{Start-Sleep -Milliseconds 100}}
        if((Get-ScheduledTask -TaskName $name).State -eq 'Running'){{throw 'Desktop task did not stop for its verified update'}}
    }}
}}
$action=New-ScheduledTaskAction -Execute $path -Argument 'keyboard run'
$trigger=New-ScheduledTaskTrigger -AtLogOn -User $sid
$principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$task=New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
Register-ScheduledTask -TaskName $name -InputObject $task -Force | Out-Null
# The interactive token is supplied by Windows. No account password or machine
# credential is saved in this task, including when setup came through SSH.
$legacy='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Remove-ItemProperty -Path $legacy -Name PortHubKeyboard -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName $name
"#
    ))
}
pub(super) fn install(executable: &Path) -> Result<()> {
    use base64::Engine;
    use std::os::windows::process::CommandExt;
    let release = resolve(executable)?;
    let encoded = script(&release)?
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let powershell = std::env::var_os("SystemRoot").context("Windows SystemRoot is unavailable")?;
    let powershell = Path::new(&powershell).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let status = Command::new(powershell)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &base64::engine::general_purpose::STANDARD.encode(encoded),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000)
        .status()?;
    ensure!(status.success(),"Cannot register interactive desktop startup; run porthub keyboard enable from the desktop account");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn system_registration_does_not_require_an_unsupported_windows_user_service() {
        let layouts = super::super::registration_layouts(false).unwrap();
        assert_eq!(layouts.len(), 1);
        assert!(!layouts[0].user);
        assert!(super::super::registration_layouts(true).is_err());
    }
    #[test]
    fn startup_uses_interactive_token_without_account_password_or_system_hive() {
        let text = script(Path::new("C:\\Program Files\\PortHub\\bin\\porthub.exe")).unwrap();
        assert!(text.contains("-LogonType Interactive"));
        assert!(text.contains("if($sid -in @('S-1-5-18','S-1-5-19','S-1-5-20')){exit 0}"));
        assert!(text.contains("Start-ScheduledTask -TaskName $name"));
        assert!(text.contains("$priorSid -ne $sid"));
        assert!(text.contains("ManagedHelper $previous.Actions[0].Execute"));
        assert!(text.contains("$previous.Actions[0].Execute -ne $path -or -not $currentHelper"));
        assert!(
            text.find("Stop-ScheduledTask -TaskName $name").unwrap()
                < text.find("Register-ScheduledTask -TaskName $name").unwrap()
        );
        assert!(!text.contains("Stop-Process"));
        assert!(!text.contains("-Password"));
        assert!(script(Path::new("C:\\bad\npath")).is_err());
    }
}
