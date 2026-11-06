$ErrorActionPreference = 'Stop'
function Update-PortHubSessionPath {
    $porthubMachinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    foreach ($porthubEntry in ($porthubMachinePath -split ';')) {
        $porthubEntry = [Environment]::ExpandEnvironmentVariables($porthubEntry).TrimEnd('\')
        if ($porthubEntry.EndsWith('\PortHub\bin', [StringComparison]::OrdinalIgnoreCase) -and (Test-Path (Join-Path $porthubEntry 'porthub.exe')) -and (($env:Path -split ';') -notcontains $porthubEntry)) {
            $env:Path = $porthubEntry + ';' + $env:Path
        }
    }
}
$porthubUrl = {{URL}}
$porthubIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$porthubPrincipal = [Security.Principal.WindowsPrincipal]::new($porthubIdentity)
if (-not $porthubPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'PortHub needs administrator permission to install its service. Approve the Windows prompt to continue.'
    $porthubScriptUrl = $porthubUrl.TrimEnd('/') + '/windows.ps1'
    $porthubQuotedUrl = "'" + $porthubScriptUrl.Replace("'", "''") + "'"
    $porthubElevation = '$ErrorActionPreference = ''Stop''; [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; Invoke-RestMethod -Uri ' + $porthubQuotedUrl + ' -ErrorAction Stop | Invoke-Expression'
    $porthubEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($porthubElevation))
    $porthubPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
        $porthubElevated = Start-Process -FilePath $porthubPowerShell -ArgumentList @('-NoProfile', '-EncodedCommand', $porthubEncoded) -Verb RunAs -Wait -PassThru
    } catch {
        throw 'Administrator permission was not granted. Approve the Windows prompt or run the command in an Administrator terminal.'
    }
    if ($porthubElevated.ExitCode -ne 0) { throw 'PortHub installation did not complete in the administrator window.' }
    Update-PortHubSessionPath
    Write-Host 'PortHub installation completed. Open a new terminal window for Command Prompt; PowerShell can use porthub now.'
    return
}
$porthubArchitecture = $env:PROCESSOR_ARCHITEW6432
if (-not $porthubArchitecture) { $porthubArchitecture = $env:PROCESSOR_ARCHITECTURE }
try { $porthubArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() } catch {}
switch ($porthubArchitecture.ToUpperInvariant()) {
    { $_ -in 'AMD64', 'X64' } { $porthubTarget = 'windows_x86_64'; break }
    'X86' { $porthubTarget = 'windows_x86'; break }
    'ARM64' { $porthubTarget = 'windows_arm64'; break }
    default { throw 'This Windows architecture is not supported by PortHub.' }
}
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$porthubDirectory = Join-Path $env:TEMP ('porthub-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $porthubDirectory | Out-Null
try {
    $porthubFile = Join-Path $porthubDirectory 'porthub.exe'
    Invoke-WebRequest -UseBasicParsing -Uri ($porthubUrl + '/agent/' + $porthubTarget) -OutFile $porthubFile
    & $porthubFile {{ACTION}} --ticket $porthubUrl
    if ($LASTEXITCODE -ne 0) { throw 'PortHub setup failed.' }
} finally {
    Remove-Item $porthubDirectory -Recurse -Force -ErrorAction SilentlyContinue
}

Update-PortHubSessionPath
Write-Host 'PortHub installation completed. Open a new terminal window for Command Prompt; PowerShell can use porthub now.'
