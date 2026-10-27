$ErrorActionPreference = 'Stop'
$porthubUrl = {{URL}}
$porthubIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$porthubPrincipal = [Security.Principal.WindowsPrincipal]::new($porthubIdentity)
if (-not $porthubPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open an Administrator PowerShell window and run this command again.'
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
