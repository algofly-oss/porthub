$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$marker = Join-Path $env:TEMP ('porthub-installer-command-' + [Guid]::NewGuid().ToString('N'))
$env:PORTHUB_INSTALL_SMOKE_MARKER = $marker
try {
    foreach ($shell in @('cmd.exe', 'powershell.exe', 'pwsh.exe')) {
        foreach ($fixture in @(0, 1)) {
            $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $process = $null
            try {
                $port = $listener.LocalEndpoint.Port
                $commands = & node (Join-Path $root 'ui/tests/bootstrap-command-fixtures.mjs') "http://127.0.0.1:$port" | ConvertFrom-Json
                if ($LASTEXITCODE -ne 0) { throw 'Could not generate UI installer commands.' }
                $line = $commands[$fixture]
                $info = [Diagnostics.ProcessStartInfo]::new()
                $info.FileName = $shell
                $info.UseShellExecute = $false
                if ($shell -eq 'cmd.exe') {
                    # This is the exact copied line following cmd.exe /c, with
                    # no PowerShell-specific interpretation by the test runner.
                    $info.Arguments = '/d /s /c ' + $line
                } else {
                    $info.ArgumentList.Add('-NoProfile')
                    $info.ArgumentList.Add('-Command')
                    $info.ArgumentList.Add($line)
                }
                $process = [Diagnostics.Process]::Start($info)
                $accept = $listener.AcceptTcpClientAsync()
                if (-not $accept.Wait(20000)) { throw "$shell did not request the installer." }
                $client = $accept.Result
                try {
                    $stream = $client.GetStream()
                    $stream.ReadTimeout = 10000
                    $request = [IO.StreamReader]::new($stream, [Text.Encoding]::ASCII, $false, 1024, $true)
                    $first = $request.ReadLine()
                    if (-not $first.StartsWith('GET /')) { throw 'Expected an installer GET request.' }
                    $expectedPath = if ($fixture -eq 0) { '/install/test-ticket/windows.ps1' } else { '/prefix/$value/%25/!value!/''quoted''/install/test-ticket/windows.ps1' }
                    if ([Uri]::UnescapeDataString($first.Split(' ')[1]) -ne [Uri]::UnescapeDataString($expectedPath)) { throw 'The parent shell changed the installer URL.' }
                    while ($true) {
                        $headerLine = $request.ReadLine()
                        if ($null -eq $headerLine) { throw 'Installer request ended before its headers.' }
                        if ($headerLine -eq '') { break }
                    }
                    $body = '[IO.File]::WriteAllText($env:PORTHUB_INSTALL_SMOKE_MARKER, ''installed'')'
                    $bytes = [Text.Encoding]::UTF8.GetBytes($body)
                    $header = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/plain; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n")
                    $stream.Write($header, 0, $header.Length)
                    $stream.Write($bytes, 0, $bytes.Length)
                    $stream.Flush()
                } finally { $client.Dispose() }
                if (-not $process.WaitForExit(20000)) { throw "$shell installer command did not finish." }
                if ($process.ExitCode -ne 0 -or -not (Test-Path $marker) -or [IO.File]::ReadAllText($marker) -ne 'installed') { throw "$shell failed to execute the copied installer command." }
                Remove-Item $marker
                Write-Host "PASS $shell fixture $fixture"
            } finally {
                $listener.Stop()
                if ($process -and -not $process.HasExited) { $process.Kill($true) }
            }
        }
    }
    # Parse the actual served installer with Windows PowerShell 5.1 too; this
    # must not rely on PowerShell 7-only syntax or execution-policy overrides.
    $template = [IO.File]::ReadAllText((Join-Path $root 'crates/porthub-api/assets/client/install.ps1')).Replace('{{URL}}', "'https://hub.example/install/test-ticket'").Replace('{{ACTION}}', 'setup')
    $syntaxFile = Join-Path $env:TEMP ('porthub-installer-syntax-' + [Guid]::NewGuid().ToString('N') + '.ps1')
    try {
        [IO.File]::WriteAllText($syntaxFile, $template)
        $env:PORTHUB_INSTALL_SYNTAX_FILE = $syntaxFile
        & powershell.exe -NoProfile -Command '$tokens = $null; $errors = $null; [Management.Automation.Language.Parser]::ParseFile($env:PORTHUB_INSTALL_SYNTAX_FILE, [ref]$tokens, [ref]$errors) | Out-Null; if ($errors.Count) { exit 1 }'
        if ($LASTEXITCODE -ne 0) { throw 'Installer is not valid Windows PowerShell 5.1 syntax.' }
    } finally { Remove-Item $syntaxFile -ErrorAction SilentlyContinue }
} finally {
    Remove-Item $marker -ErrorAction SilentlyContinue
    Remove-Item Env:PORTHUB_INSTALL_SMOKE_MARKER -ErrorAction SilentlyContinue
    Remove-Item Env:PORTHUB_INSTALL_SYNTAX_FILE -ErrorAction SilentlyContinue
}
