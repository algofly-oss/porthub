param(
    [Parameter(Mandatory=$true)][string]$RuleScript,
    [Parameter(Mandatory=$true)][string]$Executable
)
$ErrorActionPreference = 'Stop'
if (!(Test-Path -LiteralPath $Executable -PathType Leaf)) { throw 'Test requires an existing executable' }
$body = [ScriptBlock]::Create($RuleScript)
$name = 'PortHub-USB-Test-' + [Guid]::NewGuid().ToString('N')
$oldName = $env:PORTHUB_USB_RULE
$oldExe = $env:PORTHUB_USB_EXE
$env:PORTHUB_USB_RULE = $name
$env:PORTHUB_USB_EXE = $Executable
try {
    if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) { throw 'Unexpected fixture collision' }
    # Creation and idempotent reapplication use the production script verbatim.
    & $body
    & $body
    # An owned rule left pointing at the previous immutable binary must migrate.
    $rule = Get-NetFirewallRule -Name $name -ErrorAction Stop
    $rule | Get-NetFirewallApplicationFilter | Set-NetFirewallApplicationFilter -Program ($Executable + '.previous') | Out-Null
    & $body
    $actual = @(Get-NetFirewallRule -Name $name | Get-NetFirewallApplicationFilter)
    if ($actual.Count -ne 1 -or $actual[0].Program -ne $Executable) { throw 'Executable reconciliation failed' }
    # Reusing a foreign-owned name must fail without changing its target.
    Get-NetFirewallRule -Name $name | Remove-NetFirewallRule
    New-NetFirewallRule -Name $name -DisplayName $name -Group 'PortHub test foreign owner' -Program $Executable -Protocol TCP -Direction Inbound -RemoteAddress LocalSubnet | Out-Null
    $failed = $false
    try { & $body } catch { $failed = $true }
    if (!$failed) { throw 'Foreign ownership was accepted' }
    $foreign = Get-NetFirewallRule -Name $name
    if ($foreign.Group -ne 'PortHub test foreign owner' -or ($foreign | Get-NetFirewallApplicationFilter).Program -ne $Executable) { throw 'Foreign rule was changed' }
    'OWNED_USB_FIREWALL_CREATE_REAPPLY_UPGRADE_FOREIGN_REFUSAL_PASS'
} finally {
    # This unpredictable fixture name was created in this invocation only.
    Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $env:PORTHUB_USB_RULE = $oldName
    $env:PORTHUB_USB_EXE = $oldExe
}
