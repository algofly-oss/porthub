$ErrorActionPreference = 'Stop'
$name = $env:PORTHUB_USB_RULE
$group = 'PortHub managed USB bulk'
$program = $env:PORTHUB_USB_EXE
if (!$name -or !$program -or ![IO.Path]::IsPathRooted($program)) { throw 'Invalid USB firewall rule identity' }
$old = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
if ($old) {
    if (@($old).Count -ne 1 -or $old.Group -ne $group) { throw 'USB firewall rule belongs to another owner' }
    Set-NetFirewallRule -Name $name -Enabled True -Action Allow -Direction Inbound -Profile Any -RemoteAddress LocalSubnet
    # AssociatedNetFirewallRule belongs to Get, not Set. Pipe its owned filter
    # into Set so upgrades replace the immutable executable path correctly.
    Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $old |
        Set-NetFirewallApplicationFilter -Program $program | Out-Null
    Get-NetFirewallPortFilter -AssociatedNetFirewallRule $old |
        Set-NetFirewallPortFilter -Protocol TCP -LocalPort Any | Out-Null
} else {
    New-NetFirewallRule -Name $name -DisplayName $name -Group $group -Direction Inbound -Action Allow -Profile Any -Program $program -Protocol TCP -RemoteAddress LocalSubnet | Out-Null
}
# Do not report prerequisite readiness when a policy provider ignored a change.
$rule = Get-NetFirewallRule -Name $name -ErrorAction Stop
$app = @($rule | Get-NetFirewallApplicationFilter)
$port = @($rule | Get-NetFirewallPortFilter)
$address = @($rule | Get-NetFirewallAddressFilter)
if (@($rule).Count -ne 1 -or $rule.Group -ne $group -or [string]$rule.Enabled -ne 'True' -or [string]$rule.Action -ne 'Allow' -or [string]$rule.Direction -ne 'Inbound' -or
    $app.Count -ne 1 -or $app[0].Program -ne $program -or $port.Count -ne 1 -or [string]$port[0].Protocol -notin @('TCP', '6') -or [string]$port[0].LocalPort -ne 'Any' -or
    $address.Count -ne 1 -or @($address[0].RemoteAddress).Count -ne 1 -or [string]$address[0].RemoteAddress -ne 'LocalSubnet') {
    throw 'Owned PortHub USB firewall rule verification failed'
}
