$ErrorActionPreference='Stop'
# OS scheduler/process/file-identity boundaries are mocked; no live task is changed.
. (Join-Path $PSScriptRoot '../crates/porthub-agent/src/keyboard/windows_refresh.ps1')
$global:Rsid='S-1-5-21-123-456-789-1001';$global:Rold='C:\ProgramData\PortHub\releases\'+('a'*64)+'\porthub.exe';$global:Rnew='C:\ProgramData\PortHub\releases\'+('b'*64)+'\porthub.exe';$global:Rroot='C:\ProgramData\PortHub\releases'
function Test-RefreshExecutable([string]$Path,[string]$ReleaseRoot){return $ReleaseRoot -ceq $global:Rroot -and (($Path -ceq $global:Rnew -and $global:NewHashOk) -or ($Path -ceq $global:Rold -and $global:OldHashOk))}
function Collection($Value){$o=[pscustomobject]@{Count=1;Value=$Value};$o|Add-Member ScriptMethod Item {param($n)if($n -ne 1){throw 'One-based COM index required'};return $this.Value};return $o}
function New-Task([string]$Xml,[bool]$Enabled=$true,[int]$State=4){
 $doc=Read-RefreshXml $Xml;$ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('t','urn:task')
 $cmd=$doc.SelectSingleNode('/t:Task/t:Actions/t:Exec/t:Command',$ns).InnerText;$ActionArgs=$doc.SelectSingleNode('/t:Task/t:Actions/t:Exec/t:Arguments',$ns).InnerText
 $d=[pscustomobject]@{Principal=[pscustomobject]@{UserId=$global:Rsid;LogonType=3;RunLevel=0};Actions=(Collection ([pscustomobject]@{Type=0;Path=$cmd;Arguments=$ActionArgs;WorkingDirectory=''}));Triggers=(Collection ([pscustomobject]@{Type=9;UserId=$global:Rsid}))}
 $t=[pscustomobject]@{Xml=$Xml;Definition=$d;Enabled=$Enabled;State=$State;Sddl='O:SYG:SYD:P(A;;FA;;;SY)(A;;FR;;;BA)'}
 $t|Add-Member ScriptMethod GetSecurityDescriptor {param($flags)if($flags -ne 7){throw 'Owner/group/DACL flags required'};return $this.Sddl}
 $t|Add-Member ScriptMethod Stop {param($flags)$global:Stops++;if($global:StopFailure){throw 'Injected stop failure'};$this.State=3;$global:ProcessExited=$global:StopExits}
 $t|Add-Member ScriptMethod Run {param($none)$global:Starts++;if($global:StartFailureOnce){$global:StartFailureOnce=$false;throw 'Injected start failure'};$this.State=4;$global:ProcessExited=$false;return [pscustomobject]@{Running=$true}}
 return $t
}
function Reset-Case([string]$ActionArgs='keyboard startup'){
 $global:Stops=0;$global:Starts=0;$global:Updates=0;$global:NewHashOk=$true;$global:OldHashOk=$true;$global:StopFailure=$false;$global:StopExits=$true;$global:ProcessExited=$false;$global:StartFailureOnce=$false;$global:RegisterFailure='';$global:Disposed=0;$global:OwnerSid=$global:Rsid;$global:ProcessPath=$global:Rold;$global:Creation=[DateTime]::UtcNow;$global:NativeStart=$global:Creation;$global:SessionId=2
 $xml='<Task xmlns="urn:task"><RegistrationInfo><Description>Preserved</Description></RegistrationInfo><Triggers><LogonTrigger><UserId>'+ $global:Rsid+'</UserId></LogonTrigger></Triggers><Principals><Principal><UserId>'+$global:Rsid+'</UserId></Principal></Principals><Settings><Enabled>true</Enabled><Custom>kept</Custom></Settings><Actions><Exec><Command>'+$global:Rold+'</Command><Arguments>'+$ActionArgs+'</Arguments></Exec></Actions></Task>'
 $global:Task=New-Task $xml;$global:OldXml=$xml;$global:OldSd=$global:Task.Sddl
}
function Connect-RefreshScheduler {
 $service=[pscustomobject]@{};$service|Add-Member ScriptMethod NewTask {param($flags)return [pscustomobject]@{XmlText=''}}
 $folder=[pscustomobject]@{};$folder|Add-Member ScriptMethod GetTask {param($Name)if($Name -cne 'PortHubKeyboard-'+$global:Rsid){throw 'Unexpected task namespace'};return $global:Task}
 $folder|Add-Member ScriptMethod RegisterTaskDefinition {param($Name,$Definition,$Flags,$Sid,$Password,$Logon,$Sddl)
  if($Name -cne 'PortHubKeyboard-'+$global:Rsid -or $Flags -ne 52 -or $Sid -cne $global:Rsid -or $null -ne $Password -or $Logon -ne 3 -or $Sddl -cne $global:OldSd){throw 'Unsafe scheduler update/ACE/password semantics'}
  $global:Updates++;if($global:RegisterFailure -eq 'before'){$global:RegisterFailure='';throw 'Injected pre-write registration failure'}
  $global:Task=New-Task $Definition.XmlText $true 3;$global:Task.Sddl=$Sddl
  if($global:RegisterFailure -eq 'after'){$global:RegisterFailure='';throw 'Injected post-write registration failure'}
  return $global:Task
 }
 return [pscustomobject]@{Service=$service;Folder=$folder}
}
function Get-CimInstance {param($ClassName,$Filter)return [pscustomobject]@{SessionId=$global:SessionId;ExecutablePath=$global:ProcessPath;CommandLine=('"'+$global:ProcessPath+'" '+$global:Task.Definition.Actions.Item(1).Arguments);ProcessId=1234;CreationDate=$global:Creation}}
function Invoke-CimMethod {param($InputObject,$MethodName)return [pscustomobject]@{ReturnValue=0;Sid=$global:OwnerSid}}
function Get-Process {param($Id,$ErrorAction)$p=[pscustomobject]@{Path=$global:ProcessPath;StartTime=$global:NativeStart;Handle=123};$p|Add-Member ScriptProperty HasExited {return $global:ProcessExited};$p|Add-Member ScriptMethod WaitForExit {param($ms)return $global:ProcessExited};$p|Add-Member ScriptMethod Dispose {$global:Disposed++};return $p}
function Run-Refresh{return @(Invoke-PortHubDesktopRefresh ([pscustomobject]@{executable=$global:Rnew;release_root=$global:Rroot;sids=@($global:Rsid)}))}
function Expect-Failure([scriptblock]$Work,[string]$Name){$failed=$false;try{&$Work|Out-Null}catch{$failed=$true};if(!$failed){throw "$Name unexpectedly succeeded"}}
$results=@()
foreach($ActionArgs in @('keyboard startup','keyboard run')){
 Reset-Case $ActionArgs;$old=(Read-RefreshXml $global:OldXml);$r=Run-Refresh
 if($global:Stops -ne 1 -or $global:Starts -ne 1 -or $global:Updates -ne 1 -or $global:Task.Definition.Actions.Item(1).Path -cne $global:Rnew -or $global:Task.Definition.Actions.Item(1).Arguments -cne 'keyboard startup' -or $global:Task.Sddl -cne $global:OldSd -or $global:Disposed -ne 1){throw ('Running managed task not safely refreshed '+(@{Stops=$global:Stops;Starts=$global:Starts;Updates=$global:Updates;Disposed=$global:Disposed;Path=$global:Task.Definition.Actions.Item(1).Path;Args=$global:Task.Definition.Actions.Item(1).Arguments;Result=$r}|ConvertTo-Json -Compress -Depth 4))}
 $restored=Read-RefreshXml $global:Task.Xml;$n=New-Object Xml.XmlNamespaceManager($restored.NameTable);$n.AddNamespace('t','urn:task');$restored.SelectSingleNode('/t:Task/t:Actions/t:Exec/t:Command',$n).InnerText=$global:Rold;$restored.SelectSingleNode('/t:Task/t:Actions/t:Exec/t:Arguments',$n).InnerText=$ActionArgs
 if($restored.OuterXml -cne $old.OuterXml){throw 'Non-action task XML changed'}
 $results+=@{case=('running-'+$ActionArgs);passed=$true}
}
Reset-Case;$global:Task.State=3;Run-Refresh|Out-Null;if($global:Starts -or $global:Stops -or $global:Updates -ne 1){throw 'Inactive task was started/stopped'};$results+=@{case='inactive-action-only';passed=$true}
foreach($case in @('disabled','missing','custom-args','custom-trigger','custom-workingdir','wrong-principal','system-logon','highest','old-hash','session0','foreign-process','pid-reuse')){
 Reset-Case
 switch($case){'disabled'{$global:Task.Enabled=$false};'missing'{$global:Task=$null};'custom-args'{$global:Task.Definition.Actions.Item(1).Arguments='keyboard run --other'};'custom-trigger'{$global:Task.Definition.Triggers.Item(1).Type=1};'custom-workingdir'{$global:Task.Definition.Actions.Item(1).WorkingDirectory='C:\custom'};'wrong-principal'{$global:Task.Definition.Principal.UserId='S-1-5-21-other'};'system-logon'{$global:Task.Definition.Principal.LogonType=5};'highest'{$global:Task.Definition.Principal.RunLevel=1};'old-hash'{$global:OldHashOk=$false};'session0'{$global:SessionId=0};'foreign-process'{$global:OwnerSid='S-1-5-21-other'};'pid-reuse'{$global:NativeStart=$global:Creation.AddSeconds(1)}}
 if($case -in @('session0','foreign-process','pid-reuse')){Expect-Failure {Run-Refresh} $case}else{Run-Refresh|Out-Null}
 if($global:Updates -or $global:Starts -or $global:Stops){throw "$case mutated task"};$results+=@{case=$case;passed=$true}
}
foreach($case in @('new-hash','stop-failure','wait-failure','update-before','update-after','start-failure')){
 Reset-Case
 switch($case){'new-hash'{$global:NewHashOk=$false};'stop-failure'{$global:StopFailure=$true};'wait-failure'{$global:StopExits=$false};'update-before'{$global:RegisterFailure='before'};'update-after'{$global:RegisterFailure='after'};'start-failure'{$global:StartFailureOnce=$true}}
 Expect-Failure {Run-Refresh} $case
 if($global:Task.Xml -cne $global:OldXml -and (Read-RefreshXml $global:Task.Xml).OuterXml -cne (Read-RefreshXml $global:OldXml).OuterXml){throw "$case failed to preserve/restore task definition"}
 if($global:Task.Sddl -cne $global:OldSd){throw "$case changed DACL"}
 if($case -in @('update-before','update-after','start-failure') -and $global:Task.State -ne 4){throw "$case failed to restore running task"}
 if($case -eq 'wait-failure' -and $global:Starts){throw 'Lease wait failure started duplicate helper'}
 $results+=@{case=$case;passed=$true}
}

foreach($case in @('current-running','current-inactive','current-definition-stale-process')){
 Reset-Case
 $xml=$global:OldXml.Replace($global:Rold,$global:Rnew);$global:Task=New-Task $xml $true $(if($case -eq 'current-inactive'){3}else{4})
 if($case -ne 'current-definition-stale-process'){$global:ProcessPath=$global:Rnew}
 Run-Refresh|Out-Null
 if($case -eq 'current-definition-stale-process'){
  if($global:Stops -ne 1 -or $global:Starts -ne 1 -or $global:Updates -ne 0 -or $global:Disposed -ne 1){throw 'Current definition hid stale running helper'}
 }else{if($global:Stops -or $global:Starts -or $global:Updates){throw 'Current helper was unnecessarily restarted'}}
 $results+=@{case=$case;passed=$true}
}
foreach($sid in @('S-1-5-18','S-1-5-19','S-1-5-20','invalid')){
 Reset-Case;Expect-Failure {Invoke-PortHubDesktopRefresh ([pscustomobject]@{executable=$global:Rnew;release_root=$global:Rroot;sids=@($sid)})} ('forbidden-'+$sid)
 if($global:Stops -or $global:Starts -or $global:Updates){throw 'Unauthorized account touched task'};$results+=@{case=('forbidden-'+$sid);passed=$true}
}
Expect-Failure {Read-RefreshXml '<!DOCTYPE Task [<!ENTITY x SYSTEM "file:///not-a-proof-input">]><Task>&x;</Task>'} 'DTD-prohibited';$results+=@{case='DTD-prohibited';passed=$true}
$results|ConvertTo-Json -Depth 4
