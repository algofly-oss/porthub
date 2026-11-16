# Disposable GitHub-hosted runner ONLY. No production task/service/profile edits.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('Run','Cleanup')][string]$Phase,[Parameter(Mandatory=$true)][string]$Root,[Parameter(Mandatory=$true)][string]$Repository)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($PSVersionTable.PSVersion.Major -ne 5){throw 'Native Windows PowerShell5 host required'}
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted'){throw 'Disposable GitHub-hosted runner required'}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if($sid -notmatch '^S-1-5-21-(?:[0-9]+-){3}500$'){throw 'Hosted Administrator SID500 fixture required'}
$Root=[IO.Path]::GetFullPath($Root).TrimEnd('\');$leaf=[IO.Path]::GetFileName($Root)
if($leaf -cnotmatch '^porthub-refresh-native-[a-f0-9]{32}$' -or [IO.Path]::GetDirectoryName($Root).TrimEnd('\') -cne [IO.Path]::GetTempPath().TrimEnd('\')){throw 'Exact owned temporary root required'}
$nonce=$leaf.Substring('porthub-refresh-native-'.Length);$name='PortHubPrivateRefresh-'+$nonce+'-'+$sid;$description='PortHub hosted refresh proof '+$nonce
$utf8=New-Object Text.UTF8Encoding($false,$true);$start=[DateTime]::UtcNow;$record=$null;$scheduler=New-Object -ComObject Schedule.Service;$scheduler.Connect();$folder=$scheduler.GetFolder('\')
function Hash-Bytes([byte[]]$Bytes){$h=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($h.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function Private-Path([string]$Path){
 $item=Get-Item -LiteralPath $Path;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse fixture path forbidden'}
 $acl=if($item.PSIsContainer){New-Object Security.AccessControl.DirectorySecurity}else{New-Object Security.AccessControl.FileSecurity}
 $account=New-Object Security.Principal.SecurityIdentifier($sid);$acl.SetOwner($account);$acl.SetAccessRuleProtection($true,$false)
 $inherit=if($item.PSIsContainer){[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}else{[Security.AccessControl.InheritanceFlags]::None}
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($account,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)));Set-Acl -LiteralPath $Path -AclObject $acl
}
function Assert-Private([string]$Path,[switch]$AllowOwnerOnlyInheritance){
 $item=Get-Item -LiteralPath $Path;$acl=Get-Acl -LiteralPath $Path
 if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid -or (!$acl.AreAccessRulesProtected -and !$AllowOwnerOnlyInheritance)){throw 'Fixture ownership changed'}
 foreach($ace in $acl.Access){if($ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -cne $sid -or ($ace.IsInherited -and !$AllowOwnerOnlyInheritance) -or $ace.AccessControlType -cne 'Allow'){throw 'Foreign fixture access rule'}}
}
function Save-Record($Value){$p=Join-Path $Root 'owner.json';[IO.File]::WriteAllText($p,($Value|ConvertTo-Json -Compress -Depth 8),$utf8);Private-Path $p}
function Get-OwnTask {try{return $folder.GetTask($name)}catch{if($_.Exception.HResult -eq -2147024894 -or ($_.Exception.InnerException -and $_.Exception.InnerException.HResult -eq -2147024894)){return $null};throw}}
function Resolve-Sid([string]$Value){if($Value -match '^S-1-'){return $Value};return ([Security.Principal.NTAccount]$Value).Translate([Security.Principal.SecurityIdentifier]).Value}
function Assert-OwnTask($Task){
 if(!$Task -or $Task.Definition.RegistrationInfo.Description -cne $description -or (Resolve-Sid $Task.Definition.Principal.UserId) -cne $sid -or $Task.Definition.Principal.LogonType -ne 3 -or $Task.Definition.Principal.RunLevel -ne 0 -or $Task.Definition.Actions.Count -ne 1 -or $Task.Definition.Triggers.Count -ne 1){throw 'Refusing foreign scheduler task'}
 $a=$Task.Definition.Actions.Item(1);$t=$Task.Definition.Triggers.Item(1)
 if($a.Type -ne 0 -or $a.Path -cnotin @($record.old,$record.new) -or $a.Arguments -cne 'keyboard startup' -or $a.WorkingDirectory -or $t.Type -ne 9 -or $t.Enabled -or (Resolve-Sid $t.UserId) -cne $sid){throw 'Owned task action/trigger changed'}
}
function Own-Processes {return @(Get-CimInstance Win32_Process -Filter "Name='porthub.exe'"|Where-Object{$_.ExecutablePath -and $_.ExecutablePath -cin @($record.old,$record.new)})}
function Pin-Process($Process){
 $owner=Invoke-CimMethod -InputObject $Process -MethodName GetOwnerSid
 if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $sid -or $Process.SessionId -le 0 -or $Process.CreationDate.ToUniversalTime() -lt ([DateTime]$record.created_utc).AddSeconds(-2)){throw 'Inert process identity changed'}
 $path=[string]$Process.ExecutablePath;Assert-Private $path
 if((Hash-Bytes ([IO.File]::ReadAllBytes($path))) -cne [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($path))){throw 'Inert image hash mismatch'}
 $p=Get-Process -Id $Process.ProcessId
 try{if(![string]::Equals($p.Path,$path,[StringComparison]::OrdinalIgnoreCase) -or [Math]::Abs(($p.StartTime.ToUniversalTime()-$Process.CreationDate.ToUniversalTime()).TotalMilliseconds) -ge 10){throw 'Inert PID was reused'};[void]$p.Handle;return $p}catch{$p.Dispose();throw}
}
function Wait-Image([string]$Path){$end=[DateTime]::UtcNow.AddSeconds(8);do{$rows=@(Own-Processes);if($rows.Count -eq 1 -and $rows[0].ExecutablePath -ceq $Path){$p=Pin-Process $rows[0];$p.Dispose();return $rows[0]};Start-Sleep -Milliseconds 50}while([DateTime]::UtcNow -lt $end);throw 'Inert image did not start'}
function Stop-Owned {
 $task=Get-OwnTask;if($task){Assert-OwnTask $task;$task.Stop(0)}
 $end=[DateTime]::UtcNow.AddSeconds(5);while(@(Own-Processes).Count -and [DateTime]::UtcNow -lt $end){Start-Sleep -Milliseconds 50}
 foreach($row in @(Own-Processes)){$p=Pin-Process $row;try{if(!$p.HasExited){$p.Kill();if(!$p.WaitForExit(3000)){throw 'Inert process did not stop'}}}finally{$p.Dispose()}}
 if(@(Own-Processes).Count){throw 'Inert process remains'}
}
function Stop-OwnedBootstrap {
 if(!$record.bootstrap){return}
 $saved=$record.bootstrap;$rows=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$saved.pid))
 if(!$rows.Count){return};if($rows.Count -ne 1){throw 'Bootstrap process identity ambiguous'}
 $row=$rows[0];$owner=Invoke-CimMethod -InputObject $row -MethodName GetOwnerSid
 if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $sid -or ![string]::Equals($row.ExecutablePath,$saved.image,[StringComparison]::OrdinalIgnoreCase) -or [Math]::Abs(($row.CreationDate.ToUniversalTime()-([DateTime]$saved.created_utc)).TotalMilliseconds) -ge 10 -or !$row.CommandLine.EndsWith(' '+$saved.arguments,[StringComparison]::Ordinal)){throw 'Refusing changed bootstrap process'}
 $p=Get-Process -Id $row.ProcessId
 try{if(![string]::Equals($p.Path,$row.ExecutablePath,[StringComparison]::OrdinalIgnoreCase) -or [Math]::Abs(($p.StartTime.ToUniversalTime()-$row.CreationDate.ToUniversalTime()).TotalMilliseconds) -ge 10){throw 'Bootstrap PID reused'};[void]$p.Handle;if(!$p.HasExited){$p.Kill();if(!$p.WaitForExit(3000)){throw 'Bootstrap cleanup timeout'}}}finally{$p.Dispose()}
}
function Baseline {
 return @{services=@(Get-CimInstance Win32_Service|Where-Object{$_.Name -match '(?i)^porthub'}|ForEach-Object{$_.Name});tasks=@($folder.GetTasks(1)|Where-Object{$_.Name -like 'PortHub*' -and $_.Name -cne $name}|ForEach-Object{$_.Name});real_processes=@(Get-CimInstance Win32_Process -Filter "Name='porthub.exe'"|Where-Object{!$record -or $_.ExecutablePath -cnotin @($record.old,$record.new)}|ForEach-Object{$_.ProcessId})}
}
function Cleanup-Owned {
 if(!(Test-Path -LiteralPath $Root)){if((Get-OwnTask) -or @(Get-CimInstance Win32_Process -Filter "Name='porthub.exe'"|Where-Object{$_.ExecutablePath -and $_.ExecutablePath.StartsWith($Root+'\',[StringComparison]::OrdinalIgnoreCase)}).Count){throw 'Task/process exists without owned manifest'};return @{root_absent=$true;task_absent=$true;processes_absent=$true}}
 Assert-Private $Root;$p=Join-Path $Root 'owner.json';Assert-Private $p
 if((Get-Item $p).Length -gt 8192){throw 'Owned record exceeds bound'}
 $script:record=[IO.File]::ReadAllText($p,$utf8)|ConvertFrom-Json
 if($record.nonce -cne $nonce -or $record.sid -cne $sid -or $record.task -cne $name){throw 'Owned record mismatch'}
 foreach($path in @($record.old,$record.new)){if($path -and ![IO.Path]::GetFullPath($path).StartsWith($Root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Foreign cleanup path'}}
 Stop-OwnedBootstrap;Stop-Owned;$task=Get-OwnTask;if($task){Assert-OwnTask $task;$folder.DeleteTask($name,0)}
 if((Get-OwnTask) -or @(Own-Processes).Count){throw 'Owned scheduler cleanup incomplete'}
 $after=Baseline;if(!$record.baseline -or $after.services.Count -or $after.tasks.Count -or $after.real_processes.Count -or $record.baseline.services.Count -or $record.baseline.tasks.Count -or $record.baseline.real_processes.Count){throw 'Disposable baseline changed'}
 $children=@(Get-ChildItem -LiteralPath $Root -Recurse -Force);if($children.Count -gt 32 -or @($children|Where-Object{$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw 'Unsafe cleanup tree'}
 foreach($child in $children){Assert-Private $child.FullName -AllowOwnerOnlyInheritance}
 Remove-Item -LiteralPath $Root -Recurse -Force;if(Test-Path -LiteralPath $Root){throw 'Owned root remains'}
 return @{root_absent=$true;task_absent=$true;processes_absent=$true;baseline_unchanged=$true}
}
if($Phase -eq 'Cleanup'){Cleanup-Owned|ConvertTo-Json -Compress;return}
if((Test-Path -LiteralPath $Root) -or (Get-OwnTask)){throw 'Fresh fixture namespace required'}
$before=Baseline;if($before.services.Count -or $before.tasks.Count -or $before.real_processes.Count){throw 'No existing PortHub state allowed on disposable runner'}
$sourcePath=Join-Path $Repository 'crates/porthub-agent/src/keyboard/windows_refresh.ps1';$rustPath=Join-Path $Repository 'crates/porthub-agent/src/keyboard/windows_refresh.rs'
$source=[IO.File]::ReadAllText($sourcePath,$utf8);$rust=[IO.File]::ReadAllText($rustPath,$utf8)
$needle="'PortHubKeyboard-'";if(($source.Split(@($needle),[StringSplitOptions]::None).Length-1) -ne 1){throw 'Exactly one private task-prefix adaptation required'}
$derived=$source.Replace($needle,("'PortHubPrivateRefresh-"+$nonce+"-'"))
$match=[regex]::Match($rust,'(?s)const BOOTSTRAP: &str = r#"(.*?)"#;');if(!$match.Success){throw 'Actual Rust bootstrap not found'}
$bootstrap=$match.Groups[1].Value.Replace('__SCRIPT_SHA256__',(Hash-Bytes ($utf8.GetBytes($derived))))
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap));if($encoded.Length -gt 8192){throw 'Native bootstrap argv exceeds bound'}
$record=[ordered]@{nonce=$nonce;sid=$sid;task=$name;created_utc=$start.ToString('o');old=$null;new=$null;baseline=$before;bootstrap=$null}
$failure=$null;$outcome=$null;$cleanup=$null
try{
 New-Item -ItemType Directory -Path $Root|Out-Null;Private-Path $Root;Save-Record $record
 $releases=Join-Path $Root 'releases';New-Item -ItemType Directory $releases|Out-Null;Private-Path $releases
 for($v=1;$v -le 2;$v++){
  $temporary=Join-Path $Root ('compile-'+$v+'.exe')
  $code='using System;using System.Runtime.InteropServices;using System.Threading;public static class Inert'+$v+$nonce+'{[DllImport("kernel32.dll")]static extern bool FreeConsole();public static void Main(string[] args){FreeConsole();Thread.Sleep(120000);}}'
  Add-Type -TypeDefinition $code -OutputAssembly $temporary -OutputType ConsoleApplication
  Private-Path $temporary;$digest=Hash-Bytes ([IO.File]::ReadAllBytes($temporary));$dir=Join-Path $releases $digest;New-Item -ItemType Directory $dir|Out-Null;Private-Path $dir
  $path=Join-Path $dir 'porthub.exe';Move-Item -LiteralPath $temporary -Destination $path;Private-Path $path
  if($v -eq 1){$record.old=$path}else{$record.new=$path};Save-Record $record
 }
 if($record.old -ceq $record.new){throw 'Distinct inert images required'}
 $action=New-ScheduledTaskAction -Execute $record.old -Argument 'keyboard startup'
 $trigger=New-ScheduledTaskTrigger -AtLogOn -User $sid;$trigger.Enabled=$false
 $principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
 $settings=New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 $definition=New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $description
 Register-ScheduledTask -TaskName $name -InputObject $definition|Out-Null
 $task=Get-OwnTask;Assert-OwnTask $task;$oldXml=$task.Xml;$sd=$task.GetSecurityDescriptor(7)
 . ([scriptblock]::Create($derived))
 if(-not ('RefreshBoundedDrain' -as [type])){Add-Type -TypeDefinition @'
using System;using System.IO;using System.Text;using System.Threading.Tasks;public static class RefreshBoundedDrain{public static async Task<string> Read(StreamReader r){var s=new StringBuilder();var b=new char[2048];int n;while((n=await r.ReadAsync(b,0,b.Length).ConfigureAwait(false))>0){if(s.Length+n>32768)throw new IOException("Fixture output bound");s.Append(b,0,n);}return s.ToString();}}
'@}
 function Invoke-ActualBootstrap {
  $request=@{script=$derived;request=@{executable=$record.new;release_root=$releases;sids=@($sid)}}
  $bytes=$utf8.GetBytes(($request|ConvertTo-Json -Compress -Depth 6));if($bytes.Length -gt 131072){throw 'Envelope exceeds bound'}
  $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe';$info.Arguments='-NoLogo -NoProfile -NonInteractive -EncodedCommand '+$encoded;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.StandardOutputEncoding=$utf8;$info.StandardErrorEncoding=$utf8;$info.EnvironmentVariables.Remove('PSModulePath');$info.EnvironmentVariables.Remove('PSModuleAnalysisCachePath')
  $child=[Diagnostics.Process]::Start($info)
  $record.bootstrap=@{pid=$child.Id;created_utc=$child.StartTime.ToUniversalTime().ToString('o');image=$info.FileName;arguments=$info.Arguments};Save-Record $record
  try{
   $output=[RefreshBoundedDrain]::Read($child.StandardOutput);$errors=[RefreshBoundedDrain]::Read($child.StandardError)
   $child.StandardInput.BaseStream.Write($bytes,0,$bytes.Length);$child.StandardInput.Close();$end=[DateTime]::UtcNow.AddSeconds(35)
   while(!$child.WaitForExit(50)){if($output.IsFaulted -or $errors.IsFaulted -or [DateTime]::UtcNow -gt $end){throw 'Native bootstrap exceeded bound'}}
   if(![Threading.Tasks.Task]::WaitAll(@($output,$errors),1000)){throw 'Native bootstrap output did not close'}
   if($child.ExitCode -ne 0){throw ('Native bootstrap failed: '+$errors.GetAwaiter().GetResult())}
   return $output.GetAwaiter().GetResult()|ConvertFrom-Json
  }finally{try{if(!$child.HasExited){$child.Kill();if(!$child.WaitForExit(3000)){throw 'Owned bootstrap did not exit'}}}finally{$exited=$child.HasExited;$child.Dispose();if($exited){$record.bootstrap=$null;Save-Record $record}}}
 }
 $null=$task.Run($null);$old=Wait-Image $record.old;$oldHandle=Pin-Process $old
 try{
  $active=@(Invoke-ActualBootstrap);$new=Wait-Image $record.new
  if(!$oldHandle.WaitForExit(0) -or $new.ProcessId -eq $old.ProcessId -or $active[0].state -cne 'restarted'){throw 'Active image refresh failed'}
 }finally{$oldHandle.Dispose()}
 $task=Get-OwnTask;Assert-OwnTask $task
 # Revert only action in a local XML copy; validate all other XML and exact SD.
 $doc=Read-RefreshXml $task.Xml;$ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('t',$doc.DocumentElement.NamespaceURI);$doc.SelectSingleNode('/t:Task/t:Actions/t:Exec/t:Command',$ns).InnerText=$record.old
 $copy=[pscustomobject]@{Xml=$doc.OuterXml;Sddl=$task.GetSecurityDescriptor(7)};$copy|Add-Member ScriptMethod GetSecurityDescriptor {param($flags)return $this.Sddl}
 Assert-RefreshSnapshot $copy $oldXml $sd -AllowRegisteredSecurityDescriptor
 Stop-Owned;$d=$task.Definition;$d.Actions.Item(1).Path=$record.old;$task=$folder.RegisterTaskDefinition($name,$d,52,$sid,$null,3,$sd)
 $inactive=@(Invoke-ActualBootstrap);Start-Sleep -Milliseconds 250
 if($inactive[0].state -cne 'updated-inactive' -or @(Own-Processes).Count -or (Get-OwnTask).State -eq 4){throw 'Inactive refresh started a process'}
 $task=Get-OwnTask;Assert-OwnTask $task
 if($task.Definition.Actions.Item(1).Path -cne $record.new -or $task.GetSecurityDescriptor(7) -cne $sd){throw 'Inactive refresh action/security changed'}
 $doc=Read-RefreshXml $task.Xml;$ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('t',$doc.DocumentElement.NamespaceURI);$doc.SelectSingleNode('/t:Task/t:Actions/t:Exec/t:Command',$ns).InnerText=$record.old
 $copy.Xml=$doc.OuterXml;$copy.Sddl=$task.GetSecurityDescriptor(7);Assert-RefreshSnapshot $copy $oldXml $sd -AllowRegisteredSecurityDescriptor
 $initial=Read-RefreshXml $oldXml;$final=Read-RefreshXml $task.Xml;$metaNs=New-Object Xml.XmlNamespaceManager($initial.NameTable);$metaNs.AddNamespace('t',$initial.DocumentElement.NamespaceURI);$initialSdCount=@($initial.SelectNodes('/t:Task/t:RegistrationInfo/t:SecurityDescriptor',$metaNs)).Count;$finalNs=New-Object Xml.XmlNamespaceManager($final.NameTable);$finalNs.AddNamespace('t',$final.DocumentElement.NamespaceURI);$finalSdCount=@($final.SelectNodes('/t:Task/t:RegistrationInfo/t:SecurityDescriptor',$finalNs)).Count
 $outcome=@{powershell_major=$PSVersionTable.PSVersion.Major;initial_xml_sd_nodes=$initialSdCount;final_xml_sd_nodes=$finalSdCount;active_refresh=$true;inactive_no_start=$true;exact_sd_preserved=$true;nonaction_xml_preserved=$true;hosted_sid500=$true;original_script_sha256=(Hash-Bytes ($utf8.GetBytes($source)));derived_script_sha256=(Hash-Bytes ($utf8.GetBytes($derived)));bootstrap_sha256=(Hash-Bytes ($utf8.GetBytes($bootstrap)));bootstrap_argv_chars=$encoded.Length;payload='inert sleep120 only; no files/network/input/media';production_state_touched=$false}
}catch{$failure=$_}finally{$cleanup=Cleanup-Owned}
if($failure){throw $failure}
@{proof=$outcome;cleanup=$cleanup}|ConvertTo-Json -Compress -Depth 6
