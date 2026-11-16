# Updates existing managed desktop tasks only. No service/task installation,
# feature preference changes, account inference, or interactive login creation.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
function Test-RefreshSid([string]$Sid){return $Sid.Length -lt 184 -and $Sid -match '^S-1-[0-9]+(?:-[0-9]+)+$' -and $Sid -notin @('S-1-5-18','S-1-5-19','S-1-5-20')}
function Test-RefreshExecutable([string]$Path,[string]$ReleaseRoot){
 $item=Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
 if(!$item -or $item.PSIsContainer -or $item.Name -cne 'porthub.exe' -or $item.Directory.Name -notmatch '^[a-fA-F0-9]{64}$' -or ![string]::Equals($item.Directory.Parent.FullName,$ReleaseRoot,[StringComparison]::OrdinalIgnoreCase)){return $false}
 for($at=$item;$null -ne $at;$at=$at.Parent){if($at.Attributes -band [IO.FileAttributes]::ReparsePoint){return $false};if($at -is [IO.FileInfo]){$at=$at.Directory;if($at.Attributes -band [IO.FileAttributes]::ReparsePoint){return $false}}}
 $stream=[IO.File]::OpenRead($item.FullName);$hash=[Security.Cryptography.SHA256]::Create()
 try{return ([BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-','')) -ieq $item.Directory.Name}finally{$hash.Dispose();$stream.Dispose()}
}
function Read-RefreshXml([string]$Text){
 if($Text.Length -gt 131072){throw 'Desktop task definition exceeds bounds'}
 $settings=New-Object Xml.XmlReaderSettings;$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=131072
 $reader=[Xml.XmlReader]::Create((New-Object IO.StringReader($Text)),$settings)
 try{$doc=New-Object Xml.XmlDocument;$doc.XmlResolver=$null;$doc.Load($reader);return ,$doc}finally{$reader.Dispose()}
}
function Resolve-RefreshPrincipal([string]$User){if($User -match '^S-1-'){return $User};return ([Security.Principal.NTAccount]$User).Translate([Security.Principal.SecurityIdentifier]).Value}
function Get-RefreshTask($Folder,[string]$Name){
 try{return $Folder.GetTask($Name)}catch{if($_.Exception.HResult -eq -2147024894 -or ($_.Exception.InnerException -and $_.Exception.InnerException.HResult -eq -2147024894)){return $null};throw}
}
function Test-RefreshTask($Task,[string]$Sid,[string]$ReleaseRoot){
 if(!$Task -or !$Task.Enabled){return $false}
 $d=$Task.Definition
 if((Resolve-RefreshPrincipal $d.Principal.UserId) -cne $Sid -or $d.Principal.LogonType -ne 3 -or $d.Principal.RunLevel -ne 0 -or $d.Actions.Count -ne 1 -or $d.Actions.Item(1).Type -ne 0){return $false}
 $action=$d.Actions.Item(1)
 if($action.Arguments -cnotin @('keyboard run','keyboard startup') -or $action.WorkingDirectory -or !(Test-RefreshExecutable $action.Path $ReleaseRoot)){return $false}
 # A custom registration/time trigger must never become an incidental login.
 if($d.Triggers.Count -ne 1 -or $d.Triggers.Item(1).Type -ne 9 -or (Resolve-RefreshPrincipal $d.Triggers.Item(1).UserId) -cne $Sid){return $false}
 return $true
}
function Get-RefreshProcess([string]$Sid,[string]$Arguments,[string]$ReleaseRoot){
 $owned=@()
 foreach($p in @(Get-CimInstance Win32_Process -Filter "Name='porthub.exe'")){
  if($p.SessionId -gt 0 -and (Test-RefreshExecutable $p.ExecutablePath $ReleaseRoot) -and $p.CommandLine -match ('(?i)\s'+[regex]::Escape($Arguments)+'\s*$')){
   $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
   if($owner.ReturnValue -eq 0 -and $owner.Sid -ceq $Sid){$owned+=,$p}
  }
 }
 if($owned.Count -ne 1){throw 'Running desktop task has no unique verified interactive process'}
 $p=$owned[0];$native=Get-Process -Id $p.ProcessId -ErrorAction Stop
 try{
  if(![string]::Equals($native.Path,$p.ExecutablePath,[StringComparison]::OrdinalIgnoreCase) -or [Math]::Abs(($native.StartTime.ToUniversalTime()-$p.CreationDate.ToUniversalTime()).TotalMilliseconds) -ge 10){throw 'Desktop process identity changed'}
  [void]$native.Handle;return $native
 }catch{$native.Dispose();throw}
}
function Set-RefreshDefinition($Service,$Folder,[string]$Name,[string]$Xml,[string]$Sid,[string]$Sddl){
 $definition=$Service.NewTask(0);$definition.XmlText=$Xml
 # UPDATE only: never create, grant a principal ACE, or fire registration triggers.
 return $Folder.RegisterTaskDefinition($Name,$definition,52,$Sid,$null,3,$Sddl)
}
function Get-RefreshTextHash([string]$Text){
 $hash=[Security.Cryptography.SHA256]::Create()
 try{return [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
}
function Get-RefreshXmlFields($Document){
 $fields=@{};$stack=New-Object Collections.Stack;$stack.Push([pscustomobject]@{Node=$Document.DocumentElement;Path='/Task'})
 $allowed=@('Task','RegistrationInfo','Date','Author','Description','URI','Version','Source','SecurityDescriptor','Documentation','Triggers','LogonTrigger','UserId','Enabled','Delay','StartBoundary','EndBoundary','ExecutionTimeLimit','Repetition','Interval','Duration','StopAtDurationEnd','Principals','Principal','GroupId','DisplayName','LogonType','RunLevel','ProcessTokenSidType','RequiredPrivileges','Privilege','Settings','MultipleInstancesPolicy','DisallowStartIfOnBatteries','StopIfGoingOnBatteries','AllowHardTerminate','StartWhenAvailable','NetworkProfileName','RunOnlyIfNetworkAvailable','WakeToRun','Hidden','IdleSettings','Duration','WaitTimeout','StopOnIdleEnd','RestartOnIdle','RunOnlyIfIdle','RestartOnFailure','Count','Priority','DeleteExpiredTaskAfter','UseUnifiedSchedulingEngine','DisallowStartOnRemoteAppSession','MaintenanceSettings','Period','Deadline','Exclusive','Volatile','Actions','Exec','Command','Arguments','WorkingDirectory')
 $count=0
 while($stack.Count){
  $entry=$stack.Pop();$node=$entry.Node;$path=[string]$entry.Path;$count++;if($count -gt 2048){throw 'Desktop task structural diagnostics exceeds bounds'}
  $attributes=@($node.Attributes|ForEach-Object{if($_.Prefix -ne 'xmlns' -and $_.Name -ne 'xmlns'){$_.Name+'='+$_.Value}});$fields[$path+'/@attributes']=Get-RefreshTextHash ($attributes -join '|')
  $children=@($node.ChildNodes|Where-Object{$_ -is [Xml.XmlElement]})
  if(!$children.Count){$fields[$path]=Get-RefreshTextHash $node.InnerText}
  for($i=0;$i -lt $children.Count;$i++){$child=$children[$i];$name=if($child.LocalName -cin $allowed){$child.LocalName}else{'custom-node'};$stack.Push([pscustomobject]@{Node=$child;Path=($path+'/'+$name+'['+$i+']')})}
 }
 return $fields
}
function Get-RefreshRegisteredXml($Document,[string]$Sddl){
 $doc=Read-RefreshXml $Document.OuterXml;$ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('t',$doc.DocumentElement.NamespaceURI)
 $nodes=@($doc.SelectNodes('/t:Task/t:RegistrationInfo/t:SecurityDescriptor',$ns))
 if($nodes.Count -gt 1){throw 'Duplicate desktop registration security metadata'}
 if($nodes.Count -eq 1){
  $node=$nodes[0]
  if($node.Attributes.Count -or @($node.ChildNodes|Where-Object{$_ -isnot [Xml.XmlText]}).Count -or $node.InnerText -cne $Sddl){throw 'Desktop registration security metadata differs from pinned security descriptor'}
  [void]$node.ParentNode.RemoveChild($node)
 }
 return $doc.OuterXml
}
function Assert-RefreshSnapshot($Task,[string]$Xml,[string]$Sddl,[switch]$AllowRegisteredSecurityDescriptor){
 if(!$Task){throw 'Desktop task snapshot unavailable'}
 $actual=Read-RefreshXml $Task.Xml;$expected=Read-RefreshXml $Xml;$actualSd=[string]$Task.GetSecurityDescriptor(7)
 $xmlEqual=$actual.OuterXml -ceq $expected.OuterXml
 # Registration may materialize the exact supplied SDDL in XML. This is
 # accepted ONLY for our own post-write checks; pre-mutation snapshots stay exact.
 if(!$xmlEqual -and $AllowRegisteredSecurityDescriptor -and $actualSd -ceq $Sddl){
  $xmlEqual=(Get-RefreshRegisteredXml $actual $Sddl) -ceq (Get-RefreshRegisteredXml $expected $Sddl)
 }
 if(!$xmlEqual -or $actualSd -cne $Sddl){
  $left=Get-RefreshXmlFields $expected;$right=Get-RefreshXmlFields $actual
  $paths=@(@($left.Keys)+@($right.Keys)|Sort-Object -Unique|Where-Object{$left[$_] -cne $right[$_]}|Select-Object -First 16)
  $detail=@{xml_changed=($actual.OuterXml -cne $expected.OuterXml);sd_changed=($actualSd -cne $Sddl);expected_xml_sha256=(Get-RefreshTextHash $expected.OuterXml);actual_xml_sha256=(Get-RefreshTextHash $actual.OuterXml);expected_sd_sha256=(Get-RefreshTextHash $Sddl);actual_sd_sha256=(Get-RefreshTextHash $actualSd);field_paths=$paths}|ConvertTo-Json -Compress -Depth 3
  throw ('Desktop task definition or security descriptor changed; bounded structural diff '+$detail)
 }
}

function Connect-RefreshScheduler{
 $service=New-Object -ComObject 'Schedule.Service';$service.Connect();return [pscustomobject]@{Service=$service;Folder=$service.GetFolder('\')}
}
function Invoke-PortHubDesktopRefresh($Request){
 if(!$Request.executable -or !$Request.release_root -or @($Request.sids).Count -gt 8 -or @($Request.sids).Count -eq 0 -or !(Test-RefreshExecutable $Request.executable $Request.release_root)){throw 'Verified immutable desktop target and bounded grants required'}
 foreach($sid in $Request.sids){if(!(Test-RefreshSid $sid)){throw 'Invalid explicit desktop account grant'}}
 $scheduler=Connect-RefreshScheduler;$service=$scheduler.Service;$folder=$scheduler.Folder;$results=@()
 foreach($sid in $Request.sids){
  $name='PortHubKeyboard-'+$sid;$task=Get-RefreshTask $folder $name
  if(!(Test-RefreshTask $task $sid $Request.release_root)){$results+=@{sid=$sid;state='untouched'};continue}
  $oldXml=$task.Xml;$sddl=$task.GetSecurityDescriptor(7);$oldAction=$task.Definition.Actions.Item(1);$oldPath=[string]$oldAction.Path;$oldArgs=[string]$oldAction.Arguments
  $definitionCurrent=[string]::Equals($oldPath,$Request.executable,[StringComparison]::OrdinalIgnoreCase) -and $oldArgs -ceq 'keyboard startup'
  if($definitionCurrent -and $task.State -ne 4){$results+=@{sid=$sid;state='current'};continue}
  $doc=Read-RefreshXml $oldXml;$ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('t',$doc.DocumentElement.NamespaceURI)
  $commands=@($doc.SelectNodes('/t:Task/t:Actions/t:Exec/t:Command',$ns));$argumentNodes=@($doc.SelectNodes('/t:Task/t:Actions/t:Exec/t:Arguments',$ns))
  if($commands.Count -ne 1 -or $argumentNodes.Count -ne 1){throw 'Desktop action XML is customized'}
  $commands[0].InnerText=$Request.executable;$argumentNodes[0].InnerText='keyboard startup';$newXml=$doc.OuterXml
  $wasRunning=$task.State -eq 4;$native=$null;$stopped=$false;$updated=$false;$attemptedUpdate=$false;$writtenXml=$null
  try{
   # Snapshot checks precede every side effect, including a task stop.
   $fresh=Get-RefreshTask $folder $name;Assert-RefreshSnapshot $fresh $oldXml $sddl
   if(($fresh.State -eq 4) -ne $wasRunning){throw 'Desktop task state changed before refresh'}
   if($wasRunning){
    $native=Get-RefreshProcess $sid $oldArgs $Request.release_root
    if($definitionCurrent -and [string]::Equals($native.Path,$Request.executable,[StringComparison]::OrdinalIgnoreCase)){$results+=@{sid=$sid;state='current'};continue}
    $task.Stop(0);$stopped=$true
    $deadline=[DateTime]::UtcNow.AddSeconds(5)
    while((Get-RefreshTask $folder $name).State -eq 4 -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 50}
    if((Get-RefreshTask $folder $name).State -eq 4 -or !$native.WaitForExit(5000)){throw 'Previous desktop helper did not release its process and lease'}
   }
   Assert-RefreshSnapshot (Get-RefreshTask $folder $name) $oldXml $sddl
   if(!$definitionCurrent){
    $attemptedUpdate=$true
    $task=Set-RefreshDefinition $service $folder $name $newXml $sid $sddl
    Assert-RefreshSnapshot $task $newXml $sddl -AllowRegisteredSecurityDescriptor
    $writtenXml=[string]$task.Xml;$updated=$true
   }else{$task=Get-RefreshTask $folder $name;Assert-RefreshSnapshot $task $newXml $sddl}
   if(!(Test-RefreshTask $task $sid $Request.release_root)){throw 'Updated desktop task is not managed'}
   if($wasRunning){$null=$task.Run($null)}
   $results+=@{sid=$sid;state=$(if($wasRunning){'restarted'}else{'updated-inactive'})}
  }catch{
   $failure=$_
   $current=Get-RefreshTask $folder $name
   if($attemptedUpdate -and !$updated -and $current){
    try{
     Assert-RefreshSnapshot $current $newXml $sddl -AllowRegisteredSecurityDescriptor
     $writtenXml=[string]$current.Xml;$updated=$true
    }catch{# An unrecognized edit is never adopted or overwritten.
    }
   }
   if($updated){
    # After recognizing our serialization, all later checks pin its exact bytes.
    $current=Get-RefreshTask $folder $name;Assert-RefreshSnapshot $current $writtenXml $sddl
    $restored=Set-RefreshDefinition $service $folder $name $oldXml $sid $sddl;Assert-RefreshSnapshot $restored $oldXml $sddl -AllowRegisteredSecurityDescriptor
    if($wasRunning -and $stopped){$null=$restored.Run($null)}
   }elseif($wasRunning -and $stopped){
    $current=Get-RefreshTask $folder $name;Assert-RefreshSnapshot $current $oldXml $sddl
    if($current.State -ne 4 -and ($null -eq $native -or $native.HasExited)){$null=$current.Run($null)}
   }
   throw $failure
  }finally{if($null -ne $native){$native.Dispose()}}
 }
 return $results
}
if($MyInvocation.InvocationName -ne '.'){
 $text=[Console]::In.ReadToEnd();if($text.Length -gt 16384){throw 'Desktop refresh request exceeds bounds'}
 $request=$text|ConvertFrom-Json
 @(Invoke-PortHubDesktopRefresh $request)|ConvertTo-Json -Depth 4 -Compress
}
