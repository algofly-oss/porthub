# Portable actual-script tests: only the OS cmdlets/ACL projection are replaced.
param([Parameter(Mandatory=$true)][string]$Source)
$ErrorActionPreference='Stop'
. ([ScriptBlock]::Create([IO.File]::ReadAllText($Source)))
$script:all=@();$script:extra=@();$script:adds=0;$script:removes=0;$script:failBefore=$false;$script:failAfter=$false;$script:failRemoveAfter=$false
function Get-Acl {
 $acl=[pscustomobject]@{AreAccessRulesProtected=$true}
 $acl|Add-Member ScriptMethod GetOwner {param($type) return [pscustomobject]@{Value='S-1-5-18'}}
 $acl|Add-Member ScriptMethod GetAccessRules {param($a,$b,$type) return @([pscustomobject]@{IsInherited=$false;AccessControlType='Allow';IdentityReference=[pscustomobject]@{Value='S-1-5-18'}})}
 return $acl
}
function Set-Acl {param($LiteralPath,$AclObject,$ErrorAction)}
function Get-DnsClientNrptRule {return @($script:all)}
function Get-DnsClientNrptPolicy {
 $script:policyCalls++;if($script:tamperAt -gt 0 -and $script:policyCalls -eq $script:tamperAt){[IO.File]::AppendAllText($script:path,"`n")}
 foreach($rule in $script:all){foreach($ns in $rule.Namespace){[pscustomobject]@{Namespace=$ns;NameServers=$rule.NameServers;DirectAccessEnabled=$false;DnsSecValidationRequired=$false}}}
 foreach($rule in $script:extra){$rule}
}
function Add-DnsClientNrptRule {
 param($Namespace,$NameServers,$NameEncoding,$DisplayName,$Comment,[switch]$PassThru,$ErrorAction)
 if($script:failBefore){$script:failBefore=$false;throw 'injected failure before native add'}
 $script:adds++
 $rule=[pscustomobject]@{Name=[Guid]::NewGuid().ToString('B').ToUpperInvariant();Namespace=@($Namespace);NameServers=@($NameServers);NameEncoding=$NameEncoding;DisplayName=$DisplayName;Comment=$Comment;DAEnable=$false;DAIPsecRequired=$false;DnsSecEnable=$false;DnsSecIPsecRequired=$false;DnsSecValidationRequired=$false}
 if($script:addNoOp){$script:addNoOp=$false;return $rule}
 $script:all=@($script:all)+@($rule)
 if($script:failAfter){$script:failAfter=$false;throw 'injected termination after native add before GUID checkpoint'}
 return $rule
}
function Remove-DnsClientNrptRule {param($Name,[switch]$Force,$ErrorAction);if(@($script:all|Where-Object{$_.Name -ceq $Name}).Count -ne 1){throw 'Native provider exact rule Name was not found'};$script:removes++;if($script:removeNoOp){$script:removeNoOp=$false;return};$script:all=@($script:all|Where-Object{$_.Name -ne $Name});if($script:failRemoveAfter){$script:failRemoveAfter=$false;throw 'injected failure after native removal before journal checkpoint'}}
function Assert($value,$message){if(-not $value){throw ('ASSERT: '+$message)}}
function Reset {
 $script:all=@();$script:extra=@();$script:adds=0;$script:removes=0;$script:failBefore=$false;$script:failAfter=$false;$script:failRemoveAfter=$false;$script:policyCalls=0;$script:tamperAt=0;$script:removeNoOp=$false;$script:addNoOp=$false
 $script:path=Join-Path ([IO.Path]::GetTempPath()) ('porthub-private-nrpt-'+[Guid]::NewGuid().ToString('N')+'.json')
 $seed=[ordered]@{version=1;binding=('a'*64);guid=('b'*32);server='127.203.0.2';nonce=('c'*32);committed=@();rules=@()}
 [IO.File]::WriteAllText($script:path,($seed|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
 $script:config=[pscustomobject]@{path=$script:path;binding=('a'*64);guid=('b'*32);server='127.203.0.2';desired=@('phub');mode='reconcile'}
}
function Apply {Invoke-PortHubNrpt $script:config|Out-Null}
function Fails {param([ScriptBlock]$Action);$failed=$false;try{&$Action}catch{$failed=$true};Assert $failed 'operation should fail'}
$passed=0
try {
 Reset;Apply;$nativeName=$script:all[0].Name;$normalized=([Guid]$nativeName).ToString('D');Fails {Remove-DnsClientNrptRule -Name $normalized -Force};Assert (@($script:all).Count -eq 1 -and $script:removes -eq 0) 'provider rejects normalized GUID without mutating exact native rule';$passed++;[IO.File]::Delete($path)
 Reset;Apply;$script:all[0].Name=([Guid]$script:all[0].Name).ToString('D');$config.mode='clear';Apply;Assert (@($script:all).Count -eq 0) 'removal uses observed native name without inventing brace formatting';$passed++;[IO.File]::Delete($path)
 Reset;Apply;$duplicate=$script:all[0].PSObject.Copy();$duplicate.Name=([Guid]$duplicate.Name).ToString('D');$script:all+=@($duplicate);$config.mode='clear';Fails {Apply};Assert ($script:removes -eq 0 -and @($script:all).Count -eq 2) 'ambiguous equivalent GUID native names cannot authorize deletion';$passed++;[IO.File]::Delete($path)
 Reset;Apply;$id=$script:all[0].Name;Apply;Assert ($script:adds -eq 1 -and $script:all[0].Name -eq $id) 'idempotence preserves exact GUID';$config.desired=@('phub','private.test');Apply;Assert ($script:adds -eq 2 -and @($script:all).Count -eq 2) 'expansion';$config.desired=@('private.test');Apply;Assert (@($script:all).Count -eq 1 -and $script:removes -eq 1) 'retire obsolete only';$passed++;[IO.File]::Delete($path)
 foreach($phase in @('before','after')){
  Reset;Apply;$id=$script:all[0].Name;$config.desired=@('phub','private.test');if($phase -eq 'before'){$script:failBefore=$true}else{$script:failAfter=$true};Fails {Apply};$state=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json;Assert (@($script:all).Count -eq 1 -and $script:all[0].Name -eq $id -and @($state.rules).Count -eq 1 -and @($state.committed).Count -eq 1) ('rollback '+$phase);$passed++;[IO.File]::Delete($path)
 }
 Reset;Apply;$config.desired=@('private.test');$script:failRemoveAfter=$true;Fails {Apply};$state=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json;Assert (@($script:all).Count -eq 1 -and $script:all[0].Namespace[0] -eq 'phub' -and $state.committed[0] -eq 'phub' -and $state.rules[0].id -ceq ([Guid]$script:all[0].Name).ToString('D')) 'rollback recreates exact committed policy after partial removal and repins new GUID';$passed++;[IO.File]::Delete($path)
 Reset;Apply;$id=$script:all[0].Name;$config.desired=@('private.test');$script:removeNoOp=$true;Fails {Apply};Assert (@($script:all).Count -eq 1 -and $script:all[0].Name -eq $id) 'native removal success without actual removal cannot acknowledge';$passed++;[IO.File]::Delete($path)
 Reset;$script:addNoOp=$true;Fails {Apply};Assert (@($script:all).Count -eq 0) 'native add PassThru without effective installed policy cannot acknowledge';$passed++;[IO.File]::Delete($path)
 Reset;Apply;$owned=$script:all[0];$foreign=[pscustomobject]@{Name=[Guid]::NewGuid().ToString('D');Namespace=@('.foreign.phub');NameServers=@('192.168.1.1');Comment='foreign';DisplayName='foreign';NameEncoding='Utf8WithoutMapping'};$script:all+=@($foreign);$adds=$script:adds;Fails {Apply};Assert ($script:adds -eq $adds -and @($script:all).Count -eq 2 -and $script:all[1].Name -eq $foreign.Name) 'foreign local overlap preserved';$passed++;[IO.File]::Delete($path)
 Reset;$script:extra=@([pscustomobject]@{Namespace='.phub';NameServers=@('192.168.1.1')});Fails {Apply};Assert ($script:adds -eq 0 -and $script:removes -eq 0) 'effective GPO overlap blocks before add';$passed++;[IO.File]::Delete($path)
 Reset;Apply;$script:all[0].NameServers=@('192.168.1.1');$adds=$script:adds;Fails {Apply};Assert ($script:adds -eq $adds -and $script:removes -eq 0 -and $script:all[0].NameServers[0] -eq '192.168.1.1') 'externally edited rule preserved';$passed++;[IO.File]::Delete($path)
 Reset;Apply;$state=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json;$pending=[pscustomobject]@{suffix='private.test';id=$null};$state.rules=@($state.rules)+@($pending);[IO.File]::WriteAllText($path,($state|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false));Add-DnsClientNrptRule -Namespace @('private.test','.private.test') -NameServers @('127.203.0.2') -NameEncoding Utf8WithoutMapping -DisplayName 'PortHub private namespace' -Comment ('PortHub-native-dns-v1:'+('a'*64)+':'+('c'*32)+':private.test') -PassThru|Out-Null;Apply;Assert (@($script:all).Count -eq 1 -and $script:all[0].Namespace[0] -eq 'phub') 'cold recovery removes exact uncommitted addition';$passed++;[IO.File]::Delete($path)
 Reset;$script:tamperAt=3;Fails {Apply};Assert ($script:adds -eq 0 -and $script:removes -eq 0) 'concurrent journal change fences native mutation';$passed++;[IO.File]::Delete($path)
 Reset;Apply;$config.mode='clear';Apply;Assert (@($script:all).Count -eq 0) 'clear';Apply;Assert (@($script:all).Count -eq 0) 'idempotent clear';$passed++;[IO.File]::Delete($path)
 Write-Output ('PASS actual NRPT transaction groups: '+$passed)
}finally{if($script:path -and [IO.File]::Exists($script:path)){[IO.File]::Delete($script:path)}}
