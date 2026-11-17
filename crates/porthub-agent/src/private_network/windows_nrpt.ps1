# Exact owned local NRPT only. No GPO writes, global DNS changes, policy bypass,
# registry changes, persistent PowerShell host, or arbitrary name-prefix adoption.
# https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientnrptrule
# https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientnrptpolicy
function Invoke-PortHubNrpt {
    param([Parameter(Mandatory=$true)]$Config)
    $ErrorActionPreference='Stop'
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $script:journalHash=$null
    function Bound { if($clock.Elapsed.TotalSeconds -gt 25){throw 'NRPT transaction deadline exceeded'};if($script:journalHash){AssertStateFile;if((Hash (ReadJournal)) -cne $script:journalHash){throw 'NRPT journal changed concurrently'}} }
    function Hex($v,$n){return ($v -is [string] -and $v.Length -eq $n -and $v -cmatch '^[0-9a-f]+$')}
    function Namespace($v){
        if($v -eq '.'){return '.'}
        if($v -isnot [string]){throw 'Unknown NRPT namespace shape'}
        $v=$v.TrimStart('.').ToLowerInvariant()
        if($v.Length -gt 253 -or $v -notmatch '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$'){throw 'Unknown NRPT namespace shape'}
        foreach($label in $v.Split('.')){if($label.Length -lt 1 -or $label.Length -gt 63 -or $label.StartsWith('-') -or $label.EndsWith('-')){throw 'Invalid NRPT namespace'}}
        return $v
    }
    function Overlap($a,$b){$a=Namespace $a;$b=Namespace $b;return($a -eq '.' -or $b -eq '.' -or $a -eq $b -or $a.EndsWith('.'+$b) -or $b.EndsWith('.'+$a))}
    function Names($suffix){if($suffix -eq '.'){return @('.')};return @($suffix,('.'+$suffix))}
    function SameList($a,$b){return ((@($a|ForEach-Object{[string]$_}|Sort-Object)-join "`n") -ceq (@($b|ForEach-Object{[string]$_}|Sort-Object)-join "`n"))}
    function Rules {Bound;$all=@(Get-DnsClientNrptRule -ErrorAction Stop);if($all.Count -gt 4096){throw 'Local NRPT inventory exceeds bound'};return $all}
    function Policy {Bound;$all=@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop);if($all.Count -gt 8192){throw 'Effective NRPT inventory exceeds bound'};return $all}
    function Marker($suffix){return ('PortHub-native-dns-v1:'+ $state.binding+':'+$state.nonce+':'+$suffix)}
    function Id($v){$parsed=[Guid]::Empty;if(-not [Guid]::TryParse([string]$v,[ref]$parsed) -or $parsed -eq [Guid]::Empty){throw 'Invalid NRPT rule identity'};return $parsed.ToString('D')}
    function AssertRule($actual,$expected){
        if(-not (SameList $actual.Namespace (Names $expected.suffix)) -or -not(SameList $actual.NameServers @($state.server)) -or [string]$actual.Comment -cne (Marker $expected.suffix) -or [string]$actual.DisplayName -cne 'PortHub private namespace' -or [string]$actual.NameEncoding -ne 'Utf8WithoutMapping'){throw 'Recorded NRPT rule changed externally; preserved'}
        foreach($name in @('DAEnable','DAIPsecRequired','DnsSecEnable','DnsSecIPsecRequired','DnsSecValidationRequired')){if($actual.PSObject.Properties[$name] -and [bool]$actual.$name){throw 'Recorded NRPT security policy changed externally; preserved'}}
        if($expected.id -and (Id $actual.Name) -cne $expected.id){throw 'Recorded NRPT GUID changed externally; preserved'}
    }
    function ResolveOwned($all){
        $owned=@{}
        foreach($r in @($state.rules)){
            if($r.id){$matches=@($all|Where-Object{(Id $_.Name) -ceq $r.id})}
            else{$matches=@($all|Where-Object{[string]$_.Comment -ceq (Marker $r.suffix)})}
            if($matches.Count -gt 1){throw 'Ambiguous recorded NRPT rule'}
            if($matches.Count -eq 1){AssertRule $matches[0] $r;$r.id=Id $matches[0].Name;$owned[$r.id]=$r}
        }
        return $owned
    }
    function Conflict($target){
        $all=@(Rules);$owned=ResolveOwned $all
        foreach($rule in $all){if($owned.ContainsKey((Id $rule.Name))){continue};foreach($ns in @($rule.Namespace)){foreach($suffix in $target){if(Overlap $ns $suffix){throw 'Private namespace conflicts with a foreign local NRPT rule'}}}}
        foreach($policy in @(Policy)){
            foreach($ns in @($policy.Namespace)){
                foreach($suffix in $target){
                    if(-not(Overlap $ns $suffix)){continue}
                    $matched=$false
                    foreach($r in $owned.Values){if(@(Names $r.suffix) -ccontains [string]$ns -and (SameList $policy.NameServers @($state.server))){$matched=$true;break}}
                    if(-not $matched){throw 'Private namespace conflicts with foreign effective NRPT policy'}
                    foreach($name in @('DirectAccessEnabled','DirectAccessQueryIPsecRequired','DnsSecQueryIPsecRequired','DnsSecValidationRequired')){if($policy.PSObject.Properties[$name] -and [bool]$policy.$name){throw 'Effective NRPT policy has incompatible security settings'}}
                }
            }
        }
        return $owned
    }
    function AssertStateFile {
        $item=Get-Item -LiteralPath $Config.path -Force
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'NRPT ownership journal is a reparse point'}
        $acl=Get-Acl -LiteralPath $Config.path
        if(-not $acl.AreAccessRulesProtected){throw 'NRPT ownership DACL is not protected'}
        $sid=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if($sid -notin @('S-1-5-18','S-1-5-32-544')){throw 'NRPT ownership owner is not privileged'}
        $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        if($rules.Count -lt 1 -or $rules.Count -gt 128){throw 'Invalid NRPT ownership ACL'}
        foreach($r in $rules){if($r.IsInherited -or $r.AccessControlType -ne 'Allow' -or $r.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'NRPT ownership ACL admits another principal'}}
    }
    function ReadJournal {
        $file=[IO.FileStream]::new($Config.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $memory=[IO.MemoryStream]::new();$buffer=[byte[]]::new(4096)
        try{if($file.Length -gt 262144){throw 'NRPT journal exceeds bound'};while(($n=$file.Read($buffer,0,[Math]::Min(4096,262145-$memory.Length))) -gt 0){$memory.Write($buffer,0,$n);if($memory.Length -gt 262144){throw 'NRPT journal grew beyond bound'}};return ,$memory.ToArray()}finally{$file.Dispose();$memory.Dispose()}
    }
    function Hash($bytes){$sha=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($sha.ComputeHash($bytes))}finally{$sha.Dispose()}}
    function Save {
        Bound;AssertStateFile
        if((Hash (ReadJournal)) -cne $script:journalHash){throw 'NRPT journal changed concurrently'}
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($state|ConvertTo-Json -Depth 12 -Compress))
        if($bytes.Length -gt 262144){throw 'NRPT journal exceeds bound'}
        $temp=$Config.path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
        try{$file=[IO.FileStream]::new($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()};Set-Acl -LiteralPath $temp -AclObject (Get-Acl -LiteralPath $Config.path) -ErrorAction Stop;[IO.File]::Replace($temp,$Config.path,[System.Management.Automation.Language.NullString]::Value);$script:journalHash=Hash $bytes;AssertStateFile}finally{if([IO.File]::Exists($temp)){[IO.File]::Delete($temp)}}
    }
    function Converge($target){
        $target=@($target|Sort-Object -Unique)
        [void](Conflict $target)
        foreach($suffix in $target){
            $entry=@($state.rules|Where-Object{$_.suffix -ceq $suffix})
            if($entry.Count -eq 0){$state.rules=@($state.rules)+@([pscustomobject]@{suffix=$suffix;id=$null});Save}
        }
        # Every add has a durable exact marker before the cmdlet can mutate OS state.
        foreach($suffix in $target){
            Bound;$all=@(Rules);$owned=ResolveOwned $all;$entry=@($state.rules|Where-Object{$_.suffix -ceq $suffix})[0]
            if($entry.id -and $owned.ContainsKey($entry.id)){continue}
            if($entry.id){$entry.id=$null;Save}
            [void](Conflict $target)
            Bound
            $added=Add-DnsClientNrptRule -Namespace (Names $suffix) -NameServers @($state.server) -NameEncoding Utf8WithoutMapping -DisplayName 'PortHub private namespace' -Comment (Marker $suffix) -PassThru -ErrorAction Stop
            AssertRule $added $entry;$entry.id=Id $added.Name;Save
        }
        # Verify effective routing before retiring obsolete suffixes.
        [void](Conflict $target)
        foreach($suffix in $target){foreach($ns in @(Names $suffix)){$matching=@(Policy|Where-Object{@($_.Namespace) -ccontains $ns -and (SameList $_.NameServers @($state.server))});if($matching.Count -lt 1){throw 'Owned NRPT rule is not effective; policy preserved'}}}
        foreach($entry in @($state.rules)){
            if($target -ccontains $entry.suffix){continue}
            Bound;$all=@(Rules);$owned=ResolveOwned $all
            if($entry.id -and $owned.ContainsKey($entry.id)){
                Bound;Remove-DnsClientNrptRule -Name $entry.id -Force -ErrorAction Stop
                $left=@(Rules|Where-Object{(Id $_.Name) -ceq $entry.id -or [string]$_.Comment -ceq (Marker $entry.suffix)})
                if($left.Count -gt 0){throw 'Owned NRPT removal was not acknowledged by native readback'}
            }
            $state.rules=@($state.rules|Where-Object{$_.suffix -cne $entry.suffix});Save
        }
    }
    if(-not(Hex $Config.binding 64) -or -not(Hex $Config.guid 32) -or $Config.mode -notin @('reconcile','clear')){throw 'Invalid NRPT transaction identity'}
    AssertStateFile;$raw=ReadJournal;if($raw.Length -gt 262144){throw 'NRPT journal exceeds bound'}
    $script:journalHash=Hash $raw;$state=[Text.Encoding]::UTF8.GetString($raw)|ConvertFrom-Json
    if($state.version -ne 1 -or $state.binding -cne $Config.binding -or $state.guid -cne $Config.guid -or $state.server -cne $Config.server -or -not(Hex $state.nonce 32) -or @($state.rules).Count -gt 512 -or @($state.committed).Count -gt 256){throw 'NRPT ownership identity mismatch'}
    $seen=@{};foreach($entry in @($state.rules)){if((Namespace $entry.suffix) -cne $entry.suffix -or $seen.ContainsKey($entry.suffix)){throw 'Invalid recorded NRPT namespace'};$seen[$entry.suffix]=$true;if($entry.id){$entry.id=Id $entry.id}}
    foreach($suffix in @($state.committed)){if((Namespace $suffix) -cne $suffix){throw 'Invalid committed NRPT namespace'}}
    $desired=@($Config.desired|Sort-Object -Unique);if($desired.Count -gt 256){throw 'Private NRPT namespace bound exceeded'};foreach($suffix in $desired){if((Namespace $suffix) -cne $suffix){throw 'Invalid requested NRPT namespace'}}
    # Recovery first restores the last committed set. A killed/failed child can
    # never convert an uncommitted addition into ownership of an arbitrary rule.
    if($Config.mode -eq 'clear'){Converge @();$state.committed=@();Save;return [pscustomobject]@{ok=$true;rules=0}}
    Converge @($state.committed)
    $old=@($state.committed)
    try{Converge $desired;$state.committed=@($desired);Save}
    catch{$original=$_.Exception.Message;try{Converge $old}catch{throw ('NRPT transaction failed; owned recovery pending: '+$original)};throw ('NRPT transaction rolled back: '+$original)}
    return [pscustomobject]@{ok=$true;rules=@($state.rules).Count}
}
