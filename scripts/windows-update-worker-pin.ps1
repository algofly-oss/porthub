param(
    [Parameter(Mandatory=$true)][ValidateSet('Inspect','Terminate')][string]$Action,
    [Parameter(Mandatory=$true)][uint32]$ProcessId,
    [Parameter(Mandatory=$true)][string]$Image,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$Sha256,
    [Parameter(Mandatory=$true)][string]$Record,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce,
    [string]$ExpectedCreation=''
)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable hosted runner required'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator required'}
$root=[IO.Path]::GetFullPath((Join-Path $env:ProgramData 'PortHub'))
$Image=[IO.Path]::GetFullPath($Image);$Record=[IO.Path]::GetFullPath($Record)
if($Image -ne (Join-Path $root ('releases\'+$Sha256+'\porthub.exe')) -or [IO.Path]::GetDirectoryName($Record) -ne (Join-Path $root 'native') -or [IO.Path]::GetFileName($Record) -notmatch '^[a-f0-9]{64}\.json\.windows-update\.json$'){throw 'Not an exact managed updater endpoint'}
foreach($file in @($Image,$Record)){$item=Get-Item -LiteralPath $file;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse/non-file endpoint refused'}}
$j=Get-Content -Raw -LiteralPath $Record|ConvertFrom-Json
if($j.nonce -ne $Nonce -or $j.candidate -ne $Image -or $j.release.sha256 -ne $Sha256 -or $j.phase -notin @('applying','verifying')){throw 'Journal no longer matches the intervention'}
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
public sealed class PortHubPinnedUpdate : IDisposable {
  private IntPtr process;
  public string Image { get; private set; }
  public string Creation { get; private set; }
  [StructLayout(LayoutKind.Sequential)] struct FT { public uint low, high; public ulong Value {get{return ((ulong)high<<32)|low;}} }
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr p,out FT c,out FT e,out FT k,out FT u);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr p,uint flags,StringBuilder path,ref uint size);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr token);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr p,uint code);
  [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr p,uint ms);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  public PortHubPinnedUpdate(uint pid,string image) {
    process=OpenProcess(0x101001,false,pid);
    if(process==IntPtr.Zero)throw new Win32Exception();
    try {
      if(WaitForSingleObject(process,0)!=258)throw new Exception("Worker already exited");
      uint size=32768;var text=new StringBuilder((int)size);
      if(!QueryFullProcessImageName(process,0,text,ref size))throw new Win32Exception();
      Image=text.ToString();if(!String.Equals(Image,image,StringComparison.OrdinalIgnoreCase))throw new Exception("Held image mismatch");
      FT c,e,k,u;if(!GetProcessTimes(process,out c,out e,out k,out u))throw new Win32Exception();Creation=c.Value.ToString();
      IntPtr token;if(!OpenProcessToken(process,8,out token))throw new Win32Exception();
      try{using(var owner=new WindowsIdentity(token)){if(owner.User.Value!="S-1-5-18")throw new Exception("Held process is not SYSTEM");}}finally{CloseHandle(token);}
    } catch {Dispose();throw;}
  }
  public void Stop(string creation){
    if(Creation!=creation)throw new Exception("Worker creation identity changed");
    if(!TerminateProcess(process,73))throw new Win32Exception();
    if(WaitForSingleObject(process,5000)!=0)throw new Exception("Owned worker did not exit");
  }
  public void Dispose(){if(process!=IntPtr.Zero){CloseHandle(process);process=IntPtr.Zero;}}
}
'@
$held=[PortHubPinnedUpdate]::new($ProcessId,$Image)
try {
    $p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$ProcessId)
    $pattern='^"?'+[regex]::Escape($Image)+'"?\s+__windows-update\s+--record\s+"?'+[regex]::Escape($Record)+'"?\s*$'
    if(-not $p -or $p.CommandLine -notmatch $pattern){throw 'Pinned worker arguments do not name exact private record'}
    $stream=[IO.File]::OpenRead($Image)
    try{$hash=[Security.Cryptography.SHA256]::Create();try{$digest=[BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}}finally{$stream.Dispose()}
    if($digest -ne $Sha256){throw 'Pinned worker image digest changed'}
    if($ExpectedCreation -and $held.Creation -ne $ExpectedCreation){throw 'Worker instance changed since inspection'}
    if($Action -eq 'Terminate'){
        if(-not $ExpectedCreation){throw 'Termination requires a previously inspected creation identity'}
        $held.Stop($ExpectedCreation)
    }
    @{pid=$ProcessId;creation=$held.Creation;sha256=$Sha256;terminated=($Action -eq 'Terminate')}|ConvertTo-Json -Compress
} finally {$held.Dispose()}
