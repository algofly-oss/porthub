$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
Import-Module -Name "$PSHOME\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1" -ErrorAction Stop
$stopPath=$env:PORTHUB_UPDATE_OBSERVER_STOP
if(-not $stopPath -or [IO.File]::Exists($stopPath)){throw 'Invalid observer marker'}
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable hosted runner required'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator required'}
Add-Type -ReferencedAssemblies System.Management -TypeDefinition @'
using System;
using System.Management;
using System.Threading;
public sealed class PortHubBirthWatch : IDisposable {
    private ManagementEventWatcher watcher;
    private int count;
    private bool watchStopped;
    public int Count {get{return Interlocked.CompareExchange(ref count,0,0);}}
    public PortHubBirthWatch() {
        watcher=new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='porthub.exe'"));
        watcher.EventArrived+=(sender,args)=>Interlocked.Increment(ref count);
        try{watcher.Start();}catch{watcher.Dispose();watcher=null;throw;}
    }
    public void StopWatch(){if(watcher!=null&&!watchStopped){watcher.Stop();watchStopped=true;}}
    public void Dispose(){if(watcher!=null){try{StopWatch();}finally{watcher.Dispose();watcher=null;}}}
}
'@
$watch=[PortHubBirthWatch]::new()
try {
    [Console]::WriteLine('{"ready":true}')
    $deadline=[DateTime]::UtcNow.AddSeconds(15)
    while(-not [IO.File]::Exists($stopPath) -and [DateTime]::UtcNow -lt $deadline){[Threading.Thread]::Sleep(20)}
    $expired=-not [IO.File]::Exists($stopPath)
    $watch.StopWatch()
    [Threading.Thread]::Sleep(100)
    @{count=$watch.Count;expired=$expired}|ConvertTo-Json -Compress
} finally {$watch.Dispose()}
