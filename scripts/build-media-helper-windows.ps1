# Native build-host only. Never installs services, opens media, or publishes assets.
param(
 [Parameter(Mandatory=$true)][string]$Release,
 [Parameter(Mandatory=$true)][string]$MinimumAgentVersion,
 [Parameter(Mandatory=$true)][string]$SourceRevision,
 [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess){throw 'A native 64-bit Windows build host is required'}
$mediaRoot=Split-Path -Parent $PSScriptRoot
$target='x86_64-pc-windows-msvc'
$hostLine=(& rustc -vV | Select-String '^host: ').Line
if($LASTEXITCODE -ne 0 -or $hostLine -ne "host: $target"){throw 'Use the native Windows AMD64 MSVC toolchain'}
$oldFlags=$env:CARGO_ENCODED_RUSTFLAGS
$oldRustFlags=$env:RUSTFLAGS
Push-Location $mediaRoot
try{
 & python -c 'import importlib.util,sys;from pathlib import Path;p=Path("scripts/package-media-helper.py");s=importlib.util.spec_from_file_location("media_package",p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.frozen_inputs(sys.argv[1])' $SourceRevision
 if($LASTEXITCODE -ne 0){throw 'Media source inputs are not frozen'}
 # Encoded arguments preserve checkout paths containing spaces. CRT is bundled;
 # PDB names/source remapping must never retain a developer's private directory.
 $env:CARGO_ENCODED_RUSTFLAGS=@('-C','target-feature=+crt-static',"--remap-path-prefix=$mediaRoot=/porthub-source",'-C','link-arg=/PDBALTPATH:%_PDB%','-C','link-arg=/Brepro') -join [char]31
 Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
 & cargo test --locked -p porthub-media-helper --target $target
 if($LASTEXITCODE -ne 0){throw 'Native helper unit tests failed'}
 & cargo build --locked --release -p porthub-media-helper --target $target
 if($LASTEXITCODE -ne 0){throw 'Native helper build failed'}
 $targetDirectory=if($env:CARGO_TARGET_DIR){$env:CARGO_TARGET_DIR}else{Join-Path $mediaRoot 'target'}
 $binary=Join-Path $targetDirectory "$target/release/porthub-media-helper.exe"
 & python scripts/package-media-helper.py --binary $binary --target $target --source-revision $SourceRevision --release $Release --core ">=$MinimumAgentVersion" --output $OutputDirectory
 if($LASTEXITCODE -ne 0){throw 'Native helper verification/packaging failed'}
}finally{
 if($null -eq $oldFlags){Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue}else{$env:CARGO_ENCODED_RUSTFLAGS=$oldFlags}
 if($null -eq $oldRustFlags){Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue}else{$env:RUSTFLAGS=$oldRustFlags}
 Pop-Location
}
