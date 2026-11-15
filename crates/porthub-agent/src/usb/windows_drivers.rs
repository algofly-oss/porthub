//! Installer-managed signed Windows USB prerequisites. No additional container,
//! test signing mode or certificate-store edits are used.
use anyhow::{ensure,Context,Result};
use sha2::{Digest,Sha256};
use std::{path::{Path,PathBuf},sync::Arc,time::Duration};
use crate::{control::Control,features::{self,Feature}};
struct Package{file:&'static str,url:&'static str,hash:&'static str,msi:bool}
fn packages()->[Package;2]{
    #[cfg(target_arch="aarch64")]
    return [Package{file:"usbipd-win_5.3.0_arm64.msi",url:"https://github.com/dorssel/usbipd-win/releases/download/v5.3.0/usbipd-win_5.3.0_arm64.msi",hash:"efd7c4eb99b144c1623e616064a7b262f83d0994b0d7fde16c95d4b07528b24d",msi:true},Package{file:"USBip-0.9.8.1-arm64.exe",url:"https://github.com/vadimgrn/usbip-win2/releases/download/v.0.9.8.1/USBip-0.9.8.1-arm64.exe",hash:"cab7ff97f79275eeb5c5b8bb2eb3111ff6b6c4eead07d9bec9be5bd1e3a35800",msi:false}];
    #[cfg(not(target_arch="aarch64"))]
    return [Package{file:"usbipd-win_5.3.0_x64.msi",url:"https://github.com/dorssel/usbipd-win/releases/download/v5.3.0/usbipd-win_5.3.0_x64.msi",hash:"1c984914aec944de19b64eff232421439629699f8138e3ddc29301175bc6d938",msi:true},Package{file:"USBip-0.9.8.1-x64.exe",url:"https://github.com/vadimgrn/usbip-win2/releases/download/v.0.9.8.1/USBip-0.9.8.1-x64.exe",hash:"38cad6d4432b52d5bb9409d9ad03b72fdffc4ada4cd3a48fbeca1a2752a8518a",msi:false}];
}
fn system(file:&str)->Result<PathBuf>{Ok(PathBuf::from(std::env::var_os("SystemRoot").context("Windows system directory unavailable")?).join("System32").join(file))}
async fn download(control:&Control,package:&Package,path:&Path)->Result<()> {
    if path.try_exists()? {
        use std::io::Read;
        let metadata=std::fs::symlink_metadata(path)?;ensure!(metadata.is_file()&&!metadata.file_type().is_symlink()&&metadata.len()<=64*1024*1024,"Invalid cached USB installer");
        let mut file=std::fs::File::open(path)?;let mut hash=Sha256::new();let mut buffer=[0u8;65536];loop{let n=file.read(&mut buffer)?;if n==0{break;}hash.update(&buffer[..n]);}
        ensure!(format!("{:x}",hash.finalize())==package.hash,"Cached Windows USB installer checksum mismatch");return Ok(());
    }
    let mut response=control.prerequisite_download(package.url).await.map_err(|_|anyhow::anyhow!("Windows USB prerequisite download unavailable"))?;
    ensure!(response.content_length().is_none_or(|n|n<=64*1024*1024),"Windows USB installer exceeds its size limit");let mut bytes=Vec::new();
    while let Some(chunk)=response.chunk().await.map_err(|_|anyhow::anyhow!("Windows USB installer download interrupted"))?{ensure!(bytes.len()+chunk.len()<=64*1024*1024,"Windows USB installer exceeds its size limit");bytes.extend_from_slice(&chunk);}
    ensure!(format!("{:x}",Sha256::digest(&bytes))==package.hash,"Windows USB installer checksum mismatch");crate::profile::write_private(path,&bytes,false)?;Ok(())
}
async fn signed(path:&Path)->Result<()> {
    let script="$ErrorActionPreference='Stop';if((Get-AuthenticodeSignature -LiteralPath $env:PORTHUB_USB_INSTALLER).Status -ne 'Valid'){throw 'Windows USB package signature rejected'}";
    let result=tokio::time::timeout(Duration::from_secs(40),tokio::process::Command::new(system("WindowsPowerShell/v1.0/powershell.exe")?).args(["-NoLogo","-NoProfile","-NonInteractive","-Command",script]).env("PORTHUB_USB_INSTALLER",path).kill_on_drop(true).output()).await??;
    ensure!(result.status.success(),"Windows did not validate the USB installer signature");Ok(())
}
async fn install(package:&Package,path:&Path)->Result<()> {
    signed(path).await?;
    let mut command=if package.msi{let mut c=tokio::process::Command::new(system("msiexec.exe")?);c.arg("/i").arg(path).args(["/qn","/norestart"]);c}else{let mut c=tokio::process::Command::new(path);c.args(["/VERYSILENT","/SUPPRESSMSGBOXES","/NORESTART","/COMPONENTS=main,client","/TASKS=vcredist"]);c};
    let result=tokio::time::timeout(Duration::from_secs(240),command.kill_on_drop(true).output()).await??;
    ensure!(matches!(result.status.code(),Some(0|3010)),"Windows USB driver installation failed");
    if result.status.code()==Some(3010){tracing::warn!("Windows USB prerequisite installed; Windows requested a restart. PortHub will not restart the machine.");}
    Ok(())
}
async fn direct_rule(path:&Path,control:&Control)->Result<()> {
    if !features::enabled(path,Feature::DirectConnections){return Ok(());}
    let name=format!("PortHub-USB-{}",control.profile().machine_id);let executable=std::env::current_exe()?;
    // Only the authenticated PortHub process is exposed to its local subnet.
    // Raw usbipd TCP3240 is deliberately not opened to the network.
    let script="$ErrorActionPreference='Stop';$name=$env:PORTHUB_USB_RULE;$group='PortHub managed USB bulk';$old=Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue;if($old){if($old.Group -ne $group){throw 'USB firewall rule belongs to another owner'};Set-NetFirewallRule -Name $name -Enabled True -Action Allow -Direction Inbound -Profile Any -RemoteAddress LocalSubnet;Set-NetFirewallApplicationFilter -AssociatedNetFirewallRule $old -Program $env:PORTHUB_USB_EXE | Out-Null}else{New-NetFirewallRule -Name $name -DisplayName $name -Group $group -Direction Inbound -Action Allow -Profile Any -Program $env:PORTHUB_USB_EXE -Protocol TCP -RemoteAddress LocalSubnet | Out-Null}";
    let output=tokio::time::timeout(Duration::from_secs(30),tokio::process::Command::new(system("WindowsPowerShell/v1.0/powershell.exe")?).args(["-NoLogo","-NoProfile","-NonInteractive","-Command",script]).env("PORTHUB_USB_RULE",name).env("PORTHUB_USB_EXE",executable).kill_on_drop(true).output()).await??;ensure!(output.status.success(),"Cannot configure the owned PortHub USB direct-path firewall rule");Ok(())
}
pub(super) async fn prepare(path:&Path,control:Arc<Control>)->Result<()> {
    if !features::enabled(path,Feature::Usb){return Ok(());}
    // Disposable native service fixtures deliberately use a loopback-only
    // plaintext gateway and must not install unrelated OS drivers.
    if control.profile().allow_insecure_http_for_tests && url::Url::parse(&control.profile().server).ok().and_then(|u|u.host_str().map(str::to_owned)).is_some_and(|h|h=="127.0.0.1"||h=="localhost"||h=="::1") {return Ok(());}
    let Some(layout)=crate::private_profile::windows_service_layout(path,control.profile())? else {return Ok(());};
    let folder=layout.state.parent().context("Managed Windows state directory missing")?.join("drivers/usb-installers");crate::service::directory(&folder,true)?;
    let required=[!super::windows::host_installed(),!super::windows::receive_installed()];
    for (package,needed) in packages().into_iter().zip(required){if !needed{continue;}if !features::enabled(path,Feature::Usb){return Ok(());}let file=folder.join(package.file);download(&control,&package,&file).await?;install(&package,&file).await?;if package.msi{let output=tokio::time::timeout(Duration::from_secs(30),tokio::process::Command::new(system("netsh.exe")?).args(["advfirewall","firewall","set","rule","name=usbipd","new","enable=no"]).kill_on_drop(true).output()).await??;ensure!(output.status.success(),"Cannot restrict the installed raw USB driver firewall exception");}}
    direct_rule(path,&control).await?;ensure!(super::windows::supported(),"Windows USB drivers are installed but not ready; Windows may require a restart");Ok(())
}
