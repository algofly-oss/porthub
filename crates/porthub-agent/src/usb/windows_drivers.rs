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
const SIGNATURE_SCRIPT:&str=r#"$ErrorActionPreference='Stop';Import-Module -Name "$PSHOME\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1" -ErrorAction Stop;if((Get-AuthenticodeSignature -LiteralPath $env:PORTHUB_USB_INSTALLER).Status -ne 'Valid'){throw 'Windows USB package signature rejected'}"#;
fn configure_signature(command:&mut tokio::process::Command,path:&Path){
    command.args(["-NoLogo","-NoProfile","-NonInteractive","-Command",SIGNATURE_SCRIPT])
        .env_remove("PSModulePath").env_remove("PSModuleAnalysisCachePath")
        .env("PORTHUB_USB_INSTALLER",path).kill_on_drop(true);
}
async fn signed(path:&Path)->Result<()> {
    let mut command=tokio::process::Command::new(system("WindowsPowerShell/v1.0/powershell.exe")?);
    configure_signature(&mut command,path);
    let result=tokio::time::timeout(Duration::from_secs(40),command.output()).await??;
    ensure!(result.status.success(),"Windows did not validate the USB installer signature");Ok(())
}
async fn install(package:&Package,path:&Path,profile:&Path)->Result<bool> {
    super::prerequisite_retry::after_verification(signed(path),||{
        let requested=super::prerequisite_retry::Requested::from_policy(&features::load(profile)?);
        Ok(if package.msi{requested.host}else{requested.receive})
    },||async {
    let mut command=if package.msi{let mut c=tokio::process::Command::new(system("msiexec.exe")?);c.arg("/i").arg(path).args(["/qn","/norestart"]);c}else{let mut c=tokio::process::Command::new(path);c.args(["/VERYSILENT","/SUPPRESSMSGBOXES","/NORESTART","/COMPONENTS=main,client","/TASKS=vcredist"]);c};
    let result=tokio::time::timeout(Duration::from_secs(240),command.kill_on_drop(true).output()).await??;
    ensure!(matches!(result.status.code(),Some(0|3010)),"Windows USB driver installation failed");
    if result.status.code()==Some(3010){tracing::warn!("Windows USB prerequisite installed; Windows requested a restart. PortHub will not restart the machine.");}
    Ok(())
    }).await
}
async fn direct_rule(path:&Path,control:&Control)->Result<()> {
    if !features::enabled(path,Feature::DirectConnections){return Ok(());}
    let name=format!("PortHub-USB-{}",control.profile().machine_id);let executable=std::env::current_exe()?;
    // Only the authenticated PortHub process is exposed to its local subnet.
    // Raw usbipd TCP3240 is deliberately not opened to the network.
    let script=include_str!("windows_usb_direct_rule.ps1");
    let output=tokio::time::timeout(Duration::from_secs(30),tokio::process::Command::new(system("WindowsPowerShell/v1.0/powershell.exe")?).args(["-NoLogo","-NoProfile","-NonInteractive","-Command",script]).env("PORTHUB_USB_RULE",name).env("PORTHUB_USB_EXE",executable).kill_on_drop(true).output()).await??;ensure!(output.status.success(),"Cannot configure the owned PortHub USB direct-path firewall rule");Ok(())
}
async fn restrict_raw_host()->Result<()> {
    let output=tokio::time::timeout(Duration::from_secs(30),tokio::process::Command::new(system("netsh.exe")?).args(["advfirewall","firewall","set","rule","name=usbipd","new","enable=no"]).kill_on_drop(true).output()).await??;ensure!(output.status.success(),"Cannot restrict the installed raw USB driver firewall exception");
    Ok(())
}
pub(super) async fn prepare(path:&Path,control:Arc<Control>)->Result<()> {
    let requested=||features::load(path).map(|p|super::prerequisite_retry::Requested::from_policy(&p));
    if !requested()?.any(){return Ok(());}
    // Disposable native service fixtures deliberately use a loopback-only
    // plaintext gateway and must not install unrelated OS drivers.
    if control.profile().allow_insecure_http_for_tests && url::Url::parse(&control.profile().server).ok().and_then(|u|u.host_str().map(str::to_owned)).is_some_and(|h|h=="127.0.0.1"||h=="localhost"||h=="::1") {return Ok(());}
    let Some(layout)=crate::private_profile::windows_service_layout(path,control.profile())? else {return Ok(());};
    let folder=layout.state.parent().context("Managed Windows state directory missing")?.join("drivers/usb-installers");crate::service::directory(&folder,true)?;
    let wanted=requested()?;
    if wanted.host && super::windows::host_installed(){restrict_raw_host().await?;}
    let required=[wanted.host&&!super::windows::host_installed(),wanted.receive&&!super::windows::receive_installed()];
    for (package,needed) in packages().into_iter().zip(required){
        if !needed{continue;}
        let allowed=|r:super::prerequisite_retry::Requested|if package.msi{r.host}else{r.receive};
        if !allowed(requested()?){continue;}
        let file=folder.join(package.file);download(&control,&package,&file).await?;
        if !allowed(requested()?){continue;}
        let installed=install(&package,&file,path).await?;
        if installed && package.msi{restrict_raw_host().await?;}
    }
    let wanted=requested()?;
    if wanted.direct{direct_rule(path,&control).await?;}
    ensure!(!wanted.host||super::windows::host_installed(),"Windows USB source driver is not ready; Windows may require a restart");
    ensure!(!wanted.receive||super::windows::receive_installed(),"Windows USB receive controller is not ready; Windows may require a restart");
    Ok(())
}

#[cfg(test)]
mod signature_tests {
    use super::*;
    #[test]
    fn signature_child_configuration_preserves_unrelated_environment_and_exact_policy(){
        let mut child=tokio::process::Command::new("must-not-execute-metadata-fixture");
        child.env("PSModulePath","contaminated").env("PSModuleAnalysisCachePath","contaminated").env("PORTHUB_TEST_PRESERVED","same");
        configure_signature(&mut child,Path::new("owned-installer.msi"));
        let environment:std::collections::BTreeMap<_,_>=child.as_std().get_envs().collect();
        assert_eq!(environment[std::ffi::OsStr::new("PSModulePath")],None);
        assert_eq!(environment[std::ffi::OsStr::new("PSModuleAnalysisCachePath")],None);
        assert_eq!(environment[std::ffi::OsStr::new("PORTHUB_TEST_PRESERVED")],Some(std::ffi::OsStr::new("same")));
        let arguments:Vec<_>=child.as_std().get_args().collect();
        assert_eq!(arguments,vec!["-NoLogo","-NoProfile","-NonInteractive","-Command",SIGNATURE_SCRIPT]);
        assert!(SIGNATURE_SCRIPT.contains("$PSHOME\\Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1"));
        assert!(SIGNATURE_SCRIPT.contains(".Status -ne 'Valid'"));
        assert!(!SIGNATURE_SCRIPT.contains("ExecutionPolicy"));
    }

    #[tokio::test]
    async fn native_signature_of_system_executable_survives_contaminated_module_environment()->Result<()> {
        // Read-only OS signature query; no installer, certificate-store edit,
        // policy mutation, device activation or global environment mutation.
        // Only an owned inert unsigned fixture is written, never executed.
        let executable=system("cmd.exe")?;
        ensure!(executable.is_file(),"Trusted system executable missing");
        let shell=system("WindowsPowerShell/v1.0/powershell.exe")?;
        let missing=system(&format!("porthub-absent-modules-{}",uuid::Uuid::new_v4().simple()))?;
        ensure!(!missing.exists(),"Contamination fixture path must not exist");
        let legacy="$ErrorActionPreference='Stop';if((Get-AuthenticodeSignature -LiteralPath $env:PORTHUB_USB_INSTALLER).Status -ne 'Valid'){throw 'Windows USB package signature rejected'}";
        let mut inherited=tokio::process::Command::new(&shell);
        inherited.args(["-NoLogo","-NoProfile","-NonInteractive","-Command",legacy])
            .env("PSModulePath",&missing).env("PSModuleAnalysisCachePath","NUL")
            .env("PORTHUB_USB_INSTALLER",&executable).kill_on_drop(true);
        // Legacy can succeed on hosts that repair/cache built-in module paths.
        // Record bounded observations; none is a required negative precondition.
        match tokio::time::timeout(Duration::from_secs(40),inherited.output()).await {
            Ok(Ok(observed))=>{
                ensure!(observed.stdout.len()<=65536&&observed.stderr.len()<=65536,"Legacy observation output exceeds bound");
                eprintln!("PORTHUB_SIGNATURE_LEGACY_OBSERVATION exit={:?} stdout_bytes={} stderr_bytes={} timed_out=false",observed.status.code(),observed.stdout.len(),observed.stderr.len());
            },
            Ok(Err(_))=>eprintln!("PORTHUB_SIGNATURE_LEGACY_OBSERVATION spawn_failed=true"),
            Err(_)=>eprintln!("PORTHUB_SIGNATURE_LEGACY_OBSERVATION timed_out=true"),
        }
        let mut fixed=tokio::process::Command::new(&shell);
        fixed.env("PSModulePath",&missing).env("PSModuleAnalysisCachePath","NUL");
        configure_signature(&mut fixed,&executable);
        for key in ["PSModulePath","PSModuleAnalysisCachePath"]{
            ensure!(fixed.as_std().get_envs().any(|(name,value)|name==std::ffi::OsStr::new(key)&&value.is_none()),"Signature child did not remove inherited module environment");
        }
        let verified=tokio::time::timeout(Duration::from_secs(40),fixed.output()).await??;
        ensure!(verified.stdout.len()<=65536&&verified.stderr.len()<=65536,"Fixed signature output exceeds bound");
        ensure!(verified.status.success(),"Fixed native system signature query failed");
        let directory=tempfile::Builder::new().prefix("porthub-unsigned-signature-").tempdir()?;
        let fixture=directory.path().join("inert-never-executed.ps1");
        std::fs::write(&fixture,b"# Owned unsigned signature fixture. Never executed.\r\n")?;
        let mut unsigned=tokio::process::Command::new(&shell);
        unsigned.env("PSModulePath",&missing).env("PSModuleAnalysisCachePath","NUL");
        configure_signature(&mut unsigned,&fixture);
        let denied=tokio::time::timeout(Duration::from_secs(40),unsigned.output()).await??;
        ensure!(denied.stdout.len()<=65536&&denied.stderr.len()<=65536,"Unsigned signature output exceeds bound");
        ensure!(!denied.status.success(),"Signature guard accepted a known owned unsigned script");
        Ok(())
    }
}
