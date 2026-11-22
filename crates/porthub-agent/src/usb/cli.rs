use anyhow::{ensure, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;
#[derive(clap::Args)]
pub struct Args {
    #[arg(long, global = true)]
    pub user: bool,
    #[arg(long, global = true)]
    pub registration: Option<String>,
    #[command(subcommand)]
    pub command: Action,
}
#[derive(clap::Subcommand)]
pub enum Action {
    /// List local USB devices and active onward-forwarding aliases without changing drivers.
    Devices,
    /// Safely offline local Windows USB storage volumes before forwarding (administrator).
    Prepare { busid: String },
    /// Restore only storage volumes explicitly prepared by this machine.
    Restore { busid: String },
    /// Forward a selected local USB device to another registered machine.
    #[command(alias = "share")]
    Expose {
        busid: String,
        #[arg(long)]
        to: String,
        #[arg(short = 'd', long)]
        detach: bool,
    },
    /// Attach a USB device exported by another registered machine.
    Attach {
        #[arg(long)]
        from: String,
        #[arg(long)]
        device: String,
        #[arg(short = 'd', long)]
        detach: bool,
    },
    /// List temporary foreground/background USB forwarding jobs.
    #[command(alias = "ls")]
    List,
    /// Inspect a saved USB forwarding job.
    Status { id: Option<String> },
    /// Stop a temporary USB forward and remove restart recovery.
    Stop { id: Option<String> },
}
pub async fn run(args: Args, cancel: CancellationToken) -> Result<()> {
    #[cfg(windows)]
    let restoring = matches!(&args.command, Action::Restore { .. });
    match args.command {
        Action::Devices => {
            // The daemon cache refreshes in the background; a one-shot CLI must
            // wait for native discovery instead of exiting with its empty cache.
            #[cfg(windows)]
            let devices = {
                let physical=tokio::task::spawn_blocking(super::windows::fresh_inventory).await??;
                // Alias state lives in the selected enrollment's daemon, never
                // in this short-lived CLI or the physical usbipd inventory.
                windows_inventory(physical,daemon_devices(args.user,args.registration.as_deref())).await
            };
            #[cfg(target_os="linux")]
            let devices = match daemon_devices(args.user,args.registration.as_deref()).await {
                Ok(devices) => devices,
                Err(_) => super::native_probe::broker(super::inventory).await?,
            };
            #[cfg(not(any(windows,target_os="linux")))]
            let devices = super::inventory();
            println!("{}", serde_json::to_string_pretty(&devices)?);
            if !cfg!(any(target_os = "linux",target_os="macos",windows)) {
                println!("Native USB forwarding requires Linux USB/IP or the signed Windows USB drivers.");
            }
            Ok(())
        }
        Action::Prepare { busid } | Action::Restore { busid } => {
            #[cfg(windows)]
            {
                let restore = restoring;
                if !restore {
                    let (layout, registration) = crate::keyboard::registration(
                        args.user,
                        args.registration.as_deref(),
                    )?;
                    let row = crate::service::select(&layout, Some(&registration))?;
                    ensure!(
                        crate::features::enabled(&row.spec.profile, crate::features::Feature::Usb),
                        "USB is disabled by local client policy"
                    );
                }
                tokio::task::spawn_blocking(move || {
                    super::windows::storage::run(&busid, restore)
                }).await?
            }
            #[cfg(not(windows))]
            {
                let _ = busid;
                anyhow::bail!("Explicit USB volume preparation is supported on Windows only");
            }
        }
        Action::List => crate::mapping_jobs::usb_list(None),
        Action::Status { id } => crate::mapping_jobs::usb_list(id.as_deref()),
        Action::Stop { id } => crate::mapping_jobs::usb_stop(id.as_deref()).await,
        action => {
            ensure!(
                cfg!(any(target_os = "linux",target_os="macos",windows)),
                "Native USB forwarding requires Linux USB/IP or the signed Windows USB drivers"
            );
            let (layout, registration) =
                crate::keyboard::registration(args.user, args.registration.as_deref())?;
            let row = crate::service::readable::select(&layout, Some(&registration), Some(false))?;
            let (source, destination, busid, detach) = match action {
                Action::Expose { busid, to, detach } => (row.machine_id, to, busid, detach),
                Action::Attach {
                    from,
                    device,
                    detach,
                } => {
                    ensure!(!cfg!(target_os="macos"),"macOS can export USB devices only; receiving requires an Apple-approved virtual host-controller entitlement");
                    (from, row.machine_id, device, detach)
                },
                _ => unreachable!(),
            };
            ensure!(
                porthub_components::usb::valid_busid(&busid),
                "Use a bus ID from porthub usb devices, for example 1-2"
            );
            for id in [&source, &destination] {
                ensure!(
                    id.len() == 24 && id.bytes().all(|b| b.is_ascii_hexdigit()),
                    "Use the registered machine ID shown in the host popup"
                );
            }
            let source = source.to_ascii_lowercase();
            let destination = destination.to_ascii_lowercase();
            ensure!(source != destination, "Choose two different machines");
            crate::mapping_jobs::start(
                crate::mapping_jobs::Spec::Usb {
                    user: layout.user,
                    registration,
                    source,
                    destination,
                    busid,
                },
                detach,
                cancel,
            )
            .await
        }
    }
}
#[cfg(any(target_os="linux",windows))]
async fn daemon_devices(user:bool,registration:Option<&str>)->Result<Vec<porthub_components::usb::Device>> {
    let (layout,registration)=crate::keyboard::registration(user,registration)?;
    let mut stream=crate::exposure_broker::connect_stream(&layout,&registration).await?;
    stream.write_all(b"{\"operation\":\"usb\",\"action\":\"devices\"}\n").await?;
    read_daemon_devices(stream).await
}
#[cfg(any(target_os="linux",windows,test))]
async fn read_daemon_devices<S:tokio::io::AsyncRead+Unpin>(stream:S)->Result<Vec<porthub_components::usb::Device>> {
    let mut reader=BufReader::new(stream);
    let bytes=tokio::time::timeout(std::time::Duration::from_secs(5),crate::exposure_protocol::line(&mut reader)).await??;
    let value:Value=serde_json::from_slice(&bytes)?;
    ensure!(value.get("error").is_none(),"USB inventory broker refused the selected enrollment");
    Ok(serde_json::from_value(value["devices"].clone())?)
}
#[cfg(any(windows,test))]
async fn windows_inventory(physical:Vec<porthub_components::usb::Device>,request:impl std::future::Future<Output=Result<Vec<porthub_components::usb::Device>>>)->Vec<porthub_components::usb::Device> {
    match tokio::time::timeout(std::time::Duration::from_secs(5),request).await {
        Ok(Ok(scoped))=>merge_windows_aliases(physical.clone(),scoped).unwrap_or(physical),
        _=>physical,
    }
}
#[cfg(any(windows,test))]
fn merge_windows_aliases(physical:Vec<porthub_components::usb::Device>,scoped:Vec<porthub_components::usb::Device>)->Result<Vec<porthub_components::usb::Device>> {
    let aliases=scoped.into_iter().filter(|d|d.busid.starts_with("0-")).collect::<Vec<_>>();
    let mut seen=std::collections::HashSet::new();
    ensure!(aliases.len()<=128&&aliases.iter().all(|d|d.valid()&&d.busid[2..].parse::<u64>().ok().is_some_and(|n|n.to_string()==d.busid[2..])&&seen.insert(d.busid.clone())),"Invalid or ambiguous selected-enrollment aliases");
    // Preserve fresh physical discovery; stale physical broker rows do not
    // replace it. Blocked aliases remain visible with their actual reason.
    Ok(super::inventory_with_aliases(physical,aliases))
}
pub(crate) async fn broker_worker(
    user: bool,
    registration: String,
    id: String,
    source: String,
    destination: String,
    busid: String,
    cancel: CancellationToken,
) -> Result<()> {
    let layout = if user {
        crate::service::Layout::user()?
    } else {
        crate::service::Layout::system()?
    };
    let mut stream = crate::exposure_broker::connect_stream(&layout, &registration).await?;
    stream.write_all(format!("{}\n",json!({"operation":"usb","action":"create","id":id,"source":source,"destination":destination,"busid":busid})).as_bytes()).await?;
    let mut reader = BufReader::new(stream);
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        crate::exposure_protocol::line(&mut reader),
    )
    .await??;
    let reply: Value = serde_json::from_slice(&response)?;
    ensure!(
        reply.get("error").is_none(),
        "{}",
        reply["error"].as_str().unwrap_or("USB forwarding failed")
    );
    ensure!(
        reply["forward"]["id"] == id,
        "USB gateway did not confirm the forwarding session"
    );
    crate::mapping_jobs::usb_ready(&id)?;
    println!("USB forwarding {id}: {source}/{busid} → {destination}");
    let mut byte = [0];
    tokio::select! {_=cancel.cancelled()=>{},closed=reader.read(&mut byte)=>{let _=closed?;anyhow::bail!("USB forwarding lease ended; check local feature policy and gateway connectivity");}}
    Ok(())
}

#[cfg(test)]
mod inventory_tests {
    use super::*;
    fn device(busid:&str)->porthub_components::usb::Device {
        porthub_components::usb::Device{busid:busid.into(),vendor:"1377".into(),product:"1100".into(),serial:"0214024304".into(),name:"Sennheiser Profile".into(),busnum:1,devnum:1,speed:2,blocked:None}
    }
    #[test]
    fn windows_inventory_preserves_fresh_physical_and_selected_blocked_aliases() {
        let physical=device("1-5");let mut blocked=device("0-123");blocked.blocked=Some("Local USB policy disabled".into());
        let result=merge_windows_aliases(vec![physical.clone()],vec![device("9-9"),blocked.clone()]).unwrap();
        assert_eq!(result,vec![physical,blocked]);
        assert!(merge_windows_aliases(vec![],vec![device("0-123"),device("0-123")]).is_err());
        let mut invalid=device("0-123");invalid.vendor="invalid".into();assert!(merge_windows_aliases(vec![],vec![invalid]).is_err());
    }
    #[test]
    fn alias_capacity_is_reserved_and_only_canonical_u64_aliases_are_accepted() {
        let physical=(1..=128).map(|n|device(&format!("1-{n}"))).collect();
        let own=device("0-123");let result=merge_windows_aliases(physical,vec![own.clone()]).unwrap();
        assert_eq!(result.len(),128);assert_eq!(result.last(),Some(&own));
        assert!(!result.iter().any(|d|d.busid=="1-128"));
        for busid in ["0-1.2","0-01","0-18446744073709551616","0-"] {
            assert!(merge_windows_aliases(vec![],vec![device(busid)]).is_err(),"{busid}");
        }
        assert!(merge_windows_aliases(vec![],vec![device("0-18446744073709551615")]).is_ok());
    }
    #[tokio::test]
    async fn selected_broker_response_never_adds_other_enrollment_aliases()->Result<()> {
        let (selected,mut server)=tokio::io::duplex(4096);
        let own=device("0-123");let foreign=device("0-456");
        server.write_all(format!("{}\n",json!({"devices":[own.clone()]})).as_bytes()).await?;
        let result=merge_windows_aliases(vec![device("1-5")],read_daemon_devices(selected).await?)?;
        assert!(result.contains(&own));assert!(!result.contains(&foreign));
        let (denied,mut server)=tokio::io::duplex(4096);
        server.write_all(format!("{}\n",json!({"error":"policy denied","devices":[foreign]})).as_bytes()).await?;
        let physical=vec![device("1-5")];
        assert_eq!(windows_inventory(physical.clone(),read_daemon_devices(denied)).await,physical);Ok(())
    }
    #[tokio::test(start_paused=true)]
    async fn broker_inventory_read_is_bounded_without_a_response() {
        let physical=vec![device("1-5")];
        let start=tokio::time::Instant::now();
        assert_eq!(windows_inventory(physical.clone(),std::future::pending()).await,physical);
        assert_eq!(start.elapsed(),std::time::Duration::from_secs(5));
    }
}
