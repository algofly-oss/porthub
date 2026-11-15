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
            let devices = tokio::task::spawn_blocking(super::windows::fresh_inventory).await??;
            #[cfg(target_os="linux")]
            let devices = daemon_devices(args.user,args.registration.as_deref()).await.unwrap_or_else(|_|super::inventory());
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
#[cfg(target_os="linux")]
async fn daemon_devices(user:bool,registration:Option<&str>)->Result<Vec<porthub_components::usb::Device>> {
    let (layout,registration)=crate::keyboard::registration(user,registration)?;
    let mut stream=crate::exposure_broker::connect_stream(&layout,&registration).await?;
    stream.write_all(b"{\"operation\":\"usb\",\"action\":\"devices\"}\n").await?;
    let mut reader=BufReader::new(stream);
    let bytes=tokio::time::timeout(std::time::Duration::from_secs(5),crate::exposure_protocol::line(&mut reader)).await??;
    let value:Value=serde_json::from_slice(&bytes)?;
    Ok(serde_json::from_value(value["devices"].clone())?)
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
