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
    /// List physical USB devices on this machine without changing their drivers.
    Devices,
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
    match args.command {
        Action::Devices => {
            // The daemon cache refreshes in the background; a one-shot CLI must
            // wait for native discovery instead of exiting with its empty cache.
            #[cfg(windows)]
            let devices = tokio::task::spawn_blocking(super::windows::fresh_inventory).await??;
            #[cfg(not(windows))]
            let devices = super::inventory();
            println!("{}", serde_json::to_string_pretty(&devices)?);
            if !cfg!(any(target_os = "linux",target_os="macos",windows)) {
                println!("Native USB forwarding requires Linux USB/IP or the signed Windows USB drivers.");
            }
            Ok(())
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
