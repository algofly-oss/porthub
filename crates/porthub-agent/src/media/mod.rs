//! Optional media forwarding. Inventory does not open a capture stream.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod e2e_fixture;
#[cfg(all(test,target_os="linux"))]
pub(crate) mod video_e2e_fixture;
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod windows_receiver_fixture;
pub mod session;
#[cfg(windows)]
pub(crate) mod windows_host;
pub(crate) mod actions;
pub(crate) mod config;
pub(crate) mod stream;
#[cfg(any(target_os="linux",target_os="macos",windows))]
pub(crate) mod receiver;
#[cfg(any(target_os="linux",target_os="macos",windows))]
pub(crate) mod worker;
mod host_wire;
pub mod broker;
#[cfg(any(target_os="linux",windows))]
pub(crate) mod host;
pub mod usb_audio;
pub mod usbip;
pub(crate) mod usb_video;
pub(crate) mod usbip_video;
pub(crate) mod video_stream;
pub(crate) mod video_receiver;
#[cfg(target_os = "linux")]
mod linux;
use crate::features::{self, Feature};
use anyhow::Result;
use porthub_components::media::{Inventory, Kind, Receiver};
use std::path::Path;
pub(crate) fn authorized_inventory(profile:&Path)->serde_json::Value {
    let policy=features::subscribe(profile).borrow().clone();
    let devices=broker::inventory(profile).into_iter().map(|s|serde_json::json!({"uid":s.uid,"desktop_session":s.desktop_session,"device":s.device})).collect::<Vec<_>>();
    let identity=config::identity(profile);
    serde_json::json!({"devices":devices,"desktop_connected":broker::connected(profile),"microphone_enabled":policy.enabled(Feature::MicrophoneShare),"camera_enabled":policy.enabled(Feature::CameraShare),"camera_receiver_available":identity.is_some()&&video_receiver::available(),"camera_receiver_unavailable_reason":video_receiver::unavailable_reason(),"source_availability":broker::availability(profile),"receive_enabled":policy.enabled(Feature::MediaReceive),"receiver_identity":identity,"receiver_configured":identity.is_some(),"receiver_backend":if cfg!(target_os="linux"){"linux-vhci"}else if cfg!(windows){"windows-usbip-ude"}else{"unavailable"},"receiver_unavailable_reason":if identity.is_none(){Some("Receiver USB identity required")}else{None}})
}
pub fn inventory(profile: &Path) -> Inventory {
    let policy = features::subscribe(profile).borrow().clone();
    #[cfg(target_os = "linux")]
    let native = linux::devices();
    #[cfg(not(target_os = "linux"))]
    let native: Result<Vec<porthub_components::media::Device>> = Err(anyhow::anyhow!(
        "Native media inventory backend is not implemented for this platform"
    ));
    let (mut devices, enumeration_available, unavailable_reason) = match native {
        Ok(v) => (v, true, None),
        Err(error) => (vec![], false, Some(error.to_string())),
    };
    for device in &mut devices {
        let feature = match device.kind {
            Kind::Microphone => Feature::MicrophoneShare,
            Kind::Camera => Feature::CameraShare,
        };
        if !policy.enabled(feature) {
            device.capture_available = false;
            device.unavailable_reason =
                Some("Media sharing disabled by local client policy".into());
        }
    }
    let receivers = [Kind::Microphone, Kind::Camera]
        .into_iter()
        .map(|kind| Receiver {
            kind,
            backend: if cfg!(target_os = "linux") {
                "pipewire"
            } else {
                "native"
            }
            .into(),
            publication_available: false,
            unavailable_reason: Some(
                if !policy.enabled(Feature::MediaReceive) {
                    "Media receiving disabled by local client policy"
                } else {
                    "Native receiver publisher is not installed or verified"
                }
                .into(),
            ),
        })
        .collect();
    Inventory {
        devices,
        receivers,
        enumeration_available,
        unavailable_reason,
        microphone_share_enabled: policy.enabled(Feature::MicrophoneShare),
        camera_share_enabled: policy.enabled(Feature::CameraShare),
        media_receive_enabled: policy.enabled(Feature::MediaReceive),
        capture_active: false,
    }
}
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
    /// Configure this receiver's USB identity locally.
    ReceiverIdentity {#[arg(long)]vendor:Option<u16>,#[arg(long)]product:Option<u16>,#[arg(long)]clear:bool},
    /// Publish an explicit desktop microphone or camera at another enrolled machine.
    Forward {
        #[arg(long,default_value="microphone",value_parser=["microphone","camera"])] kind:String,
        #[arg(long)] source_id:String,
        #[arg(long)] desktop_uid:u32,
        #[arg(long)] desktop_session:Option<String>,
        #[arg(long)] to:String,
        #[arg(long)] name:String,
        #[arg(long)] usb_vendor:Option<u16>,
        #[arg(long)] usb_product:Option<u16>,
        #[arg(long)] persistent:bool,
    },
    /// Remove a native-media forwarding rule created by this machine.
    Stop {id:String},
    /// Discover verified native sources in the authenticated desktop user session.
    Discover,
    /// Run the optional desktop media channel in the current unprivileged session.
    Host,
    /// Enumerate sources and receiver support without capturing media.
    Devices {
        #[arg(long)]
        json: bool,
    },
}
pub async fn run(args: Args) -> Result<()> {
    let (layout, registration) =
        crate::keyboard::registration(args.user, args.registration.as_deref())?;
    if let Action::Devices{json}=&args.command {
        use tokio::io::{AsyncWriteExt,AsyncBufReadExt,AsyncReadExt};
        let mut stream=crate::exposure_broker::connect_stream(&layout,&registration).await?;
        stream.write_all(b"{\"operation\":\"media_inventory\"}\n").await?;
        let mut bytes=Vec::new();tokio::time::timeout(std::time::Duration::from_secs(5),tokio::io::BufReader::new(stream).take(128*1024+1).read_until(b'\n',&mut bytes)).await??;
        anyhow::ensure!(!bytes.is_empty()&&bytes.len()<=128*1024,"Native media inventory unavailable");
        let value:serde_json::Value=serde_json::from_slice(&bytes)?;
        if *json {println!("{}",serde_json::to_string_pretty(&value)?);}else{
            for source in value["devices"].as_array().into_iter().flatten(){println!("{}  {}  desktop {}",source["device"]["id"].as_str().unwrap_or(""),source["device"]["name"].as_str().unwrap_or(""),source["desktop_session"].as_str().map(str::to_owned).unwrap_or_else(||source["uid"].to_string()));}
            if value["desktop_connected"]!=true {println!("No authenticated desktop media host is connected. Keep the enrolled desktop session signed in.");}
            if value["receiver_identity"].is_null(){println!("Receiver USB identity required; configure it locally with porthub media receiver-identity.");}
        }
        return Ok(());
    }
    match args.command {
        Action::ReceiverIdentity{vendor,product,clear}=>{
            anyhow::ensure!(clear && vendor.is_none() && product.is_none() || !clear && vendor.is_some() && product.is_some(),"Provide both --vendor and --product, or --clear");
            return action(&layout,&registration,serde_json::json!({"operation":"media_receiver_config","identity":if clear{None}else{Some(porthub_components::media_forward::UsbIdentity{vendor:vendor.unwrap(),product:product.unwrap()})}}),false).await;
        },
        Action::Forward{kind,source_id,desktop_uid,desktop_session,to,name,usb_vendor,usb_product,persistent}=>{
            anyhow::ensure!(usb_vendor.is_some()==usb_product.is_some(),"Provide both USB identity overrides, or use the receiver configured identity");
            return action(&layout,&registration,serde_json::json!({"operation":"media_action","action":"create","plan":{"mode":if kind=="camera"{"phv1-camera-mjpeg-v1"}else{"phm1-microphone-v1"},"source":"","destination":to,"desktop_uid":desktop_uid,"desktop_session":desktop_session,"source_id":source_id,"name":name,"identity":usb_vendor.zip(usb_product).map(|(vendor,product)|porthub_components::media_forward::UsbIdentity{vendor,product}),"persistent":persistent}}),!persistent).await;
        },
        Action::Stop{id}=>return action(&layout,&registration,serde_json::json!({"operation":"media_action","action":"stop","id":id}),false).await,
        #[cfg(any(target_os="linux",windows))]
        Action::Host=>return host::run(layout,registration,tokio_util::sync::CancellationToken::new()).await,
        Action::Discover=>{
            use tokio::io::AsyncWriteExt;
            let mut stream=crate::exposure_broker::connect_stream(&layout,&registration).await?;
            stream.write_all(b"{\"operation\":\"media_discover\"}\n").await?;
            let mut stream=tokio::io::BufReader::new(stream);
            // Discovery can return a bounded source inventory larger than generic control replies.
            use tokio::io::{AsyncReadExt,AsyncBufReadExt};let mut bytes=Vec::new();
            tokio::time::timeout(std::time::Duration::from_secs(65),(&mut stream).take(128*1024+1).read_until(b'\n',&mut bytes)).await??;
            anyhow::ensure!(!bytes.is_empty()&&bytes.len()<=128*1024,"Native media discovery unavailable");let value:serde_json::Value=serde_json::from_slice(&bytes)?;println!("{}",serde_json::to_string_pretty(&value)?);return Ok(());
        },
        #[cfg(not(any(target_os="linux",windows)))]
        Action::Host=>anyhow::bail!("Native media user broker is not available on this platform yet"),
        _=>{},
    }
    let spec = crate::service::installed(&layout, &registration)?
        .ok_or_else(|| anyhow::anyhow!("Registration manifest unavailable"))?;
    let report = inventory(&spec.profile);
    match args.command {
        Action::Host|Action::Discover|Action::Forward{..}|Action::Stop{..}|Action::ReceiverIdentity{..}=>unreachable!(),
        Action::Devices { json: true } => println!("{}", serde_json::to_string(&report)?),
        Action::Devices { json: false } => {
            if !report.enumeration_available {
                println!(
                    "Inventory unavailable: {}",
                    report.unavailable_reason.as_deref().unwrap_or("Unknown")
                );
            }
            for device in report.devices {
                println!(
                    "{}  {:?}  {}  {}",
                    device.id,
                    device.kind,
                    device.name,
                    device.unavailable_reason.as_deref().unwrap_or("Available")
                );
            }
            for receiver in report.receivers {
                println!(
                    "Receive {:?}: {}",
                    receiver.kind,
                    receiver
                        .unavailable_reason
                        .as_deref()
                        .unwrap_or("Available")
                );
            }
        }
    }
    Ok(())
}

async fn action(layout:&crate::service::Layout,registration:&str,body:serde_json::Value,lease:bool)->Result<()> {
    use tokio::io::{AsyncWriteExt,AsyncBufReadExt,AsyncReadExt};
    let mut stream=crate::exposure_broker::connect_stream(layout,registration).await?;
    stream.write_all(format!("{body}\n").as_bytes()).await?;
    let mut reader=tokio::io::BufReader::new(stream);let mut bytes=Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(30),(&mut reader).take(128*1024+1).read_until(b'\n',&mut bytes)).await??;
    anyhow::ensure!(!bytes.is_empty()&&bytes.len()<=128*1024,"Native media action returned an invalid response");
    let reply:serde_json::Value=serde_json::from_slice(&bytes)?;anyhow::ensure!(reply["error"].is_null(),"{}",reply["error"]);
    println!("{}",serde_json::to_string_pretty(&reply)?);
    if lease {tokio::select!{result=tokio::signal::ctrl_c()=>result?,closed=reader.fill_buf()=>{let _=closed?;anyhow::bail!("Native media session closed");}}}
    Ok(())
}

#[cfg(all(test,windows))]
pub(crate) mod windows_e2e_fixture;

#[cfg(all(test,windows))]
pub(crate) mod windows_video_destination_fixture;

#[cfg(all(test,windows))]
pub(crate) mod windows_fixture_security;
