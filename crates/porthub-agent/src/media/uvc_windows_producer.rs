//! Explicitly gated private UDE receiver proof. Only generated fixture pixels.
use super::{
    usb_video::{Camera, Identity},
    usbip_video::{self, CaptureDemand},
    uvc_windows_identity,
};
use anyhow::{ensure, Context, Result};
use porthub_components::{
    media::{VideoEncoding, VideoFormat, VideoFrame},
    usb::Device,
};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{watch, Notify};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
const JPEG: &[u8] = include_bytes!("../../tests/data/private_uvc_colorbars_640x480.jpg");
fn present(serial: &str) -> Result<bool> {
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
        CM_Locate_DevNodeW, CR_NO_SUCH_DEVNODE, CR_SUCCESS,
    };
    ensure!(
        uvc_windows_identity::valid_serial(serial),
        "Exact private serial required"
    );
    let mut id = format!("USB\\VID_1209&PID_0001\\{serial}")
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut node = 0;
    let code = unsafe { CM_Locate_DevNodeW(&mut node, id.as_mut_ptr(), 0) };
    match code {
        CR_SUCCESS => Ok(true),
        CR_NO_SUCH_DEVNODE => Ok(false),
        _ => anyhow::bail!("Owned synthetic USB presence query failed ({code})"),
    }
}
fn device(serial: String) -> Result<(Device, Vec<u8>)> {
    let devnum = (std::process::id() as u16).max(1);
    let device = Device {
        busid: format!("65535-{devnum}"),
        vendor: "1209".into(),
        product: "0001".into(),
        serial,
        name: "PortHub private synthetic colorbars".into(),
        busnum: 65535,
        devnum,
        speed: 3,
        blocked: None,
    };
    let mut wire = vec![0; 312];
    wire[..7].copy_from_slice(b"porthub");
    wire[256..256 + device.busid.len()].copy_from_slice(device.busid.as_bytes());
    for (offset, value) in [(288, 65535u32), (292, devnum as u32), (296, 3)] {
        wire[offset..offset + 4].copy_from_slice(&value.to_be_bytes())
    }
    wire[300..302].copy_from_slice(&0x1209u16.to_be_bytes());
    wire[302..304].copy_from_slice(&1u16.to_be_bytes());
    wire[304..306].copy_from_slice(&0x100u16.to_be_bytes());
    wire[306..309].copy_from_slice(&[0xef, 2, 1]);
    wire[309..312].copy_from_slice(&[1, 1, 2]);
    Ok((device, wire))
}
fn consumer_result(path: &Path) -> Result<Option<serde_json::Value>> {
    use std::os::windows::fs::MetadataExt;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= 8192,
        "Invalid bounded consumer report"
    );
    let mut file = std::fs::File::open(path)?;
    use std::io::Read;
    let mut bytes = Vec::new();
    file.by_ref().take(8193).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 8192, "Consumer report grew beyond bound");
    Ok(Some(serde_json::from_slice(&bytes)?))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Requires root-reviewed private synthetic UDE/MF class test window"]
async fn native_windows_uvcvideo_colorbars_generator() -> Result<()> {
    ensure!(
        std::env::var("PORTHUB_PRIVATE_UVC_CLASS_TEST").as_deref() == Ok("1"),
        "Explicit private UVC authorization required"
    );
    crate::service::require_administrator()?;
    let profile = PathBuf::from(std::env::var("PORTHUB_PRIVATE_UVC_PROFILE")?);
    ensure!(
        profile.is_absolute() && profile.is_file(),
        "Exact existing registration required"
    );
    let serial = format!("PortHubPrivateUvc{}", uuid::Uuid::new_v4().simple());
    ensure!(
        !present(&serial)?,
        "Private fixture identity already present"
    );
    let (device, wire) = device(serial.clone())?;
    let folder = tempfile::Builder::new()
        .prefix("PortHubPrivateUvcProof-")
        .tempdir()?;
    let result_file = folder.path().join("consumer-result.json");
    let camera = Arc::new(Mutex::new(Camera::new(
        Identity {
            vendor: 0x1209,
            product: 1,
        },
        serial.clone(),
    )?));
    let changed = Arc::new(Notify::new());
    let cancel = CancellationToken::new();
    let (streaming, mut demand) = watch::channel(CaptureDemand::default());
    let mut receiver = None;
    let mut executor = None;
    let mut producer = None;
    let outcome=async{
  let(attached,stream)=crate::usb::attach_virtual(&profile,&device,&wire).await?;receiver=Some(attached);
  executor=Some(AbortOnDropHandle::new(tokio::spawn(usbip_video::serve(stream,camera.clone(),0xffff0000|device.devnum as u32,changed.clone(),streaming,cancel.clone()))));
  producer=Some(AbortOnDropHandle::new(tokio::spawn({let camera=camera.clone();let changed=changed.clone();let cancel=cancel.clone();async move{
   let(mut generation,mut sequence)=(0,0u64);let mut epoch=String::new();let mut tick=tokio::time::interval(Duration::from_micros(66667));tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
   loop{tokio::select!{_=cancel.cancelled()=>return Ok::<(),anyhow::Error>(()),result=demand.changed()=>{result?},_=tick.tick()=>{}}let state=*demand.borrow_and_update();if !state.active{continue}if generation!=state.generation{generation=state.generation;sequence=0;epoch=format!("{generation:032x}");camera.lock().map_err(|_|anyhow::anyhow!("Synthetic camera engine poisoned"))?.begin_epoch(&epoch)?;}sequence+=1;camera.lock().map_err(|_|anyhow::anyhow!("Synthetic camera engine poisoned"))?.push(&epoch,VideoFrame{sequence,source_monotonic_micros:sequence*66667,format:VideoFormat{width:640,height:480,fps_num:15,fps_den:1,encoding:VideoEncoding::Mjpeg},jpeg:JPEG.to_vec()})?;changed.notify_one();}
  }})));
  println!("PRIVATE_WINDOWS_UVC_READY {}",serde_json::json!({"serial":serial,"vendor":"1209","product":"0001","result_file":result_file,"deadline_seconds":40}));
  let attached=receiver.as_mut().context("Owned receiver absent")?;let failure=attached.failed();tokio::pin!(failure);
  let result=tokio::time::timeout(Duration::from_secs(40),async{loop{if let Some(value)=consumer_result(&result_file)?{return Ok::<_,anyhow::Error>(value)}tokio::select!{result=&mut failure=>{result?;anyhow::bail!("Owned UDE receiver failed")},_=tokio::time::sleep(Duration::from_millis(50))=>{}}}}).await.context("Ordinary exact-identity camera consumer timed out")??;
  ensure!(result["ok"]==true&&result["serial"].as_str()==Some(&serial)&&result["identity_verified"]==true&&result["frames"].as_u64()==Some(45)&&result["exact_generated_jpeg"]==true&&result["physical_camera"]==false&&result["default_camera_selected"]==false,"Consumer did not prove45 exact generated camera frames");
  ensure!((2500..=5000).contains(&result["elapsed_ms"].as_u64().context("Consumer elapsed time missing")?),"Native video clock drifted");Ok::<_,anyhow::Error>(result)
 }.await;
    cancel.cancel();
    if let Some(task) = producer {
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }
    if let Some(task) = executor {
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }
    drop(receiver);
    let cleanup = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !present(&serial)? {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let clean = matches!(cleanup, Ok(Ok(())));
    let completed_frames = camera
        .lock()
        .ok()
        .map(|camera| camera.counters.completed_frames);
    println!(
        "PRIVATE_WINDOWS_UVC_SUMMARY {}",
        serde_json::json!({"serial":serial,"ok":outcome.is_ok(),"owned_usb_absent":clean,"completed_frames":completed_frames,"physical_camera":false,"saved_video":false})
    );
    ensure!(clean, "Owned synthetic camera detach could not be verified");
    let _ = outcome?;
    Ok(())
}
