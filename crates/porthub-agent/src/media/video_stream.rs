//! PHV1 camera data on an authenticated, typed media plan. USB stays local.
use super::{broker, host_wire, stream::Status, usb_video::Camera, usbip_video::CaptureDemand};
use crate::features::{self, Feature};
use anyhow::{ensure, Context, Result};
use porthub_components::media::VideoFrame;
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{watch, Notify},
};
use tokio_util::sync::CancellationToken;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    version: u8,
    active: bool,
    epoch: String,
}
impl Command {
    fn valid(&self) -> bool {
        self.version == 1
            && self.epoch.len() == 32
            && self.epoch.bytes().all(|b| b.is_ascii_hexdigit())
    }
}
struct Packet(Vec<u8>);
impl Drop for Packet {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
struct Stop(CancellationToken);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
async fn revoked(profile: &Path, feature: Feature) {
    let mut p = features::subscribe(profile);
    loop {
        if !p.borrow().enabled(feature) {
            return;
        }
        if p.changed().await.is_err() {
            return;
        }
    }
}
#[derive(Clone)]
struct Activation {
    command: Command,
    stop: CancellationToken,
}
async fn read_commands<R: AsyncRead + Unpin>(
    mut reader: host_wire::Reader<R>,
    changes: watch::Sender<Option<Activation>>,
    session: CancellationToken,
) -> Result<()> {
    let _stop = Stop(session.clone());
    let mut previous = session.child_token();
    let mut last = None;
    loop {
        let command: Command = serde_json::from_slice(&reader.next().await?)?;
        ensure!(
            command.valid() && last.as_ref() != Some(&command.epoch),
            "Invalid or replayed camera activation"
        );
        previous.cancel();
        previous = session.child_token();
        last = Some(command.epoch.clone());
        changes.send_replace(Some(Activation {
            command,
            stop: previous.clone(),
        }));
    }
}
/// The control reader remains independently polled while a frame writer stalls.
/// A receiver's stop command cancels native capture without waiting for stdout,
/// network backpressure or a later frame read to complete.
pub async fn source<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    profile: &Path,
    uid: u32,
    desktop_session: Option<&str>,
    source_id: &str,
    cancel: CancellationToken,
    status: Status,
) -> Result<()> {
    let (read, mut writer) = tokio::io::split(stream);
    let reader = host_wire::Reader::new(read);
    let session = cancel.child_token();
    let _stop = Stop(session.clone());
    let (changes, mut commands) = watch::channel::<Option<Activation>>(None);
    let control = read_commands(reader, changes, session.clone());
    let work = async {
        let mut active: Option<broker::CameraCapture> = None;
        let mut pending: Option<
            tokio_util::task::AbortOnDropHandle<Result<broker::CameraCapture>>,
        > = None;
        let mut epoch = String::new();
        loop {
            tokio::select! {biased;
                changed=commands.changed()=>{
                    changed.context("Camera activation controller closed")?;pending.take();active.take();
                    let activation=commands.borrow_and_update().clone().context("Missing camera activation")?;
                    epoch=activation.command.epoch;status(if activation.command.active{"starting"}else{"idle"});
                    if activation.command.active{
                        let profile=profile.to_owned();let desktop=desktop_session.map(str::to_owned);let source=source_id.to_owned();
                        pending=Some(tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move{
                            broker::capture_camera_session(&profile,uid,desktop.as_deref(),&source,&activation.stop).await
                        })));
                    }
                },
                started=async{pending.as_mut().unwrap().await},if pending.is_some()=>{
                    active=Some(started.context("Camera capture startup task failed")??);pending.take();status("capturing");
                },
                frame=async{active.as_mut().unwrap().next().await},if active.is_some()=>{
                    let mut frame=frame?;
                    if frame.format!=Camera::format(){frame.jpeg.fill(0);anyhow::bail!("Camera source format differs from fixed UVC mode");}
                    let encoded=host_wire::video(&epoch,&frame);frame.jpeg.fill(0);
                    let bytes=Packet(encoded.context("Invalid camera frame envelope")?);
                    host_wire::write_camera(&mut writer,&bytes.0).await?;
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {biased;_=cancel.cancelled()=>Ok(()),_=revoked(profile,Feature::CameraShare)=>anyhow::bail!("Camera sharing disabled"),r=control=>r,r=work=>r}
}
struct EngineStop(Arc<Mutex<Camera>>, Arc<Notify>);
impl Drop for EngineStop {
    fn drop(&mut self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).stop();
        self.1.notify_one();
    }
}
/// Changes carry a generation as well as a bool, so coalesced resets cannot
/// reuse an old capture epoch. Idle or late frames never repopulate the engine.
pub async fn receive<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    profile: &Path,
    camera: Arc<Mutex<Camera>>,
    notify: Arc<Notify>,
    mut demand: watch::Receiver<CaptureDemand>,
    cancel: CancellationToken,
    status: Status,
) -> Result<()> {
    #[cfg(all(test,target_os="linux"))]
    let mut header_proof=super::windows_receiver_fixture::VideoProof::new(profile)?;
    let _clear = EngineStop(camera.clone(), notify.clone());
    let (read, mut writer) = tokio::io::split(stream);
    let mut reader = host_wire::Reader::camera(read);
    let work = async {
        let mut current = *demand.borrow_and_update();
        let mut epoch = uuid::Uuid::new_v4().simple().to_string();
        transition(&camera, &epoch, current.active)?;
        #[cfg(all(test,target_os="linux"))]
        if let Some(proof)=&mut header_proof{proof.begin(&epoch,current.active)?;}
        notify.notify_one();
        host_wire::json(
            &mut writer,
            &serde_json::to_value(Command {
                version: 1,
                active: current.active,
                epoch: epoch.clone(),
            })?,
        )
        .await?;
        let mut receiving = false;
        loop {
            tokio::select! {biased;
                changed=demand.changed()=>{
                    changed.context("Virtual camera endpoint closed")?;
                    let next=*demand.borrow_and_update();if next==current{continue;}
                    current=next;epoch=uuid::Uuid::new_v4().simple().to_string();receiving=false;
                    transition(&camera,&epoch,current.active)?;
                    #[cfg(all(test,target_os="linux"))]
                    if let Some(proof)=&mut header_proof{proof.begin(&epoch,current.active)?;}
                    notify.notify_one();status(if current.active{"starting"}else{"ready"});
                    host_wire::json(&mut writer,&serde_json::to_value(Command{version:1,active:current.active,epoch:epoch.clone()})?).await?;
                },
                bytes=reader.next()=>{
                    let bytes=Packet(bytes?);
                    if bytes.0.len()>=33&&bytes.0[0]==1&&&bytes.0[1..33]!=epoch.as_bytes(){continue;}
                    let frame=host_wire::parse_video(&bytes.0,&epoch).context("Invalid camera PHV1 envelope")?;
                    #[cfg(all(test,target_os="linux"))]
                    let observed=if let Some(proof)=&header_proof{proof.inspect(&frame.jpeg)?}else{None};
                    if push_current(&camera,&epoch,frame,current,*demand.borrow())?{
                        #[cfg(all(test,target_os="linux"))]
                        if let(Some(proof),Some(meta))=(&mut header_proof,observed){proof.accepted(&epoch,meta)?;}
                        notify.notify_one();if !receiving{receiving=true;status("receiving");}
                    }
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {biased;_=cancel.cancelled()=>Ok(()),_=revoked(profile,Feature::MediaReceive)=>anyhow::bail!("Camera receiving disabled"),r=work=>r}
}
fn transition(camera: &Arc<Mutex<Camera>>, epoch: &str, active: bool) -> Result<()> {
    let mut camera = camera.lock().unwrap_or_else(|e| e.into_inner());
    if active {
        camera.begin_epoch(epoch)
    } else {
        camera.end_epoch();
        Ok(())
    }
}
fn push_current(
    camera: &Arc<Mutex<Camera>>,
    epoch: &str,
    mut frame: VideoFrame,
    expected: CaptureDemand,
    current: CaptureDemand,
) -> Result<bool> {
    let mut camera = camera.lock().unwrap_or_else(|e| e.into_inner());
    if !expected.active || current != expected || !camera.streaming() {
        frame.jpeg.fill(0);
        return Ok(false);
    }
    camera.push(epoch, frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn camera() -> Arc<Mutex<Camera>> {
        let mut c = Camera::new(
            super::super::usb_video::Identity {
                vendor: 0x1209,
                product: 1,
            },
            "PrivateOnly".into(),
        )
        .unwrap();
        c.control([0, 9, 1, 0, 0, 0, 0, 0], &[]).unwrap();
        let p = c.control([0xa1, 0x81, 0, 1, 1, 0, 34, 0], &[]).unwrap();
        c.control([0x21, 1, 0, 2, 1, 0, 34, 0], &p).unwrap();
        Arc::new(Mutex::new(c))
    }
    fn frame() -> VideoFrame {
        VideoFrame {
            sequence: 0,
            source_monotonic_micros: 1,
            format: Camera::format(),
            jpeg: include_bytes!("../../tests/data/private_uvc_colorbars_640x480.jpg").to_vec(),
        }
    }
    #[test]
    fn reset_coalescing_idle_and_old_epoch_cannot_repopulate_camera() -> Result<()> {
        let camera = camera();
        let old = "a".repeat(32);
        let new = "b".repeat(32);
        let active = CaptureDemand {
            active: true,
            generation: 1,
        };
        transition(&camera, &old, true)?;
        assert!(push_current(&camera, &old, frame(), active, active)?);
        assert!(!push_current(
            &camera,
            &old,
            frame(),
            active,
            CaptureDemand {
                active: false,
                generation: 1
            }
        )?);
        assert!(!push_current(
            &camera,
            &old,
            frame(),
            active,
            CaptureDemand {
                active: true,
                generation: 2
            }
        )?);
        camera.lock().unwrap().end_epoch();
        assert!(!push_current(&camera, &old, frame(), active, active)?);
        transition(&camera, &new, true)?;
        assert!(!push_current(&camera, &old, frame(), active, active)?);
        assert!(push_current(&camera, &new, frame(), active, active)?);
        Ok(())
    }
    #[tokio::test]
    async fn stop_control_cancels_capture_while_unrelated_writer_is_blocked() -> Result<()> {
        let (mut peer, read) = tokio::io::duplex(4096);
        let (tx, mut rx) = watch::channel(None);
        let session = CancellationToken::new();
        let controller = tokio::spawn(read_commands(
            host_wire::Reader::new(read),
            tx,
            session.clone(),
        ));
        host_wire::json(
            &mut peer,
            &serde_json::to_value(Command {
                version: 1,
                active: true,
                epoch: "a".repeat(32),
            })?,
        )
        .await?;
        rx.changed().await?;
        let capture = rx.borrow_and_update().as_ref().unwrap().stop.clone();
        let never_written = std::future::pending::<()>();
        tokio::pin!(never_written);
        host_wire::json(
            &mut peer,
            &serde_json::to_value(Command {
                version: 1,
                active: false,
                epoch: "b".repeat(32),
            })?,
        )
        .await?;
        tokio::time::timeout(std::time::Duration::from_millis(100), capture.cancelled()).await?;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), &mut never_written)
                .await
                .is_err()
        );
        drop(peer);
        assert!(controller.await?.is_err());
        assert!(session.is_cancelled());
        Ok(())
    }
}
