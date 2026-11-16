//! PHM1 framing inside an already authenticated, endpoint-bound PortHub carrier.
//! Capture is requested only by the receiver's active USB audio alternate.
use super::{broker, host_wire, usb_audio::Microphone};
use crate::features::{self, Feature};
use anyhow::{ensure, Context, Result};
use porthub_components::media::PcmContinuity;
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
#[derive(Serialize, Deserialize)]
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
pub(crate) type Status = Arc<dyn Fn(&str) + Send + Sync>;
struct Stop(CancellationToken);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
async fn revoked(profile: &Path, feature: Feature) {
    let mut policy = features::subscribe(profile);
    loop {
        if !policy.borrow().enabled(feature) {
            return;
        }
        if policy.changed().await.is_err() {
            return;
        }
    }
}
/// The authenticated plan fixes both desktop UID and stable source ID. Network
/// commands cannot choose another user's device or replace the source.
pub async fn source<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    profile: &Path,
    uid: u32,
    desktop_session: Option<&str>,
    source_id: &str,
    cancel: CancellationToken,
    status: Status,
) -> Result<()> {
    let (read, mut write) = tokio::io::split(stream);
    let mut read = host_wire::Reader::new(read);
    let session = cancel.child_token();
    let _stop = Stop(session.clone());
    let work = async {
        let mut active: Option<broker::Capture> = None;
        let mut epoch = String::new();
        let mut pending: Option<tokio_util::task::AbortOnDropHandle<Result<broker::Capture>>> =
            None;
        let mut capture_stop = session.child_token();
        let _capture_stop = Stop(capture_stop.clone());
        loop {
            tokio::select! {biased;
             bytes=read.next()=>{
              let command:Command=serde_json::from_slice(&bytes?)?;ensure!(command.valid(),"Invalid media activation command");
              capture_stop.cancel();pending.take();active.take();epoch=command.epoch;status(if command.active{"starting"}else{"idle"});
              capture_stop=session.child_token();
              if command.active {
               let profile=profile.to_owned();let source=source_id.to_owned();let desktop_session=desktop_session.map(str::to_owned);let stop=capture_stop.clone();
               pending=Some(tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move{broker::capture_session(&profile,uid,desktop_session.as_deref(),&source,&stop).await})));
              }
             },
             ready=async{pending.as_mut().unwrap().await},if pending.is_some()=>{active=Some(ready.context("Media source startup task failed")??);pending.take();status("capturing");},
             frame=async{active.as_mut().unwrap().next().await},if active.is_some()=>{
              let frame=frame?;let bytes=host_wire::pcm(&epoch,&frame).context("Invalid source PCM frame")?;
              host_wire::write(&mut write,&bytes).await?;
             }
            }
        }
    };
    tokio::select! {biased;_=cancel.cancelled()=>Ok(()),_=revoked(profile,Feature::MicrophoneShare)=>anyhow::bail!("Microphone sharing disabled"),result=work=>result}
}
/// Receiver-local audio executes USB scheduling locally, independently of WAN
/// round-trip time. Each alternate reset gets a fresh epoch; late PCM is dropped.
struct EngineStop(Arc<Mutex<Microphone>>);
impl Drop for EngineStop {
    fn drop(&mut self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).stop();
    }
}
pub async fn receive<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    profile: &Path,
    microphone: Arc<Mutex<Microphone>>,
    mut enabled: tokio::sync::watch::Receiver<bool>,
    cancel: CancellationToken,
    status: Status,
) -> Result<()> {
    let _clear = EngineStop(microphone.clone());
    let (read, mut write) = tokio::io::split(stream);
    let mut read = host_wire::Reader::new(read);
    let work = async {
        let mut generation = microphone
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stream_generation();
        let mut epoch = uuid::Uuid::new_v4().simple().to_string();
        let mut continuity = PcmContinuity::default();
        let mut receiving = false;
        let initially_active = *enabled.borrow_and_update();
        #[cfg(all(test,target_os="linux"))]
        let mut native_proof=super::windows_receiver_fixture::PcmProof::new(profile)?;
        #[cfg(all(test,target_os="linux"))]
        if let Some(proof)=native_proof.as_mut(){proof.begin(&epoch,initially_active)?;}
        host_wire::json(
            &mut write,
            &serde_json::to_value(Command {
                version: 1,
                active: initially_active,
                epoch: epoch.clone(),
            })?,
        )
        .await?;
        loop {
            tokio::select! {biased;
             changed=enabled.changed()=>{
              changed.context("Virtual microphone endpoint closed")?;
              epoch=uuid::Uuid::new_v4().simple().to_string();continuity=PcmContinuity::default();receiving=false;
              let active=*enabled.borrow_and_update();generation=microphone.lock().unwrap_or_else(|e|e.into_inner()).stream_generation();status(if active{"starting"}else{"ready"});
              #[cfg(all(test,target_os="linux"))]
              if let Some(proof)=native_proof.as_mut(){proof.begin(&epoch,active)?;}
              host_wire::json(&mut write,&serde_json::to_value(Command{version:1,active,epoch:epoch.clone()})?).await?;
             },
             bytes=read.next()=>{
              let bytes=bytes?;
              // A previous capture can have a bounded queued frame already in transit.
              if bytes.len()>=33&&bytes[0]==0&&&bytes[1..33]!=epoch.as_bytes(){continue;}
              let frame=host_wire::parse_pcm(&bytes,&epoch).context("Invalid media PCM envelope")?;
              ensure!(continuity.accept(&frame),"Replayed or overlapping media PCM");
              let active=*enabled.borrow();
              if push_current(&microphone,&frame.pcm,generation,active)? {
               #[cfg(all(test,target_os="linux"))]
               if let Some(proof)=native_proof.as_mut(){proof.record(&epoch,&frame)?;}
               if !receiving{receiving=true;status("receiving");}}
             }
            }
        }
    };
    let result = tokio::select! {biased;_=cancel.cancelled()=>Ok(()),_=revoked(profile,Feature::MediaReceive)=>anyhow::bail!("Media receiving disabled"),result=work=>result};
    result
}
fn push_current(
    microphone: &Arc<Mutex<Microphone>>,
    pcm: &[u8],
    generation: u64,
    active: bool,
) -> Result<bool> {
    let mut engine = microphone.lock().unwrap_or_else(|e| e.into_inner());
    if !active || !engine.streaming() || engine.stream_generation() != generation {
        return Ok(false);
    }
    engine.push_f32le(pcm)?;
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    use porthub_components::media::PcmFrame;
    use tokio::io::BufReader;
    #[test]
    fn ingress_waiting_before_interface_reset_cannot_repopulate_new_stream() -> Result<()> {
        let mut engine = Microphone::new(
            super::super::usb_audio::Identity {
                vendor: 0x1209,
                product: 1,
            },
            "PrivateOnly".into(),
        )?;
        engine.control([0, 9, 1, 0, 0, 0, 0, 0], &[]).unwrap();
        engine.control([1, 11, 1, 0, 1, 0, 0, 0], &[]).unwrap();
        let old = engine.stream_generation();
        // Model ingress parsed before reset but waiting for the engine lock.
        engine.control([1, 11, 1, 0, 1, 0, 0, 0], &[]).unwrap();
        let current = engine.stream_generation();
        assert_ne!(old, current);
        let engine = Arc::new(Mutex::new(engine));
        assert!(!push_current(&engine, &1.0f32.to_le_bytes(), old, true)?);
        let reply = engine.lock().unwrap().isochronous(
            2,
            &[super::super::usb_audio::IsoPacket {
                offset: 0,
                length: 2,
            }],
        )?;
        assert_eq!(reply.packed, vec![0, 0]);
        assert!(push_current(&engine, &0.5f32.to_le_bytes(), current, true)?);
        let reply = engine.lock().unwrap().isochronous(
            2,
            &[super::super::usb_audio::IsoPacket {
                offset: 0,
                length: 2,
            }],
        )?;
        assert!(i16::from_le_bytes(reply.packed.try_into().unwrap()) > 16000);
        Ok(())
    }
    #[tokio::test]
    async fn alternate_epochs_reject_late_pcm_and_receiver_policy_unpublishes() -> Result<()> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let profile = directory.path().join("fixture.json");
        let mut engine = Microphone::new(
            super::super::usb_audio::Identity {
                vendor: 0x1209,
                product: 1,
            },
            "PrivateTestOnly".into(),
        )?;
        engine.control([0, 9, 1, 0, 0, 0, 0, 0], &[]).unwrap();
        engine.control([1, 11, 1, 0, 1, 0, 0, 0], &[]).unwrap();
        let microphone = Arc::new(Mutex::new(engine));
        let observed = microphone.clone();
        let (remote, local) = tokio::io::duplex(16384);
        let (read, mut write) = tokio::io::split(remote);
        let mut read = host_wire::Reader::new(read);
        let (active, changes) = tokio::sync::watch::channel(true);
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let path = profile.clone();
        let task = tokio::spawn(async move {
            receive(local, &path, microphone, changes, stop, Arc::new(|_| {})).await
        });
        let initial: Command = serde_json::from_slice(&read.next().await?)?;
        assert!(initial.active);
        active.send_replace(true);
        let reset: Command = serde_json::from_slice(&read.next().await?)?;
        assert_ne!(
            reset.epoch, initial.epoch,
            "Even a same-alt reset starts a new capture epoch"
        );
        let frame = PcmFrame {
            sequence: 0,
            sample_offset: 0,
            source_monotonic_micros: 1,
            pcm: 0.5f32.to_le_bytes().repeat(48),
        };
        host_wire::write(&mut write, &host_wire::pcm(&initial.epoch, &frame).unwrap()).await?;
        host_wire::write(&mut write, &host_wire::pcm(&reset.epoch, &frame).unwrap()).await?;
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        let response = observed.lock().unwrap().isochronous(
            96,
            &[super::super::usb_audio::IsoPacket {
                offset: 0,
                length: 96,
            }],
        )?;
        assert_eq!(response.packed.len(), 96);
        assert!(response
            .packed
            .chunks_exact(2)
            .all(|v| i16::from_le_bytes(v.try_into().unwrap()) > 16000));
        let (control, _reply) = tokio::io::duplex(4096);
        crate::features::serve(BufReader::new(control),&profile,serde_json::json!({"operation":"client_features","feature":"media-receive","enabled":false})).await?;
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), task)
                .await??
                .is_err()
        );
        assert!(!observed.lock().unwrap().streaming());
        cancel.cancel();
        Ok(())
    }
    #[tokio::test]
    async fn idle_source_never_opens_an_unregistered_microphone() -> Result<()> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let profile = directory.path().join("fixture.json");
        let (remote, local) = tokio::io::duplex(1024);
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let task = tokio::spawn(async move {
            source(
                local,
                &profile,
                1000,
                None,
                "media:unregistered",
                stop,
                Arc::new(|_| {}),
            )
            .await
        });
        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "An idle carrier must not attempt source activation"
        );
        drop(remote);
        assert!(task.await?.is_err());
        Ok(())
    }
}
