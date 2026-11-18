//! Lifetime-owned receiver-local USB Audio Class endpoint. No public listener.
use super::{
    stream,
    usb_audio::{Identity, Microphone},
    usbip,
};
use crate::{
    control::Control,
    features::{self, Feature},
};
use anyhow::{ensure, Context, Result};
use porthub_components::{media::Kind, media_forward::Plan, usb::Device};
use std::{
    collections::BTreeSet,
    path::Path,
    sync::{Arc, Mutex, OnceLock},
};
use tokio_util::sync::CancellationToken;
struct Slot(u16);
fn slots() -> &'static Mutex<BTreeSet<u16>> {
    static S: OnceLock<Mutex<BTreeSet<u16>>> = OnceLock::new();
    S.get_or_init(Mutex::default)
}
impl Slot {
    fn acquire() -> Result<Self> {
        let mut used = slots().lock().unwrap_or_else(|e| e.into_inner());
        let n = (1..=u16::MAX)
            .find(|n| !used.contains(n))
            .context("No available local media USB identities")?;
        used.insert(n);
        Ok(Self(n))
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        slots()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}
fn device(plan: &Plan, slot: u16) -> (Device, Vec<u8>) {
    let device = Device {
        busid: format!("65535-{slot}"),
        vendor: format!("{:04x}", plan.identity.vendor),
        product: format!("{:04x}", plan.identity.product),
        serial: plan.id.clone(),
        name: plan.name.clone(),
        busnum: 65535,
        devnum: slot,
        speed: 2,
        blocked: None,
    };
    let mut wire = vec![0; 312];
    wire[..7].copy_from_slice(b"porthub");
    wire[256..256 + device.busid.len()].copy_from_slice(device.busid.as_bytes());
    for (offset, value) in [(288, 65535u32), (292, slot as u32), (296, 2)] {
        wire[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    wire[300..302].copy_from_slice(&plan.identity.vendor.to_be_bytes());
    wire[302..304].copy_from_slice(&plan.identity.product.to_be_bytes());
    wire[304..306].copy_from_slice(&0x100u16.to_be_bytes());
    wire[309] = 1;
    wire[310] = 1;
    wire[311] = 2;
    (device, wire)
}
struct Stop(CancellationToken);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
/// The caller obtains this plan from an authenticated gateway. Its stream is
/// independently re-authorized before the local endpoint can be attached.
pub async fn run(
    profile: &Path,
    control: Arc<Control>,
    plan: &Plan,
    parent: CancellationToken,
    status: stream::Status,
) -> Result<()> {
    ensure!(plan.valid(), "Invalid native media forwarding plan");
    let kind = plan.kind().context("Unknown native media plan mode")?;
    #[cfg(all(test, windows))]
    super::windows_video_destination_fixture::verify_plan(
        profile,
        plan,
        control.profile().machine_id == plan.source,
        &parent,
    )
    .await?;
    let source = control.profile().machine_id == plan.source;
    #[cfg(all(test, windows))]
    super::windows_e2e_fixture::verify_plan(&plan, source)?;
    #[cfg(all(test, target_os = "linux"))]
    super::windows_receiver_fixture::verify_plan(&plan, source)?;
    ensure!(
        source || control.profile().machine_id == plan.destination,
        "Media plan belongs to another endpoint"
    );
    if kind == Kind::Speaker {
        return super::playback::run(profile, control, plan, parent, status).await;
    }
    if !source {
        ensure!(
            super::config::identity(profile).as_ref() == Some(&plan.identity),
            "Receiver USB identity is not configured or differs from this plan"
        );
    }
    let feature = if source {
        match kind {
            Kind::Microphone => Feature::MicrophoneShare,
            Kind::Speaker => Feature::MediaReceive,
            Kind::Camera => Feature::CameraShare,
        }
    } else {
        Feature::MediaReceive
    };
    ensure!(
        features::enabled(profile, feature),
        "Local media policy disables this session"
    );
    let cancel = parent.child_token();
    let _stop = Stop(cancel.clone());
    let (local, network) = tokio::io::duplex(if kind == Kind::Camera { 65536 } else { 19200 });
    let (send, ready) = tokio::sync::oneshot::channel();
    let transport = async {
        match kind {
            Kind::Speaker => unreachable!("speaker dispatched separately"),
            Kind::Microphone => {
                crate::usb::media_transport::transfer(
                    network,
                    profile,
                    control.clone(),
                    &plan.id,
                    source,
                    cancel.clone(),
                    send,
                )
                .await
            }
            Kind::Camera => {
                crate::usb::media_transport::transfer_camera(
                    network,
                    profile,
                    control.clone(),
                    &plan.id,
                    source,
                    cancel.clone(),
                    send,
                )
                .await
            }
        }
    };
    tokio::pin!(transport);
    let endpoint = async {
        tokio::time::timeout(std::time::Duration::from_secs(60), ready)
            .await?
            .context("Authenticated media transport failed")?;
        if source {
            status("idle");
            if kind == Kind::Camera {
                ensure!(plan.format().is_some(), "Camera plan has no fixed format");
                return super::video_stream::source(
                    local,
                    profile,
                    plan.desktop_uid,
                    plan.desktop_session.as_deref(),
                    &plan.source_id,
                    cancel.child_token(),
                    status.clone(),
                )
                .await;
            }
            return stream::source(
                local,
                profile,
                plan.desktop_uid,
                plan.desktop_session.as_deref(),
                &plan.source_id,
                cancel.child_token(),
                status.clone(),
            )
            .await;
        }
        #[cfg(any(target_os = "linux", windows))]
        {
            let slot = Slot::acquire()?;
            if kind == Kind::Camera {
                return super::video_receiver::run_local(
                    profile,
                    plan,
                    slot.0,
                    local,
                    cancel.child_token(),
                    status.clone(),
                )
                .await;
            }
            let (device, wire) = device(plan, slot.0);
            let (mut attached, kernel) =
                crate::usb::media_transport::attach_audio(profile, &device, &wire).await?;
            let mut microphone = Microphone::new(
                Identity {
                    vendor: plan.identity.vendor,
                    product: plan.identity.product,
                },
                plan.id.clone(),
            )?;
            microphone.set_name(&plan.name)?;
            let engine = Arc::new(Mutex::new(microphone));
            let (active, changes) = tokio::sync::watch::channel(false);
            let usb = usbip::serve(
                kernel,
                engine.clone(),
                ((65535u32) << 16) | slot.0 as u32,
                active,
                cancel.child_token(),
            );
            status("ready");
            let pcm = stream::receive(
                local,
                profile,
                engine,
                changes,
                cancel.child_token(),
                status.clone(),
            );
            tokio::select! {biased;_=cancel.cancelled()=>Ok(()),result=usb=>result,result=pcm=>result,result=attached.failed()=>result}
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            anyhow::bail!("Native media receiver is unavailable on this platform")
        }
    };
    let identity_changes = super::config::refresh(profile);
    let policy = features::subscribe(profile);
    let initial_transport = transport_policy(&policy.borrow());
    // This independent watcher remains polled while the worker is awaiting a
    // stalled HTTP report. Existing private/direct routes must not outlive policy.
    let revoked = session_revoked(
        policy,
        identity_changes,
        feature,
        source,
        plan.identity.clone(),
        initial_transport,
    );
    tokio::select! {biased;_=parent.cancelled()=>Ok(()),_=revoked=>anyhow::bail!("Local native-media policy revoked"),result=&mut transport=>result,result=endpoint=>result}
}

fn transport_policy(policy: &features::Policy) -> [bool; 2] {
    [Feature::DirectConnections, Feature::PrivateNetwork].map(|feature| policy.enabled(feature))
}
async fn session_revoked(
    mut policy: tokio::sync::watch::Receiver<features::Policy>,
    mut identity: tokio::sync::watch::Receiver<
        Option<porthub_components::media_forward::UsbIdentity>,
    >,
    feature: Feature,
    source: bool,
    expected: porthub_components::media_forward::UsbIdentity,
    initial_transport: [bool; 2],
) {
    loop {
        let allowed = {
            let current = policy.borrow();
            current.enabled(feature) && transport_policy(&current) == initial_transport
        };
        if !allowed || (!source && identity.borrow().as_ref() != Some(&expected)) {
            return;
        }
        tokio::select! {
            changed=policy.changed()=>if changed.is_err(){return},
            changed=identity.changed(),if !source=>if changed.is_err(){return},
        }
    }
}
#[cfg(test)]
mod policy_tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn stalled_control_report_cannot_keep_a_disabled_transport_alive() -> Result<()> {
        for changed_feature in [
            Feature::PrivateNetwork,
            Feature::DirectConnections,
            Feature::MicrophoneShare,
        ] {
            let original = features::Policy::default();
            let initial_transport = transport_policy(&original);
            let (send, policy) = tokio::sync::watch::channel(original.clone());
            let expected = porthub_components::media_forward::UsbIdentity {
                vendor: 0x1209,
                product: 1,
            };
            let (_identity_send, identity) = tokio::sync::watch::channel(Some(expected.clone()));
            let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let observed = dropped.clone();
            struct Guard(Arc<std::sync::atomic::AtomicBool>);
            impl Drop for Guard {
                fn drop(&mut self) {
                    self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
            let (ready, started) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                let _guard = Guard(observed);
                let _ = ready.send(());
                // Both endpoint progress and the worker's report stay blocked.
                // The same independent session watcher must still stop ownership.
                tokio::select! {_=session_revoked(policy,identity,Feature::MicrophoneShare,true,expected,initial_transport)=>{},_=std::future::pending::<()>()=>{}}
            });
            started.await?;
            let mut unrelated = original.clone();
            unrelated.disabled.insert(Feature::Keyboard, true);
            send.send_replace(unrelated.clone());
            tokio::task::yield_now().await;
            assert!(!task.is_finished());
            let now = tokio::time::Instant::now();
            unrelated.disabled.insert(changed_feature, true);
            send.send_replace(unrelated);
            tokio::time::timeout(std::time::Duration::from_millis(1), task).await??;
            assert_eq!(now.elapsed(), std::time::Duration::ZERO);
            assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        }
        Ok(())
    }
}
