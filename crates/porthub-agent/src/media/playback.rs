//! PCM: source captures its selected output monitor; destination renders
//! to its own default speaker. Every byte remains in the authorized plan.
use super::{broker, host_wire, stream::Status};
use crate::{
    control::Control,
    features::{self, Feature},
};
use anyhow::{ensure, Context, Result};
use porthub_components::{media::PcmContinuity, media_forward::Plan};
use std::{path::Path, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
struct Stop(CancellationToken);
impl Drop for Stop {fn drop(&mut self){self.0.cancel();}}
pub async fn run(
    profile: &Path,
    control: Arc<Control>,
    plan: &Plan,
    cancel: CancellationToken,
    status: Status,
) -> Result<()> {
    let cancel=cancel.child_token();let _stop=Stop(cancel.clone());
    let render = control.profile().machine_id == plan.destination;
    ensure!(
        render || control.profile().machine_id == plan.source,
        "Wrong speaker endpoint"
    );
    ensure!(
        features::enabled(profile, Feature::MediaReceive),
        "Speaker forwarding disabled locally"
    );
    let (local, network) = tokio::io::duplex(19200);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let transport = crate::usb::media_transport::transfer_speaker(
        network,
        profile,
        control,
        &plan.id,
        !render,
        cancel.clone(),
        tx,
    );
    let endpoint = async {
        tokio::time::timeout(Duration::from_secs(60), rx)
            .await?
            .context("Speaker carrier unavailable")?;
        let desktop = broker::playback(
            profile,
            (!render).then_some((plan.desktop_uid, plan.desktop_session.as_deref())),
            &plan.source_id,
            render,
            &cancel,
        )
        .await?;
        status(if render { "rendering" } else { "capturing" });
        let (mut input, mut output) = if render {
            let (r, _) = tokio::io::split(local);
            let (_, w) = tokio::io::split(desktop);
            (
                host_wire::Reader::new(Box::new(r) as Box<dyn tokio::io::AsyncRead + Send + Unpin>),
                Box::new(w) as Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
            )
        } else {
            let (r, _) = tokio::io::split(desktop);
            let (_, w) = tokio::io::split(local);
            (
                host_wire::Reader::new(Box::new(r) as Box<dyn tokio::io::AsyncRead + Send + Unpin>),
                Box::new(w) as Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
            )
        };
        let mut continuity = PcmContinuity::default();
        loop {
            let mut bytes = input.next().await?;
            ensure!(bytes.len() >= 33, "Invalid speaker frame");
            let epoch = std::str::from_utf8(&bytes[1..33])?;
            ensure!(!render || epoch == plan.id, "Speaker plan epoch changed");
            let mut frame = host_wire::parse_pcm(&bytes, epoch).context("Invalid speaker PCM")?;
            ensure!(continuity.accept(&frame), "Replayed speaker PCM");
            bytes.fill(0);
            let mut encoded = host_wire::pcm(&plan.id, &frame).context("Invalid speaker PCM")?;
            frame.pcm.fill(0);
            let result = host_wire::write(&mut output, &encoded).await;
            encoded.fill(0);
            result?;
        }
    };
    let mut policy = features::subscribe(profile);
    let revoked = async {
        loop {
            if !policy.borrow().enabled(Feature::MediaReceive) {
                break;
            }
            if policy.changed().await.is_err() {
                break;
            }
        }
    };
    tokio::select! {biased;_=cancel.cancelled()=>Ok(()),_=revoked=>anyhow::bail!("Speaker permission revoked"),result=transport=>result,result=endpoint=>result}
}
