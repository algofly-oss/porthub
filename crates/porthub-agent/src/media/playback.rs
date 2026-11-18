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
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
pub async fn run(
    profile: &Path,
    control: Arc<Control>,
    plan: &Plan,
    cancel: CancellationToken,
    status: Status,
) -> Result<()> {
    let cancel = cancel.child_token();
    let _stop = Stop(cancel.clone());
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
        let (network_read, mut network_write) = tokio::io::split(local);
        let mut network_read = host_wire::Reader::new(
            Box::new(network_read) as Box<dyn tokio::io::AsyncRead + Send + Unpin>
        );
        // Capture must not run ahead of the receiver's actual native render ACK.
        if !render {
            wait_renderer_ready(&mut network_read, &plan.id).await?;
        }
        let desktop = broker::playback(
            profile,
            (!render).then_some((plan.desktop_uid, plan.desktop_session.as_deref())),
            &plan.source_id,
            render,
            &cancel,
        )
        .await?;
        status(if render { "rendering" } else { "capturing" });
        if render {
            host_wire::json(
                &mut network_write,
                &serde_json::to_value(RendererReady {
                    version: 1,
                    plan: plan.id.clone(),
                })?,
            )
            .await?;
        }
        let (mut input, mut output) = if render {
            let (_, w) = tokio::io::split(desktop);
            (
                network_read,
                Box::new(w) as Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
            )
        } else {
            let (r, _) = tokio::io::split(desktop);
            (
                host_wire::Reader::new(Box::new(r) as Box<dyn tokio::io::AsyncRead + Send + Unpin>),
                Box::new(network_write) as Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
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

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RendererReady {
    version: u8,
    plan: String,
}
fn validate_renderer_ready(bytes: &[u8], plan: &str) -> Result<()> {
    ensure!(bytes.len() <= 128, "Speaker readiness exceeds bound");
    let ready: RendererReady = serde_json::from_slice(bytes)?;
    ensure!(
        ready.version == 1 && ready.plan == plan,
        "Speaker renderer readiness belongs to another plan"
    );
    Ok(())
}
#[derive(Debug)]
pub(super) struct RendererNotReady;
impl std::fmt::Display for RendererNotReady {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Speaker receiver did not become ready; check it and update both clients")
    }
}
impl std::error::Error for RendererNotReady {}
async fn wait_renderer_ready<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut host_wire::Reader<R>,
    plan: &str,
) -> Result<()> {
    let bytes = tokio::time::timeout(Duration::from_secs(10), reader.next())
        .await
        .map_err(|_| RendererNotReady)??;
    validate_renderer_ready(&bytes, plan)
}
/// A bounded local audio queue must not hold desktop control processing.
pub(super) fn enqueue_pcm(tx: &tokio::sync::mpsc::Sender<Vec<u8>>, frame: Vec<u8>) -> Result<bool> {
    ensure!(
        frame.len() <= porthub_components::media::MAX_NETWORK_FRAME + 33,
        "Speaker frame exceeds bound"
    );
    match tx.try_send(frame) {
        Ok(()) => Ok(true),
        Err(
            tokio::sync::mpsc::error::TrySendError::Full(mut frame)
            | tokio::sync::mpsc::error::TrySendError::Closed(mut frame),
        ) => {
            frame.fill(0);
            Ok(false)
        }
    }
}
#[cfg(test)]
mod queue_tests {
    use super::*;
    #[tokio::test]
    async fn capture_waits_for_exact_renderer_ready() -> Result<()> {
        let (a, b) = tokio::io::duplex(1024);
        let plan = "b".repeat(32);
        let expected = plan.clone();
        let task = tokio::spawn(async move {
            let mut reader = host_wire::Reader::new(a);
            wait_renderer_ready(&mut reader, &expected).await
        });
        tokio::task::yield_now().await;
        assert!(!task.is_finished(), "No capture before native renderer ACK");
        let mut b = b;
        host_wire::json(&mut b, &serde_json::json!({"version":1,"plan":plan})).await?;
        task.await??;
        assert!(validate_renderer_ready(br#"{"version":1,"plan":"foreign"}"#, &plan).is_err());
        assert!(validate_renderer_ready(br#"{"version":2,"plan":"foreign"}"#, &plan).is_err());
        assert!(
            validate_renderer_ready(br#"{"version":1,"plan":"foreign","extra":true}"#, &plan)
                .is_err()
        );
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn old_receiver_without_ack_times_out_without_capture() -> Result<()> {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let (a, _peer) = tokio::io::duplex(1024);
        let captured = Arc::new(AtomicBool::new(false));
        let flag = captured.clone();
        let task = tokio::spawn(async move {
            let mut reader = host_wire::Reader::new(a);
            wait_renderer_ready(&mut reader, &"a".repeat(32)).await?;
            flag.store(true, Ordering::SeqCst);
            Ok::<(), anyhow::Error>(())
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(!task.is_finished());
        assert!(!captured.load(Ordering::SeqCst));
        tokio::time::advance(Duration::from_secs(1)).await;
        let error = task.await?.unwrap_err();
        assert!(error.is::<RendererNotReady>());
        assert!(!captured.load(Ordering::SeqCst));
        Ok(())
    }
    #[test]
    fn startup_burst_and_late_frames_do_not_disconnect_desktop() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut accepted = 0;
        for _ in 0..32 {
            if enqueue_pcm(&tx, vec![0; 192])
                .expect("bounded startup burst must not disconnect desktop")
            {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 4);
        for _ in 0..4 {
            assert_eq!(rx.try_recv().unwrap().len(), 192);
        }
        assert!(rx.try_recv().is_err());
        drop(rx);
        assert!(!enqueue_pcm(&tx, vec![0; 192]).unwrap());
        assert!(enqueue_pcm(
            &tx,
            vec![0; porthub_components::media::MAX_NETWORK_FRAME + 34]
        )
        .is_err());
    }
}
