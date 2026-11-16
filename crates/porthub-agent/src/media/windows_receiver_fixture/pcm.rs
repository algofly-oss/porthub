//! Test-only counters for accepted Windows PCM; no audio bytes are retained.
use super::{Config, ENV};
use anyhow::{ensure, Context, Result};
use porthub_components::{
    media::{Kind, PcmFrame},
    media_forward::Plan,
};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
#[derive(Default)]
struct Counts {
    frames: u64,
    samples: u64,
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
    first_offset: Option<u64>,
    last_end: u64,
    first_source_time: Option<u64>,
    last_source_time: u64,
    first_arrival: Option<Instant>,
    last_arrival: Option<Instant>,
}
pub(crate) struct PcmProof {
    root: PathBuf,
    plan_id: String,
    epoch: String,
    active: bool,
    consumer_nonce: Option<String>,
    counts: Counts,
    last_write: Instant,
}
impl PcmProof {
    pub(crate) fn new(profile: &Path) -> Result<Option<Self>> {
        if std::env::var_os(ENV).is_none() {
            return Ok(None);
        }
        let c = Config::load()?;
        c.approve()?;
        ensure!(
            c.kind == Kind::Microphone,
            "PCM proof cannot attest camera data"
        );
        let input = crate::profile::Profile::load(&c.profile)?;
        let registered = c
            .layout()
            .state
            .join(format!("{}.json", crate::service::identity(&input)));
        ensure!(profile == registered, "PCM proof registration differs");
        let plan: Plan = serde_json::from_slice(&crate::profile::read_private(
            &c.root.join("receiver-plan.json"),
        )?)?;
        ensure!(
            plan.valid()
                && plan.kind() == Some(c.kind)
                && plan.source_id == c.source_id
                && plan.desktop_uid == 0
                && plan.desktop_session.as_deref() == Some(c.desktop_session.as_str()),
            "PCM proof plan/source/principal differs"
        );
        Ok(Some(Self {
            root: c.root,
            plan_id: plan.id,
            epoch: String::new(),
            active: false,
            consumer_nonce: None,
            counts: Counts::default(),
            last_write: Instant::now(),
        }))
    }
    pub(crate) fn begin(&mut self, epoch: &str, active: bool) -> Result<()> {
        ensure!(
            epoch.len() == 32 && epoch.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid PCM proof epoch"
        );
        if self.counts.samples > 0 {
            self.write(true)?;
        }
        self.epoch = epoch.to_owned();
        self.active = active;
        self.counts = Counts::default();
        self.consumer_nonce = None;
        if active {
            let path = self.root.join("consumer-intent.json");
            if path.exists() {
                let bytes = crate::profile::read_private(&path)?;
                ensure!(bytes.len() <= 4096, "Consumer intent exceeds bound");
                let value: serde_json::Value = serde_json::from_slice(&bytes)?;
                let nonce = value["nonce"].as_str().context("Consumer nonce required")?;
                ensure!(
                    nonce.len() == 32
                        && nonce.bytes().all(|b| b.is_ascii_hexdigit())
                        && value["plan_id"] == self.plan_id,
                    "PCM consumer intent differs"
                );
                self.consumer_nonce = Some(nonce.to_owned());
            }
        }
        self.write(false)
    }
    pub(crate) fn record(&mut self, epoch: &str, frame: &PcmFrame) -> Result<()> {
        ensure!(
            self.active && epoch == self.epoch,
            "Retired PCM proof epoch"
        );
        let samples = frame.pcm.len() / 4;
        ensure!(
            samples > 0 && frame.pcm.len() % 4 == 0,
            "Invalid accepted PCM size"
        );
        let c = &mut self.counts;
        if let Some(last) = c.last_sequence {
            ensure!(
                frame.sequence > last
                    && frame.sample_offset >= c.last_end
                    && frame.source_monotonic_micros >= c.last_source_time,
                "Replayed PCM proof metadata"
            );
        }
        c.frames = c
            .frames
            .checked_add(1)
            .context("PCM frame count overflow")?;
        c.samples = c
            .samples
            .checked_add(samples as u64)
            .context("PCM sample count overflow")?;
        c.first_sequence.get_or_insert(frame.sequence);
        c.last_sequence = Some(frame.sequence);
        c.first_offset.get_or_insert(frame.sample_offset);
        c.last_end = frame
            .sample_offset
            .checked_add(samples as u64)
            .context("PCM offset overflow")?;
        c.first_source_time
            .get_or_insert(frame.source_monotonic_micros);
        c.last_source_time = frame.source_monotonic_micros;
        let now = Instant::now();
        c.first_arrival.get_or_insert(now);
        c.last_arrival = Some(now);
        if c.frames == 1 || self.last_write.elapsed() >= Duration::from_millis(250) {
            self.write(false)?;
        }
        Ok(())
    }
    fn write(&mut self, completed: bool) -> Result<()> {
        let c = &self.counts;
        let span = c
            .first_source_time
            .map(|first| c.last_source_time.saturating_sub(first))
            .unwrap_or(0);
        let arrival = match (c.first_arrival, c.last_arrival) {
            (Some(a), Some(b)) => b.duration_since(a).as_micros(),
            _ => 0,
        };
        let value = json!({"plan_id":self.plan_id,"epoch":self.epoch,"active":self.active&&!completed,"completed":completed,"consumer_nonce":self.consumer_nonce,"frames":c.frames,"accepted_samples":c.samples,"first_sequence":c.first_sequence,"last_sequence":c.last_sequence,"first_sample_offset":c.first_offset,"last_sample_end":c.last_end,"source_span_micros":span,"arrival_span_micros":arrival,"rate":48000,"pcm_saved":false});
        let filename = if completed {
            "accepted-pcm-completed.json"
        } else {
            "accepted-pcm-current.json"
        };
        crate::profile::write_private(
            &self.root.join(filename),
            &serde_json::to_vec(&value)?,
            true,
        )?;
        self.last_write = Instant::now();
        Ok(())
    }
}
impl Drop for PcmProof {
    fn drop(&mut self) {
        if self.counts.samples > 0 {
            let _ = self.write(true);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_pcm_proof_rejects_old_epoch_and_never_aggregates_retired_data() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().to_path_buf();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root,std::fs::Permissions::from_mode(0o700))?;
        let mut proof = PcmProof {
            root: root.clone(),
            plan_id: "a".repeat(32),
            epoch: String::new(),
            active: false,
            consumer_nonce: None,
            counts: Counts::default(),
            last_write: Instant::now(),
        };
        let epoch = "b".repeat(32);
        crate::profile::write_private(&root.join("consumer-intent.json"),&serde_json::to_vec(&json!({"nonce":"e".repeat(32),"plan_id":"a".repeat(32)}))?,false)?;
        proof.begin(&epoch, true)?;
        let frame = PcmFrame {
            sequence: 0,
            sample_offset: 0,
            source_monotonic_micros: 0,
            pcm: vec![0; 3840],
        };
        proof.record(&epoch, &frame)?;
        assert!(proof.record(&epoch, &frame).is_err());
        proof.begin(&"c".repeat(32), false)?;
        assert!(proof.record(&epoch, &frame).is_err());
        let old: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("accepted-pcm-completed.json"))?)?;
        assert_eq!(old["accepted_samples"], 960);
        assert_eq!(old["consumer_nonce"],"e".repeat(32));
        assert_eq!(old["active"],false);
        assert_eq!(old["pcm_saved"], false);
        assert!(old.get("pcm").is_none());
        proof.begin(&"d".repeat(32), true)?;
        assert_eq!(proof.counts.samples, 0);
        assert!(proof.record(&epoch, &frame).is_err());
        proof.record(&"d".repeat(32), &frame)?;
        assert_eq!(proof.counts.samples, 960);
        Ok(())
    }
    #[test]
    fn windows_pcm_proof_throttles_writes_and_flushes_only_metadata()->Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir=tempfile::tempdir()?;let root=dir.path().to_path_buf();std::fs::set_permissions(&root,std::fs::Permissions::from_mode(0o700))?;
        let mut proof=PcmProof{root:root.clone(),plan_id:"a".repeat(32),epoch:String::new(),active:false,consumer_nonce:None,counts:Counts::default(),last_write:Instant::now()};let epoch="b".repeat(32);proof.begin(&epoch,true)?;
        for i in 0..10 {proof.record(&epoch,&PcmFrame{sequence:i,sample_offset:i*960,source_monotonic_micros:i*20000,pcm:vec![0;3840]})?;}
        let current:serde_json::Value=serde_json::from_slice(&std::fs::read(root.join("accepted-pcm-current.json"))?)?;assert_eq!(current["frames"],1);assert_eq!(proof.counts.frames,10);
        proof.begin(&"c".repeat(32),false)?;let done:serde_json::Value=serde_json::from_slice(&std::fs::read(root.join("accepted-pcm-completed.json"))?)?;assert_eq!(done["accepted_samples"],9600);assert_eq!(done["source_span_micros"],180000);assert!(done.get("pcm").is_none());Ok(())
    }
}
