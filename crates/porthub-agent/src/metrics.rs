//! Low-frequency, process-free host sampling. Local policy gates collection and upload.
use crate::{
    control::Control,
    features::{self, Feature},
};
use porthub_components::metrics::{Gpu, Memory, Sample};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
pub struct Worker(tokio::task::JoinHandle<()>);
impl Drop for Worker {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub fn start(path: PathBuf, control: Arc<Control>, cancel: CancellationToken) -> Worker {
    Worker(tokio::spawn(async move {
        let mut policy = features::subscribe(&path);
        let mut system = sysinfo::System::new();
        let mut disks = sysinfo::Disks::new();
        let mut primed = false;
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {_ = cancel.cancelled()=>break,_ = tick.tick()=>{}, changed=policy.changed()=>{if changed.is_err(){break;}primed=false;continue;}}
            if !policy.borrow().enabled(Feature::Metrics) {
                primed = false;
                continue;
            }
            system.refresh_cpu_usage();
            if !primed {
                primed = true;
                continue;
            }
            system.refresh_memory();
            disks.refresh(true);
            // Exclude network/virtual mounts and count each physical filesystem once.
            let mut seen = std::collections::HashSet::new();
            let mut disk = Memory { used: 0, total: 0 };
            for d in disks.list() {
                if matches!(d.file_system().to_str(), Some("overlay" | "aufs"))
                    || d.total_space() == 0
                    || !seen.insert(d.name().to_os_string())
                {
                    continue;
                }
                disk.total = disk.total.saturating_add(d.total_space());
                disk.used = disk
                    .used
                    .saturating_add(d.total_space().saturating_sub(d.available_space()));
            }
            let gpus = gpus().await;
            let sample = Sample {
                cpu: system.global_cpu_usage().clamp(0., 100.),
                cores: system.cpus().len() as u32,
                ram: Memory {
                    used: system.used_memory(),
                    total: system.total_memory(),
                },
                disk,
                gpus,
            };
            if !sample.valid() || !features::enabled(&path, Feature::Metrics) {
                continue;
            }
            let p = control.profile();
            let body =
                serde_json::json!({"machine_id":p.machine_id,"token":p.token,"sample":sample});
            tokio::select! {biased;_=cancel.cancelled()=>break,changed=policy.changed()=>{if changed.is_err(){break;}primed=false;},_=control.request(reqwest::Method::POST,"machines/client/metrics",Some(body),&[])=>{}}
        }
    }))
}
async fn gpus() -> Vec<Gpu> {
    // NVIDIA's installed driver utility is optional; never load inference libraries.
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::process::Command::new("nvidia-smi")
            .args([
                "--query-gpu=name,utilization.gpu,memory.used,memory.total",
                "--format=csv,noheader,nounits",
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let Ok(Ok(output)) = result else {
        return vec![];
    };
    if !output.status.success() {
        return vec![];
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .take(16)
        .filter_map(|line| {
            let parts: Vec<_> = line.split(',').map(str::trim).collect();
            if parts.len() != 4 {
                return None;
            }
            let memory = parts[2]
                .parse::<u64>()
                .ok()
                .zip(parts[3].parse::<u64>().ok())
                .map(|(used, total)| Memory {
                    used: used.saturating_mul(1048576),
                    total: total.saturating_mul(1048576),
                });
            Some(Gpu {
                name: parts[0].chars().take(120).collect(),
                utilization: parts[1].parse().ok(),
                memory,
            })
        })
        .collect()
}
