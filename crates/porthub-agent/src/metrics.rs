//! Low-frequency, process-free host sampling. Local policy gates collection and upload.
use crate::{
    control::Control,
    features::{self, Feature},
};
use porthub_components::metrics::{Disk, Gpu, Memory, Sample};
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
        let mut legacy_until = None;
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
            let mut drives = Vec::new();
            let mut disk = Memory { used: 0, total: 0 };
            for d in disks.list() {
                if matches!(d.file_system().to_str(), Some("overlay" | "aufs"))
                    || d.total_space() == 0
                    || !seen.insert(d.name().to_os_string())
                {
                    continue;
                }
                if drives.len() >= 128 {
                    continue;
                }
                let name = d.name().to_string_lossy().to_string();
                drives.push(Disk {
                    id: name.chars().take(256).collect(),
                    name: name.chars().take(120).collect(),
                    used: d.total_space().saturating_sub(d.available_space()),
                    total: d.total_space(),
                });
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
                disks: drives,
            };
            if !sample.valid() || !features::enabled(&path, Feature::Metrics) {
                continue;
            }
            let p = control.profile();
            let body =
                serde_json::json!({"machine_id":p.machine_id,"token":p.token,"sample":sample});
            tokio::select! {biased;_=cancel.cancelled()=>break,changed=policy.changed()=>{if changed.is_err(){break;}primed=false;},_=upload(body, &mut legacy_until, |body| {let control=&control; async move {control.request(reqwest::Method::POST,"machines/client/metrics",Some(body),&[]).await.map(|_| ())}})=>{}}
        }
    }))
}
// Older gateways reject unknown report fields. Keep basic readings flowing while
// periodically checking whether the gateway has gained the extended schema.
async fn upload<F, Fut>(
    body: serde_json::Value,
    legacy_until: &mut Option<std::time::Instant>,
    mut send: F,
) -> Result<(), crate::control::Failure>
where
    F: FnMut(serde_json::Value) -> Fut,
    Fut: std::future::Future<Output = Result<(), crate::control::Failure>>,
{
    if legacy_until.is_some_and(|until| until > std::time::Instant::now()) {
        return send(legacy_report(body)).await;
    }
    *legacy_until = None;
    match send(body.clone()).await {
        Err(crate::control::Failure::Rejected(400 | 422)) => {
            send(legacy_report(body)).await?;
            *legacy_until = Some(std::time::Instant::now() + Duration::from_secs(60));
            Ok(())
        }
        result => result,
    }
}
fn legacy_report(mut body: serde_json::Value) -> serde_json::Value {
    if let Some(sample) = body.get_mut("sample").and_then(|v| v.as_object_mut()) {
        sample.remove("disks");
        if let Some(gpus) = sample.get_mut("gpus").and_then(|v| v.as_array_mut()) {
            for gpu in gpus {
                if let Some(gpu) = gpu.as_object_mut() {
                    for key in ["id", "temperature", "fan_speed"] {
                        gpu.remove(key);
                    }
                }
            }
        }
    }
    body
}
async fn gpus() -> Vec<Gpu> {
    // NVIDIA's installed driver utility is optional; never load inference libraries.
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::process::Command::new("nvidia-smi")
            .args([
                "--query-gpu=uuid,name,utilization.gpu,memory.used,memory.total,temperature.gpu,fan.speed",
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
    parse_gpus(&String::from_utf8_lossy(&output.stdout))
}
fn parse_gpus(output: &str) -> Vec<Gpu> {
    output
        .lines()
        .take(16)
        .filter_map(|line| {
            let p: Vec<_> = line.split(',').map(str::trim).collect();
            if p.len() != 7 {
                return None;
            }
            let number = |s: &str| s.parse::<f32>().ok().filter(|v| v.is_finite());
            Some(Gpu {
                id: Some(p[0].chars().take(128).collect()),
                name: p[1].chars().take(120).collect(),
                utilization: number(p[2]).filter(|v| (0.0..=100.0).contains(v)),
                memory: p[3]
                    .parse::<u64>()
                    .ok()
                    .zip(p[4].parse::<u64>().ok())
                    .filter(|(used, total)| used <= total)
                    .map(|(used, total)| Memory {
                        used: used.saturating_mul(1048576),
                        total: total.saturating_mul(1048576),
                    }),
                temperature: number(p[5]).filter(|v| (-40.0..=150.0).contains(v)),
                fan_speed: number(p[6]).filter(|v| (0.0..=100.0).contains(v)),
            })
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gpu_sensors_preserve_missing_values_and_device_identity() {
        let readings = parse_gpus("GPU-a, Same GPU, 75, 1024, 8192, 62, 40\nGPU-b, Same GPU, 20, 512, 8192, N/A, [Not Supported]");
        assert_eq!(readings.len(), 2);
        assert_ne!(readings[0].id, readings[1].id);
        assert_eq!(readings[0].temperature, Some(62.));
        assert_eq!(readings[0].fan_speed, Some(40.));
        assert_eq!(readings[0].memory.as_ref().unwrap().used, 1073741824);
        assert_eq!(readings[1].temperature, None);
        assert_eq!(readings[1].fan_speed, None);
    }
    #[tokio::test]
    async fn older_gateways_keep_basic_metrics_and_upgrade_without_auth_retries() {
        use crate::control::Failure;
        let body = serde_json::json!({"machine_id":"fixture","token":"fixture-secret","sample":{"cpu":42,"cores":8,"ram":{"used":4,"total":8},"disk":{"used":20,"total":100},"disks":[],"gpus":[{"id":"gpu-a","name":"GPU","utilization":70,"temperature":60,"fan_speed":40,"memory":{"used":2,"total":8}}]}});
        let mut until = None;
        let mut sent = Vec::new();
        upload(body.clone(), &mut until, |report| {
            let rejected = report["sample"].get("disks").is_some();
            sent.push(report);
            std::future::ready(if rejected {
                Err(Failure::Rejected(422))
            } else {
                Ok(())
            })
        })
        .await
        .unwrap();
        assert_eq!(sent.len(), 2);
        assert!(until.is_some());
        assert_eq!(sent[1]["token"], body["token"]);
        for key in ["cpu", "cores", "ram", "disk"] {
            assert_eq!(sent[1]["sample"][key], body["sample"][key]);
        }
        assert_eq!(
            sent[1]["sample"]["gpus"][0]["memory"],
            body["sample"]["gpus"][0]["memory"]
        );
        assert!(sent[1]["sample"]["gpus"][0].get("id").is_none());
        sent.clear();
        upload(body.clone(), &mut until, |r| {
            sent.push(r);
            std::future::ready(Ok(()))
        })
        .await
        .unwrap();
        assert_eq!(sent.len(), 1);
        assert!(sent[0]["sample"].get("disks").is_none());
        until = Some(std::time::Instant::now() - Duration::from_secs(1));
        sent.clear();
        upload(body.clone(), &mut until, |r| {
            sent.push(r);
            std::future::ready(Ok(()))
        })
        .await
        .unwrap();
        assert!(until.is_none());
        assert!(sent[0]["sample"].get("disks").is_some());
        for status in [401, 403, 503] {
            let mut calls = 0;
            let mut until = None;
            assert!(upload(body.clone(), &mut until, |_| {
                calls += 1;
                std::future::ready(Err(Failure::Rejected(status)))
            })
            .await
            .is_err());
            assert_eq!(calls, 1);
            assert!(until.is_none());
        }
    }
}
