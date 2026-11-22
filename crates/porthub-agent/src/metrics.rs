//! Low-frequency, process-free host sampling. Local policy gates collection and upload.
mod disk_identity;
#[cfg(not(target_os = "macos"))]
mod disk_sampler;
mod drive_health;
mod gpu_counter;
mod integrated_gpu;
#[cfg(any(target_os = "macos", test))]
mod mac_disk_usage;
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
        #[cfg(not(target_os = "macos"))]
        let mut disks = disk_sampler::Sampler::default();
        #[cfg(target_os = "macos")]
        let mac_disks = mac_disk_usage::Worker::start(path.clone(), cancel.clone());
        let mut native_cpu = NativeCpu::default();
        let mut integrated_gpu = integrated_gpu::Cache::default();
        let drive_health = drive_health::Worker::start(path.clone(), cancel.clone());
        let mut primed = false;
        let mut legacy_until = None;
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tick.tick() => {},
                changed = policy.changed() => {
                    if changed.is_err() { break; }
                    primed = false;
                    #[cfg(not(target_os = "macos"))]
                    disks.invalidate();
                    continue;
                }
            }
            if !policy.borrow().enabled(Feature::Metrics) {
                #[cfg(not(target_os = "macos"))]
                disks.invalidate();
                primed = false;
                continue;
            }
            system.refresh_cpu_usage();
            let measured_cpu = native_cpu
                .sample()
                .or_else(|| (!system.cpus().is_empty()).then(|| system.global_cpu_usage()))
                .filter(|v| v.is_finite());
            if !primed {
                primed = true;
                continue;
            }
            system.refresh_memory();
            #[cfg(not(target_os = "macos"))]
            let (drives, disk) = disks.sample();
            #[cfg(target_os = "macos")]
            let (drives, disk) = {
                let drives = mac_disks.sample();
                let disk = mac_disk_usage::aggregate(&drives);
                (drives, disk)
            };
            let mut gpus = gpus().await;
            if gpus.is_empty() {
                gpus = integrated_gpu.sample().await;
            }
            drive_health.cpu(measured_cpu.unwrap_or(100.));
            let drive_health_enabled = policy.borrow().enabled(Feature::DriveHealth);
            let sample = Sample {
                cpu: measured_cpu.unwrap_or(0.).clamp(0., 100.),
                cpu_available: measured_cpu.is_some(),
                cores: system.cpus().len().max(
                    std::thread::available_parallelism()
                        .map(|n| n.get())
                        .unwrap_or(1),
                ) as u32,
                ram: Memory {
                    used: system.used_memory(),
                    total: system.total_memory(),
                },
                disk,
                gpus,
                disks: drives,
                drive_health: if drive_health_enabled {
                    drive_health.snapshot()
                } else {
                    Vec::new()
                },
                drive_health_enabled,
                drive_tests_enabled: policy.borrow().enabled(Feature::DriveTests),
            };
            if !sample.valid() || !features::enabled(&path, Feature::Metrics) {
                tracing::warn!("Host metrics unavailable: an OS reading did not satisfy the bounded metrics schema");
                continue;
            }
            let p = control.profile();
            let body =
                serde_json::json!({"machine_id":p.machine_id,"token":p.token,"sample":sample});
            tokio::select! {biased;_=cancel.cancelled()=>break,changed=policy.changed()=>{if changed.is_err(){break;}primed=false;
                #[cfg(not(target_os = "macos"))] disks.invalidate();
            },_=upload(body, &mut legacy_until, |body| {let control=&control; async move {control.request(reqwest::Method::POST,"machines/client/metrics",Some(body),&[]).await.map(|_| ())}})=>{}}
        }
    }))
}
// Older gateways reject unknown report fields. Keep basic readings flowing while
// periodically checking whether the gateway has gained the extended schema.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReportFormat { Modern, WithoutExtendedDetails, Basic }
struct ReportCompatibility { format: ReportFormat, until: std::time::Instant }
async fn upload<F, Fut>(
    body: serde_json::Value,
    legacy_until: &mut Option<ReportCompatibility>,
    mut send: F,
) -> Result<(), crate::control::Failure>
where
    F: FnMut(serde_json::Value) -> Fut,
    Fut: std::future::Future<Output = Result<(), crate::control::Failure>>,
{
    if legacy_until.as_ref().is_some_and(|saved| saved.until <= std::time::Instant::now()) { *legacy_until = None; }
    let initial = legacy_until.as_ref().map(|saved| saved.format).unwrap_or(ReportFormat::Modern);
    let has_extended_details = body["sample"]["drive_health"].as_array().is_some_and(|drives| drives.iter().any(|drive| ["reported_uncorrectable_errors", "lifetime_read_bytes", "lifetime_written_bytes"].iter().any(|key| drive.get(*key).is_some()))) || body["sample"]["gpus"].as_array().is_some_and(|gpus| gpus.iter().any(|gpu| ["shared_memory", "shared_memory_capacity", "integrated"].iter().any(|key| gpu.get(*key).is_some())));
    let mut format = initial;
    loop {
        let report = match format {
            ReportFormat::Modern => body.clone(),
            ReportFormat::WithoutExtendedDetails => extended_legacy_report(body.clone()),
            ReportFormat::Basic => legacy_report(body.clone()),
        };
        match send(report).await {
            Ok(()) => {
                if format == ReportFormat::Modern { *legacy_until = None; }
                else if format != initial || legacy_until.is_none() {
                    *legacy_until = Some(ReportCompatibility {format, until: std::time::Instant::now() + Duration::from_secs(60)});
                }
                return Ok(());
            }
            Err(crate::control::Failure::Rejected(400 | 422)) if format != ReportFormat::Basic => {
                format = if format == ReportFormat::Modern && has_extended_details { ReportFormat::WithoutExtendedDetails } else { ReportFormat::Basic };
            }
            Err(error) => return Err(error),
        }
    }
}
fn extended_legacy_report(mut body: serde_json::Value) -> serde_json::Value {
    if let Some(drives) = body["sample"]["drive_health"].as_array_mut() {
        for drive in drives.iter_mut().filter_map(|d| d.as_object_mut()) {
            for key in ["reported_uncorrectable_errors", "lifetime_read_bytes", "lifetime_written_bytes"] { drive.remove(key); }
        }
    }
    if let Some(gpus) = body.get_mut("sample").and_then(|s| s.get_mut("gpus")).and_then(|g| g.as_array_mut()) {
        for gpu in gpus {
            if let Some(gpu) = gpu.as_object_mut() {
                for key in ["shared_memory", "shared_memory_capacity", "integrated"] { gpu.remove(key); }
            }
        }
    }
    body
}
fn legacy_report(body: serde_json::Value) -> serde_json::Value {
    let mut body = extended_legacy_report(body);
    if let Some(sample) = body.get_mut("sample").and_then(|v| v.as_object_mut()) {
        sample.remove("disks");
        sample.remove("drive_health");
        sample.remove("cpu_available");
        sample.remove("drive_health_enabled");
        sample.remove("drive_tests_enabled");
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
                id: Some(integrated_gpu::label(p[0], 128)),
                name: integrated_gpu::label(p[1], 120),
                shared_memory: None,
                shared_memory_capacity: None,
                integrated: None,
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
    async fn drive_detail_fallback_keeps_supported_health_on_old_gateways() {
        let body=serde_json::json!({"sample":{"drive_health":[{"id":"drive","status":"warning","reported_uncorrectable_errors":2,"lifetime_read_bytes":512000}]}});
        let mut sent=Vec::new();let mut until=None;
        upload(body,&mut until,|report|{
            let unsupported=report["sample"]["drive_health"][0].get("reported_uncorrectable_errors").is_some();sent.push(report);
            std::future::ready(if unsupported{Err(crate::control::Failure::Rejected(422))}else{Ok(())})
        }).await.unwrap();
        assert_eq!(sent.len(),2);
        assert_eq!(sent[1]["sample"]["drive_health"][0]["status"],"warning");
        assert!(sent[1]["sample"]["drive_health"][0].get("lifetime_read_bytes").is_none());
    }
    #[tokio::test]
    async fn gpu_detail_fallback_preserves_drive_history_and_handles_gateway_changes() {
        use crate::control::Failure;
        let body=serde_json::json!({"sample":{"cpu":1,"cores":2,"ram":{"used":1,"total":2},"disk":{"used":1,"total":2},"cpu_available":true,"disks":[],"drive_health":[],"drive_health_enabled":true,"gpus":[{"id":"intel","name":"Intel GPU","utilization":0,"memory":{"used":0,"total":128},"shared_memory":{"used":237,"total":8192},"shared_memory_capacity":8192,"integrated":true}]}});
        let mut until=None;let mut sent=Vec::new();
        upload(body.clone(),&mut until,|report|{
            let unsupported=report["sample"]["gpus"][0].get("shared_memory_capacity").is_some();sent.push(report);
            std::future::ready(if unsupported{Err(Failure::Rejected(422))}else{Ok(())})
        }).await.unwrap();
        assert_eq!(sent.len(),2);
        for key in ["disks","drive_health","drive_health_enabled","cpu_available"] {assert_eq!(sent[1]["sample"][key],body["sample"][key]);}
        assert_eq!(sent[1]["sample"]["gpus"][0]["id"],"intel");
        assert_eq!(sent[1]["sample"]["gpus"][0]["memory"],body["sample"]["gpus"][0]["memory"]);
        assert!(sent[1]["sample"]["gpus"][0].get("shared_memory").is_none());
        let deadline=until.as_ref().unwrap().until;sent.clear();
        upload(body.clone(),&mut until,|report|{sent.push(report);std::future::ready(Ok(()))}).await.unwrap();
        assert_eq!(sent.len(),1);assert_eq!(until.as_ref().unwrap().until,deadline,"cached success must not postpone the upgrade probe forever");
        sent.clear();
        upload(body.clone(),&mut until,|report|{let old=report["sample"].get("disks").is_some();sent.push(report);std::future::ready(if old{Err(Failure::Rejected(422))}else{Ok(())})}).await.unwrap();
        assert_eq!(sent.len(),2);assert!(sent[1]["sample"].get("disks").is_none());
        until.as_mut().unwrap().until=std::time::Instant::now()-Duration::from_secs(1);sent.clear();
        upload(body.clone(),&mut until,|report|{sent.push(report);std::future::ready(Ok(()))}).await.unwrap();
        assert!(until.is_none());assert_eq!(sent[0],body);
        for status in [401,403,503] {let mut calls=0;let mut fresh=None;assert!(upload(body.clone(),&mut fresh,|_|{calls+=1;std::future::ready(Err(Failure::Rejected(status)))}).await.is_err());assert_eq!(calls,1);assert!(fresh.is_none());}
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
        until = Some(ReportCompatibility { format: ReportFormat::Basic, until: std::time::Instant::now() - Duration::from_secs(1) });
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

#[derive(Default)]
struct NativeCpu {
    #[cfg(windows)]
    previous: Option<(u64, u64, u64)>,
}
impl NativeCpu {
    fn sample(&mut self) -> Option<f32> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetSystemTimes};
            let mut idle: FILETIME = unsafe { std::mem::zeroed() };
            let mut kernel = idle;
            let mut user = idle;
            if unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) } == 0 {
                return None;
            }
            let ticks = |v: FILETIME| ((v.dwHighDateTime as u64) << 32) | v.dwLowDateTime as u64;
            let current = (ticks(idle), ticks(kernel), ticks(user));
            let previous = self.previous.replace(current)?;
            let total = current
                .1
                .saturating_sub(previous.1)
                .saturating_add(current.2.saturating_sub(previous.2));
            if total == 0 {
                return None;
            }
            return Some(
                (100. * (1. - current.0.saturating_sub(previous.0) as f64 / total as f64)) as f32,
            );
        }
        #[cfg(not(windows))]
        {
            None
        }
    }
}
