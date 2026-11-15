//! Inventory integrated/driver-supported GPUs without guessing unsupported sensors.
use super::*;
#[cfg(windows)]
mod windows;
#[cfg(not(target_os = "linux"))]
use std::time::Instant;
#[derive(Default)]
pub(super) struct Cache {
    #[cfg(not(target_os = "linux"))]
    inventory: Vec<Gpu>,
    #[cfg(not(target_os = "linux"))]
    until: Option<Instant>,
    #[cfg(windows)]
    counters: Option<Option<super::gpu_counter::Counter>>,
    #[cfg(windows)]
    luids: std::collections::HashMap<String, u64>,
    #[cfg(windows)]
    dedicated_capacities: std::collections::HashMap<String, u64>,
}
impl Cache {
    pub async fn sample(&mut self) -> Vec<Gpu> {
        #[cfg(target_os = "linux")]
        {
            return linux();
        }
        #[cfg(not(target_os = "linux"))]
        {
            if self.until.is_none_or(|until| Instant::now() >= until) {
                #[cfg(not(windows))]
                {
                    self.inventory = inventory().await;
                }
                #[cfg(windows)]
                {
                    let adapters = tokio::task::spawn_blocking(windows::inventory)
                        .await
                        .unwrap_or_default();
                    self.luids = adapters
                        .iter()
                        .filter_map(|a| a.gpu.id.clone().zip(a.luid))
                        .collect();
                    self.dedicated_capacities = adapters
                        .iter()
                        .filter_map(|a| a.gpu.id.clone().zip(a.dedicated_capacity))
                        .collect();
                    self.inventory = adapters.into_iter().map(|a| a.gpu).collect();
                    self.counters = None;
                }
                self.until = Some(Instant::now() + Duration::from_secs(15 * 60));
            }
            let mut result = self.inventory.clone();
            #[cfg(windows)]
            {
                if self.counters.is_none() {
                    self.counters = Some(super::gpu_counter::Counter::new());
                }
                if let Some(Some(counters)) = &mut self.counters {
                    let readings = counters.sample();
                    for gpu in &mut result {
                        let luid = gpu.id.as_ref().and_then(|id| self.luids.get(id));
                        gpu.utilization = luid
                            .and_then(|luid| readings.as_ref().and_then(|v| v.get(luid)))
                            .copied();
                        let dedicated = gpu
                            .id
                            .as_ref()
                            .and_then(|id| self.dedicated_capacities.get(id))
                            .copied();
                        gpu.memory = luid
                            .and_then(|luid| counters.memory().dedicated.get(luid))
                            .copied()
                            .zip(dedicated)
                            .filter(|(u, t)| *t > 0 && u <= t)
                            .map(|(used, total)| Memory { used, total });
                        gpu.shared_memory = luid
                            .and_then(|luid| counters.memory().shared.get(luid))
                            .copied()
                            .zip(gpu.shared_memory_capacity)
                            .filter(|(u, t)| *t > 0 && u <= t)
                            .map(|(used, total)| Memory { used, total });
                    }
                }
            }
            result
        }
    }
}
pub(super) fn label(value: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in value.trim().chars().filter(|c| !c.is_control()) {
        if out.len() + ch.len_utf8() > max {
            break;
        }
        out.push(ch);
    }
    out
}
fn unknown(id: String, name: String) -> Gpu {
    Gpu {
        id: Some(label(&id, 128)),
        name: label(&name, 120),
        utilization: None,
        memory: None,
        shared_memory: None,
        shared_memory_capacity: None,
        integrated: None,
        temperature: None,
        fan_speed: None,
    }
}
#[cfg(target_os = "linux")]
fn linux() -> Vec<Gpu> {
    let Ok(entries) = std::fs::read_dir("/sys/class/drm") else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name
            .strip_prefix("card")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        let path = entry.path().join("device");
        let read = |name: &str| {
            std::fs::read_to_string(path.join(name))
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        let vendor = read("vendor");
        if vendor.is_empty() {
            continue;
        }
        let label = match vendor.as_str() {
            "0x8086" => "Intel integrated GPU",
            "0x1002" => "AMD GPU",
            "0x10de" => "NVIDIA GPU",
            _ => "Graphics adapter",
        };
        let model = read("device");
        let mut gpu = unknown(
            format!(
                "drm:{}",
                std::fs::canonicalize(&path)
                    .ok()
                    .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
                    .unwrap_or(name)
            ),
            format!("{label} · {model}"),
        );
        gpu.utilization = read("gpu_busy_percent")
            .parse::<f32>()
            .ok()
            .filter(|v| v.is_finite() && (0.0..=100.).contains(v));
        gpu.memory = read("mem_info_vram_used")
            .parse::<u64>()
            .ok()
            .zip(read("mem_info_vram_total").parse::<u64>().ok())
            .filter(|(u, t)| u <= t && *t <= i64::MAX as u64)
            .map(|(used, total)| Memory { used, total });
        rows.push(gpu);
        if rows.len() == 16 {
            break;
        }
    }
    rows
}
#[cfg(target_os = "macos")]
async fn inventory() -> Vec<Gpu> {
    let result = tokio::time::timeout(
        Duration::from_secs(4),
        tokio::process::Command::new("/usr/sbin/system_profiler")
            .args(["SPDisplaysDataType", "-json"])
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let Ok(Ok(output)) = result else {
        return Vec::new();
    };
    if !output.status.success() || output.stdout.len() > 262144 {
        return Vec::new();
    }
    let Ok(data) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return Vec::new();
    };
    data["SPDisplaysDataType"]
        .as_array()
        .into_iter()
        .flatten()
        .take(16)
        .enumerate()
        .filter_map(|(index, row)| {
            let name = row["sppci_model"]
                .as_str()
                .or_else(|| row["_name"].as_str())?;
            Some(unknown(format!("apple-gpu:{index}:{name}"), name.into()))
        })
        .collect()
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
async fn inventory() -> Vec<Gpu> {
    Vec::new()
}
