//! Reproducible model latency and resident-memory check, with no running service.
//! cargo run --release -p porthub-api --example speech-benchmark -- MODEL AUDIO.pcm [gpu]
use anyhow::{ensure, Result};
use std::{path::PathBuf, time::Instant};
use transcribe_cpp::{DeviceType, Model, ModelOptions, RunOptions, SessionOptions};
fn rss() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
        })
        .unwrap_or(0)
        * 1024
}
fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let model = PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow::anyhow!("Provide a model and PCM audio path"))?,
    );
    let audio = std::fs::read(
        args.next()
            .ok_or_else(|| anyhow::anyhow!("Provide PCM audio"))?,
    )?;
    let gpu = args.next().is_some_and(|s| s == "gpu");
    ensure!(audio.len() % 2 == 0, "Use PCM16 audio");
    let pcm: Vec<_> = audio
        .chunks_exact(2)
        .map(|b| f32::from(i16::from_le_bytes([b[0], b[1]])) / 32768.0)
        .collect();
    let baseline = rss();
    let device = transcribe_cpp::devices()
        .into_iter()
        .find(|d| {
            if gpu {
                matches!(d.device_type, DeviceType::Gpu | DeviceType::Igpu)
            } else {
                d.device_type == DeviceType::Cpu
            }
        })
        .ok_or_else(|| anyhow::anyhow!("Compute engine unavailable"))?;
    let engine = device.kind.clone();
    let start = Instant::now();
    let model = Model::load_with(
        model,
        &ModelOptions {
            device: Some(device),
            ..Default::default()
        },
    )?;
    let load = start.elapsed().as_secs_f64();
    let mut session = model.session_with(&SessionOptions {
        n_threads: 4,
        ..Default::default()
    })?;
    let start = Instant::now();
    let result = session.run(
        &pcm,
        &RunOptions {
            language: Some("en".into()),
            ..Default::default()
        },
    )?;
    let inference = start.elapsed().as_secs_f64();
    let peak = rss();
    drop(session);
    drop(model);
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    unsafe {
        libc::malloc_trim(0);
    }
    println!(
        "{}",
        serde_json::json!({"engine":engine,"audio_seconds":pcm.len() as f64/16000.,"load_seconds":load,"inference_seconds":inference,"rss_before":baseline,"rss_loaded":peak,"rss_unloaded":rss(),"text":result.text})
    );
    Ok(())
}
