//! Isolated native ISA smoke test: no App, model, account, network or inference.
#[test]
#[ignore = "runs the actual native backend; invoke explicitly in the official static toolchain"]
fn speech_backend_devices_enumerate_without_model_or_application() {
    let devices = transcribe_cpp::devices();
    assert!(
        devices
            .iter()
            .any(|device| matches!(device.device_type, transcribe_cpp::DeviceType::Cpu)),
        "the compiled native CPU backend must enumerate without a model"
    );
    println!("SPEECH_NATIVE_DEVICE_PROBE cpu_present=true devices={} arch={} model_loaded=false app_created=false",devices.len(),std::env::consts::ARCH);
}

#[test]
#[ignore = "requires explicitly supplied pinned model and PCM fixtures; no downloads"]
fn speech_backend_cpu_inference_and_drop() {
    use sha2::{Digest, Sha256};
    use transcribe_cpp::{Backend, Model, ModelOptions, RunOptions, SessionOptions};
    let model_path = std::env::var("PORTHUB_TEST_SPEECH_MODEL").unwrap();
    let model_bytes = std::fs::read(&model_path).unwrap();
    assert_eq!(model_bytes.len(), 45_981_088);
    assert_eq!(
        format!("{:x}", Sha256::digest(&model_bytes)),
        "325b9c7997cd1eff81ef709d55766565e71be696130cc3a3d444713798706834"
    );
    drop(model_bytes);
    let bytes = std::fs::read(std::env::var("PORTHUB_TEST_SPEECH_PCM").unwrap()).unwrap();
    assert_eq!(bytes.len(), 352_000);
    let pcm: Vec<f32> = bytes
        .chunks_exact(2)
        .map(|b| i16::from_le_bytes([b[0], b[1]]) as f32 / 32768.)
        .collect();
    let device = transcribe_cpp::devices()
        .into_iter()
        .find(|d| matches!(d.device_type, transcribe_cpp::DeviceType::Cpu))
        .unwrap();
    let started = std::time::Instant::now();
    let model = Model::load_with(
        model_path,
        &ModelOptions {
            device: Some(device),
            backend: Backend::Cpu,
            ..Default::default()
        },
    )
    .unwrap();
    let mut session = model
        .session_with(&SessionOptions {
            n_threads: std::thread::available_parallelism().map_or(2, |n| n.get().min(4)) as i32,
            ..Default::default()
        })
        .unwrap();
    let result = session
        .run(
            &pcm,
            &RunOptions {
                language: Some("en".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(result.text.to_lowercase().contains("country"));
    drop(result);
    drop(session);
    drop(model);
    println!(
        "SPEECH_NATIVE_INFERENCE country_match=true model_dropped=true elapsed_ms={}",
        started.elapsed().as_millis()
    );
}
