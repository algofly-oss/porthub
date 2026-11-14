//! One lazy native engine per deployment. No model, task or GPU allocation at
//! startup. A bounded actor serializes inference, switching and explicit unload.
use crate::{
    auth,
    error::{ApiError, ApiResult},
    App,
};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use mongodb::bson::{doc, Document};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};
use transcribe_cpp::{Backend, CancelToken, Model, ModelOptions, RunOptions, SessionOptions, Task};

const IDLE: Duration = Duration::from_secs(60);
const MAX_AUDIO: usize = 16_000 * 2 * 60;
#[derive(Clone, Deserialize, Serialize)]
struct Spec {
    id: String,
    name: String,
    description: String,
    filename: String,
    size: u64,
    sha256: String,
    url: String,
    languages: Vec<String>,
    translate: bool,
    auto_language: bool,
    license: String,
    source: String,
}
fn catalog() -> Vec<Spec> {
    serde_json::from_str(include_str!("models.json")).expect("embedded model catalog")
}
fn spec(id: &str) -> ApiResult<Spec> {
    catalog()
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| ApiError::bad_request("Unknown speech model"))
}
fn root() -> PathBuf {
    std::env::var_os("PORTHUB_SPEECH_MODEL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/data/speech-models"))
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub model: String,
    pub engine: String,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            model: "whisper-tiny".into(),
            engine: "cpu".into(),
        }
    }
}
#[derive(Default)]
struct Status {
    loaded: bool,
    busy: bool,
    error: Option<String>,
    download: Option<(String, u64, u64)>,
}
enum Work {
    Configure(Settings, oneshot::Sender<Result<(), String>>),
    Run {
        generation: u64,
        pcm: Vec<f32>,
        options: RunOptions,
        reply: oneshot::Sender<Result<String, String>>,
    },
    Unload(oneshot::Sender<()>),
}
pub struct Speech {
    send: mpsc::Sender<Work>,
    state: Arc<Mutex<Status>>,
    settings: Arc<Mutex<Settings>>,
    cancel: CancelToken,
    generation: Arc<AtomicU64>,
    config_lock: tokio::sync::Mutex<()>,
}
fn lock<T>(v: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    v.lock().unwrap_or_else(|e| e.into_inner())
}
fn available() -> Vec<Value> {
    transcribe_cpp::devices().into_iter().map(|d|json!({"kind":if matches!(d.device_type,transcribe_cpp::DeviceType::Gpu|transcribe_cpp::DeviceType::Igpu){"gpu"}else{"cpu"},"backend":d.kind,"name":d.name,"description":d.description})).collect()
}
impl Speech {
    fn new(settings: Settings) -> Self {
        // Static backends only: device enumeration never mutates the registry.
        let (send, mut recv) = mpsc::channel(2);
        let state = Arc::new(Mutex::new(Status::default()));
        let shared_settings = Arc::new(Mutex::new(settings.clone()));
        let generation = Arc::new(AtomicU64::new(0));
        let current_generation = generation.clone();
        let cancel = CancelToken::new();
        let (st, sc, ss) = (state.clone(), cancel.clone(), shared_settings.clone());
        tokio::spawn(async move {
            let mut loaded: Option<Model> = None;
            let mut settings = settings;
            let mut deadline = tokio::time::Instant::now() + IDLE;
            loop {
                let work = tokio::select! {
                    work=recv.recv()=>match work{Some(w)=>w,None=>break},
                    _=tokio::time::sleep_until(deadline),if loaded.is_some()=>{
                        let old=loaded.take(); let _=tokio::task::spawn_blocking(move||release_model(old)).await;
                        lock(&st).loaded=false;continue;
                    }
                };
                match work {
                    Work::Configure(next, reply) => {
                        if next.model != settings.model
                            || next.engine != settings.engine
                            || !next.enabled
                        {
                            let old = loaded.take();
                            let _ = tokio::task::spawn_blocking(move || release_model(old)).await;
                            lock(&st).loaded = false;
                        }
                        settings = next;
                        *lock(&ss) = settings.clone();
                        lock(&st).error = None;
                        let _ = reply.send(Ok(()));
                    }
                    Work::Unload(reply) => {
                        let old = loaded.take();
                        let _ = tokio::task::spawn_blocking(move || release_model(old)).await;
                        lock(&st).loaded = false;
                        let _ = reply.send(());
                    }
                    Work::Run {
                        generation,
                        pcm,
                        options,
                        reply,
                    } => {
                        if !settings.enabled {
                            let _ = reply.send(Err("Dictation is disabled".into()));
                            continue;
                        }
                        sc.reset();
                        if generation != current_generation.load(Ordering::SeqCst) {
                            let _ =
                                reply.send(Err("Transcription cancelled by engine change".into()));
                            continue;
                        }
                        lock(&st).busy = true;
                        let config = settings.clone();
                        let cancellation = sc.clone();
                        let old = loaded.take();
                        let result = tokio::task::spawn_blocking(move || {
                            let model = match old {
                                Some(m) => Ok(m),
                                None => {
                                    let model = spec(&config.model)
                                        .map_err(|_| "Unknown model".to_owned())?;
                                    let device = transcribe_cpp::devices().into_iter().find(|d| {
                                        if config.engine == "cpu" {
                                            d.kind == "cpu"
                                        } else {
                                            matches!(
                                                d.device_type,
                                                transcribe_cpp::DeviceType::Gpu
                                                    | transcribe_cpp::DeviceType::Igpu
                                            )
                                        }
                                    });
                                    let device = device.ok_or_else(|| {
                                        "Selected compute engine is unavailable".to_owned()
                                    })?;
                                    Model::load_with(
                                        root().join(model.filename),
                                        &ModelOptions {
                                            device: Some(device),
                                            backend: if config.engine == "cpu" {
                                                Backend::Cpu
                                            } else {
                                                Backend::Auto
                                            },
                                            ..Default::default()
                                        },
                                    )
                                    .map_err(|_| {
                                        "Could not load model; download it or choose another engine"
                                            .to_owned()
                                    })
                                }
                            }?;
                            let text = (|| {
                                let threads = std::thread::available_parallelism()
                                    .map_or(2, |n| n.get().min(4))
                                    as i32;
                                let mut session = model
                                    .session_with(&SessionOptions {
                                        n_threads: threads,
                                        ..Default::default()
                                    })
                                    .map_err(|_| "Could not create speech session".to_owned())?;
                                session.set_cancel_token(&cancellation);
                                let result = session.run(&pcm, &options).map_err(|_| {
                                    if cancellation.is_cancelled() {
                                        "Transcription cancelled".to_owned()
                                    } else {
                                        "Transcription failed for this model/language".to_owned()
                                    }
                                })?;
                                if cancellation.is_cancelled() {
                                    return Err("Transcription cancelled".into());
                                }
                                Ok(result.text.trim().to_owned())
                            })();
                            Ok::<_, String>((model, text))
                        })
                        .await;
                        let text = match result {
                            Ok(Ok((model, text))) => {
                                loaded = Some(model);
                                text
                            }
                            Ok(Err(e)) => Err(e),
                            Err(_) => Err("Speech worker failed".into()),
                        };
                        deadline = tokio::time::Instant::now() + IDLE;
                        {
                            let mut s = lock(&st);
                            s.busy = false;
                            s.loaded = loaded.is_some();
                            s.error = text.as_ref().err().cloned();
                        }
                        let _ = reply.send(text);
                    }
                }
            }
        });
        Self {
            send,
            state,
            settings: shared_settings,
            cancel,
            generation,
            config_lock: tokio::sync::Mutex::new(()),
        }
    }
    async fn status(&self) -> Value {
        let s = lock(&self.state);
        let settings = lock(&self.settings);
        let devices = available();
        let gpu = devices.iter().any(|d| d["kind"] == "gpu");
        let models: Vec<_> = catalog()
            .into_iter()
            .map(|m| {
                let installed = root().join(&m.filename).is_file();
                let mut v = serde_json::to_value(m).unwrap();
                v["installed"] = installed.into();
                v.as_object_mut().unwrap().remove("url");
                v
            })
            .collect();
        json!({"settings":*settings,"loaded":s.loaded,"busy":s.busy,"error":s.error,"download":s.download.as_ref().map(|(id,done,total)|json!({"model":id,"bytes":done,"total":total})),"idle_seconds":IDLE.as_secs(),"gpu_available":gpu,"devices":devices,"models":models})
    }
}
fn release_model(model: Option<Model>) {
    drop(model);
    // All native sessions have ended before this call. Return free allocator
    // arenas as well as unmapping weights, so idle RAM actually falls on Linux.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    unsafe {
        libc::malloc_trim(0);
    }
}
async fn manager(app: &App) -> ApiResult<&Speech> {
    app.keyboard
        .speech
        .get_or_try_init(|| async {
            let saved = app
                .collection("settings")
                .find_one(doc! {"_id":"keyboard_speech"})
                .await?;
            let settings = saved
                .and_then(|d| d.get_document("settings").ok().cloned())
                .and_then(|d| mongodb::bson::from_document(d).ok())
                .unwrap_or_default();
            Ok::<_, ApiError>(Speech::new(settings))
        })
        .await
}
async fn admin(app: &App, headers: &HeaderMap) -> ApiResult<Document> {
    let user = auth::current_user(app, headers).await?;
    if user.get_str("role") != Ok("admin") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Only administrators can change the shared speech engine",
        ));
    }
    Ok(user)
}
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/keyboard/speech", get(status).patch(configure))
        .route("/api/keyboard/speech/unload", post(unload))
        .route("/api/keyboard/speech/models/{id}/download", post(download))
        .route("/api/keyboard/speech/transcribe", post(transcribe))
        .layer(DefaultBodyLimit::max(MAX_AUDIO))
}
async fn status(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    auth::current_user(&app, &headers).await?;
    Ok(Json(manager(&app).await?.status().await))
}
async fn configure(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(settings): Json<Settings>,
) -> ApiResult<Json<Value>> {
    super::same_origin(&app, &headers)?;
    admin(&app, &headers).await?;
    spec(&settings.model)?;
    if !matches!(settings.engine.as_str(), "cpu" | "gpu")
        || settings.engine == "gpu" && !available().iter().any(|d| d["kind"] == "gpu")
    {
        return Err(ApiError::bad_request(
            "Selected compute engine is unavailable",
        ));
    }
    let m = manager(&app).await?;
    let _config = m.config_lock.lock().await;
    m.generation.fetch_add(1, Ordering::SeqCst);
    m.cancel.cancel();
    let (tx, rx) = oneshot::channel();
    m.send
        .send(Work::Configure(settings.clone(), tx))
        .await
        .map_err(|_| busy())?;
    rx.await
        .map_err(|_| busy())?
        .map_err(|e| ApiError::bad_request(&e))?;
    app.collection("settings")
        .update_one(
            doc! {"_id":"keyboard_speech"},
            doc! {"$set":{"settings":mongodb::bson::to_document(&settings).map_err(|_|busy())?}},
        )
        .upsert(true)
        .await?;
    Ok(Json(m.status().await))
}
fn busy() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "Speech engine is busy; try again",
    )
}
async fn unload(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    super::same_origin(&app, &headers)?;
    admin(&app, &headers).await?;
    let m = manager(&app).await?;
    let _config = m.config_lock.lock().await;
    m.generation.fetch_add(1, Ordering::SeqCst);
    m.cancel.cancel();
    let (tx, rx) = oneshot::channel();
    m.send.send(Work::Unload(tx)).await.map_err(|_| busy())?;
    rx.await.map_err(|_| busy())?;
    Ok(Json(m.status().await))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(default = "english")]
    language: String,
    #[serde(default)]
    translate: bool,
    #[serde(default)]
    romanize: bool,
}
fn english() -> String {
    "en".into()
}
fn pcm(bytes: &[u8]) -> ApiResult<Vec<f32>> {
    if bytes.len() < 3200 || bytes.len() > MAX_AUDIO || bytes.len() % 2 != 0 {
        return Err(ApiError::bad_request(
            "Use 0.1–60 seconds of 16 kHz mono PCM16 audio",
        ));
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|b| f32::from(i16::from_le_bytes([b[0], b[1]])) / 32768.0)
        .collect())
}
async fn transcribe(
    State(app): State<Arc<App>>,
    Query(options): Query<Options>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    super::same_origin(&app, &headers)?;
    auth::current_user(&app, &headers).await?;
    let pcm = pcm(&body)?;
    let m = manager(&app).await?;
    let _configuration = m.config_lock.try_lock().map_err(|_| busy())?;
    let settings = lock(&m.settings).clone();
    let model = spec(&settings.model)?;
    if !settings.enabled {
        return Err(ApiError::new(StatusCode::CONFLICT, "Dictation is disabled"));
    }
    if !root().join(&model.filename).is_file() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Download the selected model before dictating",
        ));
    }
    if options.language == "auto" && !model.auto_language
        || options.language != "auto" && !model.languages.contains(&options.language)
        || options.translate && !model.translate
    {
        return Err(ApiError::bad_request(
            "Selected model does not support that language or translation",
        ));
    }
    let run = RunOptions {
        language: (options.language != "auto").then_some(options.language),
        task: if options.translate {
            Task::Translate
        } else {
            Task::Transcribe
        },
        target_language: options.translate.then(|| "en".into()),
        ..Default::default()
    };
    let (tx, rx) = oneshot::channel();
    m.send
        .try_send(Work::Run {
            generation: m.generation.load(Ordering::SeqCst),
            pcm,
            options: run,
            reply: tx,
        })
        .map_err(|_| busy())?;
    drop(_configuration);
    let text = rx
        .await
        .map_err(|_| busy())?
        .map_err(|e| ApiError::new(StatusCode::CONFLICT, &e))?;
    let text = if options.romanize {
        super::romanize::latin(&text)
    } else {
        text
    };
    Ok(Json(json!({"text":text})))
}
async fn download(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    super::same_origin(&app, &headers)?;
    admin(&app, &headers).await?;
    let model = spec(&id)?;
    let m = manager(&app).await?;
    {
        let mut state = lock(&m.state);
        if state.download.is_some() {
            return Err(busy());
        }
        if root().join(&model.filename).is_file() {
            return Ok(Json(json!({"installed":true})));
        }
        state.download = Some((id, 0, model.size));
    }
    let worker = app.clone();
    tokio::spawn(async move {
        let Ok(m) = manager(&worker).await else {
            return;
        };
        let result = install(&worker, &model, m).await;
        let mut state = lock(&m.state);
        state.download = None;
        state.error = result.err();
    });
    Ok(Json(json!({"downloading":true})))
}
async fn install(app: &App, model: &Spec, m: &Speech) -> Result<(), String> {
    let path = root().join(&model.filename);
    let temp = path.with_extension("partial");
    let result = async {
        tokio::fs::create_dir_all(root())
            .await
            .map_err(|_| "Cannot create model directory")?;
        let mut response = app
            .http
            .get(&model.url)
            .timeout(Duration::from_secs(1800))
            .send()
            .await
            .map_err(|_| "Model download failed")?
            .error_for_status()
            .map_err(|_| "Model download failed")?;
        if response.content_length().is_some_and(|n| n != model.size) {
            return Err("Model size does not match catalog");
        }
        let mut file = tokio::fs::File::create(&temp)
            .await
            .map_err(|_| "Cannot write model")?;
        let mut hash = Sha256::new();
        let mut bytes = 0;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "Model download interrupted")?
        {
            bytes += chunk.len() as u64;
            if bytes > model.size {
                return Err("Model exceeds expected size");
            }
            hash.update(&chunk);
            file.write_all(&chunk)
                .await
                .map_err(|_| "Cannot write model")?;
            lock(&m.state).download = Some((model.id.clone(), bytes, model.size));
        }
        if bytes != model.size || format!("{:x}", hash.finalize()) != model.sha256 {
            return Err("Model checksum verification failed");
        }
        file.sync_all().await.map_err(|_| "Cannot save model")?;
        drop(file);
        tokio::fs::rename(&temp, &path)
            .await
            .map_err(|_| "Cannot publish model")?;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temp).await;
    }
    result.map_err(str::to_owned)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audio_and_catalog_are_bounded() {
        assert!(pcm(&[0; 3]).is_err());
        assert!(pcm(&vec![0; MAX_AUDIO + 2]).is_err());
        assert_eq!(pcm(&vec![0; 3200]).ok().unwrap().len(), 1600);
        let specs = catalog();
        assert_eq!(specs[0].id, "whisper-tiny");
        assert!(specs.iter().all(|s| s.sha256.len() == 64
            && !s.filename.contains('/')
            && s.url.starts_with("https://huggingface.co/")));
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires a downloaded pinned tiny model and 16kHz PCM fixture"]
    async fn native_cpu_dictation_and_explicit_unload() {
        let bytes = std::fs::read(std::env::var("PORTHUB_TEST_SPEECH_PCM").unwrap()).unwrap();
        let speech = Speech::new(Settings::default());
        assert_eq!(speech.status().await["loaded"], false);
        let (tx, rx) = oneshot::channel();
        speech
            .send
            .send(Work::Run {
                generation: speech.generation.load(Ordering::SeqCst),
                pcm: pcm(&bytes).ok().unwrap(),
                options: RunOptions {
                    language: Some("en".into()),
                    ..Default::default()
                },
                reply: tx,
            })
            .await
            .unwrap();
        let result = rx.await.unwrap().unwrap();
        assert!(result.to_lowercase().contains("country"), "{result}");
        assert_eq!(speech.status().await["loaded"], true);
        let (tx, rx) = oneshot::channel();
        speech.send.send(Work::Unload(tx)).await.unwrap();
        rx.await.unwrap();
        assert_eq!(speech.status().await["loaded"], false);
        let (tx, rx) = oneshot::channel();
        speech
            .send
            .send(Work::Configure(
                Settings {
                    enabled: false,
                    ..Settings::default()
                },
                tx,
            ))
            .await
            .unwrap();
        rx.await.unwrap().unwrap();
        let (tx, rx) = oneshot::channel();
        speech
            .send
            .send(Work::Run {
                generation: speech.generation.load(Ordering::SeqCst),
                pcm: vec![0.; 16000],
                options: RunOptions::default(),
                reply: tx,
            })
            .await
            .unwrap();
        assert!(rx.await.unwrap().unwrap_err().contains("disabled"));
    }
}
