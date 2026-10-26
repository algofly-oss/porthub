//! Direct, resumable file uploads. The destination HTTP listener owns the
//! bytes; the PortHub gateway only needs to provide discovery/routing.
use crate::state;
use anyhow::{bail, ensure, Context, Result};
use axum::{
    body::Body,
    extract::{Path as AxumPath, Request, State},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post, put},
    Json, Router,
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CHUNK: u64 = 8 * 1024 * 1024;

#[derive(Clone)]
struct ReceiveState {
    root: PathBuf,
    staging: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Manifest {
    name: String,
    size: u64,
    chunk_size: u64,
    chunks: u64,
    #[serde(default)]
    modified_unix: i64,
    #[serde(default)]
    modified_nanos: u32,
}

fn valid_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn session_dir(state: &ReceiveState, id: &str) -> Result<PathBuf> {
    ensure!(valid_id(id), "invalid upload identifier");
    Ok(state.staging.join(id))
}

fn safe_name(name: &str) -> Result<PathBuf> {
    let path = Path::new(name);
    ensure!(
        !name.is_empty() && !path.is_absolute() && !name.contains(['\\', ':', '\0']),
        "upload name must be relative"
    );
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => clean.push(value),
            _ => bail!("upload path contains an unsafe component"),
        }
    }
    ensure!(!clean.as_os_str().is_empty(), "upload name is empty");
    ensure!(clean.components().count() > 0, "upload name is empty");
    Ok(clean)
}

fn append_path(base: &reqwest::Url, relative: &str) -> Result<reqwest::Url> {
    let mut url = base.clone();
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("URL cannot accept a file path"))?;
        segments.pop_if_empty();
        for part in relative.split('/') {
            segments.push(part);
        }
    }
    Ok(url)
}

/// Keep protocol requests at the receiver root and apply URL directories to
/// manifest names. URL path segments are decoded once and validated before use.
fn upload_target(value: &str, relative: &str) -> Result<(reqwest::Url, String)> {
    let mut endpoint = reqwest::Url::parse(value)?;
    ensure!(
        matches!(endpoint.scheme(), "http" | "https"),
        "upload URL must use HTTP or HTTPS"
    );
    let prefix = percent_encoding::percent_decode_str(endpoint.path()).decode_utf8()?;
    let prefix = prefix.trim_matches('/');
    let name = if prefix.is_empty() {
        relative.to_owned()
    } else {
        format!("{prefix}/{relative}")
    };
    safe_name(&name)?;
    endpoint.set_path("/");
    endpoint.set_fragment(None);
    Ok((endpoint, name))
}

async fn destination(root: &Path, name: &str) -> Result<PathBuf> {
    let target = root.join(safe_name(name)?);
    let parent = target.parent().context("upload has no parent directory")?;
    // Validate each existing ancestor before creating anything below it.
    let mut current = root.to_owned();
    for component in parent.strip_prefix(root)?.components() {
        current.push(component);
        match tokio::fs::symlink_metadata(&current).await {
            Ok(metadata) => ensure!(
                metadata.is_dir() && !metadata.is_symlink(),
                "upload parent is not a real directory"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if let Err(error) = tokio::fs::create_dir(&current).await {
                    if error.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(error.into());
                    }
                }
                let metadata = tokio::fs::symlink_metadata(&current).await?;
                ensure!(
                    metadata.is_dir() && !metadata.is_symlink(),
                    "upload parent is not a real directory"
                );
            }
            Err(error) => return Err(error.into()),
        }
    }
    let canonical_parent = tokio::fs::canonicalize(parent).await?;
    ensure!(
        canonical_parent.starts_with(root),
        "upload path escapes destination"
    );
    Ok(target)
}

async fn write_body(body: Body, path: &Path, maximum: Option<u64>) -> Result<u64> {
    let mut file = tokio::fs::File::create(path).await?;
    let mut size = 0u64;
    let mut stream = body.into_data_stream();
    let result = async {
        while let Some(data) = stream.next().await {
            let data = data?;
            size = size
                .checked_add(data.len() as u64)
                .context("upload size overflow")?;
            if let Some(maximum) = maximum {
                ensure!(size <= maximum, "upload body exceeds the expected size");
            }
            file.write_all(&data).await?;
        }
        file.sync_all().await?;
        Ok::<_, anyhow::Error>(size)
    }
    .await;
    if result.is_err() {
        drop(file);
        let _ = tokio::fs::remove_file(path).await;
    }
    result
}

async fn init(
    State(state): State<Arc<ReceiveState>>,
    AxumPath(id): AxumPath<String>,
    Json(manifest): Json<Manifest>,
) -> impl IntoResponse {
    let result = async {
        let dir = session_dir(&state, &id)?;
        ensure!(manifest.chunk_size == CHUNK, "invalid upload chunk size");
        ensure!(
            manifest.modified_nanos < 1_000_000_000,
            "invalid modification timestamp"
        );
        ensure!(
            manifest.chunks == manifest.size.div_ceil(CHUNK),
            "invalid chunk count"
        );
        ensure!(
            manifest.chunks <= 1_000_000,
            "upload exceeds the supported maximum size"
        );
        // The wire format uses `/` on every platform. `PathBuf` normalizes
        // separators to `\\` on Windows, so comparing its native string form
        // to the manifest would incorrectly reject valid nested paths there.
        // `safe_name` already rejects roots, prefixes, and traversal parts.
        safe_name(&manifest.name)?;
        tokio::fs::create_dir_all(&dir).await?;
        let file = dir.join("manifest.json");
        if tokio::fs::try_exists(&file).await? {
            let previous: Manifest = serde_json::from_slice(&tokio::fs::read(&file).await?)?;
            ensure!(
                previous.name == manifest.name
                    && previous.size == manifest.size
                    && previous.chunks == manifest.chunks,
                "upload identifier conflicts with another transfer"
            );
        } else {
            let bytes = serde_json::to_vec(&manifest)?;
            tokio::fs::write(file, bytes).await?;
        }
        status_for(&dir, &manifest).await
    }
    .await;
    match result {
        Ok(status) => (StatusCode::OK, Json(status)).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

#[derive(Serialize)]
struct UploadStatus {
    missing: Vec<u64>,
}

async fn status(
    State(state): State<Arc<ReceiveState>>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let result = async {
        let dir = session_dir(&state, &id)?;
        let manifest: Manifest =
            serde_json::from_slice(&tokio::fs::read(dir.join("manifest.json")).await?)?;
        status_for(&dir, &manifest).await
    }
    .await;
    match result {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => (StatusCode::NOT_FOUND, error.to_string()).into_response(),
    }
}

async fn status_for(dir: &Path, manifest: &Manifest) -> Result<UploadStatus> {
    let mut missing = Vec::new();
    for index in 0..manifest.chunks {
        if !tokio::fs::try_exists(dir.join(format!("{index}.chunk"))).await? {
            missing.push(index);
        }
    }
    Ok(UploadStatus { missing })
}

async fn chunk(
    State(state): State<Arc<ReceiveState>>,
    AxumPath((id, index)): AxumPath<(String, u64)>,
    request: Request,
) -> impl IntoResponse {
    let result = async {
        let dir = session_dir(&state, &id)?;
        let manifest: Manifest =
            serde_json::from_slice(&tokio::fs::read(dir.join("manifest.json")).await?)?;
        ensure!(index < manifest.chunks, "chunk index out of range");
        let expected = (manifest.size - index * manifest.chunk_size).min(manifest.chunk_size);
        if let Some(length) = request.headers().get(header::CONTENT_LENGTH) {
            ensure!(
                length.to_str()?.parse::<u64>()? == expected,
                "chunk length mismatch"
            );
        }
        let expected_hash = request
            .headers()
            .get("x-porthub-chunk-sha256")
            .context("missing chunk integrity hash")?
            .to_str()?
            .to_owned();
        ensure!(
            expected_hash.len() == 64 && expected_hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid chunk integrity hash"
        );
        let temporary = dir.join(format!("{index}.part"));
        let count = write_body(request.into_body(), &temporary, Some(expected)).await?;
        ensure!(count == expected, "chunk length mismatch");
        let received = tokio::fs::read(&temporary).await?;
        ensure!(
            format!("{:x}", Sha256::digest(received)) == expected_hash,
            "chunk integrity check failed"
        );
        tokio::fs::rename(temporary, dir.join(format!("{index}.chunk"))).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn commit(
    State(state): State<Arc<ReceiveState>>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let result = async {
        let dir = session_dir(&state, &id)?;
        let manifest: Manifest =
            serde_json::from_slice(&tokio::fs::read(dir.join("manifest.json")).await?)?;
        ensure!(
            status_for(&dir, &manifest).await?.missing.is_empty(),
            "upload is incomplete; resume by sending missing chunks"
        );
        let target = destination(&state.root, &manifest.name).await?;
        let part = target.with_file_name(format!(".porthub-{}.partial", id));
        let mut output = tokio::fs::File::create(&part).await?;
        let mut digest = Sha256::new();
        for index in 0..manifest.chunks {
            let mut input = tokio::fs::File::open(dir.join(format!("{index}.chunk"))).await?;
            let mut buffer = vec![0u8; 256 * 1024];
            loop {
                let n = input.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                digest.update(&buffer[..n]);
                output.write_all(&buffer[..n]).await?;
            }
        }
        output.sync_all().await?;
        ensure!(
            tokio::fs::metadata(&part).await?.len() == manifest.size,
            "assembled upload size mismatch"
        );
        state::replace(&part, &target).await?;
        filetime::set_file_mtime(
            &target,
            filetime::FileTime::from_unix_time(manifest.modified_unix, manifest.modified_nanos),
        )?;
        tokio::fs::remove_dir_all(dir).await?;
        Ok::<_, anyhow::Error>(format!("{:x}", digest.finalize()))
    }
    .await;
    match result {
        Ok(hash) => (StatusCode::OK, hash).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn raw_upload(
    State(state): State<Arc<ReceiveState>>,
    AxumPath(name): AxumPath<String>,
    request: Request,
) -> impl IntoResponse {
    let result = async {
        let target = destination(&state.root, &name).await?;
        let part =
            target.with_file_name(format!(".porthub-{:016x}.partial", rand::random::<u64>()));
        let count = write_body(request.into_body(), &part, None).await?;
        state::replace(&part, &target).await?;
        Ok::<_, anyhow::Error>(count)
    }
    .await;
    match result {
        Ok(size) => (StatusCode::CREATED, format!("stored {size} bytes")).into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}

#[derive(Serialize, Deserialize)]
struct Directories {
    names: Vec<String>,
}

async fn create_directories(
    State(state): State<Arc<ReceiveState>>,
    Json(request): Json<Directories>,
) -> axum::response::Response {
    let result = async {
        ensure!(request.names.len() <= 100_000, "too many directories");
        for name in request.names {
            // destination validates every ancestor before creating it. A
            // synthetic final component lets the same checks create a folder.
            let name = safe_name(&name)?;
            destination(
                &state.root,
                &format!("{}/.porthub-directory", name.to_string_lossy()),
            )
            .await?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}

/// Add upload endpoints to the built-in HTTP server so the existing list/stop
/// manager also controls receivers after their launching terminal is gone.
pub fn routes(root: PathBuf) -> Result<Router> {
    let root = std::fs::canonicalize(root).context("upload directory is unavailable")?;
    ensure!(root.is_dir(), "upload destination must be a directory");
    let staging = state::directory("upload-sessions")?;
    prune_old_sessions(&staging)?;
    let state = Arc::new(ReceiveState { root, staging });
    Ok(Router::new()
        .route("/.porthub/directories", post(create_directories))
        .route("/.porthub/uploads/{id}", get(status).put(init))
        .route("/.porthub/uploads/{id}/chunks/{index}", put(chunk))
        .route("/.porthub/uploads/{id}/commit", post(commit))
        .route("/.porthub/raw/{*name}", put(raw_upload).post(raw_upload))
        .with_state(state))
}

fn prune_old_sessions(staging: &Path) -> Result<()> {
    let now = std::time::SystemTime::now();
    for entry in std::fs::read_dir(staging)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if !kind.is_dir() || kind.is_symlink() {
            continue;
        }
        let age = now
            .duration_since(entry.metadata()?.modified()?)
            .unwrap_or_default();
        if age > std::time::Duration::from_secs(30 * 24 * 60 * 60) {
            std::fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}

/// Parallel upload, with a local durable session token so rerunning the same
/// command resumes missing chunks rather than retransmitting completed data.
pub async fn put_file(
    file: PathBuf,
    url: String,
    relative_name: String,
    force: bool,
    semaphore: Arc<tokio::sync::Semaphore>,
    client: reqwest::Client,
) -> Result<String> {
    let metadata = tokio::fs::metadata(&file)
        .await
        .context("source file is unavailable")?;
    ensure!(metadata.is_file(), "source must be a regular file");
    let (endpoint, name) = upload_target(&url, &relative_name)?;
    let remote_file = append_path(&endpoint, &name)?;
    // Rsync-like default: matching size and modification time means skip the
    // file without reading or transmitting its contents.
    if !force {
        if let Ok(response) = client.head(remote_file.clone()).send().await {
            if response.status().is_success()
                && response
                    .headers()
                    .get(header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    == Some(metadata.len())
                && response
                    .headers()
                    .get("x-porthub-modified-nanos")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u128>().ok())
                    .zip(metadata.modified().ok())
                    .is_some_and(|(remote, local)| {
                        remote
                            == local
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_nanos()
                    })
            {
                return Ok(format!("Skipped unchanged {}", name));
            }
        }
    }
    let fingerprint = format!(
        "{}\n{}\n{}\n{}\n{}",
        endpoint,
        name,
        file.canonicalize()?.display(),
        metadata.len(),
        metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let key = format!("{:x}", Sha256::digest(fingerprint.as_bytes()));
    let local = state::directory("upload-checkpoints")?.join(key);
    let id = if local.exists() {
        tokio::fs::read_to_string(&local).await?
    } else {
        let mut random = [0u8; 32];
        rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut random)?;
        let value = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        state::write_private(&local, value.as_bytes())?;
        value
    };
    let api = append_path(&endpoint, &format!(".porthub/uploads/{id}"))?;
    let manifest = Manifest {
        modified_nanos: metadata
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)?
            .subsec_nanos(),
        name,
        size: metadata.len(),
        chunk_size: CHUNK,
        chunks: metadata.len().div_ceil(CHUNK),
        modified_unix: metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default(),
    };
    let init = client.put(api.clone()).json(&manifest).send().await;
    let response = match init {
        Ok(response) if response.status().is_success() => response,
        Ok(response)
            if matches!(
                response.status(),
                reqwest::StatusCode::NOT_FOUND
                    | reqwest::StatusCode::METHOD_NOT_ALLOWED
                    | reqwest::StatusCode::NOT_IMPLEMENTED
            ) =>
        {
            // Ordinary upload services remain usable; PUT the raw file body.
            let target = remote_file;
            let input = tokio::fs::File::open(&file).await?;
            let stream = tokio_util::io::ReaderStream::new(input);
            let response = client
                .put(target)
                .body(reqwest::Body::wrap_stream(stream))
                .send()
                .await?;
            ensure!(
                response.status().is_success(),
                "upload failed with HTTP {}",
                response.status()
            );
            return Ok(format!("Uploaded {} bytes", metadata.len()));
        }
        Ok(response) => bail!(
            "upload endpoint rejected setup with HTTP {}",
            response.status()
        ),
        Err(error) => return Err(error.into()),
    };
    let _ = response;
    #[derive(Deserialize)]
    struct Missing {
        missing: Vec<u64>,
    }
    let status: Missing = client
        .get(api.clone())
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let mut tasks = tokio::task::JoinSet::new();
    for index in status.missing {
        let semaphore = semaphore.clone();
        let client = client.clone();
        let url = append_path(&endpoint, &format!(".porthub/uploads/{id}/chunks/{index}"))?;
        let file = file.clone();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await?;
            let start = index * CHUNK;
            let len = metadata_len(&file)
                .await?
                .checked_sub(start)
                .context("source file shrank during transfer")?
                .min(CHUNK);
            let mut input = tokio::fs::File::open(file).await?;
            use tokio::io::{AsyncReadExt, AsyncSeekExt};
            input.seek(std::io::SeekFrom::Start(start)).await?;
            let mut data = vec![0u8; len as usize];
            input.read_exact(&mut data).await?;
            let chunk_hash = format!("{:x}", Sha256::digest(&data));
            let response = client
                .put(url)
                .header("x-porthub-chunk-sha256", chunk_hash)
                .body(data)
                .send()
                .await?;
            ensure!(
                response.status().is_success(),
                "chunk upload failed with HTTP {}",
                response.status()
            );
            Ok::<(), anyhow::Error>(())
        });
    }
    while let Some(task) = tasks.join_next().await {
        task??;
    }
    let current = tokio::fs::metadata(&file).await?;
    ensure!(
        current.len() == metadata.len() && current.modified().ok() == metadata.modified().ok(),
        "source file changed during transfer; rerun to resume against the new version"
    );
    let response = client
        .post(append_path(
            &endpoint,
            &format!(".porthub/uploads/{id}/commit"),
        )?)
        .send()
        .await?
        .error_for_status()?;
    let sha = response.text().await?;
    let _ = tokio::fs::remove_file(local).await;
    Ok(format!("Uploaded {} bytes; SHA-256 {sha}", metadata.len()))
}

/// Send one file or incrementally sync a directory tree. Directories are
/// walked without following symlinks; the top-level folder name is retained.
pub async fn put_path(
    path: PathBuf,
    url: String,
    connections: usize,
    contents_only: bool,
    force: bool,
) -> Result<String> {
    put_selection(path, url, connections, contents_only, force, None).await
}

/// Sync only paths named by a filesystem watcher. Missing paths are retained
/// remotely; this API never turns a local deletion into a remote deletion.
pub async fn put_changed_paths(
    path: PathBuf,
    url: String,
    connections: usize,
    contents_only: bool,
    force: bool,
    changed: Vec<PathBuf>,
) -> Result<String> {
    put_selection(path, url, connections, contents_only, force, Some(changed)).await
}

async fn put_selection(
    path: PathBuf,
    url: String,
    connections: usize,
    contents_only: bool,
    force: bool,
    changed: Option<Vec<PathBuf>>,
) -> Result<String> {
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()?;
    let metadata = tokio::fs::symlink_metadata(&path).await?;
    if metadata.is_file() {
        let name = path
            .file_name()
            .context("source has no file name")?
            .to_string_lossy()
            .into_owned();
        return put_file(
            path,
            url,
            name,
            force,
            Arc::new(tokio::sync::Semaphore::new(connections.clamp(1, 32))),
            client,
        )
        .await;
    }
    ensure!(metadata.is_dir(), "source must be a file or directory");
    let root = tokio::fs::canonicalize(&path).await?;
    let prefix = if contents_only {
        String::new()
    } else {
        format!(
            "{}/",
            path.file_name()
                .context("cannot sync a filesystem root")?
                .to_string_lossy()
        )
    };
    let mut pending = Vec::new();
    let mut files = Vec::<(PathBuf, String)>::new();
    if let Some(changed) = changed {
        for file in changed {
            let relative = file
                .strip_prefix(&root)
                .context("changed path escapes source")?;
            // Check every existing component, including parents of files:
            // a replaced directory must not turn into a followed symlink.
            let mut ancestor = root.clone();
            for part in relative.components() {
                ensure!(matches!(part, Component::Normal(_)), "unsafe changed path");
                ancestor.push(part);
                match tokio::fs::symlink_metadata(&ancestor).await {
                    Ok(metadata) => ensure!(
                        !metadata.is_symlink(),
                        "directory sync does not follow symlinks"
                    ),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                    Err(error) => return Err(error.into()),
                }
            }
            match tokio::fs::symlink_metadata(&file).await {
                Ok(metadata) if metadata.is_dir() => pending.push(file),
                Ok(metadata) if metadata.is_file() => {
                    let name = format!("{prefix}{}", relative.to_string_lossy().replace('\\', "/"));
                    files.push((file, name));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
                _ => bail!("unsupported changed filesystem entry"),
            }
        }
    } else {
        pending.push(root.clone());
    }
    let mut directories = Vec::new();
    while let Some(directory) = pending.pop() {
        let relative = directory
            .strip_prefix(&root)?
            .to_string_lossy()
            .replace('\\', "/");
        let relative = format!("{prefix}{relative}");
        let (_, name) = upload_target(
            &url,
            &if relative.is_empty() {
                ".porthub-directory".into()
            } else {
                format!("{}/.porthub-directory", relative.trim_end_matches('/'))
            },
        )?;
        if let Some((parent, _)) = name.rsplit_once('/') {
            directories.push(parent.to_owned());
        }
        let mut entries = tokio::fs::read_dir(&directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            let kind = entry.file_type().await?;
            ensure!(
                !kind.is_symlink(),
                "directory sync does not follow symlinks: {}",
                entry.path().display()
            );
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                let relative = entry
                    .path()
                    .strip_prefix(&root)?
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push((entry.path(), format!("{prefix}{relative}")));
            } else {
                bail!("unsupported filesystem entry: {}", entry.path().display());
            }
        }
    }
    if !directories.is_empty() {
        let (endpoint, _) = upload_target(&url, ".porthub-directory")?;
        for batch in directories.chunks(128) {
            let response = client
                .post(append_path(&endpoint, ".porthub/directories")?)
                .json(&Directories {
                    names: batch.to_vec(),
                })
                .send()
                .await?;
            ensure!(
                response.status().is_success()
                    || matches!(
                        response.status(),
                        StatusCode::NOT_FOUND
                            | StatusCode::METHOD_NOT_ALLOWED
                            | StatusCode::NOT_IMPLEMENTED
                    ),
                "receiver rejected destination directories with HTTP {}",
                response.status()
            );
        }
    }
    files.sort_by(|a, b| a.1.cmp(&b.1));
    files.dedup_by(|a, b| a.1 == b.1);

    let total = files.len();
    let mut sent = 0usize;
    let mut skipped = 0usize;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(connections.clamp(1, 32)));
    let mut pending = files.into_iter();
    let mut tasks = tokio::task::JoinSet::new();
    let file_workers = connections.clamp(1, 8);
    for _ in 0..file_workers {
        if let Some((file, relative)) = pending.next() {
            let url = url.clone();
            let semaphore = semaphore.clone();
            let client = client.clone();
            tasks.spawn(
                async move { put_file(file, url, relative, force, semaphore, client).await },
            );
        }
    }
    while let Some(task) = tasks.join_next().await {
        let result = task??;
        if result.starts_with("Skipped unchanged ") {
            skipped += 1;
        } else {
            sent += 1;
        }
        if let Some((file, relative)) = pending.next() {
            let url = url.clone();
            let semaphore = semaphore.clone();
            let client = client.clone();
            tasks.spawn(
                async move { put_file(file, url, relative, force, semaphore, client).await },
            );
        }
    }
    Ok(format!(
        "Synced {total} files: sent {sent}, skipped {skipped}"
    ))
}

async fn metadata_len(file: &Path) -> Result<u64> {
    Ok(tokio::fs::metadata(file).await?.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receiver_rejects_unsafe_file_names() {
        for name in ["", "../escape", "/absolute", "a/../../escape"] {
            assert!(safe_name(name).is_err(), "accepted unsafe name {name:?}");
        }
        assert_eq!(
            safe_name("nested/file.bin").unwrap(),
            PathBuf::from("nested/file.bin")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn receiver_rejects_symlinked_parent_escape() -> Result<()> {
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape"))?;
        assert!(destination(root.path(), "escape/new/deep/file.bin")
            .await
            .is_err());
        ensure!(!outside.path().join("new").exists());
        Ok(())
    }
}
