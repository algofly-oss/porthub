use crate::state;
use anyhow::{bail, ensure, Context, Result};
use futures_util::StreamExt;
use reqwest::{header, Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::mpsc,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub struct Options {
    pub url: String,
    pub directory: PathBuf,
    pub connections: usize,
    pub piece_size: u64,
    pub sha256: Option<String>,
    pub progress: bool,
}
impl Options {
    pub fn new(url: String, directory: PathBuf) -> Self {
        Self {
            url,
            directory,
            connections: 16,
            piece_size: 8 * 1024 * 1024,
            sha256: None,
            progress: true,
        }
    }
}

#[derive(Clone, Debug)]
struct Remote {
    size: Option<u64>,
    ranges: bool,
    etag: Option<String>,
    modified: Option<String>,
    name: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Checkpoint {
    version: u8,
    url: String,
    size: Option<u64>,
    etag: Option<String>,
    modified: Option<String>,
    piece_size: u64,
    complete: Vec<bool>,
}

struct Lock(std::fs::File);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

fn lock(path: &Path) -> Result<Lock> {
    let hash = format!("{:x}", Sha256::digest(path.to_string_lossy().as_bytes()));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state::directory("download-locks")?.join(hash))?;
    fs2::FileExt::try_lock_exclusive(&file).context("this file is already being downloaded")?;
    Ok(Lock(file))
}

fn sidecar(target: &Path, suffix: &str) -> PathBuf {
    let mut path = target.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

fn disposition_filename(header: &str) -> Option<String> {
    // Split parameters outside quoted strings so filenames containing ';' or
    // escaped quotes remain intact. Extended UTF-8 filenames take precedence.
    let mut parameters = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in header.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
            current.push(character);
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            current.push(character);
            continue;
        }
        if character == ';' && !quoted {
            parameters.push(std::mem::take(&mut current));
        } else {
            current.push(character);
        }
    }
    parameters.push(current);
    let mut plain = None;
    for parameter in parameters.into_iter().skip(1) {
        let Some((key, value)) = parameter.trim().split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            let mut output = String::new();
            let mut escaped = false;
            for character in value[1..value.len() - 1].chars() {
                if escaped {
                    output.push(character);
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else {
                    output.push(character);
                }
            }
            output
        } else {
            value.to_owned()
        };
        if key.trim().eq_ignore_ascii_case("filename*") {
            if let Some((charset, rest)) = value.split_once('\'') {
                if charset.eq_ignore_ascii_case("utf-8") {
                    if let Some((_, encoded)) = rest.split_once('\'') {
                        if let Ok(decoded) =
                            percent_encoding::percent_decode_str(encoded).decode_utf8()
                        {
                            if !decoded.is_empty() {
                                return Some(decoded.into_owned());
                            }
                        }
                    }
                }
            }
        } else if key.trim().eq_ignore_ascii_case("filename") && !value.is_empty() {
            plain = Some(value);
        }
    }
    plain
}

fn filename(url: &Url, disposition: Option<&str>) -> String {
    let candidate = match disposition.and_then(disposition_filename) {
        Some(name) => name
            .trim_end_matches(['/', '\\'])
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or("")
            .to_owned(),
        None => percent_encoding::percent_decode_str(
            url.path()
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or(""),
        )
        .decode_utf8_lossy()
        .into_owned(),
    };
    let mut safe = String::new();
    for character in candidate.chars() {
        let character = if character.is_control() || "<>:\"|?*/\\".contains(character) {
            '_'
        } else {
            character
        };
        if safe.len() + character.len_utf8() > 180 {
            break;
        }
        safe.push(character);
    }
    let safe = safe.trim_start_matches('.').trim_end_matches(['.', ' ']);
    if safe.is_empty() {
        return "download.bin".into();
    }
    let stem = safe.split('.').next().unwrap_or("").to_ascii_uppercase();
    if ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
    {
        format!("_{safe}")
    } else {
        safe.into()
    }
}

fn content_range(value: &str) -> Option<(u64, u64, u64)> {
    let (range, total) = value.strip_prefix("bytes ")?.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    Some((start.parse().ok()?, end.parse().ok()?, total.parse().ok()?))
}

async fn probe(client: &Client, url: &Url) -> Result<Remote> {
    let mut response = client
        .get(url.clone())
        .header(header::RANGE, "bytes=0-0")
        .header(header::ACCEPT_ENCODING, "identity")
        .send()
        .await?;
    ensure!(
        response
            .headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| value.eq_ignore_ascii_case("identity")),
        "server encoded a byte-range response"
    );
    let text = |name: header::HeaderName| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let etag = text(header::ETAG).filter(|etag| !etag.starts_with("W/"));
    let modified = text(header::LAST_MODIFIED);
    let name = filename(
        response.url(),
        response
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .and_then(|value| value.to_str().ok()),
    );
    let (size, ranges) = match response.status() {
        StatusCode::PARTIAL_CONTENT => {
            let range = text(header::CONTENT_RANGE)
                .and_then(|range| content_range(&range))
                .context("invalid probe Content-Range")?;
            ensure!(
                range.0 == 0 && range.1 == 0 && range.2 > 0,
                "server returned the wrong probe range"
            );
            (Some(range.2), true)
        }
        StatusCode::OK => (response.content_length(), false),
        StatusCode::RANGE_NOT_SATISFIABLE
            if text(header::CONTENT_RANGE).as_deref() == Some("bytes */0") =>
        {
            (Some(0), false)
        }
        status => bail!("download probe returned HTTP {status}"),
    };
    // Read one byte to complete a successful range probe so its connection can
    // be reused. Never consume an entire non-range response during probing.
    if ranges {
        let mut total = 0;
        while let Some(bytes) = response.chunk().await? {
            total += bytes.len();
            ensure!(total <= 1, "invalid probe response length");
        }
        ensure!(total == 1, "invalid probe response length");
    }
    Ok(Remote {
        size,
        ranges,
        etag,
        modified,
        name,
    })
}

fn destination(directory: &Path, name: &str, url: &str) -> Result<PathBuf> {
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("download");
    let ext = path.extension().and_then(|value| value.to_str());
    for index in 0..10000 {
        let name = if index == 0 {
            name.to_owned()
        } else {
            format!(
                "{stem}.{index}{}",
                ext.map(|ext| format!(".{ext}")).unwrap_or_default()
            )
        };
        let target = directory.join(name);
        if target.try_exists()? {
            continue;
        }
        let part = sidecar(&target, ".porthub-part");
        let control = sidecar(&target, ".porthub-part.json");
        if !part.try_exists()? && !control.try_exists()? {
            return Ok(target);
        }
        if std::fs::read(control)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Checkpoint>(&bytes).ok())
            .is_some_and(|checkpoint| checkpoint.url == url)
        {
            return Ok(target);
        }
    }
    bail!("cannot choose an unused destination filename")
}

fn checkpoint(path: &Path) -> Option<Checkpoint> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > 8 * 1024 * 1024 {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

#[derive(Clone)]
struct Work {
    client: Client,
    url: Url,
    part: PathBuf,
    remote: Remote,
    size: u64,
    piece_size: u64,
    pending: Arc<Vec<usize>>,
    next: Arc<AtomicUsize>,
    received: Arc<AtomicU64>,
}

async fn piece(work: &Work, file: &mut tokio::fs::File, index: usize) -> Result<()> {
    let start = (index as u64)
        .checked_mul(work.piece_size)
        .context("segment offset overflow")?;
    let end = start.saturating_add(work.piece_size).min(work.size) - 1;
    let mut request = work
        .client
        .get(work.url.clone())
        .header(header::RANGE, format!("bytes={start}-{end}"))
        .header(header::ACCEPT_ENCODING, "identity");
    if let Some(validator) = work.remote.etag.as_ref().or(work.remote.modified.as_ref()) {
        request = request.header(header::IF_RANGE, validator);
    }
    let mut response = request.send().await?;
    ensure!(
        response.status() == StatusCode::PARTIAL_CONTENT,
        "server stopped honoring byte ranges or the remote file changed (HTTP {})",
        response.status()
    );
    ensure!(
        response
            .headers()
            .get(header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .and_then(content_range)
            == Some((start, end, work.size)),
        "server returned an unexpected Content-Range"
    );
    ensure!(
        response
            .headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| value.eq_ignore_ascii_case("identity")),
        "server encoded a byte-range response"
    );
    for (name, expected) in [
        (header::ETAG, &work.remote.etag),
        (header::LAST_MODIFIED, &work.remote.modified),
    ] {
        if let Some(expected) = expected {
            ensure!(
                response
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    == Some(expected.as_str()),
                "remote file validator changed during download"
            );
        }
    }
    file.seek(std::io::SeekFrom::Start(start)).await?;
    let mut received = 0u64;
    let result = async {
        while let Some(bytes) = response.chunk().await? {
            ensure!(
                bytes.len() as u64 <= end - start + 1 - received,
                "server sent bytes beyond the requested range"
            );
            file.write_all(&bytes).await?;
            received += bytes.len() as u64;
            work.received
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }
        ensure!(
            received == end - start + 1,
            "range response ended before all bytes arrived"
        );
        file.flush().await?;
        file.sync_data().await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if result.is_err() {
        work.received.fetch_sub(received, Ordering::Relaxed);
    }
    result
}

async fn worker(work: Work, completed: mpsc::Sender<usize>) -> Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&work.part)
        .await?;
    loop {
        let cursor = work.next.fetch_add(1, Ordering::Relaxed);
        let Some(index) = work.pending.get(cursor).copied() else {
            return Ok(());
        };
        for attempt in 0..6 {
            match piece(&work, &mut file, index).await {
                Ok(()) => break,
                Err(error) if attempt == 5 => {
                    return Err(error.context(format!("segment {index} failed")))
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(200u64 << attempt)).await,
            }
        }
        completed
            .send(index)
            .await
            .context("download coordinator stopped")?;
    }
}

async fn single(
    client: &Client,
    url: &Url,
    part: &Path,
    expected: Option<u64>,
    received: &AtomicU64,
) -> Result<()> {
    let response = client
        .get(url.clone())
        .header(header::ACCEPT_ENCODING, "identity")
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "download returned HTTP {}",
        response.status()
    );
    let mut response = response.bytes_stream();
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(part)
        .await?;
    let mut size = 0u64;
    while let Some(bytes) = response.next().await {
        let bytes = bytes?;
        file.write_all(&bytes).await?;
        size += bytes.len() as u64;
        received.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        if let Some(expected) = expected {
            ensure!(size <= expected, "remote file size changed");
        }
    }
    if let Some(expected) = expected {
        ensure!(size == expected, "download ended before all bytes arrived");
    }
    file.flush().await?;
    file.sync_all().await?;
    Ok(())
}

async fn checksum(path: &Path, expected: &str) -> Result<()> {
    ensure!(
        expected.len() == 64 && expected.bytes().all(|value| value.is_ascii_hexdigit()),
        "SHA256 must be 64 hexadecimal characters"
    );
    let mut file = tokio::fs::File::open(path).await?;
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut sha = Sha256::new();
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        sha.update(&buffer[..read]);
    }
    ensure!(
        format!("{:x}", sha.finalize()).eq_ignore_ascii_case(expected),
        "SHA256 mismatch; partial file kept for inspection"
    );
    Ok(())
}

pub async fn get(options: Options, cancel: CancellationToken) -> Result<PathBuf> {
    ensure!(
        (1..=128).contains(&options.connections),
        "connections must be between 1 and 128"
    );
    ensure!(options.piece_size > 0, "segment size must be positive");
    let mut url = Url::parse(&options.url)?;
    ensure!(
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
        "an HTTP(S) URL is required"
    );
    url.set_fragment(None);
    tokio::fs::create_dir_all(&options.directory).await?;
    let directory = tokio::fs::canonicalize(&options.directory).await?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(60))
        .tcp_nodelay(true)
        .http1_only()
        .pool_max_idle_per_host(options.connections)
        .build()?;
    let remote = probe(&client, &url).await?;
    let target = destination(&directory, &remote.name, url.as_str())?;
    let _lock = lock(&target)?;
    ensure!(
        !target.try_exists()?,
        "destination appeared while preparing download"
    );
    let part = sidecar(&target, ".porthub-part");
    let control = sidecar(&target, ".porthub-part.json");
    for path in [&part, &control] {
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            ensure!(
                metadata.is_file(),
                "partial download path must be a regular file"
            );
        }
    }
    let size = remote.size.unwrap_or(0);
    let mut piece_size = options.piece_size.max(size.div_ceil(4096)).max(1);
    let pieces = if remote.ranges {
        size.div_ceil(piece_size) as usize
    } else {
        0
    };
    let previous = checkpoint(&control).filter(|state| {
        state.version == 1
            && state.url == url.as_str()
            && state.size == remote.size
            && state.etag == remote.etag
            && state.modified == remote.modified
            && remote.ranges
            && size > 0
            && state.piece_size > 0
            && state.complete.len() <= 4096
            && state.complete.len() as u64 == size.div_ceil(state.piece_size)
            && (remote.etag.is_some() || remote.modified.is_some())
            && std::fs::metadata(&part).is_ok_and(|metadata| metadata.len() == size)
    });
    if let Some(saved) = &previous {
        piece_size = saved.piece_size;
    }
    let mut state = previous.unwrap_or_else(|| Checkpoint {
        version: 1,
        url: url.to_string(),
        size: remote.size,
        etag: remote.etag.clone(),
        modified: remote.modified.clone(),
        piece_size,
        complete: vec![false; pieces],
    });
    let already: u64 = state
        .complete
        .iter()
        .enumerate()
        .filter(|(_, done)| **done)
        .map(|(index, _)| piece_size.min(size - index as u64 * piece_size))
        .sum();
    state::write_private(&control, &serde_json::to_vec(&state)?)?;
    let received = Arc::new(AtomicU64::new(already));
    let started = Instant::now();
    if options.progress {
        eprintln!(
            "[porthub-get] {} connections, {} bytes already complete",
            options.connections, already
        );
    }
    let transfer = async {
        if !remote.ranges || size == 0 || (remote.etag.is_none() && remote.modified.is_none()) {
            received.store(0, Ordering::Relaxed);
            single(&client, &url, &part, remote.size, &received).await?;
        } else {
            let file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&part)
                .await?;
            file.set_len(size).await?;
            drop(file);
            let pending = Arc::new(
                state
                    .complete
                    .iter()
                    .enumerate()
                    .filter_map(|(index, done)| (!*done).then_some(index))
                    .collect::<Vec<_>>(),
            );
            let work = Work {
                client: client.clone(),
                url: url.clone(),
                part: part.clone(),
                remote: remote.clone(),
                size,
                piece_size,
                pending,
                next: Arc::new(AtomicUsize::new(0)),
                received: received.clone(),
            };
            let (tx, mut rx) = mpsc::channel(options.connections * 2);
            let mut workers = JoinSet::new();
            for _ in 0..options.connections.min(work.pending.len()) {
                workers.spawn(worker(work.clone(), tx.clone()));
            }
            drop(tx);
            while !workers.is_empty() {
                tokio::select! {
                    Some(index)=rx.recv()=>{state.complete[index]=true;state::write_private(&control,&serde_json::to_vec(&state)?)?;},
                    Some(result)=workers.join_next()=>{result??;},
                }
            }
            while let Ok(index) = rx.try_recv() {
                state.complete[index] = true;
            }
            state::write_private(&control, &serde_json::to_vec(&state)?)?;
            ensure!(
                state.complete.iter().all(|done| *done),
                "not every segment completed"
            );
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::pin!(transfer);
    let mut timer = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            result=&mut transfer=>{result?;break;},
            _=cancel.cancelled()=>bail!("download interrupted; completed segments are saved for resume"),
            _=timer.tick(),if options.progress=>{
                let done=received.load(Ordering::Relaxed);let seconds=started.elapsed().as_secs_f64().max(0.001);
                eprintln!("[porthub-get] {:.1}/{} MiB  {:.2} MB/s",done as f64/1048576.0,remote.size.map(|size|format!("{:.1}",size as f64/1048576.0)).unwrap_or_else(||"?".into()),done.saturating_sub(already) as f64/seconds/1_000_000.0);
            },
        }
    }
    let seconds = started.elapsed().as_secs_f64();
    if let Some(expected) = &options.sha256 {
        checksum(&part, expected).await?;
    }
    state::publish(&part, &target).await.context(
        "could not publish download without overwriting an existing file; partial file kept",
    )?;
    tokio::fs::remove_file(&control).await?;
    if options.progress {
        eprintln!(
            "[porthub-get] Saved {} ({:.2} MB/s)",
            target.display(),
            received.load(Ordering::Relaxed).saturating_sub(already) as f64
                / seconds.max(0.001)
                / 1_000_000.0
        );
    }
    Ok(target)
}
