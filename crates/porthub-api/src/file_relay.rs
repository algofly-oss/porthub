//! Anonymous, memory-bounded file rendezvous. Senders answer byte-range requests
//! in small streaming chunks; no file content is written to disk or MongoDB.
use crate::{
    error::{ApiError, ApiResult},
    App,
};
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use futures_util::{Stream, StreamExt};
use rand::RngCore;
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
const CHUNK: u64 = 4 * 1024 * 1024;
const IDLE: Duration = Duration::from_secs(90);
fn missing() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "Transfer unavailable. Keep the sender command running.",
    )
    .header("cache-control", "no-store")
}
fn secret() -> String {
    let mut bytes = [0; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
struct Chunk {
    cancel: CancellationToken,
    start: u64,
    len: u64,
    tx: mpsc::Sender<Result<Bytes, io::Error>>,
    done: oneshot::Sender<()>,
    progress: Arc<std::sync::atomic::AtomicU64>,
}
struct Slot {
    key: String,
    name: String,
    size: u64,
    last_sender: Mutex<Instant>,
    queue: mpsc::Sender<String>,
    requests: tokio::sync::Mutex<mpsc::Receiver<String>>,
    pending: Mutex<HashMap<String, Chunk>>,
    stop: CancellationToken,
    downloads: Arc<Semaphore>,
}
impl Slot {
    fn expired(&self) -> bool {
        self.stop.is_cancelled()
            || self
                .last_sender
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .elapsed()
                > IDLE
    }
    fn authenticated(&self, headers: &HeaderMap) -> bool {
        use sha2::{Digest, Sha256};
        use subtle::ConstantTimeEq;
        let provided = headers
            .get("x-transfer-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        bool::from(Sha256::digest(provided).ct_eq(&Sha256::digest(self.key.as_bytes())))
    }
}
pub struct Hub {
    slots: Mutex<HashMap<String, Arc<Slot>>>,
    downloads: Arc<Semaphore>,
}
impl Default for Hub {
    fn default() -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            downloads: Arc::new(Semaphore::new(256)),
        }
    }
}
impl Hub {
    pub fn close(&self) {
        for slot in self
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
        {
            slot.stop.cancel();
        }
    }
    fn get(&self, id: &str) -> ApiResult<Arc<Slot>> {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let slot = slots.get(id).cloned().ok_or_else(missing)?;
        if slot.expired() {
            slot.stop.cancel();
            slots.remove(id);
            return Err(missing());
        }
        Ok(slot)
    }
    fn publisher(&self, id: &str, headers: &HeaderMap) -> ApiResult<Arc<Slot>> {
        let slot = self.get(id)?;
        if !slot.authenticated(headers) {
            return Err(missing());
        }
        *slot.last_sender.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        Ok(slot)
    }
}
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/transfers", post(create))
        .route("/api/transfers/sender", get(sender))
        .route(
            "/api/transfers/{id}",
            get(download).head(head).delete(close),
        )
        .route("/api/transfers/{id}/next", get(next))
        .route(
            "/api/transfers/{id}/chunks/{request}",
            axum::routing::put(upload).post(upload),
        )
        .layer(axum::extract::DefaultBodyLimit::disable())
        .layer(axum::middleware::map_response(
            |mut response: Response| async move {
                response.headers_mut().insert(
                    "cache-control",
                    HeaderValue::from_static("no-store, no-transform"),
                );
                response
                    .headers_mut()
                    .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
                response.headers_mut().insert(
                    "x-content-type-options",
                    HeaderValue::from_static("nosniff"),
                );
                response
            },
        ))
}
async fn sender() -> Response {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        include_str!("transfer_sender.sh"),
    )
        .into_response()
}
async fn create(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Response> {
    let size = headers
        .get("x-transfer-size")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or_else(|| ApiError::bad_request("Provide the file size in X-Transfer-Size"))?;
    let name = if let Some(encoded) = headers.get("x-transfer-name-encoded") {
        percent_encoding::percent_decode_str(
            encoded
                .to_str()
                .map_err(|_| ApiError::bad_request("Invalid filename"))?,
        )
        .decode_utf8()
        .map_err(|_| ApiError::bad_request("Invalid filename"))?
        .into_owned()
    } else {
        headers
            .get("x-transfer-name")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .unwrap_or("download.bin")
            .to_owned()
    };
    let name = name
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\')
        .take(255)
        .collect::<String>();
    let mut slots = app
        .file_relay
        .slots
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    slots.retain(|_, s| {
        if s.expired() {
            s.stop.cancel();
            false
        } else {
            true
        }
    });
    if slots.len() >= 128 {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "Transfer capacity is full. Try again shortly.",
        ));
    }
    let id = secret();
    let key = secret();
    let (queue, requests) = mpsc::channel(128);
    slots.insert(
        id.clone(),
        Arc::new(Slot {
            key: key.clone(),
            name: if name.is_empty() {
                "download.bin".into()
            } else {
                name
            },
            size,
            last_sender: Mutex::new(Instant::now()),
            queue,
            requests: tokio::sync::Mutex::new(requests),
            pending: Mutex::new(HashMap::new()),
            stop: CancellationToken::new(),
            downloads: Arc::new(Semaphore::new(64)),
        }),
    );
    Ok((StatusCode::CREATED, format!("{id} {key}\n")).into_response())
}
async fn close(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let slot = app.file_relay.publisher(&id, &headers)?;
    slot.stop.cancel();
    app.file_relay
        .slots
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id);
    Ok(StatusCode::NO_CONTENT.into_response())
}
async fn next(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let slot = app.file_relay.publisher(&id, &headers)?;
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        let mut rx = slot.requests.lock().await;
        loop {
            let request =
                tokio::select! {_ = slot.stop.cancelled()=>return None,request=rx.recv()=>request?};
            let pending = slot.pending.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(chunk) = pending.get(&request) {
                return Some(format!("{request} {} {}\n", chunk.start, chunk.len));
            }
        }
    })
    .await;
    match result {
        Ok(Some(value)) => Ok(value.into_response()),
        Ok(None) => Err(missing()),
        Err(_) => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}
fn range(headers: &HeaderMap, size: u64) -> Result<(u64, u64, bool), ()> {
    let Some(header) = headers.get("range") else {
        return Ok((0, size, false));
    };
    let value = header
        .to_str()
        .map_err(|_| ())?
        .strip_prefix("bytes=")
        .ok_or(())?;
    if value.contains(',') || size == 0 {
        return Err(());
    }
    let (start, end) = value.split_once('-').ok_or(())?;
    if start.is_empty() {
        let len = end.parse::<u64>().map_err(|_| ())?.min(size);
        if len == 0 {
            return Err(());
        }
        return Ok((size - len, size, true));
    }
    let start = start.parse::<u64>().map_err(|_| ())?;
    if start >= size {
        return Err(());
    }
    let end = if end.is_empty() {
        size
    } else {
        end.parse::<u64>()
            .map_err(|_| ())?
            .checked_add(1)
            .ok_or(())?
            .min(size)
    };
    if end <= start {
        return Err(());
    }
    Ok((start, end, true))
}
fn file_headers(slot: &Slot, start: u64, end: u64, partial: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert("accept-ranges", HeaderValue::from_static("bytes"));
    headers.insert("content-length", (end - start).to_string().parse().unwrap());
    let ascii: String = slot
        .name
        .chars()
        .map(|c| {
            if (c.is_ascii_graphic() || c == ' ') && c != '"' && c != '\\' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let escaped =
        percent_encoding::utf8_percent_encode(&slot.name, percent_encoding::NON_ALPHANUMERIC);
    if let Ok(value) =
        format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{escaped}").parse()
    {
        headers.insert("content-disposition", value);
    }
    if partial {
        headers.insert(
            "content-range",
            format!("bytes {start}-{}/{}", end - 1, slot.size)
                .parse()
                .unwrap(),
        );
    }
    headers
}
async fn head(State(app): State<Arc<App>>, Path(id): Path<String>) -> ApiResult<Response> {
    let slot = app.file_relay.get(&id)?;
    Ok((
        StatusCode::OK,
        file_headers(&slot, 0, slot.size, false),
        Body::empty(),
    )
        .into_response())
}
struct PendingGuard {
    cancel: CancellationToken,
    slot: Arc<Slot>,
    id: String,
}
impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.slot
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}
struct Download {
    rx: mpsc::Receiver<Result<Bytes, io::Error>>,
    actor: tokio::task::JoinHandle<()>,
    _global: OwnedSemaphorePermit,
    _local: OwnedSemaphorePermit,
}
impl Stream for Download {
    type Item = Result<Bytes, io::Error>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().rx.poll_recv(cx)
    }
}
impl Drop for Download {
    fn drop(&mut self) {
        self.actor.abort();
    }
}
async fn download(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let slot = app.file_relay.get(&id)?;
    let (start, end, partial) = match range(&headers, slot.size) {
        Ok(r) => r,
        Err(_) => {
            return Ok((
                StatusCode::RANGE_NOT_SATISFIABLE,
                [("content-range", format!("bytes */{}", slot.size))],
                Body::empty(),
            )
                .into_response())
        }
    };
    let global = app
        .file_relay
        .downloads
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::new(StatusCode::TOO_MANY_REQUESTS, "Download capacity is full"))?;
    let local = slot.downloads.clone().try_acquire_owned().map_err(|_| {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "This transfer has too many active connections",
        )
    })?;
    let status = if partial {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let headers = file_headers(&slot, start, end, partial);
    let (tx, rx) = mpsc::channel(2);
    let actor = tokio::spawn(async move {
        if let Err(error) = stream_download(slot, tx.clone(), start, end).await {
            let _ = tx.send(Err(error)).await;
        }
    });
    Ok((
        status,
        headers,
        Body::from_stream(Download {
            rx,
            actor,
            _global: global,
            _local: local,
        }),
    )
        .into_response())
}
async fn stream_download(
    slot: Arc<Slot>,
    tx: mpsc::Sender<Result<Bytes, io::Error>>,
    start: u64,
    end: u64,
) -> io::Result<()> {
    let mut offset = start;
    let mut failures = 0;
    while offset < end {
        if slot.expired() {
            return Err(io::Error::other("Sender disconnected"));
        }
        let request = secret();
        let (done, mut finished) = oneshot::channel();
        let cancel = slot.stop.child_token();
        let progress = Arc::new(std::sync::atomic::AtomicU64::new(0));
        slot.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                request.clone(),
                Chunk {
                    cancel: cancel.clone(),
                    start: offset,
                    len: (end - offset).min(CHUNK),
                    tx: tx.clone(),
                    done,
                    progress: progress.clone(),
                },
            );
        let guard = PendingGuard {
            cancel,
            slot: slot.clone(),
            id: request.clone(),
        };
        tokio::select! {
            _ = slot.stop.cancelled() => return Err(io::Error::other("Sender stopped the transfer")),
            result = slot.queue.send(request) => result.map_err(|_| io::Error::other("Transfer closed"))?,
        }
        let completed = tokio::select! {
            _ = slot.stop.cancelled() => return Err(io::Error::other("Sender stopped the transfer")),
            _ = tx.closed() => return Ok(()),
            result = tokio::time::timeout(Duration::from_secs(75), &mut finished) => result,
        };
        // Cancel and await an interrupted writer before another writer can send
        // into the same response. Resume only after its last delivered byte.
        drop(guard);
        let successful = matches!(completed, Ok(Ok(())));
        if completed.is_err() {
            let _ = finished.await;
        }
        let received = progress.load(std::sync::atomic::Ordering::Acquire);
        offset += received;
        if successful || received > 0 {
            failures = 0;
        } else {
            failures += 1;
            if failures > 8 {
                return Err(io::Error::other("Sender could not complete the download"));
            }
        }
    }
    Ok(())
}

async fn upload(
    State(app): State<Arc<App>>,
    Path((id, request)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Response> {
    let slot = app.file_relay.publisher(&id, &headers)?;
    let chunk = slot
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&request)
        .ok_or_else(missing)?;
    let expected = chunk.len;
    let mut stream = body.into_data_stream();
    let mut sent = 0u64;
    let done = chunk.done;
    while let Some(bytes) = tokio::select! {_=chunk.cancel.cancelled()=>return Err(missing()),frame=tokio::time::timeout(Duration::from_secs(45),stream.next())=>frame.map_err(|_|missing())?}
    {
        let bytes = bytes.map_err(|_| ApiError::bad_request("Upload stream interrupted"))?;
        if sent + bytes.len() as u64 > expected {
            return Err(ApiError::bad_request(
                "Upload chunk exceeds requested byte range",
            ));
        }
        // Frames are split so a single transport frame cannot inflate a download queue.
        for part in bytes.chunks(64 * 1024) {
            let part = Bytes::copy_from_slice(part);
            tokio::select!{_=chunk.cancel.cancelled()=>return Err(missing()),result=tokio::time::timeout(Duration::from_secs(30), chunk.tx.send(Ok(part.clone())))=>result}
                .map_err(|_| missing())?
                .map_err(|_| missing())?;
            sent += part.len() as u64;
            chunk
                .progress
                .store(sent, std::sync::atomic::Ordering::Release);
        }
    }
    if sent != expected {
        return Err(ApiError::bad_request(
            "Upload chunk ended before its requested byte range",
        ));
    }
    let _ = done.send(());
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byte_ranges_cover_parallel_resume_suffix_and_invalid_requests() {
        for (value, expected) in [
            ("bytes=0-3", Ok((0, 4, true))),
            ("bytes=4-", Ok((4, 10, true))),
            ("bytes=-3", Ok((7, 10, true))),
            ("bytes=8-100", Ok((8, 10, true))),
            ("bytes=10-", Err(())),
            ("bytes=5-2", Err(())),
            ("bytes=0-1,5-6", Err(())),
        ] {
            let mut h = HeaderMap::new();
            h.insert("range", value.parse().unwrap());
            assert_eq!(range(&h, 10), expected);
        }
    }
}
