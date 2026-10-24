use crate::state;
use anyhow::{bail, Context, Result};
use axum::serve::ListenerExt;
use axum::{
    body::{Body, HttpBody},
    extract::{Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tower_http::services::ServeFile;
mod legacy;

#[derive(Clone, Debug)]
pub struct Options {
    pub port: u16,
    pub bind: IpAddr,
    pub root: PathBuf,
    pub accept_uploads: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub pid: u32,
    pub port: u16,
    pub bind: IpAddr,
    pub root: PathBuf,
    #[serde(default)]
    pub accepts_uploads: bool,
    pub started_unix: u64,
    control: SocketAddr,
    token: String,
}

struct Registration {
    path: PathBuf,
    token: String,
}
impl Drop for Registration {
    fn drop(&mut self) {
        if std::fs::read(&self.path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Record>(&bytes).ok())
            .is_some_and(|record| record.token == self.token)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[derive(Clone)]
struct Control {
    token: String,
    shutdown: CancellationToken,
}

fn authorized(request: &Request, control: &Control) -> bool {
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some(format!("Bearer {}", control.token).as_str())
}

async fn identity(State(control): State<Control>, request: Request) -> StatusCode {
    if authorized(&request, &control) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::FORBIDDEN
    }
}
async fn stop(State(control): State<Control>, request: Request) -> StatusCode {
    if !authorized(&request, &control) {
        return StatusCode::FORBIDDEN;
    }
    control.shutdown.cancel();
    StatusCode::NO_CONTENT
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn router(root: PathBuf) -> Router {
    Router::new().fallback(files).with_state(Arc::new(root))
}

async fn files(State(root): State<Arc<PathBuf>>, mut request: Request) -> Response {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "GET, HEAD")],
        )
            .into_response();
    }
    let decoded = match percent_decode_str(request.uri().path()).decode_utf8() {
        Ok(path) => path,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if decoded.contains('\\') || decoded.contains('\0') {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let relative = Path::new(decoded.trim_start_matches('/'));
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let file = match tokio::fs::canonicalize(root.join(relative)).await {
        Ok(file) if file.starts_with(root.as_path()) => file,
        Ok(_) => return StatusCode::FORBIDDEN.into_response(),
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let metadata = match tokio::fs::metadata(&file).await {
        Ok(metadata) => metadata,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    if metadata.is_dir() {
        if !request.uri().path().ends_with('/') {
            return Redirect::permanent(&format!("{}/", request.uri().path())).into_response();
        }
        let mut entries = match tokio::fs::read_dir(&file).await {
            Ok(entries) => entries,
            Err(_) => return StatusCode::FORBIDDEN.into_response(),
        };
        let mut names = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            let suffix = if entry.file_type().await.is_ok_and(|kind| kind.is_dir()) {
                "/"
            } else {
                ""
            };
            names.push((name, suffix));
        }
        names.sort_by(|a, b| a.0.cmp(&b.0));
        let title = escape(&decoded);
        let mut html=format!("<!doctype html><meta charset=\"utf-8\"><title>Files: {title}</title><h1>Files: {title}</h1><ul>");
        if file != *root {
            html.push_str("<li><a href=\"../\">../</a></li>");
        }
        for (name, suffix) in names {
            html.push_str(&format!(
                "<li><a href=\"{}{suffix}\">{}{suffix}</a></li>",
                utf8_percent_encode(&name, NON_ALPHANUMERIC),
                escape(&name)
            ));
        }
        html.push_str("</ul>");
        let mut response = Html(html).into_response();
        if request.method() == Method::HEAD {
            let size = response.body().size_hint().exact().unwrap_or(0);
            *response.body_mut() = Body::empty();
            if let Ok(value) = HeaderValue::from_str(&size.to_string()) {
                response.headers_mut().insert(header::CONTENT_LENGTH, value);
            }
        }
        return response;
    }
    if !metadata.is_file() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|time| time.as_nanos())
        .unwrap_or(0);
    let etag = format!("\"{:x}-{modified:x}\"", metadata.len());
    if request
        .headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim() == etag || part.trim() == "*")
        })
    {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
    }
    if let Some(value) = request
        .headers()
        .get(header::IF_RANGE)
        .and_then(|value| value.to_str().ok())
    {
        let valid = if value.starts_with('"') {
            value == etag
        } else {
            httpdate::parse_http_date(value)
                .ok()
                .zip(metadata.modified().ok())
                .is_some_and(|(since, modified)| {
                    modified
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        <= since
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                })
        };
        if !valid {
            request.headers_mut().remove(header::RANGE);
        }
        request.headers_mut().remove(header::IF_RANGE);
    }
    if metadata.len() == 0 && request.headers().contains_key(header::RANGE) {
        return (
            StatusCode::RANGE_NOT_SATISFIABLE,
            [
                (header::CONTENT_RANGE, "bytes */0"),
                (header::CONTENT_LENGTH, "0"),
                (header::ETAG, etag.as_str()),
            ],
        )
            .into_response();
    }
    match ServeFile::new(file)
        .with_buf_chunk_size(256 * 1024)
        .oneshot(request)
        .await
    {
        Ok(response) => {
            let mut response = response.map(Body::new);
            response.headers_mut().insert(
                header::ETAG,
                HeaderValue::from_str(&etag).expect("generated ETag"),
            );
            let modified_unix = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|time| time.as_secs().to_string())
                .unwrap_or_default();
            if let Ok(value) = HeaderValue::from_str(&modified_unix) {
                response
                    .headers_mut()
                    .insert("x-porthub-modified-unix", value);
            }
            response
        }
        Err(error) => match error {},
    }
}

pub async fn serve(options: Options, shutdown: CancellationToken) -> Result<()> {
    let root = tokio::fs::canonicalize(&options.root)
        .await
        .context("document root is unavailable")?;
    anyhow::ensure!(root.is_dir(), "document root must be a directory");
    let data = TcpListener::bind(SocketAddr::new(options.bind, options.port)).await?;
    let port = data.local_addr()?.port();
    let control_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut secret)?;
    let token = secret
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let record = Record {
        pid: std::process::id(),
        port,
        bind: options.bind,
        root: root.clone(),
        accepts_uploads: options.accept_uploads,
        started_unix: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        control: control_listener.local_addr()?,
        token: token.clone(),
    };
    let path = state::directory("http-servers")?.join(format!("server-{port}.json"));
    state::write_private(&path, &serde_json::to_vec(&record)?)?;
    let _registration = Registration {
        path,
        token: token.clone(),
    };
    let control = Router::new()
        .route("/identity", get(identity))
        .route("/stop", post(stop))
        .with_state(Control {
            token,
            shutdown: shutdown.clone(),
        });
    let data = data.tap_io(|stream| {
        let _ = stream.set_nodelay(true);
    });
    #[cfg(unix)]
    let hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
    #[cfg(unix)]
    let hangup_guard = tokio::spawn(async move {
        if let Some(mut signal) = hangup {
            while signal.recv().await.is_some() {}
        }
    });
    let mut app = router(root.clone());
    if options.accept_uploads {
        app = app.merge(crate::upload::routes(root.clone())?);
    }
    let data_server =
        axum::serve(data, app).with_graceful_shutdown(shutdown.clone().cancelled_owned());
    let control_server = axum::serve(control_listener, control)
        .with_graceful_shutdown(shutdown.clone().cancelled_owned());
    eprintln!(
        "[porthub-http.server] Serving {} on {}:{port} (uploads: {})",
        root.display(),
        options.bind,
        options.accept_uploads
    );
    let result = tokio::select! {result=data_server=>result,result=control_server=>result};
    #[cfg(unix)]
    hangup_guard.abort();
    shutdown.cancel();
    result?;
    Ok(())
}

fn records() -> Result<Vec<(PathBuf, Record)>> {
    let mut records = Vec::new();
    for entry in std::fs::read_dir(state::directory("http-servers")?)? {
        let entry = entry?;
        if entry
            .path()
            .extension()
            .is_none_or(|extension| extension != "json")
        {
            continue;
        }
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                continue;
            }
        }
        if let Ok(record) = serde_json::from_slice::<Record>(&std::fs::read(entry.path())?) {
            if record.control.ip().is_loopback() {
                records.push((entry.path(), record));
            }
        }
    }
    records.sort_by_key(|(_, record)| record.port);
    Ok(records)
}

pub async fn list() -> Result<Vec<Record>> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(2))
        .build()?;
    let mut result = Vec::new();
    for (_, record) in records()? {
        if client
            .get(format!("http://{}/identity", record.control))
            .bearer_auth(&record.token)
            .send()
            .await
            .is_ok_and(|response| response.status() == StatusCode::NO_CONTENT)
        {
            result.push(record);
        }
    }
    result.extend(legacy::list().await?.into_iter().map(|(_, record)| record));
    result.sort_by_key(|record| record.port);
    Ok(result)
}

pub async fn stop_servers(port: Option<u16>) -> Result<Vec<u16>> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;
    let mut stopped = Vec::new();
    for (_, record) in records()? {
        if port.is_some_and(|port| port != record.port) {
            continue;
        }
        if client
            .post(format!("http://{}/stop", record.control))
            .bearer_auth(&record.token)
            .send()
            .await
            .is_ok_and(|response| response.status() == StatusCode::NO_CONTENT)
        {
            stopped.push(record.port);
        }
    }
    stopped.extend(legacy::stop(port).await?);
    if port.is_some() && stopped.is_empty() {
        bail!("no matching PortHub file server is running for this user");
    }
    Ok(stopped)
}
