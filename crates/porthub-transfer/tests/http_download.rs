use anyhow::Result;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use porthub_transfer::{
    download::{self, Options},
    server,
};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

struct Http {
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Http {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn http(router: Router) -> Result<Http> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(Http { url, task })
}
fn options(url: String, directory: PathBuf) -> Options {
    let mut options = Options::new(url, directory);
    options.connections = 4;
    options.piece_size = 256 * 1024;
    options.progress = false;
    options
}

#[tokio::test]
async fn ranges_parallel_download_checksum_and_safe_collision() -> Result<()> {
    let source = tempfile::tempdir()?;
    let destination = tempfile::tempdir()?;
    let payload: Vec<u8> = (0..3 * 1024 * 1024 + 71).map(|n| (n % 251) as u8).collect();
    tokio::fs::write(source.path().join("payload.bin"), &payload).await?;
    // Apostrophes and ampersands exercise HTML escaping on every supported OS.
    // Windows rejects angle brackets in file names before HTTP is involved.
    tokio::fs::write(source.path().join("'&.txt"), b"file").await?;
    #[cfg(not(windows))]
    tokio::fs::write(source.path().join("<&.txt"), b"file").await?;
    let http = http(server::router(
        tokio::fs::canonicalize(source.path()).await?,
    ))
    .await?;
    let client = reqwest::Client::new();
    let url = format!("{}/payload.bin", http.url);
    let range = client
        .get(&url)
        .header(header::RANGE, "bytes=3-9")
        .send()
        .await?;
    assert_eq!(range.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        range.headers()[header::CONTENT_RANGE],
        format!("bytes 3-9/{}", payload.len())
    );
    let etag = range.headers()[header::ETAG].to_str()?.to_owned();
    assert_eq!(range.bytes().await?.as_ref(), &payload[3..10]);
    let stale = client
        .get(&url)
        .header(header::RANGE, "bytes=0-0")
        .header(header::IF_RANGE, "\"stale\"")
        .send()
        .await?;
    assert_eq!(stale.status(), StatusCode::OK);
    let head = client.head(&url).send().await?;
    assert_eq!(
        head.headers()[header::CONTENT_LENGTH],
        payload.len().to_string()
    );
    assert!(head.bytes().await?.is_empty());
    let cached = client
        .get(&url)
        .header(header::IF_NONE_MATCH, etag)
        .send()
        .await?;
    assert_eq!(cached.status(), StatusCode::NOT_MODIFIED);
    let index = client.get(&http.url).send().await?.text().await?;
    assert!(index.contains("&#39;&amp;.txt"));
    assert!(!index.contains(">'&.txt<"));
    #[cfg(not(windows))]
    {
        assert!(index.contains("&lt;&amp;.txt"));
        assert!(!index.contains("><&.txt<"));
    }
    let mut settings = options(url.clone(), destination.path().into());
    settings.sha256 = Some(format!("{:x}", Sha256::digest(&payload)));
    let path = download::get(settings, CancellationToken::new()).await?;
    assert_eq!(tokio::fs::read(&path).await?, payload);
    let second = download::get(
        options(url, destination.path().into()),
        CancellationToken::new(),
    )
    .await?;
    assert_ne!(path, second);
    assert_eq!(tokio::fs::read(&second).await?, payload);
    assert!(path
        .with_file_name("payload.bin.porthub-part")
        .try_exists()?
        .eq(&false));
    Ok(())
}

#[tokio::test]
async fn non_range_and_empty_files_use_single_stream() -> Result<()> {
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    let http = http(
        Router::new()
            .route(
                "/plain",
                get(move || {
                    counted.fetch_add(1, Ordering::SeqCst);
                    async { "plain content" }
                }),
            )
            .route(
                "/empty",
                get(|| async {
                    Response::builder()
                        .status(StatusCode::RANGE_NOT_SATISFIABLE)
                        .header(header::CONTENT_RANGE, "bytes */0")
                        .body(Body::empty())
                        .unwrap()
                }),
            ),
    )
    .await?;
    let destination = tempfile::tempdir()?;
    let path = download::get(
        options(format!("{}/plain", http.url), destination.path().into()),
        CancellationToken::new(),
    )
    .await?;
    assert_eq!(tokio::fs::read(path).await?, b"plain content");
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    // Use the real file server for an empty object: probe responds 416, GET 200.
    let source = tempfile::tempdir()?;
    tokio::fs::write(source.path().join("empty"), b"").await?;
    let real = http_server(source.path().into()).await?;
    let path = download::get(
        options(format!("{}/empty", real.url), destination.path().into()),
        CancellationToken::new(),
    )
    .await?;
    assert_eq!(tokio::fs::metadata(path).await?.len(), 0);
    Ok(())
}

async fn http_server(root: PathBuf) -> Result<Http> {
    http(server::router(tokio::fs::canonicalize(root).await?)).await
}

#[tokio::test]
async fn cancellation_resumes_validated_completed_segments() -> Result<()> {
    let source = tempfile::tempdir()?;
    let destination = tempfile::tempdir()?;
    let payload = vec![73u8; 8 * 1024 * 1024];
    tokio::fs::write(source.path().join("resume.bin"), &payload).await?;
    let base = server::router(tokio::fs::canonicalize(source.path()).await?);
    // Delay data responses so cancellation is deterministic after early pieces
    // are checkpointed, rather than relying on loopback throughput timing.
    let router = base.layer(axum::middleware::from_fn(
        |request: Request<Body>, next: axum::middleware::Next| async move {
            if request
                .headers()
                .get(header::RANGE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value != "bytes=0-0")
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            next.run(request).await
        },
    ));
    let http = http(router).await?;
    let url = format!("{}/resume.bin", http.url);
    let token = CancellationToken::new();
    let cancel = token.clone();
    let dir = destination.path().to_path_buf();
    let first_url = url.clone();
    let task = tokio::spawn(async move { download::get(options(first_url, dir), token).await });
    let control = destination.path().join("resume.bin.porthub-part.json");
    for _ in 0..100 {
        if tokio::fs::read(&control)
            .await
            .ok()
            .and_then(|value| serde_json::from_slice::<serde_json::Value>(&value).ok())
            .and_then(|value| {
                value["complete"]
                    .as_array()
                    .map(|values| values.iter().any(|value| value == true))
            })
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    cancel.cancel();
    assert!(task.await?.is_err());
    let state: serde_json::Value = serde_json::from_slice(&tokio::fs::read(&control).await?)?;
    assert!(state["complete"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == true));
    assert!(state["complete"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == false));
    let mut settings = options(url, destination.path().into());
    settings.sha256 = Some(format!("{:x}", Sha256::digest(&payload)));
    let path = download::get(settings, CancellationToken::new()).await?;
    assert_eq!(tokio::fs::read(path).await?, payload);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn symlinks_cannot_escape_document_root() -> Result<()> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    tokio::fs::write(outside.path().join("secret"), b"private").await?;
    std::os::unix::fs::symlink(outside.path(), root.path().join("escape"))?;
    let http = http_server(root.path().into()).await?;
    let response = reqwest::get(format!("{}/escape/secret", http.url)).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn changed_validator_discards_old_resume_segments() -> Result<()> {
    let source = tempfile::tempdir()?;
    let destination = tempfile::tempdir()?;
    let first = vec![11u8; 8 * 1024 * 1024];
    tokio::fs::write(source.path().join("changed.bin"), &first).await?;
    let router = server::router(tokio::fs::canonicalize(source.path()).await?).layer(
        axum::middleware::from_fn(
            |request: Request<Body>, next: axum::middleware::Next| async move {
                if request
                    .headers()
                    .get(header::RANGE)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value != "bytes=0-0")
                {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                }
                next.run(request).await
            },
        ),
    );
    let http = http(router).await?;
    let url = format!("{}/changed.bin", http.url);
    let token = CancellationToken::new();
    let cancel = token.clone();
    let dir = destination.path().to_path_buf();
    let first_url = url.clone();
    let task = tokio::spawn(async move { download::get(options(first_url, dir), token).await });
    let control = destination.path().join("changed.bin.porthub-part.json");
    for _ in 0..100 {
        if tokio::fs::read(&control)
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|value| {
                value["complete"]
                    .as_array()
                    .map(|values| values.iter().any(|value| value == true))
            })
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    cancel.cancel();
    assert!(task.await?.is_err());
    let replacement = vec![23u8; 8 * 1024 * 1024];
    tokio::fs::write(source.path().join("changed.bin"), &replacement).await?;
    let mut settings = options(url, destination.path().into());
    settings.sha256 = Some(format!("{:x}", Sha256::digest(&replacement)));
    let path = download::get(settings, CancellationToken::new()).await?;
    assert_eq!(tokio::fs::read(path).await?, replacement);
    Ok(())
}

#[tokio::test]
async fn checksum_failure_never_publishes_an_incorrect_file() -> Result<()> {
    let source = tempfile::tempdir()?;
    let destination = tempfile::tempdir()?;
    tokio::fs::write(source.path().join("wrong.bin"), b"data").await?;
    let http = http_server(source.path().into()).await?;
    let mut settings = options(format!("{}/wrong.bin", http.url), destination.path().into());
    settings.sha256 = Some("0".repeat(64));
    assert!(download::get(settings, CancellationToken::new())
        .await
        .is_err());
    assert!(!destination.path().join("wrong.bin").exists());
    assert!(destination.path().join("wrong.bin.porthub-part").exists());
    Ok(())
}

#[tokio::test]
async fn trailing_slash_query_and_server_filenames_are_preserved() -> Result<()> {
    let router=Router::new()
        .route("/archive.tar.gz/",get(||async{"archive bytes"}))
        .route("/wrong-name/",get(||async{([(header::CONTENT_DISPOSITION,"attachment; filename=\"server;name.bin\"")],"server bytes")}))
        .route("/unicode/",get(||async{([(header::CONTENT_DISPOSITION,"attachment; filename=\"fallback.bin\"; filename*=UTF-8''r%C3%A9sum%C3%A9.bin")],"unicode bytes")}));
    let http = http(router).await?;
    for (path, name, body) in [
        (
            "/archive.tar.gz/?download=true",
            "archive.tar.gz",
            "archive bytes",
        ),
        ("/wrong-name/", "server;name.bin", "server bytes"),
        ("/unicode/", "résumé.bin", "unicode bytes"),
    ] {
        let destination = tempfile::tempdir()?;
        let file = download::get(
            options(format!("{}{path}", http.url), destination.path().into()),
            CancellationToken::new(),
        )
        .await?;
        assert_eq!(file.file_name().unwrap().to_string_lossy(), name);
        assert_eq!(tokio::fs::read(&file).await?, body.as_bytes());
    }
    Ok(())
}
