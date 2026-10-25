use anyhow::Result;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use futures_util::StreamExt;
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
async fn single_connection_streams_across_checkpoints_and_resumes_only_the_missing_tail(
) -> Result<()> {
    let source = tempfile::tempdir()?;
    let destination = tempfile::tempdir()?;
    let payload: Vec<u8> = (0..3 * 1024 * 1024 + 71)
        .map(|value| (value % 251) as u8)
        .collect();
    tokio::fs::write(source.path().join("continuous.bin"), &payload).await?;
    let ranges = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let recorded = ranges.clone();
    let router = server::router(tokio::fs::canonicalize(source.path()).await?).layer(
        axum::middleware::from_fn(
            move |request: Request<Body>, next: axum::middleware::Next| {
                let recorded = recorded.clone();
                async move {
                    let data = request
                        .headers()
                        .get(header::RANGE)
                        .and_then(|value| value.to_str().ok())
                        .filter(|range| *range != "bytes=0-0")
                        .map(str::to_owned);
                    if let Some(range) = &data {
                        recorded.lock().unwrap().push(range.clone());
                    }
                    let response = next.run(request).await;
                    if data.is_none() {
                        return response;
                    }
                    let (parts, body) = response.into_parts();
                    let chunks = body.into_data_stream().then(|chunk| async {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        chunk
                    });
                    Response::from_parts(parts, Body::from_stream(chunks))
                }
            },
        ),
    );
    let server = http(router).await?;
    let mut settings = options(
        format!("{}/continuous.bin", server.url),
        destination.path().into(),
    );
    settings.connections = 1;
    settings.sha256 = Some(format!("{:x}", Sha256::digest(&payload)));
    let cancel = CancellationToken::new();
    let stopping = cancel.clone();
    let first = settings.clone();
    let task = tokio::spawn(async move { download::get(first, stopping).await });
    let control = destination.path().join("continuous.bin.porthub-part.json");
    for _ in 0..200 {
        let ready = tokio::fs::read(&control)
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .is_some_and(|state| state["complete"][0] == true);
        if ready {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    cancel.cancel();
    assert!(task.await?.is_err());
    let checkpoint: serde_json::Value = serde_json::from_slice(&tokio::fs::read(&control).await?)?;
    let complete = checkpoint["complete"].as_array().unwrap();
    let first_missing = complete
        .iter()
        .position(|done| *done == false)
        .expect("cancellation must precede EOF");
    assert!(first_missing > 0);
    let path = download::get(settings.clone(), CancellationToken::new()).await?;
    assert_eq!(tokio::fs::read(path).await?, payload);
    assert_eq!(
        *ranges.lock().unwrap(),
        vec![
            format!("bytes=0-{}", payload.len() - 1),
            format!(
                "bytes={}-{}",
                first_missing as u64 * settings.piece_size,
                payload.len() - 1
            )
        ]
    );
    Ok(())
}

#[tokio::test]
async fn interrupted_continuous_response_retries_after_durable_checkpoints() -> Result<()> {
    let source = tempfile::tempdir()?;
    let destination = tempfile::tempdir()?;
    let payload: Vec<u8> = (0..3 * 1024 * 1024 + 71)
        .map(|value| (value % 251) as u8)
        .collect();
    tokio::fs::write(source.path().join("retry.bin"), &payload).await?;
    let ranges = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let recorded = ranges.clone();
    let requests = Arc::new(AtomicUsize::new(0));
    let router = server::router(tokio::fs::canonicalize(source.path()).await?).layer(
        axum::middleware::from_fn(
            move |request: Request<Body>, next: axum::middleware::Next| {
                let recorded = recorded.clone();
                let requests = requests.clone();
                async move {
                    let range = request
                        .headers()
                        .get(header::RANGE)
                        .and_then(|value| value.to_str().ok())
                        .filter(|range| *range != "bytes=0-0")
                        .map(str::to_owned);
                    let truncate = range.is_some() && requests.fetch_add(1, Ordering::Relaxed) == 0;
                    if let Some(range) = range {
                        recorded.lock().unwrap().push(range);
                    }
                    let response = next.run(request).await;
                    if !truncate {
                        return response;
                    }
                    let (parts, body) = response.into_parts();
                    let chunks = body
                        .into_data_stream()
                        .scan(512 * 1024 + 17, |remaining, chunk| {
                            let next = if *remaining == 0 {
                                None
                            } else {
                                Some(chunk.map(|bytes| {
                                    let count = bytes.len().min(*remaining);
                                    *remaining -= count;
                                    bytes.slice(..count)
                                }))
                            };
                            futures_util::future::ready(next)
                        })
                        .then(|chunk| async {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                            chunk
                        });
                    Response::from_parts(parts, Body::from_stream(chunks))
                }
            },
        ),
    );
    let server = http(router).await?;
    let mut settings = options(
        format!("{}/retry.bin", server.url),
        destination.path().into(),
    );
    settings.connections = 1;
    settings.sha256 = Some(format!("{:x}", Sha256::digest(&payload)));
    let path = download::get(settings.clone(), CancellationToken::new()).await?;
    assert_eq!(tokio::fs::read(path).await?, payload);
    let requests = ranges.lock().unwrap();
    assert_eq!(requests.len(), 2);
    let resumed = requests[1]
        .strip_prefix("bytes=")
        .unwrap()
        .split('-')
        .next()
        .unwrap()
        .parse::<u64>()?;
    assert!(resumed >= settings.piece_size && resumed <= 512 * 1024);
    assert_eq!(resumed % settings.piece_size, 0);
    Ok(())
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
async fn porthub_server_directory_get_syncs_nested_files_and_preserves_timestamps() -> Result<()> {
    let source = tempfile::tempdir()?;
    let destination = tempfile::tempdir()?;
    let dataset = source.path().join("dataset");
    tokio::fs::create_dir_all(dataset.join("nested/empty-dir")).await?;
    tokio::fs::write(dataset.join("top.txt"), b"top-level").await?;
    tokio::fs::write(dataset.join("nested/payload.bin"), vec![31; 700_123]).await?;
    tokio::fs::write(dataset.join("zero"), b"").await?;
    let source_file = dataset.join("nested/payload.bin");
    let timestamp = filetime::FileTime::from_unix_time(1_700_000_123, 456_000_000);
    filetime::set_file_mtime(&source_file, timestamp)?;
    let http = http(server::router(
        tokio::fs::canonicalize(source.path()).await?,
    ))
    .await?;

    let url = format!("{}/dataset?access=fixture", http.url);
    let parsed_url = reqwest::Url::parse(&format!("{}/dataset/?access=fixture", http.url))?;
    let staging_digest = format!("{:x}", Sha256::digest(parsed_url.as_str().as_bytes()));
    let colliding_remote_directory = format!(".porthub-download-{}", &staging_digest[..24]);
    tokio::fs::create_dir(dataset.join(&colliding_remote_directory)).await?;
    let output = download::get(
        options(url.clone(), destination.path().into()),
        CancellationToken::new(),
    )
    .await?;
    assert_eq!(
        output.file_name().and_then(|name| name.to_str()),
        Some("dataset")
    );
    assert_eq!(tokio::fs::read(output.join("top.txt")).await?, b"top-level");
    assert_eq!(
        tokio::fs::read(output.join("nested/payload.bin")).await?,
        vec![31; 700_123]
    );
    assert_eq!(tokio::fs::read(output.join("zero")).await?, b"");
    assert!(output.join("nested/empty-dir").is_dir());
    assert!(output.join(&colliding_remote_directory).is_dir());
    assert_eq!(
        tokio::fs::metadata(output.join("nested/payload.bin"))
            .await?
            .modified()?,
        timestamp.into()
    );
    let staging_named_entries = std::fs::read_dir(&output)?
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".porthub-download-"))
        .collect::<Vec<_>>();
    assert_eq!(
        staging_named_entries,
        vec![colliding_remote_directory.clone()]
    );

    // A second get reuses the directory, skips unchanged files and preserves
    // the remote mtime so later runs can make the same decision.
    let second = download::get(
        options(url.clone(), destination.path().into()),
        CancellationToken::new(),
    )
    .await?;
    assert_eq!(second, output);

    let staging_root = output.join(format!(".porthub-download-{}-1", &staging_digest[..24]));
    tokio::fs::create_dir(&staging_root).await?;
    tokio::fs::write(
        staging_root.join(format!(".porthub-owner-{}", &staging_digest[..24])),
        staging_digest.as_bytes(),
    )
    .await?;
    tokio::fs::write(staging_root.join("top.txt"), b"old-top!!").await?;
    filetime::set_file_mtime(
        &staging_root.join("top.txt"),
        filetime::FileTime::from_unix_time(1_700_000_120, 0),
    )?;
    tokio::fs::write(dataset.join("top.txt"), b"new-top!!").await?;
    filetime::set_file_mtime(
        &dataset.join("top.txt"),
        filetime::FileTime::from_unix_time(1_700_000_130, 0),
    )?;
    tokio::fs::write(output.join("unrelated.txt"), b"keep me").await?;
    let third = download::get(
        options(url.clone(), destination.path().into()),
        CancellationToken::new(),
    )
    .await?;
    assert_eq!(third, output);
    assert_eq!(tokio::fs::read(output.join("top.txt")).await?, b"new-top!!");
    assert_eq!(
        tokio::fs::read(output.join("unrelated.txt")).await?,
        b"keep me"
    );

    let contents = tempfile::tempdir()?;
    let mut contents_options = options(url, contents.path().into());
    contents_options.contents_only = true;
    let contents_result = download::get(contents_options, CancellationToken::new()).await?;
    assert_eq!(
        contents_result,
        tokio::fs::canonicalize(contents.path()).await?
    );
    assert_eq!(
        tokio::fs::read(contents.path().join("top.txt")).await?,
        b"new-top!!"
    );
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
    let destination = tempfile::tempdir()?;
    assert!(download::get(
        options(format!("{}/", http.url), destination.path().into()),
        CancellationToken::new(),
    )
    .await
    .is_err());
    assert_eq!(std::fs::read_dir(destination.path())?.count(), 0);
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
