#![cfg(unix)]
use anyhow::{ensure, Result};
use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::{header, StatusCode},
    Router,
};
use porthub_runtime::proxy::{HttpProxy, ProxyPool};
use tokio::{net::TcpListener, task::JoinSet};

#[tokio::test]
async fn web_proxy_preserves_encoded_paths_queries_host_and_explicit_upstream_auth() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let upstream = Router::new().fallback(|request: Request| async move {
        format!(
            "{}|{}|{}",
            request.uri().path_and_query().unwrap(),
            request.headers()[header::HOST].to_str().unwrap(),
            request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
        )
    });
    let mut workers = JoinSet::new();
    workers.spawn(async move {
        let _ = axum::serve(listener, upstream).await;
    });
    let proxy = HttpProxy::web(
        &format!("http://alice:pw%40ss@{address}/root%2Fprefix/?fixed=one"),
        false,
        ProxyPool::default(),
    )?;
    let request = Request::builder()
        .uri("/files%2Farchive?a=two%20words")
        .header("host", "front.example")
        .body(Body::empty())?;
    let response = proxy.forward(request).await;
    ensure!(response.status() == StatusCode::OK);
    let body = String::from_utf8(to_bytes(response.into_body(), 4096).await?.to_vec())?;
    ensure!(body==format!("/root%2Fprefix/files%2Farchive?fixed=one&a=two%20words|{address}|Basic YWxpY2U6cHdAc3M="),"{body}");
    let proxy = HttpProxy::web(&format!("http://{address}"), true, ProxyPool::default())?;
    let request = Request::builder()
        .uri("/simple")
        .header("host", "front.example:443")
        .body(Body::empty())?;
    let response = proxy.forward(request).await;
    ensure!(to_bytes(response.into_body(), 4096).await?.as_ref() == b"/simple|front.example:443|");
    workers.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn uploads_reach_the_upstream_before_the_complete_body_is_available() -> Result<()> {
    use futures_util::StreamExt;
    let seen = std::sync::Arc::new(tokio::sync::Notify::new());
    let first = seen.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let router = Router::new().fallback(move |request: Request| {
        let first = first.clone();
        async move {
            let mut body = request.into_body().into_data_stream();
            let chunk = body.next().await.unwrap().unwrap();
            first.notify_one();
            let mut count = chunk.len();
            while let Some(chunk) = body.next().await {
                count += chunk.unwrap().len();
            }
            count.to_string()
        }
    });
    let mut workers = JoinSet::new();
    workers.spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let signal = release.clone();
    let stream = futures_util::stream::unfold(0, move |step| {
        let signal = signal.clone();
        async move {
            match step {
                0 => Some((
                    Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"first")),
                    1,
                )),
                1 => {
                    signal.notified().await;
                    Some((Ok(axum::body::Bytes::from_static(b"last")), 2))
                }
                _ => None,
            }
        }
    });
    let proxy = HttpProxy::web(&format!("http://{address}"), true, ProxyPool::default())?;
    let request = Request::builder()
        .method("POST")
        .uri("/upload")
        .header("host", "upload.example")
        .body(Body::from_stream(stream))?;
    let forwarding = tokio::spawn(async move { proxy.forward(request).await });
    tokio::time::timeout(std::time::Duration::from_secs(1), seen.notified()).await?;
    release.notify_one();
    let response = forwarding.await?;
    ensure!(response.status() == StatusCode::OK);
    ensure!(to_bytes(response.into_body(), 1024).await?.as_ref() == b"9");
    workers.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn https_proxy_checks_certificate_and_hostname_independently_of_forwarded_host() -> Result<()>
{
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let der = certificate.cert.der().clone();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        certificate.cert.pem().into_bytes(),
        certificate.signing_key.serialize_pem().into_bytes(),
    )
    .await?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let upstream = Router::new().fallback(|request: Request| async move {
        request.headers()[header::HOST].to_str().unwrap().to_owned()
    });
    let mut workers = JoinSet::new();
    let server = axum_server::from_tcp_rustls(listener, tls)?;
    workers.spawn(async move {
        let _ = server.serve(upstream.into_make_service()).await;
    });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der)?;
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let pool = ProxyPool::with_tls_config(client);
    let proxy = HttpProxy::web(
        &format!("https://localhost:{}", address.port()),
        true,
        pool.clone(),
    )?;
    let response = proxy
        .forward(
            Request::builder()
                .uri("/")
                .header("host", "front.example")
                .body(Body::empty())?,
        )
        .await;
    ensure!(response.status() == StatusCode::OK);
    ensure!(to_bytes(response.into_body(), 4096).await?.as_ref() == b"front.example");
    let wrong_name = HttpProxy::web(&format!("https://{address}"), true, pool)?;
    ensure!(
        wrong_name
            .forward(Request::new(Body::empty()))
            .await
            .status()
            == StatusCode::BAD_GATEWAY
    );
    let untrusted = HttpProxy::web(
        &format!("https://localhost:{}", address.port()),
        true,
        ProxyPool::default(),
    )?;
    ensure!(
        untrusted
            .forward(Request::new(Body::empty()))
            .await
            .status()
            == StatusCode::BAD_GATEWAY
    );
    ensure!(HttpProxy::web("file:///tmp/private", true, ProxyPool::default()).is_err());
    workers.shutdown().await;
    Ok(())
}
