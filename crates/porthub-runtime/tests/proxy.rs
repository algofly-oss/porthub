#![cfg(unix)]
use axum::{
    body::{Body, Bytes},
    extract::Request,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use porthub_runtime::{proxy::HttpProxy, socket};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::Notify,
};

#[tokio::test]
async fn unix_proxy_streams_without_waiting_for_complete_response() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("api.sock");
    let (listener, _lease) = socket::bind(&path).await?;
    let continue_body = Arc::new(Notify::new());
    let signal = continue_body.clone();
    let upstream = Router::new().fallback(move |request: Request| {
        let signal = signal.clone();
        async move {
            assert_eq!(
                request.uri().path_and_query().unwrap().as_str(),
                "/stream?q=one"
            );
            assert_eq!(request.headers()[header::HOST], "porthub.test");
            assert_eq!(request.headers()[header::AUTHORIZATION], "Bearer test-only");
            assert!(!request.headers().contains_key("x-hop-only"));
            let body = futures_util::stream::unfold((0, signal), |(step, signal)| async move {
                let bytes = match step {
                    0 => Bytes::from_static(b"first chunk"),
                    1 => {
                        signal.notified().await;
                        Bytes::from_static(b"last chunk")
                    }
                    _ => return None,
                };
                Some((Ok::<_, std::io::Error>(bytes), (step + 1, signal)))
            });
            Body::from_stream(body)
        }
    });
    let upstream = tokio::spawn(async move { axum::serve(listener, upstream).await });
    let proxy = HttpProxy::unix(path);
    let router = Router::new().fallback(move |request: Request| {
        let proxy = proxy.clone();
        async move { proxy.forward(request).await }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let serving = tokio::spawn(async move { axum::serve(listener, router).await });
    let client = reqwest::Client::new();
    let mut response = client
        .get(format!("http://{address}/stream?q=one"))
        .header("host", "porthub.test")
        .header("authorization", "Bearer test-only")
        .header("connection", "x-hop-only")
        .header("x-hop-only", "remove me")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let first = tokio::time::timeout(Duration::from_secs(1), response.chunk())
        .await??
        .unwrap();
    assert_eq!(first, b"first chunk"[..]);
    continue_body.notify_one();
    assert_eq!(response.bytes().await?, b"last chunk"[..]);
    serving.abort();
    upstream.abort();
    Ok(())
}

#[tokio::test]
async fn unix_proxy_preserves_upgraded_stream_half_close() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5),async {
        let directory=tempfile::tempdir()?;
        let path=directory.path().join("api.sock");
        let (listener,_lease)=socket::bind(&path).await?;
        let router=Router::new().fallback(|mut request:Request| async move {
            let upgrade=hyper::upgrade::on(&mut request);
            tokio::spawn(async move {
                let stream=upgrade.await.unwrap();
                let mut stream=hyper_util::rt::TokioIo::new(stream);
                let mut body=Vec::new();
                stream.read_to_end(&mut body).await.unwrap();
                stream.write_all(b"reply:").await.unwrap();
                stream.write_all(&body).await.unwrap();
                stream.shutdown().await.unwrap();
            });
            (StatusCode::SWITCHING_PROTOCOLS,[(header::CONNECTION,"Upgrade"),(header::UPGRADE,"test.stream")]).into_response()
        });
        let upstream=tokio::spawn(async move {axum::serve(listener,router).await});
        let proxy=HttpProxy::unix(path);
        let router=Router::new().fallback(move |request:Request| {let proxy=proxy.clone();async move {proxy.forward(request).await}});
        let listener=TcpListener::bind("127.0.0.1:0").await?;
        let address=listener.local_addr()?;
        let serving=tokio::spawn(async move {axum::serve(listener,router).await});
        let mut client=TcpStream::connect(address).await?;
        client.write_all(b"GET /socket.io HTTP/1.1\r\nHost: porthub.test\r\nConnection: Upgrade\r\nUpgrade: test.stream\r\n\r\npipelined payload").await?;
        let mut reader=BufReader::new(client);
        let mut headers=String::new();
        while !headers.ends_with("\r\n\r\n") {assert_ne!(reader.read_line(&mut headers).await?,0);}
        assert!(headers.starts_with("HTTP/1.1 101"));
        reader.get_mut().shutdown().await?;
        let mut reply=Vec::new();
        reader.read_to_end(&mut reply).await?;
        assert_eq!(reply,b"reply:pipelined payload");
        serving.abort();upstream.abort();
        Ok::<_,anyhow::Error>(())
    }).await??;
    Ok(())
}

#[tokio::test]
async fn unavailable_upstream_returns_clean_gateway_error() {
    let directory = tempfile::tempdir().unwrap();
    let proxy = HttpProxy::unix(directory.path().join("not-there.sock"));
    let response: Response = proxy.forward(Request::new(Body::empty())).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}
