use anyhow::Result;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use porthub_firewall::service::{router, Service};
use serde_json::{json, Value};
use tower::ServiceExt;

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN in a disposable network namespace"]
async fn firewall_api_authenticates_and_persists_policy_changes() -> Result<()> {
    if std::env::var("PORTHUB_FIREWALL_KERNEL_TEST").as_deref() != Ok("1") {
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("firewall.db");
    let service =
        Service::new(&database, "porthub_test_api", "isolated-test-secret".into()).await?;
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let sampler = tokio::spawn(service.clone().sample(receiver));
    let router = router(service);
    async fn call(
        router: &axum::Router,
        method: &str,
        path: &str,
        key: &str,
        body: Value,
    ) -> Result<(StatusCode, Value)> {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .header("x-api-key", key)
                    .body(Body::from(body.to_string()))?,
            )
            .await?;
        let status = response.status();
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        Ok((status, serde_json::from_slice(&body)?))
    }
    let policy = json!({"is_public":false,"allowed_ips":["127.0.0.1"]});
    assert_eq!(
        call(
            &router,
            "PUT",
            "/api/ports/8080/policy",
            "wrong",
            policy.clone()
        )
        .await?
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &router,
            "PUT",
            "/api/ports/8080/policy",
            "isolated-test-secret",
            policy
        )
        .await?
        .0,
        StatusCode::OK
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    let echo = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut socket, _) = listener.accept().await?;
        let mut bytes = [0; 5];
        socket.read_exact(&mut bytes).await?;
        socket.write_all(&bytes).await?;
        Ok::<_, std::io::Error>(())
    });
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut socket = tokio::net::TcpStream::connect("127.0.0.1:8080").await?;
        socket.write_all(b"hello").await?;
        let mut answer = [0; 5];
        socket.read_exact(&mut answer).await?;
        assert_eq!(&answer, b"hello");
    }
    echo.await??;
    tokio::time::timeout(std::time::Duration::from_secs(4), async {
        loop {
            let (_, body) = call(
                &router,
                "POST",
                "/api/ports/traffic/snapshot",
                "isolated-test-secret",
                json!({"ports":[8080]}),
            )
            .await?;
            if body["data"]["8080"].as_array().is_some_and(|rows| {
                rows.iter().any(|s| {
                    s["in_bytes"].as_i64().unwrap_or(0) > 0
                        && s["out_bytes"].as_i64().unwrap_or(0) > 0
                })
            }) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    let persisted = porthub_firewall::store::Store::open(&database)
        .await?
        .policies()
        .await?;
    assert_eq!(persisted[&8080].allowed_ips[0].to_string(), "127.0.0.1");
    let (_, body) = call(
        &router,
        "GET",
        "/api/ports/policies/list",
        "isolated-test-secret",
        Value::Null,
    )
    .await?;
    assert_eq!(body["data"][0]["port"], 8080);
    assert_eq!(
        call(
            &router,
            "PUT",
            "/api/ports/8080/policy",
            "isolated-test-secret",
            json!({"is_public":true,"allowed_ips":["127.0.0.1"]})
        )
        .await?
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &router,
            "DELETE",
            "/api/ports/8080/policy",
            "isolated-test-secret",
            Value::Null
        )
        .await?
        .0,
        StatusCode::OK
    );
    assert!(porthub_firewall::store::Store::open(&database)
        .await?
        .policies()
        .await?
        .is_empty());
    let _ = stop.send(true);
    sampler.await??;
    let connection = nlink::netlink::Connection::<nlink::netlink::Nftables>::new()?;
    connection
        .del_table("porthub_test_api", nlink::netlink::nftables::Family::Inet)
        .await?;
    Ok(())
}
