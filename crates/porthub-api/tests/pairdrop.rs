use anyhow::{ensure, Result};
use axum::{
    body::Body,
    extract::{ws::Message, Request, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{any, get},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
mod support;
use support::Case;
#[tokio::test]
#[ignore = "requires isolated MongoDB"]
async fn pairdrop_is_public_scoped_and_strips_portal_credentials() -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let upstream = format!("http://{}/", listener.local_addr()?);
    let router=Router::new().route("/server",get(|ws:WebSocketUpgrade,headers:HeaderMap|async move{
   let safe=!headers.contains_key("cookie")&&!headers.contains_key("authorization");
   ws.on_upgrade(move|mut socket|async move{let _=socket.send(Message::Text(if safe{"anonymous"}else{"leaked"}.into())).await;while let Some(Ok(message))=socket.recv().await{if socket.send(message).await.is_err(){break;}}})
 })).fallback(any(|request:Request|async move{
   if request.uri().path()=="/redirect" {return (StatusCode::TEMPORARY_REDIRECT,[("location","/"),("set-cookie","porthub_session=bad")]).into_response();}
   Json(json!({"path":request.uri().to_string(),"cookie":request.headers().contains_key("cookie"),"authorization":request.headers().contains_key("authorization"),"transfer_key":request.headers().contains_key("x-transfer-key")})).into_response()
 }));
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let case = Case::new(porthub_api::config::Config {
        pairdrop_upstream: upstream,
        ..Default::default()
    })
    .await?;
    let result: Result<()> = async {
        let (status, headers, value) = case
            .call(
                "GET",
                "/pairdrop/config?room=test",
                "porthub_session=private",
                serde_json::Value::Null,
                &[
                    ("authorization", "Bearer private"),
                    ("x-transfer-key", "private"),
                ],
            )
            .await?;
        ensure!(status == StatusCode::OK && value["path"] == "/config?room=test");
        ensure!(
            value["cookie"] == false
                && value["authorization"] == false
                && value["transfer_key"] == false
        );
        ensure!(headers["content-security-policy"] == "frame-ancestors 'self'");
        use tower::ServiceExt;
        let response = case
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/pairdrop/redirect")
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(
            response.headers()["location"] == "/pairdrop/"
                && !response.headers().contains_key("set-cookie")
        );
        let denied = case
            .router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/pairdrop/server")
                    .header("host", "porthub.test")
                    .header("origin", "https://elsewhere.invalid")
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(denied.status() == StatusCode::FORBIDDEN);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let router = case.router.clone();
        let portal = tokio::spawn(async move { axum::serve(listener, router).await });
        let mut request = format!("ws://{address}/pairdrop/server?webrtc_supported=true")
            .into_client_request()?;
        request
            .headers_mut()
            .insert("origin", format!("http://{address}").parse()?);
        request
            .headers_mut()
            .insert("cookie", "porthub_session=private".parse()?);
        request
            .headers_mut()
            .insert("authorization", "Bearer private".parse()?);
        let (mut socket, _) = tokio_tungstenite::connect_async(request).await?;
        ensure!(socket.next().await.unwrap()?.into_text()? == "anonymous");
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "relay".into(),
            ))
            .await?;
        ensure!(socket.next().await.unwrap()?.into_text()? == "relay");
        socket.close(None).await?;
        portal.abort();
        Ok(())
    }
    .await;
    server.abort();
    case.db.drop().await?;
    result
}
