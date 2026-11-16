//! Native CLI actions use the existing OS-authenticated enrollment broker.
use crate::control::Control;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut reader: BufReader<S>,
    control: Arc<Control>,
    mut body: Value,
    cancel: CancellationToken,
) -> Result<()> {
    serve_period(reader, control, body, cancel, Duration::from_secs(15)).await
}
async fn serve_period<S: AsyncRead + AsyncWrite + Unpin>(
    mut reader: BufReader<S>,
    control: Arc<Control>,
    mut body: Value,
    cancel: CancellationToken,
    period: Duration,
) -> Result<()> {
    body.as_object_mut()
        .context("Invalid native media action")?
        .remove("operation");
    body["machine_id"] = control.profile().machine_id.clone().into();
    body["token"] = control.profile().token.clone().into();
    if body["action"] == "create" {
        body["plan"]["source"] = control.profile().machine_id.clone().into();
    }
    let reply = control
        .request(
            reqwest::Method::POST,
            "media/client/action",
            Some(body.clone()),
            &[],
        )
        .await;
    let reply = match reply.and_then(|r| r.json()) {
        Ok(value) => value,
        Err(_) => json!({"error":"Native media action was not authorized or is unavailable"}),
    };
    reader
        .get_mut()
        .write_all(format!("{reply}\n").as_bytes())
        .await?;
    if body["action"] != "create"
        || body["plan"]["persistent"] == true
        || reply["plan"]["id"].as_str().is_none()
    {
        return Ok(());
    }
    body["id"] = reply["plan"]["id"].clone();
    body.as_object_mut().unwrap().remove("plan");
    body["action"] = "renew".into();
    let mut tick = tokio::time::interval(period);
    tick.tick().await;
    loop {
        tokio::select! {biased;_=cancel.cancelled()=>break,_=reader.fill_buf()=>break,_=tick.tick()=>{
            let renewed=tokio::select!{biased;_=cancel.cancelled()=>false,_=reader.fill_buf()=>false,result=control.request(reqwest::Method::POST,"media/client/action",Some(body.clone()),&[])=>result.is_ok()};
            if !renewed {break;}
        }}
    }
    body["action"] = "stop".into();
    let _ = control
        .request(
            reqwest::Method::POST,
            "media/client/action",
            Some(body),
            &[],
        )
        .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Signals {
        renew: tokio::sync::Notify,
        stop: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }
    async fn action(
        axum::extract::State(state): axum::extract::State<Arc<Signals>>,
        axum::Json(body): axum::Json<Value>,
    ) -> axum::Json<Value> {
        assert_eq!(body["machine_id"], "a".repeat(24));
        assert_eq!(body["token"], "private-test-token");
        match body["action"].as_str() {
            Some("create") => axum::Json(json!({"plan":{"id":"b".repeat(32)}})),
            Some("renew") => {
                state.renew.notify_one();
                state.release.notified().await;
                axum::Json(json!({"ok":true}))
            }
            Some("stop") => {
                state.stop.notify_one();
                state.release.notify_waiters();
                axum::Json(json!({"ok":true}))
            }
            _ => axum::Json(json!({"error":"unsupported test action"})),
        }
    }
    #[tokio::test]
    async fn closing_cli_cancels_stalled_renew_and_stops_temporary_plan() -> Result<()> {
        let signals = Arc::new(Signals::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let server = format!("http://{}", listener.local_addr()?);
        let router = axum::Router::new()
            .route("/api/media/client/action", axum::routing::post(action))
            .with_state(signals.clone());
        let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            axum::serve(listener, router).await
        }));
        let profile = serde_json::from_value(
            json!({"server":server,"machine_id":"a".repeat(24),"token":"private-test-token","allow_insecure_http_for_tests":true}),
        )?;
        let control = Arc::new(Control::new(profile)?);
        let (server, client) = tokio::io::duplex(4096);
        let task = tokio::spawn(serve_period(
            BufReader::new(server),
            control,
            json!({"operation":"media_action","action":"create","machine_id":"untrusted","token":"untrusted","plan":{"persistent":false}}),
            CancellationToken::new(),
            Duration::from_millis(1),
        ));
        let mut client = BufReader::new(client);
        let mut line = String::new();
        client.read_line(&mut line).await?;
        assert!(line.contains(&"b".repeat(32)));
        tokio::time::timeout(Duration::from_secs(2), signals.renew.notified()).await?;
        drop(client);
        tokio::time::timeout(Duration::from_secs(2), signals.stop.notified()).await?;
        tokio::time::timeout(Duration::from_secs(2), task).await???;
        Ok(())
    }
}
