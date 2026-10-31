//! Shared bounded protocol for credential-free local exposure requests.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub request_id: String,
    pub local_port: u16,
    pub external_port: Option<u16>,
    pub subdomain: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub error: Option<String>,
    pub exposure_id: Option<String>,
    pub external_port: Option<u16>,
    pub tcp_url: Option<String>,
    pub proxy_url: Option<String>,
}
impl Request {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.request_id.len() == 32 && self.request_id.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid exposure request identity"
        );
        ensure!(
            self.local_port > 0 && self.external_port != Some(0),
            "invalid exposure port"
        );
        ensure!(
            self.subdomain.as_ref().is_none_or(|name| !name.is_empty()
                && name.len() <= 63
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
            "invalid exposure subdomain"
        );
        Ok(())
    }
}
pub(crate) async fn line<S: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    let count = reader.take(8193).read_until(b'\n', &mut bytes).await?;
    ensure!(
        count > 0 && count <= 8192 && bytes.last() == Some(&b'\n'),
        "invalid local exposure message"
    );
    Ok(bytes)
}
pub(crate) async fn send<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    value: &Reply,
) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    Ok(())
}
async fn gateway(
    control: &crate::control::Control,
    action: &str,
    mut body: serde_json::Value,
) -> Result<serde_json::Value> {
    body["machine_id"] = control.profile().machine_id.clone().into();
    body["token"] = control.profile().token.clone().into();
    let reply = control
        .request(reqwest::Method::POST, action, Some(body), &[])
        .await?;
    let payload = reply.json()?;
    Ok(payload.get("data").cloned().unwrap_or(payload))
}
pub(crate) async fn serve_connection<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: S,
    control: Arc<crate::control::Control>,
    cancel: CancellationToken,
    profile: std::path::PathBuf,
) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let bytes = tokio::time::timeout(Duration::from_secs(5), line(&mut reader)).await??;
    let message: serde_json::Value = serde_json::from_slice(&bytes)?;
    if message.get("operation").and_then(serde_json::Value::as_str) == Some("agent_stats") {
        return crate::stats::serve(reader,&control,&profile,message,cancel).await;
    }
    if message.get("operation").and_then(serde_json::Value::as_str) == Some("terminal_host") {
        return crate::terminal_transport::serve(reader, &control, message, cancel).await;
    }
    #[cfg(feature="local-tor")]
    if matches!(message.get("operation").and_then(serde_json::Value::as_str),Some("proxy_connect"|"proxy_check")) {
        return crate::proxy_transport::serve(reader, &control, &profile, message, cancel).await;
    }
    let request: Request = serde_json::from_value(message)?;
    request.validate()?;
    let created = match gateway(
        &control,
        "machines/client/expose",
        serde_json::to_value(&request)?,
    )
    .await
    {
        Ok(created) => created,
        Err(error) => {
            send(
                reader.get_mut(),
                &Reply {
                    error: Some(error.to_string()),
                    exposure_id: None,
                    external_port: None,
                    tcp_url: None,
                    proxy_url: None,
                },
            )
            .await?;
            return Ok(());
        }
    };
    let id = created
        .get("exposure_id")
        .and_then(serde_json::Value::as_str)
        .context("gateway omitted exposure identity")?
        .to_owned();
    let response = Reply {
        error: None,
        exposure_id: Some(id.clone()),
        external_port: created
            .get("external_port")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u16::try_from(value).ok()),
        tcp_url: created
            .get("tcp_url")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        proxy_url: created
            .get("proxy_url")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    };
    let result = async {
        send(reader.get_mut(), &response).await?;
        let mut renew = tokio::time::interval(Duration::from_secs(30));
        renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        renew.tick().await;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = line(&mut reader) => break,
                _ = renew.tick() => { gateway(&control, "machines/client/expose/renew", serde_json::json!({"exposure_id":id})).await?; }
            }
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    let closed = gateway(
        &control,
        "machines/client/expose/close",
        serde_json::json!({"exposure_id":id}),
    )
    .await;
    if closed.is_ok() {
        let _ = reader.get_mut().write_all(b"closed\n").await;
    }
    result?;
    closed?;
    Ok(())
}
