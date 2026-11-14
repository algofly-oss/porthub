//! Network transport runs in the installed agent; input injection remains in
//! the authenticated desktop process. No machine credentials cross the broker.
use anyhow::{ensure, Result};
use futures_util::{SinkExt, StreamExt};
use porthub_components::keyboard::MAX_FRAME;
use serde_json::{json, Value};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig, Message},
    MaybeTlsStream, WebSocketStream,
};
use tokio_util::sync::CancellationToken;

async fn open(
    control: &crate::control::Control,
) -> Result<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>> {
    for base in control.authorities() {
        let mut url = url::Url::parse(&format!("{base}/api/keyboard/host"))?;
        let scheme = match url.scheme() {
            "https" => "wss",
            "http" if control.profile().allow_insecure_http_for_tests => "ws",
            _ => continue,
        };
        url.set_scheme(scheme)
            .map_err(|_| anyhow::anyhow!("Invalid keyboard gateway"))?;
        let result = tokio::time::timeout(Duration::from_secs(12), async {
            let sources = control.stream_sources(&base).await?;
            ensure!(!sources.is_empty(), "No approved keyboard network path");
            let stream = porthub_mesh::underlay::connect(&url, &sources).await?;
            stream.set_nodelay(true)?;
            let mut request = url.as_str().into_client_request()?;
            request.headers_mut().insert(
                "x-porthub-machine-id",
                control.profile().machine_id.parse()?,
            );
            request.headers_mut().insert(
                "authorization",
                format!("Bearer {}", control.profile().token).parse()?,
            );
            let (socket, _) = tokio_tungstenite::client_async_tls_with_config(
                request,
                stream,
                Some(
                    WebSocketConfig::default()
                        .max_message_size(Some(MAX_FRAME))
                        .max_frame_size(Some(MAX_FRAME)),
                ),
                None,
            )
            .await?;
            Ok::<_, anyhow::Error>(socket)
        })
        .await;
        if let Ok(Ok(socket)) = result {
            control.prefer_proxy_authority(base);
            return Ok(socket);
        }
    }
    anyhow::bail!("Keyboard gateway unavailable")
}
pub(super) async fn line<S: AsyncRead + Unpin>(reader: &mut BufReader<S>) -> Result<Vec<u8>> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    let mut bytes = Vec::new();
    let count = reader
        .take(MAX_FRAME as u64 + 1)
        .read_until(b'\n', &mut bytes)
        .await?;
    ensure!(
        count > 0 && count <= MAX_FRAME && bytes.last() == Some(&b'\n'),
        "Invalid keyboard frame"
    );
    Ok(bytes)
}
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut local: BufReader<S>,
    control: Arc<crate::control::Control>,
    profile: &Path,
    cancel: CancellationToken,
) -> Result<()> {
    let mut policy = crate::features::subscribe(profile);
    if !policy.borrow().enabled(crate::features::Feature::Keyboard) {
        local.get_mut().write_all(b"{\"type\":\"disabled\",\"error\":\"VKeyboard is disabled locally; run porthub keyboard enable\"}\n").await?;
        return Ok(());
    }
    let mut socket = match open(&control).await {
        Ok(socket) => socket,
        Err(_) => {
            local
                .get_mut()
                .write_all(b"{\"type\":\"error\",\"error\":\"Keyboard gateway unavailable\"}\n")
                .await?;
            return Ok(());
        }
    };
    // Direct networking uses the same local egress guard as terminal sharing.
    let direct = policy
        .borrow()
        .enabled(crate::features::Feature::DirectConnections)
        && crate::terminal_policy::direct_allowed(profile, control.profile());
    local
        .get_mut()
        .write_all(format!("{}\n", json!({"type":"policy","direct":direct})).as_bytes())
        .await?;
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            changed=policy.changed()=>{if changed.is_err() || !policy.borrow().enabled(crate::features::Feature::Keyboard) || !policy.borrow().enabled(crate::features::Feature::DirectConnections){break;}}
            outgoing=line(&mut local)=>{let bytes=outgoing?;let value:Value=serde_json::from_slice(&bytes)?;ensure!(matches!(value["type"].as_str(),Some("pong"|"ack"|"direct_answer"|"direct_unavailable"|"device_status")),"Invalid desktop keyboard response");socket.send(Message::Text(value.to_string().into())).await?;}
            incoming=socket.next()=>{
                match incoming{Some(Ok(Message::Text(text)))=>{let value:Value=serde_json::from_str(&text)?;local.get_mut().write_all(format!("{value}\n").as_bytes()).await?;},Some(Ok(Message::Ping(bytes)))=>socket.send(Message::Pong(bytes)).await?,Some(Ok(Message::Pong(_)))=>{},_=>break}
            }
        }
    }
    let _ = socket.close(None).await;
    Ok(())
}
