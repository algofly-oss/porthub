//! Terminal host transport through the OS-authenticated local broker. Only the
//! service injects machine authorization; the user process supplies session caps.
use anyhow::{ensure, Result};
use futures_util::{SinkExt, StreamExt};
use porthub_terminal::protocol::{HostEvent, HostHello, HostOutput};
use serde::Deserialize;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig, Message},
    MaybeTlsStream, WebSocketStream,
};
use tokio_util::sync::CancellationToken;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation: String,
    hello: HostHello,
}

async fn open(
    control: &crate::control::Control,
) -> Result<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>> {
    for base in control.authorities() {
        let Ok(mut url) = url::Url::parse(&format!("{base}/api/terminal/host")) else {
            continue;
        };
        let scheme = match url.scheme() {
            "https" => "wss",
            "http" if control.profile().allow_insecure_http_for_tests => "ws",
            _ => continue,
        };
        url.set_scheme(scheme)
            .map_err(|_| anyhow::anyhow!("invalid terminal gateway"))?;
        let result = tokio::time::timeout(Duration::from_secs(15), async {
            let sources = control.stream_sources(&base).await?;
            ensure!(!sources.is_empty(), "terminal gateway underlay unavailable");
            let stream = porthub_mesh::underlay::connect(&url, &sources).await?;
            stream.set_nodelay(true)?;
            let mut handshake = url.as_str().into_client_request()?;
            handshake.headers_mut().insert(
                "x-porthub-machine-id",
                control.profile().machine_id.parse()?,
            );
            handshake.headers_mut().insert(
                "authorization",
                format!("Bearer {}", control.profile().token).parse()?,
            );
            let limits = WebSocketConfig::default()
                .read_buffer_size(8192)
                .write_buffer_size(8192)
                .max_message_size(Some(65536))
                .max_frame_size(Some(65536));
            let (socket, _) = tokio_tungstenite::client_async_tls_with_config(
                handshake,
                stream,
                Some(limits),
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
    anyhow::bail!("terminal gateway is unavailable")
}

pub(crate) async fn frame<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
    bytes: &mut Vec<u8>,
) -> Result<Vec<u8>> {
    // The caller retains partial bytes if select! cancels this read while a
    // gateway event arrives. Never lose a partially received JSON frame.
    let remaining = 32769usize.saturating_sub(bytes.len());
    let count = reader
        .take(remaining as u64)
        .read_until(b'\n', bytes)
        .await?;
    ensure!(
        count > 0 && bytes.len() <= 32768 && bytes.last() == Some(&b'\n'),
        "invalid terminal broker frame"
    );
    Ok(std::mem::take(bytes))
}

pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut local: BufReader<S>,
    control: &crate::control::Control,
    message: serde_json::Value,
    cancel: CancellationToken,
) -> Result<()> {
    let request: Request = serde_json::from_value(message)?;
    ensure!(
        request.operation == "terminal_host",
        "invalid terminal broker operation"
    );
    request.hello.validate(porthub_terminal::protocol::now())?;
    let mut remote = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = tokio::time::timeout(Duration::from_secs(40), open(control)) => match result {
            Ok(Ok(remote)) => remote,
            _ => {
                local.get_mut().write_all(b"{\"error\":\"terminal gateway unavailable\"}\n").await?;
                return Ok(());
            }
        }
    };
    remote
        .send(Message::Text(serde_json::to_string(&request.hello)?.into()))
        .await?;
    let mut partial = Vec::new();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            bytes = frame(&mut local, &mut partial) => {
                let bytes = match bytes { Ok(bytes) => bytes, Err(_) => break };
                let output: HostOutput = serde_json::from_slice(&bytes)?;
                if let HostOutput::Output { data, .. } = &output { porthub_terminal::protocol::decode_data(data)?; }
                tokio::time::timeout(Duration::from_secs(5), remote.send(Message::Text(serde_json::to_string(&output)?.into()))).await??;
            }
            message = remote.next() => match message {
                Some(Ok(Message::Text(text))) => {
                    let event: HostEvent = serde_json::from_str(&text)?;
                    let mut bytes = serde_json::to_vec(&event)?;
                    bytes.push(b'\n');
                    tokio::time::timeout(Duration::from_secs(5), local.get_mut().write_all(&bytes)).await??;
                }
                Some(Ok(Message::Ping(bytes))) => {
                    tokio::time::timeout(Duration::from_secs(5),remote.send(Message::Pong(bytes))).await??;
                }
                Some(Ok(Message::Pong(_))) => {},
                _ => break,
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn interrupted_frame_read_retains_partial_bytes_and_rejects_oversized_frames(
    ) -> Result<()> {
        let (mut writer, reader) = tokio::io::duplex(65536);
        let mut reader = BufReader::new(reader);
        let mut partial = Vec::new();
        writer.write_all(b"{\"type\":").await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), frame(&mut reader, &mut partial))
                .await
                .is_err()
        );
        assert_eq!(partial, b"{\"type\":");
        writer.write_all(b"\"pong\"}\n").await?;
        let bytes = frame(&mut reader, &mut partial).await?;
        assert!(matches!(
            serde_json::from_slice::<HostOutput>(&bytes)?,
            HostOutput::Pong
        ));
        assert!(partial.is_empty());
        writer.write_all(&vec![b'x'; 32769]).await?;
        assert!(frame(&mut reader, &mut partial).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn authenticated_broker_preserves_frames_and_keeps_machine_secret_private() -> Result<()>
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let profile: crate::profile::Profile = serde_json::from_value(serde_json::json!({
            "server":format!("http://{}",listener.local_addr()?),
            "machine_id":"0123456789abcdef01234567", "token":"broker-only-machine-secret",
            "allow_insecure_http_for_tests":true
        }))?;
        let gateway = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut socket = tokio_tungstenite::accept_hdr_async(
                stream,
                |request: &tokio_tungstenite::tungstenite::handshake::server::Request, response| {
                    assert_eq!(request.uri().path(), "/api/terminal/host");
                    assert!(request.uri().query().is_none());
                    assert_eq!(
                        request.headers()["authorization"],
                        "Bearer broker-only-machine-secret"
                    );
                    assert_eq!(
                        request.headers()["x-porthub-machine-id"],
                        "0123456789abcdef01234567"
                    );
                    Ok(response)
                },
            )
            .await?;
            let first = socket.next().await.unwrap()?.into_text()?;
            let _: HostHello = serde_json::from_str(&first)?;
            assert!(!first.contains("broker-only-machine-secret"));
            socket
                .send(Message::Text(
                    serde_json::to_string(&HostEvent::Ready {
                        ssh_host: "example.test".into(),
                        ssh_port: 8347,
                        public_base: "https://example.test".into(),
                    })?
                    .into(),
                ))
                .await?;
            let output = socket.next().await.unwrap()?.into_text()?;
            assert!(matches!(
                serde_json::from_str::<HostOutput>(&output)?,
                HostOutput::Pong
            ));
            socket.close(None).await?;
            Ok::<_, anyhow::Error>(())
        });
        let (local, service) = tokio::io::duplex(65536);
        let control = std::sync::Arc::new(crate::control::Control::new(profile)?);
        let owner = tokio::spawn(crate::exposure_protocol::serve_connection(
            service,
            control,
            CancellationToken::new(),
            std::path::PathBuf::from("unused-test-profile"),
        ));
        let mut local = BufReader::new(local);
        let request = serde_json::json!({"operation":"terminal_host","hello":{
            "id":"1".repeat(32),"secret":"2".repeat(64),"write_token":"3".repeat(64),"read_token":"4".repeat(64),
            "options":{"name":"quietfalcon","expires_at":0,"idle_timeout":0,"reconnect_timeout":60,
                "history_limit":100000,"mouse":true,"read_only":false,"size_policy":"smallest"}
        }});
        let mut bytes = serde_json::to_vec(&request)?;
        // Pipeline data after the opening request to verify buffered bytes are
        // preserved when the broker hands off to the terminal transport.
        bytes.extend_from_slice(b"\n{\"type\":\"pong\"}\n");
        local.get_mut().write_all(&bytes).await?;
        let mut partial = Vec::new();
        let response =
            tokio::time::timeout(Duration::from_secs(5), frame(&mut local, &mut partial)).await??;
        assert!(!String::from_utf8_lossy(&response).contains("secret"));
        assert!(matches!(
            serde_json::from_slice::<HostEvent>(&response)?,
            HostEvent::Ready { .. }
        ));
        tokio::time::timeout(Duration::from_secs(5), owner).await???;
        gateway.await??;
        Ok(())
    }
}
