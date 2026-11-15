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
pub(super) async fn line<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
    pending: &mut Vec<u8>,
) -> Result<Vec<u8>> {
    crate::terminal_transport::frame(reader, pending).await
}
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut local: BufReader<S>,
    control: Arc<crate::control::Control>,
    profile: &Path,
    cancel: CancellationToken,
) -> Result<()> {
    let policy = crate::features::subscribe(profile);
    if !policy.borrow().enabled(crate::features::Feature::Keyboard) {
        local.get_mut().write_all(b"{\"type\":\"disabled\",\"error\":\"VKeyboard is disabled locally; run porthub keyboard enable\"}\n").await?;
        return Ok(());
    }
    let socket = match open(&control).await {
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
    relay(local,socket,policy,cancel).await
}
// API hosts send a heartbeat every 20s. A bounded idle deadline also recovers
// half-open proxy connections, without changing the approved desktop wire format.
const GATEWAY_IDLE: Duration = Duration::from_secs(75);
async fn relay<L:AsyncRead+AsyncWrite+Unpin,W:AsyncRead+AsyncWrite+Unpin>(
    mut local:BufReader<L>,
    mut socket:WebSocketStream<W>,
    mut policy:tokio::sync::watch::Receiver<crate::features::Policy>,
    cancel:CancellationToken,
)->Result<()> {
    let mut pending = Vec::new();
    let idle=tokio::time::sleep(GATEWAY_IDLE);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            _=&mut idle=>{tracing::debug!("Keyboard gateway heartbeat expired; reconnecting desktop broker");break;}
            changed=policy.changed()=>{if changed.is_err() || !policy.borrow().enabled(crate::features::Feature::Keyboard) || !policy.borrow().enabled(crate::features::Feature::DirectConnections){break;}}
            outgoing=line(&mut local, &mut pending)=>{let bytes=outgoing?;let value:Value=serde_json::from_slice(&bytes)?;ensure!(matches!(value["type"].as_str(),Some("pong"|"ack"|"direct_answer"|"direct_unavailable"|"device_status")),"Invalid desktop keyboard response");tokio::time::timeout_at(idle.deadline(),socket.send(Message::Text(value.to_string().into()))).await??;}
            incoming=socket.next()=>{
                let Some(Ok(message))=incoming else{break;};
                idle.as_mut().reset(tokio::time::Instant::now()+GATEWAY_IDLE);
                match message{
                    Message::Text(text)=>{let value:Value=serde_json::from_str(&text)?;tokio::time::timeout_at(idle.deadline(),local.get_mut().write_all(format!("{value}\n").as_bytes())).await??;},
                    Message::Ping(bytes)=>tokio::time::timeout_at(idle.deadline(),socket.send(Message::Pong(bytes))).await??,
                    Message::Pong(_)=>{},_=>break,
                }
            }
        }
    }
    // A peer that stopped reading must not delay dropping the desktop pipe.
    let _ = tokio::time::timeout(Duration::from_secs(1),socket.close(None)).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn split_keyboard_frames_survive_interleaved_gateway_events() -> Result<()> {
        let (mut sender, receiver) = tokio::io::duplex(256);
        let mut reader = BufReader::new(receiver);
        let mut pending = Vec::new();
        sender.write_all(b"{\"type\":\"ack\"").await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), line(&mut reader, &mut pending))
                .await
                .is_err()
        );
        sender.write_all(b"}\n").await?;
        let value: Value = serde_json::from_slice(&line(&mut reader, &mut pending).await?)?;
        assert_eq!(value["type"], "ack");
        assert!(pending.is_empty());
        Ok(())
    }
}

#[cfg(test)]
mod heartbeat_tests {
    use super::*;
    use tokio::io::{AsyncReadExt,DuplexStream};
    use tokio_tungstenite::tungstenite::protocol::Role;

    async fn fixture()->(DuplexStream,WebSocketStream<DuplexStream>,tokio::task::JoinHandle<Result<()>>,tokio::sync::watch::Sender<crate::features::Policy>){
        let (desktop,local)=tokio::io::duplex(4096);
        let (client,server)=tokio::io::duplex(4096);
        let socket=WebSocketStream::from_raw_socket(client,Role::Client,None).await;
        let server=WebSocketStream::from_raw_socket(server,Role::Server,None).await;
        let (policy,receiver)=tokio::sync::watch::channel(crate::features::Policy::default());
        let task=tokio::spawn(relay(BufReader::new(local),socket,receiver,CancellationToken::new()));
        tokio::task::yield_now().await;
        (desktop,server,task,policy)
    }

    #[tokio::test(start_paused=true)]
    async fn silent_gateway_expires_despite_desktop_acks_and_closes_legacy_pipe()->Result<()> {
        let (mut desktop,mut gateway,task,_policy)=fixture().await;
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(20)).await;
            desktop.write_all(b"{\"type\":\"ack\",\"id\":\"fixture\"}\n").await?;
            tokio::task::yield_now().await;
            assert!(matches!(gateway.next().await,Some(Ok(Message::Text(_)))));
        }
        tokio::time::advance(Duration::from_secs(14)).await;
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        task.await??;
        let mut byte=[0u8;1];
        assert_eq!(desktop.read(&mut byte).await?,0,"approved helper must receive EOF and reconnect normally");
        assert!(matches!(gateway.next().await,Some(Ok(Message::Close(_)))),"idle cleanup must not replay input or invent desktop messages");
        Ok(())
    }

    #[tokio::test(start_paused=true)]
    async fn stalled_desktop_write_is_bounded_and_drops_the_legacy_pipe()->Result<()> {
        let (mut desktop,mut gateway,task,_policy)=fixture().await;
        let frame=json!({"type":"ping","padding":"x".repeat(8192)}).to_string();
        gateway.send(Message::Text(frame.clone().into())).await?;
        for _ in 0..5 {tokio::task::yield_now().await;}
        assert!(!task.is_finished());
        tokio::time::advance(GATEWAY_IDLE).await;
        assert!(task.await?.is_err(),"a blocked desktop writer must not bypass the idle deadline");
        let mut partial=Vec::new();desktop.read_to_end(&mut partial).await?;
        assert!(partial.len()<frame.len(),"test must exercise a genuinely blocked local write");
        Ok(())
    }

    #[tokio::test(start_paused=true)]
    async fn gateway_text_ping_and_pong_each_refresh_idle_deadline()->Result<()> {
        let (mut desktop,mut gateway,task,_policy)=fixture().await;
        for message in [Message::Text("{\"type\":\"ping\"}".into()),Message::Ping(vec![1,2].into()),Message::Pong(vec![3,4].into())] {
            tokio::time::advance(Duration::from_secs(60)).await;
            gateway.send(message).await?;
            for _ in 0..5 {tokio::task::yield_now().await;}
            assert!(!task.is_finished(),"every inbound frame must renew the deadline");
        }
        // Only the gateway Text frame crosses the existing local wire.
        let mut line=[0u8;16];let n=desktop.read(&mut line).await?;
        assert_eq!(&line[..n],b"{\"type\":\"ping\"}\n");
        tokio::time::advance(Duration::from_secs(74)).await;
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        task.await??;
        assert_eq!(desktop.read(&mut line).await?,0);
        Ok(())
    }
}
