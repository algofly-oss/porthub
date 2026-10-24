use anyhow::Result;
use futures_util::StreamExt;
use porthub_mesh::relay::Allocation;
use std::time::Duration;

#[tokio::test]
async fn cancelling_pending_turn_discovery_closes_its_websocket() -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("ws://{}/api/access/private/relay", listener.local_addr()?);
    let (allocated, received) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let mut socket = tokio_tungstenite::accept_async(socket).await?;
        anyhow::ensure!(socket.next().await.transpose()?.is_some());
        let _ = allocated.send(());
        // Deliberately never answer Allocate. Cancelling discovery must close
        // the reader even though authentication has not returned an owner.
        while let Some(message) = socket.next().await {
            if message.is_err() {
                break;
            }
        }
        anyhow::Ok(())
    });
    let discovery = tokio::spawn(async move {
        Allocation::connect(&url, "test-peer", "test-credential", true).await
    });
    tokio::time::timeout(Duration::from_secs(2), received).await??;
    discovery.abort();
    let _ = discovery.await;
    tokio::time::timeout(Duration::from_secs(2), server).await???;
    Ok(())
}

#[tokio::test]
async fn plaintext_and_credential_bearing_relay_urls_are_rejected_before_dial() {
    for (url, allow) in [
        ("ws://127.0.0.1:1/api/access/private/relay", false),
        (
            "wss://user:password@localhost/api/access/private/relay",
            false,
        ),
        (
            "wss://localhost/api/access/private/relay?token=secret",
            false,
        ),
        ("http://localhost/api/access/private/relay", true),
    ] {
        assert!(Allocation::connect(url, "peer", "credential", allow)
            .await
            .is_err());
    }
}
