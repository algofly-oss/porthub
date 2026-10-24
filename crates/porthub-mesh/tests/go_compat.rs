use anyhow::{Context, Result};
use bytes::Bytes;
use porthub_mesh::{udp::Session, Description, Identity, MAX_PACKET};
use std::{process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
#[ignore = "requires Go compatibility fixture via PORTHUB_TEST_GO_MESH_BINARY"]
async fn native_packets_interoperate_with_existing_go_peer_in_both_ice_dtls_roles() -> Result<()> {
    let binary = std::env::var("PORTHUB_TEST_GO_MESH_BINARY")
        .context("Go mesh fixture executable required")?;
    for role in ["offer", "answer"] {
        let mut child = tokio::process::Command::new(&binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut input = child.stdin.take().context("fixture stdin")?;
        let mut output = BufReader::new(child.stdout.take().context("fixture stdout")?).lines();
        let line = tokio::time::timeout(Duration::from_secs(5), output.next_line())
            .await??
            .context("fixture identity")?;
        let identity: serde_json::Value = serde_json::from_str(&line)?;
        let identity = identity["fingerprint"]
            .as_str()
            .context("fixture fingerprint")?;
        let own = Identity::new()?;
        let (local, remote) = if role == "offer" {
            ("peer-z", "peer-a")
        } else {
            ("peer-a", "peer-z")
        };
        let (peer, mut packets) =
            Session::bind("127.0.0.1:0".parse()?, local, remote, own.clone(), identity).await?;
        input
            .write_all(
                format!(
                    "{}\n",
                    serde_json::json!({"role":role,"fingerprint":own.fingerprint()})
                )
                .as_bytes(),
            )
            .await?;
        if role == "answer" {
            input
                .write_all(format!("{}\n", serde_json::to_string(&peer.description())?).as_bytes())
                .await?;
        }
        let line = tokio::time::timeout(Duration::from_secs(5), output.next_line())
            .await??
            .context("fixture description")?;
        let description: Description = serde_json::from_str(&line)?;
        peer.remote(remote, description).await?;
        if role == "offer" {
            input
                .write_all(format!("{}\n", serde_json::to_string(&peer.description())?).as_bytes())
                .await?;
        }
        tokio::time::timeout(Duration::from_secs(10), peer.ready()).await??;
        let line = tokio::time::timeout(Duration::from_secs(5), output.next_line())
            .await??
            .context("fixture ready")?;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line)?["ready"],
            true
        );
        for sequence in 0..64u32 {
            let mut packet = vec![0x45; MAX_PACKET];
            packet[4..8].copy_from_slice(&sequence.to_be_bytes());
            let packet = Bytes::from(packet);
            peer.send(packet.clone())?;
            let echo = tokio::time::timeout(Duration::from_secs(2), packets.recv())
                .await?
                .context("echo packet")?;
            assert_eq!(echo, packet);
        }
        drop(input);
        let status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
        assert!(status.success());
        peer.close().await;
    }
    Ok(())
}
