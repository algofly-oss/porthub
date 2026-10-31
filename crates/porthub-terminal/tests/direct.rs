#![cfg(feature = "direct")]
use anyhow::{ensure, Context, Result};
use porthub_terminal::direct::{Event, Peer};
use std::{
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
#[ignore = "requires Playwright and a browser; uses only loopback"]
async fn browser_connects_to_bounded_terminal_data_channel() -> Result<()> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let local = socket.local_addr()?;
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui/tests/terminal-direct.cjs");
    let mut child = tokio::process::Command::new("node")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), output.read_line(&mut line)).await??;
    let (mut peer, answer) = Peer::answer(Instant::now(), &line, &[local])?;
    let mut input = child.stdin.take().unwrap();
    input.write_all(answer.as_bytes()).await?;
    input.write_all(b"\n").await?;
    let exchange = async {
        let mut buffer = [0; 65536];
        let mut opened = false;
        loop {
            while let Some((remote, bytes)) = peer.datagram() {
                socket.send_to(&bytes, remote).await?;
            }
            while let Some(event) = peer.event()? {
                match event {
                    Event::Ready => opened = true,
                    Event::Closed => anyhow::bail!("direct channel closed before echo"),
                }
            }
            if let Some(bytes) = peer.read()? {
                ensure!(
                    opened && bytes == b"direct terminal interoperability",
                    "unexpected direct payload"
                );
                peer.send(Instant::now(), &bytes)?;
                while let Some((remote, bytes)) = peer.datagram() {
                    socket.send_to(&bytes, remote).await?;
                }
                break;
            }
            let deadline = peer
                .deadline()
                .unwrap_or(Instant::now() + Duration::from_millis(100));
            tokio::select! {
                result=socket.recv_from(&mut buffer)=>{let (count,remote)=result?;peer.receive(Instant::now(),local,remote,&buffer[..count])?;},
                _=tokio::time::sleep_until(deadline.into())=>peer.timeout(Instant::now())?,
            }
        }
        // Continue driving DTLS/SCTP until the browser receives and acknowledges.
        loop {
            if let Some(status) = child.try_wait()? {
                ensure!(status.success(), "browser direct probe failed");
                break;
            }
            while let Some((remote, bytes)) = peer.datagram() {
                socket.send_to(&bytes, remote).await?;
            }
            tokio::select! {
                result=socket.recv_from(&mut buffer)=>{let(count,remote)=result?;let _=peer.receive(Instant::now(),local,remote,&buffer[..count]);},
                _=tokio::time::sleep(Duration::from_millis(10))=>{let _=peer.timeout(Instant::now());},
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(Duration::from_secs(15), exchange)
        .await
        .context("direct exchange timed out")??;
    peer.close()?;
    Ok(())
}
