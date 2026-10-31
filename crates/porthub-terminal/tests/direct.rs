#![cfg(feature = "direct")]
use anyhow::{ensure, Context, Result};
use porthub_terminal::direct::{
    replay::{Message, Receiver, Sender},
    Event, Peer,
};
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
    let count=tokio::time::timeout(Duration::from_secs(10), output.read_line(&mut line)).await??;
    ensure!(count>0,"browser produced no SDP; check its stderr and Playwright/browser setup");
    let (mut peer, answer) = Peer::answer(Instant::now(), &line, &[local])?;
    let mut input = child.stdin.take().unwrap();
    input.write_all(answer.as_bytes()).await?;
    input.write_all(b"\n").await?;
    let mut sender = Sender::new(&"b".repeat(32))?;
    let mut receiver = Receiver::new(&"a".repeat(32))?;
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
                let Message::Data(frame) = Message::parse(&bytes)? else {
                    anyhow::bail!("expected direct input")
                };
                ensure!(
                    opened && frame.payload() == b"direct terminal interoperability",
                    "unexpected direct payload"
                );
                receiver.stage(frame)?;
                let accepted = receiver.next().context("input sequence gap")?;
                let sequence = accepted.sequence();
                let reply = sender.enqueue(accepted.payload())?;
                receiver.commit(sequence)?;
                peer.send(Instant::now(), &Message::Data(reply).encode()?)?;
                peer.send(
                    Instant::now(),
                    &Message::Ack {
                        epoch: "a".repeat(32),
                        sequence: receiver.acknowledged(),
                    }
                    .encode()?,
                )?;
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
        // Both carriers use these journals; direct duplicates must not repeat
        // application input, and output stays retained until the peer commits.
        let mut duplicates = 0;
        let mut released = false;
        loop {
            while let Some(bytes) = peer.read()? {
                match Message::parse(&bytes)? {
                    Message::Data(frame) => {
                        ensure!(!receiver.stage(frame)?, "duplicate input was applied twice");
                        duplicates += 1;
                    }
                    Message::Ack { epoch, sequence } => sender.acknowledge(&epoch, sequence)?,
                }
            }
            if !released && sender.retained_bytes() == 0 && duplicates > 0 {
                input.write_all(b"finish\n").await?;
                released = true;
            }
            if let Some(status) = child.try_wait()? {
                ensure!(status.success() && released, "browser direct probe failed");
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
