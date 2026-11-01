#![cfg(all(unix, feature = "direct"))]
use anyhow::{ensure, Context, Result};
use porthub_terminal::{
    delivery::{Frame, Message as Delivery},
    host::Attachments,
    multiplexer::{create_directory, Start, Workspace},
    protocol::*,
};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
struct Cleanup(Workspace);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.0.stop();
    }
}
fn workspace() -> Result<(tempfile::TempDir, Workspace, Cleanup)> {
    let root = tempfile::Builder::new()
        .prefix("ph-direct-")
        .tempdir_in("/tmp")?;
    let cache = root.path().join("runtime");
    create_directory(&cache)?;
    let runtime = porthub_terminal::runtime::install(
        &std::fs::read(std::env::var("PORTHUB_TEST_TERMINAL_BUNDLE")?)?,
        &cache,
        &std::env::var("PORTHUB_TEST_TERMINAL_TARGET")?,
    )?;
    let path = root.path().join("workspace");
    create_directory(&path)?;
    let workspace = Workspace::open(runtime.executable, runtime.terminfo, path)?;
    let cleanup = Cleanup(workspace.clone());
    workspace.start(&Start {
        cwd: PathBuf::from("/tmp"),
        shell: "/bin/sh".into(),
        command: vec![],
        environment: vec![("DCOUNT".into(), "0".into())],
        history_limit: 100000,
        mouse: true,
        prefix: "C-a".into(),
        cols: 100,
        rows: 30,
    })?;
    Ok((root, workspace, cleanup))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires bundled runtime and Playwright; loopback only"]
async fn real_pty_direct_actor_falls_back_without_repeating_input_or_affecting_other_guests(
) -> Result<()> {
    let (_root, workspace, _cleanup) = workspace()?;
    let mut router = Attachments::new(workspace.clone(), 2)?;
    router.configure_direct(porthub_terminal::direct::host::Config {
        addresses: vec!["127.0.0.1".parse()?],
        stun_servers: vec![],
    })?;
    router.apply(HostEvent::Ready {
        direct_transport: true,
        history_snapshots: true,
        invitations_revoked: false,
        ssh_host: String::new(),
        ssh_port: 0,
        public_base: String::new(),
    })?;
    for client in [7, 8] {
        router.apply(HostEvent::Attach {
            client,
            read_only: client == 8,
            cols: 100,
            rows: 30,
            term: "xterm-256color".into(),
        })?;
    }
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../ui/tests/terminal-direct-host.cjs");
    let mut child = tokio::process::Command::new("node")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut initial = String::new();
    tokio::time::timeout(Duration::from_secs(10), output.read_line(&mut initial)).await??;
    let offer: serde_json::Value = serde_json::from_str(&initial)?;
    let description = DirectDescription(
        offer["description"]
            .as_str()
            .context("browser offer")?
            .into(),
    );
    router.apply(HostEvent::DirectOffer {
        client: 7,
        request: 1,
        description: description.clone(),
    })?;
    let mut pending = Vec::new();
    let mut result = false;
    let mut readonly_closed = false;
    let exercise = async {
        loop {
            tokio::select! {
             event=router.next()=>match event.context("host actor output closed")? {
              HostOutput::DirectAnswer{client:7,answer}=>{let mut bytes=serde_json::to_vec(&serde_json::json!({"type":"answer","answer":answer}))?;bytes.push(b'\n');input.write_all(&bytes).await?;},
              HostOutput::DirectAnswer{client:8,answer}=>{let packet=DeliveryPacket::encode(&Delivery::Data(Frame::new(&answer.input_epoch,1,b"DCOUNT=999\r")?))?;router.apply(HostEvent::Delivery{client:8,packet})?;},
              HostOutput::Delivery{client:7,packet}=>{let mut bytes=serde_json::to_vec(&serde_json::json!({"type":"relay","packet":packet}))?;bytes.push(b'\n');input.write_all(&bytes).await?;},
              HostOutput::Closed{client:8}=>{readonly_closed=true;},
              HostOutput::Closed{client:7}=>anyhow::bail!("writer was disconnected"),
              _=>{},
             },
             count=output.read_until(b'\n',&mut pending)=>{
              ensure!(count?>0,"browser driver closed early");let event:serde_json::Value=serde_json::from_slice(&std::mem::take(&mut pending))?;
              match event["type"].as_str() {
               Some("relay")=>{let packet:DeliveryPacket=serde_json::from_value(event["packet"].clone())?;router.apply(HostEvent::Delivery{client:7,packet})?;},
               Some("result")=>{
                ensure!(event["direct"].as_u64().unwrap_or(0)>0 && event["relay"].as_u64().unwrap_or(0)>0 && event["duplicates"].as_u64().unwrap_or(0)>0,"missing actual path transition");result=true;
                let mut independent:serde_json::Value=serde_json::from_str(&description.0)?;
                independent["sdp"]=independent["sdp"].as_str().unwrap().lines().map(|line|if line.starts_with("a=ice-ufrag:"){"a=ice-ufrag:independentguest"}else if line.starts_with("a=ice-pwd:"){"a=ice-pwd:independentguestpassword123456789"}else{line}).collect::<Vec<_>>().join("\r\n").into();
                router.apply(HostEvent::DirectOffer{client:8,request:1,description:DirectDescription(independent.to_string())})?;
               },_=>anyhow::bail!("invalid browser bridge event"),
              }
             }
            }
            if result && readonly_closed {
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(Duration::from_secs(25), exercise)
        .await
        .context("direct host scenario timed out")??;
    input.write_all(b"{\"type\":\"finish\"}\n").await?;
    ensure!(
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await??
            .success(),
        "browser direct host probe failed"
    );
    ensure!(
        router.participants() == 1 && workspace.is_alive(),
        "read-only rejection must preserve the writer and shell"
    );
    let sent = workspace
        .command()
        .args([
            "send-keys",
            "-c",
            "porthub-direct-owner",
            "-t",
            "%0",
            "printf 'AFTERRO:%s\\n' \"$DCOUNT\"",
            "Enter",
        ])
        .output()?;
    ensure!(sent.status.success(), "fixture input failed");
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if workspace.capture("%0", 200)?.contains("AFTERRO:1") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    router.apply(HostEvent::Detach { client: 7 })?;
    ensure!(
        workspace.is_alive(),
        "direct detach must preserve the workspace"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires bundled runtime; loopback only"]
async fn full_delivery_window_backpressures_its_source_but_not_another_attachment() -> Result<()> {
    use porthub_terminal::{delivery::MAX_PAYLOAD, direct::host, pty::Client};
    use tokio::sync::mpsc;
    let (_root, workspace, _cleanup) = workspace()?;
    let (dummy, _dummy_receive) = mpsc::channel(64);
    let first = Client::attach(
        &workspace,
        7,
        false,
        100,
        30,
        "xterm-256color",
        dummy.clone(),
    )?;
    let second = Client::attach(&workspace, 8, false, 100, 30, "xterm-256color", dummy)?;
    let (send, mut receive) = mpsc::channel(128);
    let (source, output) = mpsc::channel(8);
    let (other_source, other_output) = mpsc::channel(8);
    let config = host::Config {
        addresses: vec!["127.0.0.1".parse()?],
        stun_servers: vec![],
    };
    let first_actor = host::spawn(7, first.input_sink(), output, send.clone(), config.clone());
    let _second_actor = host::spawn(8, second.input_sink(), other_output, send, config);
    let mut peer =
        rtc::peer_connection::RTCPeerConnectionBuilder::new().build(std::time::Instant::now())?;
    peer.create_data_channel(porthub_terminal::direct::LABEL, None)?;
    first_actor.offer(
        1,
        DirectDescription(serde_json::to_string(&peer.create_offer(None)?)?),
    )?;
    let answer = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(HostOutput::DirectAnswer { client: 7, answer }) = receive.recv().await {
                break answer;
            }
        }
    })
    .await?;
    let producer = tokio::spawn(async move {
        let data = encode_data(&vec![b'z'; MAX_PAYLOAD]);
        for _ in 0..64 {
            source
                .send(HostOutput::Output {
                    client: 7,
                    data: data.clone(),
                })
                .await?;
        }
        Ok::<_, anyhow::Error>(())
    });
    for expected in 1..=4 {
        let event = tokio::time::timeout(Duration::from_secs(3), receive.recv())
            .await?
            .context("delivery actor stopped")?;
        let HostOutput::Delivery { client: 7, packet } = event else {
            anyhow::bail!("expected sequenced output")
        };
        let Delivery::Data(frame) = packet.decode()? else {
            anyhow::bail!("expected data")
        };
        ensure!(frame.sequence() == expected && frame.payload().len() == MAX_PAYLOAD);
    }
    ensure!(
        tokio::time::timeout(Duration::from_millis(50), receive.recv())
            .await
            .is_err(),
        "full output window must wait for application ACKs"
    );
    ensure!(
        !producer.is_finished(),
        "PTY source must be backpressured instead of dropping output"
    );
    other_source
        .send(HostOutput::Output {
            client: 8,
            data: encode_data(b"other-keeps-moving"),
        })
        .await?;
    let other = tokio::time::timeout(Duration::from_secs(1), receive.recv())
        .await?
        .context("other attachment stalled")?;
    ensure!(
        matches!(other, HostOutput::Output { client: 8, .. }),
        "one guest's full window must not stop another"
    );
    first_actor.relay(DeliveryPacket::encode(&Delivery::Ack {
        epoch: answer.output_epoch.clone(),
        sequence: 4,
    })?)?;
    for expected in 5..=64 {
        let event = tokio::time::timeout(Duration::from_secs(3), receive.recv())
            .await?
            .context("delivery actor stopped")?;
        let HostOutput::Delivery { client: 7, packet } = event else {
            anyhow::bail!("output was lost before drain completed")
        };
        let Delivery::Data(frame) = packet.decode()? else {
            anyhow::bail!("expected data")
        };
        ensure!(frame.sequence() == expected && frame.payload().iter().all(|byte| *byte == b'z'));
        first_actor.relay(DeliveryPacket::encode(&Delivery::Ack {
            epoch: answer.output_epoch.clone(),
            sequence: expected,
        })?)?;
    }
    tokio::time::timeout(Duration::from_secs(3), producer).await???;
    let closed = tokio::time::timeout(Duration::from_secs(3), receive.recv())
        .await?
        .context("missing drained close")?;
    ensure!(
        matches!(closed, HostOutput::Closed { client: 7 }),
        "source EOF must follow acknowledged output"
    );
    ensure!(workspace.is_alive());
    Ok(())
}
