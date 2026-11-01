#![cfg(all(unix, feature = "direct"))]
//! Real bundled shell -> host actor -> UDP native guest -> sequenced relay.
use anyhow::{ensure, Result};
use porthub_terminal::{
    direct::{host::Config, viewer::Transport},
    host::Attachments,
    multiplexer::{create_directory, Start, Workspace},
    protocol::*,
};
use std::{path::PathBuf, time::Duration};
use tokio::net::UdpSocket;
struct Cleanup(Workspace);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.0.stop();
    }
}
fn route(host: &mut Attachments, inputs: Vec<ViewerInput>) -> Result<()> {
    for input in inputs {
        host.apply(match input {
            ViewerInput::DirectOffer {
                request,
                description,
            } => HostEvent::DirectOffer {
                client: 7,
                request,
                description,
            },
            ViewerInput::Delivery { packet } => HostEvent::Delivery { client: 7, packet },
            ViewerInput::Input { data } => HostEvent::Input { client: 7, data },
            _ => anyhow::bail!("unexpected native guest signal"),
        })?;
    }
    Ok(())
}
async fn drive(
    host: &mut Attachments,
    native: &mut Transport,
    screen: &mut Vec<u8>,
    marker: Option<&[u8]>,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(8),async {
        loop {
            if marker.map_or_else(||native.direct(),|marker|screen.windows(marker.len()).any(|bytes|bytes==marker)) {return Ok::<_,anyhow::Error>(());}
            tokio::select! {
                event=host.next()=>match event {
                    Some(HostOutput::DirectAnswer {client:7,answer})=>route(host,native.answer(&answer)?)?,
                    Some(HostOutput::Delivery {client:7,packet})=>native.receipt(packet.decode()?)?,
                    Some(HostOutput::Output {client:7,data})=>screen.extend_from_slice(&native.legacy_output(&data)?),
                    Some(HostOutput::Closed {client:7|8})|None=>anyhow::bail!("native transport change disconnected a participant"),
                    Some(HostOutput::DirectUnavailable {client:7,..})=>anyhow::bail!("loopback native path unavailable"),
                    _=>{},
                },
                relay=native.network()=>route(host,relay?)?,
            }
            while let Some(frame)=native.next_output() {
                let sequence=frame.sequence();screen.extend_from_slice(frame.payload());native.commit_output(sequence)?;
            }
            route(host,native.acknowledge_output()?)?;
            ensure!(screen.len()<262144,"native fixture output exceeded bound");
        }
    }).await??;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires bundled terminal runtime; isolated loopback only"]
async fn native_guest_keeps_the_real_shared_shell_across_direct_to_relay_fallback() -> Result<()> {
    let root = tempfile::Builder::new()
        .prefix("ph-native-udp-")
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
    let _cleanup = Cleanup(workspace.clone());
    workspace.start(&Start {
        cwd: PathBuf::from("/tmp"),
        shell: "/bin/sh".into(),
        command: vec![],
        environment: vec![
            ("DCOUNT".into(), "0".into()),
            ("ENV".into(), "".into()),
            ("BASH_ENV".into(), "".into()),
        ],
        history_limit: 100000,
        mouse: true,
        prefix: "C-a".into(),
        cols: 100,
        rows: 30,
    })?;
    // A loopback RFC 5389 responder reports each caller's actual bound socket.
    // No discovery request or ICE packet in this fixture leaves loopback.
    let stun = UdpSocket::bind("127.0.0.1:0").await?;
    let stun_servers = vec![format!("stun:{}", stun.local_addr()?)];
    let sources = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = sources.clone();
    let _stun = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        let mut bytes = [0u8; 2048];
        loop {
            let (size, source) = stun.recv_from(&mut bytes).await?;
            if size < 20 || bytes[..2] != [0, 1] {
                continue;
            }
            recorded.lock().unwrap().push(source);
            let std::net::IpAddr::V4(ip) = source.ip() else {
                continue;
            };
            let mut reply = [0u8; 32];
            reply[..4].copy_from_slice(&[1, 1, 0, 12]);
            reply[4..20].copy_from_slice(&bytes[4..20]);
            reply[20..26].copy_from_slice(&[0, 32, 0, 8, 0, 1]);
            reply[26..28].copy_from_slice(&(source.port() ^ 0x2112).to_be_bytes());
            for (index, byte) in ip.octets().into_iter().enumerate() {
                reply[28 + index] = byte ^ [0x21, 0x12, 0xa4, 0x42][index];
            }
            stun.send_to(&reply, source).await?;
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    }));
    let mut host = Attachments::new(workspace.clone(), 2)?;
    host.configure_direct(Config {
        addresses: vec!["127.0.0.1".parse()?],
        stun_servers: stun_servers.clone(),
    })?;
    host.apply(HostEvent::Ready {
        direct_transport: true,
        history_snapshots: true,
        invitations_revoked: false,
        ssh_host: String::new(),
        ssh_port: 0,
        public_base: String::new(),
    })?;
    for client in [7, 8] {
        host.apply(HostEvent::Attach {
            client,
            read_only: false,
            cols: 100,
            rows: 30,
            term: "xterm-256color".into(),
        })?;
    }
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local = socket.local_addr()?;
    let mapped = porthub_mesh::stun::mapped(&socket, &stun_servers).await;
    ensure!(
        mapped == Some(local),
        "guest discovery must reuse its eventual ICE socket"
    );
    let (mut native, offer) = Transport::offer_reflexive(socket, false, mapped)?;
    route(&mut host, vec![offer])?;
    // The host gathers its own approved socket before answering; the drive
    // loop below exercises discovery, real UDP and same-epoch relay fallback.
    let mut screen = Vec::new();
    drive(&mut host, &mut native, &mut screen, None).await?;
    let observed = sources
        .lock()
        .unwrap()
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        observed.contains(&local) && observed.len() == 2,
        "both peers must discover on their actual separate bound ICE sockets"
    );
    let command = b"DCOUNT=$((DCOUNT+1)); printf '\\r\\nNATIVE_COUNTER_%s\\r\\n' \"$DCOUNT\"\r";
    route(&mut host, native.input(command)?)?;
    drive(
        &mut host,
        &mut native,
        &mut screen,
        Some(b"NATIVE_COUNTER_1"),
    )
    .await?;
    ensure!(
        native.traffic().udp_sent > 0 && native.traffic().udp_received > 0,
        "missing real UDP traffic"
    );
    route(&mut host, native.fallback()?)?;
    route(&mut host, native.input(command)?)?;
    drive(
        &mut host,
        &mut native,
        &mut screen,
        Some(b"NATIVE_COUNTER_2"),
    )
    .await?;
    let first = host.participant_traffic(7).unwrap();
    ensure!(
        first.input_bytes == 2 * command.len() as u64,
        "replay inflated host input measurements"
    );
    ensure!(
        first.output_bytes > 0
            && first.direct_udp_sent_bytes > 0
            && first.direct_udp_received_bytes > 0,
        "host missed direct transport measurements"
    );
    let other = b"printf '\\r\\nINDEPENDENT_%s\\r\\n' OK\r";
    host.apply(HostEvent::Input {
        client: 8,
        data: encode_data(other),
    })?;
    drive(&mut host, &mut native, &mut screen, Some(b"INDEPENDENT_OK")).await?;
    ensure!(
        host.participant_traffic(7).unwrap().input_bytes == first.input_bytes,
        "another guest changed this participant's counters"
    );
    ensure!(
        host.participant_traffic(8).unwrap().input_bytes == other.len() as u64,
        "legacy relay input was not measured"
    );
    ensure!(
        host.traffic().input_bytes == first.input_bytes + other.len() as u64,
        "host totals lost a participant"
    );
    ensure!(
        workspace.is_alive(),
        "transport fallback ended the shared shell"
    );
    ensure!(
        !native.direct(),
        "fallback unexpectedly reopened direct transport"
    );
    Ok(())
}
