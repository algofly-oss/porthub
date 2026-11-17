//! Explicitly ignored two-host RAM-stream benchmark. Uses production negotiation
//! and bulk bridge; never invokes a USB adapter, block device, mount or storage IO.
//! The loopback signaling fixture is reached over an operator-owned SSH tunnel.
use super::*;
use anyhow::{ensure, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    handshake::server::{ErrorResponse, Request, Response},
    Message,
};
use tokio_util::task::AbortOnDropHandle;
const BYTES: usize = 128 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;
const AUTH: &str = "root-reviewed-memory-bulk-v1";
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Role {
    Source,
    Destination,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    role: Role,
    nonce: String,
    local: Ipv4Addr,
    peer: Ipv4Addr,
    control_port: u16,
}
impl Config {
    fn valid(&self) -> Result<()> {
        ensure!(
            self.nonce.len() == 64 && self.nonce.bytes().all(|b| b.is_ascii_hexdigit()),
            "Private fixture capability required"
        );
        ensure!(
            self.local.is_private()
                && !self.local.is_loopback()
                && self.peer.is_private()
                && !self.peer.is_loopback()
                && self.local != self.peer
                && self.control_port >= 1024,
            "Exact distinct private LAN endpoints required"
        );
        Ok(())
    }
    fn load() -> Result<Self> {
        ensure!(
            std::env::var("PORTHUB_USB_MEMORY_BENCH_AUTHORIZED").as_deref() == Ok(AUTH),
            "Explicit memory-only benchmark authorization required"
        );
        let path = std::path::PathBuf::from(std::env::var("PORTHUB_USB_MEMORY_BENCH_SPEC")?);
        let bytes = crate::profile::read_private(&path)?;
        ensure!(
            bytes.len() <= 4096,
            "Bounded private benchmark spec required"
        );
        let config: Self = serde_json::from_slice(&bytes)?;
        config.valid()?;
        Ok(config)
    }
}
fn pattern(seed: u8) -> Vec<u8> {
    (0..CHUNK)
        .map(|i| ((i % 251) as u8).wrapping_mul(17) ^ seed)
        .collect()
}
fn stamp(bytes: &mut [u8], offset: usize, seed: u8) {
    bytes[..8].copy_from_slice(&(offset as u64).to_le_bytes());
    bytes[8..16].copy_from_slice(&(u64::from(seed) ^ 0x9e3779b97f4a7c15).to_le_bytes());
}
async fn send_memory(
    writer: &mut (impl AsyncWrite + Unpin),
    length: usize,
    seed: u8,
) -> Result<String> {
    ensure!(
        length > 0 && length <= BYTES && length % CHUNK == 0,
        "Invalid bounded benchmark length"
    );
    let mut bytes = pattern(seed);
    let mut hash = Sha256::new();
    for offset in (0..length).step_by(CHUNK) {
        stamp(&mut bytes, offset, seed);
        hash.update(&bytes);
        writer.write_all(&bytes).await?;
    }
    let digest = hash.finalize();
    writer.write_all(&digest).await?;
    writer.flush().await?;
    Ok(format!("{digest:x}"))
}
async fn receive_memory(
    reader: &mut (impl AsyncRead + Unpin),
    length: usize,
    seed: u8,
) -> Result<String> {
    ensure!(
        length > 0 && length <= BYTES && length % CHUNK == 0,
        "Invalid bounded benchmark length"
    );
    let mut bytes = vec![0; CHUNK];
    let mut expected = pattern(seed);
    let mut hash = Sha256::new();
    for offset in (0..length).step_by(CHUNK) {
        reader.read_exact(&mut bytes).await?;
        stamp(&mut expected, offset, seed);
        ensure!(bytes == expected, "Memory stream pattern/order changed");
        hash.update(&bytes);
    }
    let digest = hash.finalize();
    let mut remote = [0; 32];
    reader.read_exact(&mut remote).await?;
    ensure!(
        remote.as_slice() == digest.as_slice(),
        "Memory stream SHA mismatch"
    );
    Ok(format!("{digest:x}"))
}
fn reject() -> ErrorResponse {
    tokio_tungstenite::tungstenite::http::Response::builder()
        .status(403)
        .body(Some("Private fixture rejected".into()))
        .unwrap()
}
async fn fixture_client(config: &Config) -> Result<Socket> {
    let mut request = format!("ws://127.0.0.1:{}/private-memory-only", config.control_port)
        .into_client_request()?;
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {}", config.nonce).parse()?);
    request.headers_mut().insert(
        "x-porthub-fixture-role",
        if config.role == Role::Source {
            "source"
        } else {
            "destination"
        }
        .parse()?,
    );
    let (socket, _) = tokio_tungstenite::connect_async(request).await?;
    Ok(socket)
}
async fn gateway_connection(
    listener: &TcpListener,
    nonce: &str,
) -> Result<(Role, tokio_tungstenite::WebSocketStream<TcpStream>)> {
    let (stream, peer) = listener.accept().await?;
    ensure!(
        peer.ip().is_loopback(),
        "Signaling fixture must remain loopback/SSH-only"
    );
    let auth = format!("Bearer {nonce}");
    let role = Arc::new(std::sync::Mutex::new(None));
    let captured = role.clone();
    let callback = move |request: &Request, response: Response| {
        if request.uri().path() != "/private-memory-only"
            || request
                .headers()
                .get("authorization")
                .and_then(|h| h.to_str().ok())
                != Some(&auth)
        {
            return Err(reject());
        }
        let value = match request
            .headers()
            .get("x-porthub-fixture-role")
            .and_then(|h| h.to_str().ok())
        {
            Some("source") => Role::Source,
            Some("destination") => Role::Destination,
            _ => return Err(reject()),
        };
        *captured.lock().unwrap() = Some(value);
        Ok(response)
    };
    let socket = tokio_tungstenite::accept_hdr_async_with_config(
        stream,
        callback,
        Some(
            tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                .max_message_size(Some(65536))
                .max_frame_size(Some(65536)),
        ),
    )
    .await?;
    let role = role
        .lock()
        .unwrap()
        .take()
        .context("Fixture role missing")?;
    Ok((role, socket))
}
async fn relay_gateway(
    listener: TcpListener,
    nonce: String,
    binary: Arc<AtomicUsize>,
) -> Result<()> {
    let (first, mut a) = gateway_connection(&listener, &nonce).await?;
    let (second, mut b) = gateway_connection(&listener, &nonce).await?;
    ensure!(first != second, "Duplicate private fixture role");
    loop {
        tokio::select! {
         frame=a.next()=>match frame{Some(Ok(Message::Binary(data)))=>{binary.fetch_add(data.len(),Ordering::SeqCst);anyhow::bail!("Payload reached signaling fixture")},Some(Ok(Message::Close(_)))|None=>{let _=b.close(None).await;break;},Some(Ok(frame))=>b.send(frame).await?,Some(Err(_))=>{let _=b.close(None).await;break;}},
         frame=b.next()=>match frame{Some(Ok(Message::Binary(data)))=>{binary.fetch_add(data.len(),Ordering::SeqCst);anyhow::bail!("Payload reached signaling fixture")},Some(Ok(Message::Close(_)))|None=>{let _=a.close(None).await;break;},Some(Ok(frame))=>a.send(frame).await?,Some(Err(_))=>{let _=a.close(None).await;break;}}
        }
    }
    Ok(())
}
// A typed transport EOF is expected only AFTER every payload/checksum and
// application COMMIT barrier succeeded. Never classify payload reads here.
fn destination_terminal_after_commit(complete: bool, result: Result<()>) -> Result<&'static str> {
    ensure!(complete, "Destination completion barriers not satisfied");
    match result {
        Ok(()) => Ok("clean-control-close"),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::UnexpectedEof) =>
        {
            Ok("expected-post-commit-revoke-tls-eof")
        }
        Err(error) => Err(error),
    }
}
async fn run(config: Config) -> Result<serde_json::Value> {
    let payload_bytes = Arc::new(AtomicUsize::new(0));
    let mut gateway = if config.role == Role::Source {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, config.control_port)).await?;
        println!("PORTHUB_MEMORY_SIGNAL_READY loopback-only");
        let nonce = config.nonce.clone();
        let binary = payload_bytes.clone();
        Some(AbortOnDropHandle::new(tokio::spawn(relay_gateway(
            listener, nonce, binary,
        ))))
    } else {
        None
    };
    // No enrollment/API request is made: this in-memory profile labels the test
    // authority. Control still reads NORMAL source/interface/VPN policy from env.
    let control = Control::new(crate::profile::Profile {
        format_version: 1,
        server: "https://fixture.invalid".into(),
        machine_id: if config.role == Role::Source {
            "a"
        } else {
            "b"
        }
        .repeat(24),
        token: config.nonce.clone(),
        account_email: None,
        fallback_servers: vec![],
        setup_overrides: BTreeMap::new(),
        allow_insecure_http_for_tests: false,
    })?;
    ensure!(
        getifaddrs::getifaddrs()?.any(|i| i.address.ip_addr() == Some(IpAddr::V4(config.local))
            && control.direct_interface_allowed(&i.name, IpAddr::V4(config.local))),
        "Expected local LAN source not permitted by normal policy"
    );
    let mut socket =
        tokio::time::timeout(Duration::from_secs(15), fixture_client(&config)).await??;
    let initial = features::Policy::default();
    ensure!(
        initial.enabled(Feature::Usb) && initial.enabled(Feature::DirectConnections),
        "Private policy does not permit benchmark"
    );
    let carrier = tokio::time::timeout(
        Duration::from_secs(30),
        negotiate(
            &mut socket,
            config.role == Role::Source,
            initial.enabled(Feature::Usb) && initial.enabled(Feature::DirectConnections),
            &control,
        ),
    )
    .await??;
    let bulk = carrier
        .tcp
        .context("Benchmark refuses SCTP/gateway fallback; actual direct TLS required")?;
    let local = bulk.get_ref().0.local_addr()?;
    let peer = bulk.get_ref().0.peer_addr()?;
    ensure!(
        local.ip() == IpAddr::V4(config.local)
            && peer.ip() == IpAddr::V4(config.peer)
            && !local.ip().is_loopback()
            && !peer.ip().is_loopback(),
        "Selected TLS endpoints differ from exact nonloopback hosts"
    );
    text(&mut socket, json!({"type":"memory_ready"})).await?;
    ensure!(
        next_text(&mut socket).await?["type"] == "memory_ready",
        "Peer memory barrier missing"
    );
    let (mut app, kernel) = tokio::io::duplex(256 * 1024);
    let (policy, watch) = tokio::sync::watch::channel(initial);
    let mut bridge = AbortOnDropHandle::new(tokio::spawn(bridge_bulk(
        kernel, socket, bulk, watch, None, false,
    )));
    let started = Instant::now();
    let (mut read, mut write) = tokio::io::split(&mut app);
    let seed = if config.role == Role::Source {
        0x6d
    } else {
        0x39
    };
    let receive = async {
        let digest = receive_memory(
            &mut read,
            BYTES,
            if config.role == Role::Source {
                0x39
            } else {
                0x6d
            },
        )
        .await?;
        Ok::<_, anyhow::Error>((digest, started.elapsed()))
    };
    let (sent, (received, receive_elapsed)) =
        tokio::try_join!(send_memory(&mut write, BYTES, seed), receive)?;
    let elapsed = started.elapsed();
    write.write_all(b"BENCHACK").await?;
    let mut tag = [0; 8];
    read.read_exact(&mut tag).await?;
    ensure!(&tag == b"BENCHACK", "Peer checksum completion missing");
    let revoke = Instant::now();
    let terminal_class;
    if config.role == Role::Source {
        write.write_all(b"COMMIT00").await?;
        read.read_exact(&mut tag).await?;
        ensure!(
            &tag == b"COMMITOK",
            "Peer completion acknowledgment missing"
        );
        let mut disabled = features::Policy::default();
        disabled.disabled.insert(Feature::Usb, true);
        policy.send_replace(disabled);
        tokio::time::timeout(Duration::from_secs(3), &mut bridge).await???;
        terminal_class = "local-policy-revoked";
    } else {
        read.read_exact(&mut tag).await?;
        ensure!(&tag == b"COMMIT00", "Source completion missing");
        write.write_all(b"COMMITOK").await?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), &mut bridge).await??;
        terminal_class = destination_terminal_after_commit(true, stopped)?;
    }
    if let Some(gateway) = gateway.as_mut() {
        tokio::time::timeout(Duration::from_secs(3), gateway).await???;
        ensure!(
            payload_bytes.load(Ordering::SeqCst) == 0,
            "Payload bypass assertion failed"
        );
    }
    Ok(
        json!({"scope":"paired RAM stream transport ceiling, NOT USB storage or production registry proof","fixture_gateway":"loopback authenticated capability signaling over owned SSH tunnel","session_sha256":format!("{:x}",Sha256::digest(config.nonce.as_bytes())),"role":if config.role==Role::Source{"source"}else{"destination"},"transport":"actual usb::negotiate(Control) authenticated direct bulk TLS + bridge_bulk","local":local.ip().to_string(),"peer":peer.ip().to_string(),"sent_payload_bytes":BYTES,"received_payload_bytes":BYTES,"sent_sha256":sent,"received_sha256":received,"receive_seconds":receive_elapsed.as_secs_f64(),"receive_mib_per_second":128.0/receive_elapsed.as_secs_f64(),"duplex_transfer_seconds":elapsed.as_secs_f64(),"bounded_chunk_bytes":CHUNK,"duplex_capacity_bytes":256*1024,"gateway_payload_bytes":if config.role==Role::Source{Some(payload_bytes.load(Ordering::SeqCst))}else{None},"gateway_proof_requires_source_receipt":config.role==Role::Destination,"local_usb_revocation_exercised":config.role==Role::Source,"bridge_stopped":true,"payload_and_commit_barriers_complete":true,"terminal_class":terminal_class,"stop_elapsed_ms":revoke.elapsed().as_millis(),"native_usb_opened":false,"block_devices_opened":false,"filesystem_payload_writes":0}),
    )
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Explicit Root-reviewed two-host memory-only transport benchmark; never a physical USB/storage test"]
async fn paired_lan_memory_transport_ceiling() -> Result<()> {
    let config = Config::load()?;
    let proof = tokio::time::timeout(Duration::from_secs(180), run(config)).await??;
    println!("PORTHUB_MEMORY_BULK_PROOF {}", proof);
    Ok(())
}
#[test]
fn config_rejects_loopback_public_equal_and_unbounded_auth() {
    let mut c = Config {
        role: Role::Source,
        nonce: "a".repeat(64),
        local: Ipv4Addr::new(192, 168, 0, 3),
        peer: Ipv4Addr::new(192, 168, 0, 166),
        control_port: 49231,
    };
    assert!(c.valid().is_ok());
    for ip in [Ipv4Addr::LOCALHOST, Ipv4Addr::new(8, 8, 8, 8), c.local] {
        c.peer = ip;
        assert!(c.valid().is_err());
    }
    c.peer = Ipv4Addr::new(192, 168, 0, 166);
    c.nonce = "a".repeat(65);
    assert!(c.valid().is_err());
}
#[tokio::test]
async fn bounded_pattern_stream_verifies_offsets_and_digest_without_large_allocation() -> Result<()>
{
    let (mut a, mut b) = tokio::io::duplex(1024);
    let (sent, received) = tokio::try_join!(
        send_memory(&mut a, 2 * CHUNK, 0x6d),
        receive_memory(&mut b, 2 * CHUNK, 0x6d)
    )?;
    ensure!(sent == received);
    Ok(())
}
#[tokio::test]
async fn wrong_seed_is_rejected() -> Result<()> {
    let (mut a, mut b) = tokio::io::duplex(CHUNK * 2);
    let sender = AbortOnDropHandle::new(tokio::spawn(async move {
        send_memory(&mut a, CHUNK, 0x6d).await
    }));
    ensure!(receive_memory(&mut b, CHUNK, 0x39).await.is_err());
    drop(sender);
    Ok(())
}

#[test]
fn only_typed_eof_after_completed_barriers_is_expected_revocation() -> Result<()> {
    let eof = || {
        anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "inert EOF fixture",
        ))
    };
    ensure!(
        destination_terminal_after_commit(true, Err(eof()))?
            == "expected-post-commit-revoke-tls-eof"
    );
    ensure!(destination_terminal_after_commit(false, Err(eof())).is_err());
    ensure!(destination_terminal_after_commit(false, Ok(())).is_err());
    ensure!(destination_terminal_after_commit(true, Ok(()))? == "clean-control-close");
    for kind in [
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::TimedOut,
        std::io::ErrorKind::PermissionDenied,
    ] {
        ensure!(destination_terminal_after_commit(
            true,
            Err(std::io::Error::new(kind, "inert rejected fixture").into())
        )
        .is_err());
    }
    ensure!(
        destination_terminal_after_commit(
            true,
            Err(anyhow::anyhow!("peer closed without TLS close_notify"))
        )
        .is_err(),
        "String matching must not authorize unknown errors"
    );
    Ok(())
}
