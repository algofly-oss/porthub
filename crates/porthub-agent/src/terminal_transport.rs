//! Terminal host transport through the OS-authenticated local broker. Only the
//! service injects machine authorization; the user process supplies session caps.
use anyhow::{ensure, Result};
use futures_util::{SinkExt, StreamExt};
use porthub_terminal::protocol::{HostEvent, HostHello, HostOutput};
use serde::{Deserialize, Serialize};
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

struct GatewayFeatures { snapshots: bool, direct: bool, addresses: Vec<std::net::IpAddr> }

/// Local broker envelope only. This is deliberately not a gateway HostEvent:
/// the remote gateway cannot inject an underlay policy into the OS-user host.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectPolicy {
    #[serde(rename = "type")]
    pub kind: String,
    pub addresses: Vec<std::net::IpAddr>,
    pub stun_servers: Vec<String>,
}

// Read only the securely paired registration. Display metadata and unrelated
// accounts cannot grant permission to bypass an application's selected exit.
fn direct_allowed(path: &std::path::Path, public: &crate::profile::Profile) -> bool {
    let checked = || -> Result<bool> {
        let Some(module) = crate::unified::load(path, public)? else { return Ok(true); };
        if !module.enabled { return Ok(false); }
        #[cfg(feature = "local-tor")]
        if crate::private_network::tor_preferences::load(&module.private_profile)?.system_wide {
            return Ok(false);
        }
        let status = crate::runtime::status(&module.private_profile)?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        Ok(direct_status_allowed(&status, now))
    };
    checked().unwrap_or(false)
}

fn direct_status_allowed(status: &crate::runtime::Status, now: u64) -> bool {
    status.state == "running"
        && status.updated_at <= now
        && now.saturating_sub(status.updated_at) <= 30
        && status.private_status.as_ref().is_some_and(|private| private.lease_valid && private.exit.is_none())
}

async fn open(
    control: &crate::control::Control,
) -> Result<(WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>, GatewayFeatures)> {
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
            let (socket, response) = tokio_tungstenite::client_async_tls_with_config(
                handshake,
                stream,
                Some(limits),
                None,
            )
            .await?;
            let snapshots = response.headers().get("x-porthub-history-snapshots")
                .is_some_and(|value| value == "1");
            let direct=response.headers().get("x-porthub-terminal-direct").is_some_and(|value|value=="1");
            Ok::<_, anyhow::Error>((socket, GatewayFeatures {snapshots,direct,addresses:sources}))
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
    profile: &std::path::Path,
    message: serde_json::Value,
    cancel: CancellationToken,
) -> Result<()> {
    let mut request: Request = serde_json::from_value(message)?;
    ensure!(
        request.operation == "terminal_host",
        "invalid terminal broker operation"
    );
    request.hello.validate(porthub_terminal::protocol::now())?;
    let (mut remote, features) = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = tokio::time::timeout(Duration::from_secs(40), open(control)) => match result {
            Ok(Ok(remote)) => remote,
            _ => {
                local.get_mut().write_all(b"{\"error\":\"terminal gateway unavailable\"}\n").await?;
                return Ok(());
            }
        }
    };
    // Older gateways reject unknown fields. Advertise only capabilities that
    // both the local host and the authenticated gateway support.
    request.hello.history_snapshots &= features.snapshots;
    request.hello.direct_transport &= features.direct && direct_allowed(profile, control.profile());
    remote
        .send(Message::Text(serde_json::to_string(&request.hello)?.into()))
        .await?;
    if request.hello.direct_transport {
        let policy=DirectPolicy {kind:"terminal_direct_policy".into(),addresses:features.addresses,stun_servers:vec![]};
        let mut bytes=serde_json::to_vec(&policy)?;bytes.push(b'\n');
        tokio::time::timeout(Duration::from_secs(5),local.get_mut().write_all(&bytes)).await??;
    }
    let mut partial = Vec::new();
    let mut policy_tick = tokio::time::interval(Duration::from_secs(5));
    policy_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = policy_tick.tick(), if request.hello.direct_transport => {
                // Stop the transport generation if an exit/privacy policy is
                // selected or becomes unknown. The user supervisor reconnects
                // with relay-only negotiation and retains its existing shell.
                if !direct_allowed(profile, control.profile()) { break; }
            }
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

    #[test]
    fn gateway_cannot_supply_a_local_direct_policy() -> Result<()> {
        let policy=serde_json::to_value(DirectPolicy {
            kind:"terminal_direct_policy".into(),addresses:vec![std::net::Ipv4Addr::LOCALHOST.into()],stun_servers:vec![],
        })?;
        assert!(serde_json::from_value::<HostEvent>(policy.clone()).is_err());
        assert!(serde_json::from_value::<HostOutput>(policy).is_err());
        Ok(())
    }

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
    async fn authenticated_broker_preserves_frames_and_keeps_machine_secret_private() -> Result<()> {
        for snapshots in [false,true] {for direct in [false,true] {broker_gateway(snapshots,direct,false,false).await?;}}
        broker_gateway(true,true,true,false).await?;
        Ok(())
    }

    #[tokio::test]
    async fn newly_unavailable_exit_policy_ends_only_the_direct_transport_generation() -> Result<()> {
        broker_gateway(true,true,false,true).await
    }

    #[test]
    fn direct_requires_fresh_known_policy_without_a_selected_exit() -> Result<()> {
        let mut status: crate::runtime::Status = serde_json::from_value(serde_json::json!({
            "pid":1,"state":"running","agent_version":"test","config_version":"", "service_count":0,
            "route":"private","updated_at":100,"update_request_id":"",
            "private_status":{"revision":1,"grants":0,"dns_rules":0,"lease_valid":true,"exit":null}
        }))?;
        assert!(direct_status_allowed(&status,100));
        assert!(direct_status_allowed(&status,130));
        assert!(!direct_status_allowed(&status,131));
        assert!(!direct_status_allowed(&status,99));
        status.private_status.as_mut().unwrap().lease_valid=false;
        assert!(!direct_status_allowed(&status,100));
        status.private_status.as_mut().unwrap().lease_valid=true;
        status.state="connecting".into();
        assert!(!direct_status_allowed(&status,100));
        status.state="running".into();
        for traffic_mode in [porthub_mesh::exit_policy::TrafficMode::All,porthub_mesh::exit_policy::TrafficMode::InternetOnly,porthub_mesh::exit_policy::TrafficMode::LanOnly] {
            status.private_status.as_mut().unwrap().exit=Some(crate::runtime::ExitStatus {
                name:"exit".into(),selection:"sticky".into(),traffic_mode,state:"pending".into(),
                peers:0,available:0,allow_direct_fallback:true,peer_names:vec![],
            });
            assert!(!direct_status_allowed(&status,100));
        }
        status.private_status=None;
        assert!(!direct_status_allowed(&status,100));
        Ok(())
    }

    #[cfg(feature = "local-tor")]
    #[test]
    fn secure_paired_policy_blocks_system_tor_and_a_stopped_owner() -> Result<()> {
        let fixture=tempfile::tempdir()?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(fixture.path(),std::fs::Permissions::from_mode(0o700))?;
        }
        let public:crate::profile::Profile=serde_json::from_value(serde_json::json!({
            "server":"https://example.test","machine_id":"0123456789abcdef01234567","token":"public-secret"
        }))?;
        let private:crate::private_profile::Profile=serde_json::from_value(serde_json::json!({
            "server":"https://example.test","workspace":"111111111111111111111111",
            "peer_id":"111111111111111111111111:0123456789abcdef01234567","token":"c".repeat(64)
        }))?;
        let public_path=fixture.path().join("public.json");
        let identity=crate::service::RegistrationProfile::Private(private.clone()).identity();
        let private_path=fixture.path().join(format!("{identity}.json"));
        crate::profile::write_private(&private_path,&serde_json::to_vec(&private)?,false)?;
        crate::unified::save(&public_path,&public,&crate::unified::Configuration {
            format_version:1,private_profile:private_path.clone(),enabled:true,
        })?;
        let lease=crate::profile::Lease::acquire(&private_path)?;
        let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let status=serde_json::json!({"pid":std::process::id(),"state":"running","agent_version":"test",
            "config_version":"","service_count":0,"route":"private","updated_at":now,"update_request_id":"",
            "private_status":{"revision":1,"grants":0,"dns_rules":0,"lease_valid":true,"exit":null}});
        crate::profile::write_private(&crate::profile::sibling(&private_path,".status.json"),&serde_json::to_vec(&status)?,false)?;
        assert!(direct_allowed(&public_path,&public));
        crate::private_network::tor_preferences::save(&private_path,crate::private_network::tor_preferences::Settings {
            system_wide:true,..Default::default()
        })?;
        assert!(!direct_allowed(&public_path,&public));
        crate::private_network::tor_preferences::save(&private_path,Default::default())?;
        assert!(direct_allowed(&public_path,&public));
        drop(lease);
        assert!(!direct_allowed(&public_path,&public));
        Ok(())
    }

    async fn broker_gateway(snapshots: bool, direct: bool, blocked: bool, revoke: bool) -> Result<()>
    {
        let fixture=tempfile::tempdir()?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(fixture.path(),std::fs::Permissions::from_mode(0o700))?;
        }
        let path=fixture.path().join("public.json");
        let policy_path=crate::unified::configuration_path(&path);
        if blocked {crate::profile::write_private(&policy_path,b"unreadable policy",false)?;}
        let negotiated_direct=direct && !blocked;
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
                |request: &tokio_tungstenite::tungstenite::handshake::server::Request, mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
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
                    if snapshots {
                        response.headers_mut().insert("x-porthub-history-snapshots", "1".parse().unwrap());
                    }
                    if direct {
                        response.headers_mut().insert("x-porthub-terminal-direct", "1".parse().unwrap());
                    }
                    Ok(response)
                },
            )
            .await?;
            let first = socket.next().await.unwrap()?.into_text()?;
            let hello: HostHello = serde_json::from_str(&first)?;
            assert_eq!(hello.history_snapshots, snapshots);
            assert_eq!(hello.direct_transport,negotiated_direct);
            assert_eq!(first.contains("direct_transport"),negotiated_direct);
            assert_eq!(first.contains("history_snapshots"), snapshots);
            assert!(!first.contains("broker-only-machine-secret"));
            socket
                .send(Message::Text(
                    serde_json::to_string(&HostEvent::Ready {
                        direct_transport: false,
                        history_snapshots: false,
                        invitations_revoked: false,
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
            if revoke {
                let closed=tokio::time::timeout(Duration::from_secs(8),socket.next()).await?;
                ensure!(matches!(closed,None|Some(Err(_))|Some(Ok(Message::Close(_)))),"policy revocation must close the old direct transport");
            } else { socket.close(None).await?; }
            Ok::<_, anyhow::Error>(())
        });
        let (local, service) = tokio::io::duplex(65536);
        let control = std::sync::Arc::new(crate::control::Control::new(profile)?);
        let owner = tokio::spawn(crate::exposure_protocol::serve_connection(
            service,
            control,
            CancellationToken::new(),
            path,
        ));
        let mut local = BufReader::new(local);
        let request = serde_json::json!({"operation":"terminal_host","hello":{ "history_snapshots":true,"direct_transport":true,
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
        let mut response =
            tokio::time::timeout(Duration::from_secs(5), frame(&mut local, &mut partial)).await??;
        if negotiated_direct {
            let policy:DirectPolicy=serde_json::from_slice(&response)?;
            assert_eq!(policy.kind,"terminal_direct_policy");
            assert_eq!(policy.addresses,vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
            assert!(policy.stun_servers.is_empty());
            assert!(!String::from_utf8_lossy(&response).contains("secret"));
            response=tokio::time::timeout(Duration::from_secs(5),frame(&mut local,&mut partial)).await??;
        }
        assert!(!String::from_utf8_lossy(&response).contains("secret"));
        assert!(matches!(
            serde_json::from_slice::<HostEvent>(&response)?,
            HostEvent::Ready { .. }
        ));
        if revoke {crate::profile::write_private(&policy_path,b"newly unavailable policy",false)?;}
        tokio::time::timeout(Duration::from_secs(8), owner).await???;
        gateway.await??;
        Ok(())
    }
}
