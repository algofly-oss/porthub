//! Credential-free local proxy sessions. Registration secrets remain inside the
//! OS-authenticated service; only a byte stream crosses its local broker.
use anyhow::{ensure, Context, Result};
use porthub_egress::{BoxStream, Connector, Destination};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig};
use tokio_util::sync::CancellationToken;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation: Operation,
    grant: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: u16,
}
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
enum Operation {
    #[serde(rename = "proxy_connect")]
    Connect,
    #[serde(rename = "proxy_check")]
    Check,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    error: Option<String>,
    #[serde(default)]
    ready: bool,
}
impl Request {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.grant.len() == 24 && self.grant.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid proxy grant ID"
        );
        if self.operation == Operation::Connect {
            Destination::new(self.host.clone(), self.port)?;
        } else {
            ensure!(
                self.host.is_empty() && self.port == 0,
                "proxy checks do not accept destinations"
            );
        }
        Ok(())
    }
}
fn private_registration(
    control: &crate::control::Control,
    profile: &Path,
) -> Result<crate::private_profile::Profile> {
    let config = crate::unified::load(profile, control.profile())?
        .context("this registration has no private identity")?;
    // The enrolled identity authorizes this stream. Using a shared proxy does
    // not require starting this machine's overlay or changing its routes.
    crate::private_profile::Profile::load(&config.private_profile)
}
async fn open(
    control: &crate::control::Control,
    profile: &Path,
    request: &Request,
) -> Result<BoxStream> {
    let private = private_registration(control, profile)?;
    for base in control.authorities() {
        let Ok(mut url) =
            url::Url::parse(&format!("{base}/api/access/proxy-stream/{}", request.grant))
        else {
            continue;
        };
        let scheme = match url.scheme() {
            "https" => "wss",
            "http" => "ws",
            _ => continue,
        };
        if url.set_scheme(scheme).is_err() {
            continue;
        }
        url.query_pairs_mut()
            .append_pair("host", &request.host)
            .append_pair("port", &request.port.to_string());
        let result = tokio::time::timeout(Duration::from_secs(25), async {
            let sources = control.stream_sources(&base).await?;
            ensure!(!sources.is_empty(), "gateway underlay unavailable");
            let stream = porthub_mesh::underlay::connect(&url, &sources).await?;
            let _ = stream.set_nodelay(true);
            let mut handshake = url.as_str().into_client_request()?;
            handshake
                .headers_mut()
                .insert("x-porthub-peer", private.peer_id.parse()?);
            handshake.headers_mut().insert(
                "authorization",
                format!("Bearer {}", private.token).parse()?,
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
            porthub_egress::websocket::stream(socket)
        })
        .await;
        if let Ok(Ok(stream)) = result {
            control.prefer_proxy_authority(base);
            return Ok(stream);
        }
    }
    anyhow::bail!("Shared proxy permission is unavailable or the gateway cannot be reached")
}
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut local: BufReader<S>,
    control: &crate::control::Control,
    profile: &Path,
    message: serde_json::Value,
    cancel: CancellationToken,
) -> Result<()> {
    let request: Request = serde_json::from_value(message)?;
    request.validate()?;
    if request.operation == Operation::Check {
        let result = async {
            let private = private_registration(control, profile)?;
            Ok::<_, anyhow::Error>(control.proxy_check(&private, &request.grant).await?)
        };
        let result = tokio::select! {_=cancel.cancelled()=>return Ok(()),result=tokio::time::timeout(Duration::from_secs(40),result)=>result};
        let reply = match result {
            Ok(Ok(ready)) => Reply { error: None, ready },
            _ => Reply {
                error: Some(
                    "Shared proxy permission is unavailable or the gateway cannot be reached"
                        .into(),
                ),
                ready: false,
            },
        };
        let mut bytes = serde_json::to_vec(&reply)?;
        bytes.push(b'\n');
        local.get_mut().write_all(&bytes).await?;
        return Ok(());
    }
    let remote = tokio::select! {_=cancel.cancelled()=>return Ok(()),result=tokio::time::timeout(Duration::from_secs(40),open(control,profile,&request))=>match result {Ok(result)=>result,Err(_)=>Err(anyhow::anyhow!("Shared proxy connection timed out"))}};
    let (mut remote, reply) = match remote {
        Ok(remote) => (
            Some(remote),
            Reply {
                error: None,
                ready: true,
            },
        ),
        Err(_) => (
            None,
            Reply {
                error: Some(
                    "Shared proxy permission is unavailable or the gateway cannot be reached"
                        .into(),
                ),
                ready: false,
            },
        ),
    };
    let mut response = serde_json::to_vec(&reply)?;
    response.push(b'\n');
    local.get_mut().write_all(&response).await?;
    if let Some(remote) = &mut remote {
        tokio::select! {_=cancel.cancelled()=>{}, _=tokio::io::copy_bidirectional(&mut local,remote)=>{}}
    }
    Ok(())
}

pub(crate) struct LocalConnector {
    pub registration: String,
    pub user: bool,
    pub grant: String,
}
impl LocalConnector {
    pub(crate) async fn check(&self) -> Result<bool> {
        let (_, reply) = self
            .call(Request {
                operation: Operation::Check,
                grant: self.grant.clone(),
                host: String::new(),
                port: 0,
            })
            .await?;
        Ok(reply.ready)
    }
    async fn call(&self, request: Request) -> Result<(BoxStream, Reply)> {
        request.validate()?;
        let layout = if self.user {
            crate::service::Layout::user()?
        } else {
            crate::service::Layout::system()?
        };
        let mut stream =
            crate::exposure_broker::connect_stream(&layout, &self.registration).await?;
        let mut bytes = serde_json::to_vec(&request)?;
        bytes.push(b'\n');
        stream.write_all(&bytes).await?;
        let mut reader = BufReader::new(stream);
        let reply: Reply = serde_json::from_slice(
            &tokio::time::timeout(
                Duration::from_secs(45),
                crate::exposure_protocol::line(&mut reader),
            )
            .await??,
        )?;
        ensure!(
            reply.error.is_none(),
            "{}",
            reply
                .error
                .as_deref()
                .unwrap_or("Shared proxy request failed")
        );
        Ok((Box::new(reader), reply))
    }
}
#[async_trait::async_trait]
impl Connector for LocalConnector {
    async fn connect(&self, destination: Destination) -> Result<BoxStream> {
        let (stream, _) = self
            .call(Request {
                operation: Operation::Connect,
                grant: self.grant.clone(),
                host: destination.host,
                port: destination.port,
            })
            .await?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_requests_cannot_inject_credentials_or_an_arbitrary_operation() {
        let request = serde_json::json!({"operation":"proxy_connect","grant":"a".repeat(24),"host":"example.com","port":443});
        assert!(serde_json::from_value::<Request>(request.clone())
            .unwrap()
            .validate()
            .is_ok());
        for (key, value) in [
            ("token", serde_json::json!("stolen")),
            ("operation", serde_json::json!("create_grant")),
        ] {
            let mut changed = request.clone();
            changed[key] = value;
            assert!(serde_json::from_value::<Request>(changed).is_err());
        }
        let mut changed = request;
        changed["grant"] = serde_json::json!("../other");
        assert!(serde_json::from_value::<Request>(changed)
            .unwrap()
            .validate()
            .is_err());
    }
    #[tokio::test]
    async fn broker_keeps_secrets_private_and_preserves_buffered_data_and_half_close() -> Result<()>
    {
        use futures_util::{SinkExt, StreamExt};
        use tokio::io::AsyncReadExt;
        use tokio_tungstenite::tungstenite::Message;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let available=format!("http://{address}");
        let rejected=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin=format!("http://{}",rejected.local_addr()?);
        let rejection=tokio::spawn(async move {
            let (mut socket,_)=rejected.accept().await?;let mut header=Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut bytes=[0u8;1024];let size=socket.read(&mut bytes).await?;
                anyhow::ensure!(size>0 && header.len()+size<=8192,"invalid test handshake");header.extend_from_slice(&bytes[..size]);
            }
            socket.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            Ok::<_,anyhow::Error>(())
        });
        let public: crate::profile::Profile = serde_json::from_value(serde_json::json!({
            "server":origin,"fallback_servers":[available.clone()],"machine_id":"0123456789abcdef01234567",
            "token":"public-test-secret","allow_insecure_http_for_tests":true
        }))?;
        let private = crate::private_profile::Profile {
            server: public.server.clone(),
            workspace: "abcdef0123456789abcdef01".into(),
            peer_id: format!("abcdef0123456789abcdef01:{}", public.machine_id),
            token: "private-test-secret-01234567890123456789".into(),
            account_email: None,
            fallback_servers: vec![],
            allow_insecure_http_for_tests: true,
        };
        let mut builder = tempfile::Builder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let directory = builder.tempdir()?;
        let public_path = directory.path().join("public.json");
        public.save_new(&public_path)?;
        let identity = crate::service::RegistrationProfile::Private(private.clone()).identity();
        let private_path = directory.path().join(format!("{identity}.json"));
        crate::profile::write_private(&private_path, &serde_json::to_vec(&private)?, false)?;
        crate::unified::save(
            &public_path,
            &public,
            &crate::unified::Configuration {
                format_version: 1,
                private_profile: private_path,
                enabled: false,
            },
        )?;
        let expected_peer = private.peer_id.clone();
        let expected_token = private.token.clone();
        let gateway = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            let mut socket = tokio_tungstenite::accept_hdr_async(
                socket,
                move |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                      response| {
                    assert_eq!(
                        request.headers().get("x-porthub-peer").unwrap(),
                        expected_peer.as_str()
                    );
                    assert_eq!(
                        request.headers().get("authorization").unwrap(),
                        format!("Bearer {expected_token}").as_str()
                    );
                    assert!(!request.uri().to_string().contains("secret"));
                    Ok(response)
                },
            )
            .await?;
            let mut received = 0;
            while let Some(message) = socket.next().await {
                match message? {
                    Message::Binary(bytes) => {
                        assert!(bytes.iter().all(|byte| *byte == 73));
                        received += bytes.len();
                    }
                    Message::Text(text) if text == "eof" => break,
                    _ => anyhow::bail!("unexpected proxy carrier message"),
                }
            }
            assert_eq!(received, 1024 * 1024);
            socket
                .send(Message::Binary(b"gateway-reply".to_vec().into()))
                .await?;
            socket.send(Message::Text("eof".into())).await?;
            Ok::<_, anyhow::Error>(())
        });
        let (mut local, service) = tokio::io::duplex(32768);
        let control = std::sync::Arc::new(crate::control::Control::new(public)?);
        let owner = tokio::spawn(crate::exposure_protocol::serve_connection(
            service,
            control.clone(),
            CancellationToken::new(),
            public_path,
        ));
        let request = serde_json::json!({"operation":"proxy_connect","grant":"a".repeat(24),"host":"example.test","port":443});
        let mut bytes = serde_json::to_vec(&request)?;
        bytes.push(b'\n');
        bytes.extend(vec![73; 8192]);
        local.write_all(&bytes).await?;
        let mut reader = BufReader::new(local);
        let response = crate::exposure_protocol::line(&mut reader).await?;
        assert!(!String::from_utf8_lossy(&response).contains("secret"));
        assert!(serde_json::from_slice::<Reply>(&response)?.error.is_none());
        reader
            .get_mut()
            .write_all(&vec![73; 1024 * 1024 - 8192])
            .await?;
        reader.get_mut().shutdown().await?;
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_to_end(&mut received)).await??;
        assert_eq!(received, b"gateway-reply");
        owner.await??;
        gateway.await??;rejection.await??;
        assert_eq!(control.authorities().first(),Some(&available));
        Ok(())
    }
}
