//! Loopback-only, credential-protected HTTP CONNECT/forward and SOCKS5 ingress.
//! Authorization to use a remote peer belongs to the serving connector.
use crate::{Connector, Destination};
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEADER: usize = 16 * 1024;

pub struct Credentials {
    username: String,
    password: String,
}
impl Credentials {
    pub fn new(username: String, password: String) -> Result<Self> {
        ensure!(
            !username.is_empty()
                && username.len() <= 255
                && password.len() >= 24
                && password.len() <= 255,
            "proxy credentials require a username and a 24–255 byte password"
        );
        ensure!(
            !username.contains(':')
                && !username.chars().any(char::is_control)
                && !password.chars().any(char::is_control),
            "invalid proxy credentials"
        );
        Ok(Self { username, password })
    }
    fn verify(&self, username: &[u8], password: &[u8]) -> bool {
        bool::from(
            self.username.as_bytes().ct_eq(username) & self.password.as_bytes().ct_eq(password),
        )
    }
}

pub struct Proxy {
    listener: TcpListener,
    credentials: Arc<Credentials>,
    connector: Arc<dyn Connector>,
    limit: Arc<Semaphore>,
}
impl Proxy {
    pub async fn bind(
        address: SocketAddr,
        credentials: Credentials,
        connector: Arc<dyn Connector>,
        max_connections: usize,
    ) -> Result<Self> {
        ensure!(
            address.ip().is_loopback(),
            "application proxy must bind to localhost"
        );
        ensure!(
            (1..=512).contains(&max_connections),
            "proxy connection limit must be between 1 and 512"
        );
        Ok(Self {
            listener: TcpListener::bind(address).await?,
            credentials: Arc::new(credentials),
            connector,
            limit: Arc::new(Semaphore::new(max_connections)),
        })
    }
    pub fn address(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
    pub async fn run(self, stop: CancellationToken) -> Result<()> {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _ = stop.cancelled() => break,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = self.listener.accept() => {
                    let (socket, _) = accepted?;
                    let Ok(permit) = self.limit.clone().try_acquire_owned() else { continue; };
                    let credentials = self.credentials.clone();
                    let connector = self.connector.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        // Credentials, destination names and upstream errors must
                        // never be copied into agent or gateway logs.
                        let _ = session(socket, &credentials, connector.as_ref()).await;
                    });
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}

enum Protocol {
    Socks,
    Connect,
    Http(Vec<u8>),
}
async fn session(
    mut socket: TcpStream,
    credentials: &Credentials,
    connector: &dyn Connector,
) -> Result<()> {
    let (destination, protocol) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut socket, credentials)).await??;
    let connected =
        tokio::time::timeout(Duration::from_secs(180), connector.connect(destination)).await;
    let mut upstream = match connected {
        Ok(Ok(stream)) => stream,
        _ => {
            match protocol {
                Protocol::Socks => socket.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await?,
                _ => socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await?,
            }
            bail!("proxy upstream unavailable");
        }
    };
    match protocol {
        Protocol::Socks => socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?,
        Protocol::Connect => {
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?
        }
        Protocol::Http(request) => {
            upstream.write_all(&request).await?;
            upstream.flush().await?;
        }
    }
    tokio::io::copy_bidirectional(&mut socket, &mut upstream).await?;
    Ok(())
}

async fn handshake(
    socket: &mut TcpStream,
    credentials: &Credentials,
) -> Result<(Destination, Protocol)> {
    let first = socket.read_u8().await?;
    if first == 5 {
        return socks(socket, credentials).await;
    }
    ensure!(first.is_ascii_uppercase(), "unsupported proxy protocol");
    let mut header = vec![first];
    while !header.ends_with(b"\r\n\r\n") {
        ensure!(header.len() < MAX_HEADER, "proxy header too large");
        header.push(socket.read_u8().await?);
    }
    let text = std::str::from_utf8(&header)?;
    let mut lines = text.split("\r\n");
    let request = lines.next().context("missing proxy request")?;
    let fields = request.split_whitespace().collect::<Vec<_>>();
    ensure!(
        fields.len() == 3 && matches!(fields[2], "HTTP/1.1" | "HTTP/1.0"),
        "invalid proxy request"
    );
    let mut authorization = None;
    let mut headers = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').context("invalid proxy header")?;
        if name.eq_ignore_ascii_case("proxy-authorization") {
            ensure!(authorization.is_none(), "duplicate proxy authentication");
            authorization = Some(value.trim());
        } else if !name.eq_ignore_ascii_case("proxy-connection")
            && !name.eq_ignore_ascii_case("connection")
        {
            headers.push(line);
        }
    }
    let authorized = authorization
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
        .and_then(|(_, value)| STANDARD.decode(value).ok())
        .is_some_and(|decoded| {
            decoded
                .iter()
                .position(|b| *b == b':')
                .is_some_and(|i| credentials.verify(&decoded[..i], &decoded[i + 1..]))
        });
    if !authorized {
        socket.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"PortHub\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await?;
        bail!("proxy authentication required");
    }
    if fields[0] == "CONNECT" {
        let (host, port) = authority(fields[1])?;
        return Ok((Destination::new(host, port)?, Protocol::Connect));
    }
    // HTTP forward requests use absolute-form. Destination resolution is
    // delegated to the authorized connector, never performed by this parser.
    let url = fields[1]
        .strip_prefix("http://")
        .context("use CONNECT for HTTPS")?;
    let end = url.find(['/', '?']).unwrap_or(url.len());
    let host = &url[..end];
    let (hostname, port) = if host.starts_with('[') || host.contains(':') {
        authority(host)?
    } else {
        (host.to_owned(), 80)
    };
    let path = match &url[end..] {
        "" => "/".to_owned(),
        value if value.starts_with('?') => format!("/{value}"),
        value => value.to_owned(),
    };
    let mut forwarded = format!("{} {} {}\r\n", fields[0], path, fields[2]);
    for header in headers {
        forwarded.push_str(header);
        forwarded.push_str("\r\n");
    }
    forwarded.push_str("Connection: close\r\n\r\n");
    Ok((
        Destination::new(hostname, port)?,
        Protocol::Http(forwarded.into_bytes()),
    ))
}

fn authority(value: &str) -> Result<(String, u16)> {
    let (host, port) = value
        .rsplit_once(':')
        .context("proxy destination requires a port")?;
    let host = host
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(host);
    let port = port.parse::<u16>()?;
    let destination = Destination::new(host.to_owned(), port)?;
    Ok((destination.host, destination.port))
}

async fn socks(
    socket: &mut TcpStream,
    credentials: &Credentials,
) -> Result<(Destination, Protocol)> {
    let count = socket.read_u8().await?;
    ensure!(count > 0, "missing SOCKS authentication methods");
    let mut methods = vec![0; usize::from(count)];
    socket.read_exact(&mut methods).await?;
    if !methods.contains(&2) {
        socket.write_all(&[5, 255]).await?;
        bail!("SOCKS authentication required");
    }
    socket.write_all(&[5, 2]).await?;
    ensure!(socket.read_u8().await? == 1, "invalid SOCKS authentication");
    let length = socket.read_u8().await? as usize;
    let mut username = vec![0; length];
    socket.read_exact(&mut username).await?;
    let length = socket.read_u8().await? as usize;
    let mut password = vec![0; length];
    socket.read_exact(&mut password).await?;
    if !credentials.verify(&username, &password) {
        socket.write_all(&[1, 1]).await?;
        bail!("SOCKS authentication failed");
    }
    socket.write_all(&[1, 0]).await?;
    let mut request = [0; 4];
    socket.read_exact(&mut request).await?;
    if request[..3] != [5, 1, 0] {
        socket.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        bail!("only SOCKS CONNECT is supported");
    }
    let host = match request[3] {
        1 => {
            let mut address = [0; 4];
            socket.read_exact(&mut address).await?;
            std::net::Ipv4Addr::from(address).to_string()
        }
        4 => {
            let mut address = [0; 16];
            socket.read_exact(&mut address).await?;
            std::net::Ipv6Addr::from(address).to_string()
        }
        3 => {
            let length = socket.read_u8().await? as usize;
            let mut host = vec![0; length];
            socket.read_exact(&mut host).await?;
            String::from_utf8(host)?
        }
        _ => bail!("unsupported SOCKS destination"),
    };
    Ok((
        Destination::new(host, socket.read_u16().await?)?,
        Protocol::Socks,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BoxStream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    const PASSWORD: &str = "a-long-random-session-secret";

    #[derive(Default)]
    struct Echo {
        calls: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl Connector for Echo {
        async fn connect(&self, destination: Destination) -> Result<BoxStream> {
            ensure!(
                destination == Destination::new("example.com".into(), 443)?,
                "unapproved destination"
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (local, mut remote) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let (mut reader, mut writer) = tokio::io::split(&mut remote);
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
            Ok(Box::new(local))
        }
    }
    async fn fixture() -> (
        TcpStream,
        Arc<Echo>,
        CancellationToken,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let connector = Arc::new(Echo::default());
        let proxy = Proxy::bind(
            "127.0.0.1:0".parse().unwrap(),
            Credentials::new("user".into(), PASSWORD.into()).unwrap(),
            connector.clone(),
            4,
        )
        .await
        .unwrap();
        let address = proxy.address().unwrap();
        let stop = CancellationToken::new();
        let task = tokio::spawn(proxy.run(stop.clone()));
        (
            TcpStream::connect(address).await.unwrap(),
            connector,
            stop,
            task,
        )
    }
    async fn header(socket: &mut TcpStream) -> Vec<u8> {
        let mut result = Vec::new();
        while !result.ends_with(b"\r\n\r\n") {
            result.push(socket.read_u8().await.unwrap());
        }
        result
    }
    #[tokio::test]
    async fn unauthenticated_http_cannot_open_an_upstream() {
        let (mut socket, connector, stop, task) = fixture().await;
        socket
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(header(&mut socket).await.starts_with(b"HTTP/1.1 407"));
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
        stop.cancel();
        task.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn connect_is_authenticated_and_shutdown_closes_existing_streams() {
        let (mut socket, connector, stop, task) = fixture().await;
        let auth = STANDARD.encode(format!("user:{PASSWORD}"));
        socket
            .write_all(
                format!(
                    "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(header(&mut socket).await.starts_with(b"HTTP/1.1 200"));
        socket.write_all(b"opaque TLS bytes").await.unwrap();
        let mut bytes = [0; 16];
        socket.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"opaque TLS bytes");
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        stop.cancel();
        task.await.unwrap().unwrap();
        assert_eq!(socket.read(&mut bytes).await.unwrap(), 0);
    }
    #[tokio::test]
    async fn socks_no_authentication_and_wrong_password_are_rejected() {
        let (mut socket, connector, stop, task) = fixture().await;
        socket.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        socket.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 255]);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
        stop.cancel();
        task.await.unwrap().unwrap();
        let (mut socket, connector, stop, task) = fixture().await;
        socket.write_all(&[5, 1, 2]).await.unwrap();
        socket.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 2]);
        socket
            .write_all(&[1, 4, b'u', b's', b'e', b'r', 1, b'x'])
            .await
            .unwrap();
        socket.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [1, 1]);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
        stop.cancel();
        task.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn socks_domain_is_resolved_only_by_the_authorized_connector() {
        let (mut socket, connector, stop, task) = fixture().await;
        socket.write_all(&[5, 1, 2]).await.unwrap();
        let mut reply = [0; 2];
        socket.read_exact(&mut reply).await.unwrap();
        let mut auth = vec![1, 4];
        auth.extend_from_slice(b"user");
        auth.push(PASSWORD.len() as u8);
        auth.extend_from_slice(PASSWORD.as_bytes());
        socket.write_all(&auth).await.unwrap();
        socket.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [1, 0]);
        let mut request = vec![5, 1, 0, 3, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443u16.to_be_bytes());
        socket.write_all(&request).await.unwrap();
        let mut connected = [0; 10];
        socket.read_exact(&mut connected).await.unwrap();
        assert_eq!(connected[1], 0);
        socket.write_all(b"ping").await.unwrap();
        let mut ping = [0; 4];
        socket.read_exact(&mut ping).await.unwrap();
        assert_eq!(&ping, b"ping");
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        stop.cancel();
        task.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn forward_http_strips_proxy_credentials_but_preserves_application_auth() {
        let (mut socket, connector, stop, task) = fixture().await;
        let auth = STANDARD.encode(format!("user:{PASSWORD}"));
        socket.write_all(format!("GET http://example.com:443/path?q=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {auth}\r\nAuthorization: Bearer application-key\r\nProxy-Connection: keep-alive\r\n\r\n").as_bytes()).await.unwrap();
        let forwarded = String::from_utf8(header(&mut socket).await).unwrap();
        assert!(forwarded.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(forwarded.contains("Authorization: Bearer application-key\r\n"));
        assert!(forwarded.contains("Connection: close\r\n"));
        assert!(!forwarded
            .to_ascii_lowercase()
            .contains("proxy-authorization"));
        assert!(!forwarded.contains(&auth));
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        stop.cancel();
        task.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn non_loopback_and_weak_credentials_are_rejected() {
        assert!(Credentials::new("user".into(), "short".into()).is_err());
        assert!(Proxy::bind(
            "0.0.0.0:0".parse().unwrap(),
            Credentials::new("user".into(), PASSWORD.into()).unwrap(),
            Arc::new(Echo::default()),
            4
        )
        .await
        .is_err());
    }
}
