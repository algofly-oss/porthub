//! Fixed-destination SSH ingress. Authentication stays in the API role; this
//! listener cannot choose arbitrary destinations or reach a host SSH daemon.
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, UnixStream},
    sync::{watch, Semaphore},
    task::JoinSet,
};
pub async fn run(
    listener: TcpListener,
    socket: PathBuf,
    mut stop: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let capacity = Arc::new(Semaphore::new(64));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            changed=stop.changed()=>{if changed.is_err() || *stop.borrow() {break;}},
            _=tasks.join_next(),if !tasks.is_empty()=>{},
            connection=listener.accept()=>{
                let (mut stream,_)=connection?;
                let Ok(permit)=capacity.clone().try_acquire_owned() else {continue;};
                let socket=socket.clone();let mut stopping=stop.clone();
                let _=stream.set_nodelay(true);
                tasks.spawn(async move {
                    let _permit=permit;
                    let Ok(Ok(mut upstream))=tokio::time::timeout(Duration::from_secs(3),UnixStream::connect(socket)).await else {return;};
                    tokio::select! {_=stopping.changed()=>{},_=tokio::io::copy_bidirectional(&mut stream,&mut upstream)=>{}}
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// Optional protocol selection before TLS. A peek leaves all TLS bytes intact;
/// SSH identification begins with `S` and is relayed to the fixed API socket.
/// The API still performs the complete SSH handshake and capability checks.
#[derive(Clone, Default)]
pub struct TlsIngress {
    ssh: Option<Arc<TlsSsh>>,
}
struct TlsSsh {
    socket: PathBuf,
    capacity: Arc<Semaphore>,
    stop: watch::Receiver<bool>,
}
impl TlsIngress {
    pub fn with_ssh(socket: PathBuf, stop: watch::Receiver<bool>) -> Self {
        Self {
            ssh: Some(Arc::new(TlsSsh {
                socket,
                capacity: Arc::new(Semaphore::new(64)),
                stop,
            })),
        }
    }
}
impl<S: Send + 'static> axum_server::accept::Accept<tokio::net::TcpStream, S> for TlsIngress {
    type Stream = tokio::net::TcpStream;
    type Service = S;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<(Self::Stream, S)>> + Send>,
    >;

    fn accept(&self, mut stream: Self::Stream, service: S) -> Self::Future {
        porthub_tunnel::tune_ingress_socket(&stream);
        let ssh = self.ssh.clone();
        Box::pin(async move {
            stream.set_nodelay(true)?;
            if let Some(ssh) = ssh {
                if *ssh.stop.borrow() {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                let mut prefix = [0u8; 1];
                let count = tokio::time::timeout(Duration::from_secs(3), stream.peek(&mut prefix))
                    .await
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
                if count == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                if prefix[0] == b'S' {
                    let _permit = ssh
                        .capacity
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| std::io::Error::from(std::io::ErrorKind::WouldBlock))?;
                    let mut upstream = tokio::time::timeout(
                        Duration::from_secs(3),
                        UnixStream::connect(&ssh.socket),
                    )
                    .await
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
                    let mut stopping = ssh.stop.clone();
                    tokio::select! {
                        _=stopping.changed()=>{},
                        result=tokio::io::copy_bidirectional(&mut stream,&mut upstream)=>{result?;},
                    }
                    // The SSH connection has been fully served. Do not hand its
                    // stream to rustls or construct an HTTP application request.
                    return Err(std::io::ErrorKind::ConnectionAborted.into());
                }
            }
            Ok((stream, service))
        })
    }
}

#[cfg(test)]
mod multiplex_tests {
    use super::*;
    use axum_server::accept::Accept;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }
    #[tokio::test]
    async fn fragmented_tls_is_returned_without_consuming_its_first_byte() {
        let (_stop, stopping) = watch::channel(false);
        let ingress = TlsIngress::with_ssh("/unused-api-socket".into(), stopping);
        let (mut client, server) = pair().await;
        client.write_all(&[0x16]).await.unwrap();
        let (mut server, value) = ingress.accept(server, 42).await.unwrap();
        assert_eq!(value, 42);
        client.write_all(&[0x03, 0x03, 0x00, 0x01]).await.unwrap();
        let mut bytes = [0; 5];
        server.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, [0x16, 0x03, 0x03, 0x00, 0x01]);
    }
    #[tokio::test]
    async fn disabled_ingress_needs_no_identification_bytes() {
        let (_client, server) = pair().await;
        tokio::time::timeout(
            Duration::from_millis(100),
            TlsIngress::default().accept(server, ()),
        )
        .await
        .unwrap()
        .unwrap();
    }
    #[tokio::test]
    async fn ssh_bytes_are_forwarded_only_to_the_fixed_socket() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("ssh.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let (_stop, stopping) = watch::channel(false);
        let ingress = TlsIngress::with_ssh(socket, stopping);
        let (mut client, server) = pair().await;
        let task = tokio::spawn(ingress.accept(server, ()));
        client
            .write_all(b"SSH-2.0-client\r\npayload")
            .await
            .unwrap();
        let (mut upstream, _) = listener.accept().await.unwrap();
        let mut request = [0; 23];
        upstream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"SSH-2.0-client\r\npayload");
        upstream.write_all(b"SSH-2.0-api\r\n").await.unwrap();
        let mut response = [0; 13];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"SSH-2.0-api\r\n");
        client.shutdown().await.unwrap();
        upstream.shutdown().await.unwrap();
        assert_eq!(
            task.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::ConnectionAborted
        );
    }
    #[tokio::test]
    async fn full_ssh_capacity_still_allows_tls() {
        let (_stop, stopping) = watch::channel(false);
        let ingress = TlsIngress::with_ssh("/unused-api-socket".into(), stopping);
        let _occupied = ingress
            .ssh
            .as_ref()
            .unwrap()
            .capacity
            .clone()
            .acquire_many_owned(64)
            .await
            .unwrap();
        let (mut client, server) = pair().await;
        client.write_all(b"S").await.unwrap();
        assert_eq!(
            ingress.accept(server, ()).await.unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let (mut client, server) = pair().await;
        client.write_all(&[0x16]).await.unwrap();
        ingress.accept(server, ()).await.unwrap();
    }
    #[tokio::test]
    async fn shutdown_releases_an_active_ssh_forwarder() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("ssh.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let (stop, stopping) = watch::channel(false);
        let ingress = TlsIngress::with_ssh(socket, stopping);
        let (mut client, server) = pair().await;
        let task = tokio::spawn(ingress.accept(server, ()));
        client.write_all(b"SSH-2.0-client\r\n").await.unwrap();
        let (_upstream, _) = listener.accept().await.unwrap();
        stop.send(true).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::ConnectionAborted
        );
    }
    #[tokio::test]
    async fn silent_connections_have_a_bounded_identification_deadline() {
        let (_stop, stopping) = watch::channel(false);
        let ingress = TlsIngress::with_ssh("/unused-api-socket".into(), stopping);
        let (_client, server) = pair().await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(4), ingress.accept(server, ()))
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::TimedOut
        );
    }
}
