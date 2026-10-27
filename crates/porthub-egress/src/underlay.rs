//! Tor's own connections must never enter the exit tunnel they supply.
//! Bind to the agent's discovered physical sources; an unavailable underlay
//! fails closed rather than recursively dialing through the overlay.
use async_trait::async_trait;
use futures_util::{
    io::{AsyncRead, AsyncWrite},
    stream,
};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    net::{TcpSocket, TcpStream},
    sync::watch,
};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use tor_rtcompat::{
    NetStreamListener, NetStreamProvider, StreamOps, TcpConnectOptions, TcpListenOptions,
};

#[derive(Clone)]
pub(crate) struct UnderlayTcp {
    pub sources: Option<watch::Receiver<Vec<IpAddr>>>,
}
pub(crate) struct UnderlayStream(Compat<TcpStream>);
impl AsyncRead for UnderlayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl AsyncWrite for UnderlayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}
impl StreamOps for UnderlayStream {}

pub(crate) struct NoListener;
impl NetStreamListener for NoListener {
    type Stream = UnderlayStream;
    type Incoming = stream::Empty<io::Result<(UnderlayStream, SocketAddr)>>;
    fn incoming(self) -> Self::Incoming {
        stream::empty()
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[async_trait]
impl NetStreamProvider for UnderlayTcp {
    type Stream = UnderlayStream;
    type Listener = NoListener;
    type ConnectOptions = TcpConnectOptions;
    type ListenOptions = TcpListenOptions;
    async fn connect(
        &self,
        address: &SocketAddr,
        _: &TcpConnectOptions,
    ) -> io::Result<UnderlayStream> {
        let Some(sources) = &self.sources else {
            return Ok(UnderlayStream(TcpStream::connect(address).await?.compat()));
        };
        let sources = sources.borrow().clone();
        let mut error = io::Error::new(
            io::ErrorKind::NetworkUnreachable,
            "Tor physical underlay unavailable",
        );
        for source in sources
            .into_iter()
            .filter(|source| source.is_ipv4() == address.is_ipv4() && !source.is_unspecified())
        {
            let socket = if address.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            if let Err(cause) = socket.bind(SocketAddr::new(source, 0)) {
                error = cause;
                continue;
            }
            match tokio::time::timeout(std::time::Duration::from_secs(10), socket.connect(*address))
                .await
            {
                Ok(Ok(stream)) => return Ok(UnderlayStream(stream.compat())),
                Ok(Err(cause)) => error = cause,
                Err(_) => error = io::ErrorKind::TimedOut.into(),
            }
        }
        Err(error)
    }
    async fn listen(&self, _: &SocketAddr, _: &TcpListenOptions) -> io::Result<NoListener> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "embedded Tor never opens an inbound listener",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn missing_underlay_does_not_fall_back_to_unbound_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (_, sources) = watch::channel(Vec::new());
        let provider = UnderlayTcp {
            sources: Some(sources),
        };
        assert!(provider
            .connect(&listener.local_addr().unwrap(), &Default::default())
            .await
            .is_err());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn source_binding_and_updates_apply_to_new_connections() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (sender, sources) = watch::channel(vec!["127.0.0.1".parse().unwrap()]);
        let provider = UnderlayTcp {
            sources: Some(sources),
        };
        let _stream = provider
            .connect(&listener.local_addr().unwrap(), &Default::default())
            .await
            .unwrap();
        assert_eq!(
            listener.accept().await.unwrap().1.ip(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        sender.send_replace(Vec::new());
        assert!(provider
            .connect(&listener.local_addr().unwrap(), &Default::default())
            .await
            .is_err());
        assert!(provider
            .listen(&listener.local_addr().unwrap(), &Default::default())
            .await
            .is_err());
    }
}
