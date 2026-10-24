use core::result::Result;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use super::framed::{FramedIo, SUBPROTOCOL, WEBSOCKET_FRAME_SIZE};
use super::{AddrMaybeCached, SocketOpts, TcpTransport, TlsTransport, Transport};
use crate::config::TransportConfig;
use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;
use futures_core::stream::Stream;
use futures_sink::Sink;
use tokio::io::{AsyncRead, AsyncWrite, BufReader, ReadBuf};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_rustls::TlsStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue};
use tokio_tungstenite::{accept_hdr_async_with_config, client_async_with_config};
use tokio_tungstenite::{tungstenite::protocol::Message, WebSocketStream};
use tokio_util::io::StreamReader;
use url::Url;

#[derive(Debug)]
pub enum TransportStream {
    Insecure(TcpStream),
    Secure(TlsStream<TcpStream>),
}

impl TransportStream {
    fn get_tcpstream(&self) -> &TcpStream {
        match self {
            TransportStream::Insecure(s) => s,
            TransportStream::Secure(s) => s.get_ref().0,
        }
    }
}

impl AsyncRead for TransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TransportStream::Insecure(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::Secure(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            TransportStream::Insecure(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::Secure(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            TransportStream::Insecure(s) => Pin::new(s).poll_flush(cx),
            TransportStream::Secure(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            TransportStream::Insecure(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::Secure(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[derive(Debug)]
struct StreamWrapper {
    inner: WebSocketStream<TransportStream>,
}

impl Stream for StreamWrapper {
    type Item = Result<Bytes, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.get_mut().inner).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(err))) => {
                Poll::Ready(Some(Err(Error::new(ErrorKind::Other, err))))
            }
            Poll::Ready(Some(Ok(res))) => {
                if let Message::Binary(b) = res {
                    Poll::Ready(Some(Ok(Bytes::from(b))))
                } else {
                    Poll::Ready(Some(Err(Error::new(
                        ErrorKind::InvalidData,
                        "unexpected frame",
                    ))))
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

#[derive(Debug)]
pub struct RawWebsocketTunnel {
    inner: StreamReader<StreamWrapper, Bytes>,
}

impl AsyncRead for RawWebsocketTunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RawWebsocketTunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let sw = self.get_mut().inner.get_mut();
        ready!(Pin::new(&mut sw.inner)
            .poll_ready(cx)
            .map_err(|err| Error::new(ErrorKind::Other, err)))?;

        match Pin::new(&mut sw.inner).start_send(Message::Binary(buf.to_vec())) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(Error::new(ErrorKind::Other, e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.get_mut().inner.get_mut().inner)
            .poll_flush(cx)
            .map_err(|err| Error::new(ErrorKind::Other, err))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.get_mut().inner.get_mut().inner)
            .poll_close(cx)
            .map_err(|err| Error::new(ErrorKind::Other, err))
    }
}

#[derive(Debug)]
enum SubTransport {
    Secure(TlsTransport),
    Insecure(TcpTransport),
}

#[derive(Debug)]
pub struct WebsocketTransport {
    sub: SubTransport,
    conf: WebSocketConfig,
    path: String,
    host: Option<String>,
    framing: bool,
    http_upgrade: bool,
}

#[async_trait]
impl Transport for WebsocketTransport {
    type Acceptor = TcpListener;
    type RawStream = TcpStream;
    type Stream = WebsocketTunnel;

    fn new(config: &TransportConfig) -> anyhow::Result<Self> {
        let wsconfig = config
            .websocket
            .as_ref()
            .ok_or_else(|| anyhow!("Missing websocket config"))?;

        if wsconfig.http_upgrade && !wsconfig.porthub_framing {
            return Err(anyhow!("HTTP Upgrade requires PortHub framing"));
        }
        let conf = WebSocketConfig {
            write_buffer_size: 0,
            ..WebSocketConfig::default()
        };
        let sub = match wsconfig.tls {
            true => SubTransport::Secure(TlsTransport::new(config)?),
            false => SubTransport::Insecure(TcpTransport::new(config)?),
        };
        if !wsconfig.path.starts_with('/')
            || wsconfig.path.starts_with("//")
            || wsconfig.path.contains('#')
        {
            return Err(anyhow!("websocket path must be an absolute HTTP path"));
        }
        if let Some(host) = &wsconfig.host {
            HeaderValue::from_str(host)?;
            let url = Url::parse(&format!("http://{host}"))?;
            if url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(anyhow!("invalid websocket Host override"));
            }
        }
        Ok(WebsocketTransport {
            sub,
            conf,
            path: wsconfig.path.clone(),
            host: wsconfig.host.clone(),
            framing: wsconfig.porthub_framing,
            http_upgrade: wsconfig.http_upgrade,
        })
    }

    fn hint(conn: &Self::Stream, opt: SocketOpts) {
        let raw = match conn {
            WebsocketTunnel::Raw(raw) => raw,
            WebsocketTunnel::Framed(stream) => stream.get_ref(),
            WebsocketTunnel::Direct(stream) => {
                opt.apply(stream.get_ref().get_ref().get_tcpstream());
                return;
            }
        };
        opt.apply(raw.inner.get_ref().inner.get_ref().get_tcpstream())
    }

    async fn bind<A: ToSocketAddrs + Send + Sync>(
        &self,
        addr: A,
    ) -> anyhow::Result<Self::Acceptor> {
        TcpListener::bind(addr).await.map_err(Into::into)
    }

    async fn accept(&self, a: &Self::Acceptor) -> anyhow::Result<(Self::RawStream, SocketAddr)> {
        let (s, addr) = match &self.sub {
            SubTransport::Insecure(t) => t.accept(a).await?,
            SubTransport::Secure(t) => t.accept(a).await?,
        };
        Ok((s, addr))
    }

    async fn handshake(&self, conn: Self::RawStream) -> anyhow::Result<Self::Stream> {
        let tsream = match &self.sub {
            SubTransport::Insecure(t) => TransportStream::Insecure(t.handshake(conn).await?),
            SubTransport::Secure(t) => TransportStream::Secure(t.handshake(conn).await?),
        };
        if self.http_upgrade {
            let stream = super::http_upgrade::server(tsream, &self.path).await?;
            return Ok(WebsocketTunnel::Direct(FramedIo::new(
                stream,
                super::framed::DIRECT_FRAME_SIZE,
            )));
        }
        let framing = self.framing;
        let wsstream = accept_hdr_async_with_config(tsream, move |request: &tokio_tungstenite::tungstenite::handshake::server::Request, mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
            if framing {
                let offered = request.headers().get("Sec-WebSocket-Protocol").and_then(|h| h.to_str().ok()).is_some_and(|h| h.split(',').any(|p| p.trim() == SUBPROTOCOL));
                if !offered {
                    return Err(tokio_tungstenite::tungstenite::http::Response::builder().status(400).body(Some("PortHub framing required".into())).unwrap());
                }
                response.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static(SUBPROTOCOL));
            }
            Ok(response)
        }, Some(self.conf)).await?;
        let tun = RawWebsocketTunnel {
            inner: StreamReader::new(StreamWrapper { inner: wsstream }),
        };
        Ok(if self.framing {
            WebsocketTunnel::Framed(FramedIo::new(tun, WEBSOCKET_FRAME_SIZE))
        } else {
            WebsocketTunnel::Raw(tun)
        })
    }

    async fn connect(&self, addr: &AddrMaybeCached) -> anyhow::Result<Self::Stream> {
        let u = format!("ws://{}{}", &addr.addr.as_str(), self.path);
        let url = Url::parse(&u)?;
        let tstream = match &self.sub {
            SubTransport::Insecure(t) => TransportStream::Insecure(t.connect(addr).await?),
            SubTransport::Secure(t) => TransportStream::Secure(t.connect(addr).await?),
        };
        if self.http_upgrade {
            let stream = super::http_upgrade::client(
                tstream,
                self.host.as_deref().unwrap_or(&addr.addr),
                &self.path,
            )
            .await?;
            return Ok(WebsocketTunnel::Direct(FramedIo::with_keepalive(
                stream,
                super::framed::DIRECT_FRAME_SIZE,
                std::time::Duration::from_secs(15),
            )));
        }
        let mut request = url.into_client_request()?;
        if let Some(host) = &self.host {
            request
                .headers_mut()
                .insert("Host", HeaderValue::from_str(host)?);
        }
        if self.framing {
            request.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                HeaderValue::from_static(SUBPROTOCOL),
            );
        }
        let (wsstream, response) =
            client_async_with_config(request, tstream, Some(self.conf)).await?;
        if self.framing
            && response
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|h| h.to_str().ok())
                != Some(SUBPROTOCOL)
        {
            return Err(anyhow!("server did not negotiate PortHub framing"));
        }
        let tun = RawWebsocketTunnel {
            inner: StreamReader::new(StreamWrapper { inner: wsstream }),
        };
        Ok(if self.framing {
            WebsocketTunnel::Framed(FramedIo::with_keepalive(
                tun,
                WEBSOCKET_FRAME_SIZE,
                std::time::Duration::from_secs(15),
            ))
        } else {
            WebsocketTunnel::Raw(tun)
        })
    }
}

#[derive(Debug)]
pub enum WebsocketTunnel {
    Raw(RawWebsocketTunnel),
    Framed(FramedIo<RawWebsocketTunnel>),
    Direct(FramedIo<BufReader<TransportStream>>),
}
impl AsyncRead for WebsocketTunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Raw(s) => Pin::new(s).poll_read(cx, buf),
            Self::Framed(s) => Pin::new(s).poll_read(cx, buf),
            Self::Direct(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}
impl AsyncWrite for WebsocketTunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Raw(s) => Pin::new(s).poll_write(cx, buf),
            Self::Framed(s) => Pin::new(s).poll_write(cx, buf),
            Self::Direct(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Raw(s) => Pin::new(s).poll_flush(cx),
            Self::Framed(s) => Pin::new(s).poll_flush(cx),
            Self::Direct(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Raw(s) => Pin::new(s).poll_shutdown(cx),
            Self::Framed(s) => Pin::new(s).poll_shutdown(cx),
            Self::Direct(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
