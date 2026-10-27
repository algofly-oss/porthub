//! Explicitly authorized stream egress. No listener or network activity is
//! created merely by constructing a connector.
pub mod proxy;
pub mod destination;
#[cfg(feature="websocket")]
pub mod websocket;
#[cfg(feature = "tor")]
pub mod tor;
#[cfg(feature = "tor")]
mod underlay;

use anyhow::{ensure, Result};
use async_trait::async_trait;
#[cfg(feature="tor")]
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type BoxStream = Box<dyn Stream>;

/// Keep capacity reserved for exactly the lifetime of the returned stream.
/// Dropping a proxy session drops its Tor stream immediately, without leaving
/// an unowned copy task waiting for the remote half of a connection to close.
#[cfg(feature="tor")]
struct LimitedStream<S> {
    stream: S,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
#[cfg(feature="tor")]
impl<S: AsyncRead + Unpin> AsyncRead for LimitedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
#[cfg(feature="tor")]
impl<S: AsyncWrite + Unpin> AsyncWrite for LimitedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}
impl Destination {
    pub fn new(host: String, port: u16) -> Result<Self> {
        ensure!(
            port != 0 && !host.is_empty() && host.len() <= 253,
            "invalid proxy destination"
        );
        ensure!(
            !host
                .bytes()
                .any(|c| c <= 32 || c == 127 || matches!(c, b'/' | b'\\' | b'@' | b'#' | b'?')),
            "invalid proxy destination"
        );
        Ok(Self { host, port })
    }
}

/// Serving implementations must enforce the caller's current policy, not
/// trust a local proxy listener to have performed authorization earlier.
#[async_trait]
pub trait Connector: Send + Sync {
    async fn connect(&self, destination: Destination) -> Result<BoxStream>;
}

#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, hostname: &str) -> Result<Vec<std::net::IpAddr>>;
}
