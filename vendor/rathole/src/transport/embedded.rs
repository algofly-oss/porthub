//! PortHub adapter: inject an already accepted stream without opening a listener.
use super::{AddrMaybeCached, SocketOpts, Transport};
use crate::config::TransportConfig;
use anyhow::{bail, Result};
use async_trait::async_trait;
use std::{fmt::Debug, net::SocketAddr};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::ToSocketAddrs,
};

pub trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send + Debug {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Debug> TunnelIo for T {}

#[derive(Debug)]
pub(crate) struct EmbeddedTransport;

#[async_trait]
impl Transport for EmbeddedTransport {
    type Acceptor = ();
    type RawStream = Box<dyn TunnelIo>;
    type Stream = Box<dyn TunnelIo>;

    fn new(_: &TransportConfig) -> Result<Self> {
        Ok(Self)
    }
    // Socket options belong to the HTTP/TLS listener that accepted this stream.
    fn hint(_: &Self::Stream, _: SocketOpts) {}
    async fn bind<T: ToSocketAddrs + Send + Sync>(&self, _: T) -> Result<()> {
        bail!("embedded transport does not open listeners")
    }
    async fn accept(&self, _: &()) -> Result<(Self::RawStream, SocketAddr)> {
        bail!("embedded transport accepts streams from its owner")
    }
    async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream> {
        Ok(conn)
    }
    async fn connect(&self, _: &AddrMaybeCached) -> Result<Self::Stream> {
        bail!("embedded server transport cannot initiate connections")
    }
}
