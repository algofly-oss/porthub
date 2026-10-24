//! PortHub uses rustls so agent builds do not depend on a system TLS library.
use super::{AddrMaybeCached, SocketOpts, TcpTransport, Transport};
use crate::config::{TlsConfig, TransportConfig};
use crate::helper::host_port_pair;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use std::{io::BufReader, net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_rustls::{
    rustls::{self, pki_types::ServerName},
    TlsAcceptor, TlsConnector, TlsStream,
};

pub struct TlsTransport {
    tcp: TcpTransport,
    config: TlsConfig,
    connector: TlsConnector,
    acceptor: Option<TlsAcceptor>,
}

impl std::fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTransport").finish_non_exhaustive()
    }
}

#[async_trait]
impl Transport for TlsTransport {
    type Acceptor = TcpListener;
    type RawStream = TcpStream;
    type Stream = TlsStream<TcpStream>;

    fn new(config: &TransportConfig) -> Result<Self> {
        let tcp = TcpTransport::new(config)?;
        let config = config.tls.as_ref().context("missing TLS config")?;
        if config.pkcs12.is_some() {
            bail!("convert PKCS12 identity to PEM certificate/private_key for PortHub rustls");
        }
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = &config.trusted_root {
            let certs = std::fs::read(path).context("read tls.trusted_root")?;
            for cert in rustls_pemfile::certs(&mut BufReader::new(certs.as_slice())) {
                roots.add(cert?)?;
            }
        }
        let tls = if let Some(pin) = &config.spki_sha256 {
            porthub_identity::pinned_client_config(pin)?
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        };
        let connector = TlsConnector::from(Arc::new(tls));
        let acceptor = match (&config.certificate, &config.private_key) {
            (Some(cert), Some(key)) => {
                let cert = std::fs::read(cert).context("read TLS certificate")?;
                let key = std::fs::read(key).context("read TLS private key")?;
                let certs = rustls_pemfile::certs(&mut BufReader::new(cert.as_slice()))
                    .collect::<std::io::Result<Vec<_>>>()?;
                let key = rustls_pemfile::private_key(&mut BufReader::new(key.as_slice()))?
                    .context("PEM private key missing")?;
                Some(TlsAcceptor::from(Arc::new(
                    rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(certs, key)?,
                )))
            }
            (None, None) => None,
            _ => bail!("both TLS certificate and private_key are required"),
        };
        Ok(Self {
            tcp,
            config: config.clone(),
            connector,
            acceptor,
        })
    }
    fn hint(conn: &Self::Stream, opt: SocketOpts) {
        opt.apply(conn.get_ref().0);
    }
    async fn bind<A: ToSocketAddrs + Send + Sync>(&self, addr: A) -> Result<Self::Acceptor> {
        Ok(TcpListener::bind(addr).await?)
    }
    async fn accept(&self, a: &Self::Acceptor) -> Result<(Self::RawStream, SocketAddr)> {
        self.tcp.accept(a).await
    }
    async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream> {
        Ok(self
            .acceptor
            .as_ref()
            .ok_or_else(|| anyhow!("TLS server identity missing"))?
            .accept(conn)
            .await?
            .into())
    }
    async fn connect(&self, addr: &AddrMaybeCached) -> Result<Self::Stream> {
        let name = self
            .config
            .hostname
            .as_deref()
            .unwrap_or(host_port_pair(&addr.addr)?.0);
        let name = ServerName::try_from(name.to_owned()).context("invalid TLS server name")?;
        Ok(self
            .connector
            .connect(name, self.tcp.connect(addr).await?)
            .await?
            .into())
    }
}
