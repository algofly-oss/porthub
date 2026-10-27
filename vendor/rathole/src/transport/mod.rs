use crate::config::{ClientServiceConfig, ServerServiceConfig, TcpConfig, TransportConfig};
use crate::helper::try_set_tcp_keepalive;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::fmt::{Debug, Display};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, ToSocketAddrs};
use tracing::{error, trace};

pub const DEFAULT_NODELAY: bool = true;

pub const DEFAULT_KEEPALIVE_SECS: u64 = 20;
pub const DEFAULT_KEEPALIVE_INTERVAL: u64 = 8;

#[derive(Clone)]
pub struct AddrMaybeCached {
    pub addr: String,
    pub socket_addr: Option<SocketAddr>,
}

impl AddrMaybeCached {
    pub fn new(addr: &str) -> AddrMaybeCached {
        AddrMaybeCached {
            addr: addr.to_string(),
            socket_addr: None,
        }
    }

    pub async fn resolve(&mut self, source: Option<std::net::IpAddr>) -> Result<()> {
        self.socket_addr = select_address(tokio::net::lookup_host(&self.addr).await?, source);
        anyhow::ensure!(self.socket_addr.is_some(), "no compatible gateway address");
        Ok(())
    }
}

fn select_address(mut addresses: impl Iterator<Item = SocketAddr>, source: Option<std::net::IpAddr>) -> Option<SocketAddr> {
    addresses.find(|address| address.ip().is_loopback()
        || source.is_none_or(|source| source.is_ipv4() == address.is_ipv4()))
}

#[cfg(test)]
mod source_binding_tests {
    use super::*;
    #[test]
    fn ipv6_first_dns_results_do_not_poison_ipv4_bound_channel_cache() {
        let ipv6 = "[2001:db8::10]:443".parse().unwrap();
        let ipv4 = "192.0.2.10:443".parse().unwrap();
        let source = Some("192.0.2.20".parse().unwrap());
        assert_eq!(select_address([ipv6, ipv4].into_iter(), source), Some(ipv4));
        assert_eq!(select_address([ipv6].into_iter(), source), None);
        assert_eq!(select_address([ipv6, ipv4].into_iter(), None), Some(ipv6));
        let loopback = "[::1]:443".parse().unwrap();
        assert_eq!(select_address([loopback].into_iter(), source), Some(loopback));
    }
}

impl Display for AddrMaybeCached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.socket_addr {
            Some(s) => f.write_fmt(format_args!("{}", s)),
            None => f.write_str(&self.addr),
        }
    }
}

/// Specify a transport layer, like TCP, TLS
#[async_trait]
pub trait Transport: Debug + Send + Sync {
    type Acceptor: Send + Sync;
    type RawStream: Send;
    type Stream: 'static + AsyncRead + AsyncWrite + Unpin + Send + Debug;

    fn new(config: &TransportConfig) -> Result<Self>
    where
        Self: Sized;
    /// Provide the transport with socket options, which can be handled at the need of the transport
    fn hint(conn: &Self::Stream, opts: SocketOpts);
    async fn bind<T: ToSocketAddrs + Send + Sync>(&self, addr: T) -> Result<Self::Acceptor>;
    /// accept must be cancel safe
    async fn accept(&self, a: &Self::Acceptor) -> Result<(Self::RawStream, SocketAddr)>;
    async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream>;
    async fn connect(&self, addr: &AddrMaybeCached) -> Result<Self::Stream>;
}

#[cfg(feature = "server")]
pub(crate) mod embedded;
pub mod framed;
#[cfg(feature = "websocket")]
mod http_upgrade;
mod tcp;
pub use tcp::TcpTransport;
#[cfg(feature = "tls")]
mod tls;
#[cfg(feature = "tls")]
pub use tls::TlsTransport;

#[cfg(feature = "noise")]
mod noise;
#[cfg(feature = "noise")]
pub use noise::NoiseTransport;

#[cfg(feature = "websocket")]
mod websocket;
#[cfg(feature = "websocket")]
pub use websocket::WebsocketTransport;

#[derive(Debug, Clone, Copy)]
struct Keepalive {
    // tcp_keepalive_time if the underlying protocol is TCP
    pub keepalive_secs: u64,
    // tcp_keepalive_intvl if the underlying protocol is TCP
    pub keepalive_interval: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct SocketOpts {
    // None means do not change
    nodelay: Option<bool>,
    // keepalive must be Some or None at the same time, or the behavior will be platform-dependent
    keepalive: Option<Keepalive>,
}

impl SocketOpts {
    fn none() -> SocketOpts {
        SocketOpts {
            nodelay: None,
            keepalive: None,
        }
    }

    /// Socket options for the control channel
    pub fn for_control_channel() -> SocketOpts {
        SocketOpts {
            nodelay: Some(true),  // Always set nodelay for the control channel
            ..SocketOpts::none()  // None means do not change. Keepalive is set by TcpTransport
        }
    }
}

impl SocketOpts {
    pub fn from_cfg(cfg: &TcpConfig) -> SocketOpts {
        SocketOpts {
            nodelay: Some(cfg.nodelay),
            keepalive: Some(Keepalive {
                keepalive_secs: cfg.keepalive_secs,
                keepalive_interval: cfg.keepalive_interval,
            }),
        }
    }

    pub fn from_client_cfg(cfg: &ClientServiceConfig) -> SocketOpts {
        SocketOpts {
            nodelay: cfg.nodelay,
            ..SocketOpts::none()
        }
    }

    pub fn from_server_cfg(cfg: &ServerServiceConfig) -> SocketOpts {
        SocketOpts {
            nodelay: cfg.nodelay,
            ..SocketOpts::none()
        }
    }

    pub fn apply(&self, conn: &TcpStream) {
        // Prefer Linux BBR per socket, without changing host defaults.
        // Unsupported algorithms/kernels retain their current policy.
        #[cfg(target_os = "linux")]
        {
            let algorithm =
                std::env::var("PORTHUB_TCP_CONGESTION").unwrap_or_else(|_| "bbr".into());
            if matches!(algorithm.as_str(), "bbr" | "cubic") {
                let _ =
                    socket2_modern::SockRef::from(conn).set_tcp_congestion(algorithm.as_bytes());
            }
        }
        if let Some(v) = self.keepalive {
            let keepalive_duration = Duration::from_secs(v.keepalive_secs);
            let keepalive_interval = Duration::from_secs(v.keepalive_interval);

            if let Err(e) = try_set_tcp_keepalive(conn, keepalive_duration, keepalive_interval)
                .with_context(|| "Failed to set keepalive")
            {
                error!("{:#}", e);
            }
        }

        if let Some(nodelay) = self.nodelay {
            trace!("Set nodelay {}", nodelay);
            if let Err(e) = conn
                .set_nodelay(nodelay)
                .with_context(|| "Failed to set nodelay")
            {
                error!("{:#}", e);
            }
        }
    }
}
