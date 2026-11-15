//! Bulk USB streams use authenticated TLS on the selected local interface.
//! The certificate and one-time capability travel only in the owner-authorized
//! gateway session. ICE/DTLS and the gateway remain available as fallbacks.
use anyhow::{ensure, Context, Result};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub(super) type Stream = tokio_rustls::TlsStream<TcpStream>;
const NAME: &str = "porthub-usb.local";
const ALPN: &[u8] = b"porthub-usb-bulk/1";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Offer {
    addresses: Vec<SocketAddr>,
    certificate: Vec<u8>,
    capability: String,
}
pub(super) struct Listener {
    listeners: Vec<TcpListener>,
    acceptor: TlsAcceptor,
    pub offer: Offer,
}
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}
fn tune(stream: &TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    porthub_mesh::configure_tcp(stream);
    Ok(())
}
impl Listener {
    pub async fn bind(control: Option<&crate::control::Control>) -> Result<Self> {
        let mut listeners = Vec::new();
        let mut addresses = Vec::new();
        let mut ips = Vec::new();
        for interface in getifaddrs::getifaddrs()? {
            if !interface.flags.contains(getifaddrs::InterfaceFlags::UP)
                || ["docker", "br-", "veth", "virbr", "cni", "flannel"]
                    .iter()
                    .any(|p| interface.name.starts_with(p))
            {
                continue;
            }
            let Some(IpAddr::V4(ip)) = interface.address.ip_addr() else {
                continue;
            };
            if !(ip.is_private()
                || ip.is_loopback()
                || ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
                || control
                    .is_some_and(|c| !c.direct_interface_allowed(&interface.name, IpAddr::V4(ip)))
                || ips.contains(&ip)
            {
                continue;
            }
            ips.push(ip);
            if ips.len() == 16 {
                break;
            }
        }
        for ip in ips {
            if let Ok(listener) = TcpListener::bind((ip, 0)).await {
                addresses.push(listener.local_addr()?);
                listeners.push(listener);
            }
        }
        ensure!(!listeners.is_empty(), "No approved bulk USB listener");
        let identity = rcgen::generate_simple_self_signed(vec![NAME.into()])?;
        let certificate = identity.cert.der().to_vec();
        let mut config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate.clone())],
                PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()).into(),
            )?;
        config.alpn_protocols = vec![ALPN.into()];
        let capability = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        Ok(Self {
            listeners,
            acceptor: TlsAcceptor::from(Arc::new(config)),
            offer: Offer {
                addresses,
                certificate,
                capability,
            },
        })
    }
    pub async fn accept(self) -> Result<Stream> {
        let mut attempts = JoinSet::new();
        let chosen = Arc::new(AtomicBool::new(false));
        for listener in self.listeners {
            let acceptor = self.acceptor.clone();
            let capability = self.offer.capability.clone();
            let chosen = chosen.clone();
            attempts.spawn(async move {
                // Bound both handshake work and attempts per interface. Unknown
                // clients never receive USB bytes or block the legitimate peer.
                for _ in 0..8 {
                    let (stream, _) = listener.accept().await?;
                    tune(&stream)?;
                    let authenticated = tokio::time::timeout(Duration::from_millis(800), async {
                        let mut stream = acceptor.accept(stream).await?;
                        ensure!(
                            stream.get_ref().1.alpn_protocol() == Some(ALPN),
                            "Wrong bulk USB protocol"
                        );
                        let mut token = [0; 64];
                        stream.read_exact(&mut token).await?;
                        ensure!(
                            bool::from(subtle::ConstantTimeEq::ct_eq(
                                token.as_slice(),
                                capability.as_bytes()
                            )),
                            "Bulk USB capability rejected"
                        );
                        ensure!(
                            chosen
                                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                                .is_ok(),
                            "Bulk USB path already selected"
                        );
                        stream.write_all(&[0xa5]).await?;
                        stream.flush().await?;
                        Ok::<_, anyhow::Error>(Stream::from(stream))
                    })
                    .await;
                    if let Ok(Ok(stream)) = authenticated {
                        return Ok::<_, anyhow::Error>(stream);
                    }
                }
                anyhow::bail!("Bulk USB connection limit reached")
            });
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(attempt) = attempts.join_next().await {
                if let Ok(Ok(stream)) = attempt {
                    return Ok(stream);
                }
            }
            anyhow::bail!("Bulk USB listener unavailable")
        })
        .await?
    }
}
pub(super) async fn connect(
    offer: Offer,
    control: Option<&crate::control::Control>,
) -> Result<Stream> {
    ensure!(
        !offer.addresses.is_empty()
            && offer.addresses.len() <= 16
            && offer.certificate.len() <= 4096
            && offer.capability.len() == 64
            && offer.capability.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid bulk USB offer"
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(offer.certificate))?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.into()];
    let connector = TlsConnector::from(Arc::new(config));
    let mut attempts = JoinSet::new();
    let destinations = offer
        .addresses
        .into_iter()
        .filter(|address| {
            let IpAddr::V4(ip) = address.ip() else {
                return false;
            };
            address.port() != 0
                && (ip.is_private()
                    || ip.is_loopback()
                    || ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
        })
        .collect::<Vec<_>>();
    let paths = if let Some(control) = control {
        control
            .direct_paths(&destinations)
            .await?
            .into_iter()
            .map(|p| (p.source, p.destination))
            .collect::<Vec<_>>()
    } else {
        // Only the isolated tests have no enrolled interface policy.
        destinations
            .into_iter()
            .map(|address| (IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), address))
            .collect()
    };
    for (source, address) in paths {
        let connector = connector.clone();
        let capability = offer.capability.clone();
        attempts.spawn(async move {
            let socket = tokio::net::TcpSocket::new_v4()?;
            socket.bind(SocketAddr::new(source, 0))?;
            let stream = socket.connect(address).await?;
            tune(&stream)?;
            let mut stream = connector
                .connect(ServerName::try_from(NAME)?, stream)
                .await?;
            ensure!(
                stream.get_ref().1.alpn_protocol() == Some(ALPN),
                "Wrong bulk USB protocol"
            );
            stream.write_all(capability.as_bytes()).await?;
            stream.flush().await?;
            ensure!(
                stream.read_u8().await? == 0xa5,
                "Bulk USB peer did not authenticate the connection"
            );
            Ok::<_, anyhow::Error>(Stream::from(stream))
        });
    }
    tokio::time::timeout(Duration::from_secs(4), async {
        while let Some(attempt) = attempts.join_next().await {
            if let Ok(Ok(stream)) = attempt {
                return Ok(stream);
            }
        }
        anyhow::bail!("No authenticated bulk USB path")
    })
    .await
    .context("Bulk USB connection timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn bulk_tcp_authenticates_and_preserves_full_duplex_bytes() -> Result<()> {
        let listener = Listener::bind(None).await?;
        let offer = listener.offer.clone();
        let (source, destination) = tokio::join!(listener.accept(), connect(offer, None));
        let mut source = source?;
        let mut destination = destination?;
        let payload = vec![0x6d; 8 * 1024 * 1024];
        let expected = payload.clone();
        let started = std::time::Instant::now();
        let sender = tokio::spawn(async move {
            source.write_all(&payload).await?;
            source.flush().await?;
            let mut reverse = [0; 7];
            source.read_exact(&mut reverse).await?;
            ensure!(&reverse == b"reverse");
            Ok::<_, anyhow::Error>(())
        });
        let mut received = vec![0; expected.len()];
        tokio::time::timeout(
            Duration::from_secs(10),
            destination.read_exact(&mut received),
        )
        .await??;
        ensure!(received == expected, "USB stream bytes changed");
        destination.write_all(b"reverse").await?;
        destination.flush().await?;
        sender.await??;
        eprintln!(
            "Authenticated bulk TCP USB: 8 MiB in {:.3}s",
            started.elapsed().as_secs_f64()
        );
        Ok(())
    }
    #[tokio::test]
    async fn bulk_bridge_keeps_payload_off_gateway_and_honors_revocation() -> Result<()> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let control_listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = control_listener.local_addr()?;
        let binary = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = binary.clone();
        let relay = tokio::spawn(async move {
            let (a, _) = control_listener.accept().await?;
            let mut a = tokio_tungstenite::accept_async(a).await?;
            let (b, _) = control_listener.accept().await?;
            let mut b = tokio_tungstenite::accept_async(b).await?;
            loop {
                tokio::select! {
                    frame=a.next()=>match frame {Some(Ok(Message::Ping(v)))=>a.send(Message::Pong(v)).await?,Some(Ok(Message::Binary(v)))=>{observed.fetch_add(v.len(),Ordering::Relaxed);},Some(Ok(Message::Pong(_)))=>{},_=>break},
                    frame=b.next()=>match frame {Some(Ok(Message::Ping(v)))=>b.send(Message::Pong(v)).await?,Some(Ok(Message::Binary(v)))=>{observed.fetch_add(v.len(),Ordering::Relaxed);},Some(Ok(Message::Pong(_)))=>{},_=>break},
                }
            }
            Ok::<_, anyhow::Error>(())
        });
        let (ws_a, _) = tokio_tungstenite::connect_async(format!("ws://{address}")).await?;
        let (ws_b, _) = tokio_tungstenite::connect_async(format!("ws://{address}")).await?;
        let listener = Listener::bind(None).await?;
        let offer = listener.offer.clone();
        let (tls_a, tls_b) = tokio::join!(listener.accept(), connect(offer, None));
        let (kernel_a, app_a) = tokio::io::duplex(512);
        let (kernel_b, app_b) = tokio::io::duplex(512);
        let (policy, rx) = tokio::sync::watch::channel(crate::features::Policy::default());
        let a = tokio::spawn(super::super::bridge_bulk(
            kernel_a,
            ws_a,
            tls_a?,
            rx.clone(),
        ));
        let b = tokio::spawn(super::super::bridge_bulk(kernel_b, ws_b, tls_b?, rx));
        let (mut ar, mut aw) = tokio::io::split(app_a);
        let (mut br, mut bw) = tokio::io::split(app_b);
        let bytes_a = vec![13; 2 * 1024 * 1024];
        let bytes_b = vec![57; 2 * 1024 * 1024];
        tokio::time::timeout(Duration::from_secs(10), async {
            let read_a = async {
                let mut bytes = vec![0; bytes_b.len()];
                ar.read_exact(&mut bytes).await?;
                ensure!(bytes == bytes_b);
                Ok::<_, anyhow::Error>(())
            };
            let read_b = async {
                let mut bytes = vec![0; bytes_a.len()];
                br.read_exact(&mut bytes).await?;
                ensure!(bytes == bytes_a);
                Ok::<_, anyhow::Error>(())
            };
            let (sa, sb, ra, rb) = tokio::join!(
                aw.write_all(&bytes_a),
                bw.write_all(&bytes_b),
                read_a,
                read_b
            );
            sa?;
            sb?;
            ra?;
            rb?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        ensure!(
            binary.load(Ordering::Relaxed) == 0,
            "Bulk bytes must not be relayed by the control gateway"
        );
        let mut disabled = crate::features::Policy::default();
        disabled
            .disabled
            .insert(crate::features::Feature::DirectConnections, true);
        policy.send_replace(disabled);
        tokio::time::timeout(Duration::from_secs(2), async {
            a.await??;
            b.await??;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        relay.abort();
        Ok(())
    }
    #[tokio::test]
    async fn wrong_capability_cannot_claim_the_bulk_listener() -> Result<()> {
        let listener = Listener::bind(None).await?;
        let offer = listener.offer.clone();
        let mut forged = offer.clone();
        forged.capability = "0".repeat(64);
        let serving = tokio::spawn(listener.accept());
        ensure!(connect(forged, None).await.is_err());
        let mut peer = connect(offer, None).await?;
        let mut accepted = serving.await??;
        peer.write_all(b"verified").await?;
        peer.flush().await?;
        let mut bytes = [0; 8];
        accepted.read_exact(&mut bytes).await?;
        ensure!(&bytes == b"verified");
        Ok(())
    }
    #[tokio::test]
    async fn a_different_certificate_cannot_authenticate_the_source() -> Result<()> {
        let listener = Listener::bind(None).await?;
        let mut offer = listener.offer.clone();
        offer.certificate = rcgen::generate_simple_self_signed(vec![NAME.into()])?
            .cert
            .der()
            .to_vec();
        let serving = tokio::spawn(listener.accept());
        ensure!(connect(offer, None).await.is_err());
        serving.abort();
        Ok(())
    }
    #[tokio::test]
    async fn bulk_offer_bounds_prevent_public_destination_scanning() -> Result<()> {
        let listener = Listener::bind(None).await?;
        let mut offer = listener.offer.clone();
        offer.addresses = vec!["8.8.8.8:443".parse()?];
        ensure!(connect(offer, None).await.is_err());
        let mut offer = listener.offer.clone();
        offer.addresses.resize(17, "127.0.0.1:1".parse()?);
        ensure!(connect(offer, None).await.is_err());
        Ok(())
    }
}
