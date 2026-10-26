//! Streaming HTTP/1 proxy with pooled Unix/TCP connections. Upgrade streams
//! retain bytes already read by Hyper and preserve independent half-closes.
use axum::{
    body::Body,
    http::{header, HeaderMap, Request, Response, StatusCode, Uri},
};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
};
use hyperlocal::UnixConnector;
use std::{
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

struct Upload {
    inner: Body,
    complete: Option<tokio::sync::oneshot::Sender<()>>,
}
impl hyper::body::Body for Upload {
    type Data = axum::body::Bytes;
    type Error = axum::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(result, Poll::Ready(None)) || self.inner.is_end_stream() {
            if let Some(complete) = self.complete.take() {
                let _ = complete.send(());
            }
        }
        result
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

#[derive(Clone)]
enum Target {
    Unix(PathBuf),
    Network {
        base: Uri,
        pass_host: bool,
        authorization: Option<axum::http::HeaderValue>,
    },
}
#[derive(Clone)]
pub struct HttpProxy {
    target: Target,
    clients: ProxyPool,
    access: Option<Arc<crate::public_access::Gate>>,
}
#[derive(Clone)]
pub struct ProxyPool(Arc<Clients>);
struct Clients {
    unix: Client<UnixConnector, Body>,
    network: Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>,
}
impl Default for ProxyPool {
    fn default() -> Self {
        Self::build(None)
    }
}
impl ProxyPool {
    pub fn with_tls_config(config: rustls::ClientConfig) -> Self {
        Self::build(Some(config))
    }
    fn build(config: Option<rustls::ClientConfig>) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let builder = hyper_rustls::HttpsConnectorBuilder::new();
        let tls = match config {
            Some(mut config) => {
                config.alpn_protocols.clear();
                builder.with_tls_config(config)
            }
            None => builder.with_webpki_roots(),
        };
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        connector.set_connect_timeout(Some(Duration::from_secs(3)));
        connector.set_nodelay(true);
        let https = tls.https_or_http().enable_http1().wrap_connector(connector);
        Self(Arc::new(Clients {
            unix: Client::builder(TokioExecutor::new())
                .pool_max_idle_per_host(16)
                .pool_idle_timeout(Duration::from_secs(60))
                .build(UnixConnector),
            network: Client::builder(TokioExecutor::new())
                .pool_max_idle_per_host(16)
                .pool_idle_timeout(Duration::from_secs(60))
                .build(https),
        }))
    }
}
impl HttpProxy {
    pub fn unix(path: PathBuf) -> Self {
        Self {
            target: Target::Unix(path),
            clients: ProxyPool::default(),
            access: None,
        }
    }
    pub fn tcp(base: &str) -> anyhow::Result<Self> {
        let uri: Uri = base.parse()?;
        anyhow::ensure!(
            uri.scheme_str() == Some("http")
                && uri.authority().is_some()
                && uri.path() == "/"
                && uri.query().is_none(),
            "internal TCP proxy requires an HTTP origin without a path"
        );
        Self::web(base, true, ProxyPool::default())
    }
    pub fn web(base: &str, pass_host: bool, clients: ProxyPool) -> anyhow::Result<Self> {
        use base64::Engine;
        let mut url = url::Url::parse(base)?;
        anyhow::ensure!(
            matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
            "web upstream must use HTTP or HTTPS"
        );
        url.set_fragment(None);
        let authorization = if !url.username().is_empty() || url.password().is_some() {
            let username = percent_encoding::percent_decode_str(url.username()).decode_utf8()?;
            let password =
                percent_encoding::percent_decode_str(url.password().unwrap_or("")).decode_utf8()?;
            Some(
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD
                        .encode(format!("{username}:{password}"))
                )
                .parse()?,
            )
        } else {
            None
        };
        url.set_username("")
            .map_err(|_| anyhow::anyhow!("invalid upstream credentials"))?;
        url.set_password(None)
            .map_err(|_| anyhow::anyhow!("invalid upstream credentials"))?;
        Ok(Self {
            target: Target::Network {
                base: url.as_str().parse()?,
                pass_host,
                authorization,
            },
            clients,
            access: None,
        })
    }

    pub fn with_access(mut self, id: &str, config: Option<crate::public_access::Config>) -> anyhow::Result<Self> {
        self.access = config.map(|config| crate::public_access::Gate::new(id, config).map(Arc::new)).transpose()?;
        Ok(self)
    }

    pub async fn forward(&self, request: Request<Body>) -> Response<Body> {
        self.forward_with_security(request, false).await
    }

    pub async fn forward_with_security(&self, request: Request<Body>, secure: bool) -> Response<Body> {
        let mut request = if let Some(gate) = &self.access {
            match gate.authorize(request, secure).await {
                Ok(request) => request,
                Err(response) => return response,
            }
        } else { request };
        let upgrade = is_upgrade(request.headers());
        let downstream = upgrade.then(|| hyper::upgrade::on(&mut request));
        let path = request
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let uri = match &self.target {
            Target::Unix(socket) => hyperlocal::Uri::new(socket, path).into(),
            Target::Network { base, .. } => {
                let incoming = request.uri().path();
                let root = base.path();
                let joined = match (root.ends_with('/'), incoming.starts_with('/')) {
                    (true, true) => format!("{}{}", root, &incoming[1..]),
                    (false, false) => format!("{root}/{incoming}"),
                    _ => format!("{root}{incoming}"),
                };
                let query = [base.query(), request.uri().query()]
                    .into_iter()
                    .flatten()
                    .filter(|q| !q.is_empty())
                    .collect::<Vec<_>>()
                    .join("&");
                let target = format!(
                    "{}://{}{}{}{}",
                    base.scheme_str().unwrap(),
                    base.authority().unwrap(),
                    joined,
                    if query.is_empty() { "" } else { "?" },
                    query
                );
                match target.parse() {
                    Ok(uri) => uri,
                    Err(_) => return failure(),
                }
            }
        };
        *request.uri_mut() = uri;
        // The ingress may negotiate HTTP/2 (for example with Cloudflare),
        // while both upstream pools deliberately speak HTTP/1.1.
        *request.version_mut() = axum::http::Version::HTTP_11;
        let protocol = upgrade
            .then(|| request.headers().get(header::UPGRADE).cloned())
            .flatten();
        strip_hop_headers(request.headers_mut());
        if let Some(protocol) = protocol {
            request.headers_mut().insert(
                header::CONNECTION,
                axum::http::HeaderValue::from_static("Upgrade"),
            );
            request.headers_mut().insert(header::UPGRADE, protocol);
        }
        if let Target::Network {
            base,
            pass_host,
            authorization,
        } = &self.target
        {
            if !pass_host {
                let Ok(host) = base.authority().unwrap().as_str().parse() else {
                    return failure();
                };
                request.headers_mut().insert(header::HOST, host);
            }
            if let Some(authorization) = authorization {
                request
                    .headers_mut()
                    .insert(header::AUTHORIZATION, authorization.clone());
            }
        }
        let (complete, uploaded) = tokio::sync::oneshot::channel();
        let (parts, body) = request.into_parts();
        use hyper::body::Body as _;
        let complete = if body.is_end_stream() {
            let _ = complete.send(());
            None
        } else {
            Some(complete)
        };
        let request = Request::from_parts(
            parts,
            Body::new(Upload {
                inner: body,
                complete,
            }),
        );
        let forwarding = async {
            match &self.target {
                Target::Unix(_) => self.clients.0.unix.request(request).await,
                Target::Network { .. } => self.clients.0.network.request(request).await,
            }
        };
        tokio::pin!(forwarding);
        // Start the response-header deadline after upload completion. Long
        // uploads stay streamed and configured five-minute API waits still fit.
        let result = tokio::select! {
            result=&mut forwarding=>Ok(result),
            _=uploaded=>tokio::time::timeout(Duration::from_secs(310),&mut forwarding).await,
        };
        let mut response = match result {
            Ok(Ok(response)) => response,
            _ => return failure(),
        };
        if response.status() == StatusCode::SWITCHING_PROTOCOLS {
            let Some(downstream) = downstream else {
                return failure();
            };
            let upstream = hyper::upgrade::on(&mut response);
            tokio::spawn(async move {
                let upgraded = tokio::time::timeout(Duration::from_secs(10), async {
                    tokio::try_join!(downstream, upstream)
                })
                .await;
                if let Ok(Ok((a, b))) = upgraded {
                    let _ =
                        tokio::io::copy_bidirectional(&mut TokioIo::new(a), &mut TokioIo::new(b))
                            .await;
                }
            });
        } else {
            strip_hop_headers(response.headers_mut());
        }
        let (parts, body) = response.into_parts();
        Response::from_parts(parts, Body::new(body))
    }
}
fn is_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE)
        && headers
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| {
                v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
            })
}
fn strip_hop_headers(headers: &mut HeaderMap) {
    let named: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|t| t.trim().to_owned()))
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}
fn failure() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Body::from("Upstream unavailable"))
        .unwrap()
}
