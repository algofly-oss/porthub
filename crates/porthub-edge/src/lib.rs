//! Shared HTTP ingress for the embedded Rathole server.
pub mod apply;
mod health;

use axum::{
    extract::{ws::WebSocketUpgrade, FromRequestParts, Request, State},
    http::{header, StatusCode, Version},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use hyper_util::rt::TokioIo;
use porthub_tunnel::{
    websocket::WebSocketIo, EmbeddedServer, FramedIo, TunnelIo, DIRECT_FRAME_SIZE, SUBPROTOCOL,
    WEBSOCKET_FRAME_SIZE,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::{RwLock, Semaphore};

#[derive(Clone)]
struct Edge {
    server: Arc<RwLock<EmbeddedServer>>,
    handshakes: Arc<Semaphore>,
    api: Option<porthub_runtime::proxy::HttpProxy>,
}

async fn accept(edge: Edge, io: Box<dyn TunnelIo>) {
    let accepted = edge.server.read().await.accept(io);
    match tokio::time::timeout(Duration::from_secs(10), accepted).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(%error, "tunnel disconnected"),
        Err(_) => tracing::warn!("tunnel authentication timed out"),
    }
}

async fn tunnel(State(edge): State<Edge>, mut request: Request) -> Response {
    let permit = match edge.handshakes.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if request
        .headers()
        .get(header::UPGRADE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| h.eq_ignore_ascii_case(SUBPROTOCOL))
    {
        let connection = request
            .headers()
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|h| h.to_str().ok())
            .any(|h| {
                h.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
            });
        if request.version() != Version::HTTP_11 || !connection {
            return (
                StatusCode::BAD_REQUEST,
                "HTTP/1.1 Upgrade connection required",
            )
                .into_response();
        }
        let upgrading = hyper::upgrade::on(&mut request);
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(Duration::from_secs(10), upgrading).await {
                Ok(Ok(stream)) => {
                    accept(
                        edge,
                        Box::new(FramedIo::with_read_timeout(TokioIo::new(stream), DIRECT_FRAME_SIZE, Duration::from_secs(60))),
                    )
                    .await
                }
                Ok(Err(error)) => tracing::warn!(%error, "tunnel HTTP upgrade failed"),
                Err(_) => tracing::warn!("tunnel HTTP upgrade timed out"),
            }
        });
        return (
            StatusCode::SWITCHING_PROTOCOLS,
            [
                (header::CONNECTION, "Upgrade"),
                (header::UPGRADE, SUBPROTOCOL),
            ],
        )
            .into_response();
    }
    let (mut parts, _) = request.into_parts();
    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };
    ws.protocols([SUBPROTOCOL])
        .max_message_size(1024 * 1024)
        .write_buffer_size(0)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            let framed = socket.protocol().is_some_and(|p| p == SUBPROTOCOL);
            let io: Box<dyn TunnelIo> = if framed {
                Box::new(FramedIo::with_read_timeout(
                    WebSocketIo::new(socket),
                    WEBSOCKET_FRAME_SIZE,
                    Duration::from_secs(60),
                ))
            } else {
                Box::new(WebSocketIo::new(socket))
            };
            accept(edge, io).await;
        })
}

async fn upstream(State(edge): State<Edge>, request: Request) -> Response {
    match &edge.api {
        Some(api) => api.forward(request).await,
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Clone, Copy)]
struct Ingress {
    secure: bool,
}

pub fn router(server: Arc<RwLock<EmbeddedServer>>) -> Router {
    router_with_api(server, None)
}

pub fn router_with_api(
    server: Arc<RwLock<EmbeddedServer>>,
    socket: Option<std::path::PathBuf>,
) -> Router {
    router_with_web(
        server,
        socket,
        Arc::new(porthub_runtime::web_routes::WebRoutes::new(None)),
    )
}

pub fn router_with_web(
    server: Arc<RwLock<EmbeddedServer>>,
    socket: Option<std::path::PathBuf>,
    web: Arc<porthub_runtime::web_routes::WebRoutes>,
) -> Router {
    let edge = Edge {
        server,
        handshakes: Arc::new(Semaphore::new(1024)),
        api: socket.map(porthub_runtime::proxy::HttpProxy::unix),
    };
    Router::new()
        .route("/api/tunnel", get(tunnel))
        .route("/healthz", get(health::check))
        .fallback(upstream)
        .with_state(edge)
        .layer(axum::middleware::from_fn(
            move |request: Request, next: axum::middleware::Next| {
                let web = web.clone();
                async move {
                    let secure = request
                        .extensions()
                        .get::<Ingress>()
                        .is_some_and(|ingress| ingress.secure);
                    match web.select(&request, secure) {
                        porthub_runtime::web_routes::Selection::Proxy(proxy) => {
                            proxy.forward_with_security(request, secure).await
                        }
                        porthub_runtime::web_routes::Selection::Disabled => {
                            StatusCode::NOT_FOUND.into_response()
                        }
                        porthub_runtime::web_routes::Selection::Unmatched => {
                            next.run(request).await
                        }
                    }
                }
            },
        ))
}

/// Forwarding headers are untrusted. An operator-configured public HTTPS
/// authority can establish the external scheme for an HTTP origin listener.
pub fn listener_router(router: Router, secure: bool) -> Router {
    listener_router_with_public_origin(router, secure, None)
}
pub fn listener_router_with_public_origin(
    router: Router,
    secure: bool,
    public_origin: Option<&str>,
) -> Router {
    let authority = public_origin
        .and_then(|value| url::Url::parse(value).ok())
        .filter(|url| url.scheme() == "https")
        .and_then(|url| {
            let host = url.host_str()?.to_ascii_lowercase();
            Some(if url.port_or_known_default() == Some(443) {
                host
            } else {
                format!("{host}:{}", url.port()?)
            })
        });
    router.layer(axum::middleware::from_fn(
        move |mut request: Request, next: axum::middleware::Next| {
            // HTTP/2 carries the host in :authority, not necessarily Host.
            // Preserve it before the internal HTTP/1 proxy replaces the URI.
            if request.version() == Version::HTTP_2 {
                if let Some(host) = request.uri().authority()
                    .and_then(|authority| authority.as_str().parse::<axum::http::HeaderValue>().ok())
                {
                    request.headers_mut().insert(header::HOST, host);
                }
            }
            let external_secure = secure
                || authority.as_ref().is_some_and(|authority| {
                    request
                        .headers()
                        .get(header::HOST)
                        .and_then(|host| host.to_str().ok())
                        .is_some_and(|host| {
                            host.eq_ignore_ascii_case(authority)
                                || (authority.find(':').is_none()
                                    && host.eq_ignore_ascii_case(&format!("{authority}:443")))
                        })
                });
            async move {
                let secure = external_secure;
                request.extensions_mut().insert(Ingress { secure });
                let host = request.headers().get(header::HOST).cloned();
                request.headers_mut().remove("forwarded");
                request.headers_mut().insert(
                    "x-forwarded-proto",
                    axum::http::HeaderValue::from_static(if secure { "https" } else { "http" }),
                );
                request.headers_mut().remove("x-forwarded-host");
                if let Some(host) = host {
                    request.headers_mut().insert("x-forwarded-host", host);
                }
                next.run(request).await
            }
        },
    ))
}
