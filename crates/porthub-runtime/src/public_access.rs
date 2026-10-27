//! HTTP access gate shared by direct public listeners and hostname proxies.
//! Credentials never reach the upstream application. Sessions are bounded and
//! scoped to one gate; replacing the configured verifier revokes its sessions.
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, Response, StatusCode},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub verifier: String,
    #[serde(default)]
    pub pin: bool,
}

pub struct Gate {
    config: Config,
    cookie: String,
    sessions: Mutex<HashMap<String, Instant>>,
    verifying: Arc<Semaphore>,
    waiting: Semaphore,
    credential_salt: [u8; 16],
    verified: Mutex<Option<[u8; 32]>>,
}

impl Gate {
    pub fn new(id: &str, config: Config) -> anyhow::Result<Self> {
        let parts = bcrypt::HashParts::from_str(&config.verifier)?;
        anyhow::ensure!(
            (10..=14).contains(&parts.get_cost()),
            "invalid access verifier cost"
        );
        let digest = Sha256::digest(id.as_bytes());
        let cookie = format!(
            "porthub_access_{}",
            digest[..8]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        Ok(Self {
            config,
            cookie,
            sessions: Mutex::new(HashMap::new()),
            verifying: Arc::new(Semaphore::new(1)),
            waiting: Semaphore::new(64),
            credential_salt: *uuid::Uuid::new_v4().as_bytes(),
            verified: Mutex::new(None),
        })
    }

    /// On success returns the original streaming request, with gate credentials
    /// removed. On failure returns a local response without contacting upstream.
    pub async fn authorize(
        &self,
        mut request: Request<Body>,
        secure: bool,
    ) -> Result<Request<Body>, Response<Body>> {
        let now = Instant::now();
        let mut session_ok = false;
        let mut remaining = Vec::new();
        {
            let mut sessions = self
                .sessions
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            sessions.retain(|_, expiry| *expiry > now);
            for header in request.headers().get_all(header::COOKIE) {
                if let Ok(value) = header.to_str() {
                    for part in value.split(';').map(str::trim) {
                        if let Some((name, value)) = part.split_once('=') {
                            if name == self.cookie {
                                session_ok |= sessions.contains_key(value);
                            } else {
                                remaining.push(part.to_owned());
                            }
                        }
                    }
                }
            }
        }
        request.headers_mut().remove(header::COOKIE);
        if !remaining.is_empty() {
            if let Ok(value) = remaining.join("; ").parse() {
                request.headers_mut().insert(header::COOKIE, value);
            }
        }
        let supplied = request
            .headers_mut()
            .remove("x-porthub-key")
            .and_then(|value| value.to_str().ok().map(str::to_owned));
        let login = request.uri().path() == "/_porthub/access"
            && request.method() == axum::http::Method::POST;
        if session_ok && !login {
            return Ok(request);
        }
        // A dedicated gate header takes precedence, leaving application
        // Authorization untouched. A valid gate session likewise returned above.
        let bearer = if supplied.is_none() && !login {
            request.headers().get(header::AUTHORIZATION).and_then(|value| value.to_str().ok())
                .and_then(|value| value.split_once(' '))
                .filter(|(scheme, value)| scheme.eq_ignore_ascii_case("bearer") && !value.is_empty())
                .map(|(_, value)| value.to_owned())
        } else { None };
        let consumes_authorization = bearer.is_some();
        let credential = if login {
            let bytes = tokio::time::timeout(
                Duration::from_secs(10),
                to_bytes(std::mem::replace(request.body_mut(), Body::empty()), 2048),
            )
            .await
            .map_err(|_| response(StatusCode::REQUEST_TIMEOUT, "Access request timed out"))?
            .map_err(|_| response(StatusCode::BAD_REQUEST, "Invalid access request"))?;
            url::form_urlencoded::parse(&bytes)
                .find(|(name, _)| name == "key")
                .map(|(_, value)| value.into_owned())
        } else {
            supplied.or(bearer)
        };
        let Some(credential) = credential else {
            return Err(prompt(self.config.pin));
        };
        if credential.is_empty()
            || credential.len() > 72
            || (self.config.pin
                && (credential.len() != 6 || !credential.bytes().all(|b| b.is_ascii_digit())))
        {
            return Err(if login { access_page(self.config.pin, "That credential was not accepted. Please try again.") } else { response(StatusCode::UNAUTHORIZED, "Access denied") });
        }
        let mut digest = Sha256::new();
        digest.update(self.credential_salt);
        digest.update(credential.as_bytes());
        let digest: [u8; 32] = digest.finalize().into();
        let cached = || {
            use subtle::ConstantTimeEq;
            self.verified
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_ref()
                .is_some_and(|known| bool::from(known.ct_eq(&digest)))
        };
        if !cached() {
            // Bound both work and waiters. Concurrent requests for the same
            // correct key share the first verification instead of failing.
            let _waiting = self
                .waiting
                .try_acquire()
                .map_err(|_| response(StatusCode::TOO_MANY_REQUESTS, "Try again shortly"))?;
            let permit = tokio::time::timeout(
                Duration::from_secs(3),
                self.verifying.clone().acquire_owned(),
            )
            .await
            .map_err(|_| response(StatusCode::TOO_MANY_REQUESTS, "Try again shortly"))?
            .map_err(|_| {
                response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Access verification unavailable",
                )
            })?;
            if !cached() {
                let verifier = self.config.verifier.clone();
                let (valid, _permit) = tokio::task::spawn_blocking(move || {
                    (
                        bcrypt::verify(credential, &verifier).unwrap_or(false),
                        permit,
                    )
                })
                .await
                .map_err(|_| {
                    response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Access verification unavailable",
                    )
                })?;
                if !valid {
                    return Err(if login { access_page(self.config.pin, "That credential was not accepted. Please try again.") } else { response(StatusCode::UNAUTHORIZED, "Access denied") });
                }
                *self
                    .verified
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Some(digest);
            }
        }
        if login {
            let token = format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            );
            let mut sessions = self
                .sessions
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if sessions.len() >= 4096 {
                return Err(response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Session limit reached",
                ));
            }
            sessions.insert(token.clone(), now + Duration::from_secs(8 * 3600));
            let mut result = response(StatusCode::SEE_OTHER, "Access granted");
            result
                .headers_mut()
                .insert(header::LOCATION, "/".parse().unwrap());
            result.headers_mut().insert(
                header::SET_COOKIE,
                format!(
                    "{}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800{}",
                    self.cookie,
                    if secure { "; Secure" } else { "" }
                )
                .parse()
                .unwrap(),
            );
            return Err(result);
        }
        if consumes_authorization { request.headers_mut().remove(header::AUTHORIZATION); }
        // The body is consumed only by the reserved login endpoint.
        Ok(request)
    }
}

use std::str::FromStr;
fn response(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(message.to_owned()))
        .unwrap()
}
fn prompt(pin: bool) -> Response<Body> { access_page(pin, "") }
fn access_page(pin: bool, error: &str) -> Response<Body> {
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let html = include_str!("../assets/access.html")
        .replace("{{nonce}}", &nonce)
        .replace("{{label}}", if pin { "Six-digit PIN" } else { "API key" })
        .replace("{{description}}", if pin { "six-digit PIN" } else { "API key" })
        .replace("{{input}}", if pin { "inputmode=\"numeric\" pattern=\"[0-9]{6}\" minlength=\"6\" maxlength=\"6\"" } else { "maxlength=\"72\"" })
        .replace("{{error}}", error);
    Response::builder().status(StatusCode::UNAUTHORIZED)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .header("content-security-policy", format!("default-src 'none'; style-src 'nonce-{nonce}'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"))
        .body(Body::from(html)).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn gate(id: &str) -> Gate {
        Gate::new(
            id,
            Config {
                verifier: bcrypt::hash("123456", 10).unwrap(),
                pin: true,
            },
        )
        .unwrap()
    }
    #[tokio::test]
    async fn gate_denies_missing_invalid_keys_and_preserves_authenticated_streaming_body() {
        let gate = gate("mapping-a");
        let denied = gate
            .authorize(Request::new(Body::empty()), false)
            .await
            .unwrap_err();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let denied = gate
            .authorize(
                Request::builder()
                    .header("x-porthub-key", "654321")
                    .body(Body::empty())
                    .unwrap(),
                false,
            )
            .await
            .unwrap_err();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let accepted = gate
            .authorize(
                Request::builder()
                    .header("x-porthub-key", "123456")
                    .body(Body::from("upload content"))
                    .unwrap(),
                false,
            )
            .await
            .unwrap();
        assert!(!accepted.headers().contains_key("x-porthub-key"));
        assert_eq!(
            to_bytes(accepted.into_body(), 100).await.unwrap(),
            "upload content"
        );
    }
    #[tokio::test]
    async fn bearer_gate_credentials_never_replace_application_authorization() {
        let gate = gate("headers");
        let request = Request::builder().header(header::AUTHORIZATION, "Bearer 123456")
            .body(Body::from("streaming body")).unwrap();
        let accepted = gate.authorize(request, false).await.unwrap();
        assert!(!accepted.headers().contains_key(header::AUTHORIZATION));
        assert_eq!(to_bytes(accepted.into_body(), 100).await.unwrap(), "streaming body");
        for app in ["Bearer application-token", "Basic application-credentials"] {
            let request = Request::builder().header("x-porthub-key", "123456")
                .header(header::AUTHORIZATION, app).body(Body::empty()).unwrap();
            let accepted = gate.authorize(request, false).await.unwrap();
            assert_eq!(accepted.headers()[header::AUTHORIZATION], app);
            assert!(!accepted.headers().contains_key("x-porthub-key"));
        }
        let invalid = Request::builder().header("x-porthub-key", "654321")
            .header(header::AUTHORIZATION, "Bearer 123456").body(Body::empty()).unwrap();
        assert_eq!(gate.authorize(invalid, false).await.unwrap_err().status(), StatusCode::UNAUTHORIZED);
        let prompt = prompt(true);
        assert!(prompt.headers()["content-security-policy"].to_str().unwrap().contains("style-src 'nonce-"));
        let html = String::from_utf8(to_bytes(prompt.into_body(), 16384).await.unwrap().to_vec()).unwrap();
        assert!(html.contains("pattern=\"[0-9]{6}\""));
        assert!(!html.contains("{{"));
        let invalid_login = Request::builder().method("POST").uri("/_porthub/access")
            .body(Body::from("key=wrong")).unwrap();
        let denied = gate.authorize(invalid_login, false).await.unwrap_err();
        assert_eq!(denied.headers()[header::CONTENT_TYPE], "text/html; charset=utf-8");
    }

    #[tokio::test]
    async fn browser_cookie_is_scoped_revocable_and_removed_from_upstream() {
        let gate = gate("mapping-a");
        let login = Request::builder()
            .method("POST")
            .uri("/_porthub/access")
            .body(Body::from("key=123456"))
            .unwrap();
        let result = gate.authorize(login, true).await.unwrap_err();
        assert_eq!(result.status(), StatusCode::SEE_OTHER);
        let cookie = result.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(
            cookie.contains("HttpOnly")
                && cookie.contains("Secure")
                && cookie.contains("SameSite=Strict")
        );
        let token = cookie.split(';').next().unwrap();
        let request = || {
            Request::builder()
                .header(header::COOKIE, format!("{token}; app=value"))
                .header(header::AUTHORIZATION, "Bearer app-session-token")
                .body(Body::empty())
                .unwrap()
        };
        let accepted = gate.authorize(request(), true).await.unwrap();
        assert_eq!(accepted.headers()[header::COOKIE], "app=value");
        assert_eq!(accepted.headers()[header::AUTHORIZATION], "Bearer app-session-token");
        let other = super::tests::gate("mapping-b");
        assert_eq!(
            other.authorize(request(), true).await.unwrap_err().status(),
            StatusCode::UNAUTHORIZED
        );
        let replaced = super::tests::gate("mapping-a");
        assert_eq!(
            replaced
                .authorize(request(), true)
                .await
                .unwrap_err()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        gate.sessions.lock().unwrap().clear();
        assert_eq!(
            gate.authorize(request(), true).await.unwrap_err().status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

/// HTTP/1 forwarding over an already-authenticated Rathole data channel.
/// Keep-alive requests are each checked; upgraded streams keep both half-closes.
pub async fn forward_io<V, U>(visitor: V, upstream: U, gate: Arc<Gate>) -> anyhow::Result<()>
where
    V: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use hyper_util::rt::TokioIo;
    let (sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(upstream)).await?;
    let connection = tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    // Dropping this owner on cancellation must also close the data channel.
    struct Stop(tokio::task::JoinHandle<()>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _owner = Stop(connection);
    let sender = Arc::new(tokio::sync::Mutex::new(sender));
    let service = hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
        let gate = gate.clone();
        let sender = sender.clone();
        async move {
            let result = match gate.authorize(request.map(Body::new), false).await {
                Err(response) => response,
                Ok(mut request) => {
                    let upgrade = request.headers().contains_key(header::UPGRADE);
                    let downstream = upgrade.then(|| hyper::upgrade::on(&mut request));
                    match sender.lock().await.send_request(request).await {
                        Ok(mut response) => {
                            if response.status() == StatusCode::SWITCHING_PROTOCOLS {
                                if let Some(downstream) = downstream {
                                    let upstream = hyper::upgrade::on(&mut response);
                                    tokio::spawn(async move {
                                        if let Ok((downstream, upstream)) =
                                            tokio::try_join!(downstream, upstream)
                                        {
                                            let _ = tokio::io::copy_bidirectional(
                                                &mut TokioIo::new(downstream),
                                                &mut TokioIo::new(upstream),
                                            )
                                            .await;
                                        }
                                    });
                                }
                            }
                            response.map(Body::new)
                        }
                        Err(_) => response(StatusCode::BAD_GATEWAY, "Service unavailable"),
                    }
                }
            };
            Ok::<_, std::convert::Infallible>(result)
        }
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(visitor), service)
        .with_upgrades()
        .await?;
    Ok(())
}
