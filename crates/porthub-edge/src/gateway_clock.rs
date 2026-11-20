//! Clock bootstrap on the direct gateway TLS listener. Clients authenticate
//! that listener with the key supplied during trusted enrollment.
use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use std::time::{SystemTime, UNIX_EPOCH};

const NONCE: &str = "porthub-clock-nonce";
const SECONDS: &str = "porthub-clock-unix-seconds";

pub(crate) async fn sample(headers: HeaderMap) -> Response {
    let mut values = headers.get_all(NONCE).iter();
    let Some(nonce) = values.next() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if values.next().is_some()
        || nonce.as_bytes().len() != 32
        || !nonce.as_bytes().iter().all(u8::is_ascii_hexdigit)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let mut reply = StatusCode::NO_CONTENT.into_response();
    let headers = reply.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(NONCE, nonce.clone());
    headers.insert(SECONDS, now.as_secs().into());
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn clock_sample_is_fresh_and_rejects_ambiguous_challenges() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            sample(headers.clone()).await.status(),
            StatusCode::BAD_REQUEST
        );
        let nonce = HeaderValue::from_static("0123456789abcdef0123456789abcdef");
        headers.insert(NONCE, nonce.clone());
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let response = sample(headers.clone()).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()[NONCE], nonce);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let seconds: u64 = response.headers()[SECONDS]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let end = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!((start..=end).contains(&seconds));
        headers.append(NONCE, nonce);
        assert_eq!(sample(headers).await.status(), StatusCode::BAD_REQUEST);
    }
}
