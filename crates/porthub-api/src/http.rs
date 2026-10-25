use axum::{
    extract::Request,
    http::{header, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub async fn private_api_cache(request: Request, next: Next) -> Response {
    let api = request.uri().path() == "/api" || request.uri().path().starts_with("/api/");
    let mut response = next.run(request).await;
    if api {
        response
            .headers_mut()
            .entry(header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("private, no-store"));
    }
    response
}

pub async fn cors(request: Request, next: Next) -> Response {
    let Some(origin) = request
        .headers()
        .get(header::ORIGIN)
        .cloned()
        .filter(|_| !request.uri().path().starts_with("/socket.io/"))
    else {
        return next.run(request).await;
    };
    let preflight = request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);
    let requested_headers = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .cloned();
    let mut response = if preflight {
        StatusCode::OK.into_response()
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    headers.append(header::VARY, HeaderValue::from_static("Origin"));
    if preflight {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("600"),
        );
        if let Some(value) = requested_headers {
            headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, value);
        }
    }
    response
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use axum::{body::Body, routing::get, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn api_responses_are_not_cached_and_explicit_stream_policies_are_preserved() {
        let app = Router::new()
            .route("/api/inventory", get(|| async { "live inventory" }))
            .route(
                "/api/stream",
                get(|| async {
                    (
                        [(header::CACHE_CONTROL, "private, no-store, no-transform")],
                        "stream",
                    )
                }),
            )
            .route("/asset.js", get(|| async { "asset" }))
            .layer(axum::middleware::from_fn(private_api_cache));
        for (path, expected) in [
            ("/api/inventory", Some("private, no-store")),
            ("/api/stream", Some("private, no-store, no-transform")),
            ("/asset.js", None),
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .map(|value| value.to_str().unwrap()),
                expected
            );
        }
    }
}
