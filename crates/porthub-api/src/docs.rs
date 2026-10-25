use axum::{
    response::{Html, Redirect},
    routing::get,
    Json, Router,
};
use serde_json::Value;
use std::sync::LazyLock;

static OPENAPI: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("openapi.json")).expect("bundled OpenAPI document is valid")
});

const SWAGGER: &str = r##"<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PortHub API - Swagger UI</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui.css"></head>
<body><div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({url:"/api/openapi.json",dom_id:"#swagger-ui",defaultModelsExpandDepth:-1,persistAuthorization:true});</script>
</body></html>"##;

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/api", get(|| async { Redirect::temporary("/api/docs") }))
        .route("/api/docs", get(|| async { Html(SWAGGER) }))
        .route("/api/openapi.json", get(openapi))
        .route(
            "/api/openapi-go.json",
            get(|| async { Redirect::permanent("/api/openapi.json") }),
        )
}

async fn openapi() -> Json<Value> {
    Json(OPENAPI.clone())
}

#[cfg(test)]
mod tests {
    use super::router;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        Router,
    };
    use serde_json::Value;
    use tower::ServiceExt;

    #[tokio::test]
    async fn api_root_redirects_to_swagger_ui() {
        let app: Router<()> = router();
        let response = app
            .oneshot(Request::get("/api").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(response.headers()["location"], "/api/docs");
    }

    #[tokio::test]
    async fn docs_load_bundled_openapi_document() {
        let app: Router<()> = router();
        let response = app
            .oneshot(Request::get("/api/docs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("SwaggerUIBundle"));
        assert!(body.contains("/api/openapi.json"));
    }

    #[tokio::test]
    async fn openapi_document_describes_registered_api_routes() {
        let app: Router<()> = router();
        let response = app
            .oneshot(
                Request::get("/api/openapi.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(value["openapi"], "3.0.3");
        assert!(value["paths"]["/api/machines/client/auth"]["post"].is_object());
        assert!(value["paths"]["/api/connections/list"]["get"].is_object());
        assert!(value["paths"]["/api/downloads/porthub"]["get"].is_object());
        assert!(value["paths"]["/api/downloads/porthub/{target}"]["get"].is_object());
        assert!(value["paths"]["/api/machines/command/{machine_id}"]["get"].is_object());
        assert!(value["paths"]["/api/machines/{machine_id}/status-history"]["get"].is_object());
        let private_install = &value["paths"]["/api/machines/client/private-install"]["post"];
        assert!(private_install.is_object());
        assert_eq!(
            private_install["responses"]["200"]["content"]["application/json"]["schema"]
                ["properties"]["data"]["properties"]["ticket"]["type"],
            "string"
        );
    }

    #[test]
    fn openapi_covers_every_legacy_route_method() {
        let openapi: Value = serde_json::from_str(include_str!("openapi.json")).unwrap();
        let legacy: Vec<Value> = serde_json::from_str(include_str!(
            "../../../api/cmd/porthub-api/testdata/legacy_routes.json"
        ))
        .unwrap();
        let normalize = |path: &str| {
            let mut normalized = String::with_capacity(path.len());
            let mut parameter = false;
            for ch in path.chars() {
                match ch {
                    '{' => {
                        parameter = true;
                        normalized.push_str("{}");
                    }
                    '}' => parameter = false,
                    _ if parameter => {}
                    _ => normalized.push(ch),
                }
            }
            normalized
        };
        let documented = openapi["paths"].as_object().unwrap();
        for route in legacy {
            let path = route["path"].as_str().unwrap();
            let method = route["method"].as_str().unwrap().to_ascii_lowercase();
            let entry = documented
                .iter()
                .find(|(candidate, _)| normalize(candidate) == normalize(path));
            assert!(
                entry.is_some_and(|(_, operations)| operations[&method].is_object()),
                "legacy route {method} {path} is missing from OpenAPI"
            );
        }
    }
}
