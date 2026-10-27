use crate::{error::ApiResult, App};
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use mongodb::bson::doc;
use serde_json::Value;
use std::sync::{Arc, LazyLock};

static OPENAPI: LazyLock<Value> = LazyLock::new(|| {
    let mut document:Value=serde_json::from_str(include_str!("openapi.json")).expect("bundled OpenAPI document is valid");
    document["info"]["version"]=env!("CARGO_PKG_VERSION").into();
    document
});

const SWAGGER: &str = r##"<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PortHub API - Swagger UI</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui.css"></head>
<body><div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({url:"/api/openapi.json",dom_id:"#swagger-ui",defaultModelsExpandDepth:-1,persistAuthorization:true});</script>
</body></html>"##;

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api", get(api_root))
        .route("/api/docs", get(swagger_ui))
        .route("/api/openapi.json", get(openapi))
        .route("/api/openapi-go.json", get(openapi_legacy))
}

async fn docs_enabled(app: &App) -> ApiResult<bool> {
    let setting = app
        .collection("platform_settings")
        .find_one(doc! {"_id":"platform"})
        .await?;
    Ok(crate::config::docs_enabled(
        app.config.api_docs_enabled,
        setting
            .as_ref()
            .and_then(|document| document.get_bool("api_docs_enabled").ok()),
    ))
}

async fn api_root(State(app): State<Arc<App>>) -> ApiResult<Response> {
    Ok(api_root_response(docs_enabled(&app).await?))
}

async fn swagger_ui(State(app): State<Arc<App>>) -> ApiResult<Response> {
    Ok(swagger_response(docs_enabled(&app).await?))
}

async fn openapi(State(app): State<Arc<App>>) -> ApiResult<Response> {
    Ok(schema_response(docs_enabled(&app).await?))
}

async fn openapi_legacy(State(app): State<Arc<App>>) -> ApiResult<Response> {
    Ok(openapi_legacy_response(docs_enabled(&app).await?))
}

fn openapi_legacy_response(enabled: bool) -> Response {
    if enabled {
        Redirect::permanent("/api/openapi.json").into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

fn api_root_response(enabled: bool) -> Response {
    if enabled {
        Redirect::temporary("/api/docs").into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

fn swagger_response(enabled: bool) -> Response {
    if enabled {
        Html(SWAGGER).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

fn schema_response(enabled: bool) -> Response {
    if enabled {
        axum::Json(OPENAPI.clone()).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        api_root_response, openapi_legacy_response, schema_response, swagger_response, OPENAPI,
    };
    use axum::{body::to_bytes, http::StatusCode};
    use serde_json::Value;

    #[tokio::test]
    async fn api_root_redirects_to_swagger_ui() {
        let response = api_root_response(true);
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(response.headers()["location"], "/api/docs");
        assert_eq!(api_root_response(false).status(), StatusCode::NOT_FOUND);
        assert_eq!(
            openapi_legacy_response(false).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            openapi_legacy_response(true).status(),
            StatusCode::PERMANENT_REDIRECT
        );
    }

    #[tokio::test]
    async fn docs_load_bundled_openapi_document() {
        let response = swagger_response(true);
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("SwaggerUIBundle"));
        assert!(body.contains("/api/openapi.json"));
        assert_eq!(swagger_response(false).status(), StatusCode::NOT_FOUND);
        assert_eq!(schema_response(false).status(), StatusCode::NOT_FOUND);
        assert_eq!(schema_response(true).status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn openapi_document_describes_registered_api_routes() {
        let value = OPENAPI.clone();
        assert_eq!(value["openapi"], "3.0.3");
        assert!(value["paths"]["/api/machines/client/auth"]["post"].is_object());
        assert!(value["paths"]["/api/machines/client/identity"]["post"].is_object());
        assert!(value["paths"]["/api/connections/list"]["get"].is_object());
        assert!(value["paths"]["/api/downloads/porthub"]["get"].is_object());
        assert!(value["paths"]["/api/downloads/porthub/{target}"]["get"].is_object());
        assert!(value["paths"]["/api/admin/settings/docs"]["patch"].is_object());
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
    fn proxy_permissions_exit_modes_and_block_only_dns_are_documented() {
        let value=&*OPENAPI;
        assert_eq!(value["info"]["version"],env!("CARGO_PKG_VERSION"));
        let properties=&value["paths"]["/api/access/exit-nodes"]["post"]["requestBody"]["content"]["application/json"]["schema"]["properties"];
        assert_eq!(properties["traffic_mode"]["enum"],serde_json::json!(["all","internet_only","lan_only"]));
        assert_eq!(properties["tor_circuit_groups"]["maximum"],16);
        let rule=&value["paths"]["/api/access/dns-rules/{machine}"]["put"]["requestBody"]["content"]["application/json"]["schema"]["properties"]["rules"]["items"];
        assert_eq!(rule["properties"]["action"]["properties"]["type"]["enum"],serde_json::json!(["block"]));
        assert_eq!(value["paths"]["/api/access/proxy-grants"]["post"]["security"],serde_json::json!([{"SessionCookie":[]}]));
        for path in ["/api/access/proxy-check/{grant}","/api/access/proxy-stream/{grant}","/api/access/proxy-serve/{session}","/api/access/proxy-jobs"] {
            assert_eq!(value["paths"][path]["get"]["security"],serde_json::json!([{"PrivateAgentBearer":[]}]));
        }
    }

    #[test]
    fn openapi_covers_every_legacy_route_method() {
        let openapi: Value = serde_json::from_str(include_str!("openapi.json")).unwrap();
        let legacy: Vec<Value> =
            serde_json::from_str(include_str!("../tests/fixtures/legacy_routes.json")).unwrap();
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
