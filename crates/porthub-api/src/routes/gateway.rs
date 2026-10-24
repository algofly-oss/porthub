use crate::{
    error::{ApiError, ApiResult},
    input::{ApiBody, Model},
    App,
};
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use mongodb::bson::{doc, oid::ObjectId};
use serde_json::json;
use std::sync::Arc;

pub fn router() -> Router<Arc<App>> {
    Router::new().route("/api/gateway/origin", post(origin))
}

async fn origin(State(app): State<Arc<App>>, ApiBody(body): ApiBody) -> ApiResult<Response> {
    let mut model = Model::new(body)?;
    let machine_id = model.required_string("machine_id");
    let token = model.required_string("token");
    model.string_length("machine_id", &machine_id, 1, Some(24));
    model.string_length("token", &token, 1, Some(512));
    model.finish()?;
    let denied = || ApiError::new(StatusCode::UNAUTHORIZED, "Machine authentication required");
    let id = ObjectId::parse_str(&machine_id).map_err(|_| denied())?;
    let machine = app
        .collection("machines")
        .find_one(doc! {
            "_id":id, "token":token, "enabled":{"$ne":false}, "deletion_pending":{"$ne":true}
        })
        .await?;
    if machine.is_none() {
        return Err(denied());
    }
    // Authenticate before reading the cache or triggering external discovery.
    let configured = app
        .config
        .gateway_advertised_url
        .as_deref()
        .map(crate::gateway_origin::advertised_url)
        .transpose()
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Gateway origin unavailable",
            )
        })?;
    let metadata = crate::gateway_origin::metadata(&app);
    let mut data = if let Some(url) = configured {
        let port = url.port_or_known_default().expect("validated origin port");
        let mut value = json!({"origin_url":url.to_string().trim_end_matches('/'),"public_host":url.host_str(),"public_port":port,
            "scheme":url.scheme(),"configured":true,"stale":false,"refresh_after_seconds":300});
        if let Some(host) = url
            .host_str()
            .filter(|host| host.parse::<std::net::IpAddr>().is_ok())
        {
            value["public_ip"] = json!(host);
        }
        value
    } else {
        let origin = app
            .gateway_origin
            .get(
                &app.http,
                &app.config.gateway_ip_sources,
                app.config.gateway_public_ip.as_deref(),
            )
            .await
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Gateway origin is temporarily unavailable",
                )
            })?;
        let mut value = serde_json::to_value(&origin).expect("origin serialization");
        if let Some(metadata) = &metadata {
            value["public_port"] = json!(metadata.tls_port);
            value["scheme"] = json!("https");
            value["origin_url"] = json!(format!(
                "https://{}:{}",
                origin.public_ip, metadata.tls_port
            ));
        }
        value
    };
    if data["scheme"] == "https" {
        if let Some(metadata) = metadata {
            data["spki_sha256"] = json!(metadata.spki_sha256);
        }
        data["tls_port"] = data["public_port"].clone();
    }
    Ok((
        [(header::CACHE_CONTROL, "private, no-store")],
        Json(json!({"data":data})),
    )
        .into_response())
}
