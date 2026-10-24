use crate::{
    artifacts,
    enrollment_ticket::{self, Enrollment},
    error::{ApiError, ApiResult},
    store, App,
};
use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use std::sync::Arc;
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/install/{ticket}", get(enroll))
        .route("/install/{ticket}/agent/{target}", get(asset))
        .route(
            "/api/machines/{first}/{second}/install.sh",
            get(legacy_installer),
        )
        .route("/api/install/{token}", get(legacy_short_installer))
}
async fn legacy_installer(
    State(app): State<Arc<App>>,
    Path((id, token)): Path<(String, String)>,
    request: Request,
) -> ApiResult<Response> {
    let query: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    let _guard = app.connection_lock.lock().await;
    let machine_id = crate::domain::workspaces::object_id(&id, "Invalid machine id")?;
    let machine = app
        .collection("machines")
        .find_one(mongodb::bson::doc! {"_id":machine_id})
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::GONE, "Machine deleted"))?;
    use subtle::ConstantTimeEq;
    let stored = store::string(&machine, "token");
    if stored.is_empty() || !bool::from(stored.as_bytes().ct_eq(token.as_bytes())) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Invalid machine token",
        ));
    }
    if machine.get_bool("deletion_pending") == Ok(true) {
        return Err(ApiError::new(StatusCode::GONE, "Machine deleted"));
    }
    if machine.get_bool("enabled") == Ok(false) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "Machine disabled"));
    }
    installer_response(&app, &machine, &query, request.headers()).await
}
async fn legacy_short_installer(
    State(app): State<Arc<App>>,
    Path(token): Path<String>,
    request: Request,
) -> ApiResult<Response> {
    if !(32..=200).contains(&token.len()) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Invalid machine token",
        ));
    }
    let _guard = app.connection_lock.lock().await;
    let machine=app.collection("machines").find_one(mongodb::bson::doc!{"token":&token,"enabled":{"$ne":false},"deletion_pending":{"$ne":true}}).await?.ok_or_else(||ApiError::new(StatusCode::FORBIDDEN,"Invalid machine token"))?;
    let query = url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
        .into_owned()
        .collect();
    installer_response(&app, &machine, &query, request.headers()).await
}
async fn installer_response(
    app: &App,
    machine: &mongodb::bson::Document,
    query: &std::collections::HashMap<String, String>,
    request_headers: &HeaderMap,
) -> ApiResult<Response> {
    let (_, link) = enrollment_ticket::public_link(app, request_headers, machine, query).await?;
    let code = url::Url::parse(&link)
        .expect("validated installer URL")
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .expect("installer capability")
        .to_owned();
    let enrollment = enrollment_ticket::resolve(app, &code).await?;
    let mut response_headers = headers();
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response_headers.insert(
        "x-porthub-machine-id",
        HeaderValue::from_str(&store::id(machine.get("_id"))).expect("authenticated machine id"),
    );
    if wants_json(request_headers) {
        response_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        Ok((
            response_headers,
            Json(enrollment.values(app, request_headers)?),
        )
            .into_response())
    } else {
        Ok((
            response_headers,
            launcher(&enrollment, app, request_headers, &code)?,
        )
            .into_response())
    }
}
fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (key, value) in [
        (header::CACHE_CONTROL, "no-store"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::VARY, "Accept"),
    ] {
        headers.insert(key, HeaderValue::from_static(value));
    }
    headers
}
fn launcher(
    enrollment: &Enrollment,
    app: &App,
    headers: &HeaderMap,
    ticket: &str,
) -> ApiResult<String> {
    let values = enrollment.values(app, headers)?;
    let link = enrollment_ticket::link(
        values["server"]
            .as_str()
            .or_else(|| values["profile"]["server"].as_str())
            .expect("profile server"),
        ticket,
    )?;
    let url = enrollment_ticket::shell_quote(&link);
    let action = if values["kind"] == "private" {
        "enroll --install-service"
    } else {
        "setup"
    };
    // First-download compatibility only. The binary performs credential file,
    // release and service operations natively; nothing tails or supervises it here.
    Ok(format!(
        r#"#!/bin/sh
set -eu
porthub_bootstrap_url={url}
case "$(uname -s)" in
  Linux) porthub_bootstrap_os=linux ;;
  Darwin) porthub_bootstrap_os=darwin ;;
  *) echo 'Download the native PortHub agent for this platform first.' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) porthub_bootstrap_arch=x86_64 ;;
  i?86) porthub_bootstrap_arch=x86 ;;
  aarch64|arm64) porthub_bootstrap_arch=arm64 ;;
  armv7*) porthub_bootstrap_arch=armv7 ;;
  armv6*) porthub_bootstrap_arch=armhf ;;
  *) echo 'No native PortHub agent target for this architecture.' >&2; exit 1 ;;
esac
if [ "$porthub_bootstrap_os" = linux ]; then
  porthub_bootstrap_target=$porthub_bootstrap_arch
else
  porthub_bootstrap_target=darwin_$porthub_bootstrap_arch
fi
porthub_bootstrap_dir=$(mktemp -d)
trap 'rm -rf "$porthub_bootstrap_dir"' 0
trap 'exit 1' HUP INT TERM
curl -fsS --proto '=https' "$porthub_bootstrap_url/agent/$porthub_bootstrap_target" -o "$porthub_bootstrap_dir/porthub"
chmod 700 "$porthub_bootstrap_dir/porthub"
porthub_bootstrap_user=false
for porthub_bootstrap_arg in "$@"; do
  if [ "$porthub_bootstrap_arg" = --user ]; then porthub_bootstrap_user=true; fi
done
if [ "$porthub_bootstrap_user" = true ] || [ "$(id -u)" = 0 ]; then
  "$porthub_bootstrap_dir/porthub" {action} --ticket "$porthub_bootstrap_url" "$@"
else
  sudo -- "$porthub_bootstrap_dir/porthub" {action} --ticket "$porthub_bootstrap_url" "$@"
fi
"#
    ))
}
fn wants_json(request_headers: &HeaderMap) -> bool {
    request_headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .eq_ignore_ascii_case("application/json")
            })
        })
}
async fn enroll(
    State(app): State<Arc<App>>,
    Path(ticket): Path<String>,
    request: Request,
) -> ApiResult<Response> {
    let enrollment = enrollment_ticket::resolve(&app, &ticket).await?;
    let mut headers = headers();
    headers.insert(
        "x-porthub-machine-id",
        HeaderValue::from_str(&store::id(enrollment.machine.get("_id"))).expect("ObjectId header"),
    );
    let json = wants_json(request.headers());
    if json {
        Ok((headers, Json(enrollment.values(&app, request.headers())?)).into_response())
    } else {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        Ok((
            headers,
            Body::from(launcher(&enrollment, &app, request.headers(), &ticket)?),
        )
            .into_response())
    }
}
async fn asset(
    State(app): State<Arc<App>>,
    Path((ticket, target)): Path<(String, String)>,
    request: Request,
) -> ApiResult<Response> {
    enrollment_ticket::resolve(&app, &ticket).await?;
    app.artifacts
        .get(artifacts::normalize(&target, false)?)
        .await?
        .response(request.method(), request.headers(), false)
        .await
}
