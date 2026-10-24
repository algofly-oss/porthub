use crate::{
    domain::{
        inventory,
        machine_client::{self, View},
    },
    error::{ApiError, ApiResult},
    input::{ApiBody, Model},
    store, App,
};
use axum::{
    extract::{OriginalUri, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use mongodb::bson::doc;
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc, time::Duration};

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/machines/client/auth", post(session))
        .route("/api/machines/client/sync", post(session))
        .route("/api/machines/sync", post(session))
        .route("/api/machines/client/config", get(config))
        .route("/api/machines/client/config.toml", get(config))
        .route("/api/machines/client/changes", get(config))
        .route("/api/machines/client/changes.toml", get(config))
        .route("/api/machines/client/deletion-ack", post(deletion_ack))
}

async fn session(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    ApiBody(body): ApiBody,
) -> ApiResult<Response> {
    let legacy = uri.path() == "/api/machines/sync";
    let mut model = Model::new(body)?;
    let id = model.required_string("machine_id");
    let token = model.required_string("token");
    model.string_length("token", &token, 1, None);
    let hostname = model.optional_string("hostname").unwrap_or_default();
    let local_ip = model.optional_string("local_ip").unwrap_or_default();
    let public_ip = model.optional_string("public_ip").unwrap_or_default();
    let _active = model.optional_bool("is_active");
    let version = if legacy {
        String::new()
    } else {
        model.optional_string("client_version").unwrap_or_default()
    };
    let handled = if legacy {
        String::new()
    } else {
        model
            .optional_string("client_update_last_handled_request_id")
            .unwrap_or_default()
    };
    model.finish()?;
    let machine = if legacy {
        machine_client::authenticate_legacy(&app, &id, &token).await?
    } else {
        machine_client::authenticate(&app, &id, &token).await?
    };
    let input = machine_client::Sync {
        hostname,
        local_ip,
        public_ip,
        version,
        handled,
    };
    let machine = if legacy {
        machine_client::sync_legacy(&app, &machine, input, &headers).await?
    } else {
        machine_client::sync(&app, &machine, input, &headers).await?
    };
    app.notify_status(&machine).await;
    let id = store::id(machine.get("_id"));
    let query = HashMap::new();
    let view = View {
        headers: &headers,
        query: &query,
    };
    let config = machine_client::bundle(&app, &machine, &view).await?;
    let serialized = inventory::machine(&app, &machine);
    let ips = machine_client::private_ips(&app, &machine).await?;
    let mut controls = machine_client::control_headers(&app, &machine);
    if let Ok(value) = store::string(&machine, "public_ip").parse() {
        controls.insert("x-porthub-observed-ip", value);
    }
    if let Ok(value) = ips.join(", ").parse() {
        controls.insert("x-porthub-private-ips", value);
    }
    controls.insert("cache-control", HeaderValue::from_static("no-store"));
    if legacy {
        return Ok((controls,Json(json!({"msg":"Machine synced successfully","data":serialized,"config":config,"endpoints":view.endpoints(&app,&machine)}))).into_response());
    }
    let action = if uri.path().ends_with("/auth") {
        "authenticated"
    } else {
        "synced"
    };
    Ok((controls,Json(json!({"msg":format!("Machine {action} successfully"),"data":{
        "machine":serialized,"config":config,"endpoints":view.endpoints(&app,&machine),
        "socket_auth":{"machine_id":id,"token":token,"role":"machine"},
        "socket":{"path":"/socket.io","events":{"request_config_snapshot":"/cts/machines/config-snapshot", "config_snapshot":"/stc/machines/config-snapshot","config_changed":"/stc/machines/config-changed"}},
        "polling":{"strategy":"long-poll","changes_query_parameter":"since"},
        "client":{"current_version":serialized["client_version"],"latest_version":serialized["latest_client_version"],
            "update_requested":serialized["client_update_requested"],"update_target_version":serialized["client_update_target_version"]}}}))).into_response())
}

async fn config(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult<Response> {
    let changes = uri.path().ends_with("/changes") || uri.path().ends_with("/changes.toml");
    let toml = uri.path().ends_with(".toml");
    let mut model = Model::query(query.clone());
    let id = model.required_string("machine_id");
    let token = model.required_string("token");
    model.string_length("token", &token, 1, None);
    let since = if changes {
        let value = model.required_string("since");
        model.string_length("since", &value, 1, None);
        value
    } else {
        String::new()
    };
    let wait = if changes {
        model.optional_integer("wait_seconds", 1, 300)
    } else {
        None
    };
    model.finish()?;
    let mut machine = machine_client::authenticate(&app, &id, &token).await?;
    let id = store::id(machine.get("_id"));
    let original_controls = machine_client::control_headers(&app, &machine);
    let view = View {
        headers: &headers,
        query: &query,
    };
    let signal = app.config_signals.subscribe(&id);
    let timeout = wait
        .map(|s| Duration::from_secs(s as u64))
        .unwrap_or(app.config.long_poll_timeout)
        .min(app.config.long_poll_timeout);
    let deadline = tokio::time::Instant::now() + timeout;
    let mut result;
    loop {
        // Register before reading the snapshot so a concurrent mutation cannot
        // slip between its digest check and the wait registration.
        let notification = signal.notified();
        tokio::pin!(notification);
        notification.as_mut().enable();
        result = machine_client::bundle(&app, &machine, &view).await?;
        if !changes
            || result["version"] != since
            || machine_client::control_headers(&app, &machine) != original_controls
            || tokio::time::Instant::now() >= deadline
        {
            break;
        }
        let _ = tokio::time::timeout_at(deadline, notification).await;
        machine = machine_client::authenticate(&app, &id, &token).await?;
    }
    let changed = !changes || result["version"] != since;
    if !toml {
        let body = if !changes {
            json!({"msg":"Machine config fetched successfully","data":result})
        } else if changed {
            json!({"msg":"Machine config changes fetched successfully","data":{"changed":true,"config":result}})
        } else {
            json!({"msg":"No machine config changes available","data":{"changed":false,"version":since}})
        };
        return Ok(([("cache-control", "no-store")], Json(body)).into_response());
    }
    let mut controls = machine_client::control_headers(&app, &machine);
    controls.insert("cache-control", HeaderValue::from_static("no-store"));
    controls.insert(
        "x-porthub-machine-id",
        id.parse()
            .map_err(|_| ApiError::bad_request("Invalid machine id"))?,
    );
    let version = if changed {
        result["version"].as_str().unwrap()
    } else {
        &since
    };
    controls.insert(
        "x-porthub-config-version",
        version
            .parse()
            .map_err(|_| ApiError::bad_request("Invalid configuration version"))?,
    );
    if !changed {
        return Ok((StatusCode::NO_CONTENT, controls).into_response());
    }
    controls.insert(
        "content-type",
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    Ok((
        controls,
        result["files"]["client.toml"].as_str().unwrap().to_owned(),
    )
        .into_response())
}

async fn deletion_ack(
    State(app): State<Arc<App>>,
    ApiBody(body): ApiBody,
) -> ApiResult<Json<Value>> {
    let mut model = Model::new(body)?;
    let id = model.required_string("machine_id");
    let token = model.required_string("token");
    model.string_length("token", &token, 1, None);
    model.finish()?;
    let oid = crate::domain::workspaces::object_id(&id, "Invalid machine id")?;
    let staged=app.collection("machines").update_one(
        doc! {"_id":oid,"token":&token,"deletion_pending":true,"native_deletion.phase":"committing"},
        doc! {"$set":{"native_deletion.acknowledged":true}}).await?;
    if staged.matched_count > 0 {
        app.deletion_changes.notify_one();
        return Ok(Json(
            json!({"msg":"Machine deletion acknowledged","data":{"machine_id":id,"removed":false}}),
        ));
    }
    let _guard = app.connection_lock.lock().await;
    let removed = app
        .collection("machines")
        .delete_one(doc! {"_id":oid,"token":token,"deletion_pending":true,"native_deletion":{"$exists":false}})
        .await?
        .deleted_count
        > 0;
    Ok(Json(
        json!({"msg":"Machine deletion acknowledged","data":{"machine_id":id,"removed":removed}}),
    ))
}
