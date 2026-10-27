use crate::{
    domain::{
        inventory,
        machine_client::{self, View},
        private_enrollment,
    },
    error::{ApiError, ApiResult},
    input::{ApiBody, Model},
    store, App,
};
use axum::{
    extract::{OriginalUri, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, Bson, DateTime, Document};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc, time::Duration};

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/machines/client/auth", post(session))
        .route("/api/machines/client/sync", post(session))
        .route("/api/machines/sync", post(session))
        .route("/api/machines/client/identity", post(identity))
        .route(
            "/api/machines/client/private-install",
            post(pending_private_install),
        )
        .route("/api/machines/client/config", get(config))
        .route("/api/machines/client/config.toml", get(config))
        .route("/api/machines/client/changes", get(config))
        .route("/api/machines/client/changes.toml", get(config))
        .route("/api/machines/client/deletion-ack", post(deletion_ack))
}

async fn identity(State(app): State<Arc<App>>, ApiBody(body): ApiBody) -> ApiResult<Json<Value>> {
    let mut model = Model::new(body)?;
    let id = model.required_string("machine_id");
    model.string_length("machine_id", &id, 1, Some(64));
    let token = model.required_string("token");
    model.string_length("token", &token, 1, None);
    model.finish()?;
    let machine = machine_client::authenticate(&app, &id, &token).await?;
    let owner = if let Some(user_id) = machine.get("user_id") {
        app.collection("users")
            .find_one(mongodb::bson::doc! {"_id":user_id})
            .await?
    } else {
        None
    };
    let email = owner
        .as_ref()
        .map(|user| {
            let email = store::string(user, "email");
            if email.trim().is_empty() {
                store::string(user, "username")
            } else {
                email
            }
        })
        .unwrap_or_default();
    Ok(Json(json!({"account_email":email})))
}

async fn pending_private_install(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(body): ApiBody,
) -> ApiResult<Response> {
    let mut model = Model::new(body)?;
    let id = model.required_string("machine_id");
    model.string_length("machine_id", &id, 1, Some(64));
    let token = model.required_string("token");
    model.string_length("token", &token, 1, None);
    model.finish()?;
    let machine = machine_client::authenticate(&app, &id, &token).await?;
    let mut empty = StatusCode::NO_CONTENT.into_response();
    empty
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if machine.get_bool("private_owner_revoked").unwrap_or(false) {
        return Ok(empty);
    }

    private_enrollment::initialize(&app).await?;
    crate::domain::enrollment::ensure(&app, &machine).await?;
    let machine_id = machine.get("_id").ok_or_else(ApiError::unauthenticated)?;
    let owner_id = machine
        .get("user_id")
        .ok_or_else(ApiError::unauthenticated)?;
    let peers: Vec<Document> = app
        .collection("private_peers")
        .find(doc! {"machine_id":machine_id,"owner_id":owner_id,"enabled":true,"credential_hash":{"$exists":false}})
        .limit(2)
        .await?
        .try_collect()
        .await?;
    if peers.is_empty() {
        return Ok(empty);
    }
    if peers.len() != 1 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Choose which pending private workspace to install",
        ));
    }
    let peer = &peers[0];
    let workspace = store::id(peer.get("workspace_id"));
    let owner = store::id(Some(owner_id));
    if workspace != owner {
        let membership = app
            .collection("workspace_members")
            .find_one(doc! {"_id":format!("{workspace}:{owner}")})
            .await?;
        if !membership
            .as_ref()
            .is_some_and(|record| matches!(store::string(record, "role"), "admin" | "member"))
        {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "Machine owner no longer belongs to the private workspace",
            ));
        }
    }

    let now = DateTime::now();
    let ticket = private_enrollment::token()?;
    app.collection("private_install_tickets")
        .update_many(
            doc! {"peer_id":peer.get("_id"),"consumed_at":Bson::Null},
            doc! {"$set":{"consumed_at":now}},
        )
        .await?;
    let mut claim = doc! {
        "_id":crate::domain::workspaces::token_digest(&ticket),
        "peer_id":peer.get_str("_id").unwrap_or_default(),
        "created_by":owner_id,
        "consumed_at":Bson::Null,
        "expires_at":DateTime::from_millis(now.timestamp_millis()+600_000),
    };
    if let Some(generation) = peer.get("enrollment_generation") {
        claim.insert("generation", generation.clone());
    }
    app.collection("private_install_tickets")
        .insert_one(claim)
        .await?;

    let query = HashMap::new();
    let view = View {
        headers: &headers,
        query: &query,
    };

    // Native agents consume a small structured ticket instead of executing a
    // shell installer. Keep the text installer as the default representation
    // for existing Go clients.
    if headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|entry| {
                entry.trim().split(';').next()
                    == Some("application/vnd.porthub.private-install+json")
            })
        })
    {
        let mut response = Json(json!({"data": {
            "format_version": 1,
            "server": view.public_base(&app, &machine),
            "peer_id": store::field(peer, "_id"),
            "workspace": workspace,
            "ticket": ticket,
            "fallback_servers": []
        }}))
        .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return Ok(response);
    }

    let server = view.public_base(&app, &machine);
    let script = include_str!("../../assets/client/private-install.sh")
        .replace(
            "__PRIVATE_SERVER__",
            &crate::enrollment_ticket::shell_quote(&server),
        )
        .replace(
            "__PRIVATE_TICKET__",
            &crate::enrollment_ticket::shell_quote(&ticket),
        );
    let mut response = script.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
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
    let client_os = model.optional_string("client_os").unwrap_or_default();
    let client_arch = model.optional_string("client_arch").unwrap_or_default();
    let client_os_id = model.optional_string("client_os_id").unwrap_or_default();
    let client_os_name = model.optional_string("client_os_name").unwrap_or_default();
    model.string_length("client_os_id", &client_os_id, 0, Some(64));
    model.string_length("client_os_name", &client_os_name, 0, Some(160));
    let _active = model.optional_bool("is_active");
    let version = if legacy {
        String::new()
    } else {
        model.optional_string("client_version").unwrap_or_default()
    };
    let handled = model.optional_string("client_update_last_handled_request_id");
    let native_update_protocol = !legacy || handled.is_some();
    let handled = handled.unwrap_or_default();
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
        client_os,
        client_arch,
        client_os_id,
        client_os_name,
        version,
        handled,
        native_update_protocol,
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
