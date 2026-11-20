//! A signed-in machine owner can claim a workspace explicitly prepared by its
//! local OS user. The gateway can only select a running workspace.
use super::*;
use axum::extract::Path;
use futures_util::TryStreamExt;
use mongodb::bson::oid::ObjectId;

fn denied() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "Dashboard shell unavailable")
}

async fn owner(app: &App, headers: &HeaderMap, machine: &str) -> ApiResult<String> {
    let user = crate::auth::current_user(app, headers).await?;
    let id = user.get_object_id("_id").map_err(|_| denied())?;
    registered_owner(app, machine, id).await?;
    Ok(id.to_hex())
}

async fn registered_owner(app: &App, machine: &str, id: ObjectId) -> ApiResult<()> {
    let machine = ObjectId::parse_str(machine).map_err(|_| denied())?;
    app.collection("machines").find_one(doc! {
        "_id": machine, "user_id": id, "kind": {"$ne": "virtual_host"}, "enabled": {"$ne": false},
        "deletion_pending": {"$ne": true}, "native_deletion": {"$exists": false}
    }).projection(doc!{"_id":1}).await?.ok_or_else(denied)?;
    Ok(())
}

/// Existing invitation-only shares retain their original policy. Guests in
/// an owner-reserved shell also lose access if the machine is reassigned.
pub(super) async fn permitted(
    app: &App,
    access: Option<&Connection>,
    session: &porthub_terminal::hub::Shared,
) -> ApiResult<()> {
    if let Some(access) = access {
        return access.allowed(app).await;
    }
    if let Some(account) = &session.options.dashboard_owner {
        return registered_owner(
            app,
            &session.owner,
            ObjectId::parse_str(account).map_err(|_| denied())?,
        )
        .await;
    }
    Ok(())
}

pub(super) async fn catalog(
    app: &App,
    machine: &str,
    account: &str,
) -> ApiResult<(Vec<serde_json::Value>, bool)> {
    let claimed: std::collections::HashSet<String> = app.collection("terminal_sessions")
        .find(doc!{"machine_id":machine,"state":"active","options.dashboard_owner":account,"dashboard_claim": {"$exists":true}})
        .projection(doc!{"_id":1}).await?.map_ok(|r|store::string(&r,"_id").to_owned()).try_collect().await?;
    let mut sessions = app.terminals.sessions();
    sessions.sort_by(|a, b| a.options.name.cmp(&b.options.name).then(a.id.cmp(&b.id)));
    let mut rows = Vec::new();
    let mut available = false;
    for s in sessions {
        if s.owner != machine || s.stop.is_cancelled() || s.options.access == Access::Ssh {
            continue;
        }
        if let Some(grantee) = &s.options.dashboard_owner {
            if grantee != account || s.expired(now()) {
                continue;
            }
            if !claimed.contains(&s.id) {
                if s.live_invitation_state().is_some() {
                    available = true;
                }
                continue;
            }
        }
        rows.push(serde_json::json!({"id":s.id,"name":s.options.name,"read_only":s.options.read_only, "dashboard":s.options.dashboard_owner.is_some()}));
    }
    Ok((rows, available))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Claim {
    request_id: String,
}

pub(super) async fn claim(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(machine): Path<String>,
    axum::Json(body): axum::Json<Claim>,
) -> ApiResult<impl IntoResponse> {
    origin(&headers)?;
    if !token(&body.request_id, 32) {
        return Err(bad("Invalid open-shell request"));
    }
    let account = owner(&app, &headers, &machine).await?;
    let _guard = app.terminal_lifecycle.lock().await;
    let collection = app.collection("terminal_sessions");
    let filter = doc! {"machine_id":&machine, "options.dashboard_owner":&account,"dashboard_claim":&body.request_id};
    let record = if let Some(record) = collection.find_one(filter).await? {
        if store::string(&record, "state") != "active" {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "The previously opened shell has ended",
            ));
        }
        record
    } else {
        let candidates: Vec<_> = app
            .terminals
            .sessions()
            .into_iter()
            .filter(|s| {
                s.owner == machine
                    && s.options.dashboard_owner.as_deref() == Some(&account)
                    && !s.stop.is_cancelled()
                    && !s.expired(now())
                    && s.live_invitation_state().is_some()
            })
            .map(|s| s.id.clone())
            .collect();
        collection.find_one_and_update(doc!{"_id":{"$in":candidates},"machine_id":&machine,"state":"active","options.dashboard_owner":&account,"dashboard_claim":{"$exists":false}},doc!{"$set":{"dashboard_claim":body.request_id,"dashboard_claimed_at":DateTime::now()}})
          .await?.ok_or_else(||ApiError::new(StatusCode::CONFLICT,"No fresh workspace is available on this machine"))?
    };
    Ok((
        [(axum::http::header::CACHE_CONTROL, "private, no-store")],
        axum::Json(serde_json::json!({"id":store::string(&record,"_id")})),
    ))
}

pub(super) struct Connection {
    headers: HeaderMap,
    pub machine: String,
    pub session: String,
    pub binding: String,
}
impl Connection {
    pub(super) async fn allowed(&self, app: &App) -> ApiResult<()> {
        let account = owner(app, &self.headers, &self.machine).await?;
        app.collection("terminal_sessions").find_one(doc!{"_id":&self.session,"state":"active","machine_id":&self.machine,"options.dashboard_owner":account,"dashboard_claim":{"$exists":true}})
         .projection(doc!{"_id":1}).await?.ok_or_else(denied)?;
        Ok(())
    }
}
fn origin(headers: &HeaderMap) -> ApiResult<()> {
    if !headers.contains_key("origin") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Browser origin required",
        ));
    }
    management_origin(headers)
}
pub(super) async fn join(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path((machine, session)): Path<(String, String)>,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    origin(&headers)?;
    let connection = Connection {
        binding: digest(&crate::auth::token(&headers, &app)),
        headers,
        machine,
        session,
    };
    connection.allowed(&app).await?;
    let permit = app
        .terminals
        .admit()
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "Terminal busy"))?;
    Ok(upgrade
        .max_message_size(32768)
        .max_frame_size(32768)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            viewer_socket(app, socket, Some(connection)).await
        })
        .into_response())
}

pub(super) async fn status(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path((machine, session)): Path<(String, String)>,
) -> ApiResult<impl IntoResponse> {
    Connection {
        headers,
        machine,
        session,
        binding: String::new(),
    }
    .allowed(&app)
    .await?;
    Ok((
        StatusCode::NO_CONTENT,
        [(axum::http::header::CACHE_CONTROL, "private, no-store")],
    ))
}

pub(super) async fn terminate(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path((machine, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    origin(&headers)?;
    let access = Connection { headers, machine, session: id.clone(), binding: String::new() };
    let session = {
        let _guard = app.terminal_lifecycle.lock().await;
        access.allowed(&app).await?;
        let session = app.terminals.sessions().into_iter()
            .find(|s| s.id == id && s.owner == access.machine).ok_or_else(denied)?;
        session.request_dashboard_end().map_err(|_| ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE, "Shell host unavailable. Reconnect and try again."))?;
        session
    };
    // Wait outside the lifecycle lock so the host can report its workspace exit.
    if tokio::time::timeout(Duration::from_secs(8), session.stop.cancelled()).await.is_ok()
        && matches!(session.close_event(), Some(HostEvent::Stop { reason }) if reason == "owner ended session")
    {
        return Ok(StatusCode::NO_CONTENT);
    }
    Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE,
        "The host did not confirm termination. Check the session and the installed terminal version."))
}

/// The initial, locally generated transport credentials never authorize a guest
/// for a dashboard workspace. A deliberate owner action rotates the invitations.
pub(super) fn guest_join_enabled(session: &porthub_terminal::hub::Shared) -> bool {
    session.options.dashboard_owner.is_none()
        || session
            .live_invitation_state()
            .is_some_and(|(_, revision)| revision > 0)
}

pub(super) async fn guest_links(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path((machine, id)): Path<(String, String)>,
) -> ApiResult<impl IntoResponse> {
    origin(&headers)?;
    let access = Connection {
        headers,
        machine,
        session: id.clone(),
        binding: String::new(),
    };
    let _guard = app.terminal_lifecycle.lock().await;
    access.allowed(&app).await?;
    let session = app
        .terminals
        .sessions()
        .into_iter()
        .find(|s| s.id == id && s.owner == access.machine && s.options.dashboard_owner.is_some())
        .ok_or_else(denied)?;
    let (generation, revision) = session.live_invitation_state().ok_or_else(denied)?;
    let update = InvitationUpdate {
        revision: revision.checked_add(1).ok_or_else(denied)?,
        write_token: random_token(32),
        read_token: random_token(32),
        expires_at: now() + 900,
    };
    persist_invitation_rotation(&app, &id, generation, &update).await?;
    Ok((
        [(axum::http::header::CACHE_CONTROL, "private, no-store")],
        axum::Json(serde_json::json!({
            "read":update.read_token,"write":(!session.options.read_only).then_some(update.write_token),"expires_at":update.expires_at
        })),
    ))
}
