//! Durable account retirement. Browser mutations drain before deletion; the
//! existing idle deletion worker resumes interrupted cleanup after a restart.
use crate::{
    error::{ApiError, ApiResult},
    firewall, generated, store, App,
};
use axum::http::StatusCode;
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document};

fn values(id: ObjectId) -> Vec<Bson> {
    vec![Bson::ObjectId(id), Bson::String(id.to_hex())]
}
fn expanded(rows: &[Document]) -> Vec<Bson> {
    let mut ids = Vec::new();
    for row in rows {
        if let Some(id) = row.get("_id") {
            ids.push(id.clone());
            match id {
                Bson::ObjectId(id) => ids.push(Bson::String(id.to_hex())),
                Bson::String(id) => {
                    if let Ok(id) = ObjectId::parse_str(id) {
                        ids.push(Bson::ObjectId(id));
                    }
                }
                _ => {}
            }
        }
    }
    ids
}
fn list(job: &Document, key: &str) -> Vec<Bson> {
    job.get_array(key).cloned().unwrap_or_default()
}
async fn rows(app: &App, collection: &str, filter: Document) -> ApiResult<Vec<Document>> {
    Ok(app
        .collection(collection)
        .find(filter)
        .await?
        .try_collect()
        .await?)
}

/// Caller holds account_lifecycle write, then connection_lock. Credentials are
/// revoked before publishing the closed ingress snapshot. No rollback can
/// accidentally restore an account after its clients received revocation.
pub async fn delete_locked(app: &App, id: ObjectId) -> ApiResult<()> {
    let mut user = app
        .collection("users")
        .find_one(doc! {"_id":id})
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Account not found"))?;
    if !user.contains_key("account_deletion") {
        if store::string(&user, "role") == "admin"
            && app
                .collection("users")
                .count_documents(doc! {"role":"admin","account_deletion":{"$exists":false}})
                .await?
                <= 1
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "The last administrator account cannot be deleted",
            ));
        }
        let owners = values(id);
        let machines = rows(app, "machines", doc! {"user_id":{"$in":&owners}}).await?;
        let mids = expanded(&machines);
        let peers=rows(app,"private_peers",doc!{"$or":[{"owner_id":{"$in":&owners}},{"workspace_id":{"$in":&owners}},{"machine_id":{"$in":&mids}}]}).await?;
        let groups = rows(app, "machine_groups", doc! {"user_id":{"$in":&owners}}).await?;
        let routes = rows(app, "traffic_routes", doc! {"user_id":{"$in":&owners}}).await?;
        let job = doc! {"requested_at":DateTime::now(),"next_attempt_at":DateTime::now(),
        "machine_ids":mids,"peer_ids":expanded(&peers),"group_ids":expanded(&groups),"route_ids":expanded(&routes)};
        app.collection("users")
            .update_one(doc! {"_id":id}, doc! {"$set":{"account_deletion":&job}})
            .await?;
        user.insert("account_deletion", job);
    }
    app.deletion_changes.notify_one();
    if let Err(error) = resume(app, &user).await {
        app.collection("users").update_one(doc!{"_id":id,"account_deletion":{"$exists":true}},
            doc!{"$set":{"account_deletion.next_attempt_at":DateTime::from_millis(DateTime::now().timestamp_millis()+5000)}}).await?;
        app.deletion_changes.notify_one();
        tracing::warn!(detail=%error.detail,"account access revoked; cleanup will retry");
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Account access is revoked. Cleanup is pending and will retry automatically.",
        ));
    }
    Ok(())
}

async fn resume(app: &App, user: &Document) -> ApiResult<()> {
    let id = user
        .get_object_id("_id")
        .map_err(|_| ApiError::bad_request("Invalid account"))?;
    let owner = values(id);
    let uid = id.to_hex();
    let job = user
        .get_document("account_deletion")
        .map_err(|_| ApiError::bad_request("Invalid account deletion journal"))?;
    let mids = list(job, "machine_ids");
    let pids = list(job, "peer_ids");
    let gids = list(job, "group_ids");
    let routes = list(job, "route_ids");
    let machine_filter = doc! {"$or":[{"_id":{"$in":&mids}},{"user_id":{"$in":&owner}}]};
    let connection_filter = doc! {"$or":[{"user_id":{"$in":&owner}},{"machine_id":{"$in":&mids}}]};
    let peer_filter = doc! {"$or":[{"_id":{"$in":&pids}},{"owner_id":{"$in":&owner}},{"workspace_id":{"$in":&owner}},{"machine_id":{"$in":&mids}}]};
    app.realtime.disconnect_user(&uid);
    app.collection("user_sessions")
        .delete_many(doc! {"user_id":{"$in":&owner}})
        .await?;
    app.collection("machines").update_many(machine_filter.clone(),doc!{"$set":{"enabled":false,"deletion_pending":true},"$unset":{"token":"","log_tokens":""}}).await?;
    app.collection("private_peers").update_many(peer_filter.clone(),doc!{"$set":{"enabled":false},"$unset":{"credential_hash":"","fingerprint":"","instance":""}}).await?;
    let peer_strings: Vec<_> = pids
        .iter()
        .filter_map(Bson::as_str)
        .map(str::to_owned)
        .collect();
    app.private_relay.revoke(&peer_strings);
    app.collection("connections")
        .update_many(connection_filter.clone(), doc! {"$set":{"enabled":false}})
        .await?;
    app.collection("traffic_routes")
        .update_many(
            doc! {"user_id":{"$in":&owner}},
            doc! {"$set":{"enabled":false}},
        )
        .await?;
    // The edge receives a single authoritative closed snapshot before records
    // disappear. Keep the journal if edge/firewall publication is unavailable.
    generated::rebuild(app).await?;
    generated::rebuild_web(app).await?;
    let connections = rows(app, "connections", connection_filter.clone()).await?;
    firewall::remove_many(app, &connections).await?;
    if let Some(client) = &app.firewall {
        for connection in &connections {
            if let Some(port) = connection
                .get("external_port")
                .and_then(|v| store::json(v).as_u64())
            {
                client
                    .request(
                        reqwest::Method::DELETE,
                        &format!("/ports/{port}/history"),
                        None,
                    )
                    .await?;
            }
        }
    }
    for mid in mids.iter().filter_map(|v| match v {
        Bson::ObjectId(id) => Some(id.to_hex()),
        _ => None,
    }) {
        app.realtime.disconnect_machine(&mid);
        app.config_signals.changed(&mid);
    }
    app.collection("connections")
        .delete_many(connection_filter)
        .await?;
    app.collection("traffic_routes")
        .delete_many(doc! {"user_id":{"$in":&owner}})
        .await?;
    app.collection("machine_status_events")
        .delete_many(doc! {"machine_id":{"$in":&mids}})
        .await?;
    app.collection("machine_install_tickets").delete_many(doc!{"$or":[{"machine_id":{"$in":&mids}},{"user_id":{"$in":&owner}},{"created_by":{"$in":&owner}}]}).await?;
    app.collection("private_install_tickets")
        .delete_many(doc! {"$or":[{"peer_id":{"$in":&pids}},{"created_by":{"$in":&owner}}]})
        .await?;
    app.collection("private_signals")
        .delete_many(doc! {"$or":[{"from":{"$in":&pids}},{"to":{"$in":&pids}}]})
        .await?;
    app.collection("private_peers")
        .delete_many(peer_filter)
        .await?;
    app.collection("workspace_members")
        .delete_many(doc! {"$or":[{"user_id":{"$in":&owner}},{"workspace_id":{"$in":&owner}}]})
        .await?;
    let email = store::string(user, "username").trim().to_lowercase();
    app.collection("workspace_invites").delete_many(doc!{"$or":[{"workspace_id":{"$in":&owner}},{"created_by":{"$in":&owner}},{"email":{"$regex":format!("^{}$",regex::escape(&email)),"$options":"i"}}]}).await?;
    app.collection("access_rulebooks").delete_many(doc!{"$or":[{"user_id":{"$in":&owner}},{"workspace_id":{"$in":&owner}},{"group_id":{"$in":&gids}}]}).await?;
    // Remove explicit selectors for retired identities from shared workspaces;
    // unrelated rules and other people's public machines remain intact.
    let mut retired = owner.clone();
    retired.extend(mids.clone());
    retired.extend(pids.clone());
    retired.extend(gids.clone());
    fn references(value: &Bson, ids: &[Bson]) -> bool {
        ids.contains(value)
            || match value {
                Bson::Array(items) => items.iter().any(|v| references(v, ids)),
                Bson::Document(doc) => doc.values().any(|v| references(v, ids)),
                _ => false,
            }
    }
    let mut books = app.collection("access_rulebooks").find(doc! {}).await?;
    while let Some(book) = books.try_next().await? {
        let mut set = Document::new();
        if let Ok(rules) = book.get_array("rules") {
            let kept: Vec<_> = rules
                .iter()
                .filter(|rule| !references(rule, &retired))
                .cloned()
                .collect();
            if kept.len() != rules.len() {
                set.insert("rules", kept);
            }
        }
        if book.get("created_by").is_some_and(|v| owner.contains(v)) {
            set.insert("created_by", Bson::Null);
        }
        if !set.is_empty() {
            app.collection("access_rulebooks")
                .update_one(
                    doc! {"_id":book.get("_id")},
                    doc! {"$set":set,"$inc":{"revision":1}},
                )
                .await?;
        }
    }
    app.collection("machine_groups")
        .delete_many(doc! {"user_id":{"$in":&owner}})
        .await?;
    app.collection("machine_groups")
        .update_many(
            doc! {"user_ids":{"$in":&owner}},
            doc! {"$pull":{"user_ids":{"$in":&owner}}},
        )
        .await?;
    app.collection("machines")
        .update_many(
            doc! {"group_ids":{"$in":&gids}},
            doc! {"$pull":{"group_ids":{"$in":&gids}}},
        )
        .await?;
    app.collection("machines")
        .update_many(
            doc! {"group_id":{"$in":&gids}},
            doc! {"$unset":{"group_id":""}},
        )
        .await?;
    app.collection("machines")
        .delete_many(machine_filter)
        .await?;
    app.collection("private_networks")
        .delete_many(doc! {"_id":{"$in":&owner}})
        .await?;
    let mut unset = Document::new();
    for id in routes.iter().filter_map(Bson::as_object_id) {
        unset.insert(format!("metrics.{}", id.to_hex()), "");
    }
    if !unset.is_empty() {
        app.collection("proxy_activity")
            .update_many(doc! {}, doc! {"$unset":unset,"$inc":{"revision":1}})
            .await?;
    }
    app.collection("users")
        .delete_one(doc! {"_id":id,"account_deletion":{"$exists":true}})
        .await?;
    Ok(())
}

pub async fn recover_due(app: &App) -> ApiResult<Option<DateTime>> {
    let due: Vec<Document> = app
        .collection("users")
        .find(doc! {"account_deletion.next_attempt_at":{"$lte":DateTime::now()}})
        .sort(doc! {"account_deletion.next_attempt_at":1})
        .limit(25)
        .await?
        .try_collect()
        .await?;
    for candidate in due.into_iter().take(25) {
        let id = candidate
            .get_object_id("_id")
            .map_err(|_| ApiError::bad_request("Invalid account"))?;
        let _lifecycle = app.account_lifecycle.write().await;
        let _connections = app.connection_lock.lock().await;
        let _networks = app.private_network_lock.lock().await;
        if let Some(current) = app
            .collection("users")
            .find_one(doc! {"_id":id,"account_deletion":{"$exists":true}})
            .await?
        {
            if let Err(error) = resume(app, &current).await {
                app.collection("users").update_one(doc!{"_id":id},doc!{"$set":{"account_deletion.next_attempt_at":DateTime::from_millis(DateTime::now().timestamp_millis()+5000)}}).await?;
                tracing::warn!(detail=%error.detail,"account cleanup will retry");
            }
        }
    }
    let next = app
        .collection("users")
        .find_one(doc! {"account_deletion.next_attempt_at":{"$exists":true}})
        .sort(doc! {"account_deletion.next_attempt_at":1})
        .await?;
    Ok(next.and_then(|d| {
        d.get_document("account_deletion")
            .ok()?
            .get_datetime("next_attempt_at")
            .ok()
            .copied()
    }))
}
