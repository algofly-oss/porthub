use crate::{
    auth,
    domain::{inventory, machines, workspaces::object_id},
    error::{ApiError, ApiResult},
    firewall, generated,
    input::ApiBody,
    store, App,
};
use axum::{extract::State, http::HeaderMap, routing::put, Json, Router};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, Bson, DateTime, Document},
    options::ReturnDocument,
};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;

pub fn router() -> Router<Arc<App>> {
    Router::new().route("/api/machines/update", put(update))
}

async fn update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let input = machines::parse(raw)?;
    let user = auth::current_user(&app, &headers).await?;
    let id = object_id(
        input.data_id.as_deref().unwrap_or_default(),
        "Invalid machine id",
    )?;
    let (name, aliases) = super::machines::split_names(&input.name)?;
    let _guard = app.connection_lock.lock().await;
    let owner = user.get("_id").ok_or_else(ApiError::unauthenticated)?;
    let filter = doc! {"_id":id,"user_id":owner};
    let previous = app
        .collection("machines")
        .find_one(filter.clone())
        .await?
        .ok_or_else(|| ApiError::bad_request("Machine not found"))?;
    if previous.contains_key("native_deletion") {
        return Err(ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "Machine deletion is in progress",
        ));
    }
    let enabled = input
        .enabled
        .or(input.is_active)
        .map(Bson::Boolean)
        .unwrap_or_else(|| {
            previous
                .get("enabled")
                .cloned()
                .unwrap_or(Bson::Boolean(true))
        });
    let preferences = app
        .collection("private_networks")
        .find_one(doc! {"_id":owner.to_string()})
        .await?
        .unwrap_or_default();
    let (_, dns_suffix) = crate::domain::enrollment::preferences(&preferences)?;
    let private_domains = input
        .private_domains
        .clone()
        .unwrap_or_else(|| crate::domain::private_domains::from_document(&previous));
    ensure_private_domains_unique(
        &app,
        owner,
        id,
        &name,
        &aliases,
        &private_domains,
        &dns_suffix,
    )
    .await?;
    let override_name = input.hostname.as_deref().unwrap_or_default().trim();
    let hostname = [
        override_name,
        store::string(&previous, "client_hostname").trim(),
        store::string(&previous, "hostname").trim(),
    ]
    .into_iter()
    .find(|value| !value.is_empty())
    .unwrap_or_default();
    let mut set = doc! {"name":name,"aliases":aliases,"hostname":hostname,"hostname_override":override_name,"enabled":enabled,"updated_at":DateTime::now()};
    let mut unset = Document::new();
    if let Some(domains) = &input.private_domains {
        set.insert(
            "private_domains",
            crate::domain::private_domains::to_bson(domains),
        );
    }
    if input.present.contains("group_ids") {
        let groups =
            super::machines::valid_groups(&app, owner, input.groups.unwrap_or_default()).await?;
        set.insert("group_ids", groups);
        unset.insert("group_id", "");
    }
    if input.present.contains("client_setup_public_base_url") {
        set.insert(
            "client_setup_public_base_url",
            machines::public_base(input.public_base.as_deref())?,
        );
    }
    for (key, value, label) in [
        (
            "client_setup_rathole_server_address",
            input.rathole.as_deref(),
            "Rathole server address",
        ),
        (
            "client_setup_service_domain",
            input.domain.as_deref(),
            "Service domain",
        ),
    ] {
        if input.present.contains(key) {
            set.insert(key, machines::optional_text(value, label, 255)?);
        }
    }
    if let Some(alerts) = input.alerts {
        set.insert("telegram_alerts_excluded", alerts);
    }
    let mut mutation = doc! {"$set":&set};
    if !unset.is_empty() {
        mutation.insert("$unset", unset.clone());
    }
    let updated = app
        .collection("machines")
        .find_one_and_update(filter.clone(), mutation)
        .return_document(ReturnDocument::After)
        .await?
        .ok_or_else(|| ApiError::bad_request("Machine not found"))?;
    let previous_view = inventory::machine(&app, &previous);
    let updated_view = inventory::machine(&app, &updated);
    let enabled_changed = previous_view["enabled"] != updated_view["enabled"];
    let config_changed = [
        "name",
        "hostname",
        "enabled",
        "client_setup_rathole_server_address",
        "private_domains",
    ]
    .iter()
    .any(|key| previous_view[*key] != updated_view[*key]);
    let result = async {
        // Install restrictions before publishing newly enabled listeners.
        if enabled_changed && updated.get_bool("enabled") != Ok(false) {
            firewall::sync_machine(&app, id).await?;
        }
        if config_changed {
            generated::rebuild(&app).await?;
        }
        if enabled_changed && updated.get_bool("enabled") == Ok(false) {
            firewall::sync_machine(&app, id).await?;
        }
        Ok::<(), ApiError>(())
    }
    .await;
    if let Err(error) = result {
        app.collection("machines")
            .update_one(filter, machines::recovery(&previous, &set, &unset))
            .await?;
        let was_enabled = previous.get_bool("enabled") != Ok(false);
        if enabled_changed && was_enabled {
            if let Err(recovery) = firewall::sync_machine(&app, id).await {
                tracing::error!(detail=%recovery.detail,"machine update firewall recovery failed");
                app.firewall_changes.notify_one();
                // Keep restrictive publication until policy restoration succeeds.
                return Err(error);
            }
        }
        if let Err(recovery) = generated::rebuild(&app).await {
            tracing::error!(detail=%recovery.detail,"machine update configuration recovery failed");
        }
        if enabled_changed && !was_enabled {
            if let Err(recovery) = firewall::sync_machine(&app, id).await {
                tracing::error!(detail=%recovery.detail,"machine update firewall recovery failed");
                app.firewall_changes.notify_one();
            }
        }
        return Err(error);
    }
    if config_changed {
        app.notify_config(&id.to_hex()).await;
    }
    app.notify_status(&updated).await;
    Ok(Json(
        json!({"msg":"Machine updated successfully","data":updated_view}),
    ))
}

async fn ensure_private_domains_unique(
    app: &App,
    owner: &Bson,
    machine_id: mongodb::bson::oid::ObjectId,
    name: &str,
    aliases: &[String],
    domains: &[crate::domain::private_domains::Entry],
    default_suffix: &str,
) -> ApiResult<()> {
    fn add_label(set: &mut HashSet<String>, label: &str, suffix: &str) -> bool {
        let label = crate::domain::private_names::label(Some(&Bson::String(label.to_owned())));
        set.insert(format!("{label}.{suffix}").to_ascii_lowercase())
    }
    let peers: Vec<Document> = app
        .collection("private_peers")
        .find(doc! {"workspace_id":owner})
        .projection(doc! {"machine_id":1})
        .await?
        .try_collect()
        .await?;
    let ids: Vec<Bson> = peers
        .iter()
        .filter_map(|peer| peer.get("machine_id").cloned())
        .collect();
    let machines: Vec<Document> = app
        .collection("machines")
        .find(doc! {"$or":[{"user_id":owner},{"_id":{"$in":ids}}],"deletion_pending":{"$ne":true}})
        .projection(doc! {"_id":1,"name":1,"aliases":1,"private_domains":1})
        .await?
        .try_collect()
        .await?;
    let mut candidate = HashSet::new();
    if !add_label(&mut candidate, name, default_suffix) {
        return Err(ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "Machine names and private DNS domains must be unique",
        ));
    }
    for alias in aliases {
        if !add_label(&mut candidate, alias, default_suffix) {
            return Err(ApiError::new(
                axum::http::StatusCode::CONFLICT,
                "Machine names and private DNS domains must be unique",
            ));
        }
    }
    for domain in domains {
        if domain.default {
            continue;
        }
        let full = format!("{}.{}", domain.host, domain.suffix).to_ascii_lowercase();
        if !candidate.insert(full) {
            return Err(ApiError::new(
                axum::http::StatusCode::CONFLICT,
                "Machine names and private DNS domains must be unique",
            ));
        }
    }
    for machine in machines {
        if store::id(machine.get("_id")) == machine_id.to_hex() {
            continue;
        }
        let mut existing = HashSet::new();
        add_label(
            &mut existing,
            store::string(&machine, "name"),
            default_suffix,
        );
        if let Ok(values) = machine.get_array("aliases") {
            for value in values {
                let alias = store::json(value).as_str().unwrap_or_default().to_owned();
                add_label(&mut existing, &alias, default_suffix);
            }
        }
        for domain in crate::domain::private_domains::from_document(&machine) {
            if domain.default {
                add_label(
                    &mut existing,
                    store::string(&machine, "name"),
                    default_suffix,
                );
            } else {
                existing.insert(format!("{}.{}", domain.host, domain.suffix).to_ascii_lowercase());
            }
        }
        if candidate.iter().any(|domain| existing.contains(domain)) {
            return Err(ApiError::new(
                axum::http::StatusCode::CONFLICT,
                "This machine name or private DNS domain is already registered",
            ));
        }
    }
    Ok(())
}
