use crate::{
    error::{ApiError, ApiResult},
    input::Model,
    input_compat, store, App,
};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId, Bson, Document},
    options::IndexOptions,
    IndexModel,
};
use rand::RngCore;
use serde_json::Value;
use std::{collections::HashSet, time::Duration};

pub fn token() -> ApiResult<String> {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ApiError::bad_request("Could not generate enrollment capability"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}
fn model(raw: Value) -> ApiResult<Model> {
    Model::new(
        input_compat::dictionary(raw.clone())
            .map(Value::Object)
            .unwrap_or(raw),
    )
}
fn hostname(model: &mut Model, key: &str) -> Option<String> {
    let value = model.optional_string(key)?;
    model.string_length(key, &value, 0, Some(48));
    if !model.field_valid(key) || input_compat::strip(&value).is_empty() {
        return None;
    }
    let value = input_compat::strip(&value)
        .to_lowercase()
        .trim_end_matches('.')
        .to_owned();
    if value.is_empty()
        || value.len() > 48
        || !value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        || value.starts_with('-')
        || value.ends_with('-')
    {
        model.add(
            key,
            "Use up to 48 letters, numbers or hyphens, not starting or ending with a hyphen",
            "value_error",
        );
    }
    Some(value)
}
pub fn parse(raw: Value) -> ApiResult<(String, Option<String>)> {
    let mut model = model(raw)?;
    let id = model.required_string("machine_id");
    model.string_length("machine_id", &id, 1, Some(64));
    let name = hostname(&mut model, "hostname");
    let alias = hostname(&mut model, "alias");
    model.finish()?;
    Ok((id, name.or(alias)))
}
pub fn parse_hostname(raw: Value) -> ApiResult<Option<String>> {
    let mut model = model(raw)?;
    let name = hostname(&mut model, "hostname");
    model.finish()?;
    Ok(name)
}
pub fn parse_ticket(raw: Value) -> ApiResult<String> {
    let mut model = model(raw)?;
    let ticket = model.required_string("ticket");
    model.string_length("ticket", &ticket, 32, Some(200));
    model.finish()?;
    Ok(ticket)
}
pub async fn initialize(app: &App) -> ApiResult<()> {
    app.private_enrollment_initialized
        .get_or_try_init(|| async {
            let peers = app.collection("private_peers");
            peers
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"workspace_id":1,"ip":1})
                        .options(IndexOptions::builder().unique(true).build())
                        .build(),
                )
                .await?;
            let indexes: Vec<mongodb::IndexModel> =
                peers.list_indexes().await?.try_collect().await?;
            if indexes.iter().any(|i| {
                i.options.as_ref().and_then(|o| o.name.as_deref()) == Some("workspace_id_1_alias_1")
            }) {
                peers.drop_index("workspace_id_1_alias_1").await?;
            }
            peers
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"workspace_id":1,"hostname":1})
                        .options(
                            IndexOptions::builder()
                                .name("workspace_custom_hostname".to_owned())
                                .unique(true)
                                .partial_filter_expression(doc! {"hostname":{"$type":"string"}})
                                .build(),
                        )
                        .build(),
                )
                .await?;
            app.collection("private_install_tickets")
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"expires_at":1})
                        .options(IndexOptions::builder().expire_after(Duration::ZERO).build())
                        .build(),
                )
                .await?;
            crate::enrollment_ticket::initialize(app).await?;
            Ok::<_, ApiError>(())
        })
        .await?;
    Ok(())
}
pub async fn names(app: &App, owner: ObjectId) -> ApiResult<(Vec<Document>, Vec<Document>)> {
    let peers: Vec<Document> = app
        .collection("private_peers")
        .find(doc! {"workspace_id":owner})
        .await?
        .try_collect()
        .await?;
    let ids: Vec<_> = peers
        .iter()
        .filter_map(|p| p.get("machine_id").cloned())
        .collect();
    let machines = app
        .collection("machines")
        .find(doc! {"$or":[{"user_id":owner},{"_id":{"$in":ids}}],"deletion_pending":{"$ne":true}})
        .projection(doc! {"name":1,"aliases":1})
        .await?
        .try_collect()
        .await?;
    Ok((machines, peers))
}
pub async fn check_name(app: &App, owner: ObjectId, mid: &Bson, name: &str) -> ApiResult<()> {
    let (machines, peers) = names(app, owner).await?;
    for machine in &machines {
        if machine.get("_id") == Some(mid) {
            continue;
        }
        if std::iter::once(machine.get("name"))
            .chain(machine.get_array("aliases").into_iter().flatten().map(Some))
            .any(|value| super::private_names::label(value) == name)
        {
            return Err(ApiError::new(
                axum::http::StatusCode::CONFLICT,
                "This private hostname is already in use",
            ));
        }
    }
    let assigned = super::private_names::assign(&machines, &peers);
    if peers.iter().any(|p| {
        p.get("machine_id") != Some(mid)
            && assigned
                .primary
                .get(store::string(p, "_id"))
                .is_some_and(|label| label == name)
    }) {
        return Err(ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "This private hostname is already in use",
        ));
    }
    Ok(())
}
pub fn occupied(peers: &[Document]) -> HashSet<String> {
    peers
        .iter()
        .map(|p| store::string(p, "ip").to_owned())
        .collect()
}
/// Validate a still-unconsumed capability and its issuer without exposing it.
pub async fn resolve(app: &App, ticket: &str) -> ApiResult<(Document, Document)> {
    let denied = || {
        ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            "Installer ticket is invalid, expired or already used",
        )
    };
    let claim=app.collection("private_install_tickets").find_one(doc!{"_id":super::workspaces::token_digest(ticket),"consumed_at":Bson::Null,"expires_at":{"$gt":mongodb::bson::DateTime::now()}}).await?.ok_or_else(denied)?;
    let peer = app
        .collection("private_peers")
        .find_one(
            doc! {"_id":claim.get("peer_id"),"enabled":true,"credential_hash":{"$exists":false}},
        )
        .await?
        .ok_or_else(denied)?;
    if claim.get("generation") != peer.get("enrollment_generation") {
        return Err(denied());
    }
    let owner = peer.get("workspace_id");
    let issuer = claim.get("created_by");
    if issuer != owner
        && app
            .collection("workspace_members")
            .find_one(
                doc! {"workspace_id":owner,"user_id":issuer,"role":{"$in":["admin","member"]}},
            )
            .await?
            .is_none()
    {
        return Err(denied());
    }
    if peer.get("owner_id")!=owner && app.collection("workspace_members").find_one(doc!{"workspace_id":owner,"user_id":peer.get("owner_id"),"role":{"$in":["admin","member"]}}).await?.is_none() {return Err(denied());}
    let machine=app.collection("machines").find_one(doc!{"_id":peer.get("machine_id"),"user_id":peer.get("owner_id"),"enabled":{"$ne":false},"deletion_pending":{"$ne":true},"private_owner_revoked":{"$ne":true}}).await?;
    if machine.is_none() {
        return Err(denied());
    }
    Ok((claim, peer))
}
