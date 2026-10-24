use crate::{
    error::{ApiError, ApiResult},
    store, App,
};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document};
use sha2::{Digest, Sha256};

pub fn token_digest(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

pub fn object_id(value: &str, message: &str) -> ApiResult<ObjectId> {
    ObjectId::parse_str(value).map_err(|_| ApiError::bad_request(message))
}

pub async fn access(
    app: &App,
    user: &Document,
    workspace: &str,
    manage: bool,
) -> ApiResult<(ObjectId, String)> {
    let user_id = user
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())?;
    let owner = if workspace.is_empty() {
        user_id
    } else {
        object_id(workspace, "Invalid workspace")?
    };
    let role = if owner == user_id {
        "owner".into()
    } else {
        let member = app
            .collection("workspace_members")
            .find_one(doc! {"_id":format!("{}:{}",owner.to_hex(),user_id.to_hex())})
            .await?;
        let role = member
            .as_ref()
            .map(|m| store::string(m, "role"))
            .unwrap_or("");
        if role != "admin" && role != "member" {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "You do not belong to this workspace",
            ));
        }
        role.to_owned()
    };
    if manage && role != "owner" && role != "admin" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Workspace administrator permission is required",
        ));
    }
    Ok((owner, role))
}

pub async fn valid_invitation(app: &App, token: &str) -> ApiResult<Document> {
    if !(32..=200).contains(&token.chars().count()) {
        return Err(ApiError::bad_request("Invitation is invalid or expired"));
    }
    app.collection("workspace_invites").find_one(doc! {
        "_id":token_digest(token),"consumed_at":Bson::Null,"revoked_at":Bson::Null,"expires_at":{"$gt":DateTime::now()}
    }).await?.ok_or_else(||ApiError::bad_request("Invitation is invalid or expired"))
}

pub async fn accept_invitation(app: &App, user: &Document, token: &str) -> ApiResult<String> {
    let invite = valid_invitation(app, token).await?;
    if store::string(user, "username").trim().to_lowercase() != store::string(&invite, "email") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Sign in with the email address this invitation was sent to",
        ));
    }
    let owner = invite.get("user_id").cloned().unwrap_or(Bson::Null);
    let user_id = user
        .get("_id")
        .cloned()
        .ok_or_else(ApiError::unauthenticated)?;
    let owner_id = store::id(Some(&owner));
    let uid = store::id(Some(&user_id));
    if owner_id == uid {
        return Err(ApiError::bad_request("You already own this workspace"));
    }
    let issuer = store::id(invite.get("created_by"));
    let issuer_role = if issuer == owner_id {
        "owner".to_owned()
    } else {
        app.collection("workspace_members")
            .find_one(doc! {"_id":format!("{owner_id}:{issuer}")})
            .await?
            .as_ref()
            .map(|m| store::string(m, "role").to_owned())
            .unwrap_or_default()
    };
    if !matches!(issuer_role.as_str(), "owner" | "admin")
        || (store::string(&invite, "role") == "admin" && issuer_role != "owner")
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "The invitation issuer no longer has permission",
        ));
    }
    let id = invite.get("_id").cloned().unwrap_or(Bson::Null);
    let claim = app.collection("workspace_invites").update_one(doc! {
        "_id":&id,"consumed_at":Bson::Null,"revoked_at":Bson::Null,"expires_at":{"$gt":DateTime::now()}
    },doc! {"$set":{"consumed_at":DateTime::now(),"accepted_by":&user_id}}).await?;
    if claim.modified_count != 1 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Invitation has already been used or revoked",
        ));
    }
    let joined = app.collection("workspace_members").update_one(doc! {"_id":format!("{owner_id}:{uid}")},doc! {
        "$setOnInsert":{"user_id":&user_id,"workspace_id":&owner,"role":invite.get("role").cloned().unwrap_or(Bson::Null),"joined_at":DateTime::now()}
    }).upsert(true).await;
    if let Err(error) = joined {
        let _ = app
            .collection("workspace_invites")
            .update_one(
                doc! {"_id":&id,"accepted_by":&user_id},
                doc! {
                    "$set":{"consumed_at":Bson::Null},"$unset":{"accepted_by":""}
                },
            )
            .await;
        return Err(error.into());
    }
    Ok(owner_id)
}
