use crate::{
    error::{ApiError, ApiResult},
    store, App,
};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, spec::BinarySubtype, Binary, Bson, Document};
use mongodb::{options::IndexOptions, IndexModel};
use serde_json::{json, Value};

pub fn password_hash(user: &Document) -> String {
    match user.get("password") {
        Some(Bson::Binary(binary)) => String::from_utf8(binary.bytes.clone()).unwrap_or_default(),
        Some(Bson::String(hash)) => hash.clone(),
        _ => String::new(),
    }
}

pub async fn verify_password(user: &Document, password: String) -> ApiResult<bool> {
    let hash = password_hash(user);
    tokio::task::spawn_blocking(move || bcrypt::verify(password, &hash).unwrap_or(false))
        .await
        .map_err(|_| {
            ApiError::new(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
            )
        })
}

pub async fn hash_password(password: String) -> ApiResult<Document> {
    if password.len() > 72 {
        return Err(ApiError::bad_request("Password must be at most 72 bytes"));
    }
    let hash = tokio::task::spawn_blocking(move || bcrypt::hash(password, 12))
        .await
        .map_err(|_| {
            ApiError::new(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
            )
        })?
        .map_err(|_| ApiError::bad_request("Password must be at most 72 bytes"))?;
    let salt = hash.as_bytes()[..29].to_vec();
    Ok(doc! {
        "password": Bson::Binary(Binary { subtype: BinarySubtype::Generic, bytes: hash.into_bytes() }),
        "salt": Bson::Binary(Binary { subtype: BinarySubtype::Generic, bytes: salt }),
    })
}

pub fn serialize(user: &Document) -> Value {
    let username = store::string(user, "username");
    let email = store::string(user, "email");
    json!({
        "name":store::field(user,"name"), "username":username,
        "email":if email.is_empty() {username} else {email}, "role":store::field(user,"role"),
        "created_at":store::field(user,"created_at"), "profile_picture":store::field(user,"profile_picture"),
        "has_password":!password_hash(user).is_empty(),
        "preferences":{"nav_collapsed":user.get_document("preferences").ok().and_then(|p|p.get_bool("nav_collapsed").ok()).unwrap_or(false)},
    })
}

pub async fn reload(app: &App, id: &Bson) -> ApiResult<Document> {
    app.collection("users")
        .find_one(doc! {"_id":id})
        .await?
        .ok_or_else(ApiError::unauthenticated)
}

/// Accept existing unique indexes and upgrade legacy nonunique indexes without
/// replacing an operator's index. Shared by admin and invited provisioning.
pub async fn ensure_unique_usernames(app: &App) -> ApiResult<()> {
    let indexes: Vec<IndexModel> = match app.collection("users").list_indexes().await {
        Ok(cursor) => cursor.try_collect().await?,
        Err(error) if matches!(error.kind.as_ref(),mongodb::error::ErrorKind::Command(command) if command.code==26) => {
            Vec::new()
        }
        Err(error) => return Err(error.into()),
    };
    if indexes.iter().any(|index| {
        index.keys == doc! {"username":1}
            && index.options.as_ref().and_then(|options| options.unique) == Some(true)
    }) {
        return Ok(());
    }
    app.collection("users")
        .create_index(
            IndexModel::builder()
                .keys(doc! {"username":1})
                .options(
                    IndexOptions::builder()
                        .name("porthub_unique_username".to_owned())
                        .unique(true)
                        .build(),
                )
                .build(),
        )
        .await
        .map_err(|error| {
            if store::duplicate(&error) {
                ApiError::new(
                    axum::http::StatusCode::CONFLICT,
                    "Resolve duplicate account emails before creating another account",
                )
            } else {
                error.into()
            }
        })?;
    Ok(())
}
