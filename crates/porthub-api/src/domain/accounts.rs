use crate::{
    error::{ApiError, ApiResult},
    store, App,
};
use mongodb::bson::{doc, spec::BinarySubtype, Binary, Bson, Document};
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
