use crate::{
    auth,
    domain::{accounts, workspaces},
    error::{ApiError, ApiResult},
    input::{ApiBody, Model},
    store, App,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, patch, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use mongodb::{
    bson::{doc, Bson, DateTime, Document},
    options::IndexOptions,
    IndexModel,
};
use serde_json::{json, Value};
use std::sync::{Arc, LazyLock};

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/auth/signup", post(signup))
        .route("/api/auth/preferences", patch(preferences))
        .route("/api/auth/account", patch(update_account))
        .route("/api/auth/password", patch(update_password))
        .route("/api/auth/settings/password", put(strong_password))
        .route("/api/auth/delete", delete(delete_account))
}

static EMAIL: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").expect("static email expression")
});
static IMAGE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^data:([-\w.]+/[-\w.+]+);base64,(.+)$").expect("static data URL expression")
});

fn duplicate(error: &mongodb::error::Error) -> bool {
    match error.kind.as_ref() {
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(error)) => {
            error.code == 11000
        }
        mongodb::error::ErrorKind::Command(error) => error.code == 11000,
        _ => false,
    }
}

async fn signup(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Response> {
    let mut model = Model::new(raw)?;
    let name = model.required_string("name");
    let mut username = model.required_string("username");
    let password = model.required_string("password");
    let invitation = model
        .optional_string("invitation_token")
        .unwrap_or_default();
    model.finish()?;
    if !invitation.is_empty() {
        let invite = workspaces::valid_invitation(&app, &invitation).await?;
        let email = store::string(&invite, "email");
        if username.trim().to_lowercase() != email {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "Use the email address on the invitation",
            ));
        }
        if name.trim().is_empty()
            || name.chars().count() > 100
            || !(12..=72).contains(&password.len())
        {
            return Err(ApiError::bad_request(
                "Provide a name and a password between 12 and 72 bytes",
            ));
        }
        username = email.to_owned();
        let existing = app.collection("users").find_one(doc! {"username":{"$regex":format!("^{}$",regex::escape(&username)),"$options":"i"}}).await?;
        if existing.is_some() {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "An account already exists. Sign in to accept the invitation.",
            ));
        }
        let index = IndexModel::builder()
            .keys(doc! {"username":1})
            .options(IndexOptions::builder().unique(true).build())
            .build();
        if app.collection("users").create_index(index).await.is_err() {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "An administrator must resolve duplicate account names before invited registration",
            ));
        }
    } else {
        let setting = app
            .collection("platform_settings")
            .find_one(doc! {"_id":"platform"})
            .await?;
        let signup_enabled = crate::config::signup_enabled(
            app.config.signup_disabled,
            setting
                .as_ref()
                .and_then(|d| d.get_bool("signup_enabled").ok()),
        );
        if !signup_enabled {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "sign up is disabled"));
        }
    }
    if app
        .collection("users")
        .find_one(doc! {"username":&username})
        .await?
        .is_some()
    {
        return Ok(Json(json!({"msg":"user already exists"})).into_response());
    }
    let mut user = accounts::hash_password(password).await?;
    user.extend(doc! {"name":name,"username":username,"role":"user","created_at":DateTime::now()});
    let inserted = app
        .collection("users")
        .insert_one(&user)
        .await
        .map_err(|error| {
            if duplicate(&error) {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "An account already exists. Sign in to accept the invitation.",
                )
            } else {
                error.into()
            }
        })?;
    user.insert("_id", inserted.inserted_id);
    let mut output = json!({"msg":"success"});
    if !invitation.is_empty() {
        output["workspace_id"] =
            json!(workspaces::accept_invitation(&app, &user, &invitation).await?);
    }
    let session = auth::start_session(&app, &headers, &store::id(user.get("_id"))).await?;
    Ok(auth::with_cookie(output, session))
}

async fn preferences(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let mut model = Model::new(raw)?;
    let collapsed = model.required_bool("nav_collapsed");
    model.finish()?;
    let user = auth::current_user(&app, &headers).await?;
    let result = app
        .collection("users")
        .update_one(
            doc! {"_id":user.get("_id")},
            doc! {"$set":{"preferences.nav_collapsed":collapsed}},
        )
        .await?;
    if result.matched_count == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "User not found"));
    }
    Ok(Json(json!({"nav_collapsed":collapsed})))
}

fn picture(model: &mut Model) -> Option<(String, String)> {
    let mut child = model.optional_object("profile_picture")?;
    let data = child.required_string("data_url");
    let filename = child.optional_string("filename").unwrap_or_default();
    child.optional_string("content_type");
    child.optional_integer("size", i64::MIN, i64::MAX);
    model.merge(child);
    Some((data, filename))
}

fn normalize_picture(data: &str, filename: &str) -> ApiResult<Document> {
    let data = data.trim();
    let captures = IMAGE
        .captures(data)
        .ok_or_else(|| ApiError::bad_request("Profile picture must be an image"))?;
    let mut content_type = captures[1].to_lowercase();
    if content_type == "image/jpg" {
        content_type = "image/jpeg".into();
    }
    if !matches!(
        content_type.as_str(),
        "image/png" | "image/jpeg" | "image/webp"
    ) {
        return Err(ApiError::bad_request(
            "Profile picture must be a PNG, JPG, or WebP image",
        ));
    }
    let bytes = STANDARD
        .decode(&captures[2])
        .map_err(|_| ApiError::bad_request("Profile picture could not be read"))?;
    if bytes.is_empty() {
        return Err(ApiError::bad_request("Profile picture is empty"));
    }
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(ApiError::bad_request(
            "Profile picture must be 2 MB or smaller",
        ));
    }
    Ok(
        doc! {"data_url":data,"content_type":content_type,"filename":filename.trim().chars().take(160).collect::<String>(),"size":bytes.len() as i64,"updated_at":DateTime::now()},
    )
}

async fn update_account(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let mut model = Model::new(raw)?;
    let name = model.optional_string("name").unwrap_or_default();
    let email = model
        .optional_string("email")
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    let current_password = model
        .optional_string("current_password")
        .unwrap_or_default();
    let image = picture(&mut model);
    let remove = model
        .optional_bool("remove_profile_picture")
        .unwrap_or(false);
    model.finish()?;
    let user = auth::current_user(&app, &headers).await?;
    let id = user.get("_id").ok_or_else(ApiError::unauthenticated)?;
    let current = store::string(&user, "email");
    let current = if current.is_empty() {
        store::string(&user, "username")
    } else {
        current
    };
    let mut set = Document::new();
    let mut unset = Document::new();
    let name = name.trim();
    if !name.is_empty() && name != store::string(&user, "name") {
        set.insert("name", name);
    }
    if !email.is_empty() && email != current.to_lowercase() {
        if !EMAIL.is_match(&email) {
            return Err(ApiError::bad_request("Enter a valid email address"));
        }
        if current_password.is_empty() {
            return Err(ApiError::bad_request("Current password required"));
        }
        if !accounts::verify_password(&user, current_password).await? {
            return Err(ApiError::bad_request("Incorrect password"));
        }
        if app
            .collection("users")
            .find_one(doc! {"_id":{"$ne":id},"$or":[{"username":&email},{"email":&email}]})
            .await?
            .is_some()
        {
            return Err(ApiError::bad_request("Email already exists"));
        }
        set.insert("username", &email);
        set.insert("email", email);
    }
    if let Some((data, filename)) = image {
        set.insert("profile_picture", normalize_picture(&data, &filename)?);
    } else if remove {
        unset.insert("profile_picture", "");
    }
    let mut update = Document::new();
    if !set.is_empty() {
        update.insert("$set", set);
    }
    if !unset.is_empty() {
        update.insert("$unset", unset);
    }
    if !update.is_empty() {
        app.collection("users")
            .update_one(doc! {"_id":id}, update)
            .await
            .map_err(|error| {
                if duplicate(&error) {
                    ApiError::bad_request("Email already exists")
                } else {
                    error.into()
                }
            })?;
    }
    Ok(Json(accounts::serialize(
        &accounts::reload(&app, id).await?,
    )))
}

fn password_fields(raw: Value) -> ApiResult<(String, String)> {
    let mut model = Model::new(raw)?;
    let current = model.required_string("current_password");
    let next = model.required_string("new_password");
    model.finish()?;
    Ok((current, next))
}

async fn update_password(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let (current, next) = password_fields(raw)?;
    let user = auth::current_user(&app, &headers).await?;
    if current.is_empty() {
        return Err(ApiError::bad_request("Current password required"));
    }
    if !accounts::verify_password(&user, current).await? {
        return Err(ApiError::bad_request("Incorrect password"));
    }
    if next.chars().count() < 8 {
        return Err(ApiError::bad_request(
            "Password must be at least 8 characters",
        ));
    }
    let password = accounts::hash_password(next).await?;
    app.collection("users")
        .update_one(doc! {"_id":user.get("_id")}, doc! {"$set":password})
        .await?;
    Ok(Json(json!({"msg":"success","has_password":true})))
}

async fn strong_password(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let (current, next) = password_fields(raw)?;
    let user = auth::current_user(&app, &headers).await?;
    if !accounts::verify_password(&user, current.clone()).await? {
        return Err(ApiError::bad_request("Current password is incorrect"));
    }
    if current == next {
        return Err(ApiError::bad_request(
            "New password must be different from the current password",
        ));
    }
    let strong = next.chars().count() >= 8
        && next.chars().any(|c| c.is_ascii_digit())
        && next.chars().any(|c| c.is_ascii_lowercase())
        && next.chars().any(|c| c.is_ascii_uppercase())
        && next.chars().any(|c| !c.is_ascii_alphanumeric());
    if !strong {
        return Err(ApiError::bad_request(
            "New password must include uppercase, lowercase, number, and symbol",
        ));
    }
    let password = accounts::hash_password(next).await?;
    app.collection("users")
        .update_one(doc! {"_id":user.get("_id")}, doc! {"$set":password})
        .await?;
    Ok(Json(json!({"msg":"password updated"})))
}

async fn delete_account(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Response> {
    let mut model = Model::new(raw)?;
    let username = model.required_string("username");
    let password = model.required_string("password");
    model.finish()?;
    let user = app
        .collection("users")
        .find_one(doc! {"username":username})
        .await?
        .ok_or_else(|| ApiError::bad_request("Username does not exist"))?;
    if !accounts::verify_password(&user, password).await? {
        return Err(ApiError::bad_request("Password is incorrect"));
    }
    let id = user.get("_id").ok_or_else(ApiError::unauthenticated)?;
    app.collection("users").delete_one(doc! {"_id":id}).await?;
    app.realtime.disconnect_user(&store::id(Some(id)));
    app.collection("user_sessions")
        .update_many(
            doc! {"user_id":store::id(Some(id)),"revoked_at":Bson::Null},
            doc! {"$set":{"revoked_at":DateTime::now()}},
        )
        .await?;
    Ok(auth::with_cookie(
        json!({"msg":"user deleted"}),
        auth::cookie(&headers, &app, "", 0),
    ))
}
