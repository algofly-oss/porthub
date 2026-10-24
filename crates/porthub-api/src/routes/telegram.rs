use crate::{
    auth,
    domain::{accounts, telegram},
    error::{ApiError, ApiResult},
    input::{ApiBody, Model},
    store, App,
};
use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use mongodb::bson::{doc, Document};
use serde_json::{json, Value};
use std::sync::Arc;

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/auth/telegram", get(settings).patch(update))
        .route("/api/auth/telegram/test", post(test))
}

async fn settings(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    Ok(Json(telegram::settings(
        &auth::current_user(&app, &headers).await?,
    )))
}

async fn update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let mut model = Model::new(raw)?;
    let token = model.optional_string("bot_token");
    let chats = model.optional_strings("chat_ids");
    let alerts = model.optional_bool("alerts_enabled");
    let instant = model.optional_bool("instant_alerts_enabled");
    let digest = model.optional_bool("digest_enabled");
    let interval = model.optional_integer("digest_interval_hours", i64::MIN, i64::MAX);
    model.finish()?;
    let user = auth::current_user(&app, &headers).await?;
    let id = user.get("_id").ok_or_else(ApiError::unauthenticated)?;
    let mut set = Document::new();
    if let Some(token) = token {
        set.insert("telegram_bot_token", token.trim());
    }
    if let Some(chats) = chats {
        let chats: Vec<String> = chats
            .into_iter()
            .map(|chat| chat.trim().to_owned())
            .filter(|chat| !chat.is_empty())
            .collect();
        if chats.len() > 20 {
            return Err(ApiError::bad_request(
                "You can configure at most 20 chat/channel IDs",
            ));
        }
        set.insert("telegram_chat_ids", chats);
    }
    for (key, value) in [
        ("telegram_alerts_enabled", alerts),
        ("telegram_instant_alerts_enabled", instant),
        ("telegram_digest_enabled", digest),
    ] {
        if let Some(value) = value {
            set.insert(key, value);
        }
    }
    if let Some(interval) = interval {
        if ![1, 3, 6, 12, 24].contains(&interval) {
            return Err(ApiError::bad_request(
                "Digest interval must be one of 1, 3, 6, 12, or 24 hours",
            ));
        }
        set.insert("telegram_digest_interval_hours", interval);
    }
    if !set.is_empty() {
        app.collection("users")
            .update_one(doc! {"_id":id}, doc! {"$set":set})
            .await?;
    }
    Ok(Json(telegram::settings(&accounts::reload(&app, id).await?)))
}

async fn test(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let user = auth::current_user(&app, &headers).await?;
    let token = store::string(&user, "telegram_bot_token").trim();
    let chats = user
        .get_array("telegram_chat_ids")
        .cloned()
        .unwrap_or_default();
    if token.is_empty() || chats.is_empty() {
        return Err(ApiError::bad_request(
            "Add a bot token and at least one chat ID before sending a test message",
        ));
    }
    let (sent, failed) = telegram::send(
        &app,
        token,
        &chats,
        "✅ PortHub Telegram alerts are set up correctly.",
    )
    .await;
    if sent.is_empty() {
        return Err(ApiError::bad_request(
            "Could not deliver the test message. Check the bot token and chat IDs.",
        ));
    }
    Ok(Json(json!({"msg":"success","sent":sent,"failed":failed})))
}
