use crate::{store, App};
use mongodb::bson::{Bson, Document};
use serde_json::{json, Value};

pub fn settings(user: &Document) -> Value {
    let token = store::string(user, "telegram_bot_token").trim();
    let count = token.chars().count();
    let masked = if count <= 4 {
        "*".repeat(count)
    } else {
        format!(
            "{}{}",
            "*".repeat(count - 4),
            token.chars().skip(count - 4).collect::<String>()
        )
    };
    let interval = user
        .get_i64("telegram_digest_interval_hours")
        .ok()
        .or_else(|| {
            user.get_i32("telegram_digest_interval_hours")
                .ok()
                .map(i64::from)
        })
        .filter(|value| *value != 0)
        .unwrap_or(6);
    json!({"bot_token_masked":masked,"has_bot_token":!store::string(user,"telegram_bot_token").is_empty(),
        "chat_ids":user.get_array("telegram_chat_ids").cloned().unwrap_or_default().iter().map(store::json).collect::<Vec<_>>(),
        "alerts_enabled":user.get_bool("telegram_alerts_enabled").unwrap_or(false),
        "instant_alerts_enabled":user.get_bool("telegram_instant_alerts_enabled").unwrap_or(true),
        "digest_enabled":user.get_bool("telegram_digest_enabled").unwrap_or(true),"digest_interval_hours":interval})
}

pub async fn send(
    app: &App,
    token: &str,
    chats: &[Bson],
    text: &str,
) -> (Vec<String>, Vec<String>) {
    let mut sent = Vec::new();
    let mut failed = Vec::new();
    let token = token.trim();
    if token.is_empty() {
        return (sent, failed);
    }
    // Treat the token as one path segment. Never log URLs or reqwest errors,
    // since the Bot API authenticates through this path.
    let url = reqwest::Url::parse(&app.config.telegram_base_url)
        .ok()
        .and_then(|mut url| {
            {
                let mut path = url.path_segments_mut().ok()?;
                path.pop_if_empty()
                    .push(&format!("bot{token}"))
                    .push("sendMessage");
            }
            Some(url)
        });
    for chat in chats {
        let chat = match chat {
            Bson::String(value) => value.clone(),
            Bson::Int32(value) => value.to_string(),
            Bson::Int64(value) => value.to_string(),
            _ => String::new(),
        };
        let chat = chat.trim().to_owned();
        if chat.is_empty() {
            continue;
        }
        let result = match &url {
            Some(url) => app
                .http
                .post(url.clone())
                .json(&json!({"chat_id":chat,"text":text,"parse_mode":"HTML"}))
                .send()
                .await
                .ok()
                .is_some_and(|response| response.status().as_u16() < 400),
            None => false,
        };
        if result {
            sent.push(chat);
        } else {
            failed.push(chat);
        }
    }
    (sent, failed)
}
