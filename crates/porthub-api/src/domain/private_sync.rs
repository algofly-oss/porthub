use crate::{error::ApiResult, input::Model, input_compat};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeMap, sync::LazyLock};

#[derive(Serialize)]
pub struct Description {
    pub r#type: String,
    pub sdp: String,
}
#[derive(Serialize)]
pub struct Signal {
    pub to: String,
    pub session: String,
    pub description: Description,
}
#[derive(Serialize)]
pub struct Sync {
    pub peer_id: String,
    pub token: String,
    pub fingerprint: String,
    pub instance: String,
    pub signals: Vec<Signal>,
    pub acks: Vec<String>,
    pub paths: BTreeMap<String, String>,
}
static SESSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[a-zA-Z0-9-]{16,64}\n?\z").unwrap());
static FINGERPRINT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}\z").unwrap());
fn string(model: &mut Model, key: &str, min: usize, max: usize) -> String {
    let value = model.required_string(key);
    model.string_length(key, &value, min, Some(max));
    value
}
fn session(model: &mut Model, key: &str) -> String {
    let value = model.required_string(key);
    model.regex(key, "^[a-zA-Z0-9-]{16,64}$", SESSION.is_match(&value));
    value
}
pub fn parse(raw: Value) -> ApiResult<Sync> {
    let raw = input_compat::dictionary(raw.clone())
        .map(Value::Object)
        .unwrap_or(raw);
    let mut model = Model::new(raw)?;
    let peer_id = string(&mut model, "peer_id", 0, 60);
    let token = string(&mut model, "token", 32, 200);
    let fingerprint = string(&mut model, "fingerprint", 95, 95);
    if model.field_valid("fingerprint") && !FINGERPRINT.is_match(&fingerprint) {
        model.add(
            "fingerprint",
            "A SHA-256 certificate fingerprint is required",
            "value_error",
        );
    }
    let instance = session(&mut model, "instance");
    let mut signals = Vec::new();
    for mut child in model.objects("signals", false, 0, 16) {
        if !child.is_valid() {
            model.merge(child);
            continue;
        }
        let to = string(&mut child, "to", 1, 60);
        let session = session(&mut child, "session");
        if let Some(mut description) = child.required_object("description") {
            let kind = if description.field(&["type"]).is_none() {
                description.required_string("type")
            } else {
                description.literal("type", "", &["offer", "answer", "candidate"])
            };
            let sdp = string(&mut description, "sdp", 1, 65536);
            child.merge(description);
            signals.push(Signal {
                to,
                session,
                description: Description { r#type: kind, sdp },
            });
        }
        model.merge(child);
    }
    let acks = model.string_list("acks", 128);
    let mut paths = BTreeMap::new();
    if model.field(&["paths"]).is_some() {
        if let Some(mut child) = model.required_object("paths") {
            for key in child.keys() {
                let value = child.literal(&key, "", &["direct", "relay", "connecting"]);
                paths.insert(key, value);
            }
            model.merge(child);
        }
    }
    model.finish()?;
    Ok(Sync {
        peer_id,
        token,
        fingerprint: fingerprint.to_ascii_uppercase(),
        instance,
        signals,
        acks,
        paths,
    })
}
