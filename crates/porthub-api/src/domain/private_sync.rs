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
    #[serde(skip_serializing_if = "String::is_empty")]
    pub stream_transport: String,
    #[serde(skip_serializing_if="is_false")]
    pub tor_exit: bool,
    #[serde(skip_serializing_if="Vec::is_empty")]
    pub lan_networks: Vec<String>,
    #[serde(skip_serializing_if="is_false")]
    pub lan_exit: bool,
    #[serde(skip_serializing_if="is_false")]
    pub application_proxy: bool,
    pub signals: Vec<Signal>,
    pub acks: Vec<String>,
    pub paths: BTreeMap<String, String>,
}
fn is_false(value:&bool)->bool {!*value}
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
    if model.field(&["tor_exit"]).is_some_and(|value| !value.is_boolean()) { model.add("tor_exit", "Expected a boolean", "type_error.bool"); }
    let tor_exit = if model.field(&["tor_exit"]).is_some() { model.required_bool("tor_exit") } else { false };
    let lan_networks = model.string_list("lan_networks", 32);
    if model.field(&["lan_exit"]).is_some_and(|value| !value.is_boolean()) {
        model.add("lan_exit", "Expected a boolean", "type_error.bool");
    }
    let lan_exit = model.optional_bool("lan_exit").unwrap_or(false);
    if model.field(&["application_proxy"]).is_some_and(|value|!value.is_boolean()) {
        model.add("application_proxy","Expected a boolean","type_error.bool");
    }
    let application_proxy=model.optional_bool("application_proxy").unwrap_or(false);
    for network in &lan_networks {
        if network.parse::<porthub_mesh::lan_routes::Network>().is_err() {
            model.add("lan_networks", "Expected a canonical private IPv4 network prefix", "value_error");
        }
    }
    let stream_transport = model.literal("stream_transport", "", &["", "quic1"]);
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
        stream_transport,
        tor_exit,
        lan_networks,
        lan_exit,
        application_proxy,
        signals,
        acks,
        paths,
    })
}
