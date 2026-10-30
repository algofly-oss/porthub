use crate::{
    error::ApiResult,
    input::Model,
    input_compat::{self as compat},
    store,
};
use mongodb::bson::Document;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;

#[derive(Debug, Serialize)]
pub struct Input {
    pub data_id: Option<String>,
    pub name: String,
    pub group: String,
    pub description: Option<String>,
    pub hosts: Vec<String>,
    pub target_mode: String,
    pub target_url: Option<String>,
    pub entry_points: Vec<String>,
    pub enabled: Option<bool>,
    pub connection_data_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bindings: Option<Vec<BindingInput>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing: Option<porthub_runtime::upstreams::Routing>,
}

fn list(model: &mut Model, key: &str, default: Vec<Value>, lower: bool) -> Vec<String> {
    let raw = model
        .field(&[key])
        .filter(compat::truthy)
        .unwrap_or(Value::Array(default));
    let items = match compat::items(raw) {
        Ok(items) => items,
        Err(error) => {
            model.add(key, &error, "type_error");
            return Vec::new();
        }
    };
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for item in items {
        let text = if compat::truthy(&item) {
            compat::text(&item)
        } else {
            String::new()
        };
        let mut text = compat::strip(&text).to_owned();
        if lower {
            text = text.to_lowercase();
        }
        if text.is_empty() {
            continue;
        }
        if lower && !compat::hostname(&text) {
            model.add(key, &format!("Invalid host: {text}"), "value_error");
            return Vec::new();
        }
        if seen.insert(text.clone()) {
            result.push(text);
        }
    }
    result
}
pub fn parse(raw: Value) -> ApiResult<Input> {
    if raw.get("bindings").is_some() {
        return parse_multiple(raw);
    }
    let mut model = Model::new(raw)?;
    for (primary, secondary) in [
        ("targetMode", "target_mode"),
        ("targetUrl", "target_url"),
        ("entryPoints", "entry_points"),
        ("connectionDataId", "connection_data_id"),
    ] {
        model.alias(primary, secondary);
    }
    let _user = model.optional_string("user_id");
    let data_id = model.optional_string("data_id");
    let name = model.required_string("name");
    model.string_length("name", &name, 1, None);
    let group = if model.field(&["group"]).is_some() {
        model.required_string("group")
    } else {
        String::new()
    };
    model.string_length("group", &group, 0, Some(80));
    let description = if model.field(&["description"]).is_some() {
        model.optional_string("description")
    } else {
        Some(String::new())
    };
    let hosts = list(&mut model, "hosts", Vec::new(), true);
    if hosts.is_empty() && model.field_valid("hosts") {
        model.add("hosts", "At least one host is required", "value_error");
    }
    let mode = model
        .field(&["targetMode"])
        .filter(compat::truthy)
        .map(|v| compat::text(&v))
        .unwrap_or_else(|| "manual".into());
    let target_mode = compat::strip(&mode).to_lowercase();
    if !["manual", "connection"].contains(&target_mode.as_str()) {
        model.add(
            "targetMode",
            "target_mode must be either manual or connection",
            "value_error",
        );
    }
    let mut target_url = None;
    if let Some(target) = model
        .field(&["targetUrl"])
        .filter(|value| !value.is_null() && value != &json!(""))
    {
        let text = compat::text(&target);
        let text = compat::strip(&text);
        let scheme = text
            .split_once("://")
            .map(|(scheme, _)| scheme)
            .filter(|scheme| {
                scheme
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphabetic)
                    && scheme
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
            });
        if scheme.is_some() {
            target_url = Some(text.to_owned());
        } else {
            model.add(
                "targetUrl",
                "target_url must include a scheme like http:// or tcp://",
                "value_error",
            );
        }
    }
    let mut entry_points = list(&mut model, "entryPoints", vec![json!("web")], false);
    if entry_points.is_empty() && model.field_valid("entryPoints") {
        entry_points.push("web".into());
    }
    let enabled = if model.field(&["enabled"]).is_some() {
        model.optional_bool("enabled")
    } else {
        Some(true)
    };
    let connection_data_id = model.optional_string("connectionDataId");
    if model.is_valid() {
        let target = target_url.as_deref().unwrap_or("");
        let connection = connection_data_id
            .as_deref()
            .map(compat::strip)
            .unwrap_or("");
        let error = match target_mode.as_str() {
            "connection" if connection.is_empty() => {
                Some("connectionDataId is required when targetMode is connection")
            }
            "manual" if target.is_empty() => {
                Some("targetUrl is required when targetMode is manual")
            }
            "manual"
                if !target.to_ascii_lowercase().starts_with("http://")
                    && !target.to_ascii_lowercase().starts_with("https://") =>
            {
                Some("targetUrl must use http:// or https:// when targetMode is manual")
            }
            "connection" if target.is_empty() => {
                Some("targetUrl is required when targetMode is connection")
            }
            _ => None,
        };
        if let Some(error) = error {
            model.add("__root__", error, "value_error");
        }
    }
    model.finish()?;
    Ok(Input {
        data_id,
        name,
        group,
        description,
        hosts,
        target_mode,
        target_url,
        entry_points,
        enabled,
        connection_data_id,
        bindings: None,
        routing: None,
    })
}

pub fn serialize(route: &Document) -> Value {
    let strings = |key: &str, lower: bool| {
        route
            .get_array(key)
            .into_iter()
            .flatten()
            .map(store::json)
            .map(|value| compat::text(&value))
            .map(|text| {
                if lower {
                    compat::strip(&text).to_lowercase()
                } else {
                    compat::strip(&text).to_owned()
                }
            })
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
    };
    let entries = strings("entry_points", false);
    let mode = compat::strip(store::string(route, "target_mode"));
    json!({"_id":store::id(route.get("_id")),"user_id":store::id(route.get("user_id")),"name":compat::strip(store::string(route,"name")),
        "group":compat::strip(store::string(route,"group")),"description":compat::strip(store::string(route,"description")),"hosts":strings("hosts",true),
        "target_mode":if mode.is_empty() {"manual"} else {mode},"target_url":compat::strip(store::string(route,"target_url")),
        "entry_points":if entries.is_empty() {vec!["web".to_owned()]} else {entries},"enabled":route.get_bool("enabled")!=Ok(false),
        "connection":route.get("connection").map(store::json).filter(compat::truthy).unwrap_or(Value::Null),
        "created_at":store::field(route,"created_at"),"updated_at":store::field(route,"updated_at"),
        "temporary":route.get_bool("temporary").unwrap_or(false),"managed_by":store::field(route,"managed_by"),
        "exposure_id":store::field(route,"exposure_id"),"lease_expires_at":store::field(route,"lease_expires_at"),
        "bindings":route.get("bindings").map(store::json).unwrap_or(Value::Null),
        "routing":route.get("routing").map(store::json).unwrap_or(Value::Null)})
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingInput {
    #[serde(default = "binding_id")]
    pub id: String,
    #[serde(default)]
    pub label: String,
    pub target_mode: String,
    #[serde(default)]
    pub target_url: Option<String>,
    #[serde(default)]
    pub connection_data_id: Option<String>,
    #[serde(default = "one")]
    pub priority: u32,
    #[serde(default = "one")]
    pub weight: u32,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub pass_host: Option<bool>,
    #[serde(default)]
    pub health_path: Option<String>,
}
fn binding_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
fn one() -> u32 {
    1
}
fn yes() -> bool {
    true
}
fn parse_multiple(mut raw: Value) -> ApiResult<Input> {
    use crate::error::ApiError;
    let bindings: Vec<BindingInput> = serde_json::from_value(raw["bindings"].clone())
        .map_err(|e| ApiError::bad_request(&format!("Invalid bindings: {e}")))?;
    if bindings.is_empty() || bindings.len() > 128 {
        return Err(ApiError::bad_request("Provide between 1 and 128 bindings"));
    }
    let routing: porthub_runtime::upstreams::Routing =
        serde_json::from_value(raw.get("routing").cloned().unwrap_or_else(|| json!({})))
            .map_err(|e| ApiError::bad_request(&format!("Invalid routing settings: {e}")))?;
    routing
        .validate()
        .map_err(|e| ApiError::bad_request(&e.to_string()))?;
    let mut ids = HashSet::new();
    let mut targets = HashSet::new();
    for b in &bindings {
        let fail = |message: &str| {
            ApiError::bad_request(&format!(
                "Binding {}: {message}",
                b.label.chars().take(80).collect::<String>()
            ))
        };
        if b.id.is_empty()
            || b.id.len() > 80
            || !b
                .id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
            || !ids.insert(&b.id)
        {
            return Err(fail("IDs must be unique identifiers"));
        }
        if b.label.len() > 120
            || !(1..=10000).contains(&b.priority)
            || !(1..=100).contains(&b.weight)
        {
            return Err(fail(
                "Label must be at most 120 bytes, priority 1–10000, weight 1–100",
            ));
        }
        let key = match b.target_mode.as_str() {
            "manual" => {
                let text = b.target_url.as_deref().unwrap_or("").trim();
                let url =
                    url::Url::parse(text).map_err(|_| fail("Enter a valid HTTP or HTTPS URL"))?;
                if !matches!(url.scheme(), "http" | "https")
                    || url.host_str().is_none()
                    || url.fragment().is_some()
                {
                    return Err(fail("Enter an HTTP or HTTPS URL without a fragment"));
                }
                format!("url:{url}")
            }
            "connection" => {
                let id = b.connection_data_id.as_deref().unwrap_or("");
                crate::domain::workspaces::object_id(id, "Invalid machine port binding")?;
                format!("connection:{}", id.to_lowercase())
            }
            _ => return Err(fail("Type must be manual or connection")),
        };
        if !targets.insert(key) {
            return Err(fail("This target is already in the binding list"));
        }
        if let Some(path) = &b.health_path {
            let mut health = routing.health.clone();
            health.path = path.clone();
            health.validate().map_err(|e| fail(&e.to_string()))?;
        }
    }
    let object = raw
        .as_object_mut()
        .ok_or_else(|| ApiError::bad_request("Expected proxy settings"))?;
    object.remove("bindings");
    object.remove("routing");
    // Use the compatibility parser for common fields without letting old
    // single-target aliases override the explicit multi-binding configuration.
    object.insert("targetMode".into(), json!("manual"));
    object.insert("targetUrl".into(), json!("http://placeholder.invalid"));
    object.remove("connectionDataId");
    object.remove("connection_data_id");
    let mut input = parse(raw)?;
    let first = &bindings[0];
    input.target_mode = first.target_mode.clone();
    input.target_url = first.target_url.clone();
    input.connection_data_id = first.connection_data_id.clone();
    input.bindings = Some(bindings);
    input.routing = Some(routing);
    Ok(input)
}
