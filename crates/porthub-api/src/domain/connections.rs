use crate::{error::ApiResult, input::Model, input_compat as compat};
use serde::Serialize;
use serde_json::{json, Value};
use std::net::Ipv4Addr;
#[derive(Debug, Serialize)]
pub struct Input {
    pub data_id: Option<String>,
    pub machine_id: String,
    pub service_name: String,
    pub service_description: Option<String>,
    pub internal_ip: String,
    pub internal_port: i64,
    pub external_port: i64,
    pub enabled: Option<bool>,
    pub auto_refresh_enabled: Option<bool>,
    pub auto_refresh_interval_minutes: Option<i64>,
}
pub fn parse(raw: Value) -> ApiResult<Input> {
    let mut m = Model::new(raw)?;
    for (primary, secondary) in [
        ("internalIp", "internal_ip"),
        ("autoRefreshEnabled", "auto_refresh_enabled"),
        (
            "autoRefreshIntervalMinutes",
            "auto_refresh_interval_minutes",
        ),
    ] {
        m.alias(primary, secondary);
    }
    m.optional_string("user_id");
    let data_id = m.optional_string("data_id");
    let machine_id = m.required_string("machine_id");
    let service_name = m.required_string("service_name");
    m.string_length("service_name", &service_name, 1, None);
    let service_description = if m.field(&["service_description"]).is_none() {
        Some(String::new())
    } else {
        m.optional_string("service_description")
    };
    let value = m
        .field(&["internalIp"])
        .filter(compat::truthy)
        .map(|value| compat::text(&value))
        .unwrap_or_else(|| "0.0.0.0".into());
    let value = compat::strip(&value);
    let internal_ip = if value.parse::<Ipv4Addr>().is_ok() {
        value.to_owned()
    } else if compat::hostname(value) {
        value.to_lowercase()
    } else {
        m.add(
            "internalIp",
            "Use a valid internal IPv4 address or hostname",
            "value_error",
        );
        String::new()
    };
    let internal_port = m.required_integer("internal_port", 1, 65535);
    let external_port = m.required_integer("external_port", 1, 65535);
    let enabled = if m.field(&["enabled"]).is_none() {
        Some(true)
    } else {
        m.optional_bool("enabled")
    };
    let auto_refresh_enabled = if m.field(&["autoRefreshEnabled"]).is_none() {
        Some(false)
    } else {
        m.optional_bool("autoRefreshEnabled")
    };
    let auto_refresh_interval_minutes = m.optional_integer("autoRefreshIntervalMinutes", 1, 10080);
    m.finish()?;
    Ok(Input {
        data_id,
        machine_id,
        service_name,
        service_description,
        internal_ip,
        internal_port,
        external_port,
        enabled,
        auto_refresh_enabled,
        auto_refresh_interval_minutes,
    })
}
#[derive(Serialize)]
pub struct Firewall {
    pub data_id: String,
    pub is_public: bool,
    pub allowed_ips: Vec<String>,
}
fn ipv4(value: &Value) -> Option<String> {
    match value {
        Value::Bool(value) => Some(Ipv4Addr::from(u32::from(*value)).to_string()),
        Value::Number(number) if !number.is_f64() => number
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(|value| Ipv4Addr::from(value).to_string()),
        Value::String(value) => value.parse::<Ipv4Addr>().ok().map(|ip| ip.to_string()),
        _ => None,
    }
}
pub fn firewall(raw: Value) -> ApiResult<Firewall> {
    let mut m = Model::new(raw)?;
    let data_id = m.required_string("data_id");
    let is_public = if m.field(&["is_public"]).is_none() {
        true
    } else {
        m.required_bool("is_public")
    };
    let mut allowed_ips = Vec::new();
    for (i, value) in m.list("allowed_ips").iter().enumerate() {
        if value.is_null() {
            m.add_index(
                "allowed_ips",
                i,
                "none is not an allowed value",
                "type_error.none.not_allowed",
            );
        } else if let Some(ip) = ipv4(value) {
            allowed_ips.push(ip);
        } else {
            m.add_index(
                "allowed_ips",
                i,
                "value is not a valid IPv4 address",
                "value_error.ipv4address",
            );
        }
    }
    if m.is_valid() && is_public && !allowed_ips.is_empty() {
        m.add(
            "__root__",
            "allowed_ips must be empty when is_public is true",
            "value_error",
        );
    }
    m.finish()?;
    Ok(Firewall {
        data_id,
        is_public,
        allowed_ips,
    })
}
pub fn snapshot(raw: Value) -> ApiResult<Value> {
    let mut m = Model::new(raw)?;
    let data_ids = match m.field(&["data_ids"]) {
        Some(Value::Null) => {
            m.list("data_ids");
            Vec::new()
        }
        _ => m.optional_strings("data_ids").unwrap_or_default(),
    };
    m.finish()?;
    Ok(json!({"data_ids":data_ids}))
}
