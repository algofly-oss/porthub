//! The legacy machine model accepts nullable optional fields and records which
//! keys were supplied. Updates use that distinction to clear explicit nulls.
use crate::{
    error::{ApiError, ApiResult},
    input::Model,
};
use mongodb::bson::{doc, Bson, Document};
use serde_json::Value;
use std::collections::BTreeSet;

pub struct Input {
    pub data_id: Option<String>,
    pub name: String,
    pub hostname: Option<String>,
    pub enabled: Option<bool>,
    pub is_active: Option<bool>,
    pub public_base: Option<String>,
    pub rathole: Option<String>,
    pub domain: Option<String>,
    pub groups: Option<Vec<String>>,
    pub alerts: Option<bool>,
    pub private_domains: Option<Vec<super::private_domains::Entry>>,
    pub present: BTreeSet<String>,
}

pub fn parse(raw: Value) -> ApiResult<Input> {
    let private_domains = raw
        .get("private_domains")
        .map(super::private_domains::parse)
        .transpose()?;
    let present = raw
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default();
    let mut model = Model::new(raw)?;
    let data_id = model.optional_string("data_id");
    let name = model.required_string("name");
    model.string_length("name", &name, 1, None);
    let hostname = model.optional_string("hostname");
    let enabled = model.optional_bool("enabled");
    let is_active = model.optional_bool("is_active");
    let public_base = model.optional_string("client_setup_public_base_url");
    let rathole = model.optional_string("client_setup_rathole_server_address");
    let domain = model.optional_string("client_setup_service_domain");
    let groups = model.optional_strings("group_ids");
    let alerts = model.optional_bool("telegram_alerts_excluded");
    model.finish()?;
    Ok(Input {
        data_id,
        name,
        hostname,
        enabled,
        is_active,
        public_base,
        rathole,
        domain,
        groups,
        alerts,
        private_domains,
        present,
    })
}

pub fn optional_text(value: Option<&str>, label: &str, max: usize) -> ApiResult<String> {
    let value = value.unwrap_or_default().trim();
    if value.chars().count() > max {
        return Err(ApiError::bad_request(&format!(
            "{label} must be {max} characters or fewer"
        )));
    }
    Ok(value.to_owned())
}

pub fn public_base(value: Option<&str>) -> ApiResult<String> {
    let cleaned = optional_text(value, "PortHub public base URL", 512)?;
    if cleaned.is_empty() {
        return Ok(cleaned);
    }
    // Preserve the original urlsplit validation (including its permissive
    // authority parsing) rather than normalizing the operator's saved value.
    let split = cleaned
        .trim_start_matches(|c: char| c <= ' ')
        .replace(['\t', '\r', '\n'], "");
    let valid = split.split_once(':').is_some_and(|(scheme, rest)| {
        matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https")
            && rest.strip_prefix("//").is_some_and(|tail| {
                !tail
                    .split(['/', '?', '#'])
                    .next()
                    .unwrap_or_default()
                    .is_empty()
            })
    });
    if !valid {
        return Err(ApiError::bad_request(
            "PortHub public base URL must be an http(s) URL",
        ));
    }
    Ok(cleaned.trim_end_matches('/').to_owned())
}

/// Undo only values that still match this mutation. Runtime sync can update
/// hostname/presence while a gateway or firewall operation is in flight.
/// A single Mongo update pipeline avoids losing those concurrent writes.
pub fn recovery(previous: &Document, set: &Document, unset: &Document) -> Vec<Document> {
    let mut fields = Document::new();
    for key in set.keys().chain(unset.keys()) {
        let current = format!("${key}");
        let unchanged = match set.get(key) {
            Some(value) => Bson::Document(doc! {"$eq":[&current,{"$literal":value}]}),
            None => Bson::Document(doc! {"$eq":[{"$type":&current},"missing"]}),
        };
        let original = match previous.get(key) {
            Some(value) => Bson::Document(doc! {"$literal":value}),
            None => Bson::String("$$REMOVE".into()),
        };
        fields.insert(key, doc! {"$cond":[unchanged,original,current]});
    }
    vec![doc! {"$set":fields}]
}
