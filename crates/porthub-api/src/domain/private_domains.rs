use crate::error::{ApiError, ApiResult};
use mongodb::bson::{self, Bson, Document};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Entry {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub suffix: String,
    #[serde(default)]
    pub default: bool,
}

pub fn parse(value: &Value) -> ApiResult<Vec<Entry>> {
    let entries: Vec<Entry> = serde_json::from_value(value.clone()).map_err(|_| {
        ApiError::bad_request("Private DNS domains must be a list of host and suffix pairs")
    })?;
    if entries.is_empty() || entries.len() > 16 {
        return Err(ApiError::bad_request(
            "Keep the required default domain and use at most 15 additional domains",
        ));
    }
    let mut defaults = 0;
    let mut domains = HashSet::new();
    let mut normalized = Vec::with_capacity(entries.len());
    for mut entry in entries {
        if entry.default {
            defaults += 1;
            if !entry.host.is_empty() || !entry.suffix.is_empty() {
                return Err(ApiError::bad_request(
                    "The default domain is generated from the machine name and network suffix",
                ));
            }
            normalized.push(entry);
            continue;
        }
        entry.host = entry.host.trim().trim_end_matches('.').to_ascii_lowercase();
        entry.suffix = entry.suffix.trim().trim_matches('.').to_ascii_lowercase();
        validate_name(&entry.host, "Domain host")?;
        validate_name(&entry.suffix, "Domain suffix")?;
        let full = format!("{}.{}", entry.host, entry.suffix);
        if !domains.insert(full) {
            return Err(ApiError::bad_request("Private DNS domains must be unique"));
        }
        normalized.push(entry);
    }
    if defaults != 1 {
        return Err(ApiError::bad_request(
            "The generated default private domain is required exactly once",
        ));
    }
    Ok(normalized)
}

fn validate_name(value: &str, label: &str) -> ApiResult<()> {
    if value.is_empty()
        || value.len() > 253
        || value.split('.').any(|part| {
            part.is_empty()
                || part.len() > 63
                || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || part.starts_with('-')
                || part.ends_with('-')
        })
    {
        return Err(ApiError::bad_request(&format!(
            "{label} must contain valid DNS labels"
        )));
    }
    Ok(())
}

pub fn from_document(machine: &Document) -> Vec<Entry> {
    machine
        .get_array("private_domains")
        .into_iter()
        .flatten()
        .filter_map(|value| {
            let Bson::Document(doc) = value else {
                return None;
            };
            Some(Entry {
                host: doc.get_str("host").unwrap_or_default().to_owned(),
                suffix: doc.get_str("suffix").unwrap_or_default().to_owned(),
                default: doc.get_bool("default").unwrap_or(false),
            })
        })
        .collect()
}

pub fn to_bson(entries: &[Entry]) -> Bson {
    bson::to_bson(entries).expect("private DNS domain entries are serializable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keeps_required_default_and_normalizes_custom_domains() {
        let domains = match parse(&json!([
            {"default":true},
            {"host":"Condor","suffix":".PHUB.io."}
        ])) {
            Ok(domains) => domains,
            Err(_) => panic!("valid private domains were rejected"),
        };
        assert_eq!(domains[1].host, "condor");
        assert_eq!(domains[1].suffix, "phub.io");
    }

    #[test]
    fn rejects_missing_default_invalid_names_and_duplicates() {
        assert!(parse(&json!([{ "host":"condor", "suffix":"phub.io" }])).is_err());
        assert!(
            parse(&json!([{ "default":true }, { "host":"bad/name", "suffix":"phub.io" }])).is_err()
        );
        assert!(parse(&json!([{ "default":true }, { "host":"condor", "suffix":"phub.io" }, { "host":"CONDOR", "suffix":"PHUB.IO" }])).is_err());
    }
}
