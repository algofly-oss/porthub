//! Serialization shared by inventory routes, realtime updates and operator
//! reports. Raw Mongo records (including private credentials) are never returned.
use crate::{App, store};
use mongodb::bson::{Bson, DateTime, Document, oid::ObjectId};
use serde_json::{Value, json};
use std::collections::HashSet;

pub fn default_field(document: &Document, key: &str, default: Value) -> Value {
    document.get(key).map(store::json).unwrap_or(default)
}

pub fn hostname(machine: &Document) -> String {
    ["hostname_override", "client_hostname", "hostname"]
        .iter()
        .map(|key| store::string(machine, key).trim())
        .find(|name| !name.is_empty())
        .unwrap_or("")
        .to_owned()
}

pub fn group_ids(machine: &Document) -> Vec<ObjectId> {
    let mut seen = HashSet::new();
    let mut groups: Vec<ObjectId> = machine
        .get_array("group_ids")
        .into_iter()
        .flatten()
        .filter_map(|value| match value {
            Bson::ObjectId(id) => Some(*id),
            Bson::String(value) => ObjectId::parse_str(value).ok(),
            _ => None,
        })
        .filter(|id| seen.insert(*id))
        .collect();
    if groups.is_empty() {
        let value = machine.get("group_id");
        if let Some(id) = value.and_then(|value| match value {
            Bson::ObjectId(id) => Some(*id),
            Bson::String(value) => ObjectId::parse_str(value).ok(),
            _ => None,
        }) {
            groups.push(id);
        }
    }
    groups
}

pub fn status(app: &App, machine: &Document) -> &'static str {
    status_at(app, machine, DateTime::now())
}

pub fn status_at(app: &App, machine: &Document, now: DateTime) -> &'static str {
    if machine.get_bool("enabled") == Ok(false) {
        return "disabled";
    }
    let seen = machine
        .get_datetime("last_seen_at")
        .map(|date| date.timestamp_millis())
        .unwrap_or(i64::MIN);
    if seen
        < now
            .timestamp_millis()
            .saturating_sub(app.config.machine_online_ttl_millis)
    {
        return "offline";
    }
    if machine.get_bool("auth_required").unwrap_or(false) {
        "auth_required"
    } else {
        "online"
    }
}

pub fn machine(app: &App, machine: &Document) -> Value {
    let status = status(app, machine);
    let version = store::string(machine, "client_version").trim();
    let request = store::string(machine, "client_update_request_id").trim();
    let handled = store::string(machine, "client_update_last_handled_request_id").trim();
    let mut output = json!({
        "_id":store::id(machine.get("_id")),"user_id":store::id(machine.get("user_id")),"name":default_field(machine,"name",json!("")),
        "aliases":machine.get_array("aliases").cloned().unwrap_or_default().iter().map(store::json).collect::<Vec<_>>(),
        "private_domains":crate::domain::private_domains::from_document(machine),
        "hostname":hostname(machine),"group_ids":group_ids(machine).iter().map(|id|id.to_hex()).collect::<Vec<_>>(),
        "enabled":default_field(machine,"enabled",json!(true)),"telegram_alerts_excluded":machine.get_bool("telegram_alerts_excluded").unwrap_or(false),
        "local_ip":default_field(machine,"local_ip",default_field(machine,"ip_address",json!(""))),"public_ip":default_field(machine,"public_ip",json!("")),
        "token":default_field(machine,"token",json!("")),"is_active":matches!(status,"online"|"auth_required"),"connection_status":status,
        "auth_required":status=="auth_required","client_version":version,"latest_client_version":app.config.client_version,
        "client_update_available":!version.is_empty() && version!=app.config.client_version,"client_update_requested":!request.is_empty() && request!=handled,
        "client_update_request_id":request,
    });
    for key in [
        "client_hostname",
        "client_os",
        "client_arch",
        "client_os_id",
        "client_os_name",
        "client_country",
        "hostname_override",
        "client_setup_public_base_url",
        "client_setup_rathole_server_address",
        "client_setup_service_domain",
        "client_update_target_version",
    ] {
        output[key] = json!(store::string(machine, key).trim());
    }
    for key in [
        "client_update_requested_at",
        "client_updated_at",
        "last_seen_at",
        "created_at",
        "updated_at",
    ] {
        output[key] = store::field(machine, key);
    }
    output
}

pub fn connection(app: &App, connection: &Document, machine: Option<&Document>) -> Value {
    let mut output = json!({
        "_id":store::id(connection.get("_id")),"user_id":store::id(connection.get("user_id")),"machine_id":store::id(connection.get("machine_id")),
        "service_name":default_field(connection,"service_name",json!("")),"service_description":default_field(connection,"service_description",json!("")),
        "internal_ip":default_field(connection,"internal_ip",default_field(connection,"internalIp",json!("0.0.0.0"))),
        "internal_port":store::field(connection,"internal_port"),"external_port":store::field(connection,"external_port"),
        "external_bind_ip":default_field(connection,"external_bind_ip",json!("0.0.0.0")),
        "enabled":default_field(connection,"enabled",json!(true)),"auto_refresh_enabled":default_field(connection,"auto_refresh_enabled",json!(false)),
        "temporary":default_field(connection,"temporary",json!(false)),"managed_by":default_field(connection,"managed_by",Value::Null),
        "exposure_id":default_field(connection,"exposure_id",Value::Null),"lease_expires_at":default_field(connection,"lease_expires_at",Value::Null),
        "firewall":crate::firewall::policy(connection),
        "public_access":{"mode":connection.get_document("public_access").ok().map(|value| if value.get_bool("pin") == Ok(true) {"pin"} else {"key"}).unwrap_or("off")},
    });
    for key in [
        "auto_refresh_interval_minutes",
        "auto_refreshed_at",
        "auto_refresh_next_at",
        "created_at",
        "updated_at",
    ] {
        output[key] = store::field(connection, key);
    }
    if let Some(machine) = machine {
        let status = status(app, machine);
        output["machine_name"] = default_field(machine, "name", json!(""));
        output["machine_hostname"] = json!(hostname(machine));
        output["machine_local_ip"] = default_field(
            machine,
            "local_ip",
            default_field(machine, "ip_address", json!("")),
        );
        output["machine_public_ip"] = default_field(machine, "public_ip", json!(""));
        output["machine_enabled"] = default_field(machine, "enabled", json!(true));
        output["machine_is_active"] = json!(matches!(status, "online" | "auth_required"));
        output["machine_connection_status"] = json!(status);
    } else {
        output["machine_name"] = default_field(connection, "host_name", json!(""));
        output["machine_hostname"] = default_field(connection, "host_id", json!(""));
        output["machine_local_ip"] = default_field(connection, "host_ip", json!(""));
        output["machine_public_ip"] = json!("");
        output["machine_enabled"] = json!(true);
        output["machine_is_active"] = json!(false);
        output["machine_connection_status"] = json!("unknown");
    }
    output
}
