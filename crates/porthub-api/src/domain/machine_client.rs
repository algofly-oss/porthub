//! Machine-authenticated configuration and presence. The legacy file format
//! remains readable during staged agent upgrades; no Go process is involved.
use crate::{
    error::{ApiError, ApiResult},
    generated, store, App,
};
use axum::http::{HeaderMap, StatusCode};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, Bson, DateTime, Document};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

fn should_auto_update(
    version: &str,
    latest: &str,
    request_id: &str,
    request_target: &str,
    handled_id: &str,
) -> bool {
    let outdated = if latest.is_empty() || version == latest {
        false
    } else if version.is_empty() {
        // Older native agents used the authenticated client sync endpoint
        // before reporting their release version. Their sync itself proves
        // they are native clients and can consume the gateway update headers.
        true
    } else {
        match (numeric_version(version), numeric_version(latest)) {
            (Some(current), Some(target)) => current < target,
            _ => true,
        }
    };
    outdated && (request_id.is_empty() || request_id == handled_id || request_target != latest)
}

fn update_request_completed(version: &str, target: &str, request_id: &str, handled: &str) -> bool {
    !request_id.is_empty() && (handled == request_id || !target.is_empty() && version == target)
}

fn numeric_version(value: &str) -> Option<Vec<u64>> {
    let parts = value
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (!parts.is_empty()).then_some(parts)
}

fn should_replace_reported_version(current: &str, incoming: &str) -> bool {
    if incoming.is_empty() {
        return false;
    }
    // Keep a release version if a stale legacy/hash build reports after it.
    // A numbered release can still replace it, including an intentional
    // downgrade, so the inventory reflects an actual release transition.
    numeric_version(current).is_none() || numeric_version(incoming).is_some()
}

pub async fn authenticate(app: &App, id: &str, token: &str) -> ApiResult<Document> {
    let id = super::workspaces::object_id(id, "Invalid machine id")?;
    let machine = app
        .collection("machines")
        .find_one(doc! {"_id":id,"token":token})
        .await?;
    let gone = || {
        ApiError::new(StatusCode::GONE, "Machine deleted")
            .header("x-porthub-machine-deleted", "true")
    };
    let machine = machine.ok_or_else(gone)?;
    let retired = crate::account_delete::retiring_owners(app).await?;
    if machine
        .get("user_id")
        .is_some_and(|id| retired.contains(id))
    {
        return Err(gone());
    }
    if machine.get_bool("deletion_pending").unwrap_or(false) {
        return Err(gone());
    }
    if machine.get_bool("enabled") == Ok(false) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "Machine disabled")
            .header("x-porthub-machine-disabled", "true"));
    }
    Ok(machine)
}
pub async fn authenticate_legacy(app: &App, id: &str, token: &str) -> ApiResult<Document> {
    let id = super::workspaces::object_id(id, "Invalid machine id")?;
    let machine = app
        .collection("machines")
        .find_one(doc! {"_id":id,"token":token})
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "Invalid machine credentials"))?;
    if machine.get_bool("deletion_pending") == Ok(true) {
        return Err(ApiError::new(StatusCode::GONE, "Machine deleted")
            .header("x-porthub-machine-deleted", "true"));
    }
    Ok(machine)
}

const SETUP: [(&str, &str); 3] = [
    ("public_base_url", "client_setup_public_base_url"),
    (
        "rathole_server_address",
        "client_setup_rathole_server_address",
    ),
    ("service_domain", "client_setup_service_domain"),
];

pub struct View<'a> {
    pub headers: &'a HeaderMap,
    pub query: &'a HashMap<String, String>,
}
impl View<'_> {
    pub fn setup(&self, app: &App, machine: &Document) -> Value {
        let empty = HashMap::new();
        let defaults = View {
            headers: self.headers,
            query: &empty,
        };
        let none = Document::new();
        let mut overrides = serde_json::Map::new();
        for (key, field) in SETUP {
            overrides.insert(key.into(), json!(self.overridden(machine, field)));
        }
        json!({"defaults":{"public_base_url":defaults.public_base(app,&none),"rathole_server_address":defaults.server_address(app,&none),"service_domain":app.config.service_domain.trim()},
            "overrides":overrides,"effective":{"public_base_url":self.public_base(app,machine),"rathole_server_address":self.server_address(app,machine),"service_domain":self.domain(app,machine)}})
    }
    fn overridden(&self, machine: &Document, field: &str) -> String {
        SETUP
            .iter()
            .find(|(_, key)| *key == field)
            .and_then(|(query, _)| self.query.get(*query))
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| store::string(machine, field).trim())
            .to_owned()
    }
    pub fn public_base(&self, app: &App, machine: &Document) -> String {
        let override_base = self.overridden(machine, "client_setup_public_base_url");
        let base = if !override_base.is_empty() {
            override_base
        } else if !app.config.public_base_url.trim().is_empty() {
            app.config.public_base_url.trim().into()
        } else {
            let host = self
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("localhost");
            let scheme = self
                .headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(str::trim)
                .filter(|v| *v == "https")
                .unwrap_or("http");
            format!("{scheme}://{host}")
        };
        base.trim_end_matches('/').into()
    }
    pub fn server_address(&self, app: &App, machine: &Document) -> String {
        let override_address = self.overridden(machine, "client_setup_rathole_server_address");
        if !override_address.is_empty() {
            return override_address;
        }
        if !app.config.rathole_server_address.trim().is_empty() {
            return app.config.rathole_server_address.trim().into();
        }
        let base = self.public_base(app, machine);
        let url = reqwest::Url::parse(&base).ok();
        let host = url
            .as_ref()
            .and_then(|url| url.host_str())
            .unwrap_or("localhost")
            .trim_start_matches('[')
            .trim_end_matches(']');
        let port = app
            .config
            .rathole_port
            .or_else(|| url.as_ref().and_then(|url| url.port_or_known_default()))
            .unwrap_or(443);
        format!(
            "{}:{}",
            if host.contains(':') {
                format!("[{host}]")
            } else {
                host.to_owned()
            },
            port
        )
    }
    pub fn domain(&self, app: &App, machine: &Document) -> String {
        let value = self.overridden(machine, "client_setup_service_domain");
        if value.is_empty() {
            app.config.service_domain.clone()
        } else {
            value
        }
    }
    fn setup_query(&self, mut url: String) -> String {
        for (query, _) in SETUP {
            if let Some(value) = self.query.get(query).filter(|v| !v.trim().is_empty()) {
                url.push(if url.contains('?') { '&' } else { '?' });
                url.push_str(
                    reqwest::Url::parse_with_params("http://unused/", [(query, value)])
                        .unwrap()
                        .query()
                        .unwrap(),
                );
            }
        }
        url
    }
    pub fn endpoints(&self, app: &App, machine: &Document) -> Value {
        let api = format!("{}/api", self.public_base(app, machine));
        let id = store::id(machine.get("_id"));
        let token = store::string(machine, "token");
        let mut credentials = reqwest::Url::parse("http://unused/").unwrap();
        credentials
            .query_pairs_mut()
            .append_pair("machine_id", &id)
            .append_pair("token", token);
        let credentials = credentials.query().unwrap();
        let base = format!("{api}/machines/{id}/{token}");
        let mut endpoints = json!({"auth":format!("{api}/machines/client/auth"),"sync":format!("{api}/machines/client/sync"),
            "log_stream_upload":format!("{api}/machines/client/logs"),"legacy_sync":format!("{api}/machines/sync"),
            "install_script":format!("{api}/install/{token}"),"bootstrap_script":format!("{base}/install.sh"),
            "client_cli":format!("{base}/downloads/porthub"),"client_script":format!("{base}/client.sh"),"socket_path":"/socket.io"});
        for (key, path) in [
            ("config", "config"),
            ("config_toml", "config.toml"),
            ("changes", "changes"),
            ("changes_toml", "changes.toml"),
            ("log_stream_status", "log-stream"),
        ] {
            endpoints[key] = json!(format!("{api}/machines/client/{path}?{credentials}"));
        }
        for target in [
            "x86_64",
            "darwin_x86_64",
            "darwin_arm64",
            "arm64",
            "armhf",
            "armv7",
        ] {
            endpoints[format!("rathole_{target}")] =
                json!(format!("{base}/downloads/rathole/{target}"));
        }
        for (key, value) in endpoints.as_object_mut().unwrap() {
            if ![
                "auth",
                "sync",
                "log_stream_upload",
                "legacy_sync",
                "log_stream_status",
                "socket_path",
            ]
            .contains(&key.as_str())
            {
                *value = json!(self.setup_query(value.as_str().unwrap().into()));
            }
        }
        endpoints
    }
    fn tunnel_url(&self, app: &App, machine: &Document) -> ApiResult<String> {
        let mut url = reqwest::Url::parse(&self.public_base(app, machine))
            .map_err(|_| ApiError::bad_request("Invalid PortHub public base URL"))?;
        let scheme = match url.scheme() {
            "https" => "wss",
            "http" => "ws",
            _ => return Err(ApiError::bad_request("Invalid PortHub public base URL")),
        };
        url.set_scheme(scheme)
            .map_err(|_| ApiError::bad_request("Invalid tunnel URL"))?;
        url.set_path(&format!("{}/api/tunnel", url.path().trim_end_matches('/')));
        Ok(url.into())
    }
    fn fallbacks(&self, app: &App, machine: &Document) -> Vec<String> {
        let mut values = Vec::new();
        if let Ok(mut base) = reqwest::Url::parse(&self.public_base(app, machine)) {
            if base.scheme() == "https" {
                if !app.config.tunnel_http_base_url.trim().is_empty() {
                    if let Ok(url) = reqwest::Url::parse(app.config.tunnel_http_base_url.trim()) {
                        if url.scheme() == "http" && url.host_str().is_some() {
                            base = url;
                        }
                    }
                } else if base.port().is_none_or(|port| port == 443) {
                    let _ = base.set_scheme("http");
                    let _ = base.set_port(None);
                }
                if base.scheme() == "http" {
                    base.set_path(&format!("{}/api/tunnel", base.path().trim_end_matches('/')));
                    values.push(base.to_string());
                }
            }
        }
        for base in &app.config.tunnel_fallback_base_urls {
            if let Ok(mut url) = reqwest::Url::parse(base.trim_end_matches('/')) {
                if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() {
                    url.set_path(&format!("{}/api/tunnel", url.path().trim_end_matches('/')));
                    let value = url.to_string();
                    if !values.contains(&value) {
                        values.push(value);
                    }
                }
            }
        }
        values
    }
}

fn local_address(connection: &Document) -> String {
    let ip = connection
        .get("internal_ip")
        .or_else(|| connection.get("internalIp"));
    let ip = match ip {
        Some(Bson::String(ip)) => ip.trim(),
        _ => "0.0.0.0",
    };
    let ip = if ip.is_empty() { "0.0.0.0" } else { ip };
    let host = if ip.contains(':') && !ip.starts_with('[') {
        format!("[{ip}]")
    } else {
        ip.into()
    };
    format!("{host}:{}", store::field(connection, "internal_port"))
}
fn connection_value(connection: &Document, machine: &Document) -> Value {
    json!({"_id":store::id(connection.get("_id")),"machine_id":store::id(machine.get("_id")),
        "service_key":generated::service_key(connection),"service_name":super::inventory::default_field(connection,"service_name",json!("")),
        "service_description":super::inventory::default_field(connection,"service_description",json!("")),
        "internal_ip":connection.get("internal_ip").or_else(||connection.get("internalIp")).map(store::json).unwrap_or(json!("0.0.0.0")),
        "internal_port":store::field(connection,"internal_port"),"external_port":store::field(connection,"external_port"),
        "enabled":super::inventory::default_field(connection,"enabled",json!(true)),"local_address":local_address(connection)})
}

/// Canonical, ASCII JSON retains the configuration digests used by installed
/// clients, including non-ASCII service names and supplementary Unicode planes.
pub fn canonical_json(mut value: Value) -> String {
    use std::fmt::Write;
    value.sort_all_objects();
    let serialized = value.to_string();
    let mut output = String::with_capacity(serialized.len());
    for character in serialized.chars() {
        if character.is_ascii() {
            output.push(character);
        } else {
            for unit in character.encode_utf16(&mut [0; 2]).iter() {
                write!(output, "\\u{unit:04x}").unwrap();
            }
        }
    }
    output
}

pub fn version(machine: &Document, connections: &[Document]) -> String {
    let connections: Vec<Value> = connections
        .iter()
        .map(|c| {
            let mut value = connection_value(c, machine);
            let object = value.as_object_mut().unwrap();
            for key in ["machine_id", "service_key", "local_address"] {
                object.remove(key);
            }
            object.insert("updated_at".into(), store::field(c, "updated_at"));
            value
        })
        .collect();
    let payload = json!({"machine_id":store::id(machine.get("_id")),"token":super::inventory::default_field(machine,"token",json!("")),
        "enabled":machine.get_bool("enabled")!=Ok(false),
        "client_setup_rathole_server_address":store::string(machine,"client_setup_rathole_server_address").trim(),"connections":connections});
    format!("{:x}", Sha256::digest(canonical_json(payload).as_bytes()))
}

fn quote(value: &str) -> String {
    toml::Value::String(value.into()).to_string()
}
pub fn render(
    app: &App,
    machine: &Document,
    connections: &[Document],
    view: &View<'_>,
) -> ApiResult<String> {
    let mut lines = vec![
        "# Managed by PortHub. Manual changes will be overwritten.".to_owned(),
        "[client]".into(),
        format!("remote_addr = {}", quote(&view.tunnel_url(app, machine)?)),
        String::new(),
    ];
    if let Some(endpoint) = crate::gateway_origin::tunnel_endpoint(app) {
        let direct = url::Url::parse(&endpoint).expect("validated origin");
        let primary = url::Url::parse(&view.tunnel_url(app, machine)?)
            .map_err(|_| ApiError::bad_request("Invalid gateway authority"))?;
        let modern = view
            .headers
            .get("x-porthub-agent-protocol")
            .and_then(|value| value.to_str().ok())
            == Some("rust-v1");
        let pin = crate::gateway_origin::metadata(app).filter(|_| direct.scheme() == "https");
        // Existing Go clients require HTTPS plus a key pin for this field.
        // Native clients explicitly negotiate the broader origin/proxy format.
        if modern || pin.is_some() {
            lines.push(format!("direct_addr = {}", quote(&endpoint)));
            if let Some(host) = primary.host_str() {
                lines.push(format!("direct_host = {}", quote(host)));
            }
            if direct.scheme() == "https" {
                if let Some(metadata) = pin {
                    lines.push(format!(
                        "direct_spki_sha256 = {}",
                        quote(&metadata.spki_sha256)
                    ));
                }
            }
            // An explicitly configured origin may terminate TLS or support only
            // standard WebSocket Upgrade. Probe these alternatives before traffic.
            if modern && app.config.gateway_advertised_url.is_some() {
                lines.push("direct_proxy_fallback = true".into());
            }
            lines.push(String::new());
        }
    }
    let fallback = view.fallbacks(app, machine);
    if !fallback.is_empty() {
        lines.push(format!(
            "fallback_addrs = [{}]",
            fallback
                .iter()
                .map(|s| quote(s))
                .collect::<Vec<_>>()
                .join(",")
        ));
        lines.push(String::new());
    }
    for connection in connections {
        if connection.get_bool("enabled") == Ok(false) {
            continue;
        }
        lines.extend([
            format!("[client.services.{}]", generated::service_key(connection)),
            format!("token = {}", quote(store::string(machine, "token"))),
            format!("local_addr = {}", quote(&local_address(connection))),
            String::new(),
        ]);
    }
    Ok(format!("{}\n", lines.join("\n").trim_end()))
}

pub async fn bundle(app: &App, machine: &Document, view: &View<'_>) -> ApiResult<Value> {
    let connections: Vec<Document> = app
        .collection("connections")
        .find(doc! {"machine_id":machine.get("_id")})
        .sort(doc! {"external_port":1,"_id":1})
        .await?
        .try_collect()
        .await?;
    let rendered = render(app, machine, &connections, view)?;
    let version = format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{}|porthub.tcp.v1|{rendered}",
                version(machine, &connections)
            )
            .as_bytes()
        )
    );
    Ok(
        json!({"version":version,"machine_id":store::id(machine.get("_id")),"machine_name":super::inventory::default_field(machine,"name",json!("")),
        "hostname":super::inventory::hostname(machine),"enabled":machine.get_bool("enabled")!=Ok(false),
        "rathole_server_address":view.server_address(app,machine),"service_domain":view.domain(app,machine),
        "connections":connections.iter().map(|c|connection_value(c,machine)).collect::<Vec<_>>(),
        "files":{"client.toml":rendered},"generated_at":store::json(&Bson::DateTime(DateTime::now()))}),
    )
}

pub struct Sync {
    pub hostname: String,
    pub local_ip: String,
    pub public_ip: String,
    pub client_os: String,
    pub client_arch: String,
    pub client_os_id: String,
    pub client_os_name: String,
    pub version: String,
    pub handled: String,
    pub native_update_protocol: bool,
}
pub async fn sync(
    app: &App,
    machine: &Document,
    input: Sync,
    headers: &HeaderMap,
) -> ApiResult<Document> {
    sync_inner(app, machine, input, headers, false).await
}
pub async fn sync_legacy(
    app: &App,
    machine: &Document,
    input: Sync,
    headers: &HeaderMap,
) -> ApiResult<Document> {
    sync_inner(app, machine, input, headers, true).await
}
async fn sync_inner(
    app: &App,
    machine: &Document,
    input: Sync,
    headers: &HeaderMap,
    legacy: bool,
) -> ApiResult<Document> {
    app.artifacts.refresh_background();
    let latest_client_version = app.client_version();
    let now = DateTime::now();
    let client_hostname = if input.hostname.trim().is_empty() {
        store::string(machine, "client_hostname").trim()
    } else {
        input.hostname.trim()
    };
    let hostname = [
        store::string(machine, "hostname_override").trim(),
        client_hostname,
        store::string(machine, "hostname").trim(),
    ]
    .into_iter()
    .find(|s| !s.is_empty())
    .unwrap_or("");
    let observed = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .unwrap_or("")
        .trim();
    let public_ip = [
        input.public_ip.trim(),
        store::string(machine, "public_ip"),
        observed,
    ]
    .into_iter()
    .find(|s| !s.is_empty())
    .unwrap_or("");
    let mut set = doc! {"hostname":hostname,"client_hostname":client_hostname,"local_ip":input.local_ip.trim(),"public_ip":public_ip,"auth_required":false,"last_seen_at":now};
    if let Some(country) = headers
        .get("cf-ipcountry")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .map(str::to_ascii_uppercase)
        .filter(|country| country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_alphabetic()) && country != "XX" && country != "T1")
    {
        set.insert("client_country", country);
    }
    if matches!(input.client_os.as_str(), "linux" | "macos" | "windows") {
        set.insert("client_os", &input.client_os);
    }
    if matches!(input.client_arch.as_str(), "x86_64" | "x86" | "aarch64" | "arm" | "armv7") {
        set.insert("client_arch", &input.client_arch);
    }
    if !input.client_os_id.is_empty() && input.client_os_id.len() <= 64 && input.client_os_id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)) {
        set.insert("client_os_id", &input.client_os_id);
    }
    if !input.client_os_name.is_empty() && input.client_os_name.chars().count() <= 160 && !input.client_os_name.chars().any(char::is_control) {
        set.insert("client_os_name", &input.client_os_name);
    }
    let version = input.version.trim();
    let handled = input.handled.trim();
    if should_replace_reported_version(store::string(machine, "client_version").trim(), version) {
        set.insert("client_version", version);
    }
    if !version.is_empty() {
        let request_id = store::string(machine, "client_update_request_id").trim();
        let target = store::string(machine, "client_update_target_version").trim();
        if update_request_completed(version, target, request_id, handled) {
            set.insert("client_update_last_handled_request_id", request_id);
            set.insert("client_update_target_version", "");
            set.insert("client_updated_at", now);
        } else if version == latest_client_version {
            set.insert("client_updated_at", now);
        }
    } else if !handled.is_empty()
        && handled == store::string(machine, "client_update_request_id").trim()
    {
        set.insert("client_update_last_handled_request_id", handled);
        set.insert("client_update_target_version", "");
        set.insert("client_updated_at", now);
    }
    if input.native_update_protocol
        && should_auto_update(
            version,
            &latest_client_version,
            store::string(machine, "client_update_request_id"),
            store::string(machine, "client_update_target_version"),
            handled,
        )
    {
        let mut bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        let request = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        set.insert(
            "client_update_target_version",
            latest_client_version.as_str(),
        );
        set.insert("client_update_request_id", request);
        set.insert("client_update_requested_at", now);
    }
    let id = machine
        .get_object_id("_id")
        .map_err(|_| ApiError::bad_request("Invalid machine id"))?;
    // Credential/enable/delete conditions close the race with browser revocation.
    let mut filter = doc! {"_id":id,"token":machine.get("token"),"enabled":{"$ne":false},"deletion_pending":{"$ne":true}};
    if legacy {
        filter.remove("enabled");
    }
    if set.contains_key("client_version") {
        // The client authenticated before this update. A concurrent newer
        // heartbeat must not be overwritten using that older version snapshot.
        filter.insert(
            "client_version",
            machine.get("client_version").cloned().unwrap_or(Bson::Null),
        );
    }
    if set.contains_key("client_update_target_version") {
        filter.insert(
            "client_update_request_id",
            machine
                .get("client_update_request_id")
                .cloned()
                .unwrap_or(Bson::Null),
        );
    }
    if let Some(updated) = app
        .collection("machines")
        .find_one_and_update(filter, doc! {"$set":set})
        .return_document(mongodb::options::ReturnDocument::After)
        .await?
    {
        return Ok(updated);
    }
    // Report a concurrent disable accurately: a deletion header would cause an
    // installed client to uninstall itself instead of waiting to be re-enabled.
    if legacy {
        authenticate_legacy(app, &id.to_hex(), store::string(machine, "token")).await?;
    } else {
        authenticate(app, &id.to_hex(), store::string(machine, "token")).await?;
    }
    Err(ApiError::new(
        StatusCode::CONFLICT,
        "Machine configuration changed; retry synchronization",
    ))
}

pub async fn private_ips(app: &App, machine: &Document) -> ApiResult<Vec<String>> {
    if machine.get_bool("private_owner_revoked").unwrap_or(false) {
        return Ok(Vec::new());
    }
    let peers: Vec<Document> = app
        .collection("private_peers")
        .find(
            doc! {"machine_id":machine.get("_id"),"owner_id":machine.get("user_id"),"enabled":true},
        )
        .await?
        .try_collect()
        .await?;
    let mut seen = HashSet::new();
    let mut ips: Vec<String> = peers
        .iter()
        .map(|p| store::string(p, "ip"))
        .filter_map(|ip| ip.parse::<std::net::Ipv4Addr>().ok())
        .filter(|ip| ip.is_private())
        .map(|ip| ip.to_string())
        .filter(|ip| seen.insert(ip.clone()))
        .collect();
    ips.sort();
    Ok(ips)
}

pub fn control_headers(app: &App, machine: &Document) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let latest_client_version = app.client_version();
    for (key, value) in [
        (
            "x-porthub-client-latest-version",
            latest_client_version.as_str(),
        ),
        (
            "x-porthub-client-current-version",
            store::string(machine, "client_version").trim(),
        ),
        (
            "x-porthub-client-update-requested",
            if !store::string(machine, "client_update_request_id")
                .trim()
                .is_empty()
                && store::string(machine, "client_update_request_id").trim()
                    != store::string(machine, "client_update_last_handled_request_id").trim()
            {
                "true"
            } else {
                "false"
            },
        ),
    ] {
        if let Ok(value) = value.parse() {
            headers.insert(key, value);
        }
    }
    for (key, field) in [
        (
            "x-porthub-client-target-version",
            "client_update_target_version",
        ),
        (
            "x-porthub-client-update-request-id",
            "client_update_request_id",
        ),
    ] {
        let value = store::string(machine, field).trim();
        if !value.is_empty() {
            if let Ok(value) = value.parse() {
                headers.insert(key, value);
            }
        }
    }
    headers
}

#[cfg(test)]
mod auto_update_tests {
    use super::{should_auto_update, should_replace_reported_version, update_request_completed};

    #[test]
    fn outdated_clients_get_one_gateway_update_request() {
        assert!(should_auto_update("1.3.1", "1.3.2", "", "", ""));
        assert!(should_auto_update("", "1.3.2", "", "", ""));
        assert!(!should_auto_update("1.3.2", "1.3.2", "", "", ""));
        assert!(!should_auto_update("1.10.0", "1.3.2", "", "", ""));
        assert!(!should_auto_update(
            "1.3.1", "1.3.2", "pending", "1.3.2", ""
        ));
        assert!(should_auto_update("1.3.1", "1.3.2", "pending", "1.3.1", ""));
        assert!(should_auto_update(
            "1.3.1", "1.3.2", "handled", "1.3.2", "handled"
        ));
    }

    #[test]
    fn reporting_the_requested_release_completes_its_pending_update() {
        assert!(update_request_completed("1.3.4", "1.3.4", "request-1", ""));
        assert!(update_request_completed(
            "1.3.4",
            "1.3.4",
            "request-1",
            "request-1"
        ));
        assert!(!update_request_completed("1.3.3", "1.3.4", "request-1", ""));
        assert!(!update_request_completed("1.3.4", "1.3.4", "", ""));
    }

    #[test]
    fn stale_legacy_build_cannot_replace_a_reported_release() {
        assert!(!should_replace_reported_version(
            "1.4.3",
            "legacy-build-hash"
        ));
        assert!(!should_replace_reported_version("1.4.3", ""));
        assert!(should_replace_reported_version(
            "legacy-build-hash",
            "1.4.3"
        ));
        assert!(should_replace_reported_version("1.4.3", "1.4.2"));
    }
}
