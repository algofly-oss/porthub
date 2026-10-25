//! Short-lived bootstrap capabilities. Each effective setup has its own stable
//! code so cached previews cannot change another cached command's enrollment.
use crate::{
    auth,
    domain::{inventory, machine_client::View, workspaces::object_id},
    error::{ApiError, ApiResult},
    store, App,
};
use axum::http::{HeaderMap, StatusCode};
use mongodb::{
    bson::{doc, Bson, DateTime, Document},
    options::{IndexOptions, ReturnDocument},
    IndexModel,
};
use rand::{distributions::Alphanumeric, Rng};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, time::Duration};
pub fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
fn invalid() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "Installer link is invalid or expired; refresh the setup page",
    )
}
pub fn base(value: &str) -> ApiResult<url::Url> {
    if value.len() > 2048 {
        return Err(ApiError::bad_request("Invalid PortHub public base URL"));
    }
    let url = url::Url::parse(value)
        .map_err(|_| ApiError::bad_request("Invalid PortHub public base URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ApiError::bad_request("Invalid PortHub public base URL"));
    }
    Ok(url)
}
pub fn link(base_url: &str, code: &str) -> ApiResult<String> {
    let mut url = base(base_url)?;
    url.path_segments_mut()
        .map_err(|_| invalid())?
        .pop_if_empty()
        .extend(["install", code]);
    Ok(url.into())
}
pub fn shell_quote(value: &str) -> String {
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_./:%+=@~".contains(&b))
    {
        return value.into();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
pub async fn initialize(app: &App) -> ApiResult<()> {
    app.bootstrap_initialized
        .get_or_try_init(|| async {
            app.collection("machine_install_tickets")
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"expires_at":1})
                        .options(IndexOptions::builder().expire_after(Duration::ZERO).build())
                        .build(),
                )
                .await?;
            app.collection("machine_install_tickets")
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"ticket_hash":1})
                        .options(IndexOptions::builder().unique(true).sparse(true).build())
                        .build(),
                )
                .await?;
            Ok::<_, ApiError>(())
        })
        .await?;
    Ok(())
}
fn fresh(
    machine: &Document,
    token_hash: &str,
    now: DateTime,
    setup: &Document,
    setup_digest: &str,
) -> Document {
    let code: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    doc! {"code":&code,"ticket_hash":digest(&code),"kind":"public","machine_id":machine.get("_id"),"token_digest":token_hash,"setup":setup,"setup_digest":setup_digest,
    "expires_at":DateTime::from_millis(now.timestamp_millis().saturating_add(86_400_000))}
}
pub async fn command(
    app: &App,
    headers: &HeaderMap,
    id: &str,
    query: &HashMap<String, String>,
) -> ApiResult<Value> {
    let user = auth::current_user(app, headers).await?;
    let id = object_id(id, "Invalid machine id")?;
    let _guard = app.connection_lock.lock().await;
    let machine = app
        .collection("machines")
        .find_one(doc! {"_id":id,"user_id":user.get("_id"),"deletion_pending":{"$ne":true}})
        .await?
        .ok_or_else(|| ApiError::bad_request("Machine not found"))?;
    let (setup, uri) = public_link(app, headers, &machine, query).await?;
    Ok(
        json!({"msg":"Machine command generated successfully","data":{"machine":inventory::machine(app,&machine),
        "command":format!("curl -fsSL {} | bash",shell_quote(&uri)),"native_command":format!("porthub setup --ticket {}",shell_quote(&uri)),
        "bootstrap_url":uri,"client_setup":setup}}),
    )
}
/// Mint the same scoped native installer capability for an authenticated
/// machine credential. Browser ownership checks remain in `command`.
pub async fn public_link(
    app: &App,
    headers: &HeaderMap,
    machine: &Document,
    query: &HashMap<String, String>,
) -> ApiResult<(Value, String)> {
    let id = store::id(machine.get("_id"));
    if machine.contains_key("native_deletion") {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Machine deletion is in progress",
        ));
    }
    initialize(app).await?;
    let view = View { headers, query };
    let setup = view.setup(app, machine);
    let effective = setup["effective"].clone();
    for field in ["rathole_server_address", "service_domain"] {
        let value = effective[field].as_str().unwrap_or_default();
        if value.len() > 2048 || value.chars().any(char::is_control) {
            return Err(ApiError::bad_request("Invalid client setup value"));
        }
    }
    let root = effective["public_base_url"].as_str().ok_or_else(invalid)?;
    base(root)?;
    let token_hash = digest(store::string(machine, "token"));
    let context = digest(&crate::domain::machine_client::canonical_json(
        effective.clone(),
    ));
    let key = format!(
        "native-public:{}",
        digest(&format!("{id}:{token_hash}:{context}"))
    );
    let now = DateTime::now();
    let setup_doc = mongodb::bson::to_document(&effective).map_err(|_| invalid())?;
    let coll = app.collection("machine_install_tickets");
    let result = coll
        .find_one_and_update(
            doc! {"_id":&key},
            doc! {"$setOnInsert":fresh(machine,&token_hash,now,&setup_doc,&context)},
        )
        .upsert(true)
        .return_document(ReturnDocument::After)
        .await;
    let mut ticket = match result {
        Ok(Some(ticket)) => ticket,
        Err(error) if store::duplicate(&error) => coll
            .find_one(doc! {"_id":&key})
            .await?
            .ok_or_else(invalid)?,
        Err(error) => return Err(error.into()),
        _ => return Err(invalid()),
    };
    if ticket
        .get_datetime("expires_at")
        .map_or(true, |expires| *expires <= now)
        || ticket.get_str("setup_digest").ok() != Some(context.as_str())
        || ticket.get_document("setup").map_or(true, |setup| {
            digest(&crate::domain::machine_client::canonical_json(
                store::document(setup),
            )) != context
        })
    {
        let renewed = coll
            .find_one_and_update(
                doc! {"_id":&key,"ticket_hash":ticket.get("ticket_hash")},
                doc! {"$set":fresh(machine,&token_hash,now,&setup_doc,&context)},
            )
            .return_document(ReturnDocument::After)
            .await?;
        ticket = match renewed {
            Some(ticket) => ticket,
            None => coll
                .find_one_and_update(
                    doc! {"_id":&key},
                    doc! {"$setOnInsert":fresh(machine,&token_hash,now,&setup_doc,&context)},
                )
                .upsert(true)
                .return_document(ReturnDocument::After)
                .await?
                .ok_or_else(invalid)?,
        };
    }
    let uri = link(root, store::string(&ticket, "code"))?;
    Ok((setup, uri))
}

pub struct Enrollment {
    pub account_email: String,
    pub machine: Document,
    pub setup: Document,
    pub private: Option<(String, Document)>,
}
pub async fn resolve(app: &App, code: &str) -> ApiResult<Enrollment> {
    if code.len() != 16 || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(invalid());
    }
    let hash = digest(code);
    let ticket = app
        .collection("machine_install_tickets")
        .find_one(
            doc! {"$or":[{"_id":&hash},{"ticket_hash":&hash}],"expires_at":{"$gt":DateTime::now()}},
        )
        .await?
        .ok_or_else(invalid)?;
    if ticket
        .get_str("kind")
        .is_ok_and(|kind| !matches!(kind, "public" | "private"))
    {
        return Err(invalid());
    }
    if let Ok(expected) = ticket.get_str("setup_digest") {
        let setup = ticket.get_document("setup").map_err(|_| invalid())?;
        if digest(&crate::domain::machine_client::canonical_json(
            store::document(setup),
        )) != expected
        {
            return Err(invalid());
        }
    }
    let machine=app.collection("machines").find_one(doc! {"_id":ticket.get("machine_id"),"enabled":{"$ne":false},"deletion_pending":{"$ne":true}}).await?.ok_or_else(invalid)?;
    let token = store::string(&machine, "token");
    if token.is_empty()
        || ticket.get_str("token_digest").ok() != Some(digest(token).as_str())
        || machine.contains_key("native_deletion")
    {
        return Err(invalid());
    }
    let private = if ticket.get_str("kind") == Ok("private") {
        let raw = ticket.get_str("private_ticket").map_err(|_| invalid())?;
        let (_, peer) = crate::domain::private_enrollment::resolve(app, raw).await?;
        if peer.get("machine_id") != machine.get("_id") {
            return Err(invalid());
        }
        Some((raw.to_owned(), peer))
    } else {
        None
    };
    Ok(Enrollment {
        account_email: account_email(app, &machine).await?,
        machine,
        setup: ticket.get_document("setup").cloned().unwrap_or_default(),
        private,
    })
}
impl Enrollment {
    pub fn values(&self, app: &App, headers: &HeaderMap) -> ApiResult<Value> {
        let account_email = (!self.account_email.is_empty()).then_some(self.account_email.as_str());
        let query = HashMap::new();
        let view = View {
            headers,
            query: &query,
        };
        let server = self
            .setup
            .get_str("public_base_url")
            .ok()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| view.public_base(app, &self.machine));
        base(&server)?;
        let mut seen = std::collections::HashSet::new();
        let fallbacks: Vec<_> = app
            .config
            .tunnel_fallback_base_urls
            .iter()
            .filter_map(|value| base(value).ok())
            .filter(|url| url.scheme() == "https")
            .map(|url| url.as_str().trim_end_matches('/').to_owned())
            .filter(|value| *value != server)
            .filter(|value| seen.insert(value.clone()))
            .take(8)
            .collect();
        if let Some((ticket, peer)) = &self.private {
            return Ok(
                json!({"format_version":1,"kind":"private","server":server,"peer_id":store::field(peer,"_id"),"workspace":store::field(peer,"workspace_id"),"ticket":ticket,"fallback_servers":fallbacks,"account_email":account_email}),
            );
        }
        let mut overrides = serde_json::Map::new();
        overrides.insert("public_base_url".into(), json!(server));
        for key in ["rathole_server_address", "service_domain"] {
            if let Some(Bson::String(value)) = self.setup.get(key) {
                if !value.is_empty() {
                    overrides.insert(key.into(), json!(value));
                }
            }
        }
        Ok(
            json!({"format_version":1,"profile":{"format_version":1,"server":server,
            "machine_id":store::id(self.machine.get("_id")),"token":store::string(&self.machine,"token"),
            "fallback_servers":fallbacks,"setup_overrides":overrides,"allow_insecure_http_for_tests":false,"account_email":account_email}}),
        )
    }
}

async fn account_email(app: &App, machine: &Document) -> ApiResult<String> {
    let Some(user_id) = machine.get("user_id") else {
        return Ok(String::new());
    };
    let Some(user) = app
        .collection("users")
        .find_one(doc! {"_id":user_id})
        .await?
    else {
        return Ok(String::new());
    };
    let email = store::string(&user, "email");
    Ok(if email.trim().is_empty() {
        store::string(&user, "username").to_owned()
    } else {
        email.to_owned()
    })
}
