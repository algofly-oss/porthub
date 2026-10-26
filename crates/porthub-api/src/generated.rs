//! Native gateway configuration derived from authoritative machine/service
//! records. Serial snapshots and atomic replacement prevent partial reloads.
use crate::{
    error::{ApiError, ApiResult},
    store, App,
};
use axum::http::StatusCode;
use futures_util::TryStreamExt;
use mongodb::bson::{doc, Bson, Document};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::Write,
    net::{IpAddr, SocketAddr},
    path::Path,
};

#[derive(Serialize)]
struct Service {
    token: String,
    bind_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    access: Option<porthub_runtime::public_access::Config>,
}
#[derive(Serialize)]
struct Server {
    services: BTreeMap<String, Service>,
}
#[derive(Serialize)]
struct Gateway {
    server: Server,
}

pub fn service_key(connection: &Document) -> String {
    let raw = store::id(connection.get("_id"));
    let mut name = String::new();
    for character in raw.chars() {
        if character.is_ascii_alphanumeric() || character == '_' {
            name.push(character);
        } else if !name.ends_with('_') {
            name.push('_');
        }
    }
    let name = name.trim_matches('_');
    let name = if name.is_empty() { "service" } else { name };
    format!(
        "porthub_{}_{}",
        store::field(connection, "external_port"),
        name
    )
}

pub fn render(machines: &[Document], connections: &[Document]) -> anyhow::Result<String> {
    let machines: HashMap<String, &Document> = machines
        .iter()
        .filter(|m| {
            m.get_bool("enabled") != Ok(false)
                && !m.get_bool("deletion_pending").unwrap_or(false)
                && !store::string(m, "token").is_empty()
        })
        .map(|m| (store::id(m.get("_id")), m))
        .collect();
    let mut services = BTreeMap::new();
    let mut addresses = HashSet::new();
    for connection in connections {
        if connection.get_bool("enabled") == Ok(false) {
            continue;
        }
        let Some(machine) = machines.get(&store::id(connection.get("machine_id"))) else {
            continue;
        };
        let port = match connection.get("external_port") {
            Some(Bson::Int32(port)) => u16::try_from(*port).ok(),
            Some(Bson::Int64(port)) => u16::try_from(*port).ok(),
            _ => None,
        }
        .filter(|port| *port != 0)
        .ok_or_else(|| anyhow::anyhow!("invalid public service port"))?;
        let bind = match store::string(connection, "external_bind_ip").trim() {
            "" => "0.0.0.0",
            bind => bind,
        }
        .parse::<IpAddr>()?;
        let address = SocketAddr::new(bind, port);
        anyhow::ensure!(
            addresses.insert(address),
            "duplicate public service bind address"
        );
        let previous = services.insert(
            service_key(connection),
            Service {
                access: match connection.get("public_access") {
                    None => None,
                    Some(value) => Some(mongodb::bson::from_bson(value.clone())?),
                },
                token: store::string(machine, "token").into(),
                bind_addr: address.to_string(),
            },
        );
        anyhow::ensure!(previous.is_none(), "duplicate public service key");
    }
    Ok(format!(
        "# Managed by PortHub. Manual changes will be overwritten.\n{}",
        toml::to_string(&Gateway {
            server: Server { services }
        })?
    ))
}

fn atomic_replace(path: &Path, content: &str) -> anyhow::Result<()> {
    if std::fs::read_to_string(path).ok().as_deref() == Some(content) {
        return Ok(());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o640))?;
    }
    temporary.write_all(content.as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub async fn rebuild(app: &App) -> ApiResult<()> {
    publish(app, true).await
}

async fn publish(app: &App, apply: bool) -> ApiResult<()> {
    let Some(path) = &app.config.gateway_config_path else {
        if apply && app.gateway_apply.is_some() {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Gateway configuration path is not configured",
            ));
        }
        return Ok(());
    };
    let _guard = app.gateway_config_lock.lock().await;
    let retired = crate::account_delete::retiring_owners(app).await?;
    let machines:Vec<Document>=app.collection("machines")
        .find(doc! {"user_id":{"$nin":retired},"enabled":{"$ne":false},"deletion_pending":{"$ne":true},"token":{"$nin":[Bson::Null,""]}})
        .await?.try_collect().await?;
    let ids: Vec<Bson> = machines
        .iter()
        .filter_map(|machine| machine.get("_id").cloned())
        .collect();
    let connections: Vec<Document> = app
        .collection("connections")
        .find(doc! {"machine_id":{"$in":ids},"enabled":{"$ne":false}})
        .sort(doc! {"external_port":1,"_id":1})
        .await?
        .try_collect()
        .await?;
    let content = render(&machines, &connections).map_err(internal)?;
    let digest = porthub_runtime::gateway_apply::digest(content.as_bytes());
    let path = path.clone();
    tokio::task::spawn_blocking(move || atomic_replace(&path, &content))
        .await
        .map_err(internal)?
        .map_err(internal)?;
    if apply {
        if let Some(client) = &app.gateway_apply {
            client.apply(&digest).await?;
        }
    }
    Ok(())
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    tracing::error!(%error,"gateway configuration rebuild failed");
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
}

pub async fn initialize(app: &App) -> ApiResult<()> {
    let mut machines = app
        .collection("machines")
        .find(doc! {"deletion_pending":{"$ne":true},"native_deletion":{"$exists":false}})
        .await?;
    while let Some(machine) = machines.try_next().await? {
        crate::domain::enrollment::ensure(app, &machine).await?;
    }
    // Install restrictions before an edge starting after core health can bind
    // initial listeners. Stale policy cleanup waits for the live apply channel.
    crate::firewall::prime(app).await?;
    publish(app, false).await?;
    rebuild_web(app).await
}

pub fn render_web(routes: &[Document]) -> anyhow::Result<porthub_runtime::web_routes::Config> {
    let mut result = Vec::new();
    for route in routes {
        if route.get_bool("enabled") == Ok(false) {
            continue;
        }
        let hosts: Vec<String> = route
            .get_array("hosts")
            .into_iter()
            .flatten()
            .filter_map(Bson::as_str)
            .map(|host| host.trim().to_lowercase())
            .filter(|host| !host.is_empty())
            .collect();
        let target_url = store::string(route, "target_url").trim().to_owned();
        let target = url::Url::parse(&target_url)?;
        let mode = store::string(route, "target_mode").trim();
        let pass_host = !matches!(mode, "" | "manual")
            || target.host_str().is_none_or(|host| {
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok()
                    || hosts.iter().any(|name| name.eq_ignore_ascii_case(host))
            });
        let entries: Vec<&str> = route
            .get_array("entry_points")
            .into_iter()
            .flatten()
            .filter_map(Bson::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        result.push(porthub_runtime::web_routes::Route {
            id: store::id(route.get("_id")),
            hosts,
            target_url,
            pass_host,
            http: entries.is_empty() || entries.contains(&"web"),
            https: true,
            access: None,
        });
    }
    Ok(porthub_runtime::web_routes::Config { routes: result })
}

/// Older gateways used a web proxy back to their own application listener.
/// Unified ingress already serves that application, so proxying it again would
/// either conflict with a reserved hostname or recurse into the same listener.
/// Keep the database records and let builtin gateway ingress serve these aliases.
pub fn render_web_for_gateway(
    routes: &[Document],
    settings: &crate::config::Config,
) -> anyhow::Result<porthub_runtime::web_routes::Config> {
    fn whole_origin(value: &str) -> Option<url::Origin> {
        let url = url::Url::parse(value).ok()?;
        (["http", "https"].contains(&url.scheme())
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none())
        .then(|| url.origin())
    }
    let origins: Vec<_> = std::iter::once(settings.public_base_url.as_str())
        .chain(std::iter::once(settings.tunnel_http_base_url.as_str()))
        .chain(settings.gateway_advertised_url.as_deref())
        .chain(
            settings
                .tunnel_fallback_base_urls
                .iter()
                .map(String::as_str),
        )
        .filter_map(whole_origin)
        .collect();
    let mut config = render_web(routes)?;
    config.routes.retain(|route| {
        whole_origin(&route.target_url).is_none_or(|origin| !origins.contains(&origin))
    });
    Ok(config)
}

async fn web_snapshot(app: &App) -> ApiResult<(usize, porthub_runtime::web_routes::Config)> {
    let retired = crate::account_delete::retiring_owners(app).await?;
    let routes: Vec<Document> = app
        .collection("traffic_routes")
        .find(doc! {"user_id":{"$nin":retired},"enabled":{"$ne":false}})
        .sort(doc! {"created_at":1,"_id":1})
        .await?
        .try_collect()
        .await?;
    let config = render_web_for_gateway(&routes, &app.config).map_err(internal)?;
    let gateways = std::iter::once(&app.config.public_base_url)
        .chain(std::iter::once(&app.config.tunnel_http_base_url))
        .chain(app.config.tunnel_fallback_base_urls.iter())
        .filter_map(|base| url::Url::parse(base).ok())
        .filter_map(|url| url.host_str().map(str::to_owned));
    porthub_runtime::web_routes::WebRoutes::with_gateway_hosts(gateways)
        .reload(config.clone())
        .map_err(internal)?;
    Ok((routes.len(), config))
}

#[derive(Serialize)]
pub struct Preflight {
    pub active_machines: usize,
    pub public_services: usize,
    pub web_routes: usize,
    pub proxy_routes: usize,
    pub gateway_alias_routes: usize,
}

/// Read-only production-data validation: no bootstrap, reconciliation, IPC,
/// file publication, index creation or background workers are started.
pub async fn preflight(app: &App) -> ApiResult<Preflight> {
    let retired = crate::account_delete::retiring_owners(app).await?;
    let machines: Vec<Document> = app.collection("machines")
        .find(doc! {"user_id":{"$nin":retired},"enabled":{"$ne":false},"deletion_pending":{"$ne":true},"token":{"$nin":[Bson::Null,""]}})
        .await?.try_collect().await?;
    let ids: Vec<Bson> = machines
        .iter()
        .filter_map(|m| m.get("_id").cloned())
        .collect();
    let connections: Vec<Document> = app
        .collection("connections")
        .find(doc! {"machine_id":{"$in":ids},"enabled":{"$ne":false}})
        .await?
        .try_collect()
        .await?;
    render(&machines, &connections).map_err(internal)?;
    let (web_routes, config) = web_snapshot(app).await?;
    Ok(Preflight {
        active_machines: machines.len(),
        public_services: connections.len(),
        web_routes,
        proxy_routes: config.routes.len(),
        gateway_alias_routes: web_routes - config.routes.len(),
    })
}

pub async fn rebuild_web(app: &App) -> ApiResult<()> {
    let path = app.config.web_routes_config_path.clone().or_else(|| {
        app.config
            .gateway_config_path
            .as_ref()
            .map(|path| path.with_file_name("web-routes.json"))
    });
    let Some(path) = path else {
        return Ok(());
    };
    let _guard = app.gateway_config_lock.lock().await;
    let (_, config) = web_snapshot(app).await?;
    let content = serde_json::to_string(&config).map_err(internal)?;
    tokio::task::spawn_blocking(move || atomic_replace(&path, &content))
        .await
        .map_err(internal)?
        .map_err(internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::oid::ObjectId;

    #[test]
    fn gateway_config_is_escaped_deterministic_and_has_no_control_listener() {
        let id = ObjectId::new();
        let machine = doc! {"_id":id,"token":"quoted\"token\\and\nnewline","enabled":true};
        let active = doc! {"_id":ObjectId::new(),"machine_id":id,"external_port":34001,"external_bind_ip":"127.0.0.1"};
        let disabled =
            doc! {"_id":ObjectId::new(),"machine_id":id,"external_port":34002,"enabled":false};
        let content = render(
            std::slice::from_ref(&machine),
            &[active.clone(), disabled.clone()],
        )
        .unwrap();
        assert!(!content.contains("[server]\n"));
        let config = porthub_tunnel::gateway_config(&content).unwrap();
        let services = config.server.unwrap().services;
        assert_eq!(services.len(), 1);
        let service = &services[&service_key(&active)];
        assert_eq!(service.bind_addr, "127.0.0.1:34001");
        assert_eq!(
            &**service.token.as_ref().unwrap(),
            "quoted\"token\\and\nnewline"
        );
        assert_eq!(
            content,
            render(std::slice::from_ref(&machine), &[disabled, active.clone()]).unwrap()
        );
        for patch in [
            doc! {"enabled":false},
            doc! {"deletion_pending":true},
            doc! {"token":""},
        ] {
            let mut revoked = machine.clone();
            revoked.extend(patch);
            let config = porthub_tunnel::gateway_config(
                &render(&[revoked], std::slice::from_ref(&active)).unwrap(),
            )
            .unwrap();
            assert!(config.server.unwrap().services.is_empty());
        }
    }

    #[test]
    fn rejected_or_unchanged_config_does_not_replace_the_published_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.toml");
        atomic_replace(&path, "first").unwrap();
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        atomic_replace(&path, "first").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            modified
        );
        atomic_replace(&path, "replacement").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "replacement");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640
            );
        }
        let id = ObjectId::new();
        let machine = doc! {"_id":id,"token":"test"};
        let connection = doc! {"_id":ObjectId::new(),"machine_id":id,"external_port":34001};
        assert!(render(&[machine], &[connection.clone(), connection]).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "replacement");
    }
}
