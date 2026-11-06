//! Local optional-tool management. Core version/OTA reports never include tool
//! maintenance state, and forwarding never awaits optional downloads.
mod network;
use anyhow::{ensure, Context, Result};
use porthub_components::{
    catalog::Component,
    maintenance::{Guard, Options as MaintenanceOptions},
    store::{Manager, Settings, Sources},
    transport::Http,
    worker::ContextOptions,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};
use tokio_util::sync::CancellationToken;

pub fn state_directory() -> Result<PathBuf> {
    Ok(match std::env::var_os("PORTHUB_STATE_DIR") {
        Some(path) => PathBuf::from(path),
        None => directories::BaseDirs::new()
            .context("cannot find component state directory")?
            .data_local_dir()
            .join("porthub"),
    })
}
fn gateway() -> Option<String> {
    let layouts = [
        crate::service::Layout::user(),
        crate::service::Layout::system(),
    ];
    for layout in layouts.into_iter().flatten() {
        if let Ok(records) = crate::service::readable::list(&layout) {
            if let Some(record) = records
                .into_iter()
                .find(|record| record.enabled && !record.gateway.is_empty())
            {
                return Some(record.gateway);
            }
        }
    }
    None
}
pub fn cache_root() -> Result<PathBuf> {
    let root = match std::env::var_os("PORTHUB_COMPONENT_CACHE") {
        Some(path) => PathBuf::from(path),
        None => directories::BaseDirs::new()
            .context("cannot find component cache directory")?
            .cache_dir()
            .join("porthub")
            .join("components"),
    };
    ensure!(
        root.is_absolute(),
        "PORTHUB_COMPONENT_CACHE must be an absolute path"
    );
    Ok(root)
}
pub fn manager(enrolled_gateway: Option<&str>) -> Result<Manager> {
    let root = cache_root()?;
    let parent = root.parent().context("component cache requires a parent")?;
    crate::service::directory(parent, true)?;
    let sources = match std::env::var("PORTHUB_COMPONENT_SOURCE").as_deref() {
        Ok("auto") | Err(std::env::VarError::NotPresent) => Sources::GatewayThenGithub,
        Ok("gateway") => Sources::GatewayOnly,
        Ok("github") => Sources::GithubOnly,
        _ => anyhow::bail!("PORTHUB_COMPONENT_SOURCE must be auto, gateway, or github"),
    };
    let mut disabled = BTreeSet::new();
    if let Ok(value) = std::env::var("PORTHUB_COMPONENT_DISABLED") {
        for component in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            disabled.insert(component.parse::<Component>()?);
        }
    }
    let mut pins = BTreeMap::new();
    if let Ok(value) = std::env::var("PORTHUB_COMPONENT_PINS") {
        for entry in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (component, version) = entry
                .split_once('=')
                .context("component pins require name=major.minor.patch")?;
            ensure!(
                pins.insert(component.parse::<Component>()?, version.parse()?)
                    .is_none(),
                "duplicate component pin"
            );
        }
    }
    let selected = std::env::var("PORTHUB_COMPONENT_GATEWAY")
        .ok()
        .or_else(|| enrolled_gateway.map(str::to_owned))
        .or_else(gateway);
    let gateway = selected
        .map(|value| crate::profile::base(&value, false).and_then(|value| Ok(value.parse()?)))
        .transpose()?;
    let manager = Manager::new(
        root,
        Settings {
            gateway,
            sources,
            core: crate::VERSION.parse()?,
            target: env!("PORTHUB_RUST_TARGET").replace("-musl", "-gnu"),
            disabled,
            pins,
        },
        Arc::new(Http::new()?.with_routing(Arc::new(network::Routes::new()?))),
    )?;
    let shared = match std::env::var_os("PORTHUB_COMPONENT_SHARED_CACHE") {
        Some(value) if value == "off" => return Ok(manager),
        Some(value) => PathBuf::from(value),
        None => system_cache_directory()?,
    };
    ensure!(
        shared.is_absolute(),
        "PORTHUB_COMPONENT_SHARED_CACHE must be off or an absolute path"
    );
    match manager.clone().with_shared_cache(
        shared,
        enrolled_gateway.is_some() && porthub_components::shared::system_writer(),
    ) {
        Ok(manager) => Ok(manager),
        Err(_) => {
            tracing::warn!(
                "shared optional-tool cache unavailable; using this account's private cache"
            );
            Ok(manager)
        }
    }
}
fn system_cache_directory() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Ok("/var/cache/porthub-components".into())
    }
    #[cfg(target_os = "macos")]
    {
        Ok("/Library/Caches/PortHubComponents".into())
    }
    #[cfg(windows)]
    {
        Ok(PathBuf::from(
            std::env::var_os("ProgramData").context("Windows ProgramData directory unavailable")?,
        )
        .join("PortHubComponents"))
    }
}
pub fn background(gateway: &str, cancel: &CancellationToken) -> Result<Guard> {
    let options = MaintenanceOptions {
        prefetch: match std::env::var("PORTHUB_COMPONENT_PREFETCH").as_deref() {
            Ok("false" | "0") => false,
            Ok("true" | "1") | Err(std::env::VarError::NotPresent) => true,
            _ => anyhow::bail!("PORTHUB_COMPONENT_PREFETCH must be true or false"),
        },
        ..Default::default()
    };
    Ok(Guard::start(manager(Some(gateway))?, options, cancel))
}
pub async fn worker(
    component: Component,
    cancel: &CancellationToken,
) -> Result<porthub_components::rpc::Client> {
    worker_transport(component, cancel).await
}
/// Pin one persistent worker so source updates and upgraded streams share state.
pub async fn persistent_session(
    component: Component,
    cancel: &CancellationToken,
) -> Result<porthub_components::worker::Session> {
    let mode = match std::env::var("PORTHUB_COMPONENT_TRANSPORT").as_deref() {
        Ok("auto") | Err(std::env::VarError::NotPresent) => porthub_components::worker::Mode::Auto,
        Ok("rpc") => porthub_components::worker::Mode::Rpc,
        Ok("cli") => porthub_components::worker::Mode::Cli,
        _ => anyhow::bail!("PORTHUB_COMPONENT_TRANSPORT must be auto, rpc, or cli"),
    };
    let state_directory = state_directory()?;
    crate::service::directory(&state_directory, true)?;
    manager(None)?
        .session_with_mode(component, &ContextOptions { state_directory }, mode, cancel)
        .await
}
async fn worker_transport(
    component: Component,
    cancel: &CancellationToken,
) -> Result<porthub_components::rpc::Client> {
    let manager = manager(None)?;
    if !manager.has_installation(component).await? {
        eprintln!("Preparing {component}: downloading a verified compatible tool if needed...");
    }
    let state_directory = state_directory()?;
    crate::service::directory(&state_directory, true)?;
    let mode = match std::env::var("PORTHUB_COMPONENT_TRANSPORT").as_deref() {
        Ok("auto") | Err(std::env::VarError::NotPresent) => porthub_components::worker::Mode::Auto,
        Ok("rpc") => porthub_components::worker::Mode::Rpc,
        Ok("cli") => porthub_components::worker::Mode::Cli,
        _ => anyhow::bail!("PORTHUB_COMPONENT_TRANSPORT must be auto, rpc, or cli"),
    };
    manager
        .connect(component, &ContextOptions { state_directory }, mode, cancel)
        .await
}
