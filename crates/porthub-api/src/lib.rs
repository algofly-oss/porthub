pub mod access_inventory;
pub mod account_delete;
pub mod application_proxy;
pub mod artifacts;
pub mod auth;
pub mod bootstrap;
pub mod config;
pub mod config_signals;
pub mod connection_refresh;
pub mod docs;
pub mod domain;
pub mod enrollment_ticket;
pub mod error;
pub mod firewall;
pub mod gateway_apply;
pub mod gateway_origin;
pub mod generated;
pub mod http;
pub mod input;
pub mod input_compat;
pub mod inventory_query;
pub mod inventory_traffic;
pub mod legacy_turn;
mod legacy_upgrade;
pub mod machine_delete;
mod peer_proxy;
pub mod private_relay;
pub mod private_transport;
pub mod realtime;
pub mod release_cache;
pub mod routes;
pub mod static_ui;
pub mod status_monitor;
pub mod store;
pub mod terminal;
pub mod terminal_grants;
mod terminal_journal;
pub mod web_activity;

use axum::{
    routing::{get, post},
    Json, Router,
};
use config::Config;
use mongodb::{bson::Document, Collection, Database};
use serde_json::json;
use std::sync::Arc;

pub struct App {
    pub terminals: porthub_terminal::hub::Hub,
    pub terminal_lifecycle: tokio::sync::Mutex<()>,
    pub terminal_admission_fault: std::sync::atomic::AtomicBool,
    pub inventory_traffic: inventory_traffic::Cache,
    pub account_lifecycle: tokio::sync::RwLock<()>,
    pub private_relay: private_relay::Hub,
    pub proxy_capacity: application_proxy::Capacity,
    pub(crate) proxy_pending: Arc<peer_proxy::Hub>,
    pub legacy_turn: legacy_turn::Network,
    pub private_enrollment_initialized: tokio::sync::OnceCell<()>,
    pub private_initialized: tokio::sync::OnceCell<()>,
    pub bootstrap_initialized: tokio::sync::OnceCell<()>,
    pub artifacts: artifacts::Catalog,
    pub realtime: realtime::Hub,
    pub config: Config,
    pub firewall: Option<firewall::Client>,
    pub firewall_changes: tokio::sync::Notify,
    pub deletion_changes: tokio::sync::Notify,
    pub private_network_lock: tokio::sync::Mutex<()>,
    pub connection_lock: tokio::sync::Mutex<()>,
    pub db: Database,
    pub http: reqwest::Client,
    pub gateway_origin: gateway_origin::OriginDiscovery,
    pub gateway_apply: Option<gateway_apply::Client>,
    pub ui: Option<porthub_runtime::proxy::HttpProxy>,
    pub static_ui: Option<static_ui::StaticUi>,
    pub gateway_config_lock: tokio::sync::Mutex<()>,
    pub traffic_route_lock: tokio::sync::Mutex<()>,
    pub config_signals: config_signals::ConfigSignals,
}

impl App {
    pub fn new(config: Config, db: Database) -> Self {
        let ui = if config.ui_upstream.is_empty() {
            None
        } else {
            Some(
                porthub_runtime::proxy::HttpProxy::tcp(&config.ui_upstream)
                    .expect("validated UI upstream"),
            )
        };
        let static_ui = if config.ui_root.is_empty() {
            None
        } else {
            Some(
                static_ui::StaticUi::new(std::path::Path::new(&config.ui_root))
                    .expect("validated static UI directory"),
            )
        };
        Self {
            terminals: Default::default(),
            terminal_lifecycle: Default::default(),
            terminal_admission_fault: Default::default(),
            inventory_traffic: Default::default(),
            private_enrollment_initialized: Default::default(),
            private_initialized: Default::default(),
            account_lifecycle: tokio::sync::RwLock::new(()),
            private_relay: Default::default(),
            proxy_capacity: Default::default(),
            proxy_pending: Default::default(),
            legacy_turn: Default::default(),
            bootstrap_initialized: Default::default(),
            artifacts: match &config.client_release_repository {
                Some(repository) => artifacts::Catalog::github(
                    config
                        .client_binary_dir
                        .clone()
                        .expect("release cache path configured"),
                    repository,
                )
                .expect("validated release repository"),
                None => artifacts::Catalog::new(config.client_binary_dir.clone()),
            },
            realtime: Default::default(),
            config_signals: Default::default(),
            firewall_changes: tokio::sync::Notify::new(),
            deletion_changes: tokio::sync::Notify::new(),
            firewall: firewall::Client::new(&config).expect("validated firewall configuration"),
            private_network_lock: tokio::sync::Mutex::new(()),
            connection_lock: tokio::sync::Mutex::new(()),
            gateway_config_lock: tokio::sync::Mutex::new(()),
            traffic_route_lock: tokio::sync::Mutex::new(()),
            static_ui,
            ui,
            db,
            gateway_origin: Default::default(),
            gateway_apply: config
                .edge_socket
                .as_deref()
                .map(gateway_apply::Client::new)
                .transpose()
                .expect("validated gateway IPC socket"),
            config,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("HTTP client TLS configuration"),
        }
    }
    pub fn collection(&self, name: &str) -> Collection<Document> {
        self.db.collection(name)
    }
    pub fn client_version(&self) -> String {
        self.artifacts.version(&self.config.client_version)
    }
    pub async fn notify_config(&self, id: &str) {
        self.config_signals.changed(id);
        if let Err(error) = self.realtime.config_changed(self, id).await {
            tracing::warn!(detail=%error.detail,"realtime configuration notification failed");
        }
    }
    pub async fn notify_status(&self, machine: &Document) {
        if let Err(error) = self.realtime.status_changed(self, machine).await {
            tracing::warn!(detail=%error.detail,"realtime status notification failed");
        }
    }
}

pub fn router(app: Arc<App>) -> Router {
    let realtime = realtime::Hub::install(&app);
    Router::new()
        .merge(routes::router())
        .merge(docs::router())
        .route("/api/auth/settings", get(auth::settings))
        .route("/api/ping", get(ping))
        .route("/api/auth/signin", post(auth::signin))
        .route("/api/auth/signout", post(auth::signout))
        .route("/api/auth/me", get(auth::me))
        .route("/api/auth/sessions", get(auth::sessions))
        .route(
            "/api/auth/sessions/{session_id}",
            axum::routing::delete(auth::revoke_session),
        )
        .route("/healthz", get(|| async { Json(json!({"status":"ok"})) }))
        .fallback(fallback)
        .layer(realtime)
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            auth::renew_session,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(axum::middleware::from_fn(http::private_api_cache))
        .layer(axum::middleware::from_fn(http::cors))
        .with_state(app)
}

async fn ping(
    axum::extract::State(app): axum::extract::State<Arc<App>>,
) -> Json<serde_json::Value> {
    let start = std::time::Instant::now();
    let _ = app.http.get("https://google.com").send().await;
    Json(json!({"msg":"pong","latency":format!("{:.3} ms",start.elapsed().as_secs_f64()*1000.0)}))
}

async fn fallback(
    axum::extract::State(app): axum::extract::State<Arc<App>>,
    request: axum::extract::Request,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if request.uri().path() != "/api" && !request.uri().path().starts_with("/api/") {
        if let Some(ui) = &app.static_ui {
            return ui.serve(request).await;
        }
        if let Some(ui) = &app.ui {
            return ui.forward(request).await;
        }
    }
    error::ApiError::new(axum::http::StatusCode::NOT_FOUND, "Not Found").into_response()
}
