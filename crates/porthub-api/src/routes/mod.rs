pub mod access;
pub mod account;
pub mod admin;
pub mod admin_users;
pub mod artifacts;
pub mod bootstrap;
pub mod connection_access;
pub mod connection_firewall;
pub mod connections;
pub mod dns_rules;
pub mod exit_nodes;
pub mod exposes;
pub mod gateway;
pub mod groups;
pub mod machine_client;
pub mod machine_delete;
pub mod machine_logs;
pub mod machine_update;
pub mod machines;
pub mod private_access;
pub mod private_books;
pub mod private_enrollment;
pub mod private_groups;
pub mod private_sync;
pub mod virtual_hosts;
pub mod proxy_grants;
pub mod telegram;
pub mod traffic_routes;

use crate::App;
use axum::Router;
use std::sync::Arc;

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .merge(telegram::router())
        .merge(crate::file_relay::router())
        .merge(crate::pairdrop::router())
        .merge(crate::boards::router())
        .merge(crate::keyboard::router())
        .merge(crate::machine_metrics::router())
        .merge(crate::usb::router())
        .merge(crate::native_media::router())
        .merge(crate::hosted_images::router())
        .merge(crate::image_rooms::router())
        // Retired shell URLs also match legacy machine routes or cached UI assets.
        // Reject them explicitly, before those handlers can accept credentials.
        .route("/terminal", axum::routing::any(retired_shell))
        .route("/terminal/", axum::routing::any(retired_shell))
        .route("/terminal.html", axum::routing::any(retired_shell))
        .route("/api/terminal/{*path}", axum::routing::any(retired_shell))
        .route("/api/machines/{id}/terminal-sessions", axum::routing::any(retired_shell))
        .route("/api/machines/{id}/terminal-sessions/{*path}", axum::routing::any(retired_shell))
        .merge(crate::terminal_traffic::router())
        .merge(crate::private_traffic::router())
        .merge(connections::router())
        .merge(exposes::router())
        .merge(exit_nodes::router())
        .merge(proxy_grants::router())
        .merge(crate::application_proxy::router())
        .merge(dns_rules::router())
        .merge(connection_firewall::router())
        .merge(connection_access::router())
        .merge(admin::router())
        .merge(admin_users::router())
        .merge(artifacts::router())
        .merge(bootstrap::router())
        .merge(account::router())
        .merge(groups::router())
        .merge(gateway::router())
        .merge(machines::router())
        .merge(machine_delete::router())
        .merge(machine_update::router())
        .merge(machine_client::router())
        .merge(machine_logs::router())
        .merge(access::router())
        .merge(private_access::router())
        .merge(private_books::router())
        .merge(private_enrollment::router())
        .merge(private_groups::router())
        .merge(private_sync::router())
        .merge(virtual_hosts::router())
        .merge(crate::private_relay::router())
        .merge(traffic_routes::router())
        .merge(crate::inventory_query::router())
        .merge(crate::traffic_hover::router())
}

async fn retired_shell() -> axum::http::StatusCode {
    axum::http::StatusCode::GONE
}
