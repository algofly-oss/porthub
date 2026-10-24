pub mod access;
pub mod account;
pub mod admin;
pub mod artifacts;
pub mod bootstrap;
pub mod connection_firewall;
pub mod connections;
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
pub mod telegram;
pub mod traffic_routes;

use crate::App;
use axum::Router;
use std::sync::Arc;

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .merge(telegram::router())
        .merge(connections::router())
        .merge(connection_firewall::router())
        .merge(admin::router())
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
        .merge(crate::private_relay::router())
        .merge(traffic_routes::router())
}
