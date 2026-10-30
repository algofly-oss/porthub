//! Shared native process and IPC primitives for the isolated server roles.
#[cfg(unix)]
pub mod development;
#[cfg(unix)]
pub mod file_watch;
pub mod gateway_apply;
pub mod public_access;
#[cfg(unix)]
pub mod proxy;
#[cfg(unix)]
pub mod socket;
#[cfg(unix)]
pub mod supervise;
#[cfg(unix)]
pub mod web_activity;
#[cfg(unix)]
pub mod web_routes;
#[cfg(unix)]
pub mod upstreams;

pub async fn shutdown_signal() {
    #[cfg(unix)]
    if let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}
