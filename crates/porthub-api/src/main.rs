use anyhow::Result;
use porthub_api::{config::Config, App};
use std::sync::Arc;

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    let check = match arguments.next() {
        None => false,
        Some(argument) if argument == "--check-config" => true,
        Some(argument) if argument == "--check-artifacts" => {
            let root = arguments
                .next()
                .map(std::path::PathBuf::from)
                .ok_or_else(|| {
                    anyhow::anyhow!("Usage: porthub-api --check-artifacts DIRECTORY VERSION")
                })?;
            let version = arguments
                .next()
                .and_then(|value| value.into_string().ok())
                .ok_or_else(|| {
                    anyhow::anyhow!("Usage: porthub-api --check-artifacts DIRECTORY VERSION")
                })?;
            anyhow::ensure!(
                arguments.next().is_none(),
                "Usage: porthub-api --check-artifacts DIRECTORY VERSION"
            );
            let releases = porthub_api::artifacts::verify_complete(&root, &version).await?;
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({"version":version,"releases":releases}))?
            );
            return Ok(());
        }
        Some(argument) if argument == "--help" || argument == "-h" => {
            println!("Usage: porthub-api [--check-config | --check-artifacts DIRECTORY VERSION]\n\n--check-config  Validate current database configuration without starting or modifying services\n--check-artifacts  Validate the complete image release without database or network access");
            return Ok(());
        }
        _ => anyhow::bail!("Usage: porthub-api [--check-config]"),
    };
    anyhow::ensure!(
        arguments.next().is_none(),
        "Usage: porthub-api [--check-config]"
    );
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = Config::load()?;
    if check {
        let client = mongodb::Client::with_uri_str(&config.mongo_uri).await?;
        let database = client.database(&config.mongo_database);
        let app = App::new(config, database);
        let report = porthub_api::generated::preflight(&app)
            .await
            .map_err(|error| anyhow::anyhow!("configuration preflight failed: {}", error.detail))?;
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }
    let db = porthub_api::bootstrap::database(&config).await?;
    let tcp_address = config.listen.clone();
    let app = Arc::new(App::new(config, db));
    porthub_api::enrollment_ticket::initialize(&app)
        .await
        .map_err(|error| anyhow::anyhow!("bootstrap initialization failed: {}", error.detail))?;
    porthub_api::status_monitor::initialize(&app, mongodb::bson::DateTime::now())
        .await
        .map_err(|error| {
            anyhow::anyhow!("status monitor initialization failed: {}", error.detail)
        })?;
    porthub_api::machine_delete::initialize(&app)
        .await
        .map_err(|error| {
            anyhow::anyhow!("deletion queue initialization failed: {}", error.detail)
        })?;
    porthub_api::generated::initialize(&app)
        .await
        .map_err(|error| {
            anyhow::anyhow!("native startup reconciliation failed: {}", error.detail)
        })?;
    let discovery = app.clone();
    let refresh = tokio::spawn(async move {
        if discovery.config.gateway_advertised_url.is_some() {
            std::future::pending::<()>().await;
        }
        loop {
            let origin = discovery
                .gateway_origin
                .get(
                    &discovery.http,
                    &discovery.config.gateway_ip_sources,
                    discovery.config.gateway_public_ip.as_deref(),
                )
                .await;
            let delay = origin
                .map(|value| value.refresh_after_seconds)
                .unwrap_or(30)
                .max(1);
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        }
    });
    let (activity_stop, activity_stopping) = tokio::sync::watch::channel(false);
    let activity = app.config.web_activity_log_path.clone().map(|path| {
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(error) = porthub_api::web_activity::run(app, path, activity_stopping).await {
                tracing::error!(%error,"web activity worker stopped");
            }
        })
    });
    let firewall = app.firewall.as_ref().map(|_| {
        tokio::spawn(porthub_api::firewall::run(
            app.clone(),
            activity_stop.subscribe(),
        ))
    });
    let connection_refresh = tokio::spawn(porthub_api::connection_refresh::run(
        app.clone(),
        activity_stop.subscribe(),
    ));
    let machine_delete = tokio::spawn(porthub_api::machine_delete::run(
        app.clone(),
        activity_stop.subscribe(),
    ));
    let status_monitor = tokio::spawn(porthub_api::status_monitor::run(
        app.clone(),
        activity_stop.subscribe(),
    ));
    let offline_digest = tokio::spawn(porthub_api::status_monitor::run_digest(
        app.clone(),
        activity_stop.subscribe(),
    ));
    let instant_alerts = tokio::spawn(porthub_api::status_monitor::run_alerts(
        app.clone(),
        activity_stop.subscribe(),
    ));
    let realtime = app.clone();
    let router = porthub_api::router(app);
    let result = if let Some(path) = std::env::var_os("PORTHUB_API_SOCKET") {
        let (listener, _lease) = porthub_runtime::socket::bind(std::path::Path::new(&path)).await?;
        tracing::info!("native API listening on internal Unix socket");
        axum::serve(listener, router)
            .with_graceful_shutdown(porthub_runtime::shutdown_signal())
            .await
    } else {
        let listener = tokio::net::TcpListener::bind(&tcp_address).await?;
        tracing::info!(listen = %tcp_address, "native API listening");
        axum::serve(listener, router)
            .with_graceful_shutdown(porthub_runtime::shutdown_signal())
            .await
    };
    realtime.realtime.close().await;
    refresh.abort();
    let _ = activity_stop.send(true);
    if let Some(activity) = activity {
        activity.await?;
    }
    if let Some(firewall) = firewall {
        firewall.await?;
    }
    connection_refresh.await?;
    machine_delete.await?;
    status_monitor.await?;
    offline_digest.await?;
    instant_alerts.await?;
    result?;
    Ok(())
}
