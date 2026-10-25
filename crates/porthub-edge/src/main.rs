use anyhow::{Context, Result};
use clap::Parser;
use porthub_tunnel::{gateway_config, EmbeddedServer};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::RwLock;

#[derive(Parser)]
#[command(version, about = "PortHub native public edge")]
struct Args {
    #[arg(long, value_delimiter = ',')]
    listen: Vec<SocketAddr>,
    #[arg(long, value_delimiter = ',')]
    tls_listen: Vec<SocketAddr>,
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    #[arg(long)]
    tls_key: Option<PathBuf>,
    #[arg(short = 'c', long)]
    config: PathBuf,
    #[arg(long)]
    api_socket: Option<PathBuf>,
    #[arg(long)]
    web_config: Option<PathBuf>,
    #[arg(long)]
    control_socket: Option<PathBuf>,
}

#[tokio::main(worker_threads = 4)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let mut args = Args::parse();
    if args.listen.is_empty() {
        args.listen = std::env::var("PORTHUB_EDGE_HTTP_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:47090".into())
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::parse)
            .collect::<Result<Vec<_>, _>>()?;
    }
    if args.tls_listen.is_empty() {
        args.tls_listen = std::env::var("PORTHUB_EDGE_TLS_LISTEN")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::parse)
            .collect::<Result<Vec<_>, _>>()?;
    }
    if args.tls_cert.is_none() {
        args.tls_cert = std::env::var_os("PORTHUB_TLS_CERT").map(PathBuf::from);
    }
    if args.tls_key.is_none() {
        args.tls_key = std::env::var_os("PORTHUB_TLS_KEY").map(PathBuf::from);
    }
    // Publish only a public key pin, never the certificate's private key. The
    // API mounts this role-scoped directory read-only.
    if let (Some(listen), Some(cert), Some(key), Some(control)) = (
        args.tls_listen.first(),
        args.tls_cert.as_ref(),
        args.tls_key.as_ref(),
        args.control_socket
            .clone()
            .or_else(|| std::env::var_os("PORTHUB_EDGE_SOCKET").map(PathBuf::from)),
    ) {
        use rustls::pki_types::pem::PemObject;
        use std::io::Write;
        initialize_certificate(cert, key).await?;
        let certificate = rustls::pki_types::CertificateDer::from_pem_file(cert)?;
        let metadata = porthub_identity::origin::Metadata::from_certificate(
            certificate.as_ref(),
            listen.port(),
        )?;
        let path = control.with_file_name("origin.json");
        let mut file = tempfile::NamedTempFile::new_in(
            path.parent().context("origin metadata parent missing")?,
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o640))?;
        }
        file.write_all(&serde_json::to_vec(&metadata)?)?;
        file.as_file().sync_all()?;
        file.persist(path).map_err(|error| error.error)?;
    }
    let web_path = args
        .web_config
        .take()
        .or_else(|| std::env::var_os("PORTHUB_WEB_ROUTES_CONFIG_PATH").map(PathBuf::from))
        .unwrap_or_else(|| args.config.with_file_name("web-routes.json"));
    let mut changes =
        porthub_runtime::file_watch::FileChanges::new(&[args.config.clone(), web_path.clone()])?;
    let gateway_bases = [
        std::env::var("PORT_HUB_PUBLIC_BASE_URL").unwrap_or_default(),
        std::env::var("PORT_HUB_HTTP_BASE_URL").unwrap_or_default(),
        std::env::var("PORT_HUB_FALLBACK_BASE_URLS").unwrap_or_default(),
    ];
    let gateway_hosts = gateway_bases
        .iter()
        .flat_map(|bases| bases.split(','))
        .filter_map(|base| url::Url::parse(base.trim()).ok())
        .filter_map(|url| url.host_str().map(str::to_owned));
    let activity = Arc::new(porthub_runtime::web_activity::WebActivity::default());
    let activity_path = std::env::var_os("PORTHUB_WEB_ACTIVITY_LOG_PATH")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let mut web = porthub_runtime::web_routes::WebRoutes::with_gateway_hosts(gateway_hosts);
    if activity_path.is_some() {
        web = web.with_activity(activity.clone());
    }
    let web = Arc::new(web);
    let web_data = match tokio::fs::read_to_string(&web_path).await {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            String::from("{\"routes\":[]}")
        }
        Err(error) => return Err(error.into()),
    };
    web.reload(serde_json::from_str(&web_data)?)?;
    let data = tokio::fs::read_to_string(&args.config)
        .await
        .context("read gateway config")?;
    let server = Arc::new(RwLock::new(
        EmbeddedServer::new(gateway_config(&data)?).await?,
    ));
    let shared = server.clone();
    let gateway_path = args.config.clone();
    let web_reload = web.clone();
    let mut watcher: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
        let mut previous_web = web_data;
        loop {
            if changes.changed().await.is_none() {
                anyhow::bail!("gateway configuration watcher stopped");
            }
            if let Ok(next) = tokio::fs::read_to_string(&web_path).await {
                if next != previous_web {
                    match serde_json::from_str(&next)
                        .map_err(anyhow::Error::from)
                        .and_then(|config| web_reload.reload(config))
                    {
                        Ok(()) => previous_web = next,
                        Err(error) => {
                            tracing::error!(%error,"web route reload rejected; retaining current routes")
                        }
                    }
                }
            }
            if let Err(error) = porthub_edge::apply::file(&shared, &gateway_path, None).await {
                tracing::error!(%error,"gateway reload rejected; keeping current services");
            }
        }
    });
    let router = porthub_edge::router_with_web(
        server.clone(),
        args.api_socket
            .or_else(|| std::env::var_os("PORTHUB_API_SOCKET").map(PathBuf::from)),
        web,
    );
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut serving = tokio::task::JoinSet::new();
    let mut handles = Vec::new();
    let (control_stop, mut control_stopping) = tokio::sync::watch::channel(false);
    let mut control_lease = None;
    if let Some(path) = args.control_socket.or_else(|| {
        std::env::var_os("PORTHUB_EDGE_SOCKET")
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
    }) {
        let (listener, lease) = porthub_runtime::socket::bind(&path).await?;
        control_lease = Some(lease);
        let router = porthub_edge::apply::router(server.clone(), args.config.clone());
        serving.spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    while !*control_stopping.borrow() {
                        if control_stopping.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await
        });
    }
    for listen in args.listen {
        let handle = axum_server::Handle::new();
        let router = porthub_edge::listener_router_with_public_origin(
            router.clone(),
            false,
            std::env::var("PORT_HUB_PUBLIC_BASE_URL").ok().as_deref(),
        );
        let server = axum_server::bind(listen)
            .acceptor(axum_server::accept::NoDelayAcceptor::new())
            .handle(handle.clone());
        serving.spawn(async move { server.serve(router.into_make_service()).await });
        handles.push(handle);
    }
    if !args.tls_listen.is_empty() {
        let certificate = args
            .tls_cert
            .context("TLS certificate required for HTTPS listeners")?;
        let key = args
            .tls_key
            .context("TLS private key required for HTTPS listeners")?;
        initialize_certificate(&certificate, &key).await?;
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(certificate, key).await?;
        for listen in args.tls_listen {
            let handle = axum_server::Handle::new();
            let acceptor = axum_server::tls_rustls::RustlsAcceptor::new(tls.clone())
                .acceptor(axum_server::accept::NoDelayAcceptor::new());
            let server = axum_server::bind(listen)
                .acceptor(acceptor)
                .handle(handle.clone());
            let router = porthub_edge::listener_router(router.clone(), true);
            serving.spawn(async move { server.serve(router.into_make_service()).await });
            handles.push(handle);
        }
    }
    let (activity_stop, activity_stopping) = tokio::sync::watch::channel(false);
    let mut activity_worker = activity_path.map(|path| {
        tokio::spawn(async move {
            activity
                .run(path, activity_stopping, Duration::from_secs(5))
                .await
        })
    });
    let result = tokio::select! {
        _ = porthub_runtime::shutdown_signal() => Ok(()),
        result=&mut watcher=>match result {
            Ok(Err(error))=>Err(error),
            Ok(Ok(()))=>Err(anyhow::anyhow!("gateway configuration watcher stopped")),
            Err(error)=>Err(error.into()),
        },
        result = serving.join_next() => match result {
            Some(Ok(result)) => result.map_err(anyhow::Error::from),
            Some(Err(error)) => Err(error.into()),
            None => anyhow::bail!("edge has no configured listeners"),
        }
    };
    for handle in handles {
        handle.graceful_shutdown(Some(Duration::from_secs(10)));
    }
    watcher.abort();
    let _ = control_stop.send(true);
    server.write().await.shutdown().await;
    while let Some(result) = serving.join_next().await {
        if let Err(error) = result {
            tracing::error!(%error, "edge listener failed during shutdown");
        }
    }
    drop(control_lease);
    let _ = activity_stop.send(true);
    if let Some(mut worker) = activity_worker.take() {
        match tokio::time::timeout(Duration::from_secs(5), &mut worker).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => tracing::error!(%error,"web activity final flush failed"),
            Ok(Err(error)) => tracing::error!(%error,"web activity worker failed"),
            Err(_) => {
                worker.abort();
                tracing::warn!("web activity shutdown flush timed out");
            }
        }
    }
    result
}

async fn initialize_certificate(
    certificate: &std::path::Path,
    key: &std::path::Path,
) -> Result<()> {
    if certificate.exists() {
        anyhow::ensure!(
            key.exists(),
            "HTTPS certificate exists without its private key"
        );
        return Ok(());
    }
    anyhow::ensure!(
        std::env::var("PORTHUB_ALLOW_SELF_SIGNED").as_deref() == Ok("true"),
        "HTTPS identity is missing"
    );
    let mut names = vec!["localhost".to_owned()];
    if let Ok(base) = std::env::var("PORT_HUB_PUBLIC_BASE_URL") {
        if let Ok(url) = base.parse::<axum::http::Uri>() {
            if let Some(host) = url.host() {
                names.push(host.to_owned());
            }
        }
    }
    for path in [certificate, key] {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    if !key.exists() {
        let generated = rcgen::KeyPair::generate()?;
        match write_identity(key, generated.serialize_pem().as_bytes()) {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) => {}
            Err(error) => return Err(error),
        }
    }
    // Reuse a durably written key if an earlier startup was interrupted before
    // its certificate was published; peers' SPKI pins remain valid.
    let keypair = rcgen::KeyPair::from_pem(&tokio::fs::read_to_string(key).await?)?;
    let cert = rcgen::CertificateParams::new(names)?.self_signed(&keypair)?;
    match write_identity(certificate, cert.pem().as_bytes()) {
        Ok(()) => Ok(()),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn write_identity(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .context("TLS identity needs a parent directory")?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".porthub-identity-")
        .tempfile_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn interrupted_identity_initialization_reuses_the_original_key() -> Result<()> {
        let previous = std::env::var_os("PORTHUB_ALLOW_SELF_SIGNED");
        std::env::set_var("PORTHUB_ALLOW_SELF_SIGNED", "true");
        let result = async {
            let directory = tempfile::tempdir()?;
            let certificate = directory.path().join("origin.crt");
            let key = directory.path().join("origin.key");
            initialize_certificate(&certificate, &key).await?;
            let original = tokio::fs::read(&key).await?;
            let original_certificate = tokio::fs::read(&certificate).await?;
            initialize_certificate(&certificate, &key).await?;
            assert_eq!(tokio::fs::read(&certificate).await?, original_certificate);
            tokio::fs::remove_file(&certificate).await?;
            initialize_certificate(&certificate, &key).await?;
            assert_eq!(tokio::fs::read(&key).await?, original);
            let _ = rustls::crypto::ring::default_provider().install_default();
            axum_server::tls_rustls::RustlsConfig::from_pem_file(&certificate, &key).await?;
            tokio::fs::remove_file(&key).await?;
            assert!(initialize_certificate(&certificate, &key).await.is_err());
            Ok::<_, anyhow::Error>(())
        }
        .await;
        match previous {
            Some(value) => std::env::set_var("PORTHUB_ALLOW_SELF_SIGNED", value),
            None => std::env::remove_var("PORTHUB_ALLOW_SELF_SIGNED"),
        }
        result
    }
}
