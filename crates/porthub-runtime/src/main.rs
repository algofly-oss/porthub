use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
#[command(version, about = "PortHub native server lifecycle")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    DevUi {
        #[arg(long, default_value = "/app/ui-dev")]
        source: PathBuf,
        #[arg(long, default_value = "/app/ui-live")]
        work: PathBuf,
        #[arg(long, default_value_t = 47030)]
        port: u16,
    },
    Check {
        #[arg(long)]
        socket: Option<PathBuf>,
        #[arg(long)]
        tcp: Option<String>,
        #[arg(long)]
        listen_env: Option<String>,
        #[arg(long, default_value = "/healthz")]
        path: String,
        #[arg(long)]
        api_key_env: Option<String>,
    },
    Supervise {
        #[arg(short = 'c', long)]
        config: PathBuf,
    },
}
#[tokio::main(worker_threads = 1)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    match Args::parse().command {
        Command::DevUi { source, work, port } => {
            porthub_runtime::development::run_ui(&source, &work, port)
        }
        Command::Check {
            socket,
            tcp,
            listen_env,
            path,
            api_key_env,
        } => {
            let tcp = if let Some(name) = listen_env {
                anyhow::ensure!(
                    socket.is_none() && tcp.is_none(),
                    "choose one health-check target"
                );
                let value = std::env::var(name)?;
                let mut address = value
                    .split(',')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .parse::<std::net::SocketAddr>()?;
                if address.ip().is_unspecified() {
                    address.set_ip(if address.is_ipv4() {
                        std::net::Ipv4Addr::LOCALHOST.into()
                    } else {
                        std::net::Ipv6Addr::LOCALHOST.into()
                    });
                }
                Some(format!("http://{address}"))
            } else {
                tcp
            };
            let proxy = match (socket, tcp) {
                (Some(path), None) => porthub_runtime::proxy::HttpProxy::unix(path),
                (None, Some(base)) => porthub_runtime::proxy::HttpProxy::tcp(&base)?,
                _ => anyhow::bail!("choose exactly one health-check socket or TCP origin"),
            };
            let mut request = axum::http::Request::builder().uri(format!("http://localhost{path}"));
            if let Some(name) = api_key_env {
                request = request.header("x-api-key", std::env::var(name)?);
            }
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                proxy.forward(request.body(axum::body::Body::empty())?),
            )
            .await?;
            anyhow::ensure!(
                response.status().is_success(),
                "service health check failed: {}",
                response.status()
            );
            Ok(())
        }
        Command::Supervise { config } => {
            let source = tokio::fs::read_to_string(config).await?;
            let mode = std::env::var("PORTHUB_MODE").unwrap_or_else(|_| "prod".into());
            let config = porthub_runtime::supervise::Config::parse(&source, &mode)?;
            porthub_runtime::supervise::run(config, porthub_runtime::shutdown_signal()).await
        }
    }
}
