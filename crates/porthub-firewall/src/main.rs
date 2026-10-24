use anyhow::{Context, Result};
use clap::Parser;
use porthub_firewall::service::Service;
use std::{future::IntoFuture, path::PathBuf};
#[derive(Parser)]
#[command(version, about = "PortHub isolated native firewall worker")]
struct Args {
    #[arg(long, default_value = "/run/porthub-firewall/api.sock")]
    socket: PathBuf,
    #[arg(long, default_value = "/data/firewall/firewall.db")]
    database: PathBuf,
    #[arg(long)]
    table: Option<String>,
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let key = std::env::var("FW_API_KEY").context("FW_API_KEY is required")?;
    let table = args
        .table
        .unwrap_or_else(|| std::env::var("FW_NFT_TABLE").unwrap_or_else(|_| "porthub".into()));
    let table = table.trim().strip_prefix("inet ").unwrap_or(table.trim());
    let service = Service::new(&args.database, table, key).await?;
    let (listener, _lease) = porthub_runtime::socket::bind(&args.socket).await?;
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let mut sampler = tokio::spawn(service.clone().sample(receiver));
    let router = porthub_firewall::service::router(service);
    let serving = axum::serve(listener, router)
        .with_graceful_shutdown(porthub_runtime::shutdown_signal())
        .into_future();
    tokio::pin!(serving);
    let result = tokio::select! {
        result=&mut serving=>result.map_err(anyhow::Error::from),
        result=&mut sampler=>match result {Ok(Ok(()))=>Ok(()),Ok(Err(error))=>Err(error),Err(error)=>Err(error.into())},
    };
    let _ = stop.send(true);
    if !sampler.is_finished() {
        sampler.await??;
    }
    result
}
