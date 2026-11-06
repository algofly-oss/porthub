//! Standalone local Tor proxy; no core, enrollment or PortHub server required.
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use porthub_components::{
    catalog::{Component, PROTOCOL},
    ipc::Hello,
    local::Endpoint,
    rpc,
};
use std::{path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;
#[derive(Parser)]
#[command(version=option_env!("PORTHUB_COMPONENT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),about="Independent Tor HTTP/SOCKS5 proxy and stream worker")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Start a localhost HTTP/SOCKS5 proxy. Supply a 24–255 byte password using
    /// PORTHUB_TOR_PROXY_PASSWORD; credentials are never printed or sent to core.
    Proxy {
        #[arg(long,default_value_t=1080,value_parser=clap::value_parser!(u16).range(1..))]
        port: u16,
        #[arg(long, default_value = "porthub")]
        username: String,
        #[arg(long,default_value_t=4,value_parser=clap::value_parser!(u8).range(1..=16))]
        groups: u8,
        #[arg(long)]
        directory: Option<PathBuf>,
    },
    #[command(name = "__porthub-worker", hide = true)]
    Worker {
        #[arg(long)]
        endpoint: String,
    },
    #[command(name = "__porthub-stdio", hide = true)]
    Stdio,
    #[command(name = "__porthub-multiplex", hide = true)]
    Multiplex,
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args = Args::parse();
    let cancel = CancellationToken::new();
    let signal = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        signal.cancel();
    });
    let hello = Hello {
        component: Component::Tor,
        protocol: PROTOCOL,
        version: porthub_tor::VERSION.parse()?,
    };
    match args.command {
        Command::Worker { endpoint } => {
            rpc::serve(
                Endpoint::parse(Component::Tor, &endpoint)?,
                hello,
                Arc::new(porthub_tor::Worker::default()),
                cancel,
            )
            .await
        }
        Command::Multiplex => {
            porthub_components::multiplex::serve_stdio(
                hello,
                Arc::new(porthub_tor::Worker::default()),
                cancel,
            )
            .await
        }
        Command::Stdio => {
            rpc::serve_stdio(hello, Arc::new(porthub_tor::Worker::default()), cancel).await
        }
        Command::Proxy {
            port,
            username,
            groups,
            directory,
        } => {
            let directory = directory
                .or_else(|| {
                    directories::BaseDirs::new()
                        .map(|dirs| dirs.data_local_dir().join("porthub-tor"))
                })
                .context("cannot find Tor storage; specify --directory")?;
            let password = std::env::var("PORTHUB_TOR_PROXY_PASSWORD")
                .context("set PORTHUB_TOR_PROXY_PASSWORD to a private 24–255 byte password")?;
            let credentials = porthub_egress::proxy::Credentials::new(username, password)?;
            let tor = Arc::new(porthub_egress::tor::TorPool::new(
                &directory,
                groups as usize,
                64,
            )?);
            let proxy = porthub_egress::proxy::Proxy::bind(
                ([127, 0, 0, 1], port).into(),
                credentials,
                tor.clone(),
                64,
            )
            .await?;
            eprintln!("Preparing Tor circuits for localhost:{port}...");
            tokio::select! {biased; _=cancel.cancelled()=>return Ok(()),result=tor.bootstrap()=>result?}
            eprintln!("Tor proxy ready on localhost:{port}; Ctrl-C to stop");
            proxy.run(cancel).await
        }
    }
}
