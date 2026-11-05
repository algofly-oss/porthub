//! Standalone directory synchronization; no enrollment, core or gateway needed.
use anyhow::Result;
use clap::{Parser, Subcommand};
use porthub_transfer::sync;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    version = option_env!("PORTHUB_COMPONENT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),
    about = "Watch and synchronize directories directly to an HTTP receiver",
    after_help = "Examples:\n  porthub-sync watch ./data http://receiver:8001/\n  porthub-sync watch ./data http://receiver:8001/ --detach\n  porthub-sync list\n  porthub-sync status JOB\n  porthub-sync stop JOB\n\nStart a receiver with porthub-sync receive ./backup --bind 0.0.0.0. Neither machine needs core, enrollment, or a PortHub gateway."
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Receive synchronization directly, without core or a PortHub gateway.
    Receive {
        directory: PathBuf,
        #[arg(short = 'p', long, default_value_t = 8001)]
        port: u16,
        #[arg(long, default_value = "127.0.0.1")]
        bind: std::net::IpAddr,
    },
    /// Synchronize a directory now, then watch for changes; retain remote-only files.
    Watch {
        path: PathBuf,
        url: String,
        #[arg(short = 'x', long, default_value_t = 16, value_parser = clap::value_parser!(u8).range(1..=32))]
        connections: u8,
        #[arg(long)]
        contents_only: bool,
        #[arg(long)]
        force: bool,
        #[arg(short = 'd', long)]
        detach: bool,
    },
    /// List active jobs owned by this OS account.
    #[command(alias = "ls")]
    List {
        #[arg(long)]
        json: bool,
    },
    /// Inspect an active job.
    Status {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Stop a job without removing files from its receiver.
    Stop { id: String },
    #[command(name = "__porthub-worker", hide = true)]
    Worker {
        #[arg(long)]
        endpoint: String,
    },
    // The shared library starts detached jobs with this stable internal entry.
    #[command(hide = true)]
    Sync {
        #[command(subcommand)]
        command: Internal,
    },
}
#[derive(Subcommand)]
enum Internal {
    Run { id: String },
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args = Args::parse();
    let cancel = CancellationToken::new();
    let shutdown = cancel.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            if let Ok(mut terminate) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            } else {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        shutdown.cancel();
    });
    match args.command {
        Command::Receive {
            directory,
            port,
            bind,
        } => {
            tokio::fs::create_dir_all(&directory).await?;
            porthub_transfer::server::serve(
                porthub_transfer::server::Options {
                    root: directory,
                    port,
                    bind,
                    accept_uploads: true,
                },
                cancel,
            )
            .await
        }
        Command::Worker { endpoint } => {
            use porthub_components::{
                catalog::{Component, PROTOCOL},
                ipc::Hello,
                local::Endpoint,
                rpc,
            };
            let endpoint = Endpoint::parse(Component::Sync, &endpoint)?;
            let hello = Hello {
                component: Component::Sync,
                protocol: PROTOCOL,
                version: option_env!("PORTHUB_COMPONENT_VERSION")
                    .unwrap_or(env!("CARGO_PKG_VERSION"))
                    .parse()?,
            };
            rpc::serve(
                endpoint,
                hello,
                std::sync::Arc::new(porthub_sync::Worker),
                cancel,
            )
            .await
        }
        Command::Watch {
            path,
            url,
            connections,
            contents_only,
            force,
            detach,
        } => {
            let options = sync::Options {
                path,
                url,
                connections: connections as usize,
                contents_only,
                force,
            };
            if detach {
                let id = sync::detach(options).await?;
                println!("Sync started: {id}\nView: porthub-sync status {id}\nStop: porthub-sync stop {id}");
                Ok(())
            } else {
                sync::watch(options, cancel).await
            }
        }
        Command::List { json } => {
            let jobs = sync::list().await?;
            if json {
                println!("{}", serde_json::to_string(&jobs)?);
            } else if jobs.is_empty() {
                println!("No active sync jobs");
            } else {
                for job in jobs {
                    println!(
                        "{}  {}  {} → {}",
                        job.id,
                        job.state,
                        job.source.display(),
                        job.destination
                    );
                }
            }
            Ok(())
        }
        Command::Status { id, json } => {
            let job = sync::status(&id).await?;
            if json {
                println!("{}", serde_json::to_string(&job)?);
            } else {
                println!(
                    "Sync {}: {}\nSource: {}\nDestination: {}\nCompleted syncs: {}\n{}",
                    job.id,
                    job.state,
                    job.source.display(),
                    job.destination,
                    job.completed_runs,
                    job.message
                );
            }
            Ok(())
        }
        Command::Stop { id } => {
            sync::stop(&id).await?;
            println!("Stopped sync {id}");
            Ok(())
        }
        Command::Sync {
            command: Internal::Run { id },
        } => sync::worker(id, cancel).await,
    }
}
