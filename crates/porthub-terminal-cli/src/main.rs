use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use porthub_components::protocol::terminal::Value;
use porthub_components::{
    catalog::{Component, PROTOCOL},
    ipc::Hello,
    local::Endpoint,
    rpc,
};
use std::{ffi::OsString, path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;
#[derive(Parser)]
#[command(version=porthub_terminal_cli::VERSION, about="Independent bundled tmux runtime and persistent local workspaces")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Install and verify the bundled runtime in a private directory.
    Runtime {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Run bundled tmux; use its new-session, attach, list-sessions and kill-session commands.
    Tmux {
        #[arg(long)]
        directory: Option<PathBuf>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        arguments: Vec<OsString>,
    },
    #[command(name = "__porthub-worker", hide = true)]
    Worker {
        #[arg(long)]
        endpoint: String,
    },
    #[command(name = "__porthub-stdio", hide = true)]
    Stdio,
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args = Args::parse();
    let cancel = CancellationToken::new();
    let stopped = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        stopped.cancel();
    });
    let hello = Hello {
        component: Component::Terminal,
        protocol: PROTOCOL,
        version: porthub_terminal_cli::VERSION.parse()?,
    };
    match args.command {
        Command::Worker { endpoint } => {
            rpc::serve(
                Endpoint::parse(Component::Terminal, &endpoint)?,
                hello,
                Arc::new(porthub_terminal_cli::Worker),
                cancel,
            )
            .await?
        }
        Command::Stdio => {
            rpc::serve_stdio(hello, Arc::new(porthub_terminal_cli::Worker), cancel).await?
        }
        Command::Runtime { directory } => {
            let Value::Runtime {
                executable,
                terminfo,
                version,
            } = porthub_terminal_cli::install(&directory)?;
            println!(
                "Runtime {version}\nExecutable: {}\nTerminfo: {}",
                executable.display(),
                terminfo.display()
            );
        }
        Command::Tmux {
            directory,
            arguments,
        } => {
            let directory = directory
                .or_else(|| {
                    directories::BaseDirs::new()
                        .map(|base| base.data_local_dir().join("porthub-terminal/runtimes"))
                })
                .context("cannot find terminal storage; specify --directory")?;
            let Value::Runtime {
                executable,
                terminfo,
                ..
            } = porthub_terminal_cli::install(&directory)?;
            let mut child = tokio::process::Command::new(executable)
                .args(arguments)
                .env("TERMINFO", terminfo)
                .kill_on_drop(true)
                .spawn()?;
            anyhow::ensure!(
                child.wait().await?.success(),
                "tmux command exited unsuccessfully"
            );
        }
    }
    Ok(())
}
