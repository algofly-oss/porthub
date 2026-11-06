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
    #[cfg(unix)]
    /// Attach to a saved local workspace; Ctrl+A then D detaches.
    Attach {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long,value_enum,default_value_t=porthub_terminal_cli::owner::Sidebar::Off)]
        sidebar: porthub_terminal_cli::owner::Sidebar,
    },
    #[cfg(unix)]
    #[command(hide = true)]
    Terminal {
        #[command(subcommand)]
        command: OwnerCommand,
    },
    /// Create a persistent local workspace without a core agent or gateway.
    New {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(long)]
        shell: Option<PathBuf>,
        #[arg(long = "env")]
        environment: Vec<String>,
        #[arg(long, default_value = "C-a")]
        prefix: String,
        #[arg(long, default_value_t = 100000)]
        history_limit: u32,
        #[arg(long)]
        no_mouse: bool,
        #[arg(last = true)]
        command: Vec<OsString>,
    },
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
#[cfg(unix)]
#[derive(Subcommand)]
enum OwnerCommand {
    #[command(name = "__serve", hide = true)]
    Serve { root: PathBuf, id: String },
    #[command(name = "__participants-popup", hide = true)]
    Popup {
        root: PathBuf,
        id: String,
        client: u32,
    },
    #[command(name = "__participants-view", hide = true)]
    View {
        root: PathBuf,
        id: String,
        #[arg(long)]
        sidebar: bool,
    },
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
        #[cfg(unix)]
        Command::Attach {
            directory,
            name,
            sidebar,
        } => porthub_terminal_cli::owner::attach(&directory, &name, sidebar)?,
        #[cfg(unix)]
        Command::Terminal { command } => match command {
            OwnerCommand::Serve { root, id } => {
                let parent = std::env::var("PORTHUB_COMPONENT_OWNER_PID")
                    .ok()
                    .map(|value| value.parse::<u32>())
                    .transpose()?;
                let parent_closed = async {
                    let Some(parent) = parent else {
                        std::future::pending::<()>().await;
                        return;
                    };
                    loop {
                        if unsafe { libc::getppid() } as u32 != parent {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                };
                tokio::select! {biased;
                    _=cancel.cancelled()=>{}, _=parent_closed=>{},
                    result=porthub_terminal_cli::sharing::serve(&root,&id)=>result?,
                }
            }
            OwnerCommand::Popup { root, id, client } => {
                porthub_terminal_cli::owner::popup(&root, &id, client)?
            }
            OwnerCommand::View { root, id, sidebar } => {
                porthub_terminal_cli::owner::view(&root, &id, sidebar).await?
            }
        },
        Command::New {
            directory,
            name,
            cwd,
            shell,
            environment,
            prefix,
            history_limit,
            no_mouse,
            command,
        } => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let directory = if directory.is_absolute() {
                    directory
                } else {
                    std::env::current_dir()?.join(directory)
                };
                if !directory.exists() {
                    porthub_terminal::multiplexer::create_directory(&directory)?;
                }
                let shell = shell
                    .or_else(|| {
                        ["/bin/bash", "/usr/bin/bash"]
                            .into_iter()
                            .map(PathBuf::from)
                            .find(|path| {
                                std::fs::metadata(path).is_ok_and(|metadata| {
                                    metadata.is_file() && metadata.mode() & 0o111 != 0
                                })
                            })
                    })
                    .or_else(|| std::env::var_os("SHELL").map(PathBuf::from))
                    .unwrap_or_else(|| PathBuf::from("/bin/sh"));
                let options = porthub_components::protocol::terminal::CreateOptions {
                    name,
                    cwd: cwd.unwrap_or(std::env::current_dir()?).canonicalize()?,
                    shell,
                    environment,
                    prefix,
                    history_limit,
                    no_mouse,
                    command,
                    inherited_environment: std::env::vars_os().collect(),
                };
                let job = porthub_terminal_cli::workspace::create(&directory, options, false)?;
                println!("{}", serde_json::to_string(&job)?);
            }
            #[cfg(not(unix))]
            {
                let _ = (
                    directory,
                    name,
                    cwd,
                    shell,
                    environment,
                    prefix,
                    history_limit,
                    no_mouse,
                    command,
                );
                anyhow::bail!("terminal hosting requires Unix; use WSL on Windows")
            }
        }
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
            } = porthub_terminal_cli::install(&directory)?
            else {
                anyhow::bail!("invalid runtime response")
            };
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
            } = porthub_terminal_cli::install(&directory)?
            else {
                anyhow::bail!("invalid runtime response")
            };
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
