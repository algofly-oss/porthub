//! Local workspaces use the same private bundled multiplexer as shared ones.
//! Local mode needs no registration or network. Sharing uses the local broker.
mod participant_control;
mod sharing;
use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand};
use fs2::FileExt;
use porthub_terminal::protocol::token;
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Subcommand)]
pub enum Command {
    /// Open NAME: attach if running, otherwise create a local workspace.
    #[command(external_subcommand)]
    Named(Vec<OsString>),
    /// Start a persistent local workspace; sharing is optional.
    #[command(
        after_help = "Examples:\n  porthub terminal new --name work\n  porthub terminal new --name work --shell /bin/bash --detach\n  porthub terminal new --name logs --detach -- tail -f /var/log/app.log\n\nAll creation flags also work with: porthub terminal NAME [OPTIONS]\nShare later with: porthub terminal share NAME --detach"
    )]
    New(New),
    /// Share a new workspace or an existing local workspace with SSH/browser guests.
    #[command(
        after_help = "Examples:\n  porthub terminal share work --detach\n  porthub terminal share work --access web --read-only --detach\n  porthub terminal share work --link-expires 3600 --detach\n  porthub terminal share work --registration laptop --user --detach\n\nBrowser and SSH access are both enabled by default. The command prints invitation\nlinks; show them again with: porthub terminal invite work\nUse --detach to share without attaching your terminal."
    )]
    Share(sharing::Share),
    /// Join an invitation without a PortHub account.
    Join {
        url: String,
        #[arg(long, value_enum, default_value_t = JoinTransport::Ssh)]
        transport: JoinTransport,
        /// Local registration whose exit/privacy policy controls native auto mode.
        #[cfg(feature = "terminal-direct")]
        #[arg(long)]
        registration: Option<String>,
        /// Select this OS user's registration for native auto mode.
        #[cfg(feature = "terminal-direct")]
        #[arg(long)]
        user: bool,
        /// Explicit UDP STUN endpoint for native auto mode; repeat up to twice.
        #[cfg(feature = "terminal-direct")]
        #[arg(long="stun-server",value_parser=crate::terminal_connectivity::server)]
        stun_servers: Vec<String>,
    },
    /// Show, replace or revoke invitation links.
    #[command(visible_aliases = ["url", "links"], after_help = "Show current browser URLs and SSH commands:\n  porthub terminal url NAME\n  porthub terminal invite NAME --json\n\nA local workspace has no access URL until shared:\n  porthub terminal share NAME --detach")]
    Invite {
        name: String,
        #[arg(long)]
        json: bool,
        /// Block new invitation joins without interrupting attached guests.
        #[arg(long, conflicts_with = "rotate")]
        revoke: bool,
        /// Replace invitation links without disconnecting existing participants.
        #[arg(long, visible_alias = "renew")]
        rotate: bool,
        /// New invitation lifetime in seconds; zero means until workspace end.
        #[arg(long, requires = "rotate", value_parser = clap::value_parser!(u32).range(0..=604800))]
        link_expires: Option<u32>,
    },
    /// List guests attached to a shared workspace.
    Participants {
        name: String,
        #[arg(long, conflicts_with = "watch")]
        json: bool,
        /// Interactive live selection and removal controls.
        #[arg(long)]
        watch: bool,
    },
    /// Remove one guest without ending the workspace or interrupting others.
    Kick { name: String, client: u64 },
    #[command(name = "__serve", hide = true)]
    Serve { id: String },
    #[command(name = "__participants-popup", hide = true)]
    ParticipantPopup {
        root: PathBuf,
        id: String,
        client: u32,
    },
    #[command(name = "__participants-view", hide = true)]
    ParticipantView {
        root: PathBuf,
        id: String,
        #[arg(long)]
        sidebar: bool,
    },
    /// List this OS user's running local and shared workspaces.
    #[command(alias = "ls")]
    List {
        #[arg(long)]
        json: bool,
        /// Include ended workspaces retained in local history.
        #[arg(short = 'a', long)]
        all: bool,
    },
    /// Attach or reattach, including from inside another tmux session.
    Attach {
        name: String,
        #[arg(long, value_enum, default_value_t = Sidebar::Off)]
        sidebar: Sidebar,
    },
    /// Explicitly terminate a workspace and its running tasks.
    Stop { name: String },
    /// Rename a workspace without interrupting its tasks.
    Rename { name: String, new_name: String },
    /// Run an advanced tmux command against this workspace only.
    Tmux {
        name: String,
        #[arg(last = true, required = true)]
        args: Vec<OsString>,
    },
}

impl Default for Command {
    fn default() -> Self {
        Self::New(New {
            name: None,
            cwd: None,
            shell: None,
            environment: Vec::new(),
            detach: false,
            json: false,
            prefix: "C-a".into(),
            history_limit: 100_000,
            no_mouse: false,
            sidebar: Sidebar::Off,
            command: Vec::new(),
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum JoinTransport {
    /// Ordinary installed SSH client.
    #[default]
    Ssh,
    /// Native gateway relay without an external SSH client.
    #[cfg(feature = "terminal-direct")]
    Relay,
    /// Native direct when a local agent permits it, otherwise gateway relay.
    #[cfg(feature = "terminal-direct")]
    Auto,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Sidebar {
    Auto,
    On,
    #[default]
    Off,
}

#[derive(Args, Clone)]
pub struct New {
    /// Workspace name; a friendly random name is generated when omitted.
    #[arg(long)]
    name: Option<String>,
    /// Initial working directory (defaults to the current directory).
    #[arg(long)]
    cwd: Option<PathBuf>,
    /// Shell for new workspaces (defaults to Bash when installed).
    #[arg(long)]
    shell: Option<PathBuf>,
    /// Environment overrides for the workspace, e.g. --env MODE=debug.
    #[arg(long = "env")]
    environment: Vec<String>,
    /// Start in the background; it remains available with terminal attach.
    #[arg(short = 'd', long)]
    detach: bool,
    #[arg(long, requires = "detach")]
    /// Print machine-readable workspace details (requires --detach).
    json: bool,
    /// tmux shortcut prefix, e.g. C-a (Ctrl+A) or F12.
    #[arg(long, default_value = "C-a")]
    prefix: String,
    /// Maximum retained scrollback lines (1000 to 200000).
    #[arg(long, default_value_t = 100000)]
    history_limit: u32,
    /// Disable tmux mouse handling; use the terminal emulator's selection.
    #[arg(long)]
    no_mouse: bool,
    /// Optional participant sidebar (off by default); use Ctrl+A then Shift+P on demand.
    #[arg(long, value_enum, default_value_t = Sidebar::Off)]
    sidebar: Sidebar,
    /// Command and arguments; omit to start an interactive shell.
    #[arg(last = true)]
    command: Vec<OsString>,
}

use porthub_components::protocol::terminal::Job;

fn private(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "terminal directory must be private and owned by the current user"
    );
    Ok(())
}

fn root() -> Result<PathBuf> {
    let dirs = directories::BaseDirs::new().context("cannot locate user terminal storage")?;
    // Keep explicitly configured terminal data isolated on macOS too; BaseDirs
    // follows native Library paths there and intentionally ignores XDG overrides.
    let data = match std::env::var_os("XDG_DATA_HOME").filter(|path| !path.is_empty()) {
        Some(path) => {
            let path = PathBuf::from(path);
            ensure!(path.is_absolute(), "XDG_DATA_HOME must be absolute");
            path
        }
        None => dirs.data_local_dir().to_path_buf(),
    };
    let root = data.join("porthub/terminal");
    if !root.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)?;
    }
    private(&root)?;
    Ok(root)
}

fn socket_root() -> Result<PathBuf> {
    // Keep Unix socket paths short even with a deeply nested user home.
    let root = PathBuf::from(format!("/tmp/porthub-terminal-{}", unsafe {
        libc::geteuid()
    }));
    match fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .map_err(anyhow::Error::from)
    {
        Ok(()) => {}
        Err(_) if root.exists() => {}
        Err(error) => return Err(error),
    }
    private(&root)?;
    Ok(root)
}

fn lock(root: &Path) -> Result<fs::File> {
    let path = root.join("registry.lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)?;
    ensure!(
        file.metadata()?.uid() == unsafe { libc::geteuid() },
        "invalid terminal registry owner"
    );
    file.lock_exclusive()?;
    Ok(file)
}

fn jobs(root: &Path) -> Result<Vec<Job>> {
    let mut jobs = Vec::new();
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let job: Job = serde_json::from_slice(&crate::profile::read_private(&path)?)?;
            ensure!(
                token(&job.id, 32)
                    && path.file_stem().and_then(|name| name.to_str()) == Some(&job.id),
                "invalid terminal registry identity"
            );
            jobs.push(job);
        }
    }
    jobs.sort_by_key(|job| job.created_at);
    Ok(jobs)
}

fn select(root: &Path, name: &str) -> Result<Job> {
    let mut matching: Vec<_> = jobs(root)?
        .into_iter()
        .filter(|job| job.name == name || job.id == name)
        .collect();
    ensure!(
        matching.len() == 1,
        "workspace not found or ambiguous; use a name or full ID from terminal list"
    );
    Ok(matching.remove(0))
}

fn name_valid(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b" ._-".contains(&b)),
        "name must contain 1–64 letters, numbers, spaces, dots, underscores or hyphens"
    );
    Ok(())
}

async fn terminal_operation(
    operation: porthub_components::protocol::terminal::Operation,
) -> Result<porthub_components::protocol::terminal::Value> {
    let cancel = tokio_util::sync::CancellationToken::new();
    let mut worker =
        crate::components::worker(porthub_components::catalog::Component::Terminal, &cancel)
            .await?;
    worker
        .call(operation, std::time::Duration::from_secs(30))
        .await
}
async fn running(root: &Path, id: &str) -> Result<bool> {
    let value = terminal_operation(porthub_components::protocol::terminal::Operation::Running {
        directory: root.into(),
        name: id.into(),
    })
    .await?;
    let porthub_components::protocol::terminal::Value::Running { running } = value else {
        anyhow::bail!("invalid terminal state response")
    };
    Ok(running)
}
fn local_owner_lease(root: &Path, id: &str, client: u32) -> Result<()> {
    private(root)?;
    ensure!(client > 0, "invalid terminal client");
    let job = select(root, id)?;
    private(&job.workspace)?;
    let path = job.workspace.join(format!("owner-client-{client}.lock"));
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("participant controls require a local owner attachment")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "unsafe owner attachment lease"
    );
    match file.try_lock_exclusive() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        _ => anyhow::bail!("owner attachment is no longer active"),
    }
}
async fn owner_frontend(arguments: Vec<OsString>) -> Result<()> {
    let cancel = tokio_util::sync::CancellationToken::new();
    let manager = crate::components::manager(None)?;
    if !manager
        .has_installation(porthub_components::catalog::Component::Terminal)
        .await?
    {
        eprintln!("Preparing terminal: downloading a verified compatible tool if needed...");
    }
    let (_, executable) = manager
        .resolve(porthub_components::catalog::Component::Terminal, &cancel)
        .await?;
    let mut child = porthub_components::foreground(&executable, &arguments, &cancel).await?;
    ensure!(
        child.wait().await?.success(),
        "terminal frontend exited unsuccessfully; the workspace may still be running"
    );
    Ok(())
}
async fn join_frontend(request: porthub_components::protocol::terminal::JoinRequest) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::Builder::new()
        .prefix("porthub-join-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let path = temporary.path().join("request.json");
    let bytes = serde_json::to_vec(&request)?;
    ensure!(
        bytes.len() <= 16384,
        "terminal join request exceeds size limit"
    );
    crate::profile::write_private(&path, &bytes, false)?;
    owner_frontend(vec![
        "__porthub-join".into(),
        "--request".into(),
        path.into_os_string(),
    ])
    .await
}
async fn attach(job: &Job, sidebar: Sidebar) -> Result<()> {
    owner_frontend(vec![
        "attach".into(),
        "--directory".into(),
        root()?.into_os_string(),
        "--name".into(),
        job.id.clone().into(),
        "--sidebar".into(),
        match sidebar {
            Sidebar::On => "on",
            Sidebar::Auto => "auto",
            Sidebar::Off => "off",
        }
        .into(),
    ])
    .await
}
async fn owner_view(root: &Path, id: &str, sidebar: bool) -> Result<()> {
    let mut arguments = vec![
        "terminal".into(),
        "__participants-view".into(),
        root.as_os_str().into(),
        id.into(),
    ];
    if sidebar {
        arguments.push("--sidebar".into());
    }
    owner_frontend(arguments).await
}

async fn create(root: &Path, args: New) -> Result<Job> {
    create_or_open(root, args, false).await
}
async fn create_or_open(root: &Path, args: New, reuse: bool) -> Result<Job> {
    use porthub_components::{
        catalog::Component,
        protocol::terminal::{CreateOptions, Operation, Value},
    };
    let shell = args
        .shell
        .or_else(|| {
            ["/bin/bash", "/usr/bin/bash"]
                .into_iter()
                .map(PathBuf::from)
                .find(|path| {
                    fs::metadata(path)
                        .is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0)
                })
        })
        .or_else(|| std::env::var_os("SHELL").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/bin/sh"));
    let options = CreateOptions {
        name: args.name,
        cwd: args
            .cwd
            .unwrap_or(std::env::current_dir()?)
            .canonicalize()?,
        shell,
        environment: args.environment,
        inherited_environment: std::env::vars_os().collect(),
        history_limit: args.history_limit,
        no_mouse: args.no_mouse,
        prefix: args.prefix,
        command: args.command,
    };
    let cancel = tokio_util::sync::CancellationToken::new();
    let mut worker = crate::components::worker(Component::Terminal, &cancel).await?;
    let value = worker
        .call(
            Operation::Create {
                directory: root.into(),
                options,
                reuse,
            },
            std::time::Duration::from_secs(30),
        )
        .await?;
    let Value::Workspace { job } = value else {
        anyhow::bail!("terminal helper returned an invalid workspace")
    };
    ensure!(
        token(&job.id, 32) && job.workspace == socket_root()?.join(&job.id),
        "terminal helper returned an unrelated workspace"
    );
    Ok(job)
}

async fn open_named(root: &Path, arguments: Vec<OsString>) -> Result<()> {
    use clap::Parser;
    #[derive(Parser)]
    struct Flags {
        #[command(flatten)]
        new: New,
    }
    let name = arguments
        .first()
        .and_then(|name| name.to_str())
        .context("workspace name must be valid text")?
        .to_owned();
    name_valid(&name)?;
    let mut flags = Flags::try_parse_from(
        std::iter::once(OsString::from(format!("porthub terminal {name}")))
            .chain(arguments.into_iter().skip(1)),
    )?
    .new;
    ensure!(
        flags.name.is_none(),
        "use the workspace name directly, without an additional --name"
    );
    flags.name = Some(name.clone());
    let sidebar = flags.sidebar;
    let detach = flags.detach;
    let json = flags.json;
    let job = create_or_open(root, flags, true).await?;
    if json {
        println!(
            "{}",
            serde_json::json!({"id":job.id,"name":job.name,"state":"running","shared":root.join(format!("{}.share",job.id)).exists()})
        );
    } else if detach {
        println!(
            "Workspace {} is running\nReattach: porthub terminal {}",
            job.name, job.name
        );
    }
    if !detach {
        attach(&job, sidebar).await?;
    }
    Ok(())
}

pub async fn run(command: Command) -> Result<()> {
    let root = root()?;
    match command {
        Command::ParticipantPopup { root, id, client } => {
            // Reject unauthorized legacy shortcut invocations before resolving
            // any optional code. The helper repeats the complete owner check.
            local_owner_lease(&root, &id, client)?;
            owner_frontend(vec![
                "terminal".into(),
                "__participants-popup".into(),
                root.into_os_string(),
                id.into(),
                client.to_string().into(),
            ])
            .await?
        }
        Command::ParticipantView { root, id, sidebar } => owner_view(&root, &id, sidebar).await?,
        Command::Named(arguments) => open_named(&root, arguments).await?,
        Command::Share(args) => sharing::start(&root, args).await?,
        Command::Join {
            url,
            transport,
            #[cfg(feature = "terminal-direct")]
            registration,
            #[cfg(feature = "terminal-direct")]
            user,
            #[cfg(feature = "terminal-direct")]
            stun_servers,
        } => {
            #[cfg(feature = "terminal-direct")]
            ensure!(
                matches!(transport, JoinTransport::Auto)
                    || (registration.is_none() && !user && stun_servers.is_empty()),
                "--registration, --user and --stun-server apply only to --transport auto"
            );
            use porthub_components::protocol::terminal::{
                JoinRequest, JoinTransport as HelperTransport,
            };
            let (transport, broker, servers) = match transport {
                JoinTransport::Ssh => (HelperTransport::Ssh, None, Vec::new()),
                #[cfg(feature = "terminal-direct")]
                JoinTransport::Relay => (HelperTransport::Relay, None, Vec::new()),
                #[cfg(feature = "terminal-direct")]
                JoinTransport::Auto => (
                    HelperTransport::Auto,
                    crate::terminal_guest::broker(registration.as_deref(), user)?,
                    crate::terminal_connectivity::checked(&stun_servers)?,
                ),
            };
            join_frontend(JoinRequest {
                invitation: url,
                transport,
                broker,
                stun_servers: servers,
            })
            .await?;
        }
        Command::Invite {
            name,
            json,
            revoke,
            rotate,
            link_expires,
        } => {
            let job = select(&root, &name)?;
            if rotate {
                participant_control::rotate_invitations(&job, link_expires.unwrap_or(0)).await?;
                sharing::invite(&root, &job, json)?;
            } else if revoke {
                participant_control::revoke_invitations(&job, json).await?;
            } else {
                sharing::invite(&root, &job, json)?;
            }
        }
        Command::Participants { name, json, watch } => {
            let job = select(&root, &name)?;
            if watch {
                owner_view(&root, &job.id, false).await?;
            } else {
                participant_control::request(&job, None, json).await?;
            }
        }
        Command::Kick { name, client } => {
            participant_control::request(&select(&root, &name)?, Some(client), false).await?
        }
        Command::Serve { id } => sharing::serve(&root, &id).await?,
        Command::New(args) => {
            let sidebar = args.sidebar;
            let detach = args.detach;
            let json = args.json;
            let job = create(&root, args).await?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"id":job.id,"name":job.name,"state":"running","shared":false})
                );
            } else {
                println!(
                    "Workspace {}\nReattach: porthub terminal attach {}",
                    job.name, job.name
                );
            }
            if !detach {
                attach(&job, sidebar).await?;
            }
        }
        Command::List { json, all } => {
            let mut rows = Vec::<serde_json::Value>::new();
            let mut offset = 0;
            loop {
                use porthub_components::protocol::terminal::{Operation, Value};
                let Value::Workspaces { rows: page, next } = terminal_operation(Operation::List {
                    directory: root.clone(),
                    all,
                    offset,
                })
                .await?
                else {
                    anyhow::bail!("invalid terminal listing response")
                };
                rows.extend(
                    page.into_iter()
                        .map(serde_json::to_value)
                        .collect::<std::result::Result<Vec<_>, _>>()?,
                );
                let Some(next) = next else {
                    break;
                };
                ensure!(
                    next > offset && next <= 65536,
                    "invalid terminal listing cursor"
                );
                offset = next;
            }
            if json {
                println!("{}", serde_json::to_string(&rows)?);
            } else {
                if rows.is_empty() {
                    println!(
                        "{}",
                        if all {
                            "No saved terminal workspaces."
                        } else {
                            "No running terminal workspaces."
                        }
                    );
                } else {
                    println!("NAME\tSTATE\tACCESS");
                }
                for row in rows {
                    println!(
                        "{}\t{}\t{}",
                        row["name"].as_str().unwrap(),
                        row["state"].as_str().unwrap(),
                        if row["shared"] == true {
                            "shared"
                        } else {
                            "local"
                        }
                    );
                    if row["state"] == "running" {
                        let name = row["name"].as_str().unwrap();
                        if row["shared"] == true {
                            println!("  URLs:  porthub terminal url {name}");
                        } else {
                            println!("  Share: porthub terminal share {name} --detach");
                        }
                    }
                }
                println!("\nOpen:    porthub terminal NAME\nAttach:  porthub terminal attach NAME\nShare:   porthub terminal share NAME --detach (browser + SSH)\nWeb:     porthub terminal share NAME --access web --detach\nURLs:    porthub terminal url NAME\nHistory: porthub terminal ls --all\nHelp:    porthub terminal --help");
            }
        }
        Command::Attach { name, sidebar } => attach(&select(&root, &name)?, sidebar).await?,
        Command::Stop { name } => {
            use porthub_components::protocol::terminal::{Operation, Value};
            let Value::Stopped { name } = terminal_operation(Operation::Stop {
                directory: root,
                name,
            })
            .await?
            else {
                anyhow::bail!("invalid terminal stop response")
            };
            println!("Stopped {name}");
        }
        Command::Rename { name, new_name } => {
            use porthub_components::protocol::terminal::{Operation, Value};
            let Value::Workspace { job } = terminal_operation(Operation::Rename {
                directory: root,
                name,
                new_name: new_name.clone(),
            })
            .await?
            else {
                anyhow::bail!("invalid terminal rename response")
            };
            ensure!(
                job.name == new_name && token(&job.id, 32),
                "invalid terminal renamed identity"
            );
        }
        Command::Tmux { name, args } => {
            let mut arguments = vec![
                "workspace-tmux".into(),
                "--directory".into(),
                root.into_os_string(),
                "--name".into(),
                name.into(),
                "--".into(),
            ];
            arguments.extend(args);
            owner_frontend(arguments).await?;
        }
    }
    Ok(())
}
