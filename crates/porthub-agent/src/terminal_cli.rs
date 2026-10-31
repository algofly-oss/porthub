//! Local workspaces use the same private bundled multiplexer as shared ones.
//! Local mode needs no registration or network. Sharing uses the local broker.
mod participant_control;
mod participant_panel;
mod participant_popup;
mod sharing;
use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand};
use fs2::FileExt;
use porthub_terminal::{
    multiplexer::{create_directory, Start, Workspace},
    protocol::{random_token, token},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    New(New),
    /// Share a new workspace or an existing local workspace with SSH/browser guests.
    Share(sharing::Share),
    /// Join an invitation using your ordinary SSH client; no account required.
    Join { url: String },
    /// Show, replace or revoke invitation links.
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
    ParticipantView { root: PathBuf, id: String },
    /// List this OS user's local and shared workspaces.
    #[command(alias = "ls")]
    List {
        #[arg(long)]
        json: bool,
    },
    /// Attach or reattach, including from inside another tmux session.
    Attach { name: String },
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
            command: Vec::new(),
        })
    }
}

#[derive(Args, Clone)]
pub struct New {
    /// Friendly lowercase random name when omitted.
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    cwd: Option<PathBuf>,
    #[arg(long)]
    shell: Option<PathBuf>,
    /// Environment overrides for the workspace, e.g. --env MODE=debug.
    #[arg(long = "env")]
    environment: Vec<String>,
    /// Start in the background; it remains available with terminal attach.
    #[arg(short = 'd', long)]
    detach: bool,
    #[arg(long, requires = "detach")]
    json: bool,
    #[arg(long, default_value = "C-a")]
    prefix: String,
    #[arg(long, default_value_t = 100000)]
    history_limit: u32,
    #[arg(long)]
    no_mouse: bool,
    /// Command and arguments; omit to start an interactive shell.
    #[arg(last = true)]
    command: Vec<OsString>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    id: String,
    name: String,
    executable: PathBuf,
    executable_sha256: String,
    terminfo: PathBuf,
    workspace: PathBuf,
    created_at: i64,
}

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
    match create_directory(&root) {
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

fn workspace(job: &Job) -> Result<Workspace> {
    let metadata = fs::symlink_metadata(&job.executable)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o022 == 0,
        "unsafe terminal runtime executable"
    );
    ensure!(
        format!("{:x}", Sha256::digest(fs::read(&job.executable)?)) == job.executable_sha256,
        "terminal runtime checksum mismatch"
    );
    Workspace::open(
        job.executable.clone(),
        job.terminfo.clone(),
        job.workspace.clone(),
    )
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

fn attach(job: &Job) -> Result<()> {
    let workspace = workspace(job)?;
    ensure!(workspace.is_alive(), "workspace has ended");
    // Recognize our own server instead of recursively attaching to ourselves.
    if std::env::var_os("TMUX").is_some_and(|value| {
        value.to_string_lossy().split(',').next() == workspace.socket().to_str()
    }) {
        println!("Already attached to {}", job.name);
        return Ok(());
    }
    participant_popup::attach(job, &workspace)
}

fn create(root: &Path, args: New) -> Result<Job> {
    let _guard = lock(root)?;
    create_locked(root, args)
}

fn create_locked(root: &Path, args: New) -> Result<Job> {
    let existing = jobs(root)?;
    let name = match args.name {
        Some(name) => name,
        None => {
            porthub_terminal::names::generate(|name| existing.iter().any(|job| job.name == name))?
        }
    };
    name_valid(&name)?;
    ensure!(
        !existing.iter().any(|job| job.name == name),
        "workspace name already exists"
    );
    let runtime_dir = root.join("runtimes");
    if !runtime_dir.exists() {
        create_directory(&runtime_dir)?;
    }
    let runtime = crate::terminal_runtime::install(&runtime_dir)?;
    let id = random_token(16);
    let path = socket_root()?.join(&id);
    create_directory(&path)?;
    let job = Job {
        id: id.clone(),
        name,
        executable_sha256: format!("{:x}", Sha256::digest(fs::read(&runtime.executable)?)),
        executable: runtime.executable,
        terminfo: runtime.terminfo,
        workspace: path,
        created_at: porthub_terminal::protocol::now(),
    };
    let cwd = args
        .cwd
        .unwrap_or(std::env::current_dir()?)
        .canonicalize()?;
    let shell = args
        .shell
        .or_else(|| std::env::var_os("SHELL").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/bin/sh"));
    let environment = args
        .environment
        .iter()
        .map(|entry| {
            entry
                .split_once('=')
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .context("environment overrides must use KEY=VALUE")
        })
        .collect::<Result<Vec<_>>>()?;
    let ws = workspace(&job)?;
    ws.start(&Start {
        cwd,
        shell,
        command: args.command,
        environment,
        history_limit: args.history_limit,
        mouse: !args.no_mouse,
        prefix: args.prefix,
        cols: 100,
        rows: 30,
    })?;
    if let Err(error) = crate::profile::write_private(
        &root.join(format!("{id}.json")),
        &serde_json::to_vec(&job)?,
        false,
    ) {
        let _ = ws.stop();
        return Err(error);
    }
    Ok(job)
}

fn open_named(root: &Path, arguments: Vec<OsString>) -> Result<()> {
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
    let detach = flags.detach;
    let json = flags.json;
    let guard = lock(root)?;
    let existing = jobs(root)?.into_iter().find(|job| job.name == name);
    let job = match existing {
        Some(job) if workspace(&job)?.is_alive() => job,
        ended => {
            if let Some(job) = ended {
                // Preserve the ended identity for investigation while allowing
                // the familiar name to create a fresh workspace and new caps.
                let archive = root.join("archive");
                if !archive.exists() {
                    create_directory(&archive)?;
                }
                private(&archive)?;
                fs::rename(
                    root.join(format!("{}.json", job.id)),
                    archive.join(format!("{}.json", job.id)),
                )?;
            }
            create_locked(root, flags)?
        }
    };
    drop(guard);
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
        attach(&job)?;
    }
    Ok(())
}

pub async fn run(command: Command) -> Result<()> {
    let root = root()?;
    match command {
        Command::ParticipantPopup { root, id, client } => {
            participant_popup::show(&root, &id, client)?
        }
        Command::ParticipantView { root, id } => participant_popup::view(&root, &id).await?,
        Command::Named(arguments) => open_named(&root, arguments)?,
        Command::Share(args) => sharing::start(&root, args).await?,
        Command::Join { url } => sharing::join(&url).await?,
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
                participant_panel::run(job).await?;
            } else {
                participant_control::request(&job, None, json).await?;
            }
        }
        Command::Kick { name, client } => {
            participant_control::request(&select(&root, &name)?, Some(client), false).await?
        }
        Command::Serve { id } => sharing::serve(&root, &id).await?,
        Command::New(args) => {
            let detach = args.detach;
            let json = args.json;
            let job = create(&root, args)?;
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
                attach(&job)?;
            }
        }
        Command::List { json } => {
            let rows:Vec<_>=jobs(&root)?.into_iter().map(|job|{
                let running=workspace(&job).is_ok_and(|workspace|workspace.is_alive());
                serde_json::json!({"id":job.id,"name":job.name,"state":if running{"running"}else{"ended"},"shared":root.join(format!("{}.share",job.id)).exists(),"created_at":job.created_at})
            }).collect();
            if json {
                println!("{}", serde_json::to_string(&rows)?);
            } else {
                for row in rows {
                    println!(
                        "{}\t{}\t{}",
                        row["name"].as_str().unwrap(),
                        row["state"].as_str().unwrap(),
                        row["id"].as_str().unwrap()
                    );
                }
            }
        }
        Command::Attach { name } => attach(&select(&root, &name)?)?,
        Command::Stop { name } => {
            let job = select(&root, &name)?;
            workspace(&job)?.stop()?;
            println!("Stopped {}", job.name);
        }
        Command::Rename { name, new_name } => {
            name_valid(&new_name)?;
            let _guard = lock(&root)?;
            ensure!(
                !jobs(&root)?.iter().any(|job| job.name == new_name),
                "workspace name already exists"
            );
            let mut job = select(&root, &name)?;
            job.name = new_name;
            crate::profile::write_private(
                &root.join(format!("{}.json", job.id)),
                &serde_json::to_vec(&job)?,
                true,
            )?;
        }
        Command::Tmux { name, args } => {
            ensure!(
                args.first()
                    .is_some_and(|arg| !arg.is_empty() && !arg.to_string_lossy().starts_with('-')),
                "pass a tmux command without global flags; PortHub selects this workspace's socket"
            );
            let job = select(&root, &name)?;
            ensure!(
                workspace(&job)?.command().args(args).status()?.success(),
                "tmux command failed"
            );
        }
    }
    Ok(())
}
