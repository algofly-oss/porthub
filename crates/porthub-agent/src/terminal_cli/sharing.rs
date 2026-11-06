//! Sharing supervisor belongs to the invoking OS user and outlives the CLI
//! terminal. The system service brokers credentials, never launches the shell.
use super::*;
use porthub_components::protocol::terminal::Broker;
use porthub_terminal::protocol::*;
use std::{
    os::unix::process::CommandExt,
    process::{Command as Process, Stdio},
    time::Duration,
};

#[derive(Args)]
pub struct Share {
    /// Keep this share on the gateway; never advertise a direct peer path.
    #[arg(long, conflicts_with = "stun_servers")]
    relay_only: bool,
    /// Optional UDP STUN endpoint for this host; repeat up to twice. No default.
    #[arg(long="stun-server",value_parser=crate::terminal_connectivity::server)]
    stun_servers: Vec<String>,
    /// Existing local workspace; omit to create one.
    existing: Option<String>,
    #[command(flatten)]
    local: New,
    /// Installed registration to use for the sharing gateway.
    #[arg(long)]
    registration: Option<String>,
    /// Select a registration installed for this OS user.
    #[arg(long)]
    user: bool,
    /// New-join invitation lifetime in seconds; zero means until session end.
    #[arg(long, default_value_t = 0)]
    link_expires: u32,
    /// Explicit workspace lifetime in seconds; zero disables this limit.
    #[arg(long, default_value_t = 0)]
    session_timeout: u32,
    /// Explicit idle limit in seconds; zero disables this limit.
    #[arg(long, default_value_t = 0)]
    idle_timeout: u32,
    /// Seconds to allow a disconnected host to recover its gateway connection.
    #[arg(long, default_value_t = 60)]
    reconnect_timeout: u32,
    /// Maximum simultaneous invited guests (1 to 32).
    #[arg(long, default_value_t = 16)]
    max_viewers: u8,
    /// Issue only read-only invitations; guests cannot type into the workspace.
    #[arg(long)]
    read_only: bool,
    /// Invitation access channels: SSH, browser, or both.
    #[arg(long,default_value="both",value_parser=["ssh","web","both"])]
    access: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Ready {
    ssh_host: String,
    ssh_port: u16,
    public_base: String,
}
#[derive(Serialize, Deserialize)]
struct Sharing {
    #[serde(default)]
    broker: Option<Broker>,
    #[serde(default)]
    stun_servers: Vec<String>,
    #[serde(default)]
    invitations: Option<InvitationUpdate>,
    #[serde(default)]
    pending_invitations: Option<InvitationUpdate>,
    #[serde(default)]
    invitations_revoked: bool,
    hello: HostHello,
    registration: String,
    user: bool,
    ready: Option<Ready>,
    state: String,
}

fn path(root: &Path, id: &str) -> Result<PathBuf> {
    ensure!(token(id, 32), "invalid terminal session identity");
    Ok(root.join(format!("{id}.share")))
}
fn load(root: &Path, id: &str) -> Result<Sharing> {
    let sharing: Sharing =
        serde_json::from_slice(&crate::profile::read_private(&path(root, id)?)?)?;
    ensure!(sharing.hello.id == id, "terminal sharing identity mismatch");
    sharing.hello.validate(now())?;
    crate::terminal_connectivity::checked(&sharing.stun_servers)?;
    if let Some(update) = &sharing.invitations {
        update.validate(now())?;
    }
    if let Some(pending) = &sharing.pending_invitations {
        pending.validate(now())?;
        ensure!(
            pending.revision
                == sharing
                    .invitations
                    .as_ref()
                    .map_or(0, |u| u.revision)
                    .saturating_add(1),
            "invalid pending invitation revision"
        );
    }
    Ok(sharing)
}
fn save(root: &Path, sharing: &Sharing, replace: bool) -> Result<()> {
    crate::profile::write_private(
        &path(root, &sharing.hello.id)?,
        &serde_json::to_vec(sharing)?,
        replace,
    )
}
fn worker_lock(root: &Path, id: &str) -> Result<fs::File> {
    ensure!(token(id, 32), "invalid terminal session identity");
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(root.join(format!("{id}.share.lock")))?;
    ensure!(
        file.metadata()?.uid() == unsafe { libc::geteuid() },
        "invalid terminal supervisor lock owner"
    );
    file.try_lock_exclusive()
        .context("terminal sharing supervisor is already running")?;
    Ok(file)
}
fn launch(root: &Path, id: &str) -> Result<()> {
    let log = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(root.join(format!("{id}.share.log")))?;
    ensure!(
        log.metadata()?.uid() == unsafe { libc::geteuid() },
        "invalid terminal supervisor log owner"
    );
    let mut command = Process::new(std::env::current_exe()?);
    command
        .args(["terminal", "__serve", id])
        .env_remove("TMUX")
        .env_remove("TMUX_PANE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log);
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    command.spawn()?;
    Ok(())
}

fn broker_has_history_snapshots(version: &str) -> bool {
    let parts: Vec<_> = version.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let parsed: Option<Vec<u32>> = parts
        .iter()
        .map(|part| {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            part.parse().ok()
        })
        .collect();
    parsed.is_some_and(|v| (v[0], v[1], v[2]) >= (1, 10, 0))
}

pub(super) async fn start(root: &Path, args: Share) -> Result<()> {
    let layout = if args.user {
        crate::service::Layout::user()?
    } else {
        crate::service::Layout::system()?
    };
    let registration =
        crate::service::readable::select(&layout, args.registration.as_deref(), Some(false))?;
    let sidebar = args.local.sidebar;
    let detach = args.local.detach;
    let json = args.local.json;
    // Validate before starting any shells or publishing session capabilities.
    let options = Options {
        name: "validation".into(),
        expires_at: if args.link_expires == 0 {
            0
        } else {
            now() + i64::from(args.link_expires)
        },
        session_expires_at: if args.session_timeout == 0 {
            None
        } else {
            Some(now() + i64::from(args.session_timeout))
        },
        idle_timeout: args.idle_timeout,
        reconnect_timeout: args.reconnect_timeout,
        history_limit: args.local.history_limit,
        mouse: !args.local.no_mouse,
        read_only: args.read_only,
        size_policy: SizePolicy::Smallest,
        max_viewers: args.max_viewers,
        access: match args.access.as_str() {
            "ssh" => Access::Ssh,
            "web" => Access::Web,
            _ => Access::Both,
        },
    };
    options.validate(now())?;
    let stun_servers = crate::terminal_connectivity::checked(&args.stun_servers)?;
    ensure!(
        stun_servers.is_empty() || cfg!(feature = "terminal-direct"),
        "this build does not include native terminal direct transport"
    );
    let job = if let Some(name) = args.existing {
        select(root, &name)?
    } else {
        create(root, args.local).await?
    };
    ensure!(
        workspace(&job)?.is_alive(),
        "cannot share an ended workspace"
    );
    let _registry = lock(root)?;
    if path(root, &job.id)?.exists() {
        let previous = load(root, &job.id)?;
        ensure!(
            !args.relay_only || !previous.hello.direct_transport,
            "this workspace already permits direct transport; existing guests were not changed"
        );
        ensure!(stun_servers.is_empty() || previous.stun_servers==stun_servers,"this workspace is already shared with different STUN settings; existing guests were not changed");
        ensure!(
            previous.state != "ended",
            "this sharing invitation was ended; create a new workspace to share"
        );
        if let Ok(guard) = worker_lock(root, &job.id) {
            drop(guard);
            launch(root, &job.id)?;
        }
    } else {
        let mut options = options;
        options.name = job.name.clone();
        let sharing = Sharing {
            broker: Some(Broker {
                endpoint: crate::exposure_broker::endpoint(&layout, &registration.id)?,
                owner: if args.user {
                    unsafe { libc::geteuid() }
                } else {
                    0
                },
                traffic: broker_has_history_snapshots(&registration.agent_version),
            }),
            stun_servers,
            invitations: None,
            pending_invitations: None,
            invitations_revoked: false,
            hello: HostHello {
                direct_transport: !args.relay_only
                    && cfg!(feature = "terminal-direct")
                    && broker_has_history_snapshots(&registration.agent_version),
                history_snapshots: broker_has_history_snapshots(&registration.agent_version),
                id: job.id.clone(),
                secret: random_token(32),
                write_token: random_token(32),
                read_token: random_token(32),
                options,
            },
            registration: registration.id,
            user: args.user,
            ready: None,
            state: "connecting".into(),
        };
        save(root, &sharing, false)?;
        launch(root, &job.id)?;
    }
    drop(_registry);
    for _ in 0..300 {
        let state = load(root, &job.id)?;
        if state.state == "connected" {
            break;
        }
        ensure!(
            state.state != "ended",
            "workspace ended before sharing connected"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    invite(root, &job, json)?;
    if !detach {
        attach(&job, sidebar).await?;
    }
    Ok(())
}

pub(super) fn invite(root: &Path, job: &Job, json: bool) -> Result<()> {
    let sharing = load(root, &job.id)?;
    ensure!(sharing.state != "ended", "sharing session has ended");
    ensure!(sharing.pending_invitations.is_none(), "invitation rotation is pending gateway confirmation; retry terminal invite --rotate when connected");
    ensure!(
        !sharing.invitations_revoked,
        "invitation URLs were revoked; existing participants may continue"
    );
    let write_token = sharing
        .invitations
        .as_ref()
        .map_or(sharing.hello.write_token.as_str(), |update| {
            update.write_token.as_str()
        });
    let read_token = sharing
        .invitations
        .as_ref()
        .map_or(sharing.hello.read_token.as_str(), |update| {
            update.read_token.as_str()
        });
    let expires_at = sharing
        .invitations
        .as_ref()
        .map_or(sharing.hello.options.expires_at, |update| update.expires_at);
    let Some(ready) = sharing.ready else {
        anyhow::bail!("workspace {} is running locally, but sharing is still reconnecting; use terminal invite {} when the gateway is available",job.name,job.name);
    };
    let link = |token: &str| {
        format!(
            "{}/terminal#{token}",
            ready.public_base.trim_end_matches('/')
        )
    };
    let ssh = |token: &str| format!("ssh -p {} -l {} {}", ready.ssh_port, token, ready.ssh_host);
    let web = sharing.hello.options.access != Access::Ssh;
    let ssh_enabled = sharing.hello.options.access != Access::Web;
    let interactive = !sharing.hello.options.read_only;
    let data = serde_json::json!({"name":job.name,"id":job.id,"state":sharing.state,
        "interactive_url":(web && interactive).then(||link(write_token)),
        "read_only_url":web.then(||link(read_token)),
        "interactive_ssh":(ssh_enabled && interactive).then(||ssh(write_token)),
        "read_only_ssh":ssh_enabled.then(||ssh(read_token)),
        "expires_at":expires_at,"access":sharing.hello.options.access,"stun_servers":sharing.stun_servers});
    if json {
        println!("{}", serde_json::to_string(&data)?);
    } else {
        println!("Workspace {}", job.name);
        for (key, label) in [
            ("interactive_url", "Interactive"),
            ("read_only_url", "Read only"),
            ("interactive_ssh", "SSH"),
            ("read_only_ssh", "Read-only SSH"),
        ] {
            if let Some(value) = data[key].as_str() {
                println!("{label}: {value}");
            }
        }
        println!("Reattach: porthub terminal attach {}", job.name);
        if expires_at != 0 && expires_at <= now() {
            println!(
                "Invitation expired: existing participants may continue; new joins are blocked."
            );
        }
    }
    Ok(())
}

pub(super) async fn serve(root: &Path, id: &str) -> Result<()> {
    let mut sharing = load(root, id)?;
    if sharing.broker.is_none() {
        let layout = if sharing.user {
            crate::service::Layout::user()?
        } else {
            crate::service::Layout::system()?
        };
        sharing.broker = Some(Broker {
            endpoint: crate::exposure_broker::endpoint(&layout, &sharing.registration)?,
            owner: if sharing.user {
                unsafe { libc::geteuid() }
            } else {
                0
            },
            traffic: crate::service::readable::select(
                &layout,
                Some(&sharing.registration),
                Some(false),
            )
            .is_ok_and(|record| broker_has_history_snapshots(&record.agent_version)),
        });
        save(root, &sharing, true)?;
    }
    super::owner_frontend(vec![
        "terminal".into(),
        "__serve".into(),
        root.as_os_str().into(),
        id.into(),
    ])
    .await
}
