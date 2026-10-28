use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use porthub_transfer::{download, server};
use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::process::Command as ProcessCommand;
use std::{net::IpAddr, path::PathBuf};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    name = "porthub",
    version = option_env!("PORTHUB_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),
    about = "PortHub agent and transfer tools",
    color = clap::ColorChoice::Auto,
    after_long_help = "Examples:\n  porthub ls\n  porthub http.server ./public\n  porthub http.receive ./drop\n  porthub expose 8080\n  porthub expose 8080 --subdomain myapp --detach\n  porthub push ./dataset http://host:8001/\n  porthub get https://example.com/file.iso"
)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum SyncCommand {
    /// List active directory watch jobs.
    List,
    /// Show the progress of a directory watch job.
    Status { id: String },
    /// Stop a directory watch job without removing transferred files.
    Stop { id: String },
    #[command(hide = true)]
    Run { id: String },
}

fn requires_system_privileges(args: &Args) -> bool {
    let Some(command) = args.command.as_ref() else {
        return false;
    };
    match command {
        Command::Enroll {
            install_service, ..
        } => *install_service,
        Command::Setup {
            user, no_service, ..
        } => !user && !no_service,
        Command::List { .. } => false,
        Command::Path { command } => match command {
            PathCommand::Show(_) => false,
            PathCommand::Reset(args) => !args.user && args.profile.is_none(),
            PathCommand::Set { registration, .. } => {
                !registration.user && registration.profile.is_none()
            }
        },
        #[cfg(feature="local-tor")]
        Command::Tor {command}=>match command {
            TorCommand::Status(_)=>false,
            TorCommand::Start {registration,system_wide,..}=>*system_wide || (!registration.user && registration.profile.is_none()),
            TorCommand::Stop(registration)|TorCommand::Reset(registration)=>!registration.user && registration.profile.is_none(),
        },
        Command::Start(args) | Command::Stop(args) | Command::Restart(args) => !args.user,
        Command::Remove(args) => !args.user,
        Command::Status { .. } => false,
        Command::Service { user, action } => {
            !user && !matches!(action, ServiceCommand::Status { .. })
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::Update { user, .. } => !user,
        Command::HttpServer {
            target,
            port_override,
            ..
        } => {
            (*port_override).is_some_and(is_privileged_port)
                || target.parse::<u16>().is_ok_and(is_privileged_port)
        }
        Command::HttpReceive {
            target,
            port_override,
            ..
        } => {
            (*port_override).is_some_and(is_privileged_port)
                || target.parse::<u16>().is_ok_and(is_privileged_port)
        }
        Command::Expose { .. } => false,
        #[cfg(feature="local-tor")]
        Command::Proxy {command}=>matches!(command,porthub_agent::proxy_cli::Command::Start {port,..} if is_privileged_port(*port)),
        Command::Run { profile } => {
            porthub_agent::private_network::is_profile(profile).unwrap_or(false)
        }
        _ => false,
    }
}

fn is_privileged_port(port: u16) -> bool {
    port != 0 && port < 1024
}

fn elevate_if_needed(args: &Args) -> Result<()> {
    if !requires_system_privileges(args) {
        return Ok(());
    }
    #[cfg(unix)]
    if !rustix::process::geteuid().is_root() {
        let executable = std::env::current_exe().context("cannot locate PortHub executable")?;
        let status = ProcessCommand::new("sudo")
            .arg("--")
            .arg(executable)
            .args(std::env::args_os().skip(1))
            .status()
            .context("system privileges are required; install sudo or run this command as root")?;
        std::process::exit(status.code().unwrap_or(1));
    }
    #[cfg(windows)]
    if requires_system_privileges(args) {
        porthub_agent::service::require_administrator()?;
    }
    Ok(())
}

fn paint(text: impl std::fmt::Display, style: &str) -> String {
    use std::io::IsTerminal;
    let enabled = std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").is_ok_and(|term| term != "dumb");
    if enabled {
        format!("\x1b[{style}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn display_gateway_url(server: &str) -> String {
    let server = server.trim_end_matches('/');
    server
        .strip_suffix("/api")
        .unwrap_or(server)
        .trim_end_matches('/')
        .to_owned()
}

fn print_help() -> Result<()> {
    Args::command().print_help()?;
    println!();
    Ok(())
}

fn short_version_requested(arguments: &[OsString]) -> bool {
    arguments.len() == 2 && arguments[1] == OsStr::new("-v")
}

#[derive(clap::Args, Default)]
struct HttpPublicOptions {
    /// Create a temporary public mapping through the registered PortHub agent.
    #[arg(long)]
    expose: bool,
    /// Reserve this external gateway port (the server's --port remains local).
    #[arg(long, requires = "expose")]
    public_port: Option<u16>,
    /// Create a temporary web address for the public server.
    #[arg(long, requires = "expose")]
    subdomain: Option<String>,
    /// Select the registered account when this machine has multiple registrations.
    #[arg(long, requires = "expose")]
    registration: Option<String>,
    #[arg(long, requires = "expose")]
    user: bool,
    /// Keep this server and its optional public mapping running in the background.
    #[arg(short = 'd', long)]
    detach: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Hidden Windows SCM entrypoint used by a managed PortHub service.
    #[cfg(windows)]
    #[command(name = "__windows-service", hide = true)]
    WindowsServiceHost {
        #[arg(long)]
        service_name: String,
        #[arg(long)]
        service_id: String,
        #[arg(long)]
        profile: PathBuf,
    },
    /// Enroll a private identity; long tickets are read from stdin.
    #[command(hide = true)]
    Enroll {
        #[arg(long, required_unless_present = "ticket", conflicts_with = "ticket")]
        server: Option<String>,
        #[arg(long)]
        ticket: Option<String>,
        #[arg(long, required_unless_present = "ticket")]
        profile: Option<PathBuf>,
        #[arg(long)]
        user: bool,
        /// Install and activate a system service after enrollment.
        #[arg(long, conflicts_with = "user")]
        install_service: bool,
        #[arg(long)]
        allow_insecure_http_for_tests: bool,
    },
    /// Compatibility helper for staged credentials from a generated legacy profile.
    #[command(name = "import-legacy", hide = true)]
    ImportLegacy {
        #[arg(long)]
        env_file: PathBuf,
        #[arg(long)]
        profile: PathBuf,
        /// Explicit fallback authorities belonging to the same gateway.
        #[arg(long = "fallback-server")]
        fallback_servers: Vec<String>,
    },
    /// List native registrations without exposing credentials or origin addresses.
    #[command(name = "list", alias = "ls")]
    List {
        #[arg(long)]
        user: bool,
        #[arg(long)]
        json: bool,
    },
    /// Inspect, override, or reset a private registration's path strategy.
    Path {
        #[command(subcommand)]
        command: PathCommand,
    },
    /// Start and manage authenticated application proxies.
    #[cfg(feature="local-tor")]
    Proxy {
        #[command(subcommand)]
        command:porthub_agent::proxy_cli::Command,
    },
    /// Control this registration's embedded local Tor client.
    #[cfg(feature="local-tor")]
    Tor {
        #[command(subcommand)]
        command:TorCommand,
    },
    /// Start one native registration selected by id from porthub ls.
    #[command(alias = "up")]
    Start(TenantArgs),
    /// Stop one native registration.
    #[command(alias = "down")]
    Stop(TenantArgs),
    /// Restart one native registration.
    Restart(TenantArgs),
    /// Remove one native registration, preserving other profiles and the shared CLI.
    #[command(alias = "rm", alias = "uninstall")]
    Remove(TenantArgs),
    /// Enroll using a short installer link and install the native boot-time service.
    Setup {
        #[arg(long)]
        ticket: String,
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        user: bool,
        /// Publish the interactive CLI here; defaults to /usr/local/bin or ~/.local/bin.
        #[arg(long, conflicts_with = "no_service")]
        bin_dir: Option<PathBuf>,
        /// Save credentials without activating a service (requires --profile).
        #[arg(long, requires = "profile")]
        no_service: bool,
        /// Adopt the existing CLI during the authenticated installer migration.
        #[arg(long, hide = true, conflicts_with = "no_service")]
        adopt_existing_cli: bool,
        #[arg(long)]
        allow_insecure_http_for_tests: bool,
    },
    /// Serve files with HTTP Range, cache validators and directory listings.
    #[command(name = "http.server", alias = "http-server")]
    HttpServer {
        #[arg(default_value = "8000", value_name = "PORT|PATH|list|stop")]
        target: String,
        #[arg(value_name = "PATH|PORT")]
        path: Option<String>,
        #[arg(long, default_value = "0.0.0.0")]
        bind: IpAddr,
        #[arg(short = 'p', long = "port")]
        port_override: Option<u16>,
        #[arg(long = "path")]
        root: Option<PathBuf>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        upload: bool,
        #[command(flatten)]
        public: HttpPublicOptions,
    },
    /// Receive direct HTTP uploads from curl/wget or `porthub push`.
    #[command(name = "http.receive", alias = "http-receive")]
    HttpReceive {
        #[arg(default_value = "8001", value_name = "PORT|PATH|list|stop")]
        target: String,
        #[arg(value_name = "PATH|PORT")]
        path: Option<String>,
        #[arg(long, default_value = "0.0.0.0")]
        bind: IpAddr,
        #[arg(short = 'p', long = "port")]
        port_override: Option<u16>,
        #[arg(long = "path")]
        root: Option<PathBuf>,
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        public: HttpPublicOptions,
    },
    /// Expose a local port temporarily through the PortHub gateway.
    #[command(name = "expose")]
    Expose {
        #[arg(value_name = "PORT|list|stop")]
        target: Option<String>,
        #[arg(value_name = "ID")]
        id: Option<String>,
        /// Reserve a specific external gateway port instead of choosing one.
        #[arg(long, short = 'p')]
        port: Option<u16>,
        /// Create a temporary web proxy on this subdomain label.
        #[arg(long)]
        subdomain: Option<String>,
        /// Keep the exposure running in the background.
        #[arg(long, short = 'd')]
        detach: bool,
        /// Use a per-user registration instead of the system service.
        #[arg(long)]
        user: bool,
        /// Select a registration by ID from `porthub ls` when multiple exist.
        #[arg(long)]
        registration: Option<String>,
        #[arg(long, hide = true)]
        worker: bool,
        #[arg(long, hide = true, requires = "worker")]
        session_id: Option<String>,
    },
    /// Download files or sync directories with parallel ranges and safe resume.
    Get {
        url: String,
        #[arg(short = 'd', long = "dir", default_value = ".")]
        directory: PathBuf,
        #[arg(short = 'x', long, default_value_t = 16)]
        connections: usize,
        #[arg(long)]
        sha256: Option<String>,
        /// Minimum size of a parallel download segment, in bytes.
        #[arg(long,default_value_t=8*1024*1024)]
        segment_size: u64,
        /// Put the contents of a remote directory directly in --dir.
        #[arg(long)]
        contents_only: bool,
    },
    /// Send files or sync directories directly to another PortHub receiver.
    Push {
        path: PathBuf,
        url: String,
        #[arg(short = 'x', long, default_value_t = 16)]
        connections: usize,
        /// Place directory contents directly in the receiver root instead of retaining its top folder.
        #[arg(long)]
        contents_only: bool,
        /// Send every file even when size and modification time already match.
        #[arg(long)]
        force: bool,
        /// Keep syncing directory changes until stopped.
        #[arg(short = 'w', long)]
        watch: bool,
        /// Run a watch job in the background.
        #[arg(short = 'd', long, requires = "watch")]
        detach: bool,
    },
    /// List, inspect, or stop directory watch jobs for this user.
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },
    /// Run public service forwarding using an in-process Rathole client.
    #[command(hide = true)]
    Tunnel {
        #[arg(short = 'c', long)]
        config: PathBuf,
    },
    /// Save a machine profile; read its token from stdin instead of process arguments.
    #[command(hide = true)]
    Configure {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        server: String,
        #[arg(long)]
        machine_id: String,
        #[arg(long = "fallback-server")]
        fallback_servers: Vec<String>,
        #[arg(long)]
        allow_insecure_http_for_tests: bool,
    },
    /// Run a saved machine profile, with native control sync and embedded tunnels.
    #[command(hide = true)]
    Run {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Show credential-free runtime status for a saved machine profile.
    Status {
        selector: Option<String>,
        #[arg(long, conflicts_with = "selector")]
        profile: Option<PathBuf>,
        #[arg(long)]
        user: bool,
    },
    /// Manage a boot-time service for one registered machine profile.
    #[command(hide = true)]
    Service {
        #[arg(long, global = true)]
        user: bool,
        #[command(subcommand)]
        action: ServiceCommand,
    },
    /// Display the installed agent release.
    Version {
        /// Include build provenance without changing the release version.
        #[arg(long)]
        verbose: bool,
    },
    /// Check or update an installed registration and its networking modules.
    #[command(hide = true)]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Update {
        selector: Option<String>,
        #[arg(long, conflicts_with = "selector")]
        profile: Option<PathBuf>,
        #[arg(long)]
        user: bool,
        #[arg(long, conflicts_with_all=["apply","rollback"])]
        check: bool,
        #[arg(long)]
        bin_dir: Option<PathBuf>,
        #[arg(long, conflicts_with_all=["selector","profile","check","apply","release_record"])]
        rollback: Option<PathBuf>,
        #[arg(long, hide = true, requires = "release_record")]
        apply: bool,
        #[arg(long, hide = true, requires = "apply")]
        release_record: Option<PathBuf>,
        #[arg(long,hide=true,requires="target_version",conflicts_with_all=["check","rollback"])]
        request_id: Option<String>,
        #[arg(long,hide=true,requires="request_id",conflicts_with_all=["check","rollback"])]
        target_version: Option<String>,
    },
}

struct HttpCommandOptions {
    target: String,
    path: Option<String>,
    bind: IpAddr,
    port_override: Option<u16>,
    root: Option<PathBuf>,
    all: bool,
    accept_uploads: bool,
    public: HttpPublicOptions,
}
async fn run_http_command(options: HttpCommandOptions, cancel: CancellationToken) -> Result<()> {
    let HttpCommandOptions {
        target,
        path,
        bind,
        port_override,
        root,
        all,
        accept_uploads,
        public,
    } = options;
    anyhow::ensure!(!matches!(target.as_str(), "list" | "stop") || (!public.detach && !public.expose), "--detach and --expose apply when starting a server");
    if target == "list" {
        for record in server::list().await? {
            println!(
                "port {}  bind {}  pid {}  uploads {}  {}",
                record.port,
                record.bind,
                record.pid,
                if record.accepts_uploads { "on" } else { "off" },
                record.root.display()
            );
        }
        return Ok(());
    }
    if target == "stop" {
        let port = if all {
            None
        } else {
            Some(
                path.context("usage: porthub http.server stop PORT|--all")?
                    .parse::<u16>()?,
            )
        };
        for port in server::stop_servers(port).await? {
            println!("Stopped HTTP server on port {port}");
        }
        return Ok(());
    }
    let (port, default_root) = match target.parse::<u16>() {
        Ok(port) => (
            port,
            path.map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(".")),
        ),
        Err(_) => {
            if path.is_some() {
                bail!("expected a port followed by a path");
            }
            (
                if accept_uploads { 8001 } else { 8000 },
                PathBuf::from(target),
            )
        }
    };
    porthub_agent::http_tools::run(
        server::Options {
            port: port_override.unwrap_or(port),
            bind,
            root: root.unwrap_or(default_root),
            accept_uploads,
        },
        porthub_agent::http_tools::Exposure { enabled: public.expose, public_port: public.public_port, subdomain: public.subdomain, registration: public.registration, user: public.user },
        public.detach,
        cancel,
    )
    .await
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct UpdateOptions {
    source: PathBuf,
    user: bool,
    check: bool,
    bin_dir: Option<PathBuf>,
    apply: bool,
    record: Option<PathBuf>,
    request: Option<porthub_agent::update::Request>,
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn update_command(options: UpdateOptions, cancel: &CancellationToken) -> Result<()> {
    let UpdateOptions {
        source,
        user,
        check,
        bin_dir,
        apply,
        record,
        request,
    } = options;
    if let Some(request) = &request {
        request.validate()?;
    }
    use porthub_agent::{
        control::Control,
        profile::{self, Profile},
        service::{self, RuntimeReady},
        update::{self, Staged},
        upgrade,
    };
    let layout = layout(user)?;
    let public = Profile::load(&source).context("updates require the public enrollment profile")?;
    let cli = porthub_agent::bootstrap::cli_path(user, bin_dir.as_deref())?;
    let manager = service::system_manager(user).await?;
    let plan = upgrade::plan(&layout, &public, Some(&cli), manager.as_ref()).await?;
    if apply {
        let record = record.context("verified release record required")?;
        anyhow::ensure!(
            record.parent() == Some(layout.state.as_path())
                && record
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("update-release-")),
            "release record is outside managed state"
        );
        let release: update::Release = serde_json::from_slice(&profile::read_private(&record)?)?;
        let staged = Staged {
            release,
            executable: std::env::current_exe()?,
        };
        staged.verify_executable(cancel).await?;
        let receipt = upgrade::apply_requested(
            &layout,
            plan,
            &staged.executable,
            manager.as_ref(),
            &RuntimeReady,
            request,
        )
        .await?;
        println!(
            "Native update completed; recovery receipt: {}",
            receipt.display()
        );
        return Ok(());
    }
    let control = Control::new(public.clone())?;
    let release = update::discover(&control, update::native_target()?, cancel).await?;
    if let Some(request) = &request {
        anyhow::ensure!(
            release.version == request.target_version,
            "requested native release is not published"
        );
    }
    if check {
        println!(
            "CLI agent {}; published release {} ({})",
            porthub_agent::VERSION,
            release.version,
            release.target
        );
        return Ok(());
    }
    let staged = update::stage(&control, &release, &layout.releases, cancel).await?;
    staged.verify_executable(cancel).await?;
    let record = layout.state.join(format!(
        "update-release-{}.json",
        release.sha256.to_ascii_lowercase()
    ));
    let bytes = serde_json::to_vec(&release)?;
    if record.try_exists()? {
        anyhow::ensure!(
            profile::read_private(&record)? == bytes,
            "staged release metadata changed"
        );
    } else {
        profile::write_private(&record, &bytes, false)?;
    }
    let canonical_profile = layout
        .state
        .join(format!("{}.json", service::identity(&public)));
    let path = |path: &std::path::Path| {
        path.to_str()
            .map(str::to_owned)
            .context("update paths must be Unicode")
    };
    let mut arguments = vec![
        "update".into(),
        "--apply".into(),
        "--profile".into(),
        path(&canonical_profile)?,
        "--release-record".into(),
        path(&record)?,
    ];
    if user {
        arguments.push("--user".into());
    }
    if let Some(request) = request {
        arguments.extend([
            "--request-id".into(),
            request.id,
            "--target-version".into(),
            request.target_version,
        ]);
    }
    if let Some(directory) = bin_dir {
        arguments.extend(["--bin-dir".into(), path(&directory)?]);
    }
    #[cfg(target_os = "linux")]
    let _job = {
        let systemd = if user {
            service::systemd::Systemd::connect_user().await?
        } else {
            service::systemd::Systemd::connect().await?
        };
        systemd
            .schedule_update(&staged.executable, &arguments)
            .await?
    };
    #[cfg(target_os = "macos")]
    let _job = {
        let launchd = service::launchd::Launchd::connect(user).await?;
        launchd
            .schedule_update(&layout.state, &staged.executable, &arguments)
            .await?
    };
    println!(
        "PortHub update to {} scheduled (current CLI version: {})",
        staged.release.version,
        porthub_agent::VERSION
    );
    Ok(())
}
#[derive(clap::Args)]
struct TenantArgs {
    selector: Option<String>,
    #[arg(long)]
    user: bool,
}
#[derive(clap::Args)]
struct PathArgs {
    /// Registration or machine ID from porthub list; optional if only one private registration exists.
    #[arg(conflicts_with = "profile")]
    selector: Option<String>,
    /// Use an explicitly saved private profile.
    #[arg(long)]
    profile: Option<PathBuf>,
    #[arg(long)]
    user: bool,
    #[arg(long)]
    json: bool,
}
#[derive(Subcommand)]
enum PathCommand {
    Show(PathArgs),
    Set {
        #[arg(value_enum)]
        mode: porthub_agent::private_network::strategy::Mode,
        #[command(flatten)]
        registration: PathArgs,
    },
    Reset(PathArgs),
}
#[cfg(feature="local-tor")]
#[derive(Subcommand)]
enum TorCommand {
    /// Prepare local Tor; optionally route this machine's internet traffic through it.
    Start {
        #[arg(long,value_parser=clap::value_parser!(u8).range(1..=16))]
        circuit_groups:Option<u8>,
        /// Route system-wide internet traffic through Tor until `porthub tor reset`.
        #[arg(long, conflicts_with = "user")]
        system_wide:bool,
        #[command(flatten)]
        registration:PathArgs,
    },
    /// Stop local Tor, closing its active streams.
    Stop(PathArgs),
    /// Show Tor readiness without administrative access.
    Status(TenantArgs),
    /// Follow the UI exit policy again.
    Reset(PathArgs),
}
#[cfg(feature="local-tor")]
fn tor_command(command:TorCommand)->Result<()> {
    use porthub_agent::{private_network::tor_preferences::{self,Mode},service::readable};
    if let TorCommand::Status(args)=command {
        let layout=layout(args.user)?;
        let owner=readable::select(&layout,args.selector.as_deref(),None)?;
        let private=if owner.private {owner} else {
            readable::list(&layout)?.into_iter().find(|record|record.private && record.machine_id==owner.machine_id && record.gateway==owner.gateway)
                .context("registration has no private agent")?
        };
        if let Some(tor)=private.private_status.as_ref().and_then(|status|status.tor.as_ref()) {
            println!("{}{}",tor.display(),if private.active==Some(true) {""} else {"; agent inactive, last reported state"});
        } else {println!("Local Tor status is unavailable from this agent version");}
        return Ok(());
    }
    let (args,mode,groups,system_wide,reset)=match command {
        TorCommand::Start {registration,circuit_groups,system_wide}=>(registration,Mode::Enabled,circuit_groups.map(usize::from),system_wide,false),
        TorCommand::Stop(args)=>(args,Mode::Disabled,None,false,true),
        TorCommand::Reset(args)=>(args,Mode::Auto,None,false,true),
        TorCommand::Status(_)=>unreachable!(),
    };
    anyhow::ensure!(!(system_wide && args.user), "system-wide Tor requires a system registration, not --user");
    #[cfg(not(any(target_os="linux",target_os="macos")))]
    anyhow::ensure!(!system_wide, "system-wide Tor routing is supported on Linux and macOS only");
    let path=path_profile(&args)?;
    let mut settings=tor_preferences::load(&path)?;
    settings.mode=mode;
    if let Some(groups)=groups { settings.circuit_groups=Some(groups); }
    if system_wide { settings.system_wide=true; }
    if reset { settings.system_wide=false; }
    if matches!(mode,Mode::Auto) { settings.circuit_groups=None; }
    let settings=tor_preferences::save(&path,settings)?;
    if args.json {println!("{}",serde_json::to_string_pretty(&settings)?);}
    else {println!("{}",match mode {
        Mode::Enabled if settings.system_wide=>"System-wide Tor requested; internet TCP will use the local Tor exit, LAN stays direct, and unsupported traffic fails closed. Use `porthub tor reset` to return to the UI policy.",
        Mode::Enabled=>"Local Tor enabled; the agent will prepare circuits in the background. No listening port is opened.",
        Mode::Disabled=>"Local Tor disabled and system-wide Tor routing removed; active Tor connections will close.",
        Mode::Auto=>"Local Tor and exit routing now follow the UI policy.",
    });}
    Ok(())
}
fn path_profile(args: &PathArgs) -> Result<PathBuf> {
    use porthub_agent::{private_network, private_profile, service};
    if let Some(path) = &args.profile {
        private_profile::Profile::load(path)?;
        return Ok(path.clone());
    }
    let selector = args.selector.as_deref().map(str::to_ascii_lowercase);
    if let Some(value) = &selector {
        anyhow::ensure!(
            (value.len() >= 6
                && value.len() <= 64
                && value.bytes().all(|ch| ch.is_ascii_hexdigit()))
                || (value.starts_with("porthub-")
                    && value.len() == 32
                    && value[8..].bytes().all(|ch| ch.is_ascii_hexdigit())),
            "invalid registration selector"
        );
    }
    let mut matches = Vec::new();
    for entry in service::select_pair(&layout(args.user)?, selector.as_deref())? {
        if private_network::is_profile(&entry.spec.profile)? {
            matches.push(entry.spec.profile);
        } else if let Some(profile) = service::private_module_profile(&entry.spec.profile)? {
            matches.push(profile);
        }
    }
    anyhow::ensure!(
        matches.len() == 1,
        "select one private registration using an ID from porthub list"
    );
    Ok(matches.remove(0))
}
fn path_strategy(command: PathCommand) -> Result<()> {
    use porthub_agent::private_network::strategy;
    let (args, mode, reset) = match command {
        PathCommand::Show(args) => (args, None, false),
        PathCommand::Set { mode, registration } => (registration, Some(mode), false),
        PathCommand::Reset(args) => (args, None, true),
    };
    let snapshot = if reset || mode.is_some() {
        None
    } else if let Some(path) = &args.profile {
        porthub_agent::service::readable::for_profile(path)?
    } else {
        Some(porthub_agent::service::readable::select(
            &layout(args.user)?,
            args.selector.as_deref(),
            Some(true),
        )?)
    };
    if let Some(record) = snapshot {
        anyhow::ensure!(record.private, "select a private registration");
        let source = if record.strategy_override {
            "override"
        } else {
            "default"
        };
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"format_version":1,"mode":record.strategy,"source":source})
                )?
            );
        } else {
            println!("Path strategy: {} ({source})", record.strategy.as_str());
        }
        return Ok(());
    }
    let path = path_profile(&args)?;
    let settings = if reset {
        strategy::reset(&path)?
    } else if let Some(mode) = mode {
        strategy::save(&path, mode)?
    } else {
        strategy::load(&path)?
    };
    if (reset || mode.is_some())
        && porthub_agent::service::readable::strategy_changed(&path, &settings, !reset).is_err()
    {
        tracing::debug!("local registration display snapshot unavailable");
    }
    let source = if strategy::path(&path).try_exists()? {
        "override"
    } else {
        "default"
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "format_version":settings.format_version,"mode":settings.mode,"source":source
            }))?
        );
    } else {
        println!("Path strategy: {} ({source})", settings.mode.as_str());
    }
    Ok(())
}
fn layout(user: bool) -> Result<porthub_agent::service::Layout> {
    if user {
        porthub_agent::service::Layout::user()
    } else {
        porthub_agent::service::Layout::system()
    }
}
async fn tenant_action(args: TenantArgs, action: porthub_agent::service::Action) -> Result<()> {
    if !args.user {
        porthub_agent::service::require_administrator()?;
    }
    let layout = layout(args.user)?;
    let manager = porthub_agent::service::system_manager(args.user).await?;
    let selected = porthub_agent::service::registration_action(&layout, args.selector.as_deref(), action, manager.as_ref())
        .await?;
    println!(
        "PortHub service operation completed: {}",
        &selected.identity[..12]
    );
    Ok(())
}

fn render_registration_table(rows: &[serde_json::Value]) -> String {
    const HEADERS: [&str; 9] = ["ID", "MACHINE", "ACCOUNT EMAIL", "ACTIVE", "PUBLIC", "PRIVATE", "PORTS", "ROUTE", "GATEWAY"];
    let cells: Vec<[String; 9]> = rows.iter().map(|row| {
        let private = row["private"].as_bool() == Some(true);
        [
            row["id"].as_str().unwrap().chars().take(12).collect(),
            row["machine_id"].as_str().unwrap().into(),
            row["email"].as_str().filter(|value| !value.is_empty()).unwrap_or("-").into(),
            match row["active"].as_bool() { Some(true) => "yes", Some(false) => "no", None => "?" }.into(),
            if private { "-" } else { row["state"].as_str().unwrap_or("-") }.into(),
            row["private_state"].as_str().or_else(|| private.then(|| row["state"].as_str()).flatten()).unwrap_or("-").into(),
            row["ports"].to_string(),
            row["route"].as_str().unwrap().into(),
            display_gateway_url(row["gateway"].as_str().unwrap()),
        ]
    }).collect();
    let widths: [usize; 9] = std::array::from_fn(|column| {
        cells.iter().map(|row| row[column].chars().count()).chain([HEADERS[column].len()]).max().unwrap()
    });
    let padded = |value: &str, column: usize| {
        if column == HEADERS.len() - 1 { value.to_owned() }
        else { format!("{value:<width$}", width = widths[column]) }
    };
    let mut output = vec![paint(HEADERS.iter().enumerate().map(|(column, value)| padded(value, column)).collect::<Vec<_>>().join("  "), "1;36")];
    for row in cells {
        let line = row.iter().enumerate().map(|(column, value)| {
            let style = match (column, value.as_str()) {
                (3, "yes") => "1;32",
                (3, "no") => "2",
                (3, _) => "33",
                (4 | 5, "running") => "32",
                (4 | 5, "configuration-rejected" | "stopped" | "interrupted") => "1;31",
                (4 | 5, "-") => "2",
                (4 | 5, _) => "33",
                (7, "direct") => "1;32",
                (7, "relay" | "gateway") | (8, _) => "36",
                (7, _) => "2",
                _ => "",
            };
            let value = padded(value, column);
            if style.is_empty() { value } else { paint(value, style) }
        }).collect::<Vec<_>>().join("  ");
        output.push(line);
    }
    output.join("\n")
}

fn registration_rows(records: Vec<porthub_agent::service::readable::Record>) -> Result<Vec<serde_json::Value>> {
    let mut groups = std::collections::BTreeMap::<_, Vec<_>>::new();
    for record in records {
        groups.entry((record.gateway.clone(), record.machine_id.clone())).or_default().push(record);
    }
    groups.into_values().map(|mut group| {
        anyhow::ensure!(group.iter().filter(|record| !record.private).count() <= 1
            && group.iter().filter(|record| record.private).count() <= 1,
            "duplicate registration components require explicit cleanup");
        let primary = group.remove(group.iter().position(|record| !record.private).unwrap_or(0));
        let private = if primary.private { Some(&primary) } else { group.iter().find(|record| record.private) };
        let mut row = serde_json::to_value(&primary)?;
        row["private_state"] = serde_json::to_value(private.map(|record| &record.state))?;
        row["private_active"] = serde_json::to_value(private.and_then(|record| record.active))?;
        row["private_version"] = serde_json::to_value(private.map(|record| &record.agent_version))?;
        Ok(row)
    }).collect()
}

async fn list_registrations(user: bool, json: bool) -> Result<()> {
    let records = porthub_agent::service::readable::list(&layout(user)?)?;
    let rows = registration_rows(records)?;
    if json {
        println!("{}", serde_json::to_string(&rows)?);
    } else if rows.is_empty() {
        println!("{}", paint("No native PortHub registrations", "2"));
    } else {
        println!("{}", render_registration_table(&rows));
    }
    Ok(())
}

fn print_private_status(record: &porthub_agent::service::readable::Record, layout: &porthub_agent::service::Layout) -> Result<()> {
    use porthub_agent::service::readable;
    let records = if record.private { vec![record.clone()] } else {
        readable::list(layout)?.into_iter().filter(|peer| peer.private && peer.machine_id == record.machine_id && peer.gateway == record.gateway).collect()
    };
    for peer in records {
        println!("Private networking: {}", peer.state);
        if peer.active != Some(true) { println!("Private policy below is the last reported state."); }
        if let Some(status) = &peer.private_status { println!("{}", status.display()); }
        else { println!("Private policy details unavailable from this agent version."); }
    }
    Ok(())
}

#[derive(Subcommand)]
enum ServiceCommand {
    Install {
        #[arg(long)]
        profile: PathBuf,
    },
    Start {
        #[arg(long)]
        profile: PathBuf,
    },
    Stop {
        #[arg(long)]
        profile: PathBuf,
    },
    Restart {
        #[arg(long)]
        profile: PathBuf,
    },
    Uninstall {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        purge: bool,
    },
    Status {
        #[arg(long)]
        profile: PathBuf,
    },
}
async fn service_command(command: ServiceCommand, user: bool) -> Result<()> {
    use porthub_agent::service::{self, Action};
    let layout = if user {
        service::Layout::user()?
    } else {
        service::Layout::system()?
    };
    match command {
        ServiceCommand::Status { profile } => {
            if let Some(record) = service::readable::for_profile(&profile)? {
                let active = record
                    .active
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".into());
                println!(
                    "installed {}; active {}; boot {}",
                    record.state != "uninstalled",
                    active,
                    record.enabled
                );
                return Ok(());
            }
            let manager = service::system_manager(user).await?;
            let state = service::status(&layout, &profile, manager.as_ref()).await?;
            println!(
                "installed {}; active {}; boot {}",
                state.installed, state.active, state.enabled
            );
        }
        command => {
            if !user {
                service::require_administrator()?;
            }
            let manager = service::system_manager(user).await?;
            let service = match command {
                ServiceCommand::Install { profile } => {
                    service::install(
                        &layout,
                        &profile,
                        &std::env::current_exe()?.canonicalize()?,
                        manager.as_ref(),
                    )
                    .await?
                }
                ServiceCommand::Start { profile } => {
                    service::action(&layout, &profile, Action::Start, manager.as_ref()).await?
                }
                ServiceCommand::Stop { profile } => {
                    service::action(&layout, &profile, Action::Stop, manager.as_ref()).await?
                }
                ServiceCommand::Restart { profile } => {
                    service::action(&layout, &profile, Action::Restart, manager.as_ref()).await?
                }
                ServiceCommand::Uninstall { profile, purge } => {
                    service::action(
                        &layout,
                        &profile,
                        Action::Uninstall { purge },
                        manager.as_ref(),
                    )
                    .await?
                }
                ServiceCommand::Status { .. } => unreachable!(),
            };
            println!("PortHub service operation completed: {}", service.service);
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}};
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let raw_args: Vec<_> = std::env::args_os().collect();
    if short_version_requested(&raw_args) {
        println!("porthub {}", porthub_agent::VERSION);
        return Ok(());
    }
    let args = Args::parse_from(raw_args);
    if args.command.is_none() {
        return print_help();
    }
    elevate_if_needed(&args)?;
    let logs = porthub_agent::logs::Buffer::default();
    let profile_to_configure = match &args.command {
        Some(Command::Run { profile }) => Some(profile),
        #[cfg(windows)]
        Some(Command::WindowsServiceHost { profile, .. }) => Some(profile),
        _ => None,
    };
    if let Some(profile) = profile_to_configure {
        if porthub_agent::private_network::is_profile(profile)? {
            logs.configure_private(&porthub_agent::private_profile::Profile::load(profile)?);
        } else {
            logs.configure(&porthub_agent::profile::Profile::load(profile)?);
        }
    }
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(logs.clone())
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,arti_client=warn,tor_=warn".into()),
        )
        .init();
    let cancel = CancellationToken::new();
    let signal_cancel = cancel.clone();
    let signal = tokio::spawn(async move {
        shutdown_signal().await;
        signal_cancel.cancel();
    });
    let result = match args.command {
        Some(Command::Enroll {
            server,
            ticket,
            profile,
            user,
            install_service,
            allow_insecure_http_for_tests,
        }) => {
            let service = if install_service {
                porthub_agent::service::require_administrator()?;
                Some((
                    porthub_agent::service::Layout::system()?,
                    porthub_agent::service::system_manager(false).await?,
                ))
            } else {
                None
            };
            let stdin_ticket = if ticket.is_none() {
                use std::io::Read;
                let mut bytes = Vec::new();
                std::io::stdin().take(202).read_to_end(&mut bytes)?;
                anyhow::ensure!(
                    bytes.len() <= 201,
                    "private installer ticket exceeds size limit"
                );
                Some(
                    String::from_utf8(bytes)
                        .context("invalid installer ticket encoding")?
                        .trim_end_matches(['\r', '\n'])
                        .to_owned(),
                )
            } else {
                None
            };
            let source = if let Some(ticket) = &ticket {
                porthub_agent::private_profile::Source::Link(ticket)
            } else {
                porthub_agent::private_profile::Source::Ticket {
                    server: server.as_deref().context("private gateway required")?,
                    ticket: stdin_ticket
                        .as_deref()
                        .context("private installer ticket required")?,
                }
            };
            let saved = porthub_agent::private_profile::enroll(
                source,
                profile.as_deref(),
                user,
                allow_insecure_http_for_tests,
                &cancel,
            )
            .await?;
            if let Some((layout, manager)) = service {
                let cli = porthub_agent::bootstrap::cli_path(false, None)?;
                porthub_agent::service::install_published(
                    &layout,
                    &saved,
                    &std::env::current_exe()?.canonicalize()?,
                    manager.as_ref(),
                    Some(&cli),
                )
                .await?;
                println!("PortHub private networking activated; CLI installed");
            } else {
                println!("PortHub private credentials saved; private networking service is not activated");
            }
            Ok(())
        }
        Some(Command::List { user, json }) => list_registrations(user, json).await,
        Some(Command::ImportLegacy {
            env_file,
            profile,
            fallback_servers,
        }) => {
            let id = porthub_agent::legacy::stage(&env_file, &profile, fallback_servers)?;
            println!("PortHub credentials staged: {}", &id[..12]);
            println!("Existing services remain active; service migration is a separate operation");
            Ok(())
        }
        Some(Command::Path { command }) => path_strategy(command),
        #[cfg(feature="local-tor")]
        Some(Command::Tor {command})=>tor_command(command),
        #[cfg(feature="local-tor")]
        Some(Command::Proxy {command})=>porthub_agent::proxy_cli::run(command,cancel).await,
        Some(Command::Start(args)) => {
            tenant_action(args, porthub_agent::service::Action::Start).await
        }
        Some(Command::Stop(args)) => {
            tenant_action(args, porthub_agent::service::Action::Stop).await
        }
        Some(Command::Restart(args)) => {
            tenant_action(args, porthub_agent::service::Action::Restart).await
        }
        Some(Command::Remove(args)) => {
            tenant_action(
                args,
                porthub_agent::service::Action::Uninstall { purge: true },
            )
            .await
        }
        Some(Command::Setup {
            ticket,
            profile,
            user,
            bin_dir,
            no_service,
            adopt_existing_cli,
            allow_insecure_http_for_tests,
        }) => {
            let layout = if no_service {
                None
            } else {
                if !user {
                    porthub_agent::service::require_administrator()?;
                }
                Some(if user {
                    porthub_agent::service::Layout::user()?
                } else {
                    porthub_agent::service::Layout::system()?
                })
            };
            let enrollment =
                porthub_agent::bootstrap::fetch(&ticket, allow_insecure_http_for_tests, &cancel)
                    .await?;
            if let Some(layout) = layout {
                let manager = porthub_agent::service::system_manager(user).await?;
                let cli = porthub_agent::bootstrap::cli_path(user, bin_dir.as_deref())?;
                if adopt_existing_cli {
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    porthub_agent::bootstrap::install_published_adopting_cli(
                        enrollment,
                        profile.as_deref(),
                        &layout,
                        &std::env::current_exe()?.canonicalize()?,
                        manager.as_ref(),
                        &cli,
                    )
                    .await?;
                    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                    anyhow::bail!("legacy CLI adoption is unavailable on this platform");
                } else {
                    porthub_agent::bootstrap::install_published(
                        enrollment,
                        profile.as_deref(),
                        &layout,
                        &std::env::current_exe()?.canonicalize()?,
                        manager.as_ref(),
                        Some(&cli),
                    )
                    .await?;
                }
                let parent = cli.parent().context("CLI bin directory missing")?;
                porthub_agent::bootstrap::register_cli_path(parent, user)?;
                println!("PortHub enrolled; native service activated");
                println!("PortHub CLI installed: {}", cli.display());
            } else {
                porthub_agent::bootstrap::save(
                    enrollment,
                    profile.as_deref().context("--profile required")?,
                )?;
                println!("PortHub enrollment profile saved");
            }
            Ok(())
        }
        Some(Command::HttpServer {
            target,
            path,
            bind,
            port_override,
            root,
            all,
            upload,
            public,
        }) => {
            run_http_command(
                HttpCommandOptions {
                    target,
                    path,
                    bind,
                    port_override,
                    root,
                    all,
                    accept_uploads: upload,
                    public,
                },
                cancel,
            )
            .await
        }
        Some(Command::HttpReceive {
            target,
            path,
            bind,
            port_override,
            root,
            all,
            public,
        }) => {
            run_http_command(
                HttpCommandOptions {
                    target,
                    path,
                    bind,
                    port_override,
                    root,
                    all,
                    accept_uploads: true,
                    public,
                },
                cancel,
            )
            .await
        }
        Some(Command::Expose {
            target,
            id,
            port,
            subdomain,
            detach,
            user,
            registration,
            worker,
            session_id,
        }) => {
            #[cfg(any(unix, windows))]
            {
                let selected_layout = layout(user)?;
                let jobs = porthub_agent::expose::job_layout()?;
                let target = target.unwrap_or_default();
                if worker {
                    return porthub_agent::expose::broker_worker(selected_layout, registration.context("missing exposure registration")?, session_id.context("missing exposure session identity")?, target.parse()?, port, subdomain, cancel).await;
                }
                return match target.as_str() {
                    "list" => porthub_agent::expose::list(&jobs),
                    "stop" => porthub_agent::expose::stop(&jobs, id.as_deref().context("usage: porthub expose stop ID")?),
                    _ => porthub_agent::expose::start_registered(user, registration.as_deref(), target.parse().context("usage: porthub expose LOCAL_PORT [--port EXTERNAL_PORT] [--subdomain NAME] [--detach]")?, port, subdomain, detach, cancel).await,
                };
            }
            #[cfg(not(any(unix, windows)))]
            anyhow::bail!("temporary exposure is not supported on this platform")
        }
        Some(Command::Get {
            url,
            directory,
            connections,
            sha256,
            segment_size,
            contents_only,
        }) => {
            let mut options = download::Options::new(url, directory);
            options.connections = connections;
            options.sha256 = sha256;
            options.piece_size = segment_size;
            options.contents_only = contents_only;
            download::get(options, cancel).await.map(|_| ())
        }
        Some(Command::Push {
            path,
            url,
            connections,
            contents_only,
            force,
            watch,
            detach,
        }) => {
            if watch {
                let options = porthub_transfer::sync::Options {
                    path,
                    url,
                    connections,
                    contents_only,
                    force,
                };
                if detach {
                    let id = porthub_transfer::sync::detach(options).await?;
                    println!("Sync started in background: {id}\nView: porthub sync status {id}\nStop: porthub sync stop {id}");
                    Ok(())
                } else {
                    porthub_transfer::sync::watch(options, cancel.clone()).await
                }
            } else {
                tokio::select! {
                    _ = cancel.cancelled() => Ok(()),
                    result = porthub_transfer::upload::put_path(path, url, connections, contents_only, force) => {
                        println!("{}", result?);
                        Ok(())
                    }
                }
            }
        }
        Some(Command::Sync { command }) => match command {
            SyncCommand::List => {
                let jobs = porthub_transfer::sync::list().await?;
                if jobs.is_empty() {
                    println!("No active sync jobs");
                } else {
                    let source_width = jobs
                        .iter()
                        .map(|job| job.source.to_string_lossy().chars().count())
                        .max()
                        .unwrap_or(0)
                        .max(6);
                    println!(
                        "{:<16}  {:<10}  {:source_width$}  DESTINATION",
                        "ID", "STATE", "SOURCE"
                    );
                    for job in jobs {
                        let source = job.source.display().to_string();
                        println!(
                            "{}  {:<10}  {source:source_width$}  {}",
                            job.id, job.state, job.destination
                        );
                    }
                }
                Ok(())
            }
            SyncCommand::Status { id } => {
                let job = porthub_transfer::sync::status(&id).await?;
                println!(
                    "Sync {}: {}\nSource: {}\nDestination: {}\nCompleted syncs: {}\n{}",
                    job.id,
                    job.state,
                    job.source.display(),
                    job.destination,
                    job.completed_runs,
                    job.message
                );
                Ok(())
            }
            SyncCommand::Stop { id } => {
                porthub_transfer::sync::stop(&id).await?;
                println!("Stopped sync {id}");
                Ok(())
            }
            SyncCommand::Run { id } => porthub_transfer::sync::worker(id, cancel.clone()).await,
        },
        Some(Command::Tunnel { config }) => {
            porthub_tunnel::run_client_until(config, cancel.cancelled_owned()).await
        }
        Some(Command::Configure {
            profile,
            server,
            machine_id,
            fallback_servers,
            allow_insecure_http_for_tests,
        }) => {
            use std::io::Read;
            let mut token = String::new();
            std::io::stdin().take(514).read_to_string(&mut token)?;
            let token = token.trim_end_matches(['\r', '\n']).to_owned();
            let value = porthub_agent::profile::Profile {
                format_version: 1,
                server,
                machine_id,
                token,
                account_email: None,
                fallback_servers,
                setup_overrides: Default::default(),
                allow_insecure_http_for_tests,
            };
            value.save_new(&profile)?;
            println!("Machine profile saved");
            Ok(())
        }
        Some(Command::Run { profile }) => {
            if porthub_agent::private_network::is_profile(&profile)? {
                #[cfg(any(target_os = "linux", target_os = "macos", windows))]
                return porthub_agent::private_network::runtime::run_with_logs(
                    profile, cancel, logs,
                )
                .await;
                #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
                anyhow::bail!("private packet device is not yet available for this platform");
            }
            porthub_agent::runtime::run_with_logs(profile, cancel, Default::default(), logs).await
        }
        Some(Command::Status {
            profile,
            selector,
            user,
        }) => {
            if let Some(profile) = profile {
                if let Some(record) = porthub_agent::service::readable::for_profile(&profile)? {
                    println!(
                        "{}; agent {}; ports {}; route {}",
                        record.state, record.agent_version, record.ports, record.route
                    );
                    print_private_status(&record, &layout(user)?)?;
                    return Ok(());
                }
                let status = porthub_agent::runtime::status(&profile)?;
                println!(
                    "{}; agent {}; ports {}; route {}",
                    status.state, status.agent_version, status.service_count, status.route
                );
                if let Some(details) = status.private_status { println!("{}", details.display()); }
            } else {
                let record = porthub_agent::service::readable::select(
                    &layout(user)?,
                    selector.as_deref(),
                    None,
                )?;
                println!(
                    "{}; agent {}; ports {}; route {}",
                    record.state, record.agent_version, record.ports, record.route
                );
                print_private_status(&record, &layout(user)?)?;
            }
            Ok(())
        }
        Some(Command::Service { action, user }) => service_command(action, user).await,
        #[cfg(windows)]
        Some(Command::WindowsServiceHost {
            service_name,
            service_id,
            profile,
        }) => porthub_agent::service::windows::run_dispatcher(
            service_name,
            service_id,
            profile,
            logs.clone(),
        ),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Some(Command::Update {
            selector,
            profile,
            user,
            check,
            bin_dir,
            rollback,
            apply,
            release_record,
            request_id,
            target_version,
        }) => {
            if !user {
                porthub_agent::service::require_administrator()?;
            }
            if let Some(receipt) = rollback {
                let layout = layout(user)?;
                let manager = porthub_agent::service::system_manager(user).await?;
                porthub_agent::upgrade::rollback(&layout, &receipt, manager.as_ref()).await?;
                println!("Previous native services restored");
                Ok(())
            } else {
                let source = if let Some(source) = profile {
                    source
                } else {
                    porthub_agent::service::select(&layout(user)?, selector.as_deref())?
                        .spec
                        .profile
                };
                let request = request_id.zip(target_version).map(|(id, target_version)| {
                    porthub_agent::update::Request { id, target_version }
                });
                update_command(
                    UpdateOptions {
                        source,
                        user,
                        check,
                        bin_dir,
                        apply,
                        record: release_record,
                        request,
                    },
                    &cancel,
                )
                .await
            }
        }
        Some(Command::Version { verbose }) => {
            println!("porthub {}", porthub_agent::VERSION);
            if verbose {
                println!("build {}", porthub_agent::BUILD_REVISION);
                println!("target {}", env!("PORTHUB_RUST_TARGET"));
            }
            Ok(())
        }
        None => print_help(),
    };
    signal.abort();
    result
}

#[cfg(test)]
mod cli_tests {
    use super::{print_help, requires_system_privileges, short_version_requested, Args};
    use clap::{CommandFactory, Parser};

    fn args(arguments: &[&str]) -> Args {
        Args::try_parse_from(arguments).expect("valid CLI fixture")
    }

    #[test]
    fn watch_and_detach_use_docker_style_flags_without_elevation() {
        for flags in [vec!["-w", "-d"], vec!["--watch", "--detach"]] {
            let mut command = vec!["porthub", "push", "./data", "http://peer:8001/nested/path/"];
            command.extend(flags);
            let parsed = args(&command);
            assert!(!requires_system_privileges(&parsed));
            assert!(matches!(
                parsed.command,
                Some(super::Command::Push {
                    watch: true,
                    detach: true,
                    ..
                })
            ));
        }
        assert!(
            Args::try_parse_from(["porthub", "push", "./data", "http://peer:8001/", "-d"]).is_err()
        );
        assert!(Args::try_parse_from([
            "porthub",
            "push",
            "./data",
            "http://peer:8001/",
            "--detached",
            "-w"
        ])
        .is_err());
        let parsed = args(&["porthub", "push", "./data", "http://peer:8001/", "-w"]);
        assert!(matches!(
            parsed.command,
            Some(super::Command::Push {
                watch: true,
                detach: false,
                ..
            })
        ));
        for command in [
            vec!["porthub", "sync", "list"],
            vec!["porthub", "sync", "status", "0123456789abcdef"],
            vec!["porthub", "sync", "stop", "0123456789abcdef"],
        ] {
            assert!(!requires_system_privileges(&args(&command)));
        }
    }

    #[test]
    fn http_tools_share_exposure_and_docker_detach_flags_without_elevation() {
        for command in ["http.server", "http.receive"] {
            for detach in ["-d", "--detach"] {
                let parsed = args(&["porthub", command, "./files", "--expose", "--public-port", "12345", "--subdomain", "files", detach]);
                assert!(!super::requires_system_privileges(&parsed));
                let Some(super::Command::HttpServer { public, .. } | super::Command::HttpReceive { public, .. }) = parsed.command else { panic!("expected HTTP command"); };
                assert!(public.expose && public.detach);
                assert_eq!(public.public_port, Some(12345));
            }
            assert!(Args::try_parse_from(["porthub", command, "--subdomain", "files"]).is_err());
        }
        assert!(!super::requires_system_privileges(&args(&["porthub", "expose", "8080"])));
        assert!(!super::requires_system_privileges(&args(&["porthub", "expose", "list"])));
    }

    #[test]
    fn transfers_default_to_sixteen_connections_and_accept_overrides() {
        for base in [
            vec!["porthub", "get", "http://example.test/file.bin"],
            vec!["porthub", "push", "file.bin", "http://example.test/"],
        ] {
            for (flags, expected) in [
                (vec![], 16),
                (vec!["-x", "1"], 1),
                (vec!["--connections", "8"], 8),
            ] {
                let mut command = base.clone();
                command.extend(flags);
                let Some(
                    super::Command::Get { connections, .. }
                    | super::Command::Push { connections, .. },
                ) = args(&command).command
                else {
                    panic!("expected transfer command");
                };
                assert_eq!(connections, expected);
            }
        }
    }

    #[test]
    fn default_help_keeps_maintenance_commands_advanced_but_accessible() {
        let command = Args::command();
        let visible = command
            .get_subcommands()
            .filter(|subcommand| !subcommand.is_hide_set())
            .map(|subcommand| subcommand.get_name().to_owned())
            .collect::<Vec<_>>();
        for common in [
            "list",
            "start",
            "stop",
            "restart",
            "setup",
            "http.server",
            "http.receive",
            "expose",
            "get",
            "push",
            "status",
            "version",
        ] {
            assert!(
                visible.iter().any(|name| name == common),
                "missing {common}"
            );
        }
        let mut advanced = vec!["enroll", "tunnel", "configure", "run", "service"];
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        advanced.push("update");
        for advanced in advanced {
            assert!(
                command
                    .get_subcommands()
                    .any(|subcommand| subcommand.get_name() == advanced && subcommand.is_hide_set()),
                "advanced command {advanced} must remain available but hidden"
            );
        }
        assert!(args(&[
            "porthub",
            "configure",
            "--profile",
            "/tmp/profile.json",
            "--server",
            "https://gateway.example",
            "--machine-id",
            "machine-id"
        ])
        .command
        .is_some());
    }

    #[test]
    fn get_accepts_directory_contents_only_option() {
        let parsed = args(&[
            "porthub",
            "get",
            "http://machine:8000/dataset/",
            "--dir",
            "./copy",
            "--contents-only",
        ]);
        assert!(matches!(
            parsed.command,
            Some(super::Command::Get {
                contents_only: true,
                ..
            })
        ));
    }

    #[cfg(feature="local-tor")]
    #[test]
    fn tor_and_proxy_commands_keep_read_only_and_user_operations_unprivileged() {
        for command in [vec!["porthub","tor","status"],vec!["porthub","proxy","ls"],vec!["porthub","proxy","status"],vec!["porthub","proxy","stop"],vec!["porthub","proxy","start","-d"],vec!["porthub","proxy","start","--detach"]] {
            assert!(!requires_system_privileges(&args(&command)));
        }
        assert!(requires_system_privileges(&args(&["porthub","tor","start"])));
        assert!(requires_system_privileges(&args(&["porthub","tor","start","--system-wide"])));
        assert!(requires_system_privileges(&args(&["porthub","tor","stop"])));
        assert!(requires_system_privileges(&args(&["porthub","proxy","start","--port","80"])));
        assert!(!requires_system_privileges(&args(&["porthub","tor","start","--user"])));
        assert!(Args::try_parse_from(["porthub","proxy","start","--detached"]).is_err());
        assert!(Args::try_parse_from(["porthub","proxy","start","--circuit-groups","17"]).is_err());
        assert!(Args::try_parse_from(["porthub","tor","start","--circuit-groups","0"]).is_err());
        assert!(Args::try_parse_from(["porthub","tor","start","--system-wide","--user"]).is_err());
    }

    #[test]
    fn routine_transfer_and_user_commands_do_not_request_elevation() {
        for arguments in [
            &["porthub", "version"][..],
            &["porthub", "push", "file.bin", "http://host:8001/"][..],
            &["porthub", "get", "http://host/file.bin"][..],
            &["porthub", "http.receive"][..],
            &["porthub", "http.server", "0", "."][..],
            &["porthub", "http.receive", "0", "."][..],
            &["porthub", "status", "--profile", "/tmp/profile.json"][..],
            &[
                "porthub",
                "service",
                "status",
                "--profile",
                "/tmp/profile.json",
            ][..],
            &["porthub", "list", "--user"][..],
            &["porthub", "list"][..],
            &["porthub", "status"][..],
            &["porthub", "path", "show"][..],
            &["porthub", "setup", "--ticket", "ticket", "--user"][..],
        ] {
            assert!(
                !requires_system_privileges(&args(arguments)),
                "unexpected elevation for {arguments:?}"
            );
        }
    }

    #[test]
    fn system_service_commands_and_privileged_ports_request_elevation() {
        for arguments in [
            &["porthub", "setup", "--ticket", "ticket"][..],
            &["porthub", "start", "abcdef"][..],
            &["porthub", "path", "reset"][..],
            &["porthub", "http.server", "80"][..],
            &["porthub", "http.receive", "--port", "443"][..],
        ] {
            assert!(
                requires_system_privileges(&args(arguments)),
                "missing elevation for {arguments:?}"
            );
        }
    }

    #[test]
    fn authenticated_setup_can_explicitly_adopt_an_existing_cli() {
        let parsed = args(&[
            "porthub",
            "setup",
            "--ticket",
            "https://gateway.example/install/ticket",
            "--adopt-existing-cli",
        ]);
        assert!(matches!(
            parsed.command,
            Some(super::Command::Setup {
                adopt_existing_cli: true,
                ..
            })
        ));
    }

    #[test]
    fn gateway_display_strips_only_a_terminal_api_path() {
        assert_eq!(
            super::display_gateway_url("https://gateway.example/api/"),
            "https://gateway.example"
        );
        assert_eq!(
            super::display_gateway_url("https://gateway.example/api/v2"),
            "https://gateway.example/api/v2"
        );
    }

    #[test]
    fn registration_table_columns_align_with_headers() {
        let table = super::render_registration_table(&[serde_json::json!({
            "id": "0d2bab5a347aabcdef123456",
            "machine_id": "6ad9f6aeeaf54977a4f930f7",
            "email": "mneonizer@gmail.com",
            "active": true,
            "state": "running",
            "private_state": "stopped",
            "ports": 0,
            "route": "primary",
            "gateway": "https://porthub.algofly.in"
        })]);
        let mut lines = table.lines();
        let header = lines.next().unwrap();
        let row = lines.next().unwrap();
        for (heading, value) in [
            ("ID", "0d2bab5a347a"),
            ("MACHINE", "6ad9f6aeeaf54977a4f930f7"),
            ("ACCOUNT EMAIL", "mneonizer@gmail.com"),
            ("ACTIVE", "yes"),
            ("PUBLIC", "running"),
            ("PRIVATE", "stopped"),
            ("ROUTE", "primary"),
            ("GATEWAY", "https://porthub.algofly.in"),
        ] {
            assert_eq!(
                header.find(heading),
                row.find(value),
                "column {heading} does not align"
            );
        }
        let ports_column = header.find("PORTS").unwrap();
        assert_eq!(row[ports_column..].split_whitespace().next(), Some("0"));
        assert_eq!(header.find("PRIVATE").unwrap() - header.find("PUBLIC").unwrap(), "running".len() + 2);
        assert_eq!(ports_column - header.find("PRIVATE").unwrap(), "PRIVATE".len() + 2);
        assert_eq!(header.find("ACTIVE").unwrap() - header.find("ACCOUNT EMAIL").unwrap(), "mneonizer@gmail.com".len() + 2);
    }

    #[test]
    fn registration_columns_expand_for_long_account_and_state_values() {
        let email = "longer.account.registration@example.com";
        let state = "configuration-rejected";
        let table = super::render_registration_table(&[serde_json::json!({
            "id":"0d2bab5a347aabcdef123456", "machine_id":"6ad9f6aeeaf54977a4f930f7",
            "email":email, "active":false, "state":state, "private_state":"running",
            "ports":12, "route":"primary", "gateway":"https://porthub.algofly.in"
        })]);
        let lines: Vec<_> = table.lines().collect();
        assert_eq!(lines[0].find("ACTIVE"), lines[1].find("no"));
        assert_eq!(lines[0].find("PUBLIC"), lines[1].find(state));
        assert_eq!(lines[0].find("PRIVATE"), lines[1].find("running"));
        assert_eq!(lines[0].find("ACTIVE").unwrap() - lines[0].find("ACCOUNT EMAIL").unwrap(), email.len() + 2);
        assert_eq!(lines[0].find("PRIVATE").unwrap() - lines[0].find("PUBLIC").unwrap(), state.len() + 2);
    }

    #[test]
    fn bare_invocation_is_a_help_request() {
        let args = args(&["porthub"]);
        assert!(args.command.is_none());
        assert!(!requires_system_privileges(&args));
        print_help().expect("help should print successfully");
    }

    #[test]
    fn registration_rows_share_one_id_but_keep_tenants_and_gateways_separate() {
        let record = |id: char, private: bool, machine: &str, gateway: &str| {
            porthub_agent::service::readable::Record {
                format_version: 1, id: id.to_string().repeat(64), machine_id: machine.into(),
                email: "owner@example.com".into(), gateway: gateway.into(), private,
                enabled: true, active: Some(!private), state: if private { "stopped" } else { "running" }.into(),
                agent_version: porthub_agent::VERSION.into(), ports: if private { 0 } else { 2 },
                route: if private { "private" } else { "origin" }.into(), updated_at: 1,
                strategy: Default::default(), strategy_override: false, private_status: None,
            }
        };
        let rows = super::registration_rows(vec![
            record('a', false, "machine-one", "https://one.example"),
            record('b', true, "machine-one", "https://one.example"),
            record('c', false, "machine-two", "https://one.example"),
            record('d', false, "machine-one", "https://two.example"),
        ]).unwrap();
        assert_eq!(rows.len(), 3);
        let paired = rows.iter().find(|row| row["id"] == "a".repeat(64)).unwrap();
        assert_eq!(paired["state"], "running");
        assert_eq!(paired["private_state"], "stopped");
        assert_eq!(paired["ports"], 2);
        assert!(rows.iter().all(|row| row["id"] != "b".repeat(64)));
    }

    #[test]
    fn lowercase_v_displays_the_release_version() {
        assert!(short_version_requested(&["porthub".into(), "-v".into()]));
        assert!(!short_version_requested(&[
            "porthub".into(),
            "-v".into(),
            "list".into(),
        ]));
    }
}
