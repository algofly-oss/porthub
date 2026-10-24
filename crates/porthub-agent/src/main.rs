use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use porthub_transfer::{download, server};
use std::{net::IpAddr, path::PathBuf};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    name = "porthub",
    version = option_env!("PORTHUB_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),
    about = "PortHub native agent: tunnels, HTTP file serving and parallel downloads"
)]
struct Args {
    /// Rathole-compatible client configuration (legacy -c form).
    #[arg(short = 'c', long)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Adopt generated legacy Linux registrations, retaining recovery backups.
    #[cfg(target_os = "linux")]
    AdoptLegacy {
        #[arg(long, default_value = "/etc/porthub")]
        legacy_root: PathBuf,
        #[arg(long, default_value = "/usr/local/bin/porthub")]
        cli: PathBuf,
        #[arg(long, default_value = "/opt/porthub/bin/porthub")]
        private_executable: PathBuf,
        #[arg(long)]
        server: Option<String>,
        #[arg(long = "fallback-server")]
        fallback_servers: Vec<String>,
        /// Activate the inspected registrations; without this flag only inspect.
        #[arg(long, conflicts_with = "rollback")]
        apply: bool,
        /// Restore a previous adoption receipt's original CLI and service state.
        #[arg(long)]
        rollback: Option<PathBuf>,
        /// List retained adoption/recovery receipts without reading credentials.
        #[arg(long, conflicts_with_all = ["apply", "rollback"])]
        receipts: bool,
        /// Queue adoption outside the legacy service's process group.
        #[arg(long, conflicts_with_all = ["apply", "rollback", "receipts"])]
        handoff: bool,
        #[arg(long, hide=true, conflicts_with_all=["handoff","rollback","receipts"])]
        enrollment: Option<PathBuf>,
    },
    /// Enroll a private identity; long tickets are read from stdin.
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
    /// Stage credentials from a legacy client.env without changing running services.
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
        #[arg(long)]
        allow_insecure_http_for_tests: bool,
        #[arg(long = "install-path", hide = true, conflicts_with_all = ["bin_dir","no_service"])]
        legacy_install_path: Option<PathBuf>,
        #[arg(long = "tenant", hide = true)]
        legacy_tenant: Option<String>,
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
    },
    /// Download with parallel byte ranges, safe resume, and optional SHA256.
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
    },
    /// Run public service forwarding using an in-process Rathole client.
    Tunnel {
        #[arg(short = 'c', long)]
        config: PathBuf,
    },
    /// Save a machine profile; read its token from stdin instead of process arguments.
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
    /// Check or update an existing native Linux registration and its private pair.
    #[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
struct UpdateOptions {
    source: PathBuf,
    user: bool,
    check: bool,
    bin_dir: Option<PathBuf>,
    apply: bool,
    record: Option<PathBuf>,
    request: Option<porthub_agent::update::Request>,
}
#[cfg(target_os = "linux")]
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
    let systemd = if user {
        service::systemd::Systemd::connect_user().await?
    } else {
        service::systemd::Systemd::connect().await?
    };
    let job = systemd
        .schedule_update(&staged.executable, &arguments)
        .await?;
    println!("Verified native release queued: {job}");
    Ok(())
}
#[derive(clap::Args)]
struct TenantArgs {
    selector: Option<String>,
    #[arg(long)]
    user: bool,
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
    let selected = porthub_agent::service::select(&layout, args.selector.as_deref())?;
    let manager = porthub_agent::service::system_manager(args.user).await?;
    porthub_agent::service::action(&layout, &selected.spec.profile, action, manager.as_ref())
        .await?;
    println!(
        "PortHub service operation completed: {}",
        &selected.spec.identity[..12]
    );
    Ok(())
}
async fn list_registrations(user: bool, json: bool) -> Result<()> {
    let entries = porthub_agent::service::registrations(&layout(user)?)?;
    let mut rows = Vec::new();
    if !entries.is_empty() {
        let manager = porthub_agent::service::system_manager(user).await?;
        for entry in entries {
            let state = manager.state(&entry.spec).await?;
            let runtime = porthub_agent::runtime::status(&entry.spec.profile).ok();
            rows.push(serde_json::json!({"id":entry.spec.identity,"machine_id":entry.machine_id,"active":state.active,"enabled":state.enabled,
                "state":runtime.as_ref().map(|state|state.state.as_str()).unwrap_or("unavailable"),
                "agent_version":runtime.as_ref().map(|state|state.agent_version.as_str()).unwrap_or(""),
                "services":runtime.as_ref().map(|state|state.service_count).unwrap_or(0),"route":runtime.as_ref().map(|state|state.route.as_str()).unwrap_or("")}));
        }
    }
    if json {
        println!("{}", serde_json::to_string(&rows)?);
    } else if rows.is_empty() {
        println!("No native PortHub registrations");
    } else {
        println!("ID            MACHINE                   ACTIVE  STATE                  SERVICES  ROUTE");
        for row in rows {
            println!(
                "{}  {}  {:<6}  {:<21}  {:<8}  {}",
                &row["id"].as_str().unwrap()[..12],
                row["machine_id"].as_str().unwrap(),
                row["active"],
                row["state"].as_str().unwrap(),
                row["services"],
                row["route"].as_str().unwrap()
            );
        }
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
                        &std::env::current_exe()?,
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
    let args = Args::parse();
    let logs = porthub_agent::logs::Buffer::default();
    if let Some(Command::Run { profile }) = &args.command {
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
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    if args.config.is_some() && args.command.is_some() {
        bail!("use either -c CONFIG or a subcommand");
    }
    let cancel = CancellationToken::new();
    let signal_cancel = cancel.clone();
    let signal = tokio::spawn(async move {
        shutdown_signal().await;
        signal_cancel.cancel();
    });
    let result = match args.command {
        #[cfg(target_os = "linux")]
        Some(Command::AdoptLegacy {
            legacy_root,
            cli,
            private_executable,
            server,
            fallback_servers,
            apply,
            rollback,
            receipts,
            handoff,
            enrollment,
        }) => {
            use porthub_agent::{adopt, service};
            service::require_administrator()?;
            let layout = service::Layout::system()?;
            let manager = service::system_manager(false).await?;
            if receipts {
                println!("{}", serde_json::to_string(&adopt::receipts(&layout)?)?);
            } else if let Some(receipt) = rollback {
                adopt::rollback(&layout, &receipt, manager.as_ref()).await?;
                println!("Original PortHub registrations restored");
            } else {
                let options = adopt::Options {
                    legacy_root,
                    cli,
                    private_executable,
                    server,
                    fallback_servers,
                };
                if handoff {
                    let prepared = adopt::prepare_handoff(
                        &layout,
                        &options,
                        &std::env::current_exe()?,
                        manager.as_ref(),
                    )
                    .await?;
                    let controller = service::systemd::Systemd::connect().await?;
                    let job = controller
                        .schedule_adoption(&prepared.executable, &prepared.arguments)
                        .await?;
                    println!(
                        "Native adoption queued for {} registrations: {job}",
                        prepared.registrations
                    );
                    return Ok(());
                }
                let mut plan = adopt::plan(&layout, &options, manager.as_ref()).await?;
                if let Some(enrollment) = enrollment {
                    plan =
                        plan.for_enrollment(&porthub_agent::profile::Profile::load(&enrollment)?)?;
                }
                println!(
                    "Verified {} legacy PortHub registrations",
                    plan.registrations()
                );
                if apply {
                    let receipt = adopt::apply(
                        &layout,
                        plan,
                        &std::env::current_exe()?,
                        manager.as_ref(),
                        &adopt::RuntimeReady,
                    )
                    .await?;
                    println!(
                        "Native registrations adopted; recovery receipt: {}",
                        receipt.display()
                    );
                }
            }
            Ok(())
        }
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
                    &std::env::current_exe()?,
                    manager.as_ref(),
                    Some(&cli),
                )
                .await?;
                println!("PortHub private service activated; CLI installed");
            } else {
                println!("PortHub private credentials saved; private networking service is not activated");
            }
            Ok(())
        }
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
        Some(Command::List { user, json }) => list_registrations(user, json).await,
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
            allow_insecure_http_for_tests,
            legacy_install_path,
            legacy_tenant,
        }) => {
            if let Some(tenant) = legacy_tenant {
                anyhow::ensure!(
                    tenant.len() <= 120
                        && tenant
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
                    "invalid legacy installer tenant"
                );
            }
            let bin_dir = if let Some(path) = legacy_install_path {
                anyhow::ensure!(
                    path.is_absolute() && path.file_name().is_some_and(|name| name == "porthub"),
                    "legacy installer path must name an absolute porthub executable"
                );
                Some(
                    path.parent()
                        .context("legacy CLI path needs a parent")?
                        .to_owned(),
                )
            } else {
                bin_dir
            };
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
                #[cfg(target_os = "linux")]
                if !user && porthub_agent::legacy::is_generated_cli(&cli)? {
                    anyhow::ensure!(profile.is_none(),"use adopt-legacy to migrate existing registrations before choosing a custom bootstrap profile path");
                    let options = porthub_agent::adopt::Options {
                        cli: cli.clone(),
                        server: Some(enrollment.server.clone()),
                        fallback_servers: enrollment.fallback_servers.clone(),
                        ..Default::default()
                    };
                    let prepared = porthub_agent::adopt::prepare_enrollment_handoff(
                        &layout,
                        &options,
                        &std::env::current_exe()?,
                        manager.as_ref(),
                        &enrollment,
                    )
                    .await?;
                    let controller = porthub_agent::service::systemd::Systemd::connect().await?;
                    let job = controller
                        .schedule_adoption(&prepared.executable, &prepared.arguments)
                        .await?;
                    println!("Existing enrollment verified; native adoption queued: {job}");
                    return Ok(());
                }
                porthub_agent::bootstrap::install_published(
                    enrollment,
                    profile.as_deref(),
                    &layout,
                    &std::env::current_exe()?,
                    manager.as_ref(),
                    Some(&cli),
                )
                .await?;
                println!("PortHub enrolled; native service activated");
                println!("PortHub CLI installed: {}", cli.display());
                let parent = cli.parent().context("CLI bin directory missing")?;
                if !std::env::var_os("PATH")
                    .is_some_and(|path| std::env::split_paths(&path).any(|item| item == parent))
                {
                    println!(
                        "Add {} to PATH to invoke porthub directly",
                        parent.display()
                    );
                }
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
        }) => {
            if target == "list" {
                for record in server::list().await? {
                    println!(
                        "port {}  bind {}  pid {}  {}",
                        record.port,
                        record.bind,
                        record.pid,
                        record.root.display()
                    );
                }
                Ok(())
            } else if target == "stop" {
                let port = if all {
                    None
                } else {
                    Some(
                        path.context("usage: porthub http.server stop PORT|--all")?
                            .parse::<u16>()?,
                    )
                };
                for port in server::stop_servers(port).await? {
                    println!("Stopped http.server on port {port}");
                }
                Ok(())
            } else {
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
                        (8000, PathBuf::from(target))
                    }
                };
                server::serve(
                    server::Options {
                        port: port_override.unwrap_or(port),
                        bind,
                        root: root.unwrap_or(default_root),
                    },
                    cancel,
                )
                .await
            }
        }
        Some(Command::Get {
            url,
            directory,
            connections,
            sha256,
            segment_size,
        }) => {
            let mut options = download::Options::new(url, directory);
            options.connections = connections;
            options.sha256 = sha256;
            options.piece_size = segment_size;
            download::get(options, cancel).await.map(|_| ())
        }
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
                #[cfg(target_os = "linux")]
                return porthub_agent::private_network::runtime::run(profile, cancel).await;
                #[cfg(not(target_os = "linux"))]
                anyhow::bail!("private packet device is not yet available for this platform");
            }
            porthub_agent::runtime::run_with_logs(profile, cancel, Default::default(), logs).await
        }
        Some(Command::Status {
            profile,
            selector,
            user,
        }) => {
            let profile = match profile {
                Some(profile) => profile,
                None => {
                    porthub_agent::service::select(&layout(user)?, selector.as_deref())?
                        .spec
                        .profile
                }
            };
            let status = porthub_agent::runtime::status(&profile)?;
            println!(
                "{}; agent {}; services {}; route {}",
                status.state, status.agent_version, status.service_count, status.route
            );
            Ok(())
        }
        Some(Command::Service { action, user }) => service_command(action, user).await,
        #[cfg(target_os = "linux")]
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
        None => {
            porthub_tunnel::run_client_until(
                args.config
                    .context("supply a command or -c CONFIG; see --help")?,
                cancel.cancelled_owned(),
            )
            .await
        }
    };
    signal.abort();
    result
}
