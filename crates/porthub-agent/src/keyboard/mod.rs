//! Optional desktop module of the existing PortHub executable. Its service
//! broker owns authentication; this module runs as the logged-in OS user.
mod broker;
mod direct;
mod input;
#[cfg(target_os = "linux")]
mod uinput;
use anyhow::{ensure, Context, Result};
pub(crate) use broker::serve;
use porthub_components::keyboard::{Ack, Command, Input};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;
#[derive(clap::Args)]
pub struct Args {
    #[arg(long, global = true)]
    pub user: bool,
    #[arg(long, global = true)]
    pub registration: Option<String>,
    #[command(subcommand)]
    pub command: Option<Action>,
}
#[derive(clap::Subcommand)]
pub enum Action {
    Enable,
    Disable,
    Status,
    #[command(hide = true)]
    Run,
}
/// Readable registration metadata selects the credential-free broker only.
pub(crate) fn registration(
    user: bool,
    selector: Option<&str>,
) -> Result<(crate::service::Layout, String)> {
    let layouts = if user {
        vec![crate::service::Layout::user()?]
    } else {
        vec![
            crate::service::Layout::system()?,
            crate::service::Layout::user()?,
        ]
    };
    let mut found = Vec::new();
    for layout in layouts {
        if let Ok(rows) = crate::service::readable::list(&layout) {
            for row in rows.into_iter().filter(|r| !r.private && r.enabled) {
                if selector.is_none_or(|s| row.id.starts_with(s) || row.machine_id.starts_with(s)) {
                    found.push((layout.clone(), row));
                }
            }
        }
    }
    if selector.is_none() && found.len() > 1 {
        let preferred: Vec<_> = found
            .iter()
            .enumerate()
            .filter(|(_, (_, r))| {
                url::Url::parse(&r.gateway)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_owned))
                    .as_deref()
                    == Some("porthub.algofly.in")
            })
            .map(|(i, _)| i)
            .collect();
        if preferred.len() == 1 {
            let (layout, row) = found.swap_remove(preferred[0]);
            return Ok((layout, row.id));
        }
    }
    ensure!(
        found.len() == 1,
        "Choose a unique registration with --registration; use porthub ls to see enrolled machines"
    );
    let (layout, row) = found.pop().unwrap();
    Ok((layout, row.id))
}
pub async fn run(args: Args, cancel: CancellationToken) -> Result<()> {
    match args.command.unwrap_or(Action::Status) {
        Action::Run => {
            let (layout, id) = registration(args.user, args.registration.as_deref())?;
            let root = directories::ProjectDirs::from("dev", "porthub", "porthub")
                .context("Cannot locate desktop state")?
                .data_local_dir()
                .join("keyboard");
            crate::service::directory(&root, true).with_context(|| {
                format!(
                    "Cannot create VKeyboard desktop state at {}",
                    root.display()
                )
            })?;
            use fs2::FileExt;
            let lease = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(root.join(format!("{id}.lock")))?;
            lease
                .try_lock_exclusive()
                .context("VKeyboard module is already running for this desktop registration")?;
            loop {
                let result = session(&layout, &id, cancel.clone()).await;
                if result
                    .as_ref()
                    .err()
                    .is_some_and(|e| e.to_string().contains("disabled locally"))
                {
                    return Ok(());
                }
                if cancel.is_cancelled() {
                    return Ok(());
                }
                tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(5))=>{}}
            }
        }
        action => {
            let enabled = match action {
                Action::Enable => Some(true),
                Action::Disable => Some(false),
                _ => None,
            };
            crate::features::run(crate::features::Args {
                user: args.user,
                registration: args.registration.clone(),
                command: enabled.map(|on| {
                    if on {
                        crate::features::Action::Enable {
                            feature: crate::features::Feature::Keyboard,
                        }
                    } else {
                        crate::features::Action::Disable {
                            feature: crate::features::Feature::Keyboard,
                        }
                    }
                }),
            })
            .await?;
            if enabled == Some(true) {
                let executable = stable_cli(args.user)?;
                install_desktop(&executable, args.user)?;
                spawn(&executable, args.user, args.registration.as_deref())?;
            }
            Ok(())
        }
    }
}
fn stable_cli(user: bool) -> Result<PathBuf> {
    let current = std::env::current_exe()?.canonicalize()?;
    for path in [
        crate::bootstrap::cli_path(user, None)?,
        crate::bootstrap::cli_path(!user, None)?,
    ] {
        if path.canonicalize().ok().as_ref() == Some(&current) {
            return Ok(path);
        }
    }
    Ok(current)
}
fn spawn(executable: &Path, user: bool, registration: Option<&str>) -> Result<()> {
    let mut command = std::process::Command::new(executable);
    command.args(["keyboard", "run"]);
    if user {
        command.arg("--user");
    }
    if let Some(id) = registration {
        command.args(["--registration", id]);
    }
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000008);
    }
    command
        .spawn()
        .context("Cannot start desktop VKeyboard module")?;
    Ok(())
}
/// Register desktop startup while installing the same CLI. Never resets policy.
/// Headless services have no clipboard and do not initialize native input.
pub(crate) fn install_desktop(executable: &Path, user: bool) -> Result<()> {
    let path = executable.to_str().context("Invalid CLI path")?;
    ensure!(!path.contains(['\n', '\r', '\0']), "Invalid CLI path");
    #[cfg(target_os = "linux")]
    {
        let directory = if user || !rustix::process::geteuid().is_root() {
            directories::BaseDirs::new()
                .context("No desktop configuration directory")?
                .config_dir()
                .join("autostart")
        } else {
            PathBuf::from("/etc/xdg/autostart")
        };
        std::fs::create_dir_all(&directory)?;
        let quoted = path
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('`', "\\`")
            .replace('$', "\\$")
            .replace('%', "%%");
        std::fs::write(directory.join("porthub-keyboard.desktop"),format!("[Desktop Entry]\nType=Application\nName=PortHub desktop input\nExec=\"{quoted}\" keyboard run{}\nTerminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n",if user{" --user"}else{""}))?;
    }
    #[cfg(target_os = "macos")]
    {
        let base = directories::BaseDirs::new().context("No user directory")?;
        let root = if !user && rustix::process::geteuid().is_root() {
            PathBuf::from("/Library/LaunchAgents")
        } else {
            base.home_dir().join("Library/LaunchAgents")
        };
        std::fs::create_dir_all(&root)?;
        let xml = path
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        std::fs::write(root.join("in.porthub.keyboard.plist"),format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Label</key><string>in.porthub.keyboard</string><key>ProgramArguments</key><array><string>{xml}</string><string>keyboard</string><string>run</string>{}</array><key>RunAtLoad</key><true/></dict></plist>",if user{"<string>--user</string>"}else{""}))?;
    }
    #[cfg(windows)]
    {
        let key = windows_registry::CURRENT_USER
            .create("Software\\Microsoft\\Windows\\CurrentVersion\\Run")?;
        key.set_string(
            "PortHubKeyboard",
            format!("\"{}\" keyboard run", path.replace('"', "")),
        )?;
    }
    Ok(())
}
async fn write<S: tokio::io::AsyncWrite + Unpin>(stream: &mut S, value: &Value) -> Result<()> {
    stream.write_all(format!("{value}\n").as_bytes()).await?;
    Ok(())
}
struct Worker {
    send: std::sync::mpsc::SyncSender<(Command, tokio::sync::oneshot::Sender<Result<()>>)>,
}
impl Worker {
    fn start() -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<(
            Command,
            tokio::sync::oneshot::Sender<Result<()>>,
        )>(16);
        std::thread::Builder::new()
            .name("porthub-desktop-input".into())
            .spawn(move || {
                let mut desktop: Option<input::Desktop> = None;
                loop {
                    let incoming = if desktop.as_ref().is_some_and(|d| d.has_held()) {
                        rx.recv_timeout(Duration::from_secs(1))
                    } else {
                        rx.recv()
                            .map_err(|_| std::sync::mpsc::RecvTimeoutError::Disconnected)
                    };
                    match incoming {
                        Ok((command, reply)) => {
                            let result = (|| {
                                if matches!(command, Command::ReleaseAll {}) {
                                    if let Some(d) = &mut desktop {
                                        d.release();
                                    }
                                    return Ok(());
                                }
                                if desktop.is_none() {
                                    desktop = Some(input::Desktop::new()?);
                                }
                                desktop.as_mut().unwrap().execute(&command)
                            })();
                            let _ = reply.send(result);
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            if let Some(d) = &mut desktop {
                                d.deadman();
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
            .expect("desktop input worker");
        Self { send: tx }
    }
    async fn execute(&self, command: Command) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.send
            .try_send((command, tx))
            .context("Desktop input queue is full")?;
        rx.await.context("Desktop input worker stopped")?
    }
}
async fn session(
    layout: &crate::service::Layout,
    registration: &str,
    cancel: CancellationToken,
) -> Result<()> {
    let mut stream = crate::exposure_broker::connect_stream(layout, registration).await?;
    write(&mut stream, &json!({"operation":"keyboard_host"})).await?;
    let mut local = BufReader::new(stream);
    let mut pending = Vec::new();
    let mut active: Option<String> = None;
    let mut direct: Option<direct::Direct> = None;
    let mut allow_direct = false;
    let mut worker: Option<Worker> = None;
    let mut seen = VecDeque::<Ack>::new();
    let mut window = Instant::now();
    let mut count = 0;
    loop {
        let direct_read = async {
            match &mut direct {
                Some(d) => d.next().await,
                None => std::future::pending().await,
            }
        };
        let message = tokio::select! {
            _=cancel.cancelled()=>break,
            bytes=broker::line(&mut local, &mut pending)=>serde_json::from_slice::<Value>(&bytes?)?,
            bytes=direct_read=>match bytes{Ok(bytes)=>{
                let input:Input=serde_json::from_slice(&bytes)?;json!({"type":"input","session":active,"input":input})
            },Err(error)=>{tracing::debug!(reason=%error,"Local VKeyboard path failed; using relay");direct=None;continue;}}
        };
        match message["type"].as_str() {
            Some("policy") => allow_direct = message["direct"] == true,
            Some("ping") => write(local.get_mut(), &json!({"type":"pong"})).await?,
            Some("disabled") => anyhow::bail!("VKeyboard disabled locally"),
            Some("error") => anyhow::bail!("Keyboard gateway unavailable"),
            Some("start") => {
                direct = None;
                if let Some(w) = &worker {
                    let _ = w.execute(Command::ReleaseAll {}).await;
                }
                active = message["session"].as_str().map(str::to_owned);
                seen.clear();
                if worker.is_none() {
                    worker = Some(Worker::start());
                }
            }
            Some("stop") if message["session"].as_str() == active.as_deref() => {
                direct = None;
                if let Some(w) = &worker {
                    let _ = w.execute(Command::ReleaseAll {}).await;
                }
                active = None;
                seen.clear();
            }
            Some("input")
                if active.is_some() && message["session"].as_str() == active.as_deref() =>
            {
                let input: Input = serde_json::from_value(message["input"].clone())?;
                input.validate()?;
                if window.elapsed() > Duration::from_secs(1) {
                    window = Instant::now();
                    count = 0;
                }
                count += 1;
                ensure!(count <= 200, "Desktop input rate exceeded");
                let ack = if let Some(previous) = seen.iter().find(|a| a.id == input.id) {
                    previous.clone()
                } else {
                    let result = worker
                        .as_ref()
                        .context("Desktop input session unavailable")?
                        .execute(input.command)
                        .await;
                    let ack = Ack {
                        id: input.id,
                        ok: result.is_ok(),
                        error: result
                            .err()
                            .map(|e| e.to_string().chars().take(300).collect()),
                    };
                    seen.push_back(ack.clone());
                    if seen.len() > 4096 {
                        seen.pop_front();
                    }
                    ack
                };
                let value = json!({"type":"ack","session":active,"ack":ack});
                if let Some(d) = &mut direct {
                    if d.send(value.to_string().as_bytes()).await.is_err() {
                        direct = None;
                    }
                }
                write(local.get_mut(), &value).await?;
            }
            Some("direct_offer")
                if active.is_some() && message["session"].as_str() == active.as_deref() =>
            {
                if !allow_direct || direct.is_some() {
                    write(
                        local.get_mut(),
                        &json!({"type":"direct_unavailable","session":active}),
                    )
                    .await?;
                    continue;
                }
                let offer = message["description"]
                    .as_str()
                    .context("Missing local connection offer")?;
                match direct::Direct::answer(offer).await {
                    Ok((connection, answer)) => {
                        direct = Some(connection);
                        write(
                            local.get_mut(),
                            &json!({"type":"direct_answer","session":active,"description":answer}),
                        )
                        .await?;
                    }
                    Err(_) => {
                        write(
                            local.get_mut(),
                            &json!({"type":"direct_unavailable","session":active}),
                        )
                        .await?
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(w) = worker.take() {
        let _ = w.execute(Command::ReleaseAll {}).await;
    }
    Ok(())
}
