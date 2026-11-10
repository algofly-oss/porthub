//! Durable, per-OS-user port mappings. Only explicit stop removes desired state.
use anyhow::{ensure, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Spec {
    Forward {
        target: String,
        bind: IpAddr,
        port: u16,
    },
    Exposure {
        user: bool,
        registration: String,
        local_port: u16,
        external_port: Option<u16>,
        subdomain: Option<String>,
    },
}
impl Spec {
    fn exposure(&self) -> bool {
        matches!(self, Self::Exposure { .. })
    }
    fn port(&self) -> u16 {
        match self {
            Self::Forward { port, .. } => *port,
            Self::Exposure { local_port, .. } => *local_port,
        }
    }
    fn validate(&self) -> Result<()> {
        ensure!(self.port() > 0, "Invalid mapping port");
        match self {
            Self::Forward { target, .. } => {
                crate::forward::destination(target)?;
            }
            Self::Exposure {
                registration,
                external_port,
                subdomain,
                ..
            } => {
                ensure!(
                    registration.len() == 64
                        && registration.bytes().all(|b| b.is_ascii_hexdigit())
                        && *external_port != Some(0),
                    "Invalid exposure registration or port"
                );
                ensure!(
                    subdomain.as_ref().is_none_or(|s| !s.is_empty()
                        && s.len() <= 63
                        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
                    "Invalid exposure subdomain"
                );
            }
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    id: String,
    recover: bool,
    spec: Spec,
}
#[derive(Serialize, Deserialize)]
struct Status {
    state: String,
    pid: u32,
    message: Option<String>,
}
fn root() -> Result<PathBuf> {
    let path = directories::ProjectDirs::from("dev", "porthub", "porthub")
        .context("Cannot locate user configuration")?
        .config_dir()
        .join("mappings");
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&path)?;
    crate::service::directory(&path, true)?;
    Ok(path)
}
fn file(root: &Path, id: &str) -> Result<PathBuf> {
    ensure!(
        id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid mapping ID"
    );
    Ok(root.join(format!("{id}.json")))
}
fn read(path: &Path) -> Result<Job> {
    let bytes = crate::profile::read_private(path)?;
    ensure!(bytes.len() <= 8192, "Mapping configuration is too large");
    let job: Job = serde_json::from_slice(&bytes)?;
    ensure!(
        path.file_stem().and_then(|s| s.to_str()) == Some(job.id.as_str()),
        "Mapping identity does not match its filename"
    );
    job.spec.validate()?;
    Ok(job)
}
fn write(root: &Path, job: &Job) -> Result<()> {
    crate::profile::write_private(
        &file(root, &job.id)?,
        &serde_json::to_vec_pretty(job)?,
        true,
    )
}
fn state(root: &Path, id: &str, value: &str, message: Option<String>) -> Result<()> {
    crate::profile::write_private(
        &file(root, id)?.with_extension("status"),
        &serde_json::to_vec(&Status {
            state: value.into(),
            pid: std::process::id(),
            message,
        })?,
        true,
    )
}
fn active(root: &Path, job: &Job) -> Result<bool> {
    if job.spec.exposure() && crate::expose::session_active(&job.id)? {
        return Ok(true);
    }
    let path = file(root, &job.id)?.with_extension("lock");
    if !path.try_exists()? {
        return Ok(false);
    }
    crate::profile::read_private(&path)?;
    let lock = OpenOptions::new().read(true).write(true).open(path)?;
    match lock.try_lock_exclusive() {
        Ok(()) => {
            FileExt::unlock(&lock)?;
            Ok(false)
        }
        Err(e) if e.raw_os_error() == fs2::lock_contended_error().raw_os_error() => Ok(true),
        Err(e) => Err(e.into()),
    }
}
fn jobs(root: &Path) -> Result<Vec<Job>> {
    let mut rows = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.extension().is_some_and(|s| s == "json") {
            rows.push(read(&path)?);
        }
        ensure!(rows.len() <= 128, "Too many saved mappings");
    }
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(rows)
}
fn select(root: &Path, exposure: bool, selector: Option<&str>) -> Result<Job> {
    let rows = jobs(root)?
        .into_iter()
        .filter(|job| {
            job.spec.exposure() == exposure
                && selector
                    .is_none_or(|s| job.id.starts_with(s) || job.spec.port().to_string() == s)
        })
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1,
        "Select one mapping by its unique ID prefix or local port from the list"
    );
    Ok(rows.into_iter().next().unwrap())
}
fn describe(root: &Path, job: &Job) -> Result<()> {
    let running = active(root, job)?;
    let status = crate::profile::read_private(&file(root, &job.id)?.with_extension("status"))
        .ok()
        .and_then(|b| serde_json::from_slice::<Status>(&b).ok());
    let label = if running {
        status
            .as_ref()
            .map(|s| s.state.as_str())
            .unwrap_or("running")
    } else if job.recover {
        "recovering"
    } else {
        "stopped"
    };
    match &job.spec {
        Spec::Forward { target, bind, port } => println!(
            "{}  {:<11}  {} -> {}  recovery:{}",
            &job.id[..12],
            label,
            crate::forward::address(*bind, *port),
            target,
            job.recover
        ),
        Spec::Exposure {
            local_port,
            external_port,
            subdomain,
            ..
        } => {
            println!(
                "{}  {:<11}  localhost:{} -> gateway:{}  recovery:{}",
                &job.id[..12],
                label,
                local_port,
                external_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "automatic".into()),
                job.recover
            );
            if let Some(name) = subdomain {
                println!("  Subdomain: {name}");
            }
            crate::expose::describe_session(&job.id)?;
        }
    }
    if let Some(message) = status.and_then(|s| s.message) {
        println!("  Last error: {message}");
    }
    Ok(())
}
pub(crate) fn is_saved(id: &str) -> Result<bool> {
    Ok(file(&root()?, id)?.try_exists()?)
}
fn matching(root: &Path, exposure: bool, selector: Option<&str>) -> Result<bool> {
    Ok(jobs(root)?.iter().any(|j| {
        j.spec.exposure() == exposure
            && selector.is_none_or(|s| j.id.starts_with(s) || j.spec.port().to_string() == s)
    }))
}
pub fn list(exposure: bool) -> Result<()> {
    let root = root()?;
    let rows = jobs(&root)?
        .into_iter()
        .filter(|j| j.spec.exposure() == exposure)
        .collect::<Vec<_>>();
    let legacy = if exposure {
        crate::expose::list_unmanaged()?
    } else {
        0
    };
    if rows.is_empty() && legacy == 0 {
        println!(
            "No saved {}.",
            if exposure { "exposures" } else { "forwards" }
        );
    }
    for job in rows {
        describe(&root, &job)?;
    }
    Ok(())
}
pub fn status(exposure: bool, selector: Option<&str>) -> Result<()> {
    let root = root()?;
    if exposure && !matching(&root, true, selector)? {
        return crate::expose::legacy_status(selector);
    }
    describe(&root, &select(&root, exposure, selector)?)
}
pub async fn stop(exposure: bool, selector: Option<&str>) -> Result<()> {
    let root = root()?;
    if exposure && !matching(&root, true, selector)? {
        return crate::expose::stop(
            &crate::expose::job_layout()?,
            selector.context("Use porthub expose stop ID")?,
        );
    }
    let job = select(&root, exposure, selector)?;
    // Remove desired state first; a concurrent supervisor cannot resurrect it.
    std::fs::remove_file(file(&root, &job.id)?)?;
    if exposure {
        let _ = crate::expose::stop(&crate::expose::job_layout()?, &job.id);
    }
    tokio::time::timeout(Duration::from_secs(25), async {
        while active(&root, &job)? {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("Mapping recovery is disabled; shutdown is still pending")??;
    for suffix in ["status", "lock", "assigned"] {
        let _ = std::fs::remove_file(file(&root, &job.id)?.with_extension(suffix));
    }
    println!("Stopped {}. Restart recovery disabled.", &job.id[..12]);
    Ok(())
}
pub async fn start(spec: Spec, recover: bool, cancel: CancellationToken) -> Result<()> {
    spec.validate()?;
    let root = root()?;
    ensure!(
        jobs(&root)?.len() < 128,
        "This account already has 128 saved mappings"
    );
    if recover {
        install_recovery().await?;
    }
    let job = Job {
        id: uuid::Uuid::new_v4().simple().to_string(),
        spec,
        recover,
    };
    write(&root, &job)?;
    if !recover {
        return worker(&job.id, cancel).await;
    }
    let ready = tokio::time::timeout(Duration::from_secs(55), async {
        loop {
            let status =
                crate::profile::read_private(&file(&root, &job.id)?.with_extension("status"))
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Status>(&b).ok());
            let exposure_ready = job.spec.exposure() && crate::expose::session_ready(&job.id)?;
            if exposure_ready || status.as_ref().is_some_and(|s| s.state == "running") {
                return Ok::<_, anyhow::Error>(());
            }
            if let Some(status) = status.filter(|s| s.state == "failed") {
                anyhow::bail!("{}", status.message.unwrap_or_default());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    describe(&root, &read(&file(&root, &job.id)?)?)?;
    if !matches!(ready, Ok(Ok(()))) {
        println!("Mapping saved; recovery will retry automatically. Inspect its status or stop it to cancel.");
    }
    println!(
        "Stop: porthub {} stop {}",
        if job.spec.exposure() {
            "expose"
        } else {
            "forward"
        },
        &job.id[..12]
    );
    Ok(())
}
pub async fn worker(id: &str, cancel: CancellationToken) -> Result<()> {
    let root = root()?;
    let path = file(&root, id)?;
    let job = read(&path)?;
    let lock_path = path.with_extension("lock");
    if !lock_path.try_exists()? {
        let _ = crate::profile::write_private(&lock_path, b"", false);
    }
    let lock = OpenOptions::new().read(true).write(true).open(&lock_path)?;
    lock.try_lock_exclusive()
        .context("Mapping already has an owner")?;
    // A stop may have raced with acquiring ownership.
    read(&path)?;
    state(&root, id, "starting", None)?;
    let work = cancel.child_token();
    let _guard = work.clone().drop_guard();
    let result=async {
        let mut operation_job=job.clone();
        if let Spec::Exposure{external_port,..}=&mut operation_job.spec {
            if external_port.is_none() {
                *external_port=crate::profile::read_private(&path.with_extension("assigned")).ok()
                    .and_then(|b|String::from_utf8(b).ok()).and_then(|s|s.parse::<u16>().ok()).filter(|p|*p>0);
            }
        }
        let operation=async {
            match operation_job.spec.clone() {
                Spec::Forward{target,bind,port}=>{
                    let listener=tokio::net::TcpListener::bind(crate::forward::address(bind,port)).await.context("Cannot bind the local port; choose a different --bind or --local-port")?;
                    state(&root,id,"running",None)?;describe(&root,&operation_job)?;
                    crate::forward::serve(listener,target,work.clone()).await
                },
                Spec::Exposure{user,registration,local_port,external_port,subdomain}=>{
                    let layout=if user{crate::service::Layout::user()?}else{crate::service::Layout::system()?};
                    crate::expose::broker_worker(layout,registration,id.into(),local_port,external_port,subdomain,work.clone()).await
                }
            }
        };
        tokio::pin!(operation);
        let mut check=tokio::time::interval(Duration::from_millis(300));
        loop {
            tokio::select! {
                result=&mut operation=>return result,
                _=cancel.cancelled()=>{work.cancel();return operation.await;},
                _=check.tick()=>{
                    if !path.try_exists()? {work.cancel();return operation.await;}
                    // Retain the originally allocated gateway port on recovery.
                    if job.spec.exposure() {
                        if let Some(port)=crate::expose::ready_port(id)? {
                            state(&root,id,"running",None)?;
                            let assigned=path.with_extension("assigned");
                            if !assigned.try_exists()? {crate::profile::write_private(&assigned,port.to_string().as_bytes(),false)?;}
                        }
                    }
                }
            }
        }
    }.await;
    match &result {
        Ok(()) => {
            state(&root, id, "stopped", None)?;
        }
        Err(e) => {
            state(&root, id, "failed", Some(format!("{e:#}")))?;
        }
    }
    if !job.recover {
        let _ = std::fs::remove_file(path);
    }
    drop(lock);
    result
}
pub async fn supervise(cancel: CancellationToken) -> Result<()> {
    let root = root()?;
    let daemon_path = root.join("supervisor.lock");
    if !daemon_path.try_exists()? {
        let _ = crate::profile::write_private(&daemon_path, b"", false);
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(daemon_path)?;
    lock.try_lock_exclusive()
        .context("Mapping recovery is already running")?;
    let mut workers = Vec::new();
    loop {
        workers.retain_mut(|child: &mut tokio::process::Child| {
            child.try_wait().ok().flatten().is_none()
        });
        for job in jobs(&root)? {
            if !job.recover || active(&root, &job)? {
                continue;
            }
            let log_path = file(&root, &job.id)?.with_extension("log");
            if !log_path.try_exists()? {
                crate::profile::write_private(&log_path, b"", false)?;
            }
            let log = OpenOptions::new().append(true).open(log_path)?;
            if log.metadata()?.len() > 1024 * 1024 {
                log.set_len(0)?;
            }
            let mut command = tokio::process::Command::new(executable()?);
            command
                .args(["mapping-worker", &job.id])
                .stdin(std::process::Stdio::null())
                .stdout(log.try_clone()?)
                .stderr(log);
            command.kill_on_drop(true);
            if let Ok(child) = command.spawn() {
                workers.push(child);
            }
        }
        tokio::select! {_=cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(3))=>{}}
    }
    for mut child in workers {
        let _ = child.kill().await;
    }
    Ok(())
}
fn executable() -> Result<PathBuf> {
    let current = std::env::current_exe()?;
    let invoked = std::env::args_os().next().map(PathBuf::from);
    for user in [false, true] {
        if let Ok(path) = crate::bootstrap::cli_path(user, None) {
            if invoked.as_ref() == Some(&path) && path.is_file()
                || path.canonicalize().ok() == current.canonicalize().ok()
            {
                return Ok(path);
            }
        }
    }
    Ok(current)
}
async fn command(program: &str, args: &[&str]) -> Result<()> {
    let output = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::process::Command::new(program).args(args).output(),
    )
    .await
    .context("Startup registration timed out")??;
    ensure!(
        output.status.success(),
        "Cannot configure mapping recovery: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}
#[cfg(target_os = "linux")]
async fn install_recovery() -> Result<()> {
    let uid = rustix::process::getuid().as_raw();
    if uid != 0 {
        command(
            "loginctl",
            &["--no-ask-password", "enable-linger", &uid.to_string()],
        )
        .await
        .context("Allow user services at boot with: loginctl enable-linger <user>")?;
    }
    let layout = if uid == 0 {
        crate::service::Layout::system()?
    } else {
        crate::service::Layout::user()?
    };
    std::fs::create_dir_all(&layout.units)?;
    let path = layout.units.join("porthub-mappings.service");
    let exe = executable()?
        .to_str()
        .context("CLI path must be Unicode")?
        .to_owned();
    ensure!(!exe.chars().any(char::is_control), "Invalid CLI path");
    let escaped = exe
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
        .replace('$', "$$");
    let wanted = if uid == 0 {
        "multi-user.target"
    } else {
        "default.target"
    };
    let contents=format!("# Managed by PortHub port mapping recovery\n[Unit]\nDescription=PortHub saved port mappings\nAfter=network-online.target\n[Service]\nType=simple\nExecStart=\"{escaped}\" mapping-supervisor\nRestart=always\nRestartSec=5\nUMask=0077\nTimeoutStopSec=20\n[Install]\nWantedBy={wanted}\n");
    if path.try_exists()? {
        ensure!(
            crate::profile::read_private(&path)?
                .starts_with(b"# Managed by PortHub port mapping recovery\n"),
            "The mapping recovery unit already exists and is not managed by PortHub"
        );
    }
    crate::profile::write_private(&path, contents.as_bytes(), true)?;
    if uid == 0 {
        command("systemctl", &["daemon-reload"]).await?;
        command(
            "systemctl",
            &["enable", "--now", "porthub-mappings.service"],
        )
        .await
    } else {
        command("systemctl", &["--user", "daemon-reload"]).await?;
        command(
            "systemctl",
            &["--user", "enable", "--now", "porthub-mappings.service"],
        )
        .await
    }
}
#[cfg(target_os = "macos")]
async fn install_recovery() -> Result<()> {
    let layout = crate::service::Layout::user()?;
    std::fs::create_dir_all(&layout.units)?;
    let path = layout.units.join("dev.porthub.mappings.plist");
    let exe = executable()?
        .to_str()
        .context("CLI path must be Unicode")?
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let contents=format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Label</key><string>dev.porthub.mappings</string><key>ProgramArguments</key><array><string>{exe}</string><string>mapping-supervisor</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>5</integer><key>Umask</key><integer>63</integer></dict></plist>");
    crate::profile::write_private(&path, contents.as_bytes(), true)?;
    let domain = format!("gui/{}", rustix::process::getuid().as_raw());
    if command(
        "launchctl",
        &["print", &format!("{domain}/dev.porthub.mappings")],
    )
    .await
    .is_ok()
    {
        return Ok(());
    }
    command(
        "launchctl",
        &[
            "bootstrap",
            &domain,
            path.to_str().context("Invalid startup path")?,
        ],
    )
    .await
}
#[cfg(windows)]
async fn install_recovery() -> Result<()> {
    let root = root()?;
    let exe = executable()?
        .to_str()
        .context("CLI path must be Unicode")?
        .to_owned();
    let script = root.join("recover.vbs");
    // An OS startup shortcut runs the per-user supervisor without a console.
    let contents=format!("CreateObject(\"WScript.Shell\").Run Chr(34) & \"{}\" & Chr(34) & \" mapping-supervisor\", 0, False\r\n",exe.replace('"',"\"\""));
    let appdata = std::env::var_os("APPDATA").context("Cannot locate Windows startup folder")?;
    let startup = PathBuf::from(appdata)
        .join("Microsoft/Windows/Start Menu/Programs/Startup/PortHub mappings.vbs");
    crate::profile::write_private(&script, contents.as_bytes(), true)?;
    crate::profile::write_private(&startup, contents.as_bytes(), true)?;
    command(
        "wscript.exe",
        &[script.to_str().context("Invalid startup path")?],
    )
    .await
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
async fn install_recovery() -> Result<()> {
    anyhow::bail!("Detached mapping recovery is unsupported on this platform")
}

pub fn adopt_exposure(id: String, spec: Spec) -> Result<()> {
    spec.validate()?;
    let root = root()?;
    let path = file(&root, &id)?;
    if !path.try_exists()? {
        write(
            &root,
            &Job {
                id,
                recover: true,
                spec,
            },
        )?;
    }
    Ok(())
}
pub async fn enable_recovery() -> Result<()> {
    install_recovery().await
}
