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
    Usb{user:bool,registration:String,source:String,destination:String,busid:String},
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
            Self::Usb{..}=>0,
            Self::Forward { port, .. } => *port,
            Self::Exposure { local_port, .. } => *local_port,
        }
    }
    fn validate(&self) -> Result<()> {
        ensure!(self.port() > 0 || matches!(self,Self::Usb{..}), "Invalid mapping port");
        match self {
            Self::Usb{registration,source,destination,busid,..}=>{ensure!(registration.len()==64&&registration.bytes().all(|b|b.is_ascii_hexdigit())&&source!=destination&&[source,destination].iter().all(|s|s.len()==24&&s.bytes().all(|b|b.is_ascii_hexdigit()))&&porthub_components::usb::valid_busid(busid),"Invalid USB forwarding job");},
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
fn state_override() -> Result<Option<String>> {
    std::env::var_os("PORTHUB_STATE_DIR")
        .map(|value| {
            let value = value
                .into_string()
                .map_err(|_| anyhow::anyhow!("PORTHUB_STATE_DIR must be Unicode"))?;
            ensure!(
                Path::new(&value).is_absolute() && !value.chars().any(char::is_control),
                "PORTHUB_STATE_DIR must be an absolute path without control characters"
            );
            Ok(value)
        })
        .transpose()
}
fn recovery_suffix() -> Result<String> {
    use sha2::{Digest, Sha256};
    Ok(state_override()?
        .map(|value| {
            format!(
                "-{}",
                &format!("{:x}", Sha256::digest(value.as_bytes()))[..12]
            )
        })
        .unwrap_or_default())
}
fn root() -> Result<PathBuf> {
    let path = if let Some(configured) = state_override()? {
        PathBuf::from(configured).join("mappings")
    } else {
        directories::ProjectDirs::from("dev", "porthub", "porthub")
            .context("Cannot locate user configuration")?
            .config_dir()
            .join("mappings")
    };
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
    let lock = crate::profile::open_private_lock(&path)?;
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
        Spec::Usb{source,destination,busid,..}=>println!("{}  {:<11}  USB {}/{} -> {}  recovery:{}",&job.id[..12],label,source,busid,destination,job.recover),
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
        .filter(|j| j.spec.exposure() == exposure && (exposure || !matches!(j.spec,Spec::Usb{..})))
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
    stop_job(&root, &job).await
}
async fn stop_job(root: &Path, job: &Job) -> Result<()> {
    // Remove desired state first; a concurrent supervisor cannot resurrect it.
    std::fs::remove_file(file(root, &job.id)?)?;
    if job.spec.exposure() {
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
        if matches!(job.spec,Spec::Usb{..}) {"usb"} else if job.spec.exposure() {
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
    let lock = crate::profile::open_private_lock(&lock_path)?;
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
                Spec::Usb{user,registration,source,destination,busid}=>crate::usb::cli::broker_worker(user,registration,id.into(),source,destination,busid,work.clone()).await,
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
        let mut exposure_announced=false;
        loop {
            tokio::select! {
                result=&mut operation=>return result,
                _=cancel.cancelled()=>{work.cancel();return operation.await;},
                _=check.tick()=>{
                    if !path.try_exists()? {work.cancel();return operation.await;}
                    // Retain the originally allocated gateway port on recovery.
                    if job.spec.exposure() && !exposure_announced {
                        if let Some(port)=crate::expose::ready_port(id)? {
                            state(&root,id,"running",None)?;
                            exposure_announced = true;
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
    // This hidden Windows command is a background supervisor. Detach only
    // this process, never hide or close the invoking user's terminal.
    #[cfg(windows)] unsafe {windows_sys::Win32::System::Console::FreeConsole();}

    #[cfg(windows)]
    { let current=std::env::current_exe()?;if let Some(identity)=current.parent().and_then(Path::file_name).and_then(|v|v.to_str()).filter(|v|v.len()==64&&v.bytes().all(|b|b.is_ascii_hexdigit())) {let canonical=current.canonicalize()?;ensure!(pinned_windows_executable(&current,current.parent().and_then(Path::parent).context("Mapping release root missing")?)?.is_some_and(|path|path.canonicalize().ok().as_ref()==Some(&canonical)),"Mapping supervisor image checksum failed: {identity}");}}

    let root = root()?;
    let daemon_path = root.join("supervisor.lock");
    if !daemon_path.try_exists()? {
        let _ = crate::profile::write_private(&daemon_path, b"", false);
    }
    let lock = crate::profile::open_private_lock(&daemon_path)?;
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
            #[cfg(windows)] command.creation_flags(0x08000000); // CREATE_NO_WINDOW
            command.kill_on_drop(true);
            if let Ok(child) = command.spawn() {
                workers.push(child);
            }
        }
        tokio::select! {_=cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(3))=>{}}
    }
    #[cfg(unix)]
    {
        // Let exposure workers close their gateway leases before a restart.
        for child in &workers {
            if let Some(pid) = child.id() {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(18), async {
            for child in &mut workers {
                let _ = child.wait().await;
            }
        })
        .await;
    }
    for mut child in workers {
        let _ = child.kill().await;
    }
    Ok(())
}
#[cfg(windows)]
fn pinned_windows_executable(current: &Path, releases: &Path) -> Result<Option<PathBuf>> {
    use sha2::{Digest,Sha256};
    use std::io::Read;
    fn hash(path:&Path)->Result<String>{
        let metadata=std::fs::symlink_metadata(path)?;
        ensure!(metadata.is_file()&&metadata.len()<=256*1024*1024,"Mapping executable must be a bounded regular file");
        let mut file=std::fs::File::open(path)?;
        let mut hash=Sha256::new();let mut buffer=[0u8;65536];
        loop{let n=file.read(&mut buffer)?;if n==0{break;}hash.update(&buffer[..n]);}
        Ok(format!("{:x}",hash.finalize()))
    }
    let identity=hash(current)?;
    let directory=releases.join(&identity);
    let target=directory.join("porthub.exe");
    if !target.try_exists()?{return Ok(None);}
    ensure!(std::fs::symlink_metadata(&directory)?.is_dir(),"Mapping release directory must be real");
    ensure!(hash(&target)?==identity,"Mapping immutable executable checksum mismatch");
    Ok(Some(target))
}
fn executable() -> Result<PathBuf> {
    let current = std::env::current_exe()?;
    #[cfg(windows)]
    {
        if let Some(pinned)=pinned_windows_executable(&current,&crate::service::Layout::system()?.releases)? {
            return Ok(pinned);
        }
        let published=crate::bootstrap::cli_path(false,None)?;
        ensure!(published.canonicalize().ok().as_ref()!=Some(&current.canonicalize()?),"The installed CLI has no verified immutable release; repair PortHub setup before starting background mappings");
        return Ok(current);
    }
    #[cfg(not(windows))]
    {

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
}
async fn command(program: &str, args: &[&str]) -> Result<()> {
    let output = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::process::Command::new(program).args(args).kill_on_drop(true).output(),
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
    let unit = format!("porthub-mappings{}.service", recovery_suffix()?);
    let path = layout.units.join(&unit);
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
    let environment = state_override()?
        .map(|value| {
            format!(
                "Environment=\"PORTHUB_STATE_DIR={}\"\n",
                value
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('%', "%%")
            )
        })
        .unwrap_or_default();
    let wanted = if uid == 0 {
        "multi-user.target"
    } else {
        "default.target"
    };
    let contents=format!("# Managed by PortHub port mapping recovery\n[Unit]\nDescription=PortHub saved port mappings\nAfter=network-online.target\n[Service]\nType=simple\nExecStart=\"{escaped}\" mapping-supervisor\n{environment}Restart=always\nRestartSec=5\nUMask=0077\nTimeoutStopSec=20\n[Install]\nWantedBy={wanted}\n");
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
        command("systemctl", &["enable", "--now", &unit]).await
    } else {
        command("systemctl", &["--user", "daemon-reload"]).await?;
        command("systemctl", &["--user", "enable", "--now", &unit]).await
    }
}
#[cfg(target_os = "macos")]
async fn install_recovery() -> Result<()> {
    let layout = crate::service::Layout::user()?;
    std::fs::create_dir_all(&layout.units)?;
    let label = format!("dev.porthub.mappings{}", recovery_suffix()?);
    let path = layout.units.join(format!("{label}.plist"));
    let exe = executable()?
        .to_str()
        .context("CLI path must be Unicode")?
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let environment=state_override()?.map(|value|format!("<key>EnvironmentVariables</key><dict><key>PORTHUB_STATE_DIR</key><string>{}</string></dict>",value.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;"))).unwrap_or_default();
    let contents=format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>{exe}</string><string>mapping-supervisor</string></array>{environment}<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>5</integer><key>Umask</key><integer>63</integer></dict></plist>");
    crate::profile::write_private(&path, contents.as_bytes(), true)?;
    let domain = format!("gui/{}", rustix::process::getuid().as_raw());
    if command("launchctl", &["print", &format!("{domain}/{label}")])
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
#[cfg(any(windows,test))]
fn windows_recovery_script(metadata:&serde_json::Value,suffix:&str)->Result<String>{
    use base64::Engine;
    ensure!(suffix.is_empty()||(suffix.len()==13&&suffix.starts_with('-')&&suffix[1..].bytes().all(|b|b.is_ascii_hexdigit())),"Invalid recovery namespace");
    let payload=base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(metadata)?);
    Ok(WINDOWS_RECOVERY_SCRIPT.replace("__META_PAYLOAD__",&payload).replace("__STATE_SUFFIX__",suffix))
}
#[cfg(any(windows,test))]
const WINDOWS_RECOVERY_SCRIPT:&str=r###"$ErrorActionPreference='Stop'
$metaPayload='__META_PAYLOAD__'
$meta=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($metaPayload))|ConvertFrom-Json
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$sid=$identity.User.Value
if($sid -in @('S-1-5-18','S-1-5-19','S-1-5-20')){throw 'Mapping recovery requires the enrolled Windows user account'}
$name='PortHubMappings-'+$sid+'__STATE_SUFFIX__'
$descriptionPrefix='PortHub mapping recovery v1 '+$sid+' '
$powerShell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$runner=@'
$ErrorActionPreference='Stop'
$m=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('PAYLOAD_LITERAL'))|ConvertFrom-Json
$item=Get-Item -LiteralPath $m.executable
if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($item.Directory.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Mapping image is not a regular immutable release'}
if((Get-FileHash -LiteralPath $m.executable -Algorithm SHA256).Hash -ne $m.sha256){throw 'Mapping executable checksum changed'}
if($null -ne $m.state_override){$env:PORTHUB_STATE_DIR=[string]$m.state_override}else{Remove-Item Env:PORTHUB_STATE_DIR -ErrorAction SilentlyContinue}
& $m.executable mapping-supervisor
exit $LASTEXITCODE
'@
function ActionArguments([string]$payload){
 $code=$runner.Replace('PAYLOAD_LITERAL',$payload)
 return '-NoLogo -NoProfile -NonInteractive -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
}
function ActionFor([string]$payload){
 $data=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))|ConvertFrom-Json
 if($null -eq $data.state_override){return [pscustomobject]@{Execute=[string]$data.executable;Arguments='mapping-supervisor'}}
 return [pscustomobject]@{Execute=$powerShell;Arguments=(ActionArguments $payload)}
}
function VerifiedImage([string]$candidate,[string]$hash){
 if($hash -notmatch '^[a-fA-F0-9]{64}$'){return $false}
 $item=Get-Item -LiteralPath $candidate -ErrorAction SilentlyContinue
 if(-not $item -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($item.Directory.Attributes -band [IO.FileAttributes]::ReparsePoint)){return $false}
 if($item.Name -ne 'porthub.exe' -or $item.Directory.Name -ne $hash){return $false}
 if(@($meta.allowed_roots|Where-Object {[IO.Path]::GetFullPath($_) -eq $item.Directory.Parent.FullName}).Count -eq 0){return $false}
 return (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash -eq $hash
}
if(-not (VerifiedImage $meta.executable $meta.sha256)){throw 'Mapping target is not a checksum-verified immutable release'}
$actionSpec=ActionFor $metaPayload
$previous=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if($previous){
 $priorSid=$previous.Principal.UserId
 if($priorSid -notmatch '^S-1-'){$priorSid=([Security.Principal.NTAccount]$priorSid).Translate([Security.Principal.SecurityIdentifier]).Value}
 if($priorSid -ne $sid -or [string]$previous.Principal.LogonType -notin @('Interactive','3') -or [string]$previous.Principal.RunLevel -notin @('Limited','0') -or @($previous.Actions).Count -ne 1 -or -not $previous.Description.StartsWith($descriptionPrefix)){throw 'Refusing to replace an unverified mapping recovery task'}
 $oldPayload=$previous.Description.Substring($descriptionPrefix.Length)
 try{$old=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($oldPayload))|ConvertFrom-Json}catch{throw 'Mapping task ownership metadata is invalid'}
 $oldAction=ActionFor $oldPayload
 if($old.kind -ne 'porthub.mapping-recovery.v1' -or [IO.Path]::GetFullPath($old.root) -ne [IO.Path]::GetFullPath($meta.root) -or $old.state_override -cne $meta.state_override -or ($previous.Actions[0].Execute -ne $oldAction.Execute) -or ($previous.Actions[0].Arguments -cne $oldAction.Arguments) -or -not (VerifiedImage $old.executable $old.sha256)){throw 'Refusing to replace a modified mapping recovery task'}
}
# Recognize the exact former startup template, including its verified old image.
# Never remove an edited or unrelated startup entry just because its name matches.
$environment=''
if($null -ne $meta.state_override){$environment='shell.Environment("PROCESS")("PORTHUB_STATE_DIR") = "'+$meta.state_override.Replace('"','""')+'"'+"`r`n"}
$prefix='Set shell = CreateObject("WScript.Shell")'+"`r`n"+$environment+'shell.Run Chr(34) & "'
$suffix='" & Chr(34) & " mapping-supervisor", 0, False'+"`r`n"
$legacy=@((Join-Path $meta.root 'recover.vbs'),(Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\PortHub mappings__STATE_SUFFIX__.vbs'))
$ownedLegacy=@()
foreach($path in $legacy){
 if(!(Test-Path -LiteralPath $path)){continue}
 $file=Get-Item -LiteralPath $path
 if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Legacy mapping recovery is not a regular file'}
 $text=[IO.File]::ReadAllText($path)
 if(-not $text.StartsWith($prefix) -or -not $text.EndsWith($suffix)){throw 'Refusing to remove an unverified legacy mapping startup file'}
 $prior=$text.Substring($prefix.Length,$text.Length-$prefix.Length-$suffix.Length).Replace('""','"')
 $hash=Split-Path (Split-Path $prior -Parent) -Leaf
 if(-not (VerifiedImage $prior $hash)){throw 'Legacy mapping startup image is not verified'}
 $ownedLegacy+= $path
}
if(-not $previous -or $previous.Actions[0].Execute -ne $actionSpec.Execute -or $previous.Actions[0].Arguments -cne $actionSpec.Arguments){
 $action=New-ScheduledTaskAction -Execute $actionSpec.Execute -Argument $actionSpec.Arguments
 $trigger=New-ScheduledTaskTrigger -AtLogOn -User $sid
 $principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
 $settings=New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 $task=New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description ($descriptionPrefix+$metaPayload)
 Register-ScheduledTask -TaskName $name -InputObject $task -Force | Out-Null
}
# Task Scheduler owns this process tree independently of the creating SSH job.
# IgnoreNew preserves any existing healthy generation and active user mappings.
Start-ScheduledTask -TaskName $name
foreach($path in $ownedLegacy){Remove-Item -LiteralPath $path}
"###;
#[cfg(windows)]
async fn install_recovery() -> Result<()> {
    use base64::Engine;
    use sha2::{Digest,Sha256};
    use std::io::Read;
    let root=root()?;
    let lock_path=root.join("recovery-install.lock");
    if !lock_path.try_exists()? {let _=crate::profile::write_private(&lock_path,b"",false);}
    let lock=crate::profile::open_private_lock(&lock_path)?;
    lock.try_lock_exclusive().context("Mapping recovery setup is already running")?;
    let source=executable()?;
    let mut input=std::fs::File::open(&source)?;let mut digest=Sha256::new();let mut buffer=[0u8;65536];
    ensure!(input.metadata()?.len()<=256*1024*1024,"Mapping executable exceeds its size limit");
    loop{let n=input.read(&mut buffer)?;if n==0{break;}digest.update(&buffer[..n]);}
    let hash=format!("{:x}",digest.finalize());
    let managed=crate::service::Layout::system()?.releases;
    let runtime=root.join("runtime");
    let target=if source.file_name()==Some(std::ffi::OsStr::new("porthub.exe"))&&source.parent().and_then(Path::file_name).and_then(|v|v.to_str())==Some(hash.as_str())&&source.parent().and_then(Path::parent).is_some_and(|parent|parent==managed||parent==runtime) {source.clone()}else{
        let directory=runtime.join(&hash);crate::service::directory(&directory,true)?;
        let target=directory.join("porthub.exe");
        if !target.try_exists()? {let bytes=std::fs::read(&source)?;ensure!(format!("{:x}",Sha256::digest(&bytes))==hash,"Mapping image changed during pinning");crate::profile::write_private(&target,&bytes,false)?;}
        target
    };
    let metadata=serde_json::json!({"kind":"porthub.mapping-recovery.v1","executable":target,"sha256":hash,"root":root,"state_override":state_override()?,"allowed_roots":[managed,runtime]});
    let script=windows_recovery_script(&metadata,&recovery_suffix()?)?;
    let encoded=base64::engine::general_purpose::STANDARD.encode(script.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
    let powershell=PathBuf::from(std::env::var_os("SystemRoot").context("Windows SystemRoot unavailable")?).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    command(powershell.to_str().context("Invalid Windows PowerShell path")?,&["-NoLogo","-NoProfile","-NonInteractive","-EncodedCommand",&encoded]).await
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

// USB uses the same durable jobs, process locks and OS restart supervisor as TCP forwards.
pub(crate) fn usb_ready(id:&str)->Result<()>{state(&root()?,id,"running",None)}
pub fn usb_list(selector:Option<&str>)->Result<()>{let root=root()?;let rows:Vec<_>=jobs(&root)?.into_iter().filter(|j|matches!(j.spec,Spec::Usb{..})&&selector.is_none_or(|s|j.id.starts_with(s))).collect();if selector.is_some(){ensure!(rows.len()==1,"Choose a unique USB forwarding job ID");}if rows.is_empty(){println!("No saved USB forwards.");}for row in rows{describe(&root,&row)?;}Ok(())}
pub async fn usb_stop(selector:Option<&str>)->Result<()>{let rows:Vec<_>=jobs(&root()?)?.into_iter().filter(|j|matches!(j.spec,Spec::Usb{..})&&selector.is_none_or(|s|j.id.starts_with(s))).collect();ensure!(rows.len()==1,"Choose a unique USB forwarding job ID");stop(false,Some(&rows[0].id)).await}

#[cfg(test)]
mod private_lock_tests {
    use super::*;

    #[tokio::test]
    async fn held_job_locks_allow_active_list_and_stop_for_tcp_usb_foreground_and_recovery() -> Result<()> {
        let root = tempfile::tempdir()?;
        #[cfg(unix)]
        { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(root.path(),std::fs::Permissions::from_mode(0o700))?; }
        for recover in [false,true] {
            for spec in [Spec::Forward {target:"127.0.0.1:8080".into(),bind:"127.0.0.1".parse()?,port:18080},
                Spec::Usb {user:false,registration:"a".repeat(64),source:"a".repeat(24),destination:"b".repeat(24),busid:"1-2".into()}] {
                let job=Job{id:uuid::Uuid::new_v4().simple().to_string(),recover,spec};
                write(root.path(),&job)?;
                let path=file(root.path(),&job.id)?;
                let lock_path=path.with_extension("lock");
                crate::profile::write_private(&lock_path,b"",false)?;
                let held=crate::profile::open_private_lock(&lock_path)?;
                held.try_lock_exclusive()?;
                assert!(active(root.path(),&job)?);
                let listed=jobs(root.path())?;
                assert_eq!(listed.len(),1);
                describe(root.path(),&listed[0])?;
                let worker=tokio::spawn(async move {
                    while path.exists(){tokio::time::sleep(Duration::from_millis(10)).await;}
                    drop(held);
                });
                stop_job(root.path(),&job).await?;
                worker.await?;
                assert!(jobs(root.path())?.is_empty());
                assert!(!lock_path.exists());
            }
        }
        let path=root.path().join("supervisor.lock");
        crate::profile::write_private(&path,b"",false)?;
        let held=crate::profile::open_private_lock(&path)?;
        held.try_lock_exclusive()?;
        let contender=crate::profile::open_private_lock(&path)?;
        assert_eq!(contender.try_lock_exclusive().unwrap_err().raw_os_error(),fs2::lock_contended_error().raw_os_error());
        let oversized=root.path().join("oversized.lock");
        crate::profile::write_private(&oversized,b"",false)?;
        std::fs::OpenOptions::new().write(true).open(&oversized)?.set_len(4*1024*1024+1)?;
        assert!(crate::profile::open_private_lock(&oversized).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let link=root.path().join("symlink.lock");std::os::unix::fs::symlink(&path,&link)?;
            assert!(crate::profile::open_private_lock(&link).is_err());
            let unsafe_file=root.path().join("readable.lock");crate::profile::write_private(&unsafe_file,b"",false)?;
            std::fs::set_permissions(&unsafe_file,std::fs::Permissions::from_mode(0o644))?;
            assert!(crate::profile::open_private_lock(&unsafe_file).is_err());
        }
        Ok(())
    }
}

#[cfg(all(test,windows))]
mod windows_executable_tests {
    use super::*;
    use sha2::{Digest,Sha256};
    #[test]
    fn background_workers_pin_only_matching_immutable_release() -> Result<()> {
        let root=tempfile::tempdir()?;
        let cli=root.path().join("porthub.exe");let bytes=b"fixture executable";
        std::fs::write(&cli,bytes)?;
        let releases=root.path().join("releases");std::fs::create_dir(&releases)?;
        assert!(pinned_windows_executable(&cli,&releases)?.is_none());
        let leaf=releases.join(format!("{:x}",Sha256::digest(bytes)));std::fs::create_dir(&leaf)?;
        let target=leaf.join("porthub.exe");std::fs::write(&target,bytes)?;
        assert_eq!(pinned_windows_executable(&cli,&releases)?,Some(target.clone()));
        std::fs::write(&target,b"modified release")?;
        assert!(pinned_windows_executable(&cli,&releases).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod windows_recovery_tests {
    use super::*;
    #[test]
    fn scheduled_recovery_treats_paths_as_data() {
        use base64::Engine;
        let sentinel="C:\\state\\quoted' & $(untrusted)";
        let metadata=serde_json::json!({"kind":"porthub.mapping-recovery.v1","root":sentinel,"executable":sentinel,"state_override":sentinel,"sha256":"a".repeat(64),"allowed_roots":[sentinel]});
        let script=windows_recovery_script(&metadata,"-0123456789ab").unwrap();
        assert!(!script.contains(sentinel));
        let payload=script.split("$metaPayload='").nth(1).unwrap().split('\'').next().unwrap();
        let decoded:serde_json::Value=serde_json::from_slice(&base64::engine::general_purpose::STANDARD.decode(payload).unwrap()).unwrap();
        assert_eq!(decoded,metadata);
        assert!(windows_recovery_script(&metadata,"';unexpected").is_err());
    }
    #[test]
    fn scheduled_recovery_checks_ownership_before_startup_migration() {
        let script=windows_recovery_script(&serde_json::json!({}),"").unwrap();
        assert!(script.find("Refusing to replace a modified mapping recovery task").unwrap()<script.find("Register-ScheduledTask").unwrap());
        assert!(script.find("Refusing to remove an unverified legacy").unwrap()<script.find("Register-ScheduledTask").unwrap());
        assert!(script.find("Start-ScheduledTask").unwrap()<script.find("Remove-Item -LiteralPath $path").unwrap());
        assert!(!script.contains("Stop-ScheduledTask"));
    }
    #[test]
    #[ignore="Explicit native Windows lifecycle fixture renderer; requires task-specific metadata/output paths"]
    fn emit_windows_scheduler_fixture()->Result<()> {
        let metadata=std::fs::read(std::env::var("PORTHUB_TEST_RECOVERY_METADATA")?)?;
        ensure!(metadata.len()<16384,"Recovery fixture metadata exceeds limit");
        let value:serde_json::Value=serde_json::from_slice(&metadata)?;
        let script=windows_recovery_script(&value,&std::env::var("PORTHUB_TEST_RECOVERY_SUFFIX").unwrap_or_default())?;
        std::fs::write(std::env::var("PORTHUB_TEST_RECOVERY_SCRIPT")?,script)?;
        Ok(())
    }
}
