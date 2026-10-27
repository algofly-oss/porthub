//! User-owned application proxy jobs. No administrative access, public port,
//! registration credential, or additional management listener is required.
use anyhow::{ensure, Context, Result};
use clap::Subcommand;
use fs2::FileExt;
use porthub_egress::{
    proxy::{Credentials, Proxy},
    tor::TorPool,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    process::{Command as Process, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Subcommand)]
pub enum Command {
    /// Start an authenticated local HTTP/SOCKS5 proxy.
    Start {
        /// Local loopback port shared by HTTP and SOCKS5.
        #[arg(long,default_value_t=1080,value_parser=clap::value_parser!(u16).range(1..))]
        port: u16,
        /// Local Tor, or a shared proxy grant ID from Access Rules → Routes.
        #[arg(long, default_value = "tor")]
        via: String,
        /// Registration from porthub ls; omit when only one is installed.
        #[arg(long)]
        registration: Option<String>,
        /// Use a registration installed for this OS account.
        #[arg(long)]
        user: bool,
        /// Tor circuit groups (1–16); used with --via tor.
        #[arg(long,default_value_t=4,value_parser=clap::value_parser!(u8).range(1..=16))]
        circuit_groups: u8,
        /// Keep the proxy running after the terminal closes.
        #[arg(short = 'd', long = "detach")]
        detach: bool,
    },
    /// List application proxies started by this OS account.
    #[command(alias = "ls")]
    List,
    /// Show one proxy's state; omit its ID when only one exists.
    Status { id: Option<String> },
    /// Stop a proxy, including one started in a lost terminal.
    Stop { id: Option<String> },
    /// Reveal this OS account's proxy credentials explicitly.
    Credentials { id: Option<String> },
    #[command(hide = true)]
    Run { id: String },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    id: String,
    pid: u32,
    port: u16,
    via: String,
    #[serde(default)]
    registration: Option<String>,
    #[serde(default)]
    user: bool,
    circuit_groups: usize,
    state: String,
    username: String,
    password: String,
}

fn directory() -> Result<PathBuf> {
    let base = crate::expose::prepare_job_directory()?;
    let root = base.join("proxies");
    crate::service::directory(&root, true)?;
    Ok(root)
}
fn path(root: &Path, id: &str) -> Result<PathBuf> {
    ensure!(
        id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid proxy ID"
    );
    Ok(root.join(format!("{id}.json")))
}
fn read(path: &Path) -> Result<Job> {
    let bytes = crate::profile::read_private(path)?;
    ensure!(bytes.len() <= 8192, "proxy state exceeds size limit");
    let job: Job = serde_json::from_slice(&bytes).context("invalid proxy state")?;
    ensure!(
        path.file_stem().and_then(|value| value.to_str()) == Some(job.id.as_str())
            && job.port != 0
            && (1..=16).contains(&job.circuit_groups),
        "invalid proxy state identity"
    );
    Ok(job)
}
fn write(path: &Path, job: &Job) -> Result<()> {
    crate::profile::write_private(path, &serde_json::to_vec(job)?, true)
}
fn lock_path(path: &Path) -> PathBuf {
    path.with_extension("lock")
}
fn active(path: &Path) -> Result<bool> {
    let lock = lock_path(path);
    let metadata = std::fs::symlink_metadata(&lock)?;
    ensure!(metadata.is_file(), "unsafe proxy lock");
    let file = OpenOptions::new().read(true).write(true).open(lock)?;
    match file.try_lock_exclusive() {
        Ok(()) => {
            FileExt::unlock(&file)?;
            Ok(false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            || error.raw_os_error()==fs2::lock_contended_error().raw_os_error() => Ok(true),
        Err(error) => Err(error.into()),
    }
}
fn jobs(root: &Path) -> Result<Vec<Job>> {
    let mut jobs = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.extension().is_none_or(|value| value != "json") {
            continue;
        }
        if let Ok(job) = read(&path) {
            if active(&path).unwrap_or(false) {
                jobs.push(job);
            }
        }
        ensure!(jobs.len() <= 128, "too many proxy jobs");
    }
    jobs.sort_by_key(|job| job.id.clone());
    Ok(jobs)
}
fn select(root: &Path, id: Option<&str>) -> Result<Job> {
    let matches = jobs(root)?
        .into_iter()
        .filter(|job| id.is_none_or(|id| job.id.starts_with(id) || job.port.to_string() == id))
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "select one running proxy using its ID or port from porthub proxy ls"
    );
    Ok(matches.into_iter().next().unwrap())
}
fn describe(root: &Path, job: &Job) {
    println!(
        "Proxy {}: {}; via {}; localhost:{}",
        &job.id[..12],
        job.state,
        job.via,
        job.port
    );
    println!("HTTP: http://127.0.0.1:{}", job.port);
    println!("SOCKS5: socks5h://127.0.0.1:{}", job.port);
    println!(
        "curl configuration: {}",
        root.join(format!("{}.curl", job.id)).display()
    );
    println!("Credentials: porthub proxy credentials {}", &job.id[..12]);
    println!("Stop: porthub proxy stop {}", &job.id[..12]);
}

pub async fn run(command: Command, cancel: CancellationToken) -> Result<()> {
    let root = directory()?;
    match command {
        Command::List => {
            let jobs = jobs(&root)?;
            if jobs.is_empty() {
                println!("No application proxies running");
            }
            for job in jobs {
                println!(
                    "{}  {:<12}  {:<8}  localhost:{}",
                    &job.id[..12],
                    job.state,
                    job.via,
                    job.port
                );
            }
        }
        Command::Status { id } => describe(&root, &select(&root, id.as_deref())?),
        Command::Credentials { id } => {
            let job = select(&root, id.as_deref())?;
            println!("Username: {}\nPassword: {}", job.username, job.password);
        }
        Command::Stop { id } => {
            let job = select(&root, id.as_deref())?;
            let file = path(&root, &job.id)?;
            crate::profile::write_private(&file.with_extension("stop"), b"stop", true)?;
            tokio::time::timeout(Duration::from_secs(8), async {
                while file.exists() && active(&file).unwrap_or(false) {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                }
            })
            .await
            .context("proxy shutdown is still pending; no process was killed")?;
            println!("Stopped proxy {}", &job.id[..12]);
        }
        Command::Run { id } => worker(&root, &path(&root, &id)?, cancel).await?,
        Command::Start {
            port,
            via,
            registration,
            user,
            circuit_groups,
            detach,
        } => {
            ensure!(via == "tor" || (via.len()==24 && via.bytes().all(|byte|byte.is_ascii_hexdigit())),
                "Choose tor or a proxy grant ID from Access Rules → Routes");
            let registration = if via == "tor" { None } else {
                let layout = if user {crate::service::Layout::user()?}else{crate::service::Layout::system()?};
                Some(crate::service::readable::select(&layout, registration.as_deref(), Some(false))?.id)
            };
            if let Some(id)=&registration {
                println!("Checking shared proxy…");
                let connector=crate::proxy_transport::LocalConnector{registration:id.clone(),user,grant:via.clone()};
                let ready=async {
                    loop {
                        if connector.check().await? {return Ok::<_,anyhow::Error>(());}
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                };
                tokio::select! {_=cancel.cancelled()=>return Ok(()),result=tokio::time::timeout(Duration::from_secs(12),ready)=>result.context("The selected peer is still preparing; try again shortly")??}
            }
            ensure!(
                jobs(&root)?.len() < 32,
                "this account already has 32 application proxies"
            );
            let id = uuid::Uuid::new_v4().simple().to_string();
            let file = path(&root, &id)?;
            let mut secret = [0u8; 32];
            getrandom::fill(&mut secret)
                .map_err(|_| anyhow::anyhow!("proxy credential randomness unavailable"))?;
            let job = Job {
                id: id.clone(),
                pid: 0,
                port,
                via,
                registration,
                user,
                circuit_groups: usize::from(circuit_groups),
                state: "starting".into(),
                username: "porthub".into(),
                password: secret.iter().map(|byte| format!("{byte:02x}")).collect(),
            };
            crate::profile::write_private(&file, &serde_json::to_vec(&job)?, false)?;
            crate::profile::write_private(&lock_path(&file), b"", false)?;
            let configuration = format!(
                "proxy = \"http://127.0.0.1:{port}\"\nproxy-user = \"{}:{}\"\n",
                job.username, job.password
            );
            crate::profile::write_private(
                &file.with_extension("curl"),
                configuration.as_bytes(),
                false,
            )?;
            if detach {
                let mut command = Process::new(std::env::current_exe()?);
                // Keep credentials in private files, never process arguments.
                command.args(["proxy", "run", &id]).stdin(Stdio::null());
                let log_path = file.with_extension("log");
                crate::profile::write_private(&log_path, b"", false)?;
                let log = OpenOptions::new().append(true).open(&log_path)?;
                command
                    .stdout(Stdio::from(log.try_clone()?))
                    .stderr(Stdio::from(log.try_clone()?));
                #[cfg(unix)]
                {
                    use std::os::unix::process::CommandExt;
                    command.process_group(0);
                }
                #[cfg(windows)]
                let mut child = crate::detached_windows::spawn(&command, &log)?;
                #[cfg(not(windows))]
                let mut child = command.spawn()?;
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        if child.try_wait()?.is_some() {
                            anyhow::bail!("proxy worker stopped; inspect its private job log");
                        }
                        if active(&file).unwrap_or(false) && read(&file).is_ok_and(|job|job.pid==child.id() && matches!(job.state.as_str(),"preparing"|"ready")) {
                            return Ok::<_, anyhow::Error>(());
                        }
                        tokio::time::sleep(Duration::from_millis(40)).await;
                    }
                })
                .await
                .context("proxy worker did not start")??;
                describe(&root, &read(&file)?);
            } else {
                worker(&root, &file, cancel).await?;
            }
        }
    }
    Ok(())
}

struct Owner {
    file: PathBuf,
    lock: Option<File>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        for suffix in ["json", "curl", "stop"] {
            let _ = std::fs::remove_file(self.file.with_extension(suffix));
        }
        self.lock.take();
        let _ = std::fs::remove_file(lock_path(&self.file));
    }
}
fn stop_path(path: &Path) -> PathBuf {
    path.with_extension("stop")
}
fn stopped(path: &Path) -> Result<bool> {
    let stop = stop_path(path);
    match std::fs::symlink_metadata(&stop) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
        Ok(metadata) => {
            ensure!(metadata.len() == 4, "invalid proxy stop request");
            Ok(crate::profile::read_private(&stop)? == b"stop")
        }
    }
}
async fn worker(root: &Path, file: &Path, cancel: CancellationToken) -> Result<()> {
    let mut job = read(file)?;
    ensure!(job.via == "tor" || (job.via.len()==24 && job.via.bytes().all(|byte|byte.is_ascii_hexdigit())
        && job.registration.as_ref().is_some_and(|id|id.len()==64 && id.bytes().all(|byte|byte.is_ascii_hexdigit()))), "invalid proxy provider identity");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path(file))?;
    lock.try_lock_exclusive()
        .context("proxy job already has an owner")?;
    let _owner = Owner {
        file: file.into(),
        lock: Some(lock),
    };
    job.pid = std::process::id();
    job.state = "starting".into();
    write(file, &job)?;
    let work = cancel.child_token();
    let _cleanup = work.clone().drop_guard();
    let mut tasks = tokio::task::JoinSet::new();
    let (updates, mut stop) = tokio::sync::watch::channel(stopped(file)?);
    tasks.spawn(crate::private_network::settings_watch::run(
        file.into(),
        stop_path,
        stopped,
        updates,
        "proxy stop",
        work.clone(),
    ));
    let stop_work = work.clone();
    tasks.spawn(async move {
        loop {
            if *stop.borrow() {
                stop_work.cancel();
                return Ok(());
            }
            if stop.changed().await.is_err() {
                return Ok(());
            }
        }
    });
    if job.via != "tor" {
        let connector = Arc::new(crate::proxy_transport::LocalConnector {
            registration:job.registration.clone().context("proxy registration is missing")?,
            user:job.user, grant:job.via.clone(),
        });
        let proxy = Proxy::bind(([127,0,0,1],job.port).into(),
            Credentials::new(job.username.clone(),job.password.clone())?,connector,64).await?;
        job.state="ready".into();write(file,&job)?;describe(root,&job);
        let result=proxy.run(work.clone()).await;
        work.cancel();tasks.abort_all();while tasks.join_next().await.is_some(){}
        return result;
    }
    let initial = crate::private_network::interfaces::current().await?;
    let (source_updates, sources) = tokio::sync::watch::channel(initial);
    tasks.spawn(crate::private_network::interfaces::watch(
        source_updates,
        work.clone(),
    ));
    let (ip_updates, ip_sources) = tokio::sync::watch::channel(
        sources
            .borrow()
            .iter()
            .map(std::net::SocketAddr::ip)
            .collect(),
    );
    let mut source_changes = sources;
    let source_work = work.clone();
    tasks.spawn(async move {
        loop {tokio::select! {
            _=source_work.cancelled()=>return Ok(()),
            result=source_changes.changed()=>{if result.is_err(){return Ok(());}ip_updates.send_replace(source_changes.borrow_and_update().iter().map(std::net::SocketAddr::ip).collect());}
        }}
    });
    let tor = Arc::new(
        TorPool::new(&root.join("tor-cache"), job.circuit_groups, 64)?.with_underlay(ip_sources),
    );
    let proxy = Proxy::bind(
        ([127, 0, 0, 1], job.port).into(),
        Credentials::new(job.username.clone(), job.password.clone())?,
        tor.clone(),
        64,
    )
    .await?;
    let result = async {
        job.state="preparing".into();write(file,&job)?;
        println!("Preparing local Tor circuits…");
        tokio::select! {_=work.cancelled()=>return Ok(()),result=tor.bootstrap()=>result?}
        job.state = "ready".into();
        write(file, &job)?;
        describe(root, &job);
        proxy.run(work.clone()).await
    }
    .await;
    work.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn private_directory()->Result<tempfile::TempDir> {
        let mut builder=tempfile::Builder::new();
        #[cfg(unix)]
        {use std::os::unix::fs::PermissionsExt;builder.permissions(std::fs::Permissions::from_mode(0o700));}
        Ok(builder.tempdir()?)
    }
    fn job(id:&str)->Job {
        Job {id:id.into(),pid:std::process::id(),port:1080,via:"tor".into(),registration:None,user:false,circuit_groups:4,state:"ready".into(),username:"porthub".into(),password:"private-local-session-credential".into()}
    }
    #[test]
    fn process_id_is_not_authority_for_a_job() -> Result<()> {
        let root=private_directory()?;
        let record=job("0123456789abcdef0123456789abcdef");let file=path(root.path(),&record.id)?;
        write(&file,&record)?;crate::profile::write_private(&lock_path(&file),b"",false)?;
        assert!(!active(&file)?);
        let lock=OpenOptions::new().read(true).write(true).open(lock_path(&file))?;lock.try_lock_exclusive()?;
        assert!(active(&file)?);
        assert_eq!(select(root.path(),Some("1080"))?.id,record.id);
        drop(lock);assert!(jobs(root.path())?.is_empty());
        Ok(())
    }
    #[test]
    fn job_identity_and_stop_requests_are_bounded_and_private() -> Result<()> {
        let root=private_directory()?;
        assert!(path(root.path(),"../another-user").is_err());
        let record=job("0123456789abcdef0123456789abcdef");let file=path(root.path(),&record.id)?;
        write(&file,&record)?;assert!(!stopped(&file)?);
        crate::profile::write_private(&stop_path(&file),b"stop",false)?;assert!(stopped(&file)?);
        crate::profile::write_private(&stop_path(&file),b"invalid",true)?;assert!(stopped(&file).is_err());
        let mut invalid=record;invalid.id="abcdef0123456789abcdef0123456789".into();write(&file,&invalid)?;
        assert!(read(&file).is_err());
        #[cfg(unix)]
        {use std::os::unix::fs::PermissionsExt;assert_eq!(std::fs::metadata(&file)?.permissions().mode()&0o777,0o600);}
        Ok(())
    }
}
