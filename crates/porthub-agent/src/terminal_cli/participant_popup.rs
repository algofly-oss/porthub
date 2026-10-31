//! Client-targeted owner controls. A popup is not a shell pane and cannot keep
//! the workspace alive after its final shell exits. Only CLI owner attachments
//! hold the private lease checked by the shortcut; gateway guests do not.
use super::*;
use std::{ffi::OsStr, process::Child};

fn quote(value: &OsStr) -> Result<String> {
    let value = value
        .to_str()
        .context("terminal control path must be UTF-8")?;
    ensure!(!value.contains('\0'), "invalid terminal control path");
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}
fn lease_path(job: &Job, client: u32) -> PathBuf {
    job.workspace.join(format!("owner-client-{client}.lock"))
}
struct Lease {
    path: PathBuf,
    _file: fs::File,
}
impl Drop for Lease {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
fn register(job: &Job, child: &Child) -> Result<Lease> {
    let path = lease_path(job, child.id());
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "unsafe owner attachment lease"
    );
    file.try_lock_exclusive()
        .context("owner attachment lease is busy")?;
    Ok(Lease { path, _file: file })
}
pub(super) fn attach(job: &Job, workspace: &Workspace) -> Result<()> {
    let root = root()?;
    let executable = std::env::current_exe()?;
    let command = format!(
        "{} terminal __participants-popup {} {} '#{{client_pid}}' >/dev/null 2>&1 || true",
        quote(executable.as_os_str())?,
        quote(root.as_os_str())?,
        job.id
    );
    let result = workspace
        .command()
        .args(["bind-key", "P", "run-shell", "-b", &command])
        .output()?;
    ensure!(
        result.status.success(),
        "could not configure participant shortcut"
    );
    let mut child = workspace.attach(false).spawn()?;
    let lease = match register(job, &child) {
        Ok(lease) => lease,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let status = child.wait()?;
    drop(lease);
    ensure!(
        status.success(),
        "terminal attachment failed; the workspace may still be running"
    );
    Ok(())
}
pub(super) fn show(root: &Path, id: &str, client: u32) -> Result<()> {
    private(root)?;
    ensure!(client > 0, "invalid terminal client");
    let job = select(root, id)?;
    let file = crate::profile::read_private(&lease_path(&job, client));
    ensure!(
        file.is_ok(),
        "participant controls require a local owner attachment"
    );
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(lease_path(&job, client))?;
    match file.try_lock_exclusive() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        _ => anyhow::bail!("owner attachment is no longer active"),
    }
    let workspace = workspace(&job)?;
    let clients = workspace
        .command()
        .args([
            "list-clients",
            "-F",
            "#{client_pid}:#{client_name}:#{client_width}",
        ])
        .output()?;
    ensure!(clients.status.success(), "owner attachment unavailable");
    let clients = String::from_utf8_lossy(&clients.stdout);
    let fields = clients
        .lines()
        .find_map(|line| {
            let mut fields = line.splitn(3, ':');
            (fields.next()? == client.to_string()).then(|| (fields.next(), fields.next()))
        })
        .context("owner attachment unavailable")?;
    let client_name = fields.0.context("invalid owner terminal")?;
    let width = fields
        .1
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(40)
        .clamp(3, 40)
        .to_string();
    let executable = std::env::current_exe()?;
    let command = format!(
        "exec {} terminal __participants-view {} {}",
        quote(executable.as_os_str())?,
        quote(root.as_os_str())?,
        job.id
    );
    let status = workspace
        .command()
        .args([
            "display-popup",
            "-c",
            client_name,
            "-x",
            "R",
            "-y",
            "0",
            "-w",
            &width,
            "-h",
            "100%",
            "-E",
            &command,
        ])
        .status()?;
    ensure!(status.success(), "participant view could not open");
    Ok(())
}
pub(super) async fn view(root: &Path, id: &str) -> Result<()> {
    private(root)?;
    super::participant_panel::run(select(root, id)?).await
}
