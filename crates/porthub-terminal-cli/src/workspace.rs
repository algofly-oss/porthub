//! Local workspace creation and registry persistence belong to the optional tool.
use anyhow::{ensure, Context, Result};
use fs2::FileExt;
use porthub_components::protocol::terminal::{CreateOptions, Job};
use porthub_terminal::{
    multiplexer::{create_directory, Start, Workspace},
    protocol::{random_token, token},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
pub fn create(root: &Path, args: CreateOptions, reuse: bool) -> Result<Job> {
    ensure!(root.is_absolute(), "terminal directory must be absolute");
    private(root)?;
    let value = crate::install(&root.join("runtimes"))?;
    let porthub_components::protocol::terminal::Value::Runtime {
        executable,
        terminfo,
        version,
    } = value
    else {
        anyhow::bail!("invalid runtime result")
    };
    let _guard = lock(root)?;
    if reuse {
        let name = args
            .name
            .as_deref()
            .context("reusing a workspace requires its name")?;
        name_valid(name)?;
        if let Some(job) = jobs(root)?.into_iter().find(|job| job.name == name) {
            if workspace(&job)?.is_alive() {
                return Ok(job);
            }
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
    }
    create_locked(
        root,
        args,
        porthub_terminal::runtime::Runtime {
            executable,
            terminfo,
            version,
        },
    )
}
fn read_private(path: &Path) -> Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= 16384,
        "invalid workspace registry file"
    );
    let mut bytes = vec![];
    file.take(16385).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16384, "workspace registry exceeds limit");
    Ok(bytes)
}
fn write_private(path: &Path, bytes: &[u8], _replace: bool) -> Result<()> {
    let parent = path
        .parent()
        .context("workspace registry requires parent")?;
    private(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
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
            let job: Job = serde_json::from_slice(&read_private(&path)?)?;
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

fn create_locked(
    root: &Path,
    args: CreateOptions,
    runtime: porthub_terminal::runtime::Runtime,
) -> Result<Job> {
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
    let cwd = args.cwd.canonicalize()?;
    let shell = args.shell;
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
    ws.start_with_environment(
        &Start {
            cwd,
            shell,
            command: args.command,
            environment,
            history_limit: args.history_limit,
            mouse: !args.no_mouse,
            prefix: args.prefix,
            cols: 100,
            rows: 30,
        },
        &args.inherited_environment,
    )?;
    if let Err(error) = write_private(
        &root.join(format!("{id}.json")),
        &serde_json::to_vec(&job)?,
        false,
    ) {
        let _ = ws.stop();
        return Err(error);
    }
    Ok(job)
}
