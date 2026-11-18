//! Refresh an existing managed GUI worker after the native transaction commits.
//! Never installs/enables a unit, changes enrollment, or touches another user's unit.
use super::desktop::{desktop_entry, unit, UNIT};
use crate::service::{self, Layout};
use anyhow::{ensure, Context, Result};
use std::{
    collections::BTreeSet,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

fn ancestors(path: &Path) -> Result<()> {
    for parent in path.ancestors().skip(1) {
        let m = std::fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir()
                && (m.uid() == 0 || m.uid() == rustix::process::geteuid().as_raw())
                && (m.mode() & 0o022 == 0 || m.uid() == 0 && m.mode() & 0o1000 != 0),
            "Unsafe desktop startup directory {} (uid {}, mode {:o})",
            parent.display(),
            m.uid(),
            m.mode()
        );
    }
    Ok(())
}
fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    let m = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    ancestors(path)?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == rustix::process::geteuid().as_raw()
            && m.mode() & 0o022 == 0
            && m.len() <= 16384,
        "Desktop startup file is not securely owned"
    );
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let actual = f.metadata()?;
    ensure!(
        actual.dev() == m.dev() && actual.ino() == m.ino(),
        "Desktop startup file changed"
    );
    let mut bytes = Vec::new();
    f.take(16385).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16384, "Desktop startup file exceeds limit");
    Ok(Some(bytes))
}
fn executable(bytes: &[u8], user: bool) -> Result<PathBuf> {
    let text = std::str::from_utf8(bytes)?;
    let line = text
        .lines()
        .find_map(|line| line.strip_prefix("ExecStart=\""))
        .context("Desktop executable missing")?;
    let suffix = if user {
        "\" keyboard run --user"
    } else {
        "\" keyboard run"
    };
    let encoded = line
        .strip_suffix(suffix)
        .context("Desktop arguments are customized")?;
    let mut chars = encoded.chars();
    let mut decoded = String::new();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let next = chars.next().context("Incomplete desktop escape")?;
                ensure!(matches!(next, '\\' | '"'), "Invalid desktop escape");
                decoded.push(next)
            }
            '$' | '%' => {
                ensure!(chars.next() == Some(c), "Invalid desktop expansion");
                decoded.push(c)
            }
            _ => decoded.push(c),
        }
    }
    let path = PathBuf::from(decoded);
    ensure!(
        path.is_absolute() && unit(&path, user)?.as_bytes() == bytes,
        "Customized desktop unit is preserved"
    );
    Ok(path)
}
#[derive(Clone, Debug)]
struct Session {
    uid: u32,
    machine: Option<String>,
    fragment: PathBuf,
    dropins: String,
    state: String,
    enabled: String,
    pid: u32,
}
impl Session {
    fn active_owned(&self, path: &Path) -> bool {
        self.fragment == path
            && self.dropins.is_empty()
            && self.state == "active"
            && matches!(
                self.enabled.as_str(),
                "enabled" | "enabled-runtime" | "linked" | "linked-runtime"
            )
            && self.pid > 0
    }
}
#[async_trait::async_trait]
trait Manager: Sync {
    async fn sessions(&self, uids: &BTreeSet<u32>) -> Result<Vec<Session>>;
    async fn command(&self, session: &Session, verb: &str) -> Result<()>;
    fn process(&self, session: &Session) -> Result<PathBuf>;
}
struct Native;
async fn output(program: &str, args: &[String]) -> Result<String> {
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        tokio::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("Desktop manager timed out")??;
    ensure!(
        out.status.success() && out.stdout.len() <= 65536,
        "Desktop manager command failed"
    );
    Ok(String::from_utf8(out.stdout)?)
}
fn args(machine: Option<&str>, verb: &str) -> Vec<String> {
    let mut a = vec!["--user".into()];
    if let Some(m) = machine {
        a.extend(["--machine".into(), m.into()]);
    }
    a.push(verb.into());
    if verb != "daemon-reload" {
        a.push(UNIT.into());
    }
    a
}
#[async_trait::async_trait]
impl Manager for Native {
    async fn sessions(&self, uids: &BTreeSet<u32>) -> Result<Vec<Session>> {
        let machines = if rustix::process::geteuid().is_root() {
            output(
                "loginctl",
                &[
                    "list-users".into(),
                    "--no-legend".into(),
                    "--no-pager".into(),
                ],
            )
            .await?
            .lines()
            .filter_map(|line| {
                let mut words = line.split_whitespace();
                let uid = words.next()?.parse::<u32>().ok()?;
                let name = words.next()?;
                if !uids.contains(&uid)
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                {
                    return None;
                }
                Some((uid, Some(format!("{name}@.host"))))
            })
            .collect::<Vec<_>>()
        } else {
            vec![(rustix::process::geteuid().as_raw(), None)]
        };
        let mut sessions = Vec::new();
        for (uid, machine) in machines {
            let mut a = args(machine.as_deref(), "show");
            a.extend([
                "--no-pager".into(),
                "--property=FragmentPath,DropInPaths,ActiveState,UnitFileState,MainPID".into(),
            ]);
            let Ok(text) = output("systemctl", &a).await else {
                continue;
            };
            let property = |key: &str| {
                text.lines()
                    .find_map(|l| l.strip_prefix(&format!("{key}=")))
                    .unwrap_or("")
                    .to_owned()
            };
            sessions.push(Session {
                uid,
                machine,
                fragment: property("FragmentPath").into(),
                dropins: property("DropInPaths"),
                state: property("ActiveState"),
                enabled: property("UnitFileState"),
                pid: property("MainPID").parse().unwrap_or(0),
            });
        }
        Ok(sessions)
    }
    async fn command(&self, s: &Session, verb: &str) -> Result<()> {
        output("systemctl", &args(s.machine.as_deref(), verb))
            .await
            .map(|_| ())
    }
    fn process(&self, s: &Session) -> Result<PathBuf> {
        let root = PathBuf::from(format!("/proc/{}", s.pid));
        ensure!(
            std::fs::metadata(&root)?.uid() == s.uid,
            "Desktop process session owner changed"
        );
        let mut command = Vec::new();
        std::fs::File::open(root.join("cmdline"))?
            .take(16385)
            .read_to_end(&mut command)?;
        ensure!(
            command.len() <= 16384 && keyboard_arguments(&command),
            "Desktop process is not the expected keyboard worker"
        );
        Ok(std::fs::read_link(root.join("exe"))?)
    }
}
fn keyboard_arguments(bytes: &[u8]) -> bool {
    if !bytes.ends_with(&[0]) {
        return false;
    }
    let args = bytes[..bytes.len() - 1]
        .split(|byte| *byte == 0)
        .collect::<Vec<_>>();
    let Some(first) = args.first() else {
        return false;
    };
    use std::os::unix::ffi::OsStrExt;
    let path = Path::new(std::ffi::OsStr::from_bytes(first));
    path.is_absolute()
        && path.file_name().is_some_and(|name| name == "porthub")
        && (args[1..] == [b"keyboard".as_slice(), b"run".as_slice()]
            || args[1..]
                == [
                    b"keyboard".as_slice(),
                    b"run".as_slice(),
                    b"--user".as_slice(),
                ])
}
async fn refresh_at(
    layout: &Layout,
    new: &Path,
    config: &Path,
    cli: Option<&Path>,
    uids: &BTreeSet<u32>,
    manager: &impl Manager,
) -> Result<()> {
    let path = config.join("systemd/user").join(UNIT);
    let Some(before) = read(&path)? else {
        return Ok(());
    };
    let old = executable(&before, layout.user)?;
    // Both old and new must be checksum-verified immutable releases, never a
    // mutable global CLI or an arbitrary similarly-prefixed path.
    ancestors(&old)?;
    ancestors(new)?;
    if cli == Some(old.as_path()) {
        ensure!(
            service::publication::managed_link(layout, &old)? == new,
            "Published desktop CLI changed after update"
        );
    } else {
        service::publication::owned_target(layout, &old)?;
    }
    service::publication::owned_target(layout, new)?;
    let autostart = config
        .join(if layout.user {
            "autostart"
        } else {
            "xdg/autostart"
        })
        .join("porthub-keyboard.desktop");
    let startup = read(&autostart)?;
    if let Some(bytes) = &startup {
        ensure!(
            *bytes == desktop_entry(&old, layout.user)?.as_bytes()
                || *bytes == desktop_entry(new, layout.user)?.as_bytes(),
            "Customized desktop autostart is preserved"
        );
    }
    let sessions = manager.sessions(uids).await?;
    let mut active = Vec::new();
    for session in sessions.into_iter().filter(|s| s.active_owned(&path)) {
        let process = manager.process(&session)?;
        ancestors(&process)?;
        service::publication::owned_target(layout, &process)?;
        if process != new {
            active.push(session)
        }
    }
    let after = unit(new, layout.user)?.into_bytes();
    let next_startup = desktop_entry(new, layout.user)?.into_bytes();
    let changed = before != after || startup.as_ref().is_some_and(|s| *s != next_startup);
    if !changed && active.is_empty() {
        return Ok(());
    }
    let result: Result<()> = async {
        ensure!(
            read(&path)?.as_ref() == Some(&before) && read(&autostart)? == startup,
            "Desktop startup changed during upgrade"
        );
        service::atomic(&path, &after, false)?;
        if startup.is_some() {
            service::atomic(&autostart, &next_startup, false)?;
        }
        for session in &active {
            manager.command(session, "daemon-reload").await?;
            manager.command(session, "restart").await?;
            let current = manager
                .sessions(uids)
                .await?
                .into_iter()
                .find(|s| s.machine == session.machine && s.uid == session.uid)
                .context("Desktop session disappeared during refresh")?;
            ensure!(
                current.active_owned(&path) && manager.process(&current)? == new,
                "Desktop worker did not advance to the new release"
            );
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        // Restore only our exact just-written bytes. Never clobber an intervening edit.
        ensure!(
            read(&path)?.as_ref() == Some(&after) || read(&path)?.as_ref() == Some(&before),
            "Desktop refresh failed and startup was externally changed: {error}"
        );
        service::atomic(&path, &before, false)?;
        if let Some(bytes) = &startup {
            ensure!(
                read(&autostart)?.as_ref() == Some(&next_startup)
                    || read(&autostart)?.as_ref() == Some(bytes),
                "Desktop autostart changed during recovery"
            );
            service::atomic(&autostart, bytes, false)?;
        }
        for session in &active {
            manager
                .command(session, "daemon-reload")
                .await
                .context("Desktop rollback reload failed")?;
            manager
                .command(session, "restart")
                .await
                .context("Desktop rollback restart failed")?;
        }
        return Err(
            error.context("Managed desktop worker refresh failed; previous startup restored")
        );
    }
    Ok(())
}
// A historical installer emitted this exact user-owned unit. Its dynamic CLI
// already points at the committed release, so preserve every byte and permission.
fn legacy_unit(cli: &Path) -> Result<Vec<u8>> {
    let text = cli.to_str().context("Invalid legacy CLI path")?;
    ensure!(
        text.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b)),
        "Legacy CLI quoting is unsupported"
    );
    Ok(unit(cli, false)?
        .replace(
            &format!("ExecStart=\"{text}\" keyboard run"),
            &format!("ExecStart={text} keyboard run"),
        )
        .into_bytes())
}
fn legacy_read(path: &Path, uid: u32) -> Result<Vec<u8>> {
    let mut private = false;
    for parent in path.ancestors().skip(1) {
        let m = std::fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir()
                && (m.uid() == 0 || m.uid() == uid)
                && (m.mode() & 0o022 == 0 || m.uid() == 0 && m.mode() & 0o1000 != 0),
            "Unsafe legacy desktop directory"
        );
        private |= m.uid() == uid && m.mode() & 0o077 == 0;
    }
    ensure!(
        private,
        "Legacy desktop requires a private owner-only ancestor"
    );
    let m = std::fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.uid() == uid
            && m.nlink() == 1
            && m.mode() & 0o002 == 0
            && m.len() <= 16384,
        "Legacy desktop ownership is unsafe"
    );
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let actual = f.metadata()?;
    ensure!(
        actual.dev() == m.dev() && actual.ino() == m.ino(),
        "Legacy desktop unit changed"
    );
    let mut bytes = Vec::new();
    f.take(16385).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16384, "Legacy unit exceeds limit");
    Ok(bytes)
}
fn home(uid: u32) -> Result<PathBuf> {
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = vec![0u8; 65536];
    let mut result = std::ptr::null_mut();
    // SAFETY: storage remains alive while copying the returned account home.
    ensure!(
        unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        } == 0
            && !result.is_null(),
        "Desktop account is unavailable"
    );
    let entry = unsafe { entry.assume_init() };
    ensure!(
        entry.pw_uid == uid && !entry.pw_dir.is_null(),
        "Desktop account changed"
    );
    use std::os::unix::ffi::OsStrExt;
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(
        unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }.to_bytes(),
    ));
    ensure!(path.is_absolute(), "Desktop account home is not absolute");
    Ok(path)
}
async fn legacy_session(
    layout: &Layout,
    new: &Path,
    cli: &Path,
    session: &Session,
    expected: &Path,
    uids: &BTreeSet<u32>,
    manager: &impl Manager,
) -> Result<()> {
    if !uids.contains(&session.uid) || !session.active_owned(expected) {
        return Ok(());
    }
    let before = legacy_read(expected, session.uid)?;
    if before != legacy_unit(cli)? {
        return Ok(());
    }
    ancestors(cli)?;
    ensure!(
        service::publication::managed_link(layout, cli)? == new,
        "Legacy desktop CLI changed after update"
    );
    let process = manager.process(session)?;
    ancestors(&process)?;
    service::publication::owned_target(layout, &process)?;
    if process == new {
        return Ok(());
    }
    ensure!(
        legacy_read(expected, session.uid)? == before,
        "Legacy desktop startup changed during refresh"
    );
    manager.command(session, "daemon-reload").await?;
    manager.command(session, "restart").await?;
    let current = manager
        .sessions(uids)
        .await?
        .into_iter()
        .find(|s| s.machine == session.machine && s.uid == session.uid)
        .context("Legacy desktop session disappeared")?;
    ensure!(
        current.active_owned(expected)
            && legacy_read(expected, session.uid)? == before
            && manager.process(&current)? == new,
        "Legacy desktop worker did not advance; startup file preserved"
    );
    Ok(())
}
pub(super) async fn refresh(
    layout: &Layout,
    new: &Path,
    profiles: &[PathBuf],
    cli: Option<&Path>,
) -> Result<()> {
    let mut uids = BTreeSet::new();
    if layout.user {
        uids.insert(rustix::process::geteuid().as_raw());
    } else {
        let users = output(
            "loginctl",
            &[
                "list-users".into(),
                "--no-legend".into(),
                "--no-pager".into(),
            ],
        )
        .await?;
        for line in users.lines() {
            if let Some(uid) = line
                .split_whitespace()
                .next()
                .and_then(|uid| uid.parse::<u32>().ok())
            {
                if uid != 0
                    && profiles
                        .iter()
                        .any(|profile| crate::exposure_broker::authorized(uid, profile))
                {
                    uids.insert(uid);
                }
            }
        }
    }
    let config = if layout.user {
        directories::BaseDirs::new()
            .context("No desktop configuration directory")?
            .config_dir()
            .to_owned()
    } else {
        ensure!(
            rustix::process::geteuid().is_root(),
            "Desktop refresh requires the service owner"
        );
        PathBuf::from("/etc")
    };
    let mut managed = refresh_at(layout, new, &config, cli, &uids, &Native).await;
    // Keep checking independent approved user units even when an unrelated global
    // customization makes the global refresh conservatively refuse mutation.
    if !layout.user {
        if let Some(cli) = cli {
            for session in Native.sessions(&uids).await? {
                let expected = home(session.uid)?.join(".config/systemd/user").join(UNIT);
                if let Err(error) =
                    legacy_session(layout, new, cli, &session, &expected, &uids, &Native).await
                {
                    tracing::warn!(uid=session.uid,reason=%error,"Managed user desktop worker refresh incomplete");
                    if managed.is_ok() {
                        managed = Err(error);
                    }
                }
            }
        }
    }
    managed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    };
    struct Fake {
        sessions: Mutex<Vec<Session>>,
        processes: Mutex<std::collections::BTreeMap<u32, PathBuf>>,
        commands: Mutex<Vec<String>>,
        fail: AtomicBool,
        unit: PathBuf,
        restart_target: Option<PathBuf>,
    }
    #[async_trait::async_trait]
    impl Manager for Fake {
        async fn sessions(&self, uids: &BTreeSet<u32>) -> Result<Vec<Session>> {
            Ok(self
                .sessions
                .lock()
                .unwrap()
                .iter()
                .filter(|s| uids.contains(&s.uid))
                .cloned()
                .collect())
        }
        async fn command(&self, s: &Session, verb: &str) -> Result<()> {
            self.commands
                .lock()
                .unwrap()
                .push(format!("{}:{verb}", s.pid));
            if verb == "restart" {
                if self.fail.swap(false, Ordering::SeqCst) {
                    anyhow::bail!("fixture restart failure");
                }
                let path = if let Some(path) = &self.restart_target {
                    path.clone()
                } else {
                    executable(&std::fs::read(&self.unit)?, true)?
                };
                self.processes.lock().unwrap().insert(s.pid, path);
            }
            Ok(())
        }
        fn process(&self, s: &Session) -> Result<PathBuf> {
            self.processes
                .lock()
                .unwrap()
                .get(&s.pid)
                .cloned()
                .context("Fixture process missing")
        }
    }
    struct Fixture {
        _root: tempfile::TempDir,
        layout: Layout,
        config: PathBuf,
        old: PathBuf,
        new: PathBuf,
        path: PathBuf,
        startup: PathBuf,
        uids: BTreeSet<u32>,
        manager: Fake,
    }
    impl Fixture {
        fn new() -> Self {
            Self::under(&std::env::temp_dir())
        }
        fn under(parent: &Path) -> Self {
            let root = tempfile::tempdir_in(parent).unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let config = root.path().join("config");
            let releases = root.path().join("releases");
            for name in ["state", "units"] {
                let path = root.path().join(name);
                std::fs::create_dir(&path).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            std::fs::create_dir(&releases).unwrap();
            let release = |bytes: &[u8]| {
                use sha2::Digest;
                let hash = format!("{:x}", sha2::Sha256::digest(bytes));
                let dir = releases.join(hash);
                std::fs::create_dir(&dir).unwrap();
                let path = dir.join("porthub");
                std::fs::write(&path, bytes).unwrap();
                path
            };
            let old = release(b"old-owned-release");
            let new = release(b"new-owned-release");
            let path = config.join("systemd/user").join(UNIT);
            let startup = config.join("autostart/porthub-keyboard.desktop");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::create_dir_all(startup.parent().unwrap()).unwrap();
            std::fs::write(&path, unit(&old, true).unwrap()).unwrap();
            std::fs::write(&startup, desktop_entry(&old, true).unwrap()).unwrap();
            for entry in [
                releases.clone(),
                old.parent().unwrap().to_owned(),
                new.parent().unwrap().to_owned(),
                config.clone(),
                config.join("systemd"),
                config.join("systemd/user"),
                config.join("autostart"),
            ] {
                std::fs::set_permissions(entry, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            for file in [&old, &new, &path, &startup] {
                std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            let uid = rustix::process::geteuid().as_raw();
            let session = Session {
                uid,
                machine: None,
                fragment: path.clone(),
                dropins: String::new(),
                state: "active".into(),
                enabled: "enabled".into(),
                pid: 123,
            };
            let manager = Fake {
                sessions: Mutex::new(vec![session]),
                processes: Mutex::new([(123, old.clone())].into()),
                commands: Mutex::default(),
                fail: AtomicBool::new(false),
                unit: path.clone(),
                restart_target: None,
            };
            Self {
                layout: Layout {
                    user: true,
                    state: root.path().join("state"),
                    releases,
                    units: root.path().join("units"),
                },
                _root: root,
                config,
                old,
                new,
                path,
                startup,
                uids: [uid].into(),
                manager,
            }
        }
        async fn run(&self) -> Result<()> {
            refresh_at(
                &self.layout,
                &self.new,
                &self.config,
                None,
                &self.uids,
                &self.manager,
            )
            .await
        }
    }
    #[tokio::test]
    async fn old_verified_release_advances_once_and_keeps_enrollment_untouched() {
        let f = Fixture::new();
        let marker = f.config.join("local-policy");
        std::fs::write(&marker, b"keyboard=false;media=true").unwrap();
        f.run().await.unwrap();
        assert_eq!(
            std::fs::read(&f.path).unwrap(),
            unit(&f.new, true).unwrap().as_bytes()
        );
        assert_eq!(
            std::fs::read(&f.startup).unwrap(),
            desktop_entry(&f.new, true).unwrap().as_bytes()
        );
        assert_eq!(
            &*f.manager.commands.lock().unwrap(),
            &["123:daemon-reload", "123:restart"]
        );
        f.run().await.unwrap();
        assert_eq!(f.manager.commands.lock().unwrap().len(), 2);
        assert_eq!(std::fs::read(marker).unwrap(), b"keyboard=false;media=true");
    }
    #[tokio::test]
    async fn restart_failure_restores_old_files_and_worker() {
        let f = Fixture::new();
        f.manager.fail.store(true, Ordering::SeqCst);
        assert!(f
            .run()
            .await
            .unwrap_err()
            .to_string()
            .contains("previous startup restored"));
        assert_eq!(
            std::fs::read(&f.path).unwrap(),
            unit(&f.old, true).unwrap().as_bytes()
        );
        assert_eq!(
            std::fs::read(&f.startup).unwrap(),
            desktop_entry(&f.old, true).unwrap().as_bytes()
        );
        assert_eq!(f.manager.processes.lock().unwrap()[&123], f.old);
        assert_eq!(f.manager.commands.lock().unwrap().len(), 4);
    }
    #[tokio::test]
    async fn inactive_disabled_masked_dropins_and_other_users_are_never_restarted() {
        for kind in [
            "inactive",
            "disabled",
            "masked",
            "dropin",
            "foreign-fragment",
            "other-user",
        ] {
            let f = Fixture::new();
            {
                let mut sessions = f.manager.sessions.lock().unwrap();
                let s = &mut sessions[0];
                match kind {
                    "inactive" => s.state = "inactive".into(),
                    "disabled" | "masked" => s.enabled = kind.into(),
                    "dropin" => s.dropins = "/home/user/custom.conf".into(),
                    "foreign-fragment" => s.fragment = PathBuf::from("/home/user/custom.service"),
                    _ => s.uid = s.uid.wrapping_add(1),
                }
            }
            f.run().await.unwrap();
            assert!(f.manager.commands.lock().unwrap().is_empty(), "{kind}");
        }
    }
    #[tokio::test]
    async fn custom_files_symlinks_and_corrupted_releases_are_preserved() {
        for kind in [
            "custom-unit",
            "custom-autostart",
            "symlink-unit",
            "corrupt-release",
        ] {
            let f = Fixture::new();
            match kind {
                "custom-unit" => {
                    std::fs::write(&f.path, b"[Service]\nExecStart=/bin/true\n").unwrap()
                }
                "custom-autostart" => std::fs::write(&f.startup, b"custom user startup").unwrap(),
                "symlink-unit" => {
                    std::fs::remove_file(&f.path).unwrap();
                    std::os::unix::fs::symlink("/dev/null", &f.path).unwrap()
                }
                _ => std::fs::write(&f.old, b"corrupt").unwrap(),
            };
            let before = std::fs::read(&f.path).unwrap();
            assert!(f.run().await.is_err(), "{kind}");
            assert_eq!(std::fs::read(&f.path).unwrap(), before);
            assert!(f.manager.commands.lock().unwrap().is_empty());
        }
    }
    #[tokio::test]
    async fn published_cli_requires_exact_verified_publication_path() {
        let f = Fixture::new();
        let cli = f.config.join("porthub");
        std::os::unix::fs::symlink(&f.new, &cli).unwrap();
        std::fs::write(&f.path, unit(&cli, true).unwrap()).unwrap();
        std::fs::write(&f.startup, desktop_entry(&cli, true).unwrap()).unwrap();
        assert!(f.run().await.is_err());
        refresh_at(
            &f.layout,
            &f.new,
            &f.config,
            Some(&cli),
            &f.uids,
            &f.manager,
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read(&f.path).unwrap(),
            unit(&f.new, true).unwrap().as_bytes()
        );
    }
    #[test]
    fn exact_unit_parser_roundtrips_and_rejects_extra_directives() {
        let path = Path::new("/tmp/Port Hub/$a%/porthub");
        let content = unit(path, true).unwrap();
        assert_eq!(executable(content.as_bytes(), true).unwrap(), path);
        assert!(executable(format!("{content}Environment=EVIL=true\n").as_bytes(), true).is_err());
        assert!(executable(content.as_bytes(), false).is_err());
    }
    #[tokio::test]
    async fn legacy_private_user_unit_restarts_from_published_cli_without_changing_any_file_metadata(
    ) {
        let mut f = Fixture::new();
        let cli = f.config.join("porthub");
        std::os::unix::fs::symlink(&f.new, &cli).unwrap();
        std::fs::set_permissions(&f.config, std::fs::Permissions::from_mode(0o700)).unwrap();
        let bytes = legacy_unit(&cli).unwrap();
        std::fs::write(&f.path, &bytes).unwrap();
        std::fs::set_permissions(&f.path, std::fs::Permissions::from_mode(0o664)).unwrap();
        f.manager.restart_target = Some(f.new.clone());
        let session = f.manager.sessions.lock().unwrap()[0].clone();
        let before = std::fs::metadata(&f.path).unwrap();
        legacy_session(
            &f.layout, &f.new, &cli, &session, &f.path, &f.uids, &f.manager,
        )
        .await
        .unwrap();
        let after = std::fs::metadata(&f.path).unwrap();
        assert_eq!(
            (before.uid(), before.gid(), before.mode(), before.ino()),
            (after.uid(), after.gid(), after.mode(), after.ino())
        );
        assert_eq!(std::fs::read(&f.path).unwrap(), bytes);
        assert_eq!(f.manager.processes.lock().unwrap()[&123], f.new);
        legacy_session(
            &f.layout, &f.new, &cli, &session, &f.path, &f.uids, &f.manager,
        )
        .await
        .unwrap();
        assert_eq!(f.manager.commands.lock().unwrap().len(), 2);
    }
    #[tokio::test]
    async fn legacy_rejects_missing_private_ancestor_and_untrusted_cli_without_restarting() {
        for kind in [
            "public-path",
            "foreign-cli",
            "custom-unit",
            "disabled",
            "other-user",
        ] {
            // The public-path case needs a shared ancestor even when the runner has a private TMPDIR.
            let mut f = if kind == "public-path" {
                Fixture::under(Path::new("/tmp"))
            } else {
                Fixture::new()
            };
            let cli = f.config.join("porthub");
            std::os::unix::fs::symlink(&f.new, &cli).unwrap();
            std::fs::write(&f.path, legacy_unit(&cli).unwrap()).unwrap();
            f.manager.restart_target = Some(f.new.clone());
            let mut session = f.manager.sessions.lock().unwrap()[0].clone();
            match kind {
                "public-path" => {
                    std::fs::set_permissions(f._root.path(), std::fs::Permissions::from_mode(0o755))
                        .unwrap()
                }
                "foreign-cli" => {
                    std::fs::remove_file(&cli).unwrap();
                    std::os::unix::fs::symlink("/bin/true", &cli).unwrap()
                }
                "custom-unit" => {
                    let mut bytes = legacy_unit(&cli).unwrap();
                    bytes.extend_from_slice(b"Environment=USER_CUSTOM=1\n");
                    std::fs::write(&f.path, bytes).unwrap()
                }
                "disabled" => session.enabled = "disabled".into(),
                _ => session.uid = session.uid.wrapping_add(1),
            };
            let before = std::fs::read(&f.path).unwrap();
            let result = legacy_session(
                &f.layout, &f.new, &cli, &session, &f.path, &f.uids, &f.manager,
            )
            .await;
            if matches!(kind, "public-path" | "foreign-cli") {
                assert!(result.is_err(), "{kind}");
            } else {
                result.unwrap();
            }
            assert_eq!(std::fs::read(&f.path).unwrap(), before);
            assert!(f.manager.commands.lock().unwrap().is_empty(), "{kind}");
        }
    }
    #[test]
    fn process_arguments_require_keyboard_worker_and_no_unapproved_flags() {
        assert!(keyboard_arguments(
            b"/usr/local/bin/porthub\0keyboard\0run\0"
        ));
        assert!(keyboard_arguments(
            b"/opt/releases/abc/porthub\0keyboard\0run\0--user\0"
        ));
        for args in [
            b"/usr/local/bin/porthub\0agent\0".as_slice(),
            b"/usr/local/bin/porthub\0keyboard\0run\0--registration\0other\0".as_slice(),
            b"porthub\0keyboard\0run\0".as_slice(),
        ] {
            assert!(!keyboard_arguments(args));
        }
    }
}
