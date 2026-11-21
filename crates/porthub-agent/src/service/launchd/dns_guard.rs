//! A boot-local launchd job for an already managed system registration. The
//! only launchd socket is a root-only Unix control socket, never an IP socket.
use super::{loaded_job_matches, marker, path, Launchd};
use crate::service::{self, Layout, Spec};
use anyhow::{ensure, Context, Result};
use std::path::{Path, PathBuf};

fn job(id: &str) -> Result<(String, PathBuf, PathBuf)> {
    ensure!(
        id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid DNS service identity"
    );
    let label = format!("porthub-dns-v1-{}", &id[..24]);
    let root = Path::new("/private/var/run");
    Ok((
        label.clone(),
        root.join(format!("{label}.plist")),
        root.join(format!("{label}.sock")),
    ))
}

fn contents(spec: &Spec) -> Result<String> {
    let (label, _, socket) = job(&spec.identity)?;
    Ok(format!("{}<plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>{}</string><string>private-dns-guard</string><string>{}</string></array><key>Sockets</key><dict><key>Control</key><dict><key>SockType</key><string>stream</string><key>SockPathName</key><string>{}</string><key>SockPathMode</key><integer>384</integer></dict></dict><key>Umask</key><integer>63</integer><key>ThrottleInterval</key><integer>1</integer><key>ProcessType</key><string>Background</string></dict></plist>\n",
        marker(&spec.identity),path(&spec.executable)?,spec.identity,path(&socket)?))
}

fn socket_identity(path: &Path) -> Result<Option<(u64, u64)>> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    match std::fs::symlink_metadata(path) {
        Ok(m) => {
            ensure!(
                m.uid() == 0 && m.file_type().is_socket() && m.mode() & 0o077 == 0,
                "unowned DNS socket node"
            );
            Ok(Some((m.dev() as u64, m.ino())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

async fn unlink_stopped_socket(path: &Path, expected: (u64, u64)) -> Result<()> {
    let Some(identity) = socket_identity(path)? else {
        return Ok(());
    };
    ensure!(
        identity == expected,
        "DNS control socket replaced during shutdown"
    );
    match tokio::net::UnixStream::connect(path).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
        _ => anyhow::bail!("another listener still owns the DNS control socket"),
    }
    ensure!(
        socket_identity(path)? == Some(expected),
        "DNS control socket changed before unlink"
    );
    std::fs::remove_file(path)?;
    Ok(())
}

async fn reconcile(spec: &Spec, wanted: bool) -> Result<Option<PathBuf>> {
    if spec.user {
        return Ok(None);
    }
    let (label, plist, socket) = job(&spec.identity)?;
    let expected = contents(spec)?;
    let previous = service::regular(&plist)?;
    if previous.is_none() && !wanted {
        return Ok(None);
    }
    ensure!(
        previous
            .as_ref()
            .is_none_or(|p| p.starts_with(marker(&spec.identity).as_bytes())),
        "DNS service plist has another owner"
    );
    let target = format!("system/{label}");
    let description = Launchd::command(&["print", &target]).await?;
    let file = plist.to_str().context("invalid DNS service path")?;
    let original = socket_identity(&socket)?;
    if description.status.success() {
        ensure!(
            previous.is_some() && loaded_job_matches(&String::from_utf8(description.stdout)?, file),
            "DNS job belongs to another service"
        );
        if wanted && previous.as_deref() == Some(expected.as_bytes()) {
            return Ok(Some(socket));
        }
        Launchd::checked(&["bootout", &target]).await?;
    } else {
        ensure!(
            description.status.code() == Some(113),
            "cannot inspect owned DNS service"
        );
    }
    if let Some(identity) = original {
        ensure!(
            previous.is_some(),
            "DNS control path already exists without an owned job"
        );
        unlink_stopped_socket(&socket, identity).await?;
    }
    if !wanted {
        if previous.is_some() {
            std::fs::remove_file(plist)?;
        }
        return Ok(None);
    }
    service::atomic(&plist, expected.as_bytes(), true)?;
    Launchd::checked(&["bootstrap", "system", file]).await?;
    Ok(Some(socket))
}

pub(crate) async fn registered_socket(
    profile: &Path,
    enrollment: &crate::private_profile::Profile,
) -> Result<Option<PathBuf>> {
    if !rustix::process::geteuid().is_root() {
        return Ok(None);
    }
    let layout = Layout::system()?;
    if profile.parent() != Some(layout.state.as_path()) {
        return Ok(None);
    }
    let meta = std::fs::symlink_metadata(&layout.state)?;
    ensure!(
        meta.is_dir() && service::trusted_directory(&layout.state, &meta),
        "untrusted private service state"
    );
    let standalone = service::RegistrationProfile::Private(enrollment.clone()).identity();
    let public = service::identity(&enrollment.control_profile());
    let manager = Launchd::connect(false).await?;
    for id in [&standalone, &public] {
        let Some(spec) = service::installed(&layout, id)? else {
            continue;
        };
        if !manager.owns_process(&spec, std::process::id()).await? {
            continue;
        }
        if id == &public {
            let public = crate::profile::Profile::load(&spec.profile)?;
            let module = crate::unified::load(&spec.profile, &public)?;
            if !module.is_some_and(|m| m.enabled && m.private_profile == profile) {
                continue;
            }
        } else if spec.profile != profile {
            continue;
        }
        return reconcile(&spec, true).await;
    }
    Ok(None)
}

pub(crate) async fn remove(spec: &Spec) -> Result<()> {
    reconcile(spec, false).await.map(|_| ())
}

pub(crate) fn socket(id: &str) -> Result<PathBuf> {
    Ok(job(id)?.2)
}

pub(crate) async fn authorized(id: &str, pid: u32) -> Result<bool> {
    job(id)?;
    let layout = Layout::system()?;
    let Some(spec) = service::installed(&layout, id)? else {
        return Ok(false);
    };
    Launchd::connect(false)
        .await?
        .owns_process(&spec, pid)
        .await
}
