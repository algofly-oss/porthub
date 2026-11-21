//! Kernel handles retained by the managed Linux service during a worker change.
use anyhow::{ensure, Context, Result};
use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{IoSlice, Read},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, BorrowedFd, FromRawFd},
        unix::net::{UnixDatagram, UnixStream},
    },
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock,
    },
    time::Duration,
};

const ROLES: [&str; 4] = ["ph-net1-tun", "ph-net1-state", "ph-net1-udp", "ph-net1-tcp"];
pub(super) struct Stored {
    pub anchor: File,
    pub state: File,
    pub udp: File,
    pub tcp: File,
}
static INHERITED: Mutex<Option<Stored>> = Mutex::new(None);
static MANAGER: OnceLock<PathBuf> = OnceLock::new();
static EXITING: AtomicBool = AtomicBool::new(false);

pub fn shutting_down() {
    EXITING.store(true, Ordering::Release);
}
pub(super) fn exiting() -> bool {
    EXITING.load(Ordering::Acquire)
}
pub(super) fn available() -> bool {
    MANAGER.get().is_some()
}
pub(super) fn take() -> Option<Stored> {
    INHERITED.lock().unwrap_or_else(|e| e.into_inner()).take()
}

/// A disabled enrollment or an unreachable control plane must not pin private
/// routes indefinitely. A freshly authorized worker takes the handles before
/// this timer, or starts cold after it. Only a process with inherited state
/// creates a timer.
pub fn bound_recovery_window(profile: Option<&std::path::Path>) -> Result<()> {
    if INHERITED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_none()
    {
        return Ok(());
    }
    let enabled = (|| -> Result<bool> {
        match profile {
            Some(path) if super::is_profile(path)? => Ok(true),
            Some(path) => Ok(
                crate::unified::load(path, &crate::profile::Profile::load(path)?)?
                    .is_some_and(|configuration| configuration.enabled),
            ),
            None => Ok(false),
        }
    })();
    match enabled {
        Ok(true) => {}
        Ok(false) => return clear(),
        Err(error) => {
            clear()?;
            return Err(error);
        }
    }
    tokio::spawn(async {
        crate::unified::suspend_aware_delay(Duration::from_secs(15)).await;
        let mut inherited = INHERITED.lock().unwrap_or_else(|e| e.into_inner());
        if inherited.take().is_some() {
            if let Err(error) = clear_manager() {
                tracing::warn!(%error,"private resource retirement pending");
            }
        }
    });
    Ok(())
}

/// Called once, before creating the async runtime or opening any files.
pub fn initialize() -> Result<()> {
    let Some(socket) = std::env::var_os("NOTIFY_SOCKET").map(PathBuf::from) else {
        return Ok(());
    };
    let uid = rustix::process::geteuid().as_raw();
    let expected = if uid == 0 {
        PathBuf::from("/run/systemd/notify")
    } else {
        PathBuf::from(format!("/run/user/{uid}/systemd/notify"))
    };
    // A caller can set NOTIFY_SOCKET. Never send a privileged network handle to
    // a caller-selected path. Unmanaged invocations keep the regular cold start.
    // Older managers support FDSTORE=1 without exporting the capacity.
    // Their generated service unit requests four slots just like newer ones.
    let capacity = std::env::var("FDSTORE").ok();
    if socket != expected
        || capacity
            .as_deref()
            .is_some_and(|n| n.parse::<u32>().unwrap_or(0) < 4)
        || (capacity.is_none() && std::env::var_os("INVOCATION_ID").is_none())
    {
        return Ok(());
    }
    let _ = MANAGER.set(socket);
    if std::env::var("LISTEN_PID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        != Some(std::process::id())
    {
        return Ok(());
    }
    let count: usize = std::env::var("LISTEN_FDS")?.parse()?;
    ensure!(
        count <= 1024,
        "invalid number of inherited service descriptors"
    );
    let names = std::env::var("LISTEN_FDNAMES").unwrap_or_default();
    let mut received = BTreeMap::new();
    let mut unique = true;
    let mut labels = names.split(':');
    for i in 0..count {
        let name = labels.next().unwrap_or("");
        let raw = 3 + i as i32;
        // Check the raw number before constructing any Rust owner. A malformed
        // activation environment can name a closed descriptor.
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
        ensure!(flags >= 0, "missing inherited service descriptor");
        ensure!(
            unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == 0,
            "could not protect inherited service descriptor"
        );
        if ROLES.contains(&name) {
            let file = unsafe { File::from_raw_fd(raw) };
            unique &= received.insert(name, file).is_none();
        }
    }
    if unique && received.len() == ROLES.len() {
        let stored = Stored {
            anchor: received.remove(ROLES[0]).unwrap(),
            state: received.remove(ROLES[1]).unwrap(),
            udp: received.remove(ROLES[2]).unwrap(),
            tcp: received.remove(ROLES[3]).unwrap(),
        };
        *INHERITED.lock().unwrap_or_else(|e| e.into_inner()) = Some(stored);
    } else if !received.is_empty() {
        clear()?;
    }
    Ok(())
}

fn notify(message: &str, fd: Option<BorrowedFd<'_>>) -> Result<()> {
    let path = MANAGER.get().context("no service descriptor store")?;
    let socket = UnixDatagram::unbound()?;
    socket.set_write_timeout(Some(Duration::from_millis(500)))?;
    socket.connect(path)?;
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let fds;
    if let Some(fd) = fd {
        fds = [fd];
        ensure!(
            control.push(SendAncillaryMessage::ScmRights(&fds)),
            "descriptor buffer too small"
        );
    }
    let size = sendmsg(
        &socket,
        &[IoSlice::new(message.as_bytes())],
        &mut control,
        SendFlags::empty(),
    )?;
    ensure!(size == message.len(), "short service-manager notification");
    Ok(())
}

pub(super) fn publish(handles: [BorrowedFd<'_>; 4]) -> Result<()> {
    for (role, fd) in ROLES.iter().zip(handles) {
        if let Err(error) = notify(&format!("FDSTORE=1\nFDNAME={role}"), Some(fd)) {
            let _ = clear();
            return Err(error);
        }
    }
    Ok(())
}

pub(super) fn clear() -> Result<()> {
    if !available() {
        return Ok(());
    }
    let mut inherited = INHERITED.lock().unwrap_or_else(|e| e.into_inner());
    drop(inherited.take());
    clear_manager()
}
fn clear_manager() -> Result<()> {
    for role in ROLES {
        notify(&format!("FDSTOREREMOVE=1\nFDNAME={role}"), None)?;
    }
    // Quarantine cannot acknowledge source removal while the manager still
    // owns its duplicate. BARRIER acknowledges all earlier notifications.
    let (mut reader, writer) = UnixStream::pair()?;
    reader.set_read_timeout(Some(Duration::from_secs(1)))?;
    notify("BARRIER=1", Some(writer.as_fd()))?;
    drop(writer);
    ensure!(
        reader.read(&mut [0])? == 0,
        "invalid descriptor store barrier"
    );
    Ok(())
}
