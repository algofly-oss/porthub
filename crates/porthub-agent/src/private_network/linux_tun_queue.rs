//! Linux assigns each open TUN file a packet queue. Only a detached queue may
//! hold the interface between workers. The replacement always reads a fresh file.
use anyhow::{ensure, Context, Result};
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

fn attach(name: &str, flags: i32) -> Result<File> {
    ensure!(
        porthub_mesh::underlay::porthub_tun_name(name) && name.len() < libc::IFNAMSIZ,
        "invalid private TUN name"
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open("/dev/net/tun")
        .context("cannot open private TUN device")?;
    // ifreq contains a union. Zero all its bytes and copy the validated name
    // before setting the flags member required by TUNSETIFF.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *slot = byte as libc::c_char;
    }
    request.ifr_ifru.ifru_flags = flags as libc::c_short;
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
        return Err(std::io::Error::last_os_error()).context("private TUN attachment failed");
    }
    Ok(file)
}

pub(super) fn create(name: &str, restartable: bool) -> Result<File> {
    let flags = libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL;
    attach(
        name,
        if restartable {
            flags | libc::IFF_MULTI_QUEUE
        } else {
            flags
        },
    )
}

fn verify(file: &File, name: &str, index: u32, detached: bool) -> Result<()> {
    let mut info: libc::ifreq = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNGETIFF, &mut info) } == 0,
        "private queue no longer belongs to a TUN"
    );
    let flags = i32::from(unsafe { info.ifr_ifru.ifru_flags } as u16);
    let required = libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE;
    ensure!(
        flags & required == required
            && flags & (libc::IFF_TAP | libc::IFF_PERSIST) == 0
            && (flags & libc::IFF_DETACH_QUEUE != 0) == detached
            && info
                .ifr_name
                .iter()
                .map(|c| *c as u8)
                .take_while(|c| *c != 0)
                .eq(name.bytes()),
        "private queue configuration changed"
    );
    // TUNGETDEVNETNS returns a new owned descriptor. An identically named
    // interface in another namespace can have exactly the same numeric index.
    let fd = unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNGETDEVNETNS) };
    ensure!(fd >= 0, "could not establish private queue namespace");
    let namespace = unsafe { File::from_raw_fd(fd) }.metadata()?;
    let current = std::fs::metadata("/proc/thread-self/ns/net")?;
    ensure!(
        (namespace.dev(), namespace.ino()) == (current.dev(), current.ino()),
        "private queue belongs to another namespace"
    );
    let name = std::ffi::CString::new(name)?;
    ensure!(
        index != 0 && unsafe { libc::if_nametoindex(name.as_ptr()) } == index,
        "private queue interface changed"
    );
    Ok(())
}

pub(super) fn detach_anchor(active: &File, name: &str, index: u32) -> Result<File> {
    verify(active, name, index, false)?;
    let anchor = attach(
        name,
        libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE,
    )?;
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_ifru.ifru_flags = libc::IFF_DETACH_QUEUE as libc::c_short;
    ensure!(
        unsafe { libc::ioctl(anchor.as_raw_fd(), libc::TUNSETQUEUE, &mut request) } == 0,
        "could not detach private interface reference"
    );
    verify(active, name, index, false)?;
    verify(&anchor, name, index, true)?;
    Ok(anchor)
}

pub(super) fn resume(anchor: &File, name: &str, index: u32) -> Result<File> {
    verify(anchor, name, index, true)?;
    let active = attach(
        name,
        libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE,
    )?;
    verify(anchor, name, index, true)?;
    verify(&active, name, index, false)?;
    Ok(active)
}
