//! One versioned local handshake. Bound frames before allocating, and require
//! exactly the two expected descriptors with close-on-exec set.
use anyhow::{ensure, Context, Result};
use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};
use std::{
    fs::File,
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    path::Path,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, Interest},
    net::{UnixListener, UnixStream},
};

pub(super) async fn write(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= 60_000, "DNS guard message exceeds limit");
    stream.write_u16(bytes.len() as u16).await?;
    stream.write_all(bytes).await?;
    Ok(())
}

pub(super) async fn read(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let count = usize::from(stream.read_u16().await?);
    ensure!(count <= 60_000, "DNS guard message exceeds limit");
    let mut bytes = vec![0; count];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

pub(super) async fn send(stream: &UnixStream, pair: &(File, File)) -> Result<()> {
    stream
        .async_io(Interest::WRITABLE, || {
            let mut buffer = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
            let mut control = SendAncillaryBuffer::new(&mut buffer);
            let fds = [pair.0.as_fd(), pair.1.as_fd()];
            if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
                return Err(std::io::Error::other("invalid DNS descriptor buffer"));
            }
            let len = sendmsg(
                stream,
                &[IoSlice::new(b"1")],
                &mut control,
                SendFlags::empty(),
            )?;
            if len != 1 {
                return Err(std::io::Error::other("short DNS descriptor write"));
            }
            Ok(())
        })
        .await?;
    Ok(())
}

pub(super) async fn receive(stream: &UnixStream) -> Result<(File, File)> {
    let pair = stream
        .async_io(Interest::READABLE, || {
            let mut buffer = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
            let mut control = RecvAncillaryBuffer::new(&mut buffer);
            let mut mark = [0];
            let msg = recvmsg(
                stream,
                &mut [IoSliceMut::new(&mut mark)],
                &mut control,
                RecvFlags::empty(),
            )?;
            let fds: Vec<OwnedFd> = control
                .drain()
                .filter_map(|m| match m {
                    RecvAncillaryMessage::ScmRights(fds) => Some(fds),
                    _ => None,
                })
                .flatten()
                .collect();
            if mark != *b"1"
                || msg.bytes != 1
                || msg.flags.contains(ReturnFlags::CTRUNC)
                || fds.len() != 2
            {
                return Err(std::io::Error::other("invalid DNS descriptor response"));
            }
            for fd in &fds {
                rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::CLOEXEC)?;
            }
            let [udp, tcp]: [OwnedFd; 2] = fds.try_into().unwrap();
            if rustix::net::sockopt::socket_type(&udp)? != rustix::net::SocketType::DGRAM
                || rustix::net::sockopt::socket_type(&tcp)? != rustix::net::SocketType::STREAM
            {
                return Err(std::io::Error::other("unexpected DNS descriptor roles"));
            }
            Ok((File::from(udp), File::from(tcp)))
        })
        .await?;
    Ok(pair)
}

pub(super) fn peer_pid(stream: &UnixStream) -> Result<u32> {
    let (mut uid, mut gid) = (u32::MAX, u32::MAX);
    let mut pid = 0i32;
    let mut len = std::mem::size_of_val(&pid) as libc::socklen_t;
    ensure!(
        unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0 && uid == 0,
        "DNS guard peer must be root"
    );
    ensure!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut i32).cast(),
                &mut len,
            )
        } == 0
            && len as usize == std::mem::size_of_val(&pid)
            && pid > 0,
        "cannot identify DNS guard peer"
    );
    Ok(pid as u32)
}

pub(super) fn activated(path: &Path) -> Result<UnixListener> {
    unsafe extern "C" {
        fn launch_activate_socket(
            name: *const libc::c_char,
            fds: *mut *mut libc::c_int,
            count: *mut libc::size_t,
        ) -> libc::c_int;
    }
    let mut fds = std::ptr::null_mut();
    let mut count = 0;
    ensure!(
        unsafe { launch_activate_socket(c"Control".as_ptr(), &mut fds, &mut count) } == 0
            && !fds.is_null(),
        "missing DNS launchd control socket"
    );
    // launch_activate_socket transfers the descriptors and a malloc'd array to us.
    let mut owned: Vec<_> = unsafe { std::slice::from_raw_parts(fds, count) }
        .iter()
        .map(|fd| unsafe { OwnedFd::from_raw_fd(*fd) })
        .collect();
    unsafe {
        libc::free(fds.cast());
    }
    ensure!(owned.len() == 1, "unexpected launchd socket count");
    let listener = std::os::unix::net::UnixListener::from(owned.pop().unwrap());
    ensure!(
        listener.local_addr()?.as_pathname().is_some(),
        "unexpected launchd control socket"
    );
    // launchd binds Control in its private runtime directory and publishes a
    // second name at SockPathName. The accepted root service PID authenticates
    // the connection to that publicized, root-owned control node.
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(path).context("missing DNS control socket")?;
    ensure!(
        metadata.uid() == 0 && metadata.mode() & 0o077 == 0 && metadata.file_type().is_socket(),
        "unsafe DNS control socket permissions"
    );
    listener.set_nonblocking(true)?;
    rustix::io::fcntl_setfd(&listener, rustix::io::FdFlags::CLOEXEC)?;
    Ok(UnixListener::from_std(listener)?)
}

pub(super) async fn connect(path: &Path) -> Result<UnixStream> {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match UnixStream::connect(path).await {
                Ok(stream) => return Ok(stream),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await
    .context("launchd did not publish its control socket")?
}
