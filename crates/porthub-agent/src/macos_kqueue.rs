//! Single-filter macOS kernel event queues used by the private module.
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::Duration,
};
use tokio::io::{unix::AsyncFd, Interest};

pub(crate) fn register(event: libc::kevent) -> io::Result<AsyncFd<OwnedFd>> {
    // SAFETY: successful kqueue returns a uniquely owned descriptor.
    let raw = unsafe { libc::kqueue() };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let queue = unsafe { OwnedFd::from_raw_fd(raw) };
    // macOS kqueue has no atomic CLOEXEC creation flag.
    if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: one initialized change, no output array, and a live queue.
    if unsafe { libc::kevent(raw, &event, 1, std::ptr::null_mut(), 0, std::ptr::null()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    AsyncFd::with_interest(queue, Interest::READABLE)
}

pub(crate) async fn next_flags(queue: &AsyncFd<OwnedFd>) -> io::Result<u32> {
    queue
        .async_io(Interest::READABLE, |fd| {
            let mut event = std::mem::MaybeUninit::<libc::kevent>::uninit();
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: the single output slot is initialized when kevent returns one.
            let count = unsafe {
                libc::kevent(
                    fd.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    event.as_mut_ptr(),
                    1,
                    &timeout,
                )
            };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            if count == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let event = unsafe { event.assume_init() };
            if event.flags & libc::EV_ERROR != 0 {
                return Err(io::Error::from_raw_os_error(event.data as i32));
            }
            Ok(event.fflags)
        })
        .await
}

pub(crate) fn continuous_timer(delay: Duration) -> io::Result<AsyncFd<OwnedFd>> {
    let nanos = delay
        .as_nanos()
        .try_into()
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    register(libc::kevent {
        ident: 1,
        filter: libc::EVFILT_TIMER,
        flags: libc::EV_ADD | libc::EV_ONESHOT,
        fflags: libc::NOTE_NSECONDS | libc::NOTE_MACH_CONTINUOUS_TIME,
        data: nanos,
        udata: std::ptr::null_mut(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn continuous_retry_timer_is_readable_once_after_its_deadline() -> io::Result<()> {
        let delay = Duration::from_millis(60);
        let started = std::time::SystemTime::now();
        let timer = continuous_timer(delay)?;
        tokio::time::timeout(Duration::from_secs(2), next_flags(&timer)).await??;
        assert!(started.elapsed().unwrap() >= delay);
        assert!(
            tokio::time::timeout(Duration::from_millis(80), next_flags(&timer))
                .await
                .is_err()
        );
        Ok(())
    }
}
