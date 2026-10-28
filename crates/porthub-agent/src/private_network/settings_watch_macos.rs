//! One directory descriptor and one kqueue, irrespective of sibling files.
use notify::{Config, Event, EventKind, RecursiveMode};
use std::{
    fs::OpenOptions,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
};
use tokio::{
    io::{unix::AsyncFd, Interest},
    task::JoinHandle,
};

type Handler = Box<dyn FnMut(notify::Result<Event>) + Send>;

pub(super) struct DirectoryWatcher {
    handler: Option<Handler>,
    task: Option<JoinHandle<()>>,
}
impl DirectoryWatcher {
    pub(super) fn new(
        handler: impl FnMut(notify::Result<Event>) + Send + 'static,
        _: Config,
    ) -> notify::Result<Self> {
        Ok(Self {
            handler: Some(Box::new(handler)),
            task: None,
        })
    }
    pub(super) fn watch(&mut self, path: &Path, mode: RecursiveMode) -> notify::Result<()> {
        if mode != RecursiveMode::NonRecursive || self.task.is_some() {
            return Err(notify::Error::generic(
                "preference watcher accepts one directory",
            ));
        }
        self.start(path).map_err(notify::Error::io)
    }
    fn start(&mut self, path: &Path) -> io::Result<()> {
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_EVTONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        if !parent.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "preference parent is not a directory",
            ));
        }
        // SAFETY: successful kqueue returns a uniquely owned descriptor.
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let queue = unsafe { OwnedFd::from_raw_fd(raw) };
        // macOS kqueue has no atomic CLOEXEC creation flag.
        if unsafe { libc::fcntl(queue.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let event = libc::kevent {
            ident: parent.as_raw_fd() as usize,
            filter: libc::EVFILT_VNODE,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags: libc::NOTE_WRITE
                | libc::NOTE_EXTEND
                | libc::NOTE_ATTRIB
                | libc::NOTE_DELETE
                | libc::NOTE_RENAME
                | libc::NOTE_REVOKE,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // Register only this directory. Never enumerate or watch its children.
        if unsafe {
            libc::kevent(
                queue.as_raw_fd(),
                &event,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let queue = AsyncFd::with_interest(queue, Interest::READABLE)?;
        let path = path.to_owned();
        let mut handler = self
            .handler
            .take()
            .ok_or_else(|| io::Error::other("watcher already started"))?;
        self.task = Some(tokio::spawn(async move {
            // Retain the registered directory vnode for the task's lifetime.
            let _parent = parent;
            loop {
                let result = async {
                    let mut ready = queue.readable().await?;
                    match ready.try_io(|queue| {
                        // SAFETY: output is initialized by kevent when it returns 1.
                        let mut event: libc::kevent = unsafe { std::mem::zeroed() };
                        let timeout = libc::timespec {
                            tv_sec: 0,
                            tv_nsec: 0,
                        };
                        let count = unsafe {
                            libc::kevent(
                                queue.as_raw_fd(),
                                std::ptr::null(),
                                0,
                                &mut event,
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
                        if event.flags & libc::EV_ERROR != 0 {
                            return Err(io::Error::from_raw_os_error(event.data as i32));
                        }
                        Ok(event.fflags)
                    }) {
                        Ok(result) => result.map(Some),
                        Err(_) => Ok(None),
                    }
                }
                .await;
                match result {
                    Ok(None) => continue,
                    Ok(Some(flags))
                        if flags & (libc::NOTE_DELETE | libc::NOTE_RENAME | libc::NOTE_REVOKE)
                            == 0 =>
                    {
                        handler(Ok(Event::new(EventKind::Modify(
                            notify::event::ModifyKind::Any,
                        ))
                        .add_path(path.clone())));
                    }
                    Ok(_) => {
                        handler(Err(notify::Error::generic("preference directory replaced")));
                        break;
                    }
                    Err(error) => {
                        handler(Err(notify::Error::io(error)));
                        break;
                    }
                }
            }
        }));
        Ok(())
    }
}
impl Drop for DirectoryWatcher {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
