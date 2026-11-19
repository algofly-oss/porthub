//! One directory descriptor and one kqueue, irrespective of sibling files.
use crate::macos_kqueue;
use notify::{Config, Event, EventKind, RecursiveMode};
use std::{
    fs::OpenOptions,
    io,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
};
use tokio::task::JoinHandle;

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
        let queue = macos_kqueue::register(event)?;
        let path = path.to_owned();
        let mut handler = self
            .handler
            .take()
            .ok_or_else(|| io::Error::other("watcher already started"))?;
        self.task = Some(tokio::spawn(async move {
            // Retain the registered directory vnode for the task's lifetime.
            let _parent = parent;
            loop {
                match macos_kqueue::next_flags(&queue).await {
                    Ok(flags)
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
