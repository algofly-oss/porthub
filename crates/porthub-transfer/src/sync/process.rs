//! Launch a worker without leaving terminal or pipe handles in the child.
use anyhow::{Context, Result};

pub(super) struct Child {
    #[cfg(unix)]
    inner: std::process::Child,
    #[cfg(windows)]
    handle: std::os::windows::io::OwnedHandle,
}

pub(super) fn spawn(id: &str) -> Result<Child> {
    let executable = std::env::current_exe()?;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new(executable);
        command
            .args(["sync", "run", id])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // setsid is async-signal-safe and isolates terminal hangups.
        unsafe {
            command.pre_exec(|| {
                rustix::process::setsid().map_err(std::io::Error::from)?;
                Ok(())
            });
        }
        Ok(Child {
            inner: command.spawn().context("cannot start detached sync job")?,
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::Threading::{
                CreateProcessW, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS, PROCESS_INFORMATION,
                STARTUPINFOW,
            },
        };
        let application: Vec<u16> = executable
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut arguments = vec![b'"' as u16];
        arguments.extend(executable.as_os_str().encode_wide());
        arguments.extend("\" sync run ".encode_utf16());
        arguments.extend(id.encode_utf16());
        arguments.push(0);
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut information: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // Stdio::null alone does not disable inheritance of other pipe handles.
        // Use bInheritHandles=FALSE so capturing the launcher output reaches EOF
        // while this long-lived worker continues running.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                arguments.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                std::ptr::null(),
                std::ptr::null(),
                &startup,
                &mut information,
            )
        };
        if created == 0 {
            return Err(std::io::Error::last_os_error()).context("cannot start detached sync job");
        }
        unsafe {
            CloseHandle(information.hThread);
        }
        Ok(Child {
            handle: unsafe {
                std::os::windows::io::OwnedHandle::from_raw_handle(information.hProcess)
            },
        })
    }
}

impl Child {
    pub(super) fn try_wait(&mut self) -> Result<Option<String>> {
        #[cfg(unix)]
        {
            Ok(self.inner.try_wait()?.map(|exit| exit.to_string()))
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::{
                Foundation::{WAIT_FAILED, WAIT_TIMEOUT},
                System::Threading::{GetExitCodeProcess, WaitForSingleObject},
            };
            match unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) } {
                WAIT_TIMEOUT => Ok(None),
                WAIT_FAILED => Err(std::io::Error::last_os_error().into()),
                _ => {
                    let mut code = 0;
                    if unsafe { GetExitCodeProcess(self.handle.as_raw_handle(), &mut code) } == 0 {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    Ok(Some(format!("exit code {code}")))
                }
            }
        }
    }
    pub(super) fn terminate(&mut self) {
        #[cfg(unix)]
        {
            let _ = self.inner.kill();
            let _ = self.inner.wait();
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
            unsafe {
                TerminateProcess(self.handle.as_raw_handle(), 1);
                WaitForSingleObject(self.handle.as_raw_handle(), 5_000);
            }
        }
    }
    pub(super) fn release(self) {
        #[cfg(unix)]
        std::thread::spawn(move || {
            let mut child = self.inner;
            let _ = child.wait();
        });
        // Windows automatically reaps exited processes; OwnedHandle closes our
        // reference when self is dropped without stopping the worker.
    }
}
