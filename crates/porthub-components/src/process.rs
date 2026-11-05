//! Detached workers must not inherit a caller's terminal/capture pipe handles.
use anyhow::{Context, Result};
use std::path::Path;
pub(crate) struct Child {
    #[cfg(unix)]
    inner: tokio::process::Child,
    #[cfg(windows)]
    handle: std::os::windows::io::OwnedHandle,
}
pub(crate) fn spawn(executable: &Path, endpoint: &str, state: &Path) -> Result<Child> {
    #[cfg(unix)]
    {
        use std::process::Stdio;
        let mut command = tokio::process::Command::new(executable);
        command
            .args(["__porthub-worker", "--endpoint", endpoint])
            .env("PORTHUB_STATE_DIR", state)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(false);
        unsafe {
            command.pre_exec(|| {
                rustix::process::setsid().map_err(std::io::Error::from)?;
                Ok(())
            });
        }
        Ok(Child {
            inner: command
                .spawn()
                .context("cannot start verified component worker")?,
        })
    }
    #[cfg(windows)]
    {
        use anyhow::ensure;
        use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::Threading::{
                CreateProcessW, CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT,
                DETACHED_PROCESS, PROCESS_INFORMATION, STARTUPINFOW,
            },
        };
        let application: Vec<_> = executable
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut arguments = quote(executable.as_os_str());
        arguments.extend(" __porthub-worker --endpoint ".encode_utf16());
        arguments.extend(quote(std::ffi::OsStr::new(endpoint)));
        arguments.push(0);
        ensure!(
            arguments.len() <= 32767,
            "component worker command exceeds Windows limit"
        );
        let mut variables: Vec<_> = std::env::vars_os()
            .filter(|(name, _)| {
                !name
                    .to_string_lossy()
                    .eq_ignore_ascii_case("PORTHUB_STATE_DIR")
            })
            .collect();
        variables.push(("PORTHUB_STATE_DIR".into(), state.as_os_str().to_owned()));
        variables.sort_by_cached_key(|(key, _)| key.to_string_lossy().to_uppercase());
        let mut environment = Vec::new();
        for (key, value) in variables {
            environment.extend(key.encode_wide());
            environment.push(b'=' as u16);
            environment.extend(value.encode_wide());
            environment.push(0);
        }
        environment.push(0);
        ensure!(
            environment.len() <= 1024 * 1024,
            "component worker environment exceeds limit"
        );
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut information: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // bInheritHandles=FALSE matters even when stdio is null: otherwise an
        // unrelated inheritable parent pipe can keep `porthub ... --detach`
        // capture open for the lifetime of this persistent worker.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                arguments.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                std::ptr::null(),
                &startup,
                &mut information,
            )
        };
        if created == 0 {
            return Err(std::io::Error::last_os_error())
                .context("cannot start verified component worker");
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
#[cfg(windows)]
fn quote(value: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let mut output = vec![b'"' as u16];
    let mut slashes = 0;
    for unit in value.encode_wide() {
        if unit == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        output.extend(std::iter::repeat_n(
            b'\\' as u16,
            if unit == b'"' as u16 {
                slashes * 2 + 1
            } else {
                slashes
            },
        ));
        slashes = 0;
        output.push(unit);
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    output.push(b'"' as u16);
    output
}
impl Child {
    pub(crate) fn exited(&mut self) -> Result<bool> {
        #[cfg(unix)]
        {
            Ok(self.inner.try_wait()?.is_some())
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::{
                Foundation::{WAIT_FAILED, WAIT_TIMEOUT},
                System::Threading::WaitForSingleObject,
            };
            let status = unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) };
            if status == WAIT_FAILED {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(status != WAIT_TIMEOUT)
        }
    }
    pub(crate) fn start_kill(&mut self) -> Result<()> {
        #[cfg(unix)]
        {
            self.inner.start_kill()?;
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::Threading::TerminateProcess;
            if !self.exited()? && unsafe { TerminateProcess(self.handle.as_raw_handle(), 1) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(())
    }
    pub(crate) async fn kill(&mut self) -> Result<()> {
        self.start_kill()?;
        self.wait().await
    }
    pub(crate) async fn wait(&mut self) -> Result<()> {
        #[cfg(unix)]
        {
            let _ = self.inner.wait().await?;
        }
        #[cfg(windows)]
        {
            while !self.exited()? {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
        Ok(())
    }
}
