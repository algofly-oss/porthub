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

/// Concurrent process creation may briefly inherit another thread's writable
/// temporary-file descriptor before exec closes CLOEXEC handles. Linux can then
/// reject exec with ETXTBSY even though publication has closed its own writer.
/// Retry only errors proving that process creation did not succeed.
pub(crate) async fn retry_spawn<T>(
    cancel: &tokio_util::sync::CancellationToken,
    mut launch: impl FnMut() -> Result<T>,
) -> Result<T> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut delay = std::time::Duration::from_millis(10);
    loop {
        anyhow::ensure!(!cancel.is_cancelled(), "component startup cancelled");
        match launch() {
            Ok(child) => return Ok(child),
            Err(error) => {
                let retry = error.downcast_ref::<std::io::Error>().is_some_and(|io| {
                    #[cfg(unix)]
                    {
                        io.raw_os_error() == Some(libc::ETXTBSY)
                    }
                    #[cfg(windows)]
                    {
                        io.raw_os_error() == Some(32)
                    } // ERROR_SHARING_VIOLATION
                });
                if !retry || tokio::time::Instant::now() + delay >= deadline {
                    return Err(error);
                }
                tokio::select! {biased; _=cancel.cancelled()=>anyhow::bail!("component startup cancelled"),_=tokio::time::sleep(delay)=>{}}
                delay = (delay * 2).min(std::time::Duration::from_millis(100));
            }
        }
    }
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    use tokio_util::sync::CancellationToken;
    #[tokio::test]
    async fn permission_rejections_and_cancellation_do_not_repeat_startup() {
        let mut calls = 0;
        let result: Result<()> = retry_spawn(&CancellationToken::new(), || {
            calls += 1;
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls, 1);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let _: Result<()> = retry_spawn(&cancel, || {
            calls += 1;
            Ok(())
        })
        .await;
        assert_eq!(calls, 1);
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn actual_exec_recovers_after_a_writable_descriptor_is_closed() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir()?;
        let executable = root.path().join("fixture");
        std::fs::copy("/bin/true", &executable)?;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))?;
        let writer = std::fs::OpenOptions::new().write(true).open(&executable)?;
        let task = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(75)).await;
            drop(writer);
        });
        let mut attempts = 0;
        let mut child = retry_spawn(&CancellationToken::new(), || {
            attempts += 1;
            Ok(std::process::Command::new(&executable).spawn()?)
        })
        .await?;
        assert!(child.wait()?.success());
        assert!(attempts > 1);
        task.await?;
        Ok(())
    }
}
