//! Detached workers inherit only their private log and NUL input handles.
//! Inheriting the launcher's captured output would keep its caller waiting for EOF.
use anyhow::{ensure, Context, Result};
use std::{
    ffi::OsStr,
    fs::File,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    process::Command,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, WAIT_FAILED, WAIT_TIMEOUT,
    },
    System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
        InitializeProcThreadAttributeList, TerminateProcess, UpdateProcThreadAttribute,
        WaitForSingleObject, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
        EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        STARTF_USESTDHANDLES, STARTUPINFOEXW,
    },
};

fn quoted(value: &OsStr, output: &mut Vec<u16>) -> Result<()> {
    output.push(b'"' as u16);
    let mut slashes = 0;
    for unit in value.encode_wide() {
        ensure!(unit != 0, "background argument contains NUL");
        if unit == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        if unit == b'"' as u16 {
            output.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2 + 1));
        } else {
            output.extend(std::iter::repeat_n(b'\\' as u16, slashes));
        }
        output.push(unit);
        slashes = 0;
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    output.push(b'"' as u16);
    Ok(())
}
fn inheritable(file: &File) -> Result<OwnedHandle> {
    let mut duplicate = std::ptr::null_mut();
    ensure!(
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                file.as_raw_handle(),
                GetCurrentProcess(),
                &mut duplicate,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            )
        } != 0,
        "cannot prepare background log handle"
    );
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate) })
}
pub(crate) struct Child {
    handle: OwnedHandle,
    pid: u32,
}
pub(crate) fn spawn(command: &Command, log: &File) -> Result<Child> {
    ensure!(
        command.get_current_dir().is_none() && command.get_envs().next().is_none(),
        "background environment must be inherited from the launcher"
    );
    let application: Vec<_> = command.get_program().encode_wide().chain(Some(0)).collect();
    let mut arguments = Vec::new();
    quoted(command.get_program(), &mut arguments)?;
    for value in command.get_args() {
        arguments.push(b' ' as u16);
        quoted(value, &mut arguments)?;
    }
    arguments.push(0);
    let log = inheritable(log)?;
    let input = inheritable(&File::open("NUL")?)?;
    let handles: [HANDLE; 2] = [input.as_raw_handle(), log.as_raw_handle()];
    let mut size = 0;
    unsafe {
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
    }
    ensure!(
        size > 0 && size <= 65536,
        "invalid process attribute allocation"
    );
    let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let attributes = storage.as_mut_ptr().cast();
    ensure!(
        unsafe { InitializeProcThreadAttributeList(attributes, 1, 0, &mut size) } != 0,
        "cannot initialize background process attributes"
    );
    struct Attributes(windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for Attributes {
        fn drop(&mut self) {
            unsafe {
                DeleteProcThreadAttributeList(self.0);
            }
        }
    }
    let _attributes = Attributes(attributes);
    ensure!(
        unsafe {
            UpdateProcThreadAttribute(
                attributes,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(&handles),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } != 0,
        "cannot restrict background handle inheritance"
    );
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[1];
    startup.lpAttributeList = attributes;
    let mut information: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            arguments.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | EXTENDED_STARTUPINFO_PRESENT,
            std::ptr::null(),
            std::ptr::null(),
            &startup.StartupInfo,
            &mut information,
        )
    };
    if created == 0 {
        return Err(std::io::Error::last_os_error()).context("cannot start detached worker");
    }
    unsafe {
        CloseHandle(information.hThread);
    }
    Ok(Child {
        handle: unsafe { OwnedHandle::from_raw_handle(information.hProcess) },
        pid: information.dwProcessId,
    })
}
impl Child {
    pub(crate) fn id(&self) -> u32 {
        self.pid
    }
    pub(crate) fn try_wait(&mut self) -> Result<Option<u32>> {
        match unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_FAILED => Err(std::io::Error::last_os_error().into()),
            _ => {
                let mut code = 0;
                ensure!(
                    unsafe { GetExitCodeProcess(self.handle.as_raw_handle(), &mut code) } != 0,
                    "cannot inspect background worker"
                );
                Ok(Some(code))
            }
        }
    }
    pub(crate) fn kill(&mut self) -> Result<()> {
        ensure!(
            unsafe { TerminateProcess(self.handle.as_raw_handle(), 1) } != 0,
            "cannot terminate background worker"
        );
        Ok(())
    }
    pub(crate) fn wait(&mut self) -> Result<()> {
        let result = unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 5000) };
        ensure!(
            result != WAIT_TIMEOUT && result != WAIT_FAILED,
            "background worker did not stop"
        );
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn quoted_arguments_preserve_spaces_quotes_and_trailing_backslashes() {
        for (input, expected) in [
            ("a b", "\"a b\""),
            ("a\"b", "\"a\\\"b\""),
            ("C:\\folder\\", "\"C:\\folder\\\\\""),
        ] {
            let mut output = Vec::new();
            super::quoted(std::ffi::OsStr::new(input), &mut output).unwrap();
            assert_eq!(String::from_utf16(&output).unwrap(), expected);
        }
    }
}
