//! Credentials stay restricted to SYSTEM and local Administrators.
//! The separate display directory grants Users file read/traverse rights.
//! No shell helpers are involved; the DACL is applied with the native security API.
use anyhow::{ensure, Context, Result};
use std::{os::windows::ffi::OsStrExt, path::Path, ptr};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    },
    Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    },
};

pub(crate) fn managed_root() -> Result<std::path::PathBuf> {
    let program_data =
        std::env::var_os("ProgramData").context("Windows ProgramData directory is unavailable")?;
    ensure!(
        !program_data.is_empty(),
        "Windows ProgramData directory is empty"
    );
    Ok(Path::new(&program_data).join("PortHub"))
}

pub(crate) fn is_managed(path: &Path) -> bool {
    managed_root().ok().is_some_and(|root| {
        path.starts_with(root)
            && path
                .components()
                .all(|component| !matches!(component, std::path::Component::ParentDir))
    })
}

pub(crate) fn secure(path: &Path, directory: bool) -> Result<()> {
    apply(path, directory, false)
}
pub(crate) fn readable(path: &Path, directory: bool) -> Result<()> {
    apply(path, directory, true)
}
fn apply(path: &Path, directory: bool, readable: bool) -> Result<()> {
    ensure!(
        if readable {
            path.starts_with(managed_root()?.with_file_name("PortHubStatus"))
                && path
                    .components()
                    .all(|c| !matches!(c, std::path::Component::ParentDir))
        } else {
            is_managed(path)
        },
        "refusing to change ACL outside PortHub state"
    );
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        } && !metadata.file_type().is_symlink(),
        "refusing to change ACL on a PortHub reparse point"
    );
    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let sddl = if readable && directory {
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"
    } else if readable {
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"
    } else if directory {
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    } else {
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
    };
    let sddl_wide = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: Input strings are NUL-terminated and output pointers refer to a
    // live local variable. The allocated descriptor is freed below.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    ensure!(converted != 0, "cannot build PortHub Windows access policy");
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = ptr::null_mut();
    // SAFETY: The descriptor was created by the Windows conversion API above.
    let got_dacl =
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) };
    if got_dacl == 0 || present == 0 || dacl.is_null() {
        // SAFETY: `descriptor` was allocated by ConvertString... and is freed once.
        unsafe { LocalFree(descriptor) };
        anyhow::bail!("cannot read PortHub Windows access policy");
    }
    let info: OBJECT_SECURITY_INFORMATION =
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    // SAFETY: The path is NUL-terminated, and `dacl` remains valid until the
    // descriptor is freed. The API copies the ACL into the file security data.
    let result = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            info,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    // SAFETY: `descriptor` was allocated by ConvertString... and is freed once.
    unsafe { LocalFree(descriptor) };
    ensure!(
        result == 0,
        "cannot secure PortHub Windows state (code {result})"
    );
    Ok(())
}
