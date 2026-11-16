//! Keep enrollment credentials stable across asynchronous SCM maintenance. Only
//! the profile is pinned: independent local feature-policy files stay revocable.
use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
};
const MAX_PROFILE: u64 = 4 * 1024 * 1024;
pub(super) struct EnrollmentGuard {
    _file: File,
}
impl EnrollmentGuard {
    pub(super) fn acquire(path: &Path, expected_sha256: &str) -> Result<Self> {
        let native = crate::service::windows_acl::managed_root()?.join("native");
        ensure!(
            path.parent() == Some(native.as_path())
                && path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|name| {
                        name.strip_suffix(".json").is_some_and(|id| {
                            id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                    }),
            "Enrollment pin requires an exact managed profile"
        );
        Self::open(path, expected_sha256)
    }
    fn open(path: &Path, expected_sha256: &str) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        // SAFETY: The owned file handle and output allocation remain live for
        // this synchronous native metadata query.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0
                && info.nNumberOfLinks == 1
                && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && file.metadata()?.is_file()
                && file.metadata()?.len() <= MAX_PROFILE,
            "Enrollment pin requires a bounded single-link regular non-reparse file"
        );
        let mut bytes = Vec::new();
        (&mut file).take(MAX_PROFILE + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_PROFILE
                && format!("{:x}", Sha256::digest(&bytes)) == expected_sha256,
            "Enrollment changed before maintenance pin"
        );
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
                SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        },
    };
    fn hash(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
    fn tighten_dacl(path: &Path) -> Result<()> {
        // Exercise the same native DACL-only operation as windows_acl::secure
        // on temporary storage, without touching real managed registrations.
        let descriptor_text = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)"
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        ensure!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    descriptor_text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            } != 0,
            "cannot create temporary DACL"
        );
        let result = (|| {
            let mut present = 0;
            let mut defaulted = 0;
            let mut dacl = std::ptr::null_mut();
            ensure!(
                unsafe {
                    GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
                } != 0
                    && present != 0
                    && !dacl.is_null(),
                "temporary DACL missing"
            );
            let mut name = path
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let status = unsafe {
                SetNamedSecurityInfoW(
                    name.as_mut_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    dacl,
                    std::ptr::null_mut(),
                )
            };
            ensure!(
                status == 0,
                "in-place DACL tightening failed while enrollment pinned: {status}"
            );
            Ok(())
        })();
        unsafe { LocalFree(descriptor) };
        result
    }
    #[test]
    fn pin_blocks_credential_write_and_rename_but_allows_read_policy_and_dacl() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("profile.json");
        let renamed = root.path().join("renamed.json");
        let policy = root.path().join("profile.json.client-features.json");
        std::fs::write(&path, b"credentials")?;
        let guard = EnrollmentGuard::open(&path, &hash(b"credentials"))?;
        assert_eq!(std::fs::read(&path)?, b"credentials");
        assert!(std::fs::write(&path, b"foreign").is_err());
        assert!(std::fs::rename(&path, &renamed).is_err());
        assert!(std::fs::remove_file(&path).is_err());
        std::fs::write(&policy, b"revoked")?;
        assert_eq!(std::fs::read(&policy)?, b"revoked");
        tighten_dacl(&path)?;
        assert_eq!(std::fs::read(&path)?, b"credentials");
        drop(guard);
        std::fs::write(&path, b"new enrollment")?;
        std::fs::rename(&path, &renamed)?;
        Ok(())
    }
    #[test]
    fn pin_rejects_wrong_credentials_and_nonfiles() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("profile.json");
        std::fs::write(&path, b"foreign")?;
        assert!(EnrollmentGuard::open(&path, &hash(b"expected")).is_err());
        assert!(EnrollmentGuard::open(root.path(), &hash(b"expected")).is_err());
        assert!(EnrollmentGuard::acquire(&path, &hash(b"foreign")).is_err());
        let alias = root.path().join("alias.json");
        std::fs::hard_link(&path, &alias)?;
        assert!(EnrollmentGuard::open(&path, &hash(b"foreign")).is_err());
        assert_eq!(std::fs::read(&alias)?, b"foreign");
        Ok(())
    }
}
