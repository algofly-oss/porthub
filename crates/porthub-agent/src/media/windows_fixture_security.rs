//! Test-only protected-DACL validator using native SID identity, never SDDL spelling.
use anyhow::{ensure, Context, Result};
use std::path::Path;
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::{ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT},
        CreateWellKnownSid, EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsValidSecurityDescriptor,
        IsValidSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_HEADER,
        ACL, DACL_SECURITY_INFORMATION, INHERITED_ACE, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    },
};
struct Free(*mut core::ffi::c_void);
impl Drop for Free {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
pub(super) fn private(path: &Path, directory: bool) -> Result<()> {
    use std::os::windows::{ffi::OsStrExt, fs::MetadataExt};
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_attributes() & 0x400 == 0
            && if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            },
        "Fixture path must not be a reparse point"
    );
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    ensure!(
        unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        } == 0,
        "Cannot inspect fixture ACL"
    );
    let _descriptor = Free(descriptor);
    validate_descriptor(descriptor, &crate::exposure_broker::media_fixture_sid()?)
}
fn validate_descriptor(descriptor: PSECURITY_DESCRIPTOR, current: &str) -> Result<()> {
    ensure!(
        !descriptor.is_null() && unsafe { IsValidSecurityDescriptor(descriptor) } != 0,
        "Invalid fixture security descriptor"
    );
    let wide = current.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut current_sid = std::ptr::null_mut();
    ensure!(
        unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut current_sid) } != 0,
        "Cannot decode current account SID"
    );
    let _current = Free(current_sid);
    let (mut control, mut revision) = (0u16, 0u32);
    let (mut owner, mut defaulted) = (std::ptr::null_mut(), 0);
    ensure!(
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } != 0
            && control & SE_DACL_PROTECTED != 0,
        "Fixture requires a protected DACL"
    );
    ensure!(
        unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) } != 0
            && !owner.is_null()
            && unsafe { IsValidSid(owner) } != 0
            && unsafe { EqualSid(owner, current_sid) } != 0,
        "Fixture owner is not the exact current account"
    );
    let (mut dacl, mut present) = (std::ptr::null_mut(), 0);
    ensure!(
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            != 0
            && present != 0
            && !dacl.is_null(),
        "Fixture DACL missing/null"
    );
    let header = unsafe { std::ptr::read_unaligned(dacl) };
    ensure!(
        header.AclSize as usize >= std::mem::size_of::<ACL>()
            && header.AceCount > 0
            && header.AceCount <= 128,
        "Empty or excessive fixture DACL"
    );
    let mut system = [0u32; 17];
    let mut admins = [0u32; 17];
    let (mut system_len, mut admins_len) = (68u32, 68u32);
    ensure!(
        unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                std::ptr::null_mut(),
                system.as_mut_ptr().cast(),
                &mut system_len,
            )
        } != 0
            && unsafe {
                CreateWellKnownSid(
                    WinBuiltinAdministratorsSid,
                    std::ptr::null_mut(),
                    admins.as_mut_ptr().cast(),
                    &mut admins_len,
                )
            } != 0,
        "Cannot construct trusted OS SIDs"
    );
    let start = dacl as usize;
    let end = start
        .checked_add(header.AclSize as usize)
        .context("ACL bounds overflow")?;
    for index in 0..u32::from(header.AceCount) {
        let mut raw = std::ptr::null_mut();
        ensure!(
            unsafe { GetAce(dacl, index, &mut raw) } != 0 && !raw.is_null(),
            "Cannot inspect fixture ACE"
        );
        let address = raw as usize;
        ensure!(
            address >= start + std::mem::size_of::<ACL>()
                && address
                    .checked_add(std::mem::size_of::<ACE_HEADER>())
                    .is_some_and(|v| v <= end),
            "ACE header outside ACL"
        );
        let ace = unsafe { std::ptr::read_unaligned(raw.cast::<ACE_HEADER>()) };
        // SDK ACCESS_ALLOWED_ACE_TYPE is 0. Object/callback/deny ACEs are not accepted.
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        ensure!(
            ace.AceType == 0
                && ace.AceFlags & (INHERITED_ACE as u8) == 0
                && ace.AceSize as usize >= sid_offset + 8
                && address
                    .checked_add(ace.AceSize as usize)
                    .is_some_and(|v| v <= end),
            "Fixture ACE type/inheritance/bounds invalid"
        );
        let sid = unsafe { raw.cast::<u8>().add(sid_offset) };
        let subauthorities = unsafe { *sid.add(1) } as usize;
        let sid_len = 8 + 4 * subauthorities;
        ensure!(
            subauthorities <= 15 && sid_offset + sid_len <= ace.AceSize as usize,
            "Fixture ACE SID exceeds its bounds"
        );
        let sid = sid.cast::<core::ffi::c_void>() as PSID;
        ensure!(
            unsafe { IsValidSid(sid) } != 0 && unsafe { GetLengthSid(sid) } as usize == sid_len,
            "Invalid fixture ACE SID"
        );
        ensure!(
            unsafe { EqualSid(sid, current_sid) } != 0
                || unsafe { EqualSid(sid, system.as_mut_ptr().cast()) } != 0
                || unsafe { EqualSid(sid, admins.as_mut_ptr().cast()) } != 0,
            "Fixture ACL admits another principal"
        );
    }
    Ok(())
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
            GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, DACL_SECURITY_INFORMATION,
            OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            UNPROTECTED_DACL_SECURITY_INFORMATION,
        },
    };
    fn descriptor(text: &str, current: &str) -> Result<()> {
        let wide = text.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let mut value = std::ptr::null_mut();
        ensure!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut value,
                    std::ptr::null_mut(),
                )
            } != 0,
            "Cannot build temporary descriptor"
        );
        let _free = super::Free(value);
        super::validate_descriptor(value, current)
    }
    #[test]
    fn native_sid_equivalence_preserves_current_owner_without_accepting_foreign_aliases(
    ) -> Result<()> {
        let sid = crate::exposure_broker::media_fixture_sid()?;
        descriptor(
            &format!("O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)"),
            &sid,
        )?;
        let local_admin = format!("O:LAD:P(A;;FA;;;LA)(A;;FA;;;SY)(A;;FA;;;BA)");
        if sid.ends_with("-500") {
            descriptor(&local_admin, &sid)?;
        } else {
            assert!(descriptor(&local_admin, &sid).is_err());
        }
        let foreign = "BU"; // Builtin Users is a valid alias but never the account SID.
        assert!(descriptor(
            &format!("O:{sid}D:P(A;;FA;;;{sid})(A;;FR;;;{foreign})"),
            &sid
        )
        .is_err());
        assert!(
            descriptor(&format!("O:SYD:P(A;;FA;;;{sid})"), &sid).is_err(),
            "Wrong owner must fail"
        );
        assert!(descriptor(&format!("O:{sid}D:P(A;ID;FA;;;{sid})"), &sid).is_err());
        assert!(descriptor(&format!("O:{sid}D:P(D;;FA;;;{sid})"), &sid).is_err());
        assert!(descriptor(&format!("O:{sid}D:P"), &sid).is_err());
        assert!(descriptor(&format!("O:{sid}D:(A;;FA;;;{sid})"), &sid).is_err());
        Ok(())
    }
    fn set_own_test_acl(path: &Path, extra: &str, protected: bool) -> Result<()> {
        let sid = crate::exposure_broker::media_fixture_sid()?;
        let text = format!(
            "O:{sid}D:{}(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA){extra}",
            if protected { "P" } else { "" }
        )
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
        let mut descriptor = std::ptr::null_mut();
        ensure!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            } != 0,
            "Cannot construct owned test ACL"
        );
        struct Free(*mut core::ffi::c_void);
        impl Drop for Free {
            fn drop(&mut self) {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
        let _free = Free(descriptor);
        let (mut owner, mut dacl) = (std::ptr::null_mut(), std::ptr::null_mut());
        let (mut present, mut defaulted) = (0, 0);
        ensure!(
            unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) } != 0
                && unsafe {
                    GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
                } != 0
                && present != 0,
            "Cannot decode test ACL"
        );
        let mut wide = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let flag = if protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        ensure!(
            unsafe {
                SetNamedSecurityInfoW(
                    wide.as_mut_ptr(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | flag,
                    owner,
                    std::ptr::null_mut(),
                    dacl,
                    std::ptr::null_mut(),
                )
            } == 0,
            "Cannot set own temporary test ACL"
        );
        Ok(())
    }
    fn owned_acl_metadata(path: &Path) -> Result<String> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
        };
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut descriptor = std::ptr::null_mut();
        ensure!(
            unsafe {
                GetNamedSecurityInfoW(
                    wide.as_ptr(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut descriptor,
                )
            } == 0,
            "Cannot inspect own test ACL"
        );
        struct Free(*mut core::ffi::c_void);
        impl Drop for Free {
            fn drop(&mut self) {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
        let _descriptor = Free(descriptor);
        let mut text = std::ptr::null_mut();
        ensure!(
            unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor,
                    SDDL_REVISION_1,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    &mut text,
                    std::ptr::null_mut(),
                )
            } != 0,
            "Cannot format own test ACL"
        );
        let _text = Free(text.cast());
        let mut n = 0;
        while n < 1024 && unsafe { *text.add(n) } != 0 {
            n += 1;
        }
        ensure!(n < 1024, "Own test ACL diagnostic exceeds bound");
        Ok(String::from_utf16(unsafe {
            std::slice::from_raw_parts(text, n)
        })?)
    }
    #[test]
    fn shared_fixture_acl_accepts_only_owned_protected_file_and_directory() -> Result<()> {
        // Only new temporary files, no service, driver, endpoint or user settings.
        let root = tempfile::tempdir()?;
        set_own_test_acl(root.path(), "", true)?;
        let path = root.path().join("owned.json");
        std::fs::write(&path, b"{}")?;
        set_own_test_acl(&path, "", true)?;
        println!(
            "PRIVATE_FIXTURE_ACL stage=directory current_sid={} sddl={}",
            crate::exposure_broker::media_fixture_sid()?,
            owned_acl_metadata(root.path())?
        );
        println!(
            "PRIVATE_FIXTURE_ACL stage=file current_sid={} sddl={}",
            crate::exposure_broker::media_fixture_sid()?,
            owned_acl_metadata(&path)?
        );
        private(root.path(), true).context("Own protected directory validator")?;
        private(&path, false).context("Own protected file validator")?;
        assert!(private(&path, true).is_err());
        assert!(private(root.path(), false).is_err());
        set_own_test_acl(&path, "(A;;FR;;;WD)", true)?;
        assert!(
            private(&path, false).is_err(),
            "foreign readable principal must fail"
        );
        set_own_test_acl(&path, "", false)?;
        assert!(
            private(&path, false).is_err(),
            "unprotected inherited ACL must fail"
        );
        set_own_test_acl(&path, "", true)?;
        private(&path, false)?;
        Ok(())
    }
}
