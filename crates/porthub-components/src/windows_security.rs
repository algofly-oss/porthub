//! Restrict downloaded executables to the current account, SYSTEM and admins.
//! Never inherit a writable Users ACL or follow junctions when securing a cache.
use anyhow::{ensure, Result};
use std::{
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetNamedSecurityInfoW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        EqualSid, GetSecurityDescriptorDacl, GetTokenInformation, TokenOwner, TokenUser,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
pub fn secure_directory(path: &Path) -> Result<()> {
    ensure!(
        std::fs::symlink_metadata(path)?.file_attributes() & 0x400 == 0,
        "unsafe component directory reparse point"
    );
    let wide: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        let mut token = ptr::null_mut();
        ensure!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0,
            "cannot inspect component cache account"
        );
        let mut length = 0;
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut length);
        // TokenUser is small. Bound the native output before allocating aligned storage.
        if length == 0 || length > 65536 {
            CloseHandle(token);
            anyhow::bail!("invalid component account token");
        }
        let mut storage = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            storage.as_mut_ptr().cast(),
            length,
            &mut length,
        );
        if ok == 0 {
            CloseHandle(token);
            anyhow::bail!("cannot read component cache account");
        }
        let mut owner_length = 0;
        GetTokenInformation(token, TokenOwner, ptr::null_mut(), 0, &mut owner_length);
        if owner_length == 0 || owner_length > 65536 {
            CloseHandle(token);
            anyhow::bail!("invalid component default owner");
        }
        let mut owner_storage =
            vec![0usize; (owner_length as usize).div_ceil(std::mem::size_of::<usize>())];
        let owner_ok = GetTokenInformation(
            token,
            TokenOwner,
            owner_storage.as_mut_ptr().cast(),
            owner_length,
            &mut owner_length,
        );
        CloseHandle(token);
        ensure!(owner_ok != 0, "cannot read component default owner");
        let default_owner = &*owner_storage.as_ptr().cast::<TOKEN_OWNER>();
        let user = &*storage.as_ptr().cast::<TOKEN_USER>();
        let mut owner = ptr::null_mut();
        let mut security = ptr::null_mut();
        let status = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut security,
        );
        if status != 0 {
            anyhow::bail!("cannot inspect component cache owner");
        }
        // Elevated Windows processes commonly create files owned by their
        // token's default owner (Administrators), rather than TokenUser.
        let owned = !owner.is_null()
            && (EqualSid(owner, user.User.Sid) != 0 || EqualSid(owner, default_owner.Owner) != 0);
        LocalFree(security);
        ensure!(owned, "component cache must be owned by this account");
        let mut sid = ptr::null_mut();
        ensure!(
            ConvertSidToStringSidW(user.User.Sid, &mut sid) != 0,
            "cannot format component account"
        );
        let mut size = 0;
        while *sid.add(size) != 0 {
            size += 1;
        }
        let sid_text = String::from_utf16_lossy(std::slice::from_raw_parts(sid, size));
        LocalFree(sid.cast());
        let sddl: Vec<_> = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid_text})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = ptr::null_mut();
        ensure!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut()
            ) != 0,
            "cannot build component cache access policy"
        );
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = ptr::null_mut();
        let ok = GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted);
        if ok == 0 || present == 0 || dacl.is_null() {
            LocalFree(descriptor);
            anyhow::bail!("invalid component cache access policy");
        }
        let result = SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        );
        LocalFree(descriptor);
        ensure!(result == 0, "cannot secure component cache (code {result})");
    }
    Ok(())
}
