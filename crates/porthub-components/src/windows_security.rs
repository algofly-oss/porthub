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

/// Read TokenUser for the actual pipe peer, rather than trusting a pipe name or
/// a broad Administrators DACL. Handles are released on every error path.
pub fn process_account(pid: u32) -> Result<String> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        ensure!(!process.is_null(), "cannot inspect component peer process");
        let process = OwnedHandle::from_raw_handle(process);
        let mut token = ptr::null_mut();
        ensure!(
            OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) != 0,
            "cannot inspect component peer account"
        );
        let token = OwnedHandle::from_raw_handle(token);
        let mut length = 0;
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut length,
        );
        ensure!(
            length > 0 && length <= 65536,
            "invalid component peer account token"
        );
        let mut storage = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
        ensure!(
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                storage.as_mut_ptr().cast(),
                length,
                &mut length
            ) != 0,
            "cannot read component peer account"
        );
        let user = &*storage.as_ptr().cast::<TOKEN_USER>();
        let mut sid = ptr::null_mut();
        ensure!(
            ConvertSidToStringSidW(user.User.Sid, &mut sid) != 0,
            "cannot format component peer account"
        );
        let mut length = 0;
        while *sid.add(length) != 0 {
            length += 1;
        }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(sid, length));
        LocalFree(sid.cast());
        Ok(value)
    }
}
pub fn same_account(pid: u32) -> Result<()> {
    ensure!(
        process_account(pid)? == process_account(std::process::id())?,
        "component IPC peer belongs to another account"
    );
    Ok(())
}
pub fn pipe(
    address: &str,
    first: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    let account = process_account(std::process::id())?;
    let sddl: Vec<_> = format!("D:P(A;;GA;;;{account})")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    unsafe {
        let mut descriptor = ptr::null_mut();
        ensure!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut()
            ) != 0,
            "cannot build component pipe access policy"
        );
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let result = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .max_instances(64)
            .create_with_security_attributes_raw(
                address,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            );
        LocalFree(descriptor);
        Ok(result?)
    }
}

fn sid_text(sid: windows_sys::Win32::Security::PSID) -> Result<String> {
    unsafe {
        let mut text = ptr::null_mut();
        ensure!(
            ConvertSidToStringSidW(sid, &mut text) != 0,
            "cannot inspect shared cache principal"
        );
        let mut length = 0;
        while *text.add(length) != 0 {
            length += 1;
        }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(text, length));
        LocalFree(text.cast());
        Ok(value)
    }
}
struct Descriptor(windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub fn privileged() -> Result<bool> {
    use windows_sys::Win32::Security::{
        Authorization::ConvertStringSidToSidW, CheckTokenMembership,
    };
    let value: Vec<_> = "S-1-5-32-544".encode_utf16().chain(Some(0)).collect();
    unsafe {
        let mut administrators = ptr::null_mut();
        ensure!(
            ConvertStringSidToSidW(value.as_ptr(), &mut administrators) != 0,
            "cannot inspect administrator membership"
        );
        let mut member = 0;
        let ok = CheckTokenMembership(ptr::null_mut(), administrators, &mut member);
        LocalFree(administrators);
        ensure!(ok != 0, "cannot inspect administrator membership");
        Ok(member != 0 || process_account(std::process::id())? == "S-1-5-18")
    }
}
/// Public software caches accept read/execute grants for other users, but no
/// write/delete/ownership grants outside this account, SYSTEM or administrators.
pub fn check_public(path: &Path) -> Result<()> {
    inspect_public(path, false)
}
pub fn check_public_ancestor(path: &Path) -> Result<()> {
    inspect_public(path, true)
}
fn inspect_public(path: &Path, ancestor: bool) -> Result<()> {
    use windows_sys::Win32::Security::{GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER};
    ensure!(
        std::fs::symlink_metadata(path)?.file_attributes() & 0x400 == 0,
        "shared cache is a reparse point"
    );
    let current = process_account(std::process::id())?;
    let trusted = |sid: &str| sid == current || matches!(sid, "S-1-5-18" | "S-1-5-32-544");
    let path_wide: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        let mut owner = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        ensure!(
            GetNamedSecurityInfoW(
                path_wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor
            ) == 0,
            "cannot inspect shared cache access policy"
        );
        let _descriptor = Descriptor(descriptor);
        ensure!(
            !owner.is_null() && !dacl.is_null() && trusted(&sid_text(owner)?),
            "shared cache owner is not trusted"
        );
        for index in 0..(*dacl).AceCount {
            let mut ace = ptr::null_mut();
            ensure!(
                GetAce(dacl, index as u32, &mut ace) != 0 && !ace.is_null(),
                "invalid shared cache access policy"
            );
            let header = &*ace.cast::<ACE_HEADER>();
            if ancestor && header.AceFlags & 0x08 != 0 {
                continue;
            } // inherit-only
            if header.AceType == 1 {
                continue;
            } // Denials cannot grant mutation.
            ensure!(
                header.AceType == 0,
                "unsupported shared cache permission entry"
            );
            let allowed = &*ace.cast::<ACCESS_ALLOWED_ACE>();
            let sid = (&allowed.SidStart as *const u32).cast_mut().cast();
            // Primitive mutation rights, excluding shared read-control/synchronize
            // bits present in both FILE_GENERIC_READ and FILE_GENERIC_WRITE.
            const MUTATE: u32 = 0x0000_0002
                | 0x0000_0004
                | 0x0000_0010
                | 0x0000_0040
                | 0x0000_0100
                | 0x0001_0000
                | 0x0004_0000
                | 0x0008_0000
                | 0x1000_0000
                | 0x4000_0000;
            ensure!(
                allowed.Mask
                    & if ancestor {
                        0x0000_0040 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x1000_0000
                    } else {
                        MUTATE
                    }
                    == 0
                    || trusted(&sid_text(sid)?),
                "shared component cache is writable by another account"
            );
        }
    }
    Ok(())
}
/// Only use on newly created cache entries. Existing cache directories must
/// pass check_public first; this never adopts arbitrary installation folders.
pub fn make_public(path: &Path, directory: bool) -> Result<()> {
    use windows_sys::Win32::Security::{GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION};
    ensure!(
        std::fs::symlink_metadata(path)?.file_attributes() & 0x400 == 0,
        "shared cache is a reparse point"
    );
    let elevated = privileged()?;
    let account = if elevated {
        "BA".to_string()
    } else {
        process_account(std::process::id())?
    };
    let inherit = if directory { "OICI" } else { "" };
    let sddl: Vec<_> = format!("O:{account}D:P(A;{inherit};FA;;;SY)(A;{inherit};FA;;;BA)(A;{inherit};FA;;;{account})(A;{inherit};FRFX;;;BU)")
        .encode_utf16().chain(Some(0)).collect();
    let path_wide: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        let mut descriptor = ptr::null_mut();
        ensure!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut()
            ) != 0,
            "cannot build shared cache policy"
        );
        let _descriptor = Descriptor(descriptor);
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = ptr::null_mut();
        let mut owner = ptr::null_mut();
        ensure!(
            GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) != 0
                && present != 0
                && !dacl.is_null()
                && GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) != 0
                && !owner.is_null(),
            "invalid shared cache policy"
        );
        let status = SetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        );
        ensure!(status == 0, "cannot secure shared cache (code {status})");
    }
    Ok(())
}
