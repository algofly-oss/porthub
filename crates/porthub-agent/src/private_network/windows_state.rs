//! Protected native ownership state. Never adopt records from an inherited or foreign ACL.
use anyhow::{ensure, Context, Result};
use std::path::Path;
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT},
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
fn private(path: &Path, directory: bool) -> Result<()> {
    use std::os::windows::{ffi::OsStrExt, fs::MetadataExt};
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_attributes() & 0x400 == 0
            && if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            },
        "Native state path must not be a reparse point"
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
    validate_descriptor(descriptor)
}
fn validate_descriptor(descriptor: PSECURITY_DESCRIPTOR) -> Result<()> {
    ensure!(
        !descriptor.is_null() && unsafe { IsValidSecurityDescriptor(descriptor) } != 0,
        "Invalid native state security descriptor"
    );
    let (mut control, mut revision) = (0u16, 0u32);
    let (mut owner, mut defaulted) = (std::ptr::null_mut(), 0);
    ensure!(
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } != 0
            && control & SE_DACL_PROTECTED != 0,
        "Native state requires a protected DACL"
    );
    ensure!(
        unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) } != 0
            && !owner.is_null()
            && unsafe { IsValidSid(owner) } != 0,
        "Native state owner missing"
    );
    let (mut dacl, mut present) = (std::ptr::null_mut(), 0);
    ensure!(
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            != 0
            && present != 0
            && !dacl.is_null(),
        "Native state DACL missing/null"
    );
    let header = unsafe { std::ptr::read_unaligned(dacl) };
    ensure!(
        header.AclSize as usize >= std::mem::size_of::<ACL>()
            && header.AceCount > 0
            && header.AceCount <= 128,
        "Empty or excessive native state DACL"
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
    ensure!(
        unsafe { EqualSid(owner, system.as_mut_ptr().cast()) } != 0
            || unsafe { EqualSid(owner, admins.as_mut_ptr().cast()) } != 0,
        "Native state owner must be SYSTEM or Administrators"
    );
    let start = dacl as usize;
    let end = start
        .checked_add(header.AclSize as usize)
        .context("ACL bounds overflow")?;
    for index in 0..u32::from(header.AceCount) {
        let mut raw = std::ptr::null_mut();
        ensure!(
            unsafe { GetAce(dacl, index, &mut raw) } != 0 && !raw.is_null(),
            "Cannot inspect native state ACE"
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
            "Native state ACE type/inheritance/bounds invalid"
        );
        let sid = unsafe { raw.cast::<u8>().add(sid_offset) };
        let subauthorities = unsafe { *sid.add(1) } as usize;
        let sid_len = 8 + 4 * subauthorities;
        ensure!(
            subauthorities <= 15 && sid_offset + sid_len <= ace.AceSize as usize,
            "Native state ACE SID exceeds its bounds"
        );
        let sid = sid.cast::<core::ffi::c_void>() as PSID;
        ensure!(
            unsafe { IsValidSid(sid) } != 0 && unsafe { GetLengthSid(sid) } as usize == sid_len,
            "Invalid native state ACE SID"
        );
        ensure!(
            unsafe { EqualSid(sid, system.as_mut_ptr().cast()) } != 0
                || unsafe { EqualSid(sid, admins.as_mut_ptr().cast()) } != 0,
            "Native state ACL admits another principal"
        );
    }
    Ok(())
}

pub(super) fn state_path(profile: &Path, suffix: &str) -> Result<std::path::PathBuf> {
    let root = crate::service::windows_acl::managed_root()?.canonicalize()?;
    let profile = profile.canonicalize()?;
    ensure!(
        matches!(root.components().next(),Some(std::path::Component::Prefix(p)) if matches!(p.kind(),std::path::Prefix::Disk(_)|std::path::Prefix::VerbatimDisk(_))),
        "native ownership requires local Windows state"
    );
    ensure!(
        profile.starts_with(&root),
        "Windows native ownership requires a managed protected profile"
    );
    let relative = profile.strip_prefix(&root)?;
    private(&root, true)?;
    let mut cursor = root;
    for component in relative.components() {
        ensure!(
            matches!(component, std::path::Component::Normal(_)),
            "invalid managed profile path"
        );
        cursor.push(component.as_os_str());
        private(&cursor, cursor != profile)?;
    }
    Ok(crate::profile::sibling(&profile, suffix))
}
pub(super) fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    read_bounded(path, 65536)
}
pub(super) fn read_bounded<T: serde::de::DeserializeOwned>(
    path: &Path,
    limit: usize,
) -> Result<Option<T>> {
    read_bytes_bounded(path, limit)?
        .map(|bytes| Ok(serde_json::from_slice(&bytes)?))
        .transpose()
}
pub(super) fn read_bytes_bounded(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    ensure!(
        matches!(
            limit,
            65536 | 262144 | super::native_ownership::MAX_LEDGER_BYTES
        ),
        "invalid native state byte budget"
    );
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    private(path, false)?;
    use std::io::Read;
    let file = crate::profile::open_private_lock(path)?;
    ensure!(
        file.metadata()?.len() <= limit as u64,
        "native ownership record exceeds bound"
    );
    let mut data = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut data)?;
    ensure!(data.len() <= limit, "native ownership record exceeds bound");
    Ok(Some(data))
}
pub(super) fn write<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    write_bounded(path, value, 65536)
}
pub(super) fn write_bounded<T: serde::Serialize>(
    path: &Path,
    value: &T,
    limit: usize,
) -> Result<()> {
    let data = serde_json::to_vec(value)?;
    write_bytes_bounded(path, &data, limit)
}
pub(super) fn write_bytes_bounded(path: &Path, data: &[u8], limit: usize) -> Result<()> {
    ensure!(
        matches!(
            limit,
            65536 | 262144 | super::native_ownership::MAX_LEDGER_BYTES
        ),
        "invalid native state byte budget"
    );
    private(path.parent().context("native state parent missing")?, true)?;
    if path.try_exists()? {
        private(path, false)?;
    }
    ensure!(data.len() <= limit, "native ownership record exceeds bound");
    crate::profile::write_private(path, data, true)?;
    // The temporary file's default owner can be the invoking elevated admin.
    // Set only our just-written journal to the privileged local Administrators
    // owner; never normalize/adopt a pre-existing untrusted record.
    privileged_owner(path)?;
    private(path, false)
}

pub(super) fn profile_binding(profile: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::os::windows::ffi::OsStrExt;
    let identity: serde_json::Value =
        serde_json::from_slice(&crate::profile::read_private(profile)?)?;
    let fields = ["server", "workspace", "peer_id"].map(|key| {
        identity
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty() && v.len() <= 4096)
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("native ownership profile identity is incomplete"))
    });
    let fields = fields.into_iter().collect::<Result<Vec<_>>>()?;
    let mut hash = Sha256::new();
    hash.update(b"porthub-windows-native-owner-v1\0");
    for unit in profile.as_os_str().encode_wide() {
        hash.update(unit.to_le_bytes());
    }
    hash.update([0, 0]);
    hash.update(serde_json::to_vec(&fields)?);
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn descriptor(value: &str) -> Result<()> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        let wide: Vec<_> = value.encode_utf16().chain(Some(0)).collect();
        let mut sd = std::ptr::null_mut();
        ensure!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    std::ptr::null_mut(),
                )
            } != 0,
            "cannot build test descriptor"
        );
        let _guard = Free(sd);
        validate_descriptor(sd)
    }
    #[test]
    fn only_protected_privileged_owner_and_allow_principals_are_accepted() {
        descriptor("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)").unwrap();
        for invalid in [
            "O:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)",
            "O:SYD:P(A;;FA;;;SY)(A;;FR;;;BU)",
            "O:SYD:(A;;FA;;;SY)",
            "O:SYD:P",
            "O:SYD:P(D;;FA;;;BA)(A;;FA;;;SY)",
        ] {
            assert!(descriptor(invalid).is_err(), "{invalid}");
        }
    }
}

fn privileged_owner(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    let mut admins = [0u32; 17];
    let mut length = 68;
    ensure!(
        unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                std::ptr::null_mut(),
                admins.as_mut_ptr().cast(),
                &mut length,
            )
        } != 0,
        "cannot build native journal owner"
    );
    let wide: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    ensure!(
        unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                admins.as_mut_ptr().cast(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == 0,
        "cannot assign protected native journal owner"
    );
    Ok(())
}
