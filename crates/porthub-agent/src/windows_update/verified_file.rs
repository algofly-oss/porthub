//! Small process-local integrity cache for protected immutable core files.
//! Holds identity/digest data only, never an open handle across calls. Critical
//! staging/execution checks still use the existing uncached SHA verification.
//! Metadata stamps are an idle-check optimization, not proof that bytes cannot
//! change: a cached digest outside the current expected set must be rehashed.
use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    volume: u64,
    id: u64,
    size: u64,
    written: i128,
    changed: i128,
    created: i128,
}
#[cfg(windows)]
fn open(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    Ok(OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?)
}
#[cfg(all(test, not(windows)))]
fn open(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?)
}
#[cfg(windows)]
fn stamp(file: &File) -> Result<Stamp> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO,
    };
    unsafe {
        let mut info: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        let mut basic: FILE_BASIC_INFO = std::mem::zeroed();
        ensure!(
            GetFileInformationByHandle(file.as_raw_handle(), &mut info) != 0
                && GetFileInformationByHandleEx(
                    file.as_raw_handle(),
                    FileBasicInfo,
                    (&mut basic as *mut FILE_BASIC_INFO).cast(),
                    std::mem::size_of::<FILE_BASIC_INFO>() as u32
                ) != 0,
            "Cannot identify protected core file"
        );
        ensure!(
            info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 && file.metadata()?.is_file(),
            "Core path must be a regular non-reparse file"
        );
        Ok(Stamp {
            volume: u64::from(info.dwVolumeSerialNumber),
            id: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
            written: i128::from(basic.LastWriteTime),
            changed: i128::from(basic.ChangeTime),
            created: i128::from(basic.CreationTime),
        })
    }
}
#[cfg(all(test, not(windows)))]
fn stamp(file: &File) -> Result<Stamp> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    ensure!(m.is_file(), "Core path must be a regular file");
    Ok(Stamp {
        volume: m.dev(),
        id: m.ino(),
        size: m.len(),
        written: i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
        changed: i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec()),
        created: 0,
    })
}
#[derive(Default)]
struct Cache {
    entries: Mutex<BTreeMap<PathBuf, (Stamp, String)>>,
    #[cfg(test)]
    reads: std::sync::atomic::AtomicUsize,
}
impl Cache {
    fn hash(&self, path: &Path, expected: &[&str]) -> Result<String> {
        ensure!(
            (1..=2).contains(&expected.len())
                && expected
                    .iter()
                    .all(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())),
            "Expected core digest missing"
        );
        let mut held = open(path)?;
        let identity = stamp(&held)?;
        ensure!(
            identity.size > 0 && identity.size <= 256 * 1024 * 1024,
            "Core file exceeds size bound"
        );
        if let Some((previous, digest)) = self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(path)
            .cloned()
        {
            if previous == identity
                && expected.iter().any(|e| digest.eq_ignore_ascii_case(e))
                && stamp(&open(path)?)? == identity
            {
                return Ok(digest);
            }
        }
        // Once fresh validation is required, an unsuccessful read or digest
        // mismatch must not leave an older digest eligible for a later caller.
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(path);
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        let mut total = 0u64;
        loop {
            let n = held.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            total = total
                .checked_add(n as u64)
                .ok_or_else(|| anyhow::anyhow!("Core size overflow"))?;
            ensure!(total <= identity.size, "Core file changed while hashing");
            hash.update(&buffer[..n]);
        }
        ensure!(
            total == identity.size && stamp(&held)? == identity && stamp(&open(path)?)? == identity,
            "Core file identity changed while hashing"
        );
        let digest = format!("{:x}", hash.finalize());
        #[cfg(test)]
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ensure!(
            expected.iter().any(|e| digest.eq_ignore_ascii_case(e)),
            "Core digest differs from pinned release"
        );
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= 8 && !entries.contains_key(path) {
            if let Some(first) = entries.keys().next().cloned() {
                entries.remove(&first);
            }
        }
        entries.insert(path.into(), (identity, digest.clone()));
        Ok(digest)
    }
}
pub(super) fn hash(path: &Path, expected: &[&str]) -> Result<String> {
    static CACHE: OnceLock<Cache> = OnceLock::new();
    CACHE.get_or_init(Cache::default).hash(path, expected)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    fn expected(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
    #[test]
    fn unchanged_files_are_hashed_once_and_same_size_edits_invalidate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.exe");
        std::fs::write(&path, b"original").unwrap();
        let c = Cache::default();
        let first = c.hash(&path, &[&expected(b"original")]).unwrap();
        for _ in 0..8 {
            assert_eq!(c.hash(&path, &[&expected(b"original")]).unwrap(), first);
        }
        assert_eq!(c.reads.load(Ordering::SeqCst), 1);
        std::fs::write(&path, b"modified").unwrap();
        assert_ne!(c.hash(&path, &[&expected(b"modified")]).unwrap(), first);
        assert_eq!(c.reads.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn same_stamp_cached_mismatch_rehashes_current_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.exe");
        std::fs::write(&path, b"modified").unwrap();
        let c = Cache::default();
        // Model a same-size edit whose Windows timestamps did not advance.
        // Inject the exact current stamp so this regression never relies on
        // scheduler timing, timestamp granularity, or a sleep.
        let identity = stamp(&open(&path).unwrap()).unwrap();
        c.entries
            .lock()
            .unwrap()
            .insert(path.clone(), (identity.clone(), expected(b"original")));
        assert_eq!(
            c.hash(&path, &[&expected(b"modified")]).unwrap(),
            expected(b"modified")
        );
        assert_eq!(c.reads.load(Ordering::SeqCst), 1);
        c.entries
            .lock()
            .unwrap()
            .insert(path.clone(), (identity, expected(b"original")));
        assert!(c.hash(&path, &[&expected(b"unknown!")]).is_err());
        assert_eq!(c.reads.load(Ordering::SeqCst), 2);
        assert!(c.entries.lock().unwrap().get(&path).is_none());
        assert!(c.hash(&path, &[&expected(b"original")]).is_err());
        assert_eq!(c.reads.load(Ordering::SeqCst), 3);
    }
    #[test]
    fn atomic_replacement_invalidates_identity_and_cache_holds_no_rename_blocking_handle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.exe");
        std::fs::write(&path, b"bytes").unwrap();
        let c = Cache::default();
        let first = c.hash(&path, &[&expected(b"bytes")]).unwrap();
        let replacement = dir.path().join("replacement.exe");
        std::fs::write(&replacement, b"bytes").unwrap();
        // Move the original first so this exact test is portable on Windows too.
        std::fs::rename(&path, dir.path().join("retired.exe")).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        assert_eq!(c.hash(&path, &[&expected(b"bytes")]).unwrap(), first);
        assert_eq!(c.reads.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn cache_is_bounded_and_does_not_accept_missing_or_nonregular_paths() {
        let dir = tempfile::tempdir().unwrap();
        let c = Cache::default();
        for n in 0..12 {
            let p = dir.path().join(n.to_string());
            std::fs::write(&p, b"core").unwrap();
            c.hash(&p, &[&expected(b"core")]).unwrap();
        }
        assert!(c.entries.lock().unwrap().len() <= 8);
        assert!(c
            .hash(&dir.path().join("missing"), &[&expected(b"core")])
            .is_err());
        assert!(c.hash(dir.path(), &[&expected(b"core")]).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn symlink_cannot_hit_a_previously_cached_path() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("core");
        let other = dir.path().join("other");
        std::fs::write(&p, b"core").unwrap();
        std::fs::write(&other, b"core").unwrap();
        let c = Cache::default();
        c.hash(&p, &[&expected(b"core")]).unwrap();
        std::fs::remove_file(&p).unwrap();
        symlink(&other, &p).unwrap();
        assert!(c.hash(&p, &[&expected(b"core")]).is_err());
    }
    #[test]
    fn unverified_mismatch_is_never_admitted_to_cache() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("core.exe");
        std::fs::write(&p, b"untrusted").unwrap();
        let c = Cache::default();
        assert!(c.hash(&p, &[&expected(b"expected")]).is_err());
        assert!(c.entries.lock().unwrap().is_empty());
        assert_eq!(
            c.hash(&p, &[&expected(b"untrusted")]).unwrap(),
            expected(b"untrusted")
        );
        assert_eq!(c.reads.load(Ordering::SeqCst), 2);
    }
}
