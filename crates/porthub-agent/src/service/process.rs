//! Compare readiness records with the executable actually owned by the OS process.
use std::path::Path;

pub(super) fn matches(pid: u32, expected: &Path) -> bool {
    executable(pid)
        .zip(std::fs::canonicalize(expected).ok())
        .is_some_and(|(running, expected)| running == expected)
}

#[cfg(target_os = "linux")]
fn executable(pid: u32) -> Option<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(target_os = "macos")]
fn executable(pid: u32) -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let pid = i32::try_from(pid).ok()?;
    if pid <= 0 {
        return None;
    }
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: proc_pidpath writes at most the supplied size into this live
    // allocation. No pointers escape; malformed or failed results are rejected.
    let size = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if size <= 0 || size as usize > buffer.len() {
        return None;
    }
    let end = buffer.iter().position(|byte| *byte == 0)?;
    buffer.truncate(end);
    std::fs::canonicalize(std::ffi::OsString::from_vec(buffer)).ok()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn executable(_pid: u32) -> Option<std::path::PathBuf> {
    None
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn readiness_requires_the_running_executable_not_a_stale_pid_record() -> anyhow::Result<()> {
        let current = std::env::current_exe()?;
        assert!(matches(std::process::id(), &current));
        assert!(!matches(0, &current));
        assert!(!matches(u32::MAX, &current));
        // A real, unrelated OS executable also must not satisfy readiness.
        assert!(!matches(std::process::id(), Path::new("/bin/sh")));
        Ok(())
    }
}
