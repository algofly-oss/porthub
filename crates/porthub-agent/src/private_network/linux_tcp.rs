//! Linux TCP send autotuning for native private-network endpoints.
use std::{ffi::CString, fs, io, path::Path};

const WMEM: &str = "proc/sys/net/ipv4/tcp_wmem";
const KERNEL_DEFAULT: [&str; 3] = ["4096", "16384", "4194304"];
const WAN_LIMIT: &str = "4096 16384 33554432";

fn matches_setting(line: &str) -> bool {
    let key = line
        .trim_start()
        .trim_start_matches('-')
        .split(['=', ' ', '\t'])
        .next()
        .unwrap_or("");
    if key.is_empty() || key.starts_with(['#', ';']) {
        return false;
    }
    let Ok(pattern) = CString::new(key.replace('.', "/")) else {
        return false;
    };
    // The two C strings live throughout fnmatch; FNM_PATHNAME matches sysctl.d glob semantics.
    unsafe {
        libc::fnmatch(
            pattern.as_ptr(),
            c"net/ipv4/tcp_wmem".as_ptr(),
            libc::FNM_PATHNAME,
        ) == 0
    }
}

fn configured(path: &Path) -> io::Result<bool> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text.lines().any(matches_setting)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

fn apply(root: &Path) -> io::Result<()> {
    let setting = root.join(WMEM);
    if !fs::read_to_string(&setting)?
        .split_whitespace()
        .eq(KERNEL_DEFAULT)
    {
        return Ok(());
    }
    if configured(&root.join("etc/sysctl.conf"))? {
        return Ok(());
    }
    for dir in [
        "etc/sysctl.d",
        "run/sysctl.d",
        "usr/local/lib/sysctl.d",
        "usr/lib/sysctl.d",
        "lib/sysctl.d",
    ] {
        let entries = match fs::read_dir(root.join(dir)) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        for entry in entries {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "conf") && configured(&path)? {
                return Ok(());
            }
        }
    }
    fs::write(setting, WAN_LIMIT)?;
    tracing::info!("raised network namespace TCP send autotuning ceiling to 32 MiB");
    Ok(())
}

pub(super) fn configure_send_autotuning() {
    if std::env::var_os("PORTHUB_PRIVATE_TCP_AUTOTUNE").as_deref()
        == Some(std::ffi::OsStr::new("0"))
    {
        return;
    }
    if let Err(error) = apply(Path::new("/")) {
        tracing::debug!(%error, "retaining existing Linux TCP send autotuning policy");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raises_only_unmanaged_default_and_preserves_custom_values() -> io::Result<()> {
        let root = tempfile::tempdir()?;
        let setting = root.path().join(WMEM);
        fs::create_dir_all(setting.parent().unwrap())?;
        fs::create_dir_all(root.path().join("etc/sysctl.d"))?;
        fs::write(&setting, KERNEL_DEFAULT.join("\t"))?;
        let policy = root.path().join("etc/sysctl.d/99-local.conf");
        fs::write(&policy, "net.ipv4.tcp_wmem = 4096 16384 4194304")?;
        apply(root.path())?;
        assert_eq!(fs::read_to_string(&setting)?, KERNEL_DEFAULT.join("\t"));
        fs::remove_file(policy)?;
        apply(root.path())?;
        apply(root.path())?;
        assert_eq!(fs::read_to_string(&setting)?, WAN_LIMIT);
        for custom in [
            "4096 32768 4194304",
            "4096 16384 1048576",
            "4096 16384 67108864",
        ] {
            fs::write(&setting, custom)?;
            apply(root.path())?;
            assert_eq!(fs::read_to_string(&setting)?, custom);
        }
        Ok(())
    }
    #[test]
    fn explicit_sysctl_policy_including_globs_is_preserved() {
        for line in [
            "net.ipv4.tcp_wmem = 4096 16384 4194304",
            "-net/ipv4/tcp_wmem",
            " net.ipv4.tcp_* = 1",
            "net/ipv4/tcp_?mem = 1",
        ] {
            assert!(matches_setting(line), "{line}");
        }
        for line in [
            "#net.ipv4.tcp_wmem = 1",
            "; net.ipv4.tcp_wmem = 1",
            "net.ipv4.tcp_rmem=1",
            "net.ipv6.*=1",
            "",
        ] {
            assert!(!matches_setting(line), "{line}");
        }
    }
}
