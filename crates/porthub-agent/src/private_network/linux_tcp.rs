//! Linux TCP autotuning for native private-network endpoints.
use std::{
    ffi::{CStr, CString, OsStr},
    fs, io,
    os::unix::ffi::OsStrExt,
    path::Path,
};

struct Setting {
    key: &'static CStr,
    kernel_default: [&'static str; 3],
    wan_limit: &'static str,
}

const SEND: Setting = Setting {
    key: c"net/ipv4/tcp_wmem",
    kernel_default: ["4096", "16384", "4194304"],
    wan_limit: "4096 16384 33554432",
};
const RECEIVE: Setting = Setting {
    key: c"net/ipv4/tcp_rmem",
    kernel_default: ["4096", "131072", "6291456"],
    wan_limit: "4096 131072 33554432",
};

fn matches_setting(line: &str, setting: &Setting) -> bool {
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
    unsafe { libc::fnmatch(pattern.as_ptr(), setting.key.as_ptr(), libc::FNM_PATHNAME) == 0 }
}

fn configured(path: &Path, setting: &Setting) -> io::Result<bool> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text.lines().any(|line| matches_setting(line, setting))),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

fn apply(root: &Path, policy: &Setting) -> io::Result<()> {
    let setting = root
        .join("proc/sys")
        .join(OsStr::from_bytes(policy.key.to_bytes()));
    if !fs::read_to_string(&setting)?
        .split_whitespace()
        .eq(policy.kernel_default)
    {
        return Ok(());
    }
    if configured(&root.join("etc/sysctl.conf"), policy)? {
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
            if path.extension().is_some_and(|ext| ext == "conf") && configured(&path, policy)? {
                return Ok(());
            }
        }
    }
    fs::write(setting, policy.wan_limit)?;
    tracing::info!(setting = ?policy.key, "raised network namespace TCP autotuning ceiling to 32 MiB");
    Ok(())
}

pub(super) fn configure_autotuning() {
    if std::env::var_os("PORTHUB_PRIVATE_TCP_AUTOTUNE").as_deref()
        == Some(std::ffi::OsStr::new("0"))
    {
        return;
    }
    for policy in [&SEND, &RECEIVE] {
        if let Err(error) = apply(Path::new("/"), policy) {
            tracing::debug!(%error, setting = ?policy.key, "retaining existing Linux TCP autotuning policy");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raises_only_unmanaged_default_and_preserves_custom_values() -> io::Result<()> {
        let root = tempfile::tempdir()?;
        let setting = root.path().join("proc/sys/net/ipv4/tcp_wmem");
        fs::create_dir_all(setting.parent().unwrap())?;
        fs::create_dir_all(root.path().join("etc/sysctl.d"))?;
        fs::write(&setting, SEND.kernel_default.join("\t"))?;
        let policy = root.path().join("etc/sysctl.d/99-local.conf");
        fs::write(&policy, "net.ipv4.tcp_wmem = 4096 16384 4194304")?;
        apply(root.path(), &SEND)?;
        assert_eq!(
            fs::read_to_string(&setting)?,
            SEND.kernel_default.join("\t")
        );
        fs::remove_file(policy)?;
        apply(root.path(), &SEND)?;
        apply(root.path(), &SEND)?;
        assert_eq!(fs::read_to_string(&setting)?, SEND.wan_limit);
        for custom in [
            "4096 32768 4194304",
            "4096 16384 1048576",
            "4096 16384 67108864",
        ] {
            fs::write(&setting, custom)?;
            apply(root.path(), &SEND)?;
            assert_eq!(fs::read_to_string(&setting)?, custom);
        }
        Ok(())
    }
    #[test]
    fn receive_ceiling_respects_independent_administrator_policy() -> io::Result<()> {
        let root = tempfile::tempdir()?;
        let receive = root.path().join("proc/sys/net/ipv4/tcp_rmem");
        fs::create_dir_all(receive.parent().unwrap())?;
        fs::create_dir_all(root.path().join("etc/sysctl.d"))?;
        let policy = root.path().join("etc/sysctl.d/50-private.conf");
        let original = RECEIVE.kernel_default.join(" ");
        fs::write(&receive, &original)?;
        for rule in [
            "net.ipv4.tcp_rmem=4096 131072 6291456",
            "-net/ipv4/tcp_?mem",
        ] {
            fs::write(&policy, rule)?;
            apply(root.path(), &RECEIVE)?;
            assert_eq!(fs::read_to_string(&receive)?, original);
        }
        fs::write(&policy, "net.ipv4.tcp_wmem=4096 16384 4194304")?;
        apply(root.path(), &RECEIVE)?;
        assert_eq!(fs::read_to_string(&receive)?, RECEIVE.wan_limit);
        for custom in [
            "4096 131072 1048576",
            "4096 262144 6291456",
            "4096 131072 67108864",
        ] {
            fs::write(&receive, custom)?;
            apply(root.path(), &RECEIVE)?;
            assert_eq!(fs::read_to_string(&receive)?, custom);
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
            assert!(matches_setting(line, &SEND), "{line}");
        }
        for line in [
            "#net.ipv4.tcp_wmem = 1",
            "; net.ipv4.tcp_wmem = 1",
            "net.ipv4.tcp_rmem=1",
            "net.ipv6.*=1",
            "",
        ] {
            assert!(!matches_setting(line, &SEND), "{line}");
        }
    }
}
