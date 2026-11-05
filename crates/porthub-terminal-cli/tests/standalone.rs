use std::process::Command;
fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_porthub-terminal"))
}
#[test]
fn independent_cli_exposes_local_tmux_without_core_or_gateway() {
    let help = command().arg("--help").output().unwrap();
    assert!(help.status.success());
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("tmux") && text.contains("runtime"));
    assert!(command()
        .arg("--version")
        .output()
        .unwrap()
        .status
        .success());
    assert!(!command()
        .args(["runtime", "--directory", "relative"])
        .output()
        .unwrap()
        .status
        .success());
}
#[cfg(unix)]
#[test]
fn bundled_runtime_creates_lists_and_kills_an_isolated_workspace() {
    if option_env!("PORTHUB_TERMINAL_BUNDLE").is_none() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let runtime = root.path().join("runtime");
    let socket = root.path().join("tmux.sock");
    struct Stop<'a>(&'a std::path::Path, &'a std::path::Path);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            let _ = command()
                .arg("tmux")
                .arg("--directory")
                .arg(self.0)
                .arg("--")
                .arg("-S")
                .arg(self.1)
                .arg("kill-server")
                .output();
        }
    }
    let _stop = Stop(&runtime, &socket);
    let version = command()
        .arg("tmux")
        .arg("--directory")
        .arg(&runtime)
        .args(["--", "-V"])
        .output()
        .unwrap();
    assert!(
        version.status.success(),
        "{}",
        String::from_utf8_lossy(&version.stderr)
    );
    assert!(String::from_utf8_lossy(&version.stdout).contains("tmux "));
    let created = command()
        .env("SHELL", "/bin/sh")
        .arg("tmux")
        .arg("--directory")
        .arg(&runtime)
        .arg("--")
        .arg("-S")
        .arg(&socket)
        .args([
            "-f",
            "/dev/null",
            "new-session",
            "-d",
            "-s",
            "fixture",
            "sleep 60",
        ])
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let listed = command()
        .arg("tmux")
        .arg("--directory")
        .arg(&runtime)
        .arg("--")
        .arg("-S")
        .arg(&socket)
        .arg("list-sessions")
        .output()
        .unwrap();
    assert!(listed.status.success());
    assert!(String::from_utf8_lossy(&listed.stdout).contains("fixture"));
}
