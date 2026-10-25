mod common;
use anyhow::Result;
#[cfg(unix)]
use porthub_agent::profile;
use porthub_agent::profile::{Lease, Profile};
fn profile() -> Profile {
    Profile {
        format_version: 1,
        server: "https://porthub.example/".into(),
        machine_id: "0123456789abcdef01234567".into(),
        token: "private-machine-token".into(),
        account_email: None,
        setup_overrides: Default::default(),
        fallback_servers: vec!["https://fallback.example/".into()],
        allow_insecure_http_for_tests: false,
    }
}
#[test]
fn profiles_are_private_atomic_identity_preserving_and_exclusively_owned() -> Result<()> {
    let dir = common::private_dir()?;
    let path = dir.path().join("machine.json");
    let mut value = profile();
    value.save_new(&path)?;
    assert!(value.save_new(&path).is_err());
    let restored = Profile::load(&path)?;
    assert_eq!(restored.server, "https://porthub.example");
    assert_eq!(restored.token, value.token);
    assert!(!format!("{restored:?}").contains(&value.token));
    assert!(!format!("{restored:?}").contains("fallback.example"));
    assert!(!Lease::running(&path)?);
    let lease = Lease::acquire(&path)?;
    assert!(Lease::running(&path)?);
    assert!(Lease::acquire(&path).is_err());
    drop(lease);
    let _lease = Lease::acquire(&path)?;
    for server in [
        "http://porthub.example",
        "https://user:password@porthub.example",
        "https://porthub.example/?token=secret",
        "https://porthub.example/#fragment",
    ] {
        value.server = server.into();
        assert!(value.validate().is_err());
    }
    Ok(())
}
#[cfg(unix)]
#[test]
fn profile_loading_rejects_symlinks_and_public_or_nonregular_files() -> Result<()> {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = common::private_dir()?;
    let path = dir.path().join("profile");
    profile().save_new(&path)?;
    let link = dir.path().join("link");
    symlink(&path, &link)?;
    assert!(Profile::load(&link).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    assert!(Profile::load(&path).is_err());
    assert!(profile::write_private(&path, b"replacement", true).is_err());
    assert!(profile::read_private(dir.path()).is_err());
    Ok(())
}
#[test]
fn configure_and_status_never_print_the_machine_token() -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let dir = common::private_dir()?;
    let path = dir.path().join("profile");
    let mut child = Command::new(env!("CARGO_BIN_EXE_porthub"))
        .args([
            "configure",
            "--server",
            "https://porthub.example",
            "--machine-id",
            "0123456789abcdef01234567",
            "--profile",
        ])
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"private-machine-token\n")?;
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-machine-token"));
    assert_eq!(Profile::load(&path)?.token, "private-machine-token");
    let output = Command::new(env!("CARGO_BIN_EXE_porthub"))
        .args(["status", "--profile"])
        .arg(&path)
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("stopped") && !text.contains("private-machine-token"));
    Ok(())
}
