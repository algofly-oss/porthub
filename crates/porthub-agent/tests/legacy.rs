#![cfg(unix)]
use porthub_agent::{legacy, profile::Profile};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

fn env() -> String {
    "PORT_HUB_TENANT=gateway-machine\nPORT_HUB_API_URL=https://porthub.example/api/\nPORT_HUB_MACHINE_ID=ABCDEF0123456789ABCDEF01\nPORT_HUB_MACHINE_TOKEN=fixture-token\nPORT_HUB_CONFIG_TOML_URL=https://porthub.example/api/config?machine_id=id&token=fixture-token\nPORT_HUB_SELF_PATH=/usr/local/bin/porthub\n".into()
}

#[test]
fn imports_generated_credentials_and_preserves_authority_prefix() {
    let profile = legacy::parse(env().as_bytes(), vec!["https://fallback.example".into()]).unwrap();
    assert_eq!(profile.server, "https://porthub.example");
    assert_eq!(profile.machine_id, "abcdef0123456789abcdef01");
    assert_eq!(profile.token, "fixture-token");
    assert_eq!(profile.fallback_servers, ["https://fallback.example"]);
    assert!(!format!("{profile:?}").contains("fixture-token"));
    let nested = env().replace(
        "https://porthub.example/api/",
        "https://porthub.example/prefix/api/",
    );
    assert_eq!(
        legacy::parse(nested.as_bytes(), vec![]).unwrap().server,
        "https://porthub.example/prefix"
    );
}

#[test]
fn literals_never_execute_or_expand_shell_and_failures_hide_values() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("must-not-exist");
    let expression = format!("$(touch {})", marker.display());
    for token in [
        expression.clone(),
        format!("\"{expression}\""),
        "`uname`".into(),
        "$HOME".into(),
        "secret;exit".into(),
    ] {
        let source = env().replace(
            "PORT_HUB_MACHINE_TOKEN=fixture-token",
            &format!("PORT_HUB_MACHINE_TOKEN={token}"),
        );
        let error = legacy::parse(source.as_bytes(), vec![])
            .unwrap_err()
            .to_string();
        assert!(!error.contains(&token));
    }
    assert!(!marker.exists());
    let source = env().replace(
        "PORT_HUB_MACHINE_TOKEN=fixture-token",
        "PORT_HUB_MACHINE_TOKEN='literal$token'",
    );
    assert_eq!(
        legacy::parse(source.as_bytes(), vec![]).unwrap().token,
        "literal$token"
    );
    for extra in [
        "source other.env",
        "export PORT_HUB_MACHINE_TOKEN=secret",
        "PORT_HUB_MACHINE_ID=secret",
        "PORT_HUB_DEBUG=\"unterminated",
        "PORT_HUB_DEBUG=bad\0data",
    ] {
        assert!(legacy::parse(format!("{}{extra}\n", env()).as_bytes(), vec![]).is_err());
    }
    let bad = env().replace(
        "https://porthub.example/api/",
        "https://secret@porthub.example/api/",
    );
    let error = legacy::parse(bad.as_bytes(), vec![])
        .unwrap_err()
        .to_string();
    assert!(!error.contains("secret"));
    assert!(legacy::parse(&vec![b'x'; 65_537], vec![]).is_err());
}

#[test]
fn staging_preserves_legacy_files_and_never_replaces_profiles() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let source = directory.path().join("client.env");
    let output = directory.path().join("profile.json");
    fs::write(&source, env()).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
    let prior = fs::read(&source).unwrap();
    let id = legacy::stage(&source, &output, vec![]).unwrap();
    assert_eq!(id.len(), 64);
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(Profile::load(&output).unwrap().token, "fixture-token");
    assert_eq!(fs::read(&source).unwrap(), prior);
    let staged = fs::read(&output).unwrap();
    assert!(legacy::stage(&source, &output, vec![]).is_err());
    assert_eq!(fs::read(&output).unwrap(), staged);
    assert_eq!(fs::read(&source).unwrap(), prior);
}

#[test]
fn source_links_permissions_special_files_and_plaintext_authorities_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("client.env");
    fs::write(&source, env()).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(legacy::read(&source, vec![]).is_err());
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&source, &link).unwrap();
    assert!(legacy::read(&link, vec![]).is_err());
    assert!(legacy::read(directory.path(), vec![]).is_err());
    let unsafe_source = env().replace(
        "https://porthub.example/api/",
        "http://porthub.example/api/",
    );
    assert!(legacy::parse(unsafe_source.as_bytes(), vec![]).is_err());
    assert!(legacy::parse(env().as_bytes(), vec!["http://fallback.example".into()]).is_err());
}

#[test]
fn actual_cli_stages_private_profile_without_exposing_credentials() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let source = directory.path().join("client.env");
    let destination = directory.path().join("profile.json");
    fs::write(&source, env()).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_porthub"))
        .arg("import-legacy")
        .arg("--env-file")
        .arg(&source)
        .arg("--profile")
        .arg(&destination)
        .arg("--fallback-server")
        .arg("https://fallback.example")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!text.contains("fixture-token"));
    assert!(!text.contains("porthub.example"));
    assert!(!text.contains("fallback.example"));
    assert!(text.contains("credentials staged"));
    assert_eq!(
        Profile::load(&destination).unwrap().fallback_servers,
        ["https://fallback.example"]
    );
}

#[test]
fn imports_explicit_tunnel_and_domain_overrides_without_replacing_the_saved_authority() {
    let source=env().replace("token=fixture-token\n", "token=fixture-token&rathole_server_address=wss%3A%2F%2Forigin.example%3A443%2Fapi%2Ftunnel&service_domain=services.example&public_base_url=https%3A%2F%2Fold-origin.example\n");
    let profile = legacy::parse(source.as_bytes(), vec![]).unwrap();
    assert_eq!(profile.server, "https://porthub.example");
    assert_eq!(
        profile.setup_overrides["rathole_server_address"],
        "wss://origin.example:443/api/tunnel"
    );
    assert_eq!(
        profile.setup_overrides["service_domain"],
        "services.example"
    );
    assert!(!profile.setup_overrides.contains_key("public_base_url"));
}
