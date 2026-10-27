use anyhow::Result;
use porthub_api::artifacts::{verify_complete, TARGETS};
use sha2::{Digest, Sha256};

#[tokio::test]
async fn release_validation_accepts_one_complete_bundle_and_needs_no_database(
) -> Result<()> {
    let directory = tempfile::tempdir()?;
    for (target, _, _) in TARGETS {
        let name = format!(
            "porthub-{target}{}",
            if target.starts_with("windows_") {
                ".exe"
            } else {
                ""
            }
        );
        std::fs::write(directory.path().join(&name), b"release-fixture")?;
        std::fs::write(directory.path().join(format!("{name}.version")), "1.2.0\n")?;
        std::fs::write(
            directory.path().join(format!("{name}.sha256")),
            format!("{:x}  {name}\n", Sha256::digest(b"release-fixture")),
        )?;
    }
    assert_eq!(verify_complete(directory.path(), "1.2.0").await?.len(), 10);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_porthub-api"))
        .arg("--check-artifacts")
        .arg(directory.path())
        .arg("1.2.0")
        .env_clear()
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["releases"].as_array().unwrap().len(), 10);
    assert!(verify_complete(directory.path(), "old-version")
        .await
        .is_err());
    let historical = directory.path().join("previous-release");
    std::fs::create_dir(&historical)?;
    assert!(verify_complete(directory.path(), "1.2.0").await.is_err());
    std::fs::remove_dir(historical)?;
    let checksum = directory.path().join("porthub-arm64.sha256");
    let original = std::fs::read(&checksum)?;
    std::fs::remove_file(&checksum)?;
    assert!(verify_complete(directory.path(), "1.2.0").await.is_err());
    std::fs::write(&checksum, original)?;
    std::fs::write(directory.path().join("porthub-arm64"), b"corrupt")?;
    assert!(verify_complete(directory.path(), "1.2.0").await.is_err());
    Ok(())
}
