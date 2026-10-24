pub fn private_dir() -> anyhow::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("porthub-agent-test-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    Ok(builder.tempdir()?)
}
