#![cfg(unix)]
#[test]
fn development_sources_are_writable_without_copying_dependencies_or_build_cache(
) -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("source");
    let work = directory.path().join("work");
    std::fs::create_dir_all(source.join("node_modules/dependency"))?;
    std::fs::create_dir_all(source.join(".next/cache"))?;
    std::fs::create_dir_all(source.join("src/pages"))?;
    std::fs::write(source.join("src/pages/home.tsx"), b"source page")?;
    std::fs::write(
        source.join("node_modules/dependency/index.js"),
        b"shared dependency",
    )?;
    std::fs::write(source.join(".next/cache/unused"), b"do not copy")?;
    porthub_runtime::development::prepare_ui(&source, &work)?;
    assert!(std::fs::symlink_metadata(work.join("node_modules"))?
        .file_type()
        .is_symlink());
    assert!(!work.join(".next").exists());
    assert_eq!(
        std::fs::read(work.join("node_modules/dependency/index.js"))?,
        b"shared dependency"
    );
    std::fs::write(work.join("src/pages/home.tsx"), b"live update")?;
    porthub_runtime::development::prepare_ui(&source, &work)?;
    assert_eq!(
        std::fs::read(work.join("src/pages/home.tsx"))?,
        b"live update"
    );
    assert_eq!(
        std::fs::read(source.join("src/pages/home.tsx"))?,
        b"source page"
    );
    Ok(())
}
