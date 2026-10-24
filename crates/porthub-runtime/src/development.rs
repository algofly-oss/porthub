//! Writable development UI source copy without duplicating installed
//! dependencies. Production never starts this optional role.
use anyhow::{Context, Result};
use std::path::Path;

pub fn prepare_ui(source: &Path, work: &Path) -> Result<()> {
    anyhow::ensure!(source.is_dir(), "development UI template is missing");
    std::fs::create_dir_all(work)?;
    let template = source.canonicalize()?;
    let workspace = work.canonicalize()?;
    anyhow::ensure!(
        !template.starts_with(&workspace) && !workspace.starts_with(&template),
        "development template and workspace must be separate"
    );
    if work.join(".porthub-ui-ready").is_file() {
        return Ok(());
    }
    copy_sources(source, work)?;
    let modules = work.join("node_modules");
    if !modules.exists() {
        std::os::unix::fs::symlink(source.join("node_modules"), modules)?;
    }
    std::fs::write(work.join(".porthub-ui-ready"), b"prepared")?;
    Ok(())
}
fn copy_sources(source: &Path, destination: &Path) -> Result<()> {
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "node_modules" || name == ".git" || name.to_string_lossy().starts_with(".next") {
            continue;
        }
        let target = destination.join(&name);
        if entry.file_type()?.is_dir() {
            std::fs::create_dir_all(&target)?;
            copy_sources(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}
pub fn run_ui(source: &Path, work: &Path, port: u16) -> Result<()> {
    prepare_ui(source, work)?;
    use std::os::unix::process::CommandExt;
    let error = std::process::Command::new("node")
        .arg(source.join("node_modules/next/dist/bin/next"))
        .args(["dev", "--hostname", "127.0.0.1", "--port"])
        .arg(port.to_string())
        .current_dir(work)
        .exec();
    Err(error).context("start optional development UI")
}
