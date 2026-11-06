//! Public, verified software only. Profiles, credentials, worker sockets and
//! retry state always remain in each account's private directories.
use crate::catalog::{Artifact, Blob, Catalog, CATALOG_ASSET, MAX_CATALOG};
use anyhow::{ensure, Result};
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
const MARKER: &str = ".porthub-components-shared";
const IDENTITY: &[u8] = b"PortHub verified public components v1\n";

#[derive(Clone)]
pub struct Cache {
    root: PathBuf,
    writer: bool,
}
fn normalized(path: PathBuf) -> Result<PathBuf> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
        "shared cache requires an absolute normalized path"
    );
    #[cfg(target_os = "macos")]
    let path = crate::store::normalize_system_alias(path)?;
    Ok(path)
}
fn trusted(path: &Path, directory: bool) -> Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink()
            && if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            },
        "unsafe shared component cache entry"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            (metadata.uid() == 0 || metadata.uid() == rustix::process::geteuid().as_raw())
                && metadata.mode() & 0o022 == 0,
            "shared component cache entry is writable by another account"
        );
    }
    #[cfg(windows)]
    crate::windows_security::check_public(path)?;
    Ok(metadata)
}
fn ancestors(root: &Path) -> Result<()> {
    for parent in root.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "unsafe shared cache ancestor"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                (metadata.uid() == 0 || metadata.uid() == rustix::process::geteuid().as_raw())
                    && (metadata.mode() & 0o022 == 0
                        || metadata.uid() == 0 && metadata.mode() & 0o1000 != 0),
                "shared cache ancestor is not trusted"
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            ensure!(
                metadata.file_attributes() & 0x400 == 0,
                "shared cache ancestor is a reparse point"
            );
            if parent.parent().is_some() {
                crate::windows_security::check_public_ancestor(parent)?;
            }
        }
    }
    Ok(())
}
fn open(path: &Path) -> Result<File> {
    trusted(path, false)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    Ok(options.open(path)?)
}
fn binary_name(artifact: &Artifact) -> String {
    format!(
        "{}-{}-{}{}",
        artifact.component,
        artifact.version,
        artifact.executable.sha256,
        if artifact.target.contains("windows") {
            ".exe"
        } else {
            ""
        }
    )
}
fn receipt_name(artifact: &Artifact) -> String {
    format!(
        "installed-{}-{}-{}.json",
        artifact.component, artifact.version, artifact.target
    )
}
fn copy_checked(mut input: File, mut output: impl Write, blob: &Blob) -> Result<()> {
    ensure!(
        input.metadata()?.len() == blob.size,
        "shared component size mismatch"
    );
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        ensure!(total <= blob.size, "shared component exceeds declared size");
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    ensure!(
        total == blob.size && format!("{:x}", hash.finalize()) == blob.sha256,
        "shared component checksum mismatch"
    );
    Ok(())
}
impl Cache {
    pub fn reader(root: PathBuf) -> Result<Self> {
        Ok(Self {
            root: normalized(root)?,
            writer: false,
        })
    }
    pub fn writer(root: PathBuf) -> Result<Self> {
        let root = normalized(root)?;
        ancestors(&root)?;
        let mut created = false;
        match std::fs::symlink_metadata(&root) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    match std::fs::DirBuilder::new().mode(0o755).create(&root) {
                        Ok(()) => created = true,
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                #[cfg(windows)]
                match std::fs::create_dir(&root) {
                    Ok(()) => created = true,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Err(error) => return Err(error.into()),
        }
        #[cfg(windows)]
        if created {
            crate::windows_security::make_public(&root, true)?;
        }
        let cache = Self { root, writer: true };
        if created {
            trusted(&cache.root, true)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&cache.root, std::fs::Permissions::from_mode(0o755))?;
            }
            cache.write(MARKER, IDENTITY)?;
        }
        cache.validate()?;
        Ok(cache)
    }
    fn validate(&self) -> Result<()> {
        ancestors(&self.root)?;
        trusted(&self.root, true)?;
        let path = self.root.join(MARKER);
        ensure!(
            trusted(&path, false)?.len() == IDENTITY.len() as u64
                && std::fs::read(path)? == IDENTITY,
            "shared cache marker missing or invalid"
        );
        Ok(())
    }
    fn lock(&self) -> Result<File> {
        ensure!(self.writer, "shared cache is read only");
        if !self.root.try_exists()? {
            Self::writer(self.root.clone())?;
        }
        self.validate()?;
        let path = self.root.join(".publish.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(&path)?;
        trusted(&path, false)?;
        file.lock_exclusive()?;
        Ok(file)
    }
    fn persist(&self, mut file: tempfile::NamedTempFile, name: &str) -> Result<()> {
        file.as_file_mut().flush()?;
        file.as_file().sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o644))?;
        }
        #[cfg(windows)]
        crate::windows_security::make_public(file.path(), false)?;
        file.persist(self.root.join(name)).map_err(|e| e.error)?;
        #[cfg(unix)]
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    fn write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let mut file = tempfile::NamedTempFile::new_in(&self.root)?;
        file.write_all(bytes)?;
        self.persist(file, name)
    }
    pub fn catalog(&self) -> Result<Option<Catalog>> {
        if !self.root.try_exists()? {
            return Ok(None);
        }
        self.validate()?;
        let path = self.root.join(CATALOG_ASSET);
        if !path.try_exists()? {
            return Ok(None);
        }
        ensure!(
            trusted(&path, false)?.len() <= MAX_CATALOG as u64,
            "shared component catalog exceeds limit"
        );
        let mut bytes = Vec::new();
        open(&path)?
            .take(MAX_CATALOG as u64 + 1)
            .read_to_end(&mut bytes)?;
        Ok(Some(Catalog::parse(&bytes)?))
    }
    pub fn publish_catalog(&self, catalog: &Catalog) -> Result<()> {
        catalog.validate()?;
        let _lock = self.lock()?;
        if let Ok(Some(previous)) = self.catalog() {
            if previous.release > catalog.release {
                return Ok(());
            }
            catalog.validate_successor(&previous)?;
            if previous.release == catalog.release {
                return Ok(());
            }
        }
        self.write(CATALOG_ASSET, &serde_json::to_vec(catalog)?)
    }
    /// Copy verified software to a user's already-private temporary file. No
    /// user writes, executes, or changes permissions in the system cache.
    pub fn copy_into(&self, artifact: &Artifact, output: &mut File) -> Result<bool> {
        artifact.validate()?;
        if !self.root.try_exists()? {
            return Ok(false);
        }
        self.validate()?;
        let path = self.root.join(binary_name(artifact));
        if !path.try_exists()? {
            return Ok(false);
        }
        copy_checked(open(&path)?, output, &artifact.executable)?;
        Ok(true)
    }
    pub fn publish_artifact(&self, artifact: &Artifact, source: &Path) -> Result<()> {
        artifact.validate()?;
        let _lock = self.lock()?;
        let receipt = self.root.join(receipt_name(artifact));
        if receipt.try_exists()? {
            ensure!(
                trusted(&receipt, false)?.len() <= 16384,
                "shared receipt exceeds limit"
            );
            let previous: Artifact = serde_json::from_slice(&std::fs::read(receipt)?)?;
            ensure!(
                previous.same_tool(artifact),
                "shared installed component version changed"
            );
        }
        let path = self.root.join(binary_name(artifact));
        if path.try_exists()?
            && copy_checked(open(&path)?, std::io::sink(), &artifact.executable).is_ok()
        {
            return Ok(());
        }
        let mut file = tempfile::NamedTempFile::new_in(&self.root)?;
        copy_checked(open(source)?, file.as_file_mut(), &artifact.executable)?;
        self.persist(file, &binary_name(artifact))?;
        self.write(&receipt_name(artifact), &serde_json::to_vec(artifact)?)
    }
    pub fn is_writer(&self) -> bool {
        self.writer
    }
}

pub fn system_writer() -> bool {
    #[cfg(unix)]
    {
        rustix::process::geteuid().is_root()
    }
    #[cfg(windows)]
    {
        crate::windows_security::privileged().unwrap_or(false)
    }
}
