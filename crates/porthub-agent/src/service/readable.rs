//! Credential-free local registration metadata. Never used to authorize mutations.
use super::{Layout, RegistrationProfile, Spec};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const LIMIT: u64 = 16 * 1024;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub format_version: u32,
    pub id: String,
    pub machine_id: String,
    pub email: String,
    pub gateway: String,
    pub private: bool,
    pub enabled: bool,
    pub active: Option<bool>,
    pub state: String,
    pub agent_version: String,
    pub ports: usize,
    pub route: String,
    pub updated_at: u64,
    pub strategy: crate::private_network::strategy::Mode,
    pub strategy_override: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_status: Option<crate::runtime::PrivateStatus>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn valid_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}
pub(crate) fn directory(layout: &Layout) -> Result<PathBuf> {
    if layout.user || layout.state != Layout::system()?.state {
        return Ok(layout.state.with_file_name("status"));
    }
    #[cfg(target_os = "linux")]
    return Ok("/var/lib/porthub-status".into());
    #[cfg(target_os = "macos")]
    return Ok("/Library/Application Support/PortHub Status".into());
    #[cfg(windows)]
    return Ok(super::windows_acl::managed_root()?.with_file_name("PortHubStatus"));
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    anyhow::bail!("native registration status is unsupported")
}
fn caller_owned(layout: &Layout) -> Result<bool> {
    Ok(layout.user || layout.state != Layout::system()?.state)
}
fn check(path: &Path, directory: bool, user: bool) -> Result<fs::Metadata> {
    #[cfg(windows)]
    let meta = super::windows_acl::retry_status_io(|| fs::symlink_metadata(path))
        .context("registration display metadata lookup unavailable")?;
    #[cfg(not(windows))]
    let meta = fs::symlink_metadata(path)?;
    check_metadata(&meta, directory, user)?;
    Ok(meta)
}
fn check_metadata(meta: &fs::Metadata, directory: bool, user: bool) -> Result<()> {
    ensure!(
        !meta.file_type().is_symlink()
            && if directory {
                meta.is_dir()
            } else {
                meta.is_file()
            },
        "registration status must be a regular owned entry"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let owner = if user {
            rustix::process::getuid().as_raw()
        } else {
            0
        };
        ensure!(
            meta.uid() == owner && meta.permissions().mode() & 0o022 == 0,
            "registration status is not owned securely"
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            meta.file_attributes() & 0x400 == 0,
            "registration status must not be a reparse point"
        );
    }
    #[cfg(not(unix))]
    let _ = user;
    Ok(())
}
fn read(path: &Path, user: bool) -> Result<Record> {
    let before = check(path, false, user)?;
    ensure!(
        before.len() <= LIMIT,
        "registration status exceeds size limit"
    );
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    }
    #[cfg(windows)]
    let file = super::windows_acl::retry_status_io(|| options.open(path))
        .context("registration display record unavailable")?;
    #[cfg(not(windows))]
    let file = options.open(path)?;
    // A publisher may atomically replace the path between stat and open. Trust
    // only the opened handle's ownership/type; either complete record is valid.
    #[cfg(windows)]
    let metadata = super::windows_acl::retry_status_io(|| file.metadata())
        .context("registration display handle unavailable")?;
    #[cfg(not(windows))]
    let metadata = file.metadata()?;
    check_metadata(&metadata, false, user)?;
    ensure!(
        metadata.len() <= LIMIT,
        "registration status exceeds size limit"
    );
    let mut bytes = Vec::new();
    #[cfg(windows)]
    {
        let mut reader = file.take(LIMIT + 1);
        super::windows_acl::retry_status_io(|| reader.read_to_end(&mut bytes))
            .context("registration display read unavailable")?;
    }
    #[cfg(not(windows))]
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= LIMIT,
        "registration status exceeds size limit"
    );
    let record: Record = serde_json::from_slice(&bytes).context("invalid registration status")?;
    ensure!(
        record.format_version == 1,
        "unsupported registration status format"
    );
    ensure!(
        valid_id(&record.id) && path.file_stem().and_then(|v| v.to_str()) == Some(&record.id),
        "registration status identity mismatch"
    );
    ensure!(
        [
            &record.machine_id,
            &record.email,
            &record.gateway,
            &record.state,
            &record.agent_version,
            &record.route
        ]
        .into_iter()
        .all(|s| s.len() <= 1024 && !s.chars().any(char::is_control)),
        "invalid registration display metadata"
    );
    Ok(record)
}
fn write(layout: &Layout, record: &Record) -> Result<()> {
    ensure!(valid_id(&record.id), "invalid registration identity");
    let root = directory(layout)?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o755);
    }
    match builder.create(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = check(&root, true, caller_owned(layout)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o755 {
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    #[cfg(windows)]
    let managed = !layout.user && root == directory(&Layout::system()?)?;
    #[cfg(windows)]
    if managed {
        super::windows_acl::readable(&root, true)?;
    }
    let mut temp = tempfile::NamedTempFile::new_in(&root)?;
    let bytes = serde_json::to_vec(record)?;
    ensure!(
        bytes.len() as u64 <= LIMIT,
        "registration status exceeds size limit"
    );
    temp.write_all(&bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))?;
    }
    #[cfg(windows)]
    if managed {
        super::windows_acl::readable(temp.path(), false)?;
    }
    #[cfg(windows)]
    super::windows_acl::persist_status(temp, &root.join(format!("{}.json", record.id)))
        .context("registration display publication unavailable")?;
    #[cfg(not(windows))]
    temp.persist(root.join(format!("{}.json", record.id)))
        .map_err(|e| e.error)?;
    Ok(())
}
async fn lookup_email(profile: &crate::profile::Profile) -> Option<String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .ok()?;
    let mut response = client
        .post(format!("{}/api/machines/client/identity", profile.server))
        .json(&serde_json::json!({"machine_id":profile.machine_id,"token":profile.token}))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if bytes.len() + chunk.len() > LIMIT as usize {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    let body: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let email = body.get("account_email")?.as_str()?;
    (email.len() <= 320 && !email.chars().any(char::is_control)).then(|| email.to_owned())
}
/// The root/user agent publishes only explicit display fields, never credentials.
pub(crate) async fn install(
    layout: &Layout,
    spec: &Spec,
    profile: &RegistrationProfile,
) -> Result<()> {
    let (server, mut email, private) = match profile {
        RegistrationProfile::Public(p) => (
            p.server.as_str(),
            p.account_email.clone().unwrap_or_default(),
            false,
        ),
        RegistrationProfile::Private(p) => (
            p.server.as_str(),
            p.account_email.clone().unwrap_or_default(),
            true,
        ),
    };
    if email.is_empty() {
        if let RegistrationProfile::Public(profile) = profile {
            email = lookup_email(profile).await.unwrap_or_default();
        }
    }
    let mut url = url::Url::parse(server)?;
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    let clean = url
        .path()
        .trim_end_matches('/')
        .strip_suffix("/api")
        .unwrap_or(url.path().trim_end_matches('/'))
        .to_owned();
    url.set_path(&clean);
    write(
        layout,
        &Record {
            format_version: 1,
            id: spec.identity.clone(),
            machine_id: profile.machine_id(),
            email,
            gateway: url.to_string().trim_end_matches('/').to_owned(),
            private,
            enabled: true,
            active: Some(true),
            state: "starting".into(),
            agent_version: crate::VERSION.into(),
            ports: 0,
            route: String::new(),
            updated_at: now(),
            strategy: Default::default(),
            strategy_override: false,
            private_status: None,
        },
    )
}
fn installed_layout(path: &Path) -> Result<Option<Layout>> {
    let system = Layout::system()?;
    if path.parent() == Some(system.state.as_path()) {
        return Ok(Some(system));
    }
    if let Ok(user) = Layout::user() {
        if path.parent() == Some(user.state.as_path()) {
            return Ok(Some(user));
        }
    }
    Ok(None)
}
pub(crate) fn refresh(path: &Path, status: &crate::runtime::Status) -> Result<()> {
    let Some(layout) = installed_layout(path)? else {
        return Ok(());
    };
    let Some(id) = path
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|id| valid_id(id))
    else {
        return Ok(());
    };
    let destination = directory(&layout)?.join(format!("{id}.json"));
    let mut record = match read(&destination, caller_owned(&layout)?) {
        Ok(record) => record,
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(())
        }
        Err(e) => return Err(e),
    };
    record.state = status.state.clone();
    record.agent_version = status.agent_version.clone();
    record.route = status.route.clone();
    record.private_status = status.private_status.clone();
    record.updated_at = status.updated_at;
    record.active = Some(!matches!(
        status.state.as_str(),
        "stopped" | "deleted" | "interrupted"
    ));
    record.ports = if record.private {
        0
    } else {
        status.service_count
    };
    if record.private {
        record.strategy = crate::private_network::strategy::load(path)?.mode;
        record.strategy_override = crate::private_network::strategy::path(path).try_exists()?;
    }
    write(&layout, &record)
}
pub(crate) fn stopped(path: &Path) -> Result<()> {
    let Some(layout) = installed_layout(path)? else {
        return Ok(());
    };
    let Some(mut record) = for_profile(path)? else {
        return Ok(());
    };
    record.state = "stopped".into();
    record.active = Some(false);
    record.updated_at = now();
    write(&layout, &record)
}
pub fn for_profile(path: &Path) -> Result<Option<Record>> {
    let Some(layout) = installed_layout(path)? else {
        return Ok(None);
    };
    let Some(id) = path
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|id| valid_id(id))
    else {
        return Ok(None);
    };
    Ok(Some(select(&layout, Some(id), None)?))
}
/// Refresh display metadata after a protected strategy change has succeeded.
pub fn strategy_changed(
    path: &Path,
    settings: &crate::private_network::strategy::Settings,
    overridden: bool,
) -> Result<()> {
    let Some(layout) = installed_layout(path)? else {
        return Ok(());
    };
    let Some(mut record) = for_profile(path)? else {
        return Ok(());
    };
    record.strategy = settings.mode;
    record.strategy_override = overridden;
    write(&layout, &record)
}
pub(super) fn remove(layout: &Layout, id: &str) -> Result<()> {
    ensure!(valid_id(id), "invalid registration identity");
    let root = directory(layout)?;
    match check(&root, true, caller_owned(layout)?) {
        Ok(_) => {}
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(())
        }
        Err(error) => return Err(error),
    }
    match fs::remove_file(root.join(format!("{id}.json"))) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub fn list(layout: &Layout) -> Result<Vec<Record>> {
    let root = directory(layout)?;
    match check(&root, true, caller_owned(layout)?) {
        Ok(_) => {}
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(Vec::new())
        }
        Err(e) => return Err(e),
    }
    let mut rows = Vec::new();
    for entry in fs::read_dir(&root)? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        ensure!(rows.len() < 4096, "too many registrations");
        let mut record = read(&path, caller_owned(layout)?)?;
        if now().saturating_sub(record.updated_at) > 90 && record.active == Some(true) {
            record.active = None;
            record.state = "status-stale".into();
        }
        rows.push(record);
    }
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    let emails: Vec<_> = rows
        .iter()
        .filter(|r| !r.email.is_empty())
        .map(|r| (r.machine_id.clone(), r.gateway.clone(), r.email.clone()))
        .collect();
    for row in &mut rows {
        if row.email.is_empty() {
            let matches: Vec<_> = emails
                .iter()
                .filter(|(id, gateway, _)| id == &row.machine_id && gateway == &row.gateway)
                .collect();
            if let Some(first) = matches.first() {
                if matches.iter().all(|item| item.2 == first.2) {
                    row.email = first.2.clone();
                }
            }
        }
    }
    Ok(rows)
}
pub fn select(layout: &Layout, selector: Option<&str>, private: Option<bool>) -> Result<Record> {
    let selector = selector.map(str::to_ascii_lowercase);
    if let Some(id) = &selector {
        ensure!(
            (id.len() >= 6 && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
                || (id.len() == 32
                    && id.starts_with("porthub-")
                    && id[8..].bytes().all(|b| b.is_ascii_hexdigit())),
            "invalid registration selector"
        );
    }
    let records = list(layout)?;
    let keys: std::collections::BTreeSet<_> = records.iter().filter(|r| {
        selector.as_deref().is_none_or(|id| r.id.starts_with(id)
            || r.machine_id.starts_with(id) || format!("porthub-{}", &r.id[..24]) == id)
    }).map(|r| (r.gateway.clone(), r.machine_id.clone())).collect();
    let mut rows: Vec<_> = records
        .into_iter()
        .filter(|r| private.is_none_or(|v| r.private == v))
        .filter(|r| {
            keys.contains(&(r.gateway.clone(), r.machine_id.clone()))
        })
        .collect();
    if private.is_none() {
        if let Some(public) = rows.iter().find(|r| !r.private) {
            if rows.iter().all(|r| {
                r.id == public.id
                    || r.private && r.machine_id == public.machine_id && r.gateway == public.gateway
            }) {
                rows.retain(|r| !r.private);
            }
        }
    }
    ensure!(
        rows.len() == 1,
        "select one registration using an ID from porthub ls"
    );
    Ok(rows.remove(0))
}

pub(super) fn service_state(layout: &Layout, id: &str, state: &super::State) -> Result<()> {
    ensure!(valid_id(id), "invalid registration identity");
    let path = directory(layout)?.join(format!("{id}.json"));
    let mut record = match read(&path, caller_owned(layout)?) {
        Ok(record) => record,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(())
        }
        Err(error) => return Err(error),
    };
    record.enabled = state.enabled;
    record.active = Some(state.active);
    record.updated_at = now();
    if !state.installed {
        record.state = "uninstalled".into();
    } else if !state.active {
        record.state = "stopped".into();
    } else if matches!(record.state.as_str(), "stopped" | "status-stale") {
        record.state = "starting".into();
    }
    write(layout, &record)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(root: &Path) -> (Layout, Spec, RegistrationProfile) {
        let profile = crate::profile::Profile {
            format_version: 1,
            server: "https://gateway.example/api".into(),
            machine_id: "1234567890abcdef12345678".into(),
            token: "never-publish-this-token".into(),
            account_email: Some("person@example.com".into()),
            fallback_servers: vec!["https://origin-secret.invalid".into()],
            setup_overrides: Default::default(),
            allow_insecure_http_for_tests: false,
        };
        let profile = RegistrationProfile::Public(profile);
        let id = profile.identity();
        let layout = Layout {
            user: true,
            state: root.join("native"),
            releases: root.join("releases"),
            units: root.join("units"),
        };
        let spec = Spec {
            user: true,
            identity: id.clone(),
            service: format!("porthub-{}", &id[..24]),
            profile: layout.state.join(format!("{id}.json")),
            executable: root.join("porthub"),
            unit: root.join("unit"),
            cli: None,
        };
        (layout, spec, profile)
    }
    #[tokio::test]
    async fn only_explicit_display_fields_are_published_and_lifecycle_stays_readable() -> Result<()>
    {
        let root = tempfile::tempdir()?;
        let (layout, spec, profile) = fixture(root.path());
        install(&layout, &spec, &profile).await?;
        let raw = fs::read_to_string(directory(&layout)?.join(format!("{}.json", spec.identity)))?;
        assert!(!raw.contains("never-publish"));
        assert!(!raw.contains("origin-secret"));
        assert!(!raw.contains("token"));
        let row = select(&layout, None, None)?;
        assert_eq!(row.gateway, "https://gateway.example");
        assert_eq!(row.email, "person@example.com");
        service_state(
            &layout,
            &spec.identity,
            &super::super::State {
                installed: true,
                enabled: false,
                active: false,
            },
        )?;
        let row = select(&layout, Some(&spec.identity[..12]), None)?;
        assert_eq!(row.active, Some(false));
        assert!(!row.enabled);
        assert_eq!(row.state, "stopped");
        remove(&layout, &spec.identity)?;
        assert!(list(&layout)?.is_empty());
        Ok(())
    }
    #[tokio::test]
    async fn stale_active_metadata_is_unknown_instead_of_claiming_a_live_service() -> Result<()> {
        let root = tempfile::tempdir()?;
        let (layout, spec, profile) = fixture(root.path());
        install(&layout, &spec, &profile).await?;
        let mut row = select(&layout, None, None)?;
        row.updated_at = now().saturating_sub(91);
        write(&layout, &row)?;
        let row = select(&layout, None, None)?;
        assert_eq!(row.active, None);
        assert_eq!(row.state, "status-stale");
        Ok(())
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_and_writable_metadata_are_rejected_without_touching_targets() -> Result<()> {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let (layout, spec, profile) = fixture(root.path());
        fs::set_permissions(outside.path(), fs::Permissions::from_mode(0o700))?;
        symlink(outside.path(), directory(&layout)?)?;
        assert!(install(&layout, &spec, &profile).await.is_err());
        assert_eq!(
            fs::metadata(outside.path())?.permissions().mode() & 0o777,
            0o700
        );
        fs::remove_file(directory(&layout)?)?;
        install(&layout, &spec, &profile).await?;
        let path = directory(&layout)?.join(format!("{}.json", spec.identity));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;
        assert!(list(&layout).is_err());
        fs::remove_file(&path)?;
        fs::write(outside.path().join("secret"), "private credential")?;
        symlink(outside.path().join("secret"), &path)?;
        assert!(list(&layout).is_err());
        Ok(())
    }
    #[tokio::test]
    async fn oversized_records_and_identity_mismatches_are_rejected() -> Result<()> {
        let root = tempfile::tempdir()?;
        let (layout, spec, profile) = fixture(root.path());
        install(&layout, &spec, &profile).await?;
        let path = directory(&layout)?.join(format!("{}.json", spec.identity));
        fs::rename(
            &path,
            directory(&layout)?.join(format!("{}.json", "a".repeat(64))),
        )?;
        assert!(list(&layout).is_err());
        fs::remove_file(directory(&layout)?.join(format!("{}.json", "a".repeat(64))))?;
        fs::write(&path, vec![b'x'; LIMIT as usize + 1])?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        }
        assert!(list(&layout)
            .unwrap_err()
            .to_string()
            .contains("size limit"));
        Ok(())
    }
    #[tokio::test]
    async fn private_pairs_are_one_default_selection_but_other_tenants_are_ambiguous() -> Result<()>
    {
        let root = tempfile::tempdir()?;
        let (layout, spec, profile) = fixture(root.path());
        install(&layout, &spec, &profile).await?;
        let public = select(&layout, None, None)?;
        let mut private = public.clone();
        private.id = "b".repeat(64);
        private.private = true;
        private.email.clear();
        write(&layout, &private)?;
        assert_eq!(select(&layout, None, None)?.id, public.id);
        assert_eq!(select(&layout, Some(&public.id[..12]), Some(true))?.id, private.id);
        assert_eq!(select(&layout, Some(&private.id[..12]), None)?.id, public.id);
        assert_eq!(
            select(&layout, Some("BBBBBB"), Some(true))?.email,
            public.email
        );
        private.id = "c".repeat(64);
        private.machine_id = "another-tenant".into();
        write(&layout, &private)?;
        assert!(select(&layout, None, None).is_err());
        assert!(select(&layout, Some("b"), None).is_err());
        assert!(
            super::super::select(&layout, Some(&spec.identity[..12])).is_err(),
            "display records must never authorize service operations"
        );
        Ok(())
    }
    #[tokio::test]
    async fn concurrent_atomic_publication_keeps_readers_on_complete_records() -> Result<()> {
        let root = tempfile::tempdir()?;
        let (layout, spec, profile) = fixture(root.path());
        install(&layout, &spec, &profile).await?;
        let mut record = select(&layout, None, None)?;
        let writer_layout = layout.clone();
        let writer = std::thread::spawn(move || -> Result<()> {
            for index in 0..200 {
                record.ports = index;
                write(&writer_layout, &record)?;
            }
            Ok(())
        });
        for _ in 0..200 {
            let row = select(&layout, None, None)?;
            assert_eq!(row.id, spec.identity);
            assert!(row.ports < 200);
        }
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("snapshot writer panicked"))??;
        Ok(())
    }
}
