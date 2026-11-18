//! Operator-published native build inputs. Separate from application uploads.
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use std::{fs::File, path::Path, sync::Arc};

const PREFIX: &str = "/native-builds/";
const TARGETS: [&str; 10] = [
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "i686-unknown-linux-musl",
    "arm-unknown-linux-musleabihf",
    "armv7-unknown-linux-musleabihf",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "i686-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
];
struct Key<'a> {
    parts: Vec<&'a str>,
    digest: Option<&'a str>,
    limit: u64,
}
fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn key(path: &str) -> Option<Key<'_>> {
    let parts: Vec<_> = path.strip_prefix(PREFIX)?.split('/').collect();
    if !hex(parts.first().copied()?, 40) {
        return None;
    }
    match parts.as_slice() {
        [_, "manifest.json"] => Some(Key {
            parts,
            digest: None,
            limit: 65536,
        }),
        [_, target, name] if TARGETS.contains(target) => {
            let digest = name.strip_suffix(".zip")?;
            if !hex(digest, 64) {
                return None;
            }
            Some(Key {
                parts,
                digest: Some(digest),
                limit: 512 * 1024 * 1024,
            })
        }
        _ => None,
    }
}

pub struct Depot {
    root: File,
    owner: u32,
    #[cfg(test)]
    fixture_writable_mount: bool,
}
impl Depot {
    pub fn new(root: &Path, owner: u32) -> anyhow::Result<Self> {
        #[cfg(unix)]
        {
            let depot = Self::open(root, owner)?;
            depot.require_read_only()?;
            Ok(depot)
        }
        #[cfg(not(unix))]
        {
            let _ = (root, owner);
            anyhow::bail!("native build depot requires Unix protected-directory support")
        }
    }
    #[cfg(unix)]
    fn protected(&self, file: &File, dir: bool, sticky_ancestor: bool) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata()?;
        let owned = m.uid() == 0 || m.uid() == self.owner;
        let mode = m.mode();
        let protected =
            mode & 0o022 == 0 || (sticky_ancestor && m.uid() == 0 && mode & 0o1000 != 0);
        if !owned || !protected || if dir { !m.is_dir() } else { !m.is_file() } {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
    #[cfg(unix)]
    fn child(&self, parent: &File, name: &std::ffi::OsStr, dir: bool) -> std::io::Result<File> {
        use std::{
            ffi::CString,
            os::{
                fd::{AsRawFd, FromRawFd},
                unix::ffi::OsStrExt,
            },
        };
        let name = CString::new(name.as_bytes()).map_err(|_| std::io::ErrorKind::InvalidInput)?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if dir { libc::O_DIRECTORY } else { 0 };
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    #[cfg(unix)]
    fn open(root: &Path, owner: u32) -> anyhow::Result<Self> {
        use std::path::Component;
        anyhow::ensure!(
            root.is_absolute() && root != Path::new("/"),
            "native build depot must be an explicit absolute directory"
        );
        let mut depot = Self {
            root: File::open("/")?,
            owner,
            #[cfg(test)]
            fixture_writable_mount: false,
        };
        let parts = root.components().collect::<Vec<_>>();
        for (i, part) in parts.iter().enumerate() {
            match part {
                Component::RootDir => {}
                Component::Normal(name) => {
                    let file = depot.child(&depot.root, name, true)?;
                    depot.protected(&file, true, i + 1 < parts.len())?;
                    depot.root = file;
                }
                _ => anyhow::bail!("invalid native build depot directory"),
            }
        }
        Ok(depot)
    }
    #[cfg(unix)]
    fn require_read_only(&self) -> anyhow::Result<()> {
        use std::os::fd::AsRawFd;
        #[cfg(test)]
        if self.fixture_writable_mount {
            return Ok(());
        }
        // A process owning the publisher files could chmod them, and root can
        // bypass DAC. Those identities require a genuinely read-only mount.
        let uid = unsafe { libc::geteuid() };
        if uid == 0 || uid == self.owner {
            let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            anyhow::ensure!(
                unsafe { libc::fstatvfs(self.root.as_raw_fd(), stat.as_mut_ptr()) } == 0,
                "cannot inspect native build depot mount"
            );
            let stat = unsafe { stat.assume_init() };
            anyhow::ensure!(
                stat.f_flag & libc::ST_RDONLY != 0,
                "publisher/API shared UID requires a read-only depot mount"
            );
        }
        let result = unsafe {
            libc::faccessat(
                self.root.as_raw_fd(),
                c".".as_ptr(),
                libc::W_OK,
                libc::AT_EACCESS,
            )
        };
        let error = std::io::Error::last_os_error().raw_os_error();
        anyhow::ensure!(result<0&&matches!(error,Some(libc::EACCES|libc::EPERM|libc::EROFS)),"native build depot must be read-only to the API process; use a separate read-only mount");
        Ok(())
    }
    #[cfg(unix)]
    fn file(&self, parts: &[&str]) -> std::io::Result<File> {
        // Keep every walk anchored to an already verified descriptor. Neither a
        // rename nor a symlink swap can redirect a later component into uploads.
        self.protected(&self.root, true, false)?;
        self.require_read_only()
            .map_err(|_| std::io::ErrorKind::PermissionDenied)?;
        let mut parent = self.root.try_clone()?;
        for (i, name) in parts.iter().enumerate() {
            let dir = i + 1 < parts.len();
            let next = self.child(&parent, std::ffi::OsStr::new(name), dir)?;
            self.protected(&next, dir, false)?;
            parent = next;
        }
        Ok(parent)
    }
    #[cfg(not(unix))]
    fn file(&self, _parts: &[&str]) -> std::io::Result<File> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}
fn failure(status: StatusCode) -> Response {
    let mut response = status.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
async fn serve(State(depot): State<Option<Arc<Depot>>>, request: Request) -> Response {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        let mut r = failure(StatusCode::METHOD_NOT_ALLOWED);
        r.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return r;
    }
    let Some(depot) = depot else {
        return failure(StatusCode::NOT_FOUND);
    };
    if request.uri().query().is_some() {
        return failure(StatusCode::NOT_FOUND);
    }
    let Some(key) = key(request.uri().path()) else {
        return failure(StatusCode::NOT_FOUND);
    };
    let parts = key.parts.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let file = match tokio::task::spawn_blocking(move || {
        depot.file(&parts.iter().map(String::as_str).collect::<Vec<_>>())
    })
    .await
    {
        Ok(Ok(file)) => file,
        _ => return failure(StatusCode::NOT_FOUND),
    };
    let length = match file.metadata() {
        Ok(m) if m.len() > 0 && m.len() <= key.limit => m.len(),
        _ => return failure(StatusCode::NOT_FOUND),
    };
    use tokio::io::AsyncReadExt;
    let body = if request.method() == Method::HEAD {
        Body::empty()
    } else {
        Body::from_stream(tokio_util::io::ReaderStream::new(
            tokio::fs::File::from_std(file).take(length),
        ))
    };
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&length.to_string()).unwrap(),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(if key.digest.is_some() {
            "application/zip"
        } else {
            "application/json"
        }),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if key.digest.is_some() {
            "public, max-age=31536000, immutable"
        } else {
            "no-store"
        }),
    );
    if let Some(digest) = key.digest {
        headers.insert(
            header::ETAG,
            HeaderValue::from_str(&format!("\"{digest}\"")).unwrap(),
        );
    }
    response
}
// Merge this router AFTER the app's session middleware has been applied: depot
// reads are public/operator-only inputs and must never renew app-user sessions.
pub fn router(depot: Option<Arc<Depot>>) -> Router {
    Router::new()
        .route("/native-builds", any(serve))
        .route("/native-builds/", any(serve))
        .route("/native-builds/{*path}", any(serve))
        .with_state(depot)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use tower::ServiceExt;
    const SOURCE: &str = "0123456789abcdef0123456789abcdef01234567";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    fn fixture() -> (tempfile::TempDir, Arc<Depot>) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut depot = Depot::open(root.path(), unsafe { libc::geteuid() }).unwrap();
        // Unit fixtures cannot mount read-only filesystems. Only this cfg(test)
        // field skips mount validation; descriptor and ownership checks remain.
        depot.fixture_writable_mount = true;
        (root, Arc::new(depot))
    }
    fn publish(root: &Path) {
        let target = root.join(SOURCE).join(TARGETS[0]);
        std::fs::create_dir_all(&target).unwrap();
        for dir in [root.join(SOURCE), target.clone()] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let manifest = root.join(SOURCE).join("manifest.json");
        let archive = target.join(format!("{DIGEST}.zip"));
        std::fs::write(&manifest, b"{\"schema_version\":1}").unwrap();
        std::fs::write(&archive, b"trusted zip bytes").unwrap();
        for file in [manifest, archive] {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
    }
    async fn request(app: Router, path: &str, method: Method) -> Response {
        app.oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    }
    #[tokio::test]
    async fn streamed_get_head_manifest_and_digest_cache_contract() {
        let (root, depot) = fixture();
        publish(root.path());
        let app = router(Some(depot));
        let path = format!("{PREFIX}{SOURCE}/{}/{DIGEST}.zip", TARGETS[0]);
        let response = request(app.clone(), &path, Method::GET).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "17");
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 64)
                .await
                .unwrap(),
            "trusted zip bytes"
        );
        let head = request(app.clone(), &path, Method::HEAD).await;
        assert_eq!(head.headers()[header::CONTENT_LENGTH], "17");
        assert!(axum::body::to_bytes(head.into_body(), 64)
            .await
            .unwrap()
            .is_empty());
        let manifest = request(
            app.clone(),
            &format!("{PREFIX}{SOURCE}/manifest.json"),
            Method::GET,
        )
        .await;
        assert_eq!(manifest.status(), StatusCode::OK);
        assert_eq!(manifest.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!manifest.headers().contains_key(header::ETAG));
        let denied = request(app, &path, Method::POST).await;
        assert_eq!(denied.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            std::fs::read(
                root.path()
                    .join(SOURCE)
                    .join(TARGETS[0])
                    .join(format!("{DIGEST}.zip"))
            )
            .unwrap(),
            b"trusted zip bytes"
        );
    }
    #[tokio::test]
    async fn strict_paths_no_listings_and_all_shipping_targets() {
        let (_, depot) = fixture();
        let app = router(Some(depot));
        for path in [
            "/native-builds",
            "/native-builds/",
            "/native-builds/../manifest.json",
            "/native-builds/%2e%2e/manifest.json",
        ] {
            assert_eq!(
                request(app.clone(), path, Method::GET).await.status(),
                StatusCode::NOT_FOUND
            );
        }
        for suffix in [
            "",
            "/",
            "/manifest.json/",
            "/%2fmanifest.json",
            "/x86_64/foo.zip",
            "/x86_64-unknown-linux-musl/../manifest.json",
            "/manifest.json?token=x",
        ] {
            assert_eq!(
                request(
                    app.clone(),
                    &format!("{PREFIX}{SOURCE}{suffix}"),
                    Method::GET
                )
                .await
                .status(),
                StatusCode::NOT_FOUND
            );
        }
        assert!(key(&format!("{PREFIX}{}/manifest.json", SOURCE.to_uppercase())).is_none());
        let targets: toml::Value =
            toml::from_str(include_str!("../../../deploy/component-platforms.toml")).unwrap();
        let mut configured = targets["targets"]
            .as_table()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        configured.sort();
        let mut allowed = TARGETS.map(str::to_string).to_vec();
        allowed.sort();
        assert_eq!(configured, allowed);
        for target in TARGETS {
            assert!(key(&format!("{PREFIX}{SOURCE}/{target}/{DIGEST}.zip")).is_some());
        }
    }
    #[tokio::test]
    async fn symlink_and_writable_component_replacement_never_escape_depot() {
        let (root, depot) = fixture();
        publish(root.path());
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("manifest.json"), b"secret").unwrap();
        let source = root.path().join(SOURCE);
        std::fs::rename(&source, root.path().join("retired")).unwrap();
        symlink(outside.path(), &source).unwrap();
        let app = router(Some(depot));
        let path = format!("{PREFIX}{SOURCE}/manifest.json");
        assert_eq!(
            request(app.clone(), &path, Method::GET).await.status(),
            StatusCode::NOT_FOUND
        );
        std::fs::remove_file(&source).unwrap();
        std::fs::rename(root.path().join("retired"), &source).unwrap();
        let manifest = source.join("manifest.json");
        std::fs::remove_file(&manifest).unwrap();
        symlink(outside.path().join("manifest.json"), &manifest).unwrap();
        assert_eq!(
            request(app.clone(), &path, Method::GET).await.status(),
            StatusCode::NOT_FOUND
        );
        std::fs::remove_file(&manifest).unwrap();
        std::fs::write(&manifest, b"{}").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            request(app, &path, Method::GET).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    #[tokio::test]
    async fn nonregular_files_and_oversized_manifests_fail_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let (root, depot) = fixture();
        publish(root.path());
        let manifest = root.path().join(SOURCE).join("manifest.json");
        std::fs::remove_file(&manifest).unwrap();
        let c = std::ffi::CString::new(manifest.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let app = router(Some(depot));
        let path = format!("{PREFIX}{SOURCE}/manifest.json");
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            request(app.clone(), &path, Method::GET),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        std::fs::remove_file(&manifest).unwrap();
        std::fs::write(&manifest, vec![b'x'; 65537]).unwrap();
        std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            request(app, &path, Method::GET).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    #[test]
    fn actual_configuration_rejects_api_writable_and_symlink_roots() {
        let (root, _) = fixture();
        assert!(Depot::new(root.path(), unsafe { libc::geteuid() }).is_err());
        let alias = root.path().with_extension("link");
        symlink(root.path(), &alias).unwrap();
        assert!(Depot::open(&alias, unsafe { libc::geteuid() }).is_err());
        std::fs::remove_file(alias).unwrap();
    }
    #[tokio::test]
    async fn full_app_depot_does_not_enter_authenticated_session_writes() {
        let (root, depot) = fixture();
        publish(root.path());
        let client =
            mongodb::Client::with_uri_str("mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=2000")
                .await
                .unwrap();
        let mut app = crate::App::new(
            crate::Config::default(),
            client.database("unused_depot_no_operations"),
        );
        app.native_build_depot = Some(depot);
        let req = Request::builder()
            .uri(format!("{PREFIX}{SOURCE}/manifest.json"))
            .header(header::COOKIE, "porthub_session=fixture-session")
            .body(Body::empty())
            .unwrap();
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            crate::router(Arc::new(app)).oneshot(req),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
}
