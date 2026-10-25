use anyhow::{ensure, Result};
use axum::{
    body::{to_bytes, Body},
    http::{HeaderMap, Method, Request, StatusCode},
};
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{
    artifacts::{self, Catalog, TARGETS},
    config::Config,
};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use tower::ServiceExt;
mod support;
use support::Case;
fn error(error: porthub_api::error::ApiError) -> anyhow::Error {
    anyhow::anyhow!("{}", error.detail)
}
async fn publish(root: &Path, target: &str, bytes: &[u8], version: &str) -> Result<()> {
    let file = format!(
        "porthub-{target}{}",
        if target.starts_with("windows_") {
            ".exe"
        } else {
            ""
        }
    );
    tokio::fs::write(root.join(&file), bytes).await?;
    tokio::fs::write(root.join(format!("{file}.version")), format!("{version}\n")).await?;
    tokio::fs::write(
        root.join(format!("{file}.sha256")),
        format!("{:x}  {file}\n", Sha256::digest(bytes)),
    )
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn public_download_catalog_and_assets_work_without_machine_credentials() -> Result<()> {
    let bundle = tempfile::tempdir()?;
    publish(bundle.path(), "x86_64", b"public-release-bytes", "1.3.0").await?;
    let case = Case::new(Config {
        client_binary_dir: Some(bundle.path().into()),
        public_base_url: "https://porthub.example".into(),
        ..Config::default()
    })
    .await?;
    let result: Result<()> = async {
        let (status, _, catalog) = case
            .call(
                "GET",
                "/api/downloads/porthub",
                "",
                serde_json::Value::Null,
                &[],
            )
            .await?;
        ensure!(status == StatusCode::OK, "public catalog returned {status}");
        ensure!(catalog["data"]
            .as_array()
            .is_some_and(|items| items.len() == 1));
        ensure!(catalog["data"][0]["version"] == "1.3.0");
        ensure!(
            catalog["data"][0]["url"] == "https://porthub.example/api/downloads/porthub/x86_64"
        );

        let request = Request::get("/api/downloads/porthub/x86_64")
            .header("host", "porthub.example")
            .body(Body::empty())?;
        let response = case.router.clone().oneshot(request).await?;
        ensure!(response.status() == StatusCode::OK);
        ensure!(response.headers()["content-disposition"] == "attachment; filename=\"porthub\"");
        ensure!(response.headers()["x-porthub-version"] == "1.3.0");
        ensure!(to_bytes(response.into_body(), 1024).await? == b"public-release-bytes"[..]);

        let request = Request::get("/api/downloads/porthub/x86_64")
            .header("host", "porthub.example")
            .header("range", "bytes=2-4")
            .body(Body::empty())?;
        let response = case.router.clone().oneshot(request).await?;
        ensure!(response.status() == StatusCode::PARTIAL_CONTENT);
        ensure!(to_bytes(response.into_body(), 1024).await? == b"bli"[..]);

        let response = case
            .router
            .clone()
            .oneshot(Request::get("/api/downloads/porthub/unknown").body(Body::empty())?)
            .await?;
        ensure!(response.status() == StatusCode::NOT_FOUND);
        Ok(())
    }
    .await;
    let cleanup = case.db.drop().await;
    result?;
    cleanup?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires isolated MongoDB and PORTHUB_TEST_AGENT_EXECUTABLE"]
async fn native_updater_downloads_verifies_and_executes_the_actual_api_published_release(
) -> Result<()> {
    use porthub_agent::{control::Control, profile::Profile, update};
    use tokio_util::sync::CancellationToken;
    let executable = std::env::var_os("PORTHUB_TEST_AGENT_EXECUTABLE")
        .ok_or_else(|| anyhow::anyhow!("current native agent executable required"))?;
    let bytes = tokio::fs::read(executable).await?;
    let target = update::native_target()?;
    let bundle = tempfile::tempdir()?;
    publish(bundle.path(), target, &bytes, porthub_agent::VERSION).await?;
    let case = Case::new(Config {
        client_binary_dir: Some(bundle.path().into()),
        // The authenticated catalog advertises this authority. The downloader
        // must reconstruct URLs from its own enrolled control authorities.
        public_base_url: "https://unconfigured.invalid".into(),
        ..Config::default()
    })
    .await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let router = case.router.clone();
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let result = async {
        let id = ObjectId::new();
        let owner = ObjectId::new();
        let token = "native-stage-fixture-token";
        case.app
            .collection("machines")
            .insert_one(doc! {"_id":id,"user_id":owner,"token":token,"enabled":true})
            .await?;
        let control = Control::new(Profile {
            format_version: 1,
            server: base,
            machine_id: id.to_hex(),
            token: token.into(),
            account_email: None,
            setup_overrides: Default::default(),
            fallback_servers: Vec::new(),
            allow_insecure_http_for_tests: true,
        })?;
        let cancel = CancellationToken::new();
        let release = update::discover(&control, target, &cancel).await?;
        use std::os::unix::fs::PermissionsExt;
        let staging = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let staged = update::stage(&control, &release, staging.path(), &cancel).await?;
        ensure!(std::fs::read(&staged.executable)? == bytes);
        staged.verify_executable(&cancel).await?;
        let mut mismatch = staged.release.clone();
        mismatch.version = "different-native-version".into();
        let mismatch = update::Staged {
            release: mismatch,
            executable: staged.executable.clone(),
        };
        ensure!(mismatch.verify_executable(&cancel).await.is_err());
        // A later edit to the staged file must fail before execution and must
        // not publish another hash directory from the altered bytes.
        tokio::fs::write(&staged.executable, b"tampered staged executable").await?;
        ensure!(staged.verify_executable(&cancel).await.is_err());
        ensure!(std::fs::read_dir(staging.path())?.count() == 1);
        anyhow::Ok(())
    }
    .await;
    server.abort();
    case.db.drop().await?;
    result
}
#[test]
fn native_targets_preserve_architectures_and_legacy_x86_alias_keeps_its_original_meaning(
) -> Result<()> {
    for (target, _, _) in TARGETS {
        ensure!(artifacts::normalize(target, false).map_err(error)? == *target);
    }
    for (alias, target) in [
        ("amd64", "x86_64"),
        ("aarch64", "arm64"),
        ("darwin_amd64", "darwin_x86_64"),
        ("arm", "armhf"),
        ("windows_amd64", "windows_x86_64"),
        ("win32", "windows_x86"),
        ("i686", "x86"),
    ] {
        ensure!(artifacts::normalize(alias, false).map_err(error)? == target);
    }
    ensure!(artifacts::normalize("x86", true).map_err(error)? == "x86_64");
    ensure!(artifacts::normalize("x86", false).map_err(error)? == "x86");
    for hostile in [
        "../x86_64",
        "x86_64/../../secret",
        "x86_64\0",
        "windows_x86_64.exe",
        "unbuilt",
    ] {
        ensure!(
            artifacts::normalize(hostile, false).err().unwrap().status == StatusCode::NOT_FOUND
        );
    }
    Ok(())
}
#[tokio::test]
async fn opened_artifacts_survive_atomic_replacement_and_hash_cache_detects_changed_files(
) -> Result<()> {
    let dir = tempfile::tempdir()?;
    publish(dir.path(), "x86_64", b"old immutable release", "v1").await?;
    let catalog = Catalog::new(Some(dir.path().into()));
    let old = catalog.get("x86_64").await.map_err(error)?;
    let old_hash = old.release.sha256.clone();
    tokio::fs::write(dir.path().join("replacement"), b"replacement version two").await?;
    tokio::fs::rename(
        dir.path().join("replacement"),
        dir.path().join("porthub-x86_64"),
    )
    .await?;
    tokio::fs::remove_file(dir.path().join("porthub-x86_64.sha256")).await?;
    tokio::fs::write(dir.path().join("porthub-x86_64.version"), "v2").await?;
    let response = old
        .response(&Method::GET, &HeaderMap::new(), false)
        .await
        .map_err(error)?;
    ensure!(response.headers()["x-porthub-agent-sha256"] == old_hash);
    ensure!(to_bytes(response.into_body(), 1024).await?.as_ref() == b"old immutable release");
    let new = catalog.get("x86_64").await.map_err(error)?;
    ensure!(new.release.sha256 != old_hash && new.release.version == "v2");
    let first = new.release.sha256;
    publish(
        dir.path(),
        "x86_64",
        b"in-place replacement with different length",
        "v3",
    )
    .await?;
    ensure!(catalog.get("x86_64").await.map_err(error)?.release.sha256 != first);
    Ok(())
}
#[tokio::test]
async fn release_metadata_fails_closed_for_missing_version_bad_digest_and_special_files(
) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let catalog = Catalog::new(Some(dir.path().into()));
    ensure!(catalog.get("x86_64").await.err().unwrap().status == StatusCode::NOT_FOUND);
    tokio::fs::write(dir.path().join("porthub-x86_64"), b"binary").await?;
    ensure!(catalog.get("x86_64").await.err().unwrap().status == StatusCode::SERVICE_UNAVAILABLE);
    publish(dir.path(), "x86_64", b"binary", "v1").await?;
    for value in [
        "wrong digest",
        &"a".repeat(600),
        "0000000000000000000000000000000000000000000000000000000000000000",
    ] {
        tokio::fs::write(dir.path().join("porthub-x86_64.sha256"), value).await?;
        ensure!(
            catalog.get("x86_64").await.err().unwrap().status == StatusCode::SERVICE_UNAVAILABLE
        );
    }
    tokio::fs::remove_file(dir.path().join("porthub-x86_64.sha256")).await?;
    for version in ["", "v1\ninjected-header", "../v1", &"a".repeat(129)] {
        tokio::fs::write(dir.path().join("porthub-x86_64.version"), version).await?;
        ensure!(
            catalog.get("x86_64").await.err().unwrap().status == StatusCode::SERVICE_UNAVAILABLE
        );
    }
    #[cfg(unix)]
    {
        use std::{
            ffi::CString,
            os::unix::{ffi::OsStrExt, fs::symlink},
        };
        let outside = tempfile::NamedTempFile::new()?;
        std::fs::write(outside.path(), "private contents")?;
        tokio::fs::remove_file(dir.path().join("porthub-x86_64.version")).await?;
        symlink(outside.path(), dir.path().join("porthub-x86_64.version"))?;
        let failed = catalog.get("x86_64").await.err().unwrap();
        ensure!(
            failed.status == StatusCode::SERVICE_UNAVAILABLE
                && !failed.detail.to_string().contains("private contents")
        );
        tokio::fs::remove_file(dir.path().join("porthub-x86_64")).await?;
        symlink(outside.path(), dir.path().join("porthub-x86_64"))?;
        ensure!(catalog.get("x86_64").await.err().unwrap().status == StatusCode::NOT_FOUND);
        tokio::fs::remove_file(dir.path().join("porthub-x86_64")).await?;
        let fifo = CString::new(dir.path().join("porthub-x86_64").as_os_str().as_bytes())?;
        ensure!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) } == 0);
        let result = tokio::time::timeout(Duration::from_secs(1), catalog.get("x86_64")).await?;
        ensure!(result.err().unwrap().status == StatusCode::NOT_FOUND);
    }
    Ok(())
}
#[tokio::test]
async fn downloads_support_resume_preconditions_head_and_safe_range_fallbacks() -> Result<()> {
    let dir = tempfile::tempdir()?;
    publish(dir.path(), "x86_64", b"0123456789", "v1").await?;
    let catalog = Catalog::new(Some(dir.path().into()));
    let hash = format!("{:x}", Sha256::digest(b"0123456789"));
    let etag = format!("\"{hash}\"");
    for (method, fields, status, expected) in [
        (
            Method::GET,
            vec![],
            StatusCode::OK,
            b"0123456789".as_slice(),
        ),
        (
            Method::HEAD,
            vec![("range", "bytes=3-5".to_owned())],
            StatusCode::PARTIAL_CONTENT,
            b"",
        ),
        (
            Method::GET,
            vec![("range", "bytes=3-5".to_owned())],
            StatusCode::PARTIAL_CONTENT,
            b"345",
        ),
        (
            Method::GET,
            vec![("range", "bytes=8-99".to_owned())],
            StatusCode::PARTIAL_CONTENT,
            b"89",
        ),
        (
            Method::GET,
            vec![("range", "bytes=-2".to_owned())],
            StatusCode::PARTIAL_CONTENT,
            b"89",
        ),
        (
            Method::GET,
            vec![("range", "bytes=8-".to_owned())],
            StatusCode::PARTIAL_CONTENT,
            b"89",
        ),
        (
            Method::GET,
            vec![("range", "bytes=10-".to_owned())],
            StatusCode::RANGE_NOT_SATISFIABLE,
            b"",
        ),
        (
            Method::GET,
            vec![("range", "bytes=-0".to_owned())],
            StatusCode::RANGE_NOT_SATISFIABLE,
            b"",
        ),
        (
            Method::GET,
            vec![("range", "bytes=oops".to_owned())],
            StatusCode::RANGE_NOT_SATISFIABLE,
            b"",
        ),
        (
            Method::GET,
            vec![("range", "items=1-2".to_owned())],
            StatusCode::OK,
            b"0123456789",
        ),
        (
            Method::GET,
            vec![("range", "bytes=0-1,8-9".to_owned())],
            StatusCode::OK,
            b"0123456789",
        ),
        (
            Method::GET,
            vec![
                ("range", "bytes=3-5".to_owned()),
                ("if-range", "\"changed\"".to_owned()),
            ],
            StatusCode::OK,
            b"0123456789",
        ),
        (
            Method::GET,
            vec![
                ("range", "bytes=3-5".to_owned()),
                ("if-range", etag.clone()),
            ],
            StatusCode::PARTIAL_CONTENT,
            b"345",
        ),
        (
            Method::GET,
            vec![("if-none-match", format!("W/{etag}"))],
            StatusCode::NOT_MODIFIED,
            b"",
        ),
        (
            Method::GET,
            vec![("if-match", "\"wrong\"".to_owned())],
            StatusCode::PRECONDITION_FAILED,
            b"",
        ),
        (
            Method::GET,
            vec![("if-match", format!("W/{etag}"))],
            StatusCode::PRECONDITION_FAILED,
            b"",
        ),
    ] {
        let mut headers = HeaderMap::new();
        for (key, value) in fields {
            headers.insert(
                axum::http::HeaderName::from_bytes(key.as_bytes())?,
                value.parse()?,
            );
        }
        let response = catalog
            .get("x86_64")
            .await
            .map_err(error)?
            .response(&method, &headers, false)
            .await
            .map_err(error)?;
        ensure!(
            response.status() == status,
            "download status differs for {headers:?}"
        );
        ensure!(
            response.headers()["etag"] == etag && response.headers()["cache-control"] == "no-store"
        );
        if status == StatusCode::RANGE_NOT_SATISFIABLE {
            ensure!(response.headers()["content-range"] == "bytes */10");
        }
        ensure!(to_bytes(response.into_body(), 1024).await?.as_ref() == expected);
    }
    let original = catalog
        .get("x86_64")
        .await
        .map_err(error)?
        .response(&Method::HEAD, &HeaderMap::new(), true)
        .await
        .map_err(error)?;
    ensure!(original.headers()["content-disposition"] == "attachment; filename=\"rathole\"");
    ensure!(
        original.headers()["x-porthub-rathole-target"] == "x86_64"
            && original.headers()["x-porthub-rathole-release"] == "v1"
    );
    for (key, status) in [
        ("if-modified-since", StatusCode::NOT_MODIFIED),
        ("if-unmodified-since", StatusCode::OK),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_bytes(key.as_bytes())?,
            original.headers()["last-modified"].clone(),
        );
        ensure!(
            catalog
                .get("x86_64")
                .await
                .map_err(error)?
                .response(&Method::GET, &headers, false)
                .await
                .map_err(error)?
                .status()
                == status
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn native_release_routes_authenticate_before_target_resolution_and_advertise_only_available_platforms(
) -> Result<()> {
    let dir = tempfile::tempdir()?;
    publish(dir.path(), "x86_64", b"native-linux", "v1").await?;
    publish(dir.path(), "windows_arm64", b"native-windows", "v2").await?;
    let case = Case::new(Config {
        client_binary_dir: Some(dir.path().into()),
        public_base_url: "https://porthub.example/base".into(),
        ..Config::default()
    })
    .await?;
    let result = async {
        let id = ObjectId::new();
        let (owner, cookie) = case.user("release-owner@example.invalid", "user").await?;
        let token = "release-auth-token";
        case.app
            .collection("machines")
            .insert_one(doc! {"_id":id,"user_id":owner,"token":token})
            .await?;
        for (path, expected) in [
            (
                "/api/machines/bad/token/downloads/agent/x86_64".into(),
                StatusCode::BAD_REQUEST,
            ),
            (
                format!("/api/machines/{id}/wrong/downloads/agent/invalid"),
                StatusCode::GONE,
            ),
            (
                format!("/api/machines/{id}/{token}/downloads/agent/invalid"),
                StatusCode::NOT_FOUND,
            ),
            (
                format!("/api/machines/{id}/{token}/downloads/agent/darwin_arm64"),
                StatusCode::NOT_FOUND,
            ),
        ] {
            let response = case
                .router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("cookie", &cookie)
                        .body(Body::empty())?,
                )
                .await?;
            ensure!(response.status() == expected);
        }
        let manifest = case
            .status(
                "GET",
                &format!("/api/machines/{id}/{token}/downloads/releases"),
                "",
                serde_json::Value::Null,
                StatusCode::OK,
            )
            .await?;
        ensure!(manifest["format_version"] == 1 && manifest["machine_id"] == id.to_hex());
        ensure!(
            manifest["releases"].as_array().unwrap().len() == 2
                && manifest["missing_targets"].as_array().unwrap().len() == TARGETS.len() - 2
        );
        ensure!(
            manifest["releases"][0]["url"]
                == format!(
                    "https://porthub.example/base/api/machines/{id}/{token}/downloads/agent/x86_64"
                )
        );
        let windows = case
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/machines/{id}/{token}/downloads/agent/windows_arm64"
                    ))
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(
            windows.status() == StatusCode::OK
                && windows.headers()["content-disposition"]
                    == "attachment; filename=\"porthub-windows_arm64.exe\""
        );
        for (field, value, status) in [
            ("enabled", false, StatusCode::FORBIDDEN),
            ("deletion_pending", true, StatusCode::GONE),
        ] {
            case.app
                .collection("machines")
                .update_one(doc! {"_id":id}, doc! {"$set":{field:value}})
                .await?;
            let response = case
                .router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/machines/{id}/{token}/downloads/releases"))
                        .body(Body::empty())?,
                )
                .await?;
            ensure!(response.status() == status);
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB and PORTHUB_TEST_AGENT_EXECUTABLE"]
async fn actual_native_get_downloads_the_authenticated_release_in_parallel_and_verifies_integrity(
) -> Result<()> {
    let executable = std::env::var("PORTHUB_TEST_AGENT_EXECUTABLE")?;
    let dir = tempfile::tempdir()?;
    let payload: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let hash = format!("{:x}", Sha256::digest(&payload));
    publish(dir.path(), "x86_64", &payload, "integration-release").await?;
    let case = Case::new(Config {
        client_binary_dir: Some(dir.path().into()),
        ..Config::default()
    })
    .await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let router = case.router.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let result = async {
        let id = ObjectId::new();
        case.app
            .collection("machines")
            .insert_one(doc! {"_id":id,"user_id":ObjectId::new(),"token":"download-token"})
            .await?;
        let target = dir.path().join("download");
        let expected = hash.clone();
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(executable)
                .args([
                    "get",
                    &format!(
                        "http://{address}/api/machines/{id}/download-token/downloads/agent/x86_64"
                    ),
                    "--connections",
                    "4",
                    "--segment-size",
                    "65536",
                    "--sha256",
                    &expected,
                    "--dir",
                ])
                .arg(&target)
                .output()
        })
        .await??;
        ensure!(
            output.status.success(),
            "native agent could not download its release"
        );
        // The agent honors the API's stable attachment filename.
        let bytes = tokio::fs::read(dir.path().join("download/porthub-x86_64")).await?;
        ensure!(format!("{:x}", Sha256::digest(bytes)) == hash);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    case.app.realtime.close().await;
    server.abort();
    case.db.drop().await?;
    result
}
