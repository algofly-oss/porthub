#![cfg(windows)]
//! Filesystem/ACL enrollment checks use an isolated ProgramData namespace. They
//! never install agent services or edit the real environment registry key.
//! The privileged network probe creates and removes its own temporary adapter.
use anyhow::{ensure, Result};
use porthub_agent::{bootstrap, profile::Profile};
use std::{ffi::OsString, path::Path};
struct ProgramData(Option<OsString>);
impl Drop for ProgramData {
    fn drop(&mut self) {
        if let Some(original) = &self.0 {
            std::env::set_var("ProgramData", original);
        } else {
            std::env::remove_var("ProgramData");
        }
    }
}
#[test]
#[ignore = "requires an Administrator token on native Windows"]
fn bootstrap_saves_protected_credentials_and_preserves_existing_identity() -> Result<()> {
    porthub_agent::service::require_administrator()?;
    let root = tempfile::tempdir()?;
    let _restore = ProgramData(std::env::var_os("ProgramData"));
    std::env::set_var("ProgramData", root.path());
    let profile = Profile {
        format_version: 1,
        server: "https://gateway.example".into(),
        machine_id: "111111111111111111111111".into(),
        token: "fixture-only-not-a-real-credential".into(),
        account_email: None,
        fallback_servers: vec![],
        setup_overrides: Default::default(),
        allow_insecure_http_for_tests: false,
    };
    let protected = root
        .path()
        .join("PortHub/native/enrollments/bootstrap.json");
    bootstrap::save(profile.clone(), &protected)?;
    let saved = Profile::load(&protected)?;
    ensure!(saved.machine_id == profile.machine_id && saved.token == profile.token);
    ensure!(!format!("{saved:?}").contains(&profile.token));
    assert_private_acl(&protected)?;
    let mut different = profile.clone();
    different.machine_id = "222222222222222222222222".into();
    ensure!(bootstrap::save(different, &protected).is_err());
    ensure!(Profile::load(&protected)?.token == profile.token);
    let outside = root.path().join("unprotected.json");
    ensure!(bootstrap::save(profile.clone(), &outside).is_err() && !outside.exists());
    let mut renewed = profile;
    renewed.token = "renewed-fixture-only".into();
    bootstrap::save(renewed.clone(), &protected)?;
    ensure!(Profile::load(&protected)?.token == renewed.token);
    assert_private_acl(&protected)?;
    Ok(())
}
fn assert_private_acl(path: &Path) -> Result<()> {
    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT},
            GetAce, ACCESS_ALLOWED_ACE, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        },
    };
    let wide: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        let mut owner = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        ensure!(
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor
            ) == 0
        );
        struct Free(windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);
        impl Drop for Free {
            fn drop(&mut self) {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
        let _free = Free(descriptor);
        ensure!(
            !owner.is_null() && !dacl.is_null() && (*dacl).AceCount == 2,
            "credential file must grant only SYSTEM and Administrators"
        );
        let mut principals = Vec::new();
        for index in 0..(*dacl).AceCount {
            let mut pointer = ptr::null_mut();
            ensure!(GetAce(dacl, index as u32, &mut pointer) != 0);
            let ace = &*pointer.cast::<ACCESS_ALLOWED_ACE>();
            ensure!(ace.Header.AceType == 0);
            let mut sid = ptr::null_mut();
            ensure!(
                ConvertSidToStringSidW((&ace.SidStart as *const u32).cast_mut().cast(), &mut sid)
                    != 0
            );
            let mut length = 0;
            while *sid.add(length) != 0 {
                length += 1;
            }
            principals.push(String::from_utf16_lossy(std::slice::from_raw_parts(
                sid, length,
            )));
            LocalFree(sid.cast());
        }
        principals.sort();
        ensure!(principals == ["S-1-5-18", "S-1-5-32-544"]);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires an Administrator token on native Windows"]
async fn private_enrollment_protects_credentials_and_rejects_unmanaged_destinations_before_claiming() -> Result<()> {
    use axum::{routing::post, Json, Router};
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    use porthub_agent::private_profile::{self, Source};
    porthub_agent::service::require_administrator()?;
    let root = tempfile::tempdir()?;
    let _restore = ProgramData(std::env::var_os("ProgramData"));
    std::env::set_var("ProgramData", root.path());
    let native = root.path().join("PortHub/native/private");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let server = format!("http://{}", listener.local_addr()?);
    let claims = Arc::new(AtomicUsize::new(0));
    let observed = claims.clone();
    let app = Router::new().route("/api/access/private/bootstrap", post(move || {
        let claims = observed.clone(); async move {
            claims.fetch_add(1, Ordering::SeqCst);
            Json(serde_json::json!({"peer_id":"0123456789abcdef01234567:abcdef0123456789abcdef01","workspace":"0123456789abcdef01234567","token":"fixture-private-credential-0123456789abcdef"}))
        }
    }));
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let cancel = tokio_util::sync::CancellationToken::new();
    let ticket = "fixture-private-ticket-0123456789abcdef";
    let outside = root.path().join("unprotected.json");
    ensure!(private_profile::enroll(Source::Ticket{server:&server,ticket},Some(&outside),false,true,&cancel).await.is_err());
    ensure!(!outside.exists() && claims.load(Ordering::SeqCst)==0);
    let path = native.join("private.json");
    private_profile::enroll(Source::Ticket{server:&server,ticket},Some(&path),false,true,&cancel).await?;
    assert_private_acl(&path)?;
    ensure!(private_profile::Profile::load(&path)?.workspace=="0123456789abcdef01234567");
    ensure!(private_profile::enroll(Source::Ticket{server:&server,ticket},Some(&path),false,true,&cancel).await.is_err());
    ensure!(claims.load(Ordering::SeqCst)==1);
    task.abort();
    Ok(())
}
