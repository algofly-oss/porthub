use anyhow::{ensure, Result};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use porthub_api::{config::Config, enrollment_ticket::digest};
use serde_json::{json, Value};
use std::time::Duration;
use tower::ServiceExt;
mod support;
use support::Case;
const TOKEN: &str = "native-bootstrap-machine-token-secret";
async fn command(case: &Case, id: ObjectId, cookie: &str, query: &str) -> Result<Value> {
    case.status(
        "GET",
        &format!("/api/machines/command/{id}{query}"),
        cookie,
        Value::Null,
        StatusCode::OK,
    )
    .await
}
fn code(value: &Value) -> Result<String> {
    let url = url::Url::parse(value["data"]["bootstrap_url"].as_str().unwrap())?;
    Ok(url.path_segments().unwrap().next_back().unwrap().to_owned())
}
async fn enrollment(case: &Case, code: &str, expected: StatusCode) -> Result<Value> {
    let (status, headers, body) = case
        .call(
            "GET",
            &format!("/install/{code}"),
            "",
            Value::Null,
            &[("accept", "application/json")],
        )
        .await?;
    ensure!(status == expected);
    if expected == StatusCode::OK {
        ensure!(
            headers["cache-control"] == "no-store" && headers["referrer-policy"] == "no-referrer"
        );
    }
    Ok(body)
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn unchanged_bootstrap_previews_reuse_code_and_different_cached_previews_remain_independent(
) -> Result<()> {
    let case = Case::new(Config {
        public_base_url: "https://hub.example".into(),
        service_domain: "phub".into(),
        tunnel_fallback_base_urls: vec![
            "https://fallback.example".into(),
            "https://fallback.example/".into(),
            "http://insecure.example".into(),
        ],
        ..Config::default()
    })
    .await?;
    let result=async {
        let (owner,cookie)=case.user("bootstrap-owner@example.invalid","user").await?;
        let (_,foreign)=case.user("bootstrap-foreign@example.invalid","user").await?;let id=ObjectId::new();
        case.app.collection("machines").insert_one(doc! {"_id":id,"user_id":owner,"token":TOKEN,"name":"Native bootstrap"}).await?;
        case.status("GET",&format!("/api/machines/command/{id}"),"",Value::Null,StatusCode::BAD_REQUEST).await?;
        case.status("GET",&format!("/api/machines/command/{id}"),&foreign,Value::Null,StatusCode::BAD_REQUEST).await?;
        let first=command(&case,id,&cookie,"").await?;let ticket=code(&first)?;
        ensure!(ticket.len()==16 && ticket.bytes().all(|b|b.is_ascii_alphanumeric()));
        ensure!(!first["data"]["command"].as_str().unwrap().contains(TOKEN));
        ensure!(first["data"]["command"]==format!("curl -fsSL https://hub.example/install/{ticket} | bash"));
        ensure!(code(&command(&case,id,&cookie,"?public_base_url=https%3A%2F%2Fhub.example&service_domain=").await?)?==ticket);
        let changed=command(&case,id,&cookie,"?public_base_url=https%3A%2F%2Fnew-hub.example%2Fprefix&rathole_server_address=origin.example%3A443&service_domain=mesh.example").await?;
        let preview_ticket=code(&changed)?;
        ensure!(preview_ticket!=ticket && changed["data"]["bootstrap_url"]==format!("https://new-hub.example/prefix/install/{preview_ticket}"));
        ensure!(enrollment(&case,&ticket,StatusCode::OK).await?["profile"]["server"]=="https://hub.example");
        ensure!(code(&command(&case,id,&cookie,"").await?)?==ticket,"reverting settings must reuse a valid cached command");
        ensure!(changed["data"]["client_setup"]["defaults"]["public_base_url"]=="https://hub.example");
        ensure!(changed["data"]["client_setup"]["overrides"]["rathole_server_address"]=="origin.example:443");
        let body=enrollment(&case,&preview_ticket,StatusCode::OK).await?;
        ensure!(body["format_version"]==1 && body["profile"]["server"]=="https://new-hub.example/prefix");
        ensure!(body["profile"]["setup_overrides"]["public_base_url"]==body["profile"]["server"]);
        ensure!(body["profile"]["setup_overrides"]["service_domain"]=="mesh.example");
        ensure!(body["profile"]["fallback_servers"]==json!(["https://fallback.example"]));
        ensure!(body["profile"]["allow_insecure_http_for_tests"]==false && body["profile"]["token"]==TOKEN);
        let response=case.router.clone().oneshot(Request::builder().uri(format!("/install/{ticket}")).body(Body::empty())?).await?;
        ensure!(response.headers()["vary"]=="Accept" && response.headers()["content-type"]=="text/plain; charset=utf-8");
        let launcher=String::from_utf8(to_bytes(response.into_body(),65536).await?.to_vec())?;
        ensure!(launcher.contains("setup $porthub_bootstrap_adopt --ticket ") && launcher.contains("-e \"$porthub_bootstrap_bin_dir/porthub\"") && launcher.contains("--proto '=https'") && !launcher.contains(TOKEN));
        let mut syntax=std::process::Command::new("sh").arg("-n").stdin(std::process::Stdio::piped()).spawn()?;
        use std::io::Write;syntax.stdin.take().unwrap().write_all(launcher.as_bytes())?;ensure!(syntax.wait()?.success());
        let stored=case.app.collection("machines").find_one(doc! {"_id":id}).await?.unwrap();
        ensure!(!stored.contains_key("client_setup_public_base_url"),"preview must not change the saved machine configuration");
        Ok::<_,anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn expiry_rotation_disable_and_retirement_revoke_bootstrap_capabilities_and_old_public_codes_work(
) -> Result<()> {
    let case = Case::new(Config {
        public_base_url: "https://hub.example".into(),
        ..Config::default()
    })
    .await?;
    let result=async {
        let (owner,cookie)=case.user("bootstrap-revoke@example.invalid","user").await?;let id=ObjectId::new();
        case.app.collection("machines").insert_one(doc! {"_id":id,"user_id":owner,"token":TOKEN}).await?;
        let ticket=code(&command(&case,id,&cookie,"").await?)?;
        for bad in ["short","0123456789abcde!","aaaaaaaaaaaaaaaa"] { enrollment(&case,bad,StatusCode::FORBIDDEN).await?; }
        case.app.collection("machine_install_tickets").update_one(doc! {"ticket_hash":digest(&ticket)},doc! {"$set":{"expires_at":DateTime::from_millis(DateTime::now().timestamp_millis()-1000)}}).await?;
        enrollment(&case,&ticket,StatusCode::FORBIDDEN).await?;
        let renewed=code(&command(&case,id,&cookie,"").await?)?;ensure!(renewed!=ticket);
        enrollment(&case,&renewed,StatusCode::OK).await?;
        case.app.collection("machines").update_one(doc! {"_id":id},doc! {"$set":{"token":"rotated-bootstrap-token"}}).await?;
        enrollment(&case,&renewed,StatusCode::FORBIDDEN).await?;
        let rotated=code(&command(&case,id,&cookie,"").await?)?;ensure!(rotated!=renewed);
        case.app.collection("machines").update_one(doc! {"_id":id},doc! {"$set":{"enabled":false}}).await?;
        enrollment(&case,&rotated,StatusCode::FORBIDDEN).await?;
        case.app.collection("machines").update_one(doc! {"_id":id},doc! {"$set":{"enabled":true}}).await?;
        enrollment(&case,&rotated,StatusCode::OK).await?;
        let legacy="LegacyPublicCode";ensure!(legacy.len()==16);
        case.app.collection("machine_install_tickets").insert_one(doc! {"_id":digest(legacy),"machine_id":id,
            "token_digest":digest("rotated-bootstrap-token"),"expires_at":DateTime::from_millis(DateTime::now().timestamp_millis()+60000)}).await?;
        enrollment(&case,legacy,StatusCode::OK).await?;
        case.app.collection("machines").update_one(doc! {"_id":id},doc! {"$set":{"deletion_pending":true}}).await?;
        enrollment(&case,&rotated,StatusCode::FORBIDDEN).await?;
        case.status("GET",&format!("/api/machines/command/{id}"),&cookie,Value::Null,StatusCode::BAD_REQUEST).await?;
        Ok::<_,anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn concurrent_owner_requests_share_one_ticket_and_asset_access_requires_a_live_capability(
) -> Result<()> {
    let assets = tempfile::tempdir()?;
    tokio::fs::write(assets.path().join("porthub-x86_64"), b"native asset").await?;
    tokio::fs::write(assets.path().join("porthub-x86_64.version"), "fixture").await?;
    let case = Case::new(Config {
        client_binary_dir: Some(assets.path().into()),
        public_base_url: "https://hub.example".into(),
        ..Config::default()
    })
    .await?;
    let result = async {
        let (owner, cookie) = case
            .user("bootstrap-concurrent@example.invalid", "user")
            .await?;
        let id = ObjectId::new();
        case.app
            .collection("machines")
            .insert_one(doc! {"_id":id,"user_id":owner,"token":TOKEN})
            .await?;
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..12 {
            let app = case.app.clone();
            let cookie = cookie.clone();
            jobs.spawn(async move {
                let mut headers = axum::http::HeaderMap::new();
                headers.insert("cookie", cookie.parse().unwrap());
                porthub_api::enrollment_ticket::command(
                    &app,
                    &headers,
                    &id.to_hex(),
                    &Default::default(),
                )
                .await
                .map_err(|error| anyhow::anyhow!("{}", error.detail))
            });
        }
        let mut codes = std::collections::BTreeSet::new();
        while let Some(result) = jobs.join_next().await {
            codes.insert(code(&result??)?);
        }
        ensure!(
            codes.len() == 1
                && case
                    .app
                    .collection("machine_install_tickets")
                    .count_documents(doc! {})
                    .await?
                    == 1
        );
        let code = codes.pop_first().unwrap();
        let response = case
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/install/{code}/agent/amd64"))
                    .header("range", "bytes=0-5")
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(
            response.status() == StatusCode::PARTIAL_CONTENT
                && to_bytes(response.into_body(), 100).await?.as_ref() == b"native"
        );
        case.app
            .collection("machines")
            .update_one(doc! {"_id":id}, doc! {"$set":{"enabled":false}})
            .await?;
        let response = case
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/install/{code}/agent/amd64"))
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(response.status() == StatusCode::FORBIDDEN);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB and the rebuilt PORTHUB_TEST_AGENT_EXECUTABLE"]
async fn actual_native_setup_fetches_private_profile_and_preserves_preview_overrides_in_control_sync(
) -> Result<()> {
    let executable = std::env::var("PORTHUB_TEST_AGENT_EXECUTABLE")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let case = Case::new(Config {
        public_base_url: format!("http://{address}"),
        ..Config::default()
    })
    .await?;
    let router = case.router.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let result = async {
        let (owner, cookie) = case
            .user("bootstrap-native@example.invalid", "user")
            .await?;
        let id = ObjectId::new();
        case.app
            .collection("machines")
            .insert_one(doc! {"_id":id,"user_id":owner,"token":TOKEN})
            .await?;
        let command = command(
            &case,
            id,
            &cookie,
            "?service_domain=preview.phub&rathole_server_address=preview.example%3A443",
        )
        .await?;
        let url = command["data"]["bootstrap_url"]
            .as_str()
            .unwrap()
            .to_owned();
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let profile = directory.path().join("machine.json");
        let path = profile.clone();
        let binary = executable.clone();
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(binary)
                .args([
                    "setup",
                    "--ticket",
                    &url,
                    "--no-service",
                    "--allow-insecure-http-for-tests",
                    "--profile",
                ])
                .arg(path)
                .output()
        })
        .await??;
        ensure!(
            output.status.success(),
            "native bootstrap CLI failed: {}",
            String::from_utf8_lossy(&output.stderr).replace(TOKEN, "[redacted]")
        );
        for output in [&output.stdout, &output.stderr] {
            let output = String::from_utf8_lossy(output);
            ensure!(!output.contains(TOKEN) && !output.contains("127.0.0.1"));
        }
        let stored: Value = serde_json::from_slice(&tokio::fs::read(&profile).await?)?;
        ensure!(
            stored["machine_id"] == id.to_hex()
                && stored["setup_overrides"]["service_domain"] == "preview.phub"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(std::fs::metadata(&profile)?.permissions().mode() & 0o077 == 0);
        }
        let mut agent = tokio::process::Command::new(&executable)
            .args(["run", "--profile"])
            .arg(&profile)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if let Ok(bytes) =
                    tokio::fs::read(profile.with_file_name("machine.json.status.json")).await
                {
                    if serde_json::from_slice::<Value>(&bytes)
                        .is_ok_and(|value| value["state"] == "running")
                    {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        let cache: Value = serde_json::from_slice(
            &tokio::fs::read(profile.with_file_name("machine.json.config.json")).await?,
        )?;
        ensure!(cache["toml"]
            .as_str()
            .unwrap()
            .contains(&format!("ws://{address}/api/tunnel")));
        let machine = case
            .app
            .collection("machines")
            .find_one(doc! {"_id":id})
            .await?
            .unwrap();
        ensure!(!machine.contains_key("client_setup_service_domain"));
        agent.kill().await?;
        agent.wait().await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    case.app.realtime.close().await;
    server.abort();
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn legacy_reinstaller_authenticates_before_minting_native_capability_and_does_not_embed_permanent_credentials(
) -> Result<()> {
    let case = Case::new(Config {
        public_base_url: "https://hub.example".into(),
        ..Default::default()
    })
    .await?;
    let result=async {
        let(owner,cookie)=case.user("legacy-reinstaller@test.invalid","user").await?;let id=ObjectId::new();
        case.app.collection("machines").insert_one(doc!{"_id":id,"user_id":owner,"token":TOKEN,"name":"Legacy reinstaller","enabled":true}).await?;
        case.status("GET",&format!("/api/machines/{id}/wrong-token/install.sh"),"",Value::Null,StatusCode::FORBIDDEN).await?;
        ensure!(case.app.collection("machine_install_tickets").count_documents(doc!{}).await?==0);
        let path=format!("/api/machines/{id}/{TOKEN}/install.sh?service_domain=requested.example");
        let response=case.router.clone().oneshot(Request::builder().uri(path).header("host","hub.example").body(Body::empty())?).await?;
        ensure!(response.status()==StatusCode::OK && response.headers()["cache-control"]=="no-store" && response.headers()["referrer-policy"]=="no-referrer");
        let body=String::from_utf8(to_bytes(response.into_body(),65536).await?.to_vec())?;
        ensure!(body.starts_with("#!/bin/sh\n") && body.contains("setup $porthub_bootstrap_adopt --ticket") && body.contains("porthub_bootstrap_adopt=--adopt-existing-cli") && !body.contains(TOKEN));
        let ticket=case.app.collection("machine_install_tickets").find_one(doc!{}).await?.unwrap();
        let code=ticket.get_str("code")?;
        let incoming=enrollment(&case,code,StatusCode::OK).await?;
        ensure!(incoming["profile"]["machine_id"]==id.to_hex() && incoming["profile"]["setup_overrides"]["service_domain"]=="requested.example");
        let preview=command(&case,id,&cookie,"?service_domain=requested.example").await?;
        ensure!(preview["data"]["bootstrap_url"]==format!("https://hub.example/install/{code}"));
        let short=case.router.clone().oneshot(Request::builder().uri(format!("/api/install/{TOKEN}?service_domain=requested.example")).header("host","hub.example").body(Body::empty())?).await?;
        ensure!(short.status()==StatusCode::OK);
        let short=String::from_utf8(to_bytes(short.into_body(),65536).await?.to_vec())?;
        ensure!(short.contains(&format!("/install/{code}"))&&!short.contains(TOKEN));
        ensure!(case.app.collection("machine_install_tickets").count_documents(doc!{}).await?==1);
        case.status("GET","/api/install/invalid-token","",Value::Null,StatusCode::FORBIDDEN).await?;
        let (status,headers,incoming)=case.call("GET",&format!("/api/install/{TOKEN}?service_domain=requested.example"),"",Value::Null,&[("accept","application/json")]).await?;
        ensure!(status==StatusCode::OK && headers["vary"]=="Accept" && incoming["profile"]["machine_id"]==id.to_hex());


        case.app.collection("machines").update_one(doc!{"_id":id},doc!{"$set":{"token":"rotated-token"}}).await?;
        case.status("GET",&format!("/api/machines/{id}/{TOKEN}/install.sh"),"",Value::Null,StatusCode::FORBIDDEN).await?;
        enrollment(&case,code,StatusCode::FORBIDDEN).await?;
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}
