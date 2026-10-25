use anyhow::{ensure, Context, Result};
use axum::{
    body::{to_bytes, Body},
    http::{HeaderMap, Request, StatusCode},
    Router,
};
use mongodb::{
    bson::{doc, oid::ObjectId, Document},
    Client, Database,
};
use porthub_api::{config::Config, domain::machine_client, App};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

#[test]
fn configuration_digest_preserves_original_ascii_json_contract() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/client-version-vectors.json")).unwrap();
    for case in fixtures.as_array().unwrap() {
        let machine: Document = serde_json::from_value(case["machine"].clone()).unwrap();
        let connections: Vec<Document> =
            serde_json::from_value(case["connections"].clone()).unwrap();
        assert_eq!(
            machine_client::version(&machine, &connections),
            case["digest"].as_str().unwrap()
        );
        let mut dated = connections.clone();
        for connection in &mut dated {
            let text = connection.get_str("updated_at").unwrap();
            let millis = chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S%.f")
                .unwrap()
                .and_utc()
                .timestamp_millis();
            connection.insert("updated_at", mongodb::bson::DateTime::from_millis(millis));
        }
        assert_eq!(
            machine_client::version(&machine, &dated),
            case["digest"].as_str().unwrap()
        );
    }
}

struct Case {
    app: Arc<App>,
    router: Router,
    db: Database,
    id: ObjectId,
}
impl Case {
    async fn new() -> Result<Self> {
        let client = Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;
        let db = client.database(&format!(
            "porthub_client_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let app = Arc::new(App::new(
            Config {
                public_base_url: "https://hub.example.invalid".into(),
                client_version: "native-release".into(),
                long_poll_timeout: Duration::from_secs(2),
                ..Config::default()
            },
            db.clone(),
        ));
        let id = ObjectId::new();
        let owner = ObjectId::new();
        db.collection::<Document>("machines").insert_one(doc! {"_id":id,"user_id":owner,"name":"Luna","token":"machine-secret",
            "enabled":true,"hostname_override":"fixed-host","client_update_request_id":"update-1","client_update_target_version":"native-release"}).await?;
        db.collection::<Document>("users")
            .insert_one(doc! {"_id":owner,"email":"nitin@example.invalid","username":"nitin@example.invalid"})
            .await?;
        db.collection::<Document>("connections").insert_many([
            doc! {"_id":ObjectId::new(),"machine_id":id,"internal_ip":"::1","internal_port":8080,"external_port":33126,"enabled":true,"service_name":"Files"},
            doc! {"_id":ObjectId::new(),"machine_id":id,"internal_ip":"127.0.0.1","internal_port":8081,"external_port":33127,"enabled":false},
        ]).await?;
        db.collection::<Document>("private_peers")
            .insert_one(doc! {"_id":format!("{}:{}",owner.to_hex(),id.to_hex()),"workspace_id":owner,"machine_id":id,"owner_id":owner,"ip":"10.203.0.7","enabled":true})
            .await?;
        let router = porthub_api::router(app.clone());
        Ok(Self {
            app,
            router,
            db,
            id,
        })
    }
    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Value,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>)> {
        self.call_accept(method, path, body, None).await
    }
    async fn call_accept(
        &self,
        method: &str,
        path: &str,
        body: Value,
        accept: Option<&str>,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>)> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "hub.example.invalid")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", "198.51.100.9, 127.0.0.1")
            .header("content-type", "application/json");
        if let Some(accept) = accept {
            request = request.header("accept", accept);
        }
        let response = self
            .router
            .clone()
            .oneshot(request.body(Body::from(body.to_string()))?)
            .await?;
        Ok((
            response.status(),
            response.headers().clone(),
            to_bytes(response.into_body(), 4 * 1024 * 1024)
                .await?
                .to_vec(),
        ))
    }
    fn query(&self) -> String {
        format!("machine_id={}&token=machine-secret", self.id)
    }
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn client_identity_returns_the_authenticated_machine_account_email() -> Result<()> {
    let case = Case::new().await?;
    let result: Result<()> = async {
        let (status, _, bytes) = case
            .call(
                "POST",
                "/api/machines/client/identity",
                json!({"machine_id":case.id.to_hex(),"token":"machine-secret"}),
            )
            .await?;
        ensure!(status == StatusCode::OK);
        let body: Value = serde_json::from_slice(&bytes)?;
        ensure!(body["account_email"] == "nitin@example.invalid");

        let (status, _, _) = case
            .call(
                "POST",
                "/api/machines/client/identity",
                json!({"machine_id":case.id.to_hex(),"token":"wrong"}),
            )
            .await?;
        ensure!(status == StatusCode::UNAUTHORIZED);
        case.db.drop().await?;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = case.db.drop().await;
    }
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn pending_private_install_negotiates_native_ticket_json() -> Result<()> {
    let case = Case::new().await?;
    let result: Result<()> = async {
        let (status, headers, bytes) = case
            .call_accept(
                "POST",
                "/api/machines/client/private-install",
                json!({"machine_id":case.id.to_hex(),"token":"machine-secret"}),
                Some("application/vnd.porthub.private-install+json"),
            )
            .await?;
        ensure!(status == StatusCode::OK);
        ensure!(headers["cache-control"] == "no-store");
        ensure!(headers["content-type"]
            .to_str()?
            .starts_with("application/json"));
        let body: Value = serde_json::from_slice(&bytes)?;
        let data = &body["data"];
        ensure!(data["format_version"] == 1);
        ensure!(data["server"] == "https://hub.example.invalid");
        let peer_id = data["peer_id"].as_str().context("native peer ID missing")?;
        let (workspace, machine) = peer_id.split_once(':').context("invalid peer ID")?;
        ensure!(machine == case.id.to_hex());
        ensure!(data["workspace"] == workspace);
        let ticket = data["ticket"].as_str().context("native ticket missing")?;
        let (status, _, bytes) = case
            .call(
                "POST",
                "/api/access/private/bootstrap",
                json!({"ticket":ticket}),
            )
            .await?;
        ensure!(status == StatusCode::OK);
        let credentials: Value = serde_json::from_slice(&bytes)?;
        ensure!(credentials["peer_id"] == data["peer_id"]);
        ensure!(credentials["workspace"] == data["workspace"]);
        Ok(())
    }
    .await;
    let cleanup = case.db.drop().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn pending_private_install_returns_a_single_use_native_enrollment_script() -> Result<()> {
    let case = Case::new().await?;
    let result: Result<()> = async {
        let body = json!({"machine_id":case.id.to_hex(),"token":"machine-secret"});
        let (status, headers, bytes) = case
            .call("POST", "/api/machines/client/private-install", body.clone())
            .await?;
        ensure!(
            status == StatusCode::OK,
            "private install returned {status}"
        );
        ensure!(headers["cache-control"] == "no-store");
        ensure!(headers["content-type"].to_str()?.starts_with("text/plain"));
        let script = String::from_utf8(bytes)?;
        ensure!(script.contains("https://hub.example.invalid"));
        ensure!(!script.contains("__PRIVATE_SERVER__"));
        ensure!(!script.contains("__PRIVATE_TICKET__"));
        let ticket = script
            .lines()
            .find_map(|line| line.strip_prefix("TICKET="))
            .context("installer script did not contain its ticket")?;
        ensure!(!ticket.is_empty());

        let (status, _, response) = case
            .call(
                "POST",
                "/api/access/private/bootstrap",
                json!({"ticket":ticket}),
            )
            .await?;
        ensure!(status == StatusCode::OK, "bootstrap returned {status}");
        let credentials: Value = serde_json::from_slice(&response)?;
        ensure!(credentials["token"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));

        let (status, _, _) = case
            .call("POST", "/api/machines/client/private-install", body)
            .await?;
        ensure!(status == StatusCode::NO_CONTENT);
        Ok(())
    }
    .await;
    let cleanup = case.db.drop().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn session_sync_and_files_preserve_updates_overrides_authentication_and_deletion(
) -> Result<()> {
    let case = Case::new().await?;
    let credentials = json!({"machine_id":case.id.to_hex(),"token":"machine-secret","hostname":" client-host ","local_ip":" 192.168.0.7 ","client_version":"older"});
    let (status, headers, body) = case
        .call("POST", "/api/machines/client/auth", credentials.clone())
        .await?;
    ensure!(
        status == StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    ensure!(
        headers["x-porthub-observed-ip"] == "198.51.100.9"
            && headers["x-porthub-private-ips"] == "10.203.0.7"
    );
    ensure!(headers["x-porthub-client-update-requested"] == "true");
    let response: Value = serde_json::from_slice(&body)?;
    ensure!(response["data"]["machine"]["hostname"] == "fixed-host");
    ensure!(response["data"]["machine"]["client_hostname"] == "client-host");
    ensure!(response["data"]["machine"]["connection_status"] == "online");
    let bundle = &response["data"]["config"];
    ensure!(
        bundle["connections"]
            .as_array()
            .context("connections")?
            .len()
            == 2
    );
    let file = bundle["files"]["client.toml"].as_str().context("file")?;
    ensure!(file.contains("wss://hub.example.invalid/api/tunnel") && file.contains("[::1]:8080"));
    ensure!(!file.contains("8081"));
    let parsed: toml::Value = toml::from_str(file)?;
    ensure!(
        parsed["client"]["fallback_addrs"][0].as_str()
            == Some("http://hub.example.invalid/api/tunnel")
    );
    let endpoint = response["data"]["endpoints"]["config_toml"]
        .as_str()
        .context("endpoint")?;
    ensure!(endpoint.contains(&case.query()));
    let config_path = format!("/api/machines/client/config.toml?{}", case.query());
    let (status, headers, raw) = case.call("GET", &config_path, Value::Null).await?;
    ensure!(
        status == StatusCode::OK
            && headers["x-porthub-config-version"]
                == bundle["version"].as_str().context("version")?
    );
    ensure!(raw == file.as_bytes());
    let override_path=format!("/api/machines/client/config?{}&public_base_url=https%3A%2F%2Foverride.invalid%3A8443&service_domain=files.invalid",case.query());
    let (_, _, raw) = case.call("GET", &override_path, Value::Null).await?;
    let override_bundle: Value = serde_json::from_slice(&raw)?;
    ensure!(override_bundle["data"]["service_domain"] == "files.invalid");
    ensure!(override_bundle["data"]["files"]["client.toml"]
        .as_str()
        .context("override file")?
        .contains("wss://override.invalid:8443/api/tunnel"));
    let mut installed = credentials.clone();
    installed["client_version"] = json!("native-release");
    let (_, headers, _) = case
        .call("POST", "/api/machines/client/sync", installed.clone())
        .await?;
    ensure!(
        headers["x-porthub-client-update-requested"] == "false"
            && !headers.contains_key("x-porthub-client-target-version")
    );
    let reconciled = case
        .db
        .collection::<Document>("machines")
        .find_one(doc! {"_id":case.id})
        .await?
        .context("reconciled machine")?;
    ensure!(reconciled.get_str("client_update_target_version")? == "");
    ensure!(reconciled.get_str("client_update_last_handled_request_id")? == "update-1");
    ensure!(reconciled.get_datetime("client_updated_at").is_ok());

    let mut handled = installed;
    handled["client_update_last_handled_request_id"] = json!("update-1");
    let (_, headers, _) = case
        .call("POST", "/api/machines/client/sync", handled)
        .await?;
    ensure!(headers["x-porthub-client-update-requested"] == "false");
    case.db
        .collection::<Document>("machines")
        .update_one(doc! {"_id":case.id}, doc! {"$set":{"enabled":false}})
        .await?;
    let (status, headers, _) = case.call("GET", &config_path, Value::Null).await?;
    ensure!(status == StatusCode::FORBIDDEN && headers["x-porthub-machine-disabled"] == "true");
    ensure!(!headers.contains_key("x-porthub-machine-deleted"));
    let mut wrong = credentials.clone();
    wrong["token"] = json!("wrong");
    let (status, headers, _) = case
        .call("POST", "/api/machines/client/auth", wrong)
        .await?;
    ensure!(status == StatusCode::GONE && headers["x-porthub-machine-deleted"] == "true");
    case.db
        .collection::<Document>("machines")
        .update_one(
            doc! {"_id":case.id},
            doc! {"$set":{"deletion_pending":true}},
        )
        .await?;
    let (status, _, body) = case
        .call("POST", "/api/machines/client/deletion-ack", credentials)
        .await?;
    ensure!(
        status == StatusCode::OK
            && serde_json::from_slice::<Value>(&body)?["data"]["removed"] == true
    );
    ensure!(case
        .db
        .collection::<Document>("machines")
        .find_one(doc! {"_id":case.id})
        .await?
        .is_none());
    case.db.drop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn change_waits_wake_without_polling_and_revalidate_revoked_credentials() -> Result<()> {
    let case = Arc::new(Case::new().await?);
    let path = format!("/api/machines/client/config?{}", case.query());
    let (_, _, body) = case.call("GET", &path, Value::Null).await?;
    let bundle: Value = serde_json::from_slice(&body)?;
    let since = bundle["data"]["version"].as_str().context("version")?;
    let changes = format!(
        "/api/machines/client/changes?{}&since={since}",
        case.query()
    );
    let waiting = case.clone();
    let path = changes.clone();
    let task = tokio::spawn(async move { waiting.call("GET", &path, Value::Null).await });
    tokio::time::sleep(Duration::from_millis(80)).await;
    ensure!(!task.is_finished());
    case.db
        .collection::<Document>("connections")
        .update_one(
            doc! {"machine_id":case.id,"enabled":true},
            doc! {"$set":{"internal_port":9090}},
        )
        .await?;
    case.app.config_signals.changed(&case.id.to_hex());
    let (status, _, body) = tokio::time::timeout(Duration::from_secs(1), task).await???;
    ensure!(
        status == StatusCode::OK
            && serde_json::from_slice::<Value>(&body)?["data"]["changed"] == true
    );
    let latest: Value = serde_json::from_slice(&body)?;
    let since = latest["data"]["config"]["version"]
        .as_str()
        .context("latest")?;
    let toml_path = format!(
        "/api/machines/client/changes.toml?{}&since={since}&wait_seconds=1",
        case.query()
    );
    let (status, headers, body) = case.call("GET", &toml_path, Value::Null).await?;
    ensure!(
        status == StatusCode::NO_CONTENT
            && body.is_empty()
            && headers["x-porthub-config-version"] == since
    );
    let waiting = case.clone();
    let task = tokio::spawn(async move { waiting.call("GET", &toml_path, Value::Null).await });
    tokio::time::sleep(Duration::from_millis(80)).await;
    case.db
        .collection::<Document>("machines")
        .update_one(doc! {"_id":case.id}, doc! {"$set":{"enabled":false}})
        .await?;
    case.app.config_signals.changed(&case.id.to_hex());
    let (status, headers, _) = tokio::time::timeout(Duration::from_secs(1), task).await???;
    ensure!(status == StatusCode::FORBIDDEN && headers["x-porthub-machine-disabled"] == "true");
    let (status, _, body) = case
        .call("GET", "/api/machines/client/config", Value::Null)
        .await?;
    ensure!(status == StatusCode::UNPROCESSABLE_ENTITY);
    ensure!(
        serde_json::from_slice::<Value>(&body)?["detail"][0]["loc"]
            == json!(["query", "machine_id"])
    );
    case.db.drop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn owner_update_request_wakes_an_idle_agent_without_changing_its_service_digest() -> Result<()>
{
    use mongodb::bson::{Bson, DateTime};
    let case = Arc::new(Case::new().await?);
    let record = case
        .app
        .collection("machines")
        .find_one(doc! {"_id":case.id})
        .await?
        .context("machine")?;
    let owner = record.get_object_id("user_id")?;
    let foreign = ObjectId::new();
    for (id, token) in [(owner, "owner-session"), (foreign, "foreign-session")] {
        case.app
            .collection("users")
            .insert_one(doc! {"_id":id,"username":format!("{id}@example.invalid")})
            .await?;
        case.app.collection("user_sessions").insert_one(doc! {"_id":token,"user_id":id.to_hex(),"revoked_at":Bson::Null,
            "renewed_at":DateTime::now(),"expires_at":DateTime::from_millis(DateTime::now().timestamp_millis()+60_000)}).await?;
    }
    async fn update(case: &Case, cookie: &str) -> Result<axum::response::Response> {
        Ok(case
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/machines/request-client-update")
                    .header("host", "hub.example.invalid")
                    .header("content-type", "application/json")
                    .header("cookie", cookie)
                    .body(Body::from(json!({"data_id":case.id.to_hex()}).to_string()))?,
            )
            .await?)
    }
    ensure!(update(&case, "").await?.status() == StatusCode::BAD_REQUEST);
    ensure!(
        update(&case, "porthub_session=foreign-session")
            .await?
            .status()
            == StatusCode::BAD_REQUEST
    );
    let (_, _, body) = case
        .call(
            "GET",
            &format!("/api/machines/client/config?{}", case.query()),
            Value::Null,
        )
        .await?;
    let current: Value = serde_json::from_slice(&body)?;
    let version = current["data"]["version"]
        .as_str()
        .context("version")?
        .to_owned();
    let changes = format!(
        "/api/machines/client/changes.toml?{}&since={version}",
        case.query()
    );
    let waiting = case.clone();
    let task = tokio::spawn(async move { waiting.call("GET", &changes, Value::Null).await });
    tokio::time::sleep(Duration::from_millis(80)).await;
    ensure!(!task.is_finished());
    let response = update(&case, "porthub_session=owner-session").await?;
    ensure!(response.status() == StatusCode::OK);
    let response: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?;
    let request = response["data"]["client_update_request_id"]
        .as_str()
        .context("update request")?;
    ensure!(request.len() == 16 && request != "update-1");
    let (status, headers, body) = tokio::time::timeout(Duration::from_secs(1), task).await???;
    ensure!(status == StatusCode::NO_CONTENT && body.is_empty());
    ensure!(
        headers["x-porthub-config-version"] == version
            && headers["x-porthub-client-update-request-id"] == request
    );
    ensure!(
        headers["x-porthub-client-target-version"] == "native-release"
            && headers["x-porthub-client-update-requested"] == "true"
    );
    case.db.drop().await?;
    Ok(())
}
