use anyhow::{ensure, Context, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, Bson};
use porthub_api::config::Config;
use serde_json::{json, Value};
use std::time::Duration;
mod support;
use support::Case;

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn concurrent_legacy_heartbeat_cannot_replace_a_reported_release() -> Result<()> {
    use porthub_api::domain::machine_client;
    let case = Case::new(Config::default()).await?;
    let result = async {
        let id = ObjectId::new();
        let stale =
            doc! {"_id":id,"token":"test-token","enabled":true,"client_version":"legacy-one"};
        case.app.collection("machines").insert_one(&stale).await?;
        case.app
            .collection("machines")
            .update_one(doc! {"_id":id}, doc! {"$set":{"client_version":"1.4.3"}})
            .await?;
        let heartbeat = |version: &str| machine_client::Sync {
            hostname: String::new(),
            local_ip: String::new(),
            public_ip: String::new(),
            version: version.into(),
            client_os: String::new(),
            client_arch: String::new(),
            client_os_id: String::new(),
            client_os_name: String::new(),
            handled: String::new(),
            native_update_protocol: false,
        };
        let headers = axum::http::HeaderMap::new();
        let error = machine_client::sync(&case.app, &stale, heartbeat("legacy-two"), &headers)
            .await
            .unwrap_err();
        ensure!(error.status == StatusCode::CONFLICT);
        let current = case
            .app
            .collection("machines")
            .find_one(doc! {"_id":id})
            .await?
            .unwrap();
        ensure!(current.get_str("client_version")? == "1.4.3");
        let legacy = machine_client::sync(&case.app, &current, heartbeat("legacy-two"), &headers)
            .await
            .map_err(|error| anyhow::anyhow!("{}", error.detail))?;
        ensure!(legacy.get_str("client_version")? == "1.4.3");
        let updated = machine_client::sync(&case.app, &legacy, heartbeat("1.4.4"), &headers)
            .await
            .map_err(|error| anyhow::anyhow!("{}", error.detail))?;
        ensure!(updated.get_str("client_version")? == "1.4.4");
        Ok(())
    }
    .await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn edits_preserve_ownership_optional_fields_aliases_and_enable_controls() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("gateway.toml");
    let case = Case::new(Config {
        gateway_config_path: Some(path.clone()),
        ..Config::default()
    })
    .await?;
    let result = async {
        let (owner,cookie) = case.user("edit-owner@test.invalid","user").await?;
        let (other,other_cookie) = case.user("edit-other@test.invalid","user").await?;
        let machine = ObjectId::new();
        let (group,foreign_group) = (ObjectId::new(),ObjectId::new());
        case.app.collection("machine_groups").insert_many([
            doc! {"_id":group,"user_id":owner},doc! {"_id":foreign_group,"user_id":other}]).await?;
        let original = doc! {"_id":machine,"user_id":owner,"name":"Luna","aliases":["old"],"hostname":"old-host",
            "hostname_override":"fixed-host","client_hostname":"runtime-host","enabled":true,"group_id":group,
            "token":"private-token","client_setup_public_base_url":"https://original.invalid","client_setup_service_domain":"original.invalid",
            "client_setup_rathole_server_address":"old.invalid:443","private_owner_revoked":true,"telegram_alerts_excluded":false};
        case.app.collection("machines").insert_one(&original).await?;
        case.app.collection("connections").insert_one(doc! {"_id":ObjectId::new(),"machine_id":machine,"external_port":39119,"internal_port":8080,"enabled":true}).await?;
        let body = json!({"data_id":machine.to_hex(),"name":"New, NEW, Work, work, Desk","hostname":"  ",
            "enabled":false,"is_active":true,"group_ids":[group.to_hex(),group.to_hex(),""],"telegram_alerts_excluded":true,
            "client_setup_public_base_url":" https://replacement.invalid/// ","client_setup_rathole_server_address":" new.invalid:443 ",
            "client_setup_service_domain":" private.invalid ","token":"injected","user_id":other.to_hex(),"private_owner_revoked":false});
        for credential in ["",other_cookie.as_str()] {
            case.status("PUT","/api/machines/update",credential,body.clone(),StatusCode::BAD_REQUEST).await?;
        }
        for (field,value) in [
            ("group_ids",json!([foreign_group.to_hex()])),
            ("group_ids",json!(["not-an-id"])),
            ("name",json!(" , , ")),
            ("client_setup_public_base_url",json!("ftp://bad.invalid")),
            ("client_setup_service_domain",json!("é".repeat(256))),
            ("client_setup_rathole_server_address",json!("é".repeat(256))),
            ("client_setup_public_base_url",json!(format!("https://{}", "x".repeat(513)))),
        ] {
            let mut invalid = body.clone(); invalid[field] = value;
            case.status("PUT","/api/machines/update",&cookie,invalid,StatusCode::BAD_REQUEST).await?;
            ensure!(case.app.collection("machines").find_one(doc! {"_id":machine}).await?.unwrap()==original);
        }
        let missing = case.status("PUT","/api/machines/update",&cookie,json!({"data_id":machine.to_hex()}),StatusCode::UNPROCESSABLE_ENTITY).await?;
        ensure!(missing["detail"][0]["loc"] == json!(["body","name"]));
        let response = case.status("PUT","/api/machines/update",&cookie,body,StatusCode::OK).await?;
        ensure!(response["msg"] == "Machine updated successfully");
        ensure!(response["data"]["name"] == "New" && response["data"]["aliases"] == json!(["Work","Desk"]));
        ensure!(response["data"]["hostname"] == "runtime-host" && response["data"]["enabled"] == false);
        ensure!(response["data"]["group_ids"] == json!([group.to_hex()]));
        ensure!(response["data"]["client_setup_public_base_url"] == "https://replacement.invalid");
        let saved = case.app.collection("machines").find_one(doc! {"_id":machine}).await?.unwrap();
        ensure!(!saved.contains_key("group_id") && saved.get_str("token")? == "private-token" && saved.get_object_id("user_id")? == owner);
        ensure!(saved.get_bool("private_owner_revoked")? && saved.get_bool("telegram_alerts_excluded")?);
        ensure!(!std::fs::read_to_string(&path)?.contains("39119"));
        case.status("POST","/api/machines/client/sync","",json!({"machine_id":machine.to_hex(),"token":"private-token"}),StatusCode::FORBIDDEN).await?;
        // Null enabled defers to the old is_active alias. Omitted groups and
        // setup fields retain values; null alerts retain the saved setting.
        let enabled = case.status("PUT","/api/machines/update",&cookie,json!({"data_id":machine.to_hex(),"name":"New",
            "enabled":null,"is_active":true,"telegram_alerts_excluded":null}),StatusCode::OK).await?;
        ensure!(enabled["data"]["enabled"] == true && enabled["data"]["telegram_alerts_excluded"] == true);
        ensure!(enabled["data"]["group_ids"] == json!([group.to_hex()]));
        ensure!(enabled["data"]["client_setup_public_base_url"] == "https://replacement.invalid");
        ensure!(std::fs::read_to_string(&path)?.contains("39119"));
        let cleared = case.status("PUT","/api/machines/update",&cookie,json!({"data_id":machine.to_hex(),"name":"New","hostname":" new-fixed ",
            "group_ids":null,"client_setup_public_base_url":null,"client_setup_rathole_server_address":null,
            "client_setup_service_domain":null}),StatusCode::OK).await?;
        ensure!(cleared["data"]["hostname"] == "new-fixed" && cleared["data"]["group_ids"] == json!([]));
        for field in ["client_setup_public_base_url","client_setup_rathole_server_address","client_setup_service_domain"] {
            ensure!(cleared["data"][field] == "");
        }
        ensure!(cleared["data"]["enabled"] == true);
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn failed_publication_restores_edits_but_preserves_concurrent_sync() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("gateway.toml");
    // A directory at the destination forces atomic publication to fail.
    std::fs::create_dir(&path)?;
    let case = Case::new(Config {
        gateway_config_path: Some(path),
        ..Config::default()
    })
    .await?;
    let result = async {
        let (owner,cookie) = case.user("rollback-owner@test.invalid","user").await?;
        let machine = ObjectId::new();
        let group = ObjectId::new();
        let original = doc! {"_id":machine,"user_id":owner,"name":"$Original","aliases":["$old"],"hostname":"old-runtime",
            "hostname_override":"$fixed","client_hostname":"old-runtime","token":"private-token","enabled":true,
            "group_id":group,"client_setup_public_base_url":Bson::Null,"telegram_alerts_excluded":true};
        case.app.collection("machines").insert_one(&original).await?;
        let publication = case.app.gateway_config_lock.lock().await;
        let edit = case.call("PUT","/api/machines/update",&cookie,json!({"data_id":machine.to_hex(),"name":"$Pending, $alias",
            "hostname":"","group_ids":[],"client_setup_public_base_url":"https://pending.invalid",
            "client_setup_service_domain":"pending.invalid","telegram_alerts_excluded":false}),&[]);
        tokio::pin!(edit);
        ensure!(tokio::time::timeout(Duration::from_millis(100),edit.as_mut()).await.is_err());
        let pending = case.app.collection("machines").find_one(doc! {"_id":machine}).await?.unwrap();
        ensure!(pending.get_str("name")? == "$Pending");
        case.status("POST","/api/machines/client/sync","",json!({"machine_id":machine.to_hex(),"token":"private-token",
            "hostname":"fresh-runtime","local_ip":"192.168.7.8","client_version":"test-release"}),StatusCode::OK).await?;
        case.status("POST","/api/machines/request-client-update",&cookie,json!({"data_id":machine.to_hex()}),StatusCode::OK).await?;
        let concurrent = case.app.collection("machines").find_one(doc! {"_id":machine}).await?.unwrap();
        let mut expected = original.clone();
        for key in ["hostname","client_hostname","local_ip","public_ip","auth_required","last_seen_at","client_version",
            "client_update_request_id","client_update_target_version","client_update_requested_at","updated_at"] {
            if let Some(value) = concurrent.get(key) { expected.insert(key,value.clone()); }
        }
        drop(publication);
        let (status,_,_) = edit.await?;
        ensure!(status == StatusCode::INTERNAL_SERVER_ERROR);
        let restored = case.app.collection("machines").find_one(doc! {"_id":machine}).await?.unwrap();
        ensure!(restored == expected,"rollback overwrote concurrent fields or lost original values: {restored:?}");
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[test]
fn setup_url_validation_retains_original_permissive_authority_and_unicode_limits() -> Result<()> {
    use porthub_api::domain::machines;
    for (value, expected) in [
        (None, ""),
        (Some(" https://host.invalid/// "), "https://host.invalid"),
        (Some("HTTP://h:80"), "HTTP://h:80"),
        (Some("http://user@"), "http://user@"),
        (Some("http://a\tb/path"), "http://a\tb/path"),
    ] {
        let actual = machines::public_base(value).map_err(|e| anyhow::anyhow!("{}", e.detail))?;
        ensure!(actual == expected);
    }
    for value in [
        "http:/nohost",
        "host.invalid",
        "ftp://host",
        "https:///path",
        "http://?query",
    ] {
        ensure!(machines::public_base(Some(value)).is_err());
    }
    ensure!(machines::optional_text(Some(&"é".repeat(255)), "Service domain", 255).is_ok());
    let error = machines::optional_text(Some(&"é".repeat(256)), "Service domain", 255)
        .err()
        .context("length error")?;
    ensure!(error.detail == "Service domain must be 255 characters or fewer");
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn enable_changes_sync_only_owned_ports_and_recover_partial_firewall_failure() -> Result<()> {
    use axum::{
        extract::{Path, State},
        http::HeaderMap,
        routing::put,
        Json, Router,
    };
    use std::{
        collections::BTreeMap,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
    };
    #[derive(Default)]
    struct Firewall {
        policies: Mutex<BTreeMap<i64, Value>>,
        fail: Mutex<Option<(String, i64)>>,
        gateway: std::path::PathBuf,
        expect_closed: AtomicBool,
    }
    async fn request(
        state: Arc<Firewall>,
        port: i64,
        headers: HeaderMap,
        body: Option<Value>,
    ) -> (StatusCode, Json<Value>) {
        if headers
            .get("x-api-key")
            .and_then(|value| value.to_str().ok())
            != Some("machine-edit-test-key")
        {
            return (StatusCode::FORBIDDEN, Json(json!({"detail":"Forbidden"})));
        }
        let method = if body.is_some() { "put" } else { "delete" };
        if method == "put" && state.expect_closed.load(Ordering::SeqCst) {
            assert!(
                !std::fs::read_to_string(&state.gateway)
                    .unwrap()
                    .contains("39119"),
                "listener was published before its restrictions were restored"
            );
        }
        let mut fail = state.fail.lock().unwrap();
        if fail
            .as_ref()
            .is_some_and(|(operation, target)| operation == method && *target == port)
        {
            fail.take();
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"detail":"test failure"})),
            );
        }
        drop(fail);
        match body {
            Some(policy) => {
                state.policies.lock().unwrap().insert(port, policy);
            }
            None => {
                state.policies.lock().unwrap().remove(&port);
            }
        }
        (StatusCode::OK, Json(json!({"data":{}})))
    }
    async fn save(
        State(state): State<Arc<Firewall>>,
        Path(port): Path<i64>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        request(state, port, headers, Some(body)).await
    }
    async fn remove(
        State(state): State<Arc<Firewall>>,
        Path(port): Path<i64>,
        headers: HeaderMap,
    ) -> (StatusCode, Json<Value>) {
        request(state, port, headers, None).await
    }
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("gateway.toml");
    let socket = temporary.path().join("firewall.sock");
    let edge_socket = temporary.path().join("edge.sock");
    let (edge, _edge_lease) = porthub_runtime::socket::bind(&edge_socket).await?;
    let ack = Router::new().route(
        "/apply",
        axum::routing::post(
            |Json(snapshot): Json<porthub_runtime::gateway_apply::Snapshot>| async move {
                Json(snapshot)
            },
        ),
    );
    let control = tokio::spawn(async move { axum::serve(edge, ack).await });
    let (listener, _lease) = porthub_runtime::socket::bind(&socket).await?;
    let firewall = Arc::new(Firewall {
        gateway: path.clone(),
        ..Default::default()
    });
    let mock = Router::new()
        .route("/api/ports/{port}/policy", put(save).delete(remove))
        .with_state(firewall.clone());
    let serving = tokio::spawn(async move { axum::serve(listener, mock).await });
    let case = Case::new(Config {
        gateway_config_path: Some(path.clone()),
        firewall_socket: Some(socket),
        edge_socket: Some(edge_socket),
        firewall_api_key: "machine-edit-test-key".into(),
        ..Config::default()
    })
    .await?;
    let result = async {
        let (owner,cookie) = case.user("firewall-edit@test.invalid","user").await?;
        let machine = ObjectId::new();
        case.app.collection("machines").insert_one(doc! {"_id":machine,"user_id":owner,"name":"Files","token":"private-token","enabled":true}).await?;
        // An inactive mapping must not publish enabled listeners before the
        // restrictions for later active rows have been installed.
        case.app.collection("connections").insert_one(doc! {"_id":ObjectId::new(),"machine_id":machine,
            "external_port":39118,"internal_port":8080,"enabled":false}).await?;
        case.app.collection("connections").insert_many([39119,39120].map(|port|doc! {"_id":ObjectId::new(),"machine_id":machine,
            "external_port":port,"internal_port":8080,"enabled":true,"firewall":{"is_public":false,"allowed_ips":["203.0.113.9"]}})).await?;
        let policy = json!({"is_public":false,"allowed_ips":["203.0.113.9"]});
        let foreign = json!({"is_public":false,"allowed_ips":["198.51.100.4"]});
        firewall.policies.lock().unwrap().extend([(39119,policy.clone()),(39120,policy.clone()),(39999,foreign.clone())]);
        let edit = |enabled|json!({"data_id":machine.to_hex(),"name":"Files","enabled":enabled});
        case.status("PUT","/api/machines/update",&cookie,edit(false),StatusCode::OK).await?;
        ensure!(firewall.policies.lock().unwrap().clone() == BTreeMap::from([(39999,foreign.clone())]));
        ensure!(!std::fs::read_to_string(&path)?.contains("39119"));
        firewall.expect_closed.store(true,Ordering::SeqCst);
        case.status("PUT","/api/machines/update",&cookie,edit(true),StatusCode::OK).await?;
        firewall.expect_closed.store(false,Ordering::SeqCst);
        let all = BTreeMap::from([(39119,policy.clone()),(39120,policy),(39999,foreign.clone())]);
        ensure!(firewall.policies.lock().unwrap().clone() == all);
        ensure!(std::fs::read_to_string(&path)?.contains("39119"));
        // Force partial disable failure; rollback restores DB, gateway and both
        // restrictions, without altering an unrelated machine's port.
        *firewall.fail.lock().unwrap() = Some(("delete".into(),39120));
        firewall.expect_closed.store(true,Ordering::SeqCst);
        case.status("PUT","/api/machines/update",&cookie,edit(false),StatusCode::BAD_GATEWAY).await?;
        firewall.expect_closed.store(false,Ordering::SeqCst);
        ensure!(case.app.collection("machines").find_one(doc! {"_id":machine}).await?.unwrap().get_bool("enabled")?);
        ensure!(firewall.policies.lock().unwrap().clone() == all);
        ensure!(std::fs::read_to_string(&path)?.contains("39119"));
        case.status("PUT","/api/machines/update",&cookie,edit(false),StatusCode::OK).await?;
        *firewall.fail.lock().unwrap() = Some(("put".into(),39120));
        firewall.expect_closed.store(true,Ordering::SeqCst);
        case.status("PUT","/api/machines/update",&cookie,edit(true),StatusCode::BAD_GATEWAY).await?;
        ensure!(!case.app.collection("machines").find_one(doc! {"_id":machine}).await?.unwrap().get_bool("enabled")?);
        ensure!(firewall.policies.lock().unwrap().clone() == BTreeMap::from([(39999,foreign)]));
        ensure!(!std::fs::read_to_string(&path)?.contains("39119"));
        Ok(())
    }.await;
    serving.abort();
    control.abort();
    let _ = control.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn agent_distribution_metadata_is_bounded_and_survives_older_heartbeats() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (owner, _) = case.user("distribution@test.invalid", "user").await?;
        let id = ObjectId::new();
        case.app.collection("machines").insert_one(doc! {"_id":id,"user_id":owner,"name":"distribution-test","enabled":true,"token":"distribution-fixture-token"}).await?;
        let base = json!({"machine_id":id.to_hex(),"token":"distribution-fixture-token","client_version":"1.5.2","client_os":"linux","client_arch":"x86_64"});
        let mut report = base.clone();
        report["client_os_id"] = json!("ubuntu");
        report["client_os_name"] = json!("Ubuntu 24.04.3 LTS");
        case.status("POST", "/api/machines/client/sync", "", report.clone(), StatusCode::OK).await?;
        // An older agent in a paired registration must not erase useful metadata.
        case.status("POST", "/api/machines/client/sync", "", base, StatusCode::OK).await?;
        let stored = case.app.collection("machines").find_one(doc! {"_id":id}).await?.unwrap();
        let view = porthub_api::domain::inventory::machine(&case.app, &stored);
        ensure!(view["client_os_id"] == "ubuntu" && view["client_os_name"] == "Ubuntu 24.04.3 LTS");
        report["client_os_name"] = json!("x".repeat(161));
        case.status("POST", "/api/machines/client/sync", "", report, StatusCode::UNPROCESSABLE_ENTITY).await?;
        Ok::<_, anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}
