use anyhow::{ensure, Context, Result};
use axum::{http::StatusCode, Router};
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime};
use porthub_api::config::Config;
use serde_json::{json, Value};
use std::sync::Arc;

mod support;
use support::Case;

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn machine_membership_handles_legacy_records_ownership_and_concurrency() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (owner, cookie) = case.user("membership-owner@test.invalid", "user").await?;
        let (foreign, foreign_cookie) = case.user("membership-other@test.invalid", "user").await?;
        let machine = ObjectId::new();
        let groups = [ObjectId::new(), ObjectId::new(), ObjectId::new()];
        case.app
            .collection("machine_groups")
            .insert_many(groups.iter().enumerate().map(
                |(i, id)| doc! {"_id":id,"user_id":if i == 2 {foreign} else {owner},"name":"Group"},
            ))
            .await?;
        case.app
            .collection("machines")
            .insert_one(doc! {"_id":machine,"user_id":owner,"name":"Legacy","group_id":groups[0]})
            .await?;
        let body =
            |group: ObjectId| json!({"machine_id":machine.to_hex(),"group_id":group.to_hex()});
        for credential in ["", foreign_cookie.as_str()] {
            case.status(
                "POST",
                "/api/machines/groups/add",
                credential,
                body(groups[1]),
                StatusCode::BAD_REQUEST,
            )
            .await?;
        }
        case.status(
            "POST",
            "/api/machines/groups/add",
            &cookie,
            body(groups[2]),
            StatusCode::BAD_REQUEST,
        )
        .await?;
        let duplicate = case
            .status(
                "POST",
                "/api/machines/groups/add",
                &cookie,
                body(groups[0]),
                StatusCode::OK,
            )
            .await?;
        ensure!(duplicate["msg"] == "Machine is already in this group");
        let untouched = case
            .app
            .collection("machines")
            .find_one(doc! {"_id":machine})
            .await?
            .unwrap();
        ensure!(untouched.contains_key("group_id") && !untouched.contains_key("updated_at"));
        let (a, b) = tokio::join!(
            case.status(
                "POST",
                "/api/machines/groups/add",
                &cookie,
                body(groups[1]),
                StatusCode::OK
            ),
            case.status(
                "POST",
                "/api/machines/groups/add",
                &cookie,
                body(groups[1]),
                StatusCode::OK
            )
        );
        a?;
        b?;
        let migrated = case
            .app
            .collection("machines")
            .find_one(doc! {"_id":machine})
            .await?
            .unwrap();
        ensure!(!migrated.contains_key("group_id"));
        ensure!(
            migrated.get_array("group_ids")?
                == &vec![Bson::ObjectId(groups[0]), Bson::ObjectId(groups[1])]
        );
        case.status(
            "POST",
            "/api/machines/groups/remove",
            &cookie,
            body(groups[0]),
            StatusCode::OK,
        )
        .await?;
        case.status(
            "POST",
            "/api/machines/groups/remove",
            &cookie,
            body(groups[0]),
            StatusCode::BAD_REQUEST,
        )
        .await?;
        // A separate old scalar can coexist with an already populated array.
        case.app
            .collection("machines")
            .update_one(doc! {"_id":machine}, doc! {"$set":{"group_id":groups[0]}})
            .await?;
        let legacy_removed = case
            .status(
                "POST",
                "/api/machines/groups/remove",
                &cookie,
                body(groups[0]),
                StatusCode::OK,
            )
            .await?;
        ensure!(legacy_removed["data"]["group_ids"] == json!([groups[1].to_hex()]));
        let (add, delete) = tokio::join!(
            case.call(
                "POST",
                "/api/machines/groups/add",
                &cookie,
                body(groups[0]),
                &[]
            ),
            case.status(
                "POST",
                "/api/groups/delete",
                &cookie,
                json!({"data_id":groups[0].to_hex()}),
                StatusCode::OK
            )
        );
        ensure!([StatusCode::OK, StatusCode::BAD_REQUEST].contains(&add?.0));
        delete?;
        let final_record = case
            .app
            .collection("machines")
            .find_one(doc! {"_id":machine})
            .await?
            .unwrap();
        ensure!(!porthub_api::domain::inventory::group_ids(&final_record).contains(&groups[0]));
        Ok(())
    }
    .await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn token_rotation_revokes_credentials_and_rolls_back_failed_publication() -> Result<()> {
    use std::time::Duration;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("gateway.toml");
    let case = Case::new(Config {
        gateway_config_path: Some(path.clone()),
        long_poll_timeout: Duration::from_secs(10),
        ..Config::default()
    })
    .await?;
    let result = async {
        let (owner,cookie) = case.user("rotation-owner@test.invalid","user").await?;
        let (_,other_cookie) = case.user("rotation-other@test.invalid","user").await?;
        let machine = ObjectId::new();
        case.app.collection("machines").insert_one(doc! {"_id":machine,"user_id":owner,"name":"Rotating","token":"old-token","enabled":true,
            "log_tokens":["old-token","",17,"previous","previous","third","fourth","fifth","sixth"]}).await?;
        case.app.collection("connections").insert_one(doc! {"_id":ObjectId::new(),"machine_id":machine,"external_port":39119,"internal_port":8080,"enabled":true}).await?;
        porthub_api::generated::rebuild(&case.app).await.map_err(|_|anyhow::anyhow!("initial publication"))?;
        let body = json!({"data_id":machine.to_hex()});
        for credential in ["",other_cookie.as_str()] {
            case.status("POST","/api/machines/refresh-token",credential,body.clone(),StatusCode::BAD_REQUEST).await?;
        }
        let config = case.status("GET",&format!("/api/machines/client/config?machine_id={machine}&token=old-token"),"",Value::Null,StatusCode::OK).await?;
        let since = config["data"]["version"].as_str().context("version")?;
        let signal = case.app.config_signals.subscribe(&machine.to_hex());
        let poll_path = format!("/api/machines/client/changes?machine_id={machine}&token=old-token&since={since}");
        let poll = case.call("GET",&poll_path,"",Value::Null,&[]);
        tokio::pin!(poll);
        // Drive the HTTP request until it has registered its long-poll wait.
        ensure!(tokio::time::timeout(Duration::from_millis(100),poll.as_mut()).await.is_err());
        let notified = signal.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let rotated = case.status("POST","/api/machines/refresh-token",&cookie,body.clone(),StatusCode::OK).await?;
        tokio::time::timeout(Duration::from_secs(1),notified).await?;
        let (status,_,_) = tokio::time::timeout(Duration::from_secs(1),poll).await??;
        ensure!(status == StatusCode::GONE,"old long poll not revoked: {status}");
        let token = rotated["data"]["token"].as_str().context("new token")?;
        ensure!(token.len()==48 && token!="old-token");
        let current = case.app.collection("machines").find_one(doc! {"_id":machine}).await?.unwrap();
        ensure!(current.get_array("log_tokens")? == &vec!["old-token","previous","third","fourth","fifth"].into_iter().map(Bson::from).collect::<Vec<_>>());
        let published = std::fs::read_to_string(&path)?;
        ensure!(published.contains(token) && !published.contains("old-token"));
        case.status("GET",&format!("/api/machines/client/config?machine_id={machine}&token=old-token"),"",Value::Null,StatusCode::GONE).await?;
        case.status("GET",&format!("/api/machines/client/config?machine_id={machine}&token={token}"),"",Value::Null,StatusCode::OK).await?;
        // Simulate a failed atomic rename, without changing permissions or any
        // production resource. The complete original Mongo document must remain.
        std::fs::remove_file(&path)?;
        std::fs::create_dir(&path)?;
        case.status("POST","/api/machines/refresh-token",&cookie,body,StatusCode::INTERNAL_SERVER_ERROR).await?;
        let restored = case.app.collection("machines").find_one(doc! {"_id":machine}).await?.unwrap();
        ensure!(restored == current,"failed rotation changed machine credentials/history");
        // Pause publication after credentials change, then exercise real sync
        // and a browser update request. Recovery must not overwrite either.
        let publication = case.app.gateway_config_lock.lock().await;
        let retry_body = json!({"data_id":machine.to_hex()});
        let retry = case.call("POST","/api/machines/refresh-token",&cookie,retry_body,&[]);
        tokio::pin!(retry);
        ensure!(tokio::time::timeout(Duration::from_millis(100),retry.as_mut()).await.is_err());
        let in_flight = case.app.collection("machines").find_one(doc! {"_id":machine}).await?.unwrap();
        let in_flight_token = in_flight.get_str("token")?;
        ensure!(in_flight_token != token);
        case.status("POST","/api/machines/client/sync","",json!({"machine_id":machine.to_hex(),"token":in_flight_token,
            "hostname":"new-runtime-host","local_ip":"192.168.4.5"}),StatusCode::OK).await?;
        case.status("POST","/api/machines/request-client-update",&cookie,json!({"data_id":machine.to_hex()}),StatusCode::OK).await?;
        let mut expected = case.app.collection("machines").find_one(doc! {"_id":machine}).await?.unwrap();
        expected.insert("token",current.get("token").unwrap().clone());
        expected.insert("log_tokens",current.get("log_tokens").unwrap().clone());
        drop(publication);
        let (status,_,_) = retry.await?;
        ensure!(status == StatusCode::INTERNAL_SERVER_ERROR);
        let preserved = case.app.collection("machines").find_one(doc! {"_id":machine}).await?.unwrap();
        ensure!(preserved == expected,"token recovery overwrote concurrent runtime/update state");
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn machine_creation_enrolls_privately_and_checks_group_ownership() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("gateway.toml");
    let case = Case::new(Config {
        gateway_config_path: Some(path.clone()),
        ..Config::default()
    })
    .await?;
    let (owner, cookie) = case.user("machine-owner@example.invalid", "user").await?;
    let (other, other_cookie) = case
        .user("other-machine-owner@example.invalid", "user")
        .await?;
    let (group, foreign_group) = (ObjectId::new(), ObjectId::new());
    case.app
        .collection("machine_groups")
        .insert_many([
            doc! {"_id":group,"user_id":owner,"name":"Owned"},
            doc! {"_id":foreign_group,"user_id":other,"name":"Foreign"},
        ])
        .await?;
    let body = json!({"name":"Luna, luna, desktop, DESKTOP, lab","hostname":"  custom.local  ",
        "client_setup_public_base_url":" https://hub.example.invalid/ ",
        "group_ids":[group.to_hex(),group.to_hex(),""]});
    case.status(
        "POST",
        "/api/machines/add",
        "",
        body.clone(),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    case.status(
        "POST",
        "/api/machines/add",
        &other_cookie,
        body.clone(),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    case.status(
        "POST",
        "/api/machines/add",
        &cookie,
        json!({"name":"bad","group_ids":[foreign_group.to_hex()]}),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    ensure!(
        case.app
            .collection("machines")
            .count_documents(doc! {})
            .await?
            == 0
    );
    let response = case
        .status("POST", "/api/machines/add", &cookie, body, StatusCode::OK)
        .await?;
    let machine = &response["data"];
    ensure!(machine["name"] == "Luna" && machine["aliases"] == json!(["desktop", "lab"]));
    ensure!(
        machine["hostname"] == "custom.local" && machine["group_ids"] == json!([group.to_hex()])
    );
    let token = machine["token"].as_str().context("token")?;
    ensure!(token.len() == 48 && token.bytes().all(|b| b.is_ascii_alphanumeric()));
    let id = ObjectId::parse_str(machine["_id"].as_str().context("id")?)?;
    let peer = case
        .app
        .collection("private_peers")
        .find_one(doc! {"machine_id":id})
        .await?
        .context("default private peer")?;
    ensure!(
        peer.get_object_id("owner_id") == Ok(owner)
            && peer.get_object_id("workspace_id") == Ok(owner)
    );
    ensure!(peer.get_bool("enabled") == Ok(true));
    let ips = case
        .status(
            "GET",
            &format!("/api/machines/private-addresses/{id}"),
            &cookie,
            json!({}),
            StatusCode::OK,
        )
        .await?;
    ensure!(ips["data"] == json!([peer.get_str("ip")?]));
    let generated = std::fs::read_to_string(&path)?;
    ensure!(porthub_tunnel::gateway_config(&generated)?
        .server
        .context("server")?
        .services
        .is_empty());
    let before = case
        .app
        .collection("private_peers")
        .find_one(doc! {"machine_id":id})
        .await?;
    porthub_api::generated::initialize(&case.app)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
    ensure!(
        case.app
            .collection("private_peers")
            .find_one(doc! {"machine_id":id})
            .await?
            == before
    );
    // Exhaustion must roll back the new machine, not leave an unenrolled record.
    case.app
        .collection("private_networks")
        .insert_one(doc! {"_id":other.to_hex(),"cidr":"10.203.0.0/28"})
        .await?;
    for host in 1..=14 {
        case.app.collection("private_peers").insert_one(doc! {"_id":format!("full-{host}"),"workspace_id":other,"ip":format!("10.203.0.{host}")}).await?;
    }
    case.status(
        "POST",
        "/api/machines/add",
        &other_cookie,
        json!({"name":"exhausted"}),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    ensure!(
        case.app
            .collection("machines")
            .count_documents(doc! {})
            .await?
            == 1
    );
    case.db.drop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn enrollment_preserves_revocation_and_invited_workspaces_and_retries_collisions(
) -> Result<()> {
    use porthub_api::domain::enrollment::{ensure as enroll, Network};
    let case = Case::new(Config::default()).await?;
    let (owner, _) = case
        .user("enrollment-owner@example.invalid", "user")
        .await?;
    case.app
        .collection("private_networks")
        .insert_one(doc! {"_id":owner.to_hex(),"cidr":"10.203.0.0/28"})
        .await?;
    let mut starts = std::collections::HashMap::new();
    let (first, second) = loop {
        let id = ObjectId::new();
        let ip = Network::parse("10.203.0.0/28")
            .unwrap()
            .allocate(&id.to_hex(), &Default::default())
            .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
        if let Some(first) = starts.insert(ip, id) {
            break (first, id);
        }
    };
    let a = doc! {"_id":first,"user_id":owner};
    let b = doc! {"_id":second,"user_id":owner};
    let (left, right) = tokio::join!(enroll(&case.app, &a), enroll(&case.app, &b));
    left.map_err(|e| anyhow::anyhow!("{}", e.detail))?;
    right.map_err(|e| anyhow::anyhow!("{}", e.detail))?;
    let left = case
        .app
        .collection("private_peers")
        .find_one(doc! {"machine_id":first})
        .await?
        .context("first")?;
    let right = case
        .app
        .collection("private_peers")
        .find_one(doc! {"machine_id":second})
        .await?
        .context("second")?;
    ensure!(left.get_str("ip")? != right.get_str("ip")?);
    // A disabled invited enrollment must retain its workspace/address/state.
    case.app
        .collection("private_peers")
        .update_one(
            doc! {"_id":left.get("_id")},
            doc! {"$set":{"workspace_id":ObjectId::new(),"enabled":false}},
        )
        .await?;
    let previous = case
        .app
        .collection("private_peers")
        .find_one(doc! {"machine_id":first})
        .await?;
    enroll(&case.app, &a)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
    ensure!(
        case.app
            .collection("private_peers")
            .find_one(doc! {"machine_id":first})
            .await?
            == previous
    );
    let revoked = doc! {"_id":ObjectId::new(),"user_id":owner,"private_owner_revoked":true};
    enroll(&case.app, &revoked)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
    ensure!(
        case.app
            .collection("private_peers")
            .count_documents(doc! {})
            .await?
            == 2
    );
    case.db.drop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn native_gateway_rebuild_tracks_database_revocation_and_keeps_invalid_snapshots_unpublished(
) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("gateway.toml");
    let case = Case::new(Config {
        gateway_config_path: Some(path.clone()),
        ..Config::default()
    })
    .await?;
    let (machine, connection) = (ObjectId::new(), ObjectId::new());
    case.app
        .collection("machines")
        .insert_one(doc! {"_id":machine,"token":"original-secret","enabled":true})
        .await?;
    case.app
        .collection("connections")
        .insert_one(
            doc! {"_id":connection,"machine_id":machine,"external_port":33120,"enabled":true},
        )
        .await?;
    let rebuild = || async {
        porthub_api::generated::rebuild(&case.app)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.detail))
    };
    rebuild().await?;
    let original = std::fs::read_to_string(&path)?;
    ensure!(
        porthub_tunnel::gateway_config(&original)?
            .server
            .context("server")?
            .services
            .len()
            == 1
    );
    case.app
        .collection("machines")
        .update_one(
            doc! {"_id":machine},
            doc! {"$set":{"token":"rotated-secret"}},
        )
        .await?;
    rebuild().await?;
    let rotated = std::fs::read_to_string(&path)?;
    ensure!(!rotated.contains("original-secret") && rotated.contains("rotated-secret"));
    case.app
        .collection("connections")
        .update_one(
            doc! {"_id":connection},
            doc! {"$set":{"external_bind_ip":"invalid-address"}},
        )
        .await?;
    ensure!(rebuild().await.is_err());
    ensure!(std::fs::read_to_string(&path)? == rotated);
    case.app
        .collection("machines")
        .update_one(
            doc! {"_id":machine},
            doc! {"$set":{"deletion_pending":true}},
        )
        .await?;
    rebuild().await?;
    ensure!(
        porthub_tunnel::gateway_config(&std::fs::read_to_string(path)?)?
            .server
            .context("server")?
            .services
            .is_empty()
    );
    case.db.drop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn group_crud_preserves_ownership_and_cleans_both_membership_shapes() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let (owner, cookie) = case.user("owner@example.invalid", "user").await?;
    let (other, other_cookie) = case.user("other@example.invalid", "user").await?;
    let body = case
        .status(
            "PUT",
            "/api/groups/update",
            &cookie,
            json!({}),
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await?;
    ensure!(
        body["detail"].as_array().unwrap().len() == 2
            && body["detail"][0]["loc"] == json!(["body", "data_id"]),
        "field errors lost their declared order"
    );
    let first = case
        .status(
            "POST",
            "/api/groups/add",
            &cookie,
            json!({"name":"  Production  "}),
            StatusCode::OK,
        )
        .await?;
    let gid = first["data"]["_id"]
        .as_str()
        .context("group ID")?
        .to_owned();
    let oid = ObjectId::parse_str(&gid)?;
    ensure!(first["data"]["name"] == "Production" && first["data"]["user_id"] == owner.to_hex());
    case.status(
        "PUT",
        "/api/groups/update",
        &other_cookie,
        json!({"data_id":gid,"name":"stolen"}),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let second = case
        .status(
            "POST",
            "/api/groups/add",
            &cookie,
            json!({"name":42}),
            StatusCode::OK,
        )
        .await?;
    ensure!(second["data"]["name"] == "42");
    let list = case
        .status(
            "GET",
            "/api/groups/list",
            &cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(list["data"].as_array().unwrap().len() == 2 && list["data"][0]["_id"] == gid);
    let owned = ObjectId::new();
    let foreign = ObjectId::new();
    case.app
        .collection("machines")
        .insert_many([
            doc! {"_id":owned,"user_id":owner,"group_id":oid,"group_ids":[oid]},
            doc! {"_id":foreign,"user_id":other,"group_id":oid,"group_ids":[oid]},
        ])
        .await?;
    case.status(
        "POST",
        "/api/groups/delete",
        &cookie,
        json!({"data_id":gid}),
        StatusCode::OK,
    )
    .await?;
    let machine = case
        .app
        .collection("machines")
        .find_one(doc! {"_id":owned})
        .await?
        .unwrap();
    ensure!(!machine.contains_key("group_id") && machine.get_array("group_ids")?.is_empty());
    let machine = case
        .app
        .collection("machines")
        .find_one(doc! {"_id":foreign})
        .await?
        .unwrap();
    ensure!(
        machine.get_object_id("group_id")? == oid && machine.get_array("group_ids")?.len() == 1
    );
    case.db.drop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn invitations_enforce_roles_origins_atomic_claims_and_member_revocation() -> Result<()> {
    let case = Case::new(Config {
        signup_disabled: true,
        ..Config::default()
    })
    .await?;
    let (owner, cookie) = case.user("owner@example.invalid", "admin").await?;
    let (member, member_cookie) = case.user("member@example.invalid", "user").await?;
    let (admin, admin_cookie) = case.user("admin@example.invalid", "user").await?;
    let (foreign, _) = case.user("foreign@example.invalid", "user").await?;
    for (id, role) in [(member, "member"), (admin, "admin")] {
        case.app.collection("workspace_members").insert_one(doc! {"_id":format!("{}:{}",owner.to_hex(),id.to_hex()),"workspace_id":owner,"user_id":id,"role":role}).await?;
    }
    let endpoint = format!("/api/access/invitations?workspace={}", owner.to_hex());
    case.status(
        "POST",
        &endpoint,
        &member_cookie,
        json!({"email":"x@example.invalid"}),
        StatusCode::FORBIDDEN,
    )
    .await?;
    case.status(
        "POST",
        &endpoint,
        &admin_cookie,
        json!({"email":"x@example.invalid","role":"admin"}),
        StatusCode::FORBIDDEN,
    )
    .await?;
    let (status, _, _) = case
        .call(
            "POST",
            &endpoint,
            &cookie,
            json!({"email":"x@example.invalid"}),
            &[("origin", "https://evil.invalid")],
        )
        .await?;
    ensure!(status == StatusCode::FORBIDDEN);
    let invalid = case
        .status(
            "POST",
            &endpoint,
            &cookie,
            json!({}),
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await?;
    ensure!(
        invalid["detail"].as_array().unwrap().len() == 1,
        "missing email reported twice"
    );
    let invitation = case
        .status(
            "POST",
            &endpoint,
            &cookie,
            json!({"email":" Guest@Example.invalid "}),
            StatusCode::OK,
        )
        .await?;
    let token = invitation["token"]
        .as_str()
        .context("invite token")?
        .to_owned();
    let preview = case
        .status(
            "POST",
            "/api/access/invitations/preview",
            "",
            json!({"token":token}),
            StatusCode::OK,
        )
        .await?;
    ensure!(preview["email"] == "guest@example.invalid" && preview["role"] == "member");
    case.status("POST","/api/auth/signup","",json!({"name":"Guest","username":"wrong@example.invalid","password":"Guest-Password1!","invitation_token":token}),StatusCode::FORBIDDEN).await?;
    let(status,headers,body)=case.call("POST","/api/auth/signup","",json!({"name":"Guest","username":"guest@example.invalid","password":"Guest-Password1!","invitation_token":token}),&[]).await?;
    ensure!(
        status == StatusCode::OK && body["workspace_id"] == owner.to_hex(),
        "invited signup failed: {body}"
    );
    let guest_cookie = headers["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let guest = case
        .app
        .collection("users")
        .find_one(doc! {"username":"guest@example.invalid"})
        .await?
        .unwrap()
        .get_object_id("_id")?;
    let membership = case
        .app
        .collection("workspace_members")
        .find_one(doc! {"_id":format!("{}:{}",owner.to_hex(),guest.to_hex())})
        .await?
        .unwrap();
    ensure!(membership.get_str("role")? == "member");
    case.status(
        "POST",
        "/api/access/invitations/accept",
        &guest_cookie,
        json!({"token":token}),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let extra = case
        .status(
            "POST",
            &endpoint,
            &cookie,
            json!({"email":"guest@example.invalid","role":"admin"}),
            StatusCode::OK,
        )
        .await?;
    case.status(
        "POST",
        "/api/access/invitations/accept",
        &guest_cookie,
        json!({"token":extra["token"]}),
        StatusCode::OK,
    )
    .await?;
    let membership = case
        .app
        .collection("workspace_members")
        .find_one(doc! {"_id":format!("{}:{}",owner.to_hex(),guest.to_hex())})
        .await?
        .unwrap();
    ensure!(
        membership.get_str("role")? == "member",
        "second invitation promoted existing membership"
    );
    let concurrent = case
        .status(
            "POST",
            &endpoint,
            &cookie,
            json!({"email":"guest@example.invalid"}),
            StatusCode::OK,
        )
        .await?;
    let (left, right) = tokio::join!(
        case.call(
            "POST",
            "/api/access/invitations/accept",
            &guest_cookie,
            json!({"token":concurrent["token"]}),
            &[]
        ),
        case.call(
            "POST",
            "/api/access/invitations/accept",
            &guest_cookie,
            json!({"token":concurrent["token"]}),
            &[]
        )
    );
    let left = left?.0;
    let right = right?.0;
    ensure!(
        [left, right]
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count()
            == 1,
        "concurrent requests both claimed the same invitation"
    );
    ensure!([left, right].iter().all(|status| matches!(
        *status,
        StatusCode::OK | StatusCode::BAD_REQUEST | StatusCode::CONFLICT
    )));
    let invalidated = case
        .status(
            "POST",
            &endpoint,
            &admin_cookie,
            json!({"email":"member@example.invalid"}),
            StatusCode::OK,
        )
        .await?;
    case.app
        .collection("workspace_members")
        .delete_one(doc! {"_id":format!("{}:{}",owner.to_hex(),admin.to_hex())})
        .await?;
    case.status(
        "POST",
        "/api/access/invitations/accept",
        &member_cookie,
        json!({"token":invalidated["token"]}),
        StatusCode::FORBIDDEN,
    )
    .await?;
    let machine = ObjectId::new();
    let foreign_machine = ObjectId::new();
    let group = ObjectId::new();
    let invite_id = "pending-from-member";
    case.app
        .collection("machines")
        .insert_many([
            doc! {"_id":machine,"user_id":owner,"private_owner_id":member},
            doc! {"_id":foreign_machine,"user_id":foreign,"private_owner_id":member},
        ])
        .await?;
    case.app
        .collection("machine_groups")
        .insert_one(doc! {"_id":group,"user_id":owner,"user_ids":[member,guest]})
        .await?;
    case.app
        .collection("workspace_invites")
        .insert_one(
            doc! {"_id":invite_id,"user_id":owner,"created_by":member,"consumed_at":Bson::Null},
        )
        .await?;
    case.status(
        "DELETE",
        &format!(
            "/api/access/members/{}?workspace={}",
            member.to_hex(),
            owner.to_hex()
        ),
        &cookie,
        Value::Null,
        StatusCode::OK,
    )
    .await?;
    ensure!(case
        .app
        .collection("machines")
        .find_one(doc! {"_id":machine})
        .await?
        .unwrap()
        .get_bool("private_owner_revoked")?);
    ensure!(!case
        .app
        .collection("machines")
        .find_one(doc! {"_id":foreign_machine})
        .await?
        .unwrap()
        .contains_key("private_owner_revoked"));
    ensure!(
        case.app
            .collection("machine_groups")
            .find_one(doc! {"_id":group})
            .await?
            .unwrap()
            .get_array("user_ids")?
            == &vec![Bson::ObjectId(guest)]
    );
    ensure!(case
        .app
        .collection("workspace_invites")
        .find_one(doc! {"_id":invite_id})
        .await?
        .unwrap()
        .get_datetime("revoked_at")
        .is_ok());
    case.db.drop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn account_changes_validate_credentials_pictures_and_session_revocation() -> Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let case = Case::new(Config::default()).await?;
    let (user, cookie) = case.user("before@example.invalid", "user").await?;
    let (other, _) = case.user("occupied@example.invalid", "user").await?;
    case.status(
        "PATCH",
        "/api/auth/preferences",
        &cookie,
        json!({"nav_collapsed":true}),
        StatusCode::OK,
    )
    .await?;
    ensure!(case
        .app
        .collection("users")
        .find_one(doc! {"_id":user})
        .await?
        .unwrap()
        .get_document("preferences")?
        .get_bool("nav_collapsed")?);
    ensure!(!case
        .app
        .collection("users")
        .find_one(doc! {"_id":other})
        .await?
        .unwrap()
        .contains_key("preferences"));
    for body in [
        json!({"email":"not-email"}),
        json!({"email":"new@example.invalid"}),
        json!({"email":"new@example.invalid","current_password":"wrong"}),
        json!({"email":"occupied@example.invalid","current_password":"Original-Password1!"}),
    ] {
        case.status(
            "PATCH",
            "/api/auth/account",
            &cookie,
            body,
            StatusCode::BAD_REQUEST,
        )
        .await?;
    }
    let body=case.status("PATCH","/api/auth/account",&cookie,json!({"name":"  Updated  ","email":" New@Example.invalid ","current_password":"Original-Password1!"}),StatusCode::OK).await?;
    ensure!(
        body["name"] == "Updated"
            && body["username"] == "new@example.invalid"
            && body["email"] == "new@example.invalid"
    );
    let data="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j0CkAAAAASUVORK5CYII=";
    let body = case
        .status(
            "PATCH",
            "/api/auth/account",
            &cookie,
            json!({"profile_picture":{"data_url":data,"filename":" avatar.png "}}),
            StatusCode::OK,
        )
        .await?;
    ensure!(
        body["profile_picture"]["filename"] == "avatar.png"
            && body["profile_picture"]["content_type"] == "image/png"
    );
    case.status(
        "PATCH",
        "/api/auth/account",
        &cookie,
        json!({"profile_picture":{"data_url":"data:text/html;base64,PGgxPjwv aDE+"}}),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let large = format!(
        "data:image/png;base64,{}",
        STANDARD.encode(vec![0u8; 2 * 1024 * 1024 + 1])
    );
    let body = case
        .status(
            "PATCH",
            "/api/auth/account",
            &cookie,
            json!({"profile_picture":{"data_url":large}}),
            StatusCode::BAD_REQUEST,
        )
        .await?;
    ensure!(body["detail"] == "Profile picture must be 2 MB or smaller");
    let body = case
        .status(
            "PATCH",
            "/api/auth/account",
            &cookie,
            json!({"remove_profile_picture":true}),
            StatusCode::OK,
        )
        .await?;
    ensure!(body["profile_picture"].is_null());
    case.status(
        "PATCH",
        "/api/auth/password",
        &cookie,
        json!({"current_password":"Original-Password1!","new_password":"short"}),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    case.status(
        "PATCH",
        "/api/auth/password",
        &cookie,
        json!({"current_password":"Original-Password1!","new_password":"é".repeat(37)}),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    case.status(
        "PATCH",
        "/api/auth/password",
        &cookie,
        json!({"current_password":"Original-Password1!","new_password":"simple-pass"}),
        StatusCode::OK,
    )
    .await?;
    case.status(
        "PUT",
        "/api/auth/settings/password",
        &cookie,
        json!({"current_password":"simple-pass","new_password":"still-weak"}),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    case.status(
        "PUT",
        "/api/auth/settings/password",
        &cookie,
        json!({"current_password":"simple-pass","new_password":"New-Strong2!"}),
        StatusCode::OK,
    )
    .await?;
    case.status(
        "POST",
        "/api/auth/signin",
        "",
        json!({"username":"new@example.invalid","password":"New-Strong2!"}),
        StatusCode::OK,
    )
    .await?;
    case.status(
        "DELETE",
        "/api/auth/delete",
        &cookie,
        json!({"username":"new@example.invalid","password":"New-Strong2!"}),
        StatusCode::OK,
    )
    .await?;
    ensure!(case
        .app
        .collection("users")
        .find_one(doc! {"_id":user})
        .await?
        .is_none());
    ensure!(
        case.app
            .collection("user_sessions")
            .count_documents(doc! {"user_id":user.to_hex(),"revoked_at":Bson::Null})
            .await?
            == 0
    );
    case.status(
        "GET",
        "/api/auth/me",
        &cookie,
        Value::Null,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    case.db.drop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn telegram_is_built_in_and_admin_overview_and_cors_preserve_contracts() -> Result<()> {
    use axum::{extract::State, http::StatusCode as HttpStatus, routing::post, Json};
    use std::sync::Mutex;
    let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let mock = Router::new()
        .route(
            "/bottest-secret-1234/sendMessage",
            post(
                |State(calls): State<Arc<Mutex<Vec<Value>>>>, Json(body): Json<Value>| async move {
                    let status = if body["chat_id"] == "bad" {
                        HttpStatus::BAD_REQUEST
                    } else {
                        HttpStatus::OK
                    };
                    calls.lock().unwrap().push(body);
                    (status, Json(json!({"ok":status==HttpStatus::OK})))
                },
            ),
        )
        .with_state(calls.clone());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, mock).await;
    });
    let case = Case::new(Config {
        telegram_base_url: base,
        client_version: "native-test".into(),
        ..Config::default()
    })
    .await?;
    let (admin, cookie) = case.user("admin@example.invalid", "admin").await?;
    let (member, member_cookie) = case.user("member@example.invalid", "user").await?;
    let defaults = case
        .status(
            "GET",
            "/api/auth/telegram",
            &cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(
        defaults["instant_alerts_enabled"] == true
            && defaults["digest_enabled"] == true
            && defaults["digest_interval_hours"] == 6
            && defaults["has_bot_token"] == false
    );
    case.status(
        "PATCH",
        "/api/auth/telegram",
        &cookie,
        json!({"digest_interval_hours":2}),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let configured=case.status("PATCH","/api/auth/telegram",&cookie,json!({"bot_token":" test-secret-1234 ","chat_ids":[" one ","bad"," "],"alerts_enabled":true}),StatusCode::OK).await?;
    ensure!(
        configured["bot_token_masked"]
            .as_str()
            .unwrap()
            .ends_with("1234")
            && !configured.to_string().contains("test-secret-1234")
            && configured["chat_ids"] == json!(["one", "bad"])
    );
    let sent = case
        .status(
            "POST",
            "/api/auth/telegram/test",
            &cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(sent["sent"] == json!(["one"]) && sent["failed"] == json!(["bad"]));
    ensure!(calls.lock().unwrap().len() == 2);
    let machine = ObjectId::new();
    let deleted = ObjectId::new();
    let now = DateTime::now();
    case.app.collection("machines").insert_many([doc! {"_id":machine,"user_id":member,"name":"Host","client_hostname":"host.local","last_seen_at":now,"group_id":ObjectId::new()},doc! {"_id":deleted,"user_id":admin,"name":"Deleted","deletion_pending":true}]).await?;
    case.app.collection("connections").insert_many([doc! {"user_id":member,"machine_id":machine,"external_port":20002,"internal_port":8000},doc! {"user_id":member,"machine_id":machine,"external_port":20001,"internal_port":22,"external_bind_ip":"192.0.2.44"}]).await?;
    case.status(
        "GET",
        "/api/admin/overview",
        &member_cookie,
        Value::Null,
        StatusCode::FORBIDDEN,
    )
    .await?;
    let overview = case
        .status(
            "GET",
            "/api/admin/overview",
            &cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    let users = overview["data"].as_array().unwrap();
    let member_data = users
        .iter()
        .find(|entry| entry["user"]["id"] == member.to_hex())
        .unwrap();
    ensure!(
        member_data["machines"][0]["ports"][0]["external_port"] == 20001
            && member_data["machines"][0]["ports"][0]["external_bind_ip"] == "192.0.2.44"
    );
    ensure!(
        member_data["machines"][0]["connection_status"] == "online"
            && member_data["machines"][0]["group_ids"]
                .as_array()
                .unwrap()
                .len()
                == 1
    );
    ensure!(users
        .iter()
        .find(|entry| entry["user"]["id"] == admin.to_hex())
        .unwrap()["machines"]
        .as_array()
        .unwrap()
        .is_empty());
    let (status, headers, _) = case
        .call(
            "OPTIONS",
            "/api/auth/account",
            "",
            Value::Null,
            &[
                ("origin", "https://app.invalid"),
                ("access-control-request-method", "PATCH"),
                ("access-control-request-headers", "Content-Type"),
            ],
        )
        .await?;
    ensure!(
        status == StatusCode::OK
            && headers["access-control-allow-origin"] == "https://app.invalid"
            && headers["access-control-allow-credentials"] == "true"
    );
    task.abort();
    case.db.drop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn machine_inventory_filters_private_addresses_and_preserves_history_window() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let (owner, cookie) = case.user("owner@example.invalid", "user").await?;
    let (other, other_cookie) = case.user("other@example.invalid", "user").await?;
    let machine = ObjectId::new();
    let revoked = ObjectId::new();
    let deleted = ObjectId::new();
    let now = DateTime::now();
    case.app.collection("machines").insert_many([
        doc! {"_id":machine,"user_id":owner,"name":"Visible","last_seen_at":now,"created_at":DateTime::from_millis(1)},
        doc! {"_id":revoked,"user_id":owner,"name":"Revoked","private_owner_revoked":true,"created_at":DateTime::from_millis(2)},
        doc! {"_id":deleted,"user_id":owner,"name":"Deleted","deletion_pending":true},
        doc! {"user_id":other,"name":"Other"}
    ]).await?;
    case.app
        .collection("private_peers")
        .insert_many([
            doc! {"owner_id":owner,"machine_id":machine,"enabled":true,"ip":"10.203.0.62"},
            doc! {"owner_id":owner,"machine_id":machine,"enabled":true,"ip":"10.203.0.62"},
            doc! {"owner_id":owner,"machine_id":machine,"enabled":true,"ip":"203.0.113.1"},
            doc! {"owner_id":owner,"machine_id":machine,"enabled":false,"ip":"10.203.0.63"},
            doc! {"owner_id":other,"machine_id":machine,"enabled":true,"ip":"10.203.0.64"},
            doc! {"owner_id":owner,"machine_id":revoked,"enabled":true,"ip":"10.203.0.65"},
        ])
        .await?;
    let inventory = case
        .status(
            "GET",
            "/api/machines/list",
            &cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(
        inventory["data"].as_array().unwrap().len() == 2
            && inventory["data"][0]["name"] == "Visible"
    );
    ensure!(
        inventory["data"][0]["private_ips"] == json!(["10.203.0.62"])
            && inventory["data"][1]["private_ips"] == json!([])
    );
    let addresses = case
        .status(
            "GET",
            &format!("/api/machines/private-addresses/{}", machine.to_hex()),
            &cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(addresses["data"] == json!(["10.203.0.62"]));
    case.status(
        "GET",
        &format!("/api/machines/private-addresses/{}", machine.to_hex()),
        &other_cookie,
        Value::Null,
        StatusCode::NOT_FOUND,
    )
    .await?;
    case.app.collection("machine_status_events").insert_many([
        doc! {"machine_id":machine,"status":"offline","changed_at":DateTime::from_millis(now.timestamp_millis()-2*86_400_000)},
        doc! {"machine_id":machine,"status":"online","changed_at":DateTime::from_millis(now.timestamp_millis()-3_600_000)}
    ]).await?;
    let history = case
        .status(
            "GET",
            &format!("/api/machines/{}/status-history?days=1", machine.to_hex()),
            &cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(
        history["current_status"] == "online"
            && history["data"].as_array().unwrap().len() == 2
            && history["data"][0]["status"] == "offline"
            && history["data"][1]["status"] == "online"
    );
    let unknown = case
        .status(
            "GET",
            &format!("/api/machines/{}/status-history", machine.to_hex()),
            &other_cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(unknown["msg"] == "Machine not found" && unknown["data"] == json!([]));
    let invalid = case
        .status(
            "GET",
            &format!("/api/machines/{}/status-history?days=367", machine.to_hex()),
            &cookie,
            Value::Null,
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await?;
    ensure!(invalid["detail"][0]["loc"] == json!(["query", "days"]));
    case.db.drop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PORTHUB_TEST_MONGO_URI pointing to an isolated MongoDB"]
async fn gateway_origin_requires_live_machine_credentials_and_shares_cached_discovery() -> Result<()>
{
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = Arc::new(AtomicUsize::new(0));
    let count = hits.clone();
    let mock = axum::Router::new()
        .route("/private", axum::routing::get(|| async { "192.168.1.1" }))
        .route("/large", axum::routing::get(|| async { "x".repeat(1024) }))
        .route(
            "/ip",
            axum::routing::get(move || {
                let count = count.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    "93.184.216.34\n"
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let serving = tokio::spawn(async move { axum::serve(listener, mock).await });
    let case = Case::new(Config {
        gateway_ip_sources: vec![
            format!("http://{address}/private"),
            format!("http://{address}/large"),
            format!("http://{address}/ip"),
        ],
        ..Config::default()
    })
    .await?;
    let machine = ObjectId::new();
    case.app
        .collection("machines")
        .insert_one(doc! {"_id":machine,"token":"machine-secret","enabled":true})
        .await?;
    let route = "/api/gateway/origin";
    let credentials = json!({"machine_id":machine.to_hex(),"token":"machine-secret"});
    case.status(
        "POST",
        route,
        "",
        json!({"machine_id":machine.to_hex(),"token":"wrong"}),
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    ensure!(
        hits.load(Ordering::SeqCst) == 0,
        "unauthenticated request triggered discovery"
    );
    let calls = futures_util::future::join_all(
        (0..16).map(|_| case.call("POST", route, "", credentials.clone(), &[])),
    )
    .await;
    for result in calls {
        let (status, headers, body) = result?;
        ensure!(status == StatusCode::OK, "{body}");
        ensure!(headers["cache-control"] == "private, no-store");
        ensure!(body["data"]["public_ip"] == "93.184.216.34");
        ensure!(body["data"]["stale"] == false);
        ensure!(body["data"]["refresh_after_seconds"]
            .as_u64()
            .is_some_and(|v| v > 0 && v <= 300));
    }
    ensure!(
        hits.load(Ordering::SeqCst) == 1,
        "concurrent calls duplicated external lookup"
    );
    case.app
        .collection("machines")
        .update_one(doc! {"_id":machine}, doc! {"$set":{"enabled":false}})
        .await?;
    case.status(
        "POST",
        route,
        "",
        credentials.clone(),
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    case.app
        .collection("machines")
        .update_one(
            doc! {"_id":machine},
            doc! {"$set":{"enabled":true,"token":"rotated"}},
        )
        .await?;
    case.status(
        "POST",
        route,
        "",
        credentials.clone(),
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    case.app
        .collection("machines")
        .update_one(
            doc! {"_id":machine},
            doc! {"$set":{"token":"machine-secret","deletion_pending":true}},
        )
        .await?;
    case.status("POST", route, "", credentials, StatusCode::UNAUTHORIZED)
        .await?;
    ensure!(hits.load(Ordering::SeqCst) == 1);
    case.db.drop().await?;
    serving.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn startup_web_routes_preserve_host_rules_and_reject_gateway_alias_conflicts() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("web-routes.json");
    let case = Case::new(Config {
        web_routes_config_path: Some(path.clone()),
        public_base_url: "https://gateway.example".into(),
        tunnel_fallback_base_urls: vec!["https://fallback.example".into()],
        ..Config::default()
    })
    .await?;
    let ids = [ObjectId::new(), ObjectId::new(), ObjectId::new()];
    case.app.collection("traffic_routes").insert_many([
        doc! {"_id":ids[0],"hosts":["docs.example"],"target_url":"https://upstream.example/base","target_mode":"manual","enabled":true},
        doc! {"_id":ids[1],"hosts":["mapped.example"],"target_url":"http://127.0.0.1:33126","target_mode":"connection","entry_points":["websecure"],"enabled":true},
        doc! {"_id":ids[2],"hosts":["disabled.example"],"target_url":"invalid-disabled-target","enabled":false},
    ]).await?;
    porthub_api::generated::rebuild_web(&case.app)
        .await
        .map_err(|error| anyhow::anyhow!("{}", error.detail))?;
    let original = std::fs::read_to_string(&path)?;
    let config: porthub_runtime::web_routes::Config = serde_json::from_str(&original)?;
    ensure!(config.routes.len() == 2);
    let manual = config
        .routes
        .iter()
        .find(|route| route.id == ids[0].to_hex())
        .context("manual")?;
    ensure!(!manual.pass_host && manual.http && manual.https);
    let mapped = config
        .routes
        .iter()
        .find(|route| route.id == ids[1].to_hex())
        .context("mapped")?;
    ensure!(mapped.pass_host && !mapped.http && mapped.https);
    for host in ["gateway.example", "fallback.example"] {
        case.app
            .collection("traffic_routes")
            .update_one(doc! {"_id":ids[0]}, doc! {"$set":{"hosts":[host]}})
            .await?;
        ensure!(porthub_api::generated::rebuild_web(&case.app)
            .await
            .is_err());
        ensure!(
            std::fs::read_to_string(&path)? == original,
            "rejected snapshot replaced active web routes"
        );
    }
    case.app
        .collection("traffic_routes")
        .update_many(doc! {}, doc! {"$set":{"enabled":false}})
        .await?;
    porthub_api::generated::rebuild_web(&case.app)
        .await
        .map_err(|error| anyhow::anyhow!("{}", error.detail))?;
    ensure!(serde_json::from_str::<porthub_runtime::web_routes::Config>(
        &std::fs::read_to_string(path)?
    )?
    .routes
    .is_empty());
    case.db.drop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn web_route_crud_enforces_ownership_claims_connections_and_publication_rollback(
) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("web-routes.json");
    let case = Case::new(Config {
        web_routes_config_path: Some(path.clone()),
        public_base_url: "https://gateway.example".into(),
        tunnel_fallback_base_urls: vec!["https://fallback.example".into()],
        ..Config::default()
    })
    .await?;
    let (owner, cookie) = case.user("route-owner@example.invalid", "user").await?;
    let (other, other_cookie) = case
        .user("other-route-owner@example.invalid", "user")
        .await?;
    let route = json!({"name":" Docs ","hosts":["DOCS.EXAMPLE","docs.example"],"targetUrl":"https://upstream.example/base","group":" manuals "});
    case.status(
        "POST",
        "/api/traffic-routes/add",
        "",
        route.clone(),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let created = case
        .status(
            "POST",
            "/api/traffic-routes/add",
            &cookie,
            route.clone(),
            StatusCode::OK,
        )
        .await?;
    let id = created["data"]["_id"]
        .as_str()
        .context("route ID")?
        .to_owned();
    ensure!(
        created["data"]["name"] == "Docs"
            && created["data"]["group"] == "manuals"
            && created["data"]["hosts"] == json!(["docs.example"])
    );
    let original = std::fs::read_to_string(&path)?;
    let published: porthub_runtime::web_routes::Config = serde_json::from_str(&original)?;
    ensure!(published.routes.len() == 1 && !published.routes[0].pass_host);
    case.status(
        "POST",
        "/api/traffic-routes/add",
        &other_cookie,
        route.clone(),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let list = case
        .status(
            "GET",
            "/api/traffic-routes/list",
            &other_cookie,
            json!({}),
            StatusCode::OK,
        )
        .await?;
    ensure!(list["data"] == json!([]));
    let mut editing = route.clone();
    editing["data_id"] = json!(id);
    editing["name"] = json!("Updated");
    case.status(
        "PUT",
        "/api/traffic-routes/update",
        &other_cookie,
        editing.clone(),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    case.status(
        "POST",
        "/api/traffic-routes/delete",
        &other_cookie,
        json!({"data_id":id}),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    for host in ["gateway.example", "fallback.example"] {
        let mut reserved = route.clone();
        reserved["hosts"] = json!([host]);
        reserved["enabled"] = json!(false);
        case.status(
            "POST",
            "/api/traffic-routes/add",
            &cookie,
            reserved,
            StatusCode::BAD_REQUEST,
        )
        .await?;
    }
    // A failed file replacement must roll back both update and deletion.
    std::fs::remove_file(&path)?;
    std::fs::create_dir(&path)?;
    case.status(
        "PUT",
        "/api/traffic-routes/update",
        &cookie,
        editing.clone(),
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await?;
    let stored = case
        .app
        .collection("traffic_routes")
        .find_one(doc! {"_id":ObjectId::parse_str(&id)?})
        .await?
        .context("route after failure")?;
    ensure!(stored.get_str("name")? == "Docs");
    case.status(
        "POST",
        "/api/traffic-routes/delete",
        &cookie,
        json!({"data_id":id}),
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await?;
    ensure!(
        case.app
            .collection("traffic_routes")
            .count_documents(doc! {})
            .await?
            == 1
    );
    let mut additional = route.clone();
    additional["hosts"] = json!(["new.example"]);
    case.status(
        "POST",
        "/api/traffic-routes/add",
        &cookie,
        additional,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await?;
    ensure!(
        case.app
            .collection("traffic_routes")
            .count_documents(doc! {})
            .await?
            == 1
    );
    std::fs::remove_dir(&path)?;
    std::fs::write(&path, &original)?;
    editing["enabled"] = json!(false);
    case.status(
        "PUT",
        "/api/traffic-routes/update",
        &cookie,
        editing,
        StatusCode::OK,
    )
    .await?;
    ensure!(serde_json::from_str::<porthub_runtime::web_routes::Config>(
        &std::fs::read_to_string(&path)?
    )?
    .routes
    .is_empty());
    // Disabled routes retain their host reservation until explicitly deleted.
    case.status(
        "POST",
        "/api/traffic-routes/add",
        &other_cookie,
        route.clone(),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    case.status(
        "POST",
        "/api/traffic-routes/delete",
        &cookie,
        json!({"data_id":id}),
        StatusCode::OK,
    )
    .await?;
    let (connection, foreign, machine) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
    case.app
        .collection("machines")
        .insert_one(doc! {"_id":machine,"user_id":owner,"name":"Luna","hostname_override":"luna"})
        .await?;
    case.app.collection("connections").insert_many([
        doc! {"_id":connection,"user_id":owner,"machine_id":machine,"service_name":"Files","internal_ip":"127.0.0.1","internal_port":8080,"external_port":33126},
        doc! {"_id":foreign,"user_id":other,"service_name":"Private to another owner","external_port":33127},
    ]).await?;
    let mapped = json!({"name":"Mapped","hosts":["mapped.example"],"targetMode":"connection","targetUrl":"http://127.0.0.1:33126","connectionDataId":connection.to_hex()});
    let mut invalid = mapped.clone();
    invalid["connectionDataId"] = json!(foreign.to_hex());
    case.status(
        "POST",
        "/api/traffic-routes/add",
        &cookie,
        invalid,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let created = case
        .status(
            "POST",
            "/api/traffic-routes/add",
            &cookie,
            mapped,
            StatusCode::OK,
        )
        .await?;
    ensure!(
        created["data"]["connection"]["machine_name"] == "Luna"
            && created["data"]["connection"]["machine_hostname"] == "luna"
    );
    let route = json!({"name":"Concurrent","hosts":["claimed.example"],"targetUrl":"http://127.0.0.1:33128"});
    let (left, right) = tokio::join!(
        case.call(
            "POST",
            "/api/traffic-routes/add",
            &cookie,
            route.clone(),
            &[]
        ),
        case.call("POST", "/api/traffic-routes/add", &other_cookie, route, &[])
    );
    let statuses = [left?.0, right?.0];
    ensure!(statuses.contains(&StatusCode::OK) && statuses.contains(&StatusCode::BAD_REQUEST));
    ensure!(
        case.app
            .collection("traffic_routes")
            .count_documents(doc! {"hosts":"claimed.example"})
            .await?
            == 1
    );
    case.db.drop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn native_web_activity_preserves_history_and_ingests_real_proxy_requests_once() -> Result<()>
{
    use porthub_runtime::{web_activity::WebActivity, web_routes::WebRoutes};
    let temp = tempfile::tempdir()?;
    let manifest = temp.path().join("web-routes.json");
    let log = temp.path().join("activity.log");
    let case = Case::new(Config {
        web_routes_config_path: Some(manifest.clone()),
        ..Config::default()
    })
    .await?;
    let (owner, cookie) = case.user("activity-owner@example.invalid", "user").await?;
    let (_, other_cookie) = case.user("other-activity@example.invalid", "user").await?;
    case.status(
        "GET",
        "/api/traffic-routes/activity",
        "",
        Value::Null,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let unavailable = case
        .status(
            "GET",
            "/api/traffic-routes/activity",
            &cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(unavailable["available"] == false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let target = listener.local_addr()?;
    let backend = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/file", axum::routing::get(|| async { "native payload" })),
        )
        .await
    });
    let created=case.status("POST","/api/traffic-routes/add",&cookie,json!({"name":"Activity fixture","hosts":["app.example.invalid"],"targetUrl":format!("http://{target}")}),StatusCode::OK).await?;
    let id = created["data"]["_id"].as_str().context("route ID")?;
    let now = chrono::Utc::now();
    let tracking = format!(
        "{}+00:00",
        porthub_api::store::datetime(now.timestamp_millis())
    );
    let mut metrics = mongodb::bson::Document::new();
    metrics.insert(id, doc! {"requests":9_i64,"last_requested_at":&tracking});
    case.app.collection("proxy_activity").insert_one(doc! {"_id":"traefik-requests-v1","revision":7_i64,"identity":"old-log","offset":500_i64,"metrics":metrics,"tracking_since":&tracking}).await?;
    let activity = Arc::new(WebActivity::default());
    let web = Arc::new(WebRoutes::new(None).with_activity(activity.clone()));
    web.reload(serde_json::from_slice(&std::fs::read(&manifest)?)?)?;
    let server = Arc::new(tokio::sync::RwLock::new(
        porthub_tunnel::EmbeddedServer::new(porthub_tunnel::gateway_config("[server.services]\n")?)
            .await?,
    ));
    let edge_router = porthub_edge::router_with_web(server.clone(), None, web);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let edge = tokio::spawn(async move { axum::serve(listener, edge_router).await });
    let client = reqwest::Client::new();
    for _ in 0..3 {
        let response = client
            .get(format!("http://{address}/file?private-query=not-recorded"))
            .header("host", "app.example.invalid")
            .send()
            .await?;
        ensure!(response.status().is_success());
        ensure!(response.text().await? == "native payload");
    }
    let (stop, stopping) = tokio::sync::watch::channel(true);
    activity
        .run(log.clone(), stopping, std::time::Duration::from_secs(5))
        .await?;
    drop(stop);
    let bytes = std::fs::read_to_string(&log)?;
    ensure!(
        !bytes.contains("private-query")
            && !bytes.contains("native payload")
            && !bytes.contains(&target.to_string())
    );
    // Ownership changes to hosts cannot reattribute an already recorded request.
    case.app
        .collection("traffic_routes")
        .update_one(
            doc! {"_id":ObjectId::parse_str(id)?,"user_id":owner},
            doc! {"$set":{"hosts":["renamed.invalid"]}},
        )
        .await?;
    let (a, b) = tokio::join!(
        porthub_api::web_activity::collect(&case.app, &log),
        porthub_api::web_activity::collect(&case.app, &log)
    );
    a?;
    b?;
    porthub_api::web_activity::collect(&case.app, &log).await?;
    let body = case
        .status(
            "GET",
            "/api/traffic-routes/activity",
            &cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(body["available"] == true && body["coverage_warning"] == false);
    ensure!(
        body["data"][0]["requests"] == 12 && body["data"][0]["monthly_requests"] == 12,
        "{body}"
    );
    ensure!(
        body["tracking_since"] == tracking && body["data"][0]["last_host"] == "app.example.invalid"
    );
    let other = case
        .status(
            "GET",
            "/api/traffic-routes/activity",
            &other_cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(other["data"] == json!([]));
    // Replay a fully written batch under a new inode, as could happen after a failed append/restart.
    std::fs::rename(&log, temp.path().join("old-copy"))?;
    std::fs::write(&log, bytes)?;
    porthub_api::web_activity::collect(&case.app, &log).await?;
    let replay = case
        .status(
            "GET",
            "/api/traffic-routes/activity",
            &cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(replay["coverage_warning"] == true && replay["data"][0]["requests"] == 12);
    let state = case
        .app
        .collection("proxy_activity")
        .find_one(doc! {"_id":"traefik-requests-v1"})
        .await?
        .context("state")?;
    ensure!(state.get_str("identity")? == "old-log" && state.get_i64("offset")? == 500);
    edge.abort();
    backend.abort();
    server.write().await.shutdown().await;
    case.db.drop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn mapped_ports_enforce_ownership_ranges_publish_and_rollback_with_firewall_ipc() -> Result<()>
{
    use axum::{
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        routing::{get, put},
        Json,
    };
    use std::{
        collections::BTreeMap,
        sync::{
            atomic::{AtomicBool, Ordering},
            Mutex,
        },
    };
    #[derive(Default)]
    struct Firewall {
        policies: Mutex<BTreeMap<i64, Value>>,
        fail: AtomicBool,
        calls: Mutex<Vec<(String, i64)>>,
    }
    async fn update(
        State(state): State<Arc<Firewall>>,
        Path(port): Path<i64>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        if headers.get("x-api-key").and_then(|v| v.to_str().ok()) != Some("test-firewall-secret") {
            return (StatusCode::FORBIDDEN, Json(json!({"detail":"Forbidden"})));
        }
        state.calls.lock().unwrap().push(("put".into(), port));
        if state.fail.swap(false, Ordering::SeqCst) {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"detail":"fixture failed"})),
            );
        }
        state.policies.lock().unwrap().insert(port, body.clone());
        (StatusCode::OK, Json(json!({"data":body})))
    }
    async fn delete(
        State(state): State<Arc<Firewall>>,
        Path(port): Path<i64>,
        headers: HeaderMap,
    ) -> (StatusCode, Json<Value>) {
        if headers.get("x-api-key").and_then(|v| v.to_str().ok()) != Some("test-firewall-secret") {
            return (StatusCode::FORBIDDEN, Json(json!({"detail":"Forbidden"})));
        }
        state.calls.lock().unwrap().push(("delete".into(), port));
        state.policies.lock().unwrap().remove(&port);
        (StatusCode::OK, Json(json!({"data":{}})))
    }
    async fn list(State(state): State<Arc<Firewall>>) -> Json<Value> {
        Json(
            json!({"data":state.policies.lock().unwrap().iter().map(|(port,p)|json!({"port":port,"is_public":p["is_public"],"allowed_ips":p["allowed_ips"]})).collect::<Vec<_>>() }),
        )
    }
    let temp = tempfile::tempdir()?;
    let socket = temp.path().join("firewall.sock");
    let config = temp.path().join("gateway.toml");
    let (listener, _lease) = porthub_runtime::socket::bind(&socket).await?;
    let firewall = Arc::new(Firewall::default());
    let mock = Router::new()
        .route("/api/ports/{port}/policy", put(update).delete(delete))
        .route("/api/ports/policies/list", get(list))
        .route("/api/ports/active", get(||async {Json(json!({"data":[{"port":49100,"last_seen":"fixture"},{"port":60000,"last_seen":"foreign"}]}))}))
        .route("/api/ports/traffic/snapshot", axum::routing::post(|Json(body):Json<Value>|async move {assert_eq!(body["ports"],json!([49100]));Json(json!({"data":{"49100":[{"rx":123}],"60000":[{"rx":999}]}}))}))
        .route("/api/ports/{port}/recent-ip-hits", get(|Path(port):Path<i64>|async move {assert_eq!(port,49100);Json(json!({"data":[{"ip":"203.0.113.5"}]}))}))
        .with_state(firewall.clone());
    let task = tokio::spawn(async move { axum::serve(listener, mock).await });
    let case = Case::new(Config {
        gateway_config_path: Some(config.clone()),
        external_port_range: Some((49100, 49101)),
        firewall_socket: Some(socket),
        firewall_api_key: "test-firewall-secret".into(),
        ..Config::default()
    })
    .await?;
    let (owner, cookie) = case.user("mapped-owner@example.invalid", "user").await?;
    let (other, other_cookie) = case.user("mapped-other@example.invalid", "user").await?;
    let (machine, other_machine) = (ObjectId::new(), ObjectId::new());
    for (id, user) in [(machine, owner), (other_machine, other)] {
        case.app.collection("machines").insert_one(doc! {"_id":id,"user_id":user,"name":"Mapped machine","token":format!("secret-{id}"),"enabled":true}).await?;
    }
    let payload = json!({"machine_id":machine.to_hex(),"service_name":" SSH ","service_description":" shell ","internal_port":22,"external_port":49100,"internal_ip":"Host.LAN","auto_refresh_enabled":true,"auto_refresh_interval_minutes":7});
    case.status(
        "POST",
        "/api/connections/add",
        "",
        payload.clone(),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    case.status(
        "POST",
        "/api/connections/add",
        &other_cookie,
        payload.clone(),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let mut invalid = payload.clone();
    invalid["external_port"] = json!(49099);
    case.status(
        "POST",
        "/api/connections/add",
        &cookie,
        invalid,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let signal = case.app.config_signals.subscribe(&machine.to_hex());
    let notified = signal.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    let created = case
        .status(
            "POST",
            "/api/connections/add",
            &cookie,
            payload.clone(),
            StatusCode::OK,
        )
        .await?;
    tokio::time::timeout(std::time::Duration::from_secs(1), notified).await?;
    let id = created["data"]["_id"].as_str().context("connection id")?;
    ensure!(
        created["data"]["internal_ip"] == "host.lan"
            && created["data"]["service_name"] == "SSH"
            && created["data"]["external_bind_ip"] == "0.0.0.0"
    );
    ensure!(
        created["data"]["auto_refresh_interval_minutes"] == 7
            && created["data"]["auto_refresh_next_at"].is_string()
    );
    let schedule = created["data"]["auto_refresh_next_at"].clone();
    let snapshot = std::fs::read_to_string(&config)?;
    ensure!(snapshot.contains("0.0.0.0:49100") && snapshot.contains(&format!("secret-{machine}")));
    ensure!(firewall.policies.lock().unwrap()[&49100]["is_public"] == true);
    case.status(
        "POST",
        "/api/connections/add",
        &cookie,
        payload.clone(),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let empty = case
        .status(
            "GET",
            "/api/connections/list",
            &other_cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(empty["data"] == json!([]));
    let unavailable = case
        .status(
            "GET",
            "/api/connections/external-port/49100/availability",
            &cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(unavailable["available"] == false);
    let available = case
        .status(
            "GET",
            &format!("/api/connections/external-port/49100/availability?data_id={id}"),
            &cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(available["available"] == true);
    let mut editing = payload.clone();
    editing["data_id"] = json!(id);
    let same = case
        .status(
            "PUT",
            "/api/connections/update",
            &cookie,
            editing.clone(),
            StatusCode::OK,
        )
        .await?;
    ensure!(same["data"]["auto_refresh_next_at"] == schedule);
    let active = case
        .status(
            "GET",
            "/api/connections/firewall/active",
            &cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(active["data"].as_array().unwrap().len() == 1 && active["data"][0]["port"] == 49100);
    let active = case
        .status(
            "GET",
            "/api/connections/firewall/active",
            &other_cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(active["data"] == json!([]));
    let traffic = case
        .status(
            "POST",
            "/api/connections/firewall/traffic/snapshot",
            &cookie,
            json!({"data_ids":[id]}),
            StatusCode::OK,
        )
        .await?;
    ensure!(
        traffic["data"].as_array().unwrap().len() == 1
            && traffic["data"][0]["traffic"][0]["rx"] == 123
    );
    let hits = case
        .status(
            "GET",
            &format!("/api/connections/firewall/recent-ip-hits/{id}"),
            &cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(hits["data"][0]["ip"] == "203.0.113.5");
    case.status(
        "GET",
        &format!("/api/connections/firewall/recent-ip-hits/{id}"),
        &other_cookie,
        Value::Null,
        StatusCode::NOT_FOUND,
    )
    .await?;
    let policy = json!({"data_id":id,"is_public":false,"allowed_ips":["203.0.113.5"]});
    case.status(
        "PUT",
        "/api/connections/firewall/policy",
        &other_cookie,
        policy.clone(),
        StatusCode::NOT_FOUND,
    )
    .await?;
    case.status(
        "PUT",
        "/api/connections/firewall/policy",
        &cookie,
        policy.clone(),
        StatusCode::OK,
    )
    .await?;
    ensure!(firewall.policies.lock().unwrap()[&49100]["allowed_ips"] == json!(["203.0.113.5"]));
    firewall.fail.store(true, Ordering::SeqCst);
    case.status(
        "PUT",
        "/api/connections/firewall/policy",
        &cookie,
        json!({"data_id":id,"is_public":true}),
        StatusCode::BAD_GATEWAY,
    )
    .await?;
    let saved = case
        .status(
            "GET",
            &format!("/api/connections/firewall/policy/{id}"),
            &cookie,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(saved["data"]["firewall"]["is_public"] == false);
    // A publication failure must restore the previous DB record and firewall.
    std::fs::remove_file(&config)?;
    std::fs::create_dir(&config)?;
    editing["external_port"] = json!(49101);
    case.status(
        "PUT",
        "/api/connections/update",
        &cookie,
        editing.clone(),
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await?;
    let record = case
        .app
        .collection("connections")
        .find_one(doc! {"_id":ObjectId::parse_str(id)?})
        .await?
        .context("restored record")?;
    ensure!(porthub_api::firewall::port(&record) == Some(49100));
    // Publication/recovery failed, so keep the candidate's restriction until
    // a successful reconciliation can prove the listener snapshot is applied.
    ensure!(
        firewall.policies.lock().unwrap().contains_key(&49100)
            && firewall.policies.lock().unwrap().contains_key(&49101)
    );
    case.status(
        "POST",
        "/api/connections/delete",
        &cookie,
        json!({"data_id":id}),
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await?;
    ensure!(
        case.app
            .collection("connections")
            .count_documents(doc! {"_id":ObjectId::parse_str(id)?})
            .await?
            == 1
    );
    let mut second = payload.clone();
    second["external_port"] = json!(49101);
    case.status(
        "POST",
        "/api/connections/add",
        &cookie,
        second.clone(),
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await?;
    ensure!(
        case.app
            .collection("connections")
            .count_documents(doc! {})
            .await?
            == 1
    );
    std::fs::remove_dir(&config)?;
    std::fs::write(&config, &snapshot)?;
    porthub_api::firewall::reconcile(&case.app)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
    ensure!(
        firewall.policies.lock().unwrap().contains_key(&49100)
            && !firewall.policies.lock().unwrap().contains_key(&49101)
    );
    firewall.fail.store(true, Ordering::SeqCst);
    case.status(
        "POST",
        "/api/connections/add",
        &cookie,
        second.clone(),
        StatusCode::BAD_GATEWAY,
    )
    .await?;
    ensure!(
        case.app
            .collection("connections")
            .count_documents(doc! {})
            .await?
            == 1
    );
    let changed = case
        .status(
            "PUT",
            "/api/connections/update",
            &cookie,
            editing.clone(),
            StatusCode::OK,
        )
        .await?;
    ensure!(changed["data"]["external_port"] == 49101);
    ensure!(!firewall.policies.lock().unwrap().contains_key(&49100));
    // A real configured custom bind address is preserved and reported.
    case.app
        .collection("connections")
        .update_one(
            doc! {"_id":ObjectId::parse_str(id)?},
            doc! {"$set":{"external_bind_ip":"127.0.0.1"}},
        )
        .await?;
    case.status(
        "PUT",
        "/api/connections/update",
        &cookie,
        editing.clone(),
        StatusCode::OK,
    )
    .await?;
    ensure!(std::fs::read_to_string(&config)?.contains("127.0.0.1:49101"));
    let random = case
        .status(
            "GET",
            "/api/connections/random",
            "",
            Value::Null,
            StatusCode::OK,
        )
        .await?;
    ensure!(random["port"] == 49100);
    // Concurrent owners contend for the globally reserved port, even when disabled.
    second["machine_id"] = json!(other_machine.to_hex());
    second["external_port"] = json!(49100);
    second["enabled"] = json!(false);
    let mut mine = second.clone();
    mine["machine_id"] = json!(machine.to_hex());
    let (a, b) = tokio::join!(
        case.call("POST", "/api/connections/add", &cookie, mine, &[]),
        case.call("POST", "/api/connections/add", &other_cookie, second, &[])
    );
    let statuses = [a?.0, b?.0];
    ensure!(
        statuses.iter().filter(|s| **s == StatusCode::OK).count() == 1
            && statuses
                .iter()
                .filter(|s| **s == StatusCode::BAD_REQUEST)
                .count()
                == 1
    );
    case.status(
        "GET",
        "/api/connections/random",
        "",
        Value::Null,
        StatusCode::CONFLICT,
    )
    .await?;
    case.status(
        "POST",
        "/api/connections/delete",
        &other_cookie,
        json!({"data_id":id}),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    case.status(
        "POST",
        "/api/connections/delete",
        &cookie,
        json!({"data_id":id}),
        StatusCode::OK,
    )
    .await?;
    ensure!(!firewall.policies.lock().unwrap().contains_key(&49101));
    // Restart-style reconciliation removes only stale PortHub worker policies.
    firewall
        .policies
        .lock()
        .unwrap()
        .insert(60000, json!({"is_public":false,"allowed_ips":[]}));
    porthub_api::firewall::reconcile(&case.app)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
    ensure!(!firewall.policies.lock().unwrap().contains_key(&60000));
    task.abort();
    case.db.drop().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn connection_refresh_recovers_leases_and_respects_concurrent_user_changes() -> Result<()> {
    use std::time::Duration;
    let temp = tempfile::tempdir()?;
    let config = temp.path().join("gateway.toml");
    let case = Case::new(Config {
        gateway_config_path: Some(config.clone()),
        ..Config::default()
    })
    .await?;
    let (owner, cookie) = case.user("refresh-owner@example.invalid", "user").await?;
    let machine = ObjectId::new();
    case.app
        .collection("machines")
        .insert_one(doc! {"_id":machine,"user_id":owner,"enabled":true,"token":"refresh-secret"})
        .await?;
    let input = json!({"machine_id":machine.to_hex(),"service_name":"Refresh fixture","internal_port":22,"external_port":49200,"auto_refresh_enabled":true,"auto_refresh_interval_minutes":10});
    let created = case
        .status(
            "POST",
            "/api/connections/add",
            &cookie,
            input.clone(),
            StatusCode::OK,
        )
        .await?;
    let id = created["data"]["_id"].as_str().context("connection id")?;
    let oid = ObjectId::parse_str(id)?;
    let record = case
        .app
        .collection("connections")
        .find_one(doc! {"_id":oid})
        .await?
        .context("record")?;
    let app = case.app.clone();
    let refreshing = tokio::spawn(async move {
        porthub_api::connection_refresh::refresh(&app, record, Duration::from_millis(200), None)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.detail))
    });
    for _ in 0..100 {
        if case
            .app
            .collection("connections")
            .count_documents(doc! {"_id":oid,"enabled":false,"native_refresh.id":{"$exists":true}})
            .await?
            == 1
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    ensure!(
        case.app
            .collection("connections")
            .count_documents(doc! {"_id":oid,"enabled":false})
            .await?
            == 1
    );
    let mut edited = input.clone();
    edited["data_id"] = json!(id);
    edited["enabled"] = json!(false);
    case.status(
        "PUT",
        "/api/connections/update",
        &cookie,
        edited.clone(),
        StatusCode::OK,
    )
    .await?;
    let result = refreshing.await??.context("user edited record")?;
    ensure!(result.get_bool("enabled") == Ok(false));
    ensure!(
        case.app
            .collection("connections")
            .count_documents(doc! {"_id":oid,"enabled":false,"native_refresh":{"$exists":false}})
            .await?
            == 1
    );
    case.status(
        "POST",
        "/api/connections/refresh",
        &cookie,
        json!({"data_id":id}),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    edited["enabled"] = json!(true);
    case.status(
        "PUT",
        "/api/connections/update",
        &cookie,
        edited.clone(),
        StatusCode::OK,
    )
    .await?;
    // Simulate a killed process during its temporary disable phase.
    let lease = doc! {"id":"interrupted-refresh","started_at":DateTime::from_millis(DateTime::now().timestamp_millis()-60_000)};
    case.app
        .collection("connections")
        .update_one(
            doc! {"_id":oid},
            doc! {"$set":{"enabled":false,"native_refresh":lease}},
        )
        .await?;
    porthub_api::connection_refresh::recover(&case.app, false)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
    let recovered = case
        .app
        .collection("connections")
        .find_one(doc! {"_id":oid})
        .await?
        .context("recovered")?;
    ensure!(
        recovered.get_bool("enabled") == Ok(true)
            && !recovered.contains_key("native_refresh")
            && recovered.contains_key("auto_refreshed_at")
    );
    ensure!(
        recovered
            .get_datetime("auto_refresh_next_at")?
            .timestamp_millis()
            > DateTime::now().timestamp_millis() + 9 * 60_000
    );
    // The actual endpoint preserves the five-second disable/reconnect behavior.
    let refreshed = case
        .status(
            "POST",
            "/api/connections/refresh",
            &cookie,
            json!({"data_id":id}),
            StatusCode::OK,
        )
        .await?;
    ensure!(refreshed["data"]["enabled"] == true);
    // Scheduled refresh finishes its own lease when the process is asked to stop.
    case.app
        .collection("connections")
        .update_one(
            doc! {"_id":oid},
            doc! {"$set":{"auto_refresh_next_at":DateTime::from_millis(0)}},
        )
        .await?;
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let app = case.app.clone();
    let worker = tokio::spawn(porthub_api::connection_refresh::run(app, stopping));
    for _ in 0..100 {
        if case
            .app
            .collection("connections")
            .count_documents(doc! {"_id":oid,"native_refresh.id":{"$exists":true}})
            .await?
            == 1
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    ensure!(
        case.app
            .collection("connections")
            .count_documents(doc! {"_id":oid,"native_refresh.id":{"$exists":true}})
            .await?
            == 1
    );
    stop.send(true)?;
    tokio::time::timeout(Duration::from_secs(2), worker).await??;
    let recovered = case
        .app
        .collection("connections")
        .find_one(doc! {"_id":oid})
        .await?
        .context("shutdown recovery")?;
    ensure!(recovered.get_bool("enabled") == Ok(true) && !recovered.contains_key("native_refresh"));
    case.db.drop().await?;
    Ok(())
}
