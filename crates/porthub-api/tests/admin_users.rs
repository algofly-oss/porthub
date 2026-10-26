use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use porthub_api::config::Config;
use serde_json::json;
mod support;
use support::Case;

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn admin_provisions_hashed_member_accounts_without_enabling_signup_or_switching_sessions(
) -> Result<()> {
    let mut config = Config::default();
    config.signup_disabled = true;
    let case = Case::new(config).await?;
    let result=async {
        let (_,admin)=case.user("admin@test.invalid","admin").await?;
        let (_,member)=case.user("member@test.invalid","user").await?;
        case.app.collection("users").create_index(mongodb::IndexModel::builder().keys(doc!{"username":1}).build()).await?;
        let body=json!({"name":"New member","email":"NEW@Example.Invalid","password":"New-Strong1!","role":"admin"});
        case.status("POST","/api/admin/users","",body.clone(),StatusCode::BAD_REQUEST).await?;
        case.status("POST","/api/admin/users",&member,body.clone(),StatusCode::FORBIDDEN).await?;
        let (status,headers,response)=case.call("POST","/api/admin/users",&admin,body.clone(),&[]).await?;
        ensure!(status==StatusCode::CREATED);ensure!(!headers.contains_key("set-cookie"));
        ensure!(response["data"]["role"]=="user" && response["data"]["email"]=="new@example.invalid");
        ensure!(!response.to_string().contains("New-Strong1!"));
        let user=case.app.collection("users").find_one(doc!{"username":"new@example.invalid"}).await?.unwrap();
        let hash=porthub_api::domain::accounts::password_hash(&user);ensure!(hash!="New-Strong1!");ensure!(bcrypt::verify("New-Strong1!",&hash)?);
        case.status("POST","/api/admin/users",&admin,body,StatusCode::CONFLICT).await?;
        case.status("POST","/api/admin/users",&admin,json!({"name":"x","email":"invalid","password":"New-Strong1!"}),StatusCode::UNPROCESSABLE_ENTITY).await?;
        case.status("POST","/api/admin/users",&admin,json!({"name":"x","email":"valid@example.invalid","password":"short"}),StatusCode::UNPROCESSABLE_ENTITY).await?;
        let (_,_,current)=case.call("GET","/api/auth/me",&admin,json!(null),&[]).await?;ensure!(current["role"]=="admin");
        case.status("POST","/api/auth/signup","",json!({"name":"No signup","username":"blocked@example.invalid","password":"New-Strong1!"}),StatusCode::FORBIDDEN).await?;
        case.status("POST","/api/auth/signin","",json!({"username":"new@example.invalid","password":"New-Strong1!"}),StatusCode::OK).await?;
        case.app.collection("platform_settings").update_one(doc!{"_id":"platform"},doc!{"$set":{"signup_enabled":true}}).upsert(true).await?;
        case.status("POST","/api/admin/users",&admin,json!({"name":"Signup enabled member","email":"enabled@example.invalid","password":"New-Strong1!"}),StatusCode::CREATED).await?;
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn admin_deletion_cascades_owned_resources_revokes_credentials_and_preserves_other_tenants(
) -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async {
        let (admin_id,admin)=case.user("admin@test.invalid","admin").await?;
        let (target,target_cookie)=case.user("delete@test.invalid","user").await?;
        let (other,other_cookie)=case.user("other@test.invalid","user").await?;
        let machine=ObjectId::new();let foreign_machine=ObjectId::new();let group=ObjectId::new();let shared_group=ObjectId::new();let route=ObjectId::new();let book=ObjectId::new();let shared_book=ObjectId::new();
        let peer=format!("{target}:{machine}");let invited_peer=format!("{target}:{foreign_machine}");let keep_peer=format!("{other}:{foreign_machine}");
        case.app.collection("machines").insert_many([
            doc!{"_id":machine,"user_id":target,"name":"Owned","token":"owned-token","enabled":true},
            doc!{"_id":foreign_machine,"user_id":other,"name":"Keep","token":"keep-token","enabled":true,"group_ids":[group,shared_group]},
        ]).await?;
        case.app.collection("connections").insert_many([
            doc!{"_id":ObjectId::new(),"machine_id":machine,"user_id":target,"external_port":35111,"enabled":true},
            doc!{"_id":ObjectId::new(),"machine_id":foreign_machine,"user_id":other,"external_port":35112,"enabled":true},
        ]).await?;
        case.app.collection("private_peers").insert_many([
            doc!{"_id":&peer,"workspace_id":target,"owner_id":target,"machine_id":machine,"credential_hash":"owned-credential"},
            doc!{"_id":&invited_peer,"workspace_id":target,"owner_id":other,"machine_id":foreign_machine},
            doc!{"_id":&keep_peer,"workspace_id":other,"owner_id":other,"machine_id":foreign_machine},
        ]).await?;
        case.app.collection("machine_groups").insert_many([
            doc!{"_id":group,"user_id":target},doc!{"_id":shared_group,"user_id":other,"user_ids":[target,admin_id]},
        ]).await?;
        case.app.collection("traffic_routes").insert_many([
            doc!{"_id":route,"user_id":target},doc!{"_id":ObjectId::new(),"user_id":other},
        ]).await?;
        case.app.collection("private_networks").insert_many([doc!{"_id":target.to_hex(),"cidr":"10.200.1.0/24"},doc!{"_id":other.to_hex(),"cidr":"10.200.2.0/24"}]).await?;
        case.app.collection("workspace_members").insert_many([
            doc!{"_id":"owned-workspace-member","workspace_id":target,"user_id":other},
            doc!{"_id":"deleted-member","workspace_id":other,"user_id":target},
            doc!{"_id":"keep-member","workspace_id":other,"user_id":admin_id},
        ]).await?;
        case.app.collection("workspace_invites").insert_many([
            doc!{"_id":"owned-invite","workspace_id":target},doc!{"_id":"issued-invite","workspace_id":other,"created_by":target},doc!{"_id":"keep-invite","workspace_id":other},
        ]).await?;
        case.app.collection("access_rulebooks").insert_many([
            doc!{"_id":book,"user_id":target},
            doc!{"_id":shared_book,"user_id":other,"created_by":target,"rules":[{"source":target.to_hex()},{"source":admin_id.to_hex()}]},
        ]).await?;
        case.app.collection("machine_install_tickets").insert_one(doc!{"_id":"machine-ticket","machine_id":machine}).await?;
        case.app.collection("private_install_tickets").insert_one(doc!{"_id":"peer-ticket","peer_id":&peer,"created_by":target}).await?;
        case.app.collection("private_signals").insert_many([doc!{"_id":"out","from":&peer,"to":&keep_peer},doc!{"_id":"in","from":&keep_peer,"to":&invited_peer},doc!{"_id":"keep","from":&keep_peer,"to":&keep_peer}]).await?;
        case.app.collection("machine_status_events").insert_one(doc!{"_id":"history","machine_id":machine}).await?;
        let mut metrics=mongodb::bson::Document::new();metrics.insert(route.to_hex(),doc!{"requests":10});metrics.insert("keep",doc!{"requests":2});
        case.app.collection("proxy_activity").insert_one(doc!{"_id":"activity","revision":0,"metrics":metrics}).await?;
        let path=format!("/api/admin/users/{target}");
        case.status("DELETE",&path,&other_cookie,json!({"confirm_email":"delete@test.invalid"}),StatusCode::FORBIDDEN).await?;
        case.status("DELETE",&path,&admin,json!({"confirm_email":"wrong@test.invalid"}),StatusCode::BAD_REQUEST).await?;
        ensure!(case.app.collection("machines").count_documents(doc!{"_id":machine}).await?==1);
        let active_request=case.app.account_lifecycle.read().await;
        let mut deletion=Box::pin(case.call("DELETE",&path,&admin,json!({"confirm_email":"delete@test.invalid"}),&[]));
        ensure!(tokio::time::timeout(std::time::Duration::from_millis(20),&mut deletion).await.is_err());
        ensure!(case.app.collection("users").count_documents(doc!{"_id":target,"account_deletion":{"$exists":false}}).await?==1);
        drop(active_request);
        ensure!(deletion.await?.0==StatusCode::OK);
        for (collection,filter) in [
            ("users",doc!{"_id":target}),("machines",doc!{"_id":machine}),("connections",doc!{"machine_id":machine}),
            ("private_peers",doc!{"workspace_id":target}),("machine_groups",doc!{"user_id":target}),
            ("traffic_routes",doc!{"user_id":target}),("access_rulebooks",doc!{"user_id":target}),
            ("user_sessions",doc!{"user_id":target.to_hex()}),("private_networks",doc!{"_id":target.to_hex()}),
            ("workspace_members",doc!{"$or":[{"user_id":target},{"workspace_id":target}]}),
            ("workspace_invites",doc!{"$or":[{"created_by":target},{"workspace_id":target}]}),
            ("machine_install_tickets",doc!{}),("private_install_tickets",doc!{}),("machine_status_events",doc!{}),
        ] {ensure!(case.app.collection(collection).count_documents(filter).await?==0,"remaining rows in {collection}");}
        ensure!(case.app.collection("machines").count_documents(doc!{"_id":foreign_machine}).await?==1);
        ensure!(case.app.collection("connections").count_documents(doc!{"machine_id":foreign_machine}).await?==1);
        ensure!(case.app.collection("private_peers").count_documents(doc!{"_id":&keep_peer}).await?==1);
        ensure!(case.app.collection("private_signals").count_documents(doc!{}).await?==1);
        let kept=case.app.collection("access_rulebooks").find_one(doc!{"_id":shared_book}).await?.unwrap();ensure!(kept.get_array("rules")?.len()==1);ensure!(kept.get("created_by")==Some(&mongodb::bson::Bson::Null));
        let activity=case.app.collection("proxy_activity").find_one(doc!{"_id":"activity"}).await?.unwrap();ensure!(!activity.get_document("metrics")?.contains_key(route.to_hex()));ensure!(activity.get_document("metrics")?.contains_key("keep"));
        case.status("GET","/api/auth/me",&target_cookie,json!(null),StatusCode::BAD_REQUEST).await?;
        let denied=porthub_api::domain::machine_client::authenticate(&case.app,&machine.to_hex(),"owned-token").await.err().unwrap();ensure!(denied.status==StatusCode::GONE);
        case.status("GET","/api/auth/me",&other_cookie,json!(null),StatusCode::OK).await?;
        case.status("DELETE",&format!("/api/admin/users/{admin_id}"),&admin,json!({"confirm_email":"admin@test.invalid"}),StatusCode::CONFLICT).await?;
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn failed_ingress_publication_keeps_a_revoked_durable_job_and_recovers() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("gateway.toml");
    std::fs::create_dir(&path)?;
    let mut config = Config::default();
    config.gateway_config_path = Some(path.clone());
    let case = Case::new(config).await?;
    let result = async {
        let (_, admin) = case.user("admin@test.invalid", "admin").await?;
        let (target, cookie) = case.user("retry@test.invalid", "user").await?;
        let (status, _, _) = case
            .call(
                "DELETE",
                &format!("/api/admin/users/{target}"),
                &admin,
                json!({"confirm_email":"retry@test.invalid"}),
                &[],
            )
            .await?;
        ensure!(status.is_server_error());
        let user = case
            .app
            .collection("users")
            .find_one(doc! {"_id":target})
            .await?
            .unwrap();
        ensure!(user.contains_key("account_deletion"));
        case.status(
            "GET",
            "/api/auth/me",
            &cookie,
            json!(null),
            StatusCode::BAD_REQUEST,
        )
        .await?;
        case.status(
            "POST",
            "/api/auth/signin",
            "",
            json!({"username":"retry@test.invalid","password":"Original-Password1!"}),
            StatusCode::BAD_REQUEST,
        )
        .await?;
        std::fs::remove_dir(&path)?;
        case.app
            .collection("users")
            .update_one(
                doc! {"_id":target},
                doc! {"$set":{"account_deletion.next_attempt_at":DateTime::from_millis(0)}},
            )
            .await?;
        porthub_api::account_delete::recover_due(&case.app)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
        ensure!(
            case.app
                .collection("users")
                .count_documents(doc! {"_id":target})
                .await?
                == 0
        );
        ensure!(path.is_file());
        Ok(())
    }
    .await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn fresh_public_signup_has_the_same_uniqueness_constraint()->Result<()> {
    let mut config=Config::default();config.signup_disabled=false;
    let case=Case::new(config).await?;
    let result=async {
        let body=json!({"name":"Fresh user","username":"fresh@example.invalid","password":"Fresh-Password1!"});
        let (first,second)=tokio::join!(case.call("POST","/api/auth/signup","",body.clone(),&[]),case.call("POST","/api/auth/signup","",body,&[]));
        let first=first?;let second=second?;
        ensure!([first.0,second.0].contains(&StatusCode::OK));
        ensure!([first.0,second.0].iter().all(|status|*status==StatusCode::OK||*status==StatusCode::CONFLICT));
        ensure!(case.app.collection("users").count_documents(doc!{"username":"fresh@example.invalid"}).await?==1);
        Ok(())
    }.await;case.db.drop().await?;result
}
