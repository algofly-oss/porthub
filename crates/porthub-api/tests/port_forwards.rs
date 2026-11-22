use anyhow::{ensure, Context, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{config::Config, routes::port_forwards::COLLECTION};
use serde_json::{json, Value};
mod support;
use support::Case;

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn owner_can_recopy_and_revoke_a_private_forward_across_restarts() -> Result<()> {
    let temp = tempfile::tempdir()?;
    std::env::set_var("PORTHUB_FORWARD_SSH_MASTER", temp.path().join("master"));
    let config = Config {
        external_port_range: Some((41200, 41201)),
        private_relay_tls_origin: Some("https://127.0.0.1:8243".into()),
        ..Config::default()
    };
    let case = Case::new(config.clone()).await?;
    let result=async {
        let (owner, cookie)=case.user("forward-owner@example.invalid","user").await?;
        let (foreign, other)=case.user("forward-other@example.invalid","admin").await?;
        let machine=ObjectId::new();
        let outsider=ObjectId::new();
        case.app.collection("machines").insert_many([
            doc!{"_id":machine,"user_id":owner,"name":"Consumer","enabled":true},
            doc!{"_id":outsider,"user_id":foreign,"name":"Other","enabled":true},
        ]).await?;
        case.app.collection("connections").insert_one(doc!{"external_port":41200_i32,"user_id":foreign,"enabled":false}).await?;
        let api="/api/port-forwards";
        let input=json!({"name":"Support laptop","machineIds":[machine.to_hex()],"mappings":[{"direction":"remote","clientPort":22}]});
        let response=case.call("POST",api,"",input.clone(),&[]).await?;
        ensure!(response.0.is_client_error());
        let response=case.call("POST",api,&cookie,input.clone(),&[("origin","https://another.invalid")]).await?;
        ensure!(response.0==StatusCode::FORBIDDEN);

        let mut invalid=input.clone();invalid["machineIds"]=json!([outsider.to_hex()]);
        case.status("POST",api,&cookie,invalid,StatusCode::BAD_REQUEST).await?;
        let mut invalid=input.clone();invalid["mappings"]=json!([{"direction":"local","machineId":outsider.to_hex(),"clientPort":23000,"servicePort":22}]);invalid["machineIds"]=json!([]);
        case.status("POST",api,&cookie,invalid,StatusCode::BAD_REQUEST).await?;
        let mut isolated=input.clone(); isolated["machineIds"]=json!([]);
        let created=case.status("POST",api,&cookie,isolated,StatusCode::OK).await?;
        let id=created["id"].as_str().context("missing new entry")?;
        let item=format!("{api}/{id}");
        let reveal=format!("{item}/credentials");
        case.status("POST",&reveal,&other,Value::Null,StatusCode::NOT_FOUND).await?;
        case.status("DELETE",&item,&other,Value::Null,StatusCode::NOT_FOUND).await?;
        let (_, headers, first)=case.call("POST",&reveal,&cookie,Value::Null,&[]).await?;
        ensure!(headers["cache-control"].to_str()?.contains("no-store"));
        ensure!(first["privateKey"].as_str().is_some_and(|v|v.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")));
        ensure!(first["mappings"][0]["gatewayPort"]==41201 && first["username"]==format!("pf-{id}"));
        let audience=format!("{item}/audience");
        let isolated=case.status("GET",api,&cookie,Value::Null,StatusCode::OK).await?;
        ensure!(isolated["entries"][0]["published"]==false);
        ensure!(isolated["entries"][0]["machineIds"].as_array().unwrap().is_empty());
        case.status("PUT",&audience,&other,json!({"public":false,"machineIds":[machine.to_hex()]}),StatusCode::NOT_FOUND).await?;
        case.status("PUT",&audience,&cookie,json!({"public":false,"machineIds":[outsider.to_hex()]}),StatusCode::BAD_REQUEST).await?;
        case.status("PUT",&audience,&cookie,json!({"public":true,"machineIds":[machine.to_hex()]}),StatusCode::BAD_REQUEST).await?;

        case.status("PUT",&audience,&cookie,json!({"public":false,"machineIds":[machine.to_hex()]}),StatusCode::OK).await?;
        let after=case.status("POST",&reveal,&cookie,Value::Null,StatusCode::OK).await?;
        ensure!(after==first, "Audience update changed SSH credentials or mappings");
        let listed=case.status("GET",api,&cookie,Value::Null,StatusCode::OK).await?;
        ensure!(listed["entries"].as_array().unwrap().len()==1);
        ensure!(listed["machines"].as_array().unwrap().len()==1 && !listed.to_string().contains("PRIVATE KEY"));
        ensure!(listed["entries"][0]["public"]==false && listed["entries"][0]["published"]==true);
        let row=case.app.collection(COLLECTION).find_one(doc!{"_id":ObjectId::parse_str(id)?}).await?.unwrap();
        ensure!(row.get_str("public_key")?.starts_with("ssh-ed25519 ") && !row.to_string().contains("PRIVATE KEY"));
        // A fresh API process opens the same master and database. Recopying a
        // command must preserve both the client credentials and its host pin.
        let fresh=std::sync::Arc::new(porthub_api::App::new(config,case.db.clone()));
        let restart=Case{router:porthub_api::router(fresh.clone()),app:fresh,db:case.db.clone()};
        let second=restart.status("POST",&reveal,&cookie,Value::Null,StatusCode::OK).await?;
        ensure!(first==second);
        case.status("PUT",&audience,&cookie,json!({"public":false}),StatusCode::OK).await?;
        let unpublished=case.status("GET",api,&cookie,Value::Null,StatusCode::OK).await?;
        ensure!(unpublished["entries"][0]["published"]==false);
        ensure!(case.status("POST",&reveal,&cookie,Value::Null,StatusCode::OK).await?==first);
        case.status("POST",api,&cookie,input,StatusCode::CONFLICT).await?;
        ensure!(case.app.collection(COLLECTION).count_documents(doc!{}).await?==1);
        // No edge is configured in this fixture: failed public publication
        // must leave the command reusable and every audience withdrawn.
        case.status("PUT",&audience,&cookie,json!({"public":true}),StatusCode::SERVICE_UNAVAILABLE).await?;
        let failed=case.status("GET",api,&cookie,Value::Null,StatusCode::OK).await?;
        ensure!(failed["entries"][0]["published"]==false);
        ensure!(case.status("POST",&reveal,&cookie,Value::Null,StatusCode::OK).await?==first);
        // A retry cannot forget uncertain public cleanup just because the
        // durable audience was already withdrawn by the failed request.
        case.status("PUT",&audience,&cookie,json!({"public":false}),StatusCode::SERVICE_UNAVAILABLE).await?;
        let pending=case.app.collection(COLLECTION).find_one(doc!{"_id":ObjectId::parse_str(id)?}).await?.unwrap();
        ensure!(pending.get_bool("audience_cleanup_pending")==Ok(true));
        // This fixture never had an edge; simulate completed cleanup before deletion.
        case.app.collection(COLLECTION).update_one(doc!{"_id":ObjectId::parse_str(id)?},doc!{"$unset":{"audience_cleanup_pending":""}}).await?;
        case.status("DELETE",&item,&cookie,Value::Null,StatusCode::NO_CONTENT).await?;
        case.status("POST",&reveal,&cookie,Value::Null,StatusCode::NOT_FOUND).await?;
        ensure!(case.app.collection("connections").count_documents(doc!{}).await?==1);
        ensure!(case.app.collection(COLLECTION).count_documents(doc!{}).await?==0);
        Ok::<_,anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}
